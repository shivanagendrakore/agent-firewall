#!/usr/bin/env node
/**
 * Captures the real-page friction corpus (LAUNCHSAFE_BROWSER_CORPUS_DIR, default ~/.launchsafe/browser-corpus/real) from the public pages listed in
 * scripts/corpus-urls.mjs, to measure the content guard's false positives on real sites.
 *
 *   node scripts/capture-corpus.mjs [--only <substring>] [--limit N] [--keep-existing]
 *
 * This is the only script in the repository that reads the internet, and it only does read-only GETs
 * of public pages: no sign-in, no forms, no clicks, a robots.txt check for every URL fetched (pages and
 * stylesheets), an identifying user agent, a pause between requests to one host. A page that refuses
 * (robots.txt, a bot wall, an error) is skipped and listed in the manifest; nothing tries to get round it.
 *
 * Each page is rendered once in a headless Chromium with a throwaway profile (so cookie banners, menus
 * and other script-built UI are in the DOM), then written as ONE self-contained static HTML file:
 *   - scripts, noscript, iframes, media, objects, <link>, <base>, meta refresh and every on* handler are removed;
 *   - every stylesheet is inlined from the CSS object model (cross-origin sheets fetched once) with
 *     @import, @font-face and every non-data url() removed, so nothing at test time touches the network;
 *   - images become an inline 1x1 gif, keeping their size attributes, or, when they have none, their real rendered
 *     (or natural) size written as width and height (images are fetched while capturing only to learn that size);
 *   - analytics and tracker requests are blocked while capturing, and tracker markup is dropped;
 *   - personal data is scrubbed: e-mail addresses, phone numbers, hidden-input values, csrf and nonce values.
 * The tests (test/e2e/friction-real.spec.ts) serve these files from 127.0.0.1 and execute nothing from them.
 */
import { mkdir, readFile, rm, writeFile, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { join, resolve } from "node:path";
import { PAGES } from "./corpus-urls.mjs";

// Outside the repo: the captured pages are other people's copyrighted pages and are not committed.
const OUT = resolve(process.env.LAUNCHSAFE_BROWSER_CORPUS_DIR ?? join(homedir(), ".launchsafe", "browser-corpus", "real"));
const UA = "LaunchSafeCorpusCapture/1.0 (+https://launchsafe.com; read-only research capture of public pages; honours robots.txt)";
const ROBOTS_TOKEN = "launchsafecorpuscapture";
const MAX_HTML_BYTES = 220_000;
const MAX_CSS_BYTES = 80_000;
const HOST_GAP_MS = 2500;
const CONCURRENCY = 3;
const TRACKERS = /(google-analytics|googletagmanager|googlesyndication|doubleclick|googleadservices|facebook\.(net|com)\/tr|connect\.facebook|hotjar|segment\.(io|com)|mixpanel|amplitude|optimizely|fullstory|clarity\.ms|newrelic|nr-data|sentry|datadoghq|quantserve|scorecardresearch|chartbeat|taboola|outbrain|criteo|adsrvr|adnxs|amazon-adsystem|pinterest\.com\/ct|snap\.licdn|ads-twitter|analytics\.twitter|bat\.bing|tiktok.*analytics|branch\.io|appsflyer|crazyegg|mouseflow|heap(analytics)?\.io|hs-analytics|hsforms|hubspot|intercom|drift\.com|zdassets|zopim|onesignal|pushwoosh)/i;

const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const opt = (n) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);

// ---------- robots.txt ----------
const robotsCache = new Map();
function parseRobots(text) {
  const groups = [];
  let cur = null;
  let lastWasAgent = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    const m = /^([A-Za-z-]+)\s*:\s*(.*)$/.exec(line);
    if (!m) continue;
    const k = m[1].toLowerCase();
    if (k === "user-agent") {
      if (!lastWasAgent || cur === null) {
        cur = { agents: [], rules: [] };
        groups.push(cur);
      }
      cur.agents.push(m[2].trim().toLowerCase());
      lastWasAgent = true;
    } else if ((k === "allow" || k === "disallow") && cur) {
      cur.rules.push({ allow: k === "allow", path: m[2].trim() });
      lastWasAgent = false;
    } else lastWasAgent = false;
  }
  return groups;
}
function ruleMatches(rule, path) {
  if (rule.path === "") return false;
  const esc = rule.path.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp("^" + esc.replace(/\\\$$/, "$")).test(path);
}
async function robotsAllows(urlStr) {
  const u = new URL(urlStr);
  if (u.protocol !== "https:" && u.protocol !== "http:") return true;
  let groups = robotsCache.get(u.origin);
  if (groups === undefined) {
    try {
      const res = await fetch(`${u.origin}/robots.txt`, { headers: { "user-agent": UA }, redirect: "follow", signal: AbortSignal.timeout(10_000) });
      // 4xx: no robots rules. 5xx or unreachable: treat as disallow, the cautious reading.
      groups = res.status >= 500 ? "deny" : res.ok ? parseRobots(await res.text()) : [];
    } catch {
      groups = "deny";
    }
    robotsCache.set(u.origin, groups);
  }
  if (groups === "deny") return false;
  const specific = groups.filter((g) => g.agents.some((a) => a !== "*" && ROBOTS_TOKEN.includes(a)));
  const use = specific.length > 0 ? specific : groups.filter((g) => g.agents.includes("*"));
  const path = u.pathname + u.search;
  let best = null;
  for (const g of use) for (const r of g.rules) if (ruleMatches(r, path) && (best === null || r.path.length > best.path.length || (r.path.length === best.path.length && r.allow))) best = r;
  return best === null || best.allow;
}

// ---------- politeness ----------
const hostNext = new Map();
async function politeWait(urlStr) {
  const h = new URL(urlStr).host;
  const at = Math.max(Date.now(), hostNext.get(h) ?? 0);
  hostNext.set(h, at + HOST_GAP_MS);
  const wait = at - Date.now();
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
}

// ---------- in-page extraction ----------
/** Runs in the page: returns { html, css parts, pending cross-origin sheets }. */
function extractInPage(maxHtml) {
  const doc = document;
  const sheets = [];
  const pendingHrefs = [];
  for (const s of Array.from(doc.styleSheets)) {
    if (s.disabled) continue;
    const media = s.media && s.media.mediaText ? s.media.mediaText : "";
    if (media && !/^(all|screen|\s)*$/i.test(media) && !/(min-|max-|width|prefers|screen)/i.test(media)) continue; // print and the like
    try {
      sheets.push({ media, text: Array.from(s.cssRules).map((r) => r.cssText).join("\n") });
    } catch {
      // A cross-origin sheet the CSS object model will not show: fetched separately.
      if (s.href) pendingHrefs.push({ index: sheets.length, href: s.href });
      sheets.push({ media, text: "" });
    }
  }
  for (const s of doc.adoptedStyleSheets ?? []) {
    try {
      sheets.push({ media: "", text: Array.from(s.cssRules).map((r) => r.cssText).join("\n") });
    } catch {
      /* ignore */
    }
  }
  // Each image's real size, read from the live page before it becomes a 1x1 placeholder: its rendered box when it
  // has one, else its natural size. Written onto the placeholder as width/height attributes (when the element has
  // none), so the snapshot lays out like the page and a picture is not mistaken for a tracking pixel.
  const liveImages = Array.from(doc.querySelectorAll("img, input[type=image]")).map((el) => {
    const r = el.getBoundingClientRect();
    const w = r.width > 2 ? r.width : (el.naturalWidth ?? 0);
    const h = r.height > 2 ? r.height : (el.naturalHeight ?? 0);
    return w > 2 && h > 2 ? { w: Math.round(w), h: Math.round(h) } : null;
  });
  const root = doc.documentElement.cloneNode(true);
  Array.from(root.querySelectorAll("img, input[type=image]")).forEach((el, i) => {
    const size = liveImages[i];
    if (size == null || el.hasAttribute("width") || el.hasAttribute("height")) return;
    el.setAttribute("width", String(size.w));
    el.setAttribute("height", String(size.h));
  });
  const gif = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
  // <noscript> (inert text with scripts on) and <template> are text an agent can read, so they stay, cleaned.
  // Repeated until nothing changes: one pass can leave a tag its removal assembled (`<scr<script></script>ipt>`).
  // Every pass only removes text, so this ends.
  const cleanMarkup = (html) => {
    let s = html;
    for (let before = ""; s !== before; ) {
      before = s;
      s = s
        .replace(/<(script|iframe|object|embed|video|audio|link|base|style)\b[\s\S]*?(<\/\1>|\/?>)/gi, "")
        .replace(/\s(src|srcset|data-src|poster|data)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, "")
        .replace(/\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, "");
    }
    return s;
  };
  const sanitize = (scope) => {
    for (const el of Array.from(scope.querySelectorAll("script,iframe,frame,object,embed,video,audio,source,track,canvas,link,base,style,portal,applet,meta[http-equiv],meta[name=csrf-token],meta[name=csrf-param],meta[name=request-id]"))) el.remove();
    for (const el of Array.from(scope.querySelectorAll("noscript"))) el.textContent = cleanMarkup(el.textContent ?? "");
    for (const el of Array.from(scope.querySelectorAll("*"))) {
      for (const a of Array.from(el.attributes)) {
        const n = a.name.toLowerCase();
        if (n.startsWith("on") || n === "nonce" || n === "integrity" || n === "crossorigin" || n === "referrerpolicy" || n === "ping" || n === "srcset" || n === "sizes" || n === "loading" || n === "decoding" || n === "fetchpriority" || n === "background" || n === "lowsrc" || n === "dynsrc" || n === "poster") el.removeAttribute(a.name);
        else if (n === "style" && /url\s*\(/i.test(a.value)) el.setAttribute(a.name, a.value.replace(/url\s*\([^)]*\)/gi, "none"));
        else if ((n === "href" || n === "src" || n === "action" || n === "formaction") && /^\s*javascript:/i.test(a.value)) el.setAttribute(a.name, "#");
        else if (n === "srcdoc") el.removeAttribute(a.name);
        else if (n.startsWith("data-") && !/^data-(theme|color|mode|bs-|state|open|expanded|hidden|dir|lang)/.test(n)) el.removeAttribute(a.name);
      }
      const tag = el.tagName.toLowerCase();
      if (tag === "template") sanitize(el.content);
      else if (tag === "img" || (tag === "input" && el.getAttribute("type") === "image")) el.setAttribute("src", gif);
      else if (tag === "a") {
        const h = el.getAttribute("href");
        if (h !== null && !/^\s*(#|javascript:|mailto:|tel:)/i.test(h)) {
          try { el.setAttribute("href", new URL(h, doc.baseURI).href); } catch { /* keep */ }
        }
      } else if (tag === "input") {
        const t = (el.getAttribute("type") ?? "text").toLowerCase();
        if (t === "hidden" || t === "password") el.setAttribute("value", "");
      } else if (tag === "use") {
        const h = el.getAttribute("href") ?? el.getAttribute("xlink:href");
        if (h && !h.startsWith("#")) { el.removeAttribute("href"); el.removeAttribute("xlink:href"); }
      } else if (tag === "image") el.remove();
    }
  };
  sanitize(root);
  // Keep the live form state a person would see (open details, typed search text is not captured: nothing was typed).
  const head = root.querySelector("head");
  const body = root.querySelector("body");
  const serialize = () => "<!doctype html>\n" + root.outerHTML;
  let truncated = false;
  let html = serialize();
  // Large inline SVGs and giant lists are what blow the budget; trim the biggest list tail first.
  if (html.length > maxHtml && body) {
    for (const svg of Array.from(body.querySelectorAll("svg"))) if (svg.outerHTML.length > 4000) svg.remove();
    html = serialize();
  }
  let guard = 0;
  while (html.length > maxHtml && body && guard++ < 120) {
    // Descend to the element that holds most of the page, then drop its tail (references, long lists, comments).
    let box = body;
    for (;;) {
      const total = box.outerHTML.length;
      let big = null;
      let bigLen = 0;
      for (const c of Array.from(box.children)) {
        const l = c.outerHTML.length;
        if (l > bigLen) { big = c; bigLen = l; }
      }
      if (big !== null && bigLen > total * 0.6 && big.children.length > 0) box = big;
      else break;
    }
    if (box.children.length < 2) break;
    const drop = Math.max(1, Math.ceil(box.children.length * 0.1));
    for (let i = 0; i < drop && box.children.length > 1; i++) box.lastElementChild.remove();
    truncated = true;
    html = serialize();
  }
  return { lang: doc.documentElement.getAttribute("lang") ?? "", dir: doc.documentElement.getAttribute("dir") ?? "", title: doc.title ?? "", sheets, pendingHrefs, htmlNoCss: html, hasHead: head !== null, truncated, textChars: (doc.body?.innerText ?? "").length };
}

// ---------- scrub and CSS clean-up ----------
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g;
const PHONE = /(?<![\w.-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?!\d)/g;
function scrubText(s) {
  return s.replace(EMAIL, "redacted@example.invalid").replace(PHONE, "000-000-0000");
}
function cleanCss(css) {
  let out = css.replace(/@import[^;]*;/gi, "");
  // Drop whole @font-face blocks (no fonts load; the fallback face is the same before and after the guard).
  out = out.replace(/@font-face\s*\{[^}]*\}/gi, "");
  out = out.replace(/url\(\s*(['"]?)(?!data:)[^)]*\1\s*\)/gi, "none");
  return out;
}
function budgetCss(parts) {
  let total = 0;
  const kept = [];
  for (const p of parts) {
    if (total + p.length > MAX_CSS_BYTES) continue;
    total += p.length;
    kept.push(p);
  }
  return kept;
}

function slug(url, category) {
  const u = new URL(url);
  const base = (u.host.replace(/^www\./, "") + u.pathname + u.search).replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 70) || u.host;
  // A non-ASCII path becomes hex-free text of its own; keep the file name ASCII and unique.
  let h = 0;
  for (const c of url) h = (h * 31 + c.codePointAt(0)) >>> 0;
  return `${category}-${base.replace(/[^\x20-\x7e]/g, "")}-${h.toString(36)}`.replace(/-+/g, "-");
}

const BLOCKED_PAGE = /(access denied|attention required|just a moment|captcha|are you a robot|verify you are human|unusual traffic|403 forbidden|request blocked|pardon our interruption)/i;

async function captureOne(browser, [category, url, license]) {
  if (!(await robotsAllows(url))) return { skipped: "robots.txt disallows the URL" };
  await politeWait(url);
  const context = await browser.newContext({ userAgent: UA, viewport: { width: 1100, height: 900 }, serviceWorkers: "block", acceptDownloads: false, javaScriptEnabled: true, locale: "en-US" });
  try {
    await context.route("**/*", async (route) => {
      const req = route.request();
      const t = req.resourceType();
      // Images load (read-only GETs, robots.txt checked) only so the snapshot can keep their real size; their bytes are not kept.
      if (t === "image") return (await robotsAllows(req.url()).catch(() => false)) && !TRACKERS.test(req.url()) ? route.continue() : route.abort();
      if (t === "media" || t === "font" || t === "websocket" || t === "eventsource" || t === "ping" || TRACKERS.test(req.url())) return route.abort();
      if (req.method() !== "GET" && t !== "document") return route.abort(); // read-only: nothing is ever POSTed
      if (req.method() !== "GET") return route.abort();
      if (t === "stylesheet" || t === "script" || t === "document") {
        const ok = await robotsAllows(req.url()).catch(() => false);
        if (!ok && t !== "document") return route.abort();
      }
      return route.continue();
    });
    const page = await context.newPage();
    const resp = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 25_000 });
    if (resp === null || resp.status() >= 400) return { skipped: `HTTP ${resp?.status() ?? "no response"}` };
    await page.waitForLoadState("networkidle", { timeout: 6000 }).catch(() => undefined);
    await page.waitForTimeout(1200);
    // Give images that are still loading a moment, so their natural size is known (lazy images below the fold keep their CSS box).
    await page.evaluate(() => Promise.all(Array.from(document.images).map((i) => (i.complete ? 0 : new Promise((ok) => { i.addEventListener("load", ok, { once: true }); i.addEventListener("error", ok, { once: true }); setTimeout(ok, 3000); }))))).catch(() => undefined);
    const finalUrl = page.url();
    if (!(await robotsAllows(finalUrl))) return { skipped: "redirected to a URL robots.txt disallows" };
    const ex = await page.evaluate(extractInPage, MAX_HTML_BYTES);
    if (BLOCKED_PAGE.test(ex.title) || ex.textChars < 300) return { skipped: `bot wall or empty page (title "${ex.title.slice(0, 50)}", ${ex.textChars} chars)` };
    // Cross-origin sheets the CSSOM would not show.
    for (const p of ex.pendingHrefs) {
      if (!(await robotsAllows(p.href).catch(() => false))) continue;
      try {
        const r = await context.request.get(p.href, { timeout: 10_000 });
        if (r.ok()) ex.sheets[p.index].text = await r.text();
      } catch {
        /* the page renders without it */
      }
    }
    const parts = budgetCss(
      ex.sheets
        .filter((s) => s.text.trim() !== "")
        .map((s) => {
          const c = cleanCss(s.text);
          return s.media && /(min-|max-|width)/i.test(s.media) ? `@media ${s.media} {\n${c}\n}` : c;
        }),
    );
    const styleTag = `<style data-launchsafe-capture>\n${parts.join("\n")}\n</style>`;
    const date = new Date().toISOString().slice(0, 10);
    const note = `<!-- Captured ${date} from ${finalUrl} by scripts/capture-corpus.mjs. Static research snapshot: scripts and external references removed, personal data scrubbed. ${license}. -->`;
    let html = ex.htmlNoCss;
    html = html.includes("</head>") ? html.replace("</head>", `<meta charset="utf-8">${styleTag}</head>`) : html.replace(/<html[^>]*>/i, (m) => `${m}<head><meta charset="utf-8">${styleTag}</head>`);
    html = html.replace("<!doctype html>", `<!doctype html>\n${note}`);
    html = scrubText(html);
    if (Buffer.byteLength(html) > MAX_HTML_BYTES + MAX_CSS_BYTES + 20_000) return { skipped: `still ${Buffer.byteLength(html)} bytes after trimming` };
    const id = slug(url, category);
    await writeFile(join(OUT, `${id}.html`), html);
    return { entry: { id, file: `${id}.html`, url, finalUrl, category, lang: ex.lang, dir: ex.dir, title: scrubText(ex.title).slice(0, 120), capturedAt: date, license, bytes: Buffer.byteLength(html), textChars: ex.textChars, truncated: ex.truncated } };
  } catch (e) {
    return { skipped: `error: ${String(e.message ?? e).split("\n")[0].slice(0, 120)}` };
  } finally {
    await context.close();
  }
}

async function main() {
  // Playwright's browser cache lives under the real home even when HOME is a throwaway folder (the safe-run sandbox).
  if (process.env.PLAYWRIGHT_BROWSERS_PATH === undefined) {
    const home = userInfo().homedir;
    process.env.PLAYWRIGHT_BROWSERS_PATH = process.platform === "darwin" ? join(home, "Library", "Caches", "ms-playwright") : join(home, ".cache", "ms-playwright");
  }
  const { chromium } = await import("@playwright/test");
  await mkdir(OUT, { recursive: true });
  const only = opt("--only");
  const limit = Number(opt("--limit") ?? Infinity);
  let list = PAGES.filter((p) => only === undefined || p[1].includes(only));
  list = list.slice(0, limit);
  if (!flag("--keep-existing")) for (const f of await readdir(OUT)) if (f.endsWith(".html")) await rm(join(OUT, f));
  const browser = await chromium.launch({ headless: true, args: ["--no-first-run", "--disable-background-networking", "--no-pings"] });
  const entries = [];
  const skipped = [];
  let next = 0;
  const worker = async () => {
    while (next < list.length) {
      const item = list[next++];
      const r = await captureOne(browser, item);
      if (r.entry) {
        entries.push(r.entry);
        console.log(`ok   ${item[0].padEnd(16)} ${r.entry.bytes.toString().padStart(7)}B ${item[1]}`);
      } else {
        skipped.push({ url: item[1], category: item[0], reason: r.skipped });
        console.log(`skip ${item[0].padEnd(16)} ${r.skipped} ${item[1]}`);
      }
    }
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  await browser.close();
  entries.sort((a, b) => a.id.localeCompare(b.id));
  skipped.sort((a, b) => a.url.localeCompare(b.url));
  const manifestPath = join(OUT, "manifest.json");
  const manifest = {
    note: "Real-page friction corpus: static, script-free snapshots of public pages, captured by scripts/capture-corpus.mjs, used only to measure the content guard's false positives (offline, from 127.0.0.1). Third-party content is kept as a research snapshot, not redistributed as a product; each licence note is the page's own terms.",
    userAgent: UA,
    capturedAt: new Date().toISOString().slice(0, 10),
    pages: entries,
    skipped,
  };
  if (flag("--keep-existing") && existsSync(manifestPath)) {
    const old = JSON.parse(await readFile(manifestPath, "utf8"));
    const byId = new Map(old.pages.map((p) => [p.id, p]));
    for (const e of entries) byId.set(e.id, e);
    manifest.pages = [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
    const seen = new Set([...skipped.map((x) => x.url), ...entries.map((e) => e.url)]);
    manifest.skipped = [...old.skipped.filter((x) => !seen.has(x.url) && !byId.has(slug(x.url, x.category))), ...skipped].sort((a, b) => a.url.localeCompare(b.url));
  }
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  console.log(`captured ${manifest.pages.length}, skipped ${skipped.length}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
