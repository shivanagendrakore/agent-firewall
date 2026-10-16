/**
 * Content guard (design 4): live DOM scan, verdicts, neutralise in agent
 * mode, MutationObserver rescans, frame hello for tab trust.
 *
 * - At DOMContentLoaded the guard walks the document (and open shadow roots):
 *   text grouped by the element that hides it (or, for visible text, by its
 *   block), HTML comments, the attributes an agent reads (alt, title,
 *   aria-label, aria-description, placeholder, value, meta content), link and
 *   image URLs, and unrendered markup (<template>, <noscript>, srcdoc).
 * - Hidden is what the browser says (checkVisibility, opacity, clipping, a
 *   tiny box with clipped overflow, off-screen, tiny font, contrast,
 *   aria-hidden); folded (closed details, spoilers, until-found) counts only
 *   with an agent-addressed hit. The judgement is the engine's
 *   (engine/guard-scan.ts over the vendored scanner).
 * - The verdict goes to the worker (`page.scanned`), which marks the tab.
 * - In agent mode, quarantine-class nodes are removed (DOM and accessibility
 *   tree) and replaced with an inert visible marker; invisible smuggling
 *   characters are stripped from text that stays. Nothing else changes, so a
 *   benign page looks exactly the same.
 * - A MutationObserver rescans what arrives later, within 50 ms, budgeted.
 */
import type { HiddenKind, QuarantineReason } from "../engine/content.js";
import { isBenignVeil, judgeLinks, judgeRuns, judgeStatic, worse, type GuardLink, type GuardRun } from "../engine/guard-scan.js";
import { hiddenKindOf, ownRendered } from "../engine/visibility.js";
import type { ContentVerdict } from "../shared/messages.js";
import { scanCharacters } from "../vendor/firewall/engine/content-scan.js";
import { isDnsExfilShape, isRawIp } from "../vendor/firewall/engine/network.js";
import { shadowRootWatcher } from "./shadow-roots.js";
import type { ContentDeps, ContentModule } from "./types.js";

export interface ContentGuard extends ContentModule {
  /** Rescan a subtree added after load (debounced and budgeted by the implementation). */
  rescan(root: Node): void;
  /** Agent mode changed: neutralise now (on) or stop neutralising new content (off; removed nodes stay removed). */
  setAgentMode(on: boolean): void;
}

/**
 * Our marker elements carry this attribute so a person (and the tests) can find them. The guard never trusts
 * it: a page can set any attribute, so the guard recognises its own markers by identity (a private WeakSet),
 * and an element that merely wears the attribute is scanned like any other (RR4).
 */
export const MARKER_ATTR = "data-launchsafe-removed";
export const MARKER_TEXT = "LaunchSafe removed hidden text addressed to an AI agent";

const SKIP = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE", "IFRAME", "OBJECT", "EMBED", "CANVAS", "VIDEO", "AUDIO"]);
const STATIC = new Set(["TEMPLATE", "NOSCRIPT", "IFRAME"]);
/** Shown on interaction, never attack text by being closed (select options, datalists). */
const SHOWN_ON_USE = new Set(["OPTION", "OPTGROUP", "DATALIST"]);
/** Roles whose hidden state means "not opened yet". */
const DISCLOSURE_ROLES = new Set(["tabpanel", "dialog", "alertdialog", "menu", "listbox", "tooltip"]);
/** Attributes an agent reads from the accessibility tree or the DOM, judged as hidden text wherever they are. */
const HIDDEN_ATTRS = ["alt", "title", "aria-label", "aria-description", "aria-roledescription", "aria-valuetext"] as const;
/** Meta tags whose content is page text an agent reads (not viewport, robots, theme colour and other settings). */
const READ_META = /^(?:description|keywords|author|subject|abstract|summary|(?:og|twitter):(?:title|description))$/;
/**
 * Attribute changes that can reveal, hide or add text: the text attributes, and `class` and `style` (a class
 * swap can make hidden text visible to an agent's reader, or hide visible text). Class and style rescans are
 * budgeted per flush (LIMITS.styleRescans); past the budget the page is marked as not fully scanned.
 */
const OBSERVED_ATTRS = ["hidden", "aria-hidden", ...HIDDEN_ATTRS, "placeholder", "value", "srcdoc", "open", "content", "src", "href", "class", "style"];
const STYLE_ATTRS = new Set(["class", "style"]);

/**
 * Not read: text a stylesheet generates (`::before` / `::after` `content`, counters, `attr()`), which is in no
 * DOM node. An agent that reads the rendered page or the accessibility tree can still see it (threat model 4,
 * row 1 residual).
 */
const LIMITS = { runs: 20_000, chars: 2 * 1024 * 1024, visibleContext: 256 * 1024, rescansPerSecond: 30, debounceMs: 40, slowDebounceMs: 250, styleRescans: 64, hostsPerPage: 200 } as const;

interface ElState {
  hidden: HiddenKind | null;
  /** The outermost element that hides this one (the node removed in agent mode). */
  root: Element | null;
  folded: boolean;
  opacity: number;
  /** Background colour behind the element, or null when an image (or unknown paint) is behind it. */
  bg: string | null;
}

type RunRef = { kind: "group"; el: Element; texts: Text[] } | { kind: "comment"; node: Comment } | { kind: "attr"; el: Element; name: string };

interface Collected {
  runs: GuardRun[];
  refs: RunRef[];
  links: GuardLink[];
  linkEls: Element[];
  statics: { el: Element; html: string }[];
  hosts: Set<string>;
  incomplete: boolean;
}

type Fix = { op: "remove"; node: Node; marker: boolean } | { op: "removeAttr"; el: Element; name: string } | { op: "stripText"; node: Text } | { op: "stripAttr"; el: Element; name: string };

const BASE: ElState = { hidden: null, root: null, folded: false, opacity: 1, bg: "rgb(255, 255, 255)" };

function parentOf(el: Element): Element | null {
  if (el.parentElement !== null) return el.parentElement;
  const p = el.parentNode;
  return p !== null && p.nodeType === 11 && "host" in p ? (p as ShadowRoot).host : null;
}

function tagNameOf(el: Element): string {
  return el.tagName.toUpperCase();
}

/** A computed length or number; `fallback` only when the value is not a number at all (0 is a number). */
function num(v: string, fallback: number): number {
  const n = Number.parseFloat(v);
  return Number.isFinite(n) ? n : fallback;
}

function stripInvisible(s: string): string {
  const ranges = scanCharacters(s).remove;
  if (ranges.length === 0) return s;
  let out = "";
  let at = 0;
  for (const [a, b] of [...ranges].sort((x, y) => x[0] - y[0])) {
    if (b <= at) continue;
    out += s.slice(at, Math.max(at, a));
    at = Math.max(at, b);
  }
  return out + s.slice(at);
}

/** Smuggling characters worth stripping from text that stays: tag characters, bidi controls, or a dense zero-width run. */
function worthStripping(s: string): boolean {
  const c = scanCharacters(s);
  return c.tagCount > 0 || c.bidiCount > 0 || c.zwMaxRun >= 4 || c.zwPositions.length >= 8;
}

export function createContentGuard(deps: ContentDeps): ContentGuard {
  const win = deps.win;
  const doc = win.document;
  let installed = false;
  let observer: MutationObserver | null = null;
  let unsubscribeRoots: (() => void) | null = null;
  let docVerdict: ContentVerdict = "deliver";
  const docReasons = new Set<string>();
  let docIncomplete = false;
  /** Part of the page was never judged: a scan over its budget, or a scan that threw (not mere churn). */
  let budgetOverflow = false;
  /** Class/style-triggered rescans queued since the last flush. */
  let styleRescans = 0;
  /** The start of the first hidden text that quarantined the page: the worker keeps it only with "keep evidence" on. */
  let docPreview = "";
  let reported = false;
  let visibleContext = "";
  const pendingFixes: Fix[] = [];
  /** Nodes already queued for removal (a rescan of the same subtree must not queue them twice). */
  const queued = new WeakSet<Node>();
  const sentHosts = new Set<string>();
  /** The marker elements this guard inserted. Module-private: page script cannot add to it (RR4). */
  const ownMarkers = new WeakSet<Element>();
  const isOwnMarker = (el: Element): boolean => ownMarkers.has(el);
  const pendingRoots = new Set<Node>();
  let timer: ReturnType<typeof setTimeout> | null = null;
  const rescanTimes: number[] = [];
  let muted = false;

  // ---- visibility ----

  const stateOf = (memo: Map<Element, ElState>, el: Element): ElState => {
    const have = memo.get(el);
    if (have !== undefined) return have;
    const parent = parentOf(el);
    const ps = parent === null ? BASE : stateOf(memo, parent);
    let st: ElState;
    if (ps.hidden !== null) st = ps;
    else st = ownState(el, parent, ps);
    memo.set(el, st);
    return st;
  };

  const ownState = (el: Element, parent: Element | null, ps: ElState): ElState => {
    const tag = tagNameOf(el);
    if (tag === "HTML" || tag === "BODY") return { ...ps, bg: backgroundOf(el, ps) };
    if (SHOWN_ON_USE.has(tag)) return ps;
    if (tag === "TITLE") return ps;
    // Folded: content a person reveals by interacting.
    const inClosedDetails = parent !== null && tagNameOf(parent) === "DETAILS" && !parent.hasAttribute("open") && !(tag === "SUMMARY" && parent.querySelector(":scope > summary") === el);
    if (inClosedDetails || el.getAttribute("hidden") === "until-found" || /(?:^|[\s_-])spoiler(?:$|[\s_-])/i.test(el.getAttribute("class") ?? "")) {
      return { ...ps, hidden: "folded", root: el, folded: true };
    }
    const style = win.getComputedStyle(el);
    // display: contents generates no box: checkVisibility() is false for it and opacity, clip and clip-path do not
    // apply, yet its children render as if they were its parent's (FP-4: MDN's main column). So it is transparent:
    // its own visibility still inherits to its children, and each child is judged on its own box.
    const contents = style.display === "contents";
    const opacity = contents ? ps.opacity : ps.opacity * num(style.opacity, 1);
    const bg = backgroundOf(el, ps, style);
    const r = el.getBoundingClientRect();
    const rendered = ownRendered(style.display, style.visibility, typeof el.checkVisibility === "function" ? () => el.checkVisibility({ opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true }) : null);
    let kind = hiddenKindOf({
      rendered,
      opacity,
      fontSizePx: num(style.fontSize, 16),
      color: style.color,
      background: bg,
      clip: contents ? "auto" : style.clip,
      clipPath: contents ? "none" : style.clipPath,
      position: style.position,
      overflowX: style.overflowX,
      overflowY: style.overflowY,
      textIndentPx: num(style.textIndent, 0),
      rect: { left: r.left + win.scrollX, top: r.top + win.scrollY, width: r.width, height: r.height },
      displayContents: style.display === "contents",
    });
    if (kind === null && el.getAttribute("aria-hidden") === "true") kind = "aria_hidden";
    // A closed tab panel, menu, dialog or anything a control says it opens (aria-controls) is shown on interaction:
    // folded, like a closed <details>, so its install commands and help text are not hidden instructions.
    if (kind !== null && kind !== "aria_hidden" && isDisclosure(el)) return { ...ps, hidden: "folded", root: el, folded: true, opacity, bg };
    return kind === null ? { hidden: null, root: null, folded: false, opacity, bg } : { hidden: kind, root: el, folded: false, opacity, bg };
  };

  /** Ids that some control says it opens (aria-controls), refreshed per scan pass. */
  let controlled = new Set<string>();
  const isDisclosure = (el: Element): boolean => {
    const role = el.getAttribute("role");
    if (role !== null && DISCLOSURE_ROLES.has(role)) return true;
    return el.id !== "" && controlled.has(el.id);
  };

  const backgroundOf = (el: Element, ps: ElState, style?: CSSStyleDeclaration): string | null => {
    const s = style ?? win.getComputedStyle(el);
    if (s.backgroundImage !== "none" && s.backgroundImage !== "") return null;
    const m = /rgba?\(([^)]*)\)/.exec(s.backgroundColor);
    if (m === null) return ps.bg;
    const parts = (m[1] ?? "").split(/[\s,/]+/).filter((p) => p !== "");
    const alpha = parts.length >= 4 ? Number(parts[3]) : 1;
    if (alpha >= 0.99) return s.backgroundColor;
    return alpha < 0.05 ? ps.bg : null;
  };

  const blockOf = (memo: Map<Element, string>, el: Element): Element => {
    let cur: Element | null = el;
    while (cur !== null) {
      const tag = tagNameOf(cur);
      if (tag === "BODY" || tag === "HTML" || tag === "TITLE") return cur;
      let d = memo.get(cur);
      if (d === undefined) {
        d = win.getComputedStyle(cur).display;
        memo.set(cur, d);
      }
      if (!d.startsWith("inline") && d !== "contents" && d !== "ruby") return cur;
      const p = parentOf(cur);
      if (p === null) return cur;
      cur = p;
    }
    return el;
  };

  // ---- collection ----

  const collect = (root: Node): Collected => {
    controlled = new Set(
      [...doc.querySelectorAll("[aria-controls]")]
        .slice(0, 5_000)
        .flatMap((c) => (c.getAttribute("aria-controls") ?? "").split(/\s+/))
        .filter((id) => id !== ""),
    );
    const out: Collected = { runs: [], refs: [], links: [], linkEls: [], statics: [], hosts: new Set(), incomplete: false };
    const memo = new Map<Element, ElState>();
    const displays = new Map<Element, string>();
    const groups = new Map<Element, number>();
    let chars = 0;
    const push = (run: GuardRun, ref: RunRef): boolean => {
      if (out.runs.length >= LIMITS.runs || chars + run.text.length > LIMITS.chars) {
        out.incomplete = true;
        return false;
      }
      chars += run.text.length;
      out.runs.push(run);
      out.refs.push(ref);
      return true;
    };

    const visitElement = (el: Element) => {
      const tag = tagNameOf(el);
      if (STATIC.has(tag)) {
        const html = tag === "TEMPLATE" ? (el as HTMLTemplateElement).innerHTML : tag === "NOSCRIPT" ? (el.textContent ?? "") : (el.getAttribute("srcdoc") ?? "");
        if (/\S/.test(html)) out.statics.push({ el, html });
      }
      const st = stateOf(memo, el);
      const hidden = st.hidden !== null;
      for (const name of HIDDEN_ATTRS) {
        const v = el.getAttribute(name);
        if (v !== null && /\p{L}/u.test(v)) push({ text: v, hidden: true, how: st.hidden ?? "not_rendered", attribute: name }, { kind: "attr", el, name });
      }
      const placeholder = el.getAttribute("placeholder");
      if (placeholder !== null && /\p{L}/u.test(placeholder)) push({ text: placeholder, hidden, ...(hidden ? { how: st.hidden ?? "not_rendered" } : {}), attribute: "placeholder" }, { kind: "attr", el, name: "placeholder" });
      if (tag === "INPUT") {
        const type = (el.getAttribute("type") ?? "text").toLowerCase();
        const v = el.getAttribute("value");
        // Never a password, and never what a person typed (only the page's own value attribute).
        if (type !== "password" && v !== null && /\p{L}/u.test(v)) {
          const h = hidden || type === "hidden";
          push({ text: v, hidden: h, ...(h ? { how: st.hidden ?? "not_rendered" } : {}), attribute: "value" }, { kind: "attr", el, name: "value" });
        }
      }
      if (tag === "META") {
        const key = (el.getAttribute("name") ?? el.getAttribute("property") ?? "").toLowerCase();
        const v = el.getAttribute("content");
        if (v !== null && READ_META.test(key) && /\p{L}/u.test(v)) push({ text: v, hidden: true, how: "not_rendered", attribute: "content" }, { kind: "attr", el, name: "content" });
      }
      if (tag === "A" || tag === "AREA" || tag === "IMG") {
        const raw = el.getAttribute(tag === "IMG" ? "src" : "href");
        if (raw !== null && raw.trim() !== "") {
          let pixel = false;
          if (tag === "IMG") {
            const w = Number(el.getAttribute("width") ?? "NaN");
            const h = Number(el.getAttribute("height") ?? "NaN");
            const r = el.getBoundingClientRect();
            pixel = (w <= 2 && h <= 2) || (!hidden && r.width <= 2 && r.height <= 2);
          }
          out.links.push({ url: raw.trim(), kind: tag === "IMG" ? "image" : "link", hidden, pixel });
          out.linkEls.push(el);
          try {
            const host = new URL(raw.trim(), win.location.href).hostname.replace(/^\[|\]$/g, "");
            if (host !== "" && (isRawIp(host) || isDnsExfilShape(host))) out.hosts.add(host);
          } catch {
            // Not a URL: nothing to add.
          }
        }
      }
    };

    const visitText = (t: Text) => {
      const parent = t.parentElement ?? (t.parentNode !== null && t.parentNode.nodeType === 11 ? ((t.parentNode as ShadowRoot).host ?? null) : null);
      if (parent === null || !/\S/.test(t.data)) return;
      const st = stateOf(memo, parent);
      const key = st.hidden !== null && st.root !== null ? st.root : blockOf(displays, parent);
      const at = groups.get(key);
      if (at !== undefined) {
        const run = out.runs[at] as GuardRun;
        run.text += t.data;
        chars += t.data.length;
        (out.refs[at] as { texts: Text[] }).texts.push(t);
        return;
      }
      const run: GuardRun = st.hidden !== null ? { text: t.data, hidden: !st.folded, how: st.hidden, ...(st.folded ? { folded: true } : {}) } : { text: t.data, hidden: false };
      if (push(run, { kind: "group", el: key, texts: [t] })) groups.set(key, out.runs.length - 1);
    };

    const walkFrom = (start: Node) => {
      const walker = doc.createTreeWalker(start, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT | NodeFilter.SHOW_COMMENT, {
        acceptNode(n) {
          if (n.nodeType === 1) {
            const el = n as Element;
            if (isOwnMarker(el)) return NodeFilter.FILTER_REJECT;
            if (SKIP.has(tagNameOf(el))) {
              // Read their attributes and unrendered markup, but not their children.
              visitElement(el);
              return NodeFilter.FILTER_REJECT;
            }
          }
          return NodeFilter.FILTER_ACCEPT;
        },
      });
      const visit = (n: Node) => {
        if (n.nodeType === 1) {
          visitElement(n as Element);
          const sr = (n as Element).shadowRoot;
          if (sr !== null) walkFrom(sr);
        } else if (n.nodeType === 3) visitText(n as Text);
        else if (n.nodeType === 8) {
          const c = n as Comment;
          if (/\p{L}/u.test(c.data)) push({ text: c.data, hidden: true, how: "comment" }, { kind: "comment", node: c });
        }
      };
      if (start.nodeType === 1 || start.nodeType === 3 || start.nodeType === 8) {
        if (start.nodeType === 1 && isOwnMarker(start as Element)) return;
        if (start.nodeType === 1 && SKIP.has(tagNameOf(start as Element))) {
          visitElement(start as Element);
          return;
        }
        visit(start);
        if (start.nodeType !== 1) return;
      }
      for (let n = walker.nextNode(); n !== null; n = walker.nextNode()) visit(n);
    };
    walkFrom(root);

    // A page that hides most of its text has not been shown yet (a fade-in, a loading veil): it is not hidden
    // text. Only a benign veil, though: hidden text that addresses an agent or is quarantine-class on its own
    // stays hidden however long it is, so padding an instruction past half the page cannot pass it off (RR5).
    const total = out.runs.reduce((n, r) => n + (r.attribute === undefined ? r.text.length : 0), 0);
    if (total > 400) {
      out.runs.forEach((r, i) => {
        const ref = out.refs[i];
        if (r.hidden && r.attribute === undefined && ref !== undefined && ref.kind === "group" && r.text.length > total / 2 && isBenignVeil(r)) out.runs[i] = { text: r.text, hidden: false };
      });
    }
    return out;
  };

  // ---- judgement and neutralising ----

  const report = (force: boolean) => {
    if (!force && reported) return;
    reported = true;
    deps
      .send({ type: "page.scanned", url: win.location.href, verdict: docVerdict, reasons: [...docReasons].slice(0, 32), scanIncomplete: docIncomplete, ...(docVerdict === "quarantine" && docPreview !== "" ? { preview: docPreview.slice(0, 400) } : {}) })
      .catch(() => undefined);
  };

  const judge = (c: Collected, partial: boolean) => {
    const rj = judgeRuns(c.runs, partial ? { visibleContext } : {});
    const lj = judgeLinks(c.links, { pageHost: win.location.hostname });
    let verdict = worse(rj.verdict, lj.verdict);
    const reasons = new Set<QuarantineReason>([...rj.reasons, ...lj.reasons]);
    const fixes: Fix[] = [];
    const removed = new Set<Node>();
    const removeNode = (node: Node, marker: boolean) => {
      if (removed.has(node) || queued.has(node)) return;
      removed.add(node);
      queued.add(node);
      fixes.push({ op: "remove", node, marker });
    };
    for (const i of rj.offending) {
      const ref = c.refs[i];
      if (ref === undefined) continue;
      if (ref.kind === "group") {
        const rtag = tagNameOf(ref.el);
        if (rtag === "BODY" || rtag === "HTML") ref.texts.forEach((t) => removeNode(t, false));
        else removeNode(ref.el, true);
      } else if (ref.kind === "comment") removeNode(ref.node, false);
      else fixes.push(tagNameOf(ref.el) === "META" ? { op: "remove", node: ref.el, marker: false } : { op: "removeAttr", el: ref.el, name: ref.name });
    }
    for (const i of rj.stripChars) {
      const ref = c.refs[i];
      const run = c.runs[i];
      if (ref === undefined || run === undefined || !worthStripping(run.text)) continue;
      if (ref.kind === "group") ref.texts.forEach((t) => fixes.push({ op: "stripText", node: t }));
      else if (ref.kind === "attr") fixes.push({ op: "stripAttr", el: ref.el, name: ref.name });
    }
    for (const i of lj.offending) {
      const el = c.linkEls[i];
      if (el !== undefined) removeNode(el, tagNameOf(el) !== "IMG");
    }
    for (const s of c.statics) {
      const sj = judgeStatic(s.html);
      if (sj.verdict !== "quarantine") continue;
      verdict = "quarantine";
      sj.reasons.forEach((r) => reasons.add(r));
      removeNode(s.el, tagNameOf(s.el) === "IFRAME");
    }
    // Keep the visible text for judging later subtrees (a hidden copy of visible text is not an instruction).
    if (visibleContext.length < LIMITS.visibleContext) {
      visibleContext += " " + c.runs.filter((r) => !r.hidden && r.folded !== true).map((r) => r.text).join(" ");
      visibleContext = visibleContext.slice(0, LIMITS.visibleContext);
    }
    if (docPreview === "" && verdict === "quarantine") {
      const first = rj.offending.map((i) => c.runs[i]).find((r) => r !== undefined && r.hidden);
      docPreview = (first?.text ?? rj.preview).replace(/\s+/g, " ").trim().slice(0, 400);
    }
    const before = docVerdict;
    const beforeReasons = docReasons.size;
    const beforeIncomplete = docIncomplete;
    docVerdict = worse(docVerdict, verdict);
    reasons.forEach((r) => docReasons.add(r));
    if (rj.scanIncomplete || c.incomplete) {
      docIncomplete = true;
      budgetOverflow = true;
    }
    escalateIfUnjudged();
    pendingFixes.push(...fixes);
    if (!reported || docVerdict !== before || docReasons.size !== beforeReasons || docIncomplete !== beforeIncomplete) report(true);
    // At most LIMITS.hostsPerPage link hosts per page go to the navigation rules (m8; the worker budgets each frame too).
    const hosts = [...c.hosts].filter((h) => !sentHosts.has(h)).slice(0, Math.max(0, LIMITS.hostsPerPage - sentHosts.size));
    if (hosts.length > 0) {
      hosts.forEach((h) => sentHosts.add(h));
      deps.send({ type: "nav.hosts", hosts: hosts.slice(0, 200) }).catch(() => undefined);
    }
    if (deps.agentMode()) neutralise();
  };

  /**
   * In agent mode, a page we could not judge in full (over the scan budget, or a scan that threw) is treated as
   * quarantined, not just "incomplete": the unscanned part may hold the instruction, and nothing can be removed
   * from it, so every sensitive action on the tab is gated (I6). Outside agent mode it stays incomplete, which
   * marks the tab untrusted; turning agent mode on later escalates it then.
   */
  const escalateIfUnjudged = (): boolean => {
    if (!budgetOverflow || !deps.agentMode() || docVerdict === "quarantine") return false;
    docVerdict = "quarantine";
    docReasons.add("scan_incomplete");
    return true;
  };

  const neutralise = () => {
    if (pendingFixes.length === 0) return;
    const fixes = pendingFixes.splice(0, pendingFixes.length);
    muted = true;
    try {
      for (const f of fixes) {
        switch (f.op) {
          case "remove": {
            const node = f.node;
            const parent = node.parentNode;
            if (parent === null) break;
            if (f.marker) {
              const m = doc.createElement("span");
              m.setAttribute(MARKER_ATTR, "");
              ownMarkers.add(m);
              m.setAttribute("role", "note");
              m.textContent = MARKER_TEXT;
              m.style.cssText = "all: initial; display: inline-block; font: 12px/1.4 system-ui, sans-serif; color: #5b6070; border: 1px dashed #9aa0ae; padding: 0 4px; margin: 2px 0;";
              parent.insertBefore(m, node);
            }
            parent.removeChild(node);
            break;
          }
          case "removeAttr":
            f.el.removeAttribute(f.name);
            break;
          case "stripText":
            if (f.node.isConnected) f.node.data = stripInvisible(f.node.data);
            break;
          case "stripAttr": {
            const v = f.el.getAttribute(f.name);
            if (v !== null) f.el.setAttribute(f.name, stripInvisible(v));
            break;
          }
        }
      }
    } finally {
      // Our own edits are not page changes: drop them before the observer reports them.
      observer?.takeRecords();
      muted = false;
    }
  };

  // ---- scanning ----

  const fullScan = () => {
    if (doc.documentElement === null) return;
    try {
      judge(collect(doc.documentElement), false);
    } catch {
      docIncomplete = true;
      budgetOverflow = true;
      escalateIfUnjudged();
      report(true);
    }
    startObserver();
  };

  const flush = () => {
    timer = null;
    styleRescans = 0;
    const roots = [...pendingRoots].filter((n) => n.isConnected);
    pendingRoots.clear();
    // Drop roots inside other roots.
    const top = roots.filter((n) => !roots.some((o) => o !== n && o.contains(n)));
    if (top.length === 0) return;
    const now = win.performance.now();
    rescanTimes.push(now);
    while (rescanTimes.length > 0 && now - (rescanTimes[0] as number) > 1000) rescanTimes.shift();
    for (const r of top) {
      try {
        judge(collect(r), true);
      } catch {
        docIncomplete = true;
        budgetOverflow = true;
        escalateIfUnjudged();
        report(true);
      }
    }
  };

  const schedule = () => {
    if (timer !== null) return;
    // A page that rewrites itself faster than we can follow is rescanned less often and reported as incomplete.
    const churning = rescanTimes.length >= LIMITS.rescansPerSecond;
    if (churning && !docIncomplete) {
      docIncomplete = true;
      report(true);
    }
    timer = setTimeout(flush, churning ? LIMITS.slowDebounceMs : LIMITS.debounceMs);
  };

  const enqueue = (n: Node) => {
    if (n.nodeType === 3) {
      const p = (n as Text).parentElement ?? n.parentNode;
      if (p !== null) pendingRoots.add(p);
    } else if (n.nodeType === 1) {
      if (isOwnMarker(n as Element)) return;
      pendingRoots.add(n);
    } else if (n.nodeType === 8 || n.nodeType === 11) pendingRoots.add(n);
    else return;
    schedule();
  };

  const startObserver = () => {
    if (observer !== null || doc.documentElement === null) return;
    observer = new MutationObserver((records) => {
      if (muted) return;
      for (const r of records) {
        if (r.type === "childList") r.addedNodes.forEach(enqueue);
        else if (r.type === "characterData") enqueue(r.target);
        else if (r.type === "attributes") {
          if (r.attributeName !== null && STYLE_ATTRS.has(r.attributeName)) {
            // A class or style change rescans that element's subtree, within a budget per flush.
            if (styleRescans >= LIMITS.styleRescans) {
              // Marks the scan incomplete (the tab becomes untrusted: its sensitive actions need approval), but
              // does not quarantine: a page that merely toggles many classes or styles (an animation, a framework)
              // would otherwise deny every sensitive action in every tab for the rest of the session.
              const beforeIncomplete = docIncomplete;
              docIncomplete = true;
              if (docIncomplete !== beforeIncomplete) report(true);
              continue;
            }
            styleRescans++;
          }
          enqueue(r.target);
        }
      }
    });
    const observeOpts: MutationObserverInit = { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: OBSERVED_ATTRS };
    observer.observe(doc.documentElement, observeOpts);
    let init = true;
    unsubscribeRoots = shadowRootWatcher(win).subscribe((root) => {
      observer?.observe(root, observeOpts);
      if (!init) enqueue(root);
    });
    init = false;
  };

  return {
    install() {
      if (installed) return;
      installed = true;
      const top = win.top === win;
      // Fire-and-forget: the worker records the frame's origin for tab trust. A failure is not retried here.
      deps.send({ type: "frame.hello", url: win.location.href, top }).catch(() => undefined);
      if (doc.readyState === "loading") doc.addEventListener("DOMContentLoaded", fullScan, { once: true });
      else fullScan();
    },
    uninstall() {
      unsubscribeRoots?.();
      unsubscribeRoots = null;
      observer?.disconnect();
      observer = null;
      if (timer !== null) clearTimeout(timer);
      timer = null;
      doc.removeEventListener("DOMContentLoaded", fullScan);
      installed = false;
    },
    rescan(root) {
      enqueue(root);
    },
    setAgentMode(on) {
      if (!on) return;
      if (escalateIfUnjudged()) report(true);
      neutralise();
    },
  };
}
