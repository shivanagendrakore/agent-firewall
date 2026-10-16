/**
 * Friction on real pages: the guard over the real-page corpus (outside the repo, see REAL_CORPUS_DIR in corpus-server.ts), static snapshots of
 * public pages (docs, news, Wikipedia, shops, SaaS pricing, GitHub, Stack Overflow, government, recipes, and
 * Arabic, Hebrew, Chinese, Japanese and Hindi pages) captured by scripts/capture-corpus.mjs.
 *
 * Offline: the snapshots are served from 127.0.0.1 and run no script; every other request fails and is asserted
 * to be zero. Measured per page, with agent mode off at load and then turned on:
 *   - the verdict (quarantine, flag, neutralize/hidden, clean);
 *   - agent mode changing the visible text (innerText) or adding a removal marker;
 *   - agent mode changing the rendered viewport (share of pixels that differ by more than a few levels; a page that
 *     already changes on its own between two screenshots before agent mode, such as a carousel, is listed as
 *     animated and left out of the pixel gate).
 * Gate: quarantine on 0 pages, flags on under 2% of pages, 0 pages with changed text, markers or pixels.
 * The totals are printed and written to test-results/friction-real.json. A page that trips the gate is a
 * finding: reproduce it minimally under test/corpus/fp-cases/ (it.fails) and write it up; do not paper over it.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import type { Page } from "@playwright/test";
import { agentModeOn, knownFindings, realCorpus, tabIdFor, tabState, type RealPage } from "./guard-helpers.js";
import { expect, test } from "./fixtures.js";

const PAGES = realCorpus();
const NO_CORPUS = "the real-page corpus is not present: run `npm run capture:corpus`, or set LAUNCHSAFE_BROWSER_CORPUS_DIR to an existing copy";
if (PAGES.length === 0) test("real corpus", () => test.skip(true, NO_CORPUS));
const BATCH = 10;
/** Share of viewport pixels that may differ (per-channel difference above 8) before a screenshot counts as changed. */
const PIXEL_THRESHOLD = 0.0005;
const HOST = "shop.test" as const;
/**
 * Pages left out of the raw gate, by name: articles about prompt injection that genuinely contain working
 * injection text (quoted visibly, or transcribed in a screenshot's alt text, which the guard reads as hidden).
 * Flagging or quarantining them is the product doing its job, not friction. They stay listed as by-design in
 * known-findings.json, so the "explained" gate still checks their verdicts. Add nothing here for a false positive.
 */
const BY_DESIGN_EXCLUDED = new Set([
  "blog-simonwillison-net-2022-Sep-12-prompt-injection-11jediv",
  "security-writing-genai-owasp-org-llmrisk-llm01-prompt-injection-15gig9z",
  "wikipedia-en-wikipedia-org-wiki-Prompt-injection-u89akj",
]);

interface Row {
  id: string;
  category: string;
  lang: string;
  verdict: "quarantine" | "flag" | "clean";
  reasons: string[];
  markers: number;
  textChanged: boolean;
  pixelDiff: number;
  /** The page changed by itself (a carousel, an animation) between two screenshots before agent mode: its pixel diff is not the guard's. */
  animated: boolean;
}
/**
 * Each batch writes its rows to a file and the gate reads them back: a failing test restarts Playwright's worker,
 * so module state does not survive. (Not under test-results/, which Playwright empties at the start of a run.)
 */
const RESULTS_DIR = "friction-real-results";
const batchFile = (n: number) => `${RESULTS_DIR}/batch-${n}.json`;

/** Fraction of pixels whose channels differ by more than 8, computed in the page (a canvas), offline. */
async function pixelDiff(page: Page, a: Buffer, b: Buffer): Promise<number> {
  if (a.equals(b)) return 0;
  return page.evaluate(
    async ([x, y]) => {
      const load = (b64: string) =>
        new Promise<HTMLImageElement>((ok, no) => {
          const i = new Image();
          i.onload = () => ok(i);
          i.onerror = () => no(new Error("decode"));
          i.src = `data:image/png;base64,${b64}`;
        });
      const [ia, ib] = await Promise.all([load(x as string), load(y as string)]);
      const w = ia.naturalWidth;
      const h = ia.naturalHeight;
      if (ib.naturalWidth !== w || ib.naturalHeight !== h) return 1;
      const px = (img: HTMLImageElement) => {
        const c = document.createElement("canvas");
        c.width = w;
        c.height = h;
        const g = c.getContext("2d") as CanvasRenderingContext2D;
        g.drawImage(img, 0, 0);
        return g.getImageData(0, 0, w, h).data;
      };
      const da = px(ia);
      const db = px(ib);
      let n = 0;
      for (let i = 0; i < da.length; i += 4) if (Math.abs((da[i] as number) - (db[i] as number)) > 8 || Math.abs((da[i + 1] as number) - (db[i + 1] as number)) > 8 || Math.abs((da[i + 2] as number) - (db[i + 2] as number)) > 8) n++;
      return n / (w * h);
    },
    [a.toString("base64"), b.toString("base64")],
  );
}

for (let start = 0; start < PAGES.length; start += BATCH) {
  const batch = PAGES.slice(start, start + BATCH);
  test(`real corpus batch ${start / BATCH + 1} of ${Math.ceil(PAGES.length / BATCH)}: verdicts, then agent mode on`, async ({ context, extensionId, serviceWorker, corpus, blockedRequests }) => {
    test.setTimeout(240_000);
    const opened: { p: RealPage; page: Page; row: Row; shot: Buffer; text: string }[] = [];
    const rows: Row[] = [];
    for (const p of batch) {
      const page = await context.newPage();
      await page.setViewportSize({ width: 1100, height: 900 });
      await page.goto(corpus.url(HOST, `/real/${p.file}`), { waitUntil: "load" });
      const tabId = await tabIdFor(serviceWorker, corpus.url(HOST, `/real/${p.file}`));
      expect(tabId, p.id).not.toBeNull();
      await page.waitForTimeout(500);
      const t = await tabState(serviceWorker, tabId as number);
      const verdict = t?.quarantined === true ? "quarantine" : t?.reasons.includes("flag_verdict") === true ? "flag" : "clean";
      const row: Row = { id: p.id, category: p.category, lang: p.lang, verdict, reasons: t?.reasons ?? [], markers: 0, textChanged: false, pixelDiff: 0, animated: false };
      const shot = await page.screenshot();
      await page.waitForTimeout(250);
      row.animated = (await pixelDiff(page, shot, await page.screenshot())) > PIXEL_THRESHOLD;
      opened.push({ p, page, row, shot, text: await page.evaluate(() => document.body.innerText) });
    }
    await agentModeOn(context, extensionId);
    for (const o of opened) {
      await o.page.bringToFront();
      await o.page.waitForTimeout(250);
      o.row.markers = await o.page.locator("[data-launchsafe-removed]").count();
      o.row.textChanged = (await o.page.evaluate(() => document.body.innerText)) !== o.text;
      o.row.pixelDiff = await pixelDiff(o.page, o.shot, await o.page.screenshot());
      rows.push(o.row);
    }
    for (const o of opened) await o.page.close();
    mkdirSync(RESULTS_DIR, { recursive: true });
    writeFileSync(batchFile(start / BATCH), JSON.stringify({ ids: batch.map((p) => p.id), rows, blocked: blockedRequests }));
    expect(blockedRequests, "a real-corpus page reached for the network").toEqual([]);
  });
}

interface FreshRow {
  id: string;
  verdict: "quarantine" | "flag" | "clean";
  /** The tab was marked private (the leak guard found an e-mail address, a secret or a one-time-code-looking number). */
  private: boolean;
  reasons: string[];
  markers: number;
}
const freshFile = (n: number) => `${RESULTS_DIR}/fresh-${n}.json`;

for (let start = 0; start < PAGES.length; start += BATCH) {
  const batch = PAGES.slice(start, start + BATCH);
  test(`real corpus loaded fresh in agent mode, batch ${start / BATCH + 1} of ${Math.ceil(PAGES.length / BATCH)}`, async ({ context, extensionId, serviceWorker, corpus, blockedRequests }) => {
    test.setTimeout(240_000);
    await agentModeOn(context, extensionId);
    const rows: FreshRow[] = [];
    for (const p of batch) {
      const page = await context.newPage();
      await page.goto(corpus.url(HOST, `/real/${p.file}`), { waitUntil: "load" });
      const tabId = await tabIdFor(serviceWorker, corpus.url(HOST, `/real/${p.file}`));
      await page.waitForTimeout(500);
      const t = await tabState(serviceWorker, tabId as number);
      rows.push({ id: p.id, verdict: t?.quarantined === true ? "quarantine" : t?.reasons.includes("flag_verdict") === true ? "flag" : "clean", private: t?.private === true, reasons: t?.reasons ?? [], markers: await page.locator("[data-launchsafe-removed]").count() });
      await page.close();
    }
    mkdirSync(RESULTS_DIR, { recursive: true });
    writeFileSync(freshFile(start / BATCH), JSON.stringify({ rows, blocked: blockedRequests }));
    expect(blockedRequests, "a real-corpus page reached for the network").toEqual([]);
  });
}

function loadFresh(): FreshRow[] | null {
  const rows: FreshRow[] = [];
  for (let start = 0; start < PAGES.length; start += BATCH) {
    try {
      rows.push(...(JSON.parse(readFileSync(freshFile(start / BATCH), "utf8")) as { rows: FreshRow[] }).rows);
    } catch {
      return null;
    }
  }
  return rows.length === PAGES.length ? rows : null;
}

/** Reads every batch's rows back; null when the corpus is empty or a batch did not run (a filtered run). */
function loadRows(): { rows: Row[]; blocked: string[] } | null {
  const rows: Row[] = [];
  let blocked: string[] = [];
  for (let start = 0; start < PAGES.length; start += BATCH) {
    try {
      const b = JSON.parse(readFileSync(batchFile(start / BATCH), "utf8")) as { rows: Row[]; blocked: string[] };
      rows.push(...b.rows);
      blocked = blocked.concat(b.blocked);
    } catch {
      /* a batch that did not run leaves the corpus incomplete */
    }
  }
  if (PAGES.length === 0 || rows.length !== PAGES.length || PAGES.some((p) => !rows.some((r) => r.id === p.id))) return null;
  return { rows, blocked };
}

function summarise(rows: Row[], blocked: string[]) {
  const n = rows.length;
  const quarantined = rows.filter((r) => r.verdict === "quarantine");
  const flagged = rows.filter((r) => r.verdict === "flag");
  const textChanged = rows.filter((r) => r.textChanged);
  const markers = rows.filter((r) => r.markers > 0);
  const animated = rows.filter((r) => r.animated);
  const pixels = rows.filter((r) => !r.animated && r.pixelDiff > PIXEL_THRESHOLD);
  const reasonCounts: Record<string, number> = {};
  for (const r of rows) for (const x of r.reasons) reasonCounts[x] = (reasonCounts[x] ?? 0) + 1;
  const byCategory: Record<string, { pages: number; flagged: number; quarantined: number }> = {};
  for (const r of rows) {
    const c = (byCategory[r.category] ??= { pages: 0, flagged: 0, quarantined: 0 });
    c.pages++;
    if (r.verdict === "flag") c.flagged++;
    if (r.verdict === "quarantine") c.quarantined++;
  }
  return { n, quarantined, flagged, textChanged, markers, animated, pixels, reasonCounts, byCategory, blocked };
}

test("real corpus gate: 0 quarantines, flags under 2%, agent mode changes nothing a person sees", async () => {
  // Was test.fail() until FP-1 to FP-5 were fixed (docs/real-corpus-findings.md). The three prompt-injection
  // articles in BY_DESIGN_EXCLUDED are left out of this gate (and only they); the report still lists their verdicts.
  const loaded = loadRows();
  test.skip(loaded === null, PAGES.length === 0 ? NO_CORPUS : "the whole real corpus has to run (every batch, unfiltered)");
  const { rows: allRows, blocked } = loaded as NonNullable<typeof loaded>;
  const excluded = allRows.filter((r) => BY_DESIGN_EXCLUDED.has(r.id));
  expect(excluded.length, "every by-design exclusion names a page in the corpus").toBe(BY_DESIGN_EXCLUDED.size);
  const rows = allRows.filter((r) => !BY_DESIGN_EXCLUDED.has(r.id));
  const t = summarise(rows, blocked);
  const report = {
    pages: t.n,
    quarantined: t.quarantined.length,
    flagged: t.flagged.length,
    flagRate: t.flagged.length / t.n,
    textChanged: t.textChanged.map((r) => r.id),
    markers: t.markers.map((r) => r.id),
    pixelOverThreshold: t.pixels.map((r) => ({ id: r.id, diff: r.pixelDiff })),
    maxPixelDiff: Math.max(0, ...rows.filter((r) => !r.animated).map((r) => r.pixelDiff)),
    pixelThreshold: PIXEL_THRESHOLD,
    animatedPages: t.animated.map((r) => r.id),
    reasonCounts: t.reasonCounts,
    quarantineIds: t.quarantined.map((r) => ({ id: r.id, reasons: r.reasons })),
    flagIds: t.flagged.map((r) => ({ id: r.id, reasons: r.reasons })),
    byCategory: t.byCategory,
    blockedRequests: t.blocked,
    byDesignExcluded: excluded.map((r) => ({ id: r.id, verdict: r.verdict, markers: r.markers, textChanged: r.textChanged, pixelDiff: r.pixelDiff })),
  };
  const fresh = loadFresh();
  (report as Record<string, unknown>).freshInAgentMode = fresh === null ? null : { quarantined: fresh.filter((r) => r.verdict === "quarantine").length, flagged: fresh.filter((r) => r.verdict === "flag").length, markers: fresh.filter((r) => r.markers > 0).length, privateTabs: fresh.filter((r) => r.private).length, privateRate: fresh.filter((r) => r.private).length / fresh.length };
  (report as Record<string, unknown>).privateTabsAgentModeOff = allRows.filter((r) => r.reasons.includes("private_data")).length;
  mkdirSync("test-results", { recursive: true });
  writeFileSync("test-results/friction-real.json", JSON.stringify(report, null, 2) + "\n");
  console.info(`real friction (by-design excluded: ${excluded.map((r) => `${r.id}=${r.verdict}`).join(", ")})`);
  console.info(`real friction: pages=${t.n} quarantined=${t.quarantined.length} flagged=${t.flagged.length} (${((100 * t.flagged.length) / t.n).toFixed(2)}%) textChanged=${t.textChanged.length} markers=${t.markers.length} pixelOver=${t.pixels.length} animated=${t.animated.length} maxPixelDiff=${report.maxPixelDiff.toFixed(5)}`);
  console.info(`real friction, fresh in agent mode and private tabs: ${JSON.stringify({ fresh: (report as Record<string, unknown>).freshInAgentMode, privateTabsAgentModeOff: (report as Record<string, unknown>).privateTabsAgentModeOff })}`);
  console.info(`real friction by category: ${JSON.stringify(t.byCategory)}`);
  expect(t.quarantined.map((r) => r.id), "quarantine verdicts on real pages").toEqual([]);
  expect(t.flagged.length / t.n, `flags: ${t.flagged.map((r) => r.id).join(", ")}`).toBeLessThan(0.02);
  expect(t.textChanged.map((r) => r.id), "agent mode changed visible text").toEqual([]);
  expect(t.markers.map((r) => r.id), "agent mode left a removal marker").toEqual([]);
  expect(t.pixels.map((r) => r.id), "agent mode changed the rendered page").toEqual([]);
  expect(t.blocked).toEqual([]);
});

test("real corpus gate, explained: every quarantine, flag, marker and visible change is a documented finding, and no finding has gone stale", async () => {
  const loaded = loadRows();
  test.skip(loaded === null, PAGES.length === 0 ? NO_CORPUS : "the whole real corpus has to run (every batch, unfiltered)");
  const { rows, blocked } = loaded as NonNullable<typeof loaded>;
  const known = knownFindings();
  const unexplained = rows.filter((r) => (r.verdict !== "clean" || r.markers > 0 || r.textChanged || (!r.animated && r.pixelDiff > PIXEL_THRESHOLD)) && known[r.id] === undefined);
  expect(unexplained.map((r) => `${r.id}: ${r.verdict} ${r.reasons.join(",")} markers=${r.markers} text=${r.textChanged} px=${r.pixelDiff.toFixed(4)}`), "new, undocumented friction: reproduce it under test/corpus/fp-cases/ and add it to known-findings.json").toEqual([]);
  const stale = Object.keys(known).filter((id) => rows.find((r) => r.id === id)?.verdict === "clean");
  expect(stale, "known findings that no longer trip the guard: delete them from known-findings.json").toEqual([]);
  const wrongVerdict = Object.entries(known).flatMap(([id, k]) => {
    const r = rows.find((x) => x.id === id);
    return r !== undefined && r.verdict !== k.verdict ? [`${id}: recorded ${k.verdict}, now ${r.verdict}`] : [];
  });
  expect(wrongVerdict, "a known finding changed its verdict").toEqual([]);
  expect(blocked, "a real-corpus page reached for the network").toEqual([]);
  // Loaded with agent mode already on, the guard's verdicts are the same pages and nothing else.
  const fresh = loadFresh();
  if (fresh !== null) {
    const freshUnexplained = fresh.filter((r) => (r.verdict !== "clean" || r.markers > 0) && known[r.id] === undefined);
    expect(freshUnexplained.map((r) => `${r.id}: ${r.verdict} markers=${r.markers}`), "agent mode on at load: undocumented friction").toEqual([]);
  }
});
