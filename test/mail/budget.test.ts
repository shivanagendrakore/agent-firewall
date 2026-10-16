/**
 * The per-message work budget (review r4, item 2): every part, channel and the rewriting pass of one
 * message draw on one deterministic budget, so a message of many parts costs no more than its budget, and
 * past it the message is withheld the same way every time.
 */
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeHtml, MATCH_STEPS } from "../../src/engine/content-html.js";
import { SCAN_LIMITS, scanContent, workBudget } from "../../src/engine/content-scan.js";
import { scanMail } from "../../src/engine/mail/detect.js";
import { filterMailResult, NOT_FULLY_SCANNED } from "../../src/engine/mail/filter.js";
import { asParsed, type MailMessage } from "../../src/engine/mail/mime.js";
import { buildMailCorpus } from "../../src/mail-corpus.js";
import { REPO } from "../helpers.js";

/** An HTML part whose cascade uses a large share of its own step bound, but stays inside it. */
const heavyPart = (i: number): string => {
  const css = Array.from({ length: 2000 }, (_, k) => `div.a${k} span{color:red}`).join("");
  return `<html><head><style>${css}</style></head><body>${"<div>".repeat(10)}<p>part ${i}</p>${"<span>x</span>".repeat(60)}${"</div>".repeat(10)}</body></html>`;
};

// A parsed message (as the parser would build it), taken by the detector as it is.
const message = (html: string[]): MailMessage =>
  asParsed({
    headers: [
      { name: "From", value: "News <news@example.com>" },
      { name: "Subject", value: "Weekly" },
    ],
    text: [],
    html,
    calendar: [],
    attachments: [],
    nested: [],
    problems: [],
  });

describe("the per-message work budget", () => {
  it("a message of many parts, each inside its own bounds, is withheld once their total passes the message's budget, deterministically", () => {
    const steps = analyzeHtml(heavyPart(0), { maxNodes: SCAN_LIMITS.maxNodes, maxCssRules: SCAN_LIMITS.maxCssRules, expired: () => false }).work.matchSteps;
    // Each part alone is complete: before the budget, every part got a fresh 4,000,000 steps and a fresh clock.
    expect(steps).toBeGreaterThan(MATCH_STEPS / 2);
    expect(steps).toBeLessThan(MATCH_STEPS);
    expect(scanContent(heavyPart(0), { html: true }).signals.filter((s) => s.id === "scan_incomplete")).toEqual([]);
    const parts = Math.ceil(SCAN_LIMITS.maxWork / steps) + 2;
    const msg = message(Array.from({ length: parts }, (_, i) => heavyPart(i)));
    const a = scanMail(msg);
    expect(a.verdict).toBe("quarantine");
    expect(a.reasons).toContain("scan_incomplete");
    expect(a.signals).toContainEqual({ id: "scan_incomplete", reason: "work" });
    // The same message, the same verdict and the same signals, whatever the clock did.
    expect(JSON.stringify(scanMail(msg))).toBe(JSON.stringify(a));
    // Fewer parts, inside the budget: delivered.
    const few = scanMail(message(Array.from({ length: 3 }, (_, i) => heavyPart(i))));
    expect(few.verdict).toBe("deliver");
  });

  it("once the budget is spent, every later part is reported incomplete without being read", () => {
    const budget = workBudget(1000);
    const big = scanContent("x".repeat(2000), { budget });
    expect(big.signals).toContainEqual({ id: "scan_incomplete", reason: "work" });
    expect(budget.spent).toBe(true);
    // A tiny part after it is not read either: the budget does not come back.
    expect(scanContent("hi", { budget }).signals).toContainEqual({ id: "scan_incomplete", reason: "work" });
  });

  it("the rewriting pass has its own budget, so text the scan read is not charged twice: a message whose scan and rewrite each fit is delivered (r5, item 2)", () => {
    // Zero-width padding with nothing directed: neutralize (strip and deliver), which runs the rewriting pass.
    const body = `${"Plain text of an ordinary letter. ".repeat(3000)}${"\u200b".repeat(10)}`;
    const value = { id: "m1", from: "A <a@example.com>", subject: "Letter", text: body };
    expect(scanMail(value).verdict).toBe("neutralize");
    // Room for one pass over the text, not for two.
    const maxWork = Math.floor(body.length * 1.5);
    const scanned = workBudget(maxWork);
    expect(scanMail(value, { budget: scanned }).verdict).toBe("neutralize");
    expect(scanned.spent).toBe(false);
    const r = filterMailResult([value], { mode: "enforce", maxWork, record: () => "rec1" });
    expect(r.withheld).toEqual([]);
    expect(r.neutralized).toBe(1);
    expect(r.outputText).toContain("Plain text of an ordinary letter");
    expect(r.outputText).not.toContain("\u200b");
  });

  it("a result that is not mail is scanned and rewritten on separate budgets too (r5, item 2)", () => {
    const text = `${"Plain text of an ordinary page. ".repeat(3000)}${"\u200b".repeat(10)}`;
    const r = filterMailResult({ note: text }, { mode: "enforce", maxWork: Math.floor(text.length * 1.5), record: () => "rec1" });
    expect(r.split).toBe(false);
    expect(r.withheld).toEqual([]);
    expect(r.neutralized).toBe(1);
    expect(r.outputText).toContain("Plain text of an ordinary page");
  });

  it("past the splitter's message bound, the rest is rewritten and scanned on separate budgets (r5, item 2)", () => {
    const text = `${"Plain text of an ordinary letter. ".repeat(3000)}${"\u200b".repeat(10)}`;
    const list: Record<string, unknown>[] = Array.from({ length: 500 }, (_, i) => ({ id: `m${i}`, from: `P <p${i}@example.com>`, subject: `S ${i}`, body: `Message ${i}.` }));
    list.push({ id: "last", from: "A <a@example.com>", subject: "Letter", text });
    const r = filterMailResult(list, { mode: "enforce", maxWork: Math.floor(text.length * 1.5), record: () => "rec1" });
    expect(r.withheld).toEqual([]);
    expect(r.outputText).toContain("Plain text of an ordinary letter");
    expect(r.outputText).not.toContain("\u200b");
  });

  it("text outside the messages withheld for the work limit says so, not that it carries hidden text for an AI agent (r5, item 2)", () => {
    const msg = { id: "m1", from: "A <a@example.com>", subject: "Hi", body: "Short and ordinary." };
    const note = "An ordinary folder description. ".repeat(2000);
    const r = filterMailResult({ messages: [msg], description: note }, { mode: "enforce", maxWork: Math.floor(note.length / 2), record: () => "rec1" });
    expect(r.withheld).toHaveLength(1);
    expect(r.withheld[0]?.scan.signals).toContainEqual({ id: "scan_incomplete", reason: "work" });
    expect(r.outputText).toContain("work limit");
    expect(r.outputText).not.toContain("hidden text addressed to an AI agent");
    expect(r.outputText).not.toContain("An ordinary folder description");
  });

  it("a work-withheld message the person released is delivered: the rewrite gets a fresh budget, and what it cannot pay for is replaced by a note (r5, item 1)", () => {
    const body = "Plain text of an ordinary letter. ".repeat(3000);
    const value = { id: "m1", from: "A <a@example.com>", subject: "Letter", text: body };
    const maxWork = Math.floor(body.length / 2);
    const first = filterMailResult([value], { mode: "enforce", maxWork, record: () => "rec1" });
    expect(first.withheld).toHaveLength(1);
    expect(first.withheld[0]?.scan.signals).toContainEqual({ id: "scan_incomplete", reason: "work" });
    const sha = first.withheld[0]?.scan.sha256 as string;
    const again = filterMailResult([value], { mode: "enforce", maxWork, released: (s) => s === sha, record: () => "rec2" });
    expect(again.withheld).toEqual([]);
    expect(again.messages[0]).toMatchObject({ verdict: "neutralize", released: true });
    const out = again.output as Record<string, unknown>[];
    expect(out[0]).toMatchObject({ id: "m1", from: "A <a@example.com>", subject: "Letter", text: NOT_FULLY_SCANNED });
    expect(again.outputText).not.toContain("Plain text of an ordinary letter");
  });

  it("a released message whose content fits the fresh rewrite budget is delivered whole (r5, item 1)", () => {
    // The scan pays for the visible text once per unshown header; the rewrite reads the strings once.
    const value = { id: "m1", from: "A <a@example.com>", subject: "Letter", headers: { "X-Note": "relay one" }, text: "Plain text. ".repeat(2000) };
    const used = workBudget();
    scanMail(value, { budget: used });
    const need = SCAN_LIMITS.maxWork - used.left;
    const maxWork = need - 1;
    const first = filterMailResult([value], { mode: "enforce", maxWork, record: () => "rec1" });
    expect(first.withheld).toHaveLength(1);
    const sha = first.withheld[0]?.scan.sha256 as string;
    const again = filterMailResult([value], { mode: "enforce", maxWork, released: (s) => s === sha, record: () => "rec2" });
    expect(again.withheld).toEqual([]);
    expect(again.outputText).toContain("Plain text.");
    expect(again.outputText).not.toContain(NOT_FULLY_SCANNED);
  });

  it("a long forwarded chain pays for its displayed text once, not once per unshown header (r5, item 3)", () => {
    const level = (i: number, nested: MailMessage[]): MailMessage =>
      asParsed({
        headers: [
          { name: "From", value: `Person ${i} <p${i}@example.com>` },
          { name: "Subject", value: `Fwd: report ${i}` },
          { name: "Date", value: "Tue, 13 Oct 2026 10:00:00 +0000" },
        ],
        text: [`Level ${i}. ${"An ordinary paragraph of a long report. ".repeat(50_000)}`],
        html: [],
        calendar: [],
        attachments: [],
        nested,
        problems: [],
      });
    let msg = level(9, []);
    for (let i = 8; i >= 0; i--) msg = level(i, [msg]);
    const len = (msg.text[0] as string).length;
    // The displayed text takes whole parts until it passes 4 MiB: charged once per unshown header (ten of
    // them, one Date line per level), it would pass the budget.
    const displayed = Math.ceil((4 * 1024 * 1024) / len) * len;
    expect(10 * len + 10 * displayed).toBeGreaterThan(SCAN_LIMITS.maxWork);
    expect(10 * len + displayed).toBeLessThan(SCAN_LIMITS.maxWork / 2);
    const budget = workBudget();
    const s = scanMail(msg, { budget });
    expect(s.signals.filter((x) => x.id === "scan_incomplete")).toEqual([]);
    expect(s.verdict).toBe("deliver");
    expect(budget.spent).toBe(false);
  });

  it("every message of the mail and content corpora uses a small part of the budget", () => {
    const corpus = buildMailCorpus(join(REPO, "test", "fixtures", "content"), join(REPO, "test", "fixtures", "mail"));
    expect(corpus.length).toBeGreaterThan(50);
    let most = 0;
    for (const m of corpus) {
      const budget = workBudget();
      const s = scanMail(m.input, { budget });
      expect(budget.spent, m.id).toBe(false);
      expect(s.signals.filter((x) => x.id === "scan_incomplete" && x.reason === "work"), m.id).toEqual([]);
      most = Math.max(most, SCAN_LIMITS.maxWork - budget.left);
    }
    expect(most).toBeLessThan(SCAN_LIMITS.maxWork / 8);
  });
});
