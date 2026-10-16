/**
 * The scanner's false-positive corpus and attack recall
 * (the measured false-positive plan). The gate: nothing
 * outside the attack set quarantines, and every attack fixture does.
 * The numbers are printed so a run shows the rates, not only pass or fail.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanContent, type ScanResult, type Verdict } from "../src/engine/content-scan.js";

const DIR = join(import.meta.dirname, "fixtures", "content");
const tags = (s: string) => Array.from(s, (c) => String.fromCodePoint(0xe0000 + (c.codePointAt(0) as number))).join("");
const expand = (s: string) => s.replace(/\{\{tags:([^}]*(?:\}(?!\})[^}]*)*)\}\}/g, (_, t: string) => tags(t));

interface Item {
  id: string;
  group: string;
  text: string;
  html: boolean;
  authFail: boolean;
  expect?: Verdict;
}

const manifest = JSON.parse(readFileSync(join(DIR, "manifest.json"), "utf8")) as { files: Record<string, { group: string; html: boolean }> };
const items: Item[] = [
  ...Object.entries(manifest.files).map(([file, m]) => ({ id: file, group: m.group, text: readFileSync(join(DIR, file), "utf8"), html: m.html, authFail: false })),
  ...(JSON.parse(readFileSync(join(DIR, "cases.json"), "utf8")) as { id: string; group: string; text: string; html?: boolean; authFail?: boolean; expect?: Verdict }[]).map((c) => ({
    id: c.id,
    group: c.group,
    text: expand(c.text),
    html: c.html === true,
    authFail: c.authFail === true,
    ...(c.expect !== undefined ? { expect: c.expect } : {}),
  })),
];
const attacks = (JSON.parse(readFileSync(join(DIR, "attacks.json"), "utf8")) as { id: string; family: string; text: string; html?: boolean; authFail?: boolean }[]).map((a) => ({
  ...a,
  text: expand(a.text),
}));

const scan = (text: string, html: boolean, authFail: boolean): ScanResult => scanContent(text, { html, authFail });

describe("content corpus: false positives", () => {
  const results = items.map((item) => ({ item, r: scan(item.text, item.html, item.authFail) }));

  it("prints the rates per group", () => {
    const groups = [...new Set(items.map((i) => i.group))].sort();
    const rows = groups.map((g) => {
      const rs = results.filter((x) => x.item.group === g).map((x) => x.r.verdict);
      const n = (v: Verdict) => rs.filter((x) => x === v).length;
      return { group: g, messages: rs.length, quarantine: n("quarantine"), neutralize: n("neutralize"), flag: n("flag"), deliver: n("deliver") };
    });
    console.log("content corpus (false positives):");
    console.table(rows);
    expect(rows.length).toBeGreaterThan(0);
  });

  for (const { item, r } of results) {
    it(`${item.group}: ${item.id} does not quarantine${item.expect !== undefined ? ` (expected ${item.expect})` : ""}`, () => {
      expect(r.verdict, JSON.stringify(r.signals)).not.toBe("quarantine");
      if (item.expect !== undefined) expect(r.verdict, JSON.stringify(r.signals)).toBe(item.expect);
    });
  }

  it("newsletters quoting injection phrases are flagged or neutralized, never quarantined", () => {
    const nl = results.filter((x) => x.item.group === "newsletter");
    expect(nl.length).toBeGreaterThan(0);
    for (const { item, r } of nl) expect(["flag", "neutralize", "deliver"], item.id).toContain(r.verdict);
  });
});

describe("content corpus: attack recall", () => {
  const results = attacks.map((a) => ({ a, r: scan(a.text, a.html === true, a.authFail === true) }));

  it("prints recall per family", () => {
    const families = [...new Set(attacks.map((a) => a.family))].sort();
    const rows = families.map((f) => {
      const rs = results.filter((x) => x.a.family === f);
      const hit = rs.filter((x) => x.r.verdict === "quarantine").length;
      return { family: f, fixtures: rs.length, quarantined: hit, recall: `${Math.round((100 * hit) / rs.length)}%` };
    });
    console.log("content corpus (attack recall):");
    console.table(rows);
    expect(rows.length).toBeGreaterThan(0);
  });

  for (const { a, r } of results) {
    it(`${a.family}: ${a.id} quarantines and the neutralized copy drops the marker`, () => {
      expect(r.verdict, JSON.stringify(r.signals)).toBe("quarantine");
      if (r.neutralized !== undefined && a.family !== "auth_fail" && a.family !== "zero_width") expect(r.neutralized).not.toMatch(/LSTEST|lstest\.example|webhook\.site/);
    });
  }
});
