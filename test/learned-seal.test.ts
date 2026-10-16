/**
 * M1 and the CLI review's I5 for learned choices: the rules are signed with a choice, the whole set is sealed
 * so a "never" deleted outside the CLI shows, and a write never drops a "never" (nothing is written while a
 * file is damaged; a "never" held only in nevers.json is kept). Temporary homes only.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { initApprover, learnedSealer, learnedSignature, signLearned, unlockApprover } from "../src/runtime/approver.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { allowsPath, learnedChecks, loadLearnedView, neversPath, readNevers, saveEntry, sealState, type LearnedEntry } from "../src/runtime/learned.js";

process.env.LAUNCHSAFE_FIREWALL_TEST = "1";

const PASS = "correct horse battery";
let root: string;
let l: Layout;
let pub: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-seal-"));
  l = layout(join(root, "home"));
  pub = initApprover(l, PASS);
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const entry = (id: string, kind: "allow" | "never", key: string, rules = ["FW-UNKNOWN-TOOL"]): LearnedEntry => ({ version: 1, id, kind, project: "/p", key: key.repeat(64).slice(0, 64), identity: kind === "allow" ? "agent:claude" : "", tool: "T", summary: "", rules, approvals: 3, createdAt: "2026-10-13T00:00:00.000Z" });
const signed = (e: LearnedEntry): LearnedEntry => ({ ...e, sig: signLearned(unlockApprover(l, PASS), e) });

describe("M1: the rules are signed with a choice", () => {
  it("v3 covers the rules; a v2 signature from before still verifies, as v2", () => {
    const e = entry("aaaa1", "allow", "a");
    const sig = signLearned(unlockApprover(l, PASS), e);
    expect(learnedSignature(pub, e, sig)).toBe("v3");
    expect(learnedSignature(pub, { ...e, rules: ["FW-OTHER"] }, sig)).toBeNull();
    const { rules: _r, ...v2fields } = e;
    const old = signLearned(unlockApprover(l, PASS), v2fields);
    expect(learnedSignature(pub, e, old)).toBe("v2");
  });
});

describe("M1: the set is sealed", () => {
  it("a never deleted from both files outside the CLI breaks the seal: no always applies, doctor warns, writes are refused", () => {
    const seal = { seal: learnedSealer(unlockApprover(l, PASS)) };
    saveEntry(l, signed(entry("aaaa1", "allow", "a")), seal);
    saveEntry(l, signed(entry("nnnn1", "never", "b")), seal);
    expect(sealState(l, pub).state).toBe("ok");
    expect(loadLearnedView(l, "/p", pub, true, "agent:claude").view.allows.size).toBe(1);
    for (const p of [allowsPath(l), neversPath(l)]) {
      const o = JSON.parse(readFileSync(p, "utf8")) as { entries: LearnedEntry[] };
      o.entries = o.entries.filter((e) => e.kind !== "never");
      writeFileSync(p, JSON.stringify(o));
    }
    expect(sealState(l, pub)).toMatchObject({ state: "broken" });
    const v = loadLearnedView(l, "/p", pub, true, "agent:claude");
    expect(v.view.allows.size).toBe(0);
    expect(v.ignored[0]?.why).toMatch(/changed outside launchsafe-firewall/);
    expect(learnedChecks(l, pub).map((c) => c.detail).join("\n")).toMatch(/a "never" may have been removed/);
    expect(() => saveEntry(l, entry("cccc1", "never", "c"), seal)).toThrow(/changed outside/);
  });

  it("a removed seal with rules-signed entries still in the files is broken", () => {
    const seal = { seal: learnedSealer(unlockApprover(l, PASS)) };
    saveEntry(l, signed(entry("aaaa1", "allow", "a")), seal);
    for (const p of [allowsPath(l), neversPath(l)]) {
      const o = JSON.parse(readFileSync(p, "utf8")) as Record<string, unknown>;
      delete o.seal;
      writeFileSync(p, JSON.stringify(o));
    }
    expect(sealState(l, pub)).toMatchObject({ state: "broken", why: "its seal was removed" });
  });

  it("a sealed set changes only with the key", () => {
    saveEntry(l, entry("nnnn1", "never", "b"), { seal: learnedSealer(unlockApprover(l, PASS)) });
    expect(() => saveEntry(l, entry("nnnn2", "never", "c"))).toThrow(/needs the approval passphrase/);
  });
});

describe("CLI-I5: a write never drops a never", () => {
  it("nothing is written while allows.json is damaged, so the nevers in nevers.json stay", () => {
    saveEntry(l, entry("nnnn1", "never", "b"));
    writeFileSync(allowsPath(l), "{ not json");
    const before = readFileSync(neversPath(l), "utf8");
    expect(() => saveEntry(l, entry("nnnn2", "never", "c"))).toThrow(/damaged; nothing was changed/);
    expect(readFileSync(neversPath(l), "utf8")).toBe(before);
    expect(readNevers(l).entries.map((e) => e.id)).toEqual(["nnnn1"]);
  });

  it("a never held only in nevers.json is kept by the next write", () => {
    mkdirSync(join(l.home, "learned"), { recursive: true });
    writeFileSync(allowsPath(l), JSON.stringify({ version: 1, entries: [] }));
    writeFileSync(neversPath(l), JSON.stringify({ version: 1, entries: [entry("nnnn1", "never", "b")] }));
    saveEntry(l, entry("nnnn2", "never", "c"));
    expect(readNevers(l).entries.map((e) => e.id).sort()).toEqual(["nnnn1", "nnnn2"]);
    expect((JSON.parse(readFileSync(allowsPath(l), "utf8")) as { entries: LearnedEntry[] }).entries.map((e) => e.id).sort()).toEqual(["nnnn1", "nnnn2"]);
  });
});
