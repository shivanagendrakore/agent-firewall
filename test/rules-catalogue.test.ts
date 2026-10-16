/**
 * One rule catalogue. Every FW- id the code emits has an entry, every active entry is used,
 * planned ids are not emitted yet, examples point at real scenario rows, the queue sentences are the
 * same strings as in v0.1, and docs/coverage.md and coverage.json are generated from the catalogue (X10, X11).
 */
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CATALOGUE, INST } from "../src/catalogue-scenarios.js";
import { ruleSentence } from "../src/engine/summary.js";
import { RULES } from "../src/rules.js";
import { REPO, testRoot } from "./helpers.js";

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? files(p) : p.endsWith(".ts") && !p.endsWith(".test.ts") ? [p] : [];
  });
}

/** FW- ids written as literals in engine and runtime code (not in the catalogue, scenario data or docs). */
export function emittedIds(srcDir: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const f of files(srcDir)) {
    if (/(?:rules|catalogue-scenarios|scenarios|catalogue)\.ts$/.test(f)) continue;
    for (const m of readFileSync(f, "utf8").matchAll(/"(FW-[A-Z][A-Z-]*[A-Z])"/g)) out.set(m[1] as string, [...(out.get(m[1] as string) ?? []), f]);
  }
  return out;
}

const V01_SENTENCES: Record<string, string> = {
  "FW-SEND": "It sends data off this machine, and the session had already read outside content.",
  "FW-MESSAGE": "It sends a message to people, and the session had already read outside content.",
  "FW-SEND-ARGS": "It sends text to an outside service, and this session holds private data and had read outside content.",
  "FW-FETCH": "It contacts a site you did not name, and the session had already read outside content.",
  "FW-FETCH-DATA": "The address itself could carry data out, and the session had already read outside content.",
  "FW-INSTRUCTIONS-HELD": "It changes the agent's own instructions, memory or settings after reading outside content, so it is kept as a proposal.",
  "FW-INSTRUCTIONS": "It changes the agent's own instructions or memory.",
  "FW-AGENT-SETTINGS": "It changes agent settings that can make code run in every future session.",
  "FW-PERSISTENCE": "It writes a file that runs code later on its own.",
  "FW-OUTSIDE-WRITE": "It writes outside the project, and the session had already read outside content.",
  "FW-DESTRUCTIVE": "It destroys data or infrastructure.",
  "FW-PRIVILEGE": "It runs with elevated privileges.",
  "FW-CREDENTIAL-READ": "It reads a credential store, which no ordinary coding task needs.",
  "FW-SECRET-VARIABLE": "It sends a secret environment variable to a service that did not issue it.",
  "FW-RAW-IP": "It contacts a bare IP address rather than a named service.",
  "FW-SYMLINK": "It links to a protected file, so later writes would reach it.",
  "FW-REMOTE-CODE": "It downloads code and runs it directly.",
  "FW-OBFUSCATED": "It runs text as a command in a way the firewall cannot read (decoded, computed, or handed to a shell by another program).",
  "FW-UNTRUSTED-CODE": "It runs code that came from outside the project.",
  "FW-TAINTED-MANIFEST": "It runs a build or task file that changed after the session read outside content.",
  "FW-INSTALL": "It downloads and runs packages, and the session had already read outside content.",
  "FW-OPAQUE-CODE": "It runs code the firewall cannot see into, and the session had already read outside content.",
  "FW-AGENT-SPAWN": "It starts another coding agent, and the session had already read outside content.",
  "FW-UNKNOWN-TOOL": "It uses a tool the firewall does not know, so it could do anything and what it returns is treated as outside content.",
  "FW-UNCLASSIFIABLE": "The firewall cannot fully check it (part is only known at run time, it sets something that changes what code runs, or it is too large to read), so it treats it as the riskiest thing it could be.",
  "FW-SECRET-FILE-PUBLISH": "It could publish a file that credentials were copied into earlier.",
  "FW-POLICY-ERROR": "The firewall's policy file is invalid, so risky actions need you.",
};

describe("rule catalogue", () => {
  const emitted = emittedIds(join(REPO, "src"));
  it("X10: every FW- id the code emits has a catalogue entry", () => {
    const missing = [...emitted.keys()].filter((id) => RULES[id] === undefined);
    expect(missing, missing.map((id) => `${id} in ${emitted.get(id)?.join(", ")}`).join("\n")).toEqual([]);
  });
  it("X10: the check catches a new literal without an entry", () => {
    const dir = join(testRoot(), "rules-src");
    mkdirSync(join(dir, "engine"), { recursive: true });
    writeFileSync(join(dir, "engine", "decide.ts"), 'hits.push({ rule: "FW-NOT-IN-CATALOGUE", outcome: "deny" });');
    expect([...emittedIds(dir).keys()].filter((id) => RULES[id] === undefined)).toEqual(["FW-NOT-IN-CATALOGUE"]);
  });
  it("every active entry is emitted by the code; planned ones are not yet", () => {
    const active = Object.values(RULES).filter((r) => r.status === "active").map((r) => r.id);
    expect(active.filter((id) => !emitted.has(id))).toEqual([]);
    expect(Object.values(RULES).filter((r) => r.status === "planned" && emitted.has(r.id)).map((r) => r.id)).toEqual([]);
    expect(Object.values(RULES).filter((r) => r.status === "planned").map((r) => r.id).sort()).toEqual([]);
  });
  it("every example row exists in the scenario suite", () => {
    const ids = new Set([...CATALOGUE.map((r) => r.id), ...INST.map((r) => r.id)]);
    const bad = Object.values(RULES).flatMap((r) => r.examples.filter((e) => e.row !== undefined && !ids.has(e.row)).map((e) => `${r.id}: ${e.row}`));
    expect(bad).toEqual([]);
  });
  it("every entry is complete, and deny rules are not approvable", () => {
    for (const r of Object.values(RULES)) {
      expect(r.title.length, r.id).toBeGreaterThan(0);
      expect(r.sentence.length, r.id).toBeGreaterThan(0);
      expect(r.why.length, r.id).toBeGreaterThan(0);
      if (r.outcome.untrusted === "deny" && r.outcome.trusted === "deny") expect(r.approvable, r.id).toBe(false);
      if (r.approvable) expect(r.approveHow, r.id).toBeDefined();
    }
  });
  it("FW-HIDDEN-OUTPUT's explanation states the dense count and the gateway's window (docs/design.md)", () => {
    const why = RULES["FW-HIDDEN-OUTPUT"]?.why ?? "";
    expect(why).toContain("dense zero-width characters (eight or more, or four in a row;");
    expect(why).toContain("withholds the result only when a phrase addressed to an AI assistant is within 200 characters of it");
  });
  it("ruleSentence() is unchanged for the v0.1 rules (same strings, moved)", () => {
    for (const [id, s] of Object.entries(V01_SENTENCES)) expect(ruleSentence([id], [])).toBe(s);
    expect(ruleSentence(["FW-SOMETHING-NEW"], ["do x: because y. more"])).toBe("Because y.");
  });
  it("X11: gen-coverage --check fails when docs/coverage.md or coverage.json is stale, passes when current", () => {
    const dir = join(testRoot(), "coverage-check");
    mkdirSync(join(dir, "docs"), { recursive: true });
    const copy = (): void => {
      for (const f of ["coverage.md", "coverage.json"]) cpSync(join(REPO, "docs", f), join(dir, "docs", f));
    };
    const run = (): number => spawnSync(process.execPath, [join(REPO, "scripts", "gen-coverage.mjs"), "--check"], { cwd: dir, encoding: "utf8" }).status ?? -1;
    copy();
    expect(run()).toBe(0);
    writeFileSync(join(dir, "docs", "coverage.md"), readFileSync(join(dir, "docs", "coverage.md"), "utf8").replace("FW-SEND", "FW-SENT"));
    expect(run()).toBe(1);
    copy();
    writeFileSync(join(dir, "docs", "coverage.json"), readFileSync(join(dir, "docs", "coverage.json"), "utf8").replace('"partly"', '"covered"'));
    expect(run()).toBe(1);
  });
});
