/**
 * Cross-cutting: policy schema version 2 with its tighten-only rules for project
 * files, and the v0.2 state events validated field by field (signed ones verified like approvals).
 */
import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { defaultConfig, mergeTighten, mergeTrusted, POLICY_VERSION, validatePolicy } from "../src/policy.js";
import { applyEvent, foldEvents, parseEvent } from "../src/engine/state.js";
import { loadPolicy } from "../src/runtime/config.js";
import { defaultRegistryRoot, mountRegistry } from "../src/runtime/run/mountpoints.js";
import { layout, PROJECT_POLICY_FILE } from "../src/runtime/layout.js";
import { appendEvents, loadState } from "../src/runtime/store.js";
import { initApprover, signStateChange, unlockApprover } from "../src/runtime/approver.js";
import { fakeRunProcess, spawnCli, tempHome } from "./helpers.js";
import { main } from "../src/climain.js";
import { budget, timed } from "./fuzz/gen.js";

describe("policy schema version 2 (read unchanged under version 3)", () => {
  it("a version 1 file is still valid (migrated in memory); the current version is 3 (test/policy-v3.test.ts)", () => {
    expect(POLICY_VERSION).toBe(3);
    expect(validatePolicy({ version: 1, denyHosts: ["evil.example.com"] }, "p")).toEqual({ denyHosts: ["evil.example.com"] });
    expect(() => validatePolicy({ version: 4 }, "p")).toThrow(/newer than this firewall understands/);
  });
  it("validates the v0.2 keys", () => {
    expect(validatePolicy({ version: 2, userOutputTools: ["X"], notUserOutputTools: ["Y"], provenance: { trustSelfAuthored: false, maxHashBytes: 1024 } }, "p")).toEqual({ userOutputTools: ["X"], notUserOutputTools: ["Y"], provenance: { trustSelfAuthored: false, maxHashBytes: 1024 } });
    expect(() => validatePolicy({ version: 2, provenance: { trustSelfAuthored: "yes" } }, "p")).toThrow(/true or false/);
    expect(() => validatePolicy({ version: 2, provenance: { bogus: 1 } }, "p")).toThrow(/not a known setting/);
    expect(() => validatePolicy({ version: 2, provenance: { maxHashBytes: -1 } }, "p")).toThrow(/whole number/);
    expect(() => validatePolicy({ version: 2, userOutputTools: [""] }, "p")).toThrow(/non-empty/);
  });
  it("defaults: provenance on, no extra user-output tools", () => {
    const d = defaultConfig();
    expect(d.version).toBe(3);
    expect(d.provenance).toEqual({ trustSelfAuthored: true, carryUntrustedWrites: true, maxHashBytes: 4194304 });
    expect(d.userOutputTools).toEqual([]);
  });
  it("user policy may loosen the new keys; a project may only tighten them", () => {
    const user = mergeTrusted(defaultConfig(), { userOutputTools: ["SendFancyFile"], provenance: { trustSelfAuthored: false } });
    expect(user.userOutputTools).toEqual(["SendFancyFile"]);
    expect(user.provenance).toEqual({ trustSelfAuthored: false, carryUntrustedWrites: true, maxHashBytes: 4194304 });
    const { config, ignored } = mergeTighten(defaultConfig(), { userOutputTools: ["SendFancyFile"], notUserOutputTools: ["Y"], provenance: { trustSelfAuthored: true, carryUntrustedWrites: false, maxHashBytes: 99999999 } });
    expect(config.userOutputTools).toEqual([]);
    expect(config.notUserOutputTools).toEqual(["Y"]);
    expect(config.provenance).toEqual(defaultConfig().provenance);
    expect(ignored.join(" | ")).toMatch(/userOutputTools.*trustSelfAuthored.*carryUntrustedWrites.*maxHashBytes/);
    const strict = mergeTighten(user, { provenance: { trustSelfAuthored: false, maxHashBytes: 10 } }).config;
    expect(strict.provenance.trustSelfAuthored).toBe(false);
    expect(strict.provenance.maxHashBytes).toBe(10);
  });
  it("policy validate reports a version 1 user file; policy migrate rewrites it", async () => {
    const home = tempHome();
    const l = layout(join(home, ".launchsafe-firewall"));
    mkdirSync(l.home, { recursive: true });
    writeFileSync(l.policy, JSON.stringify({ version: 1, denyHosts: ["evil.example.com"] }));
    expect(loadPolicy(l, [home]).notes.join(" ")).toMatch(/version 1, migrated in memory; run "launchsafe-firewall policy migrate"/);
    expect(spawnCli(["policy", "validate"], { home }).stdout).toMatch(/version 1, migrated in memory/);
    // R20: the binary refuses without a person at the keyboard; in-process with one, it rewrites.
    const refused = spawnCli(["policy", "migrate"], { home });
    expect(refused.status).toBe(1);
    expect(JSON.parse(readFileSync(l.policy, "utf8")).version).toBe(1);
    const status = await main(["policy", "migrate"], l, { write: () => undefined, humanAtKeyboard: () => Promise.resolve(true) });
    expect(status).toBe(0);
    expect(JSON.parse(readFileSync(l.policy, "utf8"))).toEqual({ version: 3, denyHosts: ["evil.example.com"] });
    expect(loadPolicy(l, [home]).notes).toEqual([]);
  });
});

describe("v0.2 state events", () => {
  it("valid events parse and fold", () => {
    const evs = [
      { type: "scope", scope: { prompt: "a".repeat(64), at: "2026-10-10T09:00:00.000Z", paths: ["/w/packages/web"], repos: [], hosts: [], intents: [], narrowed: true } },
      { type: "canary_tripped", id: "c1" },
      { type: "canary_seen", id: "c2" },
      { type: "agent_scan", rules: ["ls-agent-hidden-unicode"], incomplete: false },
      { type: "linked", parent: "parent-session" },
    ].map(parseEvent);
    expect(evs.every((e) => e.type !== "corrupt")).toBe(true);
    const s = foldEvents(evs);
    expect(s.scope?.paths).toEqual(["/w/packages/web"]);
    expect([...s.canaryTripped]).toEqual(["c1"]);
    expect(s.agentScanRules).toEqual(["ls-agent-hidden-unicode"]);
    expect(s.linkedParents).toEqual(["parent-session"]);
    expect(s.tainted).toBe(false);
  });
  it("FZ21: linked parents and agent-scan rules keep every distinct value once, in the order first seen", () => {
    const evs = ["p1", "p2", "p1", "p3", "p2"].map((parent) => parseEvent({ type: "linked", parent }));
    expect(foldEvents(evs).linkedParents).toEqual(["p1", "p2", "p3"]);
    const scans = [["a", "b"], ["b", "c", "a"], [], ["d", "d"]].map((rules) => parseEvent({ type: "agent_scan", rules, incomplete: false }));
    expect(foldEvents(scans).agentScanRules).toEqual(["a", "b", "c", "d"]);
    // Events applied one by one to a state already folded (the hook adds events to the state it loaded) keep the same rule.
    const st = foldEvents(evs);
    applyEvent(st, { type: "linked", parent: "p3" });
    applyEvent(st, { type: "linked", parent: "p4" });
    expect(st.linkedParents).toEqual(["p1", "p2", "p3", "p4"]);
    // A copy of the state has its own list, with the same members.
    const copy = structuredClone(st);
    applyEvent(copy, { type: "linked", parent: "p1" });
    applyEvent(copy, { type: "linked", parent: "p5" });
    expect(copy.linkedParents).toEqual(["p1", "p2", "p3", "p4", "p5"]);
    expect(st.linkedParents).toEqual(["p1", "p2", "p3", "p4"]);
  });
  it("FZ21: linked parents and agent-scan rules are never capped, however many there are", () => {
    // A subagent hands its taint back to every parent in the list (src/hook/claude.ts): a parent dropped from it stays trusted.
    const parents = Array.from({ length: 5000 }, (_, i) => `parent-${i}`);
    const rules = Array.from({ length: 5000 }, (_, i) => `r${i}`);
    const evs = [...parents, ...parents.slice(0, 100)].map((parent) => parseEvent({ type: "linked", parent }));
    const scans = [rules, rules.slice(0, 100)].map((r) => parseEvent({ type: "agent_scan", rules: r, incomplete: false }));
    const st = foldEvents([...evs, ...scans]);
    expect(st.linkedParents).toEqual(parents);
    expect(st.agentScanRules).toEqual(rules);
    // The same one event at a time on a state already folded (the hook's path).
    applyEvent(st, { type: "linked", parent: "parent-5000" });
    applyEvent(st, { type: "agent_scan", rules: ["r0", "r5000"], incomplete: false });
    expect(st.linkedParents.length).toBe(5001);
    expect([st.linkedParents[0], st.linkedParents.at(-1)]).toEqual(["parent-0", "parent-5000"]);
    expect(st.agentScanRules.length).toBe(5001);
    expect([st.agentScanRules[0], st.agentScanRules.at(-1)]).toEqual(["r0", "r5000"]);
  });
  // Searching the list for each value was quadratic: measured in Docker, about 18 s for these 200,000 rules and 6 s for
  // these 100,000 parents; a set takes milliseconds. The count is checked too: nothing is dropped at this size either.
  it("FZ21: 200,000 distinct agent-scan rules in one event fold in well under a second", () => {
    const limit = budget(1000);
    const scan = parseEvent({ type: "agent_scan", rules: Array.from({ length: 200_000 }, (_, i) => `rule-${i}`), incomplete: false });
    const r = timed(() => foldEvents([scan]), limit);
    expect(r.ms).toBeLessThan(limit);
    expect(r.value.agentScanRules.length).toBe(200_000);
  });
  it("FZ21: 100,000 distinct linked parents fold in well under a second", () => {
    const limit = budget(1000);
    const evs = Array.from({ length: 100_000 }, (_, i) => parseEvent({ type: "linked", parent: `parent-${i}` }));
    const r = timed(() => foldEvents(evs), limit);
    expect(r.ms).toBeLessThan(limit);
    expect(r.value.linkedParents.length).toBe(100_000);
  });
  it("malformed events become corrupt (untrusted and sensitive)", () => {
    for (const raw of [{ type: "scope" }, { type: "scope_widen", kind: "path", value: "x", id: "w1" }, { type: "budget_raise", key: "bytes", amount: -5, id: "b", sig: "s" }, { type: "canary_seen" }, { type: "agent_scan", rules: "x", incomplete: false }, { type: "linked", parent: 3 }]) {
      const e = parseEvent(raw);
      expect(e.type, JSON.stringify(raw)).toBe("corrupt");
      const s = foldEvents([e]);
      expect(s.tainted && s.sensitive).toBe(true);
    }
  });
  it("signed events count only with the approver's signature", () => {
    const home = tempHome();
    const l = layout(join(home, ".launchsafe-firewall"));
    const pub = initApprover(l, "correct horse battery");
    const priv = unlockApprover(l, "correct horse battery");
    const sig = signStateChange(priv, "scope-widen", "s1", ["path", "/w/packages/api", "w1"]);
    appendEvents(l, "s1", [{ type: "scope_widen", kind: "path", value: "/w/packages/api", id: "w1", sig }]);
    const ok = loadState(l, "s1", pub);
    expect(ok.tainted).toBe(false);
    expect(ok.scopeWidenings).toEqual([{ kind: "path", value: "/w/packages/api", id: "w1" }]);
    appendEvents(l, "s2", [{ type: "budget_raise", key: "bytes", amount: 1000, id: "b1", sig: "forged" }]);
    const bad = loadState(l, "s2", pub);
    expect(bad.tainted).toBe(true);
    expect(bad.budgetRaises).toEqual([]);
    const braise = signStateChange(priv, "budget-raise", "s3", ["bytes", "1000", "b1"]);
    appendEvents(l, "s3", [{ type: "budget_raise", key: "bytes", amount: 1000, id: "b1", sig: braise }]);
    expect(loadState(l, "s3", pub).budgetRaises).toEqual([{ key: "bytes", amount: 1000, id: "b1" }]);
    expect(loadState(l, "s3", null).tainted).toBe(true);
  });
});

describe("run.allowWritePaths (RN6): person-only", () => {
  it("validates, merges from user policy, and is ignored in a project policy", () => {
    expect(validatePolicy({ version: 2, run: { allowWritePaths: ["dist", "dist"] } }, "p")).toEqual({ run: { allowWritePaths: ["dist"] } });
    expect(() => validatePolicy({ version: 2, run: { allowWritePaths: [""] } }, "p")).toThrow(/non-empty paths/);
    expect(() => validatePolicy({ version: 2, run: { other: 1 } }, "p")).toThrow(/not a known setting/);
    expect(() => validatePolicy({ version: 2, run: [] }, "p")).toThrow(/must be an object/);
    const user = mergeTrusted(defaultConfig(), validatePolicy({ version: 2, run: { allowWritePaths: ["dist"] } }, "u"));
    expect(user.run?.allowWritePaths).toEqual(["dist"]);
    const proj = mergeTighten(defaultConfig(), validatePolicy({ version: 2, run: { allowWritePaths: ["dist"] } }, "p"));
    expect(proj.config.run).toBeUndefined();
    expect(proj.ignored.join(" ")).toMatch(/run\.allowWritePaths/);
  });
});

describe("run.privateHosts: person-only", () => {
  it("validates host patterns, merges with allowWritePaths across layers, and is ignored in a project policy", () => {
    expect(validatePolicy({ version: 2, run: { privateHosts: ["Corp.Example", "=git.x.example", "*.int.example"] } }, "p")).toEqual({ run: { privateHosts: ["corp.example", "=git.x.example", "*.int.example"] } });
    for (const bad of [[""], ["*"], ["a b"], ["http://x.example"], [1]]) expect(() => validatePolicy({ version: 2, run: { privateHosts: bad } }, "p"), JSON.stringify(bad)).toThrow(/must be a list of host names/);
    const user = mergeTrusted(defaultConfig(), validatePolicy({ version: 2, run: { allowWritePaths: ["dist"] } }, "u"));
    const managed = mergeTrusted(user, validatePolicy({ version: 2, run: { privateHosts: ["corp.example"] } }, "m"));
    expect(managed.run).toEqual({ allowWritePaths: ["dist"], privateHosts: ["corp.example"] });
    const proj = mergeTighten(defaultConfig(), validatePolicy({ version: 2, run: { privateHosts: ["corp.example"] } }, "p"));
    expect(proj.config.run).toBeUndefined();
    expect(proj.ignored.join(" ")).toMatch(/run\.privateHosts/);
  });
});

describe("R17: a broken policy file drops only itself", () => {
  const setup = (): { l: ReturnType<typeof layout>; managed: string; ws: string } => {
    const home = tempHome("r17-");
    const l = layout(join(home, ".launchsafe-firewall"));
    mkdirSync(l.home, { recursive: true });
    const ws = join(home, "ws");
    mkdirSync(ws, { recursive: true });
    return { l, managed: join(home, "managed.json"), ws };
  };
  it("a broken user file keeps the managed denyHosts and server entries and the project's tightening", () => {
    const { l, managed, ws } = setup();
    writeFileSync(l.policy, "{ not json");
    writeFileSync(managed, JSON.stringify({ version: 2, denyHosts: ["collect.example"], mcpServers: { x: { results: "untrusted", privateData: true, blockedTools: ["y"] } } }));
    writeFileSync(join(ws, PROJECT_POLICY_FILE), JSON.stringify({ version: 2, denyHosts: ["more.example"] }));
    const p = loadPolicy(l, [ws], "darwin", managed);
    expect(p.error).toBeDefined();
    expect(p.config.denyHosts).toEqual(expect.arrayContaining(["collect.example", "more.example"]));
    expect(p.config.mcpServers.x?.blockedTools).toContain("y");
  });
  it("an empty directory at the project policy: absent only while a live run holds it as its mount point; otherwise an error (fails closed), never \"no project policy\"", () => {
    const { l, managed, ws } = setup();
    writeFileSync(l.policy, JSON.stringify({ version: 2, fetchAllowHosts: ["allowed.example"] }));
    const pp = join(realpathSync(ws), PROJECT_POLICY_FILE);
    mkdirSync(pp);
    // Nobody's mount point: the policy is broken, so strict defaults and every risky action to a person.
    expect(loadPolicy(l, [ws], "linux", managed).error).toMatch(/EISDIR/);
    const fake = fakeRunProcess();
    const reg = mountRegistry(defaultRegistryRoot(), fake.pid);
    reg.claim([pp]);
    try {
      const p = loadPolicy(l, [ws], "linux", managed);
      expect(p.error).toBeUndefined();
      expect(p.sources).not.toContain(join(ws, PROJECT_POLICY_FILE));
      expect(p.config.fetchAllowHosts).toContain("allowed.example");
      // Not empty: not a mount point, whoever claims it.
      writeFileSync(join(pp, "x"), "{}");
      expect(loadPolicy(l, [ws], "linux", managed).error).toBeDefined();
      rmSync(join(pp, "x"));
    } finally {
      reg.release();
      fake.stop();
    }
    expect(existsSync(pp)).toBe(false); // the last user removed the empty mount point
  });
  it("a broken managed file also drops the user's layer (it could open what the administrator closed)", () => {
    const { l, managed, ws } = setup();
    writeFileSync(managed, "{ broken");
    writeFileSync(l.policy, JSON.stringify({ version: 2, sendAllowHosts: ["anywhere.example"] }));
    const p = loadPolicy(l, [ws], "darwin", managed);
    expect(p.error).toBeDefined();
    expect(p.config.sendAllowHosts).not.toContain("anywhere.example");
  });
});

describe("R20: commands that change the tripwires, the policy or the log need a person at the keyboard", () => {
  it.each([[["policy", "init"]], [["log", "rotate"]], [["canary", "plant"]], [["canary", "remove", "--all"]], [["policy", "migrate"]]])("%j refuses without a terminal", (args) => {
    const r = spawnCli(args);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/interactive terminal/);
  });
  it("usage errors still come first (exit 64, nothing asked)", () => {
    expect(spawnCli(["canary", "remove"]).status).toBe(64);
  });
});
