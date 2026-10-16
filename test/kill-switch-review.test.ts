/**
 * The security review of the kill switch and the behaviour monitor, one test (or more) per finding: a resume's
 * time is signed and never ahead of now; a monitor stop holds when its record cannot be written (hook, library,
 * a store without stop()); doctor fails on a logged stop whose record is gone; resume refuses a key the hooks do
 * not pin; fileStore uses the pinned key; the library and the local API count per agent; a project cannot lower
 * a stop limit below half its default; counts restart at the exact time of a resume; parts add up; tried hosts
 * are capped; ignored resumes are reported; any session id the hook records can be stopped; hashed file names
 * cannot collide with plain ones.
 */
import { appendFileSync, chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { main } from "../src/climain.js";
import { budgetPolicy, type BudgetView } from "../src/engine/budgets.js";
import { applyDecision, budgetView, emptyCounters, MAX_HOSTS } from "../src/engine/counters.js";
import { decide } from "../src/engine/decide.js";
import { emptyState } from "../src/engine/state.js";
import { decideNative, runHook, type HookEnv } from "../src/hook/claude.js";
import { defaultConfig, mergeTighten, validatePolicy } from "../src/policy.js";
import { initApprover, signStateChange, unlockApprover } from "../src/runtime/approver.js";
import { readCounters } from "../src/runtime/counters.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { readStops, resumeFields, resumeTarget, stopChecks, stopFile, stopTarget, stopView } from "../src/runtime/stops.js";
import { createGuard, memoryStore, type StateStore } from "../src/sdk/index.js";
import { fileStore } from "../src/sdk/node.js";
import type { Decision } from "../src/types.js";
import { ctx, tempHome, testRoot, WS } from "./helpers.js";

const PASS = "review test passphrase";
let home: string, ws: string, l: Layout, clock: number, seq = 0;

beforeEach(() => {
  home = tempHome("review-home-");
  ws = mkdtempSync(join(testRoot(), "review-ws-"));
  mkdirSync(join(ws, "src"), { recursive: true });
  writeFileSync(join(ws, "src", "a.ts"), "export const a = 1;\n");
  l = layout(join(home, ".launchsafe-firewall"));
  clock = Date.UTC(2026, 9, 13, 9, 0, 0);
});

/** Makes the stops directory read-only (records cannot be written; reading finds none). */
function lockStops(): void {
  mkdirSync(l.stops, { recursive: true });
  chmodSync(l.stops, 0o500);
}

const pub = (): string => JSON.parse(readFileSync(join(l.keys, "approver.json"), "utf8")).publicKey as string;

function env(): HookEnv {
  return { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, home, scratchRoots: [join(home, "tmp")], now: new Date(clock), detectNonInteractive: () => false, notifyDeps: { spawn: () => undefined, platform: "darwin", executable: () => true, now: () => clock } };
}

function pre(s: string, tool: string, input: Record<string, unknown>): { verdict: string; reason: string } {
  const r = runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: s, cwd: ws, permission_mode: "default", tool_name: tool, tool_input: input }), env());
  if (r.stdout.trim() === "") return { verdict: "allow", reason: "" };
  const o = JSON.parse(r.stdout) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
  return { verdict: o.hookSpecificOutput?.permissionDecision ?? "allow", reason: o.hookSpecificOutput?.permissionDecisionReason ?? "" };
}

async function cli(args: string[], o: { secret?: string; env?: NodeJS.ProcessEnv } = {}): Promise<{ status: number; stdout: string; stderr: string }> {
  let stdout = "";
  let stderr = "";
  const status = await main(args, l, { write: (fd, t) => (fd === 1 ? (stdout += t) : (stderr += t)), humanAtKeyboard: () => Promise.resolve(true), session: { readSecret: () => Promise.resolve(o.secret ?? PASS), env: o.env ?? {} } });
  return { status, stdout, stderr };
}

const BLOCKED = { tools: { wire_money: { kind: "blocked" as const }, search_docs: { kind: "read" as const, results: "trusted" as const, privateData: false } } };

describe("1: a resume's time is signed, and never ahead of now", () => {
  it("moving a valid resume's time breaks its signature: the session stays stopped", () => {
    initApprover(l, PASS);
    const priv = unlockApprover(l, PASS);
    const s = `r${++seq}`;
    stopTarget(l, "session", s, { by: "person", reason: "", approverKey: pub() });
    resumeTarget(l, "session", s, { sign: (f) => signStateChange(priv, "resume", s, f), approverKey: pub(), now: new Date(clock) });
    expect(readStops(l, "session", s, pub(), new Date(clock)).active).toEqual([]);
    const file = stopFile(l, "session", s);
    const lines = readFileSync(file, "utf8").trim().split("\n");
    const resume = JSON.parse(lines[1] as string) as { at: string };
    resume.at = new Date(clock + 3600000).toISOString();
    writeFileSync(file, `${lines[0]}\n${JSON.stringify(resume)}\n`);
    const r = readStops(l, "session", s, pub(), new Date(clock));
    expect(r.active).toHaveLength(1);
    expect(r.ignored).toBe(1);
  });

  it("a signed resume dated in the future counts from now (it cannot hide later counts)", () => {
    initApprover(l, PASS);
    const priv = unlockApprover(l, PASS);
    const s = `r${++seq}`;
    stopTarget(l, "session", s, { by: "person", reason: "", approverKey: pub() });
    resumeTarget(l, "session", s, { sign: (f) => signStateChange(priv, "resume", s, f), approverKey: pub(), now: new Date(clock + 86400000) });
    expect(stopView(l, s, null, pub(), new Date(clock)).resumedAt).toBe(clock);
  });
});

describe("2: a monitor stop holds when its record cannot be written", () => {
  it("the hook: the counters' sentinel keeps the session stopped", () => {
    // The stops directory can be read but not written: the record cannot be written.
    lockStops();
    const s = `r${++seq}`;
    const settings = { file_path: join(ws, ".claude", "settings.json"), content: "{}" };
    for (let i = 0; i < 19; i++) {
      clock += 5000;
      pre(s, "Write", settings);
    }
    clock += 5000;
    expect(pre(s, "Write", settings).reason).toMatch(/FW-STOPPED/);
    expect(readCounters(l, s).counters.stops).toEqual([expect.objectContaining({ scope: "session", target: s, signal: "config" })]);
    clock += 5000;
    const after = pre(s, "Read", { file_path: join(ws, "src", "a.ts") });
    expect(after.verdict).toBe("deny");
    expect(after.reason).toMatch(/stopped by the behaviour monitor/);
  }, 120_000);

  it("the library: a store without stops() or stop() still denies after the monitor fires", () => {
    const { stops: _s, stop: _t, ...bare } = memoryStore();
    const g = createGuard({ ...BLOCKED, store: bare as StateStore, session: "lib-bare" });
    for (let i = 0; i < 20; i++) g.decide({ tool: "wire_money", input: { amount: 1 } });
    const after = g.decide({ tool: "search_docs", input: { q: "x" } });
    expect(after.rules).toEqual(["FW-STOPPED"]);
    // A new guard on the same store: the counters' sentinel still stops it.
    expect(createGuard({ ...BLOCKED, store: bare as StateStore, session: "lib-bare" }).decide({ tool: "search_docs", input: { q: "x" } }).rules).toEqual(["FW-STOPPED"]);
  });

  it("the library's file store: a stop() that fails leaves the session stopped", () => {
    lockStops();
    const store = fileStore({ home: l.home, env: {} });
    const g = createGuard({ ...BLOCKED, store, session: "lib-file" });
    for (let i = 0; i < 19; i++) g.decide({ tool: "wire_money", input: { amount: 1 } });
    const x = g.decide({ tool: "wire_money", input: { amount: 1 } });
    expect(x.rules).toEqual(["FW-STOPPED"]);
    expect(x.problems?.join(" ")).toMatch(/could not be recorded/);
    expect(createGuard({ ...BLOCKED, store, session: "lib-file" }).decide({ tool: "search_docs", input: { q: "x" } }).rules).toEqual(["FW-STOPPED"]);
  });
});

describe("3: a deleted record does not un-stop silently", () => {
  it("doctor fails on a logged stop with no logged resume that is no longer in force", async () => {
    const s = `r${++seq}`;
    await cli(["session", "stop", s]);
    expect(stopChecks(l, null).filter((c) => c.status === "fail")).toEqual([]);
    rmSync(stopFile(l, "session", s));
    const fail = stopChecks(l, null).find((c) => c.status === "fail");
    expect(fail?.detail).toMatch(new RegExp(`session ${s}.*no longer in force`));
  });

  it("a monitor stop also lives in the counters: deleting its record alone does not end it", () => {
    const s = `r${++seq}`;
    const settings = { file_path: join(ws, ".claude", "settings.json"), content: "{}" };
    for (let i = 0; i < 20; i++) {
      clock += 5000;
      pre(s, "Write", settings);
    }
    rmSync(stopFile(l, "session", s));
    clock += 5000;
    expect(pre(s, "Read", { file_path: join(ws, "src", "a.ts") }).verdict).toBe("deny");
  }, 120_000);
});

describe("4: resume refuses a key the hooks do not pin", () => {
  it("the pinned key differs: nothing is written and the session stays stopped", async () => {
    initApprover(l, PASS);
    const other = layout(join(tempHome("review-other-"), ".launchsafe-firewall"));
    const otherKey = initApprover(other, PASS);
    const s = `r${++seq}`;
    await cli(["session", "stop", s]);
    const before = readFileSync(stopFile(l, "session", s), "utf8");
    const r = await cli(["session", "resume", s], { env: { LAUNCHSAFE_FIREWALL_APPROVER: otherKey } });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/pin a different approval key/);
    expect(readFileSync(stopFile(l, "session", s), "utf8")).toBe(before);
    // With the matching pin it works.
    expect((await cli(["session", "resume", s], { env: { LAUNCHSAFE_FIREWALL_APPROVER: pub() } })).status).toBe(0);
  });
});

describe("5: fileStore uses the pinned key", () => {
  it("a resume signed with a key the hooks do not pin does not resume the library's session", () => {
    initApprover(l, PASS);
    const priv = unlockApprover(l, PASS);
    const otherKey = initApprover(layout(join(tempHome("review-pin-"), ".launchsafe-firewall")), PASS);
    const s = "lib-pinned";
    stopTarget(l, "session", s, { by: "person", reason: "", approverKey: pub() });
    resumeTarget(l, "session", s, { sign: (f) => signStateChange(priv, "resume", s, f), approverKey: pub() });
    const pinned = createGuard({ ...BLOCKED, store: fileStore({ home: l.home, env: { LAUNCHSAFE_FIREWALL_APPROVER: otherKey } }), session: s });
    expect(pinned.decide({ tool: "search_docs", input: { q: "x" } }).rules).toEqual(["FW-STOPPED"]);
    const unpinned = createGuard({ ...BLOCKED, store: fileStore({ home: l.home, env: {} }), session: s });
    expect(unpinned.decide({ tool: "search_docs", input: { q: "x" } }).verdict).toBe("allow");
  });
});

describe("6: the library and the local API count per agent", () => {
  it("one blocked call in each of 20 new sessions of an agent stops the agent; other agents go on", () => {
    const store = memoryStore();
    let last: ReturnType<ReturnType<typeof createGuard>["decide"]> | undefined;
    for (let i = 0; i < 20; i++) last = createGuard({ ...BLOCKED, store, session: `bot/s${i}` }).decide({ tool: "wire_money", input: { amount: 1 } });
    expect(last?.rules).toEqual(["FW-STOPPED"]);
    expect(last?.message).toMatch(/every session of agent bot/);
    expect(createGuard({ ...BLOCKED, store, session: "bot/brand-new" }).decide({ tool: "search_docs", input: { q: "x" } }).rules).toEqual(["FW-STOPPED"]);
    expect(createGuard({ ...BLOCKED, store, session: "other/s1" }).decide({ tool: "search_docs", input: { q: "x" } }).verdict).toBe("allow");
  });

  it("the file store records the agent stop; a person's agent resume ends it", async () => {
    initApprover(l, PASS);
    const store = fileStore({ home: l.home, env: {} });
    for (let i = 0; i < 20; i++) createGuard({ ...BLOCKED, store, session: `nightly/s${i}` }).decide({ tool: "wire_money", input: { amount: 1 } });
    expect(stopView(l, "nightly/s99", "nightly", pub()).active).toMatchObject({ scope: "agent", target: "nightly", by: "monitor" });
    expect((await cli(["agent", "resume", "nightly"])).status).toBe(0);
    expect(createGuard({ ...BLOCKED, store, session: "nightly/s99" }).decide({ tool: "search_docs", input: { q: "x" } }).verdict).toBe("allow");
  });
});

describe("7: a project cannot lower a stop limit below half its default", () => {
  it("is raised to the floor and reported", () => {
    const { config, ignored } = mergeTighten(defaultConfig(), validatePolicy({ version: 3, budgets: { loop: { stopConfigTouches10m: 1, stopNewHosts10m: 25, stopNonAllow10m: 2 } } }, "project"));
    expect(budgetPolicy(config).loop.stopConfigTouches10m).toBe(10);
    expect(budgetPolicy(config).loop.stopNewHosts10m).toBe(25);
    expect(budgetPolicy(config).loop.stopNonAllow10m).toBe(30);
    expect(ignored.join(" ")).toMatch(/budgets\.loop\.stopConfigTouches10m \(raised to 10\).*below half its default/);
  });
});

describe("8: counting restarts at the exact time of a resume", () => {
  it("counts after the resume within the same minute, and not before it", () => {
    const c = emptyCounters();
    const d = decide({ action: { tool: "Write", input: { file_path: `${WS}/.claude/settings.json`, content: "{}" } }, state: emptyState(), config: defaultConfig(), ctx: ctx(), budgets: budgetView(c, false, emptyState(), new Date(clock)) });
    applyDecision(c, d, new Date(clock + 10_000));
    applyDecision(c, d, new Date(clock + 40_000));
    const v = budgetView(c, false, emptyState(), new Date(clock + 50_000));
    expect(v.recent?.("watch:config", clock + 20_000)).toBe(1);
    expect(v.recent?.("watch:config")).toBe(2);
  });
});

describe("9: the parts of one call add up for the monitor", () => {
  it("three new hosts in one call cross a limit the counts so far are just below", () => {
    const view: BudgetView = { corrupt: false, total: () => 0, window: () => 0, repeats: () => 0, allowance: () => 0, recent: (k) => (k === "watch:newhost" ? 38 : 0) };
    const actions = ["https://n1.example.org/", "https://n2.example.org/", "https://n3.example.org/"].map((url) => ({ tool: "WebFetch", input: { url, prompt: "x" } }));
    const { d } = decideNative({ tool: "web_fetch_many", input: { urls: 3 } }, actions, { state: emptyState(), config: defaultConfig(), ctx: ctx(), budgets: view, sessionId: "p1" });
    expect(d.stop?.signal).toBe("newhosts");
    expect(d.rules).toContain("FW-STOPPED");
  });
});

describe("10: tried hosts are capped", () => {
  it(`a session remembers at most ${MAX_HOSTS} hosts, forgetting the oldest`, () => {
    const c = emptyCounters();
    const base: Decision = { verdict: "allow", primaryClass: "egress_fetch", reasons: [], rules: [], effects: [], findings: [], events: [], actionHash: "h" };
    for (let i = 0; i < MAX_HOSTS + 100; i++) applyDecision(c, { ...base, budget: { usage: [], raises: [], loopEligible: false, writes: false, watch: { hosts: [`h${i}.example`], newHosts: 1, config: false } } }, new Date(clock + i));
    const hosts = Object.keys(c.session).filter((k) => k.startsWith("host:"));
    expect(hosts).toHaveLength(MAX_HOSTS);
    expect(hosts).not.toContain("host:h0.example");
    expect(hosts).toContain(`host:h${MAX_HOSTS + 99}.example`);
  });
});

describe("11: ignored resumes are reported; any session id can be stopped", () => {
  it("session list warns about a resume not signed by the key", async () => {
    initApprover(l, PASS);
    const s = `r${++seq}`;
    const { stop } = stopTarget(l, "session", s, { by: "person", reason: "", approverKey: pub() });
    appendFileSync(stopFile(l, "session", s), `${JSON.stringify({ type: "resume", id: "f", at: new Date(clock).toISOString(), stopId: stop.id, sig: "AAAA" })}\n`);
    const out = (await cli(["session", "list"])).stdout;
    expect(out).toMatch(new RegExp(`1 resume record\\(s\\) for session ${s} were ignored`));
    expect(stopChecks(l, pub()).some((c) => /were ignored/.test(c.detail))).toBe(true);
  });

  it("a session id with spaces, colons and slashes (as an agent may send) is stopped", async () => {
    const odd = "codex:abc def/ghi";
    const r = await cli(["session", "stop", odd]);
    expect(r.status, r.stderr).toBe(0);
    expect(stopView(l, odd, "codex", null).active?.target).toBe(odd);
  });
});

describe("12: hashed file names cannot collide with plain ones", () => {
  it("an id that needs hashing and a plain id that looks like the old hash get different files", () => {
    const odd = "a session id";
    const lookalike = `h-${createHash("sha256").update(odd).digest("hex").slice(0, 32)}`;
    expect(stopFile(l, "session", odd)).not.toBe(stopFile(l, "session", lookalike));
    expect(stopFile(l, "session", odd)).toMatch(/session-~[0-9a-f]{40}\.jsonl$/);
    stopTarget(l, "session", lookalike, { by: "person", reason: "", approverKey: null });
    expect(stopView(l, odd, null, null).active).toBeNull();
  });
});

describe("13: resume fields are what the signature covers", () => {
  it("include the scope, the stop, the resume's id and its time", () => {
    expect(resumeFields("agent", "s1", "r1", "2026-10-13T09:00:00.000Z")).toEqual(["agent", "s1", "r1", "2026-10-13T09:00:00.000Z"]);
  });
});
