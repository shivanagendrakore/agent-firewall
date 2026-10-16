/**
 * Spending limits (policy `caps`, rules FW-CAP and FW-CAP-WARN; docs/usage.md "Spending limits"): the
 * engine's arithmetic, the warning that fires once, the stop with what to do, the person-only raise
 * (signed, logged; forged raises and repository files raise nothing), counters that survive a restart and
 * reset at local midnight, failures counted by fingerprint, model usage through the library and the local
 * API, and no false trips on the friction corpus. Every command here is a string the engine judges.
 */
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { translateDecide, translateResult } from "../src/api/contract.js";
import { ALWAYS_FINE, TOOL_CASES, V02_FINE } from "../src/corpus.js";
import { applyCapRecord, capFailure, capFailureFingerprint, capFailureKeys, capRules, DEFAULT_CAPS, emptyCapCounts, emptyDaily, localDay, shellWord, warningShown, type CapCounts, type CapPolicy, type CapView } from "../src/engine/caps.js";
import { applyDecision, emptyCounters } from "../src/engine/counters.js";
import { decide } from "../src/engine/decide.js";
import { emptyState, foldEvents } from "../src/engine/state.js";
import { decideNative } from "../src/hook/pipeline.js";
import { runHook, trustedApproverKey, type HookEnv } from "../src/hook/claude.js";
import { defaultConfig, mergeTrusted, validatePolicy } from "../src/policy.js";
import { initApprover, signStateChange, unlockApprover } from "../src/runtime/approver.js";
import { capChecks, capStatus, dayFile, dayRaises, loadCapView, raiseCap, raisesFile, readDaily, recordDaily, resetCaps, sessionRaise } from "../src/runtime/caps.js";
import { loadPolicy } from "../src/runtime/config.js";
import { countersFile, readCounters } from "../src/runtime/counters.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { tailLog } from "../src/runtime/log.js";
import { appendEvents, loadState, sessionFile } from "../src/runtime/store.js";
import { createGuard } from "../src/sdk/guard.js";
import { memoryStore } from "../src/sdk/store.js";
import type { StateStore } from "../src/sdk/types.js";
import type { Decision, FirewallConfig } from "../src/types.js";
import { bash, ctx, spawnCli, tempHome, testRoot, WS } from "./helpers.js";

const PASS = "caps test passphrase";

function pol(over: Partial<CapPolicy> = {}): CapPolicy {
  return { ...DEFAULT_CAPS, session: { ...DEFAULT_CAPS.session }, day: { ...DEFAULT_CAPS.day }, ...over };
}

function view(o: { session?: Partial<CapCounts>; day?: Partial<CapCounts>; raise?: (scope: string, metric: string) => number } = {}): CapView {
  return { sessionId: "s1", session: { ...emptyCapCounts(), ...(o.session ?? {}) }, day: { ...emptyCapCounts(), ...(o.day ?? {}) }, raise: (s, m) => o.raise?.(s, m) ?? 0 };
}

function cfgWith(caps: Partial<CapPolicy>): FirewallConfig {
  const base = defaultConfig();
  return { ...base, caps: { ...pol(), ...caps, session: { ...DEFAULT_CAPS.session, ...(caps.session ?? {}) }, day: { ...DEFAULT_CAPS.day, ...(caps.day ?? {}) } } };
}

describe("caps: the engine", () => {
  it("under the cap nothing is said; at the cap the call is denied with what to do", () => {
    const p = pol({ session: { ...DEFAULT_CAPS.session, toolCalls: 10 } });
    expect(capRules({ policy: p, view: view({ session: { totals: { calls: 5 } } }), actionHash: "h", bytes: 0, interactive: true }).hits).toEqual([]);
    expect(capRules({ policy: p, view: view({ session: { totals: { calls: 9 } } }), actionHash: "h", bytes: 0, interactive: true }).hits.map((h) => h.rule)).toEqual(["FW-CAP-WARN"]);
    const stop = capRules({ policy: p, view: view({ session: { totals: { calls: 10 } } }), actionHash: "h", bytes: 0, interactive: true });
    expect(stop.hits.map((h) => [h.rule, h.outcome])).toEqual([["FW-CAP", "deny"]]);
    expect(stop.hits[0]?.reason).toMatch(/the limit is 10 tool calls/);
    expect(stop.hits[0]?.reason).toContain("launchsafe-firewall caps raise toolCalls 10 --session s1");
    expect(stop.record.stopped).toEqual([{ scope: "session", metric: "toolCalls", limit: 10, used: 10 }]);
  });
  it("the day cap names --today and the reset at local midnight", () => {
    const p = pol({ day: { ...DEFAULT_CAPS.day, toolCalls: 3 } });
    const stop = capRules({ policy: p, view: view({ day: { totals: { calls: 3 } } }), actionHash: "h", bytes: 0, interactive: false });
    expect(stop.hits[0]?.rule).toBe("FW-CAP");
    expect(stop.hits[0]?.reason).toContain("--today");
    expect(stop.hits[0]?.reason).toMatch(/reset at local midnight/);
  });
  it("through decide(): a stop is a deny that no stored approval covers, with every effect still reported", () => {
    const config = cfgWith({ session: { ...DEFAULT_CAPS.session, toolCalls: 1 } });
    const d = decide({ action: { tool: "Bash", input: { command: "ls" } }, state: emptyState(), config, ctx: ctx(), caps: view({ session: { totals: { calls: 1 } } }) });
    expect(d.verdict).toBe("deny");
    expect(d.rules).toEqual(["FW-CAP"]);
    expect(d.caps?.ifRuns).toEqual([{ key: "calls", amount: 1 }]);
  });
  it("the warning fires once per cap: asked when someone can answer, noted when not; a raised cap warns again near its new value", () => {
    const p = pol({ session: { ...DEFAULT_CAPS.session, toolCalls: 100 } });
    const ask = capRules({ policy: p, view: view({ session: { totals: { calls: 79 } } }), actionHash: "h", bytes: 0, interactive: true });
    expect(ask.hits.map((h) => [h.rule, h.outcome])).toEqual([["FW-CAP-WARN", "approve"]]);
    expect(ask.hits[0]?.reason).toMatch(/this session the agent has used 80 tool calls, 80% of its limit of 100/);
    expect(ask.record.warned).toEqual(["session:toolCalls@100"]);
    const note = capRules({ policy: p, view: view({ session: { totals: { calls: 79 } } }), actionHash: "h", bytes: 0, interactive: false });
    expect(note.hits.map((h) => h.outcome)).toEqual(["allow"]);
    expect(capRules({ policy: { ...p, warn: "note" }, view: view({ session: { totals: { calls: 79 } } }), actionHash: "h", bytes: 0, interactive: true }).hits.map((h) => h.outcome)).toEqual(["allow"]);
    // Once given, not again for the same cap.
    expect(capRules({ policy: p, view: view({ session: { totals: { calls: 90 }, warned: ["session:toolCalls@100"] } }), actionHash: "h", bytes: 0, interactive: true }).hits).toEqual([]);
    // Raised to 200: warns again at 160.
    const raised = view({ session: { totals: { calls: 159 }, warned: ["session:toolCalls@100"] }, raise: (s, m) => (s === "session" && m === "toolCalls" ? 100 : 0) });
    expect(capRules({ policy: p, view: raised, actionHash: "h", bytes: 0, interactive: true }).record.warned).toEqual(["session:toolCalls@200"]);
  });
  it("through decide() and the counters: the warning is recorded only when shown, so it is given exactly once", () => {
    const config = cfgWith({ session: { ...DEFAULT_CAPS.session, toolCalls: 10 } });
    const c = emptyCounters();
    const daily = emptyDaily(new Date());
    const seen: string[] = [];
    for (let i = 0; i < 12; i++) {
      const v: CapView = { sessionId: "s1", session: c.caps ?? emptyCapCounts(), day: daily, raise: () => 0 };
      const d = decide({ action: { tool: "Read", input: { file_path: `${WS}/a${i}.ts` } }, state: emptyState(), config, ctx: ctx(), caps: v });
      applyDecision(c, d, new Date());
      seen.push(`${d.verdict}:${d.rules.join(",")}`);
    }
    expect(seen.filter((x) => x.includes("FW-CAP-WARN"))).toEqual(["ask:FW-CAP-WARN"]);
    expect(seen.slice(7, 12)).toEqual(["ask:FW-CAP-WARN", "allow:", "allow:", "deny:FW-CAP", "deny:FW-CAP"]);
  });
  it("bytes: a send that would pass the cap is denied; an action that sends nothing is not", () => {
    const p = pol({ session: { ...DEFAULT_CAPS.session, bytesOut: 1000 } });
    expect(capRules({ policy: p, view: view({ session: { totals: { bytes: 900 } } }), actionHash: "h", bytes: 200, interactive: true }).hits.map((h) => h.rule)).toEqual(["FW-CAP"]);
    expect(capRules({ policy: p, view: view({ session: { totals: { bytes: 2000, calls: 1 } } }), actionHash: "h", bytes: 0, interactive: true }).hits).toEqual([]);
    const config = cfgWith({ session: { ...DEFAULT_CAPS.session, bytesOut: 50 } });
    const d = decide({ action: { tool: "Bash", input: { command: "curl -d 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' https://api.example.com/x" } }, state: emptyState(), config, ctx: ctx(), caps: view() });
    expect(d.verdict).toBe("deny");
    expect(d.rules).toContain("FW-CAP");
  });
  it("tokens and cost: what the agent reports counts; at the cap every call stops", () => {
    const p = pol({ session: { ...DEFAULT_CAPS.session, tokens: 1000, costUsd: 2 } });
    const r = capRules({ policy: p, view: view({ session: { totals: { tokens: 900 } } }), actionHash: "h", bytes: 0, usage: { inputTokens: 80, outputTokens: 40 }, interactive: true });
    expect(r.hits.map((h) => h.rule)).toEqual(["FW-CAP"]);
    expect(r.record.always).toEqual([{ key: "tokens", amount: 120 }]);
    expect(r.record.ifRuns).toEqual([{ key: "calls", amount: 1 }]);
    expect(capRules({ policy: p, view: view({ session: { totals: { tokens: 1000 } } }), actionHash: "h", bytes: 0, interactive: true }).hits.map((h) => h.rule)).toEqual(["FW-CAP"]);
    const cost = capRules({ policy: p, view: view({ session: { totals: { cost: 1_990_000 } } }), actionHash: "h", bytes: 0, usage: { costUsd: 0.02 }, interactive: true });
    expect(cost.hits[0]?.reason).toMatch(/\$1\.99 of model cost \(as the agent reported it\), and this would add \$0\.02; the limit is \$2\.00/);
    // No cap by default: nothing counted against them, nothing said.
    expect(capRules({ policy: pol(), view: view({ session: { totals: { tokens: 1e9, cost: 1e12 } } }), actionHash: "h", bytes: 0, usage: { inputTokens: 5 }, interactive: true }).hits).toEqual([]);
  });
  it("identical failures: the same action failing the same way stops at the cap; another error or action does not count", () => {
    const p = pol({ session: { ...DEFAULT_CAPS.session, identicalFailures: 3 } });
    expect(capRules({ policy: p, view: view({ session: { fails: { "h:aa": 3 } } }), actionHash: "h", bytes: 0, interactive: true }).hits.map((h) => h.rule)).toEqual(["FW-CAP"]);
    expect(capRules({ policy: p, view: view({ session: { fails: { "h:aa": 2, "h:bb": 2 } } }), actionHash: "h", bytes: 0, interactive: false }).hits.map((h) => h.rule)).toEqual([]);
    expect(capRules({ policy: p, view: view({ session: { fails: { "other:aa": 9 } } }), actionHash: "h", bytes: 0, interactive: true }).hits).toEqual([]);
  });
  it("failures are read from explicit markers only, and fingerprinted without the numbers that change", () => {
    expect(capFailure({ exitCode: 1, output: "FAIL a.test.ts:12" })).toEqual({ text: "exit 1: FAIL a.test.ts:12", status: "exit:1" });
    expect(capFailure('{"output":"boom","exitCode":2}')?.status).toBe("exit:2");
    expect(capFailure({ isError: true, content: [{ type: "text", text: "no such issue" }] })?.text).toMatch(/no such issue/);
    expect(capFailure({ exitCode: 0, output: "ok" })).toBeNull();
    expect(capFailure("Error: tests failed")).toBeNull();
    expect(capFailure({ stdout: "error error error" })).toBeNull();
    expect(capFailure("ENOENT", true)).toEqual({ text: "ENOENT", status: "failed" });
    expect(capFailureFingerprint("FAIL a.test.ts:12 in 31ms")).toBe(capFailureFingerprint("FAIL a.test.ts:14 in 2045ms"));
    expect(capFailureFingerprint("FAIL a.test.ts")).not.toBe(capFailureFingerprint("FAIL b.test.ts"));
    expect(capFailureKeys({ text: "x", status: "exit:1" })[1]).toBe("status:exit:1");
  });
  it("a native call of several actions counts once, with its parts' bytes together", () => {
    const config = cfgWith({ session: { ...DEFAULT_CAPS.session, toolCalls: 5 } });
    const native = { tool: "MultiEdit", input: { x: 1 } };
    const parts = [{ tool: "Write", input: { file_path: `${WS}/a.ts`, content: "a" } }, { tool: "Write", input: { file_path: `${WS}/b.ts`, content: "b" } }];
    const at4 = decideNative(native, parts, { state: emptyState(), config, ctx: ctx(), caps: view({ session: { totals: { calls: 4 } } }) }).d;
    expect(at4.verdict, at4.reasons.join(" ")).toBe("ask");
    expect(at4.rules).toEqual(["FW-CAP-WARN"]);
    expect(at4.caps?.ifRuns).toEqual([{ key: "calls", amount: 1 }]);
    const at5 = decideNative(native, parts, { state: emptyState(), config, ctx: ctx(), caps: view({ session: { totals: { calls: 5 } } }) }).d;
    expect(at5.verdict).toBe("deny");
    expect(at5.rules).toEqual(["FW-CAP"]);
  });
  it("localDay is the local calendar day (caps reset at local midnight)", () => {
    expect(localDay(new Date(2026, 9, 13, 23, 59, 59))).toBe("2026-10-13");
    expect(localDay(new Date(2026, 9, 14, 0, 0, 1))).toBe("2026-10-14");
  });
});

describe("caps: policy", () => {
  it("validates limits, null for no limit, warnPercent and warn", () => {
    expect(validatePolicy({ version: 3, caps: { session: { toolCalls: 10, tokens: null, costUsd: 1.5 }, warnPercent: 70, warn: "note" } }, "t").caps).toEqual({ session: { toolCalls: 10, tokens: null, costUsd: 1.5 }, warnPercent: 70, warn: "note" });
    for (const bad of [{ session: { toolCalls: 0 } }, { session: { toolCalls: 1.5 } }, { session: { calls: 1 } }, { day: { costUsd: -1 } }, { warnPercent: 100 }, { warn: "loud" }, { extra: 1 }]) expect(() => validatePolicy({ version: 3, caps: bad }, "t"), JSON.stringify(bad)).toThrow(/caps/);
  });
  it("a user policy may raise or remove a cap", () => {
    const c = mergeTrusted(defaultConfig(), validatePolicy({ version: 3, caps: { session: { toolCalls: 99999, bytesOut: null } } }, "user"));
    expect(c.caps?.session.toolCalls).toBe(99999);
    expect(c.caps?.session.bytesOut).toBeNull();
    expect(c.caps?.day.toolCalls).toBe(DEFAULT_CAPS.day.toolCalls);
  });
  it("a repository file trying to raise a cap is ignored and reported; lowering one, or setting one that had none, applies", () => {
    const home = tempHome();
    const ws = mkdtempSync(join(testRoot(), "caps-ws-"));
    const l = layout(join(home, ".launchsafe-firewall"));
    writeFileSync(join(ws, ".launchsafe-firewall.json"), JSON.stringify({ version: 3, caps: { enabled: false, warnPercent: 95, warn: "note", session: { toolCalls: 1e9, bytesOut: null, identicalFailures: 3, tokens: 5000 }, day: { costUsd: 4 } } }));
    const r = loadPolicy(l, [ws]);
    const caps = r.config.caps;
    expect(caps?.enabled).toBe(true);
    expect(caps?.warnPercent).toBe(80);
    expect(caps?.warn).toBe("ask");
    expect(caps?.session.toolCalls).toBe(DEFAULT_CAPS.session.toolCalls);
    expect(caps?.session.bytesOut).toBe(DEFAULT_CAPS.session.bytesOut);
    expect(caps?.session.identicalFailures).toBe(3);
    // Below the project floor (10000 tokens): raised to it, and reported.
    expect(caps?.session.tokens).toBe(10000);
    expect(caps?.day.costUsd).toBe(4);
    const ignored = JSON.stringify(r);
    for (const k of ["caps.enabled", "caps.warnPercent", "caps.warn", "caps.session.toolCalls", "caps.session.bytesOut", "caps.session.tokens (5000, set to 10000)"]) expect(ignored, k).toContain(k);
  });
  it("a project cannot stop the agent at its first call: every cap has a floor", () => {
    const home = tempHome();
    const ws = mkdtempSync(join(testRoot(), "caps-ws-"));
    const l = layout(join(home, ".launchsafe-firewall"));
    writeFileSync(join(ws, ".launchsafe-firewall.json"), JSON.stringify({ version: 3, caps: { session: { toolCalls: 1, bytesOut: 1, identicalFailures: 1, tokens: 1, costUsd: 0.001 }, day: { toolCalls: 1 } } }));
    const c = loadPolicy(l, [ws]).config.caps;
    expect(c?.session).toEqual({ toolCalls: 100, bytesOut: 65536, identicalFailures: 3, tokens: 10000, costUsd: 0.1 });
    expect(c?.day.toolCalls).toBe(100);
    // A person's own lower limit is kept under a project's.
    mkdirSync(l.home, { recursive: true });
    writeFileSync(l.policy, JSON.stringify({ version: 3, caps: { session: { toolCalls: 20 } } }));
    expect(loadPolicy(l, [ws]).config.caps?.session.toolCalls).toBe(20);
  });
});

// --- the hook, in a temporary home --------------------------------------------------------------------

let home: string, ws: string, l: Layout, clock: Date;

function env(o: { unattended?: boolean; now?: Date | null } = {}): HookEnv {
  return { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, home, scratchRoots: [join(home, "tmp")], ...(o.now === null ? {} : { now: o.now ?? clock }), detectNonInteractive: () => o.unattended === true, notifyDeps: { spawn: () => undefined, platform: "darwin", executable: () => true, now: () => clock.getTime() } };
}

function pre(s: string, tool: string, input: Record<string, unknown>, o: Parameters<typeof env>[0] = {}): { verdict: string; reason: string; system: string } {
  const r = runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: s, cwd: ws, permission_mode: "default", tool_name: tool, tool_input: input }), env(o));
  if (r.stdout.trim() === "") return { verdict: "allow", reason: "", system: "" };
  const j = JSON.parse(r.stdout) as { systemMessage?: string; hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
  return { verdict: j.hookSpecificOutput?.permissionDecision ?? "allow", reason: j.hookSpecificOutput?.permissionDecisionReason ?? "", system: j.systemMessage ?? "" };
}

function post(s: string, tool: string, input: Record<string, unknown>, response: unknown, o: Parameters<typeof env>[0] = {}): void {
  runHook(JSON.stringify({ hook_event_name: "PostToolUse", session_id: s, cwd: ws, tool_name: tool, tool_input: input, tool_response: response }), env(o));
}

function userPolicy(caps: unknown): void {
  mkdirSync(l.home, { recursive: true });
  writeFileSync(l.policy, JSON.stringify({ version: 3, caps }));
}

const read = (i: number): Record<string, unknown> => ({ file_path: join(ws, `f${i}.ts`) });

describe("caps: through the hook", () => {
  beforeEach(() => {
    home = tempHome("caps-home-");
    ws = mkdtempSync(join(testRoot(), "caps-ws-"));
    l = layout(join(home, ".launchsafe-firewall"));
    clock = new Date(2026, 9, 13, 10, 0, 0);
  });

  it("the warning fires once, then the stop: plain words, the session id and the command to run", () => {
    userPolicy({ session: { toolCalls: 10 } });
    const got = Array.from({ length: 12 }, (_, i) => pre("w1", "Read", read(i)));
    expect(got.map((g) => g.verdict)).toEqual(["allow", "allow", "allow", "allow", "allow", "allow", "allow", "ask", "allow", "allow", "deny", "deny"]);
    expect(got[7]?.reason).toMatch(/80%/);
    expect(got[7]?.reason).toMatch(/FW-CAP-WARN/);
    expect(got[10]?.reason).toMatch(/the limit is 10 tool calls/);
    expect(got[10]?.reason).toContain("launchsafe-firewall caps raise toolCalls 10 --session w1");
    expect(tailLog(l, 50).some((e) => e.event.type === "cap_stop" && e.event.session === "w1")).toBe(true);
  });
  it("unattended, the warning is a note (allowed, shown as a system message) and still fires once", () => {
    userPolicy({ session: { toolCalls: 10 } });
    const got = Array.from({ length: 10 }, (_, i) => pre("w2", "Read", read(i), { unattended: true }));
    expect(got.map((g) => g.verdict)).toEqual(Array(10).fill("allow"));
    expect(got.filter((g) => /% of its limit/.test(g.system)).length).toBe(1);
    expect(got[7]?.system).toMatch(/80%/);
    expect(pre("w2", "Read", read(99), { unattended: true }).verdict).toBe("deny");
  });
  it("the day cap holds across sessions and resets at local midnight", () => {
    userPolicy({ day: { toolCalls: 4 } });
    // Four calls go ahead across two sessions; the fourth reaches 80% of the day cap and asks once (FW-CAP-WARN).
    expect([0, 1].map((i) => pre("d1", "Read", read(i)).verdict)).toEqual(["allow", "allow"]);
    const d2 = [0, 1].map((i) => pre("d2", "Read", read(i)));
    expect(d2.map((x) => x.verdict)).toEqual(["allow", "ask"]);
    expect(d2[1]?.reason).toMatch(/FW-CAP-WARN/);
    const stop = pre("d3", "Read", read(9));
    expect(stop.verdict).toBe("deny");
    expect(stop.reason).toContain("--today");
    clock = new Date(2026, 9, 13, 23, 59, 0);
    expect(pre("d3", "Read", read(9)).verdict).toBe("deny");
    clock = new Date(2026, 9, 14, 0, 0, 30);
    expect(pre("d3", "Read", read(9)).verdict).toBe("allow");
    expect(readDaily(l, clock).daily.day).toBe("2026-10-14");
  });
  it("caps survive a restart: counters are files, and a new process meets the same stop", () => {
    userPolicy({ session: { toolCalls: 3 } });
    // Three calls go ahead; the third reaches 80% of the cap and asks once (FW-CAP-WARN).
    expect([0, 1, 2].map((i) => pre("r1", "Read", read(i), { now: null }).verdict)).toEqual(["allow", "allow", "ask"]);
    expect(readCounters(l, "r1").counters.caps?.totals.calls).toBe(3);
    const event = JSON.stringify({ hook_event_name: "PreToolUse", session_id: "r1", cwd: ws, permission_mode: "default", tool_name: "Read", tool_input: read(7) });
    const r = spawnCli(["hook"], { home, input: event, cwd: ws, env: { CLAUDE_PROJECT_DIR: ws } });
    expect(r.status).toBe(0);
    const j = JSON.parse(r.stdout) as { hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string } };
    expect(j.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(j.hookSpecificOutput.permissionDecisionReason).toMatch(/FW-CAP/);
  });
  it("a person's signed raise lets the agent go on, and is in the decision log; a forged raise counts for nothing", () => {
    userPolicy({ session: { toolCalls: 2 }, day: { toolCalls: 3 } });
    initApprover(l, PASS);
    const priv = unlockApprover(l, PASS);
    const sign = (subject: string, fields: readonly string[]): string => signStateChange(priv, "budget-raise", subject, fields);
    pre("p1", "Read", read(0));
    pre("p1", "Read", read(1));
    expect(pre("p1", "Read", read(2)).verdict).toBe("deny");
    // Forged: an unsigned budget_raise line makes the session untrusted and raises nothing.
    appendEvents(l, "p1", [{ type: "budget_raise", key: "cap:session:toolCalls", amount: 100, id: "cforged", sig: "Zm9yZ2Vk" }]);
    expect(pre("p1", "Read", read(3)).verdict).toBe("deny");
    expect(loadState(l, "p1", trustedApproverKey(l, {})).tainted).toBe(true);
    const id = raiseCap(l, { scope: "session", metric: "toolCalls", amount: 1, session: "p1" }, sign, clock);
    expect(tailLog(l, 50).some((e) => e.event.type === "cap_raise" && e.event.id === id && typeof e.event.sig === "string")).toBe(true);
    // The raised call goes ahead; it is the day's third call, 80% of the day cap of 3, so it asks once (FW-CAP-WARN).
    const raised = pre("p1", "Read", read(4));
    expect(raised.verdict).toBe("ask");
    expect(raised.reason).toMatch(/FW-CAP-WARN/);
    expect(raised.reason).not.toMatch(/\(rule [^)]*FW-CAP[,)]/);
    // The day cap (3) is reached by p1's three calls that ran; a forged day line raises nothing, a signed one does.
    expect(pre("p2", "Read", read(0)).verdict).toBe("deny");
    appendFileSync(raisesFile(l), `${JSON.stringify({ day: localDay(clock), metric: "toolCalls", amount: 50, id: "cx", sig: "Zm9yZ2Vk" })}\n`);
    expect(pre("p2", "Read", read(1)).verdict).toBe("deny");
    raiseCap(l, { scope: "day", metric: "toolCalls", amount: 10 }, sign, clock);
    expect(pre("p2", "Read", read(2)).verdict).toBe("allow");
    // A day raise lapses at local midnight with the day's counters.
    const next = new Date(2026, 9, 14, 9, 0, 0);
    expect(loadCapView(l, "p2", loadState(l, "p2", trustedApproverKey(l, {})), next, trustedApproverKey(l, {})).raise("day", "toolCalls")).toBe(0);
    expect(capStatus(l, loadPolicy(l, [ws]).config, null, trustedApproverKey(l, {}), clock).text).toMatch(/toolCalls\s+4 of 13 \(raised by 10\)/);
  });
  it("raiseCap refuses what is not a cap or not an amount", () => {
    const sign = (): string => "sig";
    expect(() => raiseCap(l, { scope: "day", metric: "everything" as never, amount: 1 }, sign)).toThrow(/not a cap/);
    expect(() => raiseCap(l, { scope: "day", metric: "toolCalls", amount: 1.5 }, sign)).toThrow(/whole number/);
    expect(() => raiseCap(l, { scope: "day", metric: "toolCalls", amount: -1 }, sign)).toThrow(/whole number/);
    expect(() => raiseCap(l, { scope: "session", metric: "toolCalls", amount: 1 }, sign)).toThrow(/names the session/);
  });
  it("the agent cannot raise a cap or reset the counters (FW-TAMPER); reading them is fine", () => {
    const fw = "/Users/dev/.launchsafe-firewall";
    for (const c of ["launchsafe-firewall caps raise toolCalls 100000 --today", "launchsafe-firewall caps raise costUsd 50 --session s1", `rm ${fw}/caps/day.json`, `echo '{}' > ${fw}/caps/day.json`, `echo x >> ${fw}/caps/raises.jsonl`]) {
      const d = bash(c);
      expect(d.verdict, c).toBe("deny");
      expect(d.rules, c).toContain("FW-TAMPER");
    }
    expect(bash("launchsafe-firewall caps").verdict).not.toBe("deny");
    expect(bash("launchsafe-firewall caps show --json").verdict).not.toBe("deny");
  });
  it("caps raise runs only for a person at a terminal, and checks its arguments first", () => {
    expect(spawnCli(["caps", "raise", "everything", "5", "--today"]).status).toBe(64);
    expect(spawnCli(["caps", "raise", "toolCalls", "1.5", "--today"]).status).toBe(64);
    expect(spawnCli(["caps", "raise", "toolCalls", "5"]).status).toBe(64);
    expect(spawnCli(["caps", "raise", "toolCalls", "5", "--today", "--session", "s"]).status).toBe(64);
    const r = spawnCli(["caps", "raise", "toolCalls", "5", "--today"]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("interactive terminal");
    const show = spawnCli(["caps", "--json"]);
    expect(show.status).toBe(0);
    expect((JSON.parse(show.stdout) as { day: { caps: { toolCalls: { limit: number } } } }).day.caps.toolCalls.limit).toBe(DEFAULT_CAPS.day.toolCalls);
  });
  it("identical failures through the hook: the same error again and again stops that action; another error does not count", () => {
    userPolicy({ session: { identicalFailures: 3 } });
    const cmd = { command: "npm test" };
    for (let i = 0; i < 3; i++) {
      expect(pre("f1", "Bash", cmd).verdict).not.toBe("deny");
      post("f1", "Bash", cmd, { exitCode: 1, output: `FAIL src/a.test.ts:${10 + i} expected 1 got 2 (${100 + i}ms)` });
    }
    const stop = pre("f1", "Bash", cmd);
    expect(stop.verdict).toBe("deny");
    expect(stop.reason).toMatch(/failed the same way 3 times/);
    // Another session, different errors each time: never the same failure three times.
    for (let i = 0; i < 5; i++) {
      expect(pre("f2", "Bash", cmd).verdict).not.toBe("deny");
      post("f2", "Bash", cmd, { exitCode: 1, output: `FAIL src/${"abcde"[i]}.test.ts` });
    }
    // A plain successful output never counts.
    for (let i = 0; i < 5; i++) post("f3", "Bash", cmd, "error: something printed but the tool succeeded");
    expect(pre("f3", "Bash", cmd).verdict).not.toBe("deny");
  });
  it("fail closed: a corrupt day file denies every call, is never overwritten, and only caps reset starts it again", () => {
    userPolicy({ day: { toolCalls: 100 } });
    mkdirSync(join(l.home, "caps"), { recursive: true });
    writeFileSync(dayFile(l), "{ not json");
    const r = pre("c1", "Read", read(0));
    expect(r.verdict).toBe("deny");
    expect(r.reason).toContain("launchsafe-firewall caps reset --today");
    expect(readFileSync(dayFile(l), "utf8")).toBe("{ not json");
    expect(capChecks(l).map((c) => c.detail).join(" ")).toMatch(/every tool call is denied until you run launchsafe-firewall caps reset --today/);
    resetCaps(l, { scope: "day" }, clock);
    expect(pre("c1", "Read", read(1)).verdict).toBe("allow");
    expect(tailLog(l, 20).some((e) => e.event.type === "cap_reset")).toBe(true);
  });
  it("fail closed: a day file that is a directory or a symlink loop denies every call", () => {
    userPolicy({});
    mkdirSync(dayFile(l), { recursive: true });
    expect(pre("c2", "Read", read(0)).verdict).toBe("deny");
    resetCaps(l, { scope: "day" }, clock);
    expect(pre("c2", "Read", read(1)).verdict).toBe("allow");
    rmSync(dayFile(l));
    symlinkSync(dayFile(l), dayFile(l));
    expect(pre("c2", "Read", read(2)).verdict).toBe("deny");
  });
  it("fail closed: corrupt session counters deny the session's calls, also after the budgets start them again, until caps reset", () => {
    userPolicy({});
    pre("c3", "Read", read(0));
    writeFileSync(countersFile(l, "c3"), "{ not json");
    const r = pre("c3", "Read", read(1));
    expect(r.verdict).toBe("deny");
    expect(r.reason).toContain("launchsafe-firewall caps reset --session c3");
    // An egress makes the budgets start their counters again; the caps stay reached.
    expect(pre("c3", "Bash", { command: "curl https://example.com/x" }).verdict).toBe("deny");
    expect(readCounters(l, "c3").counters.capsDamagedAt).toBeDefined();
    expect(pre("c3", "Read", read(2)).verdict).toBe("deny");
    // Other sessions are not affected.
    expect(pre("c4", "Read", read(0)).verdict).toBe("allow");
    resetCaps(l, { scope: "session", session: "c3" }, clock);
    expect(pre("c3", "Read", read(3)).verdict).toBe("allow");
    // A directory where the counters file should be: the same.
    rmSync(countersFile(l, "c4"), { force: true });
    mkdirSync(countersFile(l, "c4"));
    expect(pre("c4", "Read", read(1)).verdict).toBe("deny");
  });
  it("a day never goes backwards: a clock set back keeps the later day's counters", () => {
    userPolicy({ day: { toolCalls: 2 } });
    pre("m1", "Read", read(0));
    pre("m1", "Read", read(1));
    expect(pre("m1", "Read", read(2)).verdict).toBe("deny");
    clock = new Date(2026, 9, 12, 10, 0, 0);
    expect(pre("m1", "Read", read(3)).verdict).toBe("deny");
    expect(readDaily(l, clock).daily.day).toBe("2026-10-13");
  });
  it("raises count once by id: a replayed session event or day line raises nothing more; a day line from another firewall home raises nothing", () => {
    userPolicy({ session: { toolCalls: 2 }, day: { toolCalls: 100 } });
    initApprover(l, PASS);
    const priv = unlockApprover(l, PASS);
    const sign = (subject: string, fields: readonly string[]): string => signStateChange(priv, "budget-raise", subject, fields);
    raiseCap(l, { scope: "session", metric: "toolCalls", amount: 1, session: "rp" }, sign, clock);
    const ev = readFileSync(sessionFile(l, "rp"), "utf8").trim().split("\n").filter((x) => x.includes("budget_raise"));
    appendFileSync(sessionFile(l, "rp"), `${ev[0]}\n${ev[0]}\n`);
    const key = trustedApproverKey(l, {});
    expect(sessionRaise(loadState(l, "rp", key), "toolCalls")).toBe(1);
    raiseCap(l, { scope: "day", metric: "toolCalls", amount: 5 }, sign, clock);
    const line = readFileSync(raisesFile(l), "utf8").trim();
    appendFileSync(raisesFile(l), `${line}\n${line}\n`);
    expect(dayRaises(l, key, localDay(clock)).get("toolCalls")).toBe(5);
    // The same line in another home (same key) does not verify there.
    const other = layout(join(tempHome(), ".launchsafe-firewall"));
    mkdirSync(join(other.home, "caps"), { recursive: true });
    writeFileSync(raisesFile(other), `${line}\n`);
    expect(dayRaises(other, key, localDay(clock)).get("toolCalls")).toBeUndefined();
  });
  it("identical failures with changing output still stop at three times the limit, by exit status", () => {
    userPolicy({ session: { identicalFailures: 2 } });
    const cmd = { command: "npm test" };
    for (let i = 0; i < 6; i++) {
      expect(pre("v1", "Bash", cmd).verdict, `run ${i}`).not.toBe("deny");
      post("v1", "Bash", cmd, { exitCode: 1, output: `FAIL ${"abcdef"[i]}-random-word` });
    }
    expect(pre("v1", "Bash", cmd).verdict).toBe("deny");
  });
  it("the suggested command quotes a session id that is not a plain word", () => {
    expect(shellWord("abc-123")).toBe("abc-123");
    expect(shellWord("x; rm -rf ~")).toBe("'x; rm -rf ~'");
    expect(shellWord("it's")).toBe(`'it'\\''s'`);
    expect(shellWord("a\u001b[31mb")).toBe("'a[31mb'");
    const r = capRules({ policy: pol({ session: { ...DEFAULT_CAPS.session, toolCalls: 1 } }), view: { ...view({ session: { totals: { calls: 1 } } }), sessionId: "s $(id)" }, actionHash: "h", bytes: 0, interactive: true });
    expect(r.hits[0]?.reason).toContain("--session 's $(id)'");
  });
  it("concurrency: calls decided at the same moment can pass a limit by the calls in flight, and the next call is denied", () => {
    const config = cfgWith({ session: { ...DEFAULT_CAPS.session, toolCalls: 3 }, warn: "note" });
    const c = emptyCounters();
    applyDecision(c, decide({ action: { tool: "Read", input: { file_path: `${WS}/a` } }, state: emptyState(), config, ctx: ctx(), caps: view() }), new Date());
    applyDecision(c, decide({ action: { tool: "Read", input: { file_path: `${WS}/b` } }, state: emptyState(), config, ctx: ctx(), caps: view({ session: { totals: { calls: 1 } } }) }), new Date());
    // Two parallel calls both read 2 so far.
    const seen: CapView = { ...view(), session: structuredClone(c.caps ?? emptyCapCounts()) };
    const p1 = decide({ action: { tool: "Read", input: { file_path: `${WS}/c` } }, state: emptyState(), config, ctx: ctx(), caps: seen });
    const p2 = decide({ action: { tool: "Read", input: { file_path: `${WS}/d` } }, state: emptyState(), config, ctx: ctx(), caps: seen });
    expect([p1.verdict, p2.verdict]).toEqual(["allow", "allow"]);
    applyDecision(c, p1, new Date());
    applyDecision(c, p2, new Date());
    expect(c.caps?.totals.calls).toBe(4);
    expect(decide({ action: { tool: "Read", input: { file_path: `${WS}/e` } }, state: emptyState(), config, ctx: ctx(), caps: { ...view(), session: c.caps ?? emptyCapCounts() } }).verdict).toBe("deny");
  });
  it("tamper: the agent cannot copy over, move, edit, link or write the counters and raises", () => {
    const fw = "/Users/dev/.launchsafe-firewall";
    const files = [`${fw}/caps/day.json`, `${fw}/caps/raises.jsonl`, `${fw}/sessions/s1.counters.json`];
    for (const f of files) {
      for (const c of [`cp /tmp/x ${f}`, `mv /tmp/x ${f}`, `sed -i 's/1/0/' ${f}`, `python3 -c "open('${f}','w').write('{}')"`, `echo '{}' | tee ${f}`, `ln -sf /tmp/x ${f}`]) {
        const d = bash(c);
        expect(d.verdict, c).toBe("deny");
        expect(d.rules, c).toContain("FW-TAMPER");
      }
    }
    expect(bash("launchsafe-firewall caps reset --today").rules).toContain("FW-TAMPER");
  });
});

describe("caps: model usage through the library and the local API", () => {
  it("the library counts reported tokens and cost and stops at the cap", () => {
    const g = createGuard({ policy: { caps: { session: { tokens: 1000, costUsd: 1 } } }, store: memoryStore() });
    expect(g.decide({ tool: "Read", input: { file_path: "/w/a" }, usage: { inputTokens: 500, outputTokens: 300, costUsd: 0.5 } }).verdict).toBe("ask");
    const stop = g.decide({ tool: "Read", input: { file_path: "/w/b" }, usage: { inputTokens: 150, outputTokens: 100 } });
    expect(stop.verdict).toBe("deny");
    expect(stop.rules).toEqual(["FW-CAP"]);
    expect(stop.message).toMatch(/model tokens/);
    const g2 = createGuard({ policy: { caps: { session: { costUsd: 1 } } }, store: memoryStore() });
    expect(g2.decide({ tool: "Read", input: { file_path: "/w/a" }, usage: { costUsd: 1.01 } }).verdict).toBe("deny");
  });
  it("the library counts failures the host reports, by their error", () => {
    const g = createGuard({ policy: { caps: { session: { identicalFailures: 2 } } }, store: memoryStore(), attended: false });
    const call = { tool: "Read", input: { file_path: "/w/a" } };
    for (let i = 0; i < 2; i++) {
      expect(g.decide(call).verdict).not.toBe("deny");
      g.recordResult(call, `ENOENT: no such file, open '/w/a' (attempt ${i})`, { failed: true });
    }
    expect(g.decide(call).verdict).toBe("deny");
    expect(g.decide({ tool: "Read", input: { file_path: "/w/b" } }).verdict).not.toBe("deny");
  });
  it("usage that is not whole token counts and a finite cost is denied, read-only or not, never counted as zero", () => {
    const g = createGuard({ store: memoryStore() });
    for (const usage of [{ inputTokens: Number.POSITIVE_INFINITY }, { outputTokens: 1e13 }, { costUsd: Number.NaN }, { costUsd: Number.POSITIVE_INFINITY }, { inputTokens: -5 }, { inputTokens: 1.5 }]) {
      const d = g.decide({ tool: "Read", input: { file_path: "/w/a" }, usage });
      expect(d.verdict, JSON.stringify(usage)).toBe("deny");
      expect(d.message).toMatch(/usage/);
    }
    const r = capRules({ policy: pol(), view: view(), actionHash: "h", bytes: 0, usage: { costUsd: Number.POSITIVE_INFINITY }, interactive: true });
    expect(r.hits.map((h) => [h.rule, h.outcome])).toEqual([["FW-CAP", "deny"]]);
    expect(r.record.always).toEqual([]);
  });
  it("the library fails closed when the day's counters cannot be written, and warns when its store cannot hold caps", () => {
    const base = memoryStore();
    const broken = { ...base, recordCaps: () => { throw new Error("disk full"); } };
    const d = createGuard({ store: broken, onLogError: () => undefined }).decide({ tool: "Read", input: { file_path: "/w/a" } });
    expect(d.verdict).toBe("deny");
    expect(d.rules).toEqual(["FW-CAP"]);
    const warned: string[] = [];
    const { capView: _drop, ...rest } = memoryStore();
    void _drop;
    // capView is required; a JavaScript store without it cannot count the limits, so every call is denied.
    const noCaps = rest as unknown as StateStore;
    const g = createGuard({ store: noCaps, onLogError: (m) => warned.push(m) });
    expect(warned.join(" ")).toMatch(/no capView, so they cannot be counted and every call is denied/);
    expect(g.decide({ tool: "Read", input: { file_path: "/w/a" } }).verdict).toBe("deny");
    createGuard({ store: noCaps, policy: { caps: { enabled: false } }, onLogError: (m) => warned.push(m) });
    expect(warned.length).toBe(1);
  });
  it("the local API reads usage and failed strictly", () => {
    const ok = translateDecide({ session: "s", action: { format: "engine", tool: "Read", input: { file_path: "/a" } }, usage: { inputTokens: 10, outputTokens: 5, costUsd: 0.001 } }, []);
    expect(ok.ok && ok.call.usage).toEqual({ inputTokens: 10, outputTokens: 5, costUsd: 0.001 });
    for (const usage of [{ inputTokens: -1 }, { inputTokens: 1.5 }, { costUsd: "1" }, { tokens: 5 }, [], "x"]) expect(translateDecide({ session: "s", action: { format: "engine", tool: "Read", input: {} }, usage }, []).ok, JSON.stringify(usage)).toBe(false);
    expect(translateResult({ session: "s", decisionId: "d", output: "x", failed: true })).toEqual({ ok: true, session: "s", decisionId: "d", output: "x", failed: true });
    expect(translateResult({ session: "s", decisionId: "d", output: "x", failed: "yes" }).ok).toBe(false);
  });
});

describe("caps: no false trips on normal work", () => {
  it("the friction corpus, five times over, trusted and then untrusted, with one day's counters shared: no warning, no stop", () => {
    const cfg = defaultConfig();
    const tainted = foldEvents([{ type: "taint", source: "read a web page" }]);
    const fill = (v: unknown): unknown => (typeof v === "string" ? v.replaceAll("{WS}", WS) : typeof v === "object" && v !== null ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x)])) : v);
    const work: [string, Record<string, unknown>][] = [...ALWAYS_FINE.map((c): [string, Record<string, unknown>] => ["Bash", { command: c }]), ...TOOL_CASES.map((c): [string, Record<string, unknown>] => [c.tool, fill(c.input) as Record<string, unknown>]), ...V02_FINE.map((c): [string, Record<string, unknown>] => ["Bash", { command: c }])];
    const daily = emptyDaily(new Date(2026, 9, 13, 9, 0, 0));
    const bad: string[] = [];
    let clockMs = new Date(2026, 9, 13, 9, 0, 0).getTime();
    for (const [label, st] of [["trusted", emptyState()], ["untrusted", tainted]] as const) {
      const c = emptyCounters();
      for (let pass = 0; pass < 5; pass++) {
        for (const [tool, input] of work) {
          const now = new Date((clockMs += 2000));
          const d: Decision = decide({ action: { tool, input }, state: st, config: cfg, ctx: ctx(), caps: { sessionId: label, session: c.caps ?? emptyCapCounts(), day: daily, raise: () => 0 } });
          applyDecision(c, d, now);
          applyCapRecord(daily, d.caps ?? { always: [], ifRuns: [], warned: [], stopped: [] }, d.verdict === "allow" || d.verdict === "ask", warningShown(d.rules), "day");
          if (d.rules.some((r) => r.startsWith("FW-CAP"))) bad.push(`${tool} ${JSON.stringify(input).slice(0, 60)} (${label} pass ${pass + 1}): ${d.verdict} ${d.rules.join(",")}`);
        }
      }
    }
    expect(bad).toEqual([]);
    expect(daily.totals.calls).toBe(work.length * 10);
  });
  it("the hook records the day counters the same way (recordDaily on a real file)", () => {
    const h = tempHome();
    const lay = layout(join(h, ".launchsafe-firewall"));
    const now = new Date(2026, 9, 13, 12, 0, 0);
    const d = decide({ action: { tool: "Read", input: { file_path: `${WS}/a.ts` } }, state: emptyState(), config: defaultConfig(), ctx: ctx(), caps: view() });
    recordDaily(lay, d, now);
    recordDaily(lay, d, now);
    expect(existsSync(dayFile(lay))).toBe(true);
    expect(readDaily(lay, now).daily.totals.calls).toBe(2);
  });
});

