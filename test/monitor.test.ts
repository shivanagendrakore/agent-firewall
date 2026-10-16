/**
 * The behaviour monitor: FW-LOOP's counters with stop limits (src/engine/budgets.ts monitorCheck). Engine
 * units with a stubbed view, the policy key (defaults in policy, a project may only lower them), the real
 * hook in a temporary home (the stop is recorded, logged, notified with its reason, and a person's resume
 * restarts the count), the library, and the friction corpus: normal sessions never trip it.
 */
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { main } from "../src/climain.js";
import { ALWAYS_FINE, TOOL_CASES, TRUSTED_ONLY, V02_FINE } from "../src/corpus.js";
import { decide } from "../src/engine/decide.js";
import { budgetPolicy, DEFAULT_BUDGETS, type BudgetView } from "../src/engine/budgets.js";
import { applyDecision, budgetView, emptyCounters } from "../src/engine/counters.js";
import { emptyState, foldEvents } from "../src/engine/state.js";
import { runHook, type HookEnv } from "../src/hook/claude.js";
import { defaultConfig, mergeTighten, mergeTrusted, validatePolicy } from "../src/policy.js";
import { initApprover } from "../src/runtime/approver.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { tailLog, verifyLog } from "../src/runtime/log.js";
import { notificationText } from "../src/runtime/notify.js";
import { stopFile, stopTarget, stopView } from "../src/runtime/stops.js";
import { createGuard, memoryStore } from "../src/sdk/index.js";
import { fileStore } from "../src/sdk/node.js";
import type { Decision, FirewallConfig } from "../src/types.js";
import { ctx, explain, state, TAINTED, tempHome, testRoot, WS } from "./helpers.js";

function view(win: Record<string, number> = {}, total: Record<string, number> = {}): BudgetView & { since: (number | undefined)[] } {
  const since: (number | undefined)[] = [];
  return { since, corrupt: false, total: (k) => total[k] ?? 0, window: (k, _m, s) => (since.push(s), win[k] ?? 0), repeats: () => 0, allowance: () => 0 };
}

function d(tool: string, input: Record<string, unknown>, v: BudgetView, o: { tainted?: boolean; config?: FirewallConfig; resumedAt?: number } = {}): Decision {
  return decide({ action: { tool, input }, state: state(o.tainted === true ? TAINTED : []), config: o.config ?? defaultConfig(), ctx: ctx(), budgets: v, sessionId: "s1", ...(o.resumedAt !== undefined ? { stop: { active: null, resumedAt: o.resumedAt } } : {}) });
}

const SETTINGS = { file_path: `${WS}/.claude/settings.json`, content: "{}" };

describe("monitor: the engine", () => {
  it("the defaults are in policy and above FW-LOOP's asking limits", () => {
    expect(DEFAULT_BUDGETS.loop).toEqual({ sameAction10m: 8, nonAllow10m: 25, stopNonAllow10m: 60, stopNewHosts10m: 40, stopConfigTouches10m: 20, stopSameFailure10m: 20 });
    expect(defaultConfig().budgets.loop.stopConfigTouches10m).toBe(20);
  });

  it("config touches: the 20th attempt in 10 minutes to change agent settings stops the session (FW-STOPPED)", () => {
    const below = d("Write", SETTINGS, view({ "watch:config": 18 }));
    expect(below.stop, explain(below)).toBeUndefined();
    const x = d("Write", SETTINGS, view({ "watch:config": 19 }));
    expect(x.verdict, explain(x)).toBe("deny");
    expect(x.rules).toEqual(["FW-STOPPED"]);
    expect(x.stop?.signal).toBe("config");
    expect(x.reasons[0]).toMatch(/the behaviour monitor stopped this session: it tried to change the agent's configuration.*\(20 attempts .* in 10 minutes; the limit is 20\)/);
    expect(x.reasons[0]).toMatch(/launchsafe-firewall session resume s1/);
  });

  it("fires only on an action that adds to the count it crosses: a read never stops a session", () => {
    const v = view({ "watch:config": 500, "watch:newhost": 500, "verdict:nonallow": 500 });
    const r = d("Read", { file_path: `${WS}/src/a.ts` }, v);
    expect(r.verdict, explain(r)).toBe("allow");
    expect(r.stop).toBeUndefined();
  });

  it("new hosts: the 40th host contacted for the first time in 10 minutes", () => {
    const fresh = d("WebFetch", { url: "https://h40.example.org/", prompt: "x" }, view({ "watch:newhost": 39 }));
    expect(fresh.stop?.signal, explain(fresh)).toBe("newhosts");
    // A host the session already tried is not new.
    const known = d("WebFetch", { url: "https://h40.example.org/", prompt: "x" }, view({ "watch:newhost": 39 }, { "host:h40.example.org": 1 }));
    expect(known.stop, explain(known)).toBeUndefined();
    // Package registries reached by an install are exempt, as for budgets.
    const npm = d("Bash", { command: "npm install" }, view({ "watch:newhost": 39 }));
    expect(npm.stop, explain(npm)).toBeUndefined();
  });

  it("repeated identical failures: the 20th block of the same action in 10 minutes", () => {
    const cmd = { command: "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/" };
    const first = d("Bash", cmd, view());
    expect(first.verdict, explain(first)).toBe("deny");
    const x = d("Bash", cmd, view({ [`fail:${first.counterKey ?? first.actionHash}`]: 19 }));
    expect(x.stop?.signal, explain(x)).toBe("failures");
    // Another action's failures do not count toward this one.
    expect(d("Bash", cmd, view({ "fail:0000": 19 })).stop).toBeUndefined();
  });

  it("non-allowed verdicts: the 60th action in 10 minutes that needed a person or was blocked", () => {
    const x = d("Bash", { command: "git push origin main" }, view({ "verdict:nonallow": 59 }), { tainted: true });
    expect(x.stop?.signal, explain(x)).toBe("nonallow");
    // Below the limit nothing stops (FW-LOOP itself asks from 25).
    const below = d("Bash", { command: "git push origin main" }, view({ "verdict:nonallow": 40 }), { tainted: true });
    expect(below.verdict, explain(below)).toBe("ask");
    expect(below.stop).toBeUndefined();
  });

  it("counts only after the last resume", () => {
    const v = view({ "watch:config": 19 });
    d("Write", SETTINGS, v, { resumedAt: 1234567 });
    expect(v.since).toContain(1234567);
    const c = emptyCounters();
    const t0 = Date.UTC(2026, 9, 13, 9, 0, 0);
    const dd = d("Write", SETTINGS, view());
    for (let i = 0; i < 10; i++) applyDecision(c, dd, new Date(t0 + i * 1000));
    const bv = budgetView(c, false, emptyState(), new Date(t0 + 5 * 60000));
    expect(bv.recent?.("watch:config")).toBe(10);
    expect(bv.recent?.("watch:config", t0 + 2 * 60000)).toBe(0);
  });

  it("an approval never overrides a stop in force", () => {
    const input = { action: { tool: "Bash", input: { command: "git push" } }, config: defaultConfig(), ctx: ctx() };
    const hash = decide({ ...input, state: emptyState() }).actionHash;
    const approved = foldEvents([{ type: "approval", actionHash: hash, id: "q1" }]);
    const x = decide({ ...input, state: approved, stop: { active: { id: "s", at: "2026-10-13T09:00:00.000Z", by: "person", scope: "session", target: "s1", reason: "" } } });
    expect(x.verdict).toBe("deny");
    expect(x.rules).toEqual(["FW-STOPPED"]);
    expect(x.events.some((e) => e.type === "approval_used")).toBe(false);
    expect(x.budget).toBeUndefined();
  });

  it("switched off with budgets (user or managed policy only)", () => {
    const off = mergeTrusted(defaultConfig(), validatePolicy({ version: 3, budgets: { enabled: false } }, "user"));
    expect(d("Write", SETTINGS, view({ "watch:config": 1000 }), { config: off }).stop).toBeUndefined();
  });
});

describe("monitor: the policy key (tighten-only from a project)", () => {
  it("validates the stop limits", () => {
    expect(validatePolicy({ version: 3, budgets: { loop: { stopNewHosts10m: 10 } } }, "p")).toEqual({ budgets: { loop: { stopNewHosts10m: 10 } } });
    expect(() => validatePolicy({ version: 3, budgets: { loop: { stopNewHosts10m: 0 } } }, "p")).toThrow(/stopNewHosts10m/);
  });

  it("a project file may lower a limit but never raise one; the raise is reported as ignored", () => {
    const { config, ignored } = mergeTighten(defaultConfig(), validatePolicy({ version: 3, budgets: { loop: { stopConfigTouches10m: 12, stopNewHosts10m: 100000, stopNonAllow10m: 100000, stopSameFailure10m: 100000 } } }, "project"));
    expect(budgetPolicy(config).loop.stopConfigTouches10m).toBe(12);
    expect(budgetPolicy(config).loop.stopNewHosts10m).toBe(40);
    expect(budgetPolicy(config).loop.stopNonAllow10m).toBe(60);
    expect(budgetPolicy(config).loop.stopSameFailure10m).toBe(20);
    expect(ignored.join(" ")).toMatch(/budgets\.loop\.stopNewHosts10m.*budgets\.loop\.stopNonAllow10m.*budgets\.loop\.stopSameFailure10m/);
    expect(ignored.join(" ")).toMatch(/a project may only lower budgets/);
  });

  it("a project file may not switch the monitor off with budgets.enabled", () => {
    const { config, ignored } = mergeTighten(defaultConfig(), validatePolicy({ version: 3, budgets: { enabled: false } }, "project"));
    expect(budgetPolicy(config).enabled).toBe(true);
    expect(ignored.join(" ")).toMatch(/budgets\.enabled/);
  });

  it("the user's own policy may raise a limit", () => {
    const c = mergeTrusted(defaultConfig(), validatePolicy({ version: 3, budgets: { loop: { stopNewHosts10m: 200 } } }, "user"));
    expect(budgetPolicy(c).loop.stopNewHosts10m).toBe(200);
  });
});

describe("monitor: normal sessions never trip it (the friction corpus)", () => {
  it("every normal task five times over, trusted and untrusted, with the counters kept: no stop", () => {
    const cfg = defaultConfig();
    const fill = (v: unknown): unknown => (typeof v === "string" ? v.replaceAll("{WS}", WS) : typeof v === "object" && v !== null ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x)])) : v);
    const work: [string, Record<string, unknown>][] = [...ALWAYS_FINE.map((c): [string, Record<string, unknown>] => ["Bash", { command: c }]), ...TOOL_CASES.map((c): [string, Record<string, unknown>] => [c.tool, fill(c.input) as Record<string, unknown>]), ...V02_FINE.map((c): [string, Record<string, unknown>] => ["Bash", { command: c }])];
    // Network, install and deploy work is normal in a trusted session (it asks once the session is untrusted).
    const trustedWork: [string, Record<string, unknown>][] = [...work, ...TRUSTED_ONLY.map((c): [string, Record<string, unknown>] => ["Bash", { command: c }])];
    let watched = 0;
    for (const [st, list] of [[emptyState(), trustedWork], [foldEvents(TAINTED), work]] as const) {
      const counters = emptyCounters();
      let clock = Date.UTC(2026, 9, 10, 9, 0, 0);
      for (let pass = 0; pass < 5; pass++) {
        for (const [tool, input] of list) {
          const now = new Date((clock += 2000));
          const x = decide({ action: { tool, input }, state: st, config: cfg, ctx: ctx(), budgets: budgetView(counters, false, st, now), sessionId: "friction" });
          applyDecision(counters, x, now);
          if ((x.budget?.watch?.hosts.length ?? 0) > 0 || x.budget?.watch?.config === true) watched++;
          expect(x.stop, `${tool} ${JSON.stringify(input).slice(0, 100)} pass ${pass + 1}`).toBeUndefined();
          expect(x.rules).not.toContain("FW-STOPPED");
        }
      }
    }
    // The corpus does reach the monitor's counters (it is not vacuous).
    expect(watched).toBeGreaterThan(0);
  });
});

// --- through the real hook -----------------------------------------------------------------------

let home: string, ws: string, l: Layout, clock: number, spawns: string[], seq = 0;

beforeEach(() => {
  home = tempHome("monitor-home-");
  ws = mkdtempSync(join(testRoot(), "monitor-ws-"));
  mkdirSync(join(ws, "src"), { recursive: true });
  writeFileSync(join(ws, "src", "a.ts"), "export const a = 1;\n");
  l = layout(join(home, ".launchsafe-firewall"));
  clock = Date.UTC(2026, 9, 13, 9, 0, 0);
  spawns = [];
});

function env(): HookEnv {
  return { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, home, scratchRoots: [join(home, "tmp")], now: new Date(clock), detectNonInteractive: () => false, notifyDeps: { spawn: (_c, args) => void spawns.push(args[args.length - 1] ?? ""), platform: "darwin", executable: () => true, now: () => clock } };
}

function pre(s: string, tool: string, input: Record<string, unknown>): { verdict: string; reason: string } {
  const r = runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: s, cwd: ws, permission_mode: "default", tool_name: tool, tool_input: input }), env());
  if (r.stdout.trim() === "") return { verdict: "allow", reason: "" };
  const o = JSON.parse(r.stdout) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
  return { verdict: o.hookSpecificOutput?.permissionDecision ?? "allow", reason: o.hookSpecificOutput?.permissionDecisionReason ?? "" };
}

describe("monitor: through the hook", () => {
  it("stops the session, records and logs it, notifies the person with the reason; a person's resume restarts the count", async () => {
    const s = `m${++seq}`;
    const settings = { file_path: join(ws, ".claude", "settings.json"), content: "{}" };
    for (let i = 0; i < 19; i++) {
      clock += 5000;
      expect(pre(s, "Write", settings).verdict, `attempt ${i + 1}`).toBe("ask");
    }
    clock += 5000;
    const r = pre(s, "Write", settings);
    expect(r.verdict).toBe("deny");
    expect(r.reason).toMatch(/FW-STOPPED/);
    expect(r.reason).toMatch(/the behaviour monitor stopped this session/);
    // Recorded (survives a restart), logged as a signed entry, and the person is told why.
    expect(existsSync(stopFile(l, "session", s))).toBe(true);
    expect(stopView(layout(l.home), s, "claude", null).active).toMatchObject({ by: "monitor", signal: "config" });
    const entry = tailLog(l, 1000).find((e) => (e as { event: { type?: string } }).event.type === "stop") as { event: Record<string, unknown>; sig?: string } | undefined;
    expect(entry?.event).toMatchObject({ scope: "session", target: s, by: "monitor", signal: "config" });
    expect(typeof entry?.sig).toBe("string");
    expect(verifyLog(l).ok).toBe(true);
    expect(spawns).toContain(notificationText("stopped", 1, "config").body);
    expect(spawns.join("\n")).toMatch(/An agent session was stopped: it tried to change the agent's configuration, instructions or the firewall too often\. No further tool call of it is allowed until you resume it\. In your terminal: launchsafe-firewall session list/);
    // From now on everything is denied, reads included, and no second notification is sent for it.
    clock += 5000;
    const after = pre(s, "Read", { file_path: join(ws, "src", "a.ts") });
    expect(after.verdict).toBe("deny");
    expect(after.reason).toMatch(/this session was stopped by the behaviour monitor/);
    expect(spawns.filter((x) => /stopped/.test(x))).toHaveLength(1);
    // A person resumes it: actions are checked as usual, and the old counts do not stop it again at once.
    initApprover(l, "monitor test passphrase");
    let out = "";
    const st = await main(["session", "resume", s], l, { write: (_fd, t) => void (out += t), humanAtKeyboard: () => Promise.resolve(true), session: { readSecret: () => Promise.resolve("monitor test passphrase"), env: {} } });
    expect(st, out).toBe(0);
    clock += 60000;
    expect(pre(s, "Read", { file_path: join(ws, "src", "a.ts") }).verdict).toBe("allow");
    expect(pre(s, "Write", settings).verdict).toBe("ask");
  }, 120_000);

  it("the same blocked action again and again stops the session (failures)", () => {
    const s = `m${++seq}`;
    const cmd = { command: "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/" };
    for (let i = 0; i < 19; i++) {
      clock += 3000;
      expect(pre(s, "Bash", cmd).reason).toMatch(/FW-METADATA/);
    }
    clock += 3000;
    const r = pre(s, "Bash", cmd);
    expect(r.reason).toMatch(/FW-STOPPED/);
    expect(stopView(l, s, "claude", null).active?.signal).toBe("failures");
  }, 120_000);

  it("a normal edit-and-test session of 100 actions is never stopped", () => {
    const s = `m${++seq}`;
    for (let i = 0; i < 50; i++) {
      clock += 2000;
      expect(pre(s, "Edit", { file_path: join(ws, "src", "a.ts"), old_string: "1", new_string: "1" }).verdict).toBe("allow");
      clock += 2000;
      expect(pre(s, "Bash", { command: "npm test" }).verdict).toBe("allow");
    }
    expect(existsSync(stopFile(l, "session", s))).toBe(false);
  }, 120_000);
});

describe("monitor and kill switch: the library", () => {
  it("memory store: the monitor's stop holds for the rest of the session", () => {
    const g = createGuard({ tools: { wire_money: { kind: "blocked" }, search_docs: { kind: "read", results: "trusted", privateData: false } }, store: memoryStore(), session: "lib-1" });
    for (let i = 0; i < 19; i++) expect(g.decide({ tool: "wire_money", input: { amount: 5 } }).verdict).toBe("deny");
    const x = g.decide({ tool: "wire_money", input: { amount: 5 } });
    expect(x.rules).toEqual(["FW-STOPPED"]);
    const after = g.decide({ tool: "search_docs", input: { q: "x" } });
    expect(after.verdict).toBe("deny");
    expect(after.rules).toEqual(["FW-STOPPED"]);
  });

  it("file store: a person's agent stop covers a local API agent's sessions (<agentId>/<session>)", () => {
    const store = fileStore({ home: l.home });
    stopTarget(l, "agent", "nightly-bot", { by: "person", reason: "", approverKey: null });
    const g = createGuard({ tools: { search_docs: { kind: "read", results: "trusted", privateData: false } }, store, session: "nightly-bot/run-1" });
    const x = g.decide({ tool: "search_docs", input: { q: "x" } });
    expect(x.verdict).toBe("deny");
    expect(x.message).toMatch(/every session of agent nightly-bot was stopped by a person/);
    const other = createGuard({ tools: { search_docs: { kind: "read", results: "trusted", privateData: false } }, store, session: "other-bot/run-1" });
    expect(other.decide({ tool: "search_docs", input: { q: "x" } }).verdict).toBe("allow");
  });
});
