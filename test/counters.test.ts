/**
 * The runtime counters (sessions/<id>.counters.json) through the real
 * hook, in a temporary home: recording, windows, raises by a person's approval (an answered ask, a
 * signed queue approval), corrupt files, forged raises, loop notifications.
 */
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { runHook, type HookEnv } from "../src/hook/claude.js";
import { approvalSigner, initApprover, signStateChange, unlockApprover } from "../src/runtime/approver.js";
import { counterChecks, countersFile, readCounters } from "../src/runtime/counters.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { appendEvents, decideQueueItem, listQueue, loadState, pruneSessions } from "../src/runtime/store.js";
import { trustedApproverKey } from "../src/hook/claude.js";
import { counterKey } from "../src/engine/learn.js";
import { confirmPending, emptyCounters } from "../src/engine/counters.js";
import { tempHome, testRoot } from "./helpers.js";

let home: string, ws: string, l: Layout, clock: number, spawns: string[], seq = 0;

beforeEach(() => {
  home = tempHome("counters-home-");
  ws = mkdtempSync(join(testRoot(), "counters-ws-"));
  mkdirSync(join(ws, "src"), { recursive: true });
  l = layout(join(home, ".launchsafe-firewall"));
  clock = Date.UTC(2026, 9, 10, 9, 0, 0);
  spawns = [];
});

const session = (): string => `c${++seq}`;

function env(unattended = false): HookEnv {
  return { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, home, scratchRoots: [join(home, "tmp")], now: new Date(clock), detectNonInteractive: () => unattended, notifyDeps: { spawn: (_c, args) => void spawns.push(args[args.length - 1] ?? ""), platform: "darwin", executable: () => true, now: () => clock } };
}

function verdictOf(out: string): string {
  if (out.trim() === "") return "allow";
  const o = JSON.parse(out) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
  const dec = o.hookSpecificOutput?.permissionDecision;
  if (dec === "ask") return "ask";
  if (dec === "deny") return /held this for review/.test(o.hookSpecificOutput?.permissionDecisionReason ?? "") ? "queue" : "deny";
  return "allow";
}

function pre(s: string, tool: string, input: Record<string, unknown>, unattended = false): { verdict: string; reason: string } {
  const r = runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: s, cwd: ws, permission_mode: "default", tool_name: tool, tool_input: input }), env(unattended));
  const reason = r.stdout.trim() === "" ? "" : ((JSON.parse(r.stdout) as { hookSpecificOutput?: { permissionDecisionReason?: string } }).hookSpecificOutput?.permissionDecisionReason ?? "");
  return { verdict: verdictOf(r.stdout), reason };
}

function post(s: string, tool: string, input: Record<string, unknown>, response: unknown = "ok"): void {
  runHook(JSON.stringify({ hook_event_name: "PostToolUse", session_id: s, cwd: ws, tool_name: tool, tool_input: input, tool_response: response }), env());
}

/** A tool call a person lets run: PreToolUse, then (allowed or answered yes) PostToolUse. */
function call(s: string, tool: string, input: Record<string, unknown>, unattended = false): { verdict: string; reason: string } {
  const r = pre(s, tool, input, unattended);
  if (r.verdict === "allow" || r.verdict === "ask") post(s, tool, input);
  return r;
}

function taint(s: string): void {
  post(s, "WebFetch", { url: "https://blog.example.org/post", prompt: "read" }, "outside content");
}

function prompt(s: string, text: string): void {
  runHook(JSON.stringify({ hook_event_name: "UserPromptSubmit", session_id: s, cwd: ws, prompt: text }), env());
}

describe("budgets: runtime counters", () => {
  it("U1 + U7: 40 requests to a named host are fine, the 41st asks FW-BUDGET-REQUESTS; once approved the 42nd is allowed", () => {
    const s = session();
    prompt(s, "check https://named.example/q for me");
    taint(s);
    for (let i = 0; i < 40; i++) expect(call(s, "Bash", { command: `curl https://named.example/q?x=${i}` }).verdict, `request ${i + 1}`).toBe("allow");
    const r41 = call(s, "Bash", { command: "curl https://named.example/q?x=40" });
    expect(r41.verdict).toBe("ask");
    expect(r41.reason).toMatch(/FW-BUDGET-REQUESTS/);
    expect(r41.reason).toMatch(/40 requests to named\.example in the last 10 minutes; the budget is 40/);
    // The person said yes (the tool ran): the budget for this host is raised by 40.
    expect(readCounters(l, s).counters.raised).toEqual({ "req:named.example": 40 });
    expect(call(s, "Bash", { command: "curl https://named.example/q?x=41" }).verdict).toBe("allow");
    // 42 full hook calls (2 to 5 s alone); under full-suite load they passed the default 30 s timeout once.
  }, 120_000);
  it("an ask the person declined (no PostToolUse) raises nothing", () => {
    const s = session();
    prompt(s, "check https://named.example/q for me");
    taint(s);
    for (let i = 0; i < 40; i++) call(s, "Bash", { command: `curl https://named.example/q?x=${i}` });
    expect(pre(s, "Bash", { command: "curl https://named.example/q?x=40" }).verdict).toBe("ask");
    expect(readCounters(l, s).counters.raised).toEqual({});
    expect(readCounters(l, s).counters.pending).toHaveLength(1);
    expect(pre(s, "Bash", { command: "curl https://named.example/q?x=41" }).verdict).toBe("ask");
  });
  it("an ask nobody answered cannot turn a later run of the same action into a raise", () => {
    const at = new Date(clock);
    const c = emptyCounters();
    c.pending = [{ hash: "h1", raises: [{ key: "req:named.example", amount: 40 }], at: at.toISOString() }];
    // Long after the ask: the entry is dropped and nothing is raised.
    expect(confirmPending(c, "h1", new Date(clock + 30 * 60 * 1000))).toBe(false);
    expect(c.raised).toEqual({});
    expect(c.pending).toEqual([]);
    // Soon after the ask, the person's yes still raises the budget.
    c.pending = [{ hash: "h1", raises: [{ key: "req:named.example", amount: 40 }], at: at.toISOString() }];
    expect(confirmPending(c, "h1", new Date(clock + 30 * 1000))).toBe(true);
    expect(c.raised).toEqual({ "req:named.example": 40 });
  });
  it("windows: requests older than 10 minutes no longer count", () => {
    const s = session();
    prompt(s, "check https://named.example/q for me");
    taint(s);
    for (let i = 0; i < 40; i++) call(s, "Bash", { command: `curl https://named.example/q?x=${i}` });
    clock += 11 * 60 * 1000;
    expect(call(s, "Bash", { command: "curl https://named.example/q?x=40" }).verdict).toBe("allow");
  });
  it("U4: the same failing npm test 8 times with no edits, unattended -> queued FW-LOOP with a 'stuck' notification", () => {
    const s = session();
    for (let i = 0; i < 7; i++) expect(call(s, "Bash", { command: "npm test" }, true).verdict).toBe("allow");
    const r = pre(s, "Bash", { command: "npm test" }, true);
    expect(r.verdict).toBe("queue");
    expect(r.reason).toMatch(/FW-LOOP/);
    expect(r.reason).toMatch(/seems stuck/);
    expect(spawns).toHaveLength(1);
    expect(spawns[0]).toMatch(/held for repeating the same failing step/);
    // Approved with the passphrase: the retry runs, and the loop allowance is raised by 8.
    initApprover(l, "counters test passphrase");
    const priv = unlockApprover(l, "counters test passphrase");
    const item = listQueue(l).items.find((q) => q.status === "pending");
    decideQueueItem(l, item!.id, "approved", approvalSigner(priv));
    expect(call(s, "Bash", { command: "npm test" }, true).verdict).toBe("allow");
    // FW-LOOP counts (and so raises) under counterKey, not the exact actionHash: a changed Bash description must not reset it.
    expect(readCounters(l, s).counters.raised[`loop:${counterKey({ tool: "Bash", input: { command: "npm test" } })}`]).toBe(8);
    expect(call(s, "Bash", { command: "npm test" }, true).verdict).toBe("allow");
  });
  it("FP4: edit, npm test, edit, npm test: 20 cycles in 10 minutes are never a loop", () => {
    const s = session();
    for (let i = 0; i < 20; i++) {
      expect(call(s, "Edit", { file_path: join(ws, "src", "a.ts"), old_string: `${i}`, new_string: `${i + 1}` }).verdict).toBe("allow");
      expect(call(s, "Bash", { command: "npm test" }).verdict, `cycle ${i + 1}`).toBe("allow");
    }
  });
  it("U5: the 21st send through a chat server in 10 minutes (each approved), untrusted -> ask FW-BUDGET-MCP", () => {
    const s = session();
    taint(s);
    for (let i = 0; i < 20; i++) {
      const r = call(s, "mcp__slack__send_message", { channel: "#team", text: `update ${i}` });
      expect(r.verdict).toBe("ask");
      expect(r.reason).not.toMatch(/FW-BUDGET-MCP/);
    }
    const r = call(s, "mcp__slack__send_message", { channel: "#team", text: "update 20" });
    expect(r.verdict).toBe("ask");
    expect(r.reason).toMatch(/FW-BUDGET-MCP/);
  });
  it("U8: a corrupt counters file asks once (at the limit) in an untrusted session, then counting starts again; doctor warns", () => {
    // The budgets' own behaviour, with spending limits off: with them on, corrupt counters deny every
    // call until a person runs caps reset (test/caps.test.ts, "fail closed").
    mkdirSync(l.home, { recursive: true });
    writeFileSync(l.policy, JSON.stringify({ version: 3, caps: { enabled: false } }));
    const s = session();
    prompt(s, "check https://named.example/q for me");
    taint(s);
    mkdirSync(l.sessions, { recursive: true });
    writeFileSync(countersFile(l, s), "{ not json");
    const first = pre(s, "Bash", { command: "curl https://named.example/q?x=1" });
    expect(first.verdict).toBe("ask");
    expect(first.reason).toMatch(/FW-BUDGET-BYTES/);
    expect(first.reason).toMatch(/could not be read/);
    expect(readCounters(l, s).corrupt).toBe(false);
    expect(readCounters(l, s).counters.resetAt).toBeDefined();
    expect(pre(s, "Bash", { command: "curl https://named.example/q?x=2" }).verdict).toBe("allow");
    expect(counterChecks(l, clock).map((c) => c.detail).join(" ")).toMatch(/reset after being unreadable/);
    writeFileSync(countersFile(l, session()), '{"version": 1, "minute": []}');
    expect(counterChecks(l, Date.now()).map((c) => c.detail).join(" ")).toMatch(/unreadable for session/);
  });
  it("U9: a forged budget_raise makes the session untrusted and raises nothing; a signed one counts", () => {
    const s = session();
    initApprover(l, "counters test passphrase");
    appendEvents(l, s, [{ type: "budget_raise", key: "loop:x", amount: 1000, id: "b1", sig: "Zm9yZ2Vk" }]);
    const st = loadState(l, s, trustedApproverKey(l, {}));
    expect(st.tainted).toBe(true);
    expect(st.budgetRaises).toEqual([]);
    const s2 = session();
    const priv = unlockApprover(l, "counters test passphrase");
    appendEvents(l, s2, [{ type: "budget_raise", key: "loop:x", amount: 16, id: "b2", sig: signStateChange(priv, "budget-raise", s2, ["loop:x", "16", "b2"]) }]);
    const st2 = loadState(l, s2, trustedApproverKey(l, {}));
    expect(st2.tainted).toBe(false);
    expect(st2.budgetRaises).toEqual([{ key: "loop:x", amount: 16, id: "b2" }]);
  });
  it("a user policy with budgets switched off records nothing that asks", () => {
    mkdirSync(l.home, { recursive: true });
    writeFileSync(l.policy, JSON.stringify({ version: 2, budgets: { enabled: false } }));
    const s = session();
    for (let i = 0; i < 12; i++) expect(call(s, "Bash", { command: "npm test" }, true).verdict).toBe("allow");
  });
  it("the counters file is a session sidecar: pruned with the session", () => {
    const s = session();
    call(s, "Bash", { command: "npm test" });
    expect(existsSync(countersFile(l, s))).toBe(true);
    expect(pruneSessions(l, 0, Date.now() + 1000)).toBeGreaterThan(0);
    expect(existsSync(countersFile(l, s))).toBe(false);
  });
});
