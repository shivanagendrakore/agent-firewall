/**
 * Audit fixes in the SDK (I3, I6, I7, the bounded integration maps, reportInput's order, the log's `what`):
 * each test fails without its fix.
 */

import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createGuard, logSafe } from "../../src/sdk/guard.js";
import { claudeAgentFirewall, MAX_ASKS } from "../../src/sdk/integrations/claude-agent-sdk.js";
import { vercelFirewall } from "../../src/sdk/integrations/vercel-ai.js";
import type { DecisionCore, GuardPort } from "../../src/sdk/port.js";
import { socketProblem } from "../../src/sdk/remote-http.js";
import { memoryStore } from "../../src/sdk/store.js";
import { createRemoteGuard, type RemoteGuardOptions, type ToolSpec } from "../../src/sdk/node.js";
import type { ToolCall } from "../../src/sdk/types.js";
import { startSidecar, type FakeSidecar } from "./remote-sidecar.js";

const TOOLS: Record<string, ToolSpec> = { search_docs: { kind: "read", results: "trusted", privateData: false }, send_email: { kind: "send" } };
const read = { tool: "search_docs", input: { q: "refunds" } };

describe("I3: GuardOptions.policyError", () => {
  it("a risky call asks under FW-POLICY-ERROR and every decision's problems say why", () => {
    const g = createGuard({ policyError: "policy.json: not JSON", onLogError: () => undefined });
    const d = g.decide({ tool: "Bash", input: { command: "ls" } });
    expect(d.verdict).toBe("ask");
    expect(d.rules).toContain("FW-POLICY-ERROR");
    expect((d.problems ?? []).join("\n")).toMatch(/policy problem: policy\.json: not JSON/);
    expect((g.check({ tool: "Read", input: { file_path: "/home/agent/x" } }).problems ?? []).join("\n")).toMatch(/policy problem/);
    expect(createGuard({ onLogError: () => undefined }).decide({ tool: "Bash", input: { command: "ls" } }).rules).not.toContain("FW-POLICY-ERROR");
  });
});

describe("I6 and I7: the remote guard's transport", () => {
  let s: FakeSidecar;
  beforeEach(async () => {
    s = await startSidecar("socket");
  });
  afterEach(async () => {
    await s.close();
  });
  const opts = (extra: RemoteGuardOptions = {}): RemoteGuardOptions => ({ socketPath: s.socketPath as string, token: s.token, session: "a", tools: TOOLS, onError: () => undefined, ...extra });

  it("I6: a 500 fails closed for a read-only tool; 503 (overloaded) still lets it through", async () => {
    s.overrides.push({ status: 500, raw: "{}" });
    const g = createRemoteGuard(opts());
    expect((await g.decide(read)).verdict).toBe("deny");
    s.overrides.push({ status: 503, raw: "{}" });
    expect((await g.decide(read)).verdict).toBe("allow");
  });

  it("I7: a socket that is not mode 0600 is refused before the token is sent", async () => {
    chmodSync(s.socketPath as string, 0o666);
    const g = createRemoteGuard(opts());
    const d = await g.decide(read);
    expect(d.verdict).toBe("deny");
    expect(d.rules).toEqual(["FW-API-ERROR"]);
    expect(s.seen).toHaveLength(0);
    expect(socketProblem(s.socketPath as string)).toMatch(/not 600/);
    expect(socketProblem(s.socketPath as string, 4242)).toMatch(/belongs to user/);
  });

  it("I7: baseUrl (loopback TCP) needs allowTcp", () => {
    expect(() => createRemoteGuard({ baseUrl: "http://127.0.0.1:9" })).toThrow(/allowTcp/);
    expect(() => createRemoteGuard({ baseUrl: "http://127.0.0.1:9", allowTcp: true })).not.toThrow();
  });

  it("I1: recordPrompt goes with promptToken when one is given; everything else with the agent's token", async () => {
    const g = createRemoteGuard(opts({ promptToken: "prompt-token-not-a-secret" }));
    await g.recordPrompt("email ana@example.com");
    await g.reportInput({ source: "doc", content: "x" });
    const prompt = s.seen.find((r) => r.path.endsWith("/prompts"));
    const input = s.seen.find((r) => r.path.endsWith("/inputs"));
    expect(prompt?.headers.authorization).toBe("Bearer prompt-token-not-a-secret");
    expect(input?.headers.authorization).toBe(`Bearer ${s.token}`);
  });
});

describe("a socket owned by another user or world-writable is refused (real server shape)", () => {
  it("a 0600 socket of this user is accepted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "lsfw-sock-"));
    const p = join(dir, "s.sock");
    const srv = http.createServer();
    await new Promise<void>((r) => srv.listen(p, r));
    try {
      chmodSync(p, 0o600);
      expect(socketProblem(p)).toBeNull();
    } finally {
      await new Promise<void>((r) => srv.close(() => r()));
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/** A guard that asks about every call (or allows, by tool), counting decisions. */
function fakeGuard(verdict: (c: ToolCall) => "allow" | "ask" = () => "ask"): GuardPort<DecisionCore> & { decided: number } {
  let n = 0;
  const g = {
    session: "fake",
    decided: 0,
    check: (c: ToolCall): DecisionCore => ({ id: `c${++n}`, verdict: verdict(c), call: c, rules: [], reasons: [], message: "m", actionHash: "h" }),
    decide(c: ToolCall): DecisionCore {
      g.decided += 1;
      return { id: `d${++n}`, verdict: verdict(c), call: c, rules: [], reasons: [], message: "m", actionHash: "h" };
    },
    authorize: async (c: ToolCall) => ({ allowed: verdict(c) === "allow", decision: g.decide(c) }),
    requestApproval: async () => ({ approved: true }),
    approveAsked: () => ({ approved: true }),
    recordResult: () => ({ becameUntrusted: false, secretsSeen: 0 }),
    recordPrompt: () => undefined,
  };
  return g;
}

describe("bounded integration maps", () => {
  it("claude-agent-sdk: past MAX_ASKS the oldest ask is forgotten (its prompt goes to the fallback)", async () => {
    const f = claudeAgentFirewall(fakeGuard(), { fallback: async () => ({ behavior: "deny", message: "fallback" }) });
    const pre = f.hooks.PreToolUse?.[0]?.hooks[0];
    const signal = new AbortController().signal;
    for (let i = 0; i <= MAX_ASKS; i++) {
      await pre?.({ session_id: "s", transcript_path: "/t", cwd: "/", permission_mode: "default", hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: `x${i}` }, tool_use_id: `t${i}` } as never, `t${i}`, { signal });
    }
    const first = await f.canUseTool("Bash", { command: "x0" }, { signal, toolUseID: "t0" } as Parameters<typeof f.canUseTool>[2]);
    expect(first).toMatchObject({ behavior: "deny", message: "fallback" });
    const last = await f.canUseTool("Bash", { command: `x${MAX_ASKS}` }, { signal, toolUseID: `t${MAX_ASKS}` } as Parameters<typeof f.canUseTool>[2]);
    expect(last).toMatchObject({ behavior: "allow" });
  });

  it("vercel-ai: decisions kept for execute are bounded; a forgotten one is decided again", async () => {
    const g = fakeGuard(() => "allow");
    const v = vercelFirewall(g, { maxSeen: 2 });
    let ran = 0;
    const tools = v.tools({ t: { execute: async () => (ran += 1) } } as never) as unknown as { t: { execute: (i: unknown, o: { toolCallId: string; messages: [] }) => Promise<unknown> } };
    for (const id of ["a", "b", "c"]) await v.toolApproval({ toolCall: { toolName: "t", toolCallId: id, input: { x: id } }, messages: [] });
    const before = g.decided;
    await tools.t.execute({ x: "a" }, { toolCallId: "a", messages: [] });
    expect(g.decided).toBe(before + 1);
    await tools.t.execute({ x: "c" }, { toolCallId: "c", messages: [] });
    expect(g.decided).toBe(before + 1);
    expect(ran).toBe(2);
  });
});

describe("reportInput and the log", () => {
  it("the taint is recorded even when scanning the content fails", () => {
    const store = memoryStore();
    const g = createGuard({ store, onLogError: () => undefined });
    // A value whose property throws when read: scanning it fails.
    const hostile = Object.defineProperty({}, "text", { enumerable: true, get: (): never => { throw new Error("boom"); } });
    expect(() => g.reportInput({ source: "a web page", content: hostile })).toThrow();
    expect(g.state().untrusted).toBe(true);
  });

  it("the decision log's `what` keeps no query values or credentials", () => {
    expect(logSafe("fetch https://x.example/cb?token=abc123&u=ana")).toBe("fetch https://x.example/cb?token=…&u=…");
    const store = memoryStore();
    const g = createGuard({ store, onLogError: () => undefined });
    g.decide({ tool: "WebFetch", input: { url: "https://api.example.com/v1?key=sk_live_value_123456&q=1" } });
    const last = store.entries().filter((e) => e.event.type === "decision").pop();
    expect(String(last?.event.what)).not.toMatch(/sk_live_value_123456/);
  });
});
