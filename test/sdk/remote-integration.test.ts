/**
 * One integration end to end with the remote guard: a real AI SDK generateText run (the AI SDK's mock
 * model, stub tools) whose calls are decided by the fake sidecar. An allowed call runs and its result is
 * recorded under its decision's id; a denied call never runs; an ask runs only after the person's yes in
 * the framework and the approval in the firewall's queue; with the sidecar down, nothing but a trusted
 * read runs.
 */

import { generateText, tool, type ModelMessage } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { z } from "zod";
import { vercelFirewall } from "../../src/sdk/integrations/vercel-ai.js";
import { createRemoteGuard, type RemoteGuardOptions } from "../../src/sdk/node.js";
import { deadSocket, startSidecar, type FakeSidecar } from "./remote-sidecar.js";

const usage = { inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 1, text: 1, reasoning: 0 } };

function callModel(toolName: string, input: Record<string, unknown>, id = "call-1"): MockLanguageModelV4 {
  return new MockLanguageModelV4({
    doGenerate: async () => ({ content: [{ type: "tool-call", toolCallId: id, toolName, input: JSON.stringify(input) }], finishReason: { unified: "tool-calls", raw: "tool_calls" }, usage, warnings: [] }),
  });
}

function textModel(): MockLanguageModelV4 {
  return new MockLanguageModelV4({ doGenerate: async () => ({ content: [{ type: "text", text: "done" }], finishReason: { unified: "stop", raw: "stop" }, usage, warnings: [] }) });
}

const SPECS: RemoteGuardOptions["tools"] = {
  get_weather: { kind: "read", results: "trusted", privateData: false },
  send_email: { kind: "send" },
};

function setup(o: RemoteGuardOptions) {
  const ran: string[] = [];
  const guard = createRemoteGuard({ tools: SPECS, session: "chat-7", approvalPollMs: 10, onError: () => {}, ...o });
  const fw = vercelFirewall(guard);
  const tools = fw.tools({
    get_weather: tool({ inputSchema: z.object({ city: z.string() }), execute: async ({ city }) => (ran.push(`weather ${city}`), `sunny in ${city}`) }),
    send_email: tool({ inputSchema: z.object({ to: z.string(), body: z.string() }), execute: async ({ to }) => (ran.push(`email ${to}`), "sent") }),
  });
  return { guard, fw, tools, ran };
}

describe("Vercel AI SDK with the remote guard", () => {
  let s: FakeSidecar;
  beforeEach(async () => {
    s = await startSidecar("socket");
  });
  afterEach(async () => {
    await s.close();
  });
  const target = () => ({ socketPath: s.socketPath as string, token: s.token });

  it("an allowed call runs and its result is recorded under its decision", async () => {
    const { fw, tools, ran } = setup(target());
    const r = await generateText({ model: callModel("get_weather", { city: "Oslo" }), tools, toolApproval: fw.toolApproval, prompt: "weather?" });
    expect(ran).toEqual(["weather Oslo"]);
    expect(r.toolResults.map((x) => x.output)).toEqual(["sunny in Oslo"]);
    const result = s.seen.find((x) => x.path === "/v1/sessions/chat-7/results");
    expect(result?.body).toEqual({ decisionId: "dec_1", output: "sunny in Oslo" });
    expect((s.seen[0]?.body as { action: unknown }).action).toEqual({ format: "native", tool: "get_weather", input: { city: "Oslo" }, callId: "call-1" });
  });

  it("a denied call never runs", async () => {
    s.verdicts.set("send_email", "deny");
    const { fw, tools, ran } = setup(target());
    await generateText({ model: callModel("send_email", { to: "a@example.com", body: "x" }), tools, toolApproval: fw.toolApproval, prompt: "x" });
    expect(ran).toEqual([]);
    expect(s.seen.some((x) => x.path.endsWith("/results"))).toBe(false);
  });

  it("an ask runs only after the person's yes and the queue's approval", async () => {
    s.verdicts.set("send_email", "ask");
    const { fw, tools, ran } = setup(target());
    const prompt: ModelMessage[] = [{ role: "user", content: "email bob" }];
    const first = await generateText({ model: callModel("send_email", { to: "bob@example.com", body: "s" }), tools, toolApproval: fw.toolApproval, messages: prompt });
    expect(ran).toEqual([]);
    const req = first.content.find((p) => p.type === "tool-approval-request");
    if (req?.type !== "tool-approval-request") throw new Error(`no approval request: ${JSON.stringify(first.content)}`);
    expect(req.reason).toContain("LaunchSafe Firewall");
    const messages: ModelMessage[] = [...prompt, ...first.response.messages, { role: "tool", content: [{ type: "tool-approval-response", approvalId: req.approvalId, approved: true }] }];
    // The person approves the queue item (terminal, phone) while the run waits.
    // The ask had no queue item; the person's yes queued it as a hold (apr_2).
    setTimeout(() => s.settle("apr_2", "approved"), 30);
    await generateText({ model: textModel(), tools, toolApproval: fw.toolApproval, messages });
    expect(ran).toEqual(["email bob@example.com"]);
    // The result is recorded under the retry's decision (the allow that used the approval).
    const result = s.seen.find((x) => x.path === "/v1/sessions/chat-7/results");
    expect(result?.body).toEqual({ decisionId: "dec_3", output: "sent" });
  });

  it("the framework's yes alone does not run an ask the queue never approved", async () => {
    s.verdicts.set("send_email", "ask");
    const { fw, tools, ran } = setup({ ...target(), approvalTimeoutMs: 50 });
    const prompt: ModelMessage[] = [{ role: "user", content: "email bob" }];
    const first = await generateText({ model: callModel("send_email", { to: "bob@example.com", body: "s" }), tools, toolApproval: fw.toolApproval, messages: prompt });
    const req = first.content.find((p) => p.type === "tool-approval-request");
    if (req?.type !== "tool-approval-request") throw new Error("no approval request");
    const messages: ModelMessage[] = [...prompt, ...first.response.messages, { role: "tool", content: [{ type: "tool-approval-response", approvalId: req.approvalId, approved: true }] }];
    await generateText({ model: textModel(), tools, toolApproval: fw.toolApproval, messages });
    expect(ran).toEqual([]);
  });
});

describe("Vercel AI SDK with the remote guard and no sidecar", () => {
  it("only the trusted read runs", async () => {
    const dead = deadSocket();
    try {
      const { fw, tools, ran } = setup({ socketPath: dead.path });
      await generateText({ model: callModel("get_weather", { city: "Oslo" }), tools, toolApproval: fw.toolApproval, prompt: "x" });
      await generateText({ model: callModel("send_email", { to: "a@example.com", body: "x" }), tools, toolApproval: fw.toolApproval, prompt: "x" });
      expect(ran).toEqual(["weather Oslo"]);
    } finally {
      dead.done();
    }
  });
});
