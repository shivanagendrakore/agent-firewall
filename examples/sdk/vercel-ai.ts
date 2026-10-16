/**
 * Vercel AI SDK: the firewall as `toolApproval`, plus wrapped tools.
 * Run: npm run build && node examples/sdk/vercel-ai.ts
 * The AI SDK's mock model stands in for a real one (swap in e.g. openai("gpt-...") or anthropic("claude-...")).
 */

import { generateText, tool, type ModelMessage } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { z } from "zod";
import { createGuard } from "@launchsafe/agent-firewall/sdk";
import { vercelFirewall } from "@launchsafe/agent-firewall/sdk/vercel-ai";

const usage = { inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 1, text: 1, reasoning: 0 } };
const model = new MockLanguageModelV4({
  doGenerate: [
    { content: [{ type: "tool-call", toolCallId: "c1", toolName: "send_email", input: JSON.stringify({ to: "bob@example.com", body: "summary" }) }], finishReason: { unified: "tool-calls", raw: "tool_calls" }, usage, warnings: [] },
    { content: [{ type: "text", text: "Sent." }], finishReason: { unified: "stop", raw: "stop" }, usage, warnings: [] },
  ],
});

const guard = createGuard({ tools: { send_email: { kind: "send" } } });
const fw = vercelFirewall(guard);
const tools = fw.tools({
  send_email: tool({ inputSchema: z.object({ to: z.string(), body: z.string() }), execute: async ({ to }) => `sent to ${to}` }),
});

// Something outside wrote part of the context (a retrieved page): sends now need a person.
guard.reportInput({ source: "a retrieved web page", content: "..." });

const messages: ModelMessage[] = [{ role: "user", content: "Email bob the summary." }];
const first = await generateText({ model, tools, toolApproval: fw.toolApproval, messages });
const request = first.content.find((p) => p.type === "tool-approval-request");
console.log(`first call: ${request !== undefined ? "approval requested" : "no approval needed"}`);
if (request?.type === "tool-approval-request") {
  console.log(request.reason?.split("\n")[0]);
  // Your UI shows the request; the person says yes (addToolApprovalResponse in useChat does the same).
  messages.push(...first.response.messages, { role: "tool", content: [{ type: "tool-approval-response", approvalId: request.approvalId, approved: true }] });
  const second = await generateText({ model, tools, toolApproval: fw.toolApproval, messages });
  console.log(`after the person's yes: ${second.text}`);
}
console.log(guard.log().map((e) => `${String(e.event.type)} ${String(e.event.verdict ?? e.event.approved ?? "")}`).join("\n"));
