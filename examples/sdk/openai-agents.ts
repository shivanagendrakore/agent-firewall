/**
 * OpenAI Agents SDK: firewallTool() adds needsApproval and tool guardrails to a function tool.
 * Run: npm run build && node examples/sdk/openai-agents.ts
 * With @openai/agents, import Agent, run and tool from "@openai/agents" and use a real model; the
 * SDK's ScriptedModel stands in for one here.
 */

import { Agent, run, setTracingDisabled, tool } from "@openai/agents-core";
import { assistantMessage, functionCall, ScriptedModel } from "@openai/agents-core/testing";
import { z } from "zod";
import { createGuard } from "@launchsafe/agent-firewall/sdk";
import { firewallTool } from "@launchsafe/agent-firewall/sdk/openai-agents";

setTracingDisabled(true);
const guard = createGuard({ tools: { send_email: { kind: "send" } } });
const sendEmail = tool(
  firewallTool(guard, {
    name: "send_email",
    description: "Send an email",
    parameters: z.object({ to: z.string(), body: z.string() }),
    execute: async ({ to }: { to: string }) => `sent to ${to}`,
  }),
);

const model = new ScriptedModel([[functionCall("send_email", { to: "bob@example.com", body: "summary" }, { callId: "c1" })], [assistantMessage("Sent.")]]);
const agent = new Agent({ name: "assistant", instructions: "Help the user.", model, tools: [sendEmail] });

guard.reportInput({ source: "a support ticket", content: "..." });
let result = await run(agent, "Email bob the summary.");
for (const item of result.interruptions ?? []) {
  console.log(`approval needed for ${item.name ?? "a tool"}`);
  // Your UI asks the person; here they say yes.
  result.state.approve(item);
}
if ((result.interruptions ?? []).length > 0) result = await run(agent, result.state);
console.log(`final: ${String(result.finalOutput)}`);
console.log(guard.log().map((e) => `${String(e.event.type)} ${String(e.event.verdict ?? e.event.approved ?? "")}`).join("\n"));
