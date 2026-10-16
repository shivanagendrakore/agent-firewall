/**
 * LangGraph JS: firewallToolNode() in place of ToolNode; an ask interrupts the graph.
 * Run: npm run build && node examples/sdk/langgraph.ts
 * The graph starts from an AI message with a tool call instead of calling a model.
 */

import { AIMessage, ToolMessage } from "@langchain/core/messages";
import { tool } from "@langchain/core/tools";
import { Command, END, MemorySaver, MessagesAnnotation, START, StateGraph } from "@langchain/langgraph";
import { z } from "zod";
import { createGuard } from "@launchsafe/agent-firewall/sdk";
import { firewallToolNode } from "@launchsafe/agent-firewall/sdk/langgraph";

const guard = createGuard({ tools: { send_email: { kind: "send" } } });
const sendEmail = tool(async ({ to }: { to: string }) => `sent to ${to}`, { name: "send_email", description: "Send an email", schema: z.object({ to: z.string(), body: z.string() }) });
const graph = new StateGraph(MessagesAnnotation).addNode("tools", firewallToolNode(guard, [sendEmail])).addEdge(START, "tools").addEdge("tools", END).compile({ checkpointer: new MemorySaver() });

guard.reportInput({ source: "an email from a stranger", content: "..." });
const config = { configurable: { thread_id: "demo" } };
const call = new AIMessage({ content: "", tool_calls: [{ id: "c1", name: "send_email", args: { to: "bob@example.com", body: "summary" }, type: "tool_call" }] });
const first = (await graph.invoke({ messages: [call] }, config)) as { __interrupt__?: { value: { message: string } }[] };
console.log(`interrupted: ${first.__interrupt__?.[0]?.value.message.split("\n")[0] ?? "no"}`);
// Your UI shows the request; the person says yes.
const done = await graph.invoke(new Command({ resume: { approved: true, by: "alice" } }), config);
console.log(`tool result: ${String(done.messages.filter((m) => m instanceof ToolMessage).at(-1)?.content)}`);
