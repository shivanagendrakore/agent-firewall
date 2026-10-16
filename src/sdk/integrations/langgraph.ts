/**
 * LangGraph JS (`@langchain/langgraph` 1.4) integration (docs/library.md, "Integrations").
 *
 * `firewallToolNode(guard, tools)` is a drop-in for `ToolNode` in a StateGraph whose state has
 * `messages`. For the tool calls of the last AI message:
 *
 * - an allowed call is run by an inner ToolNode, and what it returned is recorded;
 * - an ask is put to the person with LangGraph's own human-in-the-loop primitive, `interrupt()`; the
 *   host resumes with `new Command({ resume: { approved: true, by } })` (or `true`), and only that runs
 *   the tool; anything else is a no. Each answer is bound to the call it was shown for (call id, tool
 *   and action hash): when the asks change while the graph is paused, an answer is never moved to
 *   another call, and the call is asked again;
 * - a held or denied call is not run: its ToolMessage carries the reason (status "error"), so the
 *   model sees why;
 * - a turn whose tool calls share an id is refused whole (an approval or a result could not be tied to
 *   one call);
 * - a tool that returns a Command works as in ToolNode, and the ToolMessages it carries are recorded.
 *
 * Deciding is recorded only after every interrupt has its answer: LangGraph runs a node again from the
 * start when it resumes, and the preview before the interrupts records nothing.
 *
 * Runtime imports (`interrupt`, `ToolNode`, messages) come from `@langchain/langgraph` and
 * `@langchain/core`, optional peer dependencies needed only by this subpath.
 */

import { AIMessage, isAIMessage, ToolMessage, type BaseMessage } from "@langchain/core/messages";
import type { RunnableConfig } from "@langchain/core/runnables";
import type { DynamicTool, StructuredToolInterface } from "@langchain/core/tools";
import { interrupt, isCommand } from "@langchain/langgraph";
import { ToolNode } from "@langchain/langgraph/prebuilt";
import type { DecisionCore, GuardPort } from "../port.js";
import type { ApprovalAnswer, ToolCall } from "../types.js";

/** What interrupt() hands the host for an ask (the value in the graph's __interrupt__). */
export interface FirewallInterrupt {
  type: "launchsafe_firewall_approval";
  toolCall: { id: string; name: string; args: Record<string, unknown> };
  /** The action the answer is bound to (with the call id and tool name). */
  actionHash: string;
  message: string;
  rules: string[];
}

interface Call {
  id: string;
  name: string;
  args: Record<string, unknown>;
}

/** Node runs whose interrupts are remembered (paused graphs that are never resumed are dropped oldest first). */
const MAX_PAUSED = 1000;

function callOf(c: Call): ToolCall {
  return { tool: c.name, input: c.args, callId: c.id };
}

function blocked(c: Call, d: DecisionCore): ToolMessage {
  return new ToolMessage({ content: d.message !== "" ? d.message : `LaunchSafe Agent Firewall did not allow ${c.name}`, tool_call_id: c.id, name: c.name, status: "error" });
}

/** The node run a resume belongs to: LangGraph re-runs the same task (same thread and checkpoint namespace). */
function runKey(config: RunnableConfig | undefined): string {
  const c = (config?.configurable ?? {}) as { thread_id?: unknown; checkpoint_ns?: unknown };
  return `${String(c.thread_id ?? "")}\u0000${String(c.checkpoint_ns ?? "")}`;
}

/** The ToolMessages in what ToolNode returned: messages, `{ messages }` updates and Commands' updates. */
function toolMessagesIn(x: unknown, out: ToolMessage[] = [], depth = 0): ToolMessage[] {
  if (depth > 4 || x === null || typeof x !== "object") return out;
  if (x instanceof ToolMessage) out.push(x);
  else if (Array.isArray(x)) for (const v of x) toolMessagesIn(v, out, depth + 1);
  else if (isCommand(x)) toolMessagesIn(x.update, out, depth + 1);
  else if ("messages" in x) toolMessagesIn((x as { messages: unknown }).messages, out, depth + 1);
  return out;
}

/** `guard`: createGuard() in-process, or createRemoteGuard() (the local API sidecar decides). */
export function firewallToolNode<S extends { messages: BaseMessage[] }, D extends DecisionCore = DecisionCore>(guard: GuardPort<D>, tools: (StructuredToolInterface | DynamicTool)[]): (state: S, config?: RunnableConfig) => Promise<{ messages: BaseMessage[] } | unknown[]> {
  const inner = new ToolNode(tools, { handleToolErrors: true });
  /** Per paused node run: the binding (call id, tool, action hash) of the ask raised at each interrupt index. */
  const shown = new Map<string, string[]>();

  return async (state, config) => {
    const last = state.messages[state.messages.length - 1];
    if (last === undefined || !isAIMessage(last) || (last.tool_calls ?? []).length === 0) return { messages: [] };
    const calls: Call[] = (last.tool_calls ?? []).map((tc, i) => ({ id: tc.id ?? `call_${i}`, name: tc.name, args: (tc.args ?? {}) as Record<string, unknown> }));
    // Calls sharing an id could share an approval or a result: refuse the turn, run nothing.
    const ids = calls.map((c) => c.id);
    const dup = ids.find((id, i) => ids.indexOf(id) !== i);
    if (dup !== undefined) {
      const message = `LaunchSafe Agent Firewall refused this turn: more than one tool call has the id ${JSON.stringify(dup).slice(0, 80)}, so an approval or a result could not be tied to one call. Nothing in this turn was run; call the tools again with distinct ids.`;
      return { messages: calls.map((c) => new ToolMessage({ content: message, tool_call_id: c.id, name: c.name, status: "error" })) };
    }
    // 1. Preview, recording nothing (this part runs again when the graph resumes).
    const previews: { c: Call; d: D }[] = [];
    for (const c of calls) previews.push({ c, d: await guard.check(callOf(c)) });
    // 2. One interrupt per ask, in call order. LangGraph matches resume values by interrupt index, so each
    //    index remembers which call it was raised for; an answer counts only for that call.
    const key = runKey(config);
    const record = shown.get(key) ?? [];
    shown.delete(key);
    shown.set(key, record);
    if (shown.size > MAX_PAUSED) shown.delete(shown.keys().next().value as string);
    const answers = new Map<string, { answer: ApprovalAnswer; actionHash: string }>();
    let idx = 0;
    for (const { c, d } of previews) {
      if (d.verdict !== "ask") continue;
      const binding = JSON.stringify([c.id, c.name, d.actionHash]);
      const request: FirewallInterrupt = { type: "launchsafe_firewall_approval", toolCall: { id: c.id, name: c.name, args: c.args }, actionHash: d.actionHash, message: d.message, rules: d.rules };
      for (;;) {
        const before = record[idx];
        let answer: ApprovalAnswer;
        try {
          answer = interrupt<FirewallInterrupt, ApprovalAnswer>(request);
        } catch (e) {
          // Raised (or not resumable): this index now stands for this call.
          record[idx] = binding;
          throw e;
        }
        idx += 1;
        if (before === binding) {
          answers.set(c.id, { answer, actionHash: d.actionHash });
          break;
        }
        // An answer given for another call (the asks changed while paused), or one this process never saw
        // raised: it is not applied here, and this call is asked again.
      }
    }
    shown.delete(key);
    // 3. Every answer is in: decide and record each call.
    const out = new Map<string, unknown>();
    const run: Call[] = [];
    for (const c of calls) {
      const d = await guard.decide(callOf(c));
      const a = answers.get(c.id);
      if (d.verdict === "allow") run.push(c);
      else if (d.verdict === "ask" && a !== undefined && a.actionHash === d.actionHash && (await guard.approveAsked(d, a.answer)).approved) run.push(c);
      else out.set(c.id, blocked(c, d));
    }
    if (run.length === 0) return { messages: calls.flatMap((c) => (out.has(c.id) ? [out.get(c.id) as BaseMessage] : [])) };
    const ai = new AIMessage({ content: last.content, tool_calls: run.map((c) => ({ id: c.id, name: c.name, args: c.args, type: "tool_call" as const })), ...(last.id !== undefined ? { id: last.id } : {}) });
    const result = (await inner.invoke({ ...state, messages: [...state.messages.slice(0, -1), ai] }, config)) as { messages?: unknown[] } | unknown[];
    // 4. Record what each tool returned (a Command's ToolMessages too); the model sees the masked copy
    //    when redactSecretsInOutput is set.
    const recorded = new Set<string>();
    for (const m of toolMessagesIn(result)) {
      const c = run.find((x) => x.id === m.tool_call_id);
      if (c === undefined || recorded.has(c.id)) continue;
      recorded.add(c.id);
      const note = await guard.recordResult(callOf(c), m.content, { failed: m.status === "error" });
      if (note.redacted !== undefined) m.content = note.redacted;
    }
    const commands = (Array.isArray(result) ? result : []).filter((x) => isCommand(x));
    // A tool that returned a Command without a ToolMessage for its call still ran: record what the Command carried.
    for (const c of run) if (!recorded.has(c.id)) await guard.recordResult(callOf(c), commands.map((x) => x.update));
    if (Array.isArray(result)) {
      // ToolNode's shape when a tool returned a Command: a list of updates and Commands.
      return [...calls.flatMap((c) => (out.has(c.id) ? [{ messages: [out.get(c.id) as BaseMessage] }] : [])), ...result];
    }
    for (const m of result.messages ?? []) if (m instanceof ToolMessage) out.set(m.tool_call_id, m);
    return { messages: calls.flatMap((c) => (out.has(c.id) ? [out.get(c.id) as BaseMessage] : [])) };
  };
}
