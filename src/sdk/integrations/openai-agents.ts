/**
 * OpenAI Agents SDK (JS, `@openai/agents` 0.20) integration (docs/library.md, "Integrations").
 *
 * `firewallTool(guard, options)` adds three things to a function tool's options before you pass them
 * to `tool()`:
 *
 * - `needsApproval`: true when the guard's verdict is "ask", so the run stops with an interruption and
 *   the host approves or rejects it with `result.state.approve()` / `reject()` (the Agents SDK's own
 *   human-in-the-loop protocol). When the SDK is about to interrupt, the ask is decided and recorded,
 *   and the firewall keeps its own single-use record of the call it put to the person;
 * - a tool input guardrail, which runs before the tool: it decides and records the call; an allowed
 *   call goes ahead, an ask goes ahead only when the person approved that very interruption (the
 *   firewall's record, same tool and arguments, used once; a blanket `alwaysApprove` stored by the SDK
 *   never counts), and a held or denied call is rejected with the reason (`rejectContent`: the model
 *   sees it, the tool never runs);
 * - a tool output guardrail, which records what the tool returned and, with `redactSecretsInOutput`,
 *   hands the model the masked copy.
 *
 * Types only from `@openai/agents-core` (re-exported by `@openai/agents`): nothing of the framework is
 * loaded at run time.
 */

import type { RunContext, ToolGuardrailFunctionOutput, ToolInputGuardrailDefinition, ToolInputGuardrailFunction, ToolOutputGuardrailDefinition, ToolOutputGuardrailFunction } from "@openai/agents-core";
import type { DecisionCore, GuardPort } from "../port.js";
import type { ToolCall } from "../types.js";

/** The parts of a function tool's options this integration sets (the rest are passed through). */
export interface FirewalledToolOptions {
  name: string;
  needsApproval?: boolean | ((runContext: RunContext, input: never, callId?: string) => Promise<boolean>);
  /** The tool's own function. When present it is wrapped so a run that throws is recorded as a failure (output guardrails run only on success). */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- the Agents SDK's execute takes (input, runContext, details); only its shape matters here
  execute?: (input: any, ...rest: any[]) => unknown;
  inputGuardrails?: (ToolInputGuardrailDefinition | { name: string; run: ToolInputGuardrailFunction })[];
  outputGuardrails?: (ToolOutputGuardrailDefinition | { name: string; run: ToolOutputGuardrailFunction })[];
}

/** Asks awaiting an answer kept per tool (a run's interruptions; refused ones are dropped oldest first). */
const MAX_PRESENTED = 1000;

const allow = (outputInfo?: unknown): ToolGuardrailFunctionOutput => ({ behavior: { type: "allow" }, ...(outputInfo !== undefined ? { outputInfo } : {}) });
const reject = (message: string, outputInfo?: unknown): ToolGuardrailFunctionOutput => ({ behavior: { type: "rejectContent", message }, ...(outputInfo !== undefined ? { outputInfo } : {}) });

function parseArgs(args: string): Record<string, unknown> {
  try {
    const v: unknown = JSON.parse(args);
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : { value: v };
  } catch {
    // Arguments the model wrote that are not JSON: judged as given (the tool's own parsing rejects them later).
    return { arguments: args };
  }
}

function inputOf(input: unknown): Record<string, unknown> {
  return typeof input === "object" && input !== null && !Array.isArray(input) ? (input as Record<string, unknown>) : { value: input };
}

/**
 * The tool options with the firewall added: `tool(firewallTool(guard, { name, parameters, execute }))`.
 * Your own needsApproval (if any) still applies: either one asking is an interruption.
 */
/** `guard`: createGuard() in-process, or createRemoteGuard() (the local API sidecar decides). */
export function firewallTool<T extends FirewalledToolOptions, D extends DecisionCore = DecisionCore>(guard: GuardPort<D>, options: T): T {
  const name = options.name;
  /**
   * The firewall's own record of each ask it put to the person as an interruption, by call id: the decision
   * (logged, counters moved) and the action it is about. Only an entry here, used once, for the same tool and
   * arguments, lets an approved ask run: the Agents SDK's own approval state is not enough, because
   * `state.approve(item, { alwaysApprove: true })` stores a blanket yes for the tool name that would
   * approve later calls with other arguments the person never saw.
   */
  const presented = new Map<string, D>();
  const own = options.needsApproval;

  const needsApproval = async (runContext: RunContext, input: never, callId?: string): Promise<boolean> => {
    const ownSays = typeof own === "function" ? await own(runContext, input, callId) : own === true;
    const call: ToolCall = { tool: name, input: inputOf(input), ...(callId !== undefined ? { callId } : {}) };
    const preview = await guard.check(call);
    if (preview.verdict !== "ask") return ownSays;
    if (callId === undefined) return true;
    const shown = presented.get(callId);
    if (shown !== undefined && shown.actionHash === preview.actionHash) return true;
    // The SDK interrupts only when it has no answer for this call yet: then the person is shown this exact
    // call, and the ask is decided and recorded now (as the hook records an ask when it is raised), so a
    // refusal, which never reaches the input guardrail, is still in the log and the counters.
    if (runContext.isToolApproved({ toolName: name, callId }) === undefined) {
      const d = await guard.decide(call);
      if (d.verdict === "ask") {
        presented.set(callId, d);
        // A refused ask never reaches the guardrail to be removed: keep the record bounded.
        if (presented.size > MAX_PRESENTED) presented.delete(presented.keys().next().value as string);
      }
    }
    return true;
  };

  const input: ToolInputGuardrailDefinition = {
    type: "tool_input",
    name: "launchsafe-firewall",
    run: async ({ context, toolCall }) => {
      const call: ToolCall = { tool: toolCall.name, input: parseArgs(toolCall.arguments), callId: toolCall.callId };
      const approval = context.isToolApproved({ toolName: toolCall.name, callId: toolCall.callId });
      let shown = presented.get(toolCall.callId);
      // With preApprovalInputGuardrails on, guardrails also run before the interruption: let the approval
      // request happen (the ask is already recorded); the answer is checked when the person has given it.
      // Only while the call is still an ask: otherwise the record is stale and the call is decided afresh.
      if (approval === undefined && shown !== undefined) {
        if ((await guard.check(call)).verdict === "ask") return allow({ verdict: "ask", pending: true });
        presented.delete(toolCall.callId);
        shown = undefined;
      }
      if (shown !== undefined) {
        presented.delete(toolCall.callId);
        const now = await guard.check(call);
        if (now.verdict === "ask") {
          // Single use, for the call the person was shown: same tool, same arguments.
          const same = shown.call.tool === call.tool && now.actionHash === shown.actionHash;
          const a = await guard.approveAsked(shown, same && approval === true ? { approved: true, by: `openai-agents approval of ${toolCall.callId}` } : false);
          if (a.approved) return allow({ verdict: "ask", rules: shown.rules, approved: true });
          if (same) return reject(shown.message, { verdict: "ask", rules: shown.rules });
        }
        // The verdict changed while the run was paused (or the call is not the one shown): decide it afresh.
      }
      const d = await guard.decide(call);
      if (d.verdict === "allow") return allow({ verdict: d.verdict, rules: d.rules });
      // An ask that was never put to the person as this call's own interruption is refused: a stored
      // approval for the tool (alwaysApprove) is not the firewall's approval.
      return reject(d.message, { verdict: d.verdict, rules: d.rules, ...(d.held !== undefined ? { held: d.held.id } : {}) });
    },
  };

  const output: ToolOutputGuardrailDefinition = {
    type: "tool_output",
    name: "launchsafe-firewall-result",
    run: async ({ toolCall, output: result }) => {
      const note = await guard.recordResult({ tool: toolCall.name, input: parseArgs(toolCall.arguments), callId: toolCall.callId }, result);
      const info = { becameUntrusted: note.becameUntrusted, secretsSeen: note.secretsSeen };
      // redactSecretsInOutput: the model is given the masked copy, as the hook hands Claude Code one.
      if (note.redacted !== undefined) return reject(note.redacted, { ...info, redacted: true });
      return allow(info);
    },
  };

  const execute = options.execute;
  const wrapped =
    typeof execute === "function"
      ? {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- see FirewalledToolOptions.execute
          execute: async (input: any, ...rest: any[]): Promise<unknown> => {
            try {
              return await execute(input, ...rest);
            } catch (e) {
              // The tool ran and threw: record it as a failed result (it counts toward the identical-failures limit), then rethrow.
              const details = rest[1] as { toolCall?: { callId?: unknown } } | undefined;
              const callId = details?.toolCall?.callId;
              try {
                await guard.recordResult({ tool: name, input: inputOf(input), ...(typeof callId === "string" ? { callId } : {}) }, e instanceof Error ? e.message : String(e), { failed: true });
              } catch {
                // Recording must not replace the tool's own error.
              }
              throw e;
            }
          },
        }
      : {};

  return {
    ...options,
    ...wrapped,
    needsApproval,
    inputGuardrails: [input, ...(options.inputGuardrails ?? [])],
    outputGuardrails: [...(options.outputGuardrails ?? []), output],
  };
}
