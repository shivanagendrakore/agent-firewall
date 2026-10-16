/**
 * Vercel AI SDK (`ai` 7) integration (docs/library.md, "Integrations").
 *
 * - `toolApproval`: the AI SDK's own approval hook for generateText, streamText and ToolLoopAgent. An
 *   allowed call is "not-applicable", an ask is "user-approval" (the host's UI answers with a
 *   tool-approval-response), a held or denied call is "denied" with the reason. When the person
 *   approves, the AI SDK checks approved calls through the same function on the next request; that is
 *   where the person's yes is recorded (guard.approveAsked). A deny or hold is never turned into a yes.
 * - `tools(tools)`: wraps each tool's execute as a second line (a call the guard did not allow, or that
 *   no person approved, throws instead of running) and records what an executed tool returned.
 *
 * Types only from `ai`: nothing of the framework is loaded at run time.
 */

import type { ModelMessage, ToolApprovalStatus, ToolExecutionOptions, ToolSet } from "ai";
import { actionHash } from "../../engine/decide.js";
import { BoundedMap } from "../bounded.js";
import type { DecisionCore, GuardPort } from "../port.js";
import type { GuardDecision, ToolCall } from "../types.js";
import { setOwn } from "../../own.js";

/** Thrown by a wrapped execute for a call the firewall did not let run. The AI SDK hands the message to the model. */
export class FirewallBlockedError<D extends DecisionCore = GuardDecision> extends Error {
  constructor(readonly decision: D) {
    super(decision.message !== "" ? decision.message : `LaunchSafe Agent Firewall did not allow ${decision.call.tool}`);
    this.name = "FirewallBlockedError";
  }
}

export interface ApprovalCallInfo {
  toolCall: { toolName: string; toolCallId: string; input: unknown };
  messages: ModelMessage[];
}

interface Seen<D extends DecisionCore> {
  decision: D;
  /** The action hash of the call as it was when decided: the host may mutate the input object afterwards. */
  hash: string;
  /** A person approved this call through the AI SDK's approval protocol (recorded in the guard). */
  approved: boolean;
}

function asInput(v: unknown): Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : { value: v };
}

/** The engine's action hash of a call (tool and input). */
function hashOf(call: ToolCall): string {
  return actionHash({ tool: call.tool, input: call.input });
}

/** Whether a call is the exact call whose hash was taken when it was decided (a later change to the input object shows). */
function sameCall(s: { decision: DecisionCore; hash: string }, call: ToolCall): boolean {
  return s.decision.call.tool === call.tool && s.hash === hashOf(call);
}

/** Decisions kept for the wrapped execute, and approvals remembered as used, at most. */
export const MAX_SEEN = 10_000;
export const MAX_SPENT = 100_000;

const CHANGED ="LaunchSafe Agent Firewall: the call changed after it was checked; it was not approved.";
const SPENT = "LaunchSafe Agent Firewall: this approval was already used once; a resent approval is not a new one.";

/** The person's answer to this call's approval request, from the last tool message (as the AI SDK reads it). */
export function approvalResponseFor(messages: readonly ModelMessage[], toolCallId: string): { approved: boolean; approvalId: string; reason?: string } | undefined {
  const requests = new Map<string, string>();
  for (const m of messages) {
    if (m.role !== "assistant" || typeof m.content === "string") continue;
    for (const p of m.content) if (p.type === "tool-approval-request") requests.set(p.approvalId, p.toolCallId);
  }
  const last = messages[messages.length - 1];
  if (last === undefined || last.role !== "tool") return undefined;
  for (const p of last.content) {
    if (p.type === "tool-approval-response" && requests.get(p.approvalId) === toolCallId) return { approved: p.approved === true, approvalId: p.approvalId, ...(p.reason !== undefined ? { reason: p.reason } : {}) };
  }
  return undefined;
}

export interface VercelFirewall {
  /** Pass as `toolApproval` to generateText, streamText or a ToolLoopAgent. */
  toolApproval: (info: ApprovalCallInfo) => Promise<ToolApprovalStatus>;
  /** Wraps each tool's execute: refuses what the firewall did not allow, records what ran. */
  tools<T extends ToolSet>(tools: T): T;
}

/** `guard`: createGuard() in-process, or createRemoteGuard() (the local API sidecar decides). */
export function vercelFirewall<D extends DecisionCore>(guard: GuardPort<D>, o: { maxSeen?: number; maxSpent?: number } = {}): VercelFirewall {
  /** Decisions by tool call id, until the call runs; the oldest go past MAX_SEEN (a forgotten one is decided again). */
  const seen = new BoundedMap<Seen<D>>(o.maxSeen ?? MAX_SEEN);
  /**
   * Tool calls whose approval response has already been granted once: an approval is single use. Bounded too (the
   * oldest go past MAX_SPENT): only a yes resent after that many later approvals could count again.
   */
  const spent = new BoundedMap<true>(o.maxSpent ?? MAX_SPENT);

  /** Remembers a decision with the hash of the call as it is now, so a later change to the input is seen at execute. */
  function keep(call: ToolCall, decision: D, approved: boolean): void {
    seen.set(call.callId ?? "", { decision, hash: hashOf(call), approved });
  }

  async function toolApproval(info: ApprovalCallInfo): Promise<ToolApprovalStatus> {
    const call: ToolCall = { tool: info.toolCall.toolName, input: asInput(info.toolCall.input), callId: info.toolCall.toolCallId };
    const answer = approvalResponseFor(info.messages, call.callId ?? "");
    if (answer?.approved === true && spent.has(call.callId ?? "")) {
      // A replay of a yes that was already granted (before or after the call ran) is decided as if never
      // asked, and an ask stays a no: only the first use of an approval response approves.
      const d = await guard.decide(call);
      keep(call, d, false);
      return d.verdict === "allow" ? "not-applicable" : { type: "denied", reason: d.verdict === "ask" ? SPENT : d.message };
    }
    if (answer?.approved === true) {
      // Re-validation of a call the person approved. The verdict must still be an ask: a deny or hold now stays a no.
      // The yes covers only the exact call the person was shown: a resubmitted history whose tool call changed
      // (another input under the same toolCallId) is decided afresh and never inherits the approval.
      const before = seen.get(call.callId ?? "");
      if (before !== undefined && !sameCall(before, call)) {
        const fresh = await guard.decide(call);
        keep(call, fresh, false);
        return fresh.verdict === "allow" ? "not-applicable" : { type: "denied", reason: fresh.verdict === "ask" ? CHANGED : fresh.message };
      }
      const d = before !== undefined && before.decision.verdict === "ask" ? before.decision : await guard.decide(call);
      if (d.verdict === "allow") {
        keep(call, d, false);
        return "not-applicable";
      }
      if (d.verdict !== "ask") return { type: "denied", reason: d.message };
      const a = await guard.approveAsked(d, { approved: true, by: `ai-sdk tool-approval-response ${answer.approvalId}` });
      keep(call, d, a.approved);
      if (a.approved) spent.set(call.callId ?? "", true);
      return a.approved ? "not-applicable" : { type: "denied", reason: d.message };
    }
    const d = await guard.decide(call);
    keep(call, d, false);
    if (d.verdict === "allow") return "not-applicable";
    if (d.verdict === "ask") return { type: "user-approval", reason: d.message };
    return { type: "denied", reason: d.message };
  }

  async function recordFailure(call: ToolCall, e: unknown): Promise<void> {
    try {
      await guard.recordResult(call, e instanceof Error ? e.message : String(e), { failed: true });
    } catch {
      // Recording must not replace the tool's own error.
    }
  }

  function tools<T extends ToolSet>(set: T): T {
    const out: Record<string, unknown> = {};
    for (const [name, t] of Object.entries(set)) {
      const execute = (t as { execute?: (input: unknown, options: ToolExecutionOptions<unknown>) => unknown }).execute;
      if (typeof execute !== "function") {
        setOwn(out, name, t);
        continue;
      }
      setOwn(out, name, {
        ...t,
        execute: async (input: unknown, options: ToolExecutionOptions<unknown>) => {
          const call: ToolCall = { tool: name, input: asInput(input), callId: options.toolCallId };
          const s = seen.get(options.toolCallId);
          let ok: boolean;
          if (s !== undefined) {
            // Second line: what runs must be exactly what was decided (and, for an ask, approved).
            ok = (s.decision.verdict === "allow" || s.approved) && sameCall(s, call);
            seen.delete(options.toolCallId);
            if (!ok) throw new FirewallBlockedError(s.decision);
          } else {
            // toolApproval was not wired: the guard decides here, and an ask goes to the guard's onApproval.
            const a = await guard.authorize(call);
            if (!a.allowed) throw new FirewallBlockedError(a.decision);
          }
          let result: unknown;
          try {
            result = await execute(input, options);
          } catch (e) {
            // A tool that threw ran: record the failure (it counts toward the identical-failures limit), then rethrow.
            await recordFailure(call, e);
            throw e;
          }
          const note = await guard.recordResult(call, result);
          return note.redacted !== undefined && typeof result === "string" ? note.redacted : result;
        },
      });
    }
    return out as T;
  }

  return { toolApproval, tools };
}
