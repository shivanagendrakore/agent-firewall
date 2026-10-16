/**
 * Claude Agent SDK (TypeScript, `@anthropic-ai/claude-agent-sdk` 0.3) integration (docs/library.md,
 * "Integrations"). The engine understands Claude Code's tool names natively, so no tool mapping is
 * needed; an in-process MCP server the host registered reports `mcp_server.source: "sdk"`.
 *
 * - `hooks`: PreToolUse decides each call (allow: no output, so Claude Code's own permission rules
 *   still apply; ask: `permissionDecision: "ask"`; hold or deny: `"deny"` with the reason),
 *   PostToolUse records what the tool returned (and hands back a redacted copy when the policy says
 *   so), UserPromptSubmit records the person's prompt (only when the SDK says a person or the host
 *   wrote it, never a machine-injected turn).
 * - `canUseTool`: Claude Code calls it for an "ask"; for the firewall's own asks it calls the guard's
 *   approval callback (`onApproval`) and records the answer. Other permission prompts go to the
 *   host's own `canUseTool` (`fallback`); without one they are refused: the library never approves on
 *   its own.
 *
 * Types only from the SDK: nothing of it is loaded at run time.
 */

import type { CanUseTool, HookCallbackMatcher, HookEvent, HookJSONOutput, HookInput } from "@anthropic-ai/claude-agent-sdk";
import { actionHash } from "../../engine/decide.js";
import type { DecisionCore, GuardPort } from "../port.js";
import type { ToolCall } from "../types.js";

export interface ClaudeAgentFirewallOptions {
  /** Your own canUseTool, for permission prompts the firewall did not raise. */
  fallback?: CanUseTool;
}

export interface ClaudeAgentFirewall {
  /** Pass as `options.hooks` to query() (merge with your own hooks if you have any). */
  hooks: Partial<Record<HookEvent, HookCallbackMatcher[]>>;
  /** Pass as `options.canUseTool` to query(). */
  canUseTool: CanUseTool;
}

/** The firewall's asks kept for canUseTool, at most. */
export const MAX_ASKS = 1000;

function inputOf(v: unknown): Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

/** `guard`: createGuard() in-process, or createRemoteGuard() (the local API sidecar decides). */
export function claudeAgentFirewall<D extends DecisionCore>(guard: GuardPort<D>, o: ClaudeAgentFirewallOptions = {}): ClaudeAgentFirewall {
  /** The firewall's own asks, by tool_use_id, until Claude Code calls canUseTool for them. */
  const asks = new Map<string, D>();

  const callOf = (input: { tool_name: string; tool_input: unknown; tool_use_id: string; mcp_server?: { source: string }; permission_mode?: string }): ToolCall => ({
    tool: input.tool_name,
    input: inputOf(input.tool_input),
    callId: input.tool_use_id,
    ...(input.mcp_server !== undefined ? { mcpSource: input.mcp_server.source } : {}),
    // A mode the policy lists as unattended (dontAsk) turns an ask into a held action, as on the hook path.
    ...(typeof input.permission_mode === "string" ? { permissionMode: input.permission_mode } : {}),
  });

  const preToolUse = async (input: HookInput): Promise<HookJSONOutput> => {
    if (input.hook_event_name !== "PreToolUse") return {};
    let d: D;
    try {
      d = await guard.decide(callOf(input));
    } catch (e) {
      // Claude Code treats a hook that throws as non-blocking: answer deny instead (the hook's failure policy).
      return { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: `LaunchSafe Agent Firewall could not check this action (${e instanceof Error ? e.message : String(e)}) and blocked it to be safe.` } };
    }
    if (d.verdict === "allow") return {};
    if (d.verdict === "ask") {
      asks.set(input.tool_use_id, d);
      // An ask Claude Code never puts to canUseTool (its own rules denied the call) would stay for ever: the oldest
      // go past MAX_ASKS. A forgotten ask's prompt is then like any other: the host's fallback answers it, or it is refused.
      while (asks.size > MAX_ASKS) asks.delete(asks.keys().next().value as string);
    }
    return { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: d.verdict === "ask" ? "ask" : "deny", permissionDecisionReason: d.message } };
  };

  const postToolUse = async (input: HookInput): Promise<HookJSONOutput> => {
    if (input.hook_event_name !== "PostToolUse") return {};
    const note = await guard.recordResult(callOf(input), input.tool_response);
    if (note.redacted === undefined && note.note === undefined) return {};
    return { hookSpecificOutput: { hookEventName: "PostToolUse", ...(note.note !== undefined ? { additionalContext: note.note } : {}), ...(note.redacted !== undefined ? { updatedToolOutput: note.redacted } : {}) } };
  };

  const postToolUseFailure = async (input: HookInput): Promise<HookJSONOutput> => {
    if (input.hook_event_name !== "PostToolUseFailure") return {};
    // The tool ran and failed: it counts toward the identical-failures limit, and what it brought back is still scanned.
    await guard.recordResult(callOf(input), input.error, { failed: true });
    return {};
  };

  const userPromptSubmit = async (input: HookInput): Promise<HookJSONOutput> => {
    if (input.hook_event_name !== "UserPromptSubmit") return {};
    // Only what a person (or the host on their behalf) wrote names destinations and sets the task scope.
    if (input.source === undefined || input.source === "user" || input.source === "sdk") await guard.recordPrompt(input.prompt);
    return {};
  };

  const canUseTool: CanUseTool = async (toolName, toolInput, options) => {
    const d = asks.get(options.toolUseID);
    if (d !== undefined) {
      asks.delete(options.toolUseID);
      // The approval binds to the exact call the firewall judged.
      if (d.call.tool !== toolName || actionHash({ tool: d.call.tool, input: d.call.input }) !== actionHash({ tool: toolName, input: toolInput })) {
        return { behavior: "deny", message: "LaunchSafe Agent Firewall: the call changed after it was checked; it was not approved." };
      }
      const a = await guard.requestApproval(d);
      return a.approved ? { behavior: "allow", updatedInput: toolInput } : { behavior: "deny", message: d.message };
    }
    if (o.fallback !== undefined) return o.fallback(toolName, toolInput, options);
    return { behavior: "deny", message: "LaunchSafe Agent Firewall: no approval handler for this permission prompt, and the firewall never approves on its own." };
  };

  return {
    hooks: {
      PreToolUse: [{ hooks: [preToolUse] }],
      PostToolUse: [{ hooks: [postToolUse] }],
      PostToolUseFailure: [{ hooks: [postToolUseFailure] }],
      UserPromptSubmit: [{ hooks: [userPromptSubmit] }],
    },
    canUseTool,
  };
}
