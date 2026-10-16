/**
 * The Claude Code adapter: Claude Code's hook events (captured from 2.1.289,
 * test/fixtures/claude-*.json) to the firewall's AdapterEvent, and the
 * firewall's outcome to Claude Code's output (hookSpecificOutput with
 * permissionDecision allow/ask/deny; exit 2 blocks a ConfigChange). The
 * behaviour is v0.1's, moved here unchanged (the v0.1 suite is the gate).
 */

import type { Layout } from "../runtime/layout.js";
import type { ProcessProbe } from "../runtime/ancestry.js";
import { mcpProvenance, nonInteractiveClaude } from "../runtime/context.js";
import { CLAUDE_SETTINGS } from "../runtime/install.js";
import { AdapterParseError, type AdapterEvent, type AgentAdapter, type CoverageItem, type HookIO, type HookOutcome } from "./types.js";
import { own } from "../own.js";

type Json = Record<string, unknown>;

const KINDS: Record<string, AdapterEvent["kind"]> = {
  PreToolUse: "pre_tool",
  PostToolUse: "post_tool",
  // A tool that failed (Bash non-zero exit, an MCP isError): its error is still what the tool returned.
  PostToolUseFailure: "post_tool",
  UserPromptSubmit: "prompt",
  SessionStart: "session_start",
  ConfigChange: "config_change",
};

function json(o: unknown): string {
  return `${JSON.stringify(o)}\n`;
}

export function parseClaude(input: Json): AdapterEvent {
  const name = typeof input.hook_event_name === "string" ? input.hook_event_name : "";
  // M3: an event name this version does not know that carries a tool is judged as a tool call about to run (a
  // "Post..." one as a result), never ignored: a renamed or new pre-tool event must not pass unchecked.
  const unknownWithTool = own(KINDS, name) === undefined && typeof input.tool_name === "string" && input.tool_name !== "";
  const kind = own(KINDS, name) ?? (unknownWithTool ? (/^Post/.test(name) ? "post_tool" : "pre_tool") : "ignored");
  const sessionId = typeof input.session_id === "string" && input.session_id !== "" ? input.session_id : undefined;
  // A pre-tool event without a session id would share one state with every other such event (taint, held actions):
  // block it, like the other adapters.
  if (kind === "pre_tool" && sessionId === undefined) throw new AdapterParseError(`${name} without a session_id`, true);
  const ev: AdapterEvent = {
    kind,
    agent: "claude",
    sessionId: sessionId ?? "no-session",
    cwd: typeof input.cwd === "string" && input.cwd !== "" ? input.cwd : process.cwd(),
    raw: input,
  };
  if (typeof input.permission_mode === "string") ev.permissionMode = input.permission_mode;
  if (typeof input.scratchpad_dir === "string") ev.scratchpadDir = input.scratchpad_dir;
  if (ev.kind === "pre_tool" || ev.kind === "post_tool") {
    ev.tool = typeof input.tool_name === "string" ? input.tool_name : "";
    const toolInput = input.tool_input;
    if (typeof toolInput === "object" && toolInput !== null && !Array.isArray(toolInput)) ev.input = toolInput as Json;
    else if (ev.kind === "pre_tool") throw new AdapterParseError(`${name} for ${ev.tool} without a tool_input object`, true);
    else ev.input = {};
  }
  if (ev.kind === "post_tool") {
    if (name === "PostToolUseFailure") {
      ev.failed = true;
      ev.output = input.error ?? input.tool_response ?? input.tool_output ?? "";
    } else ev.output = input.tool_response ?? input.tool_output ?? "";
  }
  if (ev.kind === "prompt") ev.prompt = typeof input.prompt === "string" ? input.prompt : "";
  if (ev.kind === "session_start" && typeof input.source === "string") ev.source = input.source;
  // F10: Claude Code 2.1.289 reports the MCP server (mcp_server: name, source) at the top level of the event.
  // I5: only there: tool_input is the model's own text and can say anything about where a server came from.
  // I4: its name is the server's identity; the tool is the rest of tool_name after mcp__<name>__. A name that
  // does not match tool_name is not used at all (the source then comes from the configuration files).
  const server = input.mcp_server;
  if (typeof server === "object" && server !== null && !Array.isArray(server) && typeof (server as Json).name === "string" && (ev.kind === "pre_tool" || ev.kind === "post_tool")) {
    const s = server as Json;
    const name = s.name as string;
    const prefix = `mcp__${name}__`;
    const tool = ev.tool ?? "";
    if (name !== "" && tool.startsWith(prefix) && tool.length > prefix.length) ev.mcp = { server: name, tool: tool.slice(prefix.length), structural: true, ...(typeof s.source === "string" ? { source: s.source } : {}) };
  } else if (typeof server === "object" && server !== null && !Array.isArray(server) && (server as Json).name === undefined && typeof (server as Json).source === "string") {
    // An event with a source and no name (older captures): the source is kept, the identity comes from the name.
    const m = /^mcp__(.+?)__(.+)$/.exec(ev.tool ?? "");
    if (m !== null) ev.mcp = { server: m[1] as string, tool: m[2] as string, source: (server as Json).source as string };
  }
  return ev;
}

export function renderClaude(ev: AdapterEvent, out: HookOutcome): HookIO {
  const stderr = out.stderr ?? "";
  switch (ev.kind) {
    case "pre_tool": {
      // M3: an event of another name judged as a pre-tool call blocks the way every Claude Code hook event can: exit 2.
      if (typeof ev.raw.hook_event_name === "string" && ev.raw.hook_event_name !== "PreToolUse" && out.verdict !== "allow") return { stdout: "", stderr: out.message, exitCode: 2 };
      if (out.updatedInput !== undefined && (out.verdict === "allow" || out.verdict === "ask")) {
        // The command with its vault references rewritten into a ticketed run. "allow" only lets the
        // rewritten input through this hook; Claude Code still applies the person's own deny and ask rules to it.
        return { stdout: json({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: out.verdict, permissionDecisionReason: out.message, updatedInput: out.updatedInput }, ...(out.systemMessage !== undefined ? { systemMessage: out.systemMessage } : {}) }), stderr, exitCode: 0 };
      }
      if (out.verdict === "allow") {
        // Say nothing (beyond the session-start alerts): Claude Code's own permission rules still apply. The firewall only ever restricts.
        if (out.systemMessage !== undefined) return { stdout: json({ systemMessage: out.systemMessage }), stderr, exitCode: 0 };
        return { stdout: "", stderr, exitCode: 0 };
      }
      const decision = out.verdict === "ask" ? "ask" : "deny";
      return { stdout: json({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision, permissionDecisionReason: out.message }, ...(out.systemMessage !== undefined ? { systemMessage: out.systemMessage } : {}) }), stderr, exitCode: 0 };
    }
    case "post_tool": {
      const o: Json = {};
      const failure = ev.raw.hook_event_name === "PostToolUseFailure";
      const spec: Json = { hookEventName: failure ? "PostToolUseFailure" : "PostToolUse" };
      if (out.additionalContext !== undefined) spec.additionalContext = out.additionalContext;
      if (out.systemMessage !== undefined) o.systemMessage = out.systemMessage;
      if (out.updatedOutput !== undefined && !failure) spec.updatedToolOutput = out.updatedOutput;
      if (Object.keys(spec).length > 1) o.hookSpecificOutput = spec;
      return { stdout: Object.keys(o).length > 0 ? json(o) : "", stderr, exitCode: 0 };
    }
    case "session_start": {
      const o: Json = {};
      if (out.additionalContext !== undefined) o.hookSpecificOutput = { hookEventName: "SessionStart", additionalContext: out.additionalContext };
      if (out.systemMessage !== undefined) o.systemMessage = out.systemMessage;
      return { stdout: Object.keys(o).length > 0 ? json(o) : "", stderr, exitCode: 0 };
    }
    case "config_change":
      return { stdout: "", stderr: out.verdict === "allow" ? stderr : out.message, exitCode: out.verdict === "allow" ? 0 : 2 };
    default:
      return { stdout: "", stderr, exitCode: 0 };
  }
}

/** Claude Code's verdict in a hook answer (tests and the scenario harness). */
export function claudeVerdict(io: HookIO): { verdict: "allow" | "ask" | "deny"; reason: string } {
  if (io.exitCode === 2) return { verdict: "deny", reason: io.stderr };
  if (io.stdout.trim() === "") return { verdict: "allow", reason: "" };
  const o = JSON.parse(io.stdout) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
  const d = o.hookSpecificOutput?.permissionDecision;
  const reason = o.hookSpecificOutput?.permissionDecisionReason ?? "";
  return { verdict: d === "ask" ? "ask" : d === "deny" ? "deny" : "allow", reason };
}

export const CLAUDE_COVERAGE: CoverageItem[] = [
  { capability: "Pre-action block on shell", status: "yes", detail: "PreToolUse on Bash" },
  { capability: "File writes seen with content", status: "yes", detail: "Write, Edit, MultiEdit, NotebookEdit" },
  { capability: "File reads seen (taint from outside files)", status: "yes", detail: "Read, Grep, Glob, LS" },
  { capability: "Web fetch and search seen", status: "yes", detail: "WebFetch, WebSearch" },
  { capability: "MCP calls seen", status: "yes", detail: "mcp__server__tool, with the configuration source (mcp_server.source)" },
  { capability: "Tool output seen (taint, fingerprints)", status: "yes", detail: "PostToolUse, with redaction (updatedToolOutput)" },
  { capability: "Asks the person", status: "yes", detail: "permissionDecision ask" },
  { capability: "Fails closed by default", status: "partial", detail: "yes, except a timeout or a killed hook, unless onFailure: block (Claude Code 2.1.295+), which install sets; the command ends in || exit 2 for a crash, and the firewall denies at its own deadline before the 600 s timeout" },
  { capability: "Settings the agent can rewrite mid-session protected", status: "yes", detail: "writes are result-checked, and ConfigChange blocks a change that removes the hooks" },
  { capability: "Managed deployment the user cannot disable", status: "yes", detail: "managed-settings.json with allowManagedHooksOnly" },
  { capability: "Prompt seen (named destinations)", status: "yes", detail: "UserPromptSubmit" },
  { capability: "Subagents", status: "yes", detail: "subagent tool calls carry the parent's session id, so taint is shared" },
  { capability: "Cloud and remote runs", status: "no", detail: "local sessions only" },
];

/**
 * Why this Claude Code session is unattended, as nonInteractiveClaude says it: -p, or a process that could not be
 * read. The reason passes through unchanged, so an unreadable process is never relabelled as -p.
 */
export function claudeUnattended(ev: AdapterEvent, env: NodeJS.ProcessEnv, l: Layout, probe: ProcessProbe = {}): string | null {
  return nonInteractiveClaude(l, ev.sessionId, env, probe);
}

export const claudeAdapter: AgentAdapter = {
  id: "claude",
  parse: parseClaude,
  normalize: (ev) => [{ tool: ev.tool ?? "", input: ev.input ?? {} }],
  render: renderClaude,
  provenance: (server, projectDir, home) => mcpProvenance(server, projectDir, home),
  nonInteractive: claudeUnattended,
  supportsAsk: true,
  supportsUpdatedOutput: true,
  // Documented: "updatedInput replaces the input" and permission rules see the rewritten form (hooks reference).
  supportsUpdatedInput: true,
  projectDirEnv: "CLAUDE_PROJECT_DIR",
  testedVersion: "2.1.289",
  settings: CLAUDE_SETTINGS,
  coverage: CLAUDE_COVERAGE,
};
