/**
 * F-d: the host application's own tools (the Claude desktop app and Claude Code's built-in tools that
 * show something to the person), so that sharing a file with the person or setting a chapter title
 * is not read as bringing outside content into the session or as sending data out.
 *
 * Names and argument shapes come from real use, not from guesses:
 * - tool_use blocks recorded in Claude desktop session transcripts (Claude Code 2.1.289, 9 Oct 2026),
 *   with the decisions the firewall logged for them (SendUserFile, SubagentHandback and
 *   mcp__ccd_session__dismiss_task were judged as unknown tools / sends);
 * - the Claude Code 2.1.289 binary: its PreToolUse input schema documents `mcp_server.source` as
 *   "sdk | plugin | user | project | local | dynamic | managed | enterprise | claudeai | agent", where
 *   "sdk" is an in-process server only the host application can register (a configuration file that
 *   declares type "sdk" is rejected). The desktop app's ccd_* servers are such servers.
 * Fixtures: test/fixtures/claude-desktop-2.1.289-*.json. A tool not listed here is judged as before
 * (an unknown tool: R2, its result is outside content and a person is asked before it runs).
 * The Artifact read actions, ArtifactData and ArtifactComments (R2) follow the action names the host
 * documents for those tools; an action not listed is judged as the riskier entry (publish), never as UI.
 */

import type { FirewallConfig } from "../types.js";

export type HostToolKind =
  /** Shows content to the person: send a file, hand a report back. */
  | "to_user"
  /** Changes only the app's UI or session bookkeeping. */
  | "ui_state"
  /** Proposes a new session with a prompt (a person must click to start it). */
  | "spawn_session"
  /** Uploads content to a hosted page: egress, never to_user. */
  | "publish"
  /** R2: returns text other people wrote (someone else's page, rows other viewers wrote, comments): outside content. */
  | "read_outside";

export interface HostTool {
  name: string;
  kind: HostToolKind;
  /** Arguments that hold file paths (a string or a list of strings). "*" means any path-shaped argument. */
  pathArgs: readonly string[];
  /** Free-text arguments shown to the person (not egress for to_user / ui_state / spawn_session). */
  textArgs: readonly string[];
  /** For publish: where the content goes. */
  destination?: string;
  /** When only some calls of the tool are this kind (Artifact publishes; its read/list/delete are not host output). */
  appliesTo?: (input: Record<string, unknown>) => boolean;
}

/** The Claude Code version whose events the catalogue was checked against (doctor compares). */
export const HOST_TOOLS_VERIFIED_VERSION = "2.1.289";

/** MCP-shaped host tools are recognised only when Claude Code says the host registered the server. */
export const HOST_MCP_SOURCE = "sdk";

/** Claude Code's built-in tools (no mcp__ prefix: an MCP server cannot take these names). */
const BUILTIN: readonly HostTool[] = [
  // {"files": [<paths>], "caption": "...", "status": "normal" | "proactive"}
  { name: "SendUserFile", kind: "to_user", pathArgs: ["files"], textArgs: ["caption", "status"] },
  // A subagent's final report to the session that started it: {"message": "..."}
  { name: "SubagentHandback", kind: "to_user", pathArgs: [], textArgs: ["message"] },
  // Publishes a local HTML/Markdown file as a page on claude.ai: {"file_path": ..., "action": ..., "url": ...}
  // Only its publish action (the default) is catalogued; read/list/delete/pin are judged as before.
  { name: "Artifact", kind: "publish", pathArgs: ["file_path", "file_paths", "files", "root"], textArgs: ["description", "title", "label"], destination: "claude.ai", appliesTo: (i) => i.action === undefined || i.action === "publish" },
  // R2: {"action": "read", "url": ...} returns a published page, possibly someone else's (and the person's own
  // pages can hold text other viewers edited); {"action": "list", "scope": "shared" | "all" | "files" | "assets"}
  // returns titles and file names other people chose. Outside content. Only "list" of the person's own
  // artifacts (scope "mine", the default) is the person's own bookkeeping.
  { name: "Artifact", kind: "read_outside", pathArgs: [], textArgs: [], destination: "claude.ai", appliesTo: (i) => i.action === "read" || (i.action === "list" && i.scope !== undefined && i.scope !== "mine") },
  { name: "Artifact", kind: "ui_state", pathArgs: [], textArgs: [], appliesTo: (i) => i.action === "list" || i.action === "pin" || i.action === "unpin" },
  // R2: an artifact's shared database (schema as offered to a desktop session, 10 Oct 2026). get/list/query
  // return rows the page's viewers wrote, profiles returns names people chose: outside content.
  // set/update/str_replace/delete/batch write rows every viewer sees: data leaves the machine (a local JSON
  // file_path, also inside batch writes, is read and sent).
  { name: "ArtifactData", kind: "read_outside", pathArgs: [], textArgs: [], destination: "claude.ai", appliesTo: (i) => i.action === "get" || i.action === "list" || i.action === "query" || i.action === "profiles" },
  { name: "ArtifactData", kind: "publish", pathArgs: ["*"], textArgs: [], destination: "claude.ai" },
  // R2: comment threads on a published page. "read" returns other people's comments: outside content.
  // "watch" manages this session's subscriptions. "reply" and "resolve" change what other people see: data leaves the machine.
  { name: "ArtifactComments", kind: "read_outside", pathArgs: [], textArgs: [], destination: "claude.ai", appliesTo: (i) => i.action === "read" },
  { name: "ArtifactComments", kind: "ui_state", pathArgs: [], textArgs: [], appliesTo: (i) => i.action === "watch" },
  { name: "ArtifactComments", kind: "publish", pathArgs: [], textArgs: [], destination: "claude.ai" },
];

/** The desktop app's in-process MCP servers (source "sdk"). */
const MCP: readonly HostTool[] = [
  // {"title": "...", "summary": "..."}
  { name: "mcp__ccd_session__mark_chapter", kind: "ui_state", pathArgs: [], textArgs: ["title", "summary"] },
  // {"task_id": "...", "reason": "..."}
  { name: "mcp__ccd_session__dismiss_task", kind: "ui_state", pathArgs: [], textArgs: ["task_id", "reason"] },
  // {"title": "...", "tldr": "...", "prompt": "...", "cwd"?: "..."}
  { name: "mcp__ccd_session__spawn_task", kind: "spawn_session", pathArgs: [], textArgs: ["title", "tldr", "prompt", "cwd"] },
  // {"until": "session_idle", "reason": "..."} (keeps the Mac awake while a long task runs)
  { name: "mcp__ccd_host__request_keep_awake", kind: "ui_state", pathArgs: [], textArgs: ["until", "reason"] },
];

/** Every entry for a name, in order: the first whose appliesTo accepts the call wins. */
const BY_NAME = new Map<string, HostTool[]>();
for (const t of [...BUILTIN, ...MCP]) BY_NAME.set(t.name, [...(BY_NAME.get(t.name) ?? []), t]);

/**
 * The host tool a call names, or null (then it is judged as before). MCP-shaped names count only when
 * the server's source is the host's own ("sdk"): a repository-defined server named ccd_session does
 * not. A tool in the policy's notUserOutputTools is never a host tool; one in userOutputTools (user or
 * managed policy only) is treated as showing something to the person.
 */
export function hostTool(name: string, mcpSource: string | undefined, cfg: Pick<FirewallConfig, "userOutputTools" | "notUserOutputTools">, input: Record<string, unknown> = {}): HostTool | null {
  try {
    if (cfg.notUserOutputTools.includes(name)) return null;
    const entries = BY_NAME.get(name);
    if (entries !== undefined) {
      const known = entries.find((t) => t.appliesTo === undefined || t.appliesTo(input));
      if (known === undefined) return null;
      if (!name.startsWith("mcp__")) return known;
      return mcpSource === HOST_MCP_SOURCE ? known : null;
    }
    if (cfg.userOutputTools.includes(name)) return { name, kind: "to_user", pathArgs: ["*"], textArgs: [] };
  } catch {
    // A malformed policy list: judge the tool as before.
  }
  return null;
}

/** Every catalogued host tool (doctor and docs). */
export function hostToolCatalogue(): readonly HostTool[] {
  return [...BUILTIN, ...MCP];
}
