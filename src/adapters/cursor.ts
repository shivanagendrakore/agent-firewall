/**
 * The Cursor adapter (the Cursor CLI, `cursor-agent`, and the IDE's agent, local runs). Cursor's hooks
 * are command hooks in hooks.json (`{ "version": 1, "hooks": { "<step>": [{ command, timeout,
 * failClosed }] } }`), one JSON event on stdin, one JSON answer on stdout. Every shape here was read
 * from the hook executor and the tool executors shipped in cursor-agent 2026.10.01-e373342 and checked
 * against cursor.com/docs/hooks (10 Oct 2026); no live run was possible without a Cursor account, so the
 * fixtures (test/fixtures/cursor-2026.10.01-src-*.json) are reconstructed from that source, not
 * captured. See docs/agents/cursor.md.
 *
 * What Cursor's hooks give the firewall:
 *
 * - preToolUse fires before every local tool (Shell, Read, Write, Delete, Grep, List, Fetch, ...) with
 *   the tool's input, and its deny is enforced (the call is rejected). It is the decision point.
 * - An MCP call reaches preToolUse as `MCP:<tool>` with no server; beforeMCPExecution follows with the
 *   server's mcp.json key and its URL or launch command, so MCP calls are decided there.
 * - beforeReadFile runs after a read, before the model sees the content: the content is recorded
 *   (decoys, secret fingerprints) like a tool's output.
 * - postToolUse and afterMCPExecution carry outputs; beforeSubmitPrompt the person's prompt;
 *   sessionStart a new conversation; subagentStart/subagentStop the Task tool's subagents.
 * - No step asks the person in a way the firewall can use (preToolUse ignores "ask"), so an action that
 *   needs a person is held in the queue.
 *
 * Cursor also runs the hooks in Claude Code's settings files (third-party import, on by default) with
 * this same payload; the pipeline routes such an event here (isCursorEvent), and shortCircuit defers it
 * to the firewall's own Cursor hooks when those run.
 */

import { ancestorArgs, uninspectedReason, type Ancestry } from "../runtime/ancestry.js";
import { lstatSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { NormalizedAction } from "../types.js";
import type { Layout } from "../runtime/layout.js";
import { atomicWrite, readText } from "../runtime/fsutil.js";
import { safeId } from "../runtime/layout.js";
import { cursorHooksProblems, MARKER } from "../engine/settings.js";
import { AdapterParseError, UNPARSEABLE_TOOL, type AdapterEvent, type AgentAdapter, type CoverageItem, type HookIO, type HookOutcome } from "./types.js";
import { own } from "../own.js";

type Json = Record<string, unknown>;

/** cursor-agent's build the shapes were read from (2026.10.01-e373342). */
export const CURSOR_TESTED_VERSION = "2026.10.01";

const KINDS: Record<string, AdapterEvent["kind"]> = {
  preToolUse: "pre_tool",
  beforeShellExecution: "pre_tool",
  beforeMCPExecution: "pre_tool",
  postToolUse: "post_tool",
  afterShellExecution: "post_tool",
  afterMCPExecution: "post_tool",
  // Runs after the file was read and before the model sees it: the content is the read's output.
  beforeReadFile: "post_tool",
  beforeSubmitPrompt: "prompt",
  sessionStart: "session_start",
  sessionEnd: "session_end",
  subagentStart: "subagent_start",
  subagentStop: "subagent_stop",
  // A tool that failed: its error is still what the tool returned (taint, secrets), and it counts toward the
  // identical-failures spending limit (AdapterEvent.failed).
  postToolUseFailure: "post_tool",
  // The firewall judges actions, not text; Tab completions are the person's own edits.
  afterFileEdit: "ignored",
  stop: "ignored",
  preCompact: "ignored",
  afterAgentResponse: "ignored",
  afterAgentThought: "ignored",
  beforeTabFileRead: "ignored",
  afterTabFileEdit: "ignored",
  workspaceOpen: "ignored",
};

/** The steps the firewall registers in Cursor's hooks.json. */
export const CURSOR_HOOK_EVENTS = ["preToolUse", "postToolUse", "postToolUseFailure", "beforeMCPExecution", "afterMCPExecution", "beforeReadFile", "beforeSubmitPrompt", "sessionStart", "subagentStart", "subagentStop"] as const;

/** Cursor's permission steps: their answer must be JSON with a permission, or the action is blocked. */
const PERMISSION_STEPS = new Set(["preToolUse", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile", "beforeTabFileRead", "subagentStart"]);

/** Cursor rejects an additional_context over 10,000 characters (and a fail-closed preToolUse then blocks). */
const MAX_CONTEXT = 9000;

function json(o: unknown): string {
  return `${JSON.stringify(o)}\n`;
}

function str(o: Json, k: string): string | undefined {
  const v = own(o, k);
  return typeof v === "string" ? v : undefined;
}

function nonEmpty(o: Json, k: string): string | undefined {
  const v = str(o, k);
  return v !== undefined && v !== "" ? v : undefined;
}

/**
 * Whether a hook event is Cursor's: every Cursor payload carries cursor_version and a camelCase step
 * name. Cursor sends exactly this payload to the hooks it imports from Claude Code's settings.
 */
export function isCursorEvent(raw: Json): boolean {
  const name = str(raw, "hook_event_name");
  return typeof raw.cursor_version === "string" && name !== undefined && /^[a-z]/.test(name);
}

/** tool_input as an object: preToolUse sends one, beforeMCPExecution a JSON string. */
function inputObject(v: unknown): Json | null {
  if (typeof v === "object" && v !== null && !Array.isArray(v)) return v as Json;
  if (typeof v === "string") {
    try {
      const p: unknown = JSON.parse(v);
      return typeof p === "object" && p !== null && !Array.isArray(p) ? (p as Json) : null;
    } catch {
      return null;
    }
  }
  return v === undefined ? {} : null;
}

export function parseCursor(raw: Json): AdapterEvent {
  const name = str(raw, "hook_event_name");
  // Without the step name nothing says this is not a tool call: fail closed.
  if (name === undefined || name === "") throw new AdapterParseError("the event has no hook_event_name", true);
  const kind = own(KINDS, name) ?? "ignored";
  const blocking = kind === "pre_tool";
  const roots = Array.isArray(raw.workspace_roots) ? raw.workspace_roots.filter((x): x is string => typeof x === "string" && x !== "") : [];
  const sessionId = nonEmpty(raw, "conversation_id") ?? nonEmpty(raw, "session_id");
  // Only Shell carries a cwd; other tools run in the workspace.
  const cwd = nonEmpty(raw, "cwd") ?? roots[0];
  if (kind !== "ignored" && sessionId === undefined) throw new AdapterParseError(`${name} without a conversation_id`, blocking);
  if (kind !== "ignored" && cwd === undefined) throw new AdapterParseError(`${name} without a cwd or workspace root`, blocking);
  const ev: AdapterEvent = { kind, agent: "cursor", sessionId: sessionId ?? "no-session", cwd: cwd ?? process.cwd(), raw };
  if (roots[0] !== undefined) ev.projectDir = roots[0];
  if (name === "beforeMCPExecution" || name === "afterMCPExecution") {
    const server = nonEmpty(raw, "mcp_server_name");
    const tool = nonEmpty(raw, "tool_name");
    // Cursor's docs: a call without a recognisable server must be treated as a deny.
    if (server === undefined || tool === undefined) throw new AdapterParseError(`${name} without mcp_server_name or tool_name`, blocking);
    const input = inputObject(raw.tool_input);
    ev.tool = `mcp__${server}__${tool}`;
    ev.input = input ?? {};
    ev.mcp = { server, tool, structural: true };
    if (input === null) ev.raw = { ...raw, launchsafe_unparseable: "tool_input is not a JSON object" };
    if (kind === "post_tool") ev.output = raw.result_json ?? "";
    return ev;
  }
  if (name === "beforeReadFile") {
    const path = nonEmpty(raw, "file_path");
    if (path === undefined) throw new AdapterParseError("beforeReadFile without a file_path", false);
    ev.tool = "Read";
    ev.input = { file_path: path };
    ev.output = str(raw, "content") ?? "";
    return ev;
  }
  if (name === "beforeShellExecution" || name === "afterShellExecution") {
    const command = str(raw, "command");
    if (command === undefined) throw new AdapterParseError(`${name} without a command`, blocking);
    ev.tool = "Shell";
    ev.input = { command, cwd: str(raw, "cwd") ?? "" };
    if (kind === "post_tool") ev.output = raw.output ?? "";
    return ev;
  }
  if (kind === "pre_tool" || kind === "post_tool") {
    const tool = nonEmpty(raw, "tool_name");
    if (tool === undefined) throw new AdapterParseError(`${name} without a tool_name`, blocking);
    const input = inputObject(raw.tool_input);
    if (input === null) throw new AdapterParseError(`${name} for ${tool} without a tool_input object`, blocking);
    ev.tool = tool;
    ev.input = input;
    // preToolUse names an MCP tool MCP:<tool>, without its server (beforeMCPExecution names it).
    if (tool.startsWith("MCP:")) ev.mcp = { server: "unknown", tool: tool.slice(4) };
    if (kind === "post_tool") ev.output = name === "postToolUseFailure" ? (raw.error_message ?? raw.error ?? raw.tool_output ?? "") : (raw.tool_output ?? "");
    if (name === "postToolUseFailure") ev.failed = true;
  }
  if (kind === "prompt") ev.prompt = str(raw, "prompt") ?? "";
  if (kind === "subagent_start" || kind === "subagent_stop") {
    // A subagent is its own conversation: subagent_id (child_conversation_id on stop), linked to the parent's.
    const child = kind === "subagent_stop" ? (nonEmpty(raw, "child_conversation_id") ?? nonEmpty(raw, "subagent_id")) : nonEmpty(raw, "subagent_id");
    const parent = nonEmpty(raw, "parent_conversation_id") ?? sessionId;
    if (child !== undefined) {
      ev.sessionId = child;
      if (parent !== undefined) ev.parentSessionId = parent;
    }
  }
  return ev;
}

function shq(s: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Cursor's tools (the names its hooks report) translated to the engine's vocabulary. */
export function normalizeCursor(ev: AdapterEvent): NormalizedAction[] {
  const tool = ev.tool ?? "";
  const input = ev.input ?? {};
  const s = (k: string): string | undefined => str(input, k);
  if (typeof ev.raw.launchsafe_unparseable === "string") return [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: ev.raw.launchsafe_unparseable } }];
  if (ev.mcp !== undefined) return [{ tool: `mcp__${ev.mcp.server}__${ev.mcp.tool}`, input }];
  switch (tool) {
    case "Shell": {
      const command = s("command");
      if (command === undefined) return [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: "no command" } }];
      const dir = s("cwd") ?? s("working_directory");
      return [{ tool: "Bash", input: { command: dir !== undefined && dir !== "" && resolve(ev.cwd, dir) !== resolve(ev.cwd) ? `cd ${shq(dir)} && ${command}` : command } }];
    }
    case "Read":
    case "ReadLints": {
      const p = s("file_path") ?? s("path");
      return p === undefined ? [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: "no file path" } }] : [{ tool: "Read", input: { file_path: p } }];
    }
    case "Write": {
      // Cursor's edits reach the hook as a Write of the whole new file text, so the result is exact (no
      // loose matching to over-approximate). Without that text the result is unknown: never judged as
      // an empty file.
      const p = s("file_path") ?? s("path");
      if (p === undefined) return [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: "no file path" } }];
      const content = s("content");
      return content === undefined ? [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: `a write to ${p} without the new file text` } }] : [{ tool: "Write", input: { file_path: p, content } }];
    }
    case "Delete": {
      const p = s("file_path") ?? s("path");
      return p === undefined ? [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: "no file path" } }] : [{ tool: "Bash", input: { command: `rm -- ${shq(p)}` } }];
    }
    case "Grep":
      return [{ tool: "Grep", input: { pattern: s("pattern") ?? "", path: s("file_path") ?? s("path") ?? ev.cwd } }];
    case "List":
      return [{ tool: "LS", input: { path: s("file_path") ?? s("path") ?? ev.cwd } }];
    case "Glob":
      return [{ tool: "Glob", input: { pattern: s("glob_pattern") ?? s("pattern") ?? "", path: s("target_directory") ?? s("path") ?? ev.cwd } }];
    case "Fetch":
    case "WebFetch":
      return [{ tool: "WebFetch", input: { url: s("url") ?? "", prompt: "" } }];
    case "WebSearch":
      return [{ tool: "WebSearch", input: { query: s("search_term") ?? s("query") ?? "" } }];
    // The Task tool starts a subagent; its own tool calls are judged one by one.
    case "Task":
    case "task":
      return [{ tool: "Agent", input }];
    // The agent's own to-do list, plan and questions (names from Cursor's tool-call kinds, not seen in a
    // hook event): they only talk to the agent and the person.
    case "updateTodos":
    case "readTodos":
    case "UpdateTodos":
    case "ReadTodos":
    case "TodoWrite":
      return [{ tool: "TodoWrite", input }];
    case "createPlan":
    case "CreatePlan":
    case "askQuestion":
    case "AskQuestion":
      return [{ tool: "AskUserQuestion", input }];
    case "ListMcpResources":
      return [{ tool: "ListMcpResourcesTool", input: { server: s("server") ?? "" } }];
    case "FetchMcpResource": {
      const out: NormalizedAction[] = [{ tool: "ReadMcpResourceTool", input: { server: s("server") ?? "", uri: s("uri") ?? "" } }];
      const dest = s("download_path");
      // Saving the resource is a write whose content the hook does not carry (a result that cannot be
      // known is judged as the worst case): judged like a shell write of unknown content to that path, so a
      // hook settings file is FW-TAMPER and a git hook or editor task asks or is held.
      if (dest !== undefined && dest !== "") out.push({ tool: "Bash", input: { command: `cat > ${shq(dest)}` } });
      return out;
    }
    default:
      // WriteShellStdin (the characters are not in the hook input), ComputerUse, RecordScreen and any
      // tool not listed: an unknown tool, held for a person.
      return [{ tool, input }];
  }
}

function cap(s: string): string {
  return s.length > MAX_CONTEXT ? `${s.slice(0, MAX_CONTEXT - 1)}…` : s;
}

export function renderCursor(ev: AdapterEvent, out: HookOutcome): HookIO {
  const stderr = out.stderr ?? "";
  const step = str(ev.raw, "hook_event_name") ?? "";
  const o: Json = {};
  // A Cursor event that came through the Claude Code hooks is answered in Claude Code's protocol, which does not
  // read a permission field: a block there is exit 2 with the reason on stderr.
  if (ev.via !== undefined && ev.kind === "pre_tool" && out.verdict !== "allow") return { stdout: "", stderr: out.message, exitCode: 2 };
  if (PERMISSION_STEPS.has(step)) {
    // Every permission step gets an explicit permission: an empty answer fails closed (failClosed: true).
    if (ev.kind === "pre_tool" && out.verdict !== "allow") {
      o.permission = "deny";
      o.user_message = out.message;
      o.agent_message = out.message;
    } else o.permission = "allow";
    if (step === "preToolUse" && out.additionalContext !== undefined) o.additional_context = cap(out.additionalContext);
  } else if (step === "beforeSubmitPrompt") o.continue = true;
  else if ((step === "postToolUse" || step === "sessionStart") && out.additionalContext !== undefined) o.additional_context = cap(out.additionalContext);
  return { stdout: json(o), stderr, exitCode: 0 };
}

/** The verdict in a Cursor hook answer (tests and the scenario harness). */
export function cursorVerdict(io: HookIO): { verdict: "allow" | "ask" | "deny"; reason: string } {
  if (io.exitCode === 2) return { verdict: "deny", reason: io.stderr };
  if (io.stdout.trim() === "") return { verdict: "allow", reason: "" };
  const o = JSON.parse(io.stdout) as { permission?: string; user_message?: string; agent_message?: string; continue?: boolean };
  const reason = o.agent_message ?? o.user_message ?? "";
  if (o.permission === "deny" || o.continue === false) return { verdict: "deny", reason };
  return { verdict: o.permission === "ask" ? "ask" : "allow", reason };
}

/** ~/.cursor: Cursor reads it from the OS home directory (no variable moves it). */
export function cursorHome(home = homedir()): string {
  return join(home, ".cursor");
}

export const CURSOR_ENTERPRISE_HOOKS: Partial<Record<NodeJS.Platform, string>> = {
  darwin: "/Library/Application Support/Cursor/hooks.json",
  linux: "/etc/cursor/hooks.json",
};

function mcpServers(text: string | null): Json {
  if (text === null) return {};
  try {
    const v = (JSON.parse(text) as Json).mcpServers;
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : {};
  } catch {
    return {};
  }
}

/** Where an MCP server was configured: the project's .cursor/mcp.json, else the user's ~/.cursor/mcp.json. */
export function cursorProvenance(server: string, projectDir: string, home = homedir()): string {
  // F42: own keys only ("constructor" or "toString" is not a configured server).
  if (Object.hasOwn(mcpServers(readText(join(resolve(projectDir), ".cursor", "mcp.json"))), server)) return "project";
  if (Object.hasOwn(mcpServers(readText(join(cursorHome(home), "mcp.json"))), server)) return "user";
  return "unknown";
}

/**
 * The text of a hooks.json Cursor would load, else null. Cursor refuses a hooks.json reached through a
 * symlink (a dotfile-managed ~/.cursor, or the file itself), so such a file is "no Cursor hook": the
 * imported Claude Code hook then decides instead of standing down for a hook that never runs. Anything
 * that is not a plain file, or cannot be inspected, counts the same way.
 */
function loadableHooks(path: string): string | null {
  try {
    if (lstatSync(dirname(path)).isSymbolicLink()) return null;
    if (!lstatSync(path).isFile()) return null;
    return readText(path);
  } catch {
    return null;
  }
}

/**
 * Whether the entry's matcher covers this tool. No matcher: every tool. A matcher is a regex on the tool
 * name; an entry narrowed by one covers only the tools it matches, so a step without a tool name or an
 * invalid or non-string matcher is not covered (the imported hook then decides).
 */
function matcherCovers(matcher: unknown, tool: string | undefined): boolean {
  if (matcher === undefined) return true;
  if (typeof matcher !== "string" || tool === undefined) return false;
  try {
    return new RegExp(matcher).test(tool);
  } catch {
    return false;
  }
}

/** Whether a hooks.json Cursor loads registers the firewall for a step and tool (and Cursor would accept the file). */
function registersStep(text: string | null, step: string, tool?: string): boolean {
  if (text === null || !text.includes(MARKER)) return false;
  try {
    const s = JSON.parse(text) as { hooks?: Record<string, unknown> };
    if (cursorHooksProblems(s).length > 0) return false;
    const list = own(s.hooks, step);
    return Array.isArray(list) && list.some((e) => typeof (e as { command?: unknown } | null)?.command === "string" && (e as { command: string }).command.includes(MARKER) && (e as { failClosed?: unknown }).failClosed === true && matcherCovers((e as { matcher?: unknown }).matcher, tool));
  } catch {
    return false;
  }
}

/**
 * Whether the firewall's own Cursor hook runs for this step (and tool): registered (fail-closed, not
 * narrowed away from the tool by a matcher, in a plain file Cursor accepts) in the user's
 * ~/.cursor/hooks.json or the enterprise file, which Cursor loads in every workspace. A project's
 * .cursor/hooks.json is not counted: Cursor skips it in an untrusted workspace.
 */
export function cursorNativeActive(step: string, home = homedir(), platform: NodeJS.Platform = process.platform, tool?: string): boolean {
  const ent = CURSOR_ENTERPRISE_HOOKS[platform];
  return registersStep(loadableHooks(join(cursorHome(home), "hooks.json")), step, tool) || (ent !== undefined && registersStep(loadableHooks(ent), step, tool));
}

/**
 * Events another hook of the firewall decides. An MCP call: preToolUse's MCP:<tool> and postToolUse's
 * carry no server, beforeMCPExecution and afterMCPExecution (registered with them) do. A read:
 * beforeReadFile carries the content postToolUse lacks. A Cursor event that came through the Claude
 * Code hooks (Cursor's third-party import) while the firewall's Cursor hook runs for the same step:
 * that hook decides (Cursor merges answers, a deny from any hook wins), so this one says allow and
 * records nothing. Without the Cursor hooks, the imported event is decided here in full.
 */
export function cursorShortCircuit(ev: AdapterEvent, o: { home?: string }): HookOutcome | null {
  const step = str(ev.raw, "hook_event_name") ?? "";
  if (ev.via !== undefined) return (step === "preToolUse" || step === "postToolUse" || step === "beforeSubmitPrompt" || step === "sessionStart") && cursorNativeActive(step, o.home, process.platform, ev.tool) ? { verdict: "allow", message: "" } : null;
  // Only when beforeMCPExecution (afterMCPExecution for the result) is registered here: without it nothing else decides.
  if ((step === "preToolUse" || step === "postToolUse") && (ev.tool ?? "").startsWith("MCP:")) return cursorNativeActive(step === "preToolUse" ? "beforeMCPExecution" : "afterMCPExecution", o.home, process.platform) ? { verdict: "allow", message: "" } : null;
  if (step === "postToolUse" && ev.tool === "Read") return { verdict: "allow", message: "" };
  return null;
}

/** Whether a Cursor CLI command line runs non-interactively (-p / --print) or runs everything (--force / --yolo). */
export function cursorUnattendedArgs(args: string): string | null {
  if (!/cursor-agent/.test(args)) return null;
  if (/(?:^|\s)(?:-p|--print)(?:\s|=|$)/.test(args)) return "the Cursor CLI is running non-interactively (-p)";
  if (/(?:^|\s)(?:-f|--force|--yolo)(?:\s|$)/.test(args)) return "the Cursor CLI runs everything without asking (--force)";
  return null;
}

/**
 * Unattended: a background agent (sessionStart's is_background_agent), `cursor-agent -p` or `--force` in
 * the process ancestry, or approvalMode "unrestricted" (Run Everything) in ~/.cursor/cli-config.json.
 * When no process could be inspected and the config says nothing, the session is treated as unattended,
 * the strict reading. A definite answer is cached per conversation; that one is not.
 */
export function nonInteractiveCursor(ev: AdapterEvent, _env: NodeJS.ProcessEnv, l: Layout, inspect: () => Ancestry = () => ancestorArgs(process.ppid, { depth: 5, pattern: "cursor-agent" })): string | null {
  const cache = join(l.sessions, `${safeId(`cursor:${ev.sessionId}`)}.meta.json`);
  if (ev.raw.is_background_agent === true) {
    const reason = "this is a Cursor background agent";
    try {
      atomicWrite(cache, JSON.stringify({ reason }));
    } catch {
      // Cache is an optimization only.
    }
    return reason;
  }
  const cached = readText(cache);
  if (cached !== null) {
    try {
      const c = JSON.parse(cached) as { reason?: string | null };
      if (c.reason === null || typeof c.reason === "string") return c.reason;
    } catch {
      // Re-detect below.
    }
  }
  let reason: string | null = null;
  const anc = inspect();
  for (const args of anc.args) {
    reason = cursorUnattendedArgs(args);
    if (reason !== null) break;
  }
  if (reason === null) {
    try {
      const cfg = JSON.parse(readText(join(cursorHome(), "cli-config.json")) ?? "{}") as { approvalMode?: unknown };
      if (cfg.approvalMode === "unrestricted") reason = 'the Cursor CLI\'s approvalMode is "unrestricted" (Run Everything)';
    } catch {
      // An unreadable config is Cursor's to report.
    }
  }
  if (reason === null && !anc.inspected) return uninspectedReason("Cursor");
  try {
    atomicWrite(cache, JSON.stringify({ reason }));
  } catch {
    // Cache is an optimization only.
  }
  return reason;
}

export const CURSOR_COVERAGE: CoverageItem[] = [
  { capability: "Pre-action block on shell", status: "yes", detail: "preToolUse on Shell (deny enforced; read from cursor-agent 2026.10.01's source)" },
  { capability: "File writes seen with content", status: "partial", detail: "preToolUse runs before Write (the whole new file text) and Delete and its deny is enforced in the CLI (read from its source); the IDE is documented to do the same, not verified; Tab completions are the person's edits and reach no agent hook" },
  { capability: "File reads seen (taint from outside files)", status: "yes", detail: "preToolUse on Read decides; beforeReadFile hands over the content after the read, before the model sees it (decoys, secret fingerprints)" },
  { capability: "Web fetch and search seen", status: "partial", detail: "Fetch is seen with its URL; WebSearch and other server-side tools reach preToolUse only through Cursor's server, under names not verified (an unlisted name is held)" },
  { capability: "MCP calls seen", status: "yes", detail: "beforeMCPExecution names the server (its mcp.json key) and its URL or launch command; the configuration source is read from .cursor/mcp.json (project, user)" },
  { capability: "Tool output seen (taint, fingerprints)", status: "yes", detail: "postToolUse, afterMCPExecution, and beforeReadFile's content; secrets in output are not redacted" },
  { capability: "Asks the person", status: "no", detail: "preToolUse ignores ask: an action that needs a person is held in the queue and denied with the queue command to approve it" },
  { capability: "Fails closed by default", status: "yes", detail: "every entry says failClosed: true, so a crash, a non-zero exit, a timeout (30 s) or no output blocks the step (read from source)" },
  { capability: "Hooks run once installed", status: "partial", detail: "the user's ~/.cursor/hooks.json always loads (no trust step); a project's .cursor/hooks.json only in a trusted workspace; Cursor drops a hooks.json whole when any entry is invalid, and refuses a symlinked one (doctor checks both)" },
  { capability: "Settings the agent can rewrite mid-session protected", status: "partial", detail: "writes to hooks.json are result-checked, including Cursor's validation of the whole file; Cursor has no ConfigChange event and reloads hooks.json on save" },
  { capability: "Managed deployment the user cannot disable", status: "partial", detail: "the enterprise hooks.json (MDM) and team hooks run in every workspace and a deny from any source wins, but nothing stops other hooks from running" },
  { capability: "Prompt seen (named destinations)", status: "yes", detail: "beforeSubmitPrompt" },
  { capability: "Subagents", status: "partial", detail: "subagentStart and subagentStop link a subagent (subagent_id) to its parent; whether its tool calls carry that id was not verified live" },
  { capability: "Cloud and remote runs", status: "no", detail: "cloud agents run only the repository's .cursor/hooks.json, where a project install's local paths do not exist (and, failing closed, block every action)" },
  { capability: "Claude Code hooks imported", status: "yes", detail: "Cursor runs the hooks in Claude Code's settings too, with its own payload: the firewall recognises the event, and defers to its Cursor hooks when they run" },
];

export function cursorHooksPath(scope: "user" | "project" | "local", projectDir: string, home: string): string {
  return scope === "user" ? join(cursorHome(home), "hooks.json") : join(resolve(projectDir), ".cursor", "hooks.json");
}

/** Cursor accepts a hooks.json only with a positive integer version. */
export function cursorEnable(s: Json): Json {
  return typeof s.version === "number" && Number.isInteger(s.version) && s.version >= 1 ? s : { version: 1, ...s };
}

/** Why Cursor would load none of the hooks in this file (it validates the file as a whole). */
export function cursorDisabledBy(s: Json): string[] {
  return cursorHooksProblems(s).map((p) => `Cursor rejects the whole file: ${p}`);
}

export function cursorManagedSnippet(command: string): string {
  return JSON.stringify({ version: 1, hooks: Object.fromEntries(CURSOR_HOOK_EVENTS.map((ev) => [ev, [{ type: "command", command, timeout: 30, failClosed: true }]])) }, null, 2);
}

export const cursorAdapter: AgentAdapter = {
  id: "cursor",
  parse: parseCursor,
  normalize: normalizeCursor,
  render: renderCursor,
  provenance: (server, projectDir, home) => cursorProvenance(server, projectDir, home),
  nonInteractive: nonInteractiveCursor,
  shortCircuit: cursorShortCircuit,
  supportsAsk: false,
  supportsUpdatedOutput: false,
  // No verified input rewrite in Cursor hooks: vault references in shell commands are refused.
  supportsUpdatedInput: false,
  projectDirEnv: "CURSOR_PROJECT_DIR",
  testedVersion: CURSOR_TESTED_VERSION,
  settings: {
    label: "Cursor",
    scopes: ["user", "project"],
    path: (scope, projectDir, home) => cursorHooksPath(scope, projectDir, home),
    events: CURSOR_HOOK_EVENTS,
    // No matcher: an entry without one runs for every tool.
    matched: new Set(),
    matchAll: "*",
    // Cursor hook timeouts are in seconds.
    timeout: 30,
    entryExtras: { failClosed: true },
    flat: true,
    refuseSymlink: true,
    failClosedEntry: (e) => e.failClosed === true,
    enable: cursorEnable,
    disabledBy: cursorDisabledBy,
    managedPaths: CURSOR_ENTERPRISE_HOOKS,
    managedSnippet: (command) => ({ path: CURSOR_ENTERPRISE_HOOKS[process.platform] ?? "/etc/cursor/hooks.json", format: "json", text: cursorManagedSnippet(command) }),
  },
  coverage: CURSOR_COVERAGE,
};
