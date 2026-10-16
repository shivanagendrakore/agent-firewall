/**
 * The Google Gemini CLI adapter. Gemini CLI's hooks are command hooks
 * registered in settings.json under `hooks`, keyed by its own event names
 * (BeforeTool, AfterTool, BeforeAgent, SessionStart, ...), reading one JSON
 * event on stdin (session_id, cwd, hook_event_name, tool_name, tool_input,
 * tool_response, prompt) and answering with `{ "decision": "deny", "reason" }`
 * (or exit 2, which blocks). See docs/agents/gemini.md for how each field was
 * verified (fixtures in test/fixtures/gemini-*.json).
 *
 * Native tools are translated to the engine's vocabulary: run_shell_command
 * is Bash, read_file/read_many_files are reads, write_file is Write, replace
 * is Edit, web_fetch is one WebFetch per URL in its prompt, save_memory is a
 * write to ~/.gemini/GEMINI.md (the agent's memory: held when untrusted).
 */

import { homedir } from "node:os";
import { join, resolve } from "node:path";
import type { NormalizedAction } from "../types.js";
import type { Layout } from "../runtime/layout.js";
import { atomicWrite, readText } from "../runtime/fsutil.js";
import { safeId } from "../runtime/layout.js";
import { ancestorArgs, uninspectedReason, type Ancestry } from "../runtime/ancestry.js";
import { AdapterParseError, UNPARSEABLE_TOOL, type AdapterEvent, type AgentAdapter, type CoverageItem, type HookIO, type HookOutcome } from "./types.js";
import { own } from "../own.js";

type Json = Record<string, unknown>;

export const GEMINI_TESTED_VERSION = "0.63.0";

const KINDS: Record<string, AdapterEvent["kind"]> = {
  BeforeTool: "pre_tool",
  AfterTool: "post_tool",
  BeforeAgent: "prompt",
  SessionStart: "session_start",
  SessionEnd: "session_end",
  // The firewall judges actions, not text.
  BeforeModel: "ignored",
  AfterModel: "ignored",
  BeforeToolSelection: "ignored",
  AfterAgent: "ignored",
  PreCompress: "ignored",
  Notification: "ignored",
};

/** The events the firewall registers in Gemini CLI's settings.json. */
export const GEMINI_HOOK_EVENTS = ["BeforeTool", "AfterTool", "BeforeAgent", "SessionStart"] as const;

function json(o: unknown): string {
  return `${JSON.stringify(o)}\n`;
}

function str(o: Json, k: string): string | undefined {
  const v = own(o, k);
  return typeof v === "string" ? v : undefined;
}

/**
 * MCP tool names: Gemini CLI names an MCP tool `<server>__<tool>` (and reports `mcp_<server>_<tool>` in
 * some versions); the hook input may also carry the server separately. Normalized to mcp__server__tool.
 */
export function geminiMcp(tool: string, input: Json, raw: Json): { server: string; tool: string; structural?: boolean } | null {
  const ctx = typeof raw.mcp_context === "object" && raw.mcp_context !== null ? (raw.mcp_context as Json) : {};
  const server = str(ctx, "server_name") ?? str(raw, "mcp_server_name") ?? str(raw, "server_name");
  const named = str(ctx, "tool_name");
  // I4: mcp_context names both the server and the tool: that is the identity, whatever the tool's full name holds.
  if (server !== undefined && server !== "" && named !== undefined && named !== "") return { server, tool: named, structural: true };
  if (server !== undefined && server !== "") return { server, tool: tool.replace(new RegExp(`^(?:mcp__)?${server.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}__`), "") };
  void input;
  const m = /^mcp__(.+?)__(.+)$/.exec(tool) ?? /^([A-Za-z0-9_.-]+?)__(.+)$/.exec(tool);
  return m !== null ? { server: m[1] as string, tool: m[2] as string } : null;
}

export function parseGemini(raw: Json): AdapterEvent {
  const name = str(raw, "hook_event_name");
  if (name === undefined || name === "") throw new AdapterParseError("the event has no hook_event_name", true);
  const kind = own(KINDS, name) ?? "ignored";
  const blocking = kind === "pre_tool";
  const sessionId = str(raw, "session_id");
  const cwd = str(raw, "cwd");
  if (kind !== "ignored" && (sessionId === undefined || sessionId === "")) throw new AdapterParseError(`${name} without a session_id`, blocking);
  if (kind !== "ignored" && (cwd === undefined || cwd === "")) throw new AdapterParseError(`${name} without a cwd`, blocking);
  const ev: AdapterEvent = { kind, agent: "gemini", sessionId: sessionId ?? "no-session", cwd: cwd ?? process.cwd(), raw };
  if (kind === "pre_tool" || kind === "post_tool") {
    const tool = str(raw, "tool_name");
    if (tool === undefined || tool === "") throw new AdapterParseError(`${name} without a tool_name`, blocking);
    const input = raw.tool_input ?? {};
    if (typeof input !== "object" || input === null || Array.isArray(input)) throw new AdapterParseError(`${name} for ${tool} without a tool_input object`, blocking);
    ev.tool = tool;
    ev.input = input as Json;
    if (!GEMINI_TOOLS.has(tool)) {
      const m = geminiMcp(tool, input as Json, raw);
      if (m !== null) ev.mcp = m;
    }
  }
  if (kind === "post_tool") ev.output = raw.tool_response ?? "";
  if (kind === "prompt") ev.prompt = str(raw, "prompt") ?? "";
  if (kind === "session_start") {
    const source = str(raw, "source");
    if (source !== undefined) ev.source = source;
  }
  return ev;
}

/** Gemini CLI's built-in tools (so a built-in is never mistaken for an MCP tool). */
export const GEMINI_TOOLS: ReadonlySet<string> = new Set(["run_shell_command", "read_file", "read_many_files", "write_file", "replace", "list_directory", "glob", "search_file_content", "grep_search", "web_fetch", "google_web_search", "save_memory", "write_todos", "update_topic", "invoke_agent", "activate_skill", "codebase_investigator", "complete_task", "enter_plan_mode", "exit_plan_mode", "ask_user", "list_background_processes", "read_background_output"]);

/**
 * The URLs in web_fetch's prompt argument, as Gemini CLI takes them: the prompt is split on whitespace
 * and every token that is a URL is requested whole, brackets and quotes included. A URL that starts inside
 * a token ("(https://...") is kept too, from its scheme to the end of the token, so no request is ever
 * judged on less than it sends. (Gemini CLI's extraction was read from its source, not captured.)
 */
export function urlsIn(text: string): string[] {
  const out: string[] = [];
  for (const tok of text.split(/\s+/)) {
    const i = tok.search(/https?:\/\//i);
    if (i !== -1) out.push(tok.slice(i));
  }
  return [...new Set(out)];
}

function hasGlob(p: string): boolean {
  return /[*?[\]{}]/.test(p);
}

/** The directory part of a glob, before its first wildcard. */
function globBase(p: string): string {
  const parts = p.split("/");
  const i = parts.findIndex(hasGlob);
  const base = parts.slice(0, i === -1 ? parts.length : i).join("/");
  return base === "" ? "." : base;
}

export function normalizeGemini(ev: AdapterEvent): NormalizedAction[] {
  const tool = ev.tool ?? "";
  const input = ev.input ?? {};
  const s = (k: string): string | undefined => str(input, k);
  switch (tool) {
    case "run_shell_command": {
      const command = s("command");
      if (command === undefined) return [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: "no command" } }];
      const dir = s("dir_path") ?? s("directory");
      return [{ tool: "Bash", input: { command: dir !== undefined && dir !== "" && dir !== "." ? `cd '${dir.replace(/'/g, `'\\''`)}' && ${command}` : command } }];
    }
    case "read_file": {
      const p = s("file_path") ?? s("absolute_path") ?? s("path");
      return p === undefined ? [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: "no file path" } }] : [{ tool: "Read", input: { file_path: p } }];
    }
    case "read_many_files": {
      const list = [input.paths, input.include].flatMap((v) => (Array.isArray(v) ? v : typeof v === "string" ? [v] : [])).filter((x): x is string => typeof x === "string");
      if (list.length === 0) return [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: "no paths" } }];
      // A glob reads whatever matches: treated as a recursive read of its base directory.
      return list.map((p) => (hasGlob(p) ? { tool: "Grep", input: { pattern: "", path: globBase(p) } } : { tool: "Read", input: { file_path: p } }));
    }
    case "write_file": {
      const p = s("file_path") ?? s("path");
      return p === undefined ? [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: "no file path" } }] : [{ tool: "Write", input: { file_path: p, content: s("content") ?? "" } }];
    }
    case "replace": {
      const p = s("file_path") ?? s("path");
      if (p === undefined) return [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: "no file path" } }];
      const all = input.allow_multiple === true || (typeof input.expected_replacements === "number" && input.expected_replacements > 1);
      // Gemini CLI's replace matches old_string flexibly (whitespace-insensitive lines) and can correct it
      // from its instruction: judged against every plausible match, and as unknown when none (match "loose").
      return [{ tool: "Edit", input: { file_path: p, old_string: s("old_string") ?? "", new_string: s("new_string") ?? "", ...(all ? { replace_all: true } : {}), match: "loose" } }];
    }
    case "list_directory":
      return [{ tool: "LS", input: { path: s("dir_path") ?? s("path") ?? ev.cwd } }];
    case "glob":
      return [{ tool: "Glob", input: { pattern: s("pattern") ?? "", path: s("dir_path") ?? s("path") ?? ev.cwd } }];
    case "search_file_content":
    case "grep_search":
      return [{ tool: "Grep", input: { pattern: s("pattern") ?? "", path: s("dir_path") ?? s("path") ?? ev.cwd } }];
    case "web_fetch": {
      const prompt = s("prompt") ?? s("url") ?? "";
      const urls = urlsIn(prompt);
      // No address the firewall can read: WebFetch of an unreadable address is a parse failure (a person decides).
      return urls.length === 0 ? [{ tool: "WebFetch", input: { url: prompt.slice(0, 200), prompt: "" } }] : urls.map((url) => ({ tool: "WebFetch", input: { url, prompt: "" } }));
    }
    case "google_web_search":
      return [{ tool: "WebSearch", input: { query: s("query") ?? "" } }];
    case "save_memory":
      return [{ tool: "Write", input: { file_path: join(geminiHome(), "GEMINI.md"), content: s("fact") ?? "" } }];
    case "write_todos":
    case "update_topic":
      return [{ tool: "TodoWrite", input }];
    // A subagent's tool calls arrive under the same session_id (captured), so its taint is the session's.
    case "invoke_agent":
    case "codebase_investigator":
      return [{ tool: "Agent", input }];
    case "activate_skill":
      return [{ tool: "Skill", input }];
    case "list_background_processes":
    case "read_background_output":
      return [{ tool: "BashOutput", input }];
    case "enter_plan_mode":
    case "exit_plan_mode":
    case "complete_task":
    case "ask_user":
      return [{ tool: "AskUserQuestion", input }];
    default: {
      const m = ev.mcp;
      if (m !== undefined) return [{ tool: `mcp__${m.server}__${m.tool}`, input }];
      return [{ tool, input }];
    }
  }
}

/** ~/.gemini (Gemini CLI has no variable that moves it; GEMINI_CLI_HOME is honoured where set). */
export function geminiHome(env: NodeJS.ProcessEnv = process.env, home = homedir()): string {
  return env.GEMINI_CLI_HOME !== undefined && env.GEMINI_CLI_HOME !== "" ? join(env.GEMINI_CLI_HOME, ".gemini") : join(home, ".gemini");
}

export function renderGemini(ev: AdapterEvent, out: HookOutcome): HookIO {
  const stderr = out.stderr ?? "";
  switch (ev.kind) {
    case "pre_tool": {
      if (out.verdict === "allow") {
        if (out.systemMessage !== undefined) return { stdout: json({ systemMessage: out.systemMessage }), stderr, exitCode: 0 };
        return { stdout: "", stderr, exitCode: 0 };
      }
      return { stdout: json({ decision: out.verdict === "ask" ? "ask" : "deny", reason: out.message, ...(out.systemMessage !== undefined ? { systemMessage: out.systemMessage } : {}) }), stderr, exitCode: 0 };
    }
    case "post_tool": {
      const o: Json = {};
      if (out.additionalContext !== undefined) o.hookSpecificOutput = { hookEventName: "AfterTool", additionalContext: out.additionalContext };
      if (out.systemMessage !== undefined) o.systemMessage = out.systemMessage;
      return { stdout: Object.keys(o).length > 0 ? json(o) : "", stderr, exitCode: 0 };
    }
    case "session_start": {
      const o: Json = {};
      if (out.additionalContext !== undefined) o.hookSpecificOutput = { hookEventName: "SessionStart", additionalContext: out.additionalContext };
      if (out.systemMessage !== undefined) o.systemMessage = out.systemMessage;
      return { stdout: Object.keys(o).length > 0 ? json(o) : "", stderr, exitCode: 0 };
    }
    default:
      return { stdout: "", stderr, exitCode: 0 };
  }
}

/** The verdict in a Gemini CLI hook answer (tests and the scenario harness). */
export function geminiVerdict(io: HookIO): { verdict: "allow" | "ask" | "deny"; reason: string } {
  if (io.exitCode === 2) return { verdict: "deny", reason: io.stderr };
  if (io.stdout.trim() === "") return { verdict: "allow", reason: "" };
  const o = JSON.parse(io.stdout) as { decision?: string; reason?: string };
  return { verdict: o.decision === "ask" ? "ask" : o.decision === "deny" || o.decision === "block" ? "deny" : "allow", reason: o.reason ?? "" };
}

/** The system settings file: GEMINI_CLI_SYSTEM_SETTINGS_PATH, else the platform's path. */
export function geminiSystemSettings(env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform): string | undefined {
  const v = env.GEMINI_CLI_SYSTEM_SETTINGS_PATH;
  return v !== undefined && v !== "" ? v : GEMINI_SYSTEM_SETTINGS[platform];
}

export const GEMINI_SYSTEM_SETTINGS: Partial<Record<NodeJS.Platform, string>> = {
  darwin: "/Library/Application Support/GeminiCli/settings.json",
  linux: "/etc/gemini-cli/settings.json",
};

function settingsServers(text: string | null): Json {
  if (text === null) return {};
  try {
    const v = (JSON.parse(text) as Json).mcpServers;
    return typeof v === "object" && v !== null ? (v as Json) : {};
  } catch {
    return {};
  }
}

/** Where an MCP server was configured: the project's .gemini/settings.json, the user's, or system settings. */
export function geminiProvenance(server: string, projectDir: string, home = homedir(), platform: NodeJS.Platform = process.platform): string {
  const sys = geminiSystemSettings(process.env, platform);
  // F42: own keys only ("constructor" or "toString" is not a configured server).
  if (sys !== undefined && Object.hasOwn(settingsServers(readText(sys)), server)) return "managed";
  if (Object.hasOwn(settingsServers(readText(join(resolve(projectDir), ".gemini", "settings.json"))), server)) return "project";
  if (Object.hasOwn(settingsServers(readText(join(geminiHome(process.env, home), "settings.json"))), server)) return "user";
  return "unknown";
}

/** Whether a Gemini CLI command line is non-interactive (-p / --prompt) or never asks (--yolo). */
export function geminiUnattendedArgs(args: string): string | null {
  if (!/(?:^|[\s/])gemini(?:\.js)?(?:\s|$)|@google\/gemini-cli/.test(args)) return null;
  if (/(?:^|\s)(?:-p|--prompt)(?:\s|=|$)/.test(args)) return "Gemini CLI is running non-interactively (-p)";
  if (/(?:^|\s)(?:-y|--yolo)(?:\s|$)|--approval-mode(?:\s+|=)yolo/.test(args)) return "Gemini CLI runs in yolo mode (no approvals)";
  return null;
}

/**
 * Unattended: `gemini -p` or yolo mode found in the process ancestry (/proc on Linux; ps, or pgrep where a
 * seatbelt sandbox forbids ps: Gemini CLI's own `-s` on macOS, captured). Gemini CLI tells its hooks nothing
 * about the mode (no field in the event, no variable), so the command line is the only source: when no
 * process could be inspected at all, the session is treated as unattended, the strict reading (Gemini
 * CLI cannot ask anyway; what changes is the unattended rules, such as the task scope). A definite answer
 * is cached per session; that one is not, so a failure that passes does not stick.
 */
export function nonInteractiveGemini(ev: AdapterEvent, _env: NodeJS.ProcessEnv, l: Layout, inspect: () => Ancestry = () => ancestorArgs(process.ppid, { depth: 4, pattern: "gemini" })): string | null {
  const cache = join(l.sessions, `${safeId(`gemini:${ev.sessionId}`)}.meta.json`);
  const cached = readText(cache);
  if (cached !== null) {
    try {
      const c = JSON.parse(cached) as { reason?: string | null };
      if (c.reason === null || typeof c.reason === "string") return c.reason;
    } catch {
      // Re-detect below.
    }
  }
  const anc = inspect();
  let reason: string | null = null;
  for (const args of anc.args) {
    reason = geminiUnattendedArgs(args);
    if (reason !== null) break;
  }
  if (reason === null && !anc.inspected) return uninspectedReason("Gemini CLI");
  try {
    atomicWrite(cache, JSON.stringify({ reason, via: anc.via }));
  } catch {
    // Cache is an optimization only.
  }
  return reason;
}

export const GEMINI_COVERAGE: CoverageItem[] = [
  { capability: "Pre-action block on shell", status: "yes", detail: "BeforeTool on run_shell_command" },
  { capability: "File writes seen with content", status: "yes", detail: "write_file, replace (save_memory, gone in 0.63.0, as a write to ~/.gemini/GEMINI.md)" },
  { capability: "File reads seen (taint from outside files)", status: "yes", detail: "read_file, list_directory, glob, grep_search (read_many_files, not registered in 0.63.0, as reads)" },
  { capability: "Web fetch and search seen", status: "yes", detail: "web_fetch (every URL in its prompt), google_web_search" },
  { capability: "MCP calls seen", status: "yes", detail: "MCP tools by server; the configuration source is read from settings.json (system, project, user)" },
  { capability: "Tool output seen (taint, fingerprints)", status: "yes", detail: "AfterTool; secrets in output are not redacted" },
  { capability: "Asks the person", status: "no", detail: "an action that needs a person is held in the queue and denied with the queue command to approve it" },
  { capability: "Fails closed by default", status: "partial", detail: "Gemini CLI blocks only on a deny decision or exit 2 with text on stderr; the wrapper prints a line before exit 2, so a crash blocks, but a hook that times out (60 s as installed) lets the tool run; the firewall denies at its own deadline (20 s) first, checked between steps" },
  { capability: "Hooks run in every folder", status: "partial", detail: "in a folder Gemini CLI does not trust, it skips all hooks (user and system included); a project's settings can also set hooksConfig.enabled false, which doctor reports" },
  { capability: "Settings the agent can rewrite mid-session protected", status: "partial", detail: "writes to settings.json are result-checked; Gemini CLI has no ConfigChange event" },
  { capability: "Managed deployment the user cannot disable", status: "partial", detail: "system settings (in a root-owned directory, or Gemini CLI skips them) override user and project settings; nothing stops other hooks from running" },
  { capability: "Prompt seen (named destinations)", status: "yes", detail: "BeforeAgent" },
  { capability: "Subagents", status: "yes", detail: "an invoke_agent subagent's tool calls carry the parent's session_id (captured), so taint is shared" },
  { capability: "Cloud and remote runs", status: "no", detail: "local sessions only" },
];

export function geminiSettingsPath(scope: "user" | "project" | "local", projectDir: string, home: string): string {
  return scope === "user" ? join(geminiHome(process.env, home), "settings.json") : join(resolve(projectDir), ".gemini", "settings.json");
}

/** Hooks run only when Gemini CLI's hook system is on (hooksConfig.enabled; tools.enableHooks in older versions). */
export function geminiEnable(s: Json): Json {
  const cfg = typeof s.hooksConfig === "object" && s.hooksConfig !== null ? (s.hooksConfig as Json) : {};
  return { ...s, hooksConfig: { ...cfg, enabled: true } };
}

export function geminiDisabledBy(s: Json): string[] {
  const out: string[] = [];
  const cfg = typeof s.hooksConfig === "object" && s.hooksConfig !== null ? (s.hooksConfig as Json) : {};
  if (cfg.enabled === false) out.push("hooksConfig.enabled is false");
  if (Array.isArray(cfg.disabled) && cfg.disabled.some((n) => typeof n === "string" && /launchsafe/i.test(n))) out.push("hooksConfig.disabled names the firewall's hook");
  return out;
}

export const geminiAdapter: AgentAdapter = {
  id: "gemini",
  parse: parseGemini,
  normalize: normalizeGemini,
  render: renderGemini,
  provenance: (server, projectDir, home) => geminiProvenance(server, projectDir, home),
  nonInteractive: nonInteractiveGemini,
  supportsAsk: false,
  supportsUpdatedOutput: false,
  // Gemini CLI documents BeforeTool tool_input overrides, not yet verified by a captured fixture: vault references in shell commands are refused.
  supportsUpdatedInput: false,
  projectDirEnv: "GEMINI_PROJECT_DIR",
  testedVersion: GEMINI_TESTED_VERSION,
  settings: {
    label: "Gemini CLI",
    scopes: ["user", "project"],
    path: (scope, projectDir, home) => geminiSettingsPath(scope, projectDir, home),
    events: GEMINI_HOOK_EVENTS,
    matched: new Set(["BeforeTool", "AfterTool"]),
    matchAll: "*",
    // Gemini CLI hook timeouts are in milliseconds. B: its own default (60 s); the internal deadline denies first.
    timeout: 60000,
    entryExtras: { name: "launchsafe-firewall" },
    enable: geminiEnable,
    disabledBy: geminiDisabledBy,
    managedPaths: GEMINI_SYSTEM_SETTINGS,
    managedSnippet: (command) => ({ path: GEMINI_SYSTEM_SETTINGS[process.platform] ?? "/etc/gemini-cli/settings.json", format: "json", text: JSON.stringify(geminiEnable({ hooks: Object.fromEntries(GEMINI_HOOK_EVENTS.map((ev) => [ev, [{ ...(ev === "BeforeTool" || ev === "AfterTool" ? { matcher: "*" } : {}), hooks: [{ name: "launchsafe-firewall", type: "command", command, timeout: 60000 }] }]])) }), null, 2) }),
  },
  coverage: GEMINI_COVERAGE,
};
