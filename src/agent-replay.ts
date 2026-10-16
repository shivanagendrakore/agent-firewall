/**
 * The agent-neutral form of the scenario and friction corpora. A
 * scenario step written as a Claude Code hook event is translated into the
 * event another agent would send for the same action, when that agent has the
 * capability (Codex has no read or web tools of its own: it reads with cat and
 * fetches with curl; Gemini CLI has its own tool for almost everything; Cursor
 * writes every edit as a Write of the whole new file and names an MCP call's
 * server only in beforeMCPExecution). Steps an agent cannot express return null
 * and are reported as not applicable.
 *
 * The translation is deliberately literal: the same paths, commands and
 * arguments, so a difference in the decision is a difference in the adapter.
 */

import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { adapterFor } from "./adapters/index.js";
import { runHook } from "./hook/claude.js";
import { layout } from "./runtime/layout.js";
import type { Scenario } from "./scenarios.js";
import type { AgentId, HookIO } from "./adapters/types.js";
import { claudeVerdict } from "./adapters/claude.js";
import { codexVerdict } from "./adapters/codex.js";
import { geminiVerdict } from "./adapters/gemini.js";
import { cursorVerdict } from "./adapters/cursor.js";
import { applyEdits } from "./engine/settings.js";
import type { Verdict } from "./types.js";
import { own } from "./own.js";

type Json = Record<string, unknown>;

function shq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

function str(o: Json, k: string): string {
  const v = own(o, k);
  return typeof v === "string" ? v : "";
}

/** A patch that adds a file (Codex apply_patch). */
export function addFilePatch(path: string, content: string): string {
  const body = content.replace(/\n$/, "").split("\n").map((l) => `+${l}`).join("\n");
  return `*** Begin Patch\n*** Add File: ${path}\n${body}\n*** End Patch\n`;
}

/** A patch that replaces text in a file (Codex apply_patch, one chunk). */
export function updateFilePatch(path: string, oldText: string, newText: string): string {
  const minus = oldText.split("\n").map((l) => `-${l}`).join("\n");
  const plus = newText.split("\n").map((l) => `+${l}`).join("\n");
  return `*** Begin Patch\n*** Update File: ${path}\n@@\n${minus}\n${plus}\n*** End Patch\n`;
}

/** A Claude Code tool call as Codex would make it, or null when Codex has no way to make it. */
export function codexTool(tool: string, input: Json): { tool: string; input: Json } | null {
  switch (tool) {
    case "Bash":
      return { tool: "Bash", input: { command: str(input, "command") } };
    case "Read":
      return { tool: "Bash", input: { command: `cat ${shq(str(input, "file_path"))}` } };
    case "Write":
      return { tool: "apply_patch", input: { command: addFilePatch(str(input, "file_path"), str(input, "content")) } };
    case "Edit":
      return { tool: "apply_patch", input: { command: updateFilePatch(str(input, "file_path"), str(input, "old_string"), str(input, "new_string")) } };
    case "WebFetch":
      return { tool: "Bash", input: { command: `curl -sS ${shq(str(input, "url"))}` } };
    case "LS":
      return { tool: "Bash", input: { command: `ls ${shq(str(input, "path") || ".")}` } };
    case "Grep":
      return { tool: "Bash", input: { command: `rg ${shq(str(input, "pattern"))} ${shq(str(input, "path") || ".")}` } };
    case "Glob":
      return { tool: "Bash", input: { command: `rg --files -g ${shq(str(input, "pattern"))}` } };
    case "TodoWrite":
      return { tool: "update_plan", input: { plan: [] } };
    default:
      // MCP tools keep their name; WebSearch is hosted by OpenAI and never reaches a hook.
      return tool.startsWith("mcp__") ? { tool, input } : null;
  }
}

/** A Claude Code tool call as Gemini CLI would make it, or null when it has no equivalent. */
export function geminiTool(tool: string, input: Json): { tool: string; input: Json } | null {
  switch (tool) {
    case "Bash":
      return { tool: "run_shell_command", input: { command: str(input, "command") } };
    case "Read":
      return { tool: "read_file", input: { file_path: str(input, "file_path") } };
    case "Write":
      return { tool: "write_file", input: { file_path: str(input, "file_path"), content: str(input, "content") } };
    case "Edit":
      return { tool: "replace", input: { file_path: str(input, "file_path"), old_string: str(input, "old_string"), new_string: str(input, "new_string") } };
    case "WebFetch":
      return { tool: "web_fetch", input: { prompt: `${str(input, "prompt") || "Summarize"} ${str(input, "url")}` } };
    case "WebSearch":
      return { tool: "google_web_search", input: { query: str(input, "query") } };
    case "LS":
      return { tool: "list_directory", input: { dir_path: str(input, "path") || "." } };
    case "Grep":
      return { tool: "search_file_content", input: { pattern: str(input, "pattern"), ...(str(input, "path") !== "" ? { dir_path: str(input, "path") } : {}) } };
    case "Glob":
      return { tool: "glob", input: { pattern: str(input, "pattern") } };
    case "TodoWrite":
      return { tool: "write_todos", input: { todos: [] } };
    default: {
      const m = /^mcp__(.+?)__(.+)$/.exec(tool);
      return m !== null ? { tool: `mcp_${m[1]}_${m[2]}`, input } : null;
    }
  }
}

/**
 * A Claude Code tool call as Cursor's agent would make it (the tool names and inputs its executors
 * report, read from cursor-agent 2026.10.01), or null when it has no equivalent. An edit is a Write of
 * the file's whole new text, so the current file is read (`readFile`) to apply it.
 */
export function cursorTool(tool: string, input: Json, readFile?: (p: string) => string | null): { tool: string; input: Json } | null {
  switch (tool) {
    case "Bash":
      return { tool: "Shell", input: { command: str(input, "command"), cwd: "" } };
    case "Read":
      return { tool: "Read", input: { file_path: str(input, "file_path") } };
    case "Write":
      return { tool: "Write", input: { file_path: str(input, "file_path"), content: str(input, "content") } };
    case "Edit": {
      const path = str(input, "file_path");
      let before: string | null = null;
      try {
        before = readFile?.(path) ?? null;
      } catch {
        before = null;
      }
      const edit = { old: str(input, "old_string"), new: str(input, "new_string"), ...(input.replace_all === true ? { all: true } : {}) };
      return { tool: "Write", input: { file_path: path, content: before === null ? edit.new : applyEdits(before, [edit]) } };
    }
    case "WebFetch":
      return { tool: "Fetch", input: { url: str(input, "url") } };
    case "WebSearch":
      return { tool: "WebSearch", input: { search_term: str(input, "query") } };
    case "LS":
      return { tool: "List", input: { file_path: str(input, "path") || "." } };
    case "Grep":
      return { tool: "Grep", input: { pattern: str(input, "pattern"), ...(str(input, "path") !== "" ? { file_path: str(input, "path") } : {}) } };
    default:
      // MCP tools become beforeMCPExecution (see toNative); Glob and TodoWrite have no hook-visible equivalent.
      return tool.startsWith("mcp__") ? { tool, input } : null;
  }
}

const NAMES: Record<Exclude<AgentId, "claude">, Record<string, string>> = {
  codex: { PreToolUse: "PreToolUse", PostToolUse: "PostToolUse", UserPromptSubmit: "UserPromptSubmit", SessionStart: "SessionStart" },
  gemini: { PreToolUse: "BeforeTool", PostToolUse: "AfterTool", UserPromptSubmit: "BeforeAgent", SessionStart: "SessionStart" },
  cursor: { PreToolUse: "preToolUse", PostToolUse: "postToolUse", UserPromptSubmit: "beforeSubmitPrompt", SessionStart: "sessionStart" },
};

/** Cursor's common fields: conversation_id (the session), the workspace root, and its version stamp. */
function cursorCommon(event: Json): Json {
  const sid = str(event, "session_id");
  const cwd = str(event, "cwd");
  return { ...(sid !== "" ? { conversation_id: sid } : {}), generation_id: `${sid || "g"}-1`, model: "default", cursor_version: "2026.10.01-e373342", ...(cwd !== "" ? { workspace_roots: [cwd] } : {}), user_email: null, transcript_path: null };
}

/**
 * A Claude Code hook event (as the scenario files write it) as `agent` would send it, or null when the
 * agent cannot take that action. session_id, cwd and the other common fields are copied.
 */
export function toNative(agent: AgentId, event: Json, io: { readFile?: (p: string) => string | null } = {}): Json | null {
  if (agent === "claude") return event;
  const name = str(event, "hook_event_name");
  const native = own(NAMES[agent], name);
  if (native === undefined) return null;
  const { tool_name: _t, tool_input: _i, tool_response: _r, hook_event_name: _h, mcp_server: server, permission_mode: mode, ...rest } = event;
  const out: Json = { ...rest, hook_event_name: native };
  if (agent === "codex" && typeof mode === "string") out.permission_mode = mode;
  if (agent === "cursor") return cursorNative(name, native, event, { ...rest, ...cursorCommon(event) }, io);
  if (name === "PreToolUse" || name === "PostToolUse") {
    const t = (agent === "codex" ? codexTool : geminiTool)(str(event, "tool_name"), (event.tool_input as Json | undefined) ?? {});
    if (t === null) return null;
    out.tool_name = t.tool;
    out.tool_input = t.input;
    if (agent === "gemini" && t.tool.startsWith("mcp_")) {
      const m = /^mcp__(.+?)__(.+)$/.exec(str(event, "tool_name"));
      if (m !== null) out.mcp_context = { server_name: m[1], tool_name: m[2] };
    }
    if (name === "PostToolUse") out.tool_response = event.tool_response ?? "";
  }
  void server;
  return out;
}

/** A Claude Code event as Cursor sends it: an MCP call is beforeMCPExecution / afterMCPExecution, which name the server. */
function cursorNative(name: string, native: string, event: Json, common: Json, io: { readFile?: (p: string) => string | null }): Json | null {
  if (name !== "PreToolUse" && name !== "PostToolUse") return { ...common, hook_event_name: native, ...(name === "SessionStart" ? { session_id: str(event, "session_id"), is_background_agent: false, composer_mode: "agent" } : {}) };
  const toolName = str(event, "tool_name");
  const input = (event.tool_input as Json | undefined) ?? {};
  const m = /^mcp__(.+?)__(.+)$/.exec(toolName);
  if (m !== null) {
    const mcp = { ...common, hook_event_name: name === "PreToolUse" ? "beforeMCPExecution" : "afterMCPExecution", tool_name: m[2], tool_input: JSON.stringify(input), mcp_server_name: m[1], command: "npx placeholder-server" };
    return name === "PostToolUse" ? { ...mcp, result_json: typeof event.tool_response === "string" ? event.tool_response : JSON.stringify(event.tool_response ?? "") } : mcp;
  }
  const t = cursorTool(toolName, input, io.readFile);
  if (t === null) return null;
  const out: Json = { ...common, hook_event_name: native, tool_name: t.tool, tool_input: t.input, tool_use_id: "tu-1" };
  if (t.tool === "Shell" && str(common, "cwd") !== "") out.cwd = str(common, "cwd");
  if (name === "PostToolUse") out.tool_output = typeof event.tool_response === "string" ? event.tool_response : JSON.stringify(event.tool_response ?? "");
  return out;
}

/**
 * An event for `agent` from a Claude Code-shaped one: Claude Code tools are translated (toNative); a tool
 * that is already the agent's own (save_memory) keeps its name and only the event name changes.
 */
export function asAgentEvent(agent: AgentId, event: Json): Json {
  if (agent === "claude") return event;
  const t = toNative(agent, event);
  if (t !== null) return t;
  const name = own(NAMES[agent], str(event, "hook_event_name"));
  return name === undefined ? event : { ...event, hook_event_name: name };
}

/** The firewall's verdict in an agent's hook answer ("queue" when the message says the action was held). */
export function verdictFor(agent: AgentId, io: HookIO): { verdict: Verdict; reason: string } {
  const v = agent === "claude" ? claudeVerdict(io) : agent === "codex" ? codexVerdict(io) : agent === "cursor" ? cursorVerdict(io) : geminiVerdict(io);
  if (v.verdict === "deny" && /held this for review/.test(v.reason)) return { verdict: "queue", reason: v.reason };
  return v;
}

/**
 * The decision a Claude Code verdict corresponds to for `agent`: an agent whose hook protocol cannot ask
 * the person gets the action held in the queue instead (the adapter's coverage says so).
 */
export function expectedFor(agent: AgentId, claude: Verdict, supportsAsk: boolean): Verdict {
  return agent !== "claude" && !supportsAsk && claude === "ask" ? "queue" : claude;
}

// --- replaying the incident scenarios through an adapter --------------------------------------------


export interface AgentStepResult {
  step: number;
  tool: string;
  verdict: Verdict;
  rules: string[];
  expect?: Verdict[];
  rule?: string;
}

/** A scenario as `agent` would play it, or the reason it cannot (a step the agent has no tool for). */
export function runScenarioAs(agent: AgentId, s: Scenario, parent = tmpdir()): { results: AgentStepResult[] } | { notApplicable: string } {
  const native = s.steps.map((step) => toNative(agent, step.event));
  const missing = s.steps.findIndex((_, i) => native[i] === null);
  if (missing !== -1) return { notApplicable: `step ${missing} (${String(s.steps[missing]?.event.tool_name ?? s.steps[missing]?.event.hook_event_name)}) has no ${adapterFor(agent).settings.label} equivalent` };
  const root = mkdtempSync(join(parent, "lsfw-replay-"));
  const ws = join(root, "workspace");
  mkdirSync(ws, { recursive: true });
  const l = layout(join(root, "state"));
  const home = join(root, "home");
  const results: AgentStepResult[] = [];
  const fill = (v: unknown): unknown => {
    if (typeof v === "string") return v.replaceAll("{WS}", ws).replaceAll("{HOME}", home);
    if (Array.isArray(v)) return v.map(fill);
    if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x)]));
    return v;
  };
  try {
    const readFile = (p: string): string | null => {
      try {
        return readFileSync(p, "utf8");
      } catch {
        return null;
      }
    };
    s.steps.forEach((step, i) => {
      // Cursor's edits carry the whole new file: translated now, against the file as earlier steps left it.
      const nativeNow = agent === "cursor" ? toNative(agent, fill({ session_id: `replay-${s.id}`, cwd: ws, permission_mode: "default", ...step.event }) as Json, { readFile }) : native[i];
      const event = fill({ session_id: `replay-${s.id}`, cwd: ws, permission_mode: "default", ...(nativeNow as Json) }) as Json;
      const res = runHook(JSON.stringify(event), { env: agent === "claude" ? { CLAUDE_PROJECT_DIR: ws, CLAUDE_CONFIG_DIR: join(root, "claude-config") } : { CLAUDE_CONFIG_DIR: join(root, "claude-config") }, layout: l, agent, home, detectNonInteractive: () => s.unattended === true, notifyDeps: { spawn: () => undefined } });
      if (step.event.hook_event_name !== "PreToolUse") return;
      const { verdict, reason } = verdictFor(agent, res);
      const rules = (/\(rule ([A-Z0-9, -]+)\)\s*$/.exec(reason)?.[1] ?? "").split(", ").filter((x) => x !== "");
      results.push({ step: i, tool: String(event.tool_name), verdict, rules, ...(step.expect !== undefined ? { expect: step.expect } : {}), ...(step.rule !== undefined ? { rule: step.rule } : {}) });
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  return { results };
}
