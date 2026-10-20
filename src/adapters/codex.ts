/**
 * The OpenAI Codex adapter (CLI and IDE extension, local runs). Codex's hook
 * protocol follows Claude Code's: the same event names and stdin fields
 * (session_id, cwd, hook_event_name, permission_mode, tool_name, tool_input,
 * tool_response), hooks registered in hooks.json in the same shape, and a
 * PreToolUse answer in hookSpecificOutput.permissionDecision. Captured live
 * from Codex 0.162.1 (test/fixtures/codex-0.162.1-*.json); see docs/agents/codex.md.
 *
 * Native tools: `Bash` (command as a string, or an argv array in older
 * versions), `apply_patch` (the patch text in tool_input.command; one patch can
 * add, update, delete and move several files) and MCP tools named
 * mcp__<server>__<tool>. Hosted web search never reaches a hook.
 */

import { homedir } from "node:os";
import { join, resolve } from "node:path";
import type { NormalizedAction } from "../types.js";
import type { Layout } from "../runtime/layout.js";
import { stripBom } from "../bom.js";
import { atomicWrite, readText, readTextExact, writeUserFile } from "../runtime/fsutil.js";
import { safeId } from "../runtime/layout.js";
import { ancestorArgs, uninspectedReason, type Ancestry } from "../runtime/ancestry.js";
import { parsePatch, type PatchOp } from "./patch.js";
import { retrust } from "../runtime/codex-trust.js";
import { MARKER } from "../engine/settings.js";
import { assertNotRealHome } from "../runtime/guard.js";
import { AdapterParseError, UNPARSEABLE_TOOL, type AdapterEvent, type AgentAdapter, type CoverageItem, type HookIO, type HookOutcome, type NormalizeIO } from "./types.js";
import { own } from "../own.js";

type Json = Record<string, unknown>;

export const CODEX_TESTED_VERSION = "0.162.1";

const KINDS: Record<string, AdapterEvent["kind"]> = {
  PreToolUse: "pre_tool",
  PostToolUse: "post_tool",
  UserPromptSubmit: "prompt",
  SessionStart: "session_start",
  SessionEnd: "session_end",
  SubagentStart: "subagent_start",
  SubagentStop: "subagent_stop",
  // The firewall decides in PreToolUse; Codex's own approval prompt is left to Codex.
  PermissionRequest: "ignored",
};

/** The events the firewall registers in Codex's hooks.json. */
export const CODEX_HOOK_EVENTS = ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"] as const;

/**
 * The events whose group carries a matcher ("*"). Codex 0.162.1 runs a UserPromptSubmit (or Stop) group
 * only when it has no matcher at all: with "*", "", ".*" or any other matcher the hook is skipped
 * silently, in `codex exec` as captured (SessionStart runs with or without one). A matcher there cost
 * the firewall every prompt: no task scope and no destinations the person named.
 */
export const CODEX_MATCHED_EVENTS: ReadonlySet<string> = new Set(["PreToolUse", "PostToolUse"]);

/** Events Codex 0.162.1 skips when their group has a matcher (captured). */
export const CODEX_UNMATCHED_ONLY: ReadonlySet<string> = new Set(["UserPromptSubmit", "Stop"]);

/** The firewall's groups in a Codex hooks file that Codex skips because they carry a matcher. */
export function codexMatcherProblems(settings: Json | null): string[] {
  const hooks = settings !== null && typeof settings.hooks === "object" && settings.hooks !== null ? (settings.hooks as Json) : {};
  const out: string[] = [];
  for (const [ev, groups] of Object.entries(hooks)) {
    if (!CODEX_UNMATCHED_ONLY.has(ev) || !Array.isArray(groups)) continue;
    for (const g of groups) {
      if (typeof g !== "object" || g === null || !("matcher" in g)) continue;
      const list = (g as { hooks?: unknown }).hooks;
      if (Array.isArray(list) && list.some((h) => typeof (h as { command?: unknown } | null)?.command === "string" && ((h as { command: string }).command).includes(MARKER))) out.push(ev);
    }
  }
  return [...new Set(out)];
}

function json(o: unknown): string {
  return `${JSON.stringify(o)}\n`;
}

function str(o: Json, k: string): string | undefined {
  const v = own(o, k);
  return typeof v === "string" ? v : undefined;
}

export function parseCodex(raw: Json): AdapterEvent {
  const name = str(raw, "hook_event_name");
  // Without the event name nothing says this is not a tool call: fail closed.
  if (name === undefined || name === "") throw new AdapterParseError("the event has no hook_event_name", true);
  const kind = own(KINDS, name) ?? "ignored";
  const blocking = kind === "pre_tool";
  const sessionId = str(raw, "session_id");
  const cwd = str(raw, "cwd");
  if (kind !== "ignored" && (sessionId === undefined || sessionId === "")) throw new AdapterParseError(`${name} without a session_id`, blocking);
  if (kind !== "ignored" && (cwd === undefined || cwd === "")) throw new AdapterParseError(`${name} without a cwd`, blocking);
  const ev: AdapterEvent = { kind, agent: "codex", sessionId: sessionId ?? "no-session", cwd: cwd ?? process.cwd(), raw };
  const mode = str(raw, "permission_mode");
  if (mode !== undefined) ev.permissionMode = mode;
  if (kind === "pre_tool" || kind === "post_tool") {
    const tool = str(raw, "tool_name");
    if (tool === undefined || tool === "") throw new AdapterParseError(`${name} without a tool_name`, blocking);
    const input = raw.tool_input;
    if (typeof input !== "object" || input === null || Array.isArray(input)) throw new AdapterParseError(`${name} for ${tool} without a tool_input object`, blocking);
    ev.tool = tool;
    ev.input = input as Json;
    const m = /^mcp__(.+?)__(.+)$/.exec(tool);
    if (m !== null) ev.mcp = { server: m[1] as string, tool: m[2] as string };
  }
  if (kind === "post_tool") ev.output = raw.tool_response ?? "";
  if (kind === "prompt") {
    // A subagent's prompt (agent_id set) is written by the parent model, not the person: it never names destinations.
    if (str(raw, "agent_id") !== undefined) ev.kind = "ignored";
    ev.prompt = str(raw, "prompt") ?? "";
  }
  if (kind === "session_start") {
    const source = str(raw, "source");
    if (source !== undefined) ev.source = source;
  }
  // Subagents: Codex reports agent_id/agent_type on the subagent's events and keeps the parent's
  // session_id, so a subagent's taint lands in the parent's state directly. A parent id, if a later
  // version reports one, links the two sessions.
  const parent = str(raw, "parent_session_id");
  if (parent !== undefined && parent !== "") ev.parentSessionId = parent;
  return ev;
}

/** Shell quoting for one argument, so the analyzer parses an argv array exactly as Codex runs it. */
function shq(s: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Codex's shell input: a string, or an argv array (["bash", "-lc", "script"] is the script itself). */
export function shellCommand(command: unknown): string | null {
  if (typeof command === "string") return command;
  if (!Array.isArray(command) || command.length === 0 || !command.every((x) => typeof x === "string")) return null;
  const argv = command as string[];
  const shell = /(?:^|\/)(?:ba|z|da)?sh$/.test(argv[0] ?? "");
  if (shell && argv.length === 3 && /^-l?c$/.test(argv[1] ?? "")) return argv[2] as string;
  return argv.map(shq).join(" ");
}

/** Every distinct patch text the input carries: which key Codex applies is its own, so when they differ all are judged. */
function patchTexts(input: Json): string[] {
  const out: string[] = [];
  for (const k of ["command", "patch", "input"]) {
    const v = own(input, k);
    let t: string | null = null;
    if (typeof v === "string") t = v;
    // Older versions sent ["apply_patch", "<patch>"].
    else if (Array.isArray(v) && v.length === 2 && v[0] === "apply_patch" && typeof v[1] === "string") t = v[1];
    if (t !== null && !out.includes(t)) out.push(t);
  }
  return out;
}

/** The actions one patch operation amounts to. */
function patchActions(op: PatchOp, cwd: string, io: NormalizeIO | undefined): NormalizedAction[] {
  if (op.kind === "add") return [{ tool: "Write", input: { file_path: op.path, content: op.content } }];
  if (op.kind === "delete") return [{ tool: "Bash", input: { command: `rm -- ${shq(op.path)}` } }];
  const out: NormalizedAction[] = [];
  const target = op.moveTo ?? op.path;
  if (op.moveTo !== undefined) out.push({ tool: "Bash", input: { command: `mv -- ${shq(op.path)} ${shq(op.moveTo)}` } });
  const appended = op.chunks.filter((c) => c.old === "");
  const edits = op.chunks.filter((c) => c.old !== "").map((c) => ({ old_string: c.old, new_string: c.new }));
  if (appended.length > 0) {
    // A chunk with no context or removed lines appends to the file: its result is the current file plus the text.
    let before: string | null = null;
    try {
      before = io?.readFile?.(resolve(cwd, op.path)) ?? null;
    } catch {
      before = null;
    }
    const added = appended.map((c) => c.new).join("\n");
    if (before === null || before === "") out.push({ tool: "Write", input: { file_path: target, content: `${added}\n` } });
    else edits.push({ old_string: before, new_string: `${before.endsWith("\n") ? before : `${before}\n`}${added}\n` });
  }
  // Codex matches a chunk's context again after trimming whitespace and folding punctuation, and anchors
  // it after its @@ line: the edit is judged against every plausible match (engine: match "loose").
  if (edits.length > 0) out.push({ tool: "MultiEdit", input: { file_path: target, edits, match: "loose" } });
  return out;
}

export function normalizeCodex(ev: AdapterEvent, io?: NormalizeIO): NormalizedAction[] {
  const tool = ev.tool ?? "";
  const input = ev.input ?? {};
  if (tool === "Bash" || tool === "shell" || tool === "local_shell" || tool === "exec_command" || tool === "container.exec") {
    // M4: which key the tool runs is the tool's own (exec_command: cmd; the others: command); when an input carries
    // both and they differ, both are judged, so a harmless one cannot stand in for the one that runs.
    const keys = tool === "exec_command" ? ["cmd", "command"] : ["command", "cmd"];
    const present = keys.filter((k) => own(input, k) !== undefined);
    if (present.length === 0) return [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: "the shell command is neither a string nor a list of strings" } }];
    const cmds: string[] = [];
    for (const k of present) {
      const c = shellCommand(own(input, k));
      if (c === null) return [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: "the shell command is neither a string nor a list of strings" } }];
      if (!cmds.includes(c)) cmds.push(c);
    }
    const workdir = typeof input.workdir === "string" && input.workdir !== "" ? input.workdir : undefined;
    return cmds.map((cmd) => ({ tool: "Bash", input: { command: workdir !== undefined && resolve(ev.cwd, workdir) !== resolve(ev.cwd) ? `cd ${shq(workdir)} && ${cmd}` : cmd } }));
  }
  if (tool === "apply_patch") {
    const texts = patchTexts(input);
    if (texts.length === 0) return [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: "no patch text in the input" } }];
    const out: NormalizedAction[] = [];
    for (const text of texts) {
      const p = parsePatch(text);
      if (!p.ok) return [{ tool: UNPARSEABLE_TOOL, input: { tool, reason: p.reason } }];
      out.push(...p.ops.flatMap((op) => patchActions(op, ev.cwd, io)));
    }
    return out;
  }
  // Codex's own agent and plan tools only talk to the agent itself (like Claude Code's Agent and TodoWrite).
  if (tool === "spawn_agent" || tool === "send_input" || tool === "wait_agent" || tool === "close_agent" || tool === "resume_agent" || tool.startsWith("multi_agent_")) return [{ tool: "Agent", input }];
  if (tool === "update_plan") return [{ tool: "TodoWrite", input }];
  if (tool === "view_image" && typeof input.path === "string") return [{ tool: "Read", input: { file_path: input.path } }];
  // MCP tools keep their name (mcp__server__tool); local function tools are judged by their arguments.
  return [{ tool, input }];
}

export function renderCodex(ev: AdapterEvent, out: HookOutcome): HookIO {
  const stderr = out.stderr ?? "";
  switch (ev.kind) {
    case "pre_tool": {
      if (out.verdict === "allow") {
        if (out.systemMessage !== undefined) return { stdout: json({ systemMessage: out.systemMessage }), stderr, exitCode: 0 };
        return { stdout: "", stderr, exitCode: 0 };
      }
      // Codex honours permissionDecision "deny" and reads the reason to the model; "ask" is mapped by
      // the pipeline (supportsAsk) before it gets here.
      const decision = out.verdict === "ask" ? "ask" : "deny";
      return { stdout: json({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision, permissionDecisionReason: out.message }, ...(out.systemMessage !== undefined ? { systemMessage: out.systemMessage } : {}) }), stderr, exitCode: 0 };
    }
    case "post_tool": {
      const o: Json = {};
      if (out.additionalContext !== undefined) o.hookSpecificOutput = { hookEventName: "PostToolUse", additionalContext: out.additionalContext };
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

/** The verdict in a Codex hook answer (tests and the scenario harness). */
export function codexVerdict(io: HookIO): { verdict: "allow" | "ask" | "deny"; reason: string } {
  if (io.exitCode === 2) return { verdict: "deny", reason: io.stderr };
  if (io.stdout.trim() === "") return { verdict: "allow", reason: "" };
  const o = JSON.parse(io.stdout) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
  const d = o.hookSpecificOutput?.permissionDecision;
  const reason = o.hookSpecificOutput?.permissionDecisionReason ?? "";
  return { verdict: d === "ask" ? "ask" : d === "deny" ? "deny" : "allow", reason };
}

/** The Codex home directory: CODEX_HOME, else ~/.codex. */
export function codexHome(env: NodeJS.ProcessEnv = process.env, home = homedir()): string {
  return env.CODEX_HOME !== undefined && env.CODEX_HOME !== "" ? env.CODEX_HOME : join(home, ".codex");
}

/** A top-level `key = "value"` (or bare value) in a TOML file, before the first table. Enough for config.toml's scalar keys. */
export function tomlTopLevel(text: string | null, key: string): string | null {
  if (text === null) return null;
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (t.startsWith("[")) break;
    const m = new RegExp(`^${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^#\\s]+))`).exec(t);
    if (m !== null) return m[1] ?? m[2] ?? m[3] ?? null;
  }
  return null;
}

/**
 * Where an MCP server was configured: the user's config.toml ([mcp_servers.<name>]), a project's
 * .codex/config.toml, else unknown (treated like a repository-defined server).
 */
export function codexProvenance(server: string, projectDir: string, home = homedir(), env: NodeJS.ProcessEnv = process.env): string {
  const has = (text: string | null): boolean => text !== null && new RegExp(`^\\s*\\[mcp_servers\\.(?:"${server.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"|${server.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})\\]`, "m").test(text);
  if (has(readText(join(resolve(projectDir), ".codex", "config.toml")))) return "project";
  if (has(readText(join(codexHome(env, home), "config.toml")))) return "user";
  return "unknown";
}

/** Process ancestors' command lines (the hook's shell, then Codex). */
/** Whether a Codex command line is non-interactive (`codex exec`) or never asks (approval policy never). */
export function codexUnattendedArgs(args: string): string | null {
  if (!/(?:^|[\s/])codex(?:\.js)?(?:\s|$)/.test(args)) return null;
  if (/(?:^|\s)(?:exec|e)(?:\s|$)/.test(args.replace(/^.*?codex(?:\.js)?\s/, " "))) return "Codex is running non-interactively (codex exec)";
  if (/(?:^|\s)(?:-a|--ask-for-approval)(?:\s+|=)never(?:\s|$)/.test(args)) return "Codex runs with approval policy never";
  if (/(?:^|\s)--dangerously-bypass-approvals-and-sandbox(?:\s|$)|(?:^|\s)--yolo(?:\s|$)/.test(args)) return "Codex runs with approvals bypassed";
  return null;
}

/**
 * Unattended: `codex exec`, approval policy never or the bypass flag found in the process ancestry, or
 * approval_policy = "never" in the user's config.toml. (Codex's permission_mode is checked first by the
 * shared context against the policy's unattendedPermissionModes, as for Claude Code.) When no process could
 * be inspected and the config says nothing, the session is treated as unattended, the strict reading. A
 * definite answer is cached per session; that one is not, so a failure that passes does not stick.
 */
export function nonInteractiveCodex(ev: AdapterEvent, env: NodeJS.ProcessEnv, l: Layout, inspect: () => Ancestry = () => ancestorArgs(process.ppid, { depth: 4, pattern: "codex" })): string | null {
  // Captured: codex exec forces approval "never", and every event then says bypassPermissions.
  if (ev.permissionMode === "bypassPermissions") return "Codex runs with approvals off (codex exec, approval policy never or the bypass flag)";
  const cache = join(l.sessions, `${safeId(`codex:${ev.sessionId}`)}.meta.json`);
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
    reason = codexUnattendedArgs(args);
    if (reason !== null) break;
  }
  if (reason === null && tomlTopLevel(readText(join(codexHome(env), "config.toml")), "approval_policy") === "never") reason = "Codex's config.toml sets approval_policy = \"never\"";
  if (reason === null && !anc.inspected) return uninspectedReason("Codex");
  try {
    atomicWrite(cache, JSON.stringify({ reason }));
  } catch {
    // Cache is an optimization only.
  }
  return reason;
}

export const CODEX_COVERAGE: CoverageItem[] = [
  { capability: "Pre-action block on shell", status: "yes", detail: "PreToolUse on Bash; the hook gets the command only, not the model's workdir, so relative paths are judged against the session's directory" },
  { capability: "Hooks run once installed", status: "partial", detail: "Codex skips a hook silently until the person trusts it (/hooks in the Codex TUI), and again after its command changes (reinstall, approver re-pin); doctor checks that trust is recorded" },
  { capability: "File writes seen with content", status: "yes", detail: "apply_patch is parsed: each added, updated, deleted or moved file is judged, and the whole patch gets one verdict" },
  { capability: "File reads seen (taint from outside files)", status: "partial", detail: "Codex has no separate read tool: reads happen through Bash (cat, rg, sed) and are judged there" },
  { capability: "Web fetch and search seen", status: "partial", detail: "fetches through Bash (curl) are seen; Codex's hosted web search and tool_search run without a hook" },
  { capability: "MCP calls seen", status: "yes", detail: "mcp__server__tool; the configuration source is read from config.toml (user or project)" },
  { capability: "Tool output seen (taint, fingerprints)", status: "yes", detail: "PostToolUse; secrets in output are not redacted (Codex can only replace MCP tool output)" },
  { capability: "Asks the person", status: "no", detail: "an action that needs a person is held in the queue and denied with the queue command to approve it" },
  { capability: "Fails closed by default", status: "partial", detail: "Codex blocks only on a deny decision or exit 2 with text on stderr; the wrapper prints a line before exit 2, so a crash blocks, but a hook that times out (600 s as installed) lets the tool run; the firewall denies at its own deadline (20 s) first, checked between steps" },
  { capability: "Settings the agent can rewrite mid-session protected", status: "partial", detail: "writes to hooks.json and config.toml (hooks, hook trust, features.hooks) are result-checked; Codex has no ConfigChange event" },
  { capability: "Managed deployment the user cannot disable", status: "yes", detail: "requirements.toml with the hooks and allow_managed_hooks_only = true" },
  { capability: "Prompt seen (named destinations)", status: "yes", detail: "UserPromptSubmit" },
  { capability: "Subagents", status: "yes", detail: "subagent events keep the parent's session_id (agent_id marks the subagent), so taint is shared; a subagent's prompt never names destinations" },
  { capability: "Cloud and remote runs", status: "no", detail: "Codex cloud tasks do not run local command hooks" },
];

export function codexHooksPath(scope: "user" | "project" | "local", projectDir: string, home: string, env: NodeJS.ProcessEnv = process.env): string {
  return scope === "user" ? join(codexHome(env, home), "hooks.json") : join(resolve(projectDir), ".codex", "hooks.json");
}

export const CODEX_MANAGED_PATHS: Partial<Record<NodeJS.Platform, string>> = {
  darwin: "/etc/codex/requirements.toml",
  linux: "/etc/codex/requirements.toml",
};

function tomlString(s: string): string {
  return `'''${s}'''`;
}

/** B: Codex's own default hook timeout (600 s); the firewall's internal deadline denies well before it. */
export const CODEX_HOOK_TIMEOUT = 600;

/** requirements.toml: the firewall's hooks as managed hooks, and (with lock) no other hooks. */
export function codexManagedSnippet(command: string, lock: boolean): string {
  const lines = ["# LaunchSafe Firewall: managed Codex hooks (deploy as an administrator)."];
  if (lock) lines.push("allow_managed_hooks_only = true");
  // D: hooks on in the managed layer, so a user's or project's `[features] hooks = false` cannot switch the managed
  // hooks off (docs/agents/codex.md; whether Codex also needs `[hooks] managed_dir` is not verified, see there).
  lines.push("", "[features]", "hooks = true");
  for (const ev of CODEX_HOOK_EVENTS) {
    lines.push("", `[[hooks.${ev}]]`, ...(CODEX_MATCHED_EVENTS.has(ev) ? [`matcher = "*"`] : []));
    lines.push(`[[hooks.${ev}.hooks]]`, `type = "command"`, `command = ${tomlString(command)}`, `timeout = ${CODEX_HOOK_TIMEOUT}`);
  }
  return `${lines.join("\n")}\n`;
}

/**
 * After the person installed, removed or re-pinned the firewall's Codex hooks: record their trust in
 * $CODEX_HOME/config.toml (Codex skips untrusted and changed hooks silently), keeping the trust of the
 * person's other hooks as they move. A backup of config.toml is kept.
 */
export function recordCodexTrust(w: { path: string; before: Json | null; after: Json | null; home: string; backupDir: string }): void {
  const config = join(codexHome(process.env, w.home), "config.toml");
  assertNotRealHome(config);
  // The backup is the file as it was, a byte order mark included; the trust tables are read without the mark.
  const exact = readTextExact(config);
  const text = exact === null ? null : stripBom(exact);
  const next = retrust(text, w.path, w.before, w.after);
  if (next === (text ?? "") || (text === null && next.trim() === "")) return;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  atomicWrite(join(w.backupDir, `${stamp}-codex-config.toml.json`), JSON.stringify({ path: config, existed: exact !== null, content: exact }, null, 2));
  writeUserFile(config, next);
}

export const codexAdapter: AgentAdapter = {
  id: "codex",
  parse: parseCodex,
  normalize: normalizeCodex,
  render: renderCodex,
  provenance: (server, projectDir, home) => codexProvenance(server, projectDir, home),
  nonInteractive: nonInteractiveCodex,
  supportsAsk: false,
  supportsUpdatedOutput: false,
  // Codex documents allow plus updatedInput, but no captured fixture shows it applied (and its capture treated ask as an error): unverified, so vault references in shell commands are refused.
  supportsUpdatedInput: false,
  testedVersion: CODEX_TESTED_VERSION,
  settings: {
    label: "Codex",
    scopes: ["user", "project"],
    path: (scope, projectDir, home) => codexHooksPath(scope, projectDir, home),
    events: CODEX_HOOK_EVENTS,
    matched: CODEX_MATCHED_EVENTS,
    matchAll: "*",
    timeout: CODEX_HOOK_TIMEOUT,
    afterWrite: recordCodexTrust,
    disabledBy: () => [],
    managedPaths: CODEX_MANAGED_PATHS,
    managedSnippet: (command, lock) => ({ path: CODEX_MANAGED_PATHS[process.platform] ?? "/etc/codex/requirements.toml", format: "toml", text: codexManagedSnippet(command, lock) }),
  },
  coverage: CODEX_COVERAGE,
};
