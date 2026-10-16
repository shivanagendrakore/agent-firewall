/**
 * The adapter interface. The engine is agent-agnostic: a
 * NormalizedAction goes in, a Decision comes out. An adapter only translates:
 * the agent's hook event into an AdapterEvent and NormalizedActions, and the
 * firewall's outcome back into the agent's output format and exit code. No
 * policy lives in an adapter; every verdict comes from decide().
 */

import type { NormalizedAction, Verdict } from "../types.js";
import type { Layout } from "../runtime/layout.js";

export type AgentId = "claude" | "codex" | "gemini" | "cursor";

export const AGENT_IDS: readonly AgentId[] = ["claude", "codex", "gemini", "cursor"];

export type EventKind = "pre_tool" | "post_tool" | "prompt" | "session_start" | "session_end" | "config_change" | "subagent_start" | "subagent_stop" | "ignored";

export interface AdapterEvent {
  kind: EventKind;
  /** "gateway" for the MCP gateway's calls through the shared pipeline (src/gateway/). */
  agent: AgentId | "gateway";
  /** The agent's own session id (the pipeline namespaces it per agent for state files). */
  sessionId: string;
  /** Subagents: the parent's session id, when the agent reports it. */
  parentSessionId?: string;
  cwd: string;
  projectDir?: string;
  /** Native tool name. */
  tool?: string;
  /** Native tool input. */
  input?: Record<string, unknown>;
  /** post_tool: what the tool returned. */
  output?: unknown;
  /** post_tool: the agent reported that the tool failed (Cursor's postToolUseFailure). */
  failed?: boolean;
  prompt?: string;
  permissionMode?: string;
  /** Session start: why the session started ("startup", "resume", ...), when the agent says. */
  source?: string;
  /** A client scratch directory the agent may write freely (Claude Code's scratchpad). */
  scratchpadDir?: string;
  /**
   * I4: `structural` when the event names the server and the tool in fields of their own (Claude Code's
   * mcp_server.name, Cursor's mcp_server_name, Gemini CLI's mcp_context); otherwise they were split out of one name,
   * which is ambiguous when it holds more than one "__".
   */
  mcp?: { server: string; tool: string; source?: string; structural?: boolean };
  /**
   * The `hook --agent` the event arrived through, when it differs from the adapter that parsed it:
   * Cursor runs the hooks in Claude Code's settings files too (third-party import), with its own
   * payload, so a Cursor event can arrive at `hook --agent claude`.
   */
  via?: AgentId;
  raw: Record<string, unknown>;
}

/** What the firewall wants to tell the agent, before the agent's format is applied. */
export interface HookOutcome {
  verdict: Verdict;
  /** The reason a person (and the agent) reads; empty for a silent allow. */
  message: string;
  /** Text added to the model's context (post_tool, session_start). */
  additionalContext?: string;
  /** post_tool: a redacted replacement for the tool's output, when the agent supports it. */
  updatedOutput?: string;
  /** pre_tool: the tool input rewritten by the firewall (vault references as a ticketed run), when the agent supports it. */
  updatedInput?: Record<string, unknown>;
  /** A note shown to the person (session-start alerts). */
  systemMessage?: string;
  /** Diagnostics for the agent's log (stderr). */
  stderr?: string;
}

export interface HookIO {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/** One line of the coverage table: what this agent's hooks let the firewall see and enforce. */
export interface CoverageItem {
  capability: string;
  status: "yes" | "partial" | "no";
  detail: string;
}

export type Scope = "user" | "project" | "local";

/** How an agent registers command hooks, and where. */
export interface AdapterSettings {
  /** The agent's name for people. */
  label: string;
  /** Scopes this agent has a settings file for. */
  scopes: readonly Scope[];
  /** The settings file for a scope. */
  path(scope: Scope, projectDir: string, home: string): string;
  /** The events the firewall registers, in the agent's names. */
  events: readonly string[];
  /** Events whose groups take a tool matcher, and the matcher that means "every tool". */
  matched: ReadonlySet<string>;
  matchAll: string;
  /** The hook timeout as the agent's settings express it (seconds or milliseconds). */
  timeout: number;
  /** Extra keys the agent needs on each hook entry (a name, for example). */
  entryExtras?: Record<string, unknown>;
  /**
   * The agent lists hook entries directly under each event (Cursor: `{ command, timeout, failClosed }`)
   * instead of Claude Code's groups (`{ matcher, hooks: [entry] }`).
   */
  flat?: boolean;
  /**
   * Whether an installed entry fails closed, when the agent says so on the entry itself (Cursor's
   * `failClosed: true`) rather than through the command's `|| exit 2` wrapper.
   */
  failClosedEntry?: (entry: Record<string, unknown>) => boolean;
  /** The agent does not load a settings file reached through a symlink (Cursor's hooks.json), so install refuses one rather than write hooks that never run. */
  refuseSymlink?: boolean;
  /** Settings changes the agent needs for hooks to run at all (an enable flag), merged into the file on install. */
  enable?: (settings: Record<string, unknown>) => Record<string, unknown>;
  /**
   * Called after install, uninstall or an approver re-pin wrote the agent's hooks file (person-run
   * only), with the file's content before and after: Codex records the trust of the firewall's hooks.
   */
  afterWrite?: (w: { path: string; before: Record<string, unknown> | null; after: Record<string, unknown> | null; home: string; backupDir: string }) => void;
  /** Why hooks would not run with these settings (empty when they do). */
  disabledBy(settings: Record<string, unknown>): string[];
  /** Managed (administrator) deployment: where, and the document to deploy. */
  managedPaths: Partial<Record<NodeJS.Platform, string>>;
  managedSnippet(command: string, lockOtherHooks: boolean): { path: string; format: "json" | "toml"; text: string };
}

export interface AgentAdapter {
  id: AgentId;
  /** Throws AdapterParseError on a malformed event (a pre-tool event then fails closed). */
  parse(raw: Record<string, unknown>): AdapterEvent;
  /** One native call can be several actions (a multi-file patch). */
  normalize(ev: AdapterEvent, io?: NormalizeIO): NormalizedAction[];
  /** The agent's output format and exit code for an outcome. */
  render(ev: AdapterEvent, out: HookOutcome): HookIO;
  /** Where an MCP server was configured, when the event does not say. */
  provenance(server: string, projectDir: string, home?: string): string;
  /** Why nobody can answer a prompt in this session (unattended), or null. */
  nonInteractive(ev: AdapterEvent, env: NodeJS.ProcessEnv, l: Layout): string | null;
  /** The agent's hook protocol can put a question to the person ("ask"). Without it, ask becomes a held action. */
  supportsAsk: boolean;
  /** The agent can replace a tool's output after it ran (redaction). */
  supportsUpdatedOutput: boolean;
  /**
   * The agent applies a rewritten tool input from PreToolUse (Claude Code's updatedInput), verified
   * by fixture. Only then are vault references in a shell command rewritten; otherwise FW-VAULT-UNSUPPORTED.
   */
  supportsUpdatedInput: boolean;
  /** The environment variable the agent sets to the project directory for hooks, if any. */
  projectDirEnv?: string;
  /**
   * An answer given before the shared pipeline runs, or null to run it: an event another hook of the
   * firewall decides (Cursor: an MCP call is decided at beforeMCPExecution, which names the server;
   * a Cursor event arriving through the Claude Code hooks while the firewall's own Cursor hooks run).
   */
  shortCircuit?: (ev: AdapterEvent, o: { home?: string }) => HookOutcome | null;
  /** The agent's version the fixtures were captured from (or documented for). */
  testedVersion: string;
  settings: AdapterSettings;
  coverage: CoverageItem[];
}

/** I/O an adapter may use while normalizing (reading a file a patch updates). Injected so adapters stay testable. */
export interface NormalizeIO {
  readFile?: (absPath: string) => string | null;
}

export class AdapterParseError extends Error {
  /** The event is (or may be) a pre-tool event: fail closed. */
  readonly blocking: boolean;
  constructor(message: string, blocking: boolean) {
    super(message);
    this.blocking = blocking;
  }
}

/** The firewall-internal tool name for a native call that cannot be read (classified as a parse failure). */
export { UNPARSEABLE_TOOL } from "../engine/classify.js";
