/**
 * The library's public types (docs/library.md). Browser-safe: types only.
 */

import type { BudgetView, MonitorSignal } from "../engine/budgets.js";
import type { StopView } from "../engine/stop.js";
import type { CapView, ModelUsage } from "../engine/caps.js";
import type { Counters } from "../engine/counters.js";
import type { LockfileReader, PackageIntel } from "../engine/packages.js";
import type { VaultView } from "../engine/vault-ref.js";
import type { PolicyDoc } from "../policy.js";
import type { CanaryIndex, Context, Decision, Effect, Finding, FirewallConfig, NormalizedAction, SessionState, StateEvent } from "../types.js";

export type { CapView, Counters, Decision, FirewallConfig, ModelUsage, NormalizedAction, PolicyDoc, SessionState, StateEvent, VaultView };

/** The library's verdicts: the engine's "queue" is "hold" (held for a person's review). */
export type GuardVerdict = "allow" | "ask" | "hold" | "deny";

/** A tool call as the host's agent loop knows it. */
export interface ToolCall {
  /** The tool's name in the host's agent (mapped through the guard's `tools`). */
  tool: string;
  /** The tool's arguments. */
  input: Record<string, unknown>;
  /** The framework's id for this call, kept in the log. */
  callId?: string;
  /** For mcp__ tools: where the MCP server was configured ("user", "project", "sdk"...). Unstated means "unknown" (untrusted). */
  mcpSource?: string;
  /**
   * The agent's permission mode for this call, when the framework reports one (the Claude Agent SDK's
   * permission_mode). A mode listed in the policy's unattendedPermissionModes (default: dontAsk, bypassPermissions and auto) means no
   * one can answer, so an ask becomes a held action, as on the hook path.
   */
  permissionMode?: string;
  /**
   * Model usage behind this call, when the agent loop knows it (tokens, and its own cost estimate in US
   * dollars). Counted toward the token and cost spending limits (policy `caps`); the firewall never calls
   * a model and keeps no prices.
   */
  usage?: ModelUsage;
}

/** What a host may say about a tool result besides its output (recordResult). */
export interface ResultOptions {
  /**
   * The tool failed. A failure counts toward the identical-failures spending limit of this exact call,
   * by its error text (the output). Without it, only explicit markers in the output count (an MCP
   * result's isError, a non-zero exitCode).
   */
  failed?: boolean;
}

/** Engine tools a host tool can be (`as`). Any tool name the engine models is accepted. */
export type EngineTool = "Bash" | "Read" | "Write" | "Edit" | "MultiEdit" | "Glob" | "Grep" | "LS" | "WebFetch" | "WebSearch" | "NotebookEdit" | (string & Record<never, never>);

/** A host tool that is one of the tools the engine models. */
export interface AsToolSpec {
  as: EngineTool;
  /** Translates the host tool's arguments to the engine tool's input (default: unchanged). */
  input?: (args: Record<string, unknown>) => Record<string, unknown>;
}

/** A host tool judged like an MCP tool. */
export interface KindToolSpec {
  /** What a call does: reads, sends or writes outside, destroys, or must never run. */
  kind: "read" | "send" | "destroy" | "blocked";
  /** Whether what it returns can carry text outsiders wrote (default "untrusted"). */
  results?: "trusted" | "untrusted";
  /** Whether what it returns is private data (default true). */
  privateData?: boolean;
  /** The server it belongs to (default: the tool's own name). Tools of one server share `results` and `privateData`. */
  server?: string;
}

export type ToolSpec = AsToolSpec | KindToolSpec;

/** A held action: needs a person's review, never done by the agent now. */
export interface HeldAction {
  id: string;
  session: string;
  createdAt: string;
  /** The host's tool name and arguments (credentials masked, long strings cut). */
  tool: string;
  input: unknown;
  /** The hash an approval binds to: approving lets exactly this call run once. */
  actionHash: string;
  rules: string[];
  reasons: string[];
  /** "proposal": a change to the agent's instructions, memory or files that run code later. */
  kind: "approval" | "proposal";
  proposal?: { target: string; change: string };
  status: "pending" | "approved" | "rejected";
  decidedAt?: string;
  by?: string;
}

/** What the guard decided about one call. */
export interface GuardDecision {
  /** Correlates the decision with its log entry and an approval. */
  id: string;
  verdict: GuardVerdict;
  /** The call as the host gave it. */
  call: ToolCall;
  /** The action the engine judged (the host's tool mapped to the engine's vocabulary). */
  action: NormalizedAction;
  /** Stable rule ids, most severe first, and one plain-language reason per rule. */
  rules: string[];
  reasons: string[];
  /** One text for the person and the model ("" when allowed). Control characters escaped. */
  message: string;
  actionHash: string;
  primaryClass: Decision["primaryClass"];
  /** Set when the verdict is "hold". */
  held?: HeldAction;
  /** The engine's whole decision (effects, findings, state events). */
  engine: Decision;
  /**
   * What went wrong recording this decision (the decision log, onHold). The verdict already accounts for it:
   * a decision the log refused to record is never an allow (FW-LOG-UNRECORDED).
   */
  problems?: string[];
}

/** What the host's approval callback is given. */
export interface ApprovalRequest {
  session: string;
  decision: GuardDecision;
  /** The same text as decision.message. */
  message: string;
}

/** The host's answer. Only `true` or `{ approved: true }` approves; anything else is a no. */
export type ApprovalAnswer = boolean | { approved: boolean; by?: string; note?: string } | null | undefined;

export type ApprovalHandler = (req: ApprovalRequest) => ApprovalAnswer | Promise<ApprovalAnswer>;

export interface Authorization<D = GuardDecision> {
  /** Whether the tool may run now. */
  allowed: boolean;
  decision: D;
  /** Set for an "ask": what the host answered, normalized. */
  approval?: { approved: boolean; by?: string; note?: string };
}

/** Untrusted content that entered the agent outside a tool call (a retrieved document, an email in the prompt). */
export interface UntrustedInput {
  /** Where it came from, in a few words (kept in the session's taint sources). */
  source: string;
  content: unknown;
  /** The content is private data (a customer record, a private repository): later sends are judged with that in mind. */
  private?: boolean;
}

export interface ResultNote {
  /** The session became untrusted because of this result. */
  becameUntrusted: boolean;
  /** Credentials seen in the output (their fingerprints are remembered; their values never leave). */
  secretsSeen: number;
  /** The output with credentials masked, when the policy sets redactSecretsInOutput and something was masked. */
  redacted?: string;
  /** A note for the model when the session just became untrusted (as the hook adds to Claude Code's context). */
  note?: string;
}

export interface SessionSnapshot {
  session: string;
  untrusted: boolean;
  untrustedBecause: string[];
  holdsPrivateData: boolean;
  privateBecause: string[];
  /** Destinations the person named (an untrusted session may still contact these). */
  namedDestinations: string[];
}

export interface LogEntry {
  seq: number;
  ts: string;
  prev: string;
  event: Record<string, unknown>;
  hash: string;
  /** Base64 signature of the hash bytes ("" when the store has no signer). */
  sig: string;
  /** The file store (v0.3 and later): "signed", and `sig` then covers `entry:<hash>:heads-signed` (docs/design.md). */
  heads?: "signed";
}

export interface LogVerifyResult {
  ok: boolean;
  entries: number;
  /** Whether every entry carries a signature that verified. */
  signed: boolean;
  problems: string[];
}

/** Signs a log entry's hash (32 bytes). Synchronous: decisions are. */
export interface LogSigner {
  sign(hash: Uint8Array): string;
  /** Checks a signature made by sign(); absent: signatures are not checked by verifyLog. */
  verify?(hash: Uint8Array, sig: string): boolean;
}

/** What a held item is made from. */
export interface HoldInput {
  session: string;
  tool: string;
  input: unknown;
  actionHash: string;
  rules: string[];
  reasons: string[];
  kind: "approval" | "proposal";
  proposal?: { target: string; change: string };
  cwd: string;
  summary?: string;
  trustSources?: string[];
  unattended: boolean;
}

/** What the ledger is told before an action that may run (a partial write keeps part of what was there). */
export interface LedgerNote {
  session: string;
  /** The engine tool the call was judged as (Write, Edit, Bash...). */
  tool: string;
  effects: readonly Effect[];
  maxHashBytes: number;
  caseInsensitive: boolean;
}

/** What the ledger is told after a tool ran: the action's effects, re-derived with the ledger's lookups attached. */
export interface LedgerRecord extends LedgerNote {
  findings: readonly Finding[];
  /** The session was untrusted before this action. */
  taintedBefore: boolean;
}

/**
 * F-e: the provenance ledger, files the agent wrote itself (src/runtime/ledger.ts, docs/design.md "Provenance").
 * Each entry holds the hash of the content a session left and whether that session was untrusted at the time. It
 * is what carries "an untrusted session wrote this" from one session into the next: a later trusted session that
 * runs the file, or a build whose manifest it is, is asked (FW-UNTRUSTED-CODE, FW-TAINTED-MANIFEST), and a file a
 * trusted session wrote reads back without counting as outside content. Taint lives in one session's events, so
 * without a ledger nothing a session wrote reaches the next one.
 *
 * The guard uses it only when it also has file access (GuardOptions.fs), because it hashes real files. Any method
 * may throw: a lookup that throws is "unknown" (the v0.1 classification, never looser), a note or a record that
 * throws loses that entry. fileStore() has one over the runtime's files, shared with the hook; memoryStore() has
 * none, since nothing in it outlives the process.
 */
export interface ProvenanceLedger {
  /** The provenance of a file's current content; null when unknown (no entry, a hash that no longer matches, too large). */
  file(absPath: string, maxHashBytes: number, caseInsensitive: boolean): { selfAuthored: boolean; taintedAtWrite: boolean } | null;
  /** Whether an agent session created a directory (and whether it was untrusted then); null when unknown. */
  dir(absDir: string, caseInsensitive: boolean): { createdBySession: boolean; taintedAtWrite: boolean } | null;
  /** Before an action that will run (allow or ask): what a partial write outside the workspace is about to keep. */
  note(n: LedgerNote): void;
  /** After a tool ran: hashes the files it left and records them, untrusted when the session or the action was. */
  record(r: LedgerRecord): void;
}

/**
 * The guard's memory. Every method is synchronous. A store may serve several guards (sessions); each
 * method that takes a session touches only that session's data.
 */
export interface StateStore {
  readonly kind: string;
  /** The firewall's own data directory, which the agent may never touch (protected like the hook's). */
  readonly firewallHome: string;
  /** The session's state, folded from its events. Approvals the store cannot vouch for are ignored and make the session untrusted. */
  load(session: string): SessionState;
  append(session: string, events: readonly StateEvent[]): void;
  /**
   * Uses the approval `approvalId` for `actionHash` once, atomically (across processes for fileStore): records
   * "approval_used" only if nothing used it since it was loaded. False: it was used already, and nothing was
   * written. Optional for custom stores; without it the guard appends the decision's events as before.
   */
  consumeApproval?(session: string, actionHash: string, approvalId: string): boolean;
  /** The engine's view of the session's budget counters at `now`. */
  budgetView(session: string, state: SessionState, now: Date): BudgetView;
  /** Adds what a decision used to the counters (and an approval's raise). */
  recordBudget(session: string, d: Decision, now: Date): void;
  /** An asked action that exceeded a budget ran (the person said yes): raise what it exceeded. */
  confirmBudget(session: string, actionHash: string, now?: Date): void;
  /**
   * Spending limits: the session's and today's counters and the person's raises (policy `caps`). Required: a
   * store without it (a JavaScript caller's) cannot count the limits, so while they are on every call is denied
   * (set caps.enabled to false to run without them). The session part goes with recordBudget.
   */
  capView(session: string, state: SessionState, now: Date): CapView;
  /** Adds the day part of a decision's spending-limit usage (all sessions of the store). */
  recordCaps?(session: string, d: Decision, now: Date): void;
  /** A result that failed: one more identical failure of `actionHash`, under each key (its error's fingerprint, its status). */
  recordFailure?(session: string, actionHash: string, fingerprints: readonly string[], now: Date): void;
  /** A decision stopped at a spending limit (FW-CAP): where a session suspension can hook in. Informs only. */
  capStopped?(session: string, d: Decision): void;
  /** Records a held action; the same pending action in the same session reuses its item. */
  hold(item: HoldInput): HeldAction;
  held(id: string): HeldAction | null;
  listHeld(session?: string): HeldAction[];
  /** A person's decision on a held item. Approval lets that exact action run once in its session. */
  settle(id: string, status: "approved" | "rejected", by: string): HeldAction;
  /**
   * Appends one entry. The guard bounds each event first; a store that will not take one throws an error
   * named "LogRefused" (the guard then writes a short fallback entry) or "LogUnrecorded" (nothing was
   * written: the decision fails closed). Any other error is reported and the decision stands.
   */
  appendLog(event: Record<string, unknown>): LogEntry;
  /** The log, oldest first (the last `limit` entries when given). */
  entries(limit?: number): LogEntry[];
  verifyLog(): LogVerifyResult;
  /** Decoy files the person planted (fileStore), or undefined. */
  canaries?(caseInsensitive: boolean, realpath?: (p: string) => string): CanaryIndex | undefined;
  /**
   * The vault's view (names, bindings and fingerprints from the signed index, never a value), read for each
   * call as the hook reads it (fileStore), or undefined when there is no vault.
   */
  vault?(): VaultView | undefined;
  /**
   * The kill switch: a stop in force for this session (or its agent) and the last resume. Required: a store
   * that keeps no person's stops returns `{ active: null }` (memoryStore keeps the monitor's). A JavaScript
   * store without it still stops on the monitor's sentinel in the counters. A store whose stops() throws makes
   * every call (reads too) fail closed. fileStore reads the runtime's records (`session stop`, `agent stop`).
   */
  stops(session: string, agent?: string | null): StopView;
  /**
   * "Fewer prompts": the person's "never" choices for a project (its root directory), keyed by learnKey().
   * Required: a store that keeps none returns an empty map. fileStore reads them from the firewall's home, as the
   * hook does. A store whose nevers() throws makes every call fail closed. GuardOptions.nevers overrides it.
   */
  nevers(projectRoot: string): ReadonlyMap<string, string>;
  /**
   * Known hosts: the hosts a person approved for a project (its root directory), as the hook reads them
   * (FW-NEW-HOST). Optional; without it no host counts as approved there (every new host asks).
   */
  knownHosts?(projectRoot: string): readonly string[];
  /**
   * Records that the behaviour monitor stopped a session, or (scope "agent", the agent's own counters) every session
   * of an agent. `id` is the stop's id, already in the counters' sentinel. Returns whether a new stop was recorded.
   */
  stop?(target: string, s: { signal: MonitorSignal; reason: string; scope: "session" | "agent"; id: string }, now: Date): { created: boolean; id: string };
  /**
   * F-e: the provenance ledger, which makes a file an untrusted session wrote stay untrusted in later sessions.
   * Optional, and used only when the guard has file access (GuardOptions.fs). fileStore has one (the hook's, in
   * the same firewall home); memoryStore has none, so a guard on it carries nothing from one session to another.
   */
  ledger?: ProvenanceLedger;
}

/** File-system access the engine may use (resolving symlinks, reading a file a change is judged by). Node fills these in. */
export interface GuardFs {
  realpath?: (absPath: string) => string;
  readFile?: (absPath: string) => string | null;
  /** For the task scope: whether a path is a file, a directory or missing. */
  stat?: (absPath: string) => "file" | "dir" | null;
  /** F33: a file's size in bytes (null if missing), so an upload counts its file toward the budgets. */
  size?: (absPath: string) => number | null;
}

/**
 * F13: agent settings files judged by their result whatever they are called: the files the firewall's hooks
 * are installed in (`registered`) and those the agents read from where their environment points (`agents`).
 * Node fills these in as the hook does.
 */
export interface GuardSettingsFiles {
  registered?: string[];
  agents?: string[];
  /** The sandbox profiles `doctor --fix` installed (a weakening is FW-TAMPER). */
  sandboxProfiles?: Context["sandboxProfiles"];
  /** The MCP client configurations the gateway wrapped (unwrapping one is FW-TAMPER). */
  gatewayConfigs?: Context["gatewayConfigs"];
}

export interface GuardOptions {
  /**
   * "Fewer prompts": the person's "never" choices for this guard's project, keyed by learnKey() of the
   * action (the local API reads them from the firewall's home). Called on every decision; a "never" denies
   * the exact action (FW-LEARNED-DENY). "Always" choices never apply in the library.
   */
  nevers?: () => ReadonlyMap<string, string>;
  /** The session id (one guard = one agent session). Default: a random id. */
  session?: string;
  /**
   * The agent this guard's session belongs to (default: the part before "/" of a session named <agentId>/<session>,
   * as the local API names them). With it the behaviour monitor counts per agent too, and stops the agent.
   */
  agent?: string;
  /**
   * What the calls are: "tool" (default), an agent's tool calls; "network", requests a network middleware
   * (OpenShell's supervisor, docs/sandboxes.md) asks about on the agent's behalf. Network traffic is not a tool
   * call: it is not counted toward the toolCalls spending limit, and not toward the agent-wide behaviour
   * monitor (one agent's tool calls and its programs' HTTP requests have different rates); the session's own
   * monitor, budgets and every rule still apply.
   */
  traffic?: "tool" | "network";
  /** Known hosts: the hosts a person approved for this guard's project (default: the store's, for the first workspace root). */
  knownHosts?: () => readonly string[];
  /** Project roots whose files are the agent's own work. Default: none. */
  workspace?: string | string[];
  /** Where relative paths resolve. Default: the first workspace root, else "/". */
  cwd?: string;
  /** The home directory the agent's paths are judged against (~/.ssh...). Default "/home/agent" (Node: os.homedir()). */
  home?: string;
  /** Directories the agent may write freely (temp, scratch). Default none (Node: the OS temp directories). */
  scratch?: string[];
  /** The policy, in the policy file's schema (docs/policy.md), applied over the defaults; or a whole FirewallConfig. */
  policy?: PolicyDoc | FirewallConfig;
  /**
   * Why the policy file(s) the host meant to use could not be loaded (the runtime's loadPolicy error), when the
   * host passed the strict defaults instead. As on the hook path, every risky action then needs a person
   * (FW-POLICY-ERROR), and each decision's `problems` says why. The local API sets it from the files it reads.
   */
  policyError?: string;
  /**
   * I9: bind a person's approval of a held action to this guard's cwd and workspace roots as well as the action,
   * so the approved call runs only where it was approved (a relative path or command names other files
   * elsewhere). Default false: the host chooses its own cwd. The local API sets it: its caller states the context.
   */
  bindApprovalsToContext?: boolean;
  /** The host's own tools in the engine's vocabulary. */
  tools?: Record<string, ToolSpec>;
  /** Default memoryStore(). */
  store?: StateStore;
  /** Signs the memory store's log when the guard creates the store. */
  signer?: LogSigner;
  /** The host's person. Never called for deny or hold. */
  onApproval?: ApprovalHandler;
  /** How long onApproval may take before it counts as a no (ms). Default: no limit. */
  approvalTimeoutMs?: number;
  /** Told about each new held action (show it for review). Informs only. */
  onHold?: (held: HeldAction) => void;
  /**
   * Told about each decision-log failure (the store threw while appending an entry). Default: console.warn.
   * A decision whose entry and short fallback entry were both refused is not carried out unrecorded
   * (FW-LOG-UNRECORDED); the message is also in that decision's `problems`.
   */
  onLogError?: (message: string) => void;
  /** Whether a person can answer an ask now. False: asks become holds. Default true. */
  attended?: boolean;
  /**
   * Case-insensitive file system (macOS, Windows). Default false (Node: by platform). It decides what grants trust
   * (is a path inside the workspace); protected files, secrets and credential stores are matched ignoring case
   * whatever this says, since a case-sensitive host can still hold a case-insensitive mount.
   */
  caseInsensitive?: boolean;
  fs?: GuardFs;
  settingsFiles?: GuardSettingsFiles;
  /** Where the firewall's code is installed (protected from the agent). Default a placeholder (Node: the package). */
  installDir?: string;
  /** The local malicious-package snapshot and lockfile reader (Node fills these in). */
  packageIntel?: PackageIntel;
  lockfiles?: LockfileReader;
  /**
   * The vault's view (names, bindings and fingerprints, never a value). Default: the store's (fileStore reads
   * the firewall home's signed index). With one, arguments carrying a vaulted value to a destination it is
   * not bound to are denied (FW-VAULT-EGRESS), and a vaulted value in a tool result makes the session hold
   * private data, as on the hook path. Ignored when the policy turns the vault off.
   */
  vault?: VaultView;
  /** The clock (tests). */
  now?: () => Date;
}
