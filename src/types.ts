/**
 * The vocabulary of the firewall. The engine reads a normalized action and the
 * session's state, and returns a decision. Nothing here does I/O.
 */

import type { LockfileReader, PackageIntel, PackageIntelPolicy } from "./engine/packages.js";
import type { SandboxPolicy } from "./engine/sandbox.js";
import type { RunPolicy } from "./policy-run.js";
import type { KnownHostsPolicy } from "./policy-knownhosts.js";
import type { BudgetPolicy, BudgetUse, MonitorSignal, Watch } from "./engine/budgets.js";
import type { CapPolicy, CapRecord } from "./engine/caps.js";
import type { PersistencePolicy } from "./policy-persistence.js";
import type { ScopeEffect, TaskScope, TaskScopePolicy } from "./engine/scope.js";
import type { VaultView } from "./engine/vault-ref.js";
import type { VaultPolicy } from "./policy-vault.js";
import type { GatewayDoc } from "./policy-gateway.js";
import type { EmailGuardPolicy } from "./policy-email.js";
import type { PhonePolicy } from "./policy-phone.js";
import type { LearnedAllowsPolicy } from "./policy-learned.js";
import type { OutsiderWritablePolicy } from "./engine/outsider.js";

/** What an agent's tool call does, in the terms the policy reasons about. */
export type ActionClass =
  /** Reading a file inside the workspace. */
  | "read_local_workspace"
  /** Reading content an outsider can write: the web, untrusted MCP results, files outside the workspace, downloads, third-party code. */
  | "read_external"
  /** Reading a credential: a secret file in the workspace, or a credential store on the machine. */
  | "read_secret"
  /** Writing inside the workspace (or a scratch directory). */
  | "write_workspace"
  /** Writing outside the workspace, somewhere that is neither protected nor a persistence point. */
  | "write_outside_workspace"
  /** Writing the files that program the agent: instructions, memory, settings, hooks, MCP lists. */
  | "write_protected"
  /** Writing something that runs code later on its own: shell rc files, git hooks, CI workflows, editor tasks, cron. */
  | "write_persistence"
  /** Touching the firewall itself: its config, state, approvals, pins, install, or its hook registration. */
  | "firewall_tamper"
  /** Network traffic whose only payload is the address (a GET, a DNS lookup, a clone). */
  | "egress_fetch"
  /** Network traffic that carries data out: a POST, an upload, a push, a message, a PR, an external write. */
  | "egress_send"
  /** Running code the workspace already has (tests, builds, scripts). */
  | "execute"
  /** Running code that came from outside: a pipe from curl, a downloaded file, a file written after untrusted input. */
  | "execute_untrusted"
  /** Running code the firewall cannot see into: inline interpreter code, eval, a command built from variables. */
  | "execute_opaque"
  /** Destroying data or infrastructure: recursive deletes outside a build dir, cloud deletes, DROP TABLE, force pushes. */
  | "destructive"
  /** Gaining privileges: sudo, su, setuid. */
  | "privilege"
  /** Starting another coding agent with its safety switched off. */
  | "agent_spawn"
  /** A tool whose effect the firewall does not know. */
  | "unknown";

export type Verdict = "allow" | "ask" | "queue" | "deny";

/**
 * What a rule wants, before the session's mode is applied:
 * "approve" becomes ask (a person is there) or queue (unattended);
 * "hold" always becomes queue (a proposed change to the agent's own instructions or memory, never applied by the agent);
 * "deny" is never approvable.
 */
export type Outcome = "allow" | "approve" | "hold" | "deny";

/** A single thing a tool call does. One call can have several (cat .env | curl ... is a secret read and a send). */
export interface Effect {
  cls: ActionClass;
  /** The path, URL, host, repository or command this effect is about. */
  target: string;
  /** For egress: the destination host, lower-cased, without a trailing dot. */
  host?: string;
  /** For egress: a coarse destination identity used for "the user named this" checks (a host, or github:owner/repo). */
  destination?: string;
  /** Plain-language description for the reason a person reads. */
  detail: string;
  /** Reading this brings outside content into the session (the session becomes untrusted). */
  taints?: boolean;
  /** Reading this brings private data into the session. */
  private?: boolean;
  /** A file this action downloads; later reads of it are outside content and running it is untrusted code. */
  download?: string;
  /** Further files the same action downloads, when effects that are otherwise equal were merged (downloadsOf reads both). */
  moreDownloads?: string[];
  /** For egress: the text that leaves the machine (URL, body, arguments), scanned for credentials and personal data. */
  payload?: string;
  /** F33: for egress: the size of files the request uploads (curl -T, -d @f, -F x=@f), counted by the byte budgets. */
  uploadBytes?: number;
  /** For writes to instructions or memory: the change, kept as a proposal when the session is untrusted. */
  proposal?: string;
  /** Refinements a rule may use: "memory" (agent memory/plans), "settings" (files that register hooks, MCP servers, agents), "install" (package install), "message" (a message to people). */
  tags?: string[];
}

/** A hard fact found while classifying, independent of session state. Rules turn findings into verdicts. */
export interface Finding {
  id: FindingId;
  detail: string;
}

export type FindingId =
  | "capture_host"
  | "raw_ip"
  | "dns_exfil_shape"
  | "secret_in_payload"
  | "secret_fingerprint_in_payload"
  | "secret_env_in_egress"
  | "secret_flow_in_command"
  | "remote_code_pipe"
  | "obfuscated_exec"
  | "invisible_unicode"
  | "unresolvable_write_target"
  | "unresolvable_command"
  | "parse_failure"
  /** A network request a sandbox middleware refused before the engine judged it (NETWORK_REFUSED_TOOL). */
  | "network_refused"
  | "too_large"
  | "destroy_root"
  /** An action that cannot be undone and that no agent may take (src/engine/catastrophic.ts). */
  | "catastrophic"
  | "credential_store_read"
  | "symlink_to_protected"
  | "bypass_flags"
  | "hook_disable"
  | "url_data_capacity"
  | "insecure_scheme"
  | "pii_in_payload"
  | "recursive_home_sweep"
  | "metadata_endpoint"
  | "env_injection"
  | "blocked_tool"
  | "canary_read"
  | "policy_error"
  // Package vetting (src/engine/packages.ts).
  | "malicious_package"
  | "malicious_package_maybe"
  | "typosquat_name"
  | "lockfile_malicious"
  | "intel_unreadable"
  | "lockfile_unreadable";

export interface Decision {
  verdict: Verdict;
  /** The class the decision was mainly about (the most severe effect). */
  primaryClass: ActionClass | "none";
  /** One line per rule that fired, most severe first. */
  reasons: string[];
  /** Stable rule ids, in the same order as reasons. */
  rules: string[];
  effects: Effect[];
  findings: Finding[];
  /** State changes to record if the action goes ahead (taint, sensitivity, downloads...). */
  events: StateEvent[];
  /** Stable hash of the action, used to match a human approval to the exact same action. */
  actionHash: string;
  /**
   * The key the loop and failure counters count the action under (counterKey(): the action without cosmetic
   * fields such as a Bash description). Absent: actionHash (decisions written before it existed).
   */
  counterKey?: string;
  /** What the action adds to the session's budget counters, and what approving it raises (set when budgets were checked). */
  budget?: { usage: BudgetUse[]; raises: BudgetUse[]; loopEligible: boolean; writes: boolean; watch?: Watch };
  /**
   * Set when the behaviour monitor (FW-LOOP's stop limits) stopped the session with this action: the runtime
   * records the stop and notifies the person. The action itself is denied (FW-STOPPED).
   */
  stop?: {
    signal: MonitorSignal;
    reason: string;
    /** "agent": the agent's own counters crossed the limit (library and local API), so every session of it stops. */
    scope?: "session" | "agent";
    /** The stop's id and target, set by the runtime before it records the counters (the sentinel names them). */
    id?: string;
    target?: string;
  };
  /** What the action adds to the spending-limit counters, the warnings it gives and the caps it stops at (set when caps were checked). */
  caps?: CapRecord;
  /** What the task scope did (or, in log mode, would have done) to this decision. Absent when it had nothing to say. */
  scope?: ScopeEffect;
  /**
   * A stored approval of this exact action that was not used, and why in plain words (a rule it was not shown now
   * asks, or it was given for another working directory or project). Set only when the action still asks.
   */
  approvalIgnored?: string;
  /**
   * The vault references the action carries in positions that leave the machine, and how each
   * would be substituted. Substitution happens only when the final verdict is allow (an answered ask, or an
   * approved retry). Absent when the action carries no reference in such a position.
   */
  vault?: VaultDecision;
  /**
   * Watch mode (src/policy-rollout.ts): what enforcing would have done to an action watch mode let run.
   * Absent unless watch mode was active and changed the verdict.
   */
  watch?: { verdict: Verdict; rules: string[]; reasons: string[] };
}

/** One planned substitution: never a value, only the reference and where it goes. */
export interface VaultSubstitution {
  /** The reference as written ("vault://github/token"). */
  ref: string;
  name: string;
  field: string;
  kind: string;
  via: "gateway" | "run" | "hook";
  /** host, `mcp:<server>:<tool>`, or the argv display. */
  destination: string;
  /** The binding that permits it, as one line (bindingSummary). */
  binding: string;
  /**
   * MCP (via gateway): the argument path the reference was checked at ("token", "headers.auth"). The value
   * is put in at this path only; a reference anywhere else in the arguments stays text.
   */
  path?: string;
}

export interface VaultDecision {
  refs: string[];
  substitute: VaultSubstitution[];
}

/** A tool call in a client-neutral shape. MCP tools are named mcp__server__tool, as in Claude Code. */
export interface NormalizedAction {
  tool: string;
  input: Record<string, unknown>;
}

/** Where the action runs. Paths are absolute and already normalized by the caller where it can. */
export interface Context {
  cwd: string;
  /**
   * F-f: false when a command moved to a directory that cannot be known (cd "$SOME_DIR"); cwd is then
   * UNKNOWN_CWD and relative paths resolve inexactly. Undefined means known.
   */
  cwdKnown?: boolean;
  /** F-f: the command changed directory (cd, pushd, git -C...) before this part: cwd is where it runs. */
  cwdShifted?: boolean;
  /** The project root(s). Paths under these are the workspace. */
  workspaceRoots: string[];
  home: string;
  /** Directories the agent may write freely (OS temp, the client's scratchpad). */
  scratchRoots: string[];
  /** Where the firewall keeps its own state and config. Always protected. */
  firewallHome: string;
  /**
   * Where the firewall's code is installed.
   * @deprecated since 0.2 (F-c): use `identity`. Kept for one release; when `identity` is absent the
   * engine derives a narrowed fallback identity from it (its dist/, node_modules/ and package.json).
   */
  firewallInstallDir: string;
  /** F-c: what is actually installed (from the registered hook commands). Protected by identity, not by name. */
  identity?: FirewallIdentity;
  /** Whether a person can answer an "ask" right now. When false, approvals become queued. */
  interactive: boolean;
  /** Where the MCP server behind an mcp__ tool was configured (Claude Code's mcp_server.source), when known. */
  mcpSource?: string;
  /**
   * I4: the server and tool the agent's event named in fields of their own (not split out of the tool's name). An
   * mcp__ name that spells exactly these is read as them, however many "__" it holds.
   */
  mcpTool?: { server: string; tool: string };
  /**
   * The directories a filesystem-type MCP server was started with (absolute, from its own launch
   * arguments), when they could be read; undefined when unknown. G6: a server whose roots all lie in
   * the workspace reads nothing outside it.
   */
  mcpRoots?: string[];
  /**
   * Case-insensitive file system (macOS, Windows): the platform's rule, used where a comparison grants trust (inside
   * the workspace or the scratch directory, a file the agent wrote itself). I1: it does not decide protection.
   * The lists of protected files, persistence points, secrets and credential stores, the firewall's own directory
   * and the agents' settings files are matched ignoring case on every platform, because a Linux host cannot know
   * whether a directory (WSL on /mnt/c, an SMB or exFAT mount) folds case.
   */
  caseInsensitive: boolean;
  /**
   * Resolves symlinks for an absolute path that may not exist yet (the realpath of its longest existing
   * prefix plus the rest). Throws when the path cannot be resolved (a symlink loop, no permission): the
   * engine then treats the path as possibly protected (SELF-016). Injected so the engine stays pure.
   */
  realpath?: (absPath: string) => string;
  /** Reads a small file's current content (null if missing or unreadable). Injected so the engine stays pure. */
  readFile?: (absPath: string) => string | null;
  /**
   * Scratch-target name patterns from the person's signed allowlist (`launchsafe-firewall scratch add`, user
   * level only): a catastrophic delete whose every target matches one is asked instead of denied. Absent: none.
   */
  scratchTargets?: string[];
  /** F33: a file's size in bytes (null if missing or unreadable). Injected. */
  fileSize?: (absPath: string) => number | null;
  /** Settings files the firewall's hooks are installed in (from its install record and managed settings). */
  registeredSettings?: string[];
  /**
   * F13: hook settings files known by where the agents look for them, whatever they are called ($CODEX_HOME's
   * hooks.json and config.toml, GEMINI_CLI_SYSTEM_SETTINGS_PATH, Gemini CLI's home settings). Judged by their result.
   */
  agentSettings?: string[];
  /**
   * F-e: what the provenance ledger knows about a file's current content (null: nothing, or any doubt).
   * selfAuthored is false when the agent wrote the file but its content has changed since. Injected.
   */
  provenance?: (absPath: string) => { selfAuthored: boolean; taintedAtWrite: boolean } | null;
  /** F-e: whether an agent session created this directory (and whether it was untrusted then). Injected. */
  dirProvenance?: (absDir: string) => { createdBySession: boolean; taintedAtWrite: boolean } | null;
  /**
   * The hosts a person approved for this project (knownHosts, src/runtime/knownhosts.ts), read from the
   * firewall's own directory. Absent: none (with knownHosts.mode "ask", every host outside the policy's lists
   * and the built-in set then asks).
   */
  knownHosts?: { approved: readonly string[] };
  /** The decoy files the person planted (canary plant), loaded from the registry. Absent when there are none or the registry is unreadable. */
  canaries?: CanaryIndex;
  /** The local malicious-package snapshot (read lazily; absent = no package intel). */
  packageIntel?: PackageIntel;
  /** Reads lockfiles for an install from a lockfile (bounded; runtime I/O injected). */
  lockfiles?: LockfileReader;
  /** The sandbox profiles `doctor --fix` installed (settings file and the recorded `sandbox` object). Absent when protection is off. */
  sandboxProfiles?: { path: string; installed: Record<string, unknown> }[];
  /** The vault's names, kinds, bindings and fingerprints from the signed index (never a value). Absent when there is no vault. */
  vault?: VaultView;
  /**
   * How references can be substituted for this call. `shellRewrite`: the agent rewrites tool
   * input (Claude Code's updatedInput) and the policy allows it; `gatewayServers`: MCP servers behind the
   * gateway (wrapped entries, or the gateway's own call), the only ones a reference can reach as a value.
   */
  vaultPaths?: { shellRewrite: boolean; gatewayServers: readonly string[] };
  /**
   * MCP client configuration files the gateway wrapped (from gateway/install.json): the
   * file and, per server name, the wrapped entry's canonical hash. Judged by their result in settings.ts.
   */
  gatewayConfigs?: { path: string; wrapped: Record<string, string> }[];
}

/** The registry's view the engine needs: decoy paths and the fingerprints of their unique values. Built by the runtime, never by the engine. */
export interface CanaryIndex {
  /** Decoy paths (realpaths, as planted). */
  paths: Set<string>;
  /** Fingerprints of the decoys' unique values (same function as secrets.ts). */
  fingerprints: Set<string>;
  /** Lookup key of a path (lower-cased on a case-insensitive file system) to its decoy id. */
  byPath: Map<string, string>;
  /** Fingerprint to decoy id. */
  byFingerprint: Map<string, string>;
}

/**
 * F-c: the firewall as installed, identified by the hook commands that run it. Everything here is an
 * absolute path (both the path as recorded and its realpath where they differ). Nothing is protected
 * because of what it is called.
 */
export interface FirewallIdentity {
  /** The CLI files named in registered hook commands (usually one). */
  cliFiles: string[];
  /** Directories whose contents run when the hook runs: <pkg>/dist and <pkg>/node_modules (or a lone bundle's directory). */
  runtimeRoots: string[];
  /** Single files that are part of the runtime: <pkg>/package.json. */
  runtimeFiles: string[];
  /** The package roots those runtime roots belong to (building inside one rewrites the runtime). */
  packageRoots: string[];
  /** Node binaries named in hook commands. */
  nodeBinaries: string[];
  /** The firewall's data: firewallHome, ~/.launchsafe-firewall, a LAUNCHSAFE_FIREWALL_HOME in a hook command, managed policy dirs. */
  dataRoots: string[];
  /** Bare command names that run the CLI (always includes launchsafe-firewall, so an unresolvable bare name fails closed). */
  binNames: string[];
  /** The system-keychain service names the vault stores its values under (identityOf adds the default). */
  vaultServices?: string[];
  /** How it was built. */
  source: "hook-command" | "fallback-install-dir";
}

export type StateEvent =
  | { type: "taint"; source: string }
  | { type: "sensitive"; source: string }
  | { type: "fingerprint"; hash: string }
  | { type: "user_destinations"; destinations: string[] }
  | { type: "downloaded"; path: string }
  | { type: "tainted_write"; path: string }
  | { type: "secret_path"; path: string }
  /** The session read a credential (a credential store, a secret file, a CLI's stored token): later sends need a person. */
  | { type: "credential_read"; source: string }
  /** `proposal`: the approved item was a proposal shown with its diff (set by the store that verified it, never read from disk). */
  /**
   * B1/I2 (approval message v2): `nonce`, `exp`, `rules`, `cwd` and `projectDir` are signed with the rest. An
   * approval without them is a v1 line, no longer honoured.
   */
  | { type: "approval"; actionHash: string; id: string; sig?: string; proposal?: true; nonce?: string; exp?: string; rules?: string[]; cwd?: string; projectDir?: string }
  | { type: "corrupt"; detail: string }
  /** `id`: the approval used (B1: that id never counts again in the session). Older lines name only the action. */
  | { type: "approval_used"; actionHash: string; id?: string }
  /**
   * An approval signed by a paired phone's passkey (a full WebAuthn assertion over `m`). It
   * counts only after loadState() re-verified it against the pinned phones (`verified`, never read from
   * disk) and before `exp`; docs/phone.md.
   */
  | { type: "phone_approval"; actionHash: string; id: string; credentialId: string; m: string; authData: string; clientData: string; sig: string; exp: string; verified?: true }
  // v0.2 (07-cross-cutting). Read and validated now; the items that act on them land later.
  /** The task scope derived from the person's prompt. */
  | { type: "scope"; scope: TaskScope }
  /** A person widened the scope (signed with the approver key). */
  | { type: "scope_widen"; kind: string; value: string; id: string; sig: string }
  /** A person raised a budget (signed with the approver key). */
  | { type: "budget_raise"; key: string; amount: number; id: string; sig: string }
  /** The session read, wrote or deleted a decoy file. */
  | { type: "canary_tripped"; id: string }
  /** A decoy's value appeared in a tool result. */
  | { type: "canary_seen"; id: string }
  /** The agent-configuration scan at session start. */
  | { type: "agent_scan"; rules: string[]; incomplete: boolean }
  /** This session is a subagent of another one. */
  | { type: "linked"; parent: string }
  /**
   * Outside content showed a command (`c:`) or named a package to install (`p:`): the fingerprint (a hash
   * prefix, never the text) and the source that showed it. FW-OUTSIDE-COMMAND compares later commands with them.
   */
  | { type: "outside_command"; hash: string; source: string; tokens?: string[] };

/** What the firewall remembers about a session. Built only by folding events; taint never goes away. */
export interface SessionState {
  tainted: boolean;
  taintSources: string[];
  sensitive: boolean;
  sensitiveSources: string[];
  fingerprints: Set<string>;
  userDestinations: Set<string>;
  downloaded: Set<string>;
  taintedWrites: Set<string>;
  /** Files this session copied credentials into: reading them is reading a secret. */
  secretPaths: Set<string>;
  /**
   * What credentials this session read (bounded, newest last). Once any, a send to a host the person has not
   * allowed needs a person (FW-CREDENTIAL-FLOW). Absent in states built before it existed: none.
   */
  credentialReads?: string[];
  /** Approvals not yet used, by action hash. */
  approvals: Map<string, string>;
  /**
   * V37: the action hashes among `approvals` whose approval was given on a proposal (the person saw its
   * diff). Only these may let through an action now held as a proposal; any other approval (passphrase or
   * phone, on an approval item) overrides only an "approve" outcome. Absent: none.
   */
  proposalApprovals?: Set<string>;
  /**
   * I2: what each approval in `approvals` was signed for (v2 approvals): the rule ids the person was shown,
   * its expiry, and where it was given. Absent for an approval that carries none (the library's memory store).
   */
  approvalGrants?: Map<string, { id: string; rules?: string[]; exp?: string; cwd?: string; projectDir?: string }>;
  /** v0.2 state (task scope, agent scan, budgets, subagents): folded from their events. */
  /** The current task's scope (null: no prompt was recorded, today's rules apply). */
  scope: TaskScope | null;
  scopeWidenings: { kind: string; value: string; id: string }[];
  budgetRaises: { key: string; amount: number; id: string }[];
  /** The session-start scan ran for this session (an agent_scan event exists). */
  agentScanned: boolean;
  agentScanRules: string[];
  agentScanIncomplete: boolean;
  linkedParents: string[];
  /** Decoys this session touched (ids). Once set, every send in the session needs a person. */
  canaryTripped: Set<string>;
  /** Decoys whose value appeared in this session's tool output (ids). */
  canarySeen: Set<string>;
  /** Commands and packages outside content showed: fingerprint -> the source that showed it first. Absent: none. */
  outsideCommands?: Map<string, string>;
  /** Distinctive-word sets of commands outside content showed (hashes), with their source: a command holding every word matches. */
  outsideTokenSets?: [string[], string][];
}

export type DataKind = "credential" | "card" | "iban" | "national_id";

export type McpTrust =
  /** Results come from the user's own machine or trusted systems and do not taint. */
  | "trusted"
  /** Results carry text outsiders can write (issues, email, chat, web pages, tickets). */
  | "untrusted";

export interface McpServerPolicy {
  /** Whether this server's results taint the session. */
  results: McpTrust;
  /** Whether reading from this server counts as reading private data. */
  privateData: boolean;
  /** Tool-name overrides: which tools only read, which send or write externally, which destroy. */
  readTools?: string[];
  sendTools?: string[];
  destructiveTools?: string[];
  /** Tools that must never be called. */
  blockedTools?: string[];
}

/** Workspace decoys. `enabled: false` is user or managed policy only. */
export interface CanaryPolicy {
  /** Watch for decoys at all (the registry is read, reads are tripwires, values are denied on egress). */
  enabled: boolean;
  /** A recursive read (grep -r, rg --no-ignore, tar) whose scope contains a decoy trips it. Off by default: ordinary searches sweep directories. */
  tripOnRecursive: boolean;
  /** `install` offers to plant workspace decoys (a yes/no prompt in a terminal). On by default. */
  offerAtInstall: boolean;
  /** The install offer also covers decoys in the home directory (~/.aws, ~/.ssh, ...). Off by default; `canary plant --home` is the explicit way. */
  homeDecoys: boolean;
}

/** F-e: the provenance ledger (files the agent wrote itself). */
export interface ProvenancePolicy {
  /** Reading a file whose content is exactly what a trusted session wrote does not taint. Loosening: user/managed policy only. */
  trustSelfAuthored: boolean;
  /** Files an untrusted session wrote stay untrusted in later sessions (running them, running a manifest). Stricter. */
  carryUntrustedWrites: boolean;
  /** Files larger than this are not hashed (and so fall back to v0.1 classification). */
  maxHashBytes: number;
}

export interface FirewallConfig {
  /** Policy schema version (POLICY_VERSION in src/policy.ts). */
  version: 3;
  /** Hosts that may be fetched from even in a tainted session (package registries, docs). Suffix match on a dot boundary. */
  fetchAllowHosts: string[];
  /** Hosts that may be sent to even in a tainted session. Empty by default on purpose. */
  sendAllowHosts: string[];
  /** Hosts never contacted. */
  denyHosts: string[];
  /** Per MCP server name (the middle part of mcp__server__tool). Exact name, or a pattern ending in *. */
  mcpServers: Record<string, McpServerPolicy>;
  /** Server policy for servers not listed. */
  mcpDefault: McpServerPolicy;
  /** Extra workspace-relative globs that count as third-party content (reading taints). */
  untrustedPaths: string[];
  /** Extra globs, relative to the workspace or absolute (~ allowed), that are protected. */
  protectedPaths: string[];
  /** Extra secret file globs. */
  secretPaths: string[];
  /** Absolute roots outside the workspace whose files may be read without tainting (system headers, toolchains). */
  trustedReadRoots: string[];
  /** When true, every file in the workspace is treated as untrusted (reviewing someone else's repository). */
  untrustedWorkspace: boolean;
  /** Destinations allowed to receive a kind of sensitive data that is otherwise never sent (card numbers to a payment API). */
  dataAllowHosts: Record<DataKind, string[]>;
  /** Published test values (Stripe test cards, example IBANs, sk_test_ keys) are not treated as sensitive data. */
  allowTestValues: boolean;
  /** Treat every session as unattended (no one answers prompts): approvals are queued. */
  unattended: boolean;
  /** Local hours in which sessions are unattended, e.g. [{ "from": "22:00", "to": "07:00" }]. */
  unattendedHours: { from: string; to: string }[];
  /** Write a masked copy of secrets out of tool results before the model sees them (PostToolUse). */
  redactSecretsInOutput: boolean;
  /** Writes to the agent's instructions and memory proceed in a trusted session (they are always held once untrusted). */
  allowInstructionWritesWhenTrusted: boolean;
  /** Claude Code permission modes in which nobody answers a prompt, so approvals are queued instead of asked. */
  unattendedPermissionModes: string[];
  /** Branch patterns protected from force pushes and deletes, besides main, master and trunk (always protected). */
  protectedBranches?: string[];
  /** F-d: extra tool names (exact) that only show something to the person (non-tainting). User/managed policy only. */
  userOutputTools: string[];
  /** F-d: tool names that must never be treated as showing something to the person (a project may add these). */
  notUserOutputTools: string[];
  /** F-e: the provenance ledger. */
  provenance: ProvenancePolicy;
  /** The agent-configuration scan at session start. */
  agentScan: AgentScanPolicy;
  /** MCP server configuration, tool-name and tool-description pinning. */
  mcpPinning: McpPinningPolicy;
  /** Decoy files planted by the person. */
  canaries: CanaryPolicy;
  /** Local desktop notifications for held and blocked actions. Informs only; never approves. */
  notifications: NotificationPolicy;
  /** Per-task scope from the person's prompt (src/policy-scope.ts). */
  taskScope: TaskScopePolicy;
  /** Malicious-package, typosquat and lockfile checks (defaults in src/engine/packages.ts). */
  packageIntel?: Partial<PackageIntelPolicy>;
  /** Sources outsiders can write, and commands they suggest (defaults in src/engine/outsider.ts). */
  outsiderWritable?: Partial<OutsiderWritablePolicy>;
  /** Claude Code's OS sandbox profile (defaults in src/engine/sandbox.ts). */
  sandbox?: Partial<SandboxPolicy>;
  /** v0.3 `run`: paths a person exempts from run's read-only rule on agent-named scripts (src/policy-run.ts). */
  run?: Partial<RunPolicy>;
  /** Ask before contacting a host this project has never contacted (src/policy-knownhosts.ts; absent = off). */
  knownHosts?: Partial<KnownHostsPolicy>;
  /** Content checks for CI, git-hook, editor-task, dev-container and environment-hook files. */
  persistence: PersistencePolicy;
  /** Outbound byte and request budgets, MCP-call budgets, loop detection (defaults in src/engine/budgets.ts). */
  budgets: BudgetPolicy;
  /** Spending limits per session and per day, which stop the agent (defaults in src/engine/caps.ts; absent = defaults). */
  caps?: CapPolicy;
  /** The vault (defaults in src/policy-vault.ts; absent = defaults). */
  vault?: Partial<Omit<VaultPolicy, "confirmDefault">> & { confirmDefault?: Partial<VaultPolicy["confirmDefault"]> };
  /** The MCP gateway (defaults in src/policy-gateway.ts; absent = defaults). */
  gateway?: GatewayDoc["gateway"];
  /** The email guard (defaults in src/policy-email.ts; absent = defaults). */
  emailGuard?: Partial<EmailGuardPolicy>;
  /** Phone approvals (defaults in src/policy-phone.ts; absent = defaults). */
  phone?: Partial<Omit<PhonePolicy, "requireUserVerification">>;
  /** Rollout mode (src/policy-rollout.ts; absent = enforce). Watch mode needs a person's signed grant (src/runtime/rollout.ts). */
  rollout?: RolloutPolicy;
  /** Learned project allows: whether they apply and when they are offered (defaults in src/policy-learned.ts; absent = defaults). */
  learnedAllows?: Partial<LearnedAllowsPolicy>;
}

/** "enforce" (the default) applies every verdict; "watch" logs what would have been asked, held or blocked and lets it run, except the always-enforced core. */
export type RolloutMode = "enforce" | "watch";

export interface RolloutPolicy {
  mode: RolloutMode;
}

/** Which agent-safety findings make a session start untrusted. */
export interface AgentScanPolicy {
  /** Loosening (false): user/managed policy only. */
  enabled: boolean;
  /** "high": critical, or high severity with high confidence (default); "critical": critical only; "never": log only. */
  taintOn: "critical" | "high" | "never";
  /** Also scan the user's own agent files (~/.claude) and auto memory. Loosening (false): user/managed only. */
  userScope: boolean;
}

/** MCP pins (firewallHome/pins/mcp.json). */
export interface McpPinningPolicy {
  enabled: boolean;
  /** Tool names a server exposes in this many hours after its first-use pin are added without an alert. */
  newToolGraceHours: number;
  /** A changed configuration, a new tool after the grace window or a changed tool description taints the session. */
  taintOnChange: boolean;
}

export type NotifyKind = "queued" | "proposal" | "denied_dlp" | "canary" | "loop" | "agent_config" | "mcp_changed" | "mcp_withheld" | "mail_quarantined" | "stopped" | "cap";

export interface NotificationPolicy {
  enabled: boolean;
  on: NotifyKind[];
  /** True: only notify when the session is unattended. */
  onlyWhenUnattended: boolean;
  /** At most one notification per kind in this many seconds; suppressed ones are folded into the next count. */
  minIntervalSec: number;
}
