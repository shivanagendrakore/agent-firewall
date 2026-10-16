// Vendored from LaunchSafe's agent-safety package (src/types.ts), Apache-2.0, at commit fc329d4314dc07a65da266a1256b1da0d17ec97c.
// Licence: Apache-2.0 (see NOTICE).
// Transform: add ".js" to relative import specifiers.
// Do not edit here: it is copied from the upstream package by
// `node scripts/sync-agent-safety.mjs` (`--check` verifies the copy).

// DIVERGES FROM UPSTREAM (firewall audit B1, B2, I5, I10): a "coverage" rule family (files and lines
// the check could not read fully), the full command behind an inventory item (for receipt hashes),
// and the inventory kinds for hooks of other agents and dev-container commands. Upstream should take
// these changes.

/** The shared shapes of the agent-safety check. Pure types: safe in the browser. */

export type AgentSeverity = "critical" | "high" | "medium" | "low";

/** The rule families, as the docs and the result page group them. */
export type AgentRuleFamily =
  | "auto_run" // commands the agent or editor runs on its own: hooks, folder-open tasks, helpers
  | "model_endpoint" // the model endpoint moved to another host
  | "secret_in_config" // a credential written into an agent file
  | "mcp_launch" // how tool servers are launched and reached
  | "hidden_instructions" // text in instruction files a person would not see or would not expect
  | "permissions" // what the agent may do without asking
  | "agent_memory" // notes the agent writes for itself and loads into every session
  | "blast_radius" // broad agent powers next to production credentials
  | "coverage"; // a file or line the check could not read fully (unparseable, oversize, over the work budget)

/** The finding types the Runner API knows, for the ones these rules produce. */
export type AgentFindingType = "hardcoded_secret" | "sensitive_data_exposure" | "security_misconfiguration" | "code_injection" | "privilege_escalation" | "other";

/** One file the check reads: its path in the repository (forward slashes) and its text. */
export interface AgentFile {
  path: string;
  content: string;
}

export interface AgentFinding {
  /** `ls-agent-…`: stable, so a retest can find the same finding again. */
  ruleId: string;
  family: AgentRuleFamily;
  title: string;
  severity: AgentSeverity;
  /** How sure the rule is that this is a real problem (not how bad it is). */
  confidence: "high" | "medium" | "low";
  /** `CWE-123`, or null where no CWE fits honestly. */
  cwe: string | null;
  findingType: AgentFindingType;
  /** Repository path, forward slashes. */
  file: string;
  /** 1-based. */
  line: number;
  /** The line as evidence, with any credential value masked. Never the raw secret. */
  evidence: string;
  /** What could happen, in plain English. */
  impact: string;
  /** The exact change that fixes it. */
  fix: string;
}

/** What starts on its own, or what the agent connects to. */
export type AgentInventoryKind = "hook" | "status_line" | "helper" | "folder_open_task" | "startup_command" | "mcp_local" | "mcp_remote";

/**
 * One thing a file makes run or connect without anyone asking, whether or not
 * a rule flagged it. Not a finding: a formatter hook is normal. It is the
 * honest list of "what runs automatically" a person should know about.
 */
export interface AgentInventoryItem {
  kind: AgentInventoryKind;
  file: string;
  /** 1-based. */
  line: number;
  /** What it is, in words: `PostToolUse hook`, `MCP server "docs"`. */
  label: string;
  /** The command line or address, with any credential masked, at most 200 characters. */
  detail: string;
  /**
   * Hex SHA-256 of the whole command or address as written (whitespace collapsed), so two commands
   * that differ only past the 200 characters shown are still told apart. Never the text itself.
   */
  sha256?: string;
}

/** One agent memory file the check read: listed for review, flagged or not. */
export interface AgentMemoryFile {
  path: string;
  /** Lines of text (a trailing newline does not start another). */
  lines: number;
  /** UTF-8 bytes. */
  bytes: number;
  /** A MEMORY.md index (loaded into every session), or a topic file it or its folder holds. */
  role: "index" | "topic";
}

export interface AgentSeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/** What the public grade may show: counts only, never a file or a finding. */
export interface AgentSafetySummary {
  /** Agent configuration files read (0: the repository has none). */
  filesChecked: number;
  counts: AgentSeverityCounts;
}
