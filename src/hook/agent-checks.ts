/**
 * The agent-safety hook points, kept out of claude.ts: the session-start check (agent
 * configuration scan, drift, MCP configuration pins), its inline fallback for
 * a session whose first tool call arrives without one, the pin check for an
 * MCP tool call, and the description pins fed by ToolSearch results.
 */

import { homedir } from "node:os";
import { join } from "node:path";
import type { FirewallConfig, StateEvent } from "../types.js";
import { FALLBACK_BUDGET_MS, runSessionScan, scanWorkspace, SESSION_START_BUDGET_MS, type SessionScan } from "../runtime/agentscan.js";
import { MANAGED_SETTINGS_PATHS, readRecords } from "../runtime/install.js";
import { agentMcpServers, type McpAgent } from "../runtime/agent-mcp.js";
import type { ConfiguredServer } from "../runtime/agentfiles.js";
import type { AgentId } from "../adapters/types.js";
import { vaultContext } from "./vault.js";
import type { Layout } from "../runtime/layout.js";
import { appendBounded as appendLog } from "../runtime/logbound.js";
import { unwrapGatewayEntry } from "../gateway/install.js";
import { appendEvents } from "../runtime/store.js";
import { collectAgentFiles } from "../runtime/agentfiles.js";
import { extractToolDefinitions, observeDefinitions, sessionStartPins, toolCallPins, type PinOutcome, type ToolCallPin } from "../runtime/pins.js";

export { FALLBACK_BUDGET_MS, SESSION_START_BUDGET_MS };

const MANAGED_MCP: Record<string, string> = {
  darwin: "/Library/Application Support/ClaudeCode/managed-mcp.json",
  linux: "/etc/claude-code/managed-mcp.json",
};

export interface CheckEnv {
  env: NodeJS.ProcessEnv;
  home?: string | undefined;
  now?: Date | undefined;
  /** The agent whose session this is (default Claude Code). */
  agent?: AgentId | undefined;
}

/**
 * The other agents whose MCP configuration the session-start comparison reads: every agent the
 * firewall is installed for (install records), and this session's own agent.
 */
function mcpAgents(l: Layout, agent: AgentId | undefined): McpAgent[] {
  const out = new Set<McpAgent>();
  try {
    for (const r of readRecords(l)) if (r.agent !== undefined && r.agent !== "claude") out.add(r.agent);
  } catch {
    // An unreadable install record: doctor reports it; this session's own agent is still read.
  }
  if (agent !== undefined && agent !== "claude") out.add(agent);
  return [...out];
}

/**
 * Every agent's MCP servers for the pin comparison, and which of them this session does not load:
 * Claude Code's are compared in every session (as in v0.2; Cursor also imports Claude Code's
 * configuration), another agent's only taint that agent's sessions.
 */
function startServers(l: Layout, claude: readonly ConfiguredServer[], workspace: string | null, home: string, e: CheckEnv): { servers: ConfiguredServer[]; quiet: (s: ConfiguredServer) => boolean } {
  const agent = e.agent ?? "claude";
  const others = agentMcpServers({ agents: mcpAgents(l, e.agent), workspace, home, env: e.env });
  // A server the gateway wrapped is compared as it was before (the wrapper is not a change).
  const all = [...claude, ...others].map((s) => ({ ...s, config: unwrapGatewayEntry(l, s.config) }));
  return { servers: all, quiet: (s) => s.agent !== undefined && s.agent !== agent };
}


export interface StartResult {
  events: StateEvent[];
  /** For the agent (SessionStart additionalContext). */
  context: string | null;
  /** For the person (systemMessage and stderr). */
  message: string | null;
  scan: SessionScan;
  pins: PinOutcome;
}

function joinReasons(reasons: readonly string[]): string {
  const shown = reasons.slice(0, 3).join("; ");
  return reasons.length > 3 ? `${shown}; and ${reasons.length - 3} more` : shown;
}

/**
 * Runs the session-start check and returns the events to record (the caller appends them with the
 * agent_scan marker). Never throws.
 */
export function startChecks(l: Layout, cfg: FirewallConfig, projectDir: string, sessionId: string, e: CheckEnv, budgetMs: number): StartResult {
  const home = e.home ?? homedir();
  const now = e.now ?? new Date();
  // CLAUDE_CONFIG_DIR moves Claude Code's user directory and its global config file [verify the latter]. An
  // injected home (tests, the scenario harness) wins over the variable.
  const custom = e.env.CLAUDE_CONFIG_DIR !== undefined && e.env.CLAUDE_CONFIG_DIR !== "" && e.home === undefined ? e.env.CLAUDE_CONFIG_DIR : null;
  const configDir = custom ?? join(home, ".claude");
  const claudeJson = custom !== null ? join(custom, ".claude.json") : undefined;
  const workspace = scanWorkspace(projectDir, home);
  const scan = runSessionScan({ l, workspace, home, configDir, claudeJson, cfg, budgetMs, now, managedSettings: MANAGED_SETTINGS_PATHS[process.platform], managedMcp: MANAGED_MCP[process.platform] });
  let pins: PinOutcome = { events: [], alerts: [], log: [] };
  try {
    const { servers, quiet } = startServers(l, scan.servers, workspace, home, e);
    pins = sessionStartPins(l, servers, cfg, now, { quiet });
  } catch (err) {
    pins = { events: [{ type: "taint", source: `MCP servers could not be compared with their pins (${(err as Error).message.slice(0, 120)})` }], alerts: [], log: [] };
  }
  const events: StateEvent[] = [...scan.events, ...pins.events];
  const reasons = [...scan.untrustedBecause, ...pins.events.filter((x): x is Extract<StateEvent, { type: "taint" }> => x.type === "taint").map((x) => x.source)];
  try {
    // A clean, complete scan is not logged (it would cost a signed, fsynced entry per session for nothing).
    if (reasons.length > 0 || scan.rules.length > 0 || scan.logged.length > 0 || scan.incomplete.length > 0) {
      appendLog(l, { type: "agent_scan", session: sessionId, untrusted: reasons.slice(0, 10), rules: scan.rules, logged: scan.logged.slice(0, 20), incomplete: scan.incomplete, cached: scan.cached, ms: Math.round(scan.ms) });
    }
    for (const entry of pins.log) appendLog(l, { ...entry, session: sessionId });
  } catch {
    // The log is best effort here; the state events carry the decision.
  }
  let context: string | null = null;
  let message: string | null = null;
  if (reasons.length > 0) {
    context = `LaunchSafe Firewall: this session starts untrusted because ${joinReasons(reasons)}. Sending data off the machine, sending messages, changing the agent's instructions, memory or settings, and reading credentials need the person's approval. If an action is blocked, tell the user the exact queue command from the message; do not try to work around the block.`;
    message = `LaunchSafe Firewall: this session starts untrusted: ${joinReasons(reasons)}.${pins.alerts.length > 0 ? ` ${pins.alerts.join(" ")}` : ""} Run "launchsafe-firewall doctor" for details.`;
  } else if (pins.alerts.length > 0) message = `LaunchSafe Firewall: ${pins.alerts.join(" ")}`;
  // The references the agent may use, and where (names and destinations only).
  try {
    const v = vaultContext(l, cfg, e.env);
    if (v !== null) context = context === null ? v : `${context}\n${v}`;
  } catch {
    // The listing is a convenience; without it the references still work.
  }
  // An incomplete scan (time or size caps) is logged and shown by doctor, not announced every session.
  return { events, context, message, scan, pins };
}

/**
 * R12: the MCP configuration comparison alone, for a session that was already scanned (resume, clear,
 * compact). The agent starts the servers again from their current configuration, so a server whose
 * launch line changed since the pin taints the session whatever the source. Cheap: only the server
 * lists are read (Claude Code's and every installed agent's), and sessionStartPins has a no-write fast
 * path. Never throws.
 */
export function resumePins(l: Layout, cfg: FirewallConfig, projectDir: string, sessionId: string, e: CheckEnv): PinOutcome {
  let pins: PinOutcome = { events: [], alerts: [], log: [] };
  try {
    const home = e.home ?? homedir();
    const custom = e.env.CLAUDE_CONFIG_DIR !== undefined && e.env.CLAUDE_CONFIG_DIR !== "" && e.home === undefined ? e.env.CLAUDE_CONFIG_DIR : null;
    const configDir = custom ?? join(home, ".claude");
    const workspace = scanWorkspace(projectDir, home);
    const claude = collectAgentFiles({ workspace, home, configDir, ...(custom !== null ? { claudeJson: join(custom, ".claude.json") } : {}), userScope: false, serversOnly: true, managedMcp: MANAGED_MCP[process.platform], budgetMs: SESSION_START_BUDGET_MS }).servers;
    const { servers, quiet } = startServers(l, claude, workspace, home, e);
    pins = sessionStartPins(l, servers, cfg, e.now ?? new Date(), { quiet });
  } catch (err) {
    pins = { events: [{ type: "taint", source: `MCP servers could not be compared with their pins (${(err as Error).message.slice(0, 120)})` }], alerts: [], log: [] };
  }
  try {
    for (const entry of pins.log) appendLog(l, { ...entry, session: sessionId });
  } catch {
    // Best effort.
  }
  appendEvents(l, sessionId, pins.events);
  return pins;
}

/**
 * Runs the session-start check and records its events with the agent_scan marker, so it runs once per
 * session. `fallback`: run inline before a session's first tool call (no SessionStart was seen); if
 * the time budget runs out there, the session is treated as untrusted rather than left half-checked.
 * Never throws: a failure is recorded as a taint.
 */
export function recordStart(l: Layout, cfg: FirewallConfig, projectDir: string, sessionId: string, e: CheckEnv, budgetMs: number, fallback: boolean): StartResult {
  let r: StartResult;
  try {
    r = startChecks(l, cfg, projectDir, sessionId, e, budgetMs);
    if (fallback && r.scan.incomplete.includes("the time budget ran out") && cfg.agentScan.enabled) {
      const source = "the agent's configuration could not be fully checked before the session's first action (no SessionStart check ran)";
      r.events.push({ type: "taint", source });
      r.message = `LaunchSafe Firewall: this session is untrusted: ${source}.`;
    } else if (r.scan.incomplete.length > 0 && cfg.agentScan.enabled && !r.events.some((x) => x.type === "taint")) {
      // I7: an incomplete check (time, file, byte or directory caps) left agent files unread: the session starts
      // untrusted instead of being treated as checked.
      const source = `the agent's configuration could not be fully checked (${r.scan.incomplete.join("; ").slice(0, 200)})`;
      r.events.push({ type: "taint", source });
      r.scan.untrustedBecause.push(source);
      r.message = `LaunchSafe Firewall: this session starts untrusted: ${source}. Run "launchsafe-firewall doctor" for details.`;
      if (r.context === null) r.context = `LaunchSafe Firewall: this session starts untrusted because ${source}.`;
    }
  } catch (err) {
    const source = `agent configuration could not be checked (${(err as Error).message.slice(0, 120)})`;
    r = { events: [{ type: "taint", source }], context: `LaunchSafe Firewall: this session starts untrusted because ${source}.`, message: `LaunchSafe Firewall: this session starts untrusted: ${source}.`, scan: { events: [], untrustedBecause: [source], logged: [], rules: [], incomplete: [], servers: [], cached: false, ms: 0 }, pins: { events: [], alerts: [], log: [] } };
  }
  const marker: StateEvent = { type: "agent_scan", rules: r.scan.rules, incomplete: r.scan.incomplete.length > 0 };
  r.events.push(marker);
  appendEvents(l, sessionId, r.events);
  return r;
}

/** The pin check for an MCP tool call. Never throws (a failure is a taint, not a crash of the decision). */
export function callChecks(l: Layout, cfg: FirewallConfig, server: string, tool: string, source: string | undefined, sessionId: string, now: Date): ToolCallPin {
  let r: ToolCallPin;
  try {
    r = toolCallPins(l, server, tool, source, cfg, now);
  } catch (err) {
    r = { events: [{ type: "taint", source: `MCP pins could not be checked (${(err as Error).message.slice(0, 120)})` }], alerts: [], log: [], forceUntrusted: true, rule: null, reason: null };
  }
  try {
    for (const entry of r.log) appendLog(l, { ...entry, session: sessionId });
  } catch {
    // Best effort.
  }
  return r;
}

/** Tool definitions in a ToolSearch result: description pins. Never throws. */
export function definitionChecks(l: Layout, cfg: FirewallConfig, tool: string, response: unknown, sessionId: string, now: Date): PinOutcome {
  if (tool !== "ToolSearch") return { events: [], alerts: [], log: [] };
  let r: PinOutcome;
  try {
    r = observeDefinitions(l, extractToolDefinitions(response), cfg, now);
  } catch (err) {
    r = { events: [{ type: "taint", source: `MCP tool descriptions could not be checked (${(err as Error).message.slice(0, 120)})` }], alerts: [], log: [] };
  }
  try {
    for (const entry of r.log) appendLog(l, { ...entry, session: sessionId });
  } catch {
    // Best effort.
  }
  return r;
}
