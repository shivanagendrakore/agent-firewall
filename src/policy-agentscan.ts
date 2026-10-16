/**
 * The agent-configuration scan's policy keys, kept apart from policy.ts so it stays one
 * module: `agentScan` (the SessionStart scan of the files that program the
 * agent) and `mcpPinning` (MCP configuration, tool-name and tool-description
 * pins). A project file may only tighten them: switch them on, taint on more
 * findings, shorten the grace window.
 */

import type { AgentScanPolicy, FirewallConfig, McpPinningPolicy } from "./types.js";
import { own } from "./own.js";

export const AGENT_SCAN_KEYS = ["agentScan", "mcpPinning"] as const;

export interface AgentScanDoc {
  agentScan?: Partial<AgentScanPolicy>;
  mcpPinning?: Partial<McpPinningPolicy>;
}

export function defaultAgentScan(): AgentScanPolicy {
  return { enabled: true, taintOn: "high", userScope: true };
}

export function defaultMcpPinning(): McpPinningPolicy {
  return { enabled: true, newToolGraceHours: 24, taintOnChange: true };
}

const TAINT_ON = ["critical", "high", "never"] as const;
/** How many findings each taintOn value taints on: a larger number is stricter. */
const STRICTNESS: Record<AgentScanPolicy["taintOn"], number> = { never: 0, critical: 1, high: 2 };
const MAX_GRACE_HOURS = 24 * 30;

type Raw = Record<string, unknown>;

function object(v: unknown, key: string, allowed: readonly string[], problems: string[]): Raw | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    problems.push(`"${key}" must be an object`);
    return null;
  }
  const o = v as Raw;
  for (const k of Object.keys(o)) if (!allowed.includes(k)) problems.push(`"${key}.${k}" is not a known setting (expected one of ${allowed.join(", ")})`);
  return o;
}

function bool(o: Raw, key: string, k: string, problems: string[]): boolean | undefined {
  const v = own(o, k);
  if (v === undefined) return undefined;
  if (typeof v !== "boolean") {
    problems.push(`"${key}.${k}" must be true or false`);
    return undefined;
  }
  return v;
}

/** Validates the two keys of a (migrated) policy document into `out`. */
export function validateAgentScanKeys(raw: Raw, problems: string[], out: AgentScanDoc): void {
  if (raw.agentScan !== undefined) {
    const o = object(raw.agentScan, "agentScan", ["enabled", "taintOn", "userScope"], problems);
    if (o !== null) {
      const res: Partial<AgentScanPolicy> = {};
      const enabled = bool(o, "agentScan", "enabled", problems);
      if (enabled !== undefined) res.enabled = enabled;
      const userScope = bool(o, "agentScan", "userScope", problems);
      if (userScope !== undefined) res.userScope = userScope;
      if (o.taintOn !== undefined) {
        if (typeof o.taintOn === "string" && (TAINT_ON as readonly string[]).includes(o.taintOn)) res.taintOn = o.taintOn as AgentScanPolicy["taintOn"];
        else problems.push(`"agentScan.taintOn" must be one of ${TAINT_ON.join(", ")}`);
      }
      out.agentScan = res;
    }
  }
  if (raw.mcpPinning !== undefined) {
    const o = object(raw.mcpPinning, "mcpPinning", ["enabled", "newToolGraceHours", "taintOnChange"], problems);
    if (o !== null) {
      const res: Partial<McpPinningPolicy> = {};
      const enabled = bool(o, "mcpPinning", "enabled", problems);
      if (enabled !== undefined) res.enabled = enabled;
      const taintOnChange = bool(o, "mcpPinning", "taintOnChange", problems);
      if (taintOnChange !== undefined) res.taintOnChange = taintOnChange;
      if (o.newToolGraceHours !== undefined) {
        const n = o.newToolGraceHours;
        if (typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= MAX_GRACE_HOURS) res.newToolGraceHours = n;
        else problems.push(`"mcpPinning.newToolGraceHours" must be a whole number from 0 to ${MAX_GRACE_HOURS}`);
      }
      out.mcpPinning = res;
    }
  }
}

/** Applies a project file's values for the two keys: tightening only; loosening is listed in `ignored`. */
export function tightenAgentScanKeys(base: FirewallConfig, over: AgentScanDoc, cfg: FirewallConfig, ignored: string[]): void {
  const a = over.agentScan ?? {};
  if (a.enabled === true) cfg.agentScan.enabled = true;
  if (a.enabled === false) ignored.push("agentScan.enabled (a project may only turn it on)");
  if (a.userScope === true) cfg.agentScan.userScope = true;
  if (a.userScope === false) ignored.push("agentScan.userScope (a project may only turn it on)");
  if (a.taintOn !== undefined) {
    if (STRICTNESS[a.taintOn] >= STRICTNESS[base.agentScan.taintOn]) cfg.agentScan.taintOn = a.taintOn;
    else ignored.push(`agentScan.taintOn "${a.taintOn}" (a project may only taint on more findings)`);
  }
  const m = over.mcpPinning ?? {};
  if (m.enabled === true) cfg.mcpPinning.enabled = true;
  if (m.enabled === false) ignored.push("mcpPinning.enabled (a project may only turn it on)");
  if (m.taintOnChange === true) cfg.mcpPinning.taintOnChange = true;
  if (m.taintOnChange === false) ignored.push("mcpPinning.taintOnChange (a project may only turn it on)");
  if (m.newToolGraceHours !== undefined) {
    if (m.newToolGraceHours <= base.mcpPinning.newToolGraceHours) cfg.mcpPinning.newToolGraceHours = m.newToolGraceHours;
    else ignored.push("mcpPinning.newToolGraceHours (a project may only shorten it)");
  }
}
