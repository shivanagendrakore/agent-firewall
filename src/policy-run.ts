/**
 * v0.3 `run`'s policy key, kept apart from policy.ts: `run.allowWritePaths`, the paths a person exempts from
 * the read-only rule `run` puts on scripts the workspace's agent settings run (docs/run.md, RN6: an MCP
 * server started as `node dist/index.js` freezes the build output). Only user or managed policy may set it:
 * a project file (which the agent may have written) may only tighten, so it is ignored there.
 *
 * `run.privateHosts`: admitted host names whose DNS answers may be private addresses (10/8, 172.16/12,
 * 192.168/16, 100.64/10, fc00::/7). Without it the proxy refuses such an answer for any name (DNS
 * rebinding). User or managed policy only, for the same reason.
 */

import type { FirewallConfig } from "./types.js";

export const RUN_POLICY_KEYS = ["run"] as const;

export interface RunPolicy {
  /** Workspace-relative (or absolute) paths whose agent-named scripts stay writable inside `run`. */
  allowWritePaths: string[];
  /** Host patterns (fetchAllowHosts syntax) whose DNS answers may be in private ranges. */
  privateHosts: string[];
}

export interface RunDoc {
  run?: Partial<RunPolicy>;
}

type Raw = Record<string, unknown>;

/** "name.example", "=name.example" (only itself) or "*.name.example" (only subdomains). */
const HOST_PATTERN = /^(?:=|\*\.)?[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)*$/i;

/** Validates the key of a (migrated) policy document into `out`. */
export function validateRunKeys(raw: Raw, problems: string[], out: RunDoc): void {
  if (raw.run === undefined) return;
  const v = raw.run;
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    problems.push('"run" must be an object');
    return;
  }
  const o = v as Raw;
  const res: Partial<RunPolicy> = {};
  for (const k of Object.keys(o)) if (k !== "allowWritePaths" && k !== "privateHosts") problems.push(`"run.${k}" is not a known setting (expected allowWritePaths or privateHosts)`);
  if (o.allowWritePaths !== undefined) {
    if (Array.isArray(o.allowWritePaths) && o.allowWritePaths.every((x) => typeof x === "string" && x.trim() !== "" && !/[\n\r\0]/.test(x))) res.allowWritePaths = [...new Set(o.allowWritePaths as string[])];
    else problems.push('"run.allowWritePaths" must be a list of non-empty paths');
  }
  if (o.privateHosts !== undefined) {
    if (Array.isArray(o.privateHosts) && o.privateHosts.every((x) => typeof x === "string" && HOST_PATTERN.test(x.trim()))) res.privateHosts = [...new Set((o.privateHosts as string[]).map((x) => x.trim().toLowerCase()))];
    else problems.push('"run.privateHosts" must be a list of host names (example.corp, =git.example.corp or *.example.corp)');
  }
  out.run = res;
}

/** A project file's `run`: nothing in it can loosen run's protection, so a non-empty list is ignored. */
export function tightenRunKeys(over: RunDoc, ignored: string[]): void {
  if ((over.run?.allowWritePaths ?? []).length > 0) ignored.push("run.allowWritePaths (only user or managed policy may exempt paths from run's read-only rules)");
  if ((over.run?.privateHosts ?? []).length > 0) ignored.push("run.privateHosts (only user or managed policy may let a host resolve to a private address)");
}

/** The configured exemptions (none by default). */
export function runAllowWritePaths(cfg: FirewallConfig): string[] {
  return cfg.run?.allowWritePaths ?? [];
}

/** Admitted names whose DNS answers may be private addresses (none by default). */
export function runPrivateHosts(cfg: FirewallConfig): string[] {
  return cfg.run?.privateHosts ?? [];
}
