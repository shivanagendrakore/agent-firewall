/**
 * The sandbox policy key, kept apart from policy.ts so it stays one
 * module: `sandbox` (the Claude Code OS sandbox profile `doctor --fix`
 * writes, and whether weakening it is tampering). A project file may only
 * tighten: switch protection of an installed profile on and ask for the strict
 * allowlist. It can never mark excluded commands as safe.
 */

import { DEFAULT_SANDBOX_POLICY, type SandboxPolicy } from "./engine/sandbox.js";
import type { FirewallConfig } from "./types.js";

export const SANDBOX_POLICY_KEYS = ["sandbox"] as const;

export interface SandboxDoc {
  sandbox?: Partial<SandboxPolicy>;
}

export function defaultSandbox(): SandboxPolicy {
  return { ...DEFAULT_SANDBOX_POLICY, safeExcludedCommands: [] };
}

const KEYS = ["protectInstalledProfile", "strictAllowlist", "safeExcludedCommands"] as const;

type Raw = Record<string, unknown>;

/** Validates the key of a (migrated) policy document into `out`. */
export function validateSandboxKeys(raw: Raw, problems: string[], out: SandboxDoc): void {
  if (raw.sandbox === undefined) return;
  const v = raw.sandbox;
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    problems.push('"sandbox" must be an object');
    return;
  }
  const o = v as Raw;
  const res: Partial<SandboxPolicy> = {};
  for (const k of Object.keys(o)) if (!(KEYS as readonly string[]).includes(k)) problems.push(`"sandbox.${k}" is not a known setting (expected one of ${KEYS.join(", ")})`);
  for (const k of ["protectInstalledProfile", "strictAllowlist"] as const) {
    if (o[k] === undefined) continue;
    if (typeof o[k] === "boolean") res[k] = o[k];
    else problems.push(`"sandbox.${k}" must be true or false`);
  }
  if (o.safeExcludedCommands !== undefined) {
    if (Array.isArray(o.safeExcludedCommands) && o.safeExcludedCommands.every((x) => typeof x === "string" && x.trim() !== "")) res.safeExcludedCommands = [...new Set(o.safeExcludedCommands as string[])];
    else problems.push('"sandbox.safeExcludedCommands" must be a list of non-empty strings');
  }
  out.sandbox = res;
}

/** Applies a project file's `sandbox`: tightening only; anything looser is listed in `ignored`. */
export function tightenSandboxKeys(base: FirewallConfig, over: SandboxDoc, cfg: FirewallConfig, ignored: string[]): void {
  const s = over.sandbox;
  if (s === undefined) return;
  const next: Partial<SandboxPolicy> = { ...(base.sandbox ?? {}) };
  if (s.protectInstalledProfile === true) next.protectInstalledProfile = true;
  if (s.strictAllowlist === true) next.strictAllowlist = true;
  cfg.sandbox = next;
  if (s.protectInstalledProfile === false || s.strictAllowlist === false) ignored.push("sandbox settings that switch protections off (only user or managed policy may)");
  if (s.safeExcludedCommands !== undefined && s.safeExcludedCommands.length > 0) ignored.push("sandbox.safeExcludedCommands (a project cannot mark commands as safe to run outside the sandbox)");
}
