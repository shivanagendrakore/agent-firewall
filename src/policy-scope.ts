/**
 * The task scope's policy key, kept apart from policy.ts so it stays one
 * module: `taskScope`. The scope ships log-only first
 * (mode "log": compute and log what it would ask, change no decision);
 * "enforce" is implemented and tested but not the default. A project file
 * may only move the mode toward enforce and switch the unattended intent
 * rules on.
 */

import { SCOPE_MODES, type ScopeMode, type TaskScopePolicy } from "./engine/scope.js";
import type { FirewallConfig } from "./types.js";

export { defaultTaskScope } from "./engine/scope.js";

export const SCOPE_POLICY_KEYS = ["taskScope"] as const;

export interface ScopeDoc {
  taskScope?: Partial<TaskScopePolicy>;
}

type Raw = Record<string, unknown>;

const RANK: Record<ScopeMode, number> = { off: 0, log: 1, enforce: 2 };

/** Validates `taskScope` of a (migrated) policy document into `out`. Unknown sub-keys and bad values are errors. */
export function validateScopeKeys(raw: Raw, problems: string[], out: ScopeDoc): void {
  if (raw.taskScope === undefined) return;
  const t = raw.taskScope;
  if (typeof t !== "object" || t === null || Array.isArray(t)) {
    problems.push('"taskScope" must be an object');
    return;
  }
  const res: Partial<TaskScopePolicy> = {};
  for (const [k, v] of Object.entries(t as Raw)) {
    if (k === "mode") {
      if (typeof v !== "string" || !(SCOPE_MODES as readonly string[]).includes(v)) problems.push(`"taskScope.mode" must be one of ${SCOPE_MODES.map((m) => `"${m}"`).join(", ")}`);
      else res.mode = v as ScopeMode;
    } else if (k === "unattendedIntents") {
      if (typeof v !== "boolean") problems.push('"taskScope.unattendedIntents" must be true or false');
      else res.unattendedIntents = v;
    } else problems.push(`"taskScope.${k}" is not a known setting (expected one of mode, unattendedIntents)`);
  }
  out.taskScope = res;
}

/** Applies a project file's `taskScope`: toward enforce only; loosening is listed in `ignored`. */
export function tightenScopeKeys(base: FirewallConfig, over: ScopeDoc, cfg: FirewallConfig, ignored: string[]): void {
  const t = over.taskScope;
  if (t === undefined) return;
  const current = { ...base.taskScope };
  if (t.mode !== undefined) {
    if (RANK[t.mode] >= RANK[current.mode]) current.mode = t.mode;
    else ignored.push(`taskScope.mode "${t.mode}" (a project may only move it toward "enforce")`);
  }
  if (t.unattendedIntents === true) current.unattendedIntents = true;
  if (t.unattendedIntents === false) ignored.push("taskScope.unattendedIntents (a project may only turn it on)");
  cfg.taskScope = current;
}
