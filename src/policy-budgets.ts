/**
 * The budgets policy key, kept apart from policy.ts so it stays one
 * module: `budgets` (outbound byte and request budgets, MCP-call budgets,
 * loop detection; defaults in src/engine/budgets.ts). A project file may
 * only lower limits; raising one, switching budgets off or adding exempt
 * hosts is loosening and only user or managed policy may do it.
 */

import { DEFAULT_BUDGETS, type BudgetPolicy } from "./engine/budgets.js";
import type { FirewallConfig } from "./types.js";
import { own, setOwn } from "./own.js";

export const BUDGET_POLICY_KEYS = ["budgets"] as const;

/** A policy file's `budgets`: any subset, nested groups partial too. */
export interface BudgetDoc {
  budgets?: {
    enabled?: boolean;
    untrusted?: Partial<BudgetPolicy["untrusted"]>;
    trusted?: Partial<BudgetPolicy["trusted"]>;
    loop?: Partial<BudgetPolicy["loop"]>;
    exemptHosts?: string[];
    stopScope?: "session" | "agent";
  };
}

export function defaultBudgets(): BudgetPolicy {
  return { enabled: DEFAULT_BUDGETS.enabled, untrusted: { ...DEFAULT_BUDGETS.untrusted }, trusted: { ...DEFAULT_BUDGETS.trusted }, loop: { ...DEFAULT_BUDGETS.loop }, exemptHosts: [...DEFAULT_BUDGETS.exemptHosts] };
}

const GROUPS = { untrusted: ["bytesPerHost", "bytesTotal", "requestsPerHost10m", "mcpCalls10m", "mcpSends10m"], trusted: ["bytesTotal", "requestsPerHost10m", "mcpCalls10m"], loop: ["sameAction10m", "nonAllow10m", "stopNonAllow10m", "stopNewHosts10m", "stopConfigTouches10m", "stopSameFailure10m"] } as const;
const TOP = ["enabled", "untrusted", "trusted", "loop", "exemptHosts", "stopScope"] as const;
const MAX_LIMIT = 1024 * 1024 * 1024;

type Raw = Record<string, unknown>;
type Group = keyof typeof GROUPS;

/** Validates the key of a (migrated) policy document into `out`. Limits are whole numbers from 1. */
export function validateBudgetKeys(raw: Raw, problems: string[], out: BudgetDoc): void {
  if (raw.budgets === undefined) return;
  const v = raw.budgets;
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    problems.push('"budgets" must be an object');
    return;
  }
  const o = v as Raw;
  const res: NonNullable<BudgetDoc["budgets"]> = {};
  for (const k of Object.keys(o)) if (!(TOP as readonly string[]).includes(k)) problems.push(`"budgets.${k}" is not a known setting (expected one of ${TOP.join(", ")})`);
  if (o.enabled !== undefined) {
    if (typeof o.enabled === "boolean") res.enabled = o.enabled;
    else problems.push('"budgets.enabled" must be true or false');
  }
  for (const g of Object.keys(GROUPS) as Group[]) {
    if (o[g] === undefined) continue;
    const gv = o[g];
    if (typeof gv !== "object" || gv === null || Array.isArray(gv)) {
      problems.push(`"budgets.${g}" must be an object`);
      continue;
    }
    const keys: readonly string[] = GROUPS[g];
    const vals: Record<string, number> = {};
    for (const [k, n] of Object.entries(gv as Raw)) {
      if (!keys.includes(k)) problems.push(`"budgets.${g}.${k}" is not a known setting (expected one of ${keys.join(", ")})`);
      else if (typeof n !== "number" || !Number.isInteger(n) || n < 1 || n > MAX_LIMIT) problems.push(`"budgets.${g}.${k}" must be a whole number from 1 to ${MAX_LIMIT}`);
      else setOwn(vals, k, n);
    }
    (res as Record<string, unknown>)[g] = vals;
  }
  if (o.exemptHosts !== undefined) {
    const h = o.exemptHosts;
    if (!Array.isArray(h) || !h.every((x) => typeof x === "string" && x.trim() !== "")) problems.push('"budgets.exemptHosts" must be a list of non-empty strings');
    else res.exemptHosts = h as string[];
  }
  if (o.stopScope !== undefined) {
    if (o.stopScope === "session" || o.stopScope === "agent") res.stopScope = o.stopScope;
    else problems.push('"budgets.stopScope" must be "session" or "agent"');
  }
  out.budgets = res;
}

/** The user's (or an administrator's) `budgets` over the defaults: any direction, group by group. */
export function mergeBudgets(base: BudgetPolicy, over: BudgetDoc["budgets"]): BudgetPolicy {
  if (over === undefined) return base;
  return {
    enabled: over.enabled ?? base.enabled,
    untrusted: { ...base.untrusted, ...(over.untrusted ?? {}) },
    trusted: { ...base.trusted, ...(over.trusted ?? {}) },
    loop: { ...base.loop, ...(over.loop ?? {}) },
    exemptHosts: over.exemptHosts ?? base.exemptHosts,
    ...((over.stopScope ?? base.stopScope) !== undefined ? { stopScope: over.stopScope ?? base.stopScope } : {}),
  };
}

/** Applies a project file's `budgets`: lower limits only; anything looser is listed in `ignored`. */
export function tightenBudgetKeys(base: FirewallConfig, over: BudgetDoc, cfg: FirewallConfig, ignored: string[]): void {
  const o = over.budgets;
  if (o === undefined) return;
  const b = base.budgets ?? defaultBudgets();
  const v: BudgetPolicy = { enabled: b.enabled, untrusted: { ...b.untrusted }, trusted: { ...b.trusted }, loop: { ...b.loop }, exemptHosts: [...b.exemptHosts], ...(b.stopScope !== undefined ? { stopScope: b.stopScope } : {}) };
  const raised: string[] = [];
  const floored: string[] = [];
  if (o.enabled === true) v.enabled = true;
  else if (o.enabled === false && b.enabled) raised.push("budgets.enabled");
  for (const g of Object.keys(GROUPS) as Group[]) {
    const gv = (o[g] ?? {}) as Record<string, number>;
    const target = v[g] as Record<string, number>;
    for (const [k, n] of Object.entries(gv)) {
      const cur = own(target, k);
      if (cur === undefined) continue;
      if (n > cur) {
        raised.push(`budgets.${g}.${k}`);
        continue;
      }
      // Hostile content can drive an agent into the monitor on purpose; a repository may not make that trivially
      // easy, so it cannot set a stop limit below half its default.
      const floor = g === "loop" && k.startsWith("stop") ? Math.min(cur, Math.ceil((own(DEFAULT_BUDGETS.loop as unknown as Record<string, number>, k) ?? 1) / 2)) : 1;
      if (n < floor) floored.push(`budgets.${g}.${k} (raised to ${floor})`);
      setOwn(target, k, Math.max(n, floor));
    }
  }
  if (o.exemptHosts !== undefined && o.exemptHosts.length > 0) raised.push("budgets.exemptHosts");
  cfg.budgets = v;
  // An agent-wide stop halts every session of the agent, in every repository: a repository that could ask for it
  // could let its own content stop the person's other work. So the scope is user or managed policy only.
  if (o.stopScope !== undefined) ignored.push("budgets.stopScope (where a behaviour monitor stop applies is user or managed policy only; a project's value is ignored)");
  if (floored.length > 0) ignored.push(`${floored.join(", ")} (a project may not set a behaviour monitor stop limit below half its default)`);
  if (raised.length > 0) ignored.push(`${raised.join(", ")} (a project may only lower budgets; raising one, switching budgets off or exempting hosts is user or managed policy only)`);
}
