/**
 * The spending-limits policy key, kept apart from policy.ts so it stays one module: `caps` (limits per
 * session and per day that stop the agent; defaults and meaning in src/engine/caps.ts). A project file
 * may only lower a cap, set one that had no limit, lower `warnPercent`, or ask instead of noting. Raising
 * a cap, removing one, switching caps off or warning later is user or managed policy only, and a person
 * raises a cap for now with `launchsafe-firewall caps raise`, never through a file in the repository.
 */

import { CAP_METRICS, DEFAULT_CAPS, type CapLimits, type CapPolicy } from "./engine/caps.js";
import type { FirewallConfig } from "./types.js";
import { own, setOwn } from "./own.js";

export const CAP_POLICY_KEYS = ["caps"] as const;

export interface CapDoc {
  caps?: {
    enabled?: boolean;
    warnPercent?: number;
    warn?: "ask" | "note";
    session?: Partial<CapLimits>;
    day?: Partial<CapLimits>;
  };
}

export function defaultCaps(): CapPolicy {
  return { enabled: DEFAULT_CAPS.enabled, warnPercent: DEFAULT_CAPS.warnPercent, warn: DEFAULT_CAPS.warn, session: { ...DEFAULT_CAPS.session }, day: { ...DEFAULT_CAPS.day } };
}

const TOP = ["enabled", "warnPercent", "warn", "session", "day"] as const;

/**
 * The lowest cap a project file may set. A repository is untrusted content: without a floor, a cloned
 * repository could set every cap to 1 and stop the agent at its first call (a denial of service on the
 * person's own work). User and managed policy may set any value.
 */
export const PROJECT_CAP_FLOOR: Readonly<Record<string, number>> = Object.freeze({ toolCalls: 100, bytesOut: 65536, identicalFailures: 3, tokens: 10000, costUsd: 0.1 });
const MAX_LIMIT = 1e12;

type Raw = Record<string, unknown>;

/** Validates `caps` into `out`. A limit is a whole number from 1 (costUsd: a number above 0, in US dollars), or null for no limit. */
export function validateCapKeys(raw: Raw, problems: string[], out: CapDoc): void {
  if (raw.caps === undefined) return;
  const v = raw.caps;
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    problems.push('"caps" must be an object');
    return;
  }
  const o = v as Raw;
  const res: NonNullable<CapDoc["caps"]> = {};
  for (const k of Object.keys(o)) if (!(TOP as readonly string[]).includes(k)) problems.push(`"caps.${k}" is not a known setting (expected one of ${TOP.join(", ")})`);
  if (o.enabled !== undefined) {
    if (typeof o.enabled === "boolean") res.enabled = o.enabled;
    else problems.push('"caps.enabled" must be true or false');
  }
  if (o.warnPercent !== undefined) {
    if (typeof o.warnPercent === "number" && Number.isInteger(o.warnPercent) && o.warnPercent >= 1 && o.warnPercent <= 99) res.warnPercent = o.warnPercent;
    else problems.push('"caps.warnPercent" must be a whole number from 1 to 99');
  }
  if (o.warn !== undefined) {
    if (o.warn === "ask" || o.warn === "note") res.warn = o.warn;
    else problems.push('"caps.warn" must be "ask" or "note"');
  }
  for (const g of ["session", "day"] as const) {
    if (o[g] === undefined) continue;
    const gv = o[g];
    if (typeof gv !== "object" || gv === null || Array.isArray(gv)) {
      problems.push(`"caps.${g}" must be an object`);
      continue;
    }
    const vals: Record<string, number | null> = {};
    for (const [k, n] of Object.entries(gv as Raw)) {
      if (!(CAP_METRICS as readonly string[]).includes(k)) problems.push(`"caps.${g}.${k}" is not a known setting (expected one of ${CAP_METRICS.join(", ")})`);
      else if (n === null) setOwn(vals, k, null);
      else if (k === "costUsd" ? typeof n === "number" && Number.isFinite(n) && n > 0 && n <= MAX_LIMIT : typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= MAX_LIMIT) setOwn(vals, k, n as number);
      else problems.push(`"caps.${g}.${k}" must be ${k === "costUsd" ? "a number of US dollars above 0" : "a whole number from 1"}, or null for no limit`);
    }
    res[g] = vals as Partial<CapLimits>;
  }
  out.caps = res;
}

/** The user's (or an administrator's) `caps` over the defaults: any direction. */
export function mergeCaps(base: CapPolicy | undefined, over: CapDoc["caps"]): CapPolicy {
  const b = base ?? defaultCaps();
  if (over === undefined) return b;
  return {
    enabled: over.enabled ?? b.enabled,
    warnPercent: over.warnPercent ?? b.warnPercent,
    warn: over.warn ?? b.warn,
    session: { ...b.session, ...(over.session ?? {}) },
    day: { ...b.day, ...(over.day ?? {}) },
  };
}

/** Applies a project file's `caps`: stricter only; anything looser is listed in `ignored`. */
export function tightenCapKeys(base: FirewallConfig, over: CapDoc, cfg: FirewallConfig, ignored: string[]): void {
  const o = over.caps;
  if (o === undefined) return;
  const b = base.caps ?? defaultCaps();
  const v: CapPolicy = { enabled: b.enabled, warnPercent: b.warnPercent, warn: b.warn, session: { ...b.session }, day: { ...b.day } };
  const looser: string[] = [];
  const floored: string[] = [];
  if (o.enabled === true) v.enabled = true;
  else if (o.enabled === false && b.enabled) looser.push("caps.enabled");
  if (o.warnPercent !== undefined) {
    if (o.warnPercent <= b.warnPercent) v.warnPercent = o.warnPercent;
    else looser.push("caps.warnPercent");
  }
  if (o.warn === "ask") v.warn = "ask";
  else if (o.warn === "note" && b.warn === "ask") looser.push("caps.warn");
  for (const g of ["session", "day"] as const) {
    const target = v[g] as Record<string, number | null>;
    for (const [k, n] of Object.entries(o[g] ?? {})) {
      const cur = own(target, k);
      if (cur === undefined || n === undefined) continue;
      // A limit where there was none, or a lower one, is stricter; no limit, or a higher one, is not.
      if (n !== null && (cur === null || n <= cur)) {
        const floor = own(PROJECT_CAP_FLOOR, k) ?? 0;
        // Never above what the user set, never below the floor.
        const v2 = n < floor ? Math.min(floor, cur ?? floor) : n;
        if (v2 !== n) floored.push(`caps.${g}.${k} (${n}, set to ${v2})`);
        setOwn(target, k, v2);
      } else if (n !== cur) looser.push(`caps.${g}.${k}`);
    }
  }
  cfg.caps = v;
  if (floored.length > 0) ignored.push(`${floored.join(", ")} (a project may not set a spending limit below its minimum: ${Object.entries(PROJECT_CAP_FLOOR).map(([k, v]) => `${k} ${v}`).join(", ")})`);
  if (looser.length > 0) ignored.push(`${looser.join(", ")} (a project may only lower spending limits; raising or removing one, switching them off or warning later is user or managed policy only, and a person raises one for now with launchsafe-firewall caps raise)`);
}
