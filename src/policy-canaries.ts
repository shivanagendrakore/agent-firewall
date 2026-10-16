/**
 * The decoy files' policy key, kept apart from policy.ts so it stays one
 * module: `canaries` (decoy files planted with `canary plant`). A project
 * file may only tighten it: switch the watch on, make a recursive read trip.
 * `offerAtInstall` and `homeDecoys` steer the install offer and are read only
 * from user and managed policy.
 */

import type { CanaryPolicy, FirewallConfig } from "./types.js";

export const CANARY_POLICY_KEYS = ["canaries"] as const;

export interface CanaryDoc {
  canaries?: Partial<CanaryPolicy>;
}

/** The install offer is on, home-directory decoys are off. */
export function defaultCanaries(): CanaryPolicy {
  return { enabled: true, tripOnRecursive: false, offerAtInstall: true, homeDecoys: false };
}

const CANARY_KEYS = ["enabled", "tripOnRecursive", "offerAtInstall", "homeDecoys"] as const;

type Raw = Record<string, unknown>;

/** Validates the key of a (migrated) policy document into `out`. Unknown sub-keys and non-booleans are errors. */
export function validateCanaryKeys(raw: Raw, problems: string[], out: CanaryDoc): void {
  if (raw.canaries === undefined) return;
  const c = raw.canaries;
  if (typeof c !== "object" || c === null || Array.isArray(c)) {
    problems.push('"canaries" must be an object');
    return;
  }
  const res: Partial<CanaryPolicy> = {};
  for (const [k, v] of Object.entries(c as Raw)) {
    if (!(CANARY_KEYS as readonly string[]).includes(k)) problems.push(`"canaries.${k}" is not a known setting (expected one of ${CANARY_KEYS.join(", ")})`);
    else if (typeof v !== "boolean") problems.push(`"canaries.${k}" must be true or false`);
    else res[k as keyof CanaryPolicy] = v;
  }
  out.canaries = res;
}

/** Applies a project file's `canaries`: tightening only; loosening and install-only keys are listed in `ignored`. */
export function tightenCanaryKeys(over: CanaryDoc, cfg: FirewallConfig, ignored: string[]): void {
  const c = over.canaries ?? {};
  if (c.enabled === true) cfg.canaries.enabled = true;
  if (c.tripOnRecursive === true) cfg.canaries.tripOnRecursive = true;
  if (c.enabled === false || c.tripOnRecursive === false) ignored.push("canaries settings that switch detection off (only user or managed policy may)");
  if (c.offerAtInstall !== undefined || c.homeDecoys !== undefined) ignored.push("canaries.offerAtInstall and canaries.homeDecoys (read only from user or managed policy)");
}
