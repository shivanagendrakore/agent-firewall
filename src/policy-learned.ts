/**
 * The `learnedAllows` policy key ("Fewer prompts", docs/usage.md and docs/policy.md), kept apart from
 * policy.ts like the other keys. It only governs the firewall's offer and the use of choices a person
 * made in their own terminal; the choices themselves are never in a policy file (they are signed and
 * kept in the firewall's home, src/runtime/learned.ts). A project file may only tighten: switch learned
 * allows off, or ask for more approvals before the offer.
 */

import type { FirewallConfig } from "./types.js";

export const LEARNED_POLICY_KEYS = ["learnedAllows"] as const;

export interface LearnedAllowsPolicy {
  /** False: no learned allow applies and none is offered ("never" choices still apply: they only tighten). */
  enabled: boolean;
  /** How many approvals of the same action in a project before the firewall offers to stop asking. */
  proposeAfter: number;
}

export interface LearnedDoc {
  learnedAllows?: Partial<LearnedAllowsPolicy>;
}

export const PROPOSE_AFTER_LIMITS = { min: 2, max: 100 } as const;

export function defaultLearned(): LearnedAllowsPolicy {
  return { enabled: true, proposeAfter: 3 };
}

/** The policy in effect (defaults for anything a policy file did not set). */
export function learnedPolicy(cfg: Pick<FirewallConfig, "learnedAllows">): LearnedAllowsPolicy {
  const d = defaultLearned();
  const p = cfg.learnedAllows ?? {};
  return { enabled: p.enabled ?? d.enabled, proposeAfter: p.proposeAfter ?? d.proposeAfter };
}

const KEYS = ["enabled", "proposeAfter"] as const;

type Raw = Record<string, unknown>;

/** Validates the key of a (migrated) policy document into `out`. Any other field (a list of allows) is an error. */
export function validateLearnedKeys(raw: Raw, problems: string[], out: LearnedDoc): void {
  if (raw.learnedAllows === undefined) return;
  const v = raw.learnedAllows;
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    problems.push('"learnedAllows" must be an object');
    return;
  }
  const o = v as Raw;
  const res: Partial<LearnedAllowsPolicy> = {};
  for (const k of Object.keys(o)) if (!(KEYS as readonly string[]).includes(k)) problems.push(`"learnedAllows.${k}" is not a known setting (expected one of ${KEYS.join(", ")}; the allows themselves are never in a policy file: launchsafe-firewall allow list)`);
  if (o.enabled !== undefined) {
    if (typeof o.enabled === "boolean") res.enabled = o.enabled;
    else problems.push('"learnedAllows.enabled" must be true or false');
  }
  if (o.proposeAfter !== undefined) {
    const n = o.proposeAfter;
    if (typeof n !== "number" || !Number.isInteger(n) || n < PROPOSE_AFTER_LIMITS.min || n > PROPOSE_AFTER_LIMITS.max) problems.push(`"learnedAllows.proposeAfter" must be a whole number from ${PROPOSE_AFTER_LIMITS.min} to ${PROPOSE_AFTER_LIMITS.max}`);
    else res.proposeAfter = n;
  }
  out.learnedAllows = res;
}

/** The user's (or an administrator's) setting over the layer below. */
export function mergeLearned(base: FirewallConfig["learnedAllows"], over: LearnedDoc["learnedAllows"]): FirewallConfig["learnedAllows"] {
  if (base === undefined && over === undefined) return undefined;
  return { ...(base ?? {}), ...(over ?? {}) };
}

/** Applies a project file's setting: tightening only; anything looser is listed in `ignored`. */
export function tightenLearnedKeys(base: FirewallConfig, over: LearnedDoc, cfg: FirewallConfig, ignored: string[]): void {
  const v = over.learnedAllows;
  if (v === undefined) return;
  const cur = learnedPolicy(base);
  const next: Partial<LearnedAllowsPolicy> = { ...(base.learnedAllows ?? {}) };
  if (v.enabled === false) next.enabled = false;
  if (v.enabled === true && !cur.enabled) ignored.push("learnedAllows.enabled (a repository cannot turn learned allows on)");
  if (v.proposeAfter !== undefined) {
    if (v.proposeAfter >= cur.proposeAfter) next.proposeAfter = v.proposeAfter;
    else ignored.push("learnedAllows.proposeAfter (a project may only raise it)");
  }
  cfg.learnedAllows = next;
}
