/**
 * The persistence checks' policy key, kept apart from policy.ts so it stays one
 * module: `persistence` (content checks for CI, git-hook, editor-task,
 * dev-container and environment-hook files; which of them an untrusted
 * session's writes are held as proposals for). A project file may only
 * tighten it: switch the content checks on, add tags to hold.
 */

import { PERSIST_TAGS, type PersistTag } from "./engine/paths.js";
import type { FirewallConfig } from "./types.js";

export const PERSISTENCE_POLICY_KEYS = ["persistence"] as const;

export interface PersistencePolicy {
  /** In a trusted session, ask when a change adds a code-running capability (FW-AUTORUN). false: v0.1 behaviour. */
  trustedContentChecks: boolean;
  /** Tags whose writes an untrusted session makes are held as proposals (FW-PERSISTENCE-HELD). */
  holdWhenUntrusted: PersistTag[];
}

export interface PersistenceDoc {
  persistence?: Partial<PersistencePolicy>;
}

export function defaultPersistence(): PersistencePolicy {
  return { trustedContentChecks: true, holdWhenUntrusted: ["git-hook", "editor-task", "devcontainer"] };
}

const KEYS = ["trustedContentChecks", "holdWhenUntrusted"] as const;

type Raw = Record<string, unknown>;

/** Validates the key of a (migrated) policy document into `out`. Unknown sub-keys and unknown tags are errors. */
export function validatePersistenceKeys(raw: Raw, problems: string[], out: PersistenceDoc): void {
  if (raw.persistence === undefined) return;
  const v = raw.persistence;
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    problems.push('"persistence" must be an object');
    return;
  }
  const o = v as Raw;
  const res: Partial<PersistencePolicy> = {};
  for (const k of Object.keys(o)) if (!(KEYS as readonly string[]).includes(k)) problems.push(`"persistence.${k}" is not a known setting (expected one of ${KEYS.join(", ")})`);
  if (o.trustedContentChecks !== undefined) {
    if (typeof o.trustedContentChecks === "boolean") res.trustedContentChecks = o.trustedContentChecks;
    else problems.push('"persistence.trustedContentChecks" must be true or false');
  }
  if (o.holdWhenUntrusted !== undefined) {
    const h = o.holdWhenUntrusted;
    if (!Array.isArray(h) || !h.every((t) => typeof t === "string" && (PERSIST_TAGS as readonly string[]).includes(t))) problems.push(`"persistence.holdWhenUntrusted" must be a list of tags (${PERSIST_TAGS.join(", ")})`);
    else res.holdWhenUntrusted = [...new Set(h as PersistTag[])];
  }
  out.persistence = res;
}

/** The user's (or an administrator's) `persistence` over the defaults: any direction. */
export function mergePersistence(base: PersistencePolicy, over: Partial<PersistencePolicy> | undefined): PersistencePolicy {
  return { ...base, ...(over ?? {}) };
}

/** Applies a project file's `persistence`: tightening only; anything looser is listed in `ignored`. */
export function tightenPersistenceKeys(base: FirewallConfig, over: PersistenceDoc, cfg: FirewallConfig, ignored: string[]): void {
  const o = over.persistence;
  if (o === undefined) return;
  const b = base.persistence ?? defaultPersistence();
  const v: PersistencePolicy = { trustedContentChecks: b.trustedContentChecks, holdWhenUntrusted: [...b.holdWhenUntrusted] };
  if (o.trustedContentChecks === true) v.trustedContentChecks = true;
  else if (o.trustedContentChecks === false && b.trustedContentChecks) ignored.push("persistence.trustedContentChecks (a project may only turn the content checks on)");
  if (o.holdWhenUntrusted !== undefined) {
    v.holdWhenUntrusted = [...new Set([...b.holdWhenUntrusted, ...o.holdWhenUntrusted])];
    if (b.holdWhenUntrusted.some((t) => !o.holdWhenUntrusted?.includes(t))) ignored.push("persistence.holdWhenUntrusted removals (a project may only add tags)");
  }
  cfg.persistence = v;
}
