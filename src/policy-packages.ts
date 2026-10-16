/**
 * The package vetting policy key, kept apart from policy.ts so it stays one
 * module: `packageIntel` (malicious-package, typosquat and lockfile checks;
 * defaults in src/engine/packages.ts). A project file may only make the
 * checks stricter: deny > approve > off for listed versions, approve > off
 * for typosquats, lockfile reading on, a shorter snapshot age.
 */

import { DEFAULT_PACKAGE_INTEL, type PackageIntelPolicy } from "./engine/packages.js";
import type { FirewallConfig } from "./types.js";

export const PACKAGE_POLICY_KEYS = ["packageIntel"] as const;

export interface PackageDoc {
  packageIntel?: Partial<PackageIntelPolicy>;
}

export function defaultPackageIntel(): PackageIntelPolicy {
  return { ...DEFAULT_PACKAGE_INTEL };
}

const KEYS = ["malicious", "typosquat", "lockfiles", "maxSnapshotAgeDays"] as const;

type Raw = Record<string, unknown>;

/** Validates the key of a (migrated) policy document into `out`. */
export function validatePackageKeys(raw: Raw, problems: string[], out: PackageDoc): void {
  if (raw.packageIntel === undefined) return;
  const v = raw.packageIntel;
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    problems.push('"packageIntel" must be an object');
    return;
  }
  const o = v as Raw;
  const res: Partial<PackageIntelPolicy> = {};
  for (const k of Object.keys(o)) if (!(KEYS as readonly string[]).includes(k)) problems.push(`"packageIntel.${k}" is not a known setting (expected ${KEYS.join(", ")})`);
  if (o.malicious !== undefined) {
    if (o.malicious === "deny" || o.malicious === "approve" || o.malicious === "off") res.malicious = o.malicious;
    else problems.push('"packageIntel.malicious" must be "deny", "approve" or "off"');
  }
  if (o.typosquat !== undefined) {
    if (o.typosquat === "approve" || o.typosquat === "off") res.typosquat = o.typosquat;
    else problems.push('"packageIntel.typosquat" must be "approve" or "off"');
  }
  if (o.lockfiles !== undefined) {
    if (typeof o.lockfiles === "boolean") res.lockfiles = o.lockfiles;
    else problems.push('"packageIntel.lockfiles" must be true or false');
  }
  if (o.maxSnapshotAgeDays !== undefined) {
    if (typeof o.maxSnapshotAgeDays === "number" && Number.isInteger(o.maxSnapshotAgeDays) && o.maxSnapshotAgeDays >= 1 && o.maxSnapshotAgeDays <= 3650) res.maxSnapshotAgeDays = o.maxSnapshotAgeDays;
    else problems.push('"packageIntel.maxSnapshotAgeDays" must be a whole number of days from 1 to 3650');
  }
  out.packageIntel = res;
}

const RANK_M = { off: 0, approve: 1, deny: 2 } as const;
const RANK_T = { off: 0, approve: 1 } as const;

/** Applies a project file's `packageIntel`: stricter values only; anything looser is listed in `ignored`. */
export function tightenPackageKeys(base: FirewallConfig, over: PackageDoc, cfg: FirewallConfig, ignored: string[]): void {
  const o = over.packageIntel;
  if (o === undefined) return;
  const b: PackageIntelPolicy = { ...DEFAULT_PACKAGE_INTEL, ...(base.packageIntel ?? {}) };
  const v = { ...b };
  let loosened = false;
  if (o.malicious !== undefined) {
    if (RANK_M[o.malicious] > RANK_M[b.malicious]) v.malicious = o.malicious;
    else if (RANK_M[o.malicious] < RANK_M[b.malicious]) loosened = true;
  }
  if (o.typosquat !== undefined) {
    if (RANK_T[o.typosquat] > RANK_T[b.typosquat]) v.typosquat = o.typosquat;
    else if (RANK_T[o.typosquat] < RANK_T[b.typosquat]) loosened = true;
  }
  if (o.lockfiles === true) v.lockfiles = true;
  else if (o.lockfiles === false && b.lockfiles) loosened = true;
  if (o.maxSnapshotAgeDays !== undefined) {
    if (o.maxSnapshotAgeDays < b.maxSnapshotAgeDays) v.maxSnapshotAgeDays = o.maxSnapshotAgeDays;
    else if (o.maxSnapshotAgeDays > b.maxSnapshotAgeDays) loosened = true;
  }
  cfg.packageIntel = v;
  if (loosened) ignored.push("packageIntel loosening (a project may only make package checks stricter)");
}
