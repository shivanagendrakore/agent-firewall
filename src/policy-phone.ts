/**
 * Item P's policy key, kept apart from policy.ts so the item stays one
 * module: `phone` (docs/phone.md). Defaults are described in that doc; a project file
 * may only tighten: switch phone approvals off, lower the windows, drop
 * approvable kinds, add excluded rules, lower the hold. User or managed
 * policy may raise the windows to their caps, and only they may change the
 * relay origin. `requireUserVerification` cannot be turned off in v0.3.
 */

import type { FirewallConfig } from "./types.js";

export const PHONE_POLICY_KEYS = ["phone"] as const;

export const DEFAULT_RELAY_ORIGIN = "https://approve.launchsafe.com";

export interface PhonePolicy {
  /** False ignores phone approvals entirely (pairing is still what turns them on). */
  enabled: boolean;
  itemTtlMinutes: number;
  useWithinMinutes: number;
  clockSkewMinutes: number;
  /** Always true in v0.3. */
  requireUserVerification: true;
  /** "approval" only: proposals stay terminal-only. */
  approvable: "approval"[];
  excludeRules: string[];
  /** Off by default; capped at the agent's hook timeout minus 10 s. */
  holdSeconds: number;
  /** The pinned WebAuthn origin and the relay's API base. */
  relayOrigin: string;
}

export interface PhoneDoc {
  phone?: Partial<Omit<PhonePolicy, "requireUserVerification">> & { requireUserVerification?: boolean };
}

export const PHONE_LIMITS = { itemTtlMinutes: 720, useWithinMinutes: 1440, clockSkewMinutes: 30, holdSeconds: 600 } as const;

export function defaultPhone(): PhonePolicy {
  return { enabled: true, itemTtlMinutes: 30, useWithinMinutes: 60, clockSkewMinutes: 10, requireUserVerification: true, approvable: ["approval"], excludeRules: [], holdSeconds: 0, relayOrigin: DEFAULT_RELAY_ORIGIN };
}

/** The phone policy in effect (defaults for anything a policy file did not set). */
export function phonePolicy(cfg: Pick<FirewallConfig, "phone">): PhonePolicy {
  const d = defaultPhone();
  const p = cfg.phone ?? {};
  return {
    enabled: p.enabled ?? d.enabled,
    itemTtlMinutes: p.itemTtlMinutes ?? d.itemTtlMinutes,
    useWithinMinutes: p.useWithinMinutes ?? d.useWithinMinutes,
    clockSkewMinutes: p.clockSkewMinutes ?? d.clockSkewMinutes,
    requireUserVerification: true,
    approvable: p.approvable ?? d.approvable,
    excludeRules: p.excludeRules ?? d.excludeRules,
    holdSeconds: p.holdSeconds ?? d.holdSeconds,
    relayOrigin: p.relayOrigin ?? d.relayOrigin,
  };
}

/**
 * A relay origin: https with a host (and optional port) and nothing else, or plain http to this machine
 * only (a self-hosted relay under development). The WebAuthn origin a phone signs on must equal it.
 */
export function validRelayOrigin(s: string): boolean {
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return false;
  }
  if (u.username !== "" || u.password !== "" || u.search !== "" || u.hash !== "" || (u.pathname !== "/" && u.pathname !== "")) return false;
  if (s.endsWith("/")) return false;
  if (u.protocol === "https:") return u.hostname !== "";
  return u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost" || u.hostname === "[::1]");
}

/** The WebAuthn RP ID for an origin: its host name. */
export function rpIdOf(origin: string): string {
  return new URL(origin).hostname;
}

const KEYS = ["enabled", "itemTtlMinutes", "useWithinMinutes", "clockSkewMinutes", "requireUserVerification", "approvable", "excludeRules", "holdSeconds", "relayOrigin"] as const;

type Raw = Record<string, unknown>;

/** Validates the key of a (migrated) policy document into `out`. */
export function validatePhoneKeys(raw: Raw, problems: string[], out: PhoneDoc): void {
  if (raw.phone === undefined) return;
  const v = raw.phone;
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    problems.push('"phone" must be an object');
    return;
  }
  const o = v as Raw;
  const res: NonNullable<PhoneDoc["phone"]> = {};
  for (const k of Object.keys(o)) if (!(KEYS as readonly string[]).includes(k)) problems.push(`"phone.${k}" is not a known setting (expected one of ${KEYS.join(", ")})`);
  if (o.enabled !== undefined) {
    if (typeof o.enabled === "boolean") res.enabled = o.enabled;
    else problems.push('"phone.enabled" must be true or false');
  }
  if (o.requireUserVerification !== undefined) {
    if (o.requireUserVerification === true) res.requireUserVerification = true;
    else problems.push('"phone.requireUserVerification" cannot be turned off in this version');
  }
  for (const k of ["itemTtlMinutes", "useWithinMinutes", "clockSkewMinutes", "holdSeconds"] as const) {
    if (o[k] === undefined) continue;
    const n = o[k];
    const min = k === "holdSeconds" || k === "clockSkewMinutes" ? 0 : 1;
    if (typeof n !== "number" || !Number.isInteger(n) || n < min || n > PHONE_LIMITS[k]) problems.push(`"phone.${k}" must be a whole number from ${min} to ${PHONE_LIMITS[k]}`);
    else res[k] = n;
  }
  if (o.approvable !== undefined) {
    if (!Array.isArray(o.approvable) || !o.approvable.every((x) => x === "approval")) problems.push('"phone.approvable" must be a list holding at most "approval" (proposals stay in the terminal)');
    else res.approvable = [...new Set(o.approvable as "approval"[])];
  }
  if (o.excludeRules !== undefined) {
    if (!Array.isArray(o.excludeRules) || !o.excludeRules.every((x) => typeof x === "string" && /^FW-[A-Z0-9-]{1,40}$/.test(x))) problems.push('"phone.excludeRules" must be a list of rule ids (FW-...)');
    else res.excludeRules = o.excludeRules as string[];
  }
  if (o.relayOrigin !== undefined) {
    if (typeof o.relayOrigin !== "string" || !validRelayOrigin(o.relayOrigin)) problems.push('"phone.relayOrigin" must be an https origin (scheme and host, no path), or http://127.0.0.1:<port> for a relay on this machine');
    else res.relayOrigin = o.relayOrigin;
  }
  out.phone = res;
}

/** The user's (or an administrator's) `phone` over the layer below: anything within the caps. */
export function mergePhone(base: FirewallConfig["phone"], over: PhoneDoc["phone"]): FirewallConfig["phone"] {
  if (base === undefined && over === undefined) return undefined;
  const { requireUserVerification: _ignored, ...rest } = over ?? {};
  return { ...(base ?? {}), ...rest };
}

/** Applies a project file's `phone`: tightening only; anything looser is listed in `ignored`. */
export function tightenPhoneKeys(base: FirewallConfig, over: PhoneDoc, cfg: FirewallConfig, ignored: string[]): void {
  const v = over.phone;
  if (v === undefined) return;
  const cur = phonePolicy(base);
  const next: NonNullable<FirewallConfig["phone"]> = { ...(base.phone ?? {}) };
  if (v.enabled === false) next.enabled = false;
  if (v.enabled === true && !cur.enabled) ignored.push("phone.enabled (a repository cannot turn phone approvals on)");
  for (const k of ["itemTtlMinutes", "useWithinMinutes", "clockSkewMinutes", "holdSeconds"] as const) {
    const n = v[k];
    if (n === undefined) continue;
    if (n <= cur[k]) next[k] = n;
    else ignored.push(`phone.${k} (a project may only lower it)`);
  }
  if (v.approvable !== undefined) next.approvable = cur.approvable.filter((k) => (v.approvable ?? []).includes(k));
  if (v.excludeRules !== undefined) next.excludeRules = [...new Set([...cur.excludeRules, ...v.excludeRules])];
  if (v.relayOrigin !== undefined && v.relayOrigin !== cur.relayOrigin) ignored.push("phone.relayOrigin (only user or managed policy may change the relay)");
  cfg.phone = next;
}
