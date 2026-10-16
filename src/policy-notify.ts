/**
 * The notifications policy key, kept apart from policy.ts so it stays one
 * module: `notifications` (local desktop notifications; they inform, never
 * approve). A project file may only switch them on and add kinds: never
 * switch them off, restrict them to unattended sessions or space them out.
 */

import type { FirewallConfig, NotificationPolicy, NotifyKind } from "./types.js";

export const NOTIFY_POLICY_KEYS = ["notifications"] as const;

export interface NotifyDoc {
  notifications?: Partial<NotificationPolicy>;
}

export const NOTIFY_KINDS: readonly NotifyKind[] = ["queued", "proposal", "denied_dlp", "canary", "loop", "agent_config", "mcp_changed", "mcp_withheld", "mail_quarantined", "stopped", "cap"];
/** The shortest interval a policy may set (the floor for canary and data blocks is separate, in runtime/notify.ts). */
export const MIN_NOTIFY_INTERVAL_SEC = 10;

/** Notifications are on by default, coalesced, with fixed text. */
export function defaultNotifications(): NotificationPolicy {
  return { enabled: true, on: [...NOTIFY_KINDS], onlyWhenUnattended: false, minIntervalSec: 120 };
}

const NOTIFY_KEYS = ["enabled", "on", "onlyWhenUnattended", "minIntervalSec"] as const;

type Raw = Record<string, unknown>;

/** Validates the key of a (migrated) policy document into `out`. Keys left out take the value below them (defaults, or the user's policy). */
export function validateNotifyKeys(raw: Raw, problems: string[], out: NotifyDoc): void {
  if (raw.notifications === undefined) return;
  const v = raw.notifications;
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    problems.push('"notifications" must be an object');
    return;
  }
  const o = v as Raw;
  const res: Partial<NotificationPolicy> = {};
  for (const k of Object.keys(o)) if (!(NOTIFY_KEYS as readonly string[]).includes(k)) problems.push(`"notifications.${k}" is not a known setting (expected one of ${NOTIFY_KEYS.join(", ")})`);
  if (o.enabled !== undefined) {
    if (typeof o.enabled === "boolean") res.enabled = o.enabled;
    else problems.push('"notifications.enabled" must be true or false');
  }
  if (o.onlyWhenUnattended !== undefined) {
    if (typeof o.onlyWhenUnattended === "boolean") res.onlyWhenUnattended = o.onlyWhenUnattended;
    else problems.push('"notifications.onlyWhenUnattended" must be true or false');
  }
  if (o.minIntervalSec !== undefined) {
    if (typeof o.minIntervalSec === "number" && Number.isInteger(o.minIntervalSec) && o.minIntervalSec >= MIN_NOTIFY_INTERVAL_SEC && o.minIntervalSec <= 86400) res.minIntervalSec = o.minIntervalSec;
    else problems.push(`"notifications.minIntervalSec" must be a whole number of seconds from ${MIN_NOTIFY_INTERVAL_SEC} to 86400`);
  }
  if (o.on !== undefined) {
    if (Array.isArray(o.on) && o.on.every((k) => typeof k === "string" && (NOTIFY_KINDS as readonly string[]).includes(k))) res.on = [...new Set(o.on as NotifyKind[])];
    else problems.push(`"notifications.on" must be a list of: ${NOTIFY_KINDS.join(", ")}`);
  }
  out.notifications = res;
}

/**
 * Applies a project file's `notifications`. Neutral (no secrets either way), but tighten-only for
 * consistency: on, and more kinds. Anything else that would change the setting is listed in `ignored`.
 */
export function tightenNotifyKeys(base: FirewallConfig, over: NotifyDoc, cfg: FirewallConfig, ignored: string[]): void {
  const n = over.notifications;
  if (n === undefined) return;
  cfg.notifications = { ...base.notifications, on: [...new Set([...base.notifications.on, ...(n.on ?? [])])] };
  if (n.enabled === true) cfg.notifications.enabled = true;
  const quieter = n.enabled === false || (n.onlyWhenUnattended !== undefined && n.onlyWhenUnattended !== base.notifications.onlyWhenUnattended) || (n.minIntervalSec !== undefined && n.minIntervalSec !== base.notifications.minIntervalSec);
  if (quieter) ignored.push("notifications (a project may only turn notifications on and add kinds)");
}
