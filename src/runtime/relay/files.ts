/**
 * The relay's files in the protected data directory (an agent writing any of
 * them is FW-TAMPER through the data-root rule):
 *
 * - `relay/outbox/<itemId>.json`: one record per queued item sent to the
 *   phones: its nonce, displayHash, expiry and, per phone, the random item
 *   reference and whether it was uploaded. Idempotent by item id, so a
 *   restarted daemon never sends an item twice.
 * - `relay/nonces.json`: nonces already used (kept 7 days): single use.
 * - `relay/counters.json`: the last signature counter per credential.
 * - `relay/state.json`: last contact, last error, the decisions cursor, the
 *   daemon's heartbeat: what `status` and `doctor` show.
 */

import { readdirSync } from "node:fs";
import { join } from "node:path";
import { atomicWrite, ensureDir, readText, withLock } from "../fsutil.js";
import type { Layout } from "../layout.js";
import type { PhoneItem } from "./protocol.js";
import { own, setOwn } from "../../own.js";

export function relayDir(l: Layout): string {
  return join(l.home, "relay");
}

export function outboxDir(l: Layout): string {
  return join(relayDir(l), "outbox");
}

export interface OutboxRecord {
  v: 1;
  itemId: string;
  sessionId: string;
  actionHash: string;
  nonce: string;
  displayHash: string;
  expiresAt: string;
  sealedAt: string;
  phones: Record<string, { itemRef: string; uploaded: boolean; refused?: string }>;
  /** The exact item sent (sealed again per phone on upload; its canonical hash is displayHash). */
  item?: PhoneItem;
  withdrawn?: { reason: string; at: string; sent: boolean };
}

function outboxPath(l: Layout, itemId: string): string {
  return join(outboxDir(l), `${itemId}.json`);
}

export function readOutbox(l: Layout, itemId: string): OutboxRecord | null {
  if (!/^[a-z0-9]{4,32}$/.test(itemId)) return null;
  try {
    const t = readText(outboxPath(l, itemId));
    if (t === null) return null;
    const r = JSON.parse(t) as OutboxRecord;
    return r.v === 1 && r.itemId === itemId && typeof r.nonce === "string" ? r : null;
  } catch {
    return null;
  }
}

export function writeOutbox(l: Layout, r: OutboxRecord): void {
  atomicWrite(outboxPath(l, r.itemId), JSON.stringify(r, null, 2));
}

export function listOutbox(l: Layout): OutboxRecord[] {
  let names: string[] = [];
  try {
    names = readdirSync(outboxDir(l)).filter((n) => n.endsWith(".json"));
  } catch {
    return [];
  }
  return names.map((n) => readOutbox(l, n.replace(/\.json$/, ""))).filter((r): r is OutboxRecord => r !== null);
}

/** The outbox record that holds this item reference (the relay names items only by reference). */
export function outboxByRef(l: Layout, itemRef: string): { record: OutboxRecord; credentialId: string } | null {
  for (const r of listOutbox(l)) for (const [credentialId, p] of Object.entries(r.phones)) if (p.itemRef === itemRef) return { record: r, credentialId };
  return null;
}

// --- nonces and counters (changed only under the queue lock) ----------------------------------------

const NONCE_DAYS = 7;

function readJson<T>(path: string, fallback: T): T {
  try {
    const t = readText(path);
    return t === null ? fallback : (JSON.parse(t) as T);
  } catch {
    return fallback;
  }
}

export function noncesPath(l: Layout): string {
  return join(relayDir(l), "nonces.json");
}

/** Whether a nonce was used. An unreadable file counts every nonce as used (fail closed). */
export function nonceUsed(l: Layout, nonce: string): boolean {
  try {
    const t = readText(noncesPath(l));
    if (t === null) return false;
    const v = JSON.parse(t) as { used?: Record<string, string> };
    if (typeof v.used !== "object" || v.used === null) return true;
    return Object.hasOwn(v.used, nonce);
  } catch {
    return true;
  }
}

export function markNonceUsed(l: Layout, nonce: string, now = new Date()): void {
  const v = readJson<{ used: Record<string, string> }>(noncesPath(l), { used: {} });
  const used: Record<string, string> = {};
  for (const [k, at] of Object.entries(v.used ?? {})) if (now.getTime() - Date.parse(at) < NONCE_DAYS * 86400000) setOwn(used, k, at);
  setOwn(used, nonce, now.toISOString());
  atomicWrite(noncesPath(l), JSON.stringify({ used }));
}

/**
 * Whether this is the first time an expired phone approval (by its queue item id) is reported: the hook logs one
 * line per approval, not one per call. Kept 7 days like the nonces; an unreadable file reports again (the log is
 * the only cost).
 */
export function firstExpiredReport(l: Layout, id: string, now = new Date()): boolean {
  const p = join(relayDir(l), "expired-logged.json");
  return withLock(`${p}.lock`, () => {
    const v = readJson<{ seen: Record<string, string> }>(p, { seen: {} });
    if (Object.hasOwn(v.seen ?? {}, id)) return false;
    const seen: Record<string, string> = {};
    for (const [k, at] of Object.entries(v.seen ?? {})) if (now.getTime() - Date.parse(at) < NONCE_DAYS * 86400000) setOwn(seen, k, at);
    setOwn(seen, id, now.toISOString());
    ensureDir(relayDir(l));
    atomicWrite(p, JSON.stringify({ seen }));
    return true;
  });
}

function countersPath(l: Layout): string {
  return join(relayDir(l), "counters.json");
}

export function storedCounter(l: Layout, credentialId: string): number {
  const v = readJson<Record<string, number>>(countersPath(l), {});
  const n = own(v, credentialId);
  return typeof n === "number" && Number.isFinite(n) ? n : 0;
}

export function storeCounter(l: Layout, credentialId: string, n: number): void {
  const v = readJson<Record<string, number>>(countersPath(l), {});
  atomicWrite(countersPath(l), JSON.stringify({ ...v, [credentialId]: n }));
}

// --- daemon state -----------------------------------------------------------------------------------

export interface RelayState {
  /** The decisions cursor: the daemon resumes from here after a restart. */
  cursor?: string | null;
  lastContactAt?: string;
  lastError?: string;
  lastErrorAt?: string;
  /** Set on the first failure after a success; cleared by the next success. */
  unreachableSince?: string;
  /** The relay refused the device token: unpaired in the LaunchSafe app. */
  revoked?: string;
  fairUse?: { at: string; message: string };
  /** The last per-item refusal other than fair use (unknown_phone, item_changed, expiry_too_far, not_phone_approvable). */
  lastRefusal?: { at: string; code: string; message: string };
  sealError?: { at: string; message: string };
  /** The daemon's heartbeat and process id. */
  loopAt?: string;
  pid?: number;
  /** The last terminal-only count sent. */
  lastSummary?: number;
  /** The wall clock moved backwards by more than 5 minutes between two loops. */
  clockBackwards?: { at: string; minutes: number };
}

export function statePath(l: Layout): string {
  return join(relayDir(l), "state.json");
}

export function readRelayState(l: Layout): RelayState {
  return readJson<RelayState>(statePath(l), {});
}

export function updateRelayState(l: Layout, patch: (s: RelayState) => RelayState): RelayState {
  ensureDir(relayDir(l));
  return withLock(join(relayDir(l), "state.lock"), () => {
    const next = patch(readRelayState(l));
    atomicWrite(statePath(l), JSON.stringify(next, null, 2));
    return next;
  });
}

/** One line for `status` (null when no phone is paired: nothing is shown and nothing changes). */
export function relayStatusLine(l: Layout, registered: boolean, now = new Date()): string | null {
  if (!registered) return null;
  const s = readRelayState(l);
  const when = (iso: string): string => iso.slice(0, 16).replace("T", " ");
  const lines: string[] = [];
  if (s.revoked !== undefined) lines.push("Phone approvals: this machine was unpaired in the LaunchSafe app (pair again with phone pair).");
  else if (s.unreachableSince !== undefined) lines.push(`Phone approvals: phone relay unreachable since ${when(s.unreachableSince)}; terminal approvals work as always.`);
  else lines.push(`Phone approvals: on${s.lastContactAt !== undefined ? `, last relay contact ${when(s.lastContactAt)}` : ", the relay has not been contacted yet"}.`);
  if (s.clockBackwards !== undefined && now.getTime() - Date.parse(s.clockBackwards.at) < 86400000) lines.push(`Warning: the clock moved back ${s.clockBackwards.minutes} minutes since the last relay contact; approval windows were longer by that much.`);
  return lines.join("\n");
}
