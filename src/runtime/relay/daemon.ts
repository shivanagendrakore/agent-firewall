/**
 * `launchsafe-firewall relay run`: the only process that talks to the relay
 * after pairing (installed as a login item by `phone pair`). The hook
 * never touches the network: it queues as it always did, and this daemon
 *
 * - seals each pending approval item to every pinned phone and uploads it
 *   (idempotent by item id: a restart never sends an item twice);
 * - tells the relay how many held changes wait in the terminal (a count:
 *   proposals are never sent);
 * - long-polls signed decisions, verifies each (decision.ts) and applies the
 *   good ones, resuming from the last processed decision after a restart;
 * - withdraws items decided elsewhere (the terminal) or expired, and items
 *   the current policy no longer lets a phone decide (V21);
 * - backs off on errors (up to 5 minutes), stops when the relay says the
 *   device was unpaired, and records all of it in relay/state.json for
 *   `status` and `doctor`.
 *
 * Fail closed throughout: a decision that fails any check leaves the item
 * pending, and the terminal keeps working whatever the relay does.
 */

import { randomBytes } from "node:crypto";
import { unlinkSync } from "node:fs";
import { join } from "node:path";
import { loadPolicy } from "../config.js";
import { wrappedPhonePins } from "../../gateway/clients.js";
import { installedHookCommands, pinnedPhonesOf } from "../install.js";
import type { Layout } from "../layout.js";
import { listQueue, type QueueItem } from "../store.js";
import { phonePolicy } from "../../policy-phone.js";
import type { RelayClient } from "./client.js";
import { handleDecision, phoneConfigFor, phoneExpiry, phoneSendable } from "./decision.js";
import { listOutbox, outboxDir, readOutbox, readRelayState, updateRelayState, writeOutbox, type OutboxRecord } from "./files.js";
import { readDevice, resetRegistration, type DeviceFile } from "./keys.js";
import { phonesPinOf, pinnedPhones, type PairedPhone } from "./phones.js";
import { RelayHttpError, uploadBatches, type PhoneItem, type UploadItem, type WithdrawReason } from "./protocol.js";
import { buildPhoneItem, displayHash, sealItem } from "./seal.js";
import { b64u, minutes } from "./util.js";
import { own, setOwn } from "../../own.js";

export const LONG_POLL_SECONDS = 25;
export const MAX_BACKOFF_MS = 5 * 60_000;

export interface DaemonDeps {
  l: Layout;
  client: RelayClient;
  now?: () => Date;
  /** The pin to check phones.json against: by default, the one every installed hook command carries. */
  pin?: () => string | null;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  say?: (line: string) => void;
}

/**
 * The phones pin of the installed hook commands: null unless every command pins the same list. A machine with
 * no hook (a gateway-only client) uses the pin its wrapped MCP servers carry; every wrapper must carry the same
 * one, and an HTTP-only gateway pins the list when `mcp serve` starts, so the list on file is its pin.
 */
export function installedPhonePin(l: Layout): { pin: string | null; reason?: string } {
  const { commands, problems } = installedHookCommands(l);
  if (problems.length > 0) return { pin: null, reason: problems.join("; ") };
  let pins = [...new Set(commands.map((c) => pinnedPhonesOf(c.command)))];
  if (pins.length === 0) {
    const w = wrappedPhonePins(l);
    if (w.problems.length > 0) return { pin: null, reason: w.problems.join("; ") };
    pins = [...new Set(w.pins)];
    if (pins.length === 0 && w.http) {
      const pin = phonesPinOf(l);
      return pin !== null ? { pin } : { pin: null, reason: "no paired phone" };
    }
  }
  if (pins.length === 0) return { pin: null, reason: "the firewall's hooks are not installed" };
  if (pins.length > 1 || pins[0] === null) return { pin: null, reason: "not every installed hook command and wrapped MCP server pins the same paired phones" };
  return { pin: pins[0] as string };
}

function now(d: DaemonDeps): Date {
  return (d.now ?? (() => new Date()))();
}

function pinOf(d: DaemonDeps): string | null {
  return d.pin !== undefined ? d.pin() : installedPhonePin(d.l).pin;
}

export interface SyncResult {
  uploaded: number;
  withdrawn: number;
  waitingInTerminal: number;
  skipped?: string;
}

/** Whether a pending item may go to the phone under the policy of its project. */
function sendable(l: Layout, it: QueueItem): boolean {
  if (it.status !== "pending") return false;
  // PH1/PH2: judged under the project the hook used; an unreadable policy or an item with no project stays in the terminal.
  const cfg = phoneConfigFor(l, it);
  return cfg !== null && phoneSendable(phonePolicy(cfg), it);
}

/** V21: a pending item already on a phone that the current policy no longer lets the phone decide, or has expired under it. */
function noLongerOnPhone(l: Layout, it: QueueItem, rec: OutboxRecord, at: Date): "refused" | "expired" | null {
  // Unreadable or broken policy, or no recorded project: withdraw (fail closed); the terminal still decides the item.
  const cfg = phoneConfigFor(l, it);
  if (cfg === null) return "refused";
  const pol = phonePolicy(cfg);
  if (!phoneSendable(pol, it)) return "refused";
  return at.getTime() > phoneExpiry(pol, it, rec) ? "expired" : null;
}

function newRecord(l: Layout, it: QueueItem, device: DeviceFile, phones: PairedPhone[], at: Date): OutboxRecord & { item: PhoneItem } {
  const pol = phonePolicy(phoneConfigFor(l, it) ?? {});
  const expiresAt = new Date(Date.parse(it.createdAt) + minutes(pol.itemTtlMinutes)).toISOString();
  const item = buildPhoneItem(it, { deviceId: device.deviceId as string, machine: device.label ?? "this computer", nonce: b64u(randomBytes(16)), expiresAt });
  return {
    v: 1,
    itemId: it.id,
    sessionId: it.sessionId,
    actionHash: it.actionHash,
    nonce: item.nonce,
    displayHash: displayHash(item),
    expiresAt,
    sealedAt: at.toISOString(),
    phones: Object.fromEntries(phones.map((p) => [p.credentialId, { itemRef: b64u(randomBytes(16)), uploaded: false }])),
    item,
  };
}

/** One pass over the queue and the outbox: seal and upload new items, withdraw decided ones, send the count. */
export async function syncOutbox(d: DaemonDeps): Promise<SyncResult> {
  const l = d.l;
  const at = now(d);
  const device = readDevice(l);
  if (device?.deviceId === undefined || device.token === undefined) return { uploaded: 0, withdrawn: 0, waitingInTerminal: 0, skipped: "this machine is not paired with the relay" };
  const pinned = pinnedPhones(l, pinOf(d));
  // Only ever seal to pinned phones: a key appended to phones.json must never receive an item.
  if (!pinned.ok) {
    updateRelayState(l, (s) => ({ ...s, sealError: { at: at.toISOString(), message: pinned.reason } }));
    return { uploaded: 0, withdrawn: 0, waitingInTerminal: 0, skipped: pinned.reason };
  }
  const phones = pinned.file.phones;
  const items = listQueue(l).items;
  const pending = items.filter((i) => i.status === "pending");
  let waitingInTerminal = 0;
  const uploads: { rec: OutboxRecord; credentialId: string; up: UploadItem }[] = [];
  let sealError: string | null = null;
  for (const it of pending) {
    if (!sendable(l, it)) {
      waitingInTerminal++;
      continue;
    }
    let rec = readOutbox(l, it.id);
    try {
      if (rec === null) {
        rec = newRecord(l, it, device, phones, at);
        writeOutbox(l, rec);
      }
      // A phone paired after the item was first sent gets it too.
      for (const p of phones) if (own(rec.phones, p.credentialId) === undefined) setOwn(rec.phones, p.credentialId, { itemRef: b64u(randomBytes(16)), uploaded: false });
      writeOutbox(l, rec);
      for (const p of phones) {
        const slot = own(rec.phones, p.credentialId);
        if (slot === undefined || slot.uploaded || slot.refused !== undefined || rec.item === undefined) continue;
        const sealed = sealItem(rec.item, p.ecdhPub, device, slot.itemRef);
        uploads.push({ rec, credentialId: p.credentialId, up: { itemRef: slot.itemRef, credentialId: p.credentialId, sealed: b64u(Buffer.from(JSON.stringify(sealed), "utf8")), expiresAt: rec.expiresAt, kind: "approval" } });
      }
    } catch (e) {
      sealError = `item ${it.id} could not be sealed: ${(e as Error).message}`;
    }
  }
  updateRelayState(l, (s) => {
    const { sealError: _old, ...rest } = s;
    return sealError === null ? rest : { ...rest, sealError: { at: at.toISOString(), message: sealError } };
  });
  let uploaded = 0;
  if (uploads.length > 0) {
    // The relay takes at most 50 items and 768 KB a request: one request per batch, each batch's results
    // saved before the next is sent (a failure later leaves the earlier ones recorded).
    const { batches, oversize } = uploadBatches(uploads.map((u) => u.up));
    const byRef = new Map(uploads.map((u) => [u.up.itemRef, u]));
    for (const it of oversize) {
      const u = byRef.get(it.itemRef);
      const slot = u === undefined ? undefined : own(u.rec.phones, u.credentialId);
      if (u === undefined || slot === undefined) continue;
      slot.refused = "too_large";
      writeOutbox(l, u.rec);
    }
    for (const batch of batches) {
      const res = await d.client.uploadItems(batch);
      const accepted = new Set(res.accepted);
      const touched = new Set<OutboxRecord>();
      for (const it of batch) {
        const u = byRef.get(it.itemRef);
        const slot = u === undefined ? undefined : own(u.rec.phones, u.credentialId);
        if (u === undefined || slot === undefined) continue;
        touched.add(u.rec);
        if (accepted.has(it.itemRef)) {
          slot.uploaded = true;
          uploaded++;
        }
        // A refusal is per item (fair_use, unknown_phone, item_changed, expiry_too_far, not_phone_approvable):
        // that copy is not retried; the rest of the batch stands. The terminal still decides the item.
        const refusal = res.refused.find((r) => r.itemRef === it.itemRef);
        if (refusal !== undefined) {
          slot.refused = refusal.code;
          if (refusal.code === "fair_use") updateRelayState(l, (s) => ({ ...s, fairUse: { at: at.toISOString(), message: refusal.message } }));
          else updateRelayState(l, (s) => ({ ...s, lastRefusal: { at: at.toISOString(), code: refusal.code, message: refusal.message } }));
        }
      }
      for (const rec of touched) writeOutbox(l, rec);
    }
  }
  // Items decided in the terminal (or gone): the phones stop showing them.
  let withdrawn = 0;
  const byId = new Map(items.map((i) => [i.id, i]));
  for (const rec of listOutbox(l)) {
    if (rec.withdrawn?.sent === true) continue;
    const it = byId.get(rec.itemId);
    const decided = it === undefined || it.status !== "pending";
    const phoneDecided = it?.decidedBy?.startsWith("phone") === true;
    // Still pending: withdrawn once it expires, or (V21) once the current policy no longer lets a phone decide it.
    const stale = decided || it === undefined || !Object.values(rec.phones).some((p) => p.uploaded) ? null : noLongerOnPhone(l, it, rec, at);
    const reason: WithdrawReason | null = rec.withdrawn !== undefined ? (rec.withdrawn.reason as WithdrawReason) : decided ? (phoneDecided ? (it?.status === "approved" ? "approved" : "rejected") : "decided_in_terminal") : stale;
    if (reason === null) continue;
    await withdrawRecord(d, rec, reason);
    withdrawn++;
  }
  // Counts only: the phone shows "N changes waiting in your terminal".
  if (readRelayState(l).lastSummary !== waitingInTerminal) {
    await d.client.summary({ waitingInTerminal });
    updateRelayState(l, (s) => ({ ...s, lastSummary: waitingInTerminal }));
  }
  pruneOutbox(l, at);
  return { uploaded, withdrawn, waitingInTerminal };
}

async function withdrawRecord(d: DaemonDeps, rec: OutboxRecord, reason: WithdrawReason): Promise<void> {
  const fresh = readOutbox(d.l, rec.itemId) ?? rec;
  fresh.withdrawn = { reason, at: now(d).toISOString(), sent: false };
  writeOutbox(d.l, fresh);
  for (const slot of Object.values(fresh.phones)) if (slot.uploaded) await d.client.withdraw(slot.itemRef, reason);
  fresh.withdrawn.sent = true;
  writeOutbox(d.l, fresh);
}

function pruneOutbox(l: Layout, at: Date): void {
  // Withdrawn records are kept 7 days (a late decision still finds its item and is refused properly).
  for (const rec of listOutbox(l)) {
    if (rec.withdrawn?.sent !== true || at.getTime() - Date.parse(rec.withdrawn.at) <= 7 * 86400000) continue;
    try {
      unlinkSync(join(outboxDir(l), `${rec.itemId}.json`));
    } catch {
      // Already gone.
    }
  }
}

export interface PollResult {
  received: number;
  applied: number;
  refused: number;
}

/** One long poll: fetch decisions after the saved cursor, verify and apply each, save the cursor after each. */
export async function pollOnce(d: DaemonDeps, waitSeconds = LONG_POLL_SECONDS): Promise<PollResult> {
  const l = d.l;
  const cursor = readRelayState(l).cursor ?? null;
  const res = await d.client.decisions(cursor, waitSeconds);
  const out: PollResult = { received: res.decisions.length, applied: 0, refused: 0 };
  const global = loadPolicy(l, []).config;
  for (const dec of res.decisions) {
    const o = handleDecision(l, dec, { pin: pinOf(d), cfg: global, cfgFor: (it) => phoneConfigFor(l, it), now: now(d) });
    if (o.applied !== null) out.applied++;
    else out.refused++;
    if (o.withdraw !== null && o.itemId !== undefined) {
      const rec = readOutbox(l, o.itemId);
      if (rec !== null && rec.withdrawn?.sent !== true) await withdrawRecord(d, rec, o.withdraw);
    }
    updateRelayState(l, (s) => ({ ...s, cursor: dec.id }));
  }
  if (res.decisions.length === 0 && res.cursor !== null && res.cursor !== cursor) updateRelayState(l, (s) => ({ ...s, cursor: res.cursor }));
  return out;
}

function noteSuccess(l: Layout, at: Date): void {
  updateRelayState(l, (s) => {
    const { lastError: _e, lastErrorAt: _a, unreachableSince: _u, ...rest } = s;
    return { ...rest, lastContactAt: at.toISOString() };
  });
}

function noteFailure(l: Layout, e: unknown, at: Date): "stop" | "retry" {
  if (e instanceof RelayHttpError && e.revoked) {
    // Unpaired in the app: forget the device id and token. Pairing again gets a new device id from the
    // relay, which phone pair accepts only after this reset (never a different id silently).
    resetRegistration(l);
    updateRelayState(l, (s) => ({ ...s, revoked: at.toISOString(), lastError: "this machine was unpaired in the LaunchSafe app", lastErrorAt: at.toISOString() }));
    return "stop";
  }
  const message = e instanceof RelayHttpError ? `${e.code}: ${e.message}` : (e as Error).message;
  updateRelayState(l, (s) => ({ ...s, lastError: message.slice(0, 300), lastErrorAt: at.toISOString(), unreachableSince: s.unreachableSince ?? at.toISOString(), ...(e instanceof RelayHttpError && e.fairUse ? { fairUse: { at: at.toISOString(), message: e.message } } : {}) }));
  return "retry";
}

function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted === true) return resolve();
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(t);
      resolve();
    }, { once: true });
  });
}

/** The heartbeat; also notes a wall clock that moved backwards by more than 5 minutes (it lengthens windows). */
function heartbeat(l: Layout, at: Date): void {
  updateRelayState(l, (s) => {
    const prev = s.loopAt !== undefined ? Date.parse(s.loopAt) : NaN;
    const back = Number.isFinite(prev) ? prev - at.getTime() : 0;
    return { ...s, loopAt: at.toISOString(), pid: process.pid, ...(back > minutes(5) ? { clockBackwards: { at: at.toISOString(), minutes: Math.round(back / 60000) } } : {}) };
  });
}

/**
 * Runs until `signal` aborts or the relay says this machine was unpaired. Two loops: uploads every
 * `syncEveryMs` (new items reach the phone within seconds) and the long poll for decisions.
 */
export async function runDaemon(d: DaemonDeps, o: { signal: AbortSignal; syncEveryMs?: number; waitSeconds?: number }): Promise<"stopped" | "revoked"> {
  const sleep = d.sleep ?? defaultSleep;
  const say = d.say ?? (() => undefined);
  if (readRelayState(d.l).revoked !== undefined) return "revoked";
  let revoked = false;
  const stopAll = new AbortController();
  const stop = (): void => stopAll.abort();
  o.signal.addEventListener("abort", stop, { once: true });
  const loop = async (name: string, step: () => Promise<unknown>, idleMs: number): Promise<void> => {
    let backoff = 1000;
    while (!stopAll.signal.aborted) {
      const at = now(d);
      heartbeat(d.l, at);
      try {
        await step();
        noteSuccess(d.l, now(d));
        backoff = 1000;
        if (idleMs > 0) await sleep(idleMs, stopAll.signal);
      } catch (e) {
        if (stopAll.signal.aborted) break;
        if (noteFailure(d.l, e, now(d)) === "stop") {
          revoked = true;
          say("The relay refused this machine's token: it was unpaired in the LaunchSafe app. Stopping.");
          stop();
          break;
        }
        say(`${name}: ${(e as Error).message}; retrying in ${Math.round(backoff / 1000)} s`);
        await sleep(backoff, stopAll.signal);
        backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
      }
    }
  };
  await Promise.all([loop("upload", () => syncOutbox(d), o.syncEveryMs ?? 2000), loop("decisions", () => pollOnce(d, o.waitSeconds ?? LONG_POLL_SECONDS), 0)]);
  o.signal.removeEventListener("abort", stop);
  return revoked ? "revoked" : "stopped";
}
