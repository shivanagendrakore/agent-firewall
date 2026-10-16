/**
 * The quarantine store (v0.3, ONE store shared by the email guard and the MCP
 * gateway's result scanning; docs/gateway.md describes it): one
 * file per withheld item in `quarantine/` in the protected data directory, so
 * an agent writing there is FW-TAMPER through the data-root rule.
 *
 * Email records keep the message's ids, sender, subject, the provider's
 * authentication summary, the signals, the sha256 of the message and a short
 * escaped preview of its hidden text. Never the message itself: it stays in
 * the mailbox. (An MCP result record may keep the withheld text, 1 MiB at
 * most, deleted after 30 days.)
 *
 * Release is the human channel: `mail quarantine release` (a person at the
 * keyboard, the approval passphrase when one is set) adds the message's
 * sha256 to `quarantine/released.json`, signed with the approver key, and
 * the read path then delivers that exact message with only its hidden parts
 * stripped. With an approver key (pinned, or set up on disk), unsigned or
 * badly signed entries are ignored, so a write to the file that slipped past
 * the hook still releases nothing. M5: a release lapses after RELEASE_TTL_MS
 * (its expiry is signed with it; a release made before counts for that long
 * from when it was made).
 */

import { createHash, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { accessSync, constants, existsSync, readdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { revealInvisible } from "../vendor/agent-safety/signals.js";
import { atomicWrite, readText, withLock } from "./fsutil.js";
import type { Layout } from "./layout.js";
import { newQueueId } from "./store.js";
import { approverPublicKey } from "./approver.js";

export type QuarantineStatus = "held" | "released" | "discarded";

export interface QuarantineRecord {
  version: 1;
  /** "q-" + a queue-style id. */
  id: string;
  kind: "mcp_result" | "email";
  createdAt: string;
  session: string;
  client?: string;
  server?: string;
  tool?: string;
  /** Signal names (tag_chars, hidden_html, agent_directed, ...). */
  signals: string[];
  /** The rules that withheld it (hidden_instruction, tag_chars, scan_incomplete, ...). */
  reasons?: string[];
  sha256: string;
  size: number;
  /** Email: up to 200 escaped characters of the hidden text (what the agent would have read). */
  preview: string;
  /** mcp_result only: the withheld text, at most 1 MiB. */
  body?: string;
  mail?: { provider: string; mailbox: string; messageId: string; from: string; subject: string; authResults?: string };
  /** Why the record exists in a form the person reads ("could not split the result into messages"). */
  note?: string;
  status: QuarantineStatus;
  decidedAt?: string;
}

export interface ReleasedEntry {
  sha256: string;
  id: string;
  at: string;
  /** M5: when the release stops counting (signed with it, message v2); absent on releases made before. */
  exp?: string;
  /** Ed25519 signature by the approver key over releaseMessage(sha256, id, exp); absent when no approver is set. */
  sig?: string;
}

export const MAX_BODY = 1024 * 1024;
/** Withheld MCP text is not kept longer than this; decided records are removed after it. */
export const KEEP_DAYS = 30;
const ID = /^q-[a-z0-9]{4,32}$/;

export function quarantineDir(l: Layout): string {
  return join(l.home, "quarantine");
}

function recordPath(l: Layout, id: string): string {
  return join(quarantineDir(l), `${id}.json`);
}

function releasedPath(l: Layout): string {
  return join(quarantineDir(l), "released.json");
}

const lockPath = (l: Layout) => join(l.locks, "quarantine.lock");

export function newRecordId(): string {
  return `q-${newQueueId()}`;
}

const isString = (v: unknown): v is string => typeof v === "string";
const isOptionalString = (v: unknown): boolean => v === undefined || typeof v === "string";
const isStringList = (v: unknown): boolean => Array.isArray(v) && v.every(isString);
/** A string Date.parse can read: the list sorts by it and the prune ages a record by it. */
const isTime = (v: unknown): boolean => typeof v === "string" && Number.isFinite(Date.parse(v));

/** The message the email guard keeps of a withheld message; `authResults` is the only part that may be absent. */
function validMail(m: unknown): boolean {
  if (m === undefined) return true;
  if (typeof m !== "object" || m === null || Array.isArray(m)) return false;
  const x = m as Record<string, unknown>;
  return isString(x.provider) && isString(x.mailbox) && isString(x.messageId) && isString(x.from) && isString(x.subject) && isOptionalString(x.authResults);
}

/**
 * FZ22: whether `r` is a record this store could have written. Every field the list, the review commands
 * (`mail quarantine`, `gateway quarantine`), the dashboard and the prune read is checked for its type, so a
 * record whose JSON is valid but whose fields are the wrong kind (a missing or numeric `createdAt`, a `reasons`
 * that is not a list, a `mail` that is null) is damage like any other: listRecords reports it as corrupt and
 * getRecord answers null, instead of a caller throwing on it. Optional fields may be absent, never another type.
 */
function valid(r: unknown): r is QuarantineRecord {
  if (typeof r !== "object" || r === null || Array.isArray(r)) return false;
  const x = r as Record<string, unknown>;
  return (
    x.version === 1 &&
    typeof x.id === "string" &&
    ID.test(x.id) &&
    (x.kind === "email" || x.kind === "mcp_result") &&
    isTime(x.createdAt) &&
    isString(x.session) &&
    isString(x.sha256) &&
    typeof x.size === "number" &&
    Number.isFinite(x.size) &&
    x.size >= 0 &&
    isString(x.preview) &&
    (x.status === "held" || x.status === "released" || x.status === "discarded") &&
    isStringList(x.signals) &&
    (x.reasons === undefined || isStringList(x.reasons)) &&
    isOptionalString(x.client) &&
    isOptionalString(x.server) &&
    isOptionalString(x.tool) &&
    isOptionalString(x.body) &&
    isOptionalString(x.note) &&
    (x.decidedAt === undefined || isTime(x.decidedAt)) &&
    validMail(x.mail)
  );
}

export function listRecords(l: Layout): { records: QuarantineRecord[]; corrupt: string[] } {
  const records: QuarantineRecord[] = [];
  const corrupt: string[] = [];
  let names: string[] = [];
  try {
    names = readdirSync(quarantineDir(l)).filter((n) => n.startsWith("q-") && n.endsWith(".json"));
  } catch {
    return { records, corrupt };
  }
  for (const n of names) {
    try {
      const r: unknown = JSON.parse(readText(join(quarantineDir(l), n)) ?? "");
      // A record filed under another id is damaged too: the prune and the decisions find a record by its id.
      if (!valid(r) || n !== `${r.id}.json`) throw new Error("bad record");
      records.push(r);
    } catch {
      corrupt.push(n);
    }
  }
  // valid() guarantees a string createdAt, so the sort cannot throw.
  records.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  return { records, corrupt };
}

/** FZ5: the record, or null when it is absent or damaged (as listRecords reports it); never throws. */
export function getRecord(l: Layout, id: string): QuarantineRecord | null {
  if (!ID.test(id)) return null;
  try {
    const t = readText(recordPath(l, id));
    if (t === null) return null;
    const r: unknown = JSON.parse(t);
    return valid(r) && r.id === id ? r : null;
  } catch {
    return null;
  }
}

/** The first 200 characters with control and invisible characters escaped (never executable text). */
export function previewOf(text: string): string {
  const flat = Array.from(text.replace(/\s+/g, " ").trim()).slice(0, 200).join("");
  return escapeForTerminal(flat);
}

/** Text shown to a person in a terminal: invisible and control characters escaped, so nothing hidden survives. */
export function escapeForTerminal(text: string): string {
  // eslint-disable-next-line no-control-regex -- control characters are what is being escaped
  return revealInvisible(text).replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

export interface NewMcpResult {
  session: string;
  client?: string;
  server?: string;
  tool?: string;
  signals: string[];
  /** The withheld text (kept for the person, cut at 1 MiB, removed after KEEP_DAYS). */
  text: string;
  now?: Date;
}

/** The MCP gateway's withheld result (kind mcp_result): sha256, size, an escaped preview and the text itself. */
export function addQuarantine(l: Layout, r: NewMcpResult): QuarantineRecord {
  const bytes = Buffer.from(r.text, "utf8");
  return saveRecord(
    l,
    {
      kind: "mcp_result",
      session: r.session,
      ...(r.client !== undefined ? { client: r.client } : {}),
      ...(r.server !== undefined ? { server: r.server } : {}),
      ...(r.tool !== undefined ? { tool: r.tool } : {}),
      signals: [...new Set(r.signals)],
      sha256: createHash("sha256").update(bytes).digest("hex"),
      size: bytes.length,
      preview: previewOf(r.text),
      body: bytes.length > MAX_BODY ? bytes.subarray(0, MAX_BODY).toString("utf8") : r.text,
    },
    r.now,
  ).record;
}

/**
 * Saves a withheld item. The same item (sha256) held for the same session reuses its record (Cursor sends
 * an MCP result to two hooks; an agent may read the same message twice). Returns the record and whether
 * it is new. Throws when the store cannot be written (the caller still withholds).
 */
export function saveRecord(l: Layout, rec: Omit<QuarantineRecord, "version" | "id" | "createdAt" | "status">, now = new Date()): { record: QuarantineRecord; created: boolean } {
  return withLock(lockPath(l), () => {
    const existing = listRecords(l).records.find((r) => r.status === "held" && r.session === rec.session && r.sha256 === rec.sha256 && r.kind === rec.kind);
    if (existing !== undefined) return { record: existing, created: false };
    const full: QuarantineRecord = { version: 1, id: newRecordId(), createdAt: now.toISOString(), status: "held", ...rec };
    if (full.body !== undefined && full.body.length > MAX_BODY) full.body = full.body.slice(0, MAX_BODY);
    atomicWrite(recordPath(l, full.id), JSON.stringify(full, null, 2));
    return { record: full, created: true };
  });
}

/** M5: how long a release lets the exact message through (the agent reads it again soon after the person releases it). */
export const RELEASE_TTL_MS = 7 * 86400000;

/** v2 (with `exp`) signs the expiry too; v1 (no `exp`) is what releases made before carry. */
export function releaseMessage(sha256: string, id: string, exp?: string): Buffer {
  if (exp !== undefined) return Buffer.from(JSON.stringify(["launchsafe-firewall/quarantine-release/v2", sha256, id, exp]), "utf8");
  return Buffer.from(`launchsafe-firewall/quarantine-release/v1\n${sha256}\n${id}`, "utf8");
}

export function signRelease(priv: KeyObject, sha256: string, id: string, exp?: string): string {
  return sign(null, releaseMessage(sha256, id, exp), priv).toString("base64");
}

export function verifyRelease(publicKeyB64: string, e: ReleasedEntry): boolean {
  if (e.sig === undefined) return false;
  try {
    const pub = createPublicKey({ key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki" });
    return verify(null, releaseMessage(e.sha256, e.id, e.exp), pub, Buffer.from(e.sig, "base64"));
  } catch {
    return false;
  }
}

/** When a release stops counting: its signed `exp`, or for a v1 entry its time plus the TTL. */
function releaseLapses(e: ReleasedEntry): number {
  const t = e.exp !== undefined ? Date.parse(e.exp) : Date.parse(e.at) + RELEASE_TTL_MS;
  return Number.isFinite(t) ? t : -Infinity;
}

function readReleased(l: Layout): ReleasedEntry[] {
  const t = readText(releasedPath(l));
  if (t === null) return [];
  const v: unknown = JSON.parse(t);
  const list = typeof v === "object" && v !== null && Array.isArray((v as { released?: unknown }).released) ? ((v as { released: unknown[] }).released) : [];
  return list.filter((e): e is ReleasedEntry => typeof e === "object" && e !== null && typeof (e as ReleasedEntry).sha256 === "string" && /^[0-9a-f]{64}$/.test((e as ReleasedEntry).sha256) && typeof (e as ReleasedEntry).id === "string" && typeof (e as ReleasedEntry).at === "string" && ((e as ReleasedEntry).exp === undefined || typeof (e as ReleasedEntry).exp === "string"));
}

/**
 * The sha256 values the person released, still within their time. With an approver key (the one pinned in the
 * hook command, else M5: the one set up on disk), only entries signed by it count. An unreadable file releases
 * nothing.
 */
export function releasedSet(l: Layout, approverKey: string | null, now = Date.now()): Set<string> {
  try {
    const key = approverKey ?? approverPublicKey(l);
    return new Set(
      readReleased(l)
        .filter((e) => (key === null || verifyRelease(key, e)) && now <= releaseLapses(e))
        .map((e) => e.sha256),
    );
  } catch {
    return new Set();
  }
}

/**
 * A person's decision on a held record. Release adds the sha256 to released.json (signed when `signer` is
 * given; the CLI requires it whenever an approver key is set). Discard closes the record: the item stays
 * withheld if it is read again.
 */
export function decideRecord(l: Layout, id: string, status: "released" | "discarded", signer?: (sha256: string, id: string, exp: string) => string, now = new Date()): QuarantineRecord {
  return withLock(lockPath(l), () => {
    const r = getRecord(l, id);
    if (r === null) throw new Error(`no quarantine record ${id}`);
    if (r.status !== "held") throw new Error(`quarantine record ${id} is already ${r.status}`);
    const done: QuarantineRecord = { ...r, status, decidedAt: now.toISOString() };
    if (status === "released") {
      let list: ReleasedEntry[] = [];
      try {
        list = readReleased(l);
      } catch {
        list = [];
      }
      // M5: a release lapses (its expiry is signed with it).
      const exp = new Date(now.getTime() + RELEASE_TTL_MS).toISOString();
      const entry: ReleasedEntry = { sha256: r.sha256, id: r.id, at: now.toISOString(), exp, ...(signer !== undefined ? { sig: signer(r.sha256, r.id, exp) } : {}) };
      atomicWrite(releasedPath(l), JSON.stringify({ version: 1, released: [...list.filter((e) => e.sha256 !== r.sha256), entry].slice(-5000) }, null, 2));
    }
    atomicWrite(recordPath(l, id), JSON.stringify(done, null, 2));
    return done;
  });
}

/** Held records (for status and the review list). */
export function heldCount(l: Layout, kind?: QuarantineRecord["kind"]): number {
  return listRecords(l).records.filter((r) => r.status === "held" && (kind === undefined || r.kind === kind)).length;
}

/** Removes decided records older than `days`, and withheld MCP text older than `days` from held ones. */
export function pruneQuarantine(l: Layout, days = KEEP_DAYS, now = Date.now()): number {
  let n = 0;
  for (const r of listRecords(l).records) {
    const age = now - Date.parse(r.decidedAt ?? r.createdAt);
    if (age <= days * 86400000) continue;
    try {
      if (r.status !== "held") {
        unlinkSync(recordPath(l, r.id));
        n++;
      } else if (r.body !== undefined) {
        const { body: _drop, ...rest } = r;
        void _drop;
        atomicWrite(recordPath(l, r.id), JSON.stringify(rest, null, 2));
      }
    } catch {
      // Already gone, or unwritable: doctor reports the store.
    }
  }
  return n;
}

/** Whether the store can be written (doctor; checks permissions, writes nothing). */
export function quarantineCheck(l: Layout): { status: "ok" | "warn" | "fail"; detail: string } {
  const dir = quarantineDir(l);
  const { records, corrupt } = listRecords(l);
  const held = records.filter((r) => r.status === "held").length;
  const target = existsSync(dir) ? dir : existsSync(l.home) ? l.home : null;
  if (target === null) return { status: "ok", detail: "no messages withheld yet (the store is created on first use)" };
  try {
    accessSync(target, constants.W_OK);
  } catch {
    return { status: "fail", detail: `${dir} cannot be written: withheld messages are still withheld, but cannot be recorded, reviewed or released` };
  }
  if (corrupt.length > 0) return { status: "warn", detail: `unreadable records: ${corrupt.join(", ")}` };
  return { status: "ok", detail: `${held} ${held === 1 ? "item" : "items"} withheld, waiting for review` };
}
