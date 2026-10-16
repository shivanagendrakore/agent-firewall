/**
 * The decision log: JSON lines, each entry chained to the one before by
 * SHA-256 and signed with a local Ed25519 key. Files rotate at a size limit;
 * the chain carries across files, and when old files are pruned their last
 * hash is kept as a signed anchor, so `log verify` still proves nothing in
 * the remaining files was changed, removed or reordered.
 */

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import { closeSync, fstatSync, openSync, readdirSync, readSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson } from "../engine/decide.js";
import { LogRefused } from "../engine/log-bound.js";
import { redactSecrets } from "../engine/secrets.js";
import { strictParse } from "../logbundle/verify.js";
import { extraEntryFields, extraFieldsProblem } from "../sdk/log.js";
import { hasOwn, own, setOwn } from "../own.js";
import { testMarker } from "./guard.js";
import { appendDurable, atomicWrite, ensureDir, parseJsonFile, readText, tryReadText, fsyncDir, withLock, withLockReplacing } from "./fsutil.js";
import type { Layout } from "./layout.js";

export const GENESIS = "0".repeat(64);
export const MAX_LOG_BYTES = 5 * 1024 * 1024;
export const MAX_ARCHIVES = 20;

export interface LogEntry {
  seq: number;
  ts: string;
  prev: string;
  event: Record<string, unknown>;
  hash: string;
  sig: string;
  /**
   * Written by v0.3 and later: "signed", and then `sig` covers `entry:<hash>:heads-signed` instead of the
   * hash bytes. Its presence is the signed record that heads are signed from here on, so an unsigned head
   * (its signature stripped) fails `log verify`; removing the field breaks the entry's signature.
   */
  heads?: "signed";
}

export interface Head {
  seq: number;
  hash: string;
  sig?: string;
}

export interface Anchor {
  seq: number;
  hash: string;
  sig: string;
  /** As on an entry: heads were signed by the time of the pruned files (`sig` then covers `anchor:<seq>:<hash>:heads-signed`). */
  heads?: "signed";
}

/** What an entry's signature covers: the hash bytes (v0.2), or with `heads: "signed"` the hash and that flag. */
function entrySigned(hash: string, heads: unknown): Buffer {
  return heads === "signed" ? Buffer.from(`entry:${hash}:heads-signed`) : Buffer.from(hash, "hex");
}

/** What an anchor's signature covers, the same way. */
function anchorSigned(seq: number, hash: string, heads: unknown): Buffer {
  return Buffer.from(heads === "signed" ? `anchor:${seq}:${hash}:heads-signed` : `anchor:${seq}:${hash}`);
}

function keyPaths(l: Layout): { priv: string; pub: string } {
  return { priv: join(l.keys, "log-ed25519.pem"), pub: join(l.keys, "log-ed25519.pub.pem") };
}

/**
 * Loads the signing key, creating it on first use. Creation happens once, under a lock, and the
 * public half is always derived from the private half, so concurrent first runs (several sessions
 * starting at once) cannot leave a public key that belongs to a different private key.
 */
export function loadKey(l: Layout, create = true): { priv: KeyObject; pub: KeyObject } | null {
  const p = keyPaths(l);
  const read = (): { priv: KeyObject; pub: KeyObject } | null => {
    const privPem = readText(p.priv);
    if (privPem === null) return null;
    const priv = createPrivateKey(privPem);
    return { priv, pub: createPublicKey(priv) };
  };
  const existing = read();
  if (!create) return existing;
  if (existing !== null) {
    // The two halves are two writes: a crash or a full disk between them leaves the private key without its public half. Derive it again.
    if (readText(p.pub) === null) {
      try {
        withLock(join(l.keys, "key.lock"), () => {
          if (readText(p.pub) === null) atomicWrite(p.pub, existing.pub.export({ type: "spki", format: "pem" }) as string, 0o644);
        });
      } catch {
        // The signing key is usable; keyPairConsistent and doctor report the missing half.
      }
    }
    return existing;
  }
  ensureDir(l.keys);
  return withLock(join(l.keys, "key.lock"), () => {
    const again = read();
    if (again !== null) return again;
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    atomicWrite(p.priv, privateKey.export({ type: "pkcs8", format: "pem" }) as string, 0o600);
    atomicWrite(p.pub, publicKey.export({ type: "spki", format: "pem" }) as string, 0o644);
    return { priv: privateKey, pub: publicKey };
  });
}

/** Whether the stored public key is the public half of the stored private key (false when either is damaged). */
export function keyPairConsistent(l: Layout): boolean {
  try {
    return keyPairConsistentInner(l);
  } catch {
    return false;
  }
}

function keyPairConsistentInner(l: Layout): boolean {
  const p = keyPaths(l);
  const privPem = readText(p.priv);
  const pubPem = readText(p.pub);
  if (privPem === null || pubPem === null) return privPem === null && pubPem === null;
  const derived = createPublicKey(createPrivateKey(privPem)).export({ type: "spki", format: "pem" }) as string;
  return derived.trim() === pubPem.trim();
}

/** The hash an entry must carry (exported for the dashboard's cheap head check, src/ui/logindex.ts). */
export function entryHash(prev: string, seq: number, ts: string, event: Record<string, unknown>): string {
  return createHash("sha256").update(`${prev}\n${seq}\n${ts}\n${canonicalJson(event)}`).digest("hex");
}

function currentFile(l: Layout): string {
  return join(l.log, "decisions.jsonl");
}

function archives(l: Layout): string[] {
  try {
    return readdirSync(l.log)
      .filter((n) => /^decisions-\d{8}\.jsonl$/.test(n))
      .sort();
  } catch {
    return [];
  }
}

function readHead(l: Layout): Head {
  const t = readText(join(l.log, "head.json"));
  if (t === null) return { seq: 0, hash: GENESIS };
  const h = parseJsonFile(join(l.log, "head.json"), t) as Head;
  if (typeof h !== "object" || h === null || typeof h.seq !== "number" || typeof h.hash !== "string" || (h.sig !== undefined && typeof h.sig !== "string")) throw new Error("log head is corrupt");
  return h;
}

/** How much of a log file's end is read first to find its last entry (an entry is a few hundred bytes to a few KB). */
const TAIL_BYTES = 64 * 1024;

/**
 * SR4: the largest event appendLog accepts (its canonical JSON). The hook's own events are a few KB (every
 * free-text field is sliced); the cap is for the library's appendLog, so the backward search below always
 * reaches a complete entry well inside its bound.
 */
export const MAX_EVENT_BYTES = 256 * 1024;

/**
 * SR4: how far back from the end the last complete entry is looked for (doubling from TAIL_BYTES). Past
 * this, appendLog refuses to append instead of guessing where the chain ends (which could fork it).
 */
export const MAX_TAIL_SEARCH = 4 * MAX_EVENT_BYTES;

interface Tail {
  /** The last complete entry whose hash matches its content, or null (no entries, or none in the file). */
  last: Head | null;
  /** The file's size in bytes (0 when it does not exist). */
  size: number;
  /** Whether the file exists (an append to a missing one creates it, so the directory is fsynced: SR5). */
  exists: boolean;
  /** The file is not empty and its last byte is not a newline: a write was cut off by a crash. */
  torn: boolean;
  /** SR4: no complete entry within MAX_TAIL_SEARCH of the end, and the file goes on before that. */
  unsearchable: boolean;
}

/** Bytes [from, from + len) of an open file. */
function readAt(fd: number, from: number, len: number): Buffer {
  const buf = Buffer.alloc(len);
  let got = 0;
  while (got < len) {
    const n = readSync(fd, buf, got, len - got, from + got);
    if (n === 0) break;
    got += n;
  }
  return buf.subarray(0, got);
}

/** A log line's chain position, if it is an entry whose hash matches its content. */
function entryOf(line: string): Head | null {
  try {
    const e = JSON.parse(line) as unknown;
    if (!isEntry(e) || entryHash(e.prev, e.seq, e.ts, e.event) !== e.hash) return null;
    return { seq: e.seq, hash: e.hash };
  } catch {
    return null;
  }
}

/**
 * The end of a log file: its last complete entry as written (not trusted beyond its own hash), and whether
 * a line was cut off. SR4: reads backwards in growing windows until a complete line parses as an entry, so
 * the size of the last entry does not matter, up to MAX_TAIL_SEARCH; lines that are not entries (damage,
 * which `log verify` reports) are passed over.
 */
function readTail(path: string): Tail {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return { last: null, size: 0, exists: false, torn: false, unsearchable: false };
    throw e;
  }
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return { last: null, size, exists: true, torn: false, unsearchable: false };
    const torn = readAt(fd, size - 1, 1)[0] !== 0x0a;
    for (let window = Math.min(size, TAIL_BYTES); ; window = Math.min(size, window * 2, MAX_TAIL_SEARCH)) {
      const text = readAt(fd, size - window, window).toString("utf8");
      const parts = text.split("\n");
      // A cut-off last line is not an entry (the entry before it is the end of the chain); nor is the first
      // piece of a window that starts inside the file, which may begin mid-line.
      const lines = parts.slice(window < size ? 1 : 0, torn ? -1 : undefined);
      for (let i = lines.length - 1; i >= 0; i--) {
        const line = lines[i] as string;
        if (line.trim() === "") continue;
        const last = entryOf(line);
        if (last !== null) return { last, size, exists: true, torn, unsearchable: false };
      }
      if (window >= size) return { last: null, size, exists: true, torn, unsearchable: false };
      if (window >= MAX_TAIL_SEARCH) return { last: null, size, exists: true, torn, unsearchable: true };
    }
  } finally {
    closeSync(fd);
  }
}

/**
 * appendLog refused an event before writing anything: it is too large or not plain JSON, or the log's last
 * entry cannot be found (SR4). Distinct from an I/O failure (a full disk), which callers treat differently
 * (LG1: src/runtime/logbound.ts). Defined in the browser-safe src/engine/log-bound.ts, so the library's
 * stores can throw the same refusal.
 */
export { LogRefused };

const UNSEARCHABLE = `the decision log's last entry is not within the last ${MAX_TAIL_SEARCH} bytes of its newest file, so where its chain ends is unknown.`;

/**
 * Where the next entry chains from, under the log lock. The log's own last entry is the truth (it was
 * fsynced before its hook returned); head.json is written after it without an fsync, so after a power cut
 * it can be behind by the entries made since its last update reached the disk, or unreadable. Then the
 * chain continues from the last entry on disk (never forked from an old head), the head is rewritten, and
 * the recovery is itself logged. A head ahead of the log is entries removed from the end: as before, the
 * chain continues from the head and `log verify` reports the gap.
 */
function chainBase(l: Layout): { base: Head; tail: Tail; recovered: { head: Head | null; why: string } | null } {
  let tail = readTail(currentFile(l));
  // Just after a rotation the current file is empty, or (LG3) holds no complete entry yet: a crash cut its
  // first write, or only damage is in it. Its predecessor then holds the last entry, so recovery continues
  // from there across files. The current file's own size, existence and torn end still decide how this
  // append is written.
  if (tail.last === null && !tail.unsearchable) {
    const list = archives(l);
    const prev = list[list.length - 1];
    if (prev !== undefined) {
      const before = readTail(join(l.log, prev));
      tail = { ...tail, last: before.last, unsearchable: before.unsearchable };
    }
  }
  // SR4: fail closed. Without the last entry the chain could fork from an old head; nothing is appended.
  if (tail.unsearchable) throw new LogRefused("unsearchable", `${UNSEARCHABLE} Nothing was appended; run "launchsafe-firewall log verify"`);
  let head: Head | null = null;
  let headError: Error | null = null;
  try {
    head = readText(join(l.log, "head.json")) === null ? null : readHead(l);
  } catch (e) {
    headError = e as Error;
  }
  const last = tail.last;
  if (last === null) {
    if (headError !== null) throw headError;
    return { base: head ?? { seq: 0, hash: GENESIS }, tail, recovered: null };
  }
  if (head !== null && head.seq >= last.seq) return { base: head, tail, recovered: null };
  const why = headError !== null ? "unreadable" : head === null ? "missing" : "behind the log";
  return { base: last, tail, recovered: { head, why } };
}

function signedEntry(prev: Head, event: Record<string, unknown>, priv: KeyObject): LogEntry {
  const seq = prev.seq + 1;
  const ts = new Date().toISOString();
  const hash = entryHash(prev.hash, seq, ts, event);
  const sig = sign(null, entrySigned(hash, "signed"), priv).toString("base64");
  return { seq, ts, prev: prev.hash, event, hash, sig, heads: "signed" };
}

/** The head's signature: over `head:${seq}:${hash}`, so a head cannot be moved to another entry without the key. */
function signHead(seq: number, hash: string, priv: KeyObject): string {
  return sign(null, Buffer.from(`head:${seq}:${hash}`), priv).toString("base64");
}

/**
 * Appends a signed entry. Rotates and prunes under the same lock. One fsync: the entry itself, before
 * this returns (so before the tool it decides runs). head.json is then replaced atomically without an
 * fsync, by renaming the lock file over it; it is rebuilt from the log if a power cut leaves it behind
 * (chainBase, docs/design.md "Runtime: durability and concurrency").
 */
/** I5: kept free on the log's disk and deleted when an append finds the disk full, so that append (and the gap's record) still fits. */
export const RESERVE_BYTES = 1024 * 1024;

function reservePath(l: Layout): string {
  return join(l.log, "reserve.bin");
}

function unloggedPath(l: Layout): string {
  return join(l.log, "unlogged.json");
}

function prunedPath(l: Layout): string {
  return join(l.log, "pruned.json");
}

/** I5: events that could not be logged since the last entry (the next entry records them as a log_gap). */
export interface Unlogged {
  count: number;
  first: string;
  last: string;
  types: Record<string, number>;
  /** The last error (its code, as "ENOSPC"). */
  error: string;
}

/** I6: pruned archives not yet recorded in the log (the next entry records each as a log_pruned). */
interface PrunedNote {
  file: string;
  lastSeq: number;
  lastHash: string;
  at: string;
  /** No log_export or log_anchor covered its entries when it was pruned. */
  unexported: boolean;
}

/** The write the log makes (tests replace it to simulate a full disk). */
let writeEntries: (path: string, text: string) => void = appendDurable;

/** Tests: replaces the durable append the log uses (null restores it). */
export function _setLogWriterForTest(f: ((path: string, text: string) => void) | null): void {
  writeEntries = f ?? appendDurable;
}

function readJson<T>(path: string): T | null {
  try {
    const t = readText(path);
    return t === null ? null : (JSON.parse(t) as T);
  } catch {
    return null;
  }
}

/** The unlogged count, or null (none, or the counters file is unreadable: then a zero is never assumed by doctor). */
export function readUnlogged(l: Layout): Unlogged | null {
  const u = readJson<Unlogged>(unloggedPath(l));
  return u !== null && typeof u === "object" && typeof u.count === "number" && u.count > 0 ? u : null;
}

/** I5: counts one event that could not be logged (best effort: on a full disk the freed reserve leaves room). */
function noteUnlogged(l: Layout, event: Record<string, unknown>, e: unknown): void {
  try {
    withLock(join(l.log, "unlogged.lock"), () => {
      const now = new Date().toISOString();
      const u: Unlogged = readUnlogged(l) ?? { count: 0, first: now, last: now, types: {}, error: "" };
      const t = typeof event.type === "string" ? event.type.slice(0, 64) : "unknown";
      u.count += 1;
      u.last = now;
      if (Object.keys(u.types).length < 32 || hasOwn(u.types, t)) setOwn(u.types, t, (own(u.types, t) ?? 0) + 1);
      u.error = String((e as NodeJS.ErrnoException).code ?? (e as Error).message ?? e).slice(0, 200);
      atomicWrite(unloggedPath(l), JSON.stringify(u));
    });
  } catch {
    // Nothing more can be written; the gap shows as missing sequence-free time in the log.
  }
}

/** Makes sure the reserve exists (after a successful append; skipped when it cannot be written). */
function keepReserve(l: Layout): void {
  try {
    if (statSync(reservePath(l), { throwIfNoEntry: false }) !== undefined) return;
    // Under the test marker the reserve is 4 KiB: thousands of test homes on a memory-backed disk would otherwise
    // hold a mebibyte each (the behaviour, release on ENOSPC and retry, is the same).
    writeFileSync(reservePath(l), Buffer.alloc(testMarker() ? 4096 : RESERVE_BYTES), { mode: 0o600 });
  } catch {
    // Still full: the next successful append tries again.
    try {
      unlinkSync(reservePath(l));
    } catch {
      // Not there.
    }
  }
}

function releaseReserve(l: Layout): boolean {
  try {
    unlinkSync(reservePath(l));
    return true;
  } catch {
    return false;
  }
}

/**
 * M6: the free text a decision entry carries about what the agent did (`what`, and a spawned agent's prompt
 * preview) is logged with credentials redacted and URL query strings removed, whatever wrote the event.
 */
function scrubText(s: string): string {
  return redactSecrets(s).text.replace(/\b([a-z][a-z0-9+.-]*:\/\/[^\s?#'"`<>]*)\?[^\s#'"`<>]*/gi, "$1?…");
}

function scrubEvent(event: Record<string, unknown>): Record<string, unknown> {
  let out = event;
  if (typeof event.what === "string") {
    const w = scrubText(event.what);
    if (w !== event.what) out = { ...out, what: w };
  }
  const sp = event.spawned_prompt;
  if (typeof sp === "object" && sp !== null && !Array.isArray(sp) && typeof (sp as Record<string, unknown>).preview === "string") {
    const p = (sp as Record<string, unknown>).preview as string;
    const q = scrubText(p);
    if (q !== p) out = { ...out, spawned_prompt: { ...(sp as Record<string, unknown>), preview: q } };
  }
  return out;
}

export function appendLog(l: Layout, event: Record<string, unknown>, o: { keepUnexported?: boolean } = {}): LogEntry {
  // LG2: one serialization is measured, hashed and written. The event is reduced to its canonical JSON first
  // (canonicalJson never calls toJSON, and drops what JSON cannot hold the same way every time), and the entry
  // carries that parsed copy, so the line on disk re-hashes to exactly what was signed.
  let canonical: string;
  try {
    canonical = canonicalJson(scrubEvent(event));
  } catch (e) {
    throw new LogRefused("unserializable", `a decision log event must be plain JSON data; this one could not be serialized (${(e as Error).message}). Nothing was appended`);
  }
  // SR4: checked before anything is written.
  const bytes = Buffer.byteLength(canonical);
  if (bytes > MAX_EVENT_BYTES) throw new LogRefused("size", `a decision log event must be at most ${MAX_EVENT_BYTES} bytes as JSON; this one is ${bytes} (log a summary or a hash of large data instead)`);
  const stored = JSON.parse(canonical) as Record<string, unknown>;
  if (typeof stored !== "object" || stored === null || Array.isArray(stored)) throw new LogRefused("unserializable", "a decision log event must be a JSON object. Nothing was appended");
  try {
    return appendStored(l, stored, null, o);
  } catch (e) {
    if (e instanceof LogRefused) throw e;
    // I5: a full disk. The reserve is given up and the append tried once more, noting that it was needed.
    if ((e as NodeJS.ErrnoException).code === "ENOSPC" && releaseReserve(l)) {
      try {
        return appendStored(l, stored, { type: "log_disk_full", reserve: "released" }, o);
      } catch (again) {
        noteUnlogged(l, stored, again);
        throw again;
      }
    }
    noteUnlogged(l, stored, e);
    throw e;
  }
}

function appendStored(l: Layout, stored: Record<string, unknown>, note: Record<string, unknown> | null, o: { keepUnexported?: boolean }): LogEntry {
  const key = loadKey(l);
  if (key === null) throw new Error("no log key");
  ensureDir(l.log);
  let wrote = false;
  // The lock file is given the new head and renamed over head.json to release the lock (withLockReplacing).
  const entry = withLockReplacing(join(l.log, "log.lock"), join(l.log, "head.json"), () => {
    const { base, tail, recovered } = chainBase(l);
    const lines: LogEntry[] = [];
    const push = (ev: Record<string, unknown>): LogEntry => {
      const e = signedEntry(lines[lines.length - 1] ?? base, JSON.parse(canonicalJson(ev)) as Record<string, unknown>, key.priv);
      lines.push(e);
      return e;
    };
    if (recovered !== null) push({ type: "log_head_recovered", why: recovered.why, head: recovered.head, last: base });
    // I5/I6: what happened to the log since the last entry: decisions it could not record, archives pruned.
    const gap = readUnlogged(l);
    if (gap !== null) push({ type: "log_gap", unlogged: gap.count, first: gap.first, last: gap.last, types: gap.types, error: gap.error });
    const pruned = readJson<PrunedNote[]>(prunedPath(l));
    // A damaged notes file is recorded as such, never a reason to refuse the entry (it is cleared after this write).
    if (Array.isArray(pruned)) {
      for (const p of pruned.slice(0, 50) as unknown[]) {
        const x = (typeof p === "object" && p !== null ? p : {}) as Partial<PrunedNote>;
        push({ type: "log_pruned", file: typeof x.file === "string" ? x.file.slice(0, 64) : "unknown", lastSeq: typeof x.lastSeq === "number" ? x.lastSeq : null, lastHash: typeof x.lastHash === "string" ? x.lastHash.slice(0, 64) : null, at: typeof x.at === "string" ? x.at.slice(0, 40) : null, unexported: x.unexported !== false });
      }
    } else if (pruned !== null) push({ type: "log_pruned", file: "unknown", note: "the notes of pruned files were damaged" });
    if (note !== null) push(note);
    const made = signedEntry(lines[lines.length - 1] ?? base, stored, key.priv);
    lines.push(made);
    // A line cut off by a crash stays on a line of its own (log verify reports it), never glued to this entry.
    const text = `${tail.torn ? "\n" : ""}${lines.map((e) => JSON.stringify(e)).join("\n")}\n`;
    writeEntries(currentFile(l), text);
    wrote = true;
    // Recorded: the notes are cleared (under the log lock; a count added since is kept for the next entry).
    if (gap !== null) clearUnlogged(l, gap.count);
    if (pruned !== null) unlinkQuiet(prunedPath(l));
    // SR5: a new decisions.jsonl's name must be durable too, or the fsynced entry can vanish with it.
    if (!tail.exists) fsyncDir(l.log);
    // The entries are durable: a failing rotation or prune (a full disk, a locked archive) must not report the append as failed,
    // which would record a false gap and, on a full disk, append the event twice. The next append rotates again.
    try {
      rotateIfNeeded(l, key.priv, MAX_LOG_BYTES, MAX_ARCHIVES, tail.size + Buffer.byteLength(text), o.keepUnexported === true);
    } catch {
      // Best effort.
    }
    // FZ6: the head is signed too, so a head rewritten to match a shortened log is caught (an unsigned head, as
    // v0.2 wrote it, is still read: see verifyLog).
    return { result: made, content: JSON.stringify({ seq: made.seq, hash: made.hash, sig: signHead(made.seq, made.hash, key.priv) }) };
  });
  if (wrote) keepReserve(l);
  return entry;
}

function unlinkQuiet(p: string): void {
  try {
    unlinkSync(p);
  } catch {
    // Already gone.
  }
}

function clearUnlogged(l: Layout, recorded: number): void {
  try {
    withLock(join(l.log, "unlogged.lock"), () => {
      const now = readUnlogged(l);
      if (now === null || now.count <= recorded) unlinkQuiet(unloggedPath(l));
      else atomicWrite(unloggedPath(l), JSON.stringify({ ...now, count: now.count - recorded }));
    });
  } catch {
    // The count stays; the next entry records it again (an overcount, never a hidden gap).
  }
}

function exportedPath(l: Layout): string {
  return join(l.log, "exported.json");
}

/**
 * I6: `log export` notes the last sequence number it took off the machine (best effort). Unsigned: it only
 * decides whether a pruned file is reported as exported and, with keepUnexported, kept.
 */
export function noteLogExported(l: Layout, lastSeq: number): void {
  try {
    withLock(join(l.log, "unlogged.lock"), () => {
      const cur = readJson<{ lastSeq?: unknown }>(exportedPath(l));
      const prev = typeof cur?.lastSeq === "number" ? cur.lastSeq : 0;
      if (lastSeq > prev) atomicWrite(exportedPath(l), JSON.stringify({ lastSeq, at: new Date().toISOString() }));
    });
  } catch {
    // Not noted: a later prune reports those files as not exported (stricter).
  }
}

/** The highest sequence number an export (exported.json) or a log_anchor entry says was taken off the machine (0: none). */
function exportedThrough(l: Layout): number {
  const ex = readJson<{ lastSeq?: unknown }>(exportedPath(l));
  let best = typeof ex?.lastSeq === "number" ? ex.lastSeq : 0;
  for (const f of [...archives(l), "decisions.jsonl"]) {
    const t = tryReadText(join(l.log, f));
    if (typeof t !== "string") continue;
    for (const line of t.split("\n")) {
      if (!line.includes('"log_export"') && !line.includes('"log_anchor"')) continue;
      try {
        const e = JSON.parse(line) as { event?: { type?: unknown; seq?: unknown; lastSeq?: unknown } };
        const s = e.event?.type === "log_anchor" ? e.event.seq : e.event?.type === "log_export" ? e.event.lastSeq : undefined;
        if (typeof s === "number" && s > best) best = s;
      } catch {
        // verify reports it.
      }
    }
  }
  return best;
}

function rotateIfNeeded(l: Layout, priv: KeyObject, maxBytes = MAX_LOG_BYTES, maxArchives = MAX_ARCHIVES, knownSize?: number, keepUnexported = false): void {
  let size = knownSize ?? 0;
  if (knownSize === undefined) {
    try {
      size = statSync(currentFile(l)).size;
    } catch {
      return;
    }
  }
  if (size < maxBytes) return;
  const existing = archives(l);
  const next = existing.length === 0 ? 1 : Number(/(\d{8})/.exec(existing[existing.length - 1] as string)?.[1] ?? "0") + 1;
  renameSync(currentFile(l), join(l.log, `decisions-${String(next).padStart(8, "0")}.jsonl`));
  // SR5: the rename is durable before anything depends on the archive's name (pruning, the next append).
  fsyncDir(l.log);
  pruneArchives(l, priv, maxArchives, keepUnexported);
}

/**
 * Drops the oldest archives beyond the limit, keeping a signed anchor of where the kept chain starts. I6:
 * each pruned file is noted (pruned.json) and recorded as a log_pruned entry by the next append, saying
 * whether a log_export or log_anchor had covered its entries; with `keepUnexported`, a file no export or
 * anchor covered is kept (the log then grows past the limit until one does; doctor says so).
 */
function pruneArchives(l: Layout, priv: KeyObject, maxArchives: number, keepUnexported = false): void {
  const list = archives(l);
  let covered: number | null = null;
  const prior: unknown = readJson<unknown>(prunedPath(l));
  const notes: PrunedNote[] = Array.isArray(prior) ? (prior as PrunedNote[]) : [];
  while (list.length > maxArchives) {
    const oldest = list.shift() as string;
    const lines = (readText(join(l.log, oldest)) ?? "").trim().split("\n").filter((x) => x !== "");
    const last = lines.length > 0 ? (JSON.parse(lines[lines.length - 1] as string) as LogEntry) : null;
    covered ??= exportedThrough(l);
    const unexported = last !== null && last.seq > covered;
    if (unexported && keepUnexported) break;
    if (last !== null) {
      // Once the pruned files hold an entry written with signed heads, the anchor carries that.
      const heads = last.heads === "signed" ? "signed" : undefined;
      const sig = sign(null, anchorSigned(last.seq, last.hash, heads), priv).toString("base64");
      atomicWrite(join(l.log, "anchor.json"), JSON.stringify({ seq: last.seq, hash: last.hash, sig, ...(heads !== undefined ? { heads } : {}) }));
    }
    notes.push({ file: oldest, lastSeq: last?.seq ?? 0, lastHash: last?.hash ?? "", at: new Date().toISOString(), unexported });
    atomicWrite(prunedPath(l), JSON.stringify(notes));
    unlinkSync(join(l.log, oldest));
  }
}

/** For tests and `log rotate`: force a rotation now. */
export function rotateNow(l: Layout, maxArchives = MAX_ARCHIVES, keepUnexported = false): void {
  const key = loadKey(l);
  if (key === null) return;
  withLock(join(l.log, "log.lock"), () => rotateIfNeeded(l, key.priv, 0, maxArchives, undefined, keepUnexported));
}

/**
 * I5/I6 for doctor: decisions not logged since the last entry, gaps and prunes the log records, and archives
 * kept past the limit because nothing exported them. Warnings only: `log verify` judges the chain.
 */
export function logHealthChecks(l: Layout): { name: string; status: "ok" | "warn" | "fail"; detail: string }[] {
  const out: { name: string; status: "ok" | "warn" | "fail"; detail: string }[] = [];
  const u = readUnlogged(l);
  if (u !== null) out.push({ name: "decision log gaps", status: "warn", detail: `${u.count} event(s) could not be logged between ${u.first} and ${u.last} (${u.error}); the next entry records the gap. Free disk space for ${l.log}` });
  let gaps = 0;
  let missed = 0;
  let pruned = 0;
  let unexported = 0;
  for (const e of tailLog(l, 100000)) {
    const ev = e.event as { type?: unknown; unlogged?: unknown; unexported?: unknown } | undefined;
    if (ev?.type === "log_gap") {
      gaps++;
      missed += typeof ev.unlogged === "number" ? ev.unlogged : 0;
    } else if (ev?.type === "log_pruned") {
      pruned++;
      if (ev.unexported === true) unexported++;
    }
  }
  if (gaps > 0) out.push({ name: "decision log gaps", status: "warn", detail: `the log records ${gaps} gap(s): ${missed} event(s) were not logged (the disk was full or the log could not be written)` });
  if (pruned > 0) out.push({ name: "decision log pruning", status: unexported > 0 ? "warn" : "ok", detail: `${pruned} old log file(s) were pruned${unexported > 0 ? `, ${unexported} of them before any "log export" or "log anchor" covered their entries (those entries are gone)` : ""}. Export or anchor the log regularly: launchsafe-firewall log export --out FILE` });
  if (archives(l).length > MAX_ARCHIVES) out.push({ name: "decision log pruning", status: "warn", detail: `${archives(l).length} log files are kept (more than ${MAX_ARCHIVES}) because their entries were never exported or anchored; run "launchsafe-firewall log export" or "log anchor"` });
  return out;
}

export interface VerifyResult {
  ok: boolean;
  entries: number;
  files: number;
  problems: string[];
}

/**
 * A signature's bytes, only from canonical base64: Buffer.from skips characters that are not base64, so a
 * signature with junk inserted would otherwise still verify and the edit go unnoticed.
 */
function sigBytes(sig: string): Buffer {
  const b = Buffer.from(sig, "base64");
  return b.toString("base64") === sig ? b : Buffer.alloc(0);
}

/** Whether a parsed log line has the shape of an entry (FZ4: `null`, a number or a partial object is damage, not a crash). */
/** FZ19: an entry has only its own fields (src/sdk/log.ts ENTRY_FIELDS); verifyLog names extra ones separately. */
function isEntry(v: unknown): v is LogEntry {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const e = v as Record<string, unknown>;
  if (extraEntryFields(e).length > 0) return false;
  return typeof e.seq === "number" && typeof e.ts === "string" && typeof e.prev === "string" && typeof e.hash === "string" && typeof e.sig === "string" && typeof e.event === "object" && e.event !== null && !Array.isArray(e.event) && (e.heads === undefined || e.heads === "signed");
}

/**
 * Checks every remaining entry: chain links, hashes, signatures, sequence numbers, and the head. Never throws
 * (FZ4): a damaged key, anchor, head or line is reported as a problem and the result is not ok.
 */
export function verifyLog(l: Layout): VerifyResult {
  try {
    return verifyLogInner(l);
  } catch (e) {
    return { ok: false, entries: 0, files: 0, problems: [`the log could not be checked: ${(e as Error).message}`] };
  }
}

function verifyLogInner(l: Layout): VerifyResult {
  const problems: string[] = [];
  const pubPem = readText(keyPaths(l).pub);
  if (pubPem === null) return { ok: archives(l).length === 0 && readText(currentFile(l)) === null && readText(join(l.log, "head.json")) === null, entries: 0, files: 0, problems: ["no log key yet"] };
  let pub: KeyObject;
  try {
    pub = createPublicKey(pubPem);
  } catch {
    return { ok: false, entries: 0, files: 0, problems: ["the log's public key file is damaged, so no entry can be checked"] };
  }
  let head: Head | null = null;
  let headError: string | null = null;
  try {
    head = readText(join(l.log, "head.json")) === null ? null : readHead(l);
  } catch (e) {
    headError = (e as Error).message;
  }
  /** The hash of the entry with the head's sequence number, once the walk reaches it. */
  let atHead: string | null = null;
  /** The first sequence number from which the signed record says heads are signed (null: a v0.2 log). */
  let signedHeadsSince: number | null = null;
  let prev = GENESIS;
  let expectSeq = 1;
  const anchorText = readText(join(l.log, "anchor.json"));
  if (anchorText !== null) {
    let a: Partial<Anchor> | null = null;
    try {
      a = JSON.parse(anchorText) as Partial<Anchor> | null;
    } catch {
      a = null;
    }
    if (typeof a !== "object" || a === null || typeof a.seq !== "number" || typeof a.hash !== "string" || typeof a.sig !== "string") problems.push("the anchor of pruned log files is damaged");
    else {
      if (a.heads !== undefined && a.heads !== "signed") problems.push("the anchor of pruned log files is damaged");
      else if (!verify(null, anchorSigned(a.seq, a.hash, a.heads), pub, sigBytes(a.sig))) problems.push("the anchor of pruned log files has a bad signature");
      else if (a.heads === "signed") signedHeadsSince = a.seq;
      prev = a.hash;
      expectSeq = a.seq + 1;
      // A head left behind at the point where the pruned files ended names the anchor's entry.
      if (head !== null && head.seq === a.seq) atHead = a.hash;
    }
  }
  const files = [...archives(l), "decisions.jsonl"].filter((f) => readText(join(l.log, f)) !== null);
  let entries = 0;
  for (const f of files) {
    const lines = (readText(join(l.log, f)) ?? "").split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] as string;
      if (line.trim() === "") continue;
      // M2: as strictly as a bundle line (the firewall writes every line with JSON.stringify): a duplicate key,
      // another spelling of a number or extra spacing is an edit two JSON readers could read differently.
      const parsed = strictParse(line);
      if (!parsed.ok) {
        problems.push(`${f} line ${i + 1}: ${parsed.why}`);
        continue;
      }
      const v = parsed.v;
      if (!isEntry(v)) {
        const extra = typeof v === "object" && v !== null && !Array.isArray(v) ? extraEntryFields(v) : [];
        problems.push(extra.length > 0 ? extraFieldsProblem(`${f} line ${i + 1}`, extra) : `${f} line ${i + 1}: not a log entry`);
        continue;
      }
      const e = v;
      entries++;
      if (e.seq !== expectSeq) problems.push(`${f} line ${i + 1}: sequence ${e.seq}, expected ${expectSeq} (entries missing or reordered)`);
      if (e.prev !== prev) problems.push(`${f} line ${i + 1}: does not link to the entry before it`);
      const h = entryHash(e.prev, e.seq, e.ts, e.event);
      if (h !== e.hash) problems.push(`${f} line ${i + 1}: content does not match its hash (edited)`);
      else if (!verify(null, entrySigned(e.hash, e.heads), pub, sigBytes(e.sig))) problems.push(`${f} line ${i + 1}: bad signature`);
      else if (e.heads === "signed" && signedHeadsSince === null) signedHeadsSince = e.seq;
      if (head !== null && e.seq === head.seq) atHead = e.hash;
      prev = e.hash;
      expectSeq = e.seq + 1;
    }
  }
  const lastSeq = expectSeq - 1;
  if (headError !== null) problems.push(headError);
  else if (head === null) {
    // FZ6: compared whether or not entries remain (an anchor alone still records a chain).
    if (lastSeq > 0) problems.push(entries > 0 ? "the log has entries but no recorded head (head.json is missing)" : "the log has no entries and no recorded head, but its anchor records entries");
  } else {
    // A head written before v0.3 has no signature and is still read (the upgrade keeps verifying); the next
    // entry logged signs it.
    if (head.sig !== undefined && !verify(null, Buffer.from(`head:${head.seq}:${head.hash}`), pub, sigBytes(head.sig))) problems.push("the log's recorded head has a bad signature");
    // A v0.2 log (no entry or anchor flagged) still verifies with its unsigned head until the first
    // v0.3 append; after that, a head without a signature is a stripped one.
    if (head.sig === undefined && signedHeadsSince !== null) problems.push(`the log's recorded head has no signature, but heads are signed since sequence ${signedHeadsSince} (the signature was removed)`);
    // The head is written after each entry without an fsync, so after a power cut it can be behind the
    // log (the next append rewrites it, and logs that it did). Behind is fine if it names an entry in the
    // chain; ahead of the log, or naming a different entry, is not. FZ6: compared whether or not entries
    // remain, so a deleted or emptied log whose head (or anchor) records entries does not verify as intact.
    if (head.seq > lastSeq) problems.push(entries === 0 ? `the log has no entries but its recorded head says ${head.seq} were written (the log was deleted or emptied)` : "the log ends before its recorded head (entries were removed from the end)");
    else if (head.seq === lastSeq && head.hash !== prev) problems.push("the log does not end at its recorded head (the head was removed or rewritten)");
    else if (head.seq < lastSeq && atHead !== head.hash) problems.push(`the recorded head (sequence ${head.seq}) is not an entry of this log`);
  }
  // SR4: appendLog refuses to add to a log whose last entry it cannot find; say so here too.
  const newest = [...files].reverse().find((f) => (statSync(join(l.log, f), { throwIfNoEntry: false })?.size ?? 0) > 0);
  if (newest !== undefined && readTail(join(l.log, newest)).unsearchable) problems.push(`${UNSEARCHABLE} New entries are refused until the end of ${newest} is repaired`);
  return { ok: problems.length === 0, entries, files: files.length, problems };
}

export interface LogSnapshot {
  /** Every remaining entry, oldest first, across the archives and the current file. */
  entries: LogEntry[];
  /** Lines that are not entries ("file line N"); `log verify` reports them too. */
  damaged: string[];
  head: Head | null;
  anchor: Anchor | null;
  /** The log's public key (the half of its signing key), or null when there is no key yet. */
  pub: KeyObject | null;
}

/**
 * The whole log as it is at one moment, for `log export`: the files are read under the log lock (so no
 * append or rotation happens between reading the archives and the current file) and parsed after it is
 * released. Not checked here: the exporter verifies what it builds before writing it.
 */
export function snapshotLog(l: Layout): LogSnapshot {
  const pubPem = readText(keyPaths(l).pub);
  const pub = pubPem === null ? null : createPublicKey(pubPem);
  const raw = withLock(join(l.log, "log.lock"), () => ({
    files: [...archives(l), "decisions.jsonl"].map((f) => ({ f, text: readText(join(l.log, f)) })),
    head: readText(join(l.log, "head.json")),
    anchor: readText(join(l.log, "anchor.json")),
  }));
  const entries: LogEntry[] = [];
  const damaged: string[] = [];
  for (const { f, text } of raw.files) {
    const lines = (text ?? "").split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] as string;
      if (line.trim() === "") continue;
      try {
        const v = JSON.parse(line) as unknown;
        if (isEntry(v)) entries.push(v);
        else damaged.push(`${f} line ${i + 1}`);
      } catch {
        damaged.push(`${f} line ${i + 1}`);
      }
    }
  }
  // Checked by verifyLog before an export, but read again here: damage since then is a clear refusal.
  const parse = <T>(text: string | null, what: string): T | null => {
    if (text === null) return null;
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new Error(`the log's ${what} is not valid JSON`);
    }
  };
  const head = parse<Head>(raw.head, "head (head.json)");
  const anchor = parse<Anchor>(raw.anchor, "anchor of pruned files (anchor.json)");
  return { entries, damaged, head, anchor, pub };
}

/** The last n entries, newest last. */
export function tailLog(l: Layout, n: number): LogEntry[] {
  const files = [...archives(l), "decisions.jsonl"];
  const out: LogEntry[] = [];
  for (let i = files.length - 1; i >= 0 && out.length < n; i--) {
    // FZ7: a log file that cannot be read shows nothing here; verifyLog reports it.
    const t = tryReadText(join(l.log, files[i] as string));
    const lines = (typeof t === "string" ? t : "").trim().split("\n").filter((x) => x !== "");
    for (let j = lines.length - 1; j >= 0 && out.length < n; j--) {
      try {
        out.unshift(JSON.parse(lines[j] as string) as LogEntry);
      } catch {
        // verify reports it.
      }
    }
  }
  return out;
}

export function _renameForTest(from: string, to: string): void {
  renameSync(from, to);
}

/**
 * Whether one entry (kept outside the log, such as the last rollout change) is intact and signed by this
 * log's key. Never throws. It does not show that the entry is still in the log, or the latest of its kind.
 */
export function verifyEntry(l: Layout, e: unknown): e is LogEntry {
  try {
    if (!isEntry(e)) return false;
    const pubPem = readText(keyPaths(l).pub);
    if (pubPem === null) return false;
    if (entryHash(e.prev, e.seq, e.ts, e.event) !== e.hash) return false;
    if (e.heads !== undefined && e.heads !== "signed") return false;
    return verify(null, entrySigned(e.hash, e.heads), createPublicKey(pubPem), sigBytes(e.sig));
  } catch {
    return false;
  }
}
