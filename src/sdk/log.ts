/**
 * The library's decision log: the runtime log's format (src/runtime/log.ts),
 * each entry chained to the one before by SHA-256 of (prev, seq, ts,
 * canonical event), and its hash signed by the store's signer. Browser-safe.
 */

import { sha256Hex } from "../engine/bytes.js";
import { canonicalJson } from "../engine/decide.js";
import type { LogEntry, LogSigner, LogVerifyResult } from "./types.js";

export const GENESIS = "0".repeat(64);

/**
 * The fields a log entry has; the hash and the signature cover seq, ts, prev, event (and heads, in the signature).
 * FZ19: a field added beside them (say "verdict") left a log verifying as intact. Shared by every verifier: the
 * runtime log (src/runtime/log.ts), the dashboard's index (src/ui/logindex.ts) and this one.
 */
export const ENTRY_FIELDS: ReadonlySet<string> = new Set(["seq", "ts", "prev", "event", "hash", "sig", "heads"]);

/** The fields of an entry outside ENTRY_FIELDS (none for an entry as written). */
export function extraEntryFields(v: object): string[] {
  return Object.keys(v).filter((k) => !ENTRY_FIELDS.has(k));
}

/** The problem an entry with extra fields is reported as. */
export function extraFieldsProblem(where: string, extra: readonly string[]): string {
  return `${where}: has field(s) outside its hashed content (${extra.slice(0, 5).map((k) => JSON.stringify(k.slice(0, 40))).join(", ")}), added after it was written`;
}

export function entryHash(prev: string, seq: number, ts: string, event: Record<string, unknown>): string {
  return sha256Hex(`${prev}\n${seq}\n${ts}\n${canonicalJson(event)}`);
}

export function hexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** The next entry after `prev` (or the first). */
export function nextEntry(prev: LogEntry | undefined, event: Record<string, unknown>, ts: string, signer: LogSigner | undefined): LogEntry {
  const seq = (prev?.seq ?? 0) + 1;
  const prevHash = prev?.hash ?? GENESIS;
  const hash = entryHash(prevHash, seq, ts, event);
  return { seq, ts, prev: prevHash, event, hash, sig: signer !== undefined ? signer.sign(hexBytes(hash)) : "" };
}

/** Checks links, hashes, sequence numbers and (when `verify` is given) every signature. */
export function verifyEntries(entries: readonly LogEntry[], verify?: (hash: Uint8Array, sig: string) => boolean): LogVerifyResult {
  const problems: string[] = [];
  let prev = entries[0]?.prev ?? GENESIS;
  let expect = entries[0]?.seq ?? 1;
  let signed = entries.length > 0;
  entries.forEach((e, i) => {
    const extra = extraEntryFields(e);
    if (extra.length > 0) problems.push(extraFieldsProblem(`entry ${i + 1}`, extra));
    if (e.seq !== expect) problems.push(`entry ${i + 1}: sequence ${e.seq}, expected ${expect} (entries missing or reordered)`);
    if (e.prev !== prev) problems.push(`entry ${i + 1}: does not link to the entry before it`);
    if (entryHash(e.prev, e.seq, e.ts, e.event) !== e.hash) problems.push(`entry ${i + 1}: content does not match its hash (edited)`);
    else if (e.sig === "" || verify === undefined) signed = false;
    else if (!verify(hexBytes(e.hash), e.sig)) problems.push(`entry ${i + 1}: bad signature`);
    prev = e.hash;
    expect = e.seq + 1;
  });
  return { ok: problems.length === 0, entries: entries.length, signed: signed && problems.length === 0, problems };
}
