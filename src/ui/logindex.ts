/**
 * A read-only index of the decision log for the dashboard (DB3). The log is up to 21 files of 5 MB; the
 * log screens used to parse and verify all of it on every request. Here each file is scanned once into a
 * small index (sequence number, type, verdict and where the line sits), and a page then reads only the
 * lines it shows. The index and the verification result are cached, keyed by the name, device, inode,
 * size, modification time and change time of every file that makes up the log (the files, head.json,
 * anchor.json and the public key) and by the content hashes of head.json and anchor.json, so any append,
 * rotation, prune or edit makes the next request rebuild them (FB1: a same-size rewrite with the
 * modification time put back still moves the change time, which no user call can set). A cache hit also
 * re-checks, cheaply, that the log's last line still hashes to itself and to the recorded head; if that
 * answer changed since the cache was built, it is rebuilt. Nothing is written.
 */

import { createHash } from "node:crypto";
import { closeSync, fstatSync, openSync, readdirSync, readFileSync, readSync, statSync } from "node:fs";
import { join } from "node:path";
import type { Layout } from "../runtime/layout.js";
import { entryHash, verifyLog, type LogEntry, type VerifyResult } from "../runtime/log.js";
import { extraEntryFields } from "../sdk/log.js";

export interface IndexRow {
  file: string;
  start: number;
  length: number;
  seq: number;
  type: string;
  verdict: string | undefined;
}

export interface LogIndex {
  rows: IndexRow[];
  types: string[];
  bySeq: Map<number, IndexRow>;
}

interface Cached {
  key: string;
  /** The cheap head check's answer when the entry was made. */
  headOk: boolean;
  index: LogIndex | null;
  verify: VerifyResult | null;
}

const cache = new Map<string, Cached>();

function stamp(path: string): string {
  try {
    const s = statSync(path, { bigint: true });
    return `${s.dev}:${s.ino}:${s.size}:${s.mtimeNs}:${s.ctimeNs}`;
  } catch {
    return "-";
  }
}

/** A small file's content hash (head.json, anchor.json), or "-" when absent. */
function contentHash(path: string): string {
  try {
    return createHash("sha256").update(readFileSync(path)).digest("hex").slice(0, 32);
  } catch {
    return "-";
  }
}

const TAIL_BYTES = 64 * 1024;

/** The last non-empty line of a file, read from its end only. */
function lastLine(path: string): string | null {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    return null;
  }
  try {
    const size = fstatSync(fd).size;
    const len = Math.min(size, TAIL_BYTES);
    const buf = Buffer.alloc(len);
    const n = readSync(fd, buf, 0, len, size - len);
    const lines = buf.toString("utf8", 0, n).split("\n").filter((x) => x.trim() !== "");
    return lines[lines.length - 1] ?? null;
  } finally {
    closeSync(fd);
  }
}

/**
 * Whether the log's last entry hashes to itself and matches head.json. Reads head.json and the tail of
 * the last file that has lines; never the whole log.
 */
function headHolds(l: Layout, files: readonly string[]): boolean {
  let head: { seq?: unknown; hash?: unknown } | null = null;
  try {
    head = JSON.parse(readFileSync(join(l.log, "head.json"), "utf8")) as { seq?: unknown; hash?: unknown };
  } catch {
    head = null;
  }
  for (let i = files.length - 1; i >= 0; i--) {
    const line = lastLine(join(l.log, files[i] as string));
    if (line === null) continue;
    try {
      const e = JSON.parse(line) as LogEntry;
      // FZ19: a last entry with a field outside its hashed content is not the entry that was written.
      if (typeof e !== "object" || e === null || extraEntryFields(e).length > 0) return false;
      return head !== null && e.seq === head.seq && e.hash === head.hash && entryHash(e.prev, e.seq, e.ts, e.event) === e.hash;
    } catch {
      return false;
    }
  }
  return head === null;
}

function logFiles(l: Layout): string[] {
  try {
    return [...readdirSync(l.log).filter((n) => /^decisions-\d{8}\.jsonl$/.test(n)).sort(), "decisions.jsonl"];
  } catch {
    return ["decisions.jsonl"];
  }
}

function keyOf(l: Layout): { key: string; files: string[] } {
  const files = logFiles(l);
  const head = join(l.log, "head.json");
  const anchor = join(l.log, "anchor.json");
  const parts = [...files.map((f) => `${f}=${stamp(join(l.log, f))}`), `head=${stamp(head)}#${contentHash(head)}`, `anchor=${stamp(anchor)}#${contentHash(anchor)}`, `pub=${stamp(join(l.keys, "log-ed25519.pub.pem"))}`];
  return { key: parts.join("|"), files };
}

function entryOf(l: Layout): Cached {
  const { key, files } = keyOf(l);
  const headOk = headHolds(l, files);
  const hit = cache.get(l.log);
  if (hit !== undefined && hit.key === key && hit.headOk === headOk) return hit;
  const fresh: Cached = { key, headOk, index: null, verify: null };
  cache.set(l.log, fresh);
  return fresh;
}

function build(l: Layout, files: string[]): LogIndex {
  const rows: IndexRow[] = [];
  for (const f of files) {
    let buf: Buffer;
    try {
      buf = readFileSync(join(l.log, f));
    } catch {
      continue;
    }
    let start = 0;
    while (start < buf.length) {
      let end = buf.indexOf(10, start);
      if (end === -1) end = buf.length;
      const length = end - start;
      if (length > 0 && buf.subarray(start, end).some((b) => b !== 32 && b !== 9 && b !== 13)) {
        try {
          const e = JSON.parse(buf.toString("utf8", start, end)) as LogEntry;
          if (typeof e.seq === "number") rows.push({ file: f, start, length, seq: e.seq, type: String(e.event?.type ?? "event"), verdict: typeof e.event?.verdict === "string" ? e.event.verdict : undefined });
        } catch {
          // log verify reports a line that is not JSON.
        }
      }
      start = end + 1;
    }
  }
  const bySeq = new Map<number, IndexRow>();
  for (const r of rows) bySeq.set(r.seq, r);
  return { rows, types: [...new Set(rows.map((r) => r.type))].sort(), bySeq };
}

/** The index of the log as it is now (rebuilt only when a file changed). */
export function logIndex(l: Layout): LogIndex {
  const c = entryOf(l);
  if (c.index === null) c.index = build(l, keyOf(l).files);
  return c.index;
}

/** `log verify`'s result, cached until a file changes. */
export function cachedVerify(l: Layout): VerifyResult {
  const c = entryOf(l);
  if (c.verify === null) c.verify = verifyLog(l);
  return c.verify;
}

/** Reads the lines of the given rows, and nothing else. A line that moved since indexing is dropped and the index is discarded. */
export function readRows(l: Layout, rows: readonly IndexRow[]): LogEntry[] {
  const out: LogEntry[] = [];
  let fd: number | null = null;
  let open = "";
  try {
    for (const r of rows) {
      if (fd === null || open !== r.file) {
        if (fd !== null) closeSync(fd);
        fd = openSync(join(l.log, r.file), "r");
        open = r.file;
      }
      const buf = Buffer.alloc(r.length);
      const n = readSync(fd, buf, 0, r.length, r.start);
      try {
        const e = JSON.parse(buf.toString("utf8", 0, n)) as LogEntry;
        if (e.seq === r.seq) out.push(e);
        else cache.delete(l.log);
      } catch {
        cache.delete(l.log);
      }
    }
  } finally {
    if (fd !== null) closeSync(fd);
  }
  return out;
}
