/**
 * `log export`: the decision log, or a range of it, as one self-contained bundle (docs/logs.md). The bundle
 * holds the entries exactly as written (bounded summaries stay bounded; nothing is added that the log does
 * not hold), the public key that signed them, and a manifest with counts and the first and last hash, signed
 * with the log's key. It is checked with the standalone verifier (verify.ts) before it is handed back, so an
 * export never produces a bundle that does not verify.
 */

import { sign } from "node:crypto";
import { loadKey, snapshotLog, verifyLog, type LogEntry } from "../runtime/log.js";
import type { Layout } from "../runtime/layout.js";
import { VERSION } from "../version.js";
import { BUNDLE_FORMAT, BUNDLE_VERSION, countTypes, fingerprint, headerMessage, verifyBundle, type BundleHeader, type BundleKey, type BundleManifest } from "./verify.js";

export class ExportRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExportRefused";
  }
}

export interface ExportOptions {
  /** A sequence number, or a date and time (ISO 8601, as the log's `ts`). */
  from?: string;
  to?: string;
  now?: Date;
}

export interface ExportResult {
  text: string;
  manifest: BundleManifest;
  fingerprint: string;
}

type Bound = { kind: "seq"; n: number } | { kind: "time"; ms: number };

/**
 * ISO 8601 as the log writes `ts`: a date (taken as midnight UTC), or a date and time with Z or an offset. A
 * year or year and month alone, a time without a zone (whose meaning depends on the machine) or any other form Date.parse would
 * guess at is refused.
 */
const ISO = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2}))?$/;

function parseBound(v: string | undefined, name: string): Bound | null {
  if (v === undefined) return null;
  // Digits alone are always a sequence number (so "2026" is entry 2026, never the year).
  if (/^\d+$/.test(v)) {
    if (!Number.isSafeInteger(Number(v))) throw new ExportRefused(`${name} is not a sequence number the log can hold`);
    return { kind: "seq", n: Number(v) };
  }
  const ms = ISO.test(v) ? Date.parse(v) : Number.NaN;
  if (Number.isNaN(ms)) throw new ExportRefused(`${name} must be a sequence number or an ISO 8601 date (2026-10-01) or date and time with a zone (2026-10-01T12:00:00Z), not "${v.slice(0, 40)}"`);
  return { kind: "time", ms };
}

function atOrAfter(e: LogEntry, b: Bound): boolean {
  return b.kind === "seq" ? e.seq >= b.n : Date.parse(e.ts) >= b.ms;
}

function atOrBefore(e: LogEntry, b: Bound): boolean {
  return b.kind === "seq" ? e.seq <= b.n : Date.parse(e.ts) <= b.ms;
}

/**
 * Builds the bundle. Refuses (ExportRefused) a log that does not verify, a range with no entries, and a log
 * with no entries: export is for a log whose integrity holds now; a damaged log is copied as files instead.
 * A time range is the contiguous run of entries from the first at or after `from` to the last at or before
 * `to` (by sequence, so a clock that went backwards cannot leave holes in the chain).
 */
export function exportLog(l: Layout, o: ExportOptions = {}): ExportResult {
  const from = parseBound(o.from, "--from");
  const to = parseBound(o.to, "--to");
  const v = verifyLog(l);
  if (!v.ok) throw new ExportRefused(`the log does not verify, so it is not exported (copy the files under ${l.log} instead):\n${v.problems.join("\n")}`);
  const key = loadKey(l, false);
  if (key === null) throw new ExportRefused("there is no decision log yet");
  let snap: ReturnType<typeof snapshotLog>;
  try {
    snap = snapshotLog(l);
  } catch (e) {
    throw new ExportRefused(`the log could not be read as it is now (${(e as Error).message}); run "launchsafe-firewall log verify"`);
  }
  if (snap.damaged.length > 0) throw new ExportRefused(`the log has lines that are not entries (${snap.damaged.slice(0, 5).join(", ")}); run "launchsafe-firewall log verify"`);
  const all = snap.entries;
  if (all.length === 0) throw new ExportRefused("the decision log has no entries");
  const start = from === null ? 0 : all.findIndex((e) => atOrAfter(e, from));
  let end = -1;
  for (let i = all.length - 1; i >= 0; i--) {
    if (to === null || atOrBefore(all[i] as LogEntry, to)) {
      end = i;
      break;
    }
  }
  if (start === -1 || end === -1 || start > end) throw new ExportRefused(`no entries in that range (the log holds sequence ${(all[0] as LogEntry).seq} to ${(all[all.length - 1] as LogEntry).seq}, ${(all[0] as LogEntry).ts} to ${(all[all.length - 1] as LogEntry).ts})`);
  const sel = all.slice(start, end + 1);
  const first = sel[0] as LogEntry;
  const last = sel[sel.length - 1] as LogEntry;
  const fromStart = start === 0;
  const toEnd = end === all.length - 1;
  const id = fingerprint(key.pub);
  const keys: BundleKey[] = [{ id, alg: "ed25519", spki: key.pub.export({ type: "spki", format: "der" }).toString("base64"), fromSeq: first.seq, toSeq: last.seq }];
  const eventTypes = countTypes(sel.map((e) => e.event));
  const manifest: BundleManifest = {
    createdAt: (o.now ?? new Date()).toISOString(),
    createdBy: `launchsafe-firewall ${VERSION}`,
    signer: id,
    requested: { from: o.from ?? null, to: o.to ?? null },
    fromStart,
    toEnd,
    entries: sel.length,
    firstSeq: first.seq,
    lastSeq: last.seq,
    firstHash: first.hash,
    lastHash: last.hash,
    startPrev: first.prev,
    eventTypes,
    logHead: toEnd ? snap.head : null,
    prunedAnchor: fromStart ? snap.anchor : null,
  };
  const header: BundleHeader = { format: BUNDLE_FORMAT, version: BUNDLE_VERSION, manifest, keys, sig: sign(null, headerMessage(manifest, keys), key.priv).toString("base64") };
  const text = `${JSON.stringify(header)}\n${sel.map((e) => JSON.stringify(e)).join("\n")}\n`;
  // Never hand back a bundle the verifier would refuse (a race with an append, or a log this code misreads).
  const check = verifyBundle(text, { keys: [id] });
  if (!check.ok) throw new ExportRefused(`the bundle did not verify, so it was not written:\n${check.problems.join("\n")}`);
  return { text, manifest, fingerprint: id };
}
