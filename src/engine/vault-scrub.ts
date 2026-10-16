/**
 * Scrubbing vault values out of what the model would read (results are
 * scrubbed back to the reference).
 * Pure. Two sources:
 *
 * - the values the caller just substituted (the gateway knows them for the
 *   call in flight): each value and its encodings (base64, base64url, hex,
 *   URL encoding, base32, JSON escaping) become the reference text;
 * - every fingerprinted value in the vault (the hook knows only
 *   fingerprints): clear-text occurrences become the reference.
 *
 * What remains detectable afterwards (an encoding neither pass could undo)
 * is reported, and the caller withholds the output instead of passing it on.
 */

import { fingerprintSpans } from "./secrets.js";
import { canonicalRef, entriesIn, type VaultView } from "./vault-ref.js";

export interface KnownValue {
  value: string;
  /** The reference text it replaces ("vault://github/token"). */
  ref: string;
}

function base32(buf: Buffer): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

/** A value and the encodings a tool's output may carry it in, longest first, without duplicates. */
export function encodings(value: string): string[] {
  const buf = Buffer.from(value, "utf8");
  const b64 = buf.toString("base64");
  const b32 = base32(buf);
  const all = [value, b64, b64.replace(/=+$/, ""), buf.toString("base64url"), buf.toString("hex"), buf.toString("hex").toUpperCase(), encodeURIComponent(value), b32, b32.toLowerCase(), JSON.stringify(value).slice(1, -1)];
  return [...new Set(all)].filter((x) => x !== "").sort((a, b) => b.length - a.length);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Replaces the known values (and their encodings) with their references. Short values only as whole tokens. */
function replaceKnown(text: string, known: readonly KnownValue[]): { text: string; count: number } {
  let out = text;
  let count = 0;
  const pairs = known.flatMap((k) => encodings(k.value).map((e) => ({ e, ref: k.ref }))).sort((a, b) => b.e.length - a.e.length);
  for (const { e, ref } of pairs) {
    if (!out.includes(e)) continue;
    if (e.length >= 8) {
      const parts = out.split(e);
      count += parts.length - 1;
      out = parts.join(ref);
    } else {
      // A CVC or an expiry date: replaced only where it stands alone, so ordinary numbers keep their digits.
      const re = new RegExp(`(?<![A-Za-z0-9])${escapeRe(e)}(?![A-Za-z0-9])`, "g");
      out = out.replace(re, () => {
        count++;
        return ref;
      });
    }
  }
  return { text: out, count };
}

/** Replaces every clear-text vaulted value (by fingerprint) with its reference. */
function replaceFingerprinted(text: string, view: VaultView | undefined): { text: string; count: number } {
  if (view === undefined) return { text, count: 0 };
  const refOf = new Map<string, string>();
  for (const e of view.entries) for (const [field, fp] of Object.entries(e.fingerprints)) refOf.set(fp, canonicalRef(e, field));
  if (refOf.size === 0) return { text, count: 0 };
  const spans = fingerprintSpans(text, refOf.keys());
  if (spans.length === 0) return { text, count: 0 };
  let out = "";
  let at = 0;
  for (const s of spans) {
    out += text.slice(at, s.start) + (refOf.get(s.fp) ?? "vault://?");
    at = s.end;
  }
  return { text: out + text.slice(at), count: spans.length };
}

export interface ScrubResult<T> {
  value: T;
  /** How many occurrences were replaced. */
  count: number;
  /** A vaulted value is still detectable (an encoding neither pass undid): withhold, do not deliver. */
  leftover: boolean;
}

/** One row of a dump (curl --trace / --trace-ascii, hexdump -C, xxd): an offset, a colon or spaces, then data. */
export const DUMP_ROW = /^[0-9a-fA-F]{4,8}:? {1,2}(.*)$/;
const HEX_COLS = /^((?:[0-9a-fA-F]{2} ?){1,16})(?: +\|?(.*?)\|?)?\s*$/;
/** hexdump -C: two groups of eight bytes with a double space between them, then |text|. */
const HEXDUMP_C = /^((?:[0-9a-fA-F]{2} ){1,8})(?: ((?:[0-9a-fA-F]{2} ){0,7}[0-9a-fA-F]{2}) ?)? *\|(.*)\|\s*$/;

/**
 * The data of every dump in a text, joined across its rows (V16): a value split over two rows of a hex or
 * ASCII dump is whole again here. Two strings per block: the bytes the hex columns spell, and the joined
 * text columns (curl --trace-ascii has only those).
 */
export function dumpData(text: string): string[] {
  const out: string[] = [];
  let hex = "";
  let cols = "";
  let rows = 0;
  const end = (): void => {
    if (rows > 0) {
      if (hex !== "") out.push(Buffer.from(hex, "hex").toString("utf8"));
      out.push(cols);
    }
    hex = "";
    cols = "";
    rows = 0;
  };
  for (const line of text.split(/\r?\n/)) {
    const m = DUMP_ROW.exec(line);
    if (m === null) {
      end();
      continue;
    }
    rows++;
    const data = m[1] as string;
    const c = HEXDUMP_C.exec(data);
    if (c !== null) {
      hex += `${c[1] as string}${c[2] ?? ""}`.replace(/ /g, "");
      cols += c[3] ?? "";
      continue;
    }
    const h = HEX_COLS.exec(data);
    if (h !== null && /^(?:[0-9a-fA-F]{2} )/.test(data)) {
      hex += (h[1] as string).replace(/ /g, "");
      cols += h[2] ?? "";
    } else cols += data;
  }
  end();
  return out;
}

/** Whether a vaulted value (known, or by fingerprint) can be read back from a dump in this text. */
function inDump(text: string, known: readonly KnownValue[], view: VaultView | undefined): boolean {
  if (!/^[0-9a-fA-F]{4,8}:? /m.test(text)) return false;
  return dumpData(text).some((d) => known.some((k) => encodings(k.value).some((e) => e.length >= 8 && d.includes(e))) || entriesIn(d, view).length > 0);
}

export function scrubText(text: string, known: readonly KnownValue[], view: VaultView | undefined): ScrubResult<string> {
  const a = replaceKnown(text, known);
  const b = replaceFingerprinted(a.text, view);
  const leftover = entriesIn(b.text, view).length > 0 || known.some((k) => k.value.length >= 8 && b.text.includes(k.value)) || inDump(b.text, known, view);
  return { value: b.text, count: a.count + b.count, leftover };
}

/** The same over every string of a JSON value (keys included: a server may echo a value as a key). */
export function scrubJson<T>(v: T, known: readonly KnownValue[], view: VaultView | undefined): ScrubResult<T> {
  let count = 0;
  let leftover = false;
  const walk = (x: unknown, depth: number): unknown => {
    if (depth > 64) {
      // Past the cap the subtree is not scrubbed: withhold rather than deliver it untouched.
      leftover = true;
      return x;
    }
    if (typeof x === "string") {
      const r = scrubText(x, known, view);
      count += r.count;
      leftover ||= r.leftover;
      return r.value;
    }
    if (Array.isArray(x)) return x.map((y) => walk(y, depth + 1));
    if (typeof x === "object" && x !== null) return Object.fromEntries(Object.entries(x).map(([k, y]) => [walk(k, depth + 1) as string, walk(y, depth + 1)]));
    return x;
  };
  const value = walk(v, 0) as T;
  // A value split across strings, or encoded as a whole result, is caught on the joined text.
  if (!leftover && view !== undefined) leftover = entriesIn(JSON.stringify(value), view).length > 0;
  return { value, count, leftover };
}
