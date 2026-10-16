/**
 * The standalone verifier for an exported decision-log bundle (docs/logs.md). It needs no firewall install,
 * no firewall home and no network: only Node and this one file, which imports nothing but Node's own modules,
 * so it can be copied to an auditor's machine and run as `node verify.js <bundle> [--key K] [--anchor FILE]`.
 *
 * A bundle is JSON lines. The first line is the header: the manifest (counts, the first and last hash, the
 * log's signed head and the anchor of pruned files when the export reaches them), the public keys that signed
 * the entries with the sequence range each was valid for, and a signature over both by the newest key. Every
 * further line is one log entry exactly as the firewall wrote it.
 *
 * What a pass proves: the entries are a contiguous piece of one hash chain, each signed by the key valid for
 * its sequence number, a later key endorsed by the one before it, and the manifest's counts and hashes are
 * those of exactly these entries. What it cannot prove alone is whose key that is: pin it (--key, the
 * fingerprint you kept) or check against an anchor record you wrote somewhere else (--anchor), which also
 * catches a history rewritten by someone holding the key.
 *
 * Keep this file free of imports from the rest of the package: the copy of canonicalJson below is tested
 * against the engine's (test/log-bundle.test.ts).
 */

import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const BUNDLE_FORMAT = "launchsafe-firewall-log-bundle";
export const BUNDLE_VERSION = 1;
export const ANCHOR_FORMAT = "launchsafe-firewall-log-anchor";
export const ANCHOR_VERSION = 1;
export const GENESIS = "0".repeat(64);

/** What each signature covers starts with its own label, so no signature of one kind is valid as another. */
export const HEADER_DOMAIN = `${BUNDLE_FORMAT}:v${BUNDLE_VERSION}\n`;
export const ANCHOR_DOMAIN = `${ANCHOR_FORMAT}:v${ANCHOR_VERSION}\n`;
export const KEY_ENDORSE_DOMAIN = "launchsafe-firewall-log-key:v1:";

export interface BundleEntry {
  seq: number;
  ts: string;
  prev: string;
  event: Record<string, unknown>;
  hash: string;
  sig: string;
  heads?: "signed";
}

export interface SignedHead {
  seq: number;
  hash: string;
  sig?: string;
}

export interface PrunedAnchor {
  seq: number;
  hash: string;
  sig: string;
  heads?: "signed";
}

export interface BundleKey {
  /** "sha256:" and the SHA-256 of the key's SubjectPublicKeyInfo (DER), in hex: the fingerprint to pin. */
  id: string;
  alg: "ed25519";
  /** The SubjectPublicKeyInfo (DER), base64. */
  spki: string;
  /** The sequence numbers this key signed, inclusive. */
  fromSeq: number;
  toSeq: number;
  /** For every key but the first: the key before it signs `launchsafe-firewall-log-key:v1:<id>:<fromSeq>`. */
  endorsement?: string;
}

export interface BundleManifest {
  createdAt: string;
  createdBy: string;
  /** The key that signed the header: the last one in `keys`. */
  signer: string;
  /** The range asked for (null: from the start, to the end), as given. */
  requested: { from: string | null; to: string | null };
  /** Whether the bundle starts at the log's first remaining entry and ends at its last one. */
  fromStart: boolean;
  toEnd: boolean;
  entries: number;
  firstSeq: number;
  lastSeq: number;
  firstHash: string;
  lastHash: string;
  /** The `prev` of the first entry: GENESIS for a log's very first entry. */
  startPrev: string;
  /** How many entries of each event type (an event without a string `type` counts as "(none)"). */
  eventTypes: Record<string, number>;
  /** The log's signed head at export time, when the bundle reaches the end of the log. */
  logHead: SignedHead | null;
  /** The signed anchor of pruned log files, when the bundle starts where the remaining files start. */
  prunedAnchor: PrunedAnchor | null;
}

export interface BundleHeader {
  format: typeof BUNDLE_FORMAT;
  version: number;
  manifest: BundleManifest;
  keys: BundleKey[];
  sig: string;
}

export interface AnchorRecord {
  format: typeof ANCHOR_FORMAT;
  version: number;
  seq: number;
  hash: string;
  /** The fingerprint of the key that signed the entry and this record. */
  key: string;
  at: string;
  sig: string;
}

export interface VerifyOptions {
  /** Fingerprints ("sha256:<hex>" or bare hex) or PEM public keys the bundle must be signed by. */
  keys?: readonly string[];
  /** The text of anchor files: JSON lines of anchor records (blank lines and git-notes separators are fine). */
  anchors?: readonly string[];
  /**
   * Accept a bundle that is intact but neither pinned nor anchored (--no-pin). Without it such a bundle is
   * "unauthenticated", not ok: anyone can make a self-consistent bundle with a key of their own.
   */
  allowUnpinned?: boolean;
}

/** ok: intact and authenticated (or --no-pin); unauthenticated: intact, but nothing ties it to your key; invalid: a problem. */
export type BundleStatus = "ok" | "unauthenticated" | "invalid";

/** The exit code of each status, for the CLI and the standalone entry point. */
export function statusExit(status: BundleStatus): number {
  return status === "ok" ? 0 : status === "unauthenticated" ? 2 : 1;
}

export interface BundleVerifyResult {
  /** status === "ok". */
  ok: boolean;
  status: BundleStatus;
  /** No problem was found in the bundle itself (it may still be unauthenticated). */
  intact: boolean;
  /** A --key matched or an anchor record matched: the bundle is tied to a key you trust. */
  authenticated: boolean;
  problems: string[];
  /** What was checked, for the report; never a reason on its own for ok. */
  notes: string[];
  entries: number;
  firstSeq: number | null;
  lastSeq: number | null;
  lastHash: string | null;
  /** The fingerprint of the key that signed the header, when it could be read. */
  signer: string | null;
  /** A --key matched a key of the bundle. */
  pinned: boolean;
  /** Anchor records whose position the bundle covers and that matched. */
  anchorsMatched: number;
}

// --- shared with the exporter -----------------------------------------------------------------------

/** The engine's canonicalJson (src/engine/decide.ts), copied so this file stands alone. Sorted own keys. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const o = v as Record<string, unknown>;
  // Own values only (as src/own.ts own()); Reflect.get, since this file imports nothing from the package.
  const at = (k: string): unknown => (Object.hasOwn(o, k) ? (Reflect.get(o, k) as unknown) : undefined);
  return `{${Object.keys(o)
    .filter((k) => at(k) !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(at(k))}`)
    .join(",")}}`;
}

/** Counts of event types as a plain object with own keys only ("__proto__" included as a key). */
export function countTypes(events: Iterable<Record<string, unknown>>): Record<string, number> {
  const m = new Map<string, number>();
  for (const ev of events) {
    const t = Object.hasOwn(ev, "type") && typeof ev.type === "string" ? ev.type : "(none)";
    m.set(t, (m.get(t) ?? 0) + 1);
  }
  return Object.fromEntries(m) as Record<string, number>;
}

/** The hash a log entry must carry (as src/runtime/log.ts entryHash). */
export function entryHash(prev: string, seq: number, ts: string, event: Record<string, unknown>): string {
  return createHash("sha256").update(`${prev}\n${seq}\n${ts}\n${canonicalJson(event)}`).digest("hex");
}

/** What an entry's signature covers (as src/runtime/log.ts). */
export function entryMessage(hash: string, heads: unknown): Buffer {
  return heads === "signed" ? Buffer.from(`entry:${hash}:heads-signed`) : Buffer.from(hash, "hex");
}

export function headMessage(seq: number, hash: string): Buffer {
  return Buffer.from(`head:${seq}:${hash}`);
}

export function prunedAnchorMessage(seq: number, hash: string, heads: unknown): Buffer {
  return Buffer.from(heads === "signed" ? `anchor:${seq}:${hash}:heads-signed` : `anchor:${seq}:${hash}`);
}

export function headerMessage(manifest: BundleManifest, keys: readonly BundleKey[]): Buffer {
  return Buffer.from(HEADER_DOMAIN + canonicalJson({ manifest, keys }));
}

export function endorseMessage(id: string, fromSeq: number): Buffer {
  return Buffer.from(`${KEY_ENDORSE_DOMAIN}${id}:${fromSeq}`);
}

export function anchorRecordMessage(r: Omit<AnchorRecord, "sig">): Buffer {
  const { format, version, seq, hash, key, at } = r;
  return Buffer.from(ANCHOR_DOMAIN + canonicalJson({ format, version, seq, hash, key, at }));
}

/** A public key's fingerprint: "sha256:" and the SHA-256 of its SubjectPublicKeyInfo (DER). */
export function fingerprint(pub: KeyObject): string {
  return `sha256:${createHash("sha256").update(pub.export({ type: "spki", format: "der" })).digest("hex")}`;
}

// --- checks -----------------------------------------------------------------------------------------

const HEX64 = /^[0-9a-f]{64}$/;
const FP = /^sha256:[0-9a-f]{64}$/;

/** A signature's bytes, only from canonical base64 (Buffer.from skips junk, which would hide an edit). */
function sigBytes(sig: unknown): Buffer {
  if (typeof sig !== "string") return Buffer.alloc(0);
  const b = Buffer.from(sig, "base64");
  return b.toString("base64") === sig ? b : Buffer.alloc(0);
}

function checkSig(msg: Buffer, pub: KeyObject, sig: unknown): boolean {
  try {
    const b = sigBytes(sig);
    return b.length === 64 && verify(null, msg, pub, b);
  } catch {
    return false;
  }
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * One line parsed strictly: it must be exactly what JSON.stringify writes for the value it parses to, as the
 * firewall writes every line. So a duplicate key, -0, 1.0, 1e2, a number past 2^53, extra whitespace or an
 * escape JSON.stringify would not write is refused: two JSON parsers cannot then read the line differently.
 */
export function strictParse(line: string): { ok: true; v: unknown } | { ok: false; why: string } {
  let v: unknown;
  try {
    v = JSON.parse(line) as unknown;
  } catch {
    return { ok: false, why: "not valid JSON" };
  }
  return JSON.stringify(v) === line ? { ok: true, v } : { ok: false, why: "not in canonical form (duplicate keys, a number written another way, or extra spacing)" };
}

/** Whether every key of the object is one of the allowed ones. */
function onlyKeys(o: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(o).every((k) => allowed.includes(k));
}

const ENTRY_KEYS = ["seq", "ts", "prev", "event", "hash", "sig", "heads"] as const;
const HEADER_KEYS = ["format", "version", "manifest", "keys", "sig"] as const;
const MANIFEST_KEYS = ["createdAt", "createdBy", "signer", "requested", "fromStart", "toEnd", "entries", "firstSeq", "lastSeq", "firstHash", "lastHash", "startPrev", "eventTypes", "logHead", "prunedAnchor"] as const;
const KEY_KEYS = ["id", "alg", "spki", "fromSeq", "toSeq", "endorsement"] as const;
const HEAD_KEYS = ["seq", "hash", "sig"] as const;
const PRUNED_KEYS = ["seq", "hash", "sig", "heads"] as const;
const ANCHOR_KEYS = ["format", "version", "seq", "hash", "key", "at", "sig"] as const;

function isSeq(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

function isEntry(v: unknown): v is BundleEntry {
  if (!isObj(v)) return false;
  return onlyKeys(v, ENTRY_KEYS) && isSeq(v.seq) && v.seq >= 1 && typeof v.ts === "string" && typeof v.prev === "string" && HEX64.test(v.prev) && typeof v.hash === "string" && HEX64.test(v.hash) && typeof v.sig === "string" && isObj(v.event) && (v.heads === undefined || v.heads === "signed");
}

/**
 * A --key value as a pin: a fingerprint or a PEM text is taken as it is; anything else names a file, of which
 * only a PEM public-key block is used (at most 64 KiB is read). Nothing of the file is ever printed, so a
 * --key naming some other file (a credentials file) yields only "not a fingerprint or a PEM public key".
 */
export function resolvePin(v: string): string {
  if (v.includes("-----BEGIN") || normalizePin(v) !== null) return v;
  try {
    if (statSync(v).size > 64 * 1024) return "";
    const m = /-----BEGIN PUBLIC KEY-----[A-Za-z0-9+/=\s]+-----END PUBLIC KEY-----/.exec(readFileSync(v, "utf8"));
    return m === null ? "" : m[0];
  } catch {
    return "";
  }
}

/** "sha256:<hex>" from a fingerprint (with or without the prefix, any case, colons allowed) or a PEM public key. */
export function normalizePin(pin: string): string | null {
  const t = pin.trim();
  if (t.includes("-----BEGIN")) {
    try {
      return fingerprint(createPublicKey(t));
    } catch {
      return null;
    }
  }
  const hex = t.toLowerCase().replace(/^sha256:/, "").replace(/:/g, "");
  return HEX64.test(hex) ? `sha256:${hex}` : null;
}

/** Parses anchor records from JSON lines (strictly, as bundle lines); lines that are not are counted, never shown. */
export function parseAnchorRecords(text: string): { records: unknown[]; bad: number } {
  const records: unknown[] = [];
  let bad = 0;
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    const p = strictParse(line);
    if (p.ok) records.push(p.v);
    else bad++;
  }
  return { records, bad };
}

function isAnchorRecord(v: unknown): v is AnchorRecord {
  return isObj(v) && onlyKeys(v, ANCHOR_KEYS) && v.format === ANCHOR_FORMAT && isSeq(v.seq) && v.seq >= 1 && typeof v.hash === "string" && HEX64.test(v.hash) && typeof v.key === "string" && FP.test(v.key) && typeof v.at === "string" && typeof v.sig === "string" && typeof v.version === "number";
}

interface LoadedKey {
  k: BundleKey;
  pub: KeyObject;
}

/** Checks the key list: well formed, fingerprints right, ranges contiguous over the entries, each later key endorsed. */
function checkKeys(raw: unknown, firstSeq: number, lastSeq: number, problems: string[]): LoadedKey[] | null {
  if (!Array.isArray(raw) || raw.length === 0) {
    problems.push("the bundle lists no public keys");
    return null;
  }
  const out: LoadedKey[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < raw.length; i++) {
    const k = raw[i] as unknown;
    if (!isObj(k) || !onlyKeys(k, KEY_KEYS) || typeof k.id !== "string" || k.alg !== "ed25519" || typeof k.spki !== "string" || !isSeq(k.fromSeq) || !isSeq(k.toSeq) || k.fromSeq > k.toSeq || (k.endorsement !== undefined && typeof k.endorsement !== "string")) {
      problems.push(`key ${i + 1} is malformed`);
      return null;
    }
    let pub: KeyObject;
    try {
      pub = createPublicKey({ key: Buffer.from(k.spki, "base64"), format: "der", type: "spki" });
    } catch {
      problems.push(`key ${i + 1} is not a public key`);
      return null;
    }
    if (pub.asymmetricKeyType !== "ed25519") {
      problems.push(`key ${i + 1} is not an Ed25519 key`);
      return null;
    }
    const id = fingerprint(pub);
    if (id !== k.id) problems.push(`key ${i + 1}'s fingerprint is ${id}, not the ${k.id} it claims (the key was swapped)`);
    if (seen.has(id)) problems.push(`key ${i + 1} appears twice`);
    seen.add(id);
    const kk = k as unknown as BundleKey;
    if (i === 0) {
      if (kk.fromSeq !== firstSeq) problems.push(`the first key is valid from sequence ${kk.fromSeq}, but the entries start at ${firstSeq}`);
    } else {
      const before = out[i - 1] as LoadedKey;
      if (kk.fromSeq !== before.k.toSeq + 1) problems.push(`key ${i + 1} is valid from sequence ${kk.fromSeq}, not right after key ${i} (${before.k.toSeq}): the keys' ranges must not overlap or leave a gap`);
      if (!checkSig(endorseMessage(id, kk.fromSeq), before.pub, kk.endorsement)) problems.push(`key ${i + 1} is not endorsed by key ${i} (a key may only follow the key before it if that key signed the hand-over)`);
    }
    out.push({ k: kk, pub });
  }
  const last = out[out.length - 1] as LoadedKey;
  if (last.k.toSeq !== lastSeq) problems.push(`the last key is valid to sequence ${last.k.toSeq}, but the entries end at ${lastSeq}`);
  return out;
}

function keyFor(keys: readonly LoadedKey[], seq: number): LoadedKey | null {
  return keys.find((k) => seq >= k.k.fromSeq && seq <= k.k.toSeq) ?? null;
}

function emptyResult(problems: string[]): BundleVerifyResult {
  return { ok: false, status: "invalid", intact: false, authenticated: false, problems, notes: [], entries: 0, firstSeq: null, lastSeq: null, lastHash: null, signer: null, pinned: false, anchorsMatched: 0 };
}

/** Verifies a bundle's text. Never throws: anything wrong is a problem and the result is not ok. */
export function verifyBundle(text: string, opts: VerifyOptions = {}): BundleVerifyResult {
  try {
    return verifyInner(text, opts);
  } catch (e) {
    return emptyResult([`the bundle could not be checked: ${(e as Error).message}`]);
  }
}

function verifyInner(text: string, opts: VerifyOptions): BundleVerifyResult {
  const problems: string[] = [];
  const notes: string[] = [];
  const lines = text.split("\n");
  // Only a final newline may follow the last line: anything else after it is junk that was added.
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  if (lines.length === 0) return emptyResult(["the bundle is empty"]);
  const hp = strictParse(lines[0] as string);
  if (!hp.ok) return emptyResult([`the bundle's first line is ${hp.why} (not a decision-log bundle as the firewall writes it)`]);
  const header = hp.v;
  if (!isObj(header) || header.format !== BUNDLE_FORMAT) return emptyResult(["the bundle's first line is not a decision-log bundle header"]);
  if (header.version !== BUNDLE_VERSION) return emptyResult([`the bundle is format version ${String(header.version)}; this verifier reads version ${BUNDLE_VERSION} (use a newer launchsafe-firewall)`]);
  if (!onlyKeys(header, HEADER_KEYS)) return emptyResult(["the bundle's header has fields a bundle does not have"]);
  const m = header.manifest;
  if (!isObj(m) || !onlyKeys(m, MANIFEST_KEYS) || !Object.values(isObj(m.eventTypes) ? m.eventTypes : {}).every(isSeq) || !isObj(m.requested) || ![m.requested.from, m.requested.to].every((x) => x === null || typeof x === "string") || ![m.logHead, m.prunedAnchor].every((x) => x === null || isObj(x)) || !isSeq(m.entries) || !isSeq(m.firstSeq) || !isSeq(m.lastSeq) || typeof m.firstHash !== "string" || typeof m.lastHash !== "string" || typeof m.startPrev !== "string" || !HEX64.test(m.startPrev) || !isObj(m.eventTypes) || typeof m.signer !== "string" || typeof m.fromStart !== "boolean" || typeof m.toEnd !== "boolean" || m.entries < 1 || m.firstSeq < 1) {
    return emptyResult(["the bundle's manifest is malformed"]);
  }
  const manifest = m as unknown as BundleManifest;
  const keys = checkKeys(header.keys, manifest.firstSeq, manifest.lastSeq, problems);
  if (keys === null) return { ...emptyResult(problems), signer: manifest.signer };
  const signerKey = keys[keys.length - 1] as LoadedKey;
  if (manifest.signer !== signerKey.k.id) problems.push(`the manifest names ${manifest.signer} as its signer, but the newest key is ${signerKey.k.id}`);
  if (!checkSig(headerMessage(manifest, header.keys as BundleKey[]), signerKey.pub, header.sig)) problems.push("the bundle's header (manifest and keys) has a bad signature: it was edited after export");

  // The entries: one contiguous, signed piece of the chain.
  const events: Record<string, unknown>[] = [];
  let count = 0;
  let expectSeq = manifest.firstSeq;
  let prev = manifest.startPrev;
  let firstHash: string | null = null;
  const pa = manifest.prunedAnchor as unknown;
  let flagged: number | null = isObj(pa) && pa.heads === "signed" && isSeq(pa.seq) ? pa.seq : null;
  /** seq -> hash, to check anchor records and the head against. */
  const hashAt = new Map<number, string>();
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i] as string;
    const where = `line ${i + 1}`;
    const lp = strictParse(line);
    if (!lp.ok) {
      problems.push(`${where}: ${lp.why}`);
      continue;
    }
    const v = lp.v;
    if (!isEntry(v)) {
      problems.push(`${where}: not a log entry`);
      continue;
    }
    const e = v;
    count++;
    if (e.seq !== expectSeq) problems.push(`${where}: sequence ${e.seq}, expected ${expectSeq} (entries missing or reordered)`);
    if (e.prev !== prev) problems.push(`${where}: does not link to the entry before it`);
    const h = entryHash(e.prev, e.seq, e.ts, e.event);
    if (h !== e.hash) problems.push(`${where}: content does not match its hash (edited)`);
    else {
      const key = keyFor(keys, e.seq);
      if (key === null) problems.push(`${where}: no key in the bundle is valid for sequence ${e.seq}`);
      else if (!checkSig(entryMessage(e.hash, e.heads), key.pub, e.sig)) problems.push(`${where}: bad signature (for key ${key.k.id})`);
    }
    if (e.heads === "signed") flagged ??= e.seq;
    else if (flagged !== null) problems.push(`${where}: written without signed heads after sequence ${flagged} was written with them (a downgrade)`);
    if (firstHash === null) firstHash = e.hash;
    events.push(e.event);
    hashAt.set(e.seq, e.hash);
    prev = e.hash;
    expectSeq = e.seq + 1;
  }
  const lastSeq = expectSeq - 1;
  // The manifest's counts and hashes must be those of exactly these entries (a truncated or padded bundle fails).
  if (count !== manifest.entries) problems.push(`the manifest says ${manifest.entries} entries, the bundle holds ${count}`);
  if (lastSeq !== manifest.lastSeq) problems.push(`the manifest says the entries end at sequence ${manifest.lastSeq}, they end at ${lastSeq}`);
  if (firstHash !== manifest.firstHash) problems.push("the first entry's hash is not the manifest's first hash");
  if (prev !== manifest.lastHash) problems.push("the last entry's hash is not the manifest's last hash (entries were removed or added at the end)");
  if (canonicalJson(countTypes(events)) !== canonicalJson(manifest.eventTypes)) problems.push("the counts of event types do not match the manifest");

  // Where the piece sits in the log: its start, and its end against the log's signed head.
  if (manifest.prunedAnchor !== null && manifest.prunedAnchor !== undefined) {
    const a = manifest.prunedAnchor as unknown;
    // Signed by whichever key was in use when the files were pruned: any key of the bundle may have.
    if (!isObj(a) || !onlyKeys(a, PRUNED_KEYS) || !isSeq(a.seq) || typeof a.hash !== "string" || typeof a.sig !== "string") problems.push("the anchor of pruned log files in the manifest is malformed");
    else if (!keys.some((k) => checkSig(prunedAnchorMessage(a.seq as number, a.hash as string, a.heads), k.pub, a.sig))) problems.push("the anchor of pruned log files has a bad signature");
    else if (a.seq !== manifest.firstSeq - 1 || a.hash !== manifest.startPrev) problems.push("the bundle does not start right after the anchor of pruned log files");
  } else if (manifest.fromStart && (manifest.firstSeq !== 1 || manifest.startPrev !== GENESIS)) {
    problems.push("the bundle says it starts at the log's start, but its first entry is not the log's first and no anchor of pruned files is given");
  }
  if (manifest.toEnd) {
    const hd = manifest.logHead as unknown;
    if (!isObj(hd) || !onlyKeys(hd, HEAD_KEYS) || !isSeq(hd.seq) || typeof hd.hash !== "string" || (hd.sig !== undefined && typeof hd.sig !== "string")) problems.push("the bundle says it reaches the log's end, but carries no valid head");
    else {
      const key = keyFor(keys, hd.seq) ?? signerKey;
      if (hd.sig === undefined) {
        if (flagged !== null) problems.push(`the log's head in the bundle has no signature, but heads are signed since sequence ${flagged}`);
      } else if (!checkSig(headMessage(hd.seq, hd.hash), key.pub, hd.sig)) problems.push("the log's head in the bundle has a bad signature");
      // The head is written after its entry without an fsync, so after a power cut it can name an earlier
      // entry (src/runtime/log.ts); behind is accepted when it names an entry of the bundle, ahead is not.
      const named = hd.seq === manifest.firstSeq - 1 ? manifest.startPrev : hashAt.get(hd.seq);
      if (hd.seq > manifest.lastSeq) problems.push(`the bundle ends at sequence ${manifest.lastSeq}, before the log's head (${hd.seq}): it was cut short`);
      else if (named !== hd.hash) problems.push(`the log's head (sequence ${hd.seq}) is not an entry of this bundle`);
      else if (hd.seq < manifest.lastSeq) notes.push(`the log's head named sequence ${hd.seq}, behind its last entry (${manifest.lastSeq}); a power cut leaves it so until the next append`);
    }
  }

  // Who signed it.
  const ids = new Set(keys.map((k) => k.k.id));
  let pinned = false;
  for (const raw of opts.keys ?? []) {
    const pin = normalizePin(raw);
    // Never echo the value: it may be text read from a file that is not a key at all.
    if (pin === null) problems.push("a --key value is not a fingerprint (sha256:<64 hex>) or a PEM public key (file)");
    else if (ids.has(pin)) pinned = true;
    else problems.push(`the bundle is signed by ${[...ids].join(", ")}, not by the pinned key ${pin} (another install's log, or the key was replaced)`);
  }

  // Anchor records written off the machine: the hash at each anchored position must be in the chain.
  let anchorsMatched = 0;
  let anchorsGiven = 0;
  const startPos = manifest.firstSeq - 1;
  for (const textA of opts.anchors ?? []) {
    const { records, bad } = parseAnchorRecords(textA);
    if (bad > 0) problems.push(`${bad} line(s) of an anchor file are not JSON`);
    for (const r of records) {
      anchorsGiven++;
      if (!isAnchorRecord(r)) {
        problems.push("an anchor record is malformed");
        continue;
      }
      if (r.version !== ANCHOR_VERSION) {
        problems.push(`an anchor record is version ${r.version}; this verifier reads version ${ANCHOR_VERSION}`);
        continue;
      }
      const key = keys.find((k) => k.k.id === r.key);
      if (key === undefined) {
        problems.push(`the anchor record for sequence ${r.seq} was made with key ${r.key}, which did not sign this bundle (another install's log, or the key was replaced)`);
        continue;
      }
      if (!checkSig(anchorRecordMessage(r), key.pub, r.sig)) {
        problems.push(`the anchor record for sequence ${r.seq} has a bad signature`);
        continue;
      }
      const at = r.seq === startPos ? manifest.startPrev : hashAt.get(r.seq);
      if (at !== undefined) {
        if (at !== r.hash) problems.push(`the anchor record of ${r.at} says entry ${r.seq} has hash ${r.hash.slice(0, 16)}..., the bundle's has ${at.slice(0, 16)}...: the log's history was rewritten after it was anchored`);
        else anchorsMatched++;
      } else if (r.seq > manifest.lastSeq && manifest.toEnd) {
        problems.push(`the anchor record of ${r.at} names entry ${r.seq}, but the log now ends at ${manifest.lastSeq}: entries were removed after it was anchored`);
      } else notes.push(`the anchor record for sequence ${r.seq} is outside this bundle (${startPos === 0 ? 1 : startPos}..${manifest.lastSeq}) and was not checked`);
    }
  }
  if (anchorsGiven > 0 && anchorsMatched === 0 && !problems.some((p) => p.includes("anchor record"))) problems.push("no anchor record falls inside this bundle, so none could be checked (export a range that includes an anchored entry)");
  const intact = problems.length === 0;
  const authenticated = pinned || anchorsMatched > 0;
  const status: BundleStatus = !intact ? "invalid" : authenticated || opts.allowUnpinned === true ? "ok" : "unauthenticated";
  if (!authenticated && intact) notes.push(`signed by ${signerKey.k.id}, which is not pinned: compare it with the fingerprint you kept (--key), or check an anchor record (--anchor), to know the bundle came from your install`);
  return { ok: status === "ok", status, intact, authenticated, problems, notes, entries: count, firstSeq: manifest.firstSeq, lastSeq, lastHash: prev, signer: signerKey.k.id, pinned, anchorsMatched };
}

/** The report a person reads. */
export function formatResult(r: BundleVerifyResult): string {
  const lines: string[] = [];
  const intact = `${r.entries} entries (sequence ${r.firstSeq ?? "?"} to ${r.lastSeq ?? "?"}); chain, hashes, signatures, keys and manifest counts are valid`;
  if (r.status === "invalid") lines.push("PROBLEMS:", ...r.problems);
  else if (r.status === "unauthenticated") lines.push(`UNAUTHENTICATED: ${intact}, but nothing ties the bundle to your key, and anyone can make a consistent bundle with a key of their own. Pass --key with the fingerprint you kept, or --anchor with your anchor records (--no-pin accepts it as it is).`);
  else {
    lines.push(`OK: ${intact}.`);
    if (r.pinned) lines.push(`Signed by the pinned key ${r.signer ?? ""}.`);
    if (r.anchorsMatched > 0) lines.push(`${r.anchorsMatched} anchor record(s) match.`);
    if (!r.authenticated) lines.push("Not authenticated (--no-pin): this proves the bundle is consistent, not whose it is.");
  }
  for (const n of r.notes) lines.push(`Note: ${n}`);
  return lines.join("\n");
}

// --- standalone use: node verify.js <bundle> [--key K]... [--anchor FILE]... [--json] ---------------

export function cliMain(argv: readonly string[], write: (s: string) => void = (s) => process.stdout.write(s)): number {
  const keys: string[] = [];
  const anchors: string[] = [];
  let bundle: string | null = null;
  let json = false;
  let noPin = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a === "--json") json = true;
    else if (a === "--no-pin") noPin = true;
    else if (a === "--key" || a === "--anchor") {
      const v = argv[++i];
      if (v === undefined) {
        write(`${a} needs a value\n`);
        return 64;
      }
      if (a === "--key") keys.push(resolvePin(v));
      else anchors.push(readFileSync(v, "utf8"));
    } else if (bundle === null && !a.startsWith("-")) bundle = a;
    else {
      write(`usage: node verify.js <bundle> [--key FINGERPRINT|PEM-FILE]... [--anchor FILE]... [--no-pin] [--json]\n`);
      return 64;
    }
  }
  if (bundle === null) {
    write(`usage: node verify.js <bundle> [--key FINGERPRINT|PEM-FILE]... [--anchor FILE]... [--no-pin] [--json]\n`);
    return 64;
  }
  const r = verifyBundle(readFileSync(bundle, "utf8"), { keys, anchors, allowUnpinned: noPin });
  write(`${json ? JSON.stringify(r, null, 2) : formatResult(r)}\n`);
  return statusExit(r.status);
}

// This file is its own entry point when run as `node verify.js` (it stands apart from src/cli.ts on purpose).
// eslint-disable-next-line no-restricted-properties -- the standalone verifier reads its own command line
const argv = process.argv;
/* v8 ignore next 3 */
if (argv[1] !== undefined && import.meta.url === pathToFileURL(argv[1]).href) {
  process.exitCode = cliMain(argv.slice(2));
}
