/**
 * Vault references and per-secret destination rules. Pure: no
 * I/O, no values. The runtime builds a VaultView from the signed index
 * (names, kinds, fields, bindings and fingerprints, never a value) and the
 * engine uses it to tell whether a vaulted value may go to a destination.
 *
 * A reference is `vault://<name>[#<field>]`: <name> is 1 to 4 segments of
 * [a-z0-9][a-z0-9_-]{0,62} joined by "/", <field> is [a-z0-9_]{1,32}. It must
 * start on a word boundary, so `https://example.com/vault://docs` is not one.
 */

import { setOwn } from "../own.js";
import { containsFingerprint } from "./secrets.js";
import { globMatch } from "./glob.js";
import { normalizeHost, parseUrlLike } from "./network.js";
import type { Effect } from "../types.js";

export const VAULT_KINDS = ["credential", "oauth", "card", "iban", "national_id", "personal"] as const;
export type VaultKind = (typeof VAULT_KINDS)[number];

/** Where a secret may go. Bindings live only in the signed index, never in a policy file. */
export type VaultBinding =
  | { kind: "host"; host: string; allowInUrl?: boolean; /** Plain http is allowed too (the default is https only). */ allowHttp?: boolean }
  | { kind: "mcp"; server: string; tool?: string; arg?: string }
  | { kind: "process"; argv: string[]; display: string };

export interface VaultViewEntry {
  name: string;
  kind: VaultKind;
  fields: string[];
  bindings: VaultBinding[];
  /** Per field, secrets.ts fingerprint() of the value (fields shorter than 12 characters have none). */
  fingerprints: Record<string, string>;
  /** The macOS per-use confirmation chosen at `vault add` ("always": every read shows the keychain dialog). */
  confirm?: "always" | "never";
}

/**
 * The engine's view of the vault. `signed` is false when the index's signature did not verify against
 * the person's approval key: its fingerprints are still used (a vaulted value is still a credential), but
 * no binding is trusted, so no destination is bound.
 */
export interface VaultView {
  signed: boolean;
  entries: VaultViewEntry[];
  /**
   * FB5: why the index cannot be trusted (unreadable, or its signature does not verify). Sending anything
   * then asks (FW-VAULT-INDEX): a stored value could leave unrecognised, or the bindings be forged.
   */
  damaged?: string;
}

const SEGMENT = "[a-z0-9][a-z0-9_-]{0,62}";
export const NAME_RE = new RegExp(`^${SEGMENT}(?:/${SEGMENT}){0,3}$`);
export const FIELD_RE = /^[a-z0-9_]{1,32}$/;
const REF_SOURCE = `(?<![A-Za-z0-9_./:#-])vault://(${SEGMENT}(?:/${SEGMENT}){0,3})(?:#([a-z0-9_]{1,32}))?(?![A-Za-z0-9_/#-])`;

export interface VaultRef {
  /** The reference as written. */
  text: string;
  name: string;
  /** The field named after "#", if any. */
  field?: string;
  index: number;
}

export function isValidName(name: string): boolean {
  return name.length <= 255 && NAME_RE.test(name);
}

export function isValidField(field: string): boolean {
  return FIELD_RE.test(field);
}

/** Every reference in a text (inside quotes and JSON strings too), in order. */
export function findRefs(text: string): VaultRef[] {
  const out: VaultRef[] = [];
  for (const m of text.matchAll(new RegExp(REF_SOURCE, "g"))) {
    out.push({ text: m[0], name: m[1] as string, ...(m[2] !== undefined ? { field: m[2] } : {}), index: m.index });
  }
  return out;
}

/** Parses one whole reference, or null. */
export function parseRef(s: string): VaultRef | null {
  const r = findRefs(s);
  return r.length === 1 && r[0]?.index === 0 && r[0].text === s ? r[0] : null;
}

export function formatRef(name: string, field?: string): string {
  return field === undefined ? `vault://${name}` : `vault://${name}#${field}`;
}

export type Resolved = { ok: true; entry: VaultViewEntry; field: string } | { ok: false; reason: string };

/**
 * What a reference names. A reference to no entry, or to a field the entry lacks, is unknown, so a typo
 * never lets the reference text go out as if it were a value. Without "#field" an entry with one field
 * resolves to it; an entry with several needs the field.
 */
export function resolveRef(ref: Pick<VaultRef, "name" | "field">, view: VaultView | undefined): Resolved {
  const entry = view?.entries.find((e) => e.name === ref.name);
  if (entry === undefined) return { ok: false, reason: `no such secret: ${formatRef(ref.name)}` };
  if (ref.field === undefined) {
    if (entry.fields.length === 1) return { ok: true, entry, field: entry.fields[0] as string };
    return { ok: false, reason: `${formatRef(ref.name)} has several fields (${entry.fields.join(", ")}); name one with #field` };
  }
  if (!entry.fields.includes(ref.field)) return { ok: false, reason: `${formatRef(ref.name)} has no field "${ref.field}" (it has ${entry.fields.join(", ")})` };
  return { ok: true, entry, field: ref.field };
}

/** A host binding: the exact host, or any subdomain when written "*.example.com" (not the apex). */
export function hostBindingMatches(pattern: string, host: string): boolean {
  const h = normalizeHost(host);
  const p = pattern.trim().toLowerCase();
  if (p.startsWith("*.")) return h.endsWith(`.${normalizeHost(p.slice(2))}`);
  return h === normalizeHost(p);
}

/** Whether a host pattern is acceptable in a binding: a DNS name, optionally "*." in front; never a bare "*" or a TLD wildcard. */
export function validHostPattern(pattern: string): boolean {
  const p = pattern.trim().toLowerCase();
  const base = p.startsWith("*.") ? p.slice(2) : p;
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(base)) return false;
  return !p.startsWith("*.") || base.includes(".");
}

/** An MCP tool pattern (glob over the tool's name, `*` and `?` only). */
export function toolMatches(pattern: string | undefined, tool: string | undefined): boolean {
  if (pattern === undefined) return true;
  if (tool === undefined) return false;
  // Past the matcher's bounds a binding does not match: the value is not released.
  return globMatch(pattern, tool, false, false);
}

/**
 * A process binding: the argv pattern matches word for word; "*" is allowed only as a whole trailing word
 * and matches any (possibly empty) rest. A bare "*" program never matches anything.
 */
export function processBindingMatches(pattern: readonly string[], argv: readonly string[]): boolean {
  if (pattern.length === 0 || pattern[0] === "*") return false;
  const trailing = pattern[pattern.length - 1] === "*";
  const fixed = trailing ? pattern.slice(0, -1) : pattern;
  if (fixed.some((w) => w === "*")) return false;
  if (trailing ? argv.length < fixed.length : argv.length !== fixed.length) return false;
  return fixed.every((w, i) => argv[i] === w);
}

/** A binding as one line, for `vault list` and the log (no value, no fingerprint). */
export function bindingSummary(b: VaultBinding): string {
  if (b.kind === "host") return `host ${b.host}${b.allowInUrl === true ? " (also in the URL)" : ""}${b.allowHttp === true ? " (also over plain http)" : ""}`;
  if (b.kind === "mcp") return `mcp ${b.server}${b.tool !== undefined ? `:${b.tool}` : ""}${b.arg !== undefined ? `:${b.arg}` : ""}`;
  return `process ${b.display}`;
}

function serversOf(e: Effect): string[] {
  return (e.tags ?? []).filter((t) => t.startsWith("mcp-call:")).map((t) => t.slice(9));
}

function toolOf(e: Effect): string | undefined {
  return (e.tags ?? []).find((t) => t.startsWith("mcp-tool:"))?.slice(9);
}

function onlyAtArg(payload: string | undefined, arg: string, prints: readonly string[]): boolean {
  if (payload === undefined || arg === "" || prints.length === 0) return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    return false;
  }
  if (typeof parsed !== "object" || parsed === null) return false;
  let matched = false;
  let complete = true;
  const walk = (x: unknown, p: string, d: number): unknown => {
    if (!complete) return x;
    if (d > REF_PATHS_DEPTH) {
      complete = false;
      return x;
    }
    if (typeof x === "string") {
      if (p === arg && containsFingerprint(x, prints)) {
        matched = true;
        return "";
      }
      return x;
    }
    if (Array.isArray(x)) return x.map((y, i) => walk(y, `${p}[${i}]`, d + 1));
    if (typeof x === "object" && x !== null) {
      const out: Record<string, unknown> = {};
      for (const [k, y] of Object.entries(x)) setOwn(out, k, walk(y, p === "" ? k : `${p}.${k}`, d + 1));
      return out;
    }
    return x;
  };
  const stripped = walk(parsed, "", 0);
  return complete && matched && !containsFingerprint(JSON.stringify(stripped), prints);
}

/**
 * Whether an egress effect goes somewhere this entry is bound to. Process bindings never bind an egress
 * effect (only `run` uses them). A value in the URL itself also needs allowInUrl, because secrets in
 * URLs end up in server logs and proxies. With an unsigned index nothing is bound.
 */
export function egressBound(entry: VaultViewEntry, e: Effect, view: VaultView): boolean {
  if (!view.signed) return false;
  if (entry.kind === "oauth") return false;
  const prints = Object.values(entry.fingerprints);
  const targetUrl = parseUrlLike(e.target);
  const inUrl = targetUrl !== null && prints.length > 0 && containsFingerprint(e.target, prints);
  for (const b of entry.bindings) {
    if (b.kind === "host") {
      if (e.host === undefined || !hostBindingMatches(b.host, e.host)) continue;
      if (inUrl && b.allowInUrl !== true) continue;
      if (targetUrl === null || (targetUrl.scheme !== "https" && !(targetUrl.scheme === "http" && b.allowHttp === true))) continue;
      return true;
    }
    if (b.kind === "mcp") {
      if (!serversOf(e).includes(b.server)) continue;
      if (!toolMatches(b.tool, toolOf(e))) continue;
      if (b.arg !== undefined && !onlyAtArg(e.payload, b.arg, prints)) continue;
      return true;
    }
  }
  return false;
}

/** Every fingerprint in the view. */
export function vaultFingerprints(view: VaultView | undefined): string[] {
  return view === undefined ? [] : view.entries.flatMap((e) => Object.values(e.fingerprints));
}

/**
 * The entries whose value (in any encoding containsFingerprint handles) is in this text. One scan over all
 * fingerprints first, so text without any vaulted value costs one pass.
 */
export function entriesIn(text: string, view: VaultView | undefined): VaultViewEntry[] {
  const all = vaultFingerprints(view);
  if (view === undefined || all.length === 0 || text === "" || !containsFingerprint(text, all)) return [];
  return view.entries.filter((e) => {
    const p = Object.values(e.fingerprints);
    return p.length > 0 && containsFingerprint(text, p);
  });
}

/** Where a reference sits inside a JSON value: a dotted path ("headers.token", "items[2].key"). */
export interface RefAt {
  ref: VaultRef;
  path: string;
}

/** How far refPaths looks: past either cap the arguments are refused, never partly checked. */
export const REF_PATHS_MAX = 1000;
export const REF_PATHS_DEPTH = 64;

/** Every reference in the strings of a JSON value, with its path. Keys are not searched (a key is never a value). */
export function refPaths(v: unknown, path = "", out: RefAt[] = [], depth = 0): RefAt[] {
  return refPathsChecked(v, path, out, depth).paths;
}

/**
 * refPaths, and whether the walk saw everything: false when it stopped at REF_PATHS_MAX references or
 * REF_PATHS_DEPTH levels. A caller that decides on the paths must refuse an incomplete walk (V17): a
 * reference it did not see could otherwise be substituted where no binding allows it.
 */
export function refPathsChecked(v: unknown, path = "", out: RefAt[] = [], depth = 0): { paths: RefAt[]; complete: boolean } {
  let complete = true;
  const walk = (x: unknown, p: string, d: number): void => {
    if (!complete) return;
    if (d > REF_PATHS_DEPTH) {
      // Only a subtree that carries a reference makes the walk incomplete; deep arguments without one are fine.
      if (findRefs(typeof x === "string" ? x : JSON.stringify(x) ?? "").length > 0) complete = false;
      return;
    }
    if (typeof x === "string") {
      for (const ref of findRefs(x)) {
        if (out.length >= REF_PATHS_MAX) {
          complete = false;
          return;
        }
        out.push({ ref, path: p });
      }
    } else if (Array.isArray(x)) {
      x.forEach((y, i) => walk(y, `${p}[${i}]`, d + 1));
    } else if (typeof x === "object" && x !== null) {
      for (const [k, y] of Object.entries(x)) walk(y, p === "" ? k : `${p}.${k}`, d + 1);
    }
  };
  walk(v, path, depth);
  return { paths: out, complete };
}

/** A reference's canonical text (with the field it resolves to), the key substitution and scrubbing use. */
export function canonicalRef(entry: Pick<VaultViewEntry, "name" | "fields">, field: string): string {
  return entry.fields.length === 1 ? formatRef(entry.name) : formatRef(entry.name, field);
}
