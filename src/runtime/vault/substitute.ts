/**
 * Reading values for an allowed substitution, and its audit entries
 * (see docs/vault.md). Values exist here only for
 * the one action, in memory; they are never logged, queued or returned to a
 * caller that would print them. A failure denies: an action is never sent
 * with a reference left in where a value should be.
 */

import { bindingSummary, findRefs, hostBindingMatches, REF_PATHS_DEPTH, toolMatches } from "../../engine/vault-ref.js";
import type { KnownValue } from "../../engine/vault-scrub.js";
import type { VaultSubstitution } from "../../types.js";
import type { Layout } from "../layout.js";
import { appendBounded as appendLog } from "../logbound.js";
import { accountFor, type VaultBackend } from "./backend.js";
import { openBackend } from "./backends.js";
import { loadIndex, type BackendId, type VaultEntry } from "./index.js";

export type BackendFor = (id: BackendId) => VaultBackend;

/**
 * The stores a hook or the gateway can read: the keychain and the Secret Service. The encrypted file store
 * needs the approval passphrase, which no unattended process has (its `vault unlock` is not built), so a
 * read from it fails and the action is denied.
 */
export function defaultBackendFor(l: Layout): BackendFor {
  return (id) => openBackend(id, l, { passphrase: "" });
}

/** Whether the entry (as the signed index has it now) still permits this substitution. */
function stillBound(e: VaultEntry, s: VaultSubstitution): boolean {
  return e.bindings.some((b) => {
    if (bindingSummary(b) !== s.binding) return false;
    if (b.kind === "host") return hostBindingMatches(b.host, s.destination);
    if (b.kind === "mcp") {
      const [, server, ...tool] = s.destination.split(":");
      return b.server === server && toolMatches(b.tool, tool.join(":")) && (b.arg === undefined || b.arg === s.path);
    }
    return s.via === "run";
  });
}

export type ReadResult = { ok: true; values: KnownValue[] } | { ok: false; ref: string; why: string };

/**
 * The values for these substitutions, read from the stores. The index is read again and verified against
 * the trusted key, so a binding revoked since the decision, or an index changed on disk, stops it.
 */
export function readValues(l: Layout, subs: readonly VaultSubstitution[], trustedKey: string | null, backendFor: BackendFor): ReadResult {
  const st = loadIndex(l, trustedKey);
  if (st.state !== "ok") return { ok: false, ref: subs[0]?.ref ?? "vault://", why: st.state === "unsigned" ? st.reason : st.state === "corrupt" ? st.error : "the vault is empty" };
  const values: KnownValue[] = [];
  for (const s of subs) {
    if (values.some((v) => v.ref === s.ref)) continue;
    const e = st.index.entries.find((x) => x.name === s.name);
    if (e === undefined || !e.fields.includes(s.field)) return { ok: false, ref: s.ref, why: "no such secret any more" };
    if (!stillBound(e, s)) return { ok: false, ref: s.ref, why: `it is no longer bound to ${s.destination}` };
    try {
      const value = backendFor(e.backend).read(accountFor(e.name, s.field));
      if (value === "") return { ok: false, ref: s.ref, why: "the stored value is empty" };
      values.push({ ref: s.ref, value });
    } catch (err) {
      return { ok: false, ref: s.ref, why: `could not read it from the ${e.backend} store (${(err as Error).message.slice(0, 160)})` };
    }
  }
  return { ok: true, values };
}

/**
 * One pass over the references of a text: each whole reference whose text is a known one becomes its value,
 * and everything else (a value's own text included) is copied as it is. Never re-scanned, so a value that
 * contains "vault://other" is not expanded again, and text that only looks like a reference stays text.
 */
function replaceRefs(text: string, values: readonly KnownValue[]): string {
  const byRef = new Map(values.map((k) => [k.ref, k.value] as const));
  let out = "";
  let at = 0;
  for (const r of findRefs(text)) {
    const v = byRef.get(r.text);
    if (v === undefined) continue;
    out += text.slice(at, r.index) + v;
    at = r.index + r.text.length;
  }
  return at === 0 ? text : out + text.slice(at);
}

/** Puts the values in place of their references in every string of a JSON value. */
export function substituteJson<T>(v: T, values: readonly KnownValue[]): T {
  const walk = (x: unknown): unknown => {
    if (typeof x === "string") return replaceRefs(x, values);
    if (Array.isArray(x)) return x.map(walk);
    if (typeof x === "object" && x !== null) return Object.fromEntries(Object.entries(x).map(([k, y]) => [k, walk(y)]));
    return x;
  };
  return walk(v) as T;
}

/**
 * Puts each value in at the argument paths its substitutions were checked at (VaultSubstitution.path), and
 * nowhere else (V17): a reference at any other path stays text. Paths are formatted as refPaths formats
 * them; a substitution without a path puts nothing in. Never deeper than refPaths looks.
 */
export function substituteAtPaths<T>(v: T, subs: readonly VaultSubstitution[], values: readonly KnownValue[]): T {
  const allowed = new Map<string, KnownValue[]>();
  for (const s of subs) {
    if (s.path === undefined) continue;
    const k = values.find((x) => x.ref === s.ref);
    if (k === undefined) continue;
    allowed.set(s.path, [...(allowed.get(s.path) ?? []), k]);
  }
  const walk = (x: unknown, p: string, d: number): unknown => {
    if (d > REF_PATHS_DEPTH) return x;
    if (typeof x === "string") return replaceRefs(x, allowed.get(p) ?? []);
    if (Array.isArray(x)) return x.map((y, i) => walk(y, `${p}[${i}]`, d + 1));
    if (typeof x === "object" && x !== null) return Object.fromEntries(Object.entries(x).map(([k, y]) => [k, walk(y, p === "" ? k : `${p}.${k}`, d + 1)]));
    return x;
  };
  return walk(v, "", 0) as T;
}

/** `vault_use`: one per substituted reference. Never a value or a fingerprint. */
export function logUse(l: Layout, s: VaultSubstitution, o: { session: string; action: string; verdict: string; extra?: Record<string, unknown> }): void {
  appendLog(l, { type: "vault_use", session: o.session, ref: s.ref, kind: s.kind, via: s.via, destination: s.destination, binding: s.binding, action: o.action, verdict: o.verdict, ...(o.extra ?? {}) });
}

/** `vault_denied`: a refused use (a rule, or a store that could not be read). */
export function logDenied(l: Layout, o: { session: string; refs: readonly string[]; rule?: string; destination?: string; problem?: string; extra?: Record<string, unknown> }): void {
  appendLog(l, { type: "vault_denied", session: o.session, refs: o.refs.slice(0, 10), ...(o.rule !== undefined ? { rule: o.rule } : {}), ...(o.destination !== undefined ? { destination: o.destination } : {}), ...(o.problem !== undefined ? { problem: o.problem.slice(0, 300) } : {}), ...(o.extra ?? {}) });
}
