/**
 * The vault index (`vault/index.json`): which secrets exist, their kinds,
 * fields, backends and bindings, and the fingerprints of their values. It
 * holds no value. A forged binding would let a value go to the wrong host, so
 * the index is signed with the approver key (the approval passphrase unlocks
 * it) and verified against the pinned approver key; a bad signature means no
 * destination is bound.
 */

import { createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { join } from "node:path";
import { canonicalJson } from "../../engine/decide.js";
import { FIELD_RE, isValidName, VAULT_KINDS, type VaultBinding, type VaultKind, type VaultView } from "../../engine/vault-ref.js";
import type { Confirm } from "../../policy-vault.js";
import { atomicWrite, ensureDir, readText, withLock } from "../fsutil.js";
import { assertNotRealHome } from "../guard.js";
import type { Layout } from "../layout.js";

export type BackendId = "keychain" | "libsecret" | "file";
export const BACKEND_IDS: readonly BackendId[] = ["keychain", "libsecret", "file"];

export interface VaultEntry {
  name: string;
  kind: VaultKind;
  fields: string[];
  backend: BackendId;
  /** The macOS Keychain access list chosen at add time ("always": every read shows the keychain dialog). */
  confirm: Confirm;
  bindings: VaultBinding[];
  /** Per field, secrets.ts fingerprint() of the value; never the value. */
  fingerprints: Record<string, string>;
  createdAt: string;
  rotatedAt?: string;
}

export interface VaultIndex {
  version: 1;
  entries: VaultEntry[];
  signedAt: string;
  /** Ed25519 over the canonical JSON of {version, entries, signedAt}, with the approver key, base64. */
  sig: string;
}

export function vaultDir(l: Layout): string {
  return join(l.home, "vault");
}

export function indexPath(l: Layout): string {
  return join(vaultDir(l), "index.json");
}

function message(version: 1, entries: readonly VaultEntry[], signedAt: string): Buffer {
  return Buffer.from(`launchsafe-firewall/vault-index/v1\n${canonicalJson({ version, entries, signedAt })}`, "utf8");
}

export function signIndex(priv: KeyObject, entries: readonly VaultEntry[], now: Date = new Date()): VaultIndex {
  const signedAt = now.toISOString();
  return { version: 1, entries: [...entries], signedAt, sig: sign(null, message(1, entries, signedAt), priv).toString("base64") };
}

/** Whether the index was signed by the approver key whose public half (base64 SPKI DER) is given. */
export function verifyIndex(idx: VaultIndex, publicKeyB64: string | null): boolean {
  if (publicKeyB64 === null || publicKeyB64 === "") return false;
  try {
    const pub = createPublicKey({ key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki" });
    return verify(null, message(idx.version, idx.entries, idx.signedAt), pub, Buffer.from(idx.sig, "base64"));
  } catch {
    return false;
  }
}

const isStr = (v: unknown): v is string => typeof v === "string";

function parseBinding(v: unknown): VaultBinding | null {
  if (typeof v !== "object" || v === null) return null;
  const b = v as Record<string, unknown>;
  if (b.kind === "host" && isStr(b.host) && (b.allowInUrl === undefined || typeof b.allowInUrl === "boolean") && (b.allowHttp === undefined || typeof b.allowHttp === "boolean")) return { kind: "host", host: b.host, ...(b.allowInUrl === true ? { allowInUrl: true } : {}), ...(b.allowHttp === true ? { allowHttp: true } : {}) };
  if (b.kind === "mcp" && isStr(b.server) && (b.tool === undefined || isStr(b.tool)) && (b.arg === undefined || isStr(b.arg))) return { kind: "mcp", server: b.server, ...(isStr(b.tool) ? { tool: b.tool } : {}), ...(isStr(b.arg) ? { arg: b.arg } : {}) };
  if (b.kind === "process" && Array.isArray(b.argv) && b.argv.every(isStr) && isStr(b.display)) return { kind: "process", argv: b.argv as string[], display: b.display };
  return null;
}

function parseEntry(v: unknown): VaultEntry | null {
  if (typeof v !== "object" || v === null) return null;
  const e = v as Record<string, unknown>;
  if (!isStr(e.name) || !isValidName(e.name)) return null;
  if (!isStr(e.kind) || !(VAULT_KINDS as readonly string[]).includes(e.kind)) return null;
  if (!Array.isArray(e.fields) || e.fields.length === 0 || !e.fields.every((f) => isStr(f) && FIELD_RE.test(f))) return null;
  if (!isStr(e.backend) || !(BACKEND_IDS as readonly string[]).includes(e.backend)) return null;
  if (e.confirm !== "always" && e.confirm !== "never") return null;
  if (!Array.isArray(e.bindings)) return null;
  const bindings = e.bindings.map(parseBinding);
  if (bindings.some((b) => b === null)) return null;
  if (typeof e.fingerprints !== "object" || e.fingerprints === null || !Object.values(e.fingerprints).every(isStr)) return null;
  if (!isStr(e.createdAt) || (e.rotatedAt !== undefined && !isStr(e.rotatedAt))) return null;
  return {
    name: e.name,
    kind: e.kind as VaultKind,
    fields: e.fields as string[],
    backend: e.backend as BackendId,
    confirm: e.confirm,
    bindings: bindings as VaultBinding[],
    fingerprints: { ...(e.fingerprints as Record<string, string>) },
    createdAt: e.createdAt,
    ...(isStr(e.rotatedAt) ? { rotatedAt: e.rotatedAt } : {}),
  };
}

/** Parses an index file's text strictly; null when anything is off. */
export function parseIndex(text: string): VaultIndex | null {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null) return null;
  const o = raw as Record<string, unknown>;
  if (o.version !== 1 || !Array.isArray(o.entries) || !isStr(o.signedAt) || !isStr(o.sig)) return null;
  const entries = o.entries.map(parseEntry);
  if (entries.some((e) => e === null)) return null;
  const names = new Set((entries as VaultEntry[]).map((e) => e.name));
  if (names.size !== entries.length) return null;
  return { version: 1, entries: entries as VaultEntry[], signedAt: o.signedAt, sig: o.sig };
}

export type IndexState =
  | { state: "absent" }
  | { state: "corrupt"; error: string }
  | { state: "unsigned"; index: VaultIndex; reason: string }
  | { state: "ok"; index: VaultIndex };

/**
 * Reads and verifies the index against the approver key the caller trusts (the hook: the key pinned in
 * its command; the CLI: the key on disk). Never throws.
 */
export function loadIndex(l: Layout, trustedKey: string | null): IndexState {
  let text: string | null;
  try {
    text = readText(indexPath(l));
  } catch (e) {
    return { state: "corrupt", error: `${indexPath(l)} cannot be read (${(e as Error).message})` };
  }
  if (text === null) return { state: "absent" };
  const idx = parseIndex(text);
  if (idx === null) return { state: "corrupt", error: `${indexPath(l)} is not a valid vault index` };
  if (trustedKey === null) return { state: "unsigned", index: idx, reason: "no approval key is set or pinned" };
  if (!verifyIndex(idx, trustedKey)) return { state: "unsigned", index: idx, reason: "the vault index is not signed by your approval key" };
  return { state: "ok", index: idx };
}

/** The engine's view: names, kinds, fields, bindings and fingerprints. Undefined when there is no usable index. */
export function vaultView(st: IndexState): VaultView | undefined {
  if (st.state === "absent") return undefined;
  // FB5: an unreadable index is not "no vault": nothing can be recognised, so sends fail closed.
  if (st.state === "corrupt") return { signed: false, entries: [], damaged: st.error };
  return { signed: st.state === "ok", ...(st.state === "unsigned" ? { damaged: st.reason } : {}), entries: st.index.entries.map((e) => ({ name: e.name, kind: e.kind, fields: [...e.fields], bindings: e.bindings, fingerprints: { ...e.fingerprints }, confirm: e.confirm })) };
}

export class VaultIndexError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultIndexError";
  }
}

/**
 * Changes the index under its lock: reads it, refuses to build on one that does not verify against the
 * key being used to sign (re-signing a forged index would launder it), applies the change and re-signs.
 */
export function updateIndex<T>(l: Layout, priv: KeyObject, change: (entries: VaultEntry[]) => T, now: Date = new Date()): T {
  assertNotRealHome(indexPath(l));
  ensureDir(vaultDir(l));
  const pub = (createPublicKey(priv).export({ type: "spki", format: "der" }) as Buffer).toString("base64");
  return withLock(join(vaultDir(l), "index.lock"), () => {
    const st = loadIndex(l, pub);
    if (st.state === "corrupt") throw new VaultIndexError(`${st.error}. Nothing was changed. Move it aside to start an empty vault (the stored values stay in the backend until you add the same names again).`);
    if (st.state === "unsigned") throw new VaultIndexError(`${st.reason}, so it may have been changed by something other than you. Nothing was changed. Check ${indexPath(l)}; to start over, move it aside.`);
    const entries = st.state === "ok" ? st.index.entries.map((e) => ({ ...e, bindings: [...e.bindings], fields: [...e.fields], fingerprints: { ...e.fingerprints } })) : [];
    const result = change(entries);
    atomicWrite(indexPath(l), `${JSON.stringify(signIndex(priv, entries, now), null, 2)}\n`, 0o600);
    return result;
  });
}
