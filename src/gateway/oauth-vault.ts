/**
 * Upstream OAuth tokens in the vault (
 * upstream OAuth tokens are entries of kind `oauth`, bound `mcp:<server>`,
 * substituted into the upstream Authorization header, never into arguments).
 *
 * - `mcp login` (person-run, approval passphrase) stores the access and
 *   refresh tokens as `vault://mcp/<server>` (fields access_token and
 *   refresh_token) and signs the entry and its binding into the index. The
 *   login's file in `gateway/tokens/` then keeps only what is not secret
 *   (issuer, resource, client id, token endpoint) and the entry's name.
 * - A refresh happens unattended in the gateway, which has no approval key:
 *   it writes the new values straight to the store (the binding does not
 *   change, so the signed index need not) and records their fingerprints in
 *   `vault/oauth-prints.json`. That file is unsigned, which is safe because
 *   fingerprints only ever add detection (scrubbing, FW-VAULT-EGRESS); a
 *   binding never comes from it. Each refresh is a `vault_change` entry.
 * - The gateway uses a token only when the signed index still has the entry,
 *   of kind oauth, bound to that server: a forged or revoked binding means no
 *   Authorization header, and the person is asked to sign in again.
 */

import type { KeyObject } from "node:crypto";
import { join } from "node:path";
import { fingerprint } from "../engine/secrets.js";
import { isValidName, type VaultView } from "../engine/vault-ref.js";
import type { Confirm } from "../policy-vault.js";
import { atomicWrite, ensureDir, readText, withLock } from "../runtime/fsutil.js";
import type { Layout } from "../runtime/layout.js";
import { appendLog } from "../runtime/log.js";
import { accountFor, type VaultBackend } from "../runtime/vault/backend.js";
import { loadIndex, vaultDir } from "../runtime/vault/index.js";
import { addSecret, allowBinding, rotateSecret } from "../runtime/vault/store.js";
import type { BackendFor } from "../runtime/vault/substitute.js";
import type { TokenSet } from "./oauth.js";
import { own, setOwn } from "../own.js";

export const OAUTH_FIELDS = ["access_token", "refresh_token"] as const;
/** Stored as the refresh token when the server issued none (the store refuses an empty value). */
const NO_REFRESH = "-";

/** The vault name for a server's tokens (`mcp/<server>`), or null when the server's name cannot be one. */
export function oauthVaultName(server: string): string | null {
  const slug = server.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^[-_]+/, "").slice(0, 63);
  const name = `mcp/${slug}`;
  return slug !== "" && isValidName(name) ? name : null;
}

export function rotatingPrintsPath(l: Layout): string {
  return join(vaultDir(l), "oauth-prints.json");
}

type Prints = Record<string, Record<string, string>>;

function readPrints(l: Layout): Prints {
  try {
    const t = readText(rotatingPrintsPath(l));
    if (t === null) return {};
    const v = JSON.parse(t) as unknown;
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Prints) : {};
  } catch {
    return {};
  }
}

function writePrints(l: Layout, name: string, prints: Record<string, string> | null): void {
  ensureDir(vaultDir(l));
  withLock(`${rotatingPrintsPath(l)}.lock`, () => {
    const all = readPrints(l);
    if (prints === null) delete all[name];
    else setOwn(all, name, prints);
    atomicWrite(rotatingPrintsPath(l), `${JSON.stringify(all, null, 2)}\n`, 0o600);
  });
}

/** The view with the current (refreshed) tokens' fingerprints in place of the signed ones, for oauth entries only. */
export function withRotatingPrints(l: Layout, view: VaultView | undefined): VaultView | undefined {
  if (view === undefined || !view.entries.some((e) => e.kind === "oauth")) return view;
  const all = readPrints(l);
  return { ...view, entries: view.entries.map((e) => (e.kind === "oauth" && own(all, e.name) !== undefined ? { ...e, fingerprints: { ...e.fingerprints, ...Object.fromEntries(Object.entries(own(all, e.name) ?? {}).filter(([f, fp]) => e.fields.includes(f) && typeof fp === "string")) } } : e)) };
}

function valuesOf(t: TokenSet): Record<string, string> {
  return { access_token: t.accessToken, refresh_token: t.refreshToken ?? NO_REFRESH };
}

/** Person-run (`mcp login`): stores or replaces the tokens as an oauth entry bound to the server, signed. */
export function storeLoginInVault(l: Layout, priv: KeyObject, server: string, tokens: TokenSet, backend: VaultBackend, confirm: Confirm): string {
  const name = oauthVaultName(server);
  if (name === null) throw new Error(`the server name ${server} cannot be a vault name`);
  const st = loadIndex(l, null);
  const existing = st.state === "ok" || st.state === "unsigned" ? st.index.entries.find((e) => e.name === name) : undefined;
  if (existing !== undefined && existing.kind !== "oauth") throw new Error(`vault://${name} exists already and is not an OAuth token; remove it or rename the server`);
  if (existing !== undefined) rotateSecret(l, priv, name, valuesOf(tokens), () => backend);
  else addSecret(l, priv, { name, kind: "oauth", fields: [...OAUTH_FIELDS], values: valuesOf(tokens), confirm, backend });
  const after = loadIndex(l, null);
  const entry = after.state === "ok" || after.state === "unsigned" ? after.index.entries.find((e) => e.name === name) : undefined;
  if (entry !== undefined && !entry.bindings.some((b) => b.kind === "mcp" && b.server === server && b.tool === undefined)) allowBinding(l, priv, name, { kind: "mcp", server });
  writePrints(l, name, null);
  appendLog(l, { type: "vault_change", op: existing !== undefined ? "rotate" : "add", name, kind: "oauth", binding: `mcp ${server}`, via: "mcp login" });
  return name;
}

/** The tokens for a server, when the signed index still binds the entry to it; null otherwise. */
export function readVaultTokens(l: Layout, name: string, server: string, trustedKey: string | null, backendFor: BackendFor): TokenSet | null {
  const st = loadIndex(l, trustedKey);
  if (st.state !== "ok") return null;
  const e = st.index.entries.find((x) => x.name === name);
  if (e === undefined || e.kind !== "oauth" || !e.bindings.some((b) => b.kind === "mcp" && b.server === server)) return null;
  try {
    const b = backendFor(e.backend);
    const access = b.read(accountFor(name, "access_token"));
    const refresh = b.read(accountFor(name, "refresh_token"));
    return { accessToken: access, ...(refresh !== NO_REFRESH ? { refreshToken: refresh } : {}) };
  } catch {
    return null;
  }
}

/** Unattended (the gateway's refresh): new values to the store, their fingerprints to the unsigned side file. */
export function refreshVaultTokens(l: Layout, name: string, server: string, tokens: TokenSet, trustedKey: string | null, backendFor: BackendFor): void {
  const st = loadIndex(l, trustedKey);
  if (st.state !== "ok") throw new Error("the vault index does not verify");
  const e = st.index.entries.find((x) => x.name === name);
  if (e === undefined || e.kind !== "oauth" || !e.bindings.some((b) => b.kind === "mcp" && b.server === server)) throw new Error(`vault://${name} is not an OAuth token bound to ${server}`);
  const b = backendFor(e.backend);
  const values = valuesOf(tokens);
  for (const f of OAUTH_FIELDS) b.write(accountFor(name, f), values[f] as string, { confirm: e.confirm });
  const prints: Record<string, string> = {};
  for (const f of OAUTH_FIELDS) {
    const fp = fingerprint(values[f] as string);
    if (fp !== null) prints[f] = fp;
  }
  writePrints(l, name, prints);
  appendLog(l, { type: "vault_change", op: "refresh", name, kind: "oauth", binding: `mcp ${server}`, via: "gateway" });
}
