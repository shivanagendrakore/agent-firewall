/**
 * Doctor's vault checks: the index's signature, which store this machine
 * uses and how strong it is, entries whose store is not available here,
 * values missing from the store, and the per-use confirmation of financial
 * and personal values. Static checks: the sandbox probes (that the
 * store is unreachable from inside the agent's sandbox) come with the hook
 * rewrite. Not part of the protection score.
 */

import { vaultPolicy } from "../../policy-vault.js";
import type { FirewallConfig } from "../../types.js";
import type { Check } from "../doctor.js";
import type { Layout } from "../layout.js";
import { accountFor, type Availability } from "./backend.js";
import { backendAvailable } from "./backends.js";
import { keychainBackend } from "./keychain.js";
import { indexPath, loadIndex, type BackendId, type VaultEntry } from "./index.js";

const APPROVE_KINDS = new Set(["card", "iban", "national_id", "personal"]);

export interface VaultDoctorOptions {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  /** The approver key the index must be signed with (the one on disk; doctor's approval check compares it with the hook's pin). */
  trustedKey: string | null;
  available?: (id: BackendId) => Availability;
  /** Whether a value exists in its store without reading it; null when the store cannot tell. */
  exists?: (entry: VaultEntry, field: string) => boolean | null;
}

function defaultExists(platform: NodeJS.Platform): (entry: VaultEntry, field: string) => boolean | null {
  return (entry, field) => {
    if (entry.backend !== "keychain" || platform !== "darwin") return null;
    try {
      return keychainBackend({ platform }).exists(accountFor(entry.name, field));
    } catch {
      return null;
    }
  };
}

export function vaultChecks(l: Layout, cfg: FirewallConfig, o: VaultDoctorOptions): Check[] {
  const platform = o.platform ?? process.platform;
  const env = o.env ?? process.env;
  const pol = vaultPolicy(cfg);
  const available = o.available ?? ((id: BackendId) => backendAvailable(id, { platform, env }));
  const out: Check[] = [];
  const st = loadIndex(l, o.trustedKey);
  const native: BackendId | null = platform === "darwin" ? "keychain" : platform === "linux" ? "libsecret" : null;
  const nativeOk = native !== null && available(native).ok;
  const storeLine = native === null ? `${platform} has no supported store` : nativeOk ? `new secrets go to the ${native === "keychain" ? "macOS Keychain" : "Secret Service"}` : pol.fileFallback ? `new secrets go to the encrypted file store (no ${native === "keychain" ? "Keychain" : "Secret Service"}: ${available(native).reason ?? "unavailable"})` : `no store for new secrets: ${available(native).reason ?? "unavailable"}`;

  if (st.state === "absent") {
    out.push({ name: "vault", status: "ok", detail: `no secrets stored (add one with "launchsafe-firewall vault add <name>" in your own terminal); ${storeLine}` });
    if (pol.fileFallback) out.push({ name: "vault file store", status: "warn", detail: 'policy vault.fileFallback is on: the encrypted file store protects only against backups and accidental reads; code running as you can read it while it is unlocked' });
    return out;
  }
  if (st.state === "corrupt") {
    out.push({ name: "vault", status: "fail", detail: `${st.error}: stored values cannot be recognised if they leak, so ${pol.enabled ? "every send asks (FW-VAULT-INDEX)" : "the vault is off"}. Move it aside and add the secrets again` });
    return out;
  }
  const entries = st.index.entries;
  const bindings = entries.reduce((n, e) => n + e.bindings.length, 0);
  if (st.state === "unsigned") out.push({ name: "vault", status: "fail", detail: `${indexPath(l)}: ${st.reason}, so no secret is bound to any destination (values are still recognised and denied everywhere)${pol.enabled ? " and every send asks (FW-VAULT-INDEX)" : ""}. If you did not change it, something else did` });
  else if (!pol.enabled) out.push({ name: "vault", status: "warn", detail: `off (policy vault.enabled is false): ${entries.length} stored value(s) are not recognised if they leak` });
  else out.push({ name: "vault", status: "ok", detail: `${entries.length} secret(s), ${bindings} binding(s), signed by your approval key; ${storeLine}` });

  const unbound = entries.filter((e) => e.bindings.length === 0).map((e) => e.name);
  if (unbound.length > 0) out.push({ name: "vault bindings", status: "ok", detail: `not bound to any destination yet (their values may go nowhere): ${unbound.slice(0, 5).join(", ")}${unbound.length > 5 ? ", ..." : ""}` });

  const byBackend = (id: BackendId): VaultEntry[] => entries.filter((e) => e.backend === id);
  for (const id of ["keychain", "libsecret", "file"] as const) {
    const list = byBackend(id);
    if (list.length === 0) continue;
    const a = available(id);
    if (!a.ok) out.push({ name: "vault store", status: "warn", detail: `${list.length} secret(s) are in the ${id} store, which is not available here (${a.reason ?? "unavailable"}): ${list.slice(0, 5).map((e) => e.name).join(", ")}` });
  }
  if (byBackend("libsecret").length > 0) out.push({ name: "vault store strength", status: "warn", detail: "Secret Service items have no per-application protection: once your login keyring is unlocked, any program running as you on the session bus can read them. Run the agent inside its OS sandbox, which has no bus socket" });
  if (byBackend("file").length > 0 || pol.fileFallback) out.push({ name: "vault file store", status: "warn", detail: "the encrypted file store protects only against backups and accidental reads; code running as you can read it while it is unlocked" });
  const silent = entries.filter((e) => e.backend === "keychain" && e.confirm === "never" && APPROVE_KINDS.has(e.kind));
  if (silent.length > 0) out.push({ name: "vault confirmation", status: "warn", detail: `stored without per-use confirmation, so any program running as you can read them through /usr/bin/security: ${silent.map((e) => `${e.name} (${e.kind})`).join(", ")}. To change one, "vault remove" it and "vault add" it again with --confirm always` });
  if (byBackend("keychain").some((e) => e.confirm === "never")) out.push({ name: "vault keychain", status: "ok", detail: 'items stored with confirm "never" trust /usr/bin/security; never click "Always Allow" on a keychain dialog for an item stored with "always", which would add the asking program to its list' });

  const exists = o.exists ?? defaultExists(platform);
  const missing: string[] = [];
  for (const e of entries) {
    if (!available(e.backend).ok) continue;
    for (const f of e.fields) if (exists(e, f) === false) missing.push(`${e.name}#${f}`);
  }
  if (missing.length > 0) out.push({ name: "vault values", status: "fail", detail: `in the index but missing from the store (an action using them would be denied): ${missing.slice(0, 5).join(", ")}. Run "launchsafe-firewall vault rotate <name>" to store them again` });
  return out;
}
