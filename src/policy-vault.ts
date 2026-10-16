/**
 * Item V's policy key, kept apart from policy.ts so the item stays one
 * module: `vault` (docs/vault.md).
 *
 * Tighten-only for a project file: it may set a kind's confirmation to
 * "always", the file fallback to false, add kinds that need approval, set
 * approveWhenUntrusted to true, turn the shell rewrite or the SessionStart
 * listing off, and lower ticketSeconds (5 minimum); nothing else. Bindings
 * never live in a policy file, so no repository can bind a secret to its own
 * host.
 */

import { VAULT_KINDS, type VaultKind } from "./engine/vault-ref.js";
import type { FirewallConfig } from "./types.js";

export const VAULT_POLICY_KEYS = ["vault"] as const;

export type Confirm = "always" | "never";

export interface VaultPolicy {
  /** User or managed only may set false: then no vault view is built and FW-VAULT-EGRESS does not apply. */
  enabled: boolean;
  /** macOS Keychain per-use confirmation chosen at `vault add` time, per kind. */
  confirmDefault: Record<VaultKind, Confirm>;
  /** The encrypted file store on Linux without a Secret Service. User or managed only may set true. */
  fileFallback: boolean;
  /** Kinds whose every use needs a person (FW-VAULT-APPROVE). Financial values always. A project may add kinds. */
  approveKinds: VaultKind[];
  /** Any substitution in an untrusted session needs a person. A project may only set true. */
  approveWhenUntrusted: boolean;
  /** "auto": rewrite a shell command's references into a ticketed `run` for agents verified to rewrite input; "off": never (FW-VAULT-UNSUPPORTED). */
  shellRewrite: "auto" | "off";
  /** How long a `run` ticket issued by the hook stays valid (5 to 120; a project may only lower it). */
  ticketSeconds: number;
  /** SessionStart tells the agent which references exist and where they may go (names and destinations only). */
  listInContext: boolean;
}

export interface VaultDoc {
  vault?: Partial<Omit<VaultPolicy, "confirmDefault">> & { confirmDefault?: Partial<Record<VaultKind, Confirm>> };
}

export const TICKET_MIN = 5;
export const TICKET_MAX = 120;

/** Defaults: per-use confirmation for financial and personal values, none for API and OAuth tokens; no file fallback. */
export function defaultVault(): VaultPolicy {
  return {
    enabled: true,
    confirmDefault: { card: "always", iban: "always", national_id: "always", personal: "always", credential: "never", oauth: "never" },
    fileFallback: false,
    approveKinds: ["card", "iban", "national_id", "personal"],
    approveWhenUntrusted: true,
    shellRewrite: "auto",
    ticketSeconds: 30,
    listInContext: true,
  };
}

/** The vault policy in effect (defaults for anything a policy file did not set). */
export function vaultPolicy(cfg: Pick<FirewallConfig, "vault">): VaultPolicy {
  const d = defaultVault();
  const v = cfg.vault ?? {};
  return {
    enabled: v.enabled ?? d.enabled,
    confirmDefault: { ...d.confirmDefault, ...(v.confirmDefault ?? {}) },
    fileFallback: v.fileFallback ?? d.fileFallback,
    approveKinds: v.approveKinds ?? d.approveKinds,
    approveWhenUntrusted: v.approveWhenUntrusted ?? d.approveWhenUntrusted,
    shellRewrite: v.shellRewrite ?? d.shellRewrite,
    ticketSeconds: Math.min(TICKET_MAX, Math.max(TICKET_MIN, v.ticketSeconds ?? d.ticketSeconds)),
    listInContext: v.listInContext ?? d.listInContext,
  };
}

const KEYS = ["enabled", "confirmDefault", "fileFallback", "approveKinds", "approveWhenUntrusted", "shellRewrite", "ticketSeconds", "listInContext"] as const;

type Raw = Record<string, unknown>;

/** Validates the key of a (migrated) policy document into `out`. */
export function validateVaultKeys(raw: Raw, problems: string[], out: VaultDoc): void {
  if (raw.vault === undefined) return;
  const v = raw.vault;
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    problems.push('"vault" must be an object');
    return;
  }
  const o = v as Raw;
  const res: NonNullable<VaultDoc["vault"]> = {};
  for (const k of Object.keys(o)) if (!(KEYS as readonly string[]).includes(k)) problems.push(`"vault.${k}" is not a known setting (expected one of ${KEYS.join(", ")})`);
  for (const k of ["enabled", "fileFallback", "approveWhenUntrusted", "listInContext"] as const) {
    if (o[k] === undefined) continue;
    if (typeof o[k] === "boolean") res[k] = o[k];
    else problems.push(`"vault.${k}" must be true or false`);
  }
  if (o.approveKinds !== undefined) {
    if (!Array.isArray(o.approveKinds) || o.approveKinds.some((k) => !(VAULT_KINDS as readonly unknown[]).includes(k))) problems.push(`"vault.approveKinds" must be a list of vault kinds (${VAULT_KINDS.join(", ")})`);
    else res.approveKinds = [...new Set(o.approveKinds as VaultKind[])];
  }
  if (o.shellRewrite !== undefined) {
    if (o.shellRewrite === "auto" || o.shellRewrite === "off") res.shellRewrite = o.shellRewrite;
    else problems.push('"vault.shellRewrite" must be "auto" or "off"');
  }
  if (o.ticketSeconds !== undefined) {
    if (typeof o.ticketSeconds === "number" && Number.isInteger(o.ticketSeconds) && o.ticketSeconds >= TICKET_MIN && o.ticketSeconds <= TICKET_MAX) res.ticketSeconds = o.ticketSeconds;
    else problems.push(`"vault.ticketSeconds" must be a whole number of seconds from ${TICKET_MIN} to ${TICKET_MAX}`);
  }
  if (o.confirmDefault !== undefined) {
    const c = o.confirmDefault;
    if (typeof c !== "object" || c === null || Array.isArray(c)) problems.push('"vault.confirmDefault" must be an object of kind to "always" or "never"');
    else {
      const cd: Partial<Record<VaultKind, Confirm>> = {};
      for (const [k, val] of Object.entries(c as Raw)) {
        if (!(VAULT_KINDS as readonly string[]).includes(k)) problems.push(`"vault.confirmDefault.${k}" is not a vault kind (expected ${VAULT_KINDS.join(", ")})`);
        else if (val !== "always" && val !== "never") problems.push(`"vault.confirmDefault.${k}" must be "always" or "never"`);
        else cd[k as VaultKind] = val;
      }
      res.confirmDefault = cd;
    }
  }
  out.vault = res;
}

/** The user's (or an administrator's) `vault` over the layer below: anything goes. */
export function mergeVault(base: FirewallConfig["vault"], over: VaultDoc["vault"]): FirewallConfig["vault"] {
  if (base === undefined && over === undefined) return undefined;
  return { ...(base ?? {}), ...(over ?? {}), confirmDefault: { ...(base?.confirmDefault ?? {}), ...(over?.confirmDefault ?? {}) } };
}

/** Applies a project file's `vault`: tightening only; anything looser is listed in `ignored`. */
export function tightenVaultKeys(base: FirewallConfig, over: VaultDoc, cfg: FirewallConfig, ignored: string[]): void {
  const v = over.vault;
  if (v === undefined) return;
  const next: NonNullable<FirewallConfig["vault"]> = { ...(base.vault ?? {}), confirmDefault: { ...(base.vault?.confirmDefault ?? {}) } };
  const loosened: string[] = [];
  if (v.enabled === false) loosened.push("vault.enabled (a repository must not switch off your vault)");
  if (v.fileFallback === true) loosened.push("vault.fileFallback (only user or managed policy may turn the file store on)");
  if (v.fileFallback === false) next.fileFallback = false;
  for (const [k, c] of Object.entries(v.confirmDefault ?? {}) as [VaultKind, Confirm][]) {
    if (c === "always") (next.confirmDefault as Record<string, Confirm>)[k] = "always";
    else loosened.push(`vault.confirmDefault.${k} (a project may only ask for confirmation)`);
  }
  const cur = vaultPolicy(base);
  if (v.approveKinds !== undefined) {
    // Adding kinds tightens; leaving one out never removes it.
    next.approveKinds = [...new Set([...cur.approveKinds, ...v.approveKinds])];
    if (cur.approveKinds.some((k) => !v.approveKinds?.includes(k))) loosened.push("vault.approveKinds (a project may add kinds that need approval, not remove them)");
  }
  if (v.approveWhenUntrusted === true) next.approveWhenUntrusted = true;
  if (v.approveWhenUntrusted === false) loosened.push("vault.approveWhenUntrusted (a project may only turn it on)");
  if (v.shellRewrite === "off") next.shellRewrite = "off";
  if (v.listInContext === false) next.listInContext = false;
  if (v.ticketSeconds !== undefined) {
    if (v.ticketSeconds <= cur.ticketSeconds) next.ticketSeconds = v.ticketSeconds;
    else loosened.push("vault.ticketSeconds (a project may only lower it)");
  }
  cfg.vault = next;
  ignored.push(...loosened);
}
