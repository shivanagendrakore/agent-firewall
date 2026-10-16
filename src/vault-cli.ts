/**
 * The vault's commands. `vault add/allow/revoke/remove/rotate`
 * change what may leave the machine, so they run only for a person: an
 * interactive terminal that is not under an agent, and the approval
 * passphrase, which unlocks the key that signs the index. The firewall's
 * engine also refuses them from inside an agent (changesState). `vault list`
 * is read-only and never shows a value.
 *
 * Every dependency that touches the terminal or a store comes in through
 * VaultCliDeps, so tests run the real handlers with a fake store and scripted
 * input, and never reach this machine's keychain.
 */

import type { Parsed } from "./cliargs.js";
import { bindingSummary, formatRef, type VaultKind } from "./engine/vault-ref.js";
import { vaultPolicy, type Confirm } from "./policy-vault.js";
import type { Layout } from "./runtime/layout.js";
import type { BackendFactory } from "./runtime/vault/backends.js";
import type { BackendId, VaultEntry } from "./runtime/vault/index.js";
import { setOwn } from "./own.js";

type Ok = Extract<Parsed, { kind: "ok" }>;

export interface VaultCliDeps {
  out: (s: string) => void;
  err: (s: string) => void;
  humanAtKeyboard: () => Promise<boolean>;
  /** Reads a line with echo off (the passphrase, each value). */
  readSecret: (prompt: string) => Promise<string>;
  /** Reads a line with echo on (a "yes" confirmation). */
  ask: (prompt: string) => Promise<string>;
  /** Opens a store; tests pass a fake one. */
  openBackend: BackendFactory;
  /** Whether a store can be used here (tests pass a fake answer). */
  available: (id: BackendId) => { ok: boolean; reason?: string };
  platform: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
  cwd: string;
}

const EXIT_USAGE = 64;

function flag(p: Ok, name: string): boolean {
  return p.flags.get(name) === true;
}

function opt(p: Ok, name: string): string | undefined {
  const v = p.flags.get(name);
  return typeof v === "string" ? v : undefined;
}

function entryLines(e: VaultEntry): string[] {
  const head = `${formatRef(e.name)}  ${e.kind}  fields ${e.fields.join(", ")}  ${e.backend}${e.backend === "keychain" ? ` (confirm ${e.confirm})` : ""}  added ${e.createdAt.slice(0, 10)}${e.rotatedAt !== undefined ? `, rotated ${e.rotatedAt.slice(0, 10)}` : ""}`;
  const binds = e.bindings.length === 0 ? ["    bound to nothing yet: its value may go nowhere"] : e.bindings.map((b, i) => `    ${i + 1}. ${bindingSummary(b)}`);
  return [head, ...binds];
}

/** `vault` and `vault list`: read-only, for anyone (agents included). */
export async function vaultList(p: Ok, l: Layout, d: VaultCliDeps): Promise<number> {
  const { loadIndex } = await import("./runtime/vault/index.js");
  const { approverPublicKey } = await import("./runtime/approver.js");
  let key: string | null = null;
  try {
    key = approverPublicKey(l);
  } catch {
    key = null;
  }
  const st = loadIndex(l, key);
  if (st.state === "corrupt") {
    d.err(`${st.error}. Run "launchsafe-firewall doctor".`);
    return 1;
  }
  const entries = st.state === "absent" ? [] : st.index.entries;
  const signed = st.state === "ok" || st.state === "absent";
  if (flag(p, "--json")) {
    d.out(JSON.stringify({ signed, ...(st.state === "unsigned" ? { problem: st.reason } : {}), secrets: entries.map((e) => ({ ref: formatRef(e.name), name: e.name, kind: e.kind, fields: e.fields, backend: e.backend, confirm: e.confirm, bindings: e.bindings, createdAt: e.createdAt, ...(e.rotatedAt !== undefined ? { rotatedAt: e.rotatedAt } : {}) })) }, null, 2));
    return st.state === "unsigned" ? 1 : 0;
  }
  if (st.state === "unsigned") d.err(`WARNING: ${st.reason}. No secret is bound to any destination until this is resolved; run "launchsafe-firewall doctor".`);
  if (entries.length === 0) {
    d.out('The vault is empty. In your own terminal: launchsafe-firewall vault add <name>, then vault allow <name> --host <host>.');
    return 0;
  }
  for (const e of entries) for (const line of entryLines(e)) d.out(line);
  d.out("\nWrite a reference such as vault://<name> (or vault://<name>#<field>) where the value would go. Values are never shown.");
  return st.state === "unsigned" ? 1 : 0;
}

/** The person-at-keyboard check, the approver key, the passphrase: what every changing command starts with. */
async function unlock(l: Layout, d: VaultCliDeps): Promise<{ priv: import("node:crypto").KeyObject; passphrase: string } | null> {
  const { approverPublicKey, unlockApprover } = await import("./runtime/approver.js");
  const { assertNotRealHome } = await import("./runtime/guard.js");
  const { vaultDir } = await import("./runtime/vault/index.js");
  assertNotRealHome(vaultDir(l));
  if (!(await d.humanAtKeyboard())) return null;
  if (approverPublicKey(l) === null) {
    d.err('The vault is signed with your approval key, and no approval passphrase is set. In your own terminal run "launchsafe-firewall approver init" first.');
    return null;
  }
  const passphrase = await d.readSecret("Approval passphrase: ");
  try {
    return { priv: unlockApprover(l, passphrase), passphrase };
  } catch (e) {
    d.err(`${(e as Error).message}. Nothing was changed.`);
    return null;
  }
}

async function readValues(name: string, fields: readonly string[], d: VaultCliDeps): Promise<Record<string, string>> {
  const values: Record<string, string> = {};
  for (const f of fields) setOwn(values, f, await d.readSecret(`${fields.length === 1 ? "Value" : f} for ${formatRef(name, fields.length === 1 ? undefined : f)} (not shown; never type it into the agent): `));
  return values;
}

/** Turns a known error into a message and exit status; anything else is rethrown. */
async function failure(e: unknown, d: VaultCliDeps): Promise<number> {
  const { VaultUsageError } = await import("./runtime/vault/store.js");
  const { VaultIndexError } = await import("./runtime/vault/index.js");
  const { VaultBackendError, RealStoreRefused } = await import("./runtime/vault/backend.js");
  if (e instanceof RealStoreRefused) throw e;
  if (e instanceof VaultUsageError || e instanceof VaultIndexError || e instanceof VaultBackendError) {
    d.err(`launchsafe-firewall vault: ${e.message}`);
    return e instanceof VaultUsageError ? EXIT_USAGE : 1;
  }
  throw e;
}

async function canaryIndex(l: Layout): Promise<import("./types.js").CanaryIndex | undefined> {
  const { loadCanaryIndex } = await import("./runtime/canaries.js");
  try {
    return loadCanaryIndex(l, process.platform === "darwin", (p) => p);
  } catch {
    return undefined;
  }
}

async function logChange(l: Layout, event: Record<string, unknown>): Promise<void> {
  const { appendLog } = await import("./runtime/log.js");
  appendLog(l, { type: "vault_change", ...event });
}

export async function vaultAdd(p: Ok, l: Layout, d: VaultCliDeps): Promise<number> {
  const { checkName, chooseBackend, parseFields, addSecret } = await import("./runtime/vault/store.js");
  const { loadPolicy } = await import("./runtime/config.js");
  const name = p.positionals[0] as string;
  const kind = (opt(p, "--kind") ?? "credential") as VaultKind;
  let fields: string[];
  try {
    checkName(name);
    fields = parseFields(opt(p, "--fields"), kind);
  } catch (e) {
    return failure(e, d);
  }
  const pol = vaultPolicy(loadPolicy(l, [d.cwd]).config);
  const confirm = (opt(p, "--confirm") ?? pol.confirmDefault[kind]) as Confirm;
  const chosen = chooseBackend(d.platform, pol, d.available);
  if (chosen.id === null) {
    d.err(`launchsafe-firewall vault add: no secret store can be used here: ${chosen.reason}.`);
    return 1;
  }
  const u = await unlock(l, d);
  if (u === null) return 1;
  if (chosen.id === "keychain" && confirm === "never" && pol.confirmDefault[kind] === "always") d.out(`Note: ${kind} values are stored with per-use confirmation by default; with --confirm never any program running as you can read this one through /usr/bin/security.`);
  try {
    const values = await readValues(name, fields, d);
    const backend = d.openBackend(chosen.id, l, { passphrase: u.passphrase, platform: d.platform, env: d.env });
    const r = addSecret(l, u.priv, { name, kind, fields, values, confirm, backend, canaries: await canaryIndex(l) });
    await logChange(l, { op: "add", name, kind, backend: chosen.id, fields: fields.length });
    d.out(`Stored ${formatRef(name)} (${kind}, ${fields.join(", ")}) in the ${chosen.id === "keychain" ? `macOS Keychain (confirm ${confirm})` : chosen.id === "libsecret" ? "Secret Service" : "encrypted file store"}.`);
    if (r.short.length > 0) d.out(`Field(s) ${r.short.join(", ")} are shorter than 12 characters, so the firewall cannot recognise them if they leak; the other fields are recognised in the documented encodings (docs/vault.md).`);
    d.out(`It is bound to nothing yet. Next: launchsafe-firewall vault allow ${name} --host <host>`);
    return 0;
  } catch (e) {
    return failure(e, d);
  }
}

export async function vaultAllow(p: Ok, l: Layout, d: VaultCliDeps): Promise<number> {
  const { parseBinding, allowBinding } = await import("./runtime/vault/store.js");
  const name = p.positionals[0] as string;
  let parsed: ReturnType<typeof parseBinding>;
  try {
    parsed = parseBinding({ ...(opt(p, "--host") !== undefined ? { host: opt(p, "--host") as string } : {}), allowInUrl: flag(p, "--allow-in-url"), allowHttp: flag(p, "--allow-http"), ...(opt(p, "--mcp") !== undefined ? { mcp: opt(p, "--mcp") as string } : {}), ...(opt(p, "--process") !== undefined ? { process: opt(p, "--process") as string } : {}) });
  } catch (e) {
    return failure(e, d);
  }
  d.out(`Bind ${formatRef(name)} to ${bindingSummary(parsed.binding)}.`);
  if (parsed.warning !== undefined) d.out(`Warning: ${parsed.warning}.`);
  const u = await unlock(l, d);
  if (u === null) return 1;
  try {
    const entry = allowBinding(l, u.priv, name, parsed.binding);
    await logChange(l, { op: "allow", name, kind: entry.kind, binding: bindingSummary(parsed.binding) });
    d.out(`${formatRef(name)} may now go to ${bindingSummary(parsed.binding)} (binding ${entry.bindings.length}).`);
    return 0;
  } catch (e) {
    return failure(e, d);
  }
}

export async function vaultRevoke(p: Ok, l: Layout, d: VaultCliDeps): Promise<number> {
  const { revokeBinding } = await import("./runtime/vault/store.js");
  const name = p.positionals[0] as string;
  const raw = p.positionals[1] as string;
  if (!/^\d+$/.test(raw)) {
    d.err('launchsafe-firewall vault revoke: <n> must be a binding number from "launchsafe-firewall vault list".');
    return EXIT_USAGE;
  }
  const u = await unlock(l, d);
  if (u === null) return 1;
  try {
    const r = revokeBinding(l, u.priv, name, Number(raw));
    await logChange(l, { op: "revoke", name, kind: r.entry.kind, binding: bindingSummary(r.removed) });
    d.out(`Removed binding ${raw} of ${formatRef(name)}: ${bindingSummary(r.removed)}.`);
    return 0;
  } catch (e) {
    return failure(e, d);
  }
}

export async function vaultRemove(p: Ok, l: Layout, d: VaultCliDeps): Promise<number> {
  const { removeSecret } = await import("./runtime/vault/store.js");
  const name = p.positionals[0] as string;
  const u = await unlock(l, d);
  if (u === null) return 1;
  if ((await d.ask(`Delete ${formatRef(name)} and its stored values? Type "yes": `)).trim().toLowerCase() !== "yes") {
    d.out("Nothing was changed.");
    return 1;
  }
  try {
    const r = removeSecret(l, u.priv, name, (id) => d.openBackend(id, l, { passphrase: u.passphrase, platform: d.platform, env: d.env }));
    await logChange(l, { op: "remove", name, kind: r.entry.kind });
    d.out(`Removed ${formatRef(name)}.`);
    for (const x of r.problems) d.err(`Could not delete a stored value: ${x}. Delete it in your keychain or keyring by hand (service launchsafe-firewall).`);
    return r.problems.length === 0 ? 0 : 1;
  } catch (e) {
    return failure(e, d);
  }
}

export async function vaultRotate(p: Ok, l: Layout, d: VaultCliDeps): Promise<number> {
  const { rotateSecret } = await import("./runtime/vault/store.js");
  const { loadIndex } = await import("./runtime/vault/index.js");
  const { approverPublicKey } = await import("./runtime/approver.js");
  const name = p.positionals[0] as string;
  const st = loadIndex(l, approverPublicKey(l));
  if (st.state !== "ok") {
    d.err(`launchsafe-firewall vault rotate: ${st.state === "absent" ? `no such secret: ${formatRef(name)}` : st.state === "corrupt" ? st.error : st.reason}. Run "launchsafe-firewall vault list".`);
    return 1;
  }
  const entry = st.index.entries.find((e) => e.name === name);
  if (entry === undefined) {
    d.err(`launchsafe-firewall vault rotate: no such secret: ${formatRef(name)}. Run "launchsafe-firewall vault list".`);
    return 1;
  }
  const u = await unlock(l, d);
  if (u === null) return 1;
  try {
    const fields = entry.fields;
    const values = await readValues(name, fields, d);
    const r = rotateSecret(l, u.priv, name, values, (id) => d.openBackend(id, l, { passphrase: u.passphrase, platform: d.platform, env: d.env }), { canaries: await canaryIndex(l) });
    await logChange(l, { op: "rotate", name, kind: r.entry.kind });
    d.out(`Replaced the value${fields.length === 1 ? "" : "s"} of ${formatRef(name)}. Its bindings are unchanged.`);
    if (r.short.length > 0) d.out(`Field(s) ${r.short.join(", ")} are shorter than 12 characters, so the firewall cannot recognise them if they leak.`);
    return 0;
  } catch (e) {
    return failure(e, d);
  }
}

export const VAULT_HANDLERS: Record<string, (p: Ok, l: Layout, d: VaultCliDeps) => Promise<number>> = {
  vault: vaultList,
  "vault list": vaultList,
  "vault add": vaultAdd,
  "vault allow": vaultAllow,
  "vault revoke": vaultRevoke,
  "vault remove": vaultRemove,
  "vault rotate": vaultRotate,
};

/**
 * After `approver rotate`: the index was signed with the old key, so re-sign it with the new one, but only
 * if it verifies against the old key (re-signing a forged index would launder it), and re-wrap the file
 * store's data key. Returns lines to print.
 */
export async function afterApproverRotate(l: Layout, oldPublicKey: string | null, newPriv: import("node:crypto").KeyObject, oldPassphrase: string, newPassphrase: string): Promise<string[]> {
  const { loadIndex, indexPath, signIndex, vaultDir } = await import("./runtime/vault/index.js");
  const { rewrapFileStore } = await import("./runtime/vault/file.js");
  const { atomicWrite, withLock } = await import("./runtime/fsutil.js");
  const { join } = await import("node:path");
  const { existsSync } = await import("node:fs");
  const lines: string[] = [];
  if (!existsSync(vaultDir(l))) return lines;
  const st = withLock(join(vaultDir(l), "index.lock"), () => {
    const cur = loadIndex(l, oldPublicKey);
    if (cur.state === "ok") atomicWrite(indexPath(l), `${JSON.stringify(signIndex(newPriv, cur.index.entries), null, 2)}\n`, 0o600);
    return cur;
  });
  if (st.state === "ok") {
    lines.push(`The vault index is now signed with the new key (${st.index.entries.length} secret(s)).`);
    await logChange(l, { op: "resign", name: "*", kind: "*" });
  } else if (st.state === "unsigned" || st.state === "corrupt") {
    lines.push(`The vault index was not signed by the old key (${st.state === "corrupt" ? st.error : st.reason}), so it was not re-signed. Run "launchsafe-firewall doctor".`);
  }
  try {
    if (rewrapFileStore(l, oldPassphrase, newPassphrase)) lines.push("The vault's file store now opens with the new passphrase.");
  } catch (e) {
    lines.push(`The vault's file store could not be re-keyed: ${(e as Error).message}.`);
  }
  return lines;
}
