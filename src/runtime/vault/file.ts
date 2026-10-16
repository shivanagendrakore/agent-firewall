/**
 * Encrypted file backend (`vault/store.enc`), for Linux without a Secret
 * Service and only with `vault.fileFallback: true` (off by default).
 *
 * A random 256-bit data key encrypts each value with AES-256-GCM (the account
 * is the additional data, so values cannot be swapped between entries). The
 * data key is wrapped with a key derived by scrypt from the approval
 * passphrase with this file's own salt (the KDF in approver.ts), so changing
 * the passphrase only re-wraps the data key.
 *
 * This protects against backups and accidental reads only: code running as
 * the same user while the store is unlocked can read it. Doctor says so.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { join } from "node:path";
import { derivePassphraseKey } from "../approver.js";
import { atomicWrite, ensureDir, readText, withLock } from "../fsutil.js";
import { assertNotRealHome } from "../guard.js";
import type { Layout } from "../layout.js";
import { VaultBackendError, type VaultBackend } from "./backend.js";
import { vaultDir } from "./index.js";
import { own, setOwn } from "../../own.js";

interface Sealed {
  iv: string;
  tag: string;
  ct: string;
}

interface StoreFile {
  version: 1;
  salt: string;
  wrap: Sealed;
  entries: Record<string, Sealed>;
}

const WRAP_AAD = "launchsafe-firewall/vault-store/v1/wrap";
const entryAad = (account: string): string => `launchsafe-firewall/vault-store/v1/entry/${account}`;

export function storePath(l: Layout): string {
  return join(vaultDir(l), "store.enc");
}

function seal(key: Buffer, plain: Buffer, aad: string): Sealed {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(Buffer.from(aad, "utf8"));
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return { iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), ct: ct.toString("base64") };
}

function open(key: Buffer, s: Sealed, aad: string): Buffer {
  const d = createDecipheriv("aes-256-gcm", key, Buffer.from(s.iv, "base64"));
  d.setAAD(Buffer.from(aad, "utf8"));
  d.setAuthTag(Buffer.from(s.tag, "base64"));
  return Buffer.concat([d.update(Buffer.from(s.ct, "base64")), d.final()]);
}

function readStore(l: Layout): StoreFile | null {
  const t = readText(storePath(l));
  if (t === null) return null;
  const s = JSON.parse(t) as StoreFile;
  if (s.version !== 1 || typeof s.salt !== "string" || typeof s.wrap !== "object" || typeof s.entries !== "object" || s.entries === null) throw new VaultBackendError(`${storePath(l)} is not a valid vault store`);
  return s;
}

function writeStore(l: Layout, s: StoreFile): void {
  assertNotRealHome(storePath(l));
  ensureDir(vaultDir(l));
  atomicWrite(storePath(l), `${JSON.stringify(s, null, 2)}\n`, 0o600);
}

function unwrap(s: StoreFile, passphrase: string): Buffer {
  try {
    return open(derivePassphraseKey(passphrase, Buffer.from(s.salt, "base64")), s.wrap, WRAP_AAD);
  } catch {
    throw new VaultBackendError("the vault's file store does not open with this passphrase");
  }
}

function newStore(passphrase: string): { store: StoreFile; key: Buffer } {
  const key = randomBytes(32);
  const salt = randomBytes(16);
  return { key, store: { version: 1, salt: salt.toString("base64"), wrap: seal(derivePassphraseKey(passphrase, salt), key, WRAP_AAD), entries: {} } };
}

/** The file backend, unlocked with the approval passphrase (the person typed it for this command). */
export function fileBackend(l: Layout, passphrase: string): VaultBackend {
  const lock = (): string => join(vaultDir(l), "store.lock");
  const withStore = <T>(fn: (s: StoreFile, key: Buffer) => { result: T; dirty: boolean }, create: boolean): T => {
    // Opened without the passphrase (a hook or the gateway: defaultBackendFor passes ""), the store is
    // locked: nothing is read, and above all nothing is written, which would create a store whose key is
    // wrapped with an empty passphrase, readable by anything that runs as you.
    if (passphrase === "") throw new VaultBackendError("the vault's file store is locked: it opens only with the approval passphrase, typed for a vault command");
    ensureDir(vaultDir(l));
    return withLock(lock(), () => {
      const existing = readStore(l);
      if (existing === null && !create) return fn({ version: 1, salt: "", wrap: { iv: "", tag: "", ct: "" }, entries: {} }, Buffer.alloc(32)).result;
      const { store, key } = existing === null ? newStore(passphrase) : { store: existing, key: unwrap(existing, passphrase) };
      const r = fn(store, key);
      if (r.dirty || existing === null) writeStore(l, store);
      return r.result;
    });
  };
  return {
    id: "file",
    available: () => ({ ok: true }),
    write(account, value) {
      if (value === "") throw new VaultBackendError("an empty value cannot be stored");
      withStore((s, key) => {
        setOwn(s.entries, account, seal(key, Buffer.from(value, "utf8"), entryAad(account)));
        return { result: undefined, dirty: true };
      }, true);
    },
    read(account) {
      return withStore((s, key) => {
        const e = own(s.entries, account);
        if (e === undefined) throw new VaultBackendError(`no value for ${account} in the file store`);
        try {
          return { result: open(key, e, entryAad(account)).toString("utf8"), dirty: false };
        } catch {
          throw new VaultBackendError(`the file store's entry for ${account} is damaged`);
        }
      }, false);
    },
    remove(account) {
      return withStore((s) => {
        if (own(s.entries, account) === undefined) return { result: false, dirty: false };
        delete s.entries[account];
        return { result: true, dirty: true };
      }, false);
    },
    exists(account) {
      const s = readStore(l);
      return s !== null && own(s.entries, account) !== undefined;
    },
  };
}

/** After `approver rotate`: re-wraps the data key with the new passphrase. False when there is no file store. */
export function rewrapFileStore(l: Layout, oldPassphrase: string, newPassphrase: string): boolean {
  if (newPassphrase === "") throw new VaultBackendError("the vault's file store is never wrapped with an empty passphrase");
  ensureDir(vaultDir(l));
  return withLock(join(vaultDir(l), "store.lock"), () => {
    const s = readStore(l);
    if (s === null) return false;
    const key = unwrap(s, oldPassphrase);
    const salt = randomBytes(16);
    writeStore(l, { ...s, salt: salt.toString("base64"), wrap: seal(derivePassphraseKey(newPassphrase, salt), key, WRAP_AAD) });
    return true;
  });
}
