/**
 * An in-memory store behind the real VaultBackend interface, and a recording
 * runner for the real backends' argument building. Neither ever starts a
 * process, so no test reaches this machine's keychain or keyring.
 */
import type { RunResult, Runner, VaultBackend } from "../../src/runtime/vault/backend.js";
import { VaultBackendError } from "../../src/runtime/vault/backend.js";
import type { BackendId } from "../../src/runtime/vault/index.js";
import type { Confirm } from "../../src/policy-vault.js";

export interface FakeStore extends VaultBackend {
  values: Map<string, { value: string; confirm: Confirm }>;
  /** Make the next writes fail (a locked keychain). */
  failWrites: boolean;
  failRemoves: boolean;
}

export function fakeBackend(id: BackendId = "keychain"): FakeStore {
  const values = new Map<string, { value: string; confirm: Confirm }>();
  const b: FakeStore = {
    id,
    values,
    failWrites: false,
    failRemoves: false,
    available: () => ({ ok: true }),
    write(account, value, o) {
      if (b.failWrites) throw new VaultBackendError(`the fake store refused to store ${account}`);
      values.set(account, { value, confirm: o.confirm });
    },
    read(account) {
      const v = values.get(account);
      if (v === undefined) throw new VaultBackendError(`no value for ${account}`);
      return v.value;
    },
    remove(account) {
      if (b.failRemoves) throw new VaultBackendError(`the fake store could not delete ${account}`);
      return values.delete(account);
    },
    exists: (account) => values.has(account),
  };
  return b;
}

export interface Call {
  cmd: string;
  args: string[];
  input?: string;
}

/** A runner that records each call and answers from a script (default: success, empty output). */
export function recordingRunner(answer: (c: Call) => Partial<RunResult> = () => ({})): { run: Runner; calls: Call[] } {
  const calls: Call[] = [];
  const run: Runner = (cmd, args, input) => {
    const c: Call = { cmd, args: [...args], ...(input !== undefined ? { input } : {}) };
    calls.push(c);
    return { status: 0, stdout: "", stderr: "", ...answer(c) };
  };
  return { run, calls };
}

/** A real-looking secret (credential-shaped, 40 characters) that is obviously a test value to a person. */
export const TOKEN = "ghp_TESTvaultTOKEN0123456789abcdefABCDEF12";
export const IBAN = "DE89370400440532013000";
/** A value with no credential shape: only the vault makes it a credential. */
export const OPAQUE = "opaque-internal-key-7Hq2Lm9Xz4Pw";
