/**
 * The secret store behind the vault: one interface, three backends (macOS
 * Keychain, Linux Secret Service, an encrypted file). Each value is stored
 * under the service "launchsafe-firewall" and the account "<name>:<field>".
 *
 * Helpers run only from fixed system paths (never found through PATH, the
 * rule notify.ts uses for notify-send), and a value is never put in argv,
 * where `ps` would show it: it goes to the helper's standard input.
 *
 * Tests never reach a real store: the default runner refuses to start any
 * helper while a test marker is set, unless a person runs the opt-in manual
 * test (LAUNCHSAFE_FIREWALL_VAULT_REAL_KEYCHAIN=1).
 */

import { FIREWALL_VAULT_SERVICE } from "../../engine/identity.js";
import { spawnSync } from "node:child_process";
import { accessSync, constants, existsSync } from "node:fs";
import { testMarker } from "../guard.js";
import { isTrustedSystemFile } from "../notify.js";
import type { BackendId } from "./index.js";
import type { Confirm } from "../../policy-vault.js";

// One name for the store and for self-protection (the engine's identity refuses the store's tools on it).
export const VAULT_SERVICE = FIREWALL_VAULT_SERVICE;

/** Set by a person for the opt-in manual keychain test only. */
export const REAL_STORE_TEST_VAR = "LAUNCHSAFE_FIREWALL_VAULT_REAL_KEYCHAIN";

export interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
}

/** Runs a helper: the command, its arguments, and what to write to its standard input (never a value in args). */
export type Runner = (cmd: string, args: readonly string[], input?: string) => RunResult;

export interface Availability {
  ok: boolean;
  reason?: string;
}

export interface VaultBackend {
  readonly id: BackendId;
  /** Whether this store can be used on this machine now. */
  available(): Availability;
  /** Stores (or replaces) one value. Throws VaultBackendError. */
  write(account: string, value: string, o: { confirm: Confirm }): void;
  /** Reads one value. Throws VaultBackendError when missing or locked. */
  read(account: string): string;
  /** Deletes one value; false when it was not there. */
  remove(account: string): boolean;
  /** Whether a value exists, without reading it (no confirmation dialog); null when this store cannot tell. */
  exists(account: string): boolean | null;
}

export class VaultBackendError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultBackendError";
  }
}

/** The account a field's value is stored under. Names and fields are restricted to [a-z0-9_/-], so no quoting can break. */
export function accountFor(name: string, field: string): string {
  return `${name}:${field}`;
}

/** The helper's environment: this process's, without variables that load code into it. */
function helperEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(env).filter(([k]) => !/^(?:LD_|DYLD_)/.test(k)));
}

export class RealStoreRefused extends Error {
  constructor(cmd: string) {
    super(`refusing to run ${cmd}: a test marker is set, and tests never touch a real secret store (the opt-in manual test sets ${REAL_STORE_TEST_VAR}=1)`);
    this.name = "RealStoreRefused";
  }
}

export const defaultRunner: Runner = (cmd, args, input) => {
  if (testMarker(process.env) && process.env[REAL_STORE_TEST_VAR] !== "1") throw new RealStoreRefused(cmd);
  const r = spawnSync(cmd, [...args], { input, encoding: "utf8", timeout: 60_000, maxBuffer: 1024 * 1024, env: helperEnv(process.env), stdio: [input !== undefined ? "pipe" : "ignore", "pipe", "pipe"] });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", ...(r.error !== undefined ? { error: r.error } : {}) };
};

function executable(p: string): boolean {
  try {
    accessSync(p, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export interface SystemBinaryDeps {
  exists?: (p: string) => boolean;
  trusted?: (p: string) => boolean;
}

/** The first of the fixed paths that holds a root-owned, not user-writable executable; null when none does. */
export function systemBinary(paths: readonly string[], deps: SystemBinaryDeps = {}): string | null {
  const ok = deps.exists ?? ((p: string) => existsSync(p) && executable(p));
  const trusted = deps.trusted ?? isTrustedSystemFile;
  return paths.find((p) => ok(p) && trusted(p)) ?? null;
}

/** A single trailing newline the helpers print after a value (a value read from a terminal line has none). */
export function stripNewline(s: string): string {
  return s.endsWith("\n") ? s.slice(0, -1) : s;
}
