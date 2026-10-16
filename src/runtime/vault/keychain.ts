/**
 * macOS Keychain backend: /usr/bin/security, never found through PATH.
 *
 * Writing uses `security -i` (interactive mode) with the command on standard
 * input, so the value never appears in argv or `ps`. The value travels as
 * `-X <hex>` (security's hexadecimal password option), so no character of it
 * can meet the interactive parser's quoting; the stored data is
 * "lsfw1:" + base64 of the UTF-8 value, so it reads back byte for byte
 * whatever it contains (security prints non-text data as hex).
 *
 * With confirm "always" the item is created with an empty trusted-application
 * list (`-T ""`): every read shows the macOS keychain dialog and needs the
 * person. With "never", /usr/bin/security (the creator) is trusted, so any
 * same-user process can read it silently through that tool.
 */

import { defaultRunner, stripNewline, systemBinary, VAULT_SERVICE, VaultBackendError, type Availability, type Runner, type SystemBinaryDeps, type VaultBackend } from "./backend.js";
import type { Confirm } from "../../policy-vault.js";

export const SECURITY = "/usr/bin/security";
const PREFIX = "lsfw1:";

/** Characters allowed in the interactive command's quoted words (service, account, label). */
const SAFE_WORD = /^[A-Za-z0-9 _.:/@#-]{1,255}$/;

function quote(word: string): string {
  if (!SAFE_WORD.test(word)) throw new VaultBackendError(`cannot pass "${word}" to the keychain safely`);
  return `"${word}"`;
}

export function encodeStored(value: string): string {
  return `${PREFIX}${Buffer.from(value, "utf8").toString("base64")}`;
}

export function decodeStored(data: string): string {
  if (!data.startsWith(PREFIX)) throw new VaultBackendError("the keychain item was not written by the vault (unexpected format)");
  return Buffer.from(data.slice(PREFIX.length), "base64").toString("utf8");
}

/** The interactive-mode line that adds (or replaces, -U) an item. The value is only in it as hex. */
export function addCommandLine(service: string, account: string, value: string, confirm: Confirm): string {
  const hex = Buffer.from(encodeStored(value), "utf8").toString("hex");
  const acl = confirm === "always" ? ' -T ""' : "";
  return `add-generic-password -U -s ${quote(service)} -a ${quote(account)} -l ${quote(`LaunchSafe Firewall vault ${account}`)} -D ${quote("LaunchSafe Firewall secret")}${acl} -X ${hex}\n`;
}

export function readArgs(service: string, account: string): string[] {
  return ["find-generic-password", "-s", service, "-a", account, "-w"];
}

export function existsArgs(service: string, account: string): string[] {
  return ["find-generic-password", "-s", service, "-a", account];
}

export function deleteArgs(service: string, account: string): string[] {
  return ["delete-generic-password", "-s", service, "-a", account];
}

/** security -i exits 0 even when a command fails; a failing command prints "<command>: returned <code>". */
function interactiveFailure(out: string): string | null {
  const m = /returned (-?\d+)/.exec(out);
  return m === null ? null : (m[1] as string);
}

/** errSecItemNotFound, as `security` reports it (exit status 44 for find/delete). */
const NOT_FOUND_EXIT = 44;

export interface KeychainOptions {
  runner?: Runner;
  service?: string;
  platform?: NodeJS.Platform;
  binary?: SystemBinaryDeps;
}

export function keychainBackend(o: KeychainOptions = {}): VaultBackend {
  const run = o.runner ?? defaultRunner;
  const service = o.service ?? VAULT_SERVICE;
  const platform = o.platform ?? process.platform;
  const bin = (): string => {
    const b = platform === "darwin" ? systemBinary([SECURITY], o.binary) : null;
    if (b === null) throw new VaultBackendError(`${SECURITY} is not available`);
    return b;
  };
  return {
    id: "keychain",
    available(): Availability {
      if (platform !== "darwin") return { ok: false, reason: "the macOS Keychain exists only on macOS" };
      return systemBinary([SECURITY], o.binary) !== null ? { ok: true } : { ok: false, reason: `${SECURITY} is missing or not a root-owned system file` };
    },
    write(account, value, opts) {
      if (value === "") throw new VaultBackendError("an empty value cannot be stored");
      const r = run(bin(), ["-i"], addCommandLine(service, account, value, opts.confirm));
      const failed = r.error !== undefined || r.status !== 0 ? String(r.status) : interactiveFailure(`${r.stdout}\n${r.stderr}`);
      if (failed !== null) throw new VaultBackendError(`the keychain refused to store ${account} (security returned ${failed}${r.error !== undefined ? `: ${r.error.message}` : ""})`);
      // Interactive mode reports failures only as text: confirm the item is there.
      if (this.exists(account) === false) throw new VaultBackendError(`the keychain did not store ${account}`);
    },
    read(account) {
      const r = run(bin(), readArgs(service, account));
      if (r.status === NOT_FOUND_EXIT) throw new VaultBackendError(`no keychain item for ${account}`);
      if (r.error !== undefined || r.status !== 0) throw new VaultBackendError(`could not read ${account} from the keychain (security exited ${String(r.status)}${r.error !== undefined ? `: ${r.error.message}` : ""}); a declined or unanswered confirmation dialog ends this way too`);
      return decodeStored(stripNewline(r.stdout));
    },
    remove(account) {
      const r = run(bin(), deleteArgs(service, account));
      if (r.status === NOT_FOUND_EXIT) return false;
      if (r.error !== undefined || r.status !== 0) throw new VaultBackendError(`could not delete ${account} from the keychain (security exited ${String(r.status)})`);
      return true;
    },
    exists(account) {
      const r = run(bin(), existsArgs(service, account));
      if (r.status === 0) return true;
      if (r.status === NOT_FOUND_EXIT) return false;
      return null;
    },
  };
}
