/**
 * Linux Secret Service backend: `secret-tool` (libsecret), run only from
 * fixed root-owned system paths. `secret-tool store` reads the value from its
 * standard input, so it never appears in argv.
 *
 * Nothing protects an item per application: once the login keyring is
 * unlocked, any same-user process on the session bus can read it. Only the OS
 * sandbox (no bus socket inside it) and the firewall's own rules stand between
 * the agent and the value; doctor says so.
 */

import { defaultRunner, stripNewline, systemBinary, VAULT_SERVICE, VaultBackendError, type Availability, type Runner, type SystemBinaryDeps, type VaultBackend } from "./backend.js";

export const SECRET_TOOL_PATHS: readonly string[] = ["/usr/bin/secret-tool", "/bin/secret-tool", "/usr/local/bin/secret-tool"];

export function storeArgs(service: string, account: string): string[] {
  return ["store", `--label=LaunchSafe Firewall vault ${account}`, "service", service, "name", account];
}

export function lookupArgs(service: string, account: string): string[] {
  return ["lookup", "service", service, "name", account];
}

export function clearArgs(service: string, account: string): string[] {
  return ["clear", "service", service, "name", account];
}

export interface LibsecretOptions {
  runner?: Runner;
  service?: string;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  binary?: SystemBinaryDeps;
}

export function libsecretBackend(o: LibsecretOptions = {}): VaultBackend {
  const run = o.runner ?? defaultRunner;
  const service = o.service ?? VAULT_SERVICE;
  const platform = o.platform ?? process.platform;
  const env = o.env ?? process.env;
  const availability = (): Availability => {
    if (platform !== "linux") return { ok: false, reason: "the Secret Service backend is for Linux" };
    if ((env.DBUS_SESSION_BUS_ADDRESS ?? "") === "") return { ok: false, reason: "no D-Bus session bus (DBUS_SESSION_BUS_ADDRESS is not set; a headless session has no Secret Service)" };
    if (systemBinary(SECRET_TOOL_PATHS, o.binary) === null) return { ok: false, reason: `secret-tool is not installed as a root-owned file in ${SECRET_TOOL_PATHS.join(", ")} (try: sudo apt install libsecret-tools)` };
    return { ok: true };
  };
  const bin = (): string => {
    const a = availability();
    const b = systemBinary(SECRET_TOOL_PATHS, o.binary);
    if (!a.ok || b === null) throw new VaultBackendError(a.reason ?? "secret-tool is not available");
    return b;
  };
  return {
    id: "libsecret",
    available: availability,
    write(account, value) {
      if (value === "") throw new VaultBackendError("an empty value cannot be stored");
      const r = run(bin(), storeArgs(service, account), value);
      if (r.error !== undefined || r.status !== 0) throw new VaultBackendError(`the Secret Service refused to store ${account} (secret-tool exited ${String(r.status)}${r.stderr.trim() !== "" ? `: ${r.stderr.trim().slice(0, 200)}` : ""})`);
    },
    read(account) {
      const r = run(bin(), lookupArgs(service, account));
      if (r.error !== undefined || r.status !== 0 || r.stdout === "") throw new VaultBackendError(`could not read ${account} from the Secret Service (missing, or the keyring is locked)`);
      return stripNewline(r.stdout);
    },
    remove(account) {
      const r = run(bin(), clearArgs(service, account));
      // secret-tool clear exits 0 whether or not something matched.
      if (r.error !== undefined || r.status !== 0) throw new VaultBackendError(`could not delete ${account} from the Secret Service (secret-tool exited ${String(r.status)})`);
      return true;
    },
    // secret-tool search prints the secret itself, so existence is not probed.
    exists() {
      return null;
    },
  };
}
