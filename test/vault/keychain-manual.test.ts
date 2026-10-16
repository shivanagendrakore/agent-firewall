/**
 * Opt-in, manual: exercises the REAL macOS Keychain through the vault's keychain backend, under a
 * separate service name ("launchsafe-firewall-manual-test") so it never touches the firewall's own
 * items. Skipped unless a person runs it on purpose:
 *
 *   LAUNCHSAFE_FIREWALL_VAULT_REAL_KEYCHAIN=1 npx vitest run test/vault/keychain-manual.test.ts
 *
 * It writes one random test value with confirm "never", reads it back, checks the value never reached
 * argv, and deletes it (also when an assertion fails). The confirm "always" path shows a keychain
 * dialog on read, so it only checks the write and the delete; answer "Deny" if a dialog appears.
 * This is the check of: security -i quoting, -X hex values, -T "".
 */
import { randomBytes } from "node:crypto";
import { afterAll, describe, expect, it } from "vitest";
import { defaultRunner, REAL_STORE_TEST_VAR, type Runner } from "../../src/runtime/vault/backend.js";
import { keychainBackend } from "../../src/runtime/vault/keychain.js";

const enabled = process.env[REAL_STORE_TEST_VAR] === "1" && process.platform === "darwin";
const SERVICE = "launchsafe-firewall-manual-test";

describe.skipIf(!enabled)("real macOS Keychain (manual, opt-in; skipped by default: set LAUNCHSAFE_FIREWALL_VAULT_REAL_KEYCHAIN=1 on macOS)", () => {
  const argvSeen: string[] = [];
  const run: Runner = (cmd, args, input) => {
    argvSeen.push([cmd, ...args].join(" "));
    return defaultRunner(cmd, args, input);
  };
  const kc = keychainBackend({ runner: run, service: SERVICE });
  const accounts: string[] = [];
  afterAll(() => {
    for (const a of accounts) {
      try {
        kc.remove(a);
      } catch {
        // Already gone.
      }
    }
  });

  it('confirm "never": write, read back exactly, value never in argv, delete', () => {
    const account = `manual/${randomBytes(4).toString("hex")}:value`;
    accounts.push(account);
    const value = `lsfw-manual-${randomBytes(12).toString("hex")} "quoted" 'single' Grüße`;
    kc.write(account, value, { confirm: "never" });
    expect(kc.exists(account)).toBe(true);
    expect(kc.read(account)).toBe(value);
    kc.write(account, `${value}-rotated`, { confirm: "never" });
    expect(kc.read(account)).toBe(`${value}-rotated`);
    expect(argvSeen.join("\n")).not.toContain("lsfw-manual-");
    expect(kc.remove(account)).toBe(true);
    expect(kc.exists(account)).toBe(false);
  });

  it('confirm "always": the item is created with an empty access list (write and delete only; a read would prompt)', () => {
    const account = `manual/${randomBytes(4).toString("hex")}:value`;
    accounts.push(account);
    kc.write(account, `lsfw-manual-${randomBytes(12).toString("hex")}`, { confirm: "always" });
    expect(kc.exists(account)).toBe(true);
    expect(kc.remove(account)).toBe(true);
  });
});
