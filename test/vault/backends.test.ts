/**
 * Vault: the backends. The macOS Keychain and Linux Secret Service backends are tested through a
 * recording runner only (argument building, where the value goes, how failures are read): no test
 * starts /usr/bin/security or secret-tool, and the default runner refuses to while a test marker is set.
 * The encrypted file backend is pure Node and is exercised for real in a temporary directory.
 */
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { accountFor, defaultRunner, RealStoreRefused, systemBinary, VAULT_SERVICE } from "../../src/runtime/vault/backend.js";
import { addCommandLine, decodeStored, encodeStored, keychainBackend, SECURITY } from "../../src/runtime/vault/keychain.js";
import { libsecretBackend } from "../../src/runtime/vault/libsecret.js";
import { fileBackend, rewrapFileStore, storePath } from "../../src/runtime/vault/file.js";
import { openBackend } from "../../src/runtime/vault/backends.js";
import { layout } from "../../src/runtime/layout.js";
import { testRoot } from "../helpers.js";
import { recordingRunner, TOKEN } from "./fake.js";

const trusted = { exists: () => true, trusted: () => true };

describe("the default runner never reaches a real store under test", () => {
  it("refuses to start any helper while the test marker is set", () => {
    expect(() => defaultRunner(SECURITY, ["find-generic-password", "-s", VAULT_SERVICE])).toThrow(RealStoreRefused);
    const kc = keychainBackend({ platform: "darwin", binary: trusted });
    expect(() => kc.read("x:value")).toThrow(RealStoreRefused);
    expect(() => openBackend("libsecret", layout(testRoot()), { passphrase: "", platform: "linux", env: { DBUS_SESSION_BUS_ADDRESS: "unix:path=/x" } }).read("x")).toThrow();
  });
  it("helpers come only from fixed root-owned paths, never PATH", () => {
    expect(systemBinary(["/usr/bin/x", "/bin/x"], { exists: (p) => p === "/bin/x", trusted: () => true })).toBe("/bin/x");
    expect(systemBinary(["/usr/bin/x"], { exists: () => true, trusted: () => false })).toBeNull();
  });
});

describe("macOS Keychain backend (argument building only)", () => {
  it("writes through security -i with the command on stdin; the value is never in argv, only hex-encoded on stdin", () => {
    const { run, calls } = recordingRunner((c) => (c.args[0] === "find-generic-password" ? { status: 0 } : {}));
    keychainBackend({ runner: run, platform: "darwin", binary: trusted }).write(accountFor("github/token", "value"), TOKEN, { confirm: "never" });
    expect(calls[0]?.cmd).toBe(SECURITY);
    expect(calls[0]?.args).toEqual(["-i"]);
    expect(calls.flatMap((c) => c.args).join(" ")).not.toContain(TOKEN);
    expect(calls[0]?.input).not.toContain(TOKEN);
    expect(calls[0]?.input).toMatch(/^add-generic-password -U -s "launchsafe-firewall" -a "github\/token:value" -l "LaunchSafe Firewall vault github\/token:value" -D "LaunchSafe Firewall secret" -X [0-9a-f]+\n$/);
    expect(calls[0]?.input).not.toContain("-T");
    // Confirms the item is there afterwards (interactive mode reports failures only as text).
    expect(calls[1]?.args).toEqual(["find-generic-password", "-s", VAULT_SERVICE, "-a", "github/token:value"]);
  });
  it('confirm "always" creates the item with an empty trusted-application list (-T "")', () => {
    expect(addCommandLine(VAULT_SERVICE, "bank/primary:iban", "DE00", "always")).toContain(' -T "" -X ');
  });
  it("the stored data round-trips any text byte for byte (prefix + base64 under hex)", () => {
    for (const v of [TOKEN, "Grüße – 東京 \"quoted\" 'single' $HOME `x` \\n", "a b"]) {
      expect(decodeStored(encodeStored(v))).toBe(v);
      const hex = /-X ([0-9a-f]+)/.exec(addCommandLine(VAULT_SERVICE, "a:value", v, "never"))?.[1] as string;
      expect(decodeStored(Buffer.from(hex, "hex").toString("utf8"))).toBe(v);
    }
    expect(() => decodeStored("plain")).toThrow(/not written by the vault/);
  });
  it("reads with find-generic-password -w (no value in argv) and decodes", () => {
    const { run, calls } = recordingRunner(() => ({ stdout: `${encodeStored(TOKEN)}\n` }));
    expect(keychainBackend({ runner: run, platform: "darwin", binary: trusted }).read("github/token:value")).toBe(TOKEN);
    expect(calls[0]?.args).toEqual(["find-generic-password", "-s", VAULT_SERVICE, "-a", "github/token:value", "-w"]);
  });
  it("a failure printed by interactive mode, a missing item and a declined dialog are errors, never a value", () => {
    const failing = recordingRunner(() => ({ stderr: "add-generic-password: returned -25308\n" }));
    expect(() => keychainBackend({ runner: failing.run, platform: "darwin", binary: trusted }).write("a:value", TOKEN, { confirm: "always" })).toThrow(/refused to store a:value \(security returned -25308\)/);
    const missing = recordingRunner(() => ({ status: 44 }));
    const kc = keychainBackend({ runner: missing.run, platform: "darwin", binary: trusted });
    expect(() => kc.read("a:value")).toThrow(/no keychain item/);
    expect(kc.remove("a:value")).toBe(false);
    expect(kc.exists("a:value")).toBe(false);
    const declined = recordingRunner(() => ({ status: 51 }));
    expect(() => keychainBackend({ runner: declined.run, platform: "darwin", binary: trusted }).read("a:value")).toThrow(/confirmation dialog/);
  });
  it("deletes with delete-generic-password; unavailable off macOS or without a trusted /usr/bin/security", () => {
    const { run, calls } = recordingRunner();
    expect(keychainBackend({ runner: run, platform: "darwin", binary: trusted }).remove("a:value")).toBe(true);
    expect(calls[0]?.args).toEqual(["delete-generic-password", "-s", VAULT_SERVICE, "-a", "a:value"]);
    expect(keychainBackend({ platform: "linux" }).available().ok).toBe(false);
    expect(keychainBackend({ platform: "darwin", binary: { exists: () => true, trusted: () => false } }).available().ok).toBe(false);
  });
  it("refuses a word the interactive parser could misread", () => {
    expect(() => addCommandLine(VAULT_SERVICE, 'a"b', "v", "never")).toThrow(/safely/);
  });
});

describe("Linux Secret Service backend (argument building only)", () => {
  const env = { DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1000/bus" };
  it("stores with the value on stdin, looks up and clears by service and name", () => {
    const { run, calls } = recordingRunner((c) => (c.args[0] === "lookup" ? { stdout: TOKEN } : {}));
    const b = libsecretBackend({ runner: run, platform: "linux", env, binary: trusted });
    b.write("github/token:value", TOKEN, { confirm: "never" });
    expect(calls[0]?.cmd).toBe("/usr/bin/secret-tool");
    expect(calls[0]?.args).toEqual(["store", "--label=LaunchSafe Firewall vault github/token:value", "service", VAULT_SERVICE, "name", "github/token:value"]);
    expect(calls[0]?.input).toBe(TOKEN);
    expect(calls[0]?.args.join(" ")).not.toContain(TOKEN);
    expect(b.read("github/token:value")).toBe(TOKEN);
    expect(calls[1]?.args).toEqual(["lookup", "service", VAULT_SERVICE, "name", "github/token:value"]);
    b.remove("github/token:value");
    expect(calls[2]?.args).toEqual(["clear", "service", VAULT_SERVICE, "name", "github/token:value"]);
    expect(b.exists("x")).toBeNull();
  });
  it("is unavailable without a session bus, off Linux, or without a root-owned secret-tool; a failed lookup is an error", () => {
    expect(libsecretBackend({ platform: "linux", env: {}, binary: trusted }).available().reason).toMatch(/session bus/);
    expect(libsecretBackend({ platform: "darwin", env, binary: trusted }).available().ok).toBe(false);
    expect(libsecretBackend({ platform: "linux", env, binary: { exists: () => true, trusted: () => false } }).available().reason).toMatch(/root-owned/);
    const locked = recordingRunner(() => ({ status: 1 }));
    expect(() => libsecretBackend({ runner: locked.run, platform: "linux", env, binary: trusted }).read("a:value")).toThrow(/locked/);
  });
});

describe("encrypted file backend (real, in a temporary directory)", () => {
  const PASS = "correct horse battery";
  const home = (): ReturnType<typeof layout> => layout(join(mkdtempSync(join(testRoot(), "vault-file-")), "home"));
  it("round-trips values, never stores them in the clear, and opens only with the passphrase", () => {
    const l = home();
    const b = fileBackend(l, PASS);
    b.write("github/token:value", TOKEN, { confirm: "never" });
    b.write("bank/primary:iban", "DE89370400440532013000", { confirm: "never" });
    expect(b.read("github/token:value")).toBe(TOKEN);
    expect(b.exists("bank/primary:iban")).toBe(true);
    const raw = readFileSync(storePath(l), "utf8");
    expect(raw).not.toContain(TOKEN);
    expect(raw).not.toContain("DE89370400440532013000");
    expect(() => fileBackend(l, "wrong passphrase!").read("github/token:value")).toThrow(/does not open/);
    expect(b.remove("github/token:value")).toBe(true);
    expect(b.remove("github/token:value")).toBe(false);
    expect(() => b.read("github/token:value")).toThrow(/no value/);
  });
  it("an entry cannot be moved to another account (the account is authenticated data)", () => {
    const l = home();
    const b = fileBackend(l, PASS);
    b.write("a:value", TOKEN, { confirm: "never" });
    const doc = JSON.parse(readFileSync(storePath(l), "utf8")) as { entries: Record<string, unknown> };
    doc.entries["b:value"] = doc.entries["a:value"];
    writeFileSync(storePath(l), JSON.stringify(doc));
    expect(() => b.read("b:value")).toThrow(/damaged/);
  });
  it("approver rotate re-wraps the data key: the new passphrase opens it, the old one no longer does", () => {
    const l = home();
    fileBackend(l, PASS).write("a:value", TOKEN, { confirm: "never" });
    expect(rewrapFileStore(l, PASS, "a brand new passphrase")).toBe(true);
    expect(fileBackend(l, "a brand new passphrase").read("a:value")).toBe(TOKEN);
    expect(() => fileBackend(l, PASS).read("a:value")).toThrow(/does not open/);
    expect(rewrapFileStore(home(), PASS, "x")).toBe(false);
  });
});
