/**
 * Vault: doctor's vault checks and the `vault` policy key (tighten-only for a project).
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { defaultConfig, mergeTighten, mergeTrusted, validatePolicy } from "../../src/policy.js";
import { vaultPolicy } from "../../src/policy-vault.js";
import { doctor } from "../../src/runtime/doctor.js";
import { initApprover, unlockApprover } from "../../src/runtime/approver.js";
import { layout } from "../../src/runtime/layout.js";
import { indexPath, updateIndex, type VaultEntry } from "../../src/runtime/vault/index.js";
import { vaultChecks } from "../../src/runtime/vault/doctor.js";
import { testRoot } from "../helpers.js";

const PASS = "correct horse battery";
const entry = (name: string, over: Partial<VaultEntry> = {}): VaultEntry => ({ name, kind: "credential", fields: ["value"], backend: "keychain", confirm: "never", bindings: [], fingerprints: {}, createdAt: "2026-10-10T00:00:00.000Z", ...over });

function home(): { l: ReturnType<typeof layout>; pub: string; priv: ReturnType<typeof unlockApprover> } {
  const l = layout(join(mkdtempSync(join(testRoot(), "vault-doctor-")), "home"));
  const pub = initApprover(l, PASS);
  return { l, pub, priv: unlockApprover(l, PASS) };
}

const ok = () => ({ ok: true });

describe("doctor: vault", () => {
  it("no index: ok, says where new secrets go", () => {
    const { l, pub } = home();
    const c = vaultChecks(l, defaultConfig(), { platform: "darwin", trustedKey: pub, available: ok });
    expect(c).toEqual([{ name: "vault", status: "ok", detail: expect.stringMatching(/no secrets stored.*macOS Keychain/) as unknown as string }]);
  });
  it("a signed index: ok with counts; unbound entries named; an unsigned one fails (V9); a damaged one fails", () => {
    const { l, pub, priv } = home();
    updateIndex(l, priv, (e) => e.push(entry("github/token", { bindings: [{ kind: "host", host: "api.github.com" }] }), entry("npm/token")));
    const c = vaultChecks(l, defaultConfig(), { platform: "darwin", trustedKey: pub, available: ok, exists: () => true });
    expect(c.find((x) => x.name === "vault")).toMatchObject({ status: "ok", detail: expect.stringMatching(/^2 secret\(s\), 1 binding\(s\), signed/) as unknown as string });
    expect(c.find((x) => x.name === "vault bindings")?.detail).toMatch(/npm\/token/);
    expect(vaultChecks(l, defaultConfig(), { platform: "darwin", trustedKey: null, available: ok, exists: () => true }).find((x) => x.name === "vault")?.status).toBe("fail");
    writeFileSync(indexPath(l), "{");
    expect(vaultChecks(l, defaultConfig(), { platform: "darwin", trustedKey: pub, available: ok }).find((x) => x.name === "vault")).toMatchObject({ status: "fail" });
  });
  it("warns about store strength (Secret Service, file store), silent financial items, unavailable stores; fails on missing values", () => {
    const { l, pub, priv } = home();
    updateIndex(l, priv, (e) => e.push(entry("a"), entry("card/x", { kind: "card", fields: ["number"] }), entry("b", { backend: "libsecret" }), entry("c", { backend: "file" })));
    const c = vaultChecks(l, defaultConfig(), { platform: "darwin", trustedKey: pub, available: (id) => (id === "libsecret" ? { ok: false, reason: "not Linux" } : { ok: true }), exists: (e) => e.name !== "a" });
    const by = (n: string) => c.find((x) => x.name === n);
    expect(by("vault confirmation")?.detail).toMatch(/card\/x \(card\)/);
    expect(by("vault store")?.detail).toMatch(/libsecret store, which is not available here \(not Linux\): b/);
    expect(by("vault store strength")?.status).toBe("warn");
    expect(by("vault file store")?.status).toBe("warn");
    expect(by("vault values")).toMatchObject({ status: "fail", detail: expect.stringMatching(/a#value/) as unknown as string });
  });
  it("policy vault.enabled false with stored values warns; the full doctor includes the vault checks", () => {
    const { l, pub, priv } = home();
    updateIndex(l, priv, (e) => e.push(entry("a")));
    expect(vaultChecks(l, { ...defaultConfig(), vault: { enabled: false } }, { platform: "darwin", trustedKey: pub, available: ok, exists: () => true }).find((x) => x.name === "vault")?.status).toBe("warn");
    const all = doctor(l, l.home, { home: l.home, platform: "linux", claudeVersion: null, probe: () => false });
    expect(all.some((x) => x.name === "vault")).toBe(true);
    expect(all.find((x) => x.name === "vault")?.weight).toBeUndefined();
  });
});

describe("policy: vault", () => {
  it("defaults: financial kinds confirm per use and the vault checks are on", () => {
    const p = vaultPolicy(defaultConfig());
    expect(p).toEqual({ enabled: true, confirmDefault: { card: "always", iban: "always", national_id: "always", personal: "always", credential: "never", oauth: "never" }, fileFallback: false, approveKinds: ["card", "iban", "national_id", "personal"], approveWhenUntrusted: true, shellRewrite: "auto", ticketSeconds: 30, listInContext: true });
  });
  it("validates strictly", () => {
    expect(validatePolicy({ version: 2, vault: { enabled: false, fileFallback: true, confirmDefault: { credential: "always" } } }, "user")).toMatchObject({ vault: { enabled: false, fileFallback: true, confirmDefault: { credential: "always" } } });
    expect(() => validatePolicy({ version: 2, vault: { bindings: [] } }, "p")).toThrow(/vault.bindings" is not a known setting/);
    expect(() => validatePolicy({ version: 2, vault: { confirmDefault: { password: "always" } } }, "p")).toThrow(/not a vault kind/);
    expect(() => validatePolicy({ version: 2, vault: { confirmDefault: { card: "sometimes" } } }, "p")).toThrow(/"always" or "never"/);
    expect(() => validatePolicy({ version: 2, vault: { fileFallback: "yes" } }, "p")).toThrow(/true or false/);
  });
  it("the user's policy may loosen; a project may only tighten", () => {
    const user = mergeTrusted(defaultConfig(), validatePolicy({ version: 2, vault: { fileFallback: true, confirmDefault: { card: "never" } } }, "user"));
    expect(vaultPolicy(user)).toMatchObject({ fileFallback: true, confirmDefault: { card: "never", iban: "always" } });
    const { config, ignored } = mergeTighten(user, validatePolicy({ version: 2, vault: { enabled: false, fileFallback: false, confirmDefault: { credential: "always", iban: "never" } } }, "project"));
    expect(vaultPolicy(config)).toMatchObject({ enabled: true, fileFallback: false, confirmDefault: { credential: "always", card: "never", iban: "always" } });
    expect(ignored.join("; ")).toMatch(/vault.enabled/);
    expect(ignored.join("; ")).toMatch(/vault.confirmDefault.iban/);
    const on = mergeTighten(defaultConfig(), validatePolicy({ version: 2, vault: { fileFallback: true } }, "project"));
    expect(vaultPolicy(on.config).fileFallback).toBe(false);
    expect(on.ignored.join(" ")).toMatch(/fileFallback/);
  });
  it("a config without vault keys merges to no vault key (policy show is unchanged)", () => {
    expect(mergeTrusted(defaultConfig(), {}).vault).toBeUndefined();
  });
});
