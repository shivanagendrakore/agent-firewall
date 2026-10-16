/**
 * Vault: the signed index. Signed with the approver key, verified against the key the caller
 * trusts; an edit on disk (V9) or a different key leaves the vault unsigned (nothing bound), a damaged
 * file gives no view, and a change is never built on an index that does not verify.
 */
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { initApprover, publicKeyOf, unlockApprover } from "../../src/runtime/approver.js";
import { layout } from "../../src/runtime/layout.js";
import { indexPath, loadIndex, parseIndex, signIndex, updateIndex, vaultView, verifyIndex, type VaultEntry } from "../../src/runtime/vault/index.js";
import { buildContext } from "../../src/runtime/context.js";
import { defaultConfig } from "../../src/policy.js";
import { testRoot } from "../helpers.js";

const PASS = "correct horse battery";

function setup(): { l: ReturnType<typeof layout>; priv: ReturnType<typeof unlockApprover>; pub: string } {
  const l = layout(join(mkdtempSync(join(testRoot(), "vault-index-")), "home"));
  const pub = initApprover(l, PASS);
  return { l, priv: unlockApprover(l, PASS), pub };
}

const entry = (name: string, over: Partial<VaultEntry> = {}): VaultEntry => ({ name, kind: "credential", fields: ["value"], backend: "keychain", confirm: "never", bindings: [{ kind: "host", host: "api.github.com" }], fingerprints: { value: "32:1:2:0123456789abcdef01234567" }, createdAt: "2026-10-10T00:00:00.000Z", ...over });

describe("vault index", () => {
  it("is signed with the approver key and verifies only against it", () => {
    const { priv, pub } = setup();
    const idx = signIndex(priv, [entry("github/token")]);
    expect(verifyIndex(idx, pub)).toBe(true);
    expect(publicKeyOf(priv)).toBe(pub);
    const other = (generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
    expect(verifyIndex(idx, other)).toBe(false);
    expect(verifyIndex(idx, null)).toBe(false);
  });
  it("updateIndex writes a private, signed file; loadIndex reads it back", () => {
    const { l, priv, pub } = setup();
    updateIndex(l, priv, (entries) => entries.push(entry("github/token")));
    expect(statSync(indexPath(l)).mode & 0o777).toBe(0o600);
    const st = loadIndex(l, pub);
    expect(st.state).toBe("ok");
    expect(vaultView(st)).toEqual({ signed: true, entries: [{ name: "github/token", kind: "credential", fields: ["value"], bindings: [{ kind: "host", host: "api.github.com" }], fingerprints: { value: "32:1:2:0123456789abcdef01234567" }, confirm: "never" }] });
    expect(readFileSync(indexPath(l), "utf8")).not.toMatch(/"value":\s*"[^3]/);
  });
  it("V9: a binding added on disk breaks the signature: unsigned (nothing bound), and no change builds on it", () => {
    const { l, priv, pub } = setup();
    updateIndex(l, priv, (entries) => entries.push(entry("github/token")));
    const doc = JSON.parse(readFileSync(indexPath(l), "utf8")) as { entries: VaultEntry[] };
    doc.entries[0]?.bindings.push({ kind: "host", host: "attacker.example" });
    writeFileSync(indexPath(l), JSON.stringify(doc));
    const st = loadIndex(l, pub);
    expect(st.state).toBe("unsigned");
    expect(vaultView(st)?.signed).toBe(false);
    expect(() => updateIndex(l, priv, () => undefined)).toThrow(/not signed by your approval key/);
  });
  it("no trusted key means unsigned; a damaged file is corrupt and gives a damaged view with nothing in it (FB5)", () => {
    const { l, priv } = setup();
    updateIndex(l, priv, (entries) => entries.push(entry("github/token")));
    expect(loadIndex(l, null).state).toBe("unsigned");
    writeFileSync(indexPath(l), "{not json");
    const st = loadIndex(l, null);
    expect(st.state).toBe("corrupt");
    expect(vaultView(st)).toMatchObject({ signed: false, entries: [], damaged: expect.stringMatching(/not a valid vault index/) });
    expect(() => updateIndex(l, priv, () => undefined)).toThrow(/not a valid vault index/);
    expect(vaultView({ state: "absent" })).toBeUndefined();
  });
  it("parsing is strict: bad names, kinds, backends, duplicate names, unknown binding kinds", () => {
    const { priv } = setup();
    const ok = signIndex(priv, [entry("a")]);
    expect(parseIndex(JSON.stringify(ok))).not.toBeNull();
    for (const bad of [entry("Bad Name"), entry("a", { kind: "password" as never }), entry("a", { backend: "cloud" as never }), entry("a", { bindings: [{ kind: "anywhere" } as never] }), entry("a", { fields: [] })]) {
      expect(parseIndex(JSON.stringify({ ...ok, entries: [bad] }))).toBeNull();
    }
    expect(parseIndex(JSON.stringify({ ...ok, entries: [entry("a"), entry("a")] }))).toBeNull();
  });
  it("buildContext gives the engine the view, verified against the key the hook pins", () => {
    const { l, priv, pub } = setup();
    updateIndex(l, priv, (entries) => entries.push(entry("github/token")));
    const base = { l, cfg: defaultConfig(), basics: { sessionId: "s", cwd: l.home }, detectNonInteractive: () => false };
    expect(buildContext({ ...base, env: { LAUNCHSAFE_FIREWALL_APPROVER: pub } }).ctx.vault?.signed).toBe(true);
    const other = (generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
    expect(buildContext({ ...base, env: { LAUNCHSAFE_FIREWALL_APPROVER: other } }).ctx.vault?.signed).toBe(false);
    expect(buildContext({ ...base, cfg: { ...defaultConfig(), vault: { enabled: false } }, env: {} }).ctx.vault).toBeUndefined();
  });
});
