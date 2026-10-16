/**
 * The vault's commands, run in-process through main() with a fake store and scripted
 * terminal input (the real handlers, never this machine's keychain). They need a person and the approval
 * passphrase, sign the index, log a vault_change entry, and never print, log or index a value.
 */
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { main } from "../../src/climain.js";
import { fingerprint } from "../../src/engine/secrets.js";
import { initApprover, publicKeyOf, rotateApprover, unlockApprover, approverPublicKey } from "../../src/runtime/approver.js";
import { plantCanaries, loadRegistry } from "../../src/runtime/canaries.js";
import { layout, type Layout } from "../../src/runtime/layout.js";
import { tailLog, verifyLog } from "../../src/runtime/log.js";
import { indexPath, loadIndex } from "../../src/runtime/vault/index.js";
import { afterApproverRotate } from "../../src/vault-cli.js";
import type { VaultCliDeps } from "../../src/vault-cli.js";
import { testRoot } from "../helpers.js";
import { fakeBackend, IBAN, OPAQUE, TOKEN, type FakeStore } from "./fake.js";

const PASS = "correct horse battery";

interface Harness {
  l: Layout;
  store: FakeStore;
  run: (args: string[], o?: { secrets?: string[]; answers?: string[]; human?: boolean; deps?: Partial<VaultCliDeps> }) => Promise<{ status: number; stdout: string; stderr: string; prompts: string[] }>;
}

function harness(o: { approver?: boolean; platform?: NodeJS.Platform } = {}): Harness {
  const l = layout(join(mkdtempSync(join(testRoot(), "vault-cli-")), "home"));
  if (o.approver !== false) initApprover(l, PASS);
  const store = fakeBackend(o.platform === "linux" ? "libsecret" : "keychain");
  return {
    l,
    store,
    async run(args, r = {}) {
      let stdout = "";
      let stderr = "";
      const prompts: string[] = [];
      const secrets = [...(r.secrets ?? [])];
      const answers = [...(r.answers ?? [])];
      const status = await main(args, l, {
        write: (fd, s) => (fd === 1 ? (stdout += s) : (stderr += s)),
        humanAtKeyboard: () => Promise.resolve(r.human ?? true),
        vault: {
          readSecret: (p) => {
            prompts.push(p);
            return Promise.resolve(secrets.shift() ?? "");
          },
          ask: (p) => {
            prompts.push(p);
            return Promise.resolve(answers.shift() ?? "");
          },
          openBackend: () => store,
          available: () => ({ ok: true }),
          platform: o.platform ?? "darwin",
          env: {},
          ...(r.deps ?? {}),
        },
      });
      return { status, stdout, stderr, prompts };
    },
  };
}

function vaultLog(l: Layout): Record<string, unknown>[] {
  return tailLog(l, 100).map((e) => e.event).filter((e) => e.type === "vault_change");
}

function allFiles(dir: string): string {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((d) => d.isFile())
    .map((d) => readFileSync(join(d.parentPath, d.name), "utf8"))
    .join("\n");
}

describe("vault add", () => {
  it("stores each value in the backend, signs the index with fingerprints only, and logs the change", async () => {
    const h = harness();
    const r = await h.run(["vault", "add", "github/token"], { secrets: [PASS, TOKEN] });
    expect(r.status, r.stderr).toBe(0);
    expect(r.prompts[0]).toBe("Approval passphrase: ");
    expect(r.prompts[1]).toMatch(/vault:\/\/github\/token .*not shown/);
    expect(h.store.values.get("github/token:value")).toEqual({ value: TOKEN, confirm: "never" });
    const st = loadIndex(h.l, approverPublicKey(h.l));
    expect(st.state).toBe("ok");
    const e = st.state === "ok" ? st.index.entries[0] : undefined;
    expect(e).toMatchObject({ name: "github/token", kind: "credential", fields: ["value"], backend: "keychain", confirm: "never", bindings: [], fingerprints: { value: fingerprint(TOKEN) } });
    expect(vaultLog(h.l)).toEqual([{ type: "vault_change", op: "add", name: "github/token", kind: "credential", backend: "keychain", fields: 1 }]);
    expect(verifyLog(h.l).ok).toBe(true);
    expect(r.stdout).toMatch(/bound to nothing yet/);
    // The value is nowhere on disk and nowhere in the output.
    expect(allFiles(h.l.home)).not.toContain(TOKEN);
    expect(r.stdout + r.stderr).not.toContain(TOKEN);
  });
  it("a financial kind gets its default fields and per-use confirmation; a short field is said to be unrecognisable", async () => {
    const h = harness();
    const r = await h.run(["vault", "add", "bank/primary", "--kind", "iban"], { secrets: [PASS, IBAN, "COBADEFFXXX", "Ada Lovelace"] });
    expect(r.status, r.stderr).toBe(0);
    expect([...h.store.values.keys()]).toEqual(["bank/primary:iban", "bank/primary:bic", "bank/primary:holder"]);
    expect(h.store.values.get("bank/primary:iban")?.confirm).toBe("always");
    expect(r.stdout).toMatch(/Field\(s\) bic are shorter than 12 characters/);
    const card = await h.run(["vault", "add", "card/main", "--kind", "card", "--fields", "number,cvc", "--confirm", "never"], { secrets: [PASS, "4111111111111111", "123"] });
    expect(card.status, card.stderr).toBe(0);
    expect(card.stdout).toMatch(/with --confirm never any program running as you can read this one/);
    expect(h.store.values.get("card/main:cvc")?.confirm).toBe("never");
  });
  it("refuses without a person, without an approval key, with a wrong passphrase: nothing is stored", async () => {
    const h = harness();
    expect((await h.run(["vault", "add", "x/y"], { secrets: [PASS, TOKEN], human: false })).status).toBe(1);
    const wrong = await h.run(["vault", "add", "x/y"], { secrets: ["wrong passphrase!", TOKEN] });
    expect(wrong.status).toBe(1);
    expect(wrong.stderr).toMatch(/wrong approval passphrase/);
    expect(wrong.prompts).toHaveLength(1);
    const none = harness({ approver: false });
    const r = await none.run(["vault", "add", "x/y"], { secrets: [TOKEN] });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/approver init/);
    expect(h.store.values.size + none.store.values.size).toBe(0);
    expect(vaultLog(h.l)).toEqual([]);
  });
  it("refuses a bad name or field list before asking anything, an existing name, an empty value and a decoy's value", async () => {
    const h = harness();
    const bad = await h.run(["vault", "add", "GitHub Token"]);
    expect(bad.status).toBe(64);
    expect(bad.prompts).toEqual([]);
    expect((await h.run(["vault", "add", "x", "--fields", "a,a"])).status).toBe(64);
    expect((await h.run(["vault", "add", "x", "--kind", "password"])).status).toBe(64);
    await h.run(["vault", "add", "github/token"], { secrets: [PASS, TOKEN] });
    const again = await h.run(["vault", "add", "github/token"], { secrets: [PASS, OPAQUE] });
    expect(again.status).toBe(64);
    expect(again.stderr).toMatch(/exists already; use "vault rotate/);
    expect(h.store.values.get("github/token:value")?.value).toBe(TOKEN);
    expect((await h.run(["vault", "add", "empty"], { secrets: [PASS, ""] })).stderr).toMatch(/no value was given/);
    const ws = mkdtempSync(join(testRoot(), "vault-ws-"));
    plantCanaries(h.l, { workspace: ws, kinds: ["env"] });
    const reg = loadRegistry(h.l);
    const decoy = reg.ok ? (reg.canaries[0]?.token as string) : "";
    const d = await h.run(["vault", "add", "decoy"], { secrets: [PASS, decoy] });
    expect(d.status).toBe(64);
    expect(d.stderr).toMatch(/decoy/);
  });
  it("on Linux without a Secret Service: refused unless the user policy allows the file store", async () => {
    const h = harness({ platform: "linux" });
    const r = await h.run(["vault", "add", "x"], { secrets: [PASS, TOKEN], deps: { available: (id) => (id === "libsecret" ? { ok: false, reason: "no D-Bus session bus" } : { ok: true }) } });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/fileFallback/);
    expect(r.prompts).toEqual([]);
  });
  it("a backend failure (locked keychain) stores nothing in the index", async () => {
    const h = harness();
    h.store.failWrites = true;
    const r = await h.run(["vault", "add", "x"], { secrets: [PASS, TOKEN] });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/refused to store/);
    expect(loadIndex(h.l, approverPublicKey(h.l)).state).toBe("absent");
  });
});

describe("vault allow / revoke / list / rotate / remove", () => {
  async function withSecret(): Promise<Harness> {
    const h = harness();
    await h.run(["vault", "add", "github/token"], { secrets: [PASS, TOKEN] });
    return h;
  }
  it("allow adds a signed binding; list shows names and bindings, never a value; revoke removes it by number", async () => {
    const h = await withSecret();
    const a = await h.run(["vault", "allow", "github/token", "--host", "API.GitHub.com"], { secrets: [PASS] });
    expect(a.status, a.stderr).toBe(0);
    const m = await h.run(["vault", "allow", "github/token", "--mcp", "github:create_*"], { secrets: [PASS] });
    expect(m.status, m.stderr).toBe(0);
    const list = await h.run(["vault", "list"]);
    expect(list.status).toBe(0);
    expect(list.stdout).toContain("vault://github/token  credential");
    expect(list.stdout).toContain("1. host api.github.com");
    expect(list.stdout).toContain("2. mcp github:create_*");
    expect(list.stdout).not.toContain(TOKEN);
    const json = JSON.parse((await h.run(["vault", "list", "--json"])).stdout) as { signed: boolean; secrets: { bindings: unknown[]; fingerprints?: unknown }[] };
    expect(json.signed).toBe(true);
    expect(json.secrets[0]?.bindings).toHaveLength(2);
    expect(json.secrets[0]?.fingerprints).toBeUndefined();
    const rv = await h.run(["vault", "revoke", "github/token", "1"], { secrets: [PASS] });
    expect(rv.status, rv.stderr).toBe(0);
    expect(rv.stdout).toContain("host api.github.com");
    expect(vaultLog(h.l).map((e) => [e.op, e.binding])).toEqual([["add", undefined], ["allow", "host api.github.com"], ["allow", "mcp github:create_*"], ["revoke", "host api.github.com"]]);
    expect((await h.run(["vault", "revoke", "github/token", "5"], { secrets: [PASS] })).status).toBe(64);
  });
  it("allow refuses bad destinations before asking for the passphrase", async () => {
    const h = await withSecret();
    for (const args of [["--host", "*"], ["--host", "*.com"], ["--host", "a.com", "--mcp", "x"], ["--mcp", "a:b:c:d"], ["--process", "*"], ["--process", "curl * -d"], ["--allow-in-url", "--mcp", "x"]]) {
      const r = await h.run(["vault", "allow", "github/token", ...args]);
      expect(r.status, args.join(" ")).toBe(64);
      expect(r.prompts).toEqual([]);
    }
    const none = await h.run(["vault", "allow", "nope", "--host", "a.example"], { secrets: [PASS] });
    expect(none.stderr).toMatch(/no such secret/);
    const trailing = await h.run(["vault", "allow", "github/token", "--process", "gh pr *"], { secrets: [PASS] });
    expect(trailing.status).toBe(0);
    expect(trailing.stdout).toMatch(/Warning: "gh pr \*" ends in \*/);
  });
  it("rotate replaces the value and its fingerprint, keeps the bindings", async () => {
    const h = await withSecret();
    await h.run(["vault", "allow", "github/token", "--host", "api.github.com"], { secrets: [PASS] });
    const r = await h.run(["vault", "rotate", "github/token"], { secrets: [PASS, OPAQUE] });
    expect(r.status, r.stderr).toBe(0);
    expect(h.store.values.get("github/token:value")?.value).toBe(OPAQUE);
    const st = loadIndex(h.l, approverPublicKey(h.l));
    const e = st.state === "ok" ? st.index.entries[0] : undefined;
    expect(e?.fingerprints.value).toBe(fingerprint(OPAQUE));
    expect(e?.bindings).toHaveLength(1);
    expect(e?.rotatedAt).toBeDefined();
    expect((await h.run(["vault", "rotate", "nope"], { secrets: [PASS] })).stderr).toMatch(/no such secret/);
  });
  it("remove needs a typed yes, deletes the values and the entry; a value the store cannot delete is reported", async () => {
    const h = await withSecret();
    const no = await h.run(["vault", "remove", "github/token"], { secrets: [PASS], answers: ["no"] });
    expect(no.status).toBe(1);
    expect(h.store.values.size).toBe(1);
    const yes = await h.run(["vault", "remove", "github/token"], { secrets: [PASS], answers: ["yes"] });
    expect(yes.status, yes.stderr).toBe(0);
    expect(h.store.values.size).toBe(0);
    const st = loadIndex(h.l, approverPublicKey(h.l));
    expect(st.state === "ok" ? st.index.entries : null).toEqual([]);
    const h2 = await withSecret();
    h2.store.failRemoves = true;
    const r = await h2.run(["vault", "remove", "github/token"], { secrets: [PASS], answers: ["yes"] });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/Could not delete a stored value/);
  });
  it("V9: an index edited on disk is reported by list and refused by every change", async () => {
    const h = await withSecret();
    const doc = JSON.parse(readFileSync(indexPath(h.l), "utf8")) as { entries: { bindings: unknown[] }[] };
    doc.entries[0]?.bindings.push({ kind: "host", host: "attacker.example" });
    const { writeFileSync } = await import("node:fs");
    writeFileSync(indexPath(h.l), JSON.stringify(doc));
    const list = await h.run(["vault", "list"]);
    expect(list.status).toBe(1);
    expect(list.stderr).toMatch(/not signed by your approval key/);
    const allow = await h.run(["vault", "allow", "github/token", "--host", "api.github.com"], { secrets: [PASS] });
    expect(allow.status).toBe(1);
    expect(allow.stderr).toMatch(/Nothing was changed/);
    expect((await h.run(["vault", "rotate", "github/token"], { secrets: [PASS, OPAQUE] })).status).toBe(1);
    expect(h.store.values.get("github/token:value")?.value).toBe(TOKEN);
  });
  it("an empty vault lists as empty; vault alone is list", async () => {
    const h = harness();
    const r = await h.run(["vault"]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/The vault is empty/);
  });
});

describe("approver rotate keeps the vault", () => {
  it("re-signs an index that verifies against the old key; refuses to launder one that does not", async () => {
    const h = harness();
    await h.run(["vault", "add", "github/token"], { secrets: [PASS, TOKEN] });
    const oldKey = approverPublicKey(h.l);
    rotateApprover(h.l, PASS, "a brand new passphrase");
    const fresh = unlockApprover(h.l, "a brand new passphrase");
    expect(loadIndex(h.l, publicKeyOf(fresh)).state).toBe("unsigned");
    const lines = await afterApproverRotate(h.l, oldKey, fresh, PASS, "a brand new passphrase");
    expect(lines.join(" ")).toMatch(/now signed with the new key \(1 secret/);
    expect(loadIndex(h.l, publicKeyOf(fresh)).state).toBe("ok");
    // A second rotation with a stale "old key" (the index is not signed by it) is not re-signed.
    const again = await afterApproverRotate(h.l, oldKey, fresh, PASS, "x");
    expect(again.join(" ")).toMatch(/was not re-signed/);
  });
});
