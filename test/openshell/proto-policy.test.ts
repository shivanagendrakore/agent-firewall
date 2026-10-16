/**
 * The OpenShell pieces that need no server: the protobuf codec, the extension token checks, and the
 * OpenShell policy that mirrors the firewall's host lists (docs/sandboxes.md).
 */

import { describe, expect, it } from "vitest";
import { verifyExtensionToken, loadPublicKey, loadPublicKeys, JwtError } from "../../src/openshell/jwt.js";
import { openShellHost, openShellPolicy } from "../../src/openshell/policy.js";
import { decode, enums, jsonToStruct, msg, ProtoError, str, structToJson, uint, Writer } from "../../src/openshell/proto.js";
import { defaultConfig, PolicyError, validatePolicy } from "../../src/policy.js";
import type { FirewallConfig } from "../../src/types.js";
import { gatewayKeys } from "./supervisor.js";

describe("proto", () => {
  it("round-trips strings, varints, nested messages and Struct", () => {
    const b = new Writer().str(1, "héllo").uint(2, 300).msg(3, new Writer().str(1, "in")).msg(4, jsonToStruct({ a: 1.5, b: "x", c: true, d: false, e: null, f: [1, "two", { g: [] }] })).finish();
    const m = decode(b);
    expect(str(m, 1)).toBe("héllo");
    expect(uint(m, 2)).toBe(300);
    expect(str(decode(m.get(3)?.[0]?.bytes as Buffer), 1)).toBe("in");
    expect({ ...structToJson(decode(m.get(4)?.[0]?.bytes as Buffer)) }).toEqual({ a: 1.5, b: "x", c: true, d: false, e: null, f: [1, "two", { g: [] }] });
  });
  it("refuses truncated and malformed input", () => {
    expect(() => decode(Buffer.from([0x0a, 0x05, 0x61]))).toThrow(ProtoError);
    expect(() => decode(Buffer.from([0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]))).toThrow(ProtoError);
    expect(() => decode(Buffer.from([0x0b]))).toThrow(ProtoError);
  });
  it("a Struct key named __proto__ is a plain key", () => {
    const o = structToJson(decode(jsonToStruct(JSON.parse('{"__proto__": {"polluted": true}}') as Record<string, unknown>).finish()));
    expect(Object.getPrototypeOf(o)).toBeNull();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});

describe("extension tokens", () => {
  const k = gatewayKeys();
  const cfg = { publicKey: k.publicKey, gatewayId: "gw", audience: "aud-1" };
  const now = 1_800_000_000;
  const good = { iss: "openshell-gateway:gw", aud: "aud-1", exp: now + 60, caller_kind: "supervisor", sandbox_id: "s1" };
  it("accepts a supervisor's and the gateway's token", () => {
    expect(verifyExtensionToken(k.mint(good), cfg, now)).toEqual({ kind: "supervisor", sandboxId: "s1" });
    expect(verifyExtensionToken(k.mint({ ...good, caller_kind: "gateway", sandbox_id: undefined }), cfg, now)).toEqual({ kind: "gateway" });
    expect(verifyExtensionToken(k.mint({ ...good, aud: ["x", "aud-1"] }), cfg, now)).toMatchObject({ kind: "supervisor" });
  });
  it("refuses every way a token can be wrong", () => {
    const bad: [Record<string, unknown>, Record<string, unknown>?][] = [
      [{ ...good, exp: now - 31 }],
      [{ ...good, exp: undefined }],
      [{ ...good, nbf: now + 120 }],
      [{ ...good, iss: "https://gateway" }],
      [{ ...good, aud: "aud-2" }],
      [{ ...good, caller_kind: "user" }],
      [{ ...good, sandbox_id: "" }],
      [good, { typ: "JWT", alg: "EdDSA" }],
      [good, { typ: "openshell-ext+jwt", alg: "HS256" }],
      [good, { typ: "openshell-ext+jwt", alg: "EdDSA", crit: ["x"] }],
    ];
    for (const [c, h] of bad) expect(() => verifyExtensionToken(k.mint(c, h), cfg, now), JSON.stringify([c, h])).toThrow(JwtError);
    const t = k.mint(good);
    expect(() => verifyExtensionToken(`${t.slice(0, -4)}AAAA`, cfg, now)).toThrow(JwtError);
    expect(() => verifyExtensionToken("a.b", cfg, now)).toThrow(JwtError);
    expect(() => verifyExtensionToken(gatewayKeys().mint(good), cfg, now)).toThrow(JwtError);
  });
  it("loads only an Ed25519 public key", () => {
    expect(loadPublicKey(k.publicKey.export({ format: "pem", type: "spki" }).toString()).asymmetricKeyType).toBe("ed25519");
    expect(loadPublicKey(JSON.stringify(k.publicKey.export({ format: "jwk" }))).asymmetricKeyType).toBe("ed25519");
  });
});

describe("openshell policy", () => {
  const cfg = (o: Partial<FirewallConfig>): FirewallConfig => ({ ...defaultConfig(), ...o });

  it("wildcards: '*.x' becomes '**.x', and a two-label one is left out (OpenShell needs three labels)", () => {
    expect(openShellHost("docs.example.com")).toEqual({ host: "docs.example.com" });
    expect(openShellHost("*.example.com")).toEqual({ host: "**.example.com" });
    expect(openShellHost("*.com")).toHaveProperty("reason");
  });

  it("mirrors the host lists: send hosts full, fetch hosts read-only (code hosts full), deny list and IPs never listed; the middleware covers every listed host", () => {
    const r = openShellPolicy(cfg({ fetchAllowHosts: ["docs.example.com", "github.com", "10.0.0.1"], sendAllowHosts: ["=api.partner.example"], denyHosts: ["gist.github.com", "bad.example"] }), { agent: "claude" });
    expect(r.problems).toEqual([]);
    expect(r.hosts).toEqual(
      expect.arrayContaining([
        { host: "docs.example.com", access: "read-only", from: "fetchAllowHosts" },
        { host: "**.docs.example.com", access: "read-only", from: "fetchAllowHosts" },
        { host: "github.com", access: "full", from: "fetchAllowHosts" },
        { host: "**.github.com", access: "full", from: "fetchAllowHosts" },
        { host: "api.partner.example", access: "full", from: "sendAllowHosts" },
      ]),
    );
    expect(r.hosts.some((h) => h.host.includes("10.0.0.1") || h.host.includes("bad.example"))).toBe(false);
    expect(r.dropped.some((d) => d.pattern === "10.0.0.1")).toBe(true);
    expect(r.middlewareOnlyDenies).toEqual(["gist.github.com"]);
    expect(r.yaml).toContain('host: "api.anthropic.com"');
    expect(r.yaml).toContain("middleware: \"launchsafe-firewall\"");
    expect(r.yaml).toContain("on_error: fail_closed");
    expect(r.yaml).toMatch(/include: \[.*"\*\*\.github\.com".*\]/);
    // The model API is admitted but not judged by the middleware.
    expect(r.yaml).not.toMatch(/include: \[[^\]]*api\.anthropic\.com/);
    expect(r.yaml).toContain("# denyHosts inside an admitted wildcard, refused only by the middleware: \"gist.github.com\"");
  });

  it("splits more than 32 hosts over several middleware entries with unique orders, and refuses a --send-host the firewall would not admit", () => {
    const many = Array.from({ length: 40 }, (_, i) => `=h${i}.example.com`);
    const r = openShellPolicy(cfg({ fetchAllowHosts: many, sendAllowHosts: [] }));
    expect((r.yaml.match(/^ {2}launchsafe-firewall-\d+:$/gm) ?? []).length).toBe(2);
    expect(r.yaml).toContain("order: 10");
    expect(r.yaml).toContain("order: 20");
    expect(openShellPolicy(cfg({}), { sendHosts: ["169.254.169.254"] }).problems.length).toBe(1);
  });

  it("an empty policy is still valid YAML, and --no-middleware leaves the middleware out", () => {
    const r = openShellPolicy(cfg({ fetchAllowHosts: [], sendAllowHosts: [] }), { middleware: null });
    expect(r.yaml).toContain("network_policies: {}");
    expect(r.yaml).not.toContain("network_middlewares");
  });
});

describe("review fixes: wire types, token lifetime and keys, policy text", () => {
  it("a known field with the wrong wire type is an error, not a default; repeated enums packed or not", () => {
    const m = decode(new Writer().uint(1, 5).str(2, "x").finish());
    expect(() => str(m, 1)).toThrow(ProtoError);
    expect(() => uint(m, 2)).toThrow(ProtoError);
    expect(() => msg(m, 1)).toThrow(ProtoError);
    expect(enums(decode(new Writer().bytes(8, Buffer.from([1, 2, 3])).uint(8, 2).finish()), 8)).toEqual([1, 2, 3, 2]);
    expect(() => enums(decode(new Writer().bytes(8, Buffer.from([0x80])).finish()), 8)).toThrow(ProtoError);
  });

  const k = gatewayKeys();
  const now = 1_800_000_000;
  const good = { iss: "openshell-gateway:gw", aud: "aud-1", exp: now + 60, caller_kind: "supervisor", sandbox_id: "s1" };
  it("caps a token's lifetime (exp - iat, and exp - now) and refuses an iat in the future", () => {
    const cfg = { publicKey: k.publicKey, gatewayId: "gw", audience: "aud-1", maxLifetimeSeconds: 600 };
    expect(verifyExtensionToken(k.mint({ ...good, iat: now - 10 }), cfg, now)).toMatchObject({ kind: "supervisor" });
    for (const c of [{ ...good, iat: now - 10, exp: now + 900 }, { ...good, exp: now + 10_000 }, { ...good, iat: now + 300 }, { ...good, iat: "yesterday" }, { ...good, iat: now - 1000, exp: now + 10 }]) {
      expect(() => verifyExtensionToken(k.mint(c), cfg, now), JSON.stringify(c)).toThrow(JwtError);
    }
    expect(() => verifyExtensionToken(k.mint({ ...good, exp: now + 7200 }), { publicKey: k.publicKey, gatewayId: "gw", audience: "aud-1" }, now)).toThrow(JwtError);
  });

  it("accepts any of several gateway keys (a rotation), and loads them from PEM blocks or a JWK Set", () => {
    const old = gatewayKeys();
    const cfg = { publicKey: [old.publicKey, k.publicKey], gatewayId: "gw", audience: "aud-1" };
    expect(verifyExtensionToken(k.mint(good), cfg, now)).toMatchObject({ kind: "supervisor" });
    expect(verifyExtensionToken(old.mint(good), cfg, now)).toMatchObject({ kind: "supervisor" });
    expect(() => verifyExtensionToken(gatewayKeys().mint(good), cfg, now)).toThrow(JwtError);
    const pem = (x: typeof k): string => x.publicKey.export({ format: "pem", type: "spki" }).toString();
    expect(loadPublicKeys(`${pem(old)}\n${pem(k)}`).length).toBe(2);
    expect(loadPublicKeys(JSON.stringify({ keys: [old.publicKey.export({ format: "jwk" }), k.publicKey.export({ format: "jwk" })] })).length).toBe(2);
    expect(loadPublicKeys(pem(k)).length).toBe(1);
  });

  const cfg = (o: Partial<FirewallConfig>): FirewallConfig => ({ ...defaultConfig(), ...o });
  it("a control character in a host is refused: in the policy file, in --send-host, and in what reaches the generator", () => {
    expect(() => validatePolicy({ version: 3, denyHosts: ["evil.example\nnetwork_policies: {}"] }, "test")).toThrow(PolicyError);
    expect(() => validatePolicy({ version: 3, fetchAllowHosts: ["a.example\u2028b"] }, "test")).toThrow(PolicyError);
    const viaFlag = openShellPolicy(cfg({}), { sendHosts: ["x.example\n# injected"] });
    expect(viaFlag.problems[0]).toContain("control character");
    expect(viaFlag.yaml).toBe("");
    const viaConfig = openShellPolicy(cfg({ fetchAllowHosts: ["github.com"], denyHosts: ["gist.github.com\nversion: 2"] }));
    expect(viaConfig.problems[0]).toContain("denyHosts");
    expect(viaConfig.yaml).toBe("");
    expect(openShellPolicy(cfg({}), { middleware: "a\nb" }).problems.length).toBe(1);
    expect(openShellPolicy(cfg({}), { endpoint: "https://x\n[evil]" }).problems.length).toBe(1);
  });

  it("every value printed into a comment is JSON-quoted", () => {
    const r = openShellPolicy(cfg({ fetchAllowHosts: ["github.com", "10.0.0.1"], denyHosts: ["gist.github.com"] }), { agent: "codex" });
    expect(r.yaml).toContain('# left out: "10.0.0.1" (');
    expect(r.yaml).toContain('model API ("api.openai.com", "chatgpt.com", "auth.openai.com")');
    expect(r.yaml).toContain("Nothing judges or counts what is sent there");
    // eslint-disable-next-line no-control-regex -- control characters are what must not appear
    for (const line of r.yaml.split("\n")) expect(line).not.toMatch(/[\u0000-\u0008\u000b-\u001f]/);
  });

  it("--no-middleware with a deny that only the middleware enforces: a loud warning, in the result and in the YAML", () => {
    const r = openShellPolicy(cfg({ fetchAllowHosts: ["github.com"], denyHosts: ["gist.github.com"] }), { middleware: null });
    expect(r.problems).toEqual([]);
    expect(r.warnings.join(" ")).toContain('nothing refuses "gist.github.com"');
    expect(r.yaml).toContain('# WARNING: denyHosts inside an admitted wildcard, and NOT refused (no middleware): "gist.github.com"');
    expect(openShellPolicy(cfg({ fetchAllowHosts: ["github.com"], denyHosts: ["gist.github.com"] })).warnings).toEqual([]);
  });
});
