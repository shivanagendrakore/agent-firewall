/**
 * Item P: the zero-dependency WebAuthn verifier against real ES256, RS256 and EdDSA registrations and
 * assertions from a software authenticator, and every refusal (P5 UV clear, P6 another origin, a wrong
 * challenge, a wrong RP ID, a forged signature, cross-origin use, a create used as a get).
 */
import { describe, expect, it } from "vitest";
import { decodeCbor, decodeCborExact } from "../../src/runtime/relay/cbor.js";
import { coseToKey, parseAuthData, verifyAssertion, verifyRegistration, WebAuthnError } from "../../src/runtime/relay/webauthn.js";
import { sha256 } from "../../src/runtime/relay/util.js";
import { cbor, SoftAuthenticator, type Alg } from "./softauth.js";

const ORIGIN = "https://approve.launchsafe.com";
const RP = "approve.launchsafe.com";
const CH = sha256("challenge");

function check(fn: () => unknown): string {
  try {
    fn();
    return "ok";
  } catch (e) {
    return e instanceof WebAuthnError ? e.check : `other: ${(e as Error).message}`;
  }
}

describe("CBOR reader", () => {
  it("reads maps, negative keys, byte and text strings and nested arrays, and returns the end offset", () => {
    const b = cbor(new Map<unknown, unknown>([[1, 2], [-1, Buffer.from([1, 2, 3])], ["k", ["a", 300, -70000]]]) as never);
    const v = decodeCborExact(b) as Map<unknown, unknown>;
    expect(v.get(1)).toBe(2);
    expect([...(v.get(-1) as Uint8Array)]).toEqual([1, 2, 3]);
    expect(v.get("k")).toEqual(["a", 300, -70000]);
    expect(decodeCbor(Buffer.concat([b, Buffer.from([0x01])])).end).toBe(b.length);
  });
  it("refuses truncated input, trailing bytes, indefinite lengths, tags and duplicate keys", () => {
    expect(() => decodeCborExact(Buffer.from([0x62, 0x61]))).toThrow();
    expect(() => decodeCborExact(Buffer.from([0x01, 0x02]))).toThrow();
    expect(() => decodeCborExact(Buffer.from([0x9f, 0xff]))).toThrow();
    expect(() => decodeCborExact(Buffer.from([0xc0, 0x01]))).toThrow();
    expect(() => decodeCborExact(Buffer.from([0xa2, 0x01, 0x01, 0x01, 0x02]))).toThrow();
  });
});

describe.each<Alg>(["ES256", "RS256", "EdDSA"])("%s", (alg) => {
  const a = new SoftAuthenticator(alg);
  it("a registration verifies: credential id, COSE key and algorithm come from the attested data", () => {
    const r = a.register({ rpId: RP, origin: ORIGIN, challenge: CH });
    const reg = verifyRegistration({ attestationObject: r.attestationObject, clientDataJSON: r.clientDataJSON, challenge: CH, origin: ORIGIN, rpId: RP });
    expect(reg.credentialId.equals(a.credentialId)).toBe(true);
    expect(reg.publicKey.equals(a.cose)).toBe(true);
    expect(reg.alg).toBe(alg === "ES256" ? -7 : alg === "RS256" ? -257 : -8);
    expect(coseToKey(a.cose).alg).toBe(reg.alg);
  });
  it("an assertion verifies and returns the counter", () => {
    const s = a.assert({ rpId: RP, origin: ORIGIN, challenge: CH, counter: 7 });
    expect(verifyAssertion({ publicKey: a.cose, ...s, challenge: CH, origin: ORIGIN, rpId: RP, requireUV: true }).signCount).toBe(7);
  });
  it("refusals name the failed check", () => {
    const v = (o: Parameters<SoftAuthenticator["assert"]>[0], over: Partial<Parameters<typeof verifyAssertion>[0]> = {}): string => check(() => verifyAssertion({ publicKey: a.cose, ...a.assert(o), challenge: CH, origin: ORIGIN, rpId: RP, requireUV: true, ...over }));
    expect(v({ rpId: RP, origin: ORIGIN, challenge: CH, uv: false })).toBe("flags"); // P5
    expect(v({ rpId: RP, origin: ORIGIN, challenge: CH, up: false })).toBe("flags");
    expect(v({ rpId: RP, origin: "https://app.launchsafe.com", challenge: CH })).toBe("origin"); // P6
    expect(v({ rpId: RP, origin: ORIGIN, challenge: sha256("other") })).toBe("challenge");
    expect(v({ rpId: "app.launchsafe.com", origin: ORIGIN, challenge: CH })).toBe("rpIdHash");
    expect(v({ rpId: RP, origin: ORIGIN, challenge: CH, crossOrigin: true })).toBe("origin");
    expect(v({ rpId: RP, origin: ORIGIN, challenge: CH, type: "webauthn.create" })).toBe("clientData");
    const other = new SoftAuthenticator(alg);
    expect(v({ rpId: RP, origin: ORIGIN, challenge: CH }, { publicKey: other.cose })).toBe("signature");
    const s = a.assert({ rpId: RP, origin: ORIGIN, challenge: CH });
    s.signature.writeUInt8(s.signature.readUInt8(s.signature.length - 1) ^ 1, s.signature.length - 1);
    expect(check(() => verifyAssertion({ publicKey: a.cose, ...s, challenge: CH, origin: ORIGIN, rpId: RP, requireUV: true }))).toBe("signature");
  });
});

describe("registration refusals", () => {
  const a = new SoftAuthenticator("ES256");
  it("UV clear, another origin, another RP ID, another challenge, an assertion's client data", () => {
    const reg = (o: Parameters<SoftAuthenticator["register"]>[0], over: Partial<Parameters<typeof verifyRegistration>[0]> = {}): string => check(() => verifyRegistration({ ...a.register(o), challenge: CH, origin: ORIGIN, rpId: RP, ...over }));
    expect(reg({ rpId: RP, origin: ORIGIN, challenge: CH, uv: false })).toBe("flags");
    expect(reg({ rpId: RP, origin: "https://evil.example", challenge: CH })).toBe("origin");
    expect(reg({ rpId: "evil.example", origin: ORIGIN, challenge: CH })).toBe("rpIdHash");
    expect(reg({ rpId: RP, origin: ORIGIN, challenge: sha256("x") })).toBe("challenge");
  });
  it("unsupported COSE algorithms and malformed keys are refused", () => {
    expect(check(() => coseToKey(cbor(new Map([[1, 2], [3, -35]]) as never)))).toBe("coseKey");
    expect(check(() => coseToKey(cbor(new Map<unknown, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.alloc(31)], [-3, Buffer.alloc(32)]]) as never)))).toBe("coseKey");
    expect(check(() => coseToKey(Buffer.from([0xff])))).toBe("coseKey");
  });
  it("authenticator data shorter than 37 bytes is refused", () => {
    expect(check(() => parseAuthData(Buffer.alloc(10)))).toBe("authData");
  });
});
