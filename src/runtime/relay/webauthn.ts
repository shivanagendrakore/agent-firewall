/**
 * A zero-dependency WebAuthn verifier for what the firewall checks itself:
 * a passkey registration at pairing (W3C WebAuthn Level 3 §7.1, the parts
 * that matter here) and an assertion on every phone decision (§7.2). The
 * relay never verifies anything: the firewall pins the credential's public
 * key and checks each signature locally, so neither the relay nor the agent
 * can make an approval.
 *
 * Supported algorithms: ES256 (-7), RS256 (-257) and EdDSA (-8, Ed25519),
 * through node:crypto. Each failed check names its step, so the daemon can
 * log why a decision was dropped.
 */

import { createPublicKey, verify, type KeyObject } from "node:crypto";
import { decodeCbor, decodeCborExact, type CborValue } from "./cbor.js";
import { b64u, equalBytes, sha256 } from "./util.js";

export const ALGS = { ES256: -7, RS256: -257, EdDSA: -8 } as const;
export type CoseAlg = (typeof ALGS)[keyof typeof ALGS];
const KNOWN_ALGS = new Set<number>([ALGS.ES256, ALGS.RS256, ALGS.EdDSA]);

export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;
export const FLAG_AT = 0x40;
export const FLAG_ED = 0x80;

export class WebAuthnError extends Error {
  constructor(
    /** Which check failed, for the log ("clientData", "rpIdHash", "flags", "signature", ...). */
    readonly check: string,
    message: string,
  ) {
    super(message);
  }
}

function fail(check: string, message: string): never {
  throw new WebAuthnError(check, message);
}

// --- COSE keys --------------------------------------------------------------------------------------

function get(m: Map<CborValue, CborValue>, k: number): CborValue {
  return m.get(k);
}

function bytes(v: CborValue, what: string): Uint8Array {
  if (!(v instanceof Uint8Array)) fail("coseKey", `the COSE key's ${what} is missing`);
  return v;
}

/** The algorithm and a node:crypto public key from a COSE_Key (RFC 9052/9053). */
export function coseToKey(cose: Uint8Array): { alg: CoseAlg; key: KeyObject } {
  let v: CborValue;
  try {
    v = decodeCborExact(cose);
  } catch (e) {
    fail("coseKey", `the COSE key is not valid CBOR (${(e as Error).message})`);
  }
  if (!(v instanceof Map)) fail("coseKey", "the COSE key is not a map");
  const kty = get(v, 1);
  const alg = get(v, 3);
  if (typeof alg !== "number" || !KNOWN_ALGS.has(alg)) fail("coseKey", `unsupported algorithm ${String(alg)} (ES256, RS256 and EdDSA are)`);
  try {
    if (alg === ALGS.ES256) {
      if (kty !== 2 || get(v, -1) !== 1) fail("coseKey", "an ES256 key must be EC2 on P-256");
      const x = bytes(get(v, -2), "x");
      const y = bytes(get(v, -3), "y");
      if (x.length !== 32 || y.length !== 32) fail("coseKey", "a P-256 coordinate must be 32 bytes");
      return { alg, key: createPublicKey({ key: { kty: "EC", crv: "P-256", x: b64u(x), y: b64u(y) }, format: "jwk" }) };
    }
    if (alg === ALGS.RS256) {
      if (kty !== 3) fail("coseKey", "an RS256 key must be RSA");
      const n = bytes(get(v, -1), "n");
      const e = bytes(get(v, -2), "e");
      if (n.length < 256) fail("coseKey", "an RSA key must have at least 2048 bits");
      return { alg, key: createPublicKey({ key: { kty: "RSA", n: b64u(n), e: b64u(e) }, format: "jwk" }) };
    }
    if (kty !== 1 || get(v, -1) !== 6) fail("coseKey", "an EdDSA key must be OKP on Ed25519");
    const x = bytes(get(v, -2), "x");
    if (x.length !== 32) fail("coseKey", "an Ed25519 key must be 32 bytes");
    return { alg: ALGS.EdDSA, key: createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: b64u(x) }, format: "jwk" }) };
  } catch (e) {
    if (e instanceof WebAuthnError) throw e;
    fail("coseKey", `the COSE key is not a usable public key (${(e as Error).message})`);
  }
}

// --- authenticator data -----------------------------------------------------------------------------

export interface AuthData {
  rpIdHash: Buffer;
  flags: number;
  signCount: number;
  attested?: { aaguid: Buffer; credentialId: Buffer; publicKey: Buffer };
}

export function parseAuthData(buf: Uint8Array): AuthData {
  const b = Buffer.from(buf);
  if (b.length < 37) fail("authData", "the authenticator data is too short");
  const out: AuthData = { rpIdHash: b.subarray(0, 32), flags: b[32] as number, signCount: b.readUInt32BE(33) };
  if ((out.flags & FLAG_AT) !== 0) {
    if (b.length < 55) fail("authData", "the attested credential data is too short");
    const aaguid = b.subarray(37, 53);
    const idLen = b.readUInt16BE(53);
    if (idLen === 0 || idLen > 1023 || b.length < 55 + idLen) fail("authData", "the credential id length is invalid");
    const credentialId = b.subarray(55, 55 + idLen);
    let end: number;
    try {
      end = decodeCbor(b, 55 + idLen).end;
    } catch (e) {
      fail("authData", `the credential public key is not valid CBOR (${(e as Error).message})`);
    }
    out.attested = { aaguid, credentialId, publicKey: b.subarray(55 + idLen, end) };
    if ((out.flags & FLAG_ED) === 0 && end !== b.length) fail("authData", "trailing bytes after the credential public key");
  }
  return out;
}

// --- client data ------------------------------------------------------------------------------------

interface ClientData {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin?: boolean;
  topOrigin?: string;
}

function parseClientData(raw: Uint8Array): ClientData {
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch {
    fail("clientData", "clientDataJSON is not JSON");
  }
  if (typeof v !== "object" || v === null) fail("clientData", "clientDataJSON is not an object");
  const o = v as Record<string, unknown>;
  if (typeof o.type !== "string" || typeof o.challenge !== "string" || typeof o.origin !== "string") fail("clientData", "clientDataJSON lacks type, challenge or origin");
  return o as unknown as ClientData;
}

function checkClientData(cd: ClientData, type: "webauthn.get" | "webauthn.create", challenge: Uint8Array, origin: string): void {
  if (cd.type !== type) fail("clientData", `clientDataJSON.type is ${JSON.stringify(cd.type)}, not ${type}`);
  if (cd.challenge !== b64u(challenge)) fail("challenge", "the signed challenge is not the digest of this decision");
  if (cd.origin !== origin) fail("origin", `the passkey was used on ${JSON.stringify(cd.origin)}, not the pinned origin ${origin}`);
  if (cd.crossOrigin !== undefined && cd.crossOrigin !== false) fail("origin", "the passkey was used cross-origin");
  if (cd.topOrigin !== undefined) fail("origin", "the passkey was used inside another site (topOrigin)");
}

function checkFlags(flags: number, requireUV: boolean): void {
  if ((flags & FLAG_UP) === 0) fail("flags", "user presence (UP) is not set");
  if (requireUV && (flags & FLAG_UV) === 0) fail("flags", "user verification (UV) is not set: the phone did not check a biometric or PIN");
}

// --- registration (pairing) -------------------------------------------------------------------------

export interface Registration {
  credentialId: Buffer;
  /** The COSE_Key bytes from the attested credential data. */
  publicKey: Buffer;
  alg: CoseAlg;
  signCount: number;
}

/**
 * Checks a passkey registration made for this pairing: clientDataJSON (type webauthn.create, the
 * pairing's challenge, the pinned origin), the attestation object's authenticator data (rpIdHash, UP
 * and UV, attested credential data with a supported algorithm). Attestation statements are not trusted
 * or needed: what binds the credential to this person is the pairing MAC, which the relay cannot forge.
 */
export function verifyRegistration(o: { attestationObject: Uint8Array; clientDataJSON: Uint8Array; challenge: Uint8Array; origin: string; rpId: string; requireUV?: boolean }): Registration {
  checkClientData(parseClientData(o.clientDataJSON), "webauthn.create", o.challenge, o.origin);
  let att: CborValue;
  try {
    att = decodeCborExact(o.attestationObject);
  } catch (e) {
    fail("attestation", `the attestation object is not valid CBOR (${(e as Error).message})`);
  }
  if (!(att instanceof Map) || typeof att.get("fmt") !== "string" || !(att.get("authData") instanceof Uint8Array)) fail("attestation", "the attestation object lacks fmt or authData");
  const ad = parseAuthData(att.get("authData") as Uint8Array);
  if (!equalBytes(ad.rpIdHash, sha256(o.rpId))) fail("rpIdHash", `the passkey belongs to another site than ${o.rpId}`);
  checkFlags(ad.flags, o.requireUV !== false);
  if (ad.attested === undefined) fail("authData", "the registration carries no credential");
  const { alg } = coseToKey(ad.attested.publicKey);
  return { credentialId: Buffer.from(ad.attested.credentialId), publicKey: Buffer.from(ad.attested.publicKey), alg, signCount: ad.signCount };
}

// --- assertion (each decision) ----------------------------------------------------------------------

export interface AssertionInput {
  /** The pinned credential's COSE public key. */
  publicKey: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  signature: Uint8Array;
  /** What the challenge must be (SHA-256 of the decision message). */
  challenge: Uint8Array;
  origin: string;
  rpId: string;
  requireUV: boolean;
}

/**
 * Checks 2 to 4 of docs/phone.md: clientDataJSON (type webauthn.get, the challenge, the pinned origin,
 * not cross-origin), authenticator data (rpIdHash, UP and UV), and the signature over
 * authenticatorData || SHA-256(clientDataJSON) with the pinned key. Returns the signature counter (check
 * 5 is the caller's: it knows the stored count). Throws WebAuthnError naming the failed step.
 */
export function verifyAssertion(a: AssertionInput): { signCount: number; flags: number } {
  checkClientData(parseClientData(a.clientDataJSON), "webauthn.get", a.challenge, a.origin);
  const ad = parseAuthData(a.authenticatorData);
  if (!equalBytes(ad.rpIdHash, sha256(a.rpId))) fail("rpIdHash", `the assertion is for another site than ${a.rpId}`);
  checkFlags(ad.flags, a.requireUV);
  const { alg, key } = coseToKey(a.publicKey);
  const data = Buffer.concat([Buffer.from(a.authenticatorData), sha256(a.clientDataJSON)]);
  let ok = false;
  try {
    // WebAuthn ES256 signatures are ASN.1 DER (§6.5.6); RS256 is PKCS #1 v1.5; EdDSA is raw.
    ok = alg === ALGS.ES256 ? verify("sha256", data, { key, dsaEncoding: "der" }, a.signature) : alg === ALGS.RS256 ? verify("sha256", data, key, a.signature) : verify(null, data, key, a.signature);
  } catch {
    ok = false;
  }
  if (!ok) fail("signature", "the passkey signature does not verify with the pinned key");
  return { signCount: ad.signCount, flags: ad.flags };
}
