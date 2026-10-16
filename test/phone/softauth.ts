/**
 * Test only: a software WebAuthn authenticator that makes real registrations
 * and assertions with ES256 (P-256), RS256 (RSA 2048) and EdDSA (Ed25519)
 * keys, the way a phone's platform authenticator would, plus knobs for the
 * attacks the tests need (UV clear, another origin, a stale counter).
 */
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";

type Cbor = number | string | Uint8Array | Cbor[] | Map<Cbor, Cbor> | boolean | null;

function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}

/** A minimal CBOR encoder (what an authenticator emits). */
export function cbor(v: Cbor): Buffer {
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") {
    const b = Buffer.from(v, "utf8");
    return Buffer.concat([head(3, b.length), b]);
  }
  if (v instanceof Uint8Array) return Buffer.concat([head(2, v.length), Buffer.from(v)]);
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(cbor)]);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  if (v === true) return Buffer.from([0xf5]);
  if (v === false) return Buffer.from([0xf4]);
  return Buffer.from([0xf6]);
}

const sha256 = (b: Uint8Array | string): Buffer => createHash("sha256").update(b).digest();
const b64u = (b: Uint8Array): string => Buffer.from(b).toString("base64url");

export type Alg = "ES256" | "RS256" | "EdDSA";

export class SoftAuthenticator {
  readonly credentialId: Buffer;
  readonly privateKey: KeyObject;
  readonly cose: Buffer;
  counter: number;
  constructor(
    readonly alg: Alg = "ES256",
    /** A synced passkey reports 0 on every assertion. */
    readonly synced = false,
  ) {
    this.credentialId = Buffer.from(createHash("sha256").update(`${alg}${Math.random()}`).digest().subarray(0, 20));
    this.counter = synced ? 0 : 1;
    if (alg === "ES256") {
      const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const j = publicKey.export({ format: "jwk" });
      this.privateKey = privateKey;
      this.cose = cbor(new Map<Cbor, Cbor>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(j.x as string, "base64url")], [-3, Buffer.from(j.y as string, "base64url")]]));
    } else if (alg === "RS256") {
      const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const j = publicKey.export({ format: "jwk" });
      this.privateKey = privateKey;
      this.cose = cbor(new Map<Cbor, Cbor>([[1, 3], [3, -257], [-1, Buffer.from(j.n as string, "base64url")], [-2, Buffer.from(j.e as string, "base64url")]]));
    } else {
      const { privateKey, publicKey } = generateKeyPairSync("ed25519");
      const j = publicKey.export({ format: "jwk" });
      this.privateKey = privateKey;
      this.cose = cbor(new Map<Cbor, Cbor>([[1, 1], [3, -8], [-1, 6], [-2, Buffer.from(j.x as string, "base64url")]]));
    }
  }

  private authData(rpId: string, flags: number, attested: boolean, count: number): Buffer {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(count, 0);
    const base = Buffer.concat([sha256(rpId), Buffer.from([flags]), c]);
    if (!attested) return base;
    const len = Buffer.alloc(2);
    len.writeUInt16BE(this.credentialId.length, 0);
    return Buffer.concat([base, Buffer.alloc(16), len, this.credentialId, this.cose]);
  }

  private signData(data: Buffer): Buffer {
    if (this.alg === "ES256") return sign("sha256", data, { key: this.privateKey, dsaEncoding: "der" });
    if (this.alg === "RS256") return sign("sha256", data, this.privateKey);
    return sign(null, data, this.privateKey);
  }

  /** navigator.credentials.create: attestation "none". */
  register(o: { rpId: string; origin: string; challenge: Uint8Array; uv?: boolean }): { attestationObject: Buffer; clientDataJSON: Buffer } {
    const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: b64u(o.challenge), origin: o.origin, crossOrigin: false }), "utf8");
    const flags = 0x01 | (o.uv === false ? 0 : 0x04) | 0x40 | (this.synced ? 0x18 : 0);
    const attestationObject = cbor(new Map<Cbor, Cbor>([["fmt", "none"], ["attStmt", new Map()], ["authData", this.authData(o.rpId, flags, true, this.synced ? 0 : 0)]]));
    return { attestationObject, clientDataJSON };
  }

  /** navigator.credentials.get. */
  assert(o: { rpId: string; origin: string; challenge: Uint8Array; uv?: boolean; up?: boolean; counter?: number; crossOrigin?: boolean; type?: string }): { authenticatorData: Buffer; clientDataJSON: Buffer; signature: Buffer } {
    const count = o.counter ?? (this.synced ? 0 : ++this.counter);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: o.type ?? "webauthn.get", challenge: b64u(o.challenge), origin: o.origin, crossOrigin: o.crossOrigin ?? false }), "utf8");
    const flags = (o.up === false ? 0 : 0x01) | (o.uv === false ? 0 : 0x04) | (this.synced ? 0x18 : 0);
    const authenticatorData = this.authData(o.rpId, flags, false, count);
    const signature = this.signData(Buffer.concat([authenticatorData, sha256(clientDataJSON)]));
    return { authenticatorData, clientDataJSON, signature };
  }
}
