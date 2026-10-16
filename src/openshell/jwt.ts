/**
 * Verifies the short-lived token OpenShell's gateway sends with every call to a middleware service when the
 * gateway has JWT signing configured (docs.nvidia.com/openshell, "Authenticating Extensions"): typ
 * `openshell-ext+jwt`, alg EdDSA (pinned, never read from the token), a valid Ed25519 signature from one of
 * the gateway's public keys (configured by the operator, never discovered; several while a key rotates), an
 * unexpired `exp` no further away than the longest lifetime this service accepts (and `exp - iat` within it
 * when `iat` is present), the exact audience, `iss` = `openshell-gateway:<gateway id>`, and a `caller_kind`
 * of `gateway` or `supervisor` (a supervisor's token names its sandbox in `sandbox_id`). A repeated `jti` is
 * not refused: OpenShell reuses a token until it rotates.
 */

import { createPublicKey, verify, type JsonWebKey, type KeyObject } from "node:crypto";

export interface JwtConfig {
  /** The gateway's Ed25519 public key, or keys (any one may have signed: the old and new key during a rotation). */
  publicKey: KeyObject | readonly KeyObject[];
  gatewayId: string;
  audience: string;
  /** Clock skew allowed on exp, nbf and iat, in seconds (default 30). */
  leewaySeconds?: number;
  /** The longest token lifetime accepted, in seconds (default 3600): exp - iat, and exp - now. */
  maxLifetimeSeconds?: number;
}

export const DEFAULT_MAX_LIFETIME_SECONDS = 3600;
/** Keys one key file may hold. */
const MAX_KEYS = 8;

export interface Caller {
  kind: "gateway" | "supervisor";
  /** The sandbox a supervisor's token is bound to. */
  sandboxId?: string;
}

export class JwtError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JwtError";
  }
}

function ed25519(key: KeyObject): KeyObject {
  if (key.asymmetricKeyType !== "ed25519") throw new JwtError(`the gateway key must be an Ed25519 public key (got ${key.asymmetricKeyType ?? "unknown"})`);
  return key;
}

export function loadPublicKey(pemOrJwk: string): KeyObject {
  const t = pemOrJwk.trim();
  return ed25519(t.startsWith("{") ? createPublicKey({ key: JSON.parse(t) as JsonWebKey, format: "jwk" }) : createPublicKey(t));
}

/**
 * Every key in a key file: one PEM key, several PEM blocks one after another, one JWK, or a JWK Set
 * (`{"keys": [...]}`). Each must be an Ed25519 public key.
 */
export function loadPublicKeys(text: string): KeyObject[] {
  const t = text.trim();
  let keys: KeyObject[];
  if (t.startsWith("{")) {
    const j = JSON.parse(t) as { keys?: unknown };
    keys = Array.isArray(j.keys) ? j.keys.map((k) => ed25519(createPublicKey({ key: k as JsonWebKey, format: "jwk" }))) : [loadPublicKey(t)];
  } else {
    const blocks = t.match(/-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/g) ?? [];
    keys = blocks.length > 0 ? blocks.map((b) => loadPublicKey(b)) : [loadPublicKey(t)];
  }
  if (keys.length === 0) throw new JwtError("the key file holds no key");
  if (keys.length > MAX_KEYS) throw new JwtError(`the key file holds more than ${MAX_KEYS} keys`);
  return keys;
}

function b64json(part: string, what: string): Record<string, unknown> {
  if (!/^[A-Za-z0-9_-]*$/.test(part)) throw new JwtError(`the token's ${what} is not base64url`);
  try {
    const v = JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as unknown;
    if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error("not an object");
    return v as Record<string, unknown>;
  } catch {
    throw new JwtError(`the token's ${what} is not a JSON object`);
  }
}

/** The caller a bearer token names, or a JwtError saying why it is refused. */
export function verifyExtensionToken(token: string, cfg: JwtConfig, nowSeconds: number = Math.floor(Date.now() / 1000)): Caller {
  const parts = token.split(".");
  if (parts.length !== 3) throw new JwtError("the token is not a JWS compact serialization");
  const [h, p, s] = parts as [string, string, string];
  const header = b64json(h, "header");
  if (header.typ !== "openshell-ext+jwt") throw new JwtError('the token\'s typ is not "openshell-ext+jwt"');
  if (header.alg !== "EdDSA") throw new JwtError('the token\'s alg is not "EdDSA"');
  if (header.crit !== undefined) throw new JwtError("the token has critical header parameters this service does not understand");
  if (!/^[A-Za-z0-9_-]+$/.test(s)) throw new JwtError("the token's signature is not base64url");
  const signed = Buffer.from(`${h}.${p}`, "ascii");
  const sig = Buffer.from(s, "base64url");
  const keys: readonly KeyObject[] = Array.isArray(cfg.publicKey) ? (cfg.publicKey as readonly KeyObject[]) : [cfg.publicKey as KeyObject];
  if (!keys.some((k) => verify(null, signed, k, sig))) throw new JwtError("the token's signature does not verify with the gateway's key");
  const c = b64json(p, "claims");
  const leeway = cfg.leewaySeconds ?? 30;
  const maxLife = cfg.maxLifetimeSeconds ?? DEFAULT_MAX_LIFETIME_SECONDS;
  if (typeof c.exp !== "number" || !Number.isFinite(c.exp)) throw new JwtError("the token has no exp");
  if (nowSeconds > c.exp + leeway) throw new JwtError("the token has expired");
  if (c.exp - nowSeconds > maxLife + leeway) throw new JwtError(`the token is valid for longer than ${maxLife} seconds`);
  if (c.iat !== undefined) {
    if (typeof c.iat !== "number" || !Number.isFinite(c.iat)) throw new JwtError("the token's iat is not a number");
    if (c.iat > nowSeconds + leeway) throw new JwtError("the token was issued in the future");
    if (c.exp - c.iat > maxLife) throw new JwtError(`the token's lifetime (exp - iat) is longer than ${maxLife} seconds`);
  }
  if (c.nbf !== undefined && (typeof c.nbf !== "number" || nowSeconds + leeway < c.nbf)) throw new JwtError("the token is not valid yet");
  if (c.iss !== `openshell-gateway:${cfg.gatewayId}`) throw new JwtError("the token's issuer is not this gateway");
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!aud.includes(cfg.audience)) throw new JwtError("the token's audience is not this service");
  if (c.caller_kind === "gateway") return { kind: "gateway" };
  if (c.caller_kind === "supervisor") {
    if (typeof c.sandbox_id !== "string" || c.sandbox_id === "") throw new JwtError("a supervisor's token must name its sandbox");
    return { kind: "supervisor", sandboxId: c.sandbox_id };
  }
  throw new JwtError("the token's caller_kind is neither gateway nor supervisor");
}
