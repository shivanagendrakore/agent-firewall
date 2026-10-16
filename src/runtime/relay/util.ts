/**
 * Small helpers the phone-approval modules share: base64url, SHA-256, the
 * canonical JSON every signed or hashed structure uses (the engine's, so a
 * displayHash computed here equals one computed by the phone's web app with
 * the same rule: keys sorted, no whitespace), and the session tag.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { canonicalJson } from "../../engine/decide.js";

export { canonicalJson };

export function b64u(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

/** Strict base64url: the alphabet only, no padding. Throws on anything else. */
export function unb64u(s: unknown, what = "value"): Buffer {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Error(`${what} is not base64url`);
  return Buffer.from(s, "base64url");
}

export function sha256(data: Uint8Array | string): Buffer {
  return createHash("sha256").update(data).digest();
}

export function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** sha256(session id), first 12 hex characters: lets the phone group items without revealing the session. */
export function sessionTag(sessionId: string): string {
  return sha256Hex(sessionId).slice(0, 12);
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Minutes to milliseconds. */
export function minutes(n: number): number {
  return n * 60_000;
}
