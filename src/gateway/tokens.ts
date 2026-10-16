/**
 * The per-client bearer for the local HTTP gateway (client to
 * gateway): `lsgw_<32 random bytes,
 * base64url>`, kept in keys/gateway-clients.json (mode 600) and written into
 * the client's configuration as a header. The gateway accepts only its own
 * tokens and never forwards them.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { atomicWrite, ensureDir, readText, withLock } from "../runtime/fsutil.js";
import type { Layout } from "../runtime/layout.js";
import { own, setOwn } from "../own.js";

export function tokensPath(l: Layout): string {
  return join(l.keys, "gateway-clients.json");
}

function readTokens(l: Layout): Record<string, string> {
  const t = readText(tokensPath(l));
  if (t === null) return {};
  const v = JSON.parse(t) as unknown;
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error(`${tokensPath(l)} is not a token file`);
  return Object.fromEntries(Object.entries(v as Record<string, unknown>).filter((e): e is [string, string] => typeof e[1] === "string"));
}

/** The client's bearer, created on first use. */
export function clientToken(l: Layout, client: string): string {
  ensureDir(l.keys);
  return withLock(`${tokensPath(l)}.lock`, () => {
    const all = readTokens(l);
    const existing = own(all, client);
    if (existing !== undefined) return existing;
    const token = `lsgw_${randomBytes(32).toString("base64url")}`;
    setOwn(all, client, token);
    atomicWrite(tokensPath(l), `${JSON.stringify(all, null, 2)}\n`, 0o600);
    return token;
  });
}

/** Which client a bearer belongs to, or null (constant-time comparison per token). */
export function clientOfToken(l: Layout, token: string): string | null {
  let all: Record<string, string>;
  try {
    all = readTokens(l);
  } catch {
    return null;
  }
  const got = Buffer.from(token);
  for (const [client, t] of Object.entries(all)) {
    const want = Buffer.from(t);
    if (want.length === got.length && timingSafeEqual(want, got)) return client;
  }
  return null;
}

/** The local gateway address a wrapped HTTP entry points at. */
export function gatewayUrl(port: number, client: string, server: string): string {
  return `http://127.0.0.1:${port}/c/${encodeURIComponent(client)}/u/${encodeURIComponent(server)}`;
}
