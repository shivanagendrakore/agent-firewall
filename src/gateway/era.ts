/**
 * Dual-era MCP (2026-07-28 basic/versioning). Modern requests carry their
 * protocol version, client capabilities and client info in `_meta`; legacy
 * clients and servers (2025-11-25 and earlier) open with `initialize`.
 *
 * Towards the upstream the gateway is a dual-era client: it probes with
 * `server/discover` and falls back to `initialize` on any error that is not a
 * recognised modern error, or on no answer (never on one specific code: the
 * stdio binding forbids that). Towards the client it accepts either. When the
 * two eras differ, the gateway answers the client's handshake itself and
 * rewrites `_meta` on the requests it forwards. Input requests (sampling,
 * elicitation, roots) are not translated between eras in v0.3.
 */

import { HEADER_MISMATCH, MISSING_CLIENT_CAPABILITY, UNSUPPORTED_PROTOCOL_VERSION, type Json } from "./jsonrpc.js";

export const MODERN_VERSION = "2026-07-28";
export const MODERN_VERSIONS: readonly string[] = [MODERN_VERSION];
/** Newest first. */
export const LEGACY_VERSIONS: readonly string[] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

export const META_VERSION = "io.modelcontextprotocol/protocolVersion";
export const META_CAPS = "io.modelcontextprotocol/clientCapabilities";
export const META_CLIENT = "io.modelcontextprotocol/clientInfo";
/** MCP RequestMetaSchema: the task a request belongs to, `{ taskId }` (LG5). */
export const META_RELATED_TASK = "io.modelcontextprotocol/related-task";
export const META_SERVER = "io.modelcontextprotocol/serverInfo";
const MODERN_META_PREFIX = "io.modelcontextprotocol/";

export type Era = "modern" | "legacy";

const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

export function metaOf(params: Json | undefined): Json {
  return isObj(params?._meta) ? params._meta : {};
}

/** The protocol version a modern request declares, or null. */
export function declaredVersion(params: Json | undefined): string | null {
  const v = metaOf(params)[META_VERSION];
  return typeof v === "string" ? v : null;
}

/** A modern error that identifies a modern server (it must not trigger the legacy fallback). */
export function isModernError(code: number): boolean {
  return code === HEADER_MISMATCH || code === MISSING_CLIENT_CAPABILITY || code === UNSUPPORTED_PROTOCOL_VERSION;
}

export interface ClientIdentity {
  capabilities: Json;
  info: Json;
}

/** Params with modern `_meta` added (a legacy client's request forwarded to a modern server). */
export function withModernMeta(params: Json | undefined, who: ClientIdentity): Json {
  const p = { ...(params ?? {}) };
  p._meta = { ...metaOf(params), [META_VERSION]: MODERN_VERSION, [META_CAPS]: who.capabilities, [META_CLIENT]: who.info };
  return p;
}

/** Params without the modern `_meta` keys (a modern client's request forwarded to a legacy server). */
export function withoutModernMeta(params: Json | undefined): Json | undefined {
  if (params === undefined) return undefined;
  const meta = metaOf(params);
  const rest = Object.fromEntries(Object.entries(meta).filter(([k]) => !k.startsWith(MODERN_META_PREFIX)));
  const p = { ...params };
  if (Object.keys(rest).length > 0) p._meta = rest;
  else delete p._meta;
  return p;
}

/** The version the gateway answers a legacy client's `initialize` with: the one asked for when known, else the newest it knows. */
export function legacyVersionFor(requested: unknown): string {
  return typeof requested === "string" && LEGACY_VERSIONS.includes(requested) ? requested : (LEGACY_VERSIONS[0] as string);
}

/** An InitializeResult for a legacy client, from a modern server's DiscoverResult. */
export function initializeFromDiscover(discover: Json, requested: unknown): Json {
  const info = metaOf(discover)[META_SERVER];
  return {
    protocolVersion: legacyVersionFor(requested),
    capabilities: isObj(discover.capabilities) ? discover.capabilities : {},
    serverInfo: isObj(info) ? info : { name: "unknown", version: "unknown" },
    ...(typeof discover.instructions === "string" ? { instructions: discover.instructions } : {}),
  };
}

/** A DiscoverResult for a modern client, from a legacy server's InitializeResult. */
export function discoverFromInitialize(init: Json): Json {
  return {
    resultType: "complete",
    supportedVersions: [MODERN_VERSION],
    capabilities: isObj(init.capabilities) ? init.capabilities : {},
    _meta: { [META_SERVER]: isObj(init.serverInfo) ? init.serverInfo : { name: "unknown", version: "unknown" } },
    ...(typeof init.instructions === "string" ? { instructions: init.instructions } : {}),
  };
}

/** The server's self-reported version, from a DiscoverResult or an InitializeResult. */
export function serverVersionOf(r: Json | undefined): string | undefined {
  if (r === undefined) return undefined;
  const info = isObj(r.serverInfo) ? r.serverInfo : metaOf(r)[META_SERVER];
  return isObj(info) && typeof info.version === "string" ? `${typeof info.name === "string" ? info.name : "?"}@${info.version}` : undefined;
}
