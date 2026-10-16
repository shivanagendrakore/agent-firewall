/**
 * Streamable HTTP request metadata (MCP 2026-07-28 basic/transports/
 * streamable-http, "Request Metadata"):
 *
 * - every POST carries `MCP-Protocol-Version` (equal to the body's
 *   `_meta["io.modelcontextprotocol/protocolVersion"]`), `Mcp-Method`
 *   (`method`) and, for tools/call, resources/read and prompts/get,
 *   `Mcp-Name` (`params.name` or `params.uri`);
 * - values that are not plain visible ASCII are sent as
 *   `=?base64?<base64 of UTF-8>?=`, and a server decodes before comparing;
 * - tool parameters marked `x-mcp-header` are mirrored as `Mcp-Param-{Name}`;
 * - a server that reads the body rejects any mismatch, or a missing required
 *   header, with 400 and JSON-RPC -32020 HeaderMismatch.
 *
 * The gateway validates the client's headers like a body-reading server, and
 * towards the upstream regenerates every one of them from the body it actually
 * sends, never copying the client's. Only an allowlist of client headers is
 * forwarded: Authorization, Cookie and hop-by-hop headers never are.
 */

import { declaredVersion, MODERN_VERSIONS } from "./era.js";
import type { Json, Request } from "./jsonrpc.js";
import { own } from "../own.js";

const NAMED = new Set(["tools/call", "resources/read", "prompts/get"]);
const SENTINEL = /^=\?base64\?([A-Za-z0-9+/=]*)\?=$/;
const SAFE = /^[\x21-\x7e](?:[\x20-\x7e\t]*[\x21-\x7e])?$/;
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/** A value as an HTTP header value (plain when safe, else the Base64 sentinel). */
export function encodeHeaderValue(v: string): string {
  if (SAFE.test(v) && !(v.startsWith("=?base64?") && v.endsWith("?="))) return v;
  return `=?base64?${Buffer.from(v, "utf8").toString("base64")}?=`;
}

/** A header value as text (sentinel decoded); null when it carries invalid characters. */
export function decodeHeaderValue(v: string): string | null {
  const m = SENTINEL.exec(v);
  if (m !== null) {
    try {
      return Buffer.from(m[1] ?? "", "base64").toString("utf8");
    } catch {
      return null;
    }
  }
  // eslint-disable-next-line no-control-regex -- header values must not carry control characters
  return /[\u0000-\u0008\u000a-\u001f\u007f]/.test(v) ? null : v;
}

/** The value of `Mcp-Name` for a request, or undefined when the method has none. */
function nameOf(r: Request): string | undefined {
  if (!NAMED.has(r.method)) return undefined;
  const p = r.params ?? {};
  const v = r.method === "resources/read" ? p.uri : p.name;
  return typeof v === "string" ? v : undefined;
}

type Headers = Record<string, string | string[] | undefined>;

function header(h: Headers, name: string): string | undefined {
  const v = own(h, name.toLowerCase());
  return Array.isArray(v) ? v.join(", ") : v;
}

/** How deep both x-mcp-header walks go; a schema nested deeper is invalid (fail closed), never half-read. */
const HEADER_WALK_DEPTH = 32;

/**
 * The x-mcp-header annotations of a schema: header name and property path. A schema past the depth cap
 * throws: the tool's schema is invalid (validMcpHeaderSchema says so first), so no caller guesses which
 * required headers the unread part would have named.
 */
export function headerParams(schema: unknown): { name: string; path: string[] }[] {
  const out: { name: string; path: string[] }[] = [];
  const walk = (s: unknown, path: string[], depth: number): void => {
    if (typeof s !== "object" || s === null) return;
    if (depth > HEADER_WALK_DEPTH) throw new RangeError(`an input schema nested deeper than ${HEADER_WALK_DEPTH} levels`);
    const props = (s as Json).properties;
    if (typeof props !== "object" || props === null) return;
    for (const [k, v] of Object.entries(props as Json)) {
      if (typeof v !== "object" || v === null) continue;
      const h = (v as Json)["x-mcp-header"];
      if (typeof h === "string") out.push({ name: h, path: [...path, k] });
      walk(v, [...path, k], depth + 1);
    }
  };
  walk(schema, [], 0);
  return out;
}

/**
 * Why a tool's x-mcp-header annotations are invalid (the client MUST then exclude the tool), or null.
 * Checks: a token name, case-insensitively unique, on a primitive (string, integer, boolean) property
 * reachable only through `properties`.
 */
export function validMcpHeaderSchema(schema: unknown): string | null {
  const seen = new Set<string>();
  let bad: string | null = null;
  const walk = (s: unknown, depth: number, reachable: boolean): void => {
    if (bad !== null || typeof s !== "object" || s === null) return;
    if (depth > HEADER_WALK_DEPTH) {
      bad = `a schema nested deeper than ${HEADER_WALK_DEPTH} levels, which cannot be checked for x-mcp-header`;
      return;
    }
    const o = s as Json;
    if ("x-mcp-header" in o) {
      const h = o["x-mcp-header"];
      if (!reachable) bad = "an x-mcp-header outside a chain of properties";
      else if (typeof h !== "string" || h === "" || !TOKEN.test(h)) bad = "an x-mcp-header that is not a header token";
      else if (seen.has(h.toLowerCase())) bad = `x-mcp-header ${h} is used twice`;
      else if (!["string", "integer", "boolean"].includes(String(o.type))) bad = `x-mcp-header ${h} is on a property that is not a string, integer or boolean`;
      if (typeof h === "string") seen.add(h.toLowerCase());
    }
    for (const [k, v] of Object.entries(o)) {
      if (k === "properties" && typeof v === "object" && v !== null) for (const p of Object.values(v as Json)) walk(p, depth + 1, reachable);
      else if (typeof v === "object" && v !== null) walk(v, depth + 1, false);
    }
  };
  walk(schema, 0, true);
  return bad;
}

function valueAt(args: unknown, path: string[]): string | undefined {
  let v: unknown = args;
  for (const k of path) {
    if (typeof v !== "object" || v === null) return undefined;
    v = own(v as Json, k);
  }
  if (typeof v === "string") return v;
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number" && Number.isInteger(v)) return String(v);
  return undefined;
}

/**
 * Checks a client's POST headers against its body (the server-validation rules). Returns why it
 * mismatches, or null. `schema`: the tool's input schema, for Mcp-Param headers.
 */
export function checkClientHeaders(h: Headers, r: Request, schema?: unknown): string | null {
  const version = header(h, "mcp-protocol-version");
  const body = declaredVersion(r.params);
  if (version === undefined) return "the MCP-Protocol-Version header is missing";
  if (!MODERN_VERSIONS.includes(version)) {
    // V34: a legacy header (2025-11-25 and earlier) puts no version in the body, so a body that declares one
    // disagrees with it; and any Mcp-Method or Mcp-Name header a legacy request carries must still match.
    if (body !== null) return `MCP-Protocol-Version ${version} does not match the body's ${body} version`;
    const m = header(h, "mcp-method");
    if (m !== undefined && m !== r.method) return `Mcp-Method ${m} does not match the body's method ${r.method}`;
    const n = header(h, "mcp-name");
    if (n !== undefined && NAMED.has(r.method)) {
      const decoded = decodeHeaderValue(n);
      if (decoded === null) return "the Mcp-Name header carries invalid characters";
      const want = nameOf(r);
      if (decoded !== want) return `Mcp-Name ${decoded.slice(0, 80)} does not match the body's ${String(want).slice(0, 80)}`;
    }
    return null;
  }
  if (body !== version) return `MCP-Protocol-Version ${version} does not match the body's ${body ?? "missing"} version`;
  const method = header(h, "mcp-method");
  if (method === undefined) return "the Mcp-Method header is missing";
  if (method !== r.method) return `Mcp-Method ${method} does not match the body's method ${r.method}`;
  const want = nameOf(r);
  if (NAMED.has(r.method)) {
    const got = header(h, "mcp-name");
    if (got === undefined) return "the Mcp-Name header is missing";
    const decoded = decodeHeaderValue(got);
    if (decoded === null) return "the Mcp-Name header carries invalid characters";
    if (decoded !== want) return `Mcp-Name ${decoded.slice(0, 80)} does not match the body's ${String(want).slice(0, 80)}`;
  }
  if (r.method === "tools/call" && schema !== undefined) {
    let params: { name: string; path: string[] }[];
    try {
      params = headerParams(schema);
    } catch (e) {
      return `the tool's schema cannot be read for x-mcp-header (${(e as Error).message})`;
    }
    for (const p of params) {
      const want2 = valueAt((r.params ?? {}).arguments, p.path);
      const got = header(h, `mcp-param-${p.name}`);
      if (want2 === undefined) continue;
      if (got === undefined) return `the Mcp-Param-${p.name} header is missing`;
      const decoded = decodeHeaderValue(got);
      if (decoded === null) return `the Mcp-Param-${p.name} header carries invalid characters`;
      if (decoded !== want2) return `Mcp-Param-${p.name} does not match the body`;
    }
  }
  return null;
}

/** The headers the gateway sends upstream for a body: regenerated from the body, never copied. */
export function upstreamHeaders(r: { method: string; params?: Json }, schema?: unknown): Record<string, string> {
  const out: Record<string, string> = { "content-type": "application/json", accept: "application/json, text/event-stream" };
  const version = declaredVersion(r.params);
  if (version !== null) {
    out["mcp-protocol-version"] = version;
    out["mcp-method"] = r.method;
    const name = nameOf(r as Request);
    if (name !== undefined) out["mcp-name"] = encodeHeaderValue(name);
    if (r.method === "tools/call" && schema !== undefined) {
      let params: { name: string; path: string[] }[] = [];
      try {
        params = headerParams(schema);
      } catch {
        // Too deep to read: no Mcp-Param header is guessed, and a server that requires one answers HeaderMismatch.
      }
      for (const p of params) {
        const v = valueAt((r.params ?? {}).arguments, p.path);
        if (v !== undefined) out[`mcp-param-${p.name.toLowerCase()}`] = encodeHeaderValue(v);
      }
    }
  }
  return out;
}

/** Client headers the gateway may pass on (none of them carries a credential). */
export const FORWARD_HEADERS: readonly string[] = ["user-agent", "accept-language"];
