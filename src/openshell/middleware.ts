/**
 * The firewall as an NVIDIA OpenShell supervisor middleware (docs/sandboxes.md). OpenShell's supervisor sits
 * outside the sandbox, checks each outbound request against its own network policy, and then, for hosts a
 * policy entry selects, asks a middleware service. This service answers by asking the firewall's local API
 * (`serve --api`, docs/api.md): "given what this session read, may this request go out?"
 *
 * - Requests (HTTP_REQUEST, before OpenShell injects credentials): one `POST /v1/decide` with the engine
 *   tool `HttpRequest` (url, method, body). The body the engine scans is the request body plus every
 *   request header that can carry data (Authorization, Cookie, Referer, custom API-key headers, any header
 *   not on the short list of standard ones, and a standard one with an unusually long value), so a request
 *   with such a header is judged as a send. A body the service cannot read (compressed, binary, not
 *   UTF-8) is held for a person, never passed as if it were empty. Loopback targets, and addresses that are
 *   not on the public internet (a private network, link-local, a special-purpose block), are denied. The
 *   session is the sandbox (`<agentId>/<sandbox_id>` in the API's namespacing) or the one the policy
 *   entry's config names. allow passes; ask, hold and deny block with a reason code OpenShell logs
 *   (`launchsafe_hold_fw_send`); a hold is a queue item a person approves with `queue approve`, after
 *   which the identical retry passes once.
 * - Responses (HTTP_RESPONSE, before the sandbox receives them): the body goes to the session as the
 *   request's result (`results`), so secrets and private data it carries count, and a value the firewall
 *   redacts is redacted in what the agent receives. When the firewall redacted something and the service
 *   cannot rewrite the body (several units, not UTF-8, too large), the stream fails, so OpenShell's
 *   `on_error: fail_closed` withholds the response: never the unredacted body. A response the service
 *   does not read (compressed, binary, partial, too large) is recorded as unread outside content.
 * - WebSocket text messages the sandbox sends: each is judged like a request body.
 *
 * Every failure (the API unreachable, a bad token, a malformed message) is a gRPC error, which OpenShell
 * treats as a middleware failure: with `on_error: fail_closed` (what the generated policy sets) the
 * traffic is blocked.
 */

import { isUtf8 } from "node:buffer";
import { createHash } from "node:crypto";
import { requestJson, type Target } from "../sdk/remote-http.js";
import { SESSION_ID, middlewareDecideContext } from "../api/request.js";
import { NETWORK_REFUSED_TOOL, UNPARSEABLE_TOOL } from "../engine/classify.js";
import { classifyAnswer } from "../engine/netgate.js";
import { canonicalIpv4, isMetadataEndpoint } from "../engine/network.js";
import { credentialAssignments, redactSecrets } from "../engine/secrets.js";
import { own } from "../own.js";
import { VERSION } from "../version.js";
import { GrpcError, Status, type CallContext, type StreamHandler, type UnaryHandler } from "./grpc.js";
import { verifyExtensionToken, JwtError, type Caller, type JwtConfig } from "./jwt.js";
import { bytes, decode, enums, has, msg, msgs, str, structToJson, uint, Writer, type Fields, ProtoError } from "./proto.js";

export const SERVICE = "openshell.middleware.v1.SupervisorMiddleware";
export const RESPONSE_SERVICE = "openshell.middleware.v1.HttpResponsePreReturn";
export const CONTRACT_CAPABILITY = "openshell.supervisor-middleware.contract";
export const IMPLEMENTATION_NAME = "launchsafe/agent-firewall";

export const OP_HTTP_REQUEST = 1;
export const OP_WEBSOCKET_MESSAGE = 2;
export const OP_HTTP_RESPONSE = 3;
export const PHASE_PRE_CREDENTIALS = 1;
export const PHASE_PRE_RETURN = 2;
export const DECISION_ALLOW = 1;
export const DECISION_DENY = 2;
export const BODY_HEADERS_ONLY = 1;
export const BODY_WHOLE = 2;
export const WS_INSPECT = 1;

/** Largest body or message this service inspects (advertised in Describe; OpenShell fails a larger one). */
export const DEFAULT_MAX_PAYLOAD = 512 * 1024;
/** Headers on one request or response: more, or more bytes, is a malformed message. */
const MAX_HEADERS = 256;
const MAX_HEADER_BYTES = 64 * 1024;
/** Body units in one response: more is refused (OpenShell sends a whole body in a few). */
const MAX_UNITS = 4096;

/** What the service needs from the local API. */
export interface DecisionClient {
  decide(body: Record<string, unknown>): Promise<{ decisionId: string; verdict: string; rules: { id: string }[]; approval?: { id: string } }>;
  result(session: string, decisionId: string, output: string): Promise<{ output?: string }>;
  input(session: string, source: string, content: string): Promise<void>;
}

/** The local API over its unix socket (or 127.0.0.1), with the token `api token add` printed. */
export function apiClient(o: { target: Target; token: string; timeoutMs?: number }): DecisionClient {
  const t = o.timeoutMs ?? 400;
  const call = (method: "POST", path: string, body: unknown): Promise<unknown> => requestJson(o.target, { method, path, token: o.token, body, timeoutMs: t, maxResponseBytes: 2 * 1024 * 1024 });
  return {
    decide: async (body) => {
      const r = (await call("POST", "/v1/decide", body)) as Record<string, unknown>;
      if (typeof r.decisionId !== "string" || typeof r.verdict !== "string" || !Array.isArray(r.rules)) throw new Error("the API's decision has an unexpected shape");
      const approval = r.approval as { id?: unknown } | undefined;
      return { decisionId: r.decisionId, verdict: r.verdict, rules: (r.rules as { id?: unknown }[]).map((x) => ({ id: String(x.id ?? "") })), ...(typeof approval?.id === "string" ? { approval: { id: approval.id } } : {}) };
    },
    result: async (session, decisionId, output) => {
      const r = (await call("POST", `/v1/sessions/${encodeURIComponent(session)}/results`, { decisionId, output })) as { output?: unknown };
      return typeof r.output === "string" ? { output: r.output } : {};
    },
    input: async (session, source, content) => {
      await call("POST", `/v1/sessions/${encodeURIComponent(session)}/inputs`, { source, content });
    },
  };
}

/**
 * A session or sandbox id this service accepts: the API's syntax, and no path segment that is empty, "."
 * or ".." (the id goes into the API's URL path, where encodeURIComponent leaves dots alone).
 */
export function validSessionId(s: string): boolean {
  return SESSION_ID.test(s) && s.split("/").every((seg) => seg !== "" && seg !== "." && seg !== "..");
}

/** A policy entry's `config` for this middleware. */
export interface EntryConfig {
  /** A fixed session for every sandbox the entry applies to (default: one session per sandbox id). */
  session?: string;
  /** false (default): nobody watches the network, so an "ask" is a hold in the queue. */
  attended: boolean;
  /** Record response bodies (default true). */
  inspectResponses: boolean;
}

const CONFIG_KEYS = ["session", "attended", "inspectResponses"];

/** The entry's config, or why it is refused (ValidateConfig answers with this). */
export function parseEntryConfig(raw: Record<string, unknown>): EntryConfig | string {
  for (const k of Object.keys(raw)) if (!CONFIG_KEYS.includes(k)) return `unknown config key "${k.slice(0, 60)}" (expected ${CONFIG_KEYS.join(", ")})`;
  if (raw.session !== undefined && (typeof raw.session !== "string" || !validSessionId(raw.session))) return "session must be 1 to 200 letters, digits, '.', '_', '-', ':' or '/', with no empty, '.' or '..' part between slashes";
  if (raw.attended !== undefined && typeof raw.attended !== "boolean") return "attended must be true or false";
  if (raw.inspectResponses !== undefined && typeof raw.inspectResponses !== "boolean") return "inspectResponses must be true or false";
  return { ...(typeof raw.session === "string" ? { session: raw.session } : {}), attended: raw.attended === true, inspectResponses: raw.inspectResponses !== false };
}

function configOf(m: Fields | null): EntryConfig {
  const c = parseEntryConfig(m === null ? {} : structToJson(m));
  if (typeof c === "string") throw new GrpcError(Status.INVALID_ARGUMENT, `the middleware config is invalid: ${c}`);
  return c;
}

interface Target4 {
  scheme: string;
  host: string;
  port: number;
  method: string;
  path: string;
  query: string;
}

/** An HTTP method token (RFC 9110), at most 32 characters. */
const METHOD = /^[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]{0,31}$/;

/** The target, with a scheme and host always, and a method when the operation has one (never a silent GET). */
function targetOf(m: Fields | null, needMethod: boolean): Target4 {
  if (m === null) throw new GrpcError(Status.INVALID_ARGUMENT, "the request has no target");
  const t = { scheme: str(m, 1).toLowerCase(), host: str(m, 2).toLowerCase(), port: uint(m, 3), method: str(m, 4).toUpperCase(), path: str(m, 5), query: str(m, 6) };
  if (t.scheme === "") throw new GrpcError(Status.INVALID_ARGUMENT, "the target has no scheme");
  if (t.host === "") throw new GrpcError(Status.INVALID_ARGUMENT, "the target has no host");
  if (t.port > 65535) throw new GrpcError(Status.INVALID_ARGUMENT, "the target port is out of range");
  if (needMethod && t.method === "") throw new GrpcError(Status.INVALID_ARGUMENT, "the target has no method");
  if (t.method !== "" && !METHOD.test(t.method)) throw new GrpcError(Status.INVALID_ARGUMENT, "the target method is not an HTTP method");
  return t;
}

/** The URL the engine judges: ws and wss as http and https (the engine reads web addresses). */
export function targetUrl(t: Target4): string {
  const scheme = t.scheme === "wss" ? "https" : t.scheme === "ws" ? "http" : t.scheme;
  if (scheme !== "https" && scheme !== "http") throw new GrpcError(Status.INVALID_ARGUMENT, `unsupported scheme ${t.scheme.slice(0, 20)}`);
  if (!/^[a-z0-9.\-_:[\]]{1,253}$/.test(t.host)) throw new GrpcError(Status.INVALID_ARGUMENT, "the target host is not a host name");
  const host = t.host.includes(":") && !t.host.startsWith("[") ? `[${t.host}]` : t.host;
  const port = t.port === 0 || (scheme === "https" && t.port === 443) || (scheme === "http" && t.port === 80) ? "" : `:${t.port}`;
  const path = t.path.startsWith("/") ? t.path : `/${t.path}`;
  return `${scheme}://${host}${port}${path}${t.query !== "" ? `?${t.query}` : ""}`;
}

/**
 * A loopback target (or an address written as one integer, which resolvers may read as one): denied here.
 * The supervisor's own machine is not a destination an agent in a sandbox should reach through it.
 */
export function isLoopbackTarget(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  // The other names /etc/hosts gives this machine or the broadcast address.
  if (h === "localhost.localdomain" || h === "ip6-localhost" || h === "ip6-loopback" || h === "broadcasthost") return true;
  if (/^(?:0x[0-9a-f]+|\d+)$/.test(h)) return true;
  // Every spelling inet_aton accepts: 127.1, 127.0.1, 0x7f.0.0.1, 0177.0.0.1.
  const v4 = canonicalIpv4(h);
  if (v4 !== null) return loopbackV4(v4.split(".").map(Number));
  const w = ipv6Words(h);
  if (w === null) return false;
  if (w.slice(0, 7).every((x) => x === 0) && ((w[7] as number) === 0 || (w[7] as number) === 1)) return true;
  // An IPv4 address inside IPv6: mapped (::ffff:a.b.c.d), compatible (::a.b.c.d), translated (::ffff:0:a.b.c.d) or
  // NAT64 (64:ff9b::a.b.c.d). nonPublicAddress leaves loopback to this check: a form missing here would be judged.
  const embedded =
    (w.slice(0, 5).every((x) => x === 0) && ((w[5] as number) === 0xffff || (w[5] as number) === 0)) ||
    (w.slice(0, 4).every((x) => x === 0) && (w[4] as number) === 0xffff && (w[5] as number) === 0) ||
    ((w[0] as number) === 0x64 && (w[1] as number) === 0xff9b && w.slice(2, 6).every((x) => x === 0));
  return embedded && loopbackV4([(w[6] as number) >> 8, (w[6] as number) & 255, (w[7] as number) >> 8, (w[7] as number) & 255]);
}

/** 127.0.0.0/8 and 0.0.0.0/8. */
function loopbackV4(b: readonly number[]): boolean {
  return b[0] === 127 || b[0] === 0;
}

/**
 * Why an address target is not on the public internet, or null: a private network (10/8, 172.16/12, 192.168/16,
 * 100.64/10, fc00::/7, fec0::/10) or a block no public host lives in (link-local, multicast and reserved, the
 * documentation, benchmarking and IETF protocol-assignment blocks), in every spelling isLoopbackTarget reads (short,
 * hex and octal IPv4, IPv4 inside IPv6). The classes are the ones `run`'s DNS check refuses (classifyAnswer,
 * src/engine/netgate.ts). The middleware sees the name OpenShell resolves and never the address, so this refuses an
 * address a sandbox policy names, not a name that resolves to one. Null for a name and a public address, and for the
 * two the middleware answers another way: loopback (isLoopbackTarget, its own code, checked first) and a cloud
 * metadata address, which goes to the engine so the log says FW-METADATA, the rule that says what it is.
 */
function nonPublicAddress(host: string): string | null {
  const h = host.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (isMetadataEndpoint(h)) return null;
  const v4 = canonicalIpv4(h);
  const w = v4 === null ? ipv6Words(h) : null;
  const ip = v4 ?? (w === null ? null : w.map((x) => x.toString(16)).join(":"));
  if (ip === null) return null;
  const c = classifyAnswer(ip);
  return c.kind === "never" || c.kind === "private" ? c.why : null;
}

/** The eight 16-bit words of an IPv6 literal (with "::" and a dotted IPv4 tail), or null when it is not one. */
export function ipv6Words(h: string): number[] | null {
  if (!h.includes(":") || !/^[0-9a-f:.]{2,45}$/.test(h)) return null;
  let s = h;
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = canonicalIpv4(tail);
    if (v4 === null || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(tail)) return null;
    const b = v4.split(".").map(Number) as [number, number, number, number];
    s = `${s.slice(0, lastColon + 1)}${((b[0] << 8) | b[1]).toString(16)}:${((b[2] << 8) | b[3]).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const words = (x: string): number[] | null => {
    if (x === "") return [];
    const out: number[] = [];
    for (const p of x.split(":")) {
      if (!/^[0-9a-f]{1,4}$/.test(p)) return null;
      out.push(parseInt(p, 16));
    }
    return out;
  };
  const head = words(halves[0] as string);
  const rest = halves.length === 2 ? words(halves[1] as string) : [];
  if (head === null || rest === null) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  if (head.length + rest.length > 7) return null;
  return [...head, ...Array<number>(8 - head.length - rest.length).fill(0), ...rest];
}

/** A body as text the engine can scan: UTF-8 (invalid bytes replaced), control characters as spaces. */
export function bodyText(b: Buffer): string {
  // eslint-disable-next-line no-control-regex -- control characters are what is replaced
  return b.toString("utf8").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ");
}

export interface Header {
  name: string;
  value: string;
}

function headersOf(list: Fields[]): Header[] {
  if (list.length > MAX_HEADERS) throw new GrpcError(Status.INVALID_ARGUMENT, `more than ${MAX_HEADERS} headers`);
  let total = 0;
  return list.map((h) => {
    const name = str(h, 1).toLowerCase();
    const value = str(h, 2);
    total += name.length + value.length;
    if (total > MAX_HEADER_BYTES) throw new GrpcError(Status.INVALID_ARGUMENT, `headers over ${MAX_HEADER_BYTES} bytes`);
    return { name, value };
  });
}

function header(hs: readonly Header[], name: string): string | undefined {
  return hs.find((h) => h.name === name)?.value;
}

/**
 * Media types left out of the scan: a closed list of registered types, the wildcards, and an
 * alphabetic type and subtype (at most 24 letters, dots and dashes) with a registered structured-syntax
 * suffix (application/vnd.api+json). Anything else (a subtype with digits, a long one) is scanned, so a
 * key cannot ride in an access key id used as a media subtype.
 */
const MEDIA_TYPES = [
  "application/json", "application/xml", "application/x-www-form-urlencoded", "application/octet-stream", "application/javascript", "application/ecmascript",
  "application/graphql", "application/grpc", "application/grpc-web", "application/protobuf", "application/x-protobuf", "application/x-ndjson", "application/ndjson",
  "application/jsonl", "application/yaml", "application/x-yaml", "application/toml", "application/sql", "application/pdf", "application/zip", "application/gzip",
  "application/x-gzip", "application/x-tar", "application/zstd", "application/wasm", "application/msgpack", "application/x-msgpack", "application/cbor",
  "application/xhtml\\+xml", "application/rss\\+xml", "application/atom\\+xml", "application/problem\\+json", "application/ld\\+json", "application/geo\\+json",
  "application/manifest\\+json", "application/vnd\\.api\\+json", "application/x-sh", "application/x-git-upload-pack-request", "application/x-git-receive-pack-request",
  "text/plain", "text/html", "text/css", "text/csv", "text/xml", "text/javascript", "text/markdown", "text/x-markdown", "text/event-stream", "text/yaml",
  "multipart/form-data", "multipart/mixed", "multipart/alternative", "multipart/related", "message/http",
  "image/png", "image/jpeg", "image/gif", "image/webp", "image/avif", "image/apng", "image/svg\\+xml", "image/x-icon", "image/vnd\\.microsoft\\.icon", "image/bmp", "image/tiff",
  "audio/mpeg", "audio/ogg", "audio/wav", "audio/webm", "video/mp4", "video/webm", "video/ogg", "font/woff", "font/woff2", "font/ttf", "font/otf",
];
const MEDIA_SUFFIXED = String.raw`(?:application|text|image)\/[a-z](?:[a-z.-]{0,22}[a-z])?\+(?:json|xml|yaml|cbor|zip|gzip|zstd|json-seq|jwt|sqlite3|wbxml|ber|der|fastinfoset)`;
const MEDIA_WILDCARD = String.raw`\*\/\*|(?:application|text|image|audio|video|font|multipart|message|model)\/\*`;
/** A media type alone (matched without regard to case, as media types are). */
const MIME = `(?:${MEDIA_TYPES.join("|")}|${MEDIA_WILDCARD}|${MEDIA_SUFFIXED})`;
/** Character sets a client actually sends: Unicode, ASCII, the ISO 8859 parts and the Windows code pages. */
const CHARSET_NAME = String.raw`(?:utf-?8|utf-16(?:le|be)?|us-ascii|ascii|iso-8859-(?:1[0-5]|[1-9])|windows-125[0-8])`;
const CHARSET = String.raw`(?:\s*;\s*charset=(?:${CHARSET_NAME}|"${CHARSET_NAME}"))?`;
const QV = String.raw`(?:\s*;\s*q=(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?))?`;
/**
 * A language tag: a 2 or 3 letter language, then at most a region (2 letters, or the one numeric region clients send,
 * 419 for Latin America) or a script (4 letters). Any other numeric region is scanned: three free digits per tag
 * would be a channel.
 */
const LANGUAGE = String.raw`(?:[a-z]{2,3}(?:-(?:[A-Za-z]{2}|419|[A-Za-z]{4}))?|\*)`;
/** A comma-separated list of `item`. */
const list = (item: string): RegExp => new RegExp(`^\\s*(?:${item})(?:\\s*,\\s*(?:${item}))*\\s*$`, "i");
/** Items a negotiation list may have and still be left out of the scan (browsers send at most a handful). */
const MAX_LIST_ITEMS = 10;
/** A comma-separated list of `item`, of at most MAX_LIST_ITEMS items: a longer list is scanned. */
const shortList = (item: string): { test(v: string): boolean } => {
  const re = list(item);
  return { test: (v: string): boolean => v.split(",").length <= MAX_LIST_ITEMS && re.test(v) };
};
const HTTP_DATE = /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/;

/**
 * A User-Agent of product tokens and comments, at most 256 characters ("curl/8.4.0", "python-requests/2.31.0",
 * "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"). A product is a name of letters
 * (with "-", "." or "_" between words) and a version of digits and dots (at most 4 parts, 12 digits in all). A
 * comment holds plain words of letters, short version numbers (at most 3 parts of at most 2 digits, "10_15_7") and a fixed
 * set of platform names (X11, x86_64, Win64, rv:128.0). A word that mixes letters and digits (a key, a token, encoded
 * data) does not match, and the whole value is then scanned.
 */
const UA_VERSION = String.raw`\d{1,8}(?:\.\d{1,8}){0,3}`;
const UA_PRODUCT = String.raw`[A-Za-z]{1,24}(?:[-._][A-Za-z]{1,24}){0,3}(?:\/${UA_VERSION})?`;
const UA_WORD = String.raw`(?:[A-Za-z]{1,24}|\d{1,2}(?:[._]\d{1,2}){0,2}|x86_64|x64|x86|X11|Win64|Win32|WOW64|arm64|aarch64|amd64|i686|armv[78]l?|rv:\d{1,3}(?:\.\d{1,2})?|[A-Za-z]{1,24}\/${UA_VERSION})`;
const UA_COMMENT = String.raw`\(${UA_WORD}(?:[;,]?\s{1,2}${UA_WORD}){0,15}\)`;
const USER_AGENT_SHAPE = new RegExp(`^${UA_PRODUCT}(?:\\s{1,2}(?:${UA_PRODUCT}|${UA_COMMENT})){0,15}$`);
/** Digits in one User-Agent value, in all: a browser's has about 30 ("Chrome/120.0.6099.109" alone has 11). */
const UA_MAX_DIGITS = 40;
// A version holds at most 12 digits in all, so a card number (13 digits or more) does not fit in one; and the whole
// value at most UA_MAX_DIGITS, so digits split over many products ("x/4111 y/1111 z/1111 ...") are bounded too.
const USER_AGENT = { test: (v: string): boolean => v.length <= 256 && USER_AGENT_SHAPE.test(v) && [...v.matchAll(/\/([\d.]+)/g)].every((m) => (m[1] as string).replace(/\./g, "").length <= 12) && (v.match(/\d/g) ?? []).length <= UA_MAX_DIGITS };

/**
 * Header values with a bounded shape: such a value is not part of what the engine scans (so a plain GET stays a
 * fetch). Every other value is scanned: every other header (Authorization, Cookie, Referer, Origin, X-Api-Key,
 * anything custom), and a header listed here whose value does not fit its shape (a key in the User-Agent, data in
 * Accept-Language, a token in a MIME subtype or a charset). Host is checked against the target (hostMismatch).
 * Bounded, not closed: residual channels remain and are documented (docs/sandboxes.md, "Headers not scanned"):
 * words of letters in a User-Agent (and at most UA_MAX_DIGITS digits), up to MAX_LIST_ITEMS short language tags,
 * a suffixed subtype's letters, and Sec-WebSocket-Key, which by the protocol is 16 random bytes (24 base64
 * characters ending "==") and so carries 16 bytes of the client's choosing.
 */
const SHAPES: Readonly<Record<string, { test(v: string): boolean }>> = {
  "content-length": /^\d{1,15}$/,
  "content-type": new RegExp(`^\\s*${MIME}${CHARSET}\\s*$`, "i"),
  accept: list(`${MIME}${CHARSET}${QV}`),
  "accept-encoding": list(`(?:gzip|x-gzip|deflate|br|zstd|compress|identity|\\*)${QV}`),
  "content-encoding": list("gzip|x-gzip|deflate|br|zstd|compress|identity"),
  "accept-language": shortList(`${LANGUAGE}${QV}`),
  "accept-charset": shortList(`(?:${CHARSET_NAME}|\\*)${QV}`),
  connection: list("keep-alive|close|upgrade|te"),
  "keep-alive": list(String.raw`(?:timeout|max)=\d{1,6}`),
  te: list(`(?:trailers|gzip|deflate|chunked|compress)${QV}`),
  "transfer-encoding": list("chunked|gzip|deflate|compress|identity"),
  upgrade: list(String.raw`websocket|h2c`),
  "cache-control": list(String.raw`no-cache|no-store|no-transform|only-if-cached|max-age=\d{1,10}|max-stale(?:=\d{1,10})?|min-fresh=\d{1,10}`),
  pragma: /^\s*no-cache\s*$/i,
  expect: /^\s*100-continue\s*$/i,
  dnt: /^[01]$/,
  "upgrade-insecure-requests": /^1$/,
  "if-modified-since": HTTP_DATE,
  "if-unmodified-since": HTTP_DATE,
  range: /^bytes=\d{1,15}-\d{0,15}(?:,\s?\d{1,15}-\d{0,15}){0,7}$/,
  "sec-websocket-version": /^\d{1,3}$/,
  "sec-websocket-key": /^[A-Za-z0-9+/]{21}[AQgw]==$/,
  "sec-websocket-extensions": list(String.raw`permessage-deflate(?:\s*;\s*(?:client_max_window_bits|server_max_window_bits|client_no_context_takeover|server_no_context_takeover)(?:=\d{1,2})?){0,4}`),
  "sec-fetch-dest": /^(?:audio|audioworklet|document|embed|empty|font|frame|iframe|image|manifest|object|paintworklet|report|script|serviceworker|sharedworker|style|track|video|webidentity|worker|xslt)$/,
  "sec-fetch-mode": /^(?:cors|navigate|no-cors|same-origin|websocket)$/,
  "sec-fetch-site": /^(?:cross-site|same-origin|same-site|none)$/,
  "sec-fetch-user": /^\?1$/,
  "user-agent": USER_AGENT,
};

/** Values left out for their shape, together, at most this many bytes; past it every header is scanned. */
const SHAPED_TOTAL_MAX = 2048;

/** Where the request goes: a Host header must name it. */
export interface HostPort {
  host: string;
  port: number;
}

function bare(h: string): string {
  return h.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
}

/** Whether a Host (or :authority) value names the target: its host, with no port or the target's own. */
function namesTarget(value: string, t: HostPort): boolean {
  const m = /^(\[[0-9a-f:.]{2,45}\]|[^:[\]\s]{1,253})(?::(\d{1,5}))?$/i.exec(value.trim());
  if (m === null || bare(m[1] as string) !== bare(t.host)) return false;
  if (m[2] === undefined) return true;
  const port = Number(m[2]);
  return t.port === 0 ? port === 80 || port === 443 : port === t.port;
}

/**
 * A Host or :authority header that names another host than the target (domain fronting: the connection
 * goes to the judged host, the request to another), or null. Such a request is denied, never judged by its
 * target alone.
 */
export function hostMismatch(hs: readonly Header[], t: HostPort): string | null {
  const h = frontedHeader(hs, t);
  return h === null ? null : maskHost(h.value).slice(0, 200);
}

/** The Host or :authority header hostMismatch reports, whole and unmasked (for the refusal throttle's key). */
function frontedHeader(hs: readonly Header[], t: HostPort): Header | null {
  for (const h of hs) if ((h.name === "host" || h.name === ":authority") && !namesTarget(h.value, t)) return h;
  return null;
}

/**
 * Userinfo in a URL ("scheme://user:pass@host"): the part between "//" and the last "@" of the authority (a password
 * may hold an "@" itself: "//bob:p@ss@host" masks "bob:p@ss" whole).
 */
const URL_USERINFO = /(\/\/)[^/?#\s]*@/g;

/**
 * The value given to a key named password, passwd, secret or token (alone or as the last word of the name:
 * db_password, access_token), which credentialAssignments and redactSecrets may leave alone or only partly mask (a
 * short value, one with a "/" or a space in it). Only these names: a short value of another key ("id=7") is not a
 * credential. A quoted value is masked to its closing quote (spaces and all: `password: "my pass"`), a backslash-escaped
 * quote inside it not counting as the close (`"password":"a\"b c"`); an unquoted one to the next "&" or whitespace, or
 * its end, through anything else in it ("/", "?", "#", ",", ";", quotes and "}" included: `password=ab/cd`,
 * `password=ab,cd`, and the `"}` after `{"token":abc` is masked with it).
 */
const CREDENTIAL_VALUE = /((?:^|[\s,{;?&#/])["']?(?:[A-Za-z0-9]+[_.-])*(?:password|passwd|secret|token)["']?[ \t]{0,8}[:=][ \t]{0,8})("(?:[^"\\\n]|\\.)*"?|'(?:[^'\\\n]|\\.)*'?|[^\s&]+)/gim;

/**
 * What stands for a masked value until redactSecrets has run (too short to be taken for a value by it). It is made of
 * NUL characters, which maskCredentials first replaces in its input, so text cannot carry the sentinel in itself.
 */
const MASK_SENTINEL = "\u0000m\u0000";

/** Whether a quoted value ends with its closing quote (not one escaped by an odd run of backslashes). */
function closed(value: string, q: string): boolean {
  if (q === "" || value.length < 2 || !value.endsWith(q)) return false;
  const slashes = /\\*$/.exec(value.slice(0, -1))?.[0].length ?? 0;
  return slashes % 2 === 0;
}

/**
 * Text quoted in a refusal record (a URL, a Host or pseudo-header value) with credentials masked: userinfo in URLs,
 * credential-shaped values (redactSecrets), and assignment-style ones such as "?password=..." or "&access_token=..."
 * (credentialAssignments, as the engine's post-tool scan does; a query's "?" and "&" count as the separators it
 * expects). Always mask before truncating, so a credential cut in two is never left half visible.
 */
export function maskCredentials(text: string): string {
  // A NUL in the input is shown as U+FFFD, so only the sentinel this function writes becomes "[masked]".
  const input = text.replaceAll("\u0000", "\uFFFD");
  // First every value of a password, secret or token key, whole: before redactSecrets, whose note has spaces in it and
  // masks only up to a separator, so the rest of a value ("/cd" of "password=abcdefgh/cd") would be left.
  // The mask is a short sentinel until redactSecrets has run, so it is never taken for a value itself.
  const u = input.replace(URL_USERINFO, "$1[userinfo masked]@").replace(CREDENTIAL_VALUE, (_m, key: string, value: string) => {
    const q = value[0] === '"' || value[0] === "'" ? value[0] : "";
    return `${key}${q}${MASK_SENTINEL}${closed(value, q) ? q : ""}`;
  });
  // A path's "/" separates like "?" and "&" ("/x/password=..." and ":path /api_key=...").
  return redactSecrets(u, credentialAssignments(u.replace(/[?&#/]/g, " "))).text.split(MASK_SENTINEL).join("[masked]");
}

/** A Host value with credentials masked, and any userinfo ("user:pass@host") before its last "@". */
function maskHost(v: string): string {
  const at = v.lastIndexOf("@");
  return maskCredentials(at < 0 ? v : `[userinfo masked]@${v.slice(at + 1)}`);
}

/** The parts of the target the :scheme, :method and :path pseudo-headers restate. */
export interface TargetParts {
  scheme: string;
  method: string;
  path: string;
  query: string;
}

/** Characters RFC 3986 calls unreserved: their percent-escapes mean the same as the characters themselves. */
const UNRESERVED = /^[A-Za-z0-9._~-]$/;

/**
 * A request target (path and query) in the form :path is compared in: percent-escapes of unreserved characters
 * decoded, every other escape's hex digits in upper case (RFC 3986 6.2.2), and a bare "?" with no query after it
 * dropped. This is the normalisation OpenShell is expected to apply when it builds its target fields from the
 * request line; it is not confirmed against a real gateway (docs/sandboxes.md). A gateway that differs makes an
 * ordinary request a mismatch (a false refusal), never a pass.
 */
export function normalRequestTarget(p: string): string {
  const s = p.replace(/%([0-9A-Fa-f]{2})/g, (_m, hex: string) => {
    const c = String.fromCharCode(parseInt(hex, 16));
    return UNRESERVED.test(c) ? c : `%${hex.toUpperCase()}`;
  });
  return s.indexOf("?") === s.length - 1 ? s.slice(0, -1) : s;
}

/**
 * A :scheme, :method or :path pseudo-header that says something else than the target the engine judges (built
 * from OpenShell's target fields, targetUrl), as "name: value", or null. OpenShell hands the target and the header
 * list separately, so nothing guarantees they agree: a request whose pseudo-headers name another path (or carry
 * data the target does not) is denied like a Host mismatch, never judged by its target alone. Pseudo-headers are
 * left out of the scan only because they must restate the target; any other pseudo-header (but :protocol
 * "websocket", RFC 8441) is a mismatch too.
 */
export function pseudoMismatch(hs: readonly Header[], t: TargetParts): string | null {
  const h = pseudoHeader(hs, t);
  return h === null ? null : maskCredentials(`${h.name}: ${h.value}`).slice(0, 200);
}

/** The pseudo-header pseudoMismatch reports, whole and unmasked (for the refusal throttle's key). */
function pseudoHeader(hs: readonly Header[], t: TargetParts): Header | null {
  const path = normalRequestTarget(`${t.path.startsWith("/") || t.path === "*" ? t.path : `/${t.path}`}${t.query !== "" ? `?${t.query}` : ""}`);
  for (const h of hs) {
    if (!h.name.startsWith(":") || h.name === ":authority") continue;
    // A fragment is never part of a request target (RFC 9110 7.1): a :path with one says more than the target does.
    const ok = h.name === ":scheme" ? h.value.toLowerCase() === t.scheme : h.name === ":method" ? t.method !== "" && h.value.toUpperCase() === t.method : h.name === ":path" ? !h.value.includes("#") && normalRequestTarget(h.value) === path : h.name === ":protocol" ? h.value === "websocket" : false;
    if (!ok) return h;
  }
  return null;
}

/**
 * The header lines the engine scans as data (empty when there are none). A value is left out only when
 * its header has a strict shape (SHAPES) and the value fits it, the header is not repeated, and the values
 * left out stay under SHAPED_TOTAL_MAX bytes together; a Host naming the target is left out too.
 * Pseudo-headers other than :authority restate the target and are not data.
 */
export function dataHeaders(hs: readonly Header[], target?: HostPort): string[] {
  const seen = new Map<string, number>();
  for (const h of hs) seen.set(h.name, (seen.get(h.name) ?? 0) + 1);
  const shaped = (h: Header): boolean => {
    if (h.name === "host" || h.name === ":authority") return target !== undefined && seen.get(h.name) === 1 && namesTarget(h.value, target);
    if (h.name.startsWith(":")) return true;
    const shape = own(SHAPES, h.name);
    return shape !== undefined && seen.get(h.name) === 1 && h.value.length <= 512 && shape.test(h.value);
  };
  const skip = hs.map(shaped);
  let total = 0;
  hs.forEach((h, i) => {
    if (skip[i] === true && !h.name.startsWith(":") && h.name !== "host") total += h.name.length + h.value.length;
  });
  // Many values that each fit a shape are still data together: past the limit, every header is scanned.
  const all = total > SHAPED_TOTAL_MAX;
  return hs.filter((h, i) => (all ? !h.name.startsWith(":") || h.name === ":authority" : skip[i] !== true)).map((h) => bodyText(Buffer.from(`${h.name}: ${h.value}`, "utf8")));
}

const BINARY_TYPE = /^\s*(?:image\/|audio\/|video\/|font\/|application\/(?:octet-stream|zip|gzip|x-gzip|x-tar|x-7z-compressed|x-bzip2?|x-xz|zstd|x-zstd|pdf|x-protobuf|protobuf|vnd\.google\.protobuf|grpc|msgpack|x-msgpack|cbor|wasm|java-archive|x-java-archive|vnd\.ms-|vnd\.openxmlformats))/i;

/** Why a body cannot be read as text (compressed, binary, not UTF-8), or null when it can. */
export function unreadableBody(body: Buffer, hs: readonly Header[]): string | null {
  if (body.length === 0) return null;
  const enc = (header(hs, "content-encoding") ?? "").trim().toLowerCase();
  if (enc !== "" && enc !== "identity") return `compressed (${enc.slice(0, 40)})`;
  const type = header(hs, "content-type") ?? "";
  if (BINARY_TYPE.test(type)) return `binary (${type.trim().slice(0, 60)})`;
  if (!isUtf8(body) || body.includes(0)) return "not UTF-8 text";
  return null;
}

/** The text the engine scans for a request: its body, then its data-carrying headers. */
export function requestPayload(body: string, hs: readonly Header[], target?: HostPort): string {
  const lines = dataHeaders(hs, target);
  if (lines.length === 0) return body;
  return `${body}${body !== "" ? "\n" : ""}[request headers]\n${lines.join("\n")}`;
}

interface Ctx4 {
  requestId: string;
  sandboxId: string;
}

function contextOf(m: Fields | null): Ctx4 {
  if (m === null) throw new GrpcError(Status.INVALID_ARGUMENT, "the request has no context");
  return { requestId: str(m, 1), sandboxId: str(m, 2) };
}

/** reason_code: lowercase letters, digits and underscores, starting with a letter, at most 64 bytes. */
export function reasonCode(verdict: string, rules: readonly { id: string }[]): string {
  const rule = (rules[0]?.id ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  const code = `launchsafe_${verdict.replace(/[^a-z]/g, "")}${rule !== "" ? `_${rule}` : ""}`;
  return code.slice(0, 64).replace(/_+$/, "");
}

export const LOOPBACK_CODE = "launchsafe_deny_loopback";
/** An address target that is not on the public internet: a private network or a special-purpose block (nonPublicAddress). */
export const INTERNAL_CODE = "launchsafe_deny_internal_address";

/** The target the service refuses without judging it, with the code and the reason it records: this machine, or an address not on the public internet. */
export function refusedTarget(host: string): { code: string; reason: string } | null {
  const shown = host.slice(0, 120);
  if (isLoopbackTarget(host)) return { code: LOOPBACK_CODE, reason: `the target ${shown} is this machine (loopback)` };
  const why = nonPublicAddress(host);
  return why === null ? null : { code: INTERNAL_CODE, reason: `the target ${shown} is ${why}, not an address on the public internet` };
}

/** A Host header naming another host than the target (hostMismatch). */
export const HOST_MISMATCH_CODE = "launchsafe_deny_host_mismatch";
/** A :scheme, :method or :path pseudo-header that does not restate the target (pseudoMismatch). */
export const TARGET_MISMATCH_CODE = "launchsafe_deny_target_mismatch";

function finding(id: string): Writer {
  return new Writer().str(1, "launchsafe_firewall_rule").str(2, id.slice(0, 200)).uint(3, 1);
}

function metadata(w: Writer, field: number, entries: Record<string, string>): void {
  for (const [k, v] of Object.entries(entries)) w.msg(field, new Writer().str(1, k).str(2, v));
}

/** A bounded map of recent requests: request id to the decision whose result the response is. */
class Recent {
  private readonly m = new Map<string, { session: string; decisionId: string }>();
  constructor(private readonly max: number) {}
  set(k: string, v: { session: string; decisionId: string }): void {
    this.m.delete(k);
    this.m.set(k, v);
    while (this.m.size > this.max) {
      const first = this.m.keys().next().value;
      if (first === undefined) break;
      this.m.delete(first);
    }
  }
  take(k: string): { session: string; decisionId: string } | undefined {
    const v = this.m.get(k);
    this.m.delete(k);
    return v;
  }
}

/**
 * Identical refusals (same session, sandbox, reason code, host and, for a Host or pseudo-header mismatch, offending
 * value) within this window are recorded once, with a count.
 */
export const REFUSAL_WINDOW_MS = 60_000;
/** Refusals one sandbox's session may have recorded one by one per window; past it, its new kinds are counted together. */
export const REFUSALS_PER_WINDOW = 32;

/** Whether to record a refusal now, and how many identical ones since the last recorded one were only counted. */
export interface RefusalAdmission {
  record: boolean;
  /** Identical refusals counted, not recorded, since the last recorded one of this kind. */
  repeated: number;
  /** The sandbox's budget for this window is spent: this record stands for every kind not recorded on its own. */
  aggregate: boolean;
  /** When it was admitted (the throttle's clock): release() gives back this slot of the sandbox's window. */
  at?: number;
}

/**
 * Throttles the refusals recorded through the API, so a sandboxed agent that sends the same refused request (or a
 * WebSocket message to a refused address) in a loop cannot flood the signed log: the first refusal of a kind (same
 * session, sandbox, code and `kind`: the target host, plus a short hash of the offending Host or pseudo-header value
 * for a mismatch) in a window is recorded, later ones in the window are counted, and the count goes with the next one
 * recorded. A sandbox past REFUSALS_PER_WINDOW records in any window (a sliding one: the records of the last
 * `windowMs`, so no two windows back to back allow twice as many) has its further kinds counted together under one
 * entry per code. Bounded: the oldest kinds are forgotten first. Times are monotonic
 * milliseconds (the service passes performance.now()), so a wall-clock step cannot reopen or stretch a window.
 */
export class RefusalThrottle {
  private readonly kinds = new Map<string, { until: number; suppressed: number }>();
  /** Per sandbox, when each of its records in the last window was admitted (oldest first; at most perWindow). */
  private readonly budgets = new Map<string, number[]>();
  constructor(
    private readonly windowMs = REFUSAL_WINDOW_MS,
    private readonly perWindow = REFUSALS_PER_WINDOW,
    private readonly maxKinds = 10_000,
  ) {}

  admit(scope: string, code: string, kindOf: string, now: number): RefusalAdmission {
    let key = `${scope}\u0000${code}\u0000${kindOf}`;
    let kind = this.kinds.get(key);
    if (kind !== undefined && now < kind.until) {
      kind.suppressed++;
      return { record: false, repeated: 0, aggregate: false };
    }
    let aggregate = false;
    const budget = (this.budgets.get(scope) ?? []).filter((t) => now - t < this.windowMs);
    if (budget.length >= this.perWindow) {
      aggregate = true;
      key = `${scope}\u0000${code}\u0000*`;
      const all = this.kinds.get(key);
      if (all !== undefined && now < all.until) {
        all.suppressed++;
        // The host's own kind is not kept: it was never recorded on its own.
        return { record: false, repeated: 0, aggregate: true };
      }
      kind = all;
    } else budget.push(now);
    this.put(this.budgets, scope, budget);
    const repeated = kind?.suppressed ?? 0;
    this.put(this.kinds, key, { until: now + this.windowMs, suppressed: 0 });
    return { record: true, repeated, aggregate, at: now };
  }

  /**
   * Undoes an admission whose record failed (the API was down, or refused it): the kind's window is reopened, with the
   * count it carried, the failed refusal itself, and the identical refusals counted while the record was in flight, so
   * the next identical refusal tries to record again (and says how many went unrecorded), and the sandbox's budget gets
   * the slot back.
   */
  release(scope: string, code: string, kindOf: string, a: RefusalAdmission): void {
    if (!a.record) return;
    const key = `${scope}\u0000${code}\u0000${a.aggregate ? "*" : kindOf}`;
    const live = this.kinds.get(key)?.suppressed ?? 0;
    this.put(this.kinds, key, { until: -Infinity, suppressed: a.repeated + 1 + live });
    const budget = this.budgets.get(scope);
    if (!a.aggregate && budget !== undefined && a.at !== undefined) {
      const i = budget.lastIndexOf(a.at);
      if (i >= 0) budget.splice(i, 1);
    }
  }

  private put<V>(m: Map<string, V>, k: string, v: V): void {
    m.delete(k);
    m.set(k, v);
    while (m.size > this.maxKinds) {
      const first = m.keys().next().value;
      if (first === undefined) break;
      m.delete(first);
    }
  }
}

export interface MiddlewareOptions {
  client: DecisionClient;
  /** Verify the gateway's extension tokens (TLS deployments). Without it every caller is trusted (local development only). */
  jwt?: JwtConfig;
  maxPayloadBytes?: number;
  /** The audience this service expects (returned in Describe); empty skips the gateway's check. */
  expectedAudience?: string;
  now?: () => number;
  /** Monotonic milliseconds for the refusal throttle (default performance.now()); tests pass their own. */
  clock?: () => number;
  /** Requests remembered for their responses (default 10000). */
  recentRequests?: number;
  /** Throttles the refusals recorded through the API (default: REFUSAL_WINDOW_MS, REFUSALS_PER_WINDOW). */
  refusals?: RefusalThrottle;
  /**
   * Told when a refusal could not be recorded through the API (the request is denied all the same). Default: a line
   * on standard error. The count is in the service's `stats.refusalsUnrecorded`.
   */
  onRefusalUnrecorded?: (message: string) => void;
}

export interface MiddlewareService {
  unary: Record<string, UnaryHandler>;
  streams: Record<string, StreamHandler>;
  authorize: (ctx: CallContext) => void;
  maxMessageBytes: number;
  /** Refusals the API did not record (it was down, or refused the request), and refusals only counted (throttled). */
  stats: { refusalsUnrecorded: number; refusalsThrottled: number };
}

interface Judged {
  allow: boolean;
  code: string;
  decisionId: string;
  rules: string[];
  meta: Record<string, string>;
}

/** The firewall's middleware service: Describe, ValidateConfig, EvaluateHttpRequest, response and WebSocket streams. */
export function middlewareService(o: MiddlewareOptions): MiddlewareService {
  const max = o.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD;
  const recent = new Recent(o.recentRequests ?? 10000);
  const throttle = o.refusals ?? new RefusalThrottle();
  const clock = o.clock ?? ((): number => performance.now());
  const stats = { refusalsUnrecorded: 0, refusalsThrottled: 0 };
  const unrecorded = o.onRefusalUnrecorded ?? ((m: string): void => void process.stderr.write(`launchsafe-firewall openshell: ${m}\n`));
  // The unrecorded-refusal line is rate-limited, once per reason code per window with the count of the ones not
  // reported since, so an agent looping on a refused request while the API is down cannot flood standard error.
  const reported = new Map<string, { until: number; skipped: number }>();
  const reportUnrecorded = (code: string, message: string): void => {
    const now = clock();
    const r = reported.get(code);
    if (r !== undefined && now < r.until) {
      r.skipped++;
      return;
    }
    const more = r !== undefined && r.skipped > 0 ? ` (${r.skipped} more refused request${r.skipped === 1 ? "" : "s"} (${code}) could not be recorded since the last report)` : "";
    reported.delete(code);
    reported.set(code, { until: now + REFUSAL_WINDOW_MS, skipped: 0 });
    // Codes are few; the bound only guards against a caller inventing them.
    if (reported.size > 1000) reported.delete(reported.keys().next().value as string);
    unrecorded(`${message.slice(0, 300)}${more}`);
  };

  const authorize = (ctx: CallContext): void => {
    if (o.jwt === undefined) return;
    const h = ctx.headers.authorization;
    const m = typeof h === "string" ? /^Bearer ([A-Za-z0-9_.-]+)$/.exec(h) : null;
    if (m === null) throw new GrpcError(Status.UNAUTHENTICATED, "a gateway-issued bearer token is required");
    try {
      ctx.auth = verifyExtensionToken(m[1] as string, o.jwt, Math.floor((o.now?.() ?? Date.now()) / 1000));
    } catch (e) {
      throw new GrpcError(Status.UNAUTHENTICATED, e instanceof JwtError ? e.message : "the token cannot be verified");
    }
  };

  /** An evaluation may come only from the supervisor of the sandbox it names (when tokens are verified). */
  const sandboxCheck = (ctx: CallContext, sandboxId: string): void => {
    if (!validSessionId(sandboxId)) throw new GrpcError(Status.INVALID_ARGUMENT, "the request context has no usable sandbox id");
    if (o.jwt === undefined) return;
    const caller = ctx.auth as Caller | undefined;
    if (caller?.kind !== "supervisor") throw new GrpcError(Status.PERMISSION_DENIED, "only a sandbox supervisor may ask for an evaluation");
    if (caller.sandboxId !== sandboxId) throw new GrpcError(Status.PERMISSION_DENIED, "the token's sandbox is not the sandbox this request comes from");
  };

  const sessionFor = (cfg: EntryConfig, sandboxId: string): string => cfg.session ?? sandboxId;

  const parse = (b: Buffer): Fields => {
    try {
      return decode(b);
    } catch (e) {
      throw new GrpcError(Status.INVALID_ARGUMENT, e instanceof ProtoError ? `malformed message: ${e.message}` : "malformed message");
    }
  };

  /** Reads fields of a decoded message; a wrong wire type on a known field is a malformed message. */
  const read = <T>(f: () => T): T => {
    try {
      return f();
    } catch (e) {
      if (e instanceof ProtoError) throw new GrpcError(Status.INVALID_ARGUMENT, `malformed message: ${e.message}`);
      throw e;
    }
  };

  const api = async <T>(f: () => Promise<T>): Promise<T> => {
    try {
      return await f();
    } catch (e) {
      throw new GrpcError(Status.UNAVAILABLE, `the firewall's local API did not answer: ${(e as Error).message}`.slice(0, 300));
    }
  };

  const verdictOf = (d: Awaited<ReturnType<DecisionClient["decide"]>>): Judged => {
    const meta: Record<string, string> = { decision_id: d.decisionId, verdict: d.verdict, ...(d.approval !== undefined ? { approval_id: d.approval.id } : {}) };
    return { allow: d.verdict === "allow", code: d.verdict === "allow" ? "" : reasonCode(d.verdict, d.rules), decisionId: d.decisionId, rules: d.rules.map((r) => r.id).filter((x) => x !== ""), meta };
  };

  const callIdOf = (callId: string): Record<string, string> => (callId !== "" && callId.length <= 200 && SESSION_ID.test(callId) ? { callId } : {});

  /** Asks the API about one request or message; the result fields shared by every operation. */
  const judge = async (session: string, cfg: EntryConfig, input: { url: string; method: string; body: string }, callId: string, dryRun = false): Promise<Judged> => {
    // Middleware traffic: every rule and the sandbox session's own budgets apply, but OpenShell's requests
    // do not use up the agent's tool-call limit or its agent-wide monitor (docs/design.md).
    const d = await api(() =>
      o.client.decide({
        session,
        action: { format: "engine", tool: "HttpRequest", input: { url: input.url, method: input.method, ...(input.body !== "" ? { body: input.body } : {}) }, ...callIdOf(callId) },
        context: middlewareDecideContext(cfg.attended),
        ...(dryRun ? { dryRun: true } : {}),
      }),
    );
    return verdictOf(d);
  };

  /**
   * A request whose body the service cannot read: the host lists still apply (a dry run of the request
   * with a placeholder body: a deny stays a deny), and otherwise it is held as an action the firewall
   * cannot read, bound to the exact bytes (their SHA-256), so a person's approval lets that request
   * through once. Never judged as if the body were empty.
   */
  const judgeUnreadable = async (session: string, cfg: EntryConfig, url: string, method: string, why: string, body: Buffer, hs: readonly Header[], callId: string, target: HostPort): Promise<Judged> => {
    const digest = createHash("sha256").update(body).digest("hex");
    // The approval is bound to the whole request, not only its body: the full URL, the method and the data-carrying
    // header lines go into the digest, so a changed Authorization or X-Api-Key, or a longer URL that shares the
    // first 400 characters, is a new action and needs its own approval.
    const whole = createHash("sha256").update(JSON.stringify([url, method, dataHeaders(hs, target)])).digest("hex");
    const marker = `(a request body the firewall cannot read: ${why}, ${body.length} bytes, sha256 ${digest}, request sha256 ${whole})`;
    const pre = await judge(session, cfg, { url, method, body: requestPayload(marker, hs, target) }, "", true);
    if (pre.meta.verdict === "deny") return pre;
    // Middleware traffic, as in judge.
    const d = await api(() =>
      o.client.decide({
        session,
        action: { format: "engine", tool: UNPARSEABLE_TOOL, input: { tool: "HttpRequest", reason: `${method} ${url.slice(0, 400)} with ${marker}` }, ...callIdOf(callId) },
        context: middlewareDecideContext(cfg.attended),
      }),
    );
    return verdictOf(d);
  };

  /**
   * A request the service refuses without judging it (a loopback or other non-public address target, a Host or
   * pseudo-header naming another target): always a deny, and recorded through the API as a decision of NETWORK_REFUSED_TOOL (FW-NET-REFUSED, with
   * the reason code and why), so a domain-fronting attempt leaves a signed log entry. Identical refusals are throttled
   * (RefusalThrottle, keyed by the target host and, for a mismatch, a hash of `offending`: the whole offending value,
   * normalised): one is recorded per window, with the count of the ones only counted since the last. The URL and the
   * reason (which quotes the Host or pseudo-header value) are sent with credentials masked (maskCredentials) before
   * they are cut to length. When the API cannot record it, the request is still denied, the failure is counted and
   * reported, and the throttle is rolled back so the next identical refusal tries again. Any exception on the way
   * ends in the same clean deny.
   */
  const refused = async (session: string, sandboxId: string, cfg: EntryConfig, url: string, host: string, method: string, code: string, reason: string, offending: string, callId: string): Promise<Judged> => {
    const denied: Judged = { allow: false, code, decisionId: "", rules: [], meta: { verdict: "deny" } };
    const scope = `${session}\u0000${sandboxId}`;
    // A mismatch's offending value is in the kind: evil2 and evil3 fronted onto one target are two kinds, not one.
    const kindOf = offending === "" ? host : `${host}\u0000${createHash("sha256").update(offending).digest("hex").slice(0, 16)}`;
    let admit: RefusalAdmission | null = null;
    try {
      admit = throttle.admit(scope, code, kindOf, clock());
      if (!admit.record) {
        stats.refusalsThrottled++;
        return denied;
      }
      const counted = admit.repeated > 0 ? ` (${admit.repeated} more identical refusal${admit.repeated === 1 ? "" : "s"} since the last one recorded were counted, not recorded one by one)` : "";
      const all = admit.aggregate ? ` (this sandbox reached ${REFUSALS_PER_WINDOW} recorded refusals in ${REFUSAL_WINDOW_MS / 1000} s: refusals for other hosts or header values are counted together under this entry)` : "";
      // Masked before cut: a credential straddling the cut is never left half visible.
      const why = `${maskCredentials(reason).slice(0, 400)}${counted}${all}`;
      const d = await o.client.decide({
        session,
        action: { format: "engine", tool: NETWORK_REFUSED_TOOL, input: { url: maskCredentials(url).slice(0, 2000), method, code, reason: why, ...(admit.repeated > 0 ? { repeated: admit.repeated } : {}) }, ...callIdOf(callId) },
        context: middlewareDecideContext(cfg.attended),
      });
      return { ...denied, decisionId: d.decisionId, rules: d.rules.map((r) => r.id).filter((x) => x !== ""), meta: { decision_id: d.decisionId, verdict: "deny" } };
    } catch (e) {
      stats.refusalsUnrecorded++;
      try {
        if (admit !== null) throttle.release(scope, code, kindOf, admit);
        reportUnrecorded(code, `a refused request (${code}) could not be recorded in the firewall's log: ${(e as Error).message}`);
      } catch {
        // The report is best effort; the request is denied and counted.
      }
      return denied;
    }
  };

  const describe: UnaryHandler = async (req) => {
    const m = parse(req);
    read(() => {
      const peer = msg(m, 1);
      if (peer === null) return;
      const v = msg(peer, 1);
      if (v !== null && uint(v, 1) !== 1) throw new GrpcError(Status.FAILED_PRECONDITION, `protocol major version ${uint(v, 1)} is not supported (this service speaks 1.0)`);
      const required = (peer.get(5) ?? []).map((f) => {
        if (f.wire !== 2 || f.bytes === undefined) throw new ProtoError(`field 5 has wire type ${f.wire}, expected 2`);
        return f.bytes.toString("utf8");
      });
      const missing = required.filter((c) => c !== CONTRACT_CAPABILITY);
      if (missing.length > 0) throw new GrpcError(Status.FAILED_PRECONDITION, `required capabilities not supported: ${missing.join(", ").slice(0, 200)}`);
    });
    const binding = (op: number, phase: number): Writer => new Writer().enum(1, op).enum(2, phase).uint(3, max);
    const ext = new Writer().msg(1, new Writer().uint(1, 1).uint(2, 0)).str(2, IMPLEMENTATION_NAME).str(3, VERSION).str(4, CONTRACT_CAPABILITY);
    return new Writer()
      .str(1, "LaunchSafe Agent Firewall")
      .msg(3, binding(OP_HTTP_REQUEST, PHASE_PRE_CREDENTIALS))
      .msg(3, binding(OP_HTTP_RESPONSE, PHASE_PRE_RETURN))
      .msg(3, binding(OP_WEBSOCKET_MESSAGE, PHASE_PRE_CREDENTIALS))
      .str(4, o.expectedAudience ?? "")
      .msg(5, ext)
      .finish();
  };

  const validateConfig: UnaryHandler = async (req) => {
    const m = parse(req);
    const c = read(() => parseEntryConfig(has(m, 1) ? structToJson(msg(m, 1) ?? new Map()) : {}));
    return typeof c === "string" ? new Writer().str(2, c).finish() : new Writer().bool(1, true).finish();
  };

  const evaluateHttpRequest: UnaryHandler = async (req, ctx) => {
    const m = parse(req);
    const { c, cfg, t, hs, body } = read(() => {
      const phase = uint(m, 1);
      if (phase !== PHASE_PRE_CREDENTIALS) throw new GrpcError(Status.INVALID_ARGUMENT, `phase ${phase} is not the pre-credentials phase this binding serves`);
      return { c: contextOf(msg(m, 2)), cfg: configOf(msg(m, 3)), t: targetOf(msg(m, 4), true), hs: headersOf(msgs(m, 5)), body: bytes(m, 6) };
    });
    sandboxCheck(ctx, c.sandboxId);
    if (body.length > max) throw new GrpcError(Status.RESOURCE_EXHAUSTED, `the body is larger than ${max} bytes`);
    const url = targetUrl(t);
    const session = sessionFor(cfg, c.sandboxId);
    let j: Judged;
    const fronted = frontedHeader(hs, t);
    const pseudo = fronted === null ? pseudoHeader(hs, t) : null;
    const refusal = refusedTarget(t.host);
    if (refusal !== null) j = await refused(session, c.sandboxId, cfg, url, t.host, t.method, refusal.code, refusal.reason, "", c.requestId);
    else if (fronted !== null) j = await refused(session, c.sandboxId, cfg, url, t.host, t.method, HOST_MISMATCH_CODE, `the Host header names ${maskHost(fronted.value).slice(0, 200)}, not the target`, `host\u0000${bare(fronted.value.trim())}`, c.requestId);
    else if (pseudo !== null) j = await refused(session, c.sandboxId, cfg, url, t.host, t.method, TARGET_MISMATCH_CODE, `the pseudo-header ${maskCredentials(`${pseudo.name}: ${pseudo.value}`).slice(0, 200)} does not restate the target`, `${pseudo.name}\u0000${pseudo.name === ":path" ? normalRequestTarget(pseudo.value) : pseudo.value.trim().toLowerCase()}`, c.requestId);
    else {
      const why = unreadableBody(body, hs);
      j = why !== null ? await judgeUnreadable(session, cfg, url, t.method, why, body, hs, c.requestId, t) : await judge(session, cfg, { url, method: t.method, body: requestPayload(bodyText(body), hs, t) }, c.requestId);
      // An unreadable body's allow is an approval of opaque bytes: its response is recorded through a fresh
      // read decision (recordBody), which also marks the session as having read outside content.
      if (j.allow && why === null && c.requestId !== "") recent.set(`${c.sandboxId}\u0000${c.requestId}`, { session, decisionId: j.decisionId });
    }
    const w = new Writer().enum(1, j.allow ? DECISION_ALLOW : DECISION_DENY);
    for (const r of j.rules.slice(0, 32)) w.msg(6, finding(r));
    metadata(w, 7, j.meta);
    if (!j.allow) w.str(8, j.code);
    return w.finish();
  };

  /**
   * Records a response body as its request's result, and returns what the firewall made of it (its
   * redacted text, when it changed anything). With no remembered request (none sent, an empty request id,
   * or one evicted from the bounded map), a fresh read decision for the same address stands in, so the
   * body is still a decision's result and can be redacted; when the firewall does not allow that read,
   * the response is not delivered.
   */
  const recordBody = async (c: Ctx4, t: Target4, cfg: EntryConfig, content: string): Promise<string | undefined> => {
    const prior = c.requestId !== "" ? recent.take(`${c.sandboxId}\u0000${c.requestId}`) : undefined;
    if (prior !== undefined) return (await api(() => o.client.result(prior.session, prior.decisionId, content))).output;
    const session = sessionFor(cfg, c.sandboxId);
    const j = await judge(session, cfg, { url: targetUrl(t), method: "GET", body: "" }, "");
    if (!j.allow) throw new GrpcError(Status.PERMISSION_DENIED, `the response from ${t.host.slice(0, 120)} answers a request the firewall has no decision for, and reading it is not allowed (${j.code}): not delivered`);
    return (await api(() => o.client.result(session, j.decisionId, content))).output;
  };

  /** Records a response the service does not read as unread outside content (nothing to redact). */
  const recordUnread = async (c: Ctx4, t: Target4, cfg: EntryConfig, note: string): Promise<void> => {
    const prior = c.requestId !== "" ? recent.take(`${c.sandboxId}\u0000${c.requestId}`) : undefined;
    if (prior !== undefined) await api(() => o.client.result(prior.session, prior.decisionId, note));
    else await api(() => o.client.input(sessionFor(cfg, c.sandboxId), `a response from ${t.host.slice(0, 120)} (OpenShell)`, note));
  };

  const responseStream: StreamHandler = (ctx, send) => {
    let pre: { c: Ctx4; t: Target4; cfg: EntryConfig } | null = null;
    let parts: Buffer[] = [];
    let units = 0;
    let total = 0;
    const unfinished = async (): Promise<void> => {
      if (pre === null || units === 0) return;
      const { c, t, cfg } = pre;
      const n = units;
      parts = [];
      units = 0;
      total = 0;
      await recordUnread(c, t, cfg, `(response body from ${t.host.slice(0, 120)} not inspected: the response ended after ${n} part${n === 1 ? "" : "s"} without its final part)`);
      throw new GrpcError(Status.FAILED_PRECONDITION, `the response from ${t.host.slice(0, 120)} ended without its final part: not inspected`);
    };
    return {
      message: async (raw) => {
        const ev = parse(raw);
        const p = read(() => msg(ev, 1));
        if (p !== null) {
          const { c, t, cfg, hs, status, permitted } = read(() => ({ c: contextOf(msg(p, 1)), t: targetOf(msg(p, 2), false), cfg: configOf(msg(p, 6)), hs: headersOf(msgs(p, 4)), status: uint(p, 3), permitted: new Set(enums(p, 8)) }));
          sandboxCheck(ctx, c.sandboxId);
          if (t.scheme !== "http" && t.scheme !== "https") throw new GrpcError(Status.INVALID_ARGUMENT, `unsupported scheme ${t.scheme.slice(0, 20)}`);
          pre = { c, t, cfg };
          parts = [];
          units = 0;
          total = 0;
          const enc = (header(hs, "content-encoding") ?? "").trim().toLowerCase();
          const type = header(hs, "content-type") ?? "";
          const unreadable = enc !== "" && enc !== "identity" ? `compressed (${enc.slice(0, 40)})` : BINARY_TYPE.test(type) ? `binary (${type.trim().slice(0, 60)})` : !permitted.has(BODY_WHOLE) ? "partial, too large or bodyless" : null;
          const result = new Writer();
          if (!cfg.inspectResponses) result.msg(1, new Writer());
          else if (unreadable === null) result.msg(2, new Writer().enum(1, BODY_WHOLE));
          else {
            await recordUnread(c, t, cfg, `(response body from ${t.host.slice(0, 120)} not inspected: ${unreadable}; status ${status})`);
            result.msg(1, new Writer());
          }
          send(new Writer().msg(1, result).finish());
          return;
        }
        const body = read(() => msg(ev, 2));
        if (body !== null) {
          if (pre === null) throw new GrpcError(Status.FAILED_PRECONDITION, "a body before the preflight");
          const { seq, data, eos } = read(() => ({ seq: uint(body, 1), data: bytes(body, 2), eos: uint(body, 3) !== 0 }));
          units++;
          total += data.length;
          if (units > MAX_UNITS) throw new GrpcError(Status.RESOURCE_EXHAUSTED, `more than ${MAX_UNITS} body units in one response`);
          if (total > max) throw new GrpcError(Status.RESOURCE_EXHAUSTED, `the response body is larger than ${max} bytes`);
          parts.push(data);
          const result = new Writer().uint(1, seq);
          if (eos) {
            const all = Buffer.concat(parts);
            const n = units;
            parts = [];
            units = 0;
            total = 0;
            const sent = bodyText(all);
            const out = await recordBody(pre.c, pre.t, pre.cfg, sent);
            // Compared with the text the firewall was given, not the raw bytes: bodyText's replaced control
            // characters are not a redaction, and a clean body is never rewritten.
            if (out === undefined || out === sent) result.msg(2, new Writer());
            else if (n === 1 && isUtf8(all) && Buffer.byteLength(out, "utf8") <= max) result.msg(3, new Writer().bytes(1, Buffer.from(out, "utf8"), true));
            else {
              const why = n !== 1 ? `it arrived in ${n} parts` : !isUtf8(all) ? "it is not UTF-8 text" : `the redacted body is over ${max} bytes`;
              throw new GrpcError(Status.PERMISSION_DENIED, `the firewall redacted part of the response from ${pre.t.host.slice(0, 120)} but cannot rewrite it (${why}): not delivered`);
            }
          } else result.msg(2, new Writer());
          send(new Writer().msg(2, result).finish());
          return;
        }
        if (has(ev, 4)) {
          send(new Writer().msg(3, new Writer()).finish());
          return;
        }
        // session_end (3): no result, but a response still open here never reached its final part.
        if (has(ev, 3)) await unfinished();
      },
      // A response that ends without its final part was partly passed through, and never scanned.
      end: async () => unfinished(),
    };
  };

  const webSocketStream: StreamHandler = (ctx, send) => {
    let pre: { c: Ctx4; t: Target4; cfg: EntryConfig } | null = null;
    return {
      message: async (raw) => {
        const ev = parse(raw);
        const p = read(() => msg(ev, 1));
        if (p !== null) {
          const next = read(() => ({ c: contextOf(msg(p, 3)), t: targetOf(msg(p, 4), false), cfg: configOf(msg(p, 7)) }));
          sandboxCheck(ctx, next.c.sandboxId);
          targetUrl(next.t);
          pre = next;
          send(new Writer().msg(1, new Writer().enum(1, WS_INSPECT)).finish());
          return;
        }
        const m = read(() => msg(ev, 3));
        if (m !== null) {
          if (pre === null) throw new GrpcError(Status.FAILED_PRECONDITION, "a message before the preflight");
          const seq = read(() => uint(m, 1));
          const result = new Writer().uint(1, seq);
          const refusal = refusedTarget(pre.t.host);
          if (!has(m, 2)) {
            // OpenShell sends text only; a binary message here is judged as unreadable, and refused.
            result.enum(2, DECISION_DENY).str(6, "launchsafe_binary_message");
          } else if (refusal !== null) {
            const j = await refused(sessionFor(pre.cfg, pre.c.sandboxId), pre.c.sandboxId, pre.cfg, targetUrl(pre.t), pre.t.host, "WEBSOCKET", refusal.code, refusal.reason, "", "");
            result.enum(2, DECISION_DENY).str(6, refusal.code);
            for (const r of j.rules.slice(0, 32)) result.msg(7, finding(r));
            metadata(result, 8, j.meta);
          } else {
            const text = read(() => bytes(m, 2));
            if (text.length > max) throw new GrpcError(Status.RESOURCE_EXHAUSTED, `the message is larger than ${max} bytes`);
            const j = await judge(sessionFor(pre.cfg, pre.c.sandboxId), pre.cfg, { url: targetUrl(pre.t), method: "WEBSOCKET", body: bodyText(text) }, "");
            result.enum(2, j.allow ? DECISION_ALLOW : DECISION_DENY);
            if (!j.allow) result.str(6, j.code);
            for (const r of j.rules.slice(0, 32)) result.msg(7, finding(r));
            metadata(result, 8, j.meta);
          }
          send(new Writer().msg(2, result).finish());
        }
        // session_start (2) and session_end (4): no result.
      },
      end: async () => undefined,
    };
  };

  return {
    authorize,
    maxMessageBytes: max + 256 * 1024,
    stats,
    unary: {
      [`/${SERVICE}/Describe`]: describe,
      [`/${SERVICE}/ValidateConfig`]: validateConfig,
      [`/${SERVICE}/EvaluateHttpRequest`]: evaluateHttpRequest,
    },
    streams: {
      [`/${RESPONSE_SERVICE}/Evaluate`]: responseStream,
      [`/${SERVICE}/EvaluateWebSocketSession`]: webSocketStream,
    },
  };
}
