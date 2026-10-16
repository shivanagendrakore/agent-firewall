/**
 * JSON-RPC 2.0 for the gateway: message shapes, the bounded newline framing
 * stdio uses (one message per line, no embedded newlines: MCP 2026-07-28
 * basic/transports/stdio), and the table of requests in flight, so a result is
 * matched to the request (and the decision) that let it through.
 */

export type Id = string | number;
export type Json = Record<string, unknown>;

export interface Request {
  jsonrpc: "2.0";
  id: Id;
  method: string;
  params?: Json;
}
export interface Notification {
  jsonrpc: "2.0";
  method: string;
  params?: Json;
}
export interface Response {
  jsonrpc: "2.0";
  id: Id | null;
  result?: Json;
  error?: { code: number; message: string; data?: unknown };
}
export type Message = Request | Notification | Response;

/** 16 MiB per message and 1,000 requests in flight per direction. */
export const MAX_MESSAGE_BYTES = 16 * 1024 * 1024;
export const MAX_PENDING = 1000;
/**
 * FZ3: JSON nested deeper than this is refused at parse time. JSON.parse copes with far more, but
 * JSON.stringify (frame) and any recursive walk run out of stack near 8,000 levels, which would turn
 * a message the gateway accepted into an exception. Nothing the scanners read goes past 64 levels anyway.
 */
export const MAX_JSON_DEPTH = 1000;

export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;
export const METHOD_NOT_FOUND = -32601;
export const INVALID_PARAMS = -32602;
export const INTERNAL_ERROR = -32603;
/** MCP 2026-07-28 protocol errors (basic/index, Error Codes; renumbered in the changelog). */
export const HEADER_MISMATCH = -32020;
export const MISSING_CLIENT_CAPABILITY = -32021;
export const UNSUPPORTED_PROTOCOL_VERSION = -32022;

const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const isId = (v: unknown): v is Id => typeof v === "string" || (typeof v === "number" && Number.isFinite(v));

/** The deepest nesting of brackets outside strings: a linear scan, run before the text is parsed. */
export function jsonDepth(text: string): number {
  let depth = 0;
  let max = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) i++;
      else if (c === 0x22) inString = false;
    } else if (c === 0x22) inString = true;
    else if (c === 0x5b || c === 0x7b) {
      if (++depth > max) max = depth;
    } else if (c === 0x5d || c === 0x7d) depth--;
  }
  return max;
}

/** A parsed message, or why it is not one (the caller answers with a parse or invalid-request error). */
export function parseMessage(text: string): { ok: true; msg: Message } | { ok: false; code: number; reason: string; id: Id | null } {
  if (jsonDepth(text) > MAX_JSON_DEPTH) return { ok: false, code: INVALID_REQUEST, reason: `nested deeper than ${MAX_JSON_DEPTH} levels`, id: null };
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return { ok: false, code: PARSE_ERROR, reason: "not valid JSON", id: null };
  }
  if (!isObj(v) || v.jsonrpc !== "2.0") return { ok: false, code: INVALID_REQUEST, reason: "not a JSON-RPC 2.0 message", id: null };
  const id = isId(v.id) ? v.id : null;
  if (v.params !== undefined && !isObj(v.params)) return { ok: false, code: INVALID_REQUEST, reason: "params must be an object", id };
  if (typeof v.method === "string") {
    if (v.id !== undefined && !isId(v.id)) return { ok: false, code: INVALID_REQUEST, reason: "bad id", id: null };
    return { ok: true, msg: v as unknown as Request | Notification };
  }
  if ((v.result !== undefined || v.error !== undefined) && (isId(v.id) || v.id === null)) {
    if (v.result !== undefined && !isObj(v.result)) return { ok: false, code: INVALID_REQUEST, reason: "result must be an object", id };
    if (v.error !== undefined && !(isObj(v.error) && typeof v.error.code === "number" && typeof v.error.message === "string")) return { ok: false, code: INVALID_REQUEST, reason: "malformed error", id };
    return { ok: true, msg: v as unknown as Response };
  }
  return { ok: false, code: INVALID_REQUEST, reason: "neither a request, a notification nor a response", id };
}

export const isRequest = (m: Message): m is Request => "method" in m && "id" in m && m.id !== undefined;
export const isNotification = (m: Message): m is Notification => "method" in m && !("id" in m && m.id !== undefined);
export const isResponse = (m: Message): m is Response => !("method" in m);

export function errorResponse(id: Id | null, code: number, message: string, data?: unknown): Response {
  return { jsonrpc: "2.0", id, error: { code, message, ...(data !== undefined ? { data } : {}) } };
}

export function resultResponse(id: Id, result: Json): Response {
  return { jsonrpc: "2.0", id, result };
}

/** One message as a line (JSON.stringify never emits a raw newline, so the framing holds). */
export function frame(m: Message): string {
  return `${JSON.stringify(m)}\n`;
}

/**
 * Splits a byte stream into lines, bounded: a line longer than MAX_MESSAGE_BYTES is dropped (reported
 * once through `onOversize`) and reading continues at the next newline.
 */
export class LineFramer {
  private buf = "";
  private skipping = false;
  constructor(
    private readonly onLine: (line: string) => void,
    private readonly onOversize: () => void,
    private readonly max = MAX_MESSAGE_BYTES,
  ) {}
  push(chunk: string): void {
    let data = chunk;
    while (data.length > 0) {
      const nl = data.indexOf("\n");
      if (nl === -1) {
        if (!this.skipping) {
          this.buf += data;
          // FZ12: a trailing CR may be the first half of a CRLF the next chunk completes, and a complete line
          // drops it before its size is checked; so it is not counted here either, whatever the chunking.
          if (Buffer.byteLength(this.buf.endsWith("\r") ? this.buf.slice(0, -1) : this.buf) > this.max) {
            this.buf = "";
            this.skipping = true;
            this.onOversize();
          }
        }
        return;
      }
      const piece = data.slice(0, nl);
      data = data.slice(nl + 1);
      if (this.skipping) {
        this.skipping = false;
        this.buf = "";
        continue;
      }
      const line = (this.buf + piece).replace(/\r$/, "");
      this.buf = "";
      if (Buffer.byteLength(line) > this.max) {
        this.onOversize();
        continue;
      }
      if (line.trim() !== "") this.onLine(line);
    }
  }
}

/** Requests in flight in one direction, keyed by id. */
export class Pending<T> {
  private readonly map = new Map<string, T>();
  constructor(private readonly max = MAX_PENDING) {}
  private key(id: Id): string {
    return `${typeof id}:${String(id)}`;
  }
  /** False when the table is full (the caller refuses the request). */
  add(id: Id, v: T): boolean {
    if (this.map.size >= this.max && !this.map.has(this.key(id))) return false;
    this.map.set(this.key(id), v);
    return true;
  }
  take(id: Id): T | undefined {
    const k = this.key(id);
    const v = this.map.get(k);
    this.map.delete(k);
    return v;
  }
  has(id: Id): boolean {
    return this.map.has(this.key(id));
  }
  peek(id: Id): T | undefined {
    return this.map.get(this.key(id));
  }
  get size(): number {
    return this.map.size;
  }
}
