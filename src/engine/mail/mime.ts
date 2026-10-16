/**
 * The email guard's message parser (email guard).
 *
 * An RFC 5322 / MIME reader with no dependencies: header unfolding, RFC 2047
 * encoded words, RFC 2231 parameter values, multipart nesting up to depth 10,
 * quoted-printable and base64, charsets through `TextDecoder` (anything it
 * does not know is read as Latin-1 and noted), `message/rfc822` parts
 * (forwarded mail) read recursively, and a 10 MiB cap per message.
 *
 * It also accepts the structured shapes mail APIs and MCP servers return
 * (generic `{ from, subject, text, html, headers }`, Microsoft Graph's
 * message JSON, the Gmail API's `payload` tree), so a parsed message needs no
 * MIME round trip.
 *
 * It only reads: what a model would read, split into text channels for the
 * scanner (`channels()`). Binary attachment contents in a MIME source are not
 * read (only text, HTML and calendar parts are); their names and types are, and
 * so is every part's own header block and any header line that is not a field
 * (as text no client shows). In a structured object, base64 attachment content
 * (`contentBytes`, a Gmail attachment part's `body.data`) is read decoded, and
 * every string no other channel reads (an attachment's `content`, a body's
 * extra keys, object keys) is read by the catch-all channel (`field`).
 *
 * Pure: no I/O. Never throws on hostile input; problems are listed.
 */
import { TextDecoder, TextEncoder } from "node:util";
import { own, setOwn } from "../../own.js";

export const MIME_LIMITS = {
  /** Bytes of one message read (larger messages are withheld on the read path: `too_large`). */
  maxBytes: 10 * 1024 * 1024,
  maxDepth: 10,
  /** Parts kept per message (a flood of tiny parts is a bound like any other). */
  maxParts: 2_000,
} as const;

export interface MailHeader {
  /** As written (case kept). */
  name: string;
  /** Unfolded, not decoded (encoded words stay as they are; `headerText()` decodes). */
  value: string;
}

export interface MailAttachment {
  filename: string;
  contentType: string;
  /** Decoded size in bytes when known (structured inputs may not say). */
  size: number;
}

export type MailProblemKind = "too_large" | "depth" | "parts" | "fields" | "undecodable_charset" | "charset_mismatch" | "malformed";

export interface MailProblem {
  kind: MailProblemKind;
  detail: string;
}

export interface MailMessage {
  /** In order, top first (the receiving server's own headers are on top). */
  headers: MailHeader[];
  /** Decoded text/plain bodies. */
  text: string[];
  /** Decoded text/html bodies. */
  html: string[];
  /** Decoded text/calendar bodies (whole iCalendar documents). */
  calendar: string[];
  attachments: MailAttachment[];
  /** message/rfc822 parts (forwarded mail), parsed the same way. */
  nested: MailMessage[];
  problems: MailProblem[];
  /** A short preview the provider computed (Gmail `snippet`, Graph `bodyPreview`), scanned like text. */
  snippet?: string;
  /**
   * Text in the source that no mail client displays but a model reading the source does: multipart
   * preambles and epilogues.
   */
  unshown?: string[];
  /**
   * String fields of a structured message object that the parser does not know (a custom `notes`
   * field, a second summary), scanned like text because a model reading the object reads them too.
   */
  other?: string[];
  /**
   * The decoded contents of attachments given in base64 in a structured object (Graph's `contentBytes`, a Gmail
   * part's `body.data`): a model can decode base64, so the content is read as text (or HTML, by its type).
   */
  contents?: { text: string; html: boolean }[];
}

/**
 * MailMessages this parser built (or the firewall built from text it holds). Only these are taken as they are by
 * the detector; any other object, whatever its keys, is a message object from a tool and goes through
 * fromStructured, so a key the parser does not know is still read (by the catch-all). An object parsed from JSON
 * text is never in the set, so text that spells a MailMessage cannot pass as one.
 */
const PARSED = new WeakSet<object>();

/** Marks a MailMessage as built by the firewall (see PARSED). */
export function asParsed<T extends MailMessage>(m: T): T {
  PARSED.add(m);
  return m;
}

/** Whether a value is a MailMessage the firewall built (never true for a tool's object). */
export const isParsed = (v: unknown): v is MailMessage => typeof v === "object" && v !== null && PARSED.has(v);

const emptyMessage = (): MailMessage => asParsed({ headers: [], text: [], html: [], calendar: [], attachments: [], nested: [], problems: [] });

/**
 * Whether a string has any markup or character reference at all (the rewriting pass reads such a string as HTML). A
 * string of unknown type with markup is scanned both as text and as HTML (pieceMessage, unknown-type bodies, the
 * catch-all), so a hidden element under a tag looksLikeHtml does not know is read as hidden.
 */
export const MARKUP = /<[A-Za-z!/?]|&#/;

/**
 * One piece of text of unknown type as a message to scan: HTML when it looks like HTML; otherwise text, and HTML too
 * when it has any markup (the signals of both readings are merged).
 */
export function pieceMessage(s: string): MailMessage {
  const m = emptyMessage();
  pushUnknown(m, s);
  return m;
}

/** A body of unknown type: see pieceMessage. */
function pushUnknown(m: MailMessage, s: string): void {
  if (looksLikeHtml(s)) {
    m.html.push(s);
    return;
  }
  m.text.push(s);
  if (MARKUP.test(s)) m.html.push(s);
}

// --- bytes and charsets -------------------------------------------------------------------------

/** A JS string as the bytes it stands for: one byte per char when it fits (a raw message read as Latin-1), else UTF-8. */
export function toBytes(s: string): Uint8Array {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 0xff) return new TextEncoder().encode(s);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function latin1(b: Uint8Array, start = 0, end = b.length): string {
  let s = "";
  const CHUNK = 0x8000;
  for (let i = start; i < end; i += CHUNK) s += String.fromCharCode(...b.subarray(i, Math.min(end, i + CHUNK)));
  return s;
}

const CHARSET_ALIASES: Record<string, string> = { "us-ascii": "utf-8", ascii: "utf-8", "ansi_x3.4-1968": "utf-8", utf8: "utf-8", latin1: "iso-8859-1", "x-unknown": "", unknown: "", "unknown-8bit": "", "8bit": "", default: "" };
const decoderCache = new Map<string, TextDecoder | null>();

function decoderFor(label: string, fatal: boolean): TextDecoder | null {
  const key = `${label}|${fatal}`;
  if (decoderCache.has(key)) return decoderCache.get(key) ?? null;
  let d: TextDecoder | null;
  try {
    d = new TextDecoder(label, { fatal });
  } catch {
    d = null;
  }
  decoderCache.set(key, d);
  return d;
}

/**
 * Decodes bytes in a declared charset. ASCII is read as UTF-8 (8-bit text in a message that claims ASCII
 * is nearly always UTF-8). Invalid UTF-8 and unknown charsets fall back to Latin-1, with a problem noted:
 * never a reason to withhold by itself.
 */
export function decodeCharset(bytes: Uint8Array, charset: string | undefined, problems?: MailProblem[]): string {
  const raw = (charset ?? "utf-8").trim().toLowerCase().replace(/^["']|["']$/g, "");
  const label = own(CHARSET_ALIASES, raw) ?? raw;
  let ascii = true;
  for (const b of bytes) {
    if (b >= 0x80) {
      ascii = false;
      break;
    }
  }
  // Pure ASCII reads the same in every ASCII-compatible charset (the 7-bit ones that are not, like
  // ISO-2022-JP, are still decoded by name below).
  if (ascii && !/^(?:iso-2022|utf-16|utf-32|utf-7|hz)/.test(label)) return latin1(bytes);
  if (label === "utf-8") {
    try {
      return (decoderFor("utf-8", true) as TextDecoder).decode(bytes);
    } catch {
      problems?.push({ kind: "charset_mismatch", detail: `text declared ${raw} is not valid UTF-8; read as Latin-1` });
      return latin1(bytes);
    }
  }
  const d = label === "" ? null : decoderFor(label, false);
  if (d === null) {
    problems?.push({ kind: "undecodable_charset", detail: `charset ${raw || "(none)"} is not known; read as Latin-1` });
    return latin1(bytes);
  }
  return d.decode(bytes);
}

// --- transfer encodings -------------------------------------------------------------------------

const B64 = new Int16Array(256).fill(-1);
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".split("").forEach((c, i) => (B64[c.charCodeAt(0)] = i));
// base64url too (the Gmail API's bodies).
B64["-".charCodeAt(0)] = 62;
B64["_".charCodeAt(0)] = 63;

/** Base64 (and base64url), ignoring whitespace and junk, as a tolerant mail client does. */
export function decodeBase64(input: Uint8Array | string): Uint8Array {
  const src = typeof input === "string" ? toBytes(input) : input;
  const out = new Uint8Array(Math.floor((src.length * 3) / 4) + 3);
  let n = 0;
  let acc = 0;
  let bits = 0;
  for (const c of src) {
    if (c === 0x3d) {
      acc = 0;
      bits = 0;
      continue;
    }
    const v = B64[c] ?? -1;
    if (v < 0) continue;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[n++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, n);
}

const hexVal = (c: number): number => (c >= 0x30 && c <= 0x39 ? c - 0x30 : c >= 0x41 && c <= 0x46 ? c - 0x37 : c >= 0x61 && c <= 0x66 ? c - 0x57 : -1);

/** Quoted-printable: soft line breaks removed, =XX decoded, a malformed escape kept as written. */
export function decodeQuotedPrintable(src: Uint8Array, header = false): Uint8Array {
  const out = new Uint8Array(src.length);
  let n = 0;
  for (let i = 0; i < src.length; i++) {
    const c = src[i] as number;
    if (header && c === 0x5f) {
      out[n++] = 0x20; // "_" is a space in a Q encoded word
      continue;
    }
    if (c !== 0x3d) {
      out[n++] = c;
      continue;
    }
    const a = src[i + 1];
    const b = src[i + 2];
    if (a === 0x0d && b === 0x0a) {
      i += 2;
      continue;
    }
    if (a === 0x0a) {
      i += 1;
      continue;
    }
    // "=" followed by spaces then a line break is a soft break too.
    let j = i + 1;
    while (src[j] === 0x20 || src[j] === 0x09) j++;
    if (j > i + 1 && (src[j] === 0x0a || (src[j] === 0x0d && src[j + 1] === 0x0a))) {
      i = src[j] === 0x0d ? j + 1 : j;
      continue;
    }
    const h1 = a === undefined ? -1 : hexVal(a);
    const h2 = b === undefined ? -1 : hexVal(b);
    if (h1 >= 0 && h2 >= 0) {
      out[n++] = (h1 << 4) | h2;
      i += 2;
    } else out[n++] = c;
  }
  return out.subarray(0, n);
}

// --- headers ------------------------------------------------------------------------------------

/** RFC 2047 encoded words decoded (adjacent words joined without the whitespace between them). */
export function decodeEncodedWords(value: string, problems?: MailProblem[]): string {
  if (!value.includes("=?")) return value;
  const word = /=\?([^?\s]{1,64})\?([bBqQ])\?([^?\s]*)\?=/g;
  let out = "";
  let last = 0;
  let prevWasWord = false;
  for (const m of value.matchAll(word)) {
    const between = value.slice(last, m.index);
    if (!(prevWasWord && /^\s*$/.test(between))) out += between;
    const charset = (m[1] as string).split("*")[0] as string; // RFC 2231 language suffix
    const data = toBytes(m[3] as string);
    const bytes = (m[2] as string).toLowerCase() === "b" ? decodeBase64(data) : decodeQuotedPrintable(data, true);
    out += decodeCharset(bytes, charset, problems);
    last = m.index + m[0].length;
    prevWasWord = true;
  }
  return out + value.slice(last);
}

/** Header fields kept per header block; past it the block was not fully read (`fields`). */
export const MAX_HEADERS = 2_000;

/**
 * Where a header block's unread text goes: lines that are not header fields (junk, an mbox `From ` line) are text a
 * model reading the source reads, so they are kept for an unshown channel; a block past MAX_HEADERS is a problem.
 */
interface HeaderSink {
  junk: string[];
  problems: MailProblem[];
}

function parseHeaderBlock(block: Uint8Array, sink?: HeaderSink): MailHeader[] {
  // Headers may carry raw UTF-8 (RFC 6532); anything else is read byte for byte.
  let text: string;
  try {
    text = (decoderFor("utf-8", true) as TextDecoder).decode(block);
  } catch {
    text = latin1(block);
  }
  const out: MailHeader[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (line === "") continue;
    if ((line.startsWith(" ") || line.startsWith("\t")) && out.length > 0) {
      const h = out[out.length - 1] as MailHeader;
      h.value += ` ${line.trim()}`;
      continue;
    }
    const colon = line.indexOf(":");
    const name = colon <= 0 ? "" : line.slice(0, colon).trim();
    if (!/^[\x21-\x39\x3b-\x7e]{1,128}$/.test(name)) {
      // An mbox "From " line or junk: no client shows it, a model reading the source does.
      if (line.trim() !== "") sink?.junk.push(line);
      continue;
    }
    if (out.length >= MAX_HEADERS) {
      sink?.problems.push({ kind: "fields", detail: `more than ${MAX_HEADERS} header fields; the rest were not read` });
      break;
    }
    out.push({ name, value: line.slice(colon + 1).trim() });
  }
  return out;
}

export function headerValue(headers: readonly MailHeader[], name: string): string | undefined {
  const n = name.toLowerCase();
  return headers.find((h) => h.name.toLowerCase() === n)?.value;
}

export function headerValues(headers: readonly MailHeader[], name: string): string[] {
  const n = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === n).map((h) => h.value);
}

/** A header's text as a person reads it (encoded words decoded). */
export function headerText(headers: readonly MailHeader[], name: string): string {
  const v = headerValue(headers, name);
  return v === undefined ? "" : decodeEncodedWords(v);
}

interface ContentType {
  type: string;
  params: Record<string, string>;
}

/** `type/subtype; a=b; c="d"`, with RFC 2231 continuations and charsets in parameter values. */
export function parseParams(value: string): ContentType {
  const parts: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i] as string;
    if (c === "\\" && quoted) {
      cur += value[i + 1] ?? "";
      i++;
      continue;
    }
    if (c === '"') quoted = !quoted;
    else if (c === ";" && !quoted) {
      parts.push(cur);
      cur = "";
      continue;
    }
    cur += c;
  }
  parts.push(cur);
  const type = (parts.shift() ?? "").trim().toLowerCase();
  const raw: Record<string, string> = {};
  for (const p of parts) {
    const eq = p.indexOf("=");
    if (eq <= 0) continue;
    const k = p.slice(0, eq).trim().toLowerCase();
    let v = p.slice(eq + 1).trim();
    if (v.startsWith('"') && v.endsWith('"') && v.length >= 2) v = v.slice(1, -1);
    setOwn(raw, k, v);
  }
  const params: Record<string, string> = {};
  const continued = new Map<string, { i: number; v: string; enc: boolean }[]>();
  for (const [k, v] of Object.entries(raw)) {
    const m = /^([^*]+)\*(\d+)?(\*)?$/.exec(k);
    if (m === null) {
      setOwn(params, k, v);
      continue;
    }
    const base = m[1] as string;
    const list = continued.get(base) ?? [];
    list.push({ i: m[2] === undefined ? 0 : Number(m[2]), v, enc: m[3] !== undefined || (m[2] === undefined && k.endsWith("*")) });
    continued.set(base, list);
  }
  for (const [base, list] of continued) {
    list.sort((a, b) => a.i - b.i);
    let charset = "utf-8";
    const bytes: number[] = [];
    list.forEach((piece, idx) => {
      let v = piece.v;
      if (piece.enc && idx === 0) {
        const q = /^([^']*)'[^']*'(.*)$/.exec(v);
        if (q !== null) {
          charset = (q[1] as string) || "utf-8";
          v = q[2] as string;
        }
      }
      if (piece.enc) {
        for (let i = 0; i < v.length; i++) {
          const h1 = v[i] === "%" ? hexVal(v.charCodeAt(i + 1)) : -1;
          const h2 = v[i] === "%" ? hexVal(v.charCodeAt(i + 2)) : -1;
          if (h1 >= 0 && h2 >= 0) {
            bytes.push((h1 << 4) | h2);
            i += 2;
          } else for (const b of toBytes(v[i] as string)) bytes.push(b);
        }
      } else for (const b of toBytes(v)) bytes.push(b);
    });
    setOwn(params, base, decodeCharset(Uint8Array.from(bytes), charset));
  }
  return { type, params };
}

// --- addresses ----------------------------------------------------------------------------------

export interface MailAddress {
  name: string;
  address: string;
}

/** Splits an address list on commas outside quotes, comments and angle brackets, and decodes display names. */
export function parseAddresses(value: string): MailAddress[] {
  const out: MailAddress[] = [];
  let cur = "";
  let depth = 0;
  let quoted = false;
  let angle = false;
  const flush = () => {
    const s = cur.trim().slice(0, 1 << 20); // bounded; the patterns below are linear (a 4096 cut dropped the "<address>" of a long display name)
    cur = "";
    if (s === "") return;
    const m = /^(.*?)<([^<>]*)>\s*(?:\(.{0,200}\))?$/.exec(s);
    if (m !== null) {
      out.push({ name: cleanName(m[1] as string), address: (m[2] as string).trim() });
      return;
    }
    const c = /^([^\s(]+)\s*\((.*)\)$/.exec(s);
    if (c !== null) out.push({ name: cleanName(c[2] as string), address: (c[1] as string).trim() });
    else out.push({ name: "", address: s.replace(/^"|"$/g, "") });
  };
  for (let i = 0; i < value.length; i++) {
    const ch = value[i] as string;
    if (ch === "\\" && quoted) {
      cur += ch + (value[i + 1] ?? "");
      i++;
      continue;
    }
    if (ch === '"' && depth === 0) quoted = !quoted;
    else if (!quoted && ch === "(") depth++;
    else if (!quoted && ch === ")" && depth > 0) depth--;
    else if (!quoted && depth === 0 && ch === "<") angle = true;
    else if (!quoted && depth === 0 && ch === ">") angle = false;
    if (ch === "," && !quoted && depth === 0 && !angle) {
      flush();
      continue;
    }
    cur += ch;
    if (out.length >= 200) break;
  }
  flush();
  return out;
}

function cleanName(s: string): string {
  let n = s.trim();
  if (n.startsWith('"') && n.endsWith('"') && n.length >= 2) n = n.slice(1, -1).replace(/\\(.)/g, "$1");
  return decodeEncodedWords(n).trim();
}

// --- MIME ---------------------------------------------------------------------------------------

function indexOfSeq(b: Uint8Array, seq: readonly number[], from: number): number {
  outer: for (let i = from; i <= b.length - seq.length; i++) {
    for (let k = 0; k < seq.length; k++) if (b[i + k] !== seq[k]) continue outer;
    return i;
  }
  return -1;
}

/** Header block and body of one entity (the first blank line separates them). */
function splitEntity(b: Uint8Array): { head: Uint8Array; body: Uint8Array } {
  // A message with no header block at all (starts with a blank line).
  if (b[0] === 0x0a) return { head: b.subarray(0, 0), body: b.subarray(1) };
  if (b[0] === 0x0d && b[1] === 0x0a) return { head: b.subarray(0, 0), body: b.subarray(2) };
  const crlf = indexOfSeq(b, [0x0d, 0x0a, 0x0d, 0x0a], 0);
  const lf = indexOfSeq(b, [0x0a, 0x0a], 0);
  if (crlf === -1 && lf === -1) return { head: b, body: b.subarray(b.length) };
  if (lf !== -1 && (crlf === -1 || lf < crlf)) return { head: b.subarray(0, lf), body: b.subarray(lf + 2) };
  return { head: b.subarray(0, crlf), body: b.subarray(crlf + 4) };
}

/** The parts of a multipart body between `--boundary` lines, and the preamble and epilogue around them. */
function splitMultipart(body: Uint8Array, boundary: string): { parts: Uint8Array[]; outside: Uint8Array[] } {
  const delim = toBytes(`--${boundary}`);
  // Buffer.indexOf is native: a naive scan with a long delimiter over a large body is quadratic.
  const delimBuf = Buffer.from(delim);
  const bodyBuf = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  const parts: Uint8Array[] = [];
  const outside: Uint8Array[] = [];
  const done = () => ({ parts, outside });
  let pos = 0;
  let start = -1;
  while (pos <= body.length) {
    const at = bodyBuf.indexOf(delimBuf, pos);
    if (at === -1) break;
    const lineStart = at === 0 || body[at - 1] === 0x0a;
    if (!lineStart) {
      pos = at + 1;
      continue;
    }
    if (start !== -1) {
      let end = at;
      if (body[end - 1] === 0x0a) end--;
      if (body[end - 1] === 0x0d) end--;
      parts.push(body.subarray(start, Math.max(start, end)));
      if (parts.length >= MIME_LIMITS.maxParts) return done();
    } else if (at > 0) outside.push(body.subarray(0, at)); // the preamble
    const after = at + delim.length;
    if (body[after] === 0x2d && body[after + 1] === 0x2d) {
      // Closing delimiter: whatever follows its line is the epilogue.
      let next = after + 2;
      while (next < body.length && body[next] !== 0x0a) next++;
      if (next + 1 < body.length) outside.push(body.subarray(next + 1));
      return done();
    }
    let next = after;
    while (next < body.length && body[next] !== 0x0a) next++;
    start = next + 1;
    pos = start;
  }
  // No closing delimiter: whatever followed the last one is a part too (error-tolerant, like mail clients).
  if (start !== -1 && start < body.length) parts.push(body.subarray(start));
  // No delimiter at all: the whole body is outside any part.
  if (start === -1 && body.length > 0) outside.push(body);
  return done();
}

function decodeTransfer(body: Uint8Array, cte: string | undefined): Uint8Array {
  const enc = (cte ?? "").trim().toLowerCase();
  if (enc === "base64") return decodeBase64(body);
  if (enc === "quoted-printable") return decodeQuotedPrintable(body);
  return body;
}

interface ParseState {
  parts: number;
  /**
   * Per message, the source text no channel reads otherwise: each part's own header fields (Content-Description,
   * X- fields, every Content-Type parameter) and the lines of a header block that are not fields. Added to the
   * message's unshown text when the parse ends, one piece per message.
   */
  unread: Map<MailMessage, string[]>;
}

function unreadText(st: ParseState, msg: MailMessage, line: string): void {
  let list = st.unread.get(msg);
  if (list === undefined) st.unread.set(msg, (list = []));
  list.push(line);
}

/**
 * HTML body types: text/html, XHTML, and the HTML variants some senders add as alternatives
 * (`text/x-amp-html` for AMP mail, `text/watch-html` and `text/x-watch-html` for watches). A model reads
 * every alternative, so each is scanned as HTML.
 */
export function isHtmlType(type: string): boolean {
  return type === "text/html" || type === "application/xhtml+xml" || /^text\/[\w.+-]{0,40}html$/.test(type);
}

function parseEntity(b: Uint8Array, depth: number, msg: MailMessage, st: ParseState, isTop: boolean, defaultType = "text/plain"): void {
  const { head, body } = splitEntity(b);
  const sink: HeaderSink = { junk: [], problems: msg.problems };
  const headers = parseHeaderBlock(head, sink);
  if (isTop) msg.headers = headers;
  // A part's own header fields have no channel (the message's top fields do: channels()), nor do junk lines.
  else for (const h of headers) unreadText(st, msg, `${h.name}: ${decodeEncodedWords(h.value)}`);
  for (const line of sink.junk) unreadText(st, msg, line);
  st.parts++;
  if (st.parts > MIME_LIMITS.maxParts) {
    if (!msg.problems.some((p) => p.kind === "parts")) msg.problems.push({ kind: "parts", detail: `more than ${MIME_LIMITS.maxParts} parts; the rest were not read` });
    return;
  }
  const ctRaw = headerValue(headers, "content-type");
  const ct = ctRaw === undefined ? { type: defaultType, params: { charset: "us-ascii" } } : parseParams(ctRaw);
  const type = ct.type === "" || !ct.type.includes("/") ? "text/plain" : ct.type;
  const disp = parseParams(headerValue(headers, "content-disposition") ?? "");
  const filename = decodeEncodedWords(disp.params.filename ?? ct.params.name ?? "", msg.problems);
  const cte = headerValue(headers, "content-transfer-encoding");

  if (type.startsWith("multipart/")) {
    const boundary = ct.params.boundary;
    if (boundary === undefined || boundary === "") {
      msg.problems.push({ kind: "malformed", detail: `${type} without a boundary; read as text` });
      msg.text.push(decodeCharset(body, "utf-8", msg.problems));
      return;
    }
    // RFC 2046: a boundary is at most 70 characters; a longer one is only a way to make the scan slow.
    if (boundary.length > 70) {
      msg.problems.push({ kind: "malformed", detail: `${type} with a boundary longer than 70 characters; read as text` });
      msg.text.push(decodeCharset(body, "utf-8", msg.problems));
      return;
    }
    if (depth >= MIME_LIMITS.maxDepth) {
      msg.problems.push({ kind: "depth", detail: `multipart nesting deeper than ${MIME_LIMITS.maxDepth}; the rest were not read` });
      return;
    }
    const childDefault = type === "multipart/digest" ? "message/rfc822" : "text/plain";
    const split = splitMultipart(body, boundary);
    for (const o of split.outside) {
      const text = decodeCharset(o, "utf-8");
      if (text.trim() !== "") (msg.unshown ??= []).push(text);
    }
    for (const part of split.parts) parseEntity(part, depth + 1, msg, st, false, childDefault);
    return;
  }
  if (type === "message/rfc822" || type === "message/global") {
    if (depth >= MIME_LIMITS.maxDepth) {
      msg.problems.push({ kind: "depth", detail: `forwarded messages nested deeper than ${MIME_LIMITS.maxDepth}; the rest were not read` });
      return;
    }
    const inner = emptyMessage();
    parseEntity(decodeTransfer(body, cte), depth + 1, inner, st, true);
    msg.nested.push(inner);
    if (filename !== "") msg.attachments.push({ filename, contentType: type, size: body.length });
    return;
  }
  const decoded = decodeTransfer(body, cte);
  const isAttachment = disp.type === "attachment" || (filename !== "" && disp.type !== "inline" && !type.startsWith("text/"));
  if (!isAttachment && (type === "text/plain" || type === "text/enriched" || type === "text/markdown")) {
    msg.text.push(decodeCharset(decoded, ct.params.charset, msg.problems));
    return;
  }
  if (!isAttachment && isHtmlType(type)) {
    msg.html.push(decodeCharset(decoded, ct.params.charset, msg.problems));
    if (filename !== "") msg.attachments.push({ filename, contentType: type, size: decoded.length });
    return;
  }
  if (type === "text/calendar" || type === "application/ics") {
    // Invites are read whether attached or inline: calendar clients show their description.
    addCalendar(msg, decodeCharset(decoded, ct.params.charset, msg.problems));
    if (filename !== "") msg.attachments.push({ filename, contentType: type, size: decoded.length });
    return;
  }
  if (!isAttachment && type.startsWith("text/")) {
    // Any other inline text part (text/rtf, text/csv, text/x-anything) reaches a model reading the message.
    msg.text.push(decodeCharset(decoded, ct.params.charset, msg.problems));
    if (filename !== "") msg.attachments.push({ filename, contentType: type, size: decoded.length });
    return;
  }
  // A text attachment's content is in the source a model reads (encoded or not): it is read too.
  if (type.startsWith("text/") || isHtmlType(type)) {
    const text = decodeCharset(decoded, ct.params.charset);
    if (text.trim() !== "") (msg.contents ??= []).push({ text, html: isHtmlType(type) });
  }
  msg.attachments.push({ filename, contentType: type, size: decoded.length });
}

/** Parses one RFC 5322 message (a string as returned by an API, or its bytes). */
export function parseMime(raw: string | Uint8Array, maxBytes = MIME_LIMITS.maxBytes): MailMessage {
  const msg = emptyMessage();
  const st: ParseState = { parts: 0, unread: new Map() };
  try {
    let b = typeof raw === "string" ? toBytes(raw) : raw;
    if (b.length > maxBytes) {
      msg.problems.push({ kind: "too_large", detail: `the message is ${b.length} bytes; the limit is ${maxBytes}` });
      // Headers only, so a withheld message can still be named by sender and subject.
      b = b.subarray(0, Math.min(b.length, 256 * 1024));
      msg.headers = parseHeaderBlock(splitEntity(b).head);
      return msg;
    }
    // An mbox "From " separator line is not a header, but a model reading the source reads it.
    if (b[0] === 0x46 && latin1(b, 0, 5) === "From ") {
      const nl = b.indexOf(0x0a);
      const line = decodeCharset(nl === -1 ? b : b.subarray(0, nl), "utf-8").trim();
      if (line !== "") unreadText(st, msg, line);
      b = nl === -1 ? b.subarray(b.length) : b.subarray(nl + 1);
    }
    parseEntity(b, 0, msg, st, true);
  } catch (e) {
    msg.problems.push({ kind: "malformed", detail: `the parser failed: ${(e as Error).message}`.slice(0, 200) });
  }
  for (const [m, lines] of st.unread) if (lines.length > 0) (m.unshown ??= []).push(lines.join("\n"));
  return msg;
}

/** Whether a string looks like a raw RFC 5322 message (a header block naming a sender or subject, then a body). */
export function looksLikeRawMessage(s: string): boolean {
  if (s.length < 20) return false;
  const head = s.slice(0, 64 * 1024);
  const end = head.search(/\r?\n\r?\n/);
  const block = end === -1 ? head : head.slice(0, end);
  const names = new Set<string>();
  for (const line of block.split(/\r?\n/).slice(0, 400)) {
    const m = /^([A-Za-z][A-Za-z0-9-]{0,60}):/.exec(line);
    if (m !== null) names.add((m[1] as string).toLowerCase());
    else if (!/^[ \t]/.test(line) && !line.startsWith("From ")) return false;
  }
  return (names.has("from") || names.has("subject")) && (names.has("date") || names.has("to") || names.has("message-id") || names.has("mime-version") || names.has("received") || names.has("content-type"));
}

// --- structured shapes --------------------------------------------------------------------------

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

/**
 * Which string leaves of a structured message object a channel read: an object (or a list) and the keys (indices) of
 * it whose string values went into a channel. Everything else in the object is read by the catch-all channel
 * (`field`), so a delivered object carries no string that no channel read.
 */
type Consumed = WeakMap<object, Set<string>>;

function consume(c: Consumed | undefined, o: object | undefined, k: string | number | undefined): void {
  if (c === undefined || o === undefined || k === undefined) return;
  let set = c.get(o);
  if (set === undefined) c.set(o, (set = new Set()));
  set.add(String(k));
}

/** The first key of `keys` whose own value is a string (the `a ?? b ?? c` the readers below use). */
const firstString = (o: Json, keys: readonly string[]): string | undefined => keys.find((k) => typeof own(o, k) === "string");

/** `{ name, address }`, Graph's `{ emailAddress: { name, address } }`, or a header-style string. */
function addressText(v: unknown, c?: Consumed, parent?: object, key?: string | number): string | undefined {
  if (typeof v === "string") {
    consume(c, parent, key);
    return v;
  }
  if (Array.isArray(v)) {
    const parts: string[] = [];
    v.forEach((x, i) => {
      const t = addressText(x, c, v, i);
      if (t !== undefined) parts.push(t);
    });
    return parts.length > 0 ? parts.join(", ") : undefined;
  }
  if (!isObj(v)) return undefined;
  const ea = own(v, "emailAddress");
  const inner = isObj(ea) ? ea : v;
  const nk = firstString(inner, ["name", "displayName"]);
  const ak = firstString(inner, ["address", "email", "emailAddress"]);
  const name = nk === undefined ? "" : (own(inner, nk) as string);
  const address = ak === undefined ? "" : (own(inner, ak) as string);
  if (name === "" && address === "") return undefined;
  consume(c, inner, nk);
  consume(c, inner, ak);
  if (name === "") return address;
  return `"${name.replace(/["\\]/g, "\\$&")}" <${address}>`;
}

/**
 * A header list from the shapes mail APIs use. With `c`, the strings that became headers are marked read; a header
 * block given as one string is not (lines the header parser skips would go unread), so the catch-all reads it too.
 */
export function headerList(v: unknown, c?: Consumed): MailHeader[] {
  const out: MailHeader[] = [];
  if (Array.isArray(v)) {
    for (const h of v) {
      if (!isObj(h)) continue;
      const nk = firstString(h, ["name", "key"]);
      const value = str(own(h, "value"));
      if (nk !== undefined && value !== undefined) {
        out.push({ name: own(h, nk) as string, value });
        consume(c, h, nk);
        consume(c, h, "value");
      }
    }
  } else if (isObj(v)) {
    for (const [name, value] of Object.entries(v)) {
      if (typeof value === "string") {
        out.push({ name, value });
        consume(c, v, name);
      } else if (Array.isArray(value)) {
        value.forEach((x, i) => {
          if (typeof x !== "string") return;
          out.push({ name, value: x });
          consume(c, value, i);
        });
      }
    }
  } else if (typeof v === "string") out.push(...parseHeaderBlock(toBytes(v)));
  return out;
}

/** The Gmail API's `payload` tree (`mimeType`, `headers`, `body.data` in base64url, `parts`). */
function gmailPayload(p: Json, msg: MailMessage, depth: number, c: Consumed): void {
  if (depth > MIME_LIMITS.maxDepth) {
    msg.problems.push({ kind: "depth", detail: `parts nested deeper than ${MIME_LIMITS.maxDepth}; the rest were not read` });
    return;
  }
  const type = (str(own(p, "mimeType")) ?? "text/plain").toLowerCase();
  // Read for the charset only: a part's headers are not a channel, so the catch-all reads them.
  const headers = headerList(own(p, "headers"));
  const filename = str(own(p, "filename")) ?? "";
  const pb = own(p, "body");
  const body: Json = isObj(pb) ? pb : {};
  const data = str(own(body, "data"));
  const charset = parseParams(headerValue(headers, "content-type") ?? "").params.charset ?? "utf-8";
  const parts = own(p, "parts");
  if (Array.isArray(parts)) {
    for (const child of parts) if (isObj(child)) gmailPayload(child, msg, depth + 1, c);
    return;
  }
  if (filename !== "" || (data === undefined && str(own(body, "attachmentId")) !== undefined)) {
    msg.attachments.push({ filename, contentType: type, size: typeof own(body, "size") === "number" ? (own(body, "size") as number) : 0 });
    consume(c, p, "filename");
    if (!READ_TYPES.has(type)) {
      // An attachment's content given inline is read decoded (see attachmentContent).
      if (data !== undefined) attachmentContent(msg, data, type, c, body, "data");
      return;
    }
  }
  if (data === undefined) return;
  const text = decodeCharset(decodeBase64(data), charset, msg.problems);
  if (isHtmlType(type)) msg.html.push(text);
  else if (type === "text/calendar") addCalendar(msg, text);
  else if (type.startsWith("text/")) msg.text.push(text);
  else if (type === "message/rfc822") msg.nested.push(parseMime(text));
  else return;
  // Only base64 that decodes whole is read whole: the tolerant decoder stops at "=" and skips junk, so anything
  // else is read as it is by the catch-all too.
  if (strictBase64(data)) consume(c, body, "data");
}

/**
 * Whether a string is base64 (or base64url) the decoder reads entirely: only the alphabet, no whitespace or junk, and
 * padding only at the end. The tolerant decoder skips anything else and stops at the first "=", so a field that is
 * not strictly base64 can carry text the decoded reading never saw.
 */
export function strictBase64(s: string): boolean {
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(s)) return false;
  const pad = s.endsWith("=");
  return pad ? s.length % 4 === 0 : s.length % 4 !== 1;
}

/** Base64 attachment content longer than this is not delivered (see elideAttachments), so it is not read either. */
export const MAX_ATTACHMENT_BASE64 = 1024 * 1024;

/**
 * An attachment's base64 content (Graph's `contentBytes`, a Gmail part's `body.data`), read decoded: a model can
 * decode base64, so its text reaches the model. Read up to MAX_ATTACHMENT_BASE64 (larger content is replaced by
 * elideAttachments); marked read only when it is strictly base64, so anything else is read as it is by the catch-all too.
 */
function attachmentContent(msg: MailMessage, data: string, type: string, c: Consumed, o: object, k: string): void {
  if (data === "" || data.length > MAX_ATTACHMENT_BASE64) return;
  // No charset problem is noted: binary content is read as Latin-1 (it cannot then hold hidden characters).
  const text = decodeCharset(decodeBase64(data), "utf-8");
  if (text.trim() !== "") (msg.contents ??= []).push({ text, html: isHtmlType(type) });
  if (strictBase64(data)) consume(c, o, k);
}

/** What stands in, in the result the agent gets, for base64 attachment content longer than MAX_ATTACHMENT_BASE64. */
export const elidedAttachment = (n: number): string => `[LaunchSafe Firewall: attachment content not shown (${n} characters of base64)]`;
export const ELIDED_ATTACHMENT = /^\[LaunchSafe Firewall: attachment content not shown \(\d+ characters of base64\)\]$/;

const isLargeBase64 = (v: unknown): v is string => typeof v === "string" && v.length > MAX_ATTACHMENT_BASE64;

/**
 * A message object with each base64 attachment content longer than MAX_ATTACHMENT_BASE64 (Graph's
 * `attachments[].contentBytes`, a Gmail attachment part's `body.data`) replaced by elidedAttachment(): content that
 * large is not read (it would pass the scanner's size bound and withhold the message), so it is not delivered either.
 * The same object when there is none; otherwise a copy (the input is never changed).
 */
export function elideAttachments(o: Json): Json {
  let out = o;
  const atts = own(o, "attachments");
  if (Array.isArray(atts)) {
    let changed = false;
    const next = atts.map((a) => {
      // A calendar or a forwarded message is read like the MIME part would be (fromStructured), so it is kept.
      if (!isObj(a) || !isLargeBase64(own(a, "contentBytes")) || READ_TYPES.has(attachmentType(a))) return a;
      changed = true;
      const copy: Json = { ...a };
      setOwn(copy, "contentBytes", elidedAttachment((own(a, "contentBytes") as string).length));
      return copy;
    });
    if (changed) {
      out = { ...out };
      setOwn(out, "attachments", next);
    }
  }
  const payload = own(o, "payload");
  if (isObj(payload)) {
    const p = elidePart(payload, 0);
    if (p !== payload) {
      if (out === o) out = { ...o };
      setOwn(out, "payload", p);
    }
  }
  return out;
}

function elidePart(p: Json, depth: number): Json {
  if (depth > MIME_LIMITS.maxDepth) return p;
  let out = p;
  const parts = own(p, "parts");
  if (Array.isArray(parts)) {
    const next = parts.map((x) => (isObj(x) ? elidePart(x, depth + 1) : x));
    if (next.some((x, i) => x !== parts[i])) {
      out = { ...p };
      setOwn(out, "parts", next);
    }
    return out;
  }
  const body = own(p, "body");
  const filename = str(own(p, "filename")) ?? "";
  const type = (str(own(p, "mimeType")) ?? "").toLowerCase();
  if (filename === "" || READ_TYPES.has(type) || !isObj(body) || !isLargeBase64(own(body, "data"))) return p;
  const b: Json = { ...body };
  setOwn(b, "data", elidedAttachment((own(body, "data") as string).length));
  out = { ...p };
  setOwn(out, "body", b);
  return out;
}

/** iCalendar lines (unfolded) a calendar part is read to; past it the part was not fully read (`fields`). */
export const MAX_CALENDAR_LINES = 20_000;

const calendarLines = (ics: string): string[] => ics.replace(/\r?\n[ \t]/g, "").split(/\r?\n/);

/** A calendar part, with a problem when it has more lines than are read. */
function addCalendar(msg: MailMessage, ics: string): void {
  msg.calendar.push(ics);
  if (calendarLines(ics).length > MAX_CALENDAR_LINES) msg.problems.push({ kind: "fields", detail: `a calendar part has more than ${MAX_CALENDAR_LINES} lines; the rest were not read` });
}

/** Keys that hold a message body in the shapes mail tools return (the splitter's shape test uses the same lists). */
export const TEXT_KEYS = ["text", "textBody", "text_body", "plain", "plainText", "plain_text", "bodyText", "body_text", "content", "body", "uniqueBody", "unique_body", "message"] as const;
export const HTML_KEYS = ["html", "htmlBody", "html_body", "bodyHtml", "body_html"] as const;
export const RAW_KEYS = ["raw", "source", "rfc822", "mime", "eml"] as const;
export const SNIPPET_KEYS = ["snippet", "bodyPreview", "summary"] as const;

/** Attachment types whose content is read like the MIME part would be (a calendar, a forwarded message). */
export const READ_TYPES: ReadonlySet<string> = new Set(["text/calendar", "message/rfc822"]);

/** An attachment object's declared type (`contentType`, `mimeType` or `type`), lower case. */
const attachmentType = (a: Json): string => (str(own(a, "contentType")) ?? str(own(a, "mimeType")) ?? str(own(a, "type")) ?? "").toLowerCase();

/**
 * Whether a string body is HTML (a structured body that does not say its type). The whole string is
 * searched: a tag that only starts past the first few kilobytes (a long plain preamble, or several pieces
 * joined for one scan) still makes it HTML, so a hidden element there is read as hidden, not as text.
 */
export function looksLikeHtml(s: string): boolean {
  return /<(?:!doctype\s+html|html|body|div|table|p|span|br|td|a\s|img\s|style|font|center)\b/i.test(s);
}

/** An RFC 5322 source given as is or in base64/base64url (the Gmail API's `format=raw`), or null. */
export function rawSource(v: unknown): string | null {
  if (typeof v !== "string" || v.length < 20) return null;
  if (looksLikeRawMessage(v)) return v;
  if (!/^[A-Za-z0-9+/_=\s-]+$/.test(v.slice(0, 4096))) return null;
  const s = latin1(decodeBase64(v));
  return looksLikeRawMessage(s) ? s : null;
}

/** The key of an object's raw RFC 5322 source (the first of RAW_KEYS that holds one), or undefined. */
export function rawKey(o: Json): (typeof RAW_KEYS)[number] | undefined {
  return RAW_KEYS.find((k) => rawSource(own(o, k)) !== null);
}

/**
 * A message object from a mail API or MCP server as a MailMessage. Unknown keys are not ignored: every string in
 * the object (and every object key) that no other channel read is read by the catch-all channel (`field`). `raw`
 * (an RFC 5322 source, plain or base64url as the Gmail API returns it) is parsed and merged.
 */
export function fromStructured(o: Json, maxBytes = MIME_LIMITS.maxBytes): MailMessage {
  const c: Consumed = new WeakMap();
  // A raw source wins: it is the whole message to the parser; every other field still reaches the model.
  const rk = rawKey(o);
  if (rk !== undefined) {
    const rv = own(o, rk) as string;
    const parsed = parseMime(rawSource(rv) as string, maxBytes);
    if (looksLikeRawMessage(rv) || strictBase64(rv)) consume(c, o, rk);
    const sk = SNIPPET_KEYS.find((x) => str(own(o, x)) !== undefined);
    if (sk !== undefined) {
      parsed.snippet = own(o, sk) as string;
      consume(c, o, sk);
    }
    return catchAll(parsed, o, c);
  }
  const msg = emptyMessage();
  const hk = (["headers", "internetMessageHeaders", "header"] as const).find((x) => own(o, x) !== undefined && own(o, x) !== null);
  msg.headers = hk === undefined ? [] : headerList(own(o, hk), c);
  const payload = own(o, "payload");
  if (isObj(payload)) {
    if (msg.headers.length === 0) msg.headers = headerList(own(payload, "headers"), c);
    gmailPayload(payload, msg, 0, c);
  }
  // Header-like fields given directly (generic shapes and Graph), added when the header list lacks them.
  const direct: [string, readonly string[]][] = [
    ["From", ["from", "sender", "From"]],
    ["Reply-To", ["replyTo", "reply_to", "reply-to"]],
    ["To", ["to", "toRecipients", "recipients"]],
    ["Cc", ["cc", "ccRecipients"]],
    ["Bcc", ["bcc", "bccRecipients"]],
    ["Subject", ["subject", "Subject", "title"]],
    ["Date", ["date", "receivedDateTime", "sentDateTime", "internalDate"]],
    ["Message-ID", ["messageId", "message_id", "internetMessageId"]],
  ];
  for (const [name, keys] of direct) {
    // Only the first key present is read (`a ?? b ?? c`); a later one is read by the catch-all.
    const key = keys.find((x) => own(o, x) !== undefined && own(o, x) !== null);
    if (key === undefined || headerValue(msg.headers, name) !== undefined) continue;
    const v = own(o, key);
    let t: string | undefined;
    if (name === "Subject" || name === "Date" || name === "Message-ID") {
      t = typeof v === "number" ? String(v) : str(v);
      if (typeof v === "string") consume(c, o, key);
    } else t = addressText(v, c, o, key);
    if (t !== undefined && t !== "") msg.headers.push({ name, value: t });
  }
  // Bodies.
  for (const k of HTML_KEYS) {
    const v = str(own(o, k));
    if (v === undefined) continue;
    consume(c, o, k);
    if (v !== "") msg.html.push(v);
  }
  for (const k of TEXT_KEYS) {
    const v = own(o, k);
    if (typeof v === "string") {
      consume(c, o, k);
      // A body under a key that does not say its type: text, or HTML, or both (pushUnknown).
      if (v !== "") pushUnknown(msg, v);
    } else if (isObj(v) && (typeof own(v, "content") === "string" || typeof own(v, "data") === "string")) {
      // Graph's { contentType: "html" | "text", content } (body and uniqueBody, the part new to the
      // thread, which a client may hand the model instead of body), or another API's { mimeType, data }.
      const ck = typeof own(v, "content") === "string" ? "content" : "data";
      const data = own(v, ck) as string;
      const content = ck === "content" ? data : decodeCharset(decodeBase64(data), "utf-8", msg.problems);
      // Base64 that does not decode whole is read as it is by the catch-all too (see strictBase64).
      if (ck === "content" || strictBase64(data)) consume(c, v, ck);
      const kind = String(own(v, "contentType") ?? own(v, "mimeType") ?? own(v, "type") ?? "").toLowerCase();
      if (kind.includes("html")) msg.html.push(content);
      else if (kind === "") pushUnknown(msg, content);
      else msg.text.push(content);
    }
  }
  const sk = SNIPPET_KEYS.find((k) => {
    const v = str(own(o, k));
    return v !== undefined && v !== "";
  });
  if (sk !== undefined) {
    msg.snippet = own(o, sk) as string;
    consume(c, o, sk);
  }
  const attachments = own(o, "attachments");
  if (Array.isArray(attachments)) {
    attachments.slice(0, 500).forEach((a, i) => {
      if (typeof a === "string") {
        msg.attachments.push({ filename: a, contentType: "", size: 0 });
        consume(c, attachments, i);
      } else if (isObj(a)) {
        const fk = firstString(a, ["filename", "name", "fileName"]);
        const filename = fk === undefined ? "" : (own(a, fk) as string);
        consume(c, a, fk);
        const contentType = attachmentType(a);
        msg.attachments.push({ filename, contentType, size: typeof own(a, "size") === "number" ? (own(a, "size") as number) : 0 });
        // An inline calendar or forwarded message given with its content is read like the MIME part would be; other
        // base64 content (`contentBytes`) is read decoded; any other content is read by the catch-all.
        const ck = firstString(a, ["contentBytes", "content"]);
        if (ck !== undefined && READ_TYPES.has(contentType)) {
          const content = own(a, ck) as string;
          const text = ck === "contentBytes" ? latin1(decodeBase64(content)) : content;
          if (contentType === "text/calendar") addCalendar(msg, text);
          else msg.nested.push(parseMime(text));
          if (ck === "content" || strictBase64(content)) consume(c, a, ck);
        } else if (ck === "contentBytes") attachmentContent(msg, own(a, ck) as string, contentType, c, a, ck);
      }
    });
  }
  return catchAll(msg, o, c);
}

/** RFC 5322 and ISO 8601 dates as mail tools give them: digits, month and day names, zones, nothing else. */
const DAY = "(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)";
const MONTH = "(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)";
export const RFC_DATE = new RegExp(`^(?:${DAY},? {1,3})?\\d{1,2} {1,3}${MONTH} {1,3}\\d{2,4} {1,3}\\d{1,2}:\\d{2}(?::\\d{2})?(?: {1,3}(?:[+-]\\d{4}|[A-Z]{1,5}))?(?: {1,3}\\([A-Za-z]{1,5}\\))?$`);
export const ISO_DATE = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/;

/** Digits, hex ids of one case (UUIDs too: only "a" to "f" can spell nothing an agent would act on), and dates. */
const OPAQUE = /^(?:[0-9]{1,64}|[0-9a-f-]{1,64}|[0-9A-F-]{1,64})$/;

/**
 * Strings that can spell nothing at all: empty, digits, hex ids, dates. The structural backstop (filter.ts) skips
 * only these; it reads every other string.
 */
export function isOpaqueToken(s: string): boolean {
  return s === "" || OPAQUE.test(s) || (s.length <= 64 && (ISO_DATE.test(s) || RFC_DATE.test(s)));
}

const PLAIN_CHARS = /^[A-Za-z0-9.:@/+=,#?&~_%-]{0,512}$/;
const PLAIN_WORD = /^(?:[A-Za-z0-9]{1,32}(?:@[A-Za-z0-9]{1,32}\.[A-Za-z]{2,16})?|(?:text|image|audio|video|application|multipart|message)\/[A-Za-z0-9]{1,32})$/;

/**
 * Strings the passes do not scan one by one (a scan of each would cost more than it can find): no space, markup,
 * hidden character or Markdown link, and no words a model reads as a phrase. That is ids, numbers and dates
 * (isOpaqueToken), and short tokens of letters (an address, a folder name, a MIME type) without word separators or a
 * run of more than 32 letters and digits (base64, or words run together). Everything else is scanned.
 */
export function isPlainToken(s: string): boolean {
  if (!PLAIN_CHARS.test(s)) return false;
  if (!/[A-Za-z]/.test(s) || isOpaqueToken(s)) return true;
  return PLAIN_WORD.test(s);
}
/** Fields scanned one by one; the rest of a message with more are scanned as one piece. */
const MAX_OTHER_FIELDS = 500;
/** Values (strings, objects, list items) and characters the catch-all reads; past either the message was not fully read. */
export const MAX_FIELD_NODES = 200_000;
export const MAX_FIELD_CHARS = 16 * 1024 * 1024;

/**
 * The catch-all channel: every string and every object key in the message object that no other channel read (`c`),
 * however deep, added to `msg.other`, so a delivered message object carries no text no channel read. Iterative, with
 * no depth bound and nothing serialized. Past MAX_FIELD_NODES values or MAX_FIELD_CHARS characters the walk stops and
 * the message is noted as not fully read (`fields`: withheld on the read path).
 */
function catchAll(msg: MailMessage, o: Json, c: Consumed): MailMessage {
  const found: string[] = [];
  let chars = 0;
  let nodes = 0;
  const stack: unknown[] = [o];
  const seen = new WeakSet<object>();
  const take = (s: string) => {
    found.push(s);
    chars += s.length;
  };
  while (stack.length > 0) {
    if (nodes++ >= MAX_FIELD_NODES || chars > MAX_FIELD_CHARS) {
      msg.problems.push({ kind: "fields", detail: `the message object has more than ${MAX_FIELD_NODES} values or ${MAX_FIELD_CHARS} characters; the rest were not read` });
      break;
    }
    const x = stack.pop();
    if (typeof x === "string") {
      if (!isPlainToken(x)) take(x);
      continue;
    }
    if (typeof x !== "object" || x === null || seen.has(x)) continue;
    seen.add(x);
    const used = c.get(x);
    if (Array.isArray(x)) {
      for (let i = x.length - 1; i >= 0; i--) if (!(typeof x[i] === "string" && used?.has(String(i)) === true)) stack.push(x[i]);
      continue;
    }
    const entries = Object.entries(x);
    for (const [k] of entries) if (!isPlainToken(k)) take(k);
    for (let i = entries.length - 1; i >= 0; i--) {
      const [k, y] = entries[i] as [string, unknown];
      if (!(typeof y === "string" && used?.has(k) === true)) stack.push(y);
    }
  }
  if (found.length === 0) return msg;
  msg.other = found.length > MAX_OTHER_FIELDS ? [...found.slice(0, MAX_OTHER_FIELDS), found.slice(MAX_OTHER_FIELDS).join("\n")] : found;
  return msg;
}

// --- channels -----------------------------------------------------------------------------------

export type ChannelName = "field" | "subject" | "from_name" | "reply_to" | "recipients" | "snippet" | "text" | "html" | "calendar" | "calendar_html" | "attachment_name" | "attachment_content" | "headers" | "preamble";

export interface Channel {
  name: ChannelName;
  /** "" for the message itself, "forwarded/1", "forwarded/1/forwarded/2" for nested ones. */
  path: string;
  text: string;
  html: boolean;
  /** No mail client displays this text (other headers, MIME preambles); a model reading the source does. */
  unshown?: boolean;
}

/** Address headers a mail client displays (their display names are read like the sender's). */
export const RECIPIENT_HEADERS: readonly string[] = ["to", "cc", "bcc", "sender", "resent-from", "resent-sender", "resent-to", "resent-cc", "resent-bcc"];
/** Headers that have channels of their own. */
const OWN_CHANNEL = new Set(["subject", "from", "reply-to", ...RECIPIENT_HEADERS]);

/** Calendar properties a calendar client displays (their values are read as displayed text). */
const SHOWN_PROPERTIES: ReadonlySet<string> = new Set(["SUMMARY", "DESCRIPTION", "LOCATION", "COMMENT", "CONTACT", "CATEGORIES", "RESOURCES", "URL", "ORGANIZER", "ATTENDEE"]);
/** iCalendar structure lines, which carry no text. */
const STRUCTURE = /^(?:BEGIN|END)$/;

/** One iCalendar content line: its name, its parameters (quoted values unquoted) and its value; null for a line that is not one. */
function contentLine(line: string): { name: string; params: [string, string][]; value: string } | null {
  const nm = /^[A-Za-z0-9-]{1,200}/.exec(line);
  if (nm === null) return null;
  const name = nm[0].toUpperCase();
  const params: [string, string][] = [];
  let i = nm[0].length;
  while (line[i] === ";") {
    const eq = line.indexOf("=", i + 1);
    if (eq === -1) return null;
    const pname = line.slice(i + 1, eq).toUpperCase();
    i = eq + 1;
    let v = "";
    // A parameter value is a list of values, each quoted or not; a quoted one may hold ";", ":" and ",".
    for (;;) {
      if (line[i] === '"') {
        const close = line.indexOf('"', i + 1);
        if (close === -1) return null;
        v += line.slice(i + 1, close);
        i = close + 1;
      } else {
        const m = /^[^";:,]*/.exec(line.slice(i)) as RegExpExecArray;
        v += m[0];
        i += m[0].length;
      }
      if (line[i] !== ",") break;
      v += ",";
      i++;
    }
    params.push([pname, v]);
  }
  if (line[i] !== ":") return null;
  return { name, params, value: line.slice(i + 1) };
}

const unescapeText = (v: string): string => v.replace(/\\([nN])/g, "\n").replace(/\\([,;\\])/g, "$1");

/**
 * Every text in an iCalendar document (content lines unfolded, values unescaped): the values and the CN parameter of
 * the properties a calendar client displays (SUMMARY, DESCRIPTION, LOCATION, COMMENT, CONTACT, CATEGORIES, RESOURCES,
 * URL, ORGANIZER, ATTENDEE) as text, X-ALT-DESC and any FMTTYPE=text/html value as HTML, and everything else (other
 * properties' values, X- properties, other parameters, lines that are not content lines) as `unshown`, text no client
 * displays but a model reading the source does. Only the first MAX_CALENDAR_LINES lines are read (the parser notes a
 * part with more: `fields`).
 */
export function calendarFields(ics: string): { text: string[]; html: string[]; unshown: string[] } {
  const lines = calendarLines(ics);
  const text: string[] = [];
  const html: string[] = [];
  const unshown: string[] = [];
  for (const line of lines.slice(0, MAX_CALENDAR_LINES)) {
    if (line.trim() === "") continue;
    const cl = contentLine(line);
    if (cl === null) {
      unshown.push(line);
      continue;
    }
    if (STRUCTURE.test(cl.name)) continue;
    const value = unescapeText(cl.value);
    const asHtml = cl.name === "X-ALT-DESC" || cl.params.some(([k, v]) => k === "FMTTYPE" && /text\/html/i.test(v));
    if (asHtml) html.push(value);
    else if (SHOWN_PROPERTIES.has(cl.name)) text.push(value);
    else unshown.push(`${cl.name}:${value}`);
    for (const [k, v] of cl.params) {
      if (v.trim() === "") continue;
      if (k === "CN" && SHOWN_PROPERTIES.has(cl.name)) text.push(v);
      else unshown.push(`${cl.name};${k}=${v}`);
    }
  }
  return { text, html, unshown };
}

/**
 * A provider's preview (Gmail `snippet`, Graph `bodyPreview`) is cut at a length, which can split a
 * flag emoji's tag sequence or a surrogate pair. The cut tail is dropped, so a truncated England flag
 * is not mistaken for smuggled tag characters.
 */
export function trimTruncation(s: string): string {
  return s.replace(/[\uD800-\uDBFF]$/, "").replace(/\u{1F3F4}[\u{E0020}-\u{E007E}]{0,6}$/u, "");
}

/** Every text channel of a message a model could read, nested messages included. */
export function channels(msg: MailMessage, path = ""): Channel[] {
  const out: Channel[] = [];
  const add = (name: ChannelName, text: string, html = false, unshown?: boolean) => {
    if (text.trim() === "") return;
    const base = unshown === true ? { name, path, text, unshown: true } : { name, path, text };
    out.push({ ...base, html });
    if (!html && MARKUP.test(text) && !(name === "text" && msg.html.includes(text))) out.push({ ...base, html: true });
  };
  add("subject", headerText(msg.headers, "subject"));
  // The whole From header decoded, not only the parsed display name: a sender may encode the address
  // into the encoded word too, and mail clients still show the decoded text.
  const from = headerValue(msg.headers, "from");
  if (from !== undefined) add("from_name", decodeEncodedWords(from));
  const replyTo = headerValue(msg.headers, "reply-to");
  if (replyTo !== undefined) add("reply_to", decodeEncodedWords(replyTo));
  // Every other header reaches a model that reads the raw source (or a header list): the address
  // headers as displayed text, the rest as text no mail client displays.
  const recipients: string[] = [];
  const others: string[] = [];
  const firstSeen = new Set<string>();
  for (const h of msg.headers) {
    const n = h.name.toLowerCase();
    const line = `${h.name}: ${decodeEncodedWords(h.value)}`;
    if (RECIPIENT_HEADERS.includes(n)) recipients.push(line);
    // A repeated Subject, From or Reply-To is not the one a client shows, but a model reads it too.
    else if (!OWN_CHANNEL.has(n) || firstSeen.has(n)) others.push(line);
    firstSeen.add(n);
  }
  add("recipients", recipients.join("\n"));
  if (others.length > 0 && others.join("").trim() !== "") add("headers", others.join("\n"), false, true);
  for (const u of msg.unshown ?? []) add("preamble", u, false, true);
  if (msg.snippet !== undefined) add("snippet", trimTruncation(msg.snippet));
  for (const t of msg.text) add("text", t);
  for (const h of msg.html) add("html", h, true);
  for (const c of msg.calendar) {
    const f = calendarFields(c);
    for (const t of f.text) add("calendar", t);
    for (const h of f.html) add("calendar_html", h, true);
    const u = f.unshown.join("\n");
    if (u.trim() !== "") add("calendar", u, false, true);
  }
  for (const a of msg.attachments) {
    add("attachment_name", a.filename);
    // A content type is shown with the attachment (renderMessage); one that is not a plain token is read like its name.
    if (!isPlainToken(a.contentType)) add("attachment_name", a.contentType);
  }
  for (const a of msg.contents ?? []) add("attachment_content", a.text, a.html);
  // A field's type is unknown: read as text, as HTML, or both (as pieceMessage reads a piece).
  for (const o of msg.other ?? []) {
    if (looksLikeHtml(o)) add("field", o, true);
    else add("field", o);
  }
  msg.nested.forEach((n, i) => out.push(...channels(n, `${path === "" ? "" : `${path}/`}forwarded/${i + 1}`)));
  return out;
}
