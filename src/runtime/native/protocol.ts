/**
 * The browser link's wire format (Chrome native messaging, docs/browser-link.md): each message is a
 * 32-bit length in native byte order (little-endian on every platform the firewall supports: x64 and
 * arm64 macOS and Linux) followed by that many bytes of UTF-8 JSON.
 *
 * Everything from the browser is checked against a strict schema before anything acts on it: a fixed set
 * of message types, no unknown keys, bounded strings and arrays, and a frame size limit read from the
 * length prefix before the body is buffered. A message that does not fit is a protocol error, and the host
 * fails closed (it answers with an error and exits; the browser sees the link drop).
 *
 * Pure: no file system, no process. host.ts drives it.
 */

export const HOST_NAME = "com.launchsafe.agent_firewall";
export const PROTOCOL_VERSION = 1;
/** The largest message accepted from the browser. Its messages are a log entry or a short notice. */
export const MAX_INCOMING_BYTES = 64 * 1024;
/** Chrome refuses a message from a host larger than 1 MB. */
export const MAX_OUTGOING_BYTES = 1024 * 1024;

export class ProtocolError extends Error {
  constructor(
    readonly code: "too_large" | "bad_frame" | "bad_message" | "version" | "order",
    message: string,
  ) {
    super(message);
    this.name = "ProtocolError";
  }
}

/** Splits a byte stream into messages. Throws ProtocolError for an oversized frame (before reading its body) or bytes that are not JSON. */
export class FrameDecoder {
  private buf: Buffer = Buffer.alloc(0);

  push(chunk: Buffer): unknown[] {
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
    const out: unknown[] = [];
    for (;;) {
      if (this.buf.length < 4) return out;
      const len = this.buf.readUInt32LE(0);
      if (len > MAX_INCOMING_BYTES) throw new ProtocolError("too_large", `a browser message must be at most ${MAX_INCOMING_BYTES} bytes; this one says ${len}`);
      if (len === 0) throw new ProtocolError("bad_frame", "an empty browser message");
      if (this.buf.length < 4 + len) return out;
      const body = this.buf.subarray(4, 4 + len);
      this.buf = this.buf.subarray(4 + len);
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(body);
      } catch {
        throw new ProtocolError("bad_frame", "a browser message is not valid UTF-8");
      }
      try {
        out.push(JSON.parse(text) as unknown);
      } catch {
        throw new ProtocolError("bad_frame", "a browser message is not JSON");
      }
    }
  }

  /** Bytes of a message that has not arrived whole (the browser closed mid-message). */
  get pending(): number {
    return this.buf.length;
  }
}

/** One message as Chrome expects it from a host. Throws when it is too large (a bug: every message the host sends is small). */
export function encodeFrame(msg: HostMessage): Buffer {
  const body = Buffer.from(JSON.stringify(msg), "utf8");
  if (body.length > MAX_OUTGOING_BYTES) throw new Error(`a message to the browser must be at most ${MAX_OUTGOING_BYTES} bytes`);
  const head = Buffer.alloc(4);
  head.writeUInt32LE(body.length, 0);
  return Buffer.concat([head, body]);
}

// ---- the messages ------------------------------------------------------------------------------------

/** A browser decision as the extension's own log keeps it (its design section 9): never page text or field values. */
export interface BrowserLogEntry {
  /** The entry's place in the extension's own hash chain, so the two logs can be matched. */
  seq: number;
  hash: string;
  prevHash: string;
  /** ms since the epoch, as the extension recorded it. */
  at: number;
  /** The registrable domain of the site ("" when none). */
  site: string;
  actionClass: string | null;
  verdict: string;
  rules: string[];
  approval?: string;
  binding?: string;
  event?: string;
  detail?: string[];
}

export type BrowserMessage =
  | { type: "hello"; nonce: string; version: number; capabilities: string[]; extension: string }
  | { type: "log.append"; nonce: string; entry: BrowserLogEntry }
  | { type: "state.taint"; nonce: string; session: string; reason: string }
  | { type: "approval.request"; nonce: string; binding: string; action: { kind: string; actionClass: string | null; site: string; label: string }; surface: "firewall" }
  | { type: "approval.cancel"; nonce: string; binding: string };

export type HostMessage =
  | { type: "hello"; re: string; version: number; capabilities: string[]; firewall: string }
  | { type: "log.ack"; re: string; seq: number }
  | { type: "ack"; re: string }
  | { type: "approval.queued"; re: string; id: string }
  | { type: "approval.result"; nonce: string; binding: string; verdict: "approve" | "deny"; sig?: string }
  | { type: "state.taint"; nonce: string; session: string; reason: string }
  | { type: "error"; re?: string; code: string; message: string };

/** What the host can do for this browser: sent in its hello. "approval" only when a person can approve (an approval passphrase is set). */
export type HostCapability = "log" | "taint" | "approval";

const NONCE = /^[A-Za-z0-9_-]{8,64}$/;
const CODE = /^[a-z][a-z0-9_]{0,39}$/;
const RULE = /^[a-z][a-z0-9_.]{0,63}$/;
const DETAIL = /^[A-Za-z0-9_.:-]{1,64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const BINDING = /^[0-9a-f]{16,128}$/;
const SESSION = /^[A-Za-z0-9_-]{1,64}$/;
/** A registrable domain or host: lower-case letters, digits, dots and hyphens (punycode for the rest). */
const SITE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const VERSION_STRING = /^\d{1,5}(?:\.\d{1,5}){0,3}$/;
const APPROVAL_OUTCOMES = new Set(["approved", "denied", "expired", "redeemed", "refused"]);
const MAX_RULES = 16;
const MAX_DETAIL = 16;
const MAX_CAPABILITIES = 16;
const MAX_LABEL = 200;

type Obj = Record<string, unknown>;

function isObj(x: unknown): x is Obj {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function bad(message: string): never {
  throw new ProtocolError("bad_message", message);
}

/** The object, if it has exactly the required keys and no others besides the optional ones. */
function shape(x: unknown, what: string, required: readonly string[], optional: readonly string[] = []): Obj {
  if (!isObj(x)) bad(`${what} is not an object`);
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(x, k)) bad(`${what} has no ${k}`);
  for (const k of Object.keys(x)) if (!required.includes(k) && !optional.includes(k)) bad(`${what} has an unknown field ${JSON.stringify(k.slice(0, 40))}`);
  return x;
}

function str(x: unknown, re: RegExp, what: string): string {
  if (typeof x !== "string" || !re.test(x)) bad(`${what} is not valid`);
  return x;
}

function int(x: unknown, what: string, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof x !== "number" || !Number.isInteger(x) || x < min || x > max) bad(`${what} is not a whole number in range`);
  return x;
}

function list(x: unknown, re: RegExp, max: number, what: string): string[] {
  if (!Array.isArray(x) || x.length > max) bad(`${what} is not a list of at most ${max}`);
  return x.map((v, i) => str(v, re, `${what}[${i}]`));
}

/** A label the person reads in their terminal: printable, no control or format characters, bounded. */
function label(x: unknown): string {
  if (typeof x !== "string" || x.length === 0 || x.length > MAX_LABEL) bad("action.label is not valid");
  // eslint-disable-next-line no-control-regex -- refusing control characters is the point
  if (/[\u0000-\u001f\u007f-\u009f]|\p{Cf}|\p{Zl}|\p{Zp}/u.test(x)) bad("action.label holds control or invisible characters");
  return x;
}

function site(x: unknown, what: string): string {
  if (x === "") return "";
  if (typeof x !== "string" || x.length > 253) bad(`${what} is not valid`);
  return str(x, SITE, what);
}

function logEntry(x: unknown): BrowserLogEntry {
  const o = shape(x, "entry", ["seq", "hash", "prevHash", "at", "site", "actionClass", "verdict", "rules"], ["approval", "binding", "event", "detail"]);
  const e: BrowserLogEntry = {
    seq: int(o.seq, "entry.seq"),
    hash: str(o.hash, HEX64, "entry.hash"),
    prevHash: str(o.prevHash, HEX64, "entry.prevHash"),
    at: int(o.at, "entry.at", 0, 8.64e15),
    site: site(o.site, "entry.site"),
    actionClass: o.actionClass === null ? null : str(o.actionClass, CODE, "entry.actionClass"),
    verdict: str(o.verdict, CODE, "entry.verdict"),
    rules: list(o.rules, RULE, MAX_RULES, "entry.rules"),
  };
  if (o.approval !== undefined) {
    if (typeof o.approval !== "string" || !APPROVAL_OUTCOMES.has(o.approval)) bad("entry.approval is not valid");
    e.approval = o.approval;
  }
  if (o.binding !== undefined) e.binding = str(o.binding, BINDING, "entry.binding");
  if (o.event !== undefined) e.event = str(o.event, CODE, "entry.event");
  if (o.detail !== undefined) e.detail = list(o.detail, DETAIL, MAX_DETAIL, "entry.detail");
  return e;
}

/** A message from the browser, checked field by field. Throws ProtocolError("bad_message") for anything else. */
export function parseBrowserMessage(x: unknown): BrowserMessage {
  if (!isObj(x) || typeof x.type !== "string") bad("a message has no type");
  const type = x.type;
  switch (type) {
    case "hello": {
      const o = shape(x, "hello", ["type", "nonce", "version", "capabilities", "extension"]);
      return { type: "hello", nonce: str(o.nonce, NONCE, "nonce"), version: int(o.version, "version", 0, 1000), capabilities: list(o.capabilities, CODE, MAX_CAPABILITIES, "capabilities"), extension: str(o.extension, VERSION_STRING, "extension") };
    }
    case "log.append": {
      const o = shape(x, "log.append", ["type", "nonce", "entry"]);
      return { type: "log.append", nonce: str(o.nonce, NONCE, "nonce"), entry: logEntry(o.entry) };
    }
    case "state.taint": {
      const o = shape(x, "state.taint", ["type", "nonce", "session", "reason"]);
      return { type: "state.taint", nonce: str(o.nonce, NONCE, "nonce"), session: str(o.session, SESSION, "session"), reason: str(o.reason, CODE, "reason") };
    }
    case "approval.request": {
      const o = shape(x, "approval.request", ["type", "nonce", "binding", "action", "surface"]);
      const a = shape(o.action, "action", ["kind", "actionClass", "site", "label"]);
      if (o.surface !== "firewall") bad("surface is not valid");
      return {
        type: "approval.request",
        nonce: str(o.nonce, NONCE, "nonce"),
        binding: str(o.binding, BINDING, "binding"),
        action: { kind: str(a.kind, CODE, "action.kind"), actionClass: a.actionClass === null ? null : str(a.actionClass, CODE, "action.actionClass"), site: site(a.site, "action.site"), label: label(a.label) },
        surface: "firewall",
      };
    }
    case "approval.cancel": {
      const o = shape(x, "approval.cancel", ["type", "nonce", "binding"]);
      return { type: "approval.cancel", nonce: str(o.nonce, NONCE, "nonce"), binding: str(o.binding, BINDING, "binding") };
    }
    default:
      return bad(`unknown message type ${JSON.stringify(String(type).slice(0, 40))}`);
  }
}

/** The extension id in a `chrome-extension://<id>/` origin (32 letters a to p), or null. */
export function extensionIdOf(origin: string): string | null {
  return /^chrome-extension:\/\/([a-p]{32})\/$/.exec(origin)?.[1] ?? null;
}

export function isExtensionId(id: string): boolean {
  return /^[a-p]{32}$/.test(id);
}
