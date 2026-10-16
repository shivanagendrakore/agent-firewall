/**
 * The read-path mail filter (email guard, read-path mode): what a
 * mail tool returned, made safe for the agent.
 *
 * The **message splitter** finds the messages in a tool result whatever its
 * shape: MCP content blocks whose text is JSON, `structuredContent`, Gemini
 * CLI's `llmContent`, a JSON string, a list of message objects (or one), a
 * container of them (`messages`, `emails`, `value`, `items`, `results`,
 * `data`, `threads`), and raw RFC 5322 sources. A message-like object has a
 * body of some kind and a sender, a subject (directly or in its headers) or a
 * key only mail has (`payload`, `threadId`, `toRecipients`, ...). Each message
 * is scanned with the email detector, then:
 *
 * - a withheld message is replaced in place by a stub (`from`, `subject`,
 *   `date`, `withheld: "LaunchSafe Firewall withheld this message: ...
 *   Record <id>."`); its sender and subject are shown only as the exact text a
 *   scan of that text found clean, and are `[withheld]` otherwise;
 * - a neutralized message has its hidden parts stripped (every string value,
 *   so the JSON stays valid; a raw source is rendered as its readable parts);
 * - the rest pass unchanged.
 *
 * Strings of a split result outside its message objects (a thread snippet, a
 * folder name, object keys) are scanned one by one: a withheld one is replaced
 * by a notice and recorded, a neutralized one stripped.
 *
 * A result the splitter cannot read as messages is scanned whole with C0; a
 * quarantine verdict then withholds the whole result (fail closed), and the
 * record says the split was not possible.
 *
 * The rule throughout: nothing reaches the agent unless a pass read that very
 * text (a string no pass could read is replaced by a note the firewall writes).
 * On the read path a structural backstop holds the rule as an invariant: once
 * the output is built, every string and key in it that the firewall did not
 * write is scanned once more, and a hidden instruction there, or a walk that
 * cannot finish, withholds the whole result.
 *
 * The same function serves the hooks today and the MCP gateway's mail
 * filter later. Pure: record ids come from the caller's `record` callback.
 */
import { createHash } from "node:crypto";
import { SCAN_LIMITS, scanContent, workBudget, type ScanResult, type WorkBudget } from "../content-scan.js";
import { canonicalJson, isDirected, readMessage, scanMail, signalNames, type MailScan, type MailScanOptions } from "./detect.js";
import { calendarFields, decodeBase64, decodeCharset, decodeEncodedWords, ELIDED_ATTACHMENT, elideAttachments, fromStructured, headerList, headerText, headerValue, HTML_KEYS, isHtmlType, ISO_DATE, isOpaqueToken, isPlainToken, looksLikeHtml, looksLikeRawMessage, MARKUP, MAX_ATTACHMENT_BASE64, MAX_CALENDAR_LINES, MIME_LIMITS, parseMime, parseParams, pieceMessage, RAW_KEYS, rawKey, READ_TYPES, RFC_DATE, SNIPPET_KEYS, strictBase64, TEXT_KEYS, trimTruncation, type MailMessage, type MailProblem } from "./mime.js";
import { own, setOwn } from "../../own.js";

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

/** Keys that mark a sender, a subject and a body in the shapes mail tools return. */
const FROM_KEYS = ["from", "sender", "From", "fromAddress", "from_address"] as const;
const SUBJECT_KEYS = ["subject", "Subject"] as const;
/** Every key the parser reads a body from (mime.ts), and the header lists and payloads it reads. */
const BODY_KEYS: readonly string[] = [...TEXT_KEYS, ...HTML_KEYS, ...RAW_KEYS, ...SNIPPET_KEYS, "headers", "internetMessageHeaders", "preview"];
/** Keys of a container wrapping a list of messages or threads (not one message itself, even when it has a snippet or subject). */
const CONTAINER_KEYS = ["messages", "emails", "value", "items", "results", "data", "threads"] as const;
/** Keys a Gmail API `payload` tree carries. */
const PAYLOAD_KEYS = ["mimeType", "headers", "parts", "body"] as const;
const MAX_DEPTH = 12;
const MAX_MESSAGES = 500;
/** Read path: how deep the splitter still looks for messages past MAX_DEPTH (they are handled one by one); deeper, the result is withheld. */
const MAX_SEARCH_DEPTH = 1_000;
/** Strings the passes do not scan one by one (mime.ts isPlainToken: ids, numbers, dates, short tokens with no word separators). */
const PLAIN_TOKEN = { test: (s: string) => !s.includes("=?") && isPlainToken(s) } as const;

function headerNames(v: unknown): Set<string> {
  const out = new Set<string>();
  if (Array.isArray(v)) for (const h of v) if (isObj(h) && typeof h.name === "string") out.add(h.name.toLowerCase());
  if (isObj(v)) for (const k of Object.keys(v)) out.add(k.toLowerCase());
  return out;
}

/** Keys only a mail message has (next to a body, they make an object a message even with no sender or subject). */
const MAIL_ONLY_KEYS = ["to", "cc", "toRecipients", "ccRecipients", "messageId", "message_id", "internetMessageId", "threadId", "receivedDateTime", "internetMessageHeaders"] as const;

/**
 * Whether an object is one mail message (the splitter's shape test): a body of some kind, and a sender, a subject or
 * a key only mail has. A sender or subject counts when its key is there, even empty: an empty subject does not make a
 * message something else (its strings would then be judged one by one, apart from the message they belong to).
 */
export function isMessageLike(o: Json): boolean {
  if (CONTAINER_KEYS.some((k) => { const v = own(o, k); return Array.isArray(v) && v.some((x) => isObj(x) || (typeof x === "string" && looksLikeRawMessage(x))); })) return false;
  if (rawKey(o) !== undefined) return true;
  const present = (keys: readonly string[]) => keys.some((k) => own(o, k) !== undefined && own(o, k) !== null);
  const payload = own(o, "payload");
  const hasPayload = isObj(payload) && PAYLOAD_KEYS.some((k) => own(payload, k) !== undefined && own(payload, k) !== null);
  const mailOnly = present(MAIL_ONLY_KEYS) || hasPayload;
  // An "author" or a "title" alone is too common (issues, documents, comments): each counts as a sender or a subject
  // only next to a mail-only key.
  let from = present(FROM_KEYS) || (present(["author"]) && mailOnly);
  let subject = present(SUBJECT_KEYS) || (present(["title"]) && mailOnly);
  // Headers given as a list or map (Graph's internetMessageHeaders, the Gmail API's payload.headers).
  for (const h of [own(o, "headers"), own(o, "internetMessageHeaders"), hasPayload ? own(payload, "headers") : undefined]) {
    const names = headerNames(h);
    if (names.has("from")) from = true;
    if (names.has("subject")) subject = true;
  }
  const body = hasPayload || BODY_KEYS.some((k) => own(o, k) !== undefined && own(o, k) !== null);
  return body && (from || subject || mailOnly);
}

// --- rewriting ----------------------------------------------------------------------------------

/** What stands in for a string whose rewriting scan was cut short. */
export const NOT_FULLY_SCANNED = "[LaunchSafe Firewall: this text could not be fully scanned, so it is not shown]";

/**
 * One string with its hidden parts stripped. A scan cut short by a bound (its clock, its size) stripped only
 * what it read, so the string is replaced rather than delivered half-cleaned (fail closed). `budget` is the
 * message's work budget when the string belongs to a scanned message (the rewriting pass draws on it too).
 */
function neutralizeText(s: string, html: boolean, budget?: WorkBudget): string {
  const problems: MailProblem[] = [];
  let t = s;
  for (let i = 0; i < 2 && t.includes("=?"); i++) {
    const next = decodeEncodedWords(t, problems);
    if (problems.length > 0) return NOT_FULLY_SCANNED;
    if (next === t) break;
    t = next;
  }
  const modes = html && looksLikeHtml(t) ? [true] : html || MARKUP.test(t) ? [false, true] : [false];
  for (const h of modes) {
    const r = scanContent(t, { html: h, ...(budget !== undefined ? { budget } : {}) });
    if (r.signals.some((x) => x.id === "scan_incomplete")) return NOT_FULLY_SCANNED;
    if (r.neutralized !== undefined) t = r.neutralized;
  }
  if (t.includes("=?") && decodeEncodedWords(t) !== t) return NOT_FULLY_SCANNED;
  return t;
}

/**
 * An object's entries with their keys rewritten: a key is text the agent reads like any value, so it has its hidden
 * parts stripped on the same budget. A key the rewrite could not read (the budget ran out, a bound cut it short) is
 * not passed on unread: it is replaced by a placeholder the firewall writes, `[key withheld N]`, unique in the
 * object (as is a stripped key that would collide with another). Keys that cannot hide anything (PLAIN_TOKEN) are
 * kept as they are without a scan.
 */
function rewriteEntries(v: Json, budget: WorkBudget | undefined, value: (x: unknown, k: string) => unknown): { next: Json; changed: boolean } {
  const next: Json = {};
  let changed = false;
  let n = 0;
  for (const [k, x] of Object.entries(v)) {
    let key = k.length === 0 || PLAIN_TOKEN.test(k) ? k : neutralizeText(k, false, budget);
    if (key === NOT_FULLY_SCANNED) key = `[key withheld ${++n}]`;
    while (Object.hasOwn(next, key)) key = `[key withheld ${++n}]`;
    const y = value(x, k);
    if (key !== k || y !== x) changed = true;
    setOwn(next, key, y);
  }
  return { next, changed };
}

const TEXT_KEY_SET: ReadonlySet<string> = new Set<string>(TEXT_KEYS);

function isPayloadLike(v: Json): boolean {
  return (
    Array.isArray(own(v, "parts")) ||
    (isObj(own(v, "body")) &&
      typeof own(own(v, "body") as Json, "data") === "string" &&
      (typeof own(v, "mimeType") === "string" || own(v, "headers") !== undefined || typeof own(v, "filename") === "string"))
  );
}

function reencodeBase64(clean: string, original: string, urlDefault: boolean): string {
  if (clean === NOT_FULLY_SCANNED) return NOT_FULLY_SCANNED;
  const isUrl = urlDefault ? !/[+/=]/.test(original) : /[-_]/.test(original) && !/[+/=]/.test(original);
  return Buffer.from(clean, "utf8").toString(isUrl ? "base64url" : "base64");
}

function neutralizeEncodedData(
  data: string,
  opts: { charset?: string; isHtml: boolean; kind: "text" | "calendar" | "rfc822" | "attachment"; urlDefault: boolean },
  budget?: WorkBudget,
): string {
  if (data === "" || ELIDED_ATTACHMENT.test(data)) return data;
  if (opts.kind === "attachment") {
    if (data.length > MAX_ATTACHMENT_BASE64) return NOT_FULLY_SCANNED;
    const text = decodeCharset(decodeBase64(data), "utf-8");
    if (text.trim() === "") return strictBase64(data) ? data : neutralizeText(data, MARKUP.test(data), budget);
    const clean = neutralizeText(text, opts.isHtml || MARKUP.test(text), budget);
    if (clean === text && strictBase64(data)) return data;
    return reencodeBase64(clean, data, opts.urlDefault);
  }
  const problems: MailProblem[] = [];
  const text = decodeCharset(decodeBase64(data), opts.charset ?? "utf-8", problems);
  if (problems.length > 0) return NOT_FULLY_SCANNED;
  if (opts.kind === "rfc822") {
    const parsed = parseMime(text);
    if (parsed.problems.length > 0) return NOT_FULLY_SCANNED;
    const rendered = renderMessage(parsed, 0, budget);
    if (rendered.includes(NOT_FULLY_SCANNED)) return NOT_FULLY_SCANNED;
    return reencodeBase64(rendered, data, opts.urlDefault);
  }
  if (opts.kind === "calendar") {
    const unfolded = text.replace(/\r?\n[ \t]/g, "");
    if (unfolded.split(/\r?\n/).length > MAX_CALENDAR_LINES) return NOT_FULLY_SCANNED;
    const clean = neutralizeText(unfolded, true, budget);
    if (clean === unfolded && strictBase64(data)) return data;
    return reencodeBase64(clean, data, opts.urlDefault);
  }
  const clean = neutralizeText(text, opts.isHtml || MARKUP.test(text), budget);
  if (clean === text && strictBase64(data)) return data;
  return reencodeBase64(clean, data, opts.urlDefault);
}

function rewriteNode(v: unknown, budget: WorkBudget | undefined, depth: number, maxDepth: number, keep: boolean, partDepth?: number, inAttachments?: boolean): unknown {
  if (depth > maxDepth || (partDepth !== undefined && partDepth > MIME_LIMITS.maxDepth)) {
    if (typeof v === "string") return v.length === 0 ? v : NOT_FULLY_SCANNED;
    return typeof v === "object" && v !== null ? NOT_FULLY_SCANNED : v;
  }
  if (typeof v === "string") {
    if (v.length === 0) return v;
    return neutralizeText(v, MARKUP.test(v), budget);
  }
  if (Array.isArray(v)) {
    const next = v.map((x) => rewriteNode(x, budget, depth + 1, maxDepth, keep));
    return keep && !next.some((y, i) => y !== v[i]) ? v : next;
  }
  if (!isObj(v)) return v;
  const pDepth = partDepth ?? (isPayloadLike(v) ? 0 : undefined);
  const rawType = (typeof own(v, "contentType") === "string" ? (own(v, "contentType") as string) : typeof own(v, "mimeType") === "string" ? (own(v, "mimeType") as string) : typeof own(v, "type") === "string" ? (own(v, "type") as string) : "").toLowerCase();
  const type = parseParams(rawType).type || rawType;
  const { next, changed } = rewriteEntries(v, budget, (x, k) => {
    if (k === "payload" && isObj(x)) return rewriteNode(x, budget, depth + 1, maxDepth, keep, 0);
    if (pDepth !== undefined && k === "parts" && Array.isArray(x)) {
      if (depth + 1 > maxDepth) return NOT_FULLY_SCANNED;
      const items = x.map((c) => (isObj(c) ? rewriteNode(c, budget, depth + 2, maxDepth, keep, pDepth + 1) : rewriteNode(c, budget, depth + 2, maxDepth, keep)));
      return keep && !items.some((y, i) => y !== x[i]) ? x : items;
    }
    if (k === "attachments" && Array.isArray(x)) {
      if (depth + 1 > maxDepth) return NOT_FULLY_SCANNED;
      const items = x.map((a) => (isObj(a) ? rewriteNode(a, budget, depth + 2, maxDepth, keep, undefined, true) : rewriteNode(a, budget, depth + 2, maxDepth, keep)));
      return keep && !items.some((y, i) => y !== x[i]) ? x : items;
    }
    if (TEXT_KEY_SET.has(k) && isObj(x) && typeof own(x, "content") !== "string" && typeof own(x, "data") === "string") {
      if (depth + 1 > maxDepth) return NOT_FULLY_SCANNED;
      const asPayload = pDepth !== undefined && k === "body";
      const pType = type || "text/plain";
      const filename = typeof own(v, "filename") === "string" ? (own(v, "filename") as string) : "";
      const charset = asPayload ? (parseParams(headerValue(headerList(own(v, "headers")), "content-type") ?? "").params.charset ?? "utf-8") : "utf-8";
      const bKind = String(own(x, "contentType") ?? own(x, "mimeType") ?? own(x, "type") ?? "").toLowerCase();
      const kind: "text" | "calendar" | "rfc822" | "attachment" = asPayload
        ? filename !== "" && !READ_TYPES.has(pType)
          ? "attachment"
          : pType === "message/rfc822"
            ? "rfc822"
            : pType === "text/calendar"
              ? "calendar"
              : "text"
        : "text";
      const isHtml = asPayload ? isHtmlType(pType) : bKind.includes("html");
      const sub = rewriteEntries(x, budget, (bx, bk) => {
        if (bk === "data" && typeof bx === "string") {
          if (depth + 2 > maxDepth) return bx.length === 0 ? bx : NOT_FULLY_SCANNED;
          return neutralizeEncodedData(bx, { charset, isHtml, kind, urlDefault: asPayload }, budget);
        }
        return rewriteNode(bx, budget, depth + 2, maxDepth, keep);
      });
      return keep && !sub.changed ? x : sub.next;
    }
    if (k === "contentBytes" && typeof x === "string") {
      if (depth + 1 > maxDepth) return x.length === 0 ? x : NOT_FULLY_SCANNED;
      const kind = type === "message/rfc822" ? "rfc822" : type === "text/calendar" ? "calendar" : "attachment";
      const charset = READ_TYPES.has(type) ? "iso-8859-1" : "utf-8";
      return neutralizeEncodedData(x, { charset, isHtml: isHtmlType(type) || rawType.includes("html"), kind, urlDefault: false }, budget);
    }
    if (inAttachments && k === "content" && typeof x === "string" && typeof own(v, "contentBytes") !== "string" && READ_TYPES.has(type)) {
      if (depth + 1 > maxDepth) return x.length === 0 ? x : NOT_FULLY_SCANNED;
      if (type === "message/rfc822") {
        const parsed = parseMime(x);
        if (parsed.problems.length > 0) return NOT_FULLY_SCANNED;
        const rendered = renderMessage(parsed, 0, budget);
        return rendered.includes(NOT_FULLY_SCANNED) ? NOT_FULLY_SCANNED : rendered;
      }
      const unfolded = x.replace(/\r?\n[ \t]/g, "");
      if (unfolded.split(/\r?\n/).length > MAX_CALENDAR_LINES) return NOT_FULLY_SCANNED;
      return neutralizeText(unfolded, true, budget);
    }
    return rewriteNode(x, budget, depth + 1, maxDepth, keep);
  });
  return keep && !changed ? v : next;
}

/**
 * Strips hidden characters and hidden HTML from every string in a value, object keys included (structure kept).
 * Past `maxDepth` nothing is read, so nothing is passed on unread either: a string there, or a whole object or
 * array (its keys with it), is replaced by NOT_FULLY_SCANNED (the detector reads deeper than this bound, so a
 * delivered message can reach it).
 */
export function neutralizeDeep(v: unknown, budget?: WorkBudget, depth = 0, maxDepth = MAX_DEPTH + 8): unknown {
  return rewriteNode(v, budget, depth, maxDepth, false);
}

/** Levels of nesting `neutralizeKeep` rewrites below where it starts; deeper, a value is the note (as in neutralizeDeep). */
const KEEP_DEPTH = 256;

/**
 * `neutralizeDeep` (keys included) that returns the same value when nothing was stripped, for what lies past the
 * splitter's bounds (already that deep). Bounded too: past KEEP_DEPTH more levels a non-empty string, object or list
 * is NOT_FULLY_SCANNED, never passed on unread and never a reason to overflow the stack.
 */
function neutralizeKeep(v: unknown, budget?: WorkBudget, depth = 0): unknown {
  return rewriteNode(v, budget, depth, KEEP_DEPTH, true);
}

/**
 * A rewritten JSON value as the JSON text it came from. A value too deep to serialize (the engine's own recursion
 * limit) is not passed on as it was, unrewritten: the text is replaced by the note.
 */
function jsonText(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return NOT_FULLY_SCANNED;
  }
}

/**
 * A readable rendering of a raw message for the agent: headers it needs and its neutralized parts (charged to `budget`).
 * Each part is rewritten the way the detector read it (a text part as text, an HTML part as HTML), and an attachment's
 * name and type are both rewritten (the detector reads a type that is not a plain token like a name).
 */
export function renderMessage(msg: MailMessage, depth = 0, budget?: WorkBudget): string {
  const lines: string[] = [];
  for (const h of ["From", "To", "Cc", "Reply-To", "Date", "Subject"]) {
    const v = headerText(msg.headers, h);
    if (v !== "") lines.push(`${h}: ${neutralizeText(v, false, budget)}`);
  }
  lines.push("");
  for (const t of msg.text) lines.push(neutralizeText(t, false, budget));
  if (msg.text.length === 0) for (const h of msg.html) lines.push(neutralizeText(h, true, budget));
  if (msg.text.length === 0 && msg.html.length === 0 && msg.problems.some((p) => p.kind === "too_large")) lines.push(NOT_FULLY_SCANNED);
  for (const ics of msg.calendar) for (const t of calendarFields(ics).text) lines.push(`[calendar] ${neutralizeText(t, false, budget)}`);
  for (const a of msg.attachments) lines.push(`[attachment: ${a.filename === "" ? "" : neutralizeText(a.filename, false, budget)} (${a.contentType === "" ? "unknown type" : neutralizeText(a.contentType, false, budget)}, ${a.size} bytes; not shown)]`);
  if (depth < 10) msg.nested.forEach((n) => lines.push("", "---------- forwarded message ----------", renderMessage(n, depth + 1, budget)));
  return lines.join("\n");
}

/**
 * The id a stub repeats. An id is not one of the channels the detector reads, the pass over the text outside the
 * messages skips a stub, and a Message-ID is the sender's to choose, so an id is kept only when it can spell nothing:
 * digits only, or hex of one case only (a Gmail id; only "a" to "f" can spell nothing an agent would act on), up to
 * 64 characters. Every other id (a Message-ID, a Graph id) is given as a fingerprint the firewall writes: the first 12
 * hex digits of its SHA-256, the same for the same id, so the agent can still tell messages apart and match a stub to
 * the message it stands in for. No guess is made about whether an id reads as words.
 */
const OPAQUE_ID = /^(?:\d{1,64}|[0-9a-f]{1,64}|[0-9A-F]{1,64})$/;

export function stubId(id: unknown): string | number | undefined {
  if (typeof id === "number") return Number.isFinite(id) ? id : "[withheld]";
  if (typeof id !== "string") return undefined;
  if (OPAQUE_ID.test(id)) return id;
  return `sha256:${createHash("sha256").update(id, "utf8").digest("hex").slice(0, 12)}`;
}

/**
 * The date a stub repeats. The Date header is not a channel the detector reads, so only a date-shaped value is kept
 * as it was; another one the clock can read is given as an ISO date the firewall writes, and the rest is left out.
 */
export function stubDate(date: string): string | undefined {
  const d = date.trim();
  if (d === "") return undefined;
  if (RFC_DATE.test(d) || ISO_DATE.test(d)) return d;
  const t = Date.parse(d);
  return Number.isFinite(t) ? new Date(t).toISOString() : undefined;
}

/**
 * What the agent gets in place of a withheld message. Every field is fixed text, or a value the detector read
 * (sender, subject) with its hidden parts stripped, or a value of a strict shape (id, date): the pass over the text
 * outside the messages skips a stub, so nothing in it may be text no scan judged.
 *
 * The sender and the subject are shown only when the scan was complete (no `scan_incomplete`, no `scan_failed`)
 * and judged that very channel without finding text addressed to an agent. A scan cut short or failed may never
 * have read them (the work limit can run out before the subject), so they are `[withheld]` then: a subject the
 * scan did not judge is not shown however it reads.
 *
 * And what is shown is the exact text a scan read: the display form (a sender's name with its quotes and quoted
 * pairs undone, `"Ig\nore"` read as `Ignore`) is not the header text the channel read, so the final string, after
 * stripping and cutting, is scanned once more on a small budget of its own and shown only when that scan finished
 * and found nothing (no text addressed to an agent, nothing hidden); otherwise it is `[withheld]`.
 */
export const STUB_SCAN_WORK = 50_000;

export function stubFor(scan: MailScan, recordId: string, original: Json | string): Json {
  const complete = !scan.signals.some((x) => x.id === "scan_incomplete" || x.id === "scan_failed") && !scan.reasons.some((r) => r === "scan_incomplete" || r === "scan_failed");
  const judged = (name: string) => complete && scan.channels.some((c) => c.path === "" && c.name === name) && !scan.channels.some((c) => c.path === "" && c.name === name && c.directed);
  const cleanScan = (v: string): boolean => {
    const modes = MARKUP.test(v) ? [false, true] : [false];
    return modes.every((html) => {
      const r = scanContent(v, { html, budget: workBudget(STUB_SCAN_WORK) });
      return r.verdict === "deliver" && r.neutralized === undefined && !r.signals.some((x) => x.id === "scan_incomplete" || isDirected(x));
    });
  };
  const shown = (s: string, name: string): string => {
    if (s === "") return "";
    if (!judged(name)) return "[withheld]";
    const text = neutralizeText(s, false, workBudget(STUB_SCAN_WORK)).slice(0, 300);
    if (text === NOT_FULLY_SCANNED) return "[withheld]";
    if (MARKUP.test(s) && !cleanScan(s)) return "[withheld]";
    return cleanScan(text) ? text : "[withheld]";
  };
  const stub: Json = {};
  const id = isObj(original) ? stubId(own(original, "id")) : undefined;
  if (id !== undefined) stub.id = id;
  stub.from = shown(scan.from, "from_name");
  stub.subject = shown(scan.subject, "subject");
  const date = stubDate(scan.date);
  if (date !== undefined) stub.date = date;
  const what = scan.reasons.length > 0 ? scan.reasons.join(", ") : signalNames(scan).join(", ");
  const rec = recordId === "" ? "The record could not be saved; run launchsafe-firewall doctor" : `Record ${recordId}`;
  stub.withheld = `LaunchSafe Firewall withheld this message: ${what}. ${rec}. The person can review it with: launchsafe-firewall mail quarantine show ${recordId || "<id>"}`;
  return stub;
}

/** The text of a (rewritten) tool result, the way hooks hand a replacement back: content block texts joined. */
export function outputText(v: unknown): string {
  if (typeof v === "string") return v;
  const blocks = Array.isArray(v) ? v : isObj(v) && Array.isArray(v.content) ? v.content : isObj(v) && Array.isArray(v.llmContent) ? v.llmContent : null;
  if (blocks !== null && blocks.every((b) => isObj(b) && typeof b.text === "string")) return blocks.map((b) => (b as Json).text as string).join("\n");
  return JSON.stringify(v, null, 2);
}

// --- the filter ---------------------------------------------------------------------------------

export interface WithheldMessage {
  /** The record id the caller returned ("" when it could not be saved; in log mode always ""). */
  id: string;
  scan: MailScan;
  /** The whole result was withheld because it could not be split into messages. */
  whole: boolean;
  note?: string;
}

export interface MailFilterOptions extends MailScanOptions {
  /** "enforce": rewrite the result; "log": only report what enforce would do. */
  mode: "enforce" | "log";
  /** Called once per withheld message in enforce mode; returns the record id ("" if it could not be saved). */
  record?: (w: Omit<WithheldMessage, "id">) => string;
  /**
   * Units of work the whole result may cost, every message's scan and rewriting pass (and the text outside or
   * past them) together. Default RESULT_WORK_BUDGETS times the per-message budget (`maxWork`).
   */
  maxResultWork?: number;
  /**
   * Read path: wall-clock milliseconds the whole filter may take, every pass and the structural backstop together,
   * counted from the moment filterMailResult is called (default MAIL_DEADLINE_MS). Past it the whole result is
   * withheld (`scan_incomplete`, `time`). The clock is `now` (Date.now by default).
   */
  deadlineMs?: number;
  /** Read path: units of the structural backstop's own work budget (default BACKSTOP_WORK); past it the result is withheld. */
  backstopWork?: number;
}

/**
 * The read path's default deadline for one result, in milliseconds: well below the hook's own timeout (600 seconds for Claude Code
 * and Codex, 60 for Gemini CLI and 30 for Cursor in the installed hook entries, src/runtime/install.ts and src/adapters/), so a result too slow to check is withheld by the firewall
 * rather than delivered unchecked by an agent that gave up waiting for the hook. One scan in progress can run past it
 * by its own time limit (SCAN_LIMITS.timeoutMs) before the deadline is next looked at.
 */
export const MAIL_DEADLINE_MS = 20_000;

/** Thrown by a pass that finds the result's deadline passed; filterMailResult withholds the whole result. */
class DeadlinePassed extends Error {}

/**
 * How many per-message budgets one result may cost in all. Each message still has its own budget for its scan and
 * one for its rewrite, but they are drawn from the result's total: once it is spent, the messages left are not
 * read and are withheld on the read path (`scan_incomplete`, work), so a result of hundreds of messages, each just
 * inside its own budget, costs no more than this many.
 */
export const RESULT_WORK_BUDGETS = 4;

/** A result's total work budget: each pass draws a budget of at most `per` units from it, and pays back what it did not use. */
interface ResultWork {
  draw(): WorkBudget;
  settle(b: WorkBudget): void;
  /** One budget drawn on first use (`get`) and paid back by `done`, which says whether it ran out (false when never drawn). */
  lazy(): { get(): WorkBudget; done(): boolean };
}

function resultWork(opts: MailFilterOptions): ResultWork {
  const per = opts.maxWork ?? SCAN_LIMITS.maxWork;
  let left = opts.maxResultWork ?? RESULT_WORK_BUDGETS * per;
  const draw = (): WorkBudget => {
    const units = Math.max(0, Math.min(per, left));
    left -= units;
    return workBudget(units);
  };
  // A spent budget has left 0; an unspent one gives back what it did not use.
  const settle = (b: WorkBudget): void => {
    left += Math.max(0, b.left);
  };
  const lazy = (): { get(): WorkBudget; done(): boolean } => {
    let b: WorkBudget | undefined;
    let spent = false;
    return {
      get: () => (b ??= draw()),
      done: () => {
        if (b !== undefined) {
          spent ||= b.spent;
          settle(b);
        }
        b = undefined;
        return spent;
      },
    };
  };
  return { draw, settle, lazy };
}

export interface MailFilterResult {
  /** At least one message was found (the result could be split). */
  split: boolean;
  messages: MailScan[];
  withheld: WithheldMessage[];
  neutralized: number;
  flagged: number;
  /** The rewritten result (enforce mode, and only when something changed). */
  output?: unknown;
  /** `output` as text (what a hook hands back as the replacement). */
  outputText?: string;
}

/** Counts of each verdict (for logs). */
export function verdictCounts(scans: readonly MailScan[]): Record<string, number> {
  const out: Record<string, number> = { deliver: 0, flag: 0, neutralize: 0, quarantine: 0 };
  for (const s of scans) out[s.verdict] = (out[s.verdict] ?? 0) + 1;
  return out;
}

/**
 * Why a piece was withheld, in words that match the reason: hidden text addressed to an AI agent, or a
 * scan that could not finish (the work limit, a size bound) or failed. A piece withheld only because it
 * could not be fully read is not said to carry an instruction.
 */
export function withheldBecause(scan: Pick<MailScan, "reasons" | "signals">): string {
  const reasons: readonly MailScan["reasons"][number][] = scan.reasons.length > 0 ? scan.reasons : ["scan_incomplete"];
  if (reasons.some((r) => r !== "scan_incomplete" && r !== "scan_failed")) return `it carries hidden text addressed to an AI agent (${reasons.join(", ")})`;
  if (reasons.includes("scan_failed")) return "it could not be scanned (scan_failed)";
  const cut = (why: string) => scan.signals.some((x) => x.id === "scan_incomplete" && x.reason === why);
  if (cut("hidden_residue")) return "it has hidden characters the firewall could not strip, so it was not delivered (scan_incomplete)";
  if (cut("work")) return "it was too much to scan within the firewall's work limit, so it was not fully checked (scan_incomplete)";
  if (cut("time")) return "it could not be checked within the firewall's time limit, so it was not fully checked (scan_incomplete)";
  return "it could not be fully scanned, so it was not fully checked (scan_incomplete)";
}

/**
 * For a person reviewing a withheld message (`mail quarantine show` and `release`): when it was withheld because it
 * could not be fully read (`scan_incomplete`, `scan_failed`), the record's hidden-text preview is not the whole
 * story, or there is none at all, and this says so plainly. "" for a message that was fully read.
 */
export function notFullyReadNote(reasons: readonly string[] | undefined, preview: string): string {
  const r = reasons ?? [];
  if (!r.includes("scan_incomplete") && !r.includes("scan_failed")) return "";
  const why = r.includes("scan_failed") ? "it could not be scanned" : "it was not fully read (too large, or past the firewall's work limit)";
  return preview === ""
    ? `There is no hidden-text preview: ${why}, so the firewall does not know what it hides. Releasing it gives the agent text that was never fully checked (hidden parts it can strip are stripped; text it cannot read is replaced by a note).`
    : `This preview may be incomplete: ${why}, so the firewall did not see all of it. Releasing it gives the agent text that was never fully checked (hidden parts it can strip are stripped; text it cannot read is replaced by a note).`;
}

const RECORD = (id: string) => (id === "" ? "The record could not be saved; run launchsafe-firewall doctor." : `Record ${id}. The person can review it with: launchsafe-firewall mail quarantine show ${id}`);

const NOTICE = (id: string, scan: MailScan) => `LaunchSafe Firewall withheld this whole result: ${withheldBecause(scan)}, and it could not be split into separate messages. ${RECORD(id)}`;

/**
 * Filters a mail tool's result. `result` is what the tool returned (a string, MCP content blocks, an
 * object). Never throws: a failure while filtering withholds the whole result.
 */
export function filterMailResult(result: unknown, opts: MailFilterOptions): MailFilterResult {
  // A record callback that throws (a full disk, a broken store) must not break "never throws": its record is
  // treated as not saved (""), and the piece is still withheld.
  const record = opts.record;
  const safe: MailFilterOptions = { ...opts };
  if (record !== undefined) safe.record = (w) => {
    try {
      return record(w);
    } catch {
      return "";
    }
  };
  const fw: Written = { strings: new Set(), objects: new WeakSet(), stubs: new Set(), json: new Map(), raw: new Set(), authFail: new WeakSet(), authFailStrings: new Set(), authFailSha: new Set() };
  // One deadline for the whole result (read path), from here: every pass and the backstop look at the same clock.
  const read = (safe.path ?? "read") === "read";
  const clock = safe.now ?? Date.now;
  const started = clock();
  const limit = safe.deadlineMs ?? MAIL_DEADLINE_MS;
  const late = read ? (): boolean => clock() - started > limit : (): boolean => false;
  let out: MailFilterResult;
  try {
    // The output is built as enforce would build it in either mode (the backstop judges what the agent would get);
    // log mode reports it and hands nothing back.
    out = filterInner(result, safe, fw, late);
    if (read) {
      if (late()) throw new DeadlinePassed();
      backstop(result, out, safe, fw, late);
    }
  } catch (e) {
    out = e instanceof DeadlinePassed ? timedOut(result, safe) : failedResult(result, safe, e);
  }
  if (safe.mode !== "enforce") {
    delete out.output;
    delete out.outputText;
  }
  return out;
}

/**
 * What the firewall itself wrote into the output (notices, stubs, notes, placeholders), which the backstop does not
 * read as content, and the JSON texts the passes parsed, each with the value it stands for (the same objects, so a
 * message a pass judged is known by identity wherever it is met again).
 */
interface Written {
  strings: Set<string>;
  objects: WeakSet<object>;
  /** The stubs, as canonical JSON: an identical copy of one (a stub the agent's tool echoed) is the same text. */
  stubs: Set<string>;
  json: Map<string, unknown>;
  /**
   * Raw message sources the passes read part by part and delivered as they were. The backstop reads such a source as
   * one string, out of its parts' context (a Persian part's zero-width non-joiners, an Arabic part's direction marks):
   * a hidden instruction there still withholds the result, but what the parts' own reading kept is not stripped.
   */
  raw: Set<string>;
  /** Messages whose sender failed authentication (dmarc=fail / spf=fail without DKIM or ARC), so the backstop applies authFail to their strings. */
  authFail: WeakSet<object>;
  authFailStrings: Set<string>;
  authFailSha: Set<string>;
}

/** Values, characters and levels of nesting the backstop reads; past any of them the result is withheld (fail closed). */
const BACKSTOP_VALUES = 1_000_000;
const BACKSTOP_CHARS = 64 * 1024 * 1024;
const BACKSTOP_DEPTH = 2 * MAX_SEARCH_DEPTH;
/** The placeholder keys the rewriting passes write. */
const KEY_WITHHELD = /^\[key withheld \d+\]$/;
/** Base64 text (no markup, spaces or hidden characters): scanned in pieces when longer than one scan reads. */
const BASE64_TEXT = /^[A-Za-z0-9+/=_-]+$/;
const BASE64_CHUNK = 1024 * 1024;
/** The backstop's work budget: one default result's total (RESULT_WORK_BUDGETS per-message budgets). */
const BACKSTOP_WORK = RESULT_WORK_BUDGETS * SCAN_LIMITS.maxWork;
/**
 * Keys whose value is a provider's preview, cut at a length: only there is a cut flag emoji's tail dropped before the
 * scan. Exactly the keys the parser reads a preview from (mime.ts SNIPPET_KEYS), where the detector drops it too.
 */
const PREVIEW_KEYS: ReadonlySet<string> = new Set<string>(SNIPPET_KEYS);
/** Characters on each side of a boundary between two content blocks the fallback reads joined (see backstop). */
const JOIN_WINDOW = 32 * 1024;
/**
 * Characters of joined block text one scan reads (at most 1.5 MiB of UTF-8, inside the HTML bound), and how far each
 * next piece starts after the last: pieces overlap by half, so anything up to JOIN_STEP characters long lies whole in
 * one of them, and the joined text is read twice in all (linear in its length).
 */
const JOIN_PIECE = 512 * 1024;
const JOIN_STEP = JOIN_PIECE / 2;

/**
 * The texts of a result's content blocks, when there are at least two (one block has no boundary): MCP `content`
 * blocks of type "text", the same blocks given as a bare list (Claude Code's tool_response), and Gemini CLI's
 * `llmContent` parts (`{ text }`, no type, or type "text"). Any other list of objects with a `text` field (a list of
 * messages, notes) is not content blocks: the agent reads it as the JSON it is, not joined. Null otherwise.
 */
export function blockTexts(v: unknown): string[] | null {
  let blocks: unknown[] | null = null;
  let untyped = false;
  if (Array.isArray(v)) blocks = v;
  else if (isObj(v) && Array.isArray(own(v, "content"))) blocks = own(v, "content") as unknown[];
  else if (isObj(v) && Array.isArray(own(v, "llmContent"))) {
    blocks = own(v, "llmContent") as unknown[];
    untyped = true;
  }
  if (blocks === null) return null;
  const texts: string[] = [];
  for (const b of blocks) {
    if (!isObj(b) || typeof own(b, "text") !== "string") continue;
    const type = own(b, "type");
    if (type === "text" || (untyped && type === undefined)) texts.push(own(b, "text") as string);
  }
  return texts.length > 1 ? texts : null;
}

/** Characters at a string's edges that JSON allows around a value (JSON.parse accepts no other). */
const JSON_SPACE = (c: number): boolean => c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;

/**
 * Whether a string's trimmed edges hold anything but JSON's own whitespace (a byte order mark, a no-break or
 * ideographic space, a line separator): parseJsonText trims them, so they are in the text and in no parse.
 */
export function hasEdgeJunk(s: string): boolean {
  const t = s.trim();
  if (t.length === s.length) return false;
  let a = 0;
  while (a < s.length && JSON_SPACE(s.charCodeAt(a))) a++;
  let z = s.length;
  while (z > a && JSON_SPACE(s.charCodeAt(z - 1))) z--;
  return z - a !== t.length;
}

/**
 * The string literals of a text that looks like JSON but does not parse (a cut or broken result, trailing text after
 * it), with their escapes undone (`\uXXXX`, `\n`, ...), joined by newlines; "" when no literal has an escape. An agent
 * reads such a text as JSON and decodes the escapes: `󠁁` is a tag character to it, though the text scanned
 * as it is holds only a backslash and letters. An escape that is not JSON is kept as it is.
 */
const JSON_ESCAPES: ReadonlyMap<string, string> = new Map([
  ["n", "\n"],
  ["t", "\t"],
  ["r", "\r"],
  ["b", "\b"],
  ["f", "\f"],
  ["/", "/"],
  ["\\", "\\"],
  ['"', '"'],
]);

export function unescapedLiterals(s: string): string {
  const out: string[] = [];
  let escaped = false;
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) !== 0x22) continue;
    let lit = "";
    let j = i + 1;
    for (; j < s.length; j++) {
      const c = s[j] as string;
      if (c === '"') break;
      if (c !== "\\" || j + 1 >= s.length) {
        lit += c;
        continue;
      }
      escaped = true;
      const e = s[++j] as string;
      const hex = s.slice(j + 1, j + 5);
      if (e === "u" && /^[0-9A-Fa-f]{4}$/.test(hex)) {
        lit += String.fromCharCode(parseInt(hex, 16));
        j += 4;
      } else lit += JSON_ESCAPES.get(e) ?? `\\${e}`;
    }
    out.push(lit);
    i = j;
  }
  return escaped ? out.join("\n") : "";
}

/** What the backstop's scans of one string found. */
interface Judged {
  /** Why a scan could not finish ("" when every scan did). */
  cut: string;
  quarantine: boolean;
  reasons: MailScan["reasons"];
  /** Something hidden to strip (a neutralize verdict). */
  hidden: boolean;
  directed: boolean;
}

/**
 * The structural backstop (read path): after the output is fully built, every string and key in it (JSON text parsed,
 * as the passes parse it) is scanned once more, except what the firewall wrote itself (`w`, a released message's
 * rewritten output among it) and strings that can spell nothing (isOpaqueToken: digits, hex ids, dates), on a budget
 * of the result's size and a wall-clock deadline. A string is read as the passes read a string of unknown type (as
 * text, and as HTML too when it has markup). A string the passes judged and delivered scans the same again, so this
 * costs only time on ordinary mail; it holds the invariant "nothing reaches the agent unless a pass read that exact
 * text" even where a pass has a gap. If a string carries a hidden instruction (a quarantine verdict), or the walk or a
 * scan cannot finish (budget, size, depth, deadline), the whole result is withheld: recorded, and replaced by a
 * notice. A string with hidden parts no pass stripped (a neutralize verdict) is replaced by its stripped text (withheld
 * when that is still not clean). Content blocks, which the agent reads joined, are also read across each boundary
 * between two blocks. Visible text addressed to an AI agent in a result nothing flagged is flagged.
 */
function backstop(result: unknown, out: MailFilterResult, opts: MailFilterOptions, w: Written, late: () => boolean): void {
  const value = out.output !== undefined ? out.output : result;
  const per = opts.maxWork ?? SCAN_LIMITS.maxWork;
  const subjects = [...new Set(out.messages.map((m) => m.subject).filter((s) => s !== ""))].slice(0, 1_000);
  const common = { subjects, ...(opts.quarantineOn !== undefined ? { quarantineOn: opts.quarantineOn } : {}), ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}), ...(opts.now !== undefined ? { now: opts.now } : {}) };
  // A budget of its own, the size of a default result's total (it reads the delivered text once, which the passes
  // paid for already): a caller's smaller work limits bound the passes, not this check of what they let through.
  const base: typeof common & { budget: WorkBudget; authFail?: boolean } = { ...common, budget: workBudget(opts.backstopWork ?? BACKSTOP_WORK) };
  const skip = (s: string): boolean => isOpaqueToken(s) || s === NOT_FULLY_SCANNED || s === "[withheld]" || w.strings.has(s) || KEY_WITHHELD.test(s) || ELIDED_ATTACHMENT.test(s);
  // A JSON text a pass parsed is read as the value it stands for; one no pass parsed is read as its parse only when
  // that is all of it (no repeated keys), and otherwise as the text it is.
  const readJson = (v: string): unknown => (w.json.has(v) ? w.json.get(v) : wholeJsonText(v));
  /** How the passes read a string of unknown type (pieceMessage): HTML when it looks like HTML; otherwise text, and HTML too when it has markup. */
  const modes = (s: string): boolean[] => (looksLikeHtml(s) ? [true] : MARKUP.test(s) ? [false, true] : [false]);
  const scanOne = (s: string, preview: boolean, b: typeof base): ScanResult[] => {
    if (s.length <= BASE64_CHUNK || !BASE64_TEXT.test(s)) {
      // A provider's preview cut at a length can end inside a flag emoji's tag sequence: the cut tail is dropped, as
      // the detector drops it from a preview (at most six tag characters after a black flag, at the end).
      const t = preview ? trimTruncation(s) : s;
      return modes(t).map((html) => scanContent(t, { ...b, html }));
    }
    // Base64 cannot hold markup or hidden characters, so pieces (overlapping, for a phrase across a cut) read it whole.
    const rs: ScanResult[] = [];
    for (let i = 0; i < s.length; i += BASE64_CHUNK) rs.push(scanContent(s.slice(i, i + BASE64_CHUNK + 256), b));
    return rs;
  };
  const judge = (s: string, preview: boolean, b = base): Judged => {
    const j: Judged = { cut: "", quarantine: false, reasons: [], hidden: false, directed: false };
    for (const r of scanOne(s, preview, b)) {
      const cut = r.signals.find((x) => x.id === "scan_incomplete");
      if (cut !== undefined) {
        j.cut = cut.id === "scan_incomplete" ? cut.reason : "scan";
        return j;
      }
      if (r.verdict === "quarantine") {
        j.quarantine = true;
        for (const reason of r.reasons) if (!j.reasons.includes(reason)) j.reasons.push(reason);
      }
      if (r.verdict === "neutralize" || (r.verdict === "quarantine" && r.neutralized !== undefined)) j.hidden = true;
      if (r.signals.some((x) => x.id === "agent_directed" && !x.hidden)) j.directed = true;
    }
    return j;
  };
  const stripLiterals = (s: string, b: typeof base): { text: string; cut: boolean } => {
    let out = "";
    let last = 0;
    let changed = false;
    for (let i = 0; i < s.length; i++) {
      if (s.charCodeAt(i) !== 0x22) continue;
      let lit = "";
      let litEscaped = false;
      let j = i + 1;
      for (; j < s.length; j++) {
        const c = s[j] as string;
        if (c === '"') break;
        if (c !== "\\" || j + 1 >= s.length) {
          lit += c;
          continue;
        }
        litEscaped = true;
        const e = s[++j] as string;
        const hex = s.slice(j + 1, j + 5);
        if (e === "u" && /^[0-9A-Fa-f]{4}$/.test(hex)) {
          lit += String.fromCharCode(parseInt(hex, 16));
          j += 4;
        } else lit += JSON_ESCAPES.get(e) ?? `\\${e}`;
      }
      if (litEscaped) {
        let clean = lit;
        for (const html of modes(clean)) {
          const r = scanContent(clean, { ...b, html });
          if (r.signals.some((x) => x.id === "scan_incomplete")) return { text: s, cut: true };
          if (r.neutralized !== undefined) clean = r.neutralized;
        }
        if (clean !== lit) {
          changed = true;
          const closed = j < s.length && s[j] === '"';
          const encoded = JSON.stringify(clean);
          out += s.slice(last, i) + (closed ? encoded : encoded.slice(0, -1));
          last = closed ? j + 1 : j;
        }
      }
      i = j;
    }
    return { text: changed ? out + s.slice(last) : s, cut: false };
  };
  /**
   * A string's hidden parts stripped, each reading in turn: the stripped text, or why it cannot be delivered (a scan
   * cut short, a hidden instruction still there, or hidden characters the stripping did not remove).
   */
  const strip = (s: string, preview: boolean, b = base): { text: string } | { fail: "cut" | "quarantine" | "hidden"; text: string; reasons: MailScan["reasons"] } => {
    let t = preview ? trimTruncation(s) : s;
    for (const html of modes(t)) {
      const r = scanContent(t, { ...b, html });
      if (r.signals.some((x) => x.id === "scan_incomplete")) return { fail: "cut", text: t, reasons: [] };
      if (r.neutralized !== undefined) t = r.neutralized;
    }
    if (t.includes('"') && t.includes("\\") && unescapedLiterals(t) !== "") {
      const sl = stripLiterals(t, b);
      if (sl.cut) return { fail: "cut", text: t, reasons: [] };
      t = sl.text;
    }
    const again = judge(t, false, b);
    if (t.includes('"') && t.includes("\\")) {
      const lit = unescapedLiterals(t);
      if (lit !== "") {
        const jl = judge(lit, false, b);
        if (jl.cut !== "" && again.cut === "") again.cut = jl.cut;
        if (jl.quarantine) {
          again.quarantine = true;
          for (const reason of jl.reasons) if (!again.reasons.includes(reason)) again.reasons.push(reason);
        }
        if (jl.hidden) again.hidden = true;
      }
    }
    if (again.cut !== "") return { fail: "cut", text: t, reasons: [] };
    if (again.quarantine) return { fail: "quarantine", text: t, reasons: again.reasons };
    if (again.hidden) return { fail: "hidden", text: t, reasons: [] };
    return { text: t };
  };
  let unread = "";
  let hit: string | undefined;
  let hitScan: MailScan | undefined;
  let directed = false;
  let values = 0;
  let chars = 0;
  // A message or text the person released was met (its record's text is theirs to see).
  let released = out.messages.some((m) => m.released);
  const subs = new Map<string, string>();
  /**
   * Whether `v` withholds the result: not when the person released this exact text (`quarantine show` gives its
   * record's sha256, whatever verdict a scan of it now reaches). `cause` says why, when it is not a hidden instruction
   * the scan of `v` finds itself, so the record and the notice give the reason that holds.
   */
  const quarantined = (v: string, cause?: { reasons: MailScan["reasons"]; signal?: string }, alt?: string): boolean => {
    const s = scanMail(v, { ...opts, budget: workBudget(per) });
    const altSha = alt !== undefined ? createHash("sha256").update(alt, "utf8").digest("hex") : "";
    // The person released this exact text: it is theirs to see (the rest is still read).
    if (s.released || opts.released?.(s.sha256) === true || (altSha !== "" && opts.released?.(altSha) === true)) {
      released = true;
      return false;
    }
    hit = v;
    hitScan = s;
    if (cause !== undefined && s.verdict !== "quarantine") {
      hitScan = { ...s, verdict: "quarantine", reasons: cause.reasons, signals: cause.signal !== undefined ? [...s.signals, { id: "scan_incomplete", reason: cause.signal }] : s.signals };
    }
    return true;
  };
  const seen = new WeakSet<object>();
  const stack: { v: unknown; d: number; preview: boolean; authFail: boolean }[] = [
    { v: value, d: 0, preview: false, authFail: !out.split && out.messages.some((m) => m.auth.fail === true && !m.released) },
  ];
  while (stack.length > 0) {
    if (++values > BACKSTOP_VALUES) {
      unread = "values";
      break;
    }
    if (late()) {
      unread = "time";
      break;
    }
    const { v, d, preview, authFail } = stack.pop() as { v: unknown; d: number; preview: boolean; authFail: boolean };
    if (d > BACKSTOP_DEPTH) {
      unread = "depth";
      break;
    }
    if (typeof v === "string") {
      if (skip(v) || subs.has(v)) continue;
      const af = authFail || w.authFailStrings.has(v);
      const json = readJson(v);
      if (json !== undefined) {
        stack.push({ v: json, d: d + 1, preview, authFail: af });
        continue;
      }
      chars += v.length;
      if (chars > BACKSTOP_CHARS) {
        unread = "size";
        break;
      }
      const sb = af ? { ...base, authFail: true } : base;
      const j = judge(v, preview, sb);
      if (j.cut !== "") {
        unread = j.cut;
        break;
      }
      if (j.quarantine && quarantined(v, j.reasons.length > 0 ? { reasons: j.reasons } : undefined)) break;
      // Text with JSON string escapes is read by the agent with its escapes decoded:
      // the literals with their escapes undone are read too, and a hidden instruction there withholds the result.
      let litHidden = false;
      if (v.includes('"') && v.includes("\\")) {
        const lit = unescapedLiterals(v);
        if (lit !== "") {
          const jl = judge(lit, false, sb);
          if (jl.cut !== "") {
            unread = jl.cut;
            break;
          }
          if (jl.quarantine && quarantined(lit, jl.reasons.length > 0 ? { reasons: jl.reasons } : undefined, v)) break;
          if (jl.hidden) {
            j.hidden = true;
            litHidden = true;
          }
          if (jl.directed) j.directed = true;
        }
      }
      if ((j.hidden && !w.raw.has(v)) || litHidden) {
        // Hidden parts no pass stripped: the stripped text is delivered in its place, or the result is withheld (for
        // the reason that holds: a hidden instruction, a scan cut short, or hidden characters stripping left behind).
        const t = strip(v, preview, sb);
        if ("fail" in t) {
          const scannedReasons = t.fail === "quarantine" ? scanMail(t.text, { ...opts, budget: workBudget(per) }).reasons.filter((r) => r !== "scan_incomplete" && r !== "scan_failed") : [];
          const cause: { reasons: MailScan["reasons"]; signal?: string } =
            t.fail === "quarantine"
              ? { reasons: [...new Set([...t.reasons, ...scannedReasons])] }
              : { reasons: ["scan_incomplete" as const], signal: t.fail === "cut" ? "strip" : "hidden_residue" };
          if (cause.reasons.length === 0) cause.reasons = ["hidden_instruction"];
          if (quarantined(v, cause)) break;
          // Released: the person chose to see this exact text, as it is.
          continue;
        }
        subs.set(v, t.text);
      }
      if (j.directed) directed = true;
      continue;
    }
    if (typeof v !== "object" || v === null || seen.has(v) || w.objects.has(v)) continue;
    seen.add(v);
    if (isObj(v) && stubShaped(v) && w.stubs.has(canonicalJson(v))) continue;
    const af = authFail || w.authFail.has(v);
    if (Array.isArray(v)) {
      for (let i = v.length - 1; i >= 0; i--) stack.push({ v: v[i], d: d + 1, preview, authFail: af });
      continue;
    }
    const entries = Object.entries(v);
    for (let i = entries.length - 1; i >= 0; i--) {
      const [k, y] = entries[i] as [string, unknown];
      stack.push({ v: y, d: d + 1, preview: PREVIEW_KEYS.has(k), authFail: af });
      stack.push({ v: k, d: d + 1, preview: false, authFail: af });
    }
  }
  /** The fallback: each boundary's two sides (JOIN_WINDOW each way) read joined; a hit only where neither side alone withholds. */
  const windows = (texts: string[], jb: typeof base): void => {
    const joined = texts.join("\n");
    let pos = -1;
    for (let i = 0; i + 1 < texts.length; i++) {
      if (late()) {
        unread = "time";
        return;
      }
      pos += (texts[i] as string).length + 1;
      const a = joined.slice(Math.max(0, pos - JOIN_WINDOW), pos);
      const b = joined.slice(pos + 1, pos + 1 + JOIN_WINDOW);
      if (a.trim() === "" || b.trim() === "") continue;
      const both = judge(`${a}\n${b}`, false, jb);
      if (both.cut !== "") {
        unread = both.cut;
        return;
      }
      if (!both.quarantine) continue;
      const ja = judge(a, false, jb);
      const jz = judge(b, false, jb);
      if (ja.cut !== "" || jz.cut !== "") {
        unread = ja.cut || jz.cut;
        return;
      }
      if (ja.quarantine || jz.quarantine) continue;
      if (quarantined(`${a}\n${b}`, both.reasons.length > 0 ? { reasons: both.reasons } : undefined)) return;
    }
  };
  // Content blocks reach the agent joined (outputText): a phrase or a hidden element split across two blocks is read
  // where they meet. The joined text is read once, in overlapping pieces (linear in its length). Only what joining adds
  // counts: when it withholds, each block is read alone as text (linear too); if none withholds alone, the boundary is
  // what hid it, and the result is withheld. If one does (a released message, or JSON text the walk above read as its
  // parse), the fallback reads each boundary's two sides joined and alone (JOIN_WINDOW each way), as before.
  const texts = hit === undefined && unread === "" ? blockTexts(value) : null;
  if (texts !== null) {
    const hasAuthFail = out.messages.some((m) => m.auth.fail === true && m.verdict !== "quarantine" && !m.released);
    const jb: typeof base = { ...common, ...(hasAuthFail ? { authFail: true } : {}), budget: workBudget(opts.backstopWork ?? BACKSTOP_WORK) };
    /** A long text read in overlapping pieces: the first piece that withholds (its text) or is cut short ends the read. */
    const judgeLong = (s: string): { cut: string; quarantine?: string; reasons?: MailScan["reasons"] } => {
      for (let start = 0; ; start += JOIN_STEP) {
        if (late()) return { cut: "time" };
        // A piece starts and ends on a whole character (never between the two halves of a surrogate pair).
        const from = start > 0 && /[\uDC00-\uDFFF]/.test(s.charAt(start)) ? start - 1 : start;
        let to = Math.min(s.length, start + JOIN_PIECE);
        if (to < s.length && /[\uDC00-\uDFFF]/.test(s.charAt(to))) to++;
        const piece = s.slice(from, to);
        const j = judge(piece, false, jb);
        if (j.cut !== "") return { cut: j.cut };
        if (j.quarantine) return { cut: "", quarantine: piece, reasons: j.reasons };
        if (to >= s.length) return { cut: "" };
      }
    };
    const joined = judgeLong(texts.join("\n"));
    if (joined.cut !== "") unread = joined.cut;
    else if (joined.quarantine !== undefined) {
      let alone = false;
      for (const t of texts) {
        const j = judgeLong(t);
        if (j.cut !== "") {
          unread = j.cut;
          break;
        }
        if (j.quarantine !== undefined) {
          alone = true;
          break;
        }
      }
      if (unread === "" && !alone && !released) quarantined(joined.quarantine, joined.reasons !== undefined && joined.reasons.length > 0 ? { reasons: joined.reasons } : undefined);
      else if (unread === "") windows(texts, jb);
    }
  }
  if (hit === undefined && unread === "") {
    if (directed && out.flagged === 0) out.flagged = 1;
    if (subs.size > 0) {
      const next = substitute(value, subs, skip, readJson, w);
      out.output = next;
      out.outputText = outputText(next);
      // Counted as stripped, so a hook hands back the rewritten result.
      out.neutralized++;
    }
    return;
  }
  let scan: MailScan;
  if (hitScan !== undefined) {
    const s = hitScan;
    scan = s.verdict === "quarantine" ? s : { ...s, verdict: "quarantine", reasons: s.reasons.length > 0 ? s.reasons : ["hidden_instruction"] };
  } else {
    let sha256 = "";
    try {
      sha256 = createHash("sha256").update(outputText(value), "utf8").digest("hex");
    } catch {
      // A value that cannot be serialized: the record has no hash (it cannot be released, only reviewed).
    }
    if (sha256 !== "" && opts.released?.(sha256) === true) {
      if (directed && out.flagged === 0) out.flagged = 1;
      if (subs.size > 0) {
        const next = substitute(value, subs, skip, readJson, w);
        out.output = next;
        out.outputText = outputText(next);
        out.neutralized++;
      }
      return;
    }
    const s = scanMail("", { ...opts, budget: workBudget(0), released: () => false });
    scan = { ...s, sha256, verdict: "quarantine", reasons: ["scan_incomplete"], signals: [{ id: "scan_incomplete", reason: unread }] };
  }
  const withheld = { scan, whole: true, note: "a final check of the whole result found text the message-by-message passes had not cleared" };
  const id = opts.mode === "enforce" ? (opts.record?.(withheld) ?? "") : "";
  out.messages.push(scan);
  out.withheld.push({ id, ...withheld });
  const notice = `LaunchSafe Firewall withheld this whole result: in a final check of everything it would have delivered, ${withheldBecause(scan)}. ${RECORD(id)}`;
  out.output = notice;
  out.outputText = notice;
}

/**
 * The output with each string the backstop stripped (`subs`) replaced by its stripped text, keys included, read the way
 * the backstop read it: what it skipped is kept, a JSON text it parsed is rewritten inside and serialized again.
 */
function substitute(value: unknown, subs: ReadonlyMap<string, string>, skip: (s: string) => boolean, readJson: (s: string) => unknown, w: Written): unknown {
  const memo = new Map<object, unknown>();
  const put = (v: unknown): unknown => {
    if (typeof v === "string") {
      if (skip(v)) return v;
      const s = subs.get(v);
      if (s !== undefined) return s;
      const json = readJson(v);
      if (json === undefined) return v;
      const next = put(json);
      return next === json ? v : jsonText(next);
    }
    if (typeof v !== "object" || v === null || w.objects.has(v)) return v;
    if (isObj(v) && stubShaped(v) && w.stubs.has(canonicalJson(v))) return v;
    if (memo.has(v)) return memo.get(v);
    let next: unknown = v;
    if (Array.isArray(v)) {
      const items = v.map(put);
      if (items.some((x, i) => x !== v[i])) next = items;
    } else {
      const o: Json = {};
      let changed = false;
      let n = 0;
      for (const [k, x] of Object.entries(v)) {
        let key = put(k) as string;
        while (Object.hasOwn(o, key)) key = `[key withheld ${++n}]`;
        const y = put(x);
        if (key !== k || y !== x) changed = true;
        setOwn(o, key, y);
      }
      if (changed) next = o;
    }
    memo.set(v, next);
    return next;
  };
  return put(value);
}

/** The whole result withheld because filtering it failed. Never throws: text it cannot read is not scanned. */
function failedResult(result: unknown, opts: MailFilterOptions, e: unknown): MailFilterResult {
  let text = "";
  try {
    text = typeof result === "string" ? result : canonicalJson(result);
  } catch {
    // The result cannot even be serialized: the scan below reads nothing, and the result is withheld whole.
  }
  let message = "unknown error";
  try {
    message = e instanceof Error ? e.message : String(e);
  } catch {
    // An error whose message cannot be read: the fixed text above stands.
  }
  const scan = scanMail(pieceMessage(text), { ...opts, released: () => false });
  const failed: MailScan = { ...scan, verdict: "quarantine", reasons: ["scan_failed"], signals: [...scan.signals, { id: "scan_failed", reason: `the result could not be filtered: ${message}`.slice(0, 200) }] };
  const w = { scan: failed, whole: true, note: "the result could not be filtered" };
  const id = opts.mode === "enforce" ? (opts.record?.(w) ?? "") : "";
  const out: MailFilterResult = { split: false, messages: [failed], withheld: [{ id, ...w }], neutralized: 0, flagged: 0 };
  out.output = NOTICE(id, failed);
  out.outputText = out.output as string;
  return out;
}

/**
 * The whole result withheld because checking it took longer than the result's deadline (read path, `deadlineMs`):
 * what was not checked in time is not delivered. One record for the whole result; nothing a pass recorded before the
 * deadline is lost (its record stays in the store), but the agent gets only this notice.
 */
function timedOut(result: unknown, opts: MailFilterOptions): MailFilterResult {
  let sha256 = "";
  try {
    sha256 = createHash("sha256").update(outputText(result), "utf8").digest("hex");
  } catch {
    // A value that cannot be serialized: the record has no hash (it cannot be released, only reviewed).
  }
  const s = scanMail("", { ...opts, budget: workBudget(0), released: () => false });
  if (sha256 !== "" && opts.released?.(sha256) === true) {
    const scan: MailScan = { ...s, sha256, verdict: "neutralize", released: true, reasons: [], signals: [{ id: "scan_incomplete", reason: "time" }] };
    const next = neutralizeDeep(result, workBudget(opts.maxWork ?? SCAN_LIMITS.maxWork));
    const changed = canonicalJson(next) !== canonicalJson(result);
    return {
      split: false,
      messages: [scan],
      withheld: [],
      neutralized: 1,
      flagged: 0,
      ...(changed ? { output: next, outputText: outputText(next) } : {}),
    };
  }
  const scan: MailScan = { ...s, sha256, verdict: "quarantine", reasons: ["scan_incomplete"], signals: [{ id: "scan_incomplete", reason: "time" }] };
  const w = { scan, whole: true, note: "the result could not be checked within the firewall's time limit" };
  const id = opts.mode === "enforce" ? (opts.record?.(w) ?? "") : "";
  const notice = `LaunchSafe Firewall withheld this whole result: ${withheldBecause(scan)}. ${RECORD(id)}`;
  return { split: false, messages: [scan], withheld: [{ id, ...w }], neutralized: 0, flagged: 0, output: notice, outputText: notice };
}

function parseJsonText(s: string): unknown {
  if (s.length > 16 * 1024 * 1024) return undefined;
  const t = s.trim();
  if (!(t.startsWith("{") || t.startsWith("["))) return undefined;
  try {
    return JSON.parse(t) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * Whether a JSON text (one JSON.parse accepted) has an object with the same key twice. JSON.parse keeps the last
 * value of a repeated key, so the parse a pass reads is not all of the text: an earlier value (a first "body" with a
 * hidden instruction) is in the text and in no parse. Such a text is never delivered as it is after a pass read its
 * parse: what is delivered is the parse, serialized again, or the text read as the text it is.
 */
export function hasDuplicateKeys(s: string): boolean {
  // One set of keys per open object (null for an array), and whether the next string in it is a key.
  const keys: (Set<string> | null)[] = [];
  let expectKey = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) {
      let j = i + 1;
      while (j < s.length && s.charCodeAt(j) !== 0x22) j += s.charCodeAt(j) === 0x5c ? 2 : 1;
      const top = keys[keys.length - 1];
      if (expectKey && top !== null && top !== undefined) {
        const raw = s.slice(i, j + 1);
        const key = raw.includes("\\") ? (JSON.parse(raw) as string) : raw.slice(1, -1);
        if (top.has(key)) return true;
        top.add(key);
        expectKey = false;
      }
      i = j;
    } else if (c === 0x7b) {
      keys.push(new Set());
      expectKey = true;
    } else if (c === 0x5b) {
      keys.push(null);
      expectKey = false;
    } else if (c === 0x7d || c === 0x5d) {
      keys.pop();
      expectKey = false;
    } else if (c === 0x2c) {
      const top = keys[keys.length - 1];
      expectKey = top !== undefined && top !== null;
    }
  }
  return false;
}

/**
 * The values of a JSON text (one JSON.parse accepted) that its parse leaves out: for each key an object repeats, the
 * JSON text of every value but the last (the one JSON.parse keeps), nested repeats inside them included. Iterative,
 * linear in the text.
 */
export function shadowedValues(s: string): string[] {
  interface Frame {
    obj: boolean;
    seen: Map<string, [number, number]>;
    key: string | undefined;
    start: number;
  }
  const frames: Frame[] = [];
  const out: string[] = [];
  let expectKey = false;
  // The value of the frame's current key ends at `end`: an earlier value of the same key is shadowed by it.
  const close = (f: Frame, end: number): void => {
    if (f.key === undefined || f.start < 0) return;
    const prev = f.seen.get(f.key);
    if (prev !== undefined) out.push(s.slice(prev[0], prev[1]));
    f.seen.set(f.key, [f.start, end]);
    f.key = undefined;
    f.start = -1;
  };
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const top = frames[frames.length - 1];
    if (c === 0x22) {
      let j = i + 1;
      while (j < s.length && s.charCodeAt(j) !== 0x22) j += s.charCodeAt(j) === 0x5c ? 2 : 1;
      if (expectKey && top !== undefined && top.obj) {
        const raw = s.slice(i, j + 1);
        top.key = raw.includes("\\") ? (JSON.parse(raw) as string) : raw.slice(1, -1);
        expectKey = false;
      }
      i = j;
    } else if (c === 0x7b || c === 0x5b) {
      frames.push({ obj: c === 0x7b, seen: new Map(), key: undefined, start: -1 });
      expectKey = c === 0x7b;
    } else if (c === 0x3a) {
      if (top !== undefined && top.obj) top.start = i + 1;
    } else if (c === 0x2c) {
      if (top !== undefined && top.obj) close(top, i);
      expectKey = top !== undefined && top.obj;
    } else if (c === 0x7d || c === 0x5d) {
      if (top !== undefined && top.obj) close(top, i);
      frames.pop();
      expectKey = false;
    }
  }
  return out;
}

/** JSON text with its whitespace outside strings removed (the text JSON.stringify would write for the same tokens). */
function minified(s: string): string {
  const parts: string[] = [];
  let from = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) {
      let j = i + 1;
      while (j < s.length && s.charCodeAt(j) !== 0x22) j += s.charCodeAt(j) === 0x5c ? 2 : 1;
      i = j;
    } else if (JSON_SPACE(c)) {
      parts.push(s.slice(from, i));
      from = i + 1;
    }
  }
  parts.push(s.slice(from));
  return parts.join("");
}

/**
 * Whether a JSON text is exactly its parse written out again, but for whitespace between tokens: then it holds
 * nothing its parse leaves out (no repeated key, no other edge characters) and nothing re-serializing would change
 * (a number past double precision, `1.0`, an escape written another way), so it can be delivered as it came.
 */
function roundTrips(s: string, json: unknown): boolean {
  let again: string;
  try {
    again = JSON.stringify(json);
  } catch {
    return false;
  }
  return again.length <= s.length && minified(s) === again;
}

/**
 * A JSON text's parse when it is all of the text (no repeated keys, nothing but JSON whitespace at its edges), for a
 * reader that would deliver the text as it is.
 */
function wholeJsonText(s: string): unknown {
  const json = parseJsonText(s);
  return json !== undefined && (hasDuplicateKeys(s) || hasEdgeJunk(s)) ? undefined : json;
}

/** Most strings, and most characters, the whole-piece scan reads; past either the result is withheld. */
const MAX_PIECE_STRINGS = 200_000;
const MAX_PIECE_CHARS = 32 * 1024 * 1024;

/**
 * Every string in a value (keys included), for a whole-piece scan. Iterative and not depth-bounded, so a
 * result nested deeper than any splitter bound is still read. `complete` is false when a size bound cut
 * the walk short: the caller must then fail closed.
 */
function allText(v: unknown, maxStrings = MAX_PIECE_STRINGS, maxChars = MAX_PIECE_CHARS): { parts: string[]; chars: number; complete: boolean } {
  const parts: string[] = [];
  const stack: unknown[] = [v];
  let chars = 0;
  const seen = new WeakSet<object>();
  while (stack.length > 0) {
    if (parts.length >= maxStrings || chars >= maxChars) return { parts, chars, complete: false };
    const x = stack.pop();
    if (typeof x === "object" && x !== null) {
      if (seen.has(x)) continue;
      seen.add(x);
    }
    if (typeof x === "string") {
      const json = parseJsonText(x);
      if (json !== undefined) stack.push(json);
      // A JSON text with repeated keys (or other characters than JSON's whitespace at its edges) is read as text too:
      // its parse leaves out the values it shadows.
      if (json === undefined || hasDuplicateKeys(x) || hasEdgeJunk(x)) {
        parts.push(x);
        chars += x.length;
      }
    } else if (Array.isArray(x)) for (let i = x.length - 1; i >= 0; i--) stack.push(x[i]);
    else if (isObj(x)) {
      // An object's keys are read when it is reached, in order; then its values, in order (cutPast follows this order).
      const entries = Object.entries(x);
      for (const [k] of entries) {
        if (!PLAIN_TOKEN.test(k)) {
          parts.push(k);
          chars += k.length;
        }
      }
      for (let i = entries.length - 1; i >= 0; i--) stack.push((entries[i] as [string, unknown])[1]);
    }
  }
  return { parts, chars, complete: true };
}

/**
 * A value with everything allText(v, maxStrings, maxChars) did not read replaced by the note: the string (or key, or
 * object) the bound cuts, and everything after it. It walks in allText's order and stops where allText stops (at a
 * value reached with the bound already met), so what it keeps is only what that scan read; where it cannot follow
 * (deeper than neutralizeDeep rewrites, where everything is the note anyway), it cuts from there on, earlier rather
 * than later.
 */
function cutPast(v: unknown, maxStrings = MAX_PIECE_STRINGS, maxChars = MAX_PIECE_CHARS): unknown {
  let strings = 0;
  let chars = 0;
  let cut = false;
  const done = new Map<object, unknown>();
  const note = (x: unknown): unknown => (typeof x === "string" ? (x.length === 0 ? x : NOT_FULLY_SCANNED) : typeof x === "object" && x !== null ? NOT_FULLY_SCANNED : x);
  const walk = (x: unknown, depth: number): unknown => {
    if (cut || strings >= maxStrings || chars >= maxChars || depth > MAX_DEPTH + 8) {
      cut = true;
      return note(x);
    }
    if (typeof x === "object" && x !== null && done.has(x)) return done.get(x);
    if (typeof x === "string") {
      const json = parseJsonText(x);
      if (json !== undefined) {
        // As allText: a text with repeated keys is read as text first, then as its parse.
        if (hasDuplicateKeys(x) || hasEdgeJunk(x)) {
          strings++;
          chars += x.length;
        }
        const next = walk(json, depth + 1);
        return next === json ? x : jsonText(next);
      }
      strings++;
      chars += x.length;
      return x;
    }
    if (Array.isArray(x)) {
      const next = x.map((y) => walk(y, depth + 1));
      done.set(x, next);
      return next;
    }
    if (!isObj(x)) return x;
    const entries = Object.entries(x);
    for (const [k] of entries) {
      if (!PLAIN_TOKEN.test(k)) {
        strings++;
        chars += k.length;
      }
    }
    const next: Json = {};
    for (const [k, y] of entries) setOwn(next, k, walk(y, depth + 1));
    done.set(x, next);
    return next;
  };
  return walk(v, 0);
}

/**
 * Whether a value holds a message (a message-like object or a raw source, in JSON text too). Iterative. `spent` is
 * the result's running count of values looked at: past MAX_PIECE_STRINGS values in all it answers yes, so the caller
 * searches value by value (never less safe, only slower) rather than taking a part as one piece, and a deep result
 * is not walked once per level.
 */
function hasMessage(v: unknown, spent: { nodes: number }): boolean {
  const stack: unknown[] = [v];
  const seen = new WeakSet<object>();
  while (stack.length > 0) {
    if (++spent.nodes > MAX_PIECE_STRINGS) return true;
    const x = stack.pop();
    if (typeof x === "string") {
      const json = parseJsonText(x);
      if (json !== undefined) stack.push(json);
      else if (looksLikeRawMessage(x)) return true;
      continue;
    }
    if (typeof x !== "object" || x === null || seen.has(x)) continue;
    seen.add(x);
    if (Array.isArray(x)) for (const y of x) stack.push(y);
    else if (isObj(x)) {
      if (isMessageLike(x)) return true;
      for (const y of Object.values(x)) stack.push(y);
    }
  }
  return false;
}

/** The note on the record of the values a repeated JSON key shadows. */
const SHADOW_NOTE = "values a repeated key hides in a JSON text (JSON.parse keeps only the last)";

function filterInner(result: unknown, opts: MailFilterOptions, w: Written, late: () => boolean = () => false): MailFilterResult {
  const enforce = opts.mode === "enforce";
  const mailbox = opts.path === "mailbox";
  const out: MailFilterResult = { split: false, messages: [], withheld: [], neutralized: 0, flagged: 0 };
  const work = resultWork(opts);
  // The result's deadline (read path): a pass that finds it passed stops, and the whole result is withheld.
  const inTime = (): void => {
    if (late()) throw new DeadlinePassed();
  };
  // The same message often appears twice in one result (MCP text and structuredContent; Gemini CLI's
  // llmContent and returnDisplay): it is scanned, counted and recorded once, and rewritten everywhere.
  const done = new Map<string, unknown>();
  let found = 0;
  // A JSON text the first pass parsed, as the text it became: the same text met again is not parsed (and its messages
  // looked up) twice, and the later passes find the same objects in it (w.json).
  const jsonDone = new Map<string, string>();
  // JSON texts delivered as their parse serialized again although they held more (repeated keys, other characters at
  // their edges): what the parse left out is dropped, so the result counts as rewritten.
  let shadowed = 0;
  // JSON texts with repeated keys: once the result is known to split, the values their parse shadows are scanned.
  const shadowTexts: string[] = [];
  const parsedText = (v: string, json: unknown, depth: number): string => {
    const known = jsonDone.get(v);
    if (known !== undefined) return known;
    const next = rewrite(json, depth + 1);
    const dup = hasDuplicateKeys(v);
    // The original text only when it is exactly its parse written out again (whitespace aside): JSON.parse keeps the
    // last of repeated keys and trims more than JSON's whitespace, so a text can hold values no pass read (a first
    // "body" shadowed by a second). Otherwise what is delivered is exactly what was scanned, serialized again; that
    // can change how a number is written (past double precision) and the text's layout, never what it says.
    const text = next === json && !dup && roundTrips(v, json) ? v : jsonText(next);
    if (text !== NOT_FULLY_SCANNED) w.json.set(text, next);
    if (dup || hasEdgeJunk(v)) shadowed++;
    if (dup) shadowTexts.push(v);
    jsonDone.set(v, text);
    return text;
  };
  /**
   * The values a repeated key shadows in a JSON text, scanned as one piece: an agent whose hook cannot replace the
   * output reads the text as it came, shadowed values and all. A hidden instruction there is withheld and recorded
   * like a message (the delivered parse has dropped it already; the record and the warning are what an agent that
   * cannot be given the rewritten result gets).
   */
  const scanShadowed = (v: string): void => {
    const parts: string[] = [];
    let complete = true;
    for (const raw of shadowedValues(v)) {
      let x: unknown;
      try {
        x = JSON.parse(raw) as unknown;
      } catch {
        complete = false;
        continue;
      }
      const r = allText(x);
      for (const p of r.parts) parts.push(p);
      if (!r.complete) complete = false;
    }
    if (parts.length === 0 && complete) return;
    const scanned = work.draw();
    let scan = scanMail(pieceMessage(parts.join("\n")), { ...opts, budget: scanned });
    work.settle(scanned);
    if (!complete) scan = tooLarge(scan, opts);
    if (scan.verdict === "quarantine") {
      const withheld = { scan, whole: false, note: SHADOW_NOTE };
      const id = enforce ? (opts.record?.(withheld) ?? "") : "";
      out.messages.push(scan);
      out.withheld.push({ id, ...withheld });
    } else if (scan.verdict === "flag") out.flagged++;
  };
  const handle = (original: Json | string): unknown => {
    inTime();
    const { sha256 } = readMessage(original);
    if (done.has(sha256)) {
      const prev = done.get(sha256);
      if (w.authFailSha.has(sha256)) {
        if (typeof original === "object" && original !== null) w.authFail.add(original);
        else if (typeof original === "string") w.authFailStrings.add(original);
      }
      return prev;
    }
    found++;
    // Attachment content too large to read is not delivered either: a placeholder stands in for it.
    const value = typeof original === "string" ? original : elideAttachments(original);
    // Both budgets come out of the result's total (work): past it, a message is not read and is withheld.
    const scanned = work.draw();
    let scan = scanMail(value, { ...opts, budget: scanned });
    work.settle(scanned);
    let replacement: unknown = value;
    // On the mailbox path a message the scan could not fully read is not withheld, but it is not passed on raw either:
    // it is rewritten, and what the rewrite cannot pay for (all of it, past the result's total) is replaced by a note.
    // A message whose scan failed (a part could not be listed or scanned) was not read at all where it failed, and the
    // rewrite would read it with the same code: on the mailbox path the whole message is replaced by the note. On the
    // read path such a message is withheld, so one that gets here was released by the person: it is rewritten and
    // delivered like any released message (a string the rewrite cannot read is still replaced by the note).
    const failed = mailbox && scan.verdict !== "quarantine" && scan.signals.some((x) => x.id === "scan_failed");
    const unread = scan.verdict !== "quarantine" && scan.signals.some((x) => x.id === "scan_incomplete");
    if (failed) replacement = NOT_FULLY_SCANNED;
    else if (scan.verdict === "neutralize" || unread) {
      // The rewriting pass reads the text the scan read again, so it has a budget of its own (of the same
      // size): a message whose scan fits is not withheld because the second pass was charged for the first.
      const budget = work.draw();
      // A raw source (under any of the keys the parser reads one from) is rendered as its readable parts, as the
      // detector read it: rewritten as one string, its encoded parts (base64, quoted-printable) would pass unread.
      const rk = typeof value === "string" ? undefined : rawKey(value);
      const maxBytes = scan.released ? Infinity : MIME_LIMITS.maxBytes;
      if (typeof value === "string") replacement = renderMessage(parseMime(value, maxBytes), 0, budget);
      else if (rk !== undefined) {
        const copy: Json = { ...value };
        delete copy[rk];
        replacement = { ...(neutralizeDeep(copy, budget) as Json), rendered: renderMessage(fromStructured(value, maxBytes), 0, budget) };
      } else replacement = neutralizeDeep(value, budget);
      work.settle(budget);
      if (budget.spent) scan = outOfWork(scan, opts);
    }
    out.messages.push(scan);
    if (scan.verdict === "flag") out.flagged++;
    if (scan.verdict === "neutralize" || (scan.verdict !== "quarantine" && value !== original)) out.neutralized++;
    if (scan.verdict === "quarantine") {
      const withheld = { scan, whole: false };
      const id = enforce ? (opts.record?.(withheld) ?? "") : "";
      out.withheld.push({ id, ...withheld });
      const stub = stubFor(scan, id, value);
      // A stub is the firewall's text (its sender and subject are the exact text a scan read): see Written.
      w.objects.add(stub);
      w.stubs.add(canonicalJson(stub));
      replacement = stub;
    } else if (scan.released) {
      // The person released this message: its rewritten output (hidden parts stripped) is theirs to see, so the
      // backstop does not read it again (by identity) and withhold the result it was released into.
      if (typeof replacement === "string") w.strings.add(replacement);
      else if (typeof replacement === "object" && replacement !== null) w.objects.add(replacement);
    } else {
      if (typeof value === "string" && replacement === value) w.raw.add(value);
      if (scan.auth.fail === true) {
        w.authFailSha.add(sha256);
        if (typeof original === "object" && original !== null) w.authFail.add(original);
        else if (typeof original === "string") w.authFailStrings.add(original);
        if (typeof replacement === "object" && replacement !== null) w.authFail.add(replacement);
        else if (typeof replacement === "string") w.authFailStrings.add(replacement);
      }
    }
    done.set(sha256, replacement);
    return replacement;
  };
  // What lies past the splitter's bounds is scanned as one piece afterwards (fail closed), and hidden parts are
  // stripped from it here. On the read path the messages in it are still found and handled one by one (each on the
  // result's work total, so past it they are withheld): only the text around them is the piece.
  const beyond: unknown[] = [];
  let bound = "";
  // What lies beyond is rewritten here and scanned below, each pass on its own budget (as for a message).
  const beyondBudget = work.lazy();
  // The scan below reads at most MAX_PIECE_STRINGS strings and MAX_PIECE_CHARS characters of it, in the order they
  // are found here. On the read path a tail past those bounds withholds the whole result; on the mailbox path it is
  // not withheld, so it is treated like a part the scan could not read: the piece the bound cuts, and every piece
  // after it, is replaced by the note rather than rewritten (stripped of what the scan never judged) and passed on.
  let beyondStrings = 0;
  let beyondChars = 0;
  let beyondCut = false;
  // Read path: nesting past this is not searched for messages; the result is withheld (scan_incomplete).
  let tooDeep = false;
  const searched = { nodes: 0 };
  const pieces = new Set<unknown>();
  const piece = (v: unknown): unknown => {
    inTime();
    beyond.push(v);
    if (!beyondCut) {
      const read = allText(v, MAX_PIECE_STRINGS - beyondStrings, MAX_PIECE_CHARS - beyondChars);
      beyondStrings += read.parts.length;
      beyondChars += read.chars;
      beyondCut = !read.complete;
    }
    if (beyondCut) return NOT_FULLY_SCANNED;
    const next = neutralizeKeep(v, beyondBudget.get());
    // Judged (as one piece, below): the pass over the text outside the messages does not judge it again.
    if (typeof next === "object" && next !== null) pieces.add(next);
    return next;
  };
  /** Read path, past the bounds: messages handled one by one, the rest (strings, keys) read as pieces; undefined for a plain string. */
  const pastBounds = (v: object | string, depth: number): unknown => {
    if (depth > MAX_SEARCH_DEPTH) {
      tooDeep = true;
      return NOT_FULLY_SCANNED;
    }
    if (typeof v === "string") {
      const json = parseJsonText(v);
      if (json !== undefined) return parsedText(v, json, depth);
      return looksLikeRawMessage(v) ? handle(v) : undefined;
    }
    if (Array.isArray(v)) {
      if (!hasMessage(v, searched)) return undefined;
      const next = v.map((x) => rewrite(x, depth + 1));
      return next.some((y, i) => y !== v[i]) ? next : v;
    }
    if (!isObj(v)) return undefined;
    if (isMessageLike(v)) return handle(v);
    // A part with no message in it is one piece, as on the mailbox path.
    if (!hasMessage(v, searched)) return undefined;
    // Keys are text too: each one is read as a piece and rewritten like a value (a placeholder when unread).
    let changed = false;
    let n = 0;
    const next: Json = {};
    for (const [k, x] of Object.entries(v)) {
      let key = k;
      if (k !== "" && !PLAIN_TOKEN.test(k)) {
        key = piece(k) as string;
        if (key === NOT_FULLY_SCANNED) key = `[key withheld ${++n}]`;
      }
      while (Object.hasOwn(next, key)) key = `[key withheld ${++n}]`;
      const y = rewrite(x, depth + 1);
      if (y !== x || key !== k) changed = true;
      setOwn(next, key, y);
    }
    return changed ? next : v;
  };
  const rewrite = (v: unknown, depth: number): unknown => {
    if (depth > MAX_DEPTH || found >= MAX_MESSAGES) {
      if (typeof v !== "string" && typeof v !== "object") return v;
      if (v === null || (typeof v === "string" && v.length === 0)) return v;
      bound ||= depth > MAX_DEPTH ? `nested deeper than ${MAX_DEPTH} levels` : `more than ${MAX_MESSAGES} messages`;
      if (!mailbox) {
        const next = pastBounds(v, depth);
        if (next !== undefined) return next;
      }
      return piece(v);
    }
    if (typeof v === "string") {
      const json = parseJsonText(v);
      if (json !== undefined) return parsedText(v, json, depth);
      return looksLikeRawMessage(v) ? handle(v) : v;
    }
    if (Array.isArray(v)) {
      let changed = false;
      const next = v.map((x) => {
        const y = rewrite(x, depth + 1);
        if (y !== x) changed = true;
        return y;
      });
      return changed ? next : v;
    }
    if (!isObj(v)) return v;
    if (isMessageLike(v)) return handle(v);
    let changed = false;
    const next: Json = {};
    for (const [k, x] of Object.entries(v)) {
      const y = rewrite(x, depth + 1);
      if (y !== x) changed = true;
      setOwn(next, k, y);
    }
    return changed ? next : v;
  };
  const rewritten = rewrite(result, 0);
  out.split = found > 0;
  if (!out.split) {
    // Not readable as messages: scan the whole result as one piece of content (fail closed on a strong signal).
    const { parts, complete } = allText(result);
    const whole = parts.join("\n");
    // The whole result is one piece: its scan and its rewriting pass each have a budget (as for a message).
    const scanned = work.draw();
    let blob = scanMail(pieceMessage(whole), { ...opts, budget: scanned });
    work.settle(scanned);
    if (!complete) blob = tooLarge(blob, opts);
    let next: unknown = result;
    // On the mailbox path a result the scan could not fully read is not withheld, but it is not passed on raw either
    // (as for a message): what the scan read is rewritten, a string the rewrite cannot read becomes the note, and a
    // result whose scan failed is replaced whole by the note. A result cut short by the size bounds is replaced by the
    // note from the cut on (as a tail past the size bounds is, below): what the scan never read is not passed on.
    const blobUnread = mailbox && blob.verdict !== "quarantine" && (!complete || blob.signals.some((x) => x.id === "scan_incomplete"));
    if (mailbox && blob.verdict !== "quarantine" && blob.signals.some((x) => x.id === "scan_failed")) {
      out.messages.push(blob);
      out.output = NOT_FULLY_SCANNED;
      out.outputText = NOT_FULLY_SCANNED;
      return out;
    }
    if (blob.verdict === "neutralize" || blobUnread) {
      const budget = work.draw();
      next = neutralizeDeep(mailbox && !complete ? cutPast(result) : result, budget);
      work.settle(budget);
      if (budget.spent) blob = outOfWork(blob, opts);
    }
    out.messages.push(blob);
    if (blob.verdict === "quarantine") {
      const withheld = { scan: blob, whole: true, note: "could not split the result into messages" };
      const id = enforce ? (opts.record?.(withheld) ?? "") : "";
      out.withheld.push({ id, ...withheld });
      out.output = written(w, NOTICE(id, blob));
      out.outputText = out.output as string;
      return out;
    }
    if (blob.verdict === "flag") out.flagged++;
    if (blob.verdict === "neutralize") out.neutralized++;
    if (blob.verdict === "neutralize" || blobUnread) {
      if (canonicalJson(next) !== canonicalJson(result)) {
        out.output = next;
        out.outputText = outputText(next);
      }
    }
    return out;
  }
  // The values repeated JSON keys shadow (a result that could not be split read those texts whole, as text).
  for (const v of shadowTexts) {
    inTime();
    scanShadowed(v);
  }
  // A rewrite of what lies past the bounds that ran out of its budget put the note in place of what it could not pay
  // for: on the read path that is a part not fully read, so the result is withheld (as for a message: outOfWork).
  const beyondSpent = beyondBudget.done();
  if (beyond.length > 0 || tooDeep) {
    const read = allText(beyond);
    const { parts } = read;
    const complete = read.complete && !tooDeep;
    const text = parts.join("\n");
    const scanned = work.draw();
    let rest = scanMail(pieceMessage(text), { ...opts, budget: scanned });
    work.settle(scanned);
    if (!complete) rest = tooLarge(rest, opts);
    if (beyondSpent && rest.verdict !== "quarantine") rest = outOfWork(rest, opts);
    out.messages.push(rest);
    if (rest.verdict === "quarantine") {
      const withheld = { scan: rest, whole: true, note: `the result ${bound}; the rest was scanned as one piece` };
      const id = enforce ? (opts.record?.(withheld) ?? "") : "";
      out.withheld.push({ id, ...withheld });
      out.output = written(w, `LaunchSafe Firewall withheld this whole result: it was ${bound}, so the rest could not be split into messages, and ${withheldBecause(rest)}. ${RECORD(id)}`);
      out.outputText = out.output as string;
      return out;
    }
    // On the mailbox path the part past the bounds was rewritten already (a string the rewrite cannot read is the
    // note), but a scan of it that failed did not read it at all where it failed: the whole result is replaced by the
    // note, as the part cannot be told apart from the messages here, and nothing is passed on unread.
    if (mailbox && rest.signals.some((x) => x.id === "scan_failed")) {
      out.output = NOT_FULLY_SCANNED;
      out.outputText = NOT_FULLY_SCANNED;
      return out;
    }
    if (rest.verdict === "flag") out.flagged++;
    if (rest.verdict === "neutralize") out.neutralized++;
  }
  // A JSON text whose repeated keys were dropped counts as stripped, so a hook hands back the rewritten result.
  out.neutralized += shadowed;
  const judged = judgedSet(done.values());
  for (const p of pieces) judged.add(p);
  const final = scanOutside(rewritten, opts, out, work, judged, w, inTime);
  if (final !== result) {
    out.output = final;
    out.outputText = outputText(final);
  }
  return out;
}

/** A piece of text the firewall wrote, recorded as such (the backstop does not read it as content). */
function written(w: Written, s: string): string {
  w.strings.add(s);
  return s;
}

/**
 * A scan of text that was cut short by a size bound: withheld on the read path (the rest was never read). On the
 * mailbox path it is not withheld, but it says the scan was incomplete (the caller has put the note in place of
 * what was not read).
 */
function tooLarge(scan: MailScan, opts: MailFilterOptions): MailScan {
  if ((opts.path ?? "read") !== "read") return { ...scan, signals: [...scan.signals, { id: "scan_incomplete", reason: "too_many_strings" }] };
  return { ...scan, verdict: "quarantine", reasons: [...new Set([...scan.reasons, "scan_incomplete" as const])], signals: [...scan.signals, { id: "scan_incomplete", reason: "too_many_strings" }] };
}

/**
 * A scan whose message ran out of its rewriting budget (the scan itself read everything): withheld on the
 * read path, as a part the scan could not pay for is, rather than delivered half-rewritten. A message the
 * person released stays released: the strings the rewrite could not pay for are already replaced by
 * NOT_FULLY_SCANNED, never passed on unread, and the person chose to see the rest (the same as a released
 * message the scan could not fully read).
 */
function outOfWork(scan: MailScan, opts: MailFilterOptions): MailScan {
  if ((opts.path ?? "read") !== "read" || scan.released) return scan;
  return { ...scan, verdict: "quarantine", reasons: [...new Set([...scan.reasons, "scan_incomplete" as const])], signals: [...scan.signals, { id: "scan_incomplete", reason: "work" }] };
}

/**
 * What the first pass put in place of messages, so the pass over the text outside them does not judge it again
 * (and, once the result's work total is spent, withhold a stub for its own sender and subject). A message inside a
 * JSON text is parsed again by that pass, so stubs are known by their content: canonical JSON, the same only for
 * an object identical to one the first pass made.
 */
function judgedSet(replacements: Iterable<unknown>): Set<unknown> {
  const out = new Set<unknown>();
  for (const r of replacements) {
    out.add(r);
    if (isObj(r) && typeof r.withheld === "string") out.add(canonicalJson(r));
  }
  return out;
}

/** The keys a stub can have (stubFor), and the most characters any of its values can hold. */
const STUB_KEYS: ReadonlySet<string> = new Set(["id", "from", "subject", "date", "withheld"]);
const STUB_VALUE_CHARS = 2_000;

/**
 * Whether a value could be a stub: only the keys stubFor writes, each a short string or a number. Checked before the
 * canonical JSON is built, so the pass over the text outside the messages never serializes a large object (a result
 * of many nested objects each with a "withheld" string would otherwise be serialized once per level).
 */
function stubShaped(v: Json): boolean {
  const keys = Object.keys(v);
  if (keys.length > STUB_KEYS.size || typeof own(v, "withheld") !== "string") return false;
  for (const k of keys) {
    if (!STUB_KEYS.has(k)) return false;
    const x = own(v, k);
    if (typeof x === "number") continue;
    if (typeof x !== "string" || x.length > STUB_VALUE_CHARS) return false;
  }
  return true;
}

function isJudged(judged: ReadonlySet<unknown>, v: unknown): boolean {
  if (judged.has(v)) return true;
  return isObj(v) && stubShaped(v) && judged.has(canonicalJson(v));
}

const OUTSIDE_NOTE = "text outside the messages of the result";
/** Strings outside the messages scanned one by one; past this the rest are scanned as one piece. */
const MAX_OUTSIDE = 5_000;

/**
 * After a split, the strings of the result outside its message objects (a thread's snippet, a folder
 * name, a next-page note, object keys) reach the model too. Each is scanned as a piece of mail text: a
 * withheld one is replaced by a notice and recorded, a neutralized one has its hidden parts stripped.
 * Message objects and raw messages were judged already and are left as the first pass made them.
 */
function scanOutside(value: unknown, opts: MailFilterOptions, out: MailFilterResult, work: ResultWork, judged: ReadonlySet<unknown>, w: Written, inTime: () => void = () => undefined): unknown {
  const enforce = opts.mode === "enforce";
  const mailbox = opts.path === "mailbox";
  let count = 0;
  const overflow: string[] = [];
  // The strings outside the messages share one work budget (with the overflow scan below): thousands of them cost no more than one message.
  // Drawn from the result's total on the first string that needs a scan.
  const drawn = work.lazy();
  const judge = (s: string): string => {
    if (s.length === 0 || PLAIN_TOKEN.test(s)) return s;
    if (++count > MAX_OUTSIDE) {
      overflow.push(s);
      return s;
    }
    inTime();
    const scan = scanMail(pieceMessage(s), { ...opts, budget: drawn.get() });
    if (scan.verdict === "quarantine") {
      const withheld = { scan, whole: false, note: OUTSIDE_NOTE };
      const id = enforce ? (opts.record?.(withheld) ?? "") : "";
      out.messages.push(scan);
      out.withheld.push({ id, ...withheld });
      return written(w, `LaunchSafe Firewall withheld this text: ${withheldBecause(scan)}. ${RECORD(id)}`);
    }
    // On the mailbox path a piece the scan could not fully read (or failed on) is not withheld, and not passed on raw.
    if (mailbox && scan.signals.some((x) => x.id === "scan_incomplete" || x.id === "scan_failed")) return NOT_FULLY_SCANNED;
    if (scan.verdict === "flag") out.flagged++;
    if (scan.verdict === "neutralize") {
      out.neutralized++;
      // Stripped as the rewriting pass reads it: as HTML when it has any markup (that reading strips hidden elements).
      const html = MARKUP.test(s);
      return scan.channels.find((c) => c.html === html)?.neutralized ?? scan.channels[0]?.neutralized ?? s;
    }
    return s;
  };
  const walk = (v: unknown, depth: number, pick: (s: string) => string): unknown => {
    // What the first pass put in place of a message (a stub, a rendered raw message) was judged already. Past the
    // depth bound lies only the part past the splitter's bounds (it starts at MAX_DEPTH), which was scanned as one
    // piece, keys included, and rewritten keys included (neutralizeKeep).
    if (depth > MAX_DEPTH + 8 || isJudged(judged, v)) return v;
    if (typeof v === "string") {
      // A JSON text the first pass parsed stands for the same objects it found in it (w.json), so the messages it
      // judged there are known by identity here, as anywhere else. One no pass parsed is read as its parse only when
      // that is all of it (no repeated keys); otherwise it is judged as the text it is.
      const json = w.json.has(v) ? w.json.get(v) : wholeJsonText(v);
      if (json !== undefined) {
        const next = walk(json, depth + 1, pick);
        if (next === json) return v;
        const text = jsonText(next);
        w.json.set(text, next);
        return text;
      }
      return looksLikeRawMessage(v) ? v : pick(v);
    }
    if (Array.isArray(v)) {
      let changed = false;
      const next = v.map((x) => {
        const y = walk(x, depth + 1, pick);
        if (y !== x) changed = true;
        return y;
      });
      return changed ? next : v;
    }
    // A message object is skipped only when the first pass judged that very object (isJudged above): one that only
    // looks like a message (in JSON text the first pass did not parse, past a bound) is read string by string.
    if (!isObj(v)) return v;
    let changed = false;
    let n = 0;
    const next: Json = {};
    for (const [k, x] of Object.entries(v)) {
      let key = pick(k);
      // A rewritten key never takes the place of another (a stripped key equal to a later one, two notices).
      while (Object.hasOwn(next, key)) key = `[key withheld ${++n}]`;
      const y = walk(x, depth + 1, pick);
      if (y !== x || key !== k) changed = true;
      setOwn(next, key, y);
    }
    return changed ? next : v;
  };
  const final = walk(value, 0, judge);
  if (overflow.length === 0) {
    drawn.done();
    return final;
  }
  // Past the bound: the rest as one piece; a strong signal there withholds the whole result (fail closed).
  const blob = overflow.join("\n");
  const scan = scanMail(pieceMessage(blob), { ...opts, budget: drawn.get() });
  drawn.done();
  // On the mailbox path, past the bound: the pieces were not rewritten one by one, so a scan of them that could not
  // read them all (or failed) replaces the whole result by the note rather than passing them on unread.
  if (mailbox && scan.verdict !== "quarantine" && scan.signals.some((x) => x.id === "scan_incomplete" || x.id === "scan_failed")) {
    out.messages.push(scan);
    return NOT_FULLY_SCANNED;
  }
  if (scan.verdict === "neutralize") {
    // The pieces past the bound were passed through the walk as they were: their hidden parts are stripped now, by
    // a second walk that rewrites only them (on a budget of its own; a piece it cannot read becomes the note).
    out.messages.push(scan);
    out.neutralized++;
    const rewrite = work.lazy();
    const fixed = new Map<string, string>();
    for (const s of overflow) if (!fixed.has(s)) fixed.set(s, neutralizeKeep(s, rewrite.get()) as string);
    rewrite.done();
    return walk(final, 0, (s) => fixed.get(s) ?? s);
  }
  if (scan.verdict !== "quarantine") return final;
  const withheld = { scan, whole: true, note: `${OUTSIDE_NOTE}, past ${MAX_OUTSIDE} strings` };
  const id = enforce ? (opts.record?.(withheld) ?? "") : "";
  out.messages.push(scan);
  out.withheld.push({ id, ...withheld });
  return written(w, `LaunchSafe Firewall withheld this whole result: of the text outside its messages, ${withheldBecause(scan)}, and there was too much of it to withhold piece by piece. ${RECORD(id)}`);
}
