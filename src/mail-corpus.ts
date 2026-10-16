/**
 * The email guard's measurement corpus (a measurable false-positive
 * plan, see docs/email-guard.md), built from fixture files: the shared content
 * scanner's corpus (templates, LaunchSafe's own transactional mail, ham,
 * multilingual text, newsletters, mailing-list posts, calendar text, attack
 * payloads) wrapped as whole messages in several shapes, plus the email
 * guard's own messages (`test/fixtures/mail/`).
 *
 * Every fixture is wrapped four ways, so the parser and the splitter are
 * measured on the same content in each form a mail tool hands an agent:
 * multipart/alternative MIME (quoted-printable and base64), a single-part
 * message (legacy charsets for multilingual text), the message forwarded
 * inside another one (message/rfc822), and structured JSON (Microsoft
 * Graph's shape and the Gmail API's payload tree, alternating).
 *
 * Used by `npm run mail-friction` (the gate) and test/mail/corpus.test.ts.
 * Exported from the package so the counts can be reproduced. No real mailbox
 * content and no working exploit: attack payloads are benign markers (LSTEST).
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { TextDecoder } from "node:util";
import type { Verdict } from "./engine/content-scan.js";

export type CorpusGroup = "template" | "newsletter" | "multilingual" | "mailing_list" | "calendar" | "ham" | "attack";

export interface CorpusMessage {
  id: string;
  group: CorpusGroup;
  /** Attack family (recall is measured per family). */
  family?: string;
  /** The wrapper: mime-alt, mime-single, forwarded, graph, gmail-api, raw, json. */
  shape: string;
  /** A raw message (one char per byte) or a structured message object. */
  input: string | Record<string, unknown>;
  /** The verdict this message must get, when it is pinned. */
  expect?: Verdict;
}

// --- encoders (test data only) ------------------------------------------------------------------

const encoderTables = new Map<string, Map<string, number[]> | null>();

/** A reverse table for a charset TextDecoder knows, built by decoding every 1- and 2-byte sequence. */
function table(charset: string): Map<string, number[]> | null {
  if (encoderTables.has(charset)) return encoderTables.get(charset) ?? null;
  let dec: TextDecoder;
  try {
    dec = new TextDecoder(charset, { fatal: true });
  } catch {
    encoderTables.set(charset, null);
    return null;
  }
  const t = new Map<string, number[]>();
  for (let b = 0; b < 256; b++) {
    try {
      const s = dec.decode(Uint8Array.of(b));
      if (s.length > 0 && !t.has(s)) t.set(s, [b]);
    } catch {
      // A lead byte.
    }
  }
  if (/^(?:shift_jis|euc-jp|euc-kr|gbk|gb2312|big5)$/.test(charset)) {
    for (let a = 0x81; a <= 0xfe; a++) {
      for (let b = 0x40; b <= 0xfe; b++) {
        try {
          const s = dec.decode(Uint8Array.of(a, b));
          if (s.length === 1 && !t.has(s)) t.set(s, [a, b]);
        } catch {
          // Not a character.
        }
      }
    }
  }
  encoderTables.set(charset, t);
  return t;
}

/** Text in a legacy charset, or null when a character has no encoding there. */
export function encodeCharset(text: string, charset: string): Uint8Array | null {
  if (charset === "utf-8") return new TextEncoder().encode(text);
  const t = table(charset);
  if (t === null) return null;
  const out: number[] = [];
  for (const ch of text) {
    if (ch === "\n") {
      out.push(0x0d, 0x0a);
      continue;
    }
    const b = t.get(ch);
    if (b === undefined) return null;
    out.push(...b);
  }
  return Uint8Array.from(out);
}

const latin1 = (b: Uint8Array) => Array.from(b, (x) => String.fromCharCode(x)).join("");

function crlf(bytes: Uint8Array): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i] as number;
    if (c === 0x0a && bytes[i - 1] !== 0x0d) out.push(0x0d);
    out.push(c);
  }
  return Uint8Array.from(out);
}

export function base64Lines(bytes: Uint8Array): string {
  const s = Buffer.from(bytes).toString("base64");
  return (s.match(/.{1,76}/g) ?? [""]).join("\r\n");
}

export function quotedPrintable(bytes: Uint8Array): string {
  const lines: string[] = [];
  let line = "";
  const push = (tok: string) => {
    if (line.length + tok.length > 75) {
      lines.push(`${line}=`);
      line = "";
    }
    line += tok;
  };
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i] as number;
    if (c === 0x0d && bytes[i + 1] === 0x0a) {
      lines.push(line);
      line = "";
      i++;
      continue;
    }
    if (c === 0x0a) {
      lines.push(line);
      line = "";
      continue;
    }
    const next = bytes[i + 1];
    const trailingSpace = (c === 0x20 || c === 0x09) && (next === undefined || next === 0x0a || next === 0x0d);
    if ((c >= 0x21 && c <= 0x7e && c !== 0x3d) || ((c === 0x20 || c === 0x09) && !trailingSpace)) push(String.fromCharCode(c));
    else push(`=${c.toString(16).toUpperCase().padStart(2, "0")}`);
  }
  lines.push(line);
  return lines.join("\r\n");
}

/** A header value: as is when ASCII, else RFC 2047 encoded words (B, UTF-8), split on character boundaries. */
export function encodeHeader(text: string): string {
  // eslint-disable-next-line no-control-regex -- ASCII is exactly the range that needs no encoding
  if (/^[\x00-\x7f]*$/.test(text)) return text;
  const words: string[] = [];
  let cur = "";
  for (const ch of text) {
    if (Buffer.byteLength(cur + ch, "utf8") > 45) {
      words.push(cur);
      cur = "";
    }
    cur += ch;
  }
  if (cur !== "") words.push(cur);
  return words.map((w) => `=?UTF-8?B?${Buffer.from(w, "utf8").toString("base64")}?=`).join("\r\n ");
}

// --- MIME builder -------------------------------------------------------------------------------

export interface PartSpec {
  type: string;
  text?: string;
  charset?: string;
  encoding?: "7bit" | "8bit" | "quoted-printable" | "base64";
  filename?: string;
  disposition?: "inline" | "attachment";
  parts?: PartSpec[];
  /** message/rfc822: the inner message. */
  message?: MessageSpec;
  /** Raw bytes (latin1 string) for an attachment. */
  raw?: string;
}

export interface MessageSpec {
  headers: [string, string][];
  body: PartSpec;
}

let boundaryCounter = 0;

function buildPart(p: PartSpec, depth: number): { headers: string[]; body: string } {
  const headers: string[] = [];
  if (p.parts !== undefined) {
    const boundary = `=_ls_${depth}_${(boundaryCounter++).toString(36)}`;
    headers.push(`Content-Type: ${p.type}; boundary="${boundary}"`);
    const body = [`This is a multi-part message in MIME format.`, ...p.parts.map((c) => `--${boundary}\r\n${render(buildPart(c, depth + 1))}`), `--${boundary}--`, ""].join("\r\n");
    return { headers, body };
  }
  if (p.message !== undefined) {
    headers.push(`Content-Type: message/rfc822`);
    if (p.filename !== undefined) headers.push(`Content-Disposition: ${p.disposition ?? "attachment"}; filename="${p.filename}"`);
    return { headers, body: buildMessage(p.message) };
  }
  // A text the requested charset cannot hold goes as UTF-8, and is labelled so.
  const encoded = p.raw === undefined ? encodeCharset(p.text ?? "", p.charset ?? "utf-8") : null;
  const charset = p.raw === undefined && encoded === null ? "utf-8" : (p.charset ?? "utf-8");
  const bytes = p.raw !== undefined ? Uint8Array.from(p.raw, (c) => c.charCodeAt(0)) : crlf(encoded ?? new TextEncoder().encode(p.text ?? ""));
  const isText = p.type.startsWith("text/");
  headers.push(`Content-Type: ${p.type}${isText ? `; charset="${charset}"` : ""}${p.filename !== undefined && !isText ? `; name="${p.filename}"` : ""}${p.type === "text/calendar" ? "; method=REQUEST" : ""}`);
  if (p.filename !== undefined) {
    // Printable ASCII names go as they are; others use RFC 2231.
    const ascii = /^[\x20-\x7e]*$/.test(p.filename) && !/["\\]/.test(p.filename);
    headers.push(`Content-Disposition: ${p.disposition ?? "attachment"}; ${ascii ? `filename="${p.filename}"` : `filename*=utf-8''${encodeURIComponent(p.filename)}`}`);
  }
  const enc = p.encoding ?? (isText ? "quoted-printable" : "base64");
  headers.push(`Content-Transfer-Encoding: ${enc}`);
  const body = enc === "base64" ? base64Lines(bytes) : enc === "quoted-printable" ? quotedPrintable(bytes) : latin1(bytes);
  return { headers, body };
}

const render = (x: { headers: string[]; body: string }) => `${x.headers.join("\r\n")}\r\n\r\n${x.body}`;

/** A raw message, one char per byte (what a tool returning RFC 5322 source hands over). */
export function buildMessage(m: MessageSpec): string {
  const top = m.headers.map(([k, v]) => `${k}: ${encodeHeader(v)}`);
  const part = buildPart(m.body, 0);
  return render({ headers: [...top, "MIME-Version: 1.0", ...part.headers], body: part.body });
}

// --- authentication headers ---------------------------------------------------------------------

export type AuthKind = "pass" | "fail" | "fail_arc_list" | "outlook_pass" | "none";

export function authHeaders(kind: AuthKind, domain: string): [string, string][] {
  switch (kind) {
    case "pass":
      return [["Authentication-Results", `mx.google.com; dkim=pass header.i=@${domain} header.s=s1 header.b=AbCdEf; spf=pass (google.com: domain of bounce@${domain} designates 192.0.2.10 as permitted sender) smtp.mailfrom=bounce@${domain}; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=${domain}`]];
    case "fail":
      return [["Authentication-Results", `mx.google.com; spf=fail (google.com: domain of ${domain} does not designate 198.51.100.7 as permitted sender) smtp.mailfrom=${domain}; dkim=none; dmarc=fail (p=QUARANTINE dis=QUARANTINE) header.from=${domain}`]];
    case "fail_arc_list":
      return [
        ["ARC-Seal", "i=1; a=rsa-sha256; t=1760000000; cv=none; d=googlegroups.com; s=arc-20240605; b=QUJDREVGRw=="],
        ["Authentication-Results", `mx.google.com; dkim=fail header.i=@${domain}; arc=pass (i=1 spf=pass spfdomain=${domain} dkim=pass dkdomain=${domain} dmarc=pass fromdomain=${domain}); spf=pass (google.com: domain of list+bncBC@googlegroups.com designates 209.85.220.69 as permitted sender) smtp.mailfrom=list+bncBC@googlegroups.com; dmarc=fail (p=REJECT sp=REJECT dis=NONE arc=pass) header.from=${domain}`],
      ];
    case "outlook_pass":
      return [
        ["ARC-Authentication-Results", `i=1; mx.microsoft.com 1; spf=pass smtp.mailfrom=${domain}; dmarc=pass action=none header.from=${domain}; dkim=pass header.d=${domain}; arc=none`],
        ["Authentication-Results", `spf=pass (sender IP is 192.0.2.10) smtp.mailfrom=${domain}; dkim=pass (signature was verified) header.d=${domain};dmarc=pass action=none header.from=${domain};compauth=pass reason=100`],
      ];
    case "none":
      return [];
  }
}

// --- wrapping fixtures --------------------------------------------------------------------------

interface Content {
  id: string;
  group: CorpusGroup;
  family?: string;
  html?: string;
  text?: string;
  /** Sender authentication fails (mailing lists, auth attacks). */
  authFail?: boolean;
  expect?: Verdict;
}

const tags = (s: string) => Array.from(s, (c) => String.fromCodePoint(0xe0000 + (c.codePointAt(0) as number))).join("");
/** `{{tags:...}}` in fixture text becomes Unicode tag characters (the files stay readable). */
export const expandTags = (s: string) => s.replace(/\{\{tags:([^}]*(?:\}(?!\})[^}]*)*)\}\}/g, (_, t: string) => tags(t));

/** A legacy charset that can hold the text, by script (multilingual fixtures exercise charset decoding). */
function legacyCharset(text: string): string {
  const candidates = /\p{Script=Hebrew}/u.test(text) ? ["windows-1255", "iso-8859-8"] : /\p{Script=Arabic}/u.test(text) ? ["windows-1256"] : /\p{Script=Thai}/u.test(text) ? ["windows-874"] : /[\p{Script=Hiragana}\p{Script=Katakana}]/u.test(text) ? ["shift_jis", "euc-jp"] : /\p{Script=Hangul}/u.test(text) ? ["euc-kr"] : /\p{Script=Han}/u.test(text) ? ["gbk", "big5"] : /\p{Script=Cyrillic}/u.test(text) ? ["koi8-r", "windows-1251"] : /[À-ÿ]/.test(text) ? ["iso-8859-1", "windows-1252"] : [];
  for (const c of candidates) if (encodeCharset(text, c) !== null) return c;
  return "utf-8";
}

function senderDomain(i: number): string {
  return ["news.example.com", "mail.example.org", "notify.example.net", "example.co.uk", "billing.example.io"][i % 5] as string;
}

function baseHeaders(c: Content, i: number, auth: AuthKind): [string, string][] {
  const d = senderDomain(i);
  return [
    ...authHeaders(auth, d),
    ["From", `Example Sender <hello@${d}>`],
    ["To", "you@example.test"],
    ["Subject", `Fixture ${c.id}`],
    ["Date", `Fri, 10 Oct 2026 ${String(8 + (i % 10)).padStart(2, "0")}:00:00 +0000`],
    ["Message-ID", `<${c.id}.${i}@${d}>`],
  ];
}

function bodyAlt(c: Content): PartSpec {
  if (c.html !== undefined && c.text !== undefined) return { type: "multipart/alternative", parts: [{ type: "text/plain", text: c.text, encoding: "quoted-printable" }, { type: "text/html", text: c.html, encoding: "base64" }] };
  if (c.html !== undefined) return { type: "multipart/alternative", parts: [{ type: "text/html", text: c.html, encoding: "quoted-printable" }] };
  return { type: "text/plain", text: c.text ?? "", encoding: "quoted-printable" };
}

function bodySingle(c: Content): PartSpec {
  const text = c.html ?? c.text ?? "";
  const charset = c.group === "multilingual" ? legacyCharset(text) : "utf-8";
  return { type: c.html !== undefined ? "text/html" : "text/plain", text, charset, encoding: charset === "utf-8" ? "base64" : "8bit" };
}

function graphShape(c: Content, i: number, auth: AuthKind): Record<string, unknown> {
  const d = senderDomain(i);
  return {
    id: `AAMk${i}${c.id}`,
    subject: `Fixture ${c.id}`,
    from: { emailAddress: { name: "Example Sender", address: `hello@${d}` } },
    toRecipients: [{ emailAddress: { name: "You", address: "you@example.test" } }],
    receivedDateTime: "2026-10-10T09:00:00Z",
    bodyPreview: (c.text ?? "").slice(0, 120),
    body: { contentType: c.html !== undefined ? "html" : "text", content: c.html ?? c.text ?? "" },
    internetMessageHeaders: authHeaders(auth, d).map(([name, value]) => ({ name, value })),
  };
}

function gmailShape(c: Content, i: number, auth: AuthKind): Record<string, unknown> {
  const d = senderDomain(i);
  const b64url = (s: string) => Buffer.from(s, "utf8").toString("base64url");
  const parts: Record<string, unknown>[] = [];
  if (c.text !== undefined) parts.push({ mimeType: "text/plain", headers: [{ name: "Content-Type", value: 'text/plain; charset="UTF-8"' }], body: { size: c.text.length, data: b64url(c.text) } });
  if (c.html !== undefined) parts.push({ mimeType: "text/html", headers: [{ name: "Content-Type", value: 'text/html; charset="UTF-8"' }], body: { size: c.html.length, data: b64url(c.html) } });
  return {
    id: `18f${i.toString(16)}`,
    threadId: `18f${i.toString(16)}`,
    labelIds: ["INBOX"],
    snippet: (c.text ?? "").slice(0, 100),
    payload: { mimeType: "multipart/alternative", headers: [...authHeaders(auth, d), ["From", `Example Sender <hello@${d}>`], ["To", "you@example.test"], ["Subject", `Fixture ${c.id}`]].map(([name, value]) => ({ name, value })), parts },
  };
}

/** One content fixture as four messages. */
export function wrapContent(c: Content, i: number): CorpusMessage[] {
  const pass: AuthKind = c.authFail === true ? "fail" : i % 3 === 0 ? "outlook_pass" : "pass";
  const second: AuthKind = c.authFail === true ? (c.group === "mailing_list" ? "fail_arc_list" : "fail") : i % 2 === 0 ? "none" : "pass";
  const base = { group: c.group, ...(c.family !== undefined ? { family: c.family } : {}), ...(c.expect !== undefined ? { expect: c.expect } : {}) };
  const out: CorpusMessage[] = [
    { id: `${c.id}/mime-alt`, shape: "mime-alt", input: buildMessage({ headers: baseHeaders(c, i, pass), body: bodyAlt(c) }), ...base },
    { id: `${c.id}/mime-single`, shape: "mime-single", input: buildMessage({ headers: baseHeaders(c, i, second), body: bodySingle(c) }), ...base },
  ];
  // Forwarded: the sender-authentication rule reads the top message only, so an auth fixture is not forwarded.
  if (c.authFail !== true || c.group === "mailing_list") {
    out.push({
      id: `${c.id}/forwarded`,
      shape: "forwarded",
      input: buildMessage({
        headers: [...authHeaders("pass", "colleague.example"), ["From", "Colleague <me@colleague.example>"], ["To", "you@example.test"], ["Subject", `Fwd: Fixture ${c.id}`], ["Date", "Fri, 10 Oct 2026 12:00:00 +0000"]],
        body: { type: "multipart/mixed", parts: [{ type: "text/plain", text: "Forwarding this, see below.\n" }, { type: "message/rfc822", message: { headers: baseHeaders(c, i, c.authFail === true ? "fail" : "pass"), body: bodyAlt(c) } }] },
      }),
      ...base,
      // A forwarded mailing-list post keeps its pinned verdict only when it was not auth-dependent.
      ...(c.expect !== undefined ? { expect: c.expect } : {}),
    });
  }
  out.push(i % 2 === 0 ? { id: `${c.id}/graph`, shape: "graph", input: graphShape(c, i, second === "none" ? pass : second), ...base } : { id: `${c.id}/gmail-api`, shape: "gmail-api", input: gmailShape(c, i, second === "none" ? pass : second), ...base });
  return out;
}

interface ContentManifest {
  files: Record<string, { group: string; html: boolean }>;
}

/** The shared content scanner's fixtures as content items (HTML and text parts of one template paired). */
export function contentItems(contentDir: string): Content[] {
  const manifest = JSON.parse(readFileSync(join(contentDir, "manifest.json"), "utf8")) as ContentManifest;
  const items: Content[] = [];
  const byBase = new Map<string, { html?: string; text?: string; group: string }>();
  for (const [file, m] of Object.entries(manifest.files)) {
    const base = file.replace(/\.(?:html|txt)$/, "");
    const e = byBase.get(base) ?? { group: m.group };
    const body = readFileSync(join(contentDir, file), "utf8");
    if (m.html) e.html = body;
    else e.text = body;
    byBase.set(base, e);
  }
  for (const [base, e] of byBase) items.push({ id: base, group: e.group as CorpusGroup, ...(e.html !== undefined ? { html: e.html } : {}), ...(e.text !== undefined ? { text: e.text } : {}) });
  const cases = JSON.parse(readFileSync(join(contentDir, "cases.json"), "utf8")) as { id: string; group: string; text: string; html?: boolean; authFail?: boolean; expect?: Verdict }[];
  for (const c of cases) {
    const text = expandTags(c.text);
    // A pinned verdict that depends on the text's own (missing) authentication is only kept where it holds.
    items.push({ id: `case/${c.id}`, group: c.group as CorpusGroup, ...(c.html === true ? { html: text } : { text }), ...(c.authFail === true ? { authFail: true } : {}), ...(c.expect !== undefined ? { expect: c.expect } : {}) });
  }
  const attacks = JSON.parse(readFileSync(join(contentDir, "attacks.json"), "utf8")) as { id: string; family: string; text: string; html?: boolean; authFail?: boolean }[];
  for (const a of attacks) {
    const text = expandTags(a.text);
    items.push({ id: `attack/${a.id}`, group: "attack", family: a.family, ...(a.html === true ? { html: text } : { text }), ...(a.authFail === true ? { authFail: true } : {}) });
  }
  return items;
}

interface MailFixture {
  id: string;
  group: CorpusGroup;
  family?: string;
  expect?: Verdict;
  /** A message spec (built to MIME), a structured object, or a file under eml/. */
  message?: MessageSpec;
  json?: Record<string, unknown>;
  eml?: string;
}

/** Expands `{{tags:...}}` in every string of a fixture. */
function expandDeep<T>(v: T): T {
  if (typeof v === "string") return expandTags(v) as T;
  if (Array.isArray(v)) return v.map(expandDeep) as T;
  if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, expandDeep(x)])) as T;
  return v;
}

/** The email guard's own fixtures (test/fixtures/mail/messages.json and eml/). */
export function mailItems(mailDir: string): CorpusMessage[] {
  const list = expandDeep(JSON.parse(readFileSync(join(mailDir, "messages.json"), "utf8")) as { messages: MailFixture[] }).messages;
  const out: CorpusMessage[] = [];
  for (const f of list) {
    const base = { id: `mail/${f.id}`, group: f.group, ...(f.family !== undefined ? { family: f.family } : {}), ...(f.expect !== undefined ? { expect: f.expect } : {}) };
    if (f.message !== undefined) out.push({ ...base, shape: "mime", input: buildMessage(f.message) });
    else if (f.json !== undefined) out.push({ ...base, shape: "json", input: f.json });
    else if (f.eml !== undefined) out.push({ ...base, shape: "raw", input: readFileSync(join(mailDir, "eml", f.eml), "latin1") });
  }
  return out;
}

/** Every message of the corpus. */
export function buildMailCorpus(contentDir: string, mailDir: string): CorpusMessage[] {
  boundaryCounter = 0;
  const out: CorpusMessage[] = [];
  contentItems(contentDir).forEach((c, i) => out.push(...wrapContent(c, i)));
  out.push(...mailItems(mailDir));
  // eml files not named in messages.json are ham by default (a dropped-in sample is measured, not ignored).
  const named = new Set((JSON.parse(readFileSync(join(mailDir, "messages.json"), "utf8")) as { messages: MailFixture[] }).messages.map((m) => m.eml).filter((x): x is string => x !== undefined));
  let files: string[] = [];
  try {
    files = readdirSync(join(mailDir, "eml")).filter((n) => n.endsWith(".eml") && !named.has(n));
  } catch {
    files = [];
  }
  for (const n of files.sort()) out.push({ id: `eml/${n}`, group: "ham", shape: "raw", input: readFileSync(join(mailDir, "eml", n), "latin1") });
  return out;
}
