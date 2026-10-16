/**
 * v0.3 E1: the message parser (src/engine/mail/mime.ts). RFC 5322 headers,
 * RFC 2047 encoded words, RFC 2231 parameters, MIME nesting, transfer
 * encodings, charsets, forwarded messages, the 10 MiB cap and the structured
 * shapes mail APIs return. Hostile input never throws.
 */
import { describe, expect, it } from "vitest";
import { calendarFields, channels, decodeBase64, decodeCharset, decodeEncodedWords, decodeQuotedPrintable, fromStructured, headerText, looksLikeRawMessage, MIME_LIMITS, parseAddresses, parseMime, parseParams, rawSource, toBytes, trimTruncation, type MailProblem } from "../../src/engine/mail/mime.js";
import { buildMessage, encodeCharset } from "../../src/mail-corpus.js";

const td = (b: Uint8Array) => new TextDecoder().decode(b);

describe("transfer encodings", () => {
  it("decodes quoted-printable with soft breaks, =XX and malformed escapes kept", () => {
    expect(td(decodeQuotedPrintable(toBytes("caf=C3=A9 au l=\r\nait =ZZ ok=\n")))).toBe("café au lait =ZZ ok");
    expect(td(decodeQuotedPrintable(toBytes("a =  \r\nb")))).toBe("a b");
  });
  it("decodes base64 and base64url, ignoring whitespace and junk", () => {
    expect(td(decodeBase64("aGVs\r\nbG8g d29y\tbGQ="))).toBe("hello world");
    expect(td(decodeBase64(Buffer.from("ü?>", "utf8").toString("base64url")))).toBe("ü?>");
  });
  it("Q encoded words read _ as a space", () => {
    expect(td(decodeQuotedPrintable(toBytes("a_b=3F"), true))).toBe("a b?");
  });
});

describe("charsets", () => {
  it("decodes legacy charsets through TextDecoder", () => {
    for (const [cs, text] of [["iso-8859-1", "Réunion à 10h"], ["windows-1256", "سلام مي‌خواهم"], ["windows-1255", "שלום‏"], ["koi8-r", "Встреча"], ["shift_jis", "会議の件"], ["euc-kr", "회의"], ["big5", "會議"], ["windows-874", "สวัสดี"]] as const) {
      const bytes = encodeCharset(text, cs);
      expect(bytes, cs).not.toBeNull();
      expect(decodeCharset(bytes as Uint8Array, cs), cs).toBe(text);
    }
  });
  it("an unknown charset is read as Latin-1 and noted, never thrown", () => {
    const problems: MailProblem[] = [];
    expect(decodeCharset(Uint8Array.of(0x68, 0xe9), "x-made-up", problems)).toBe("hé");
    expect(problems.map((p) => p.kind)).toEqual(["undecodable_charset"]);
  });
  it("text that claims UTF-8 but is not is read as Latin-1 and noted", () => {
    const problems: MailProblem[] = [];
    expect(decodeCharset(Uint8Array.of(0x63, 0x61, 0x66, 0xe9), "utf-8", problems)).toBe("café");
    expect(problems[0]?.kind).toBe("charset_mismatch");
  });
  it("ASCII declared but 8-bit inside is read as UTF-8", () => {
    expect(decodeCharset(new TextEncoder().encode("naïve"), "us-ascii")).toBe("naïve");
  });
});

describe("headers", () => {
  it("decodes RFC 2047 words and joins adjacent ones without the space between", () => {
    expect(decodeEncodedWords("=?ISO-8859-1?Q?R=E9union_de_l=27=E9quipe?= =?ISO-8859-1?Q?_=E0_10h?=")).toBe("Réunion de l'équipe à 10h");
    expect(decodeEncodedWords("Hi =?UTF-8?B?w7w=?= there")).toBe("Hi ü there");
    expect(decodeEncodedWords("=?utf-8*en?q?caf=C3=A9?=")).toBe("café");
  });
  it("parses content-type parameters, quoted, continued (RFC 2231) and charset-tagged", () => {
    expect(parseParams('multipart/mixed; boundary="a;b"; x=1')).toEqual({ type: "multipart/mixed", params: { boundary: "a;b", x: "1" } });
    expect(parseParams("attachment; filename*=utf-8''Rechnung_%E2%82%AC.pdf").params.filename).toBe("Rechnung_€.pdf");
    expect(parseParams("attachment; filename*0=\"long\"; filename*1=\"name.txt\"").params.filename).toBe("longname.txt");
  });
  it("parses RFC 2231 parameter continuations >= 65 KB without stack overflow", () => {
    const big = "a".repeat(100_000);
    expect(parseParams(`attachment; filename*0="${big}"; filename*1=".txt"`).params.filename).toBe(`${big}.txt`);
  });
  it("splits address lists outside quotes and angle brackets", () => {
    expect(parseAddresses('"Lee, Morgan" <m@x.example>, b@y.example (Bee), =?UTF-8?B?w4lsaWU=?= <e@z.example>')).toEqual([
      { name: "Lee, Morgan", address: "m@x.example" },
      { name: "Bee", address: "b@y.example" },
      { name: "Élie", address: "e@z.example" },
    ]);
  });
  it("unfolds folded headers and keeps their order (top first)", () => {
    const m = parseMime("Received: a\r\n\tb\r\nAuthentication-Results: one\r\nAuthentication-Results: two\r\nSubject: long\r\n subject\r\nFrom: x@y.example\r\n\r\nbody");
    expect(m.headers.map((h) => h.value)).toEqual(["a b", "one", "two", "long subject", "x@y.example"]);
    expect(headerText(m.headers, "subject")).toBe("long subject");
  });
  it("reads raw UTF-8 headers (RFC 6532)", () => {
    const m = parseMime(Buffer.from("From: Zoë <z@example.com>\nSubject: Grüße\n\nhi", "utf8"));
    expect(headerText(m.headers, "subject")).toBe("Grüße");
  });
});

describe("MIME structure", () => {
  it("multipart/alternative: text and HTML parts with their encodings", () => {
    const raw = buildMessage({ headers: [["From", "a@example.com"], ["Subject", "S"]], body: { type: "multipart/alternative", parts: [{ type: "text/plain", text: "plain ü", encoding: "quoted-printable" }, { type: "text/html", text: "<p>html ü</p>", encoding: "base64" }] } });
    const m = parseMime(raw);
    expect(m.text).toEqual(["plain ü\r\n".trimEnd()]);
    expect(m.html).toEqual(["<p>html ü</p>"]);
    expect(m.problems).toEqual([]);
  });
  it("forwarded messages (message/rfc822) are parsed recursively, and attachments are listed, not read", () => {
    const raw = buildMessage({
      headers: [["From", "me@example.com"], ["Subject", "Fwd"]],
      body: { type: "multipart/mixed", parts: [{ type: "text/plain", text: "see below" }, { type: "message/rfc822", message: { headers: [["From", "inner@example.org"], ["Subject", "Inner"]], body: { type: "text/html", text: "<b>inner</b>" } } }, { type: "application/pdf", raw: "%PDF-1.4", filename: "a €.pdf" }] },
    });
    const m = parseMime(raw);
    expect(m.nested).toHaveLength(1);
    expect(headerText(m.nested[0]?.headers ?? [], "subject")).toBe("Inner");
    expect(m.nested[0]?.html).toEqual(["<b>inner</b>"]);
    expect(m.attachments).toEqual([{ filename: "a €.pdf", contentType: "application/pdf", size: 8 }]);
    const names = channels(m).map((c) => `${c.path}:${c.name}`);
    expect(names).toContain("forwarded/1:html");
    expect(names).toContain(":attachment_name");
  });
  it("inline AMP and watch HTML alternatives are read as HTML; other inline text types as text; attached ones are not read (V24)", () => {
    const raw = buildMessage({
      headers: [["From", "a@example.com"], ["Subject", "S"]],
      body: { type: "multipart/mixed", parts: [
        { type: "multipart/alternative", parts: [{ type: "text/plain", text: "plain" }, { type: "text/x-amp-html", text: "<p>amp</p>" }, { type: "text/watch-html", text: "<p>watch</p>" }] },
        { type: "text/rtf", text: "{\\rtf1 rich}" },
        { type: "text/csv", text: "a,b", filename: "inline.csv", disposition: "inline" },
        { type: "text/csv", text: "c,d", filename: "data.csv", disposition: "attachment" },
      ] },
    });
    const m = parseMime(raw);
    expect(m.html).toEqual(["<p>amp</p>", "<p>watch</p>"]);
    expect(m.text).toEqual(["plain", "{\\rtf1 rich}", "a,b"]);
    expect(m.attachments.map((a) => a.filename)).toEqual(["inline.csv", "data.csv"]);
  });
  it("a Gmail API payload's AMP part is read as HTML (V24)", () => {
    const data = Buffer.from("<p>amp</p>").toString("base64url");
    const m = fromStructured({ id: "1", payload: { mimeType: "multipart/alternative", headers: [{ name: "From", value: "a@example.com" }, { name: "Subject", value: "S" }], parts: [{ mimeType: "text/x-amp-html", body: { data } }] } });
    expect(m.html).toEqual(["<p>amp</p>"]);
  });
  it("nesting deeper than 10 is a bound (noted), not a crash", () => {
    let body = "Content-Type: text/plain\r\n\r\ndeep";
    for (let i = 0; i < 14; i++) body = `Content-Type: multipart/mixed; boundary="b${i}"\r\n\r\n--b${i}\r\n${body}\r\n--b${i}--\r\n`;
    const m = parseMime(`From: a@example.com\r\nSubject: deep\r\n${body}`);
    expect(m.problems.some((p) => p.kind === "depth")).toBe(true);
  });
  it("a multipart without its closing delimiter still yields its last part", () => {
    const m = parseMime('From: a@example.com\nContent-Type: multipart/mixed; boundary="x"\n\n--x\nContent-Type: text/plain\n\nfirst\n--x\nContent-Type: text/plain\n\nsecond, never closed');
    expect(m.text).toEqual(["first", "second, never closed"]);
  });
  it("a multipart without a boundary is read as text and noted", () => {
    const m = parseMime("From: a@example.com\nContent-Type: multipart/mixed\n\nhello");
    expect(m.text).toEqual(["hello"]);
    expect(m.problems[0]?.kind).toBe("malformed");
  });
  it("calendar parts: SUMMARY, DESCRIPTION, LOCATION as text, X-ALT-DESC as HTML, unescaped and unfolded", () => {
    const f = calendarFields("BEGIN:VEVENT\r\nSUMMARY:Plan\\, review\r\nDESCRIPTION:Line one\\nline\r\n  two\r\nX-ALT-DESC;FMTTYPE=text/html:<p>x</p>\r\nEND:VEVENT");
    expect(f.text).toEqual(["Plan, review", "Line one\nline two"]);
    expect(f.html).toEqual(["<p>x</p>"]);
  });
  it("a message over 10 MiB is not parsed past its headers (too_large)", () => {
    const raw = `From: big@example.com\r\nSubject: big\r\n\r\n${"a".repeat(MIME_LIMITS.maxBytes + 10)}`;
    const m = parseMime(raw);
    expect(m.problems.map((p) => p.kind)).toEqual(["too_large"]);
    expect(headerText(m.headers, "subject")).toBe("big");
    expect(m.text).toEqual([]);
  });
  it("an mbox From line is skipped", () => {
    const m = parseMime("From jo@example.com Fri Oct 10 09:00:00 2026\nFrom: Jo <jo@example.com>\nSubject: hi\n\nbody");
    expect(headerText(m.headers, "subject")).toBe("hi");
  });
  it("never throws on junk", () => {
    for (const junk of ["", "\r\n\r\n", "::::", "Content-Type: multipart/mixed; boundary=\"\"\n\n--\n--", "\u0000\u0001\u0002", "=?x?B?!!!?="]) expect(() => parseMime(junk)).not.toThrow();
  });
});

describe("structured shapes", () => {
  it("a Graph message's uniqueBody is read like its body (V25)", () => {
    const m = fromStructured({ id: "1", from: { emailAddress: { name: "Shop", address: "news@shop.example" } }, subject: "S", body: { contentType: "html", content: "<p>body</p>" }, uniqueBody: { contentType: "html", content: "<p>unique</p>" } });
    expect(m.html).toEqual(["<p>body</p>", "<p>unique</p>"]);
    const t = fromStructured({ id: "2", from: "a@example.com", subject: "S", uniqueBody: { contentType: "text", content: "new part" } });
    expect(t.text).toEqual(["new part"]);
  });
  it("a generic { from, subject, html } object", () => {
    const m = fromStructured({ from: "Ann <ann@example.com>", subject: "Hi", html: "<p>x</p>", attachments: ["a.pdf"] });
    expect(headerText(m.headers, "from")).toBe("Ann <ann@example.com>");
    expect(m.html).toEqual(["<p>x</p>"]);
    expect(m.attachments[0]?.filename).toBe("a.pdf");
  });
  it("Microsoft Graph: from.emailAddress, body.contentType, internetMessageHeaders", () => {
    const m = fromStructured({ subject: "S", from: { emailAddress: { name: "N", address: "n@example.com" } }, body: { contentType: "html", content: "<p>b</p>" }, bodyPreview: "b", internetMessageHeaders: [{ name: "Authentication-Results", value: "mx.google.com; dmarc=pass" }] });
    expect(headerText(m.headers, "from")).toBe('"N" <n@example.com>');
    expect(m.html).toEqual(["<p>b</p>"]);
    expect(m.snippet).toBe("b");
    expect(headerText(m.headers, "authentication-results")).toContain("dmarc=pass");
  });
  it("Gmail API: payload tree with base64url bodies and headers", () => {
    const m = fromStructured({ id: "1", snippet: "s", payload: { mimeType: "multipart/alternative", headers: [{ name: "From", value: "a@example.com" }, { name: "Subject", value: "G" }], parts: [{ mimeType: "text/plain", body: { data: Buffer.from("plain").toString("base64url") } }, { mimeType: "text/html", body: { data: Buffer.from("<i>h</i>").toString("base64url") } }, { mimeType: "application/pdf", filename: "f.pdf", body: { attachmentId: "x", size: 3 } }] } });
    expect(m.text).toEqual(["plain"]);
    expect(m.html).toEqual(["<i>h</i>"]);
    expect(m.attachments).toEqual([{ filename: "f.pdf", contentType: "application/pdf", size: 3 }]);
  });
  it("a raw source (plain or base64url, Gmail format=raw) wins over the other keys", () => {
    const raw = "From: r@example.com\r\nSubject: Raw\r\nDate: x\r\n\r\nraw body";
    expect(rawSource(Buffer.from(raw).toString("base64url"))).toBe(raw);
    expect(fromStructured({ raw: Buffer.from(raw).toString("base64url"), snippet: "raw" }).text).toEqual(["raw body"]);
    expect(looksLikeRawMessage(raw)).toBe(true);
    expect(looksLikeRawMessage("Subject: no other header\n\nx")).toBe(false);
  });
  it("a provider preview cut inside a flag emoji drops the cut tail", () => {
    const eng = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}";
    expect(trimTruncation(`go ${eng.slice(0, 5)}`)).toBe("go ");
    expect(trimTruncation(`go ${eng}`)).toBe(`go ${eng}`);
  });
});

describe("hostile input stays linear", () => {
  it("a boundary longer than 70 characters is malformed, read as text, and fast on a large body", () => {
    const boundary = "-".repeat(100_000);
    const body = "-".repeat(2 * 1024 * 1024);
    const t0 = Date.now();
    const m = parseMime(`From: a@example.com\nContent-Type: multipart/mixed; boundary="${boundary}"\n\n${body}`);
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(m.problems.some((p) => p.kind === "malformed")).toBe(true);
  });
  it("a normal boundary still splits parts (native search)", () => {
    const m = parseMime('From: a@example.com\nContent-Type: multipart/mixed; boundary="x"\n\n--x\nContent-Type: text/plain\n\none\n--x\nContent-Type: text/plain\n\ntwo\n--x--\n');
    expect(m.text).toEqual(["one", "two"]);
  });
  it("an address list of unclosed angle brackets and comments is parsed in bounded time", () => {
    const t0 = Date.now();
    parseAddresses("<a>(".repeat(50_000));
    expect(Date.now() - t0).toBeLessThan(2000);
  });
});
