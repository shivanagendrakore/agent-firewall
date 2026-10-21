// Vendored from the LaunchSafe Agent Firewall (src/engine/content-scan.ts), Apache-2.0, at commit 79fa72df3ba323a23e186e2ca856297a78fc8194.
// Licence: Apache-2.0 (see NOTICE).
// Do not edit here: it is copied from the firewall repository by
// `node scripts/sync-firewall.mjs` (`--check` verifies the copy).

/**
 * The shared content scanner.
 *
 * Used by the MCP gateway for every tool result and by the email guard for
 * every text channel of a message. It detects hidden text (Unicode tag
 * characters, dense zero-width characters, bidirectional controls outside
 * right-to-left text, CSS-hidden HTML) and text addressed to an AI agent, and
 * returns a verdict:
 *
 * - `quarantine`: hidden, agent-directed content (withhold it and record it);
 * - `neutralize`: hidden content with nothing agent-directed (strip it, deliver the rest);
 * - `flag`: visible agent-directed content (deliver unchanged, annotate);
 * - `deliver`.
 *
 * Deterministic, never a model. Pure: no I/O, no dependencies beyond the
 * engine's own string helpers and the vendored agent-safety signals, so the
 * gateway, the mail detector and (later) the hosted guard run the same code.
 * Bounded by size, node, rule and matching-step limits and a work budget (all
 * deterministic, see WorkBudget), and by
 * a wall-clock limit as a last resort; past a bound the result carries
 * `scan_incomplete` and the caller decides (fail closed).
 */
import { decodeTagCharacters, revealInvisible } from "../vendor/agent-safety/signals.js";
import { analyzeHtml, decodeEntities, MATCH_STEPS, type HiddenHow } from "./content-html.js";
import { LEXICON_A, LEXICON_B, lexiconHits, lexiconPlaces, type LexiconHit } from "./content-lexicon.js";
import { entropy, isCaptureHost, parseUrlLike } from "./network.js";

export type { HiddenHow } from "./content-html.js";

export type Signal =
  /** U+E0000–E007F outside an RGI subdivision flag; `decoded` is the smuggled ASCII. */
  | { id: "tag_chars"; decoded: string }
  /**
   * Zero-width characters outside emoji ZWJ sequences and Indic/Arabic/Persian joiner use (8 or more, or 4 in a row);
   * `nearInstruction` when an agent-directed phrase is within 200 characters of one of them, before or after it
   * (every place a phrase appears counts, not only its first: see phraseNear).
   */
  | { id: "zero_width_dense"; count: number; runs: number; nearInstruction: boolean }
  /** Bidirectional overrides or isolates with no right-to-left letters around them. */
  | { id: "bidi_outside_rtl"; count: number }
  /** A hidden span of HTML. `instruction` when it carries a lexicon hit; `preheader` for a marketing preview line. */
  | { id: "hidden_html"; chars: number; duplicate: boolean; how: HiddenHow[]; preheader: boolean; instruction: boolean }
  /** Lexicon A: addressed to an AI agent. */
  | { id: "agent_directed"; phrase: string; hidden: boolean; entry: string }
  /** Lexicon B: a generic imperative; only reported inside hidden text. */
  | { id: "imperative"; phrase: string; hidden: boolean; entry: string }
  /** An image or link URL that templates data for the model to fill, or a capture host (or, hidden only, a long random query value). */
  | { id: "exfil_link"; host: string; hidden: boolean; why: "template" | "capture_host" | "query_entropy" }
  | { id: "scan_incomplete"; reason: string };

export type Verdict = "deliver" | "neutralize" | "flag" | "quarantine";

/** The quarantine rules, named as in the `emailGuard.quarantineOn` policy key. */
export type QuarantineReason = "tag_chars" | "hidden_instruction" | "dense_zero_width_instruction" | "hidden_exfil_link" | "auth_fail_instruction";
export const QUARANTINE_REASONS: readonly QuarantineReason[] = ["tag_chars", "hidden_instruction", "dense_zero_width_instruction", "hidden_exfil_link", "auth_fail_instruction"];

export interface ScanResult {
  signals: Signal[];
  /** The content with hidden parts stripped; present when there was something to strip. */
  neutralized?: string;
  /** Characters removed to produce `neutralized` (code points of the source). */
  strippedChars: number;
  verdict: Verdict;
  /** The quarantine rules that fired (empty unless the verdict is `quarantine`). */
  reasons: QuarantineReason[];
  /** Up to 200 characters of the hidden text, escaped (what the agent would have read), for records. */
  hiddenPreview: string;
}

export interface ScanOptions {
  /** Parse as HTML (hidden spans, styles). */
  html?: boolean;
  /** Text bound in UTF-8 bytes (default 4 MiB). HTML is further bounded by `maxHtmlBytes`. */
  maxBytes?: number;
  maxHtmlBytes?: number;
  maxNodes?: number;
  maxCssRules?: number;
  /** Style-sheet matching steps for the document (default MATCH_STEPS, see HtmlLimits). */
  maxMatchSteps?: number;
  /**
   * The work budget this scan charges (see WorkBudget). The mail detector passes one budget to every scan of
   * a message, its rewriting pass included; without one, the scan gets its own of `maxWork` units.
   */
  budget?: WorkBudget;
  /** Units of the scan's own work budget when no `budget` is passed (default SCAN_LIMITS.maxWork). */
  maxWork?: number;
  /**
   * Wall-clock budget in milliseconds (default 2000), a last resort only. The size, node, rule and matching-step
   * bounds are what keep a scan short (a few hundred milliseconds at the bounds), so a scan's result does not
   * depend on the clock; a stage the clock does cut makes the result incomplete (`scan_incomplete`, `time`).
   */
  timeoutMs?: number;
  /** Clock in milliseconds, for tests. */
  now?: () => number;
  /** Mail only: the sender failed authentication (the mail detector's auth reader decides). */
  authFail?: boolean;
  /** Which quarantine rules apply (default all five); a removed rule degrades to neutralize or flag. */
  quarantineOn?: readonly QuarantineReason[];
  /**
   * Text only: no person is shown this text (a mail header other than the address ones, a MIME preamble),
   * but a model reading the source is. A phrase in it addressed to an AI agent is hidden text with an
   * instruction (`hidden_html`, how `not_displayed`), unless the same phrase is in `visible`, the text the
   * person is shown (an echo such as Exchange's Thread-Topic copy of the subject).
   *
   * The visible text is charged to the budget once per object, not once per scan: the mail detector passes
   * the same object for every unshown channel of a message, so a long forwarded chain with an unshown header
   * at each level pays for its displayed text once. `paid` and `norm` are that cache (set by the scan).
   */
  unshown?: UnshownContext;
  /** Mail only: the subjects of the message. A `<title>` that is the subject is the sender's tool's default, not a hidden instruction. */
  subjects?: readonly string[];
}

/** The displayed text an unshown channel is compared with, and what the scans of one message cached of it. */
export interface UnshownContext {
  visible: string;
  /** The visible text was charged to the message's budget (once). */
  paid?: boolean;
  /** The visible text normalized for the echo test (made once). */
  norm?: string;
}

export const SCAN_LIMITS = {
  maxBytes: 4 * 1024 * 1024,
  maxHtmlBytes: 2 * 1024 * 1024,
  maxNodes: 50_000,
  maxCssRules: 2_000,
  timeoutMs: 2_000,
  /** Units of work for one scan, or for all the scans of one mail message (see WorkBudget). */
  maxWork: 64_000_000,
} as const;

/**
 * A deterministic work budget, counted in units: one per character a scan reads (each part's text, and
 * once per message the displayed text unshown headers are compared against), one per style-sheet matching
 * step, and one per 64 characters searched when hidden text is compared with the visible text. Several
 * scans can share one (the mail detector gives each message one, shared by all its parts and channels; the
 * mail filter's rewriting pass, which reads the same text again, gets a second one of the same size), so
 * the work for a message is bounded by its budgets, not by its number of parts. A scan that finds the budget
 * spent does not read its content and reports `scan_incomplete` (`work`); the budget is then `spent`
 * for every later scan, and the same input is cut at the same place every time. At the default
 * (64,000,000) a message takes at most a second or two of work; every message of the mail and content
 * corpora uses a small part of it.
 */
export interface WorkBudget {
  left: number;
  /** A scan found the budget too small for its content (set once, never cleared). */
  spent: boolean;
}

export function workBudget(units: number = SCAN_LIMITS.maxWork): WorkBudget {
  return { left: units, spent: false };
}

/** Units charged per scan on top of the characters it reads (a part's fixed costs: lexicon setup, results). */
const SCAN_OVERHEAD = 64;

/**
 * Charges `units` to a budget; false (and the budget marked spent) when it cannot pay. A budget once spent
 * stays spent, so the parts after it are all reported incomplete.
 */
function charge(b: WorkBudget, units: number): boolean {
  if (b.spent || b.left < units) {
    b.left = 0;
    b.spent = true;
    return false;
  }
  b.left -= units;
  return true;
}

/** Units for searching `haystack` for `needle` (a duplicate check): the characters the search reads, per 64. */
function searchUnits(haystack: string, needle: string): { found: boolean; units: number } {
  const at = haystack.indexOf(needle);
  const read = at === -1 ? haystack.length : at + needle.length;
  return { found: at !== -1, units: 1 + (read >> 6) + (needle.length >> 6) };
}

/** Signals of each kind kept in one result (records stay small; the verdict only needs one). */
const MAX_PER_KIND = 20;

// --- characters -------------------------------------------------------------------------------

const CANDIDATE = /[\u200B-\u200D\u2060-\u2064\uFEFF\u180E\u202A-\u202E\u2066-\u2069]|\uDB40[\uDC00-\uDC7F]/g;
/** Scripts whose spelling uses ZWJ and ZWNJ (Indic, Arabic and Persian, Sinhala, and their neighbours). */
const JOINING_SCRIPT =
  /[\p{Script_Extensions=Devanagari}\p{Script_Extensions=Bengali}\p{Script_Extensions=Gurmukhi}\p{Script_Extensions=Gujarati}\p{Script_Extensions=Oriya}\p{Script_Extensions=Tamil}\p{Script_Extensions=Telugu}\p{Script_Extensions=Kannada}\p{Script_Extensions=Malayalam}\p{Script_Extensions=Sinhala}\p{Script_Extensions=Arabic}\p{Script_Extensions=Syriac}\p{Script_Extensions=Thaana}\p{Script_Extensions=Nko}\p{Script_Extensions=Mongolian}\p{Script_Extensions=Khmer}\p{Script_Extensions=Myanmar}\p{Script_Extensions=Tibetan}]/u;
const RTL = /[\p{Script=Hebrew}\p{Script=Arabic}\p{Script=Syriac}\p{Script=Thaana}\p{Script=Nko}\p{Script=Samaritan}\p{Script=Mandaic}\p{Script=Adlam}]/u;
const PICTOGRAPHIC = /\p{Extended_Pictographic}|\p{Emoji_Modifier}|\p{Regional_Indicator}/u;
const MARK = /\p{M}/u;
/** The RGI subdivision flags (England, Scotland, Wales): the only tag sequences that are emoji. */
const RGI_SUBDIVISIONS = new Set(["gbeng", "gbsct", "gbwls"]);

interface CharScan {
  /** UTF-16 [start, end) ranges of characters to strip. */
  remove: [number, number][];
  tagDecoded: string;
  tagCount: number;
  zwPositions: number[];
  zwRuns: number;
  zwMaxRun: number;
  bidiCount: number;
}

/** The code point before a UTF-16 index, and its start index. */
function prevCp(text: string, i: number): { cp: number; at: number } | null {
  if (i <= 0) return null;
  const lo = text.charCodeAt(i - 1);
  if (lo >= 0xdc00 && lo <= 0xdfff && i >= 2) {
    const hi = text.charCodeAt(i - 2);
    if (hi >= 0xd800 && hi <= 0xdbff) return { cp: text.codePointAt(i - 2) as number, at: i - 2 };
  }
  return { cp: lo, at: i - 1 };
}

function nextCp(text: string, i: number): { cp: number; at: number; len: number } | null {
  if (i >= text.length) return null;
  const cp = text.codePointAt(i) as number;
  return { cp, at: i, len: cp > 0xffff ? 2 : 1 };
}

const isZw = (c: number) => (c >= 0x200b && c <= 0x200d) || (c >= 0x2060 && c <= 0x2064) || c === 0xfeff || c === 0x180e;
const isBidi = (c: number) => (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);

/** The neighbouring letter, skipping combining marks and other joiners. */
function letterAround(text: string, i: number, dir: -1 | 1, width: number): string | null {
  let at = dir === -1 ? i : i + width;
  for (let k = 0; k < 4; k++) {
    const p = dir === -1 ? prevCp(text, at) : nextCp(text, at);
    if (p === null) return null;
    const ch = String.fromCodePoint(p.cp);
    if (MARK.test(ch) || p.cp === 0x200c || p.cp === 0x200d) {
      at = dir === -1 ? p.at : p.at + (p.cp > 0xffff ? 2 : 1);
      continue;
    }
    return ch;
  }
  return null;
}

export function scanCharacters(text: string): CharScan {
  const out: CharScan = { remove: [], tagDecoded: "", tagCount: 0, zwPositions: [], zwRuns: 0, zwMaxRun: 0, bidiCount: 0 };
  CANDIDATE.lastIndex = 0;
  let tagRunStart = -1;
  let tagRunEnd = -1;
  let lastZw = -2;
  let run = 0;
  const closeTagRun = () => {
    if (tagRunStart < 0) return;
    const runText = text.slice(tagRunStart, tagRunEnd);
    const before = prevCp(text, tagRunStart);
    const letters = decodeTagCharacters(runText);
    const isFlag = before !== null && before.cp === 0x1f3f4 && runText.endsWith("\u{E007F}") && RGI_SUBDIVISIONS.has(letters);
    if (!isFlag) {
      out.remove.push([tagRunStart, tagRunEnd]);
      out.tagDecoded += letters;
      out.tagCount += runText.length / 2;
    }
    tagRunStart = -1;
  };
  for (const m of text.matchAll(CANDIDATE)) {
    const i = m.index;
    const s = m[0];
    if (s.length === 2) {
      if (tagRunStart >= 0 && i === tagRunEnd) tagRunEnd = i + 2;
      else {
        closeTagRun();
        tagRunStart = i;
        tagRunEnd = i + 2;
      }
      // CANCEL TAG ends a sequence: whatever follows a flag is judged on its own.
      if (s.charCodeAt(1) === 0xdc7f) closeTagRun();
      continue;
    }
    const c = s.charCodeAt(0);
    if (isBidi(c)) {
      const window = text.slice(Math.max(0, i - 16), i + 17);
      if (!RTL.test(window)) {
        out.bidiCount++;
        out.remove.push([i, i + 1]);
      }
      continue;
    }
    if (!isZw(c)) continue;
    if (c === 0xfeff && i === 0) continue;
    if (c === 0x200d) {
      let p = prevCp(text, i);
      if (p !== null && p.cp === 0xfe0f) p = prevCp(text, p.at);
      const n = nextCp(text, i + 1);
      if (p !== null && n !== null && PICTOGRAPHIC.test(String.fromCodePoint(p.cp)) && PICTOGRAPHIC.test(String.fromCodePoint(n.cp))) continue;
    }
    if (c === 0x200c || c === 0x200d) {
      const before = letterAround(text, i, -1, 1);
      const after = letterAround(text, i, 1, 1);
      if ((before !== null && JOINING_SCRIPT.test(before)) || (after !== null && JOINING_SCRIPT.test(after))) continue;
    }
    out.zwPositions.push(i);
    out.remove.push([i, i + 1]);
    if (i === lastZw + 1) run++;
    else {
      if (run > 0) out.zwRuns++;
      run = 1;
    }
    out.zwMaxRun = Math.max(out.zwMaxRun, run);
    lastZw = i;
  }
  if (run > 0) out.zwRuns++;
  closeTagRun();
  return out;
}

// --- lexicon text -----------------------------------------------------------------------------

/**
 * Characters removed before phrase matching, so "ig<U+200B>nore" still reads "ignore": zero-width and bidi controls,
 * variation selectors (BMP and supplement), tag characters, and the blank fillers (Hangul fillers, the braille blank,
 * the combining grapheme joiner) that draw nothing.
 */
/* eslint-disable no-misleading-character-class -- the class lists invisible and combining characters on purpose */
const LEX_STRIP =
  /[\u00AD\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\uFE00-\uFE0F\u3164\u115F\u1160\uFFA0\u2800]|\u034F|\uDB40[\uDC00-\uDC7F\uDD00-\uDDEF]/g;
const LEX_STRIP_ONE = new RegExp(LEX_STRIP.source);
/* eslint-enable no-misleading-character-class */

/** Lookalike letters (Cyrillic, Greek, a few Latin extensions) and the lower-case Latin letter each is read as. */
const CONFUSABLES: ReadonlyMap<string, string> = new Map(
  (
    [
      [0x0430, "a"], [0x0435, "e"], [0x043e, "o"], [0x0440, "p"], [0x0441, "c"], [0x0445, "x"], [0x0443, "y"], [0x0456, "i"],
      [0x0455, "s"], [0x0458, "j"], [0x04bb, "h"], [0x043a, "k"], [0x043c, "m"], [0x0442, "t"], [0x043d, "h"], [0x0432, "b"],
      [0x0410, "a"], [0x0412, "b"], [0x0415, "e"], [0x041a, "k"], [0x041c, "m"], [0x041d, "h"], [0x041e, "o"], [0x0420, "p"],
      [0x0421, "c"], [0x0422, "t"], [0x0425, "x"], [0x0423, "y"], [0x0406, "i"], [0x0405, "s"], [0x0408, "j"],
      [0x0501, "d"], [0x051b, "q"], [0x051d, "w"], [0x0251, "a"], [0x0261, "g"], [0x0131, "i"],
      [0x03b1, "a"], [0x03bf, "o"], [0x03bd, "v"], [0x03c1, "p"], [0x03b9, "i"], [0x03c5, "u"], [0x03ba, "k"],
      [0x0391, "a"], [0x0392, "b"], [0x0395, "e"], [0x0396, "z"], [0x0397, "h"], [0x0399, "i"], [0x039a, "k"], [0x039c, "m"],
      [0x039d, "n"], [0x039f, "o"], [0x03a1, "p"], [0x03a4, "t"], [0x03a5, "y"], [0x03a7, "x"],
    ] as const
  ).map(([cp, latin]) => [String.fromCharCode(cp), latin] as const),
);

interface LexText {
  text: string;
  /** Maps an index in `text` to the index in the original (identity when null). */
  map: Int32Array | null;
}

/**
 * The text the lexicon reads: invisible fillers removed, every other non-ASCII character folded with NFKC (fullwidth
 * and mathematical letters become plain ones) and the common Cyrillic and Greek lookalikes read as Latin. `map`
 * keeps where each kept character came from. Plain ASCII is returned as it is.
 */
function lexText(original: string): LexText {
  if (!/[\u0080-\uFFFF]/.test(original)) return { text: original, map: null };
  let map = new Int32Array(Math.max(16, original.length + 16));
  let n = 0;
  const room = (k: number): void => {
    if (n + k <= map.length) return;
    const bigger = new Int32Array(Math.max(map.length * 2, n + k));
    bigger.set(map.subarray(0, n));
    map = bigger;
  };
  const parts: string[] = [];
  let i = 0;
  while (i < original.length) {
    let j = i;
    while (j < original.length && original.charCodeAt(j) < 0x80) j++;
    if (j > i) {
      parts.push(original.slice(i, j));
      room(j - i);
      for (let k = i; k < j; k++) map[n++] = k;
      i = j;
      continue;
    }
    const c = original.charCodeAt(i);
    const width = c >= 0xd800 && c <= 0xdbff && i + 1 < original.length ? 2 : 1;
    const ch = original.slice(i, i + width);
    i += width;
    if (LEX_STRIP_ONE.test(ch)) continue;
    // CJK ideographs and Hangul syllables are their own NFKC form: skipped, so a long run of them stays cheap.
    const cp = ch.codePointAt(0) as number;
    const plain = (cp >= 0x4e00 && cp <= 0x9fff) || (cp >= 0xac00 && cp <= 0xd7a3);
    const folded = (plain ? ch : ch.normalize("NFKC")).replace(LEX_STRIP, "");
    room(folded.length);
    let piece = "";
    for (const u of folded) piece += CONFUSABLES.get(u) ?? u;
    parts.push(piece);
    for (let k = 0; k < piece.length; k++) map[n++] = i - width;
  }
  return { text: parts.join(""), map: map.subarray(0, n) };
}

const originalIndex = (lt: LexText, i: number) => (lt.map === null ? i : (lt.map[Math.min(i, lt.map.length - 1)] ?? i));

// --- links ------------------------------------------------------------------------------------

const TEMPLATE = /\{[^{}\s]{1,80}\}|\{\{|<[^<>\s]{1,80}(?:>|$)|%7B[^\s]{0,80}?%7D|%3C[^\s]{0,80}?%3E/i;

function exfilWhy(url: string, hidden: boolean, pixel: boolean, kind: "image" | "link"): { host: string; why: "template" | "capture_host" | "query_entropy" } | null {
  const p = parseUrlLike(url.replace(/[{}<>]/g, (c) => encodeURIComponent(c)));
  if (p === null || !/^(?:https?|wss?)$/.test(p.scheme)) return null;
  if (TEMPLATE.test(url)) return { host: p.host, why: "template" };
  if (isCaptureHost(p.host)) return { host: p.host, why: "capture_host" };
  if (hidden && !pixel && kind === "image") {
    for (const kv of p.query.replace(/^[?#]/, "").split(/[&#;]/)) {
      const eq = kv.indexOf("=");
      let value = eq === -1 ? kv : kv.slice(eq + 1);
      try {
        value = decodeURIComponent(value.replace(/\+/g, " "));
      } catch {
        // Keep the raw value: a malformed escape is still data.
      }
      if (value.length > 64 && entropy(value) > 4.0) return { host: p.host, why: "query_entropy" };
    }
  }
  return null;
}

/** Image and link URLs written as Markdown or raw `<img>` in text. */
function textLinks(text: string): { url: string; kind: "image" | "link" }[] {
  const out: { url: string; kind: "image" | "link" }[] = [];
  // Markdown links and images: each "](" is looked back from, to a "[" within 300 characters with no "]" or line end
  // between. Trying the pattern at every "[" instead is quadratic on a long run of them.
  const target = /\s*<?([^\s)>]{1,4000}>?)/y;
  for (let at = text.indexOf("]("); at !== -1 && out.length < 500; at = text.indexOf("](", at + 2)) {
    let open = -1;
    for (let k = at - 1; k >= 0 && at - k <= 301; k--) {
      const c = text.charCodeAt(k);
      if (c === 0x5d || c === 0x0a) break;
      if (c === 0x5b) open = k;
    }
    if (open === -1) continue;
    target.lastIndex = at + 2;
    const m = target.exec(text);
    if (m !== null) out.push({ url: (m[1] ?? "").replace(/>$/, ""), kind: open > 0 && text[open - 1] === "!" ? "image" : "link" });
  }
  for (const m of text.matchAll(/<img\b[^>]{0,500}?\bsrc\s*=\s*["']?([^"'\s>]{1,4000})/gi)) out.push({ url: m[1] ?? "", kind: "image" });
  return out.slice(0, 500);
}

// --- normalization for the duplicate rule ----------------------------------------------------

const PADDING = /[\u00A0\u00AD\u200B-\u200D\u2060\uFEFF\u2007\u202F\s]|\u034F/gu;
const PADDING_ONLY = /[\u00AD\u200B-\u200D\u2060\uFEFF]|\u034F/u;

function normalizeForDuplicate(s: string): string {
  return s.toLowerCase().replace(LEX_STRIP, "").replace(PADDING, "");
}

/**
 * A marketing preheader: a hidden span made of at most 140 characters of text
 * at its start, then only padding (nbsp, ZWNJ, U+034F, soft hyphens, ZWSP).
 * A preview line with no padding counts only when it comes before any visible
 * text of the body, where mail clients take the preview from (MJML's
 * `mj-preview`, and preheaders split across two elements).
 */
function isPreheader(text: string, atStart: boolean): boolean {
  const firstPad = text.search(PADDING_ONLY);
  if (firstPad === -1 && !atStart) return false;
  const lead = firstPad === -1 ? text : text.slice(0, firstPad);
  const rest = firstPad === -1 ? "" : text.slice(firstPad);
  if (rest.replace(PADDING, "") !== "") return false;
  return lead.replace(/\s+/g, " ").trim().length <= 140;
}

// --- the scan ---------------------------------------------------------------------------------

/**
 * Index of the longest prefix of `text` whose UTF-8 encoding fits in `maxBytes`, counted the way
 * Buffer.byteLength and TextEncoder count it (FZ13): a surrogate pair is 4 bytes, and a lone surrogate
 * of either half is encoded as U+FFFD, 3 bytes. The cut never splits a pair.
 */
function utf8Prefix(text: string, maxBytes: number): number {
  if (text.length * 3 <= maxBytes) return text.length;
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    const pair = c >= 0xd800 && c <= 0xdbff && i + 1 < text.length && (text.charCodeAt(i + 1) & 0xfc00) === 0xdc00;
    const n = c < 0x80 ? 1 : c < 0x800 ? 2 : pair ? 4 : 3;
    if (bytes + n > maxBytes) return i;
    bytes += n;
    if (pair) i++;
  }
  return text.length;
}

function codePoints(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (!(c >= 0xdc00 && c <= 0xdfff && i > 0 && s.charCodeAt(i - 1) >= 0xd800 && s.charCodeAt(i - 1) <= 0xdbff)) n++;
  }
  return n;
}

function removeRanges(text: string, ranges: readonly [number, number][]): string {
  if (ranges.length === 0) return text;
  const sorted = [...ranges].sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  let out = "";
  let at = 0;
  for (const [s, e] of sorted) {
    if (e <= at) continue;
    if (s > at) out += text.slice(at, s);
    at = Math.max(at, e);
  }
  return out + text.slice(at);
}

function escapePreview(s: string): string {
  const flat = s.replace(/\s+/g, " ").trim();
  const cut = Array.from(flat).slice(0, 200).join("");
  // Control characters are exactly what this escapes, so the regex has to name them.
  // eslint-disable-next-line no-control-regex
  return revealInvisible(cut).replace(/[\u0000-\u001f\u007f-\u009f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

class Collector {
  readonly signals: Signal[] = [];
  private readonly counts = new Map<string, number>();
  private readonly seen = new Set<string>();
  add(s: Signal, dedupe?: string): void {
    if (dedupe !== undefined) {
      if (this.seen.has(dedupe)) return;
      this.seen.add(dedupe);
    }
    const n = this.counts.get(s.id) ?? 0;
    if (n >= MAX_PER_KIND) return;
    this.counts.set(s.id, n + 1);
    this.signals.push(s);
  }
  hits(hits: readonly LexiconHit[], hidden: boolean): void {
    for (const h of hits) {
      const id = h.entry.lexicon === "A" ? "agent_directed" : "imperative";
      this.add({ id, phrase: h.phrase, hidden, entry: h.entry.id }, `${id}:${h.entry.id}:${hidden}:${h.phrase.toLowerCase()}`);
    }
  }
  link(url: string, hidden: boolean, pixel: boolean, kind: "image" | "link"): boolean {
    const w = exfilWhy(url, hidden, pixel, kind);
    if (w === null) return false;
    this.add({ id: "exfil_link", host: w.host, hidden, why: w.why }, `exfil:${w.host}:${hidden}:${w.why}`);
    return true;
  }
}

/**
 * The verdict for a set of signals. Exported
 * so the mail detector can merge the signals of a message's channels and
 * decide once.
 */
export function verdictFor(signals: readonly Signal[], opts: { authFail?: boolean; quarantineOn?: readonly QuarantineReason[] } = {}): { verdict: Verdict; reasons: QuarantineReason[] } {
  const fired = new Set<QuarantineReason>();
  for (const s of signals) {
    if (s.id === "tag_chars" && /[\x21-\x7e]/.test(s.decoded)) fired.add("tag_chars");
    if (s.id === "hidden_html" && !s.duplicate && s.instruction) fired.add("hidden_instruction");
    if (s.id === "zero_width_dense" && s.nearInstruction) fired.add("dense_zero_width_instruction");
    if (s.id === "exfil_link" && s.hidden) fired.add("hidden_exfil_link");
    if (s.id === "agent_directed" && opts.authFail === true) fired.add("auth_fail_instruction");
  }
  const enabled = new Set(opts.quarantineOn ?? QUARANTINE_REASONS);
  const reasons = QUARANTINE_REASONS.filter((r) => fired.has(r) && enabled.has(r));
  if (reasons.length > 0) return { verdict: "quarantine", reasons };
  const hiddenContent = signals.some((s) => s.id === "tag_chars" || s.id === "zero_width_dense" || s.id === "bidi_outside_rtl" || (s.id === "hidden_html" && !s.duplicate));
  if (hiddenContent) return { verdict: "neutralize", reasons: [] };
  const visibleDirected = signals.some((s) => (s.id === "agent_directed" && !s.hidden) || (s.id === "exfil_link" && !s.hidden));
  return { verdict: visibleDirected ? "flag" : "deliver", reasons: [] };
}

/**
 * Scans one piece of content (an MCP result's text, one channel of a mail
 * message). `opts.html` parses it as HTML. Never throws on hostile input.
 */
export function scanContent(input: string, opts: ScanOptions = {}): ScanResult {
  const now = opts.now ?? (() => performance.now());
  const started = now();
  const timeoutMs = opts.timeoutMs ?? SCAN_LIMITS.timeoutMs;
  const expired = () => now() - started > timeoutMs;
  const col = new Collector();
  const incomplete = new Set<string>();
  const maxBytes = opts.maxBytes ?? SCAN_LIMITS.maxBytes;
  const bound = opts.html === true ? Math.min(maxBytes, opts.maxHtmlBytes ?? SCAN_LIMITS.maxHtmlBytes) : maxBytes;
  const cut = utf8Prefix(input, bound);
  const text = cut < input.length ? input.slice(0, cut) : input;
  if (cut < input.length) incomplete.add(opts.html === true ? "max_html_bytes" : "max_bytes");

  const hiddenTexts: string[] = [];
  let neutralized: string | null = null;
  const budget = opts.budget ?? workBudget(opts.maxWork);

  // The content is paid for before it is read: a part the budget cannot pay for is not read at all.
  const unshown = opts.html !== true ? opts.unshown : undefined;
  const reads = text.length + (unshown !== undefined && unshown.paid !== true ? unshown.visible.length : 0);
  if (!charge(budget, SCAN_OVERHEAD + reads)) incomplete.add("work");
  else if (opts.html === true) neutralized = scanHtml(text, opts, col, incomplete, hiddenTexts, expired, budget);
  else {
    if (unshown !== undefined) unshown.paid = true;
    neutralized = scanText(text, col, incomplete, hiddenTexts, expired, budget, unshown);
  }

  // No clock check here: a scan that finished all its work is complete however long it took, so its verdict
  // does not depend on the clock. Only a stage the deadline actually cut short reports `time` (and is withheld).
  for (const reason of incomplete) col.add({ id: "scan_incomplete", reason }, `inc:${reason}`);
  const { verdict, reasons } = verdictFor(col.signals, opts);
  const result: ScanResult = { signals: col.signals, strippedChars: 0, verdict, reasons, hiddenPreview: escapePreview(hiddenTexts.join(" ")) };
  if (neutralized !== null && neutralized !== text) {
    result.neutralized = neutralized;
    result.strippedChars = codePoints(text) - codePoints(neutralized);
  }
  return result;
}

/** How close (in characters, on either side) an agent-directed phrase has to be to a dense run's characters to make the run part of an instruction. */
const NEAR_RUN = 200;
/**
 * Places of agent-directed phrases looked at for one text's `nearInstruction`. Past this many the text counts as
 * near without looking further: it bounds the work, and a text that full of them with a dense run is held back.
 */
const NEAR_PLACES = 1000;

/**
 * Whether an agent-directed phrase (lexicon A, as in visible text) is within NEAR_RUN characters of one of
 * `positions` (indices in the original text, in order), before or after it: the distance counts from the
 * phrase's nearer end, so a long phrase before a run is not measured from its start. Every place a phrase
 * appears counts, not only its first, so a copy far away cannot hide the one beside the run. `said` tells
 * whether a phrase counts in this text (false: an echo of what the person is shown; null: the budget could not
 * pay to tell, and it counts). `pay` charges the work budget for searching a line again for its next place;
 * when it cannot, the text counts as near (the scan is then reported incomplete).
 */
function phraseNear(positions: readonly number[], lt: LexText, said: (phrase: string) => boolean | null, pay: (units: number) => boolean): boolean {
  let seen = 0;
  for (const h of lexiconPlaces(lt.text, LEXICON_A, false)) {
    if (++seen > NEAR_PLACES) return true;
    const start = originalIndex(lt, h.index);
    const last = originalIndex(lt, h.index + h.length - 1);
    // The first position at or after start - NEAR_RUN; near when it is no further than last + NEAR_RUN.
    let lo = 0;
    let hi = positions.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if ((positions[mid] as number) < start - NEAR_RUN) lo = mid + 1;
      else hi = mid;
    }
    if (lo < positions.length && (positions[lo] as number) <= last + NEAR_RUN && said(h.phrase) !== false) return true;
    if (!pay(h.lineLength)) return true;
  }
  return false;
}

/** Charges a budget for work found along the way; when it cannot pay, the scan is incomplete (`work`). */
function payer(budget: WorkBudget, incomplete: Set<string>): (units: number) => boolean {
  return (units) => {
    if (charge(budget, units)) return true;
    incomplete.add("work");
    return false;
  };
}

function addCharSignals(chars: CharScan, lt: LexText, said: (phrase: string) => boolean | null, pay: (units: number) => boolean, col: Collector): void {
  if (chars.tagCount > 0) col.add({ id: "tag_chars", decoded: chars.tagDecoded.slice(0, 2000) });
  const zwCount = chars.zwPositions.length;
  if (zwCount >= 8 || chars.zwMaxRun >= 4) {
    col.add({ id: "zero_width_dense", count: zwCount, runs: chars.zwRuns, nearInstruction: phraseNear(chars.zwPositions, lt, said, pay) });
  }
  if (chars.bidiCount > 0) col.add({ id: "bidi_outside_rtl", count: chars.bidiCount });
}

/** Lexicon and links over smuggled tag text: everything in it is hidden. */
function scanTagText(decoded: string, col: Collector, hiddenTexts: string[]): void {
  if (decoded.trim() === "") return;
  hiddenTexts.push(decoded);
  col.hits(lexiconHits(decoded, LEXICON_A, true), true);
  col.hits(lexiconHits(decoded, LEXICON_B, true), true);
  for (const l of textLinks(decoded)) col.link(l.url, true, false, l.kind);
  for (const m of decoded.matchAll(/\bhttps?:\/\/[^\s<>"')\]]{1,2000}/g)) col.link(m[0], true, false, "image");
}

function scanText(text: string, col: Collector, incomplete: Set<string>, hiddenTexts: string[], expired: () => boolean, budget: WorkBudget, unshown?: UnshownContext): string | null {
  // The clock is read between stages, as a last resort only: the size bound keeps a scan well inside the budget,
  // and a stage the deadline skips makes the result incomplete (withheld), never a partial one taken as clean.
  const late = (): boolean => {
    if (!expired()) return false;
    incomplete.add("time");
    return true;
  };
  const chars = scanCharacters(text);
  if (late()) return null;
  const lt = lexText(text);
  // Whether a phrase counts as said in this text: not when it echoes what the person is shown (null: the budget
  // could not pay to tell). The dense-run check below asks it too, for every place a phrase appears.
  let said: (phrase: string) => boolean | null = () => true;
  if (unshown === undefined) {
    col.hits(lexiconHits(lt.text, LEXICON_A, false), false);
  } else {
    const visibleNorm = (unshown.norm ??= normalizeForDuplicate(unshown.visible));
    // The entries that are strong anywhere: a header names encodings and commands ("base64") as data.
    // Each distinct phrase is looked up in the visible text once, and the search is charged to the budget.
    const echoed = new Map<string, boolean>();
    said = (phrase) => {
      const norm = normalizeForDuplicate(phrase);
      let found = echoed.get(norm);
      if (found === undefined) {
        const s = searchUnits(visibleNorm, norm);
        if (!charge(budget, s.units)) {
          incomplete.add("work");
          return null;
        }
        found = s.found;
        echoed.set(norm, found);
      }
      return !found;
    };
    const hitsA: LexiconHit[] = [];
    for (const h of lexiconHits(lt.text, LEXICON_A, false)) {
      const counts = said(h.phrase);
      if (counts === null) return null;
      if (counts) hitsA.push(h);
    }
    if (hitsA.length > 0) {
      col.add({ id: "hidden_html", chars: codePoints(text), duplicate: false, how: ["not_displayed"], preheader: false, instruction: true });
      col.hits(hitsA, true);
      hiddenTexts.push(text);
    }
  }
  if (late()) return null;
  scanTagText(chars.tagDecoded, col, hiddenTexts);
  addCharSignals(chars, lt, said, payer(budget, incomplete), col);
  if (late()) return null;
  for (const l of textLinks(lt.text)) col.link(l.url, unshown !== undefined, false, l.kind);
  return chars.remove.length > 0 ? removeRanges(text, chars.remove) : null;
}

const escapeHtmlText = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

function scanHtml(src: string, opts: ScanOptions, col: Collector, incomplete: Set<string>, hiddenTexts: string[], expired: () => boolean, budget: WorkBudget): string | null {
  // The cascade gets the document's own step bound or what is left of the budget, whichever is smaller, and
  // the steps it used (and the characters its tokenizer searched) are charged afterwards.
  const ownSteps = opts.maxMatchSteps ?? MATCH_STEPS;
  const steps = Math.min(ownSteps, budget.left);
  const doc = analyzeHtml(src, {
    maxNodes: opts.maxNodes ?? SCAN_LIMITS.maxNodes,
    maxCssRules: opts.maxCssRules ?? SCAN_LIMITS.maxCssRules,
    maxMatchSteps: steps,
    expired,
  });
  for (const r of doc.incomplete) incomplete.add(r);
  if (!charge(budget, doc.work.matchSteps + doc.work.searchedChars) || (steps < ownSteps && doc.incomplete.includes("css_work"))) {
    budget.spent = true;
    incomplete.add("work");
  }
  const remove: [number, number][] = [];

  // Tag characters anywhere in the markup (text, attributes, comments) reach a model reading it.
  const decodedSource = decodeEntities(src);
  const sourceChars = scanCharacters(decodedSource);
  scanTagText(sourceChars.tagDecoded, col, hiddenTexts);
  if (sourceChars.tagCount > 0) col.add({ id: "tag_chars", decoded: sourceChars.tagDecoded.slice(0, 2000) });

  const visibleAll = `${doc.visible}\n${doc.attributeText}`;
  const visibleChars = scanCharacters(visibleAll);
  const lt = lexText(visibleAll);
  col.hits(lexiconHits(lt.text, LEXICON_A, false), false);
  addCharSignals({ ...visibleChars, tagCount: 0 }, lt, () => true, payer(budget, incomplete), col);
  for (const l of textLinks(lt.text)) col.link(l.url, false, false, l.kind);

  const visibleNorm = normalizeForDuplicate(visibleAll);
  for (const span of doc.spans) {
    if (expired()) {
      incomplete.add("time");
      break;
    }
    // Each hidden span is compared with the whole visible text: many spans against a long text is the costly
    // case, so the comparison is charged to the budget (and the rest of the spans are not read once it is spent).
    if (!charge(budget, 16 + span.text.length)) {
      incomplete.add("work");
      break;
    }
    const core = span.text.replace(LEX_STRIP, "").replace(PADDING, "");
    const padded = PADDING_ONLY.test(span.text);
    if (core === "" && !padded) continue; // spacer cells: whitespace in a font-size:0 cell
    if (core !== "" && !/[\p{L}]/u.test(core)) continue; // separators and digits carry no instruction
    const norm = normalizeForDuplicate(span.text);
    let duplicate = false;
    if (norm !== "") {
      const s = searchUnits(visibleNorm, norm);
      if (!charge(budget, s.units)) {
        incomplete.add("work");
        break;
      }
      duplicate = s.found;
    }
    const chars = codePoints(span.text);
    if (duplicate) {
      col.add({ id: "hidden_html", chars, duplicate: true, how: span.how, preheader: false, instruction: false });
      continue;
    }
    const slt = lexText(span.text);
    const hitsA = lexiconHits(slt.text, LEXICON_A, true);
    const hitsB = lexiconHits(slt.text, LEXICON_B, true);
    // A preheader with ordinary marketing language ("click the link ...") is neutralized; an agent-addressed one is not a preheader.
    const preheader = hitsA.length === 0 && isPreheader(span.text, span.atStart);
    const instruction = !preheader && hitsA.length + hitsB.length > 0;
    col.add({ id: "hidden_html", chars, duplicate: false, how: span.how, preheader, instruction });
    if (!preheader) {
      col.hits(hitsA, true);
      col.hits(hitsB, true);
      hiddenTexts.push(span.text);
    }
    for (const l of textLinks(slt.text)) col.link(l.url, true, false, l.kind);
    remove.push(...span.ranges);
  }

  for (const c of doc.comments) {
    const clt = lexText(c.text);
    const hits = [...lexiconHits(clt.text, LEXICON_A, true), ...lexiconHits(clt.text, LEXICON_B, true)];
    if (hits.length === 0) continue;
    col.add({ id: "hidden_html", chars: codePoints(c.text), duplicate: false, how: ["comment"], preheader: false, instruction: true });
    col.hits(hits, true);
    hiddenTexts.push(c.text);
    remove.push(c.range);
  }

  // A <title> is never shown by a mail client, but a model reading the markup reads it. Text in it
  // addressed to an AI agent is hidden text with an instruction (a title that copies visible text is not).
  const subjectNorms = (opts.subjects ?? []).map(normalizeForDuplicate);
  for (const t of doc.titles) {
    const tlt = lexText(t.text);
    // Not `hidden`: a title is not hidden text, it is shown by no client (like a header), so only entries
    // that need hidden text to count (a lone "ignore previous") stay quiet.
    const hits = lexiconHits(tlt.text, LEXICON_A, false);
    if (hits.length === 0) continue;
    const norm = normalizeForDuplicate(t.text);
    if (norm !== "") {
      const s = searchUnits(visibleNorm, norm);
      if (!charge(budget, s.units)) {
        incomplete.add("work");
        break;
      }
      if (s.found) continue;
    }
    if (norm !== "" && subjectNorms.includes(norm)) continue;
    col.add({ id: "hidden_html", chars: codePoints(t.text), duplicate: false, how: ["title"], preheader: false, instruction: true });
    col.hits(hits, true);
    hiddenTexts.push(t.text);
    remove.push(t.range);
  }

  for (const l of doc.links) {
    if (col.link(l.url, l.hidden, l.pixel, l.kind) && l.hidden) remove.push(l.range);
  }

  // Visible text nodes keep their place; only their hidden characters go.
  const replacements: { range: [number, number]; text: string }[] = [];
  for (const node of doc.visibleNodes) {
    const ch = scanCharacters(node.text);
    if (ch.remove.length === 0) continue;
    replacements.push({ range: node.range, text: escapeHtmlText(removeRanges(node.text, ch.remove)) });
  }
  if (remove.length === 0 && replacements.length === 0 && sourceChars.tagCount === 0) return null;
  const edits = [...remove.map((range) => ({ range, text: "" })), ...replacements].sort((a, b) => a.range[0] - b.range[0] || b.range[1] - a.range[1]);
  let out = "";
  let at = 0;
  for (const e of edits) {
    if (e.range[1] <= at) continue;
    if (e.range[0] < at) continue; // nested in a removed range already
    out += src.slice(at, e.range[0]) + e.text;
    at = e.range[1];
  }
  out += src.slice(at);
  // Any tag characters left (in attributes, or written as numeric references) go too, except real flag emoji.
  return stripTagCharacters(out);
}

/** Removes Unicode tag characters (raw or as numeric character references) outside RGI subdivision flags. */
function stripTagCharacters(s: string): string {
  const withRefs = s.replace(/&#(?:[xX]([0-9a-fA-F]{1,7})|([0-9]{1,8}));/g, (ref: string, hex: string | undefined, dec: string | undefined) => {
    const n = hex !== undefined ? parseInt(hex, 16) : parseInt(dec ?? "", 10);
    return n >= 0xe0000 && n <= 0xe007f ? String.fromCodePoint(n) : ref;
  });
  const chars = scanCharacters(withRefs);
  const tagRanges = chars.remove.filter(([a, b]) => b - a >= 2 && withRefs.charCodeAt(a) === 0xdb40);
  return tagRanges.length === 0 ? withRefs : removeRanges(withRefs, tagRanges);
}
