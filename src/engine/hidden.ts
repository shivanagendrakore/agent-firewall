/**
 * Invisible characters and terminal control sequences in what an agent reads.
 *
 * A model reads every code point; a person looking at the same text sees only
 * what is drawn. This module finds the difference:
 *
 * - **Invisible characters**: Unicode format characters (Cf) and
 *   default-ignorable code points (zero-width spaces and joiners, word joiner,
 *   invisible operators, soft hyphen, combining grapheme joiner, Hangul
 *   fillers, Mongolian free variation selectors, Khmer inherent vowels,
 *   musical-symbol formatting, interlinear annotation, and the braille blank),
 *   minus their ordinary uses: emoji ZWJ sequences, ZWJ and ZWNJ inside
 *   joining scripts, ZWSP in Thai, Lao, Khmer and Burmese, a BOM at the start,
 *   bidirectional marks inside real right-to-left text, and email preheader
 *   padding (a joiner or soft hyphen followed by a space). One left over, or a
 *   few, is no finding (pasted text carries them): a text counts as holding
 *   hidden ones (`zeroWidthDense`) at 8 or more, or 4 in a row.
 * - **Tag characters** (ASCII smuggling) outside RGI subdivision flags.
 * - **Variation-selector smuggling**: bytes written one per variation selector
 *   (U+FE00-FE0F for 0-15, U+E0100-E01EF for 16-255), in a run after one
 *   character or spread one per character. A single selector on an emoji, a
 *   keycap or an ideograph is ordinary.
 * - **Terminal control sequences**: ANSI/ECMA-48 escapes and other C0/C1
 *   controls. SGR 8 and a foreground equal to the background conceal text,
 *   cursor moves and erases draw over it, a lone carriage return or a
 *   backspace overwrites it, OSC strings set links, titles and the clipboard.
 *   Colour, bold and faint (`style`) hide nothing.
 *
 * `markHidden` replaces each run of invisible characters with a visible
 * marker and removes every control sequence, for the places the firewall can
 * rewrite what the agent receives. Bounded: past the limits the scan says it
 * is incomplete (the caller taints) and marking falls back to removing every
 * control character.
 *
 * Pure and browser-safe: no I/O, no Node built-ins.
 */
import { own } from "../own.js";

/** What the agent receives where a run of invisible characters was. */
export const HIDDEN_MARKER = "⟦hidden⟧";

export type ControlKind =
  /** Colour, bold, faint, character sets: changes nothing a person reads. */
  | "style"
  /** SGR 8, or a foreground set equal to the background: text drawn invisible. */
  | "conceal"
  /** Cursor movement, erasing, scrolling, resets: can draw over text. */
  | "cursor"
  /** OSC, DCS, APC, PM, SOS strings: window titles, hyperlinks, the clipboard. */
  | "osc"
  /** A carriage return or backspace that writes over text on the same line. */
  | "overwrite"
  /** Any other C0 or C1 control character, and DEL. */
  | "control";

export interface HiddenScan {
  /** Unicode tag characters outside an RGI subdivision flag, and the ASCII they spell. */
  tagChars: number;
  tagDecoded: string;
  /** Variation selectors that are not an emoji's, a keycap's or an ideograph's, and the bytes they spell (as text). */
  vsChars: number;
  vsDecoded: string;
  /** Other invisible characters outside their ordinary uses; `zeroWidthDense`: 8 or more, or 4 in a row. */
  zeroWidth: number;
  zeroWidthDense: boolean;
  /** Bidirectional controls and marks with no right-to-left text around them. */
  bidi: number;
  /** Control sequences by kind. */
  controls: Record<ControlKind, number>;
  /** The text was larger than the scan looks at, or held more control sequences than it counts. */
  incomplete: boolean;
}

export interface HiddenOptions {
  /**
   * The text is the output of programs the action ran (a test run, a build). Their colours, progress lines
   * and cursor moves are ordinary, so only concealed text and OSC strings count as hiding there. Text that
   * was only read (a file, a page, an MCP result, mail) counts every control sequence.
   */
  programOutput?: boolean;
}

/** Text past this many UTF-16 units is not scanned (the scan is then incomplete). */
export const MAX_HIDDEN_SCAN = 4 * 1024 * 1024;
const MAX_CONTROLS = 100_000;
/** An OSC/DCS-style string longer than this, or broken by a line end, is unterminated. */
const MAX_STRING = 4096;

// --- characters -------------------------------------------------------------------------------

const INVISIBLE = /[\p{Cf}\p{Default_Ignorable_Code_Point}⠀]/u;
const PICTOGRAPHIC = /\p{Extended_Pictographic}|\p{Emoji_Modifier}|\p{Regional_Indicator}/u;
const EMOJI = /\p{Emoji}/u;
const HAN = /\p{Script_Extensions=Han}/u;
const MARK = /\p{M}/u;
/** Scripts whose spelling uses ZWJ and ZWNJ. */
const JOINING_SCRIPT =
  /[\p{Script_Extensions=Devanagari}\p{Script_Extensions=Bengali}\p{Script_Extensions=Gurmukhi}\p{Script_Extensions=Gujarati}\p{Script_Extensions=Oriya}\p{Script_Extensions=Tamil}\p{Script_Extensions=Telugu}\p{Script_Extensions=Kannada}\p{Script_Extensions=Malayalam}\p{Script_Extensions=Sinhala}\p{Script_Extensions=Arabic}\p{Script_Extensions=Syriac}\p{Script_Extensions=Thaana}\p{Script_Extensions=Nko}\p{Script_Extensions=Mongolian}\p{Script_Extensions=Khmer}\p{Script_Extensions=Myanmar}\p{Script_Extensions=Tibetan}]/u;
/** Scripts written without spaces, where ZWSP marks word breaks. */
const NO_SPACE_SCRIPT = /[\p{Script=Thai}\p{Script=Lao}\p{Script=Khmer}\p{Script=Myanmar}]/u;
const RTL = /[\p{Script=Hebrew}\p{Script=Arabic}\p{Script=Syriac}\p{Script=Thaana}\p{Script=Nko}\p{Script=Samaritan}\p{Script=Mandaic}\p{Script=Adlam}]/u;
const RGI_SUBDIVISIONS = new Set(["gbeng", "gbsct", "gbwls"]);

const isTag = (cp: number): boolean => cp >= 0xe0000 && cp <= 0xe007f;
const isVs = (cp: number): boolean => (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
const vsByte = (cp: number): number => (cp <= 0xfe0f ? cp - 0xfe00 : cp - 0xe0100 + 16);
const isBidi = (cp: number): boolean => (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0x200e || cp === 0x200f || cp === 0x061c;
const isSpace = (cp: number | undefined): boolean => cp !== undefined && /\s/u.test(String.fromCodePoint(cp));

interface CharHit {
  /** Index in the code-point array. */
  i: number;
  kind: "tag" | "vs" | "zw" | "bidi";
}

/** Two or more letters of a right-to-left script within `w` code points of i. */
function rtlRunNear(cps: readonly number[], i: number, w: number): boolean {
  let run = 0;
  for (let k = Math.max(0, i - w); k <= Math.min(cps.length - 1, i + w); k++) {
    if (RTL.test(String.fromCodePoint(cps[k] as number))) {
      if (++run >= 2) return true;
    } else if (!MARK.test(String.fromCodePoint(cps[k] as number))) run = 0;
  }
  return false;
}

/** The nearest letter before (dir -1) or after (dir 1) i, skipping marks and joiners. */
function letterAround(cps: readonly number[], i: number, dir: -1 | 1): number | undefined {
  for (let k = i + dir, n = 0; k >= 0 && k < cps.length && n < 4; k += dir, n++) {
    const c = cps[k] as number;
    if (c === 0x200c || c === 0x200d || MARK.test(String.fromCodePoint(c))) continue;
    return c;
  }
  return undefined;
}

const test = (re: RegExp, cp: number | undefined): boolean => cp !== undefined && re.test(String.fromCodePoint(cp));

/** Every invisible character outside its ordinary uses, by code-point index. */
function charHits(cps: readonly number[]): { hits: CharHit[]; tagDecoded: string; vsBytes: number[] } {
  const hits: CharHit[] = [];
  let tagDecoded = "";
  const vsBytes: number[] = [];
  for (let i = 0; i < cps.length; i++) {
    const cp = cps[i] as number;
    if (cp < 0xa0) continue;
    if (isTag(cp)) {
      let j = i;
      let letters = "";
      while (j < cps.length && isTag(cps[j] as number)) {
        const c = cps[j] as number;
        if (c >= 0xe0020 && c <= 0xe007e) letters += String.fromCharCode(c - 0xe0000);
        j++;
      }
      const flag = cps[i - 1] === 0x1f3f4 && cps[j - 1] === 0xe007f && RGI_SUBDIVISIONS.has(letters);
      if (!flag) {
        for (let k = i; k < j; k++) hits.push({ i: k, kind: "tag" });
        tagDecoded += letters;
      }
      i = j - 1;
      continue;
    }
    if (isVs(cp)) {
      const prev = cps[i - 1];
      const run = isVs(prev ?? 0) || isVs(cps[i + 1] ?? 0);
      // One selector on its base: an emoji's text or emoji presentation, a keycap, an ideograph's variant.
      const ordinary = !run && prev !== undefined && ((cp >= 0xfe0e && cp <= 0xfe0f && (test(EMOJI, prev) || test(PICTOGRAPHIC, prev))) || (test(HAN, prev) && (cp >= 0xe0100 || cp <= 0xfe02)));
      if (!ordinary) {
        hits.push({ i, kind: "vs" });
        vsBytes.push(vsByte(cp));
      }
      continue;
    }
    if (isBidi(cp)) {
      // Marks next to right-to-left letters, and embeddings or isolates in a right-to-left passage, are ordinary.
      if (!rtlRunNear(cps, i, cp === 0x200e || cp === 0x200f || cp === 0x061c ? 3 : 16)) hits.push({ i, kind: "bidi" });
      continue;
    }
    if (!INVISIBLE.test(String.fromCodePoint(cp))) continue;
    if (cp === 0xfeff && i === 0) continue;
    const single = !(INVISIBLE.test(String.fromCodePoint(cps[i - 1] ?? 0x20)) || INVISIBLE.test(String.fromCodePoint(cps[i + 1] ?? 0x20)));
    if (cp === 0x200d && single) {
      const p = cps[i - 1] === 0xfe0f ? cps[i - 2] : cps[i - 1];
      if (test(PICTOGRAPHIC, p) && test(PICTOGRAPHIC, cps[i + 1])) continue;
    }
    if ((cp === 0x200c || cp === 0x200d) && single && (test(JOINING_SCRIPT, letterAround(cps, i, -1)) || test(JOINING_SCRIPT, letterAround(cps, i, 1)))) continue;
    if (cp === 0x200b && single && (test(NO_SPACE_SCRIPT, cps[i - 1]) || test(NO_SPACE_SCRIPT, cps[i + 1]))) continue;
    // Email preheader padding: "&zwnj;&nbsp;", soft hyphens and combining grapheme joiners between spaces.
    if ((cp === 0x200c || cp === 0x00ad || cp === 0x034f) && (isSpace(cps[i + 1]) || cps[i + 1] === 0xa0 || isSpace(cps[i - 1]))) continue;
    hits.push({ i, kind: "zw" });
  }
  return { hits, tagDecoded, vsBytes };
}

const decoder = new TextDecoder("utf-8");

/** Printable text from decoded bytes (controls dropped), bounded. */
function bytesText(bytes: readonly number[]): string {
  // eslint-disable-next-line no-control-regex -- removing control characters is the point
  return decoder.decode(new Uint8Array(bytes.slice(0, 4000))).replace(/[\u0000-\u001f\u007f-\u009f]/g, "");
}

// --- control sequences ------------------------------------------------------------------------

/** One control sequence: its UTF-16 range, its kind, and what replaces it (empty, or a newline for a lone CR). */
interface ControlSeq {
  start: number;
  end: number;
  kind: ControlKind;
  replace: string;
}

const isPrintable = (c: number): boolean => c > 0x20 && c !== 0x7f && !(c >= 0x80 && c <= 0x9f);

/**
 * The end of an OSC/DCS-style string whose body starts at `from`: after BEL, ST (ESC \) or U+009C. A line
 * end, CAN, SUB, another ESC or 4 KiB without a terminator leaves it unterminated (-1): only its introducer
 * is a control then, and the rest is ordinary text a person also sees.
 */
function stringEnd(text: string, from: number): number {
  const stop = Math.min(text.length, from + MAX_STRING);
  for (let j = from; j < stop; j++) {
    const c = text.charCodeAt(j);
    if (c === 0x07 || c === 0x9c) return j + 1;
    if (c === 0x1b) return text.charCodeAt(j + 1) === 0x5c ? j + 2 : -1;
    if (c === 0x0a || c === 0x0d || c === 0x18 || c === 0x1a) return -1;
  }
  return -1;
}

type Colour = string | null;

/** The colour an extended-colour parameter list sets (38/48/58 ; 5 ; n or ; 2 ; r ; g ; b), and how many parameters it took. */
function extended(p: readonly string[], k: number): { colour: Colour; used: number } {
  const mode = p[k + 1];
  if (mode === "5") return { colour: `i${Number(p[k + 2] ?? "0")}`, used: 3 };
  if (mode === "2") return { colour: `r${Number(p[k + 2] ?? "0")},${Number(p[k + 3] ?? "0")},${Number(p[k + 4] ?? "0")}`, used: 5 };
  return { colour: null, used: 1 };
}

/** The basic and bright palette indexes, so 37 and 38;5;7 compare equal. */
const basic = (n: number, base: number): Colour => (n >= base && n <= base + 7 ? `i${n - base}` : n >= base + 60 && n <= base + 67 ? `i${n - base - 52}` : null);

/** Whether an SGR parameter list conceals text: SGR 8, or a foreground set equal to the background. */
function sgrConceals(params: string): boolean {
  // Colon sub-parameters (38:2::r:g:b) belong to one parameter; the first part is its code.
  const p = params === "" ? ["0"] : params.split(";");
  let fg: Colour = null;
  let bg: Colour = null;
  for (let k = 0; k < p.length; k++) {
    const part = p[k] as string;
    const sub = part.split(":");
    const code = Number(sub[0] === "" ? "0" : sub[0]);
    if (sub.length > 1) {
      // 38:5:n / 38:2:[cs]:r:g:b
      if (code === 38 || code === 48) {
        const nums = sub.slice(1).filter((x) => x !== "");
        const c: Colour = nums[0] === "5" ? `i${Number(nums[1] ?? "0")}` : nums[0] === "2" ? `r${nums.slice(-3).map(Number).join(",")}` : null;
        if (code === 38) fg = c;
        else bg = c;
      }
      continue;
    }
    if (code === 38 || code === 48 || code === 58) {
      const { colour, used } = extended(p, k);
      if (code === 38) fg = colour;
      else if (code === 48) bg = colour;
      k += used - 1;
      continue;
    }
    if (code === 8) return true;
    if (code === 0) {
      fg = null;
      bg = null;
      continue;
    }
    fg = basic(code, 30) ?? (code === 39 ? null : fg);
    bg = basic(code, 40) ?? (code === 49 ? null : bg);
  }
  return fg !== null && fg === bg;
}

/** A CSI sequence's end and kind. */
function csi(text: string, from: number): { end: number; kind: ControlKind } {
  let j = from;
  const stop = Math.min(text.length, from + MAX_STRING);
  while (j < stop && text.charCodeAt(j) >= 0x30 && text.charCodeAt(j) <= 0x3f) j++;
  const params = text.slice(from, j);
  while (j < stop && text.charCodeAt(j) >= 0x20 && text.charCodeAt(j) <= 0x2f) j++;
  const final = text.charCodeAt(j);
  if (!(final >= 0x40 && final <= 0x7e)) return { end: j, kind: "control" };
  if (final === 0x6d) return { end: j + 1, kind: sgrConceals(params) ? "conceal" : "style" };
  return { end: j + 1, kind: "cursor" };
}

/** Every control sequence in the text, up to MAX_CONTROLS (`full` says whether all were found). */
function controlsOf(text: string): { seqs: ControlSeq[]; full: boolean } {
  const out: ControlSeq[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    // Ordinary text and whitespace (tab, newline, vertical tab, form feed) go on; NUL is binary data, not a trick.
    if ((c >= 0x20 && c < 0x7f) || c === 0x09 || c === 0x0a || c === 0x0b || c === 0x0c || c === 0x00 || c > 0x9f) continue;
    if (out.length >= MAX_CONTROLS) return { seqs: out, full: false };
    if (c === 0x1b) {
      const n = text.charCodeAt(i + 1);
      let end = i + 2;
      let kind: ControlKind;
      if (n === 0x5b) ({ end, kind } = csi(text, i + 2));
      else if (n === 0x5d || n === 0x50 || n === 0x5f || n === 0x5e || n === 0x58) {
        const e = stringEnd(text, i + 2);
        end = e === -1 ? i + 2 : e;
        kind = "osc";
      } else if (n === 0x28 || n === 0x29 || n === 0x2a || n === 0x2b) {
        end = Math.min(text.length, i + 3);
        kind = "style";
      } else if (n === 0x3d || n === 0x3e) kind = "style";
      else if (n === 0x37 || n === 0x38 || n === 0x63 || n === 0x44 || n === 0x45 || n === 0x4d) kind = "cursor";
      else {
        end = Number.isNaN(n) ? i + 1 : i + 2;
        kind = "control";
      }
      out.push({ start: i, end, kind, replace: "" });
      i = end - 1;
      continue;
    }
    if (c === 0x9b) {
      const { end, kind } = csi(text, i + 1);
      out.push({ start: i, end, kind, replace: "" });
      i = end - 1;
      continue;
    }
    if (c === 0x9d || c === 0x90 || c === 0x9e || c === 0x9f || c === 0x98) {
      const e = stringEnd(text, i + 1);
      const end = e === -1 ? i + 1 : e;
      out.push({ start: i, end, kind: "osc", replace: "" });
      i = end - 1;
      continue;
    }
    if (c === 0x0d) {
      // CRLF is a line end. A lone CR between text on one line moves back to its start: what follows
      // is drawn over what came before. Shown as a line break instead, so both stay visible.
      if (text.charCodeAt(i + 1) === 0x0a) continue;
      const before = i > 0 && isPrintable(text.charCodeAt(i - 1));
      const after = i + 1 < text.length && isPrintable(text.charCodeAt(i + 1));
      out.push({ start: i, end: i + 1, kind: before && after ? "overwrite" : "control", replace: "\n" });
      continue;
    }
    if (c === 0x08) {
      out.push({ start: i, end: i + 1, kind: "overwrite", replace: "" });
      continue;
    }
    out.push({ start: i, end: i + 1, kind: "control", replace: "" });
  }
  return { seqs: out, full: true };
}

const NO_CONTROLS = (): Record<ControlKind, number> => ({ style: 0, conceal: 0, cursor: 0, osc: 0, overwrite: 0, control: 0 });

/** Counts the hidden characters and control sequences in a text. Never throws. */
export function scanHidden(input: string): HiddenScan {
  const text = input.length > MAX_HIDDEN_SCAN ? input.slice(0, MAX_HIDDEN_SCAN) : input;
  const cps = Array.from(text, (c) => c.codePointAt(0) as number);
  const { hits, tagDecoded, vsBytes } = charHits(cps);
  const controls = NO_CONTROLS();
  const { seqs, full } = controlsOf(text);
  for (const s of seqs) controls[s.kind]++;
  const zw = hits.filter((h) => h.kind === "zw");
  let maxRun = 0;
  let run = 0;
  let last = -2;
  for (const h of zw) {
    run = h.i === last + 1 ? run + 1 : 1;
    maxRun = Math.max(maxRun, run);
    last = h.i;
  }
  const vs = hits.filter((h) => h.kind === "vs").length;
  return {
    tagChars: hits.filter((h) => h.kind === "tag").length,
    tagDecoded,
    // A lone selector that is not on an emoji or an ideograph is odd but spells nothing; two or more is a message.
    vsChars: vs >= 2 ? vs : 0,
    vsDecoded: vs >= 2 ? bytesText(vsBytes) : "",
    zeroWidth: zw.length,
    zeroWidthDense: zw.length >= 8 || maxRun >= 4,
    bidi: hits.filter((h) => h.kind === "bidi").length,
    controls,
    incomplete: !full || input.length > MAX_HIDDEN_SCAN,
  };
}

/** Kinds that make text read differently to a person than to the model (the ones worth rewriting). */
export const DECEPTIVE_KINDS: ReadonlySet<string> = new Set(["tag_chars", "variation_selectors", "bidi", "terminal_conceal", "terminal_cursor", "terminal_overwrite", "terminal_osc", "scan_incomplete"]);

/** The kinds of hiding a scan found, as stable names (empty: nothing hides text from a person). */
export function hidingKinds(s: HiddenScan, opts: HiddenOptions = {}): string[] {
  const out: string[] = [];
  if (s.tagChars > 0) out.push("tag_chars");
  if (s.vsChars > 0) out.push("variation_selectors");
  if (s.zeroWidthDense) out.push("zero_width");
  if (s.bidi > 0) out.push("bidi");
  const counted: ControlKind[] = opts.programOutput === true ? ["conceal", "osc"] : ["conceal", "osc", "cursor", "overwrite", "control"];
  for (const k of counted) if (s.controls[k] > 0) out.push(`terminal_${k}`);
  if (s.incomplete) out.push("scan_incomplete");
  return out;
}

/** Text smuggled in tag characters and variation selectors, when it has any printable content. */
export function smuggledText(s: HiddenScan): string {
  const t = `${s.tagDecoded} ${s.vsDecoded}`.trim();
  return /[\x21-\x7e]|[\p{L}\p{N}]/u.test(t) ? t : "";
}

/** Plain-language names for hidingKinds, for warnings. */
export function describeKinds(kinds: readonly string[]): string {
  const names: Record<string, string> = {
    tag_chars: "Unicode tag characters",
    variation_selectors: "variation selectors that spell hidden bytes",
    zero_width: "zero-width or other invisible characters",
    bidi: "direction-changing characters",
    terminal_conceal: "terminal codes that make text invisible",
    terminal_osc: "terminal codes that set links, titles or the clipboard",
    terminal_cursor: "terminal codes that move the cursor or erase text",
    terminal_overwrite: "carriage returns or backspaces that write over text",
    terminal_control: "other control characters",
    scan_incomplete: "more text or control codes than the firewall checks",
  };
  return kinds.map((k) => own(names, k) ?? k).join(", ");
}

export interface Marked {
  text: string;
  /** Runs of invisible characters replaced by HIDDEN_MARKER. */
  marked: number;
  /** Control sequences removed (a lone CR becomes a line break). */
  removed: number;
}

// eslint-disable-next-line no-control-regex -- the fallback removes control characters
const ANY_CONTROL = /[\u0001-\u0008\u000e-\u001f\u007f-\u009f]|\r(?!\n)/g;

/**
 * The text with every run of invisible characters (tag characters outside flags, variation selectors other
 * than an emoji's or an ideograph's, zero-width and other invisible characters outside their ordinary
 * uses, bidirectional controls outside right-to-left text) replaced by one HIDDEN_MARKER, and every terminal
 * control sequence removed. Ordinary text, emoji, flags and right-to-left text are unchanged. Past the scan's
 * limits every remaining control character is removed. Never throws.
 */
export function markHidden(input: string): Marked {
  const text = input;
  const head = text.length > MAX_HIDDEN_SCAN ? text.slice(0, MAX_HIDDEN_SCAN) : text;
  const cps = Array.from(head, (c) => c.codePointAt(0) as number);
  const { hits } = charHits(cps);
  // Code-point index to UTF-16 offset.
  const offsets = new Int32Array(cps.length + 1);
  for (let k = 0, at = 0; k < cps.length; k++) {
    offsets[k] = at;
    at += (cps[k] as number) > 0xffff ? 2 : 1;
    offsets[k + 1] = at;
  }
  const edits: { start: number; end: number; replace: string; marker: boolean }[] = hits.map((h) => ({ start: offsets[h.i] as number, end: offsets[h.i + 1] as number, replace: HIDDEN_MARKER, marker: true }));
  const { seqs, full } = controlsOf(head);
  for (const c of seqs) edits.push({ start: c.start, end: c.end, replace: c.replace, marker: false });
  edits.sort((a, b) => a.start - b.start || b.end - a.end);
  let out = "";
  let at = 0;
  let marked = 0;
  let removed = 0;
  let lastMarkerEnd = -1;
  for (const e of edits) {
    if (e.end <= at) continue;
    const start = Math.max(e.start, at);
    out += text.slice(at, start);
    if (e.marker) {
      // Adjacent invisible characters (or ones separated only by removed controls) make one marker.
      if (lastMarkerEnd !== out.length) {
        out += e.replace;
        marked++;
      }
      lastMarkerEnd = out.length;
    } else {
      // A removed control keeps a marker before it adjacent to the next one (out does not grow).
      out += e.replace;
      removed++;
    }
    at = e.end;
  }
  let rest = text.slice(at);
  if (!full || text.length > MAX_HIDDEN_SCAN) {
    // Past the limits: no sequence parsing, every remaining control character goes (ESC included).
    rest = rest.replace(ANY_CONTROL, (m) => {
      removed++;
      return m === "\r" ? "\n" : "";
    });
  }
  return { text: out + rest, marked, removed };
}
