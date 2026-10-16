// Vendored from the LaunchSafe Agent Firewall (src/engine/content-html.ts), Apache-2.0, at commit 09968d171ebeda828fc07ce6c843170341f28fd0.
// Licence: Apache-2.0 (see NOTICE).
// Do not edit here: it is copied from the firewall repository by
// `node scripts/sync-firewall.mjs` (`--check` verifies the copy).

import { own } from "../own.js";
/**
 * Hidden-HTML resolver for the content scanner.
 *
 * A bounded, error-tolerant HTML tokenizer and a small style resolver, with no
 * DOM library: inline `style`, `<style>` blocks with type, class, id,
 * descendant and child selectors, specificity and `!important`. Media queries
 * are evaluated as a desktop client (1024 px wide, light scheme, screen), so a
 * block shown only on phones or in dark mode is hidden here and then judged by
 * the duplicate rule. Attribute selectors match attributes written in the
 * message (so the client hacks `[data-ogsc]` and `[x-apple-data-detectors]`,
 * keyed on attributes the client adds, match nothing). Selectors this
 * resolver does not model (pseudo-class, sibling) are skipped: in mail they
 * are client hacks (`u + .body`, `:root`).
 *
 * It answers one question: which text would a person reading the rendered
 * message not see, and how is it hidden. It also lists image and link URLs
 * (with whether they sit in hidden markup) for the exfil-link check, and
 * returns source ranges so the scanner can strip hidden parts from the
 * original markup without re-serializing it.
 *
 * Pure: no I/O. Bounded by node and rule counts and a caller's deadline.
 */

export type HiddenHow =
  | "display_none"
  | "visibility_hidden"
  | "hidden_attribute"
  | "mso_hide"
  | "font_size"
  | "opacity"
  | "zero_size"
  | "clip"
  | "offscreen"
  | "text_indent"
  | "low_contrast"
  | "mso_conditional"
  | "template"
  | "comment"
  | "title"
  /** Not HTML: text no mail client displays (other headers, a MIME preamble), see ScanOptions.unshown. */
  | "not_displayed";

export interface HtmlLimits {
  maxNodes: number;
  maxCssRules: number;
  /**
   * Steps of style-sheet matching for the whole document (a rule tried on an element, an ancestor compared,
   * an ancestor chain built, a class looked up, 64 characters of an attribute value read). The deterministic
   * bound on the cascade, whose cost is elements times rules times depth: past it the rest is not matched
   * and the result is incomplete (`css_work`). Default MATCH_STEPS.
   */
  maxMatchSteps?: number;
  /** True once the caller's time budget is spent. */
  expired: () => boolean;
}

export interface HiddenSpan {
  /** Hidden text, block boundaries as newlines. */
  text: string;
  how: HiddenHow[];
  /** Source ranges to remove when neutralizing (text nodes, hidden images). */
  ranges: [number, number][];
  /** The span began before any visible text of the body (where a preview line sits). */
  atStart: boolean;
}

export interface HtmlLink {
  url: string;
  kind: "image" | "link";
  hidden: boolean;
  /** A 1x1 (or smaller) image: a tracking pixel. */
  pixel: boolean;
  range: [number, number];
}

export interface HtmlComment {
  text: string;
  range: [number, number];
}

export interface HtmlAnalysis {
  /** Text a person sees, block boundaries as newlines. */
  visible: string;
  /** Visible `alt` and `title` attribute text (shown when images are off, or on hover). */
  attributeText: string;
  /** Source range and decoded text of every visible text node. */
  visibleNodes: { text: string; range: [number, number] }[];
  spans: HiddenSpan[];
  links: HtmlLink[];
  /** Ordinary (not conditional) comments that contain letters. */
  comments: HtmlComment[];
  /** `<title>` texts: a mail client never shows them, a model reading the markup does. */
  titles: HtmlComment[];
  /** Bounds hit: "html_nodes", "css_rules", "css_work", "time". */
  incomplete: string[];
  /**
   * The work the analysis did, counted (deterministic, unlike the clock): style-sheet matching steps used,
   * and characters read by the tokenizer's searches for the end of raw elements (`<title>`, `<style>`).
   * Callers charge it to a wider budget; tests use it to assert the bounds without a clock.
   */
  work: { matchSteps: number; searchedChars: number };
}

// --- entities ---------------------------------------------------------------------------------

const NAMED: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: "\u00a0", zwnj: "\u200c", zwj: "\u200d", shy: "\u00ad", lrm: "\u200e", rlm: "\u200f",
  copy: "©", reg: "®", trade: "™", hellip: "…", mdash: "—", ndash: "–", lsquo: "‘", rsquo: "’", ldquo: "“", rdquo: "”", sbquo: "‚", bdquo: "„",
  bull: "•", middot: "·", laquo: "«", raquo: "»", euro: "€", pound: "£", yen: "¥", cent: "¢", deg: "°", times: "×", divide: "÷", para: "¶",
  sect: "§", iexcl: "¡", iquest: "¿", ensp: "\u2002", emsp: "\u2003", thinsp: "\u2009", hairsp: "\u200a", rarr: "→", larr: "←", uarr: "↑",
  darr: "↓", check: "✓", star: "☆", hearts: "♥", eacute: "é", egrave: "è", agrave: "à", aacute: "á", uuml: "ü", ouml: "ö", auml: "ä", szlig: "ß",
  ccedil: "ç", ntilde: "ñ", oacute: "ó", iacute: "í", uacute: "ú", ecirc: "ê", acirc: "â", ocirc: "ô", NewLine: "\n", Tab: "\t",
};
const LEGACY = new Set(["amp", "lt", "gt", "quot", "nbsp", "copy", "reg"]);

export function decodeEntities(s: string): string {
  if (!s.includes("&")) return s;
  return s.replace(/&(#[0-9]{1,8}|#[xX][0-9a-fA-F]{1,7}|[A-Za-z][A-Za-z0-9]{1,31})(;?)/g, (whole, ref: string, semi: string) => {
    if (ref.startsWith("#")) {
      const n = ref[1] === "x" || ref[1] === "X" ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
      if (!Number.isFinite(n) || n <= 0 || n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return "\ufffd";
      return String.fromCodePoint(n);
    }
    const v = own(NAMED, ref);
    if (v === undefined || (semi === "" && !LEGACY.has(ref))) return whole;
    return v;
  });
}

// --- tokenizer --------------------------------------------------------------------------------

type Token =
  | { t: "start"; name: string; attrs: Map<string, string>; start: number; end: number; selfClosing: boolean }
  | { t: "end"; name: string; start: number; end: number }
  | { t: "text"; text: string; start: number; end: number }
  | { t: "comment"; text: string; start: number; end: number }
  | { t: "cond_start" }
  | { t: "cond_end" };

const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr", "keygen"]);
const RAW = new Set(["script", "style", "title", "textarea", "xmp", "noembed", "noframes", "iframe", "plaintext"]);
const BLOCK = new Set([
  "address", "article", "aside", "blockquote", "body", "br", "center", "dd", "details", "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer",
  "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p", "pre", "section", "summary", "table", "tbody", "td", "tfoot",
  "th", "thead", "tr", "ul", "caption", "html", "head", "title", "option", "textarea",
]);

class Tokenizer {
  readonly tokens: Token[] = [];
  readonly styles: string[] = [];
  readonly titles: HtmlComment[] = [];
  incomplete = false;
  timedOut = false;
  constructor(
    private readonly src: string,
    private readonly limits: HtmlLimits,
  ) {}

  private nodes = 0;
  /** Characters read by close-tag searches (HtmlAnalysis.work). */
  searched = 0;
  /** Per raw element name: the next `</name` found by a search that started at `from` (-1: none to the end of the source). */
  private readonly closes = new Map<string, { from: number; at: number }>();

  /**
   * Where the raw text of a `<name>` element that starts at `from` ends: the next `</name` (any case), or `end`.
   * A search, not a lower-cased copy of the rest of the source (a copy per raw element made a message of
   * hundreds of `<title>`s quadratic), and remembered, because positions only move forward: a later element
   * reuses the search instead of reading the same text again.
   */
  private closeTagAt(name: string, from: number, end: number): number {
    let c = this.closes.get(name);
    if (c === undefined || c.from > from || (c.at !== -1 && c.at < from)) {
      const re = new RegExp(`</${name}`, "gi");
      re.lastIndex = from;
      c = { from, at: re.exec(this.src)?.index ?? -1 };
      this.searched += (c.at === -1 ? this.src.length : c.at) - from;
      this.closes.set(name, c);
    }
    return c.at === -1 || c.at >= end ? end : c.at;
  }

  private push(tok: Token): boolean {
    // Nodes are elements and text; end tags and comment markers do not count toward the bound.
    if ((tok.t === "start" || tok.t === "text") && ++this.nodes > this.limits.maxNodes) {
      this.incomplete = true;
      return false;
    }
    if ((this.tokens.length & 1023) === 0 && this.limits.expired()) {
      this.timedOut = true;
      return false;
    }
    this.tokens.push(tok);
    return true;
  }

  private text(start: number, end: number): boolean {
    if (end <= start) return true;
    return this.push({ t: "text", text: decodeEntities(this.src.slice(start, end)), start, end });
  }

  run(start: number, end: number, inConditional: boolean): boolean {
    const src = this.src;
    let i = start;
    while (i < end) {
      const lt = src.indexOf("<", i);
      if (lt === -1 || lt >= end) return this.text(i, end);
      if (lt > i && !this.text(i, lt)) return false;
      const next = src[lt + 1] ?? "";
      if (src.startsWith("<!--", lt)) {
        const close = src.indexOf("-->", lt + 4);
        const bodyEnd = close === -1 || close > end ? end : close;
        const cEnd = close === -1 || close > end ? end : close + 3;
        const body = src.slice(lt + 4, bodyEnd);
        const cond = /^\[if\s[^\]]{0,200}\]>/i.exec(body);
        if (cond !== null && !/^\[if\s[^\]]*\]><!$/i.test(body)) {
          // Downlevel-hidden conditional comment (Outlook's copy): its content is markup only Outlook renders.
          const innerStart = lt + 4 + cond[0].length;
          const endif = body.toLowerCase().lastIndexOf("<![endif]");
          const innerEnd = endif === -1 ? bodyEnd : lt + 4 + endif;
          if (!this.push({ t: "cond_start" })) return false;
          if (!this.run(innerStart, innerEnd, true)) return false;
          if (!this.push({ t: "cond_end" })) return false;
        } else if (!/^\[if\s|^<!\[endif\]|^\[endif\]/i.test(body) && /\p{L}/u.test(body)) {
          if (!this.push({ t: "comment", text: decodeEntities(body), start: lt, end: cEnd })) return false;
        }
        i = cEnd;
        continue;
      }
      if (src.startsWith("<![CDATA[", lt)) {
        const close = src.indexOf("]]>", lt + 9);
        const cEnd = close === -1 || close > end ? end : close;
        if (!this.push({ t: "text", text: src.slice(lt + 9, cEnd), start: lt, end: Math.min(end, cEnd + 3) })) return false;
        i = Math.min(end, cEnd + 3);
        continue;
      }
      if (next === "!" || next === "?") {
        const close = src.indexOf(">", lt + 2);
        i = close === -1 || close >= end ? end : close + 1;
        continue;
      }
      if (next === "/") {
        const m = /^<\/([A-Za-z][\w:-]{0,63})[^>]{0,1000}>/.exec(src.slice(lt, Math.min(end, lt + 1100)));
        if (m === null) {
          if (!this.text(lt, lt + 1)) return false;
          i = lt + 1;
          continue;
        }
        if (!this.push({ t: "end", name: (m[1] ?? "").toLowerCase(), start: lt, end: lt + m[0].length })) return false;
        i = lt + m[0].length;
        continue;
      }
      const nm = /^<([A-Za-z][\w:-]{0,63})/.exec(src.slice(lt, Math.min(end, lt + 70)));
      if (nm === null) {
        if (!this.text(lt, lt + 1)) return false;
        i = lt + 1;
        continue;
      }
      const name = (nm[1] ?? "").toLowerCase();
      const { attrs, end: tagEnd, selfClosing } = this.attributes(lt + nm[0].length, end);
      if (!this.push({ t: "start", name, attrs, start: lt, end: tagEnd, selfClosing })) return false;
      i = tagEnd;
      if (RAW.has(name) && !selfClosing) {
        const contentEnd = this.closeTagAt(name, i, end);
        if (name === "style" && !inConditional) {
          const type = attrs.get("type");
          if (type === undefined || /^\s*text\/css\s*$/i.test(type) || type.trim() === "") this.styles.push(src.slice(i, contentEnd));
        } else if (name === "textarea") {
          if (!this.text(i, contentEnd)) return false;
        } else if (name === "title" && contentEnd > i && this.titles.length < 100) {
          this.titles.push({ text: decodeEntities(src.slice(i, contentEnd)), range: [i, contentEnd] });
        }
        i = contentEnd;
      }
    }
    return true;
  }

  private attributes(from: number, end: number): { attrs: Map<string, string>; end: number; selfClosing: boolean } {
    const src = this.src;
    const attrs = new Map<string, string>();
    let i = from;
    let selfClosing = false;
    while (i < end) {
      const c = src[i] as string;
      if (c === ">") return { attrs, end: i + 1, selfClosing };
      if (c === "/" ) {
        selfClosing = src[i + 1] === ">";
        i++;
        continue;
      }
      if (/\s/.test(c)) {
        i++;
        continue;
      }
      let j = i;
      while (j < end && !/[\s/>=]/.test(src[j] as string)) j++;
      const name = src.slice(i, j).toLowerCase();
      if (j === i) {
        i++;
        continue;
      }
      i = j;
      while (i < end && /\s/.test(src[i] as string)) i++;
      let value = "";
      if (src[i] === "=") {
        i++;
        while (i < end && /\s/.test(src[i] as string)) i++;
        const q = src[i];
        if (q === '"' || q === "'") {
          const close = src.indexOf(q, i + 1);
          const vEnd = close === -1 || close >= end ? end : close;
          value = src.slice(i + 1, vEnd);
          i = vEnd + 1;
        } else {
          let k = i;
          while (k < end && !/[\s>]/.test(src[k] as string)) k++;
          value = src.slice(i, k);
          i = k;
        }
      }
      if (!attrs.has(name)) attrs.set(name, decodeEntities(value));
    }
    return { attrs, end, selfClosing };
  }
}

// --- CSS --------------------------------------------------------------------------------------

const PROPS = new Set([
  "display", "visibility", "mso-hide", "font-size", "font", "opacity", "max-height", "height", "width", "max-width", "overflow", "overflow-x",
  "overflow-y", "clip", "clip-path", "position", "left", "top", "right", "bottom", "margin-left", "margin-top", "text-indent", "color",
  "background-color", "background", "background-image", "transform", "scale", "translate", "line-height",
]);

interface Decl {
  prop: string;
  value: string;
  important: boolean;
}

interface AttrSel {
  name: string;
  /** "" for presence (`[data-a]`), else the operator. */
  op: "" | "=" | "~=" | "|=" | "^=" | "$=" | "*=";
  value: string;
  /** The `i` flag: compare ASCII case-insensitively. */
  ci: boolean;
}

interface Compound {
  tag: string | null;
  id: string | null;
  classes: string[];
  attrs: AttrSel[];
}

interface Selector {
  compounds: Compound[];
  /** combinators[i] joins compounds[i] and compounds[i + 1]: " " or ">". */
  combinators: string[];
  specificity: number;
}

interface Rule {
  selector: Selector;
  decls: Decl[];
  order: number;
}

/** CSS comments removed (outside strings), as a browser's tokenizer drops them: an empty comment between `display:` and `none` still hides. */
export function stripCssComments(css: string): string {
  if (!css.includes("/*")) return css;
  let out = "";
  let quote = "";
  for (let i = 0; i < css.length; i++) {
    const c = css[i] as string;
    if (quote !== "") {
      out += c;
      if (c === "\\") out += css[++i] ?? "";
      else if (c === quote) quote = "";
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === "/" && css[i + 1] === "*") {
      const close = css.indexOf("*/", i + 2);
      i = close === -1 ? css.length : close + 1;
      // A comment separates tokens; a space keeps `a/**/b` from becoming one word.
      out += " ";
      continue;
    }
    out += c;
  }
  return out;
}

/**
 * CSS escapes decoded (`\61` and `\61 ` are "a", `\:` is ":"), as a browser reads an identifier:
 * `disp\61 y:none` is `display:none`. A null, surrogate or out-of-range code point becomes U+FFFD, as in CSS.
 */
export function cssUnescape(s: string): string {
  if (!s.includes("\\")) return s;
  return s.replace(/\\(?:([0-9a-fA-F]{1,6})(?:\r\n|[ \t\n\r\f])?|([^\n\r\f0-9a-fA-F])|[\n\r\f])/g, (_whole: string, hex: string | undefined, ch: string | undefined) => {
    if (hex !== undefined) {
      const n = parseInt(hex, 16);
      return n === 0 || n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff) ? "�" : String.fromCodePoint(n);
    }
    return ch ?? "";
  });
}

export function parseDeclarations(rawBlock: string): Decl[] {
  const out: Decl[] = [];
  const block = stripCssComments(rawBlock);
  let depth = 0;
  let quote = "";
  let start = 0;
  const flush = (end: number) => {
    const part = cssUnescape(block.slice(start, end));
    const colon = part.indexOf(":");
    if (colon > 0) {
      const prop = part.slice(0, colon).trim().toLowerCase();
      if (PROPS.has(prop)) {
        let value = part.slice(colon + 1).trim();
        const important = /!\s*important\s*$/i.test(value);
        if (important) value = value.replace(/!\s*important\s*$/i, "").trim();
        out.push({ prop, value: value.toLowerCase(), important });
      }
    }
    start = end + 1;
  };
  for (let i = 0; i < block.length; i++) {
    const c = block[i];
    if (quote !== "") {
      if (c === quote) quote = "";
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === "(") depth++;
    else if (c === ")") depth = Math.max(0, depth - 1);
    else if (c === ";" && depth === 0) flush(i);
  }
  flush(block.length);
  return out;
}

const ATTR_SEL = /^\s*([A-Za-z_][\w:.-]*)\s*(?:([~|^$*]?=)\s*(?:"([^"]*)"|'([^']*)'|([\w-]+))\s*([iIsS])?)?\s*$/;

/** One compound selector (`div.a#b[data-x="1"]`) from `at`; null for anything this resolver does not model. */
function parseCompound(s: string, at: number): { c: Compound; end: number } | null {
  const c: Compound = { tag: null, id: null, classes: [], attrs: [] };
  let i = at;
  let any = false;
  const tag = /^(?:\*|[A-Za-z][\w-]*)/.exec(s.slice(i, i + 80));
  if (tag !== null) {
    c.tag = tag[0] === "*" ? null : tag[0].toLowerCase();
    i += tag[0].length;
    any = true;
  }
  while (i < s.length) {
    const ch = s[i] as string;
    if (ch === "." || ch === "#") {
      const n = /^[\w-]+/.exec(s.slice(i + 1, i + 260));
      if (n === null) return null;
      if (ch === "#") c.id = n[0];
      else c.classes.push(n[0]);
      i += 1 + n[0].length;
      any = true;
      continue;
    }
    if (ch === "[") {
      const close = s.indexOf("]", i);
      if (close === -1) return null;
      const m = ATTR_SEL.exec(s.slice(i + 1, close));
      if (m === null) return null;
      c.attrs.push({ name: (m[1] as string).toLowerCase(), op: (m[2] ?? "") as AttrSel["op"], value: m[3] ?? m[4] ?? m[5] ?? "", ci: m[6] === "i" || m[6] === "I" });
      i = close + 1;
      any = true;
      continue;
    }
    if (ch === ">" || /\s/.test(ch)) break;
    // Pseudo-classes, sibling combinators (`u + .body`, Gmail's hack), namespaces: not modelled.
    return null;
  }
  return any ? { c, end: i } : null;
}

/**
 * A selector this resolver models: type, class, id and attribute selectors joined by descendant and child
 * combinators. Attribute selectors match only attributes written in the message, so the mail-client hacks
 * that key on attributes the client adds itself (`[data-ogsc]`, `[x-apple-data-detectors]`, `[owa]`) match
 * nothing, as in a desktop client that is not that one.
 */
/**
 * CSS escapes in a selector decoded where they stand for an identifier character (`.\78` is `.x`). An
 * escape for anything else (`\:`, `\.`, a space) is left in place, which parseSelector then refuses.
 */
function unescapeSelector(s: string): string | null {
  if (!s.includes("\\")) return s;
  const out = (s.replace(/\\(?:([0-9a-fA-F]{1,6}[ \t\n\r\f]?)|([^\n\r\f0-9a-fA-F]))/g, (whole: string, hex: string | undefined, ch: string | undefined) => {
    if (hex === undefined) return /^[A-Za-z_-]$/.test(ch ?? "") ? (ch as string) : whole;
    const n = parseInt(hex.trim(), 16);
    // Only a code point that is an identifier character (and not special in a selector) is decoded.
    return n >= 0x2d && n <= 0x7a && /[A-Za-z0-9_-]/.test(String.fromCharCode(n)) ? String.fromCharCode(n) : whole;
  }));
  return out.includes("\\") ? null : out;
}

function parseSelector(text: string): Selector | null {
  const s = unescapeSelector(text.trim());
  if (s === null) return null;
  if (s === "" || s.length > 2000 || /[\\@(),+~]/.test(s.replace(/\[[^\]]*\]/g, "[]"))) return null;
  const compounds: Compound[] = [];
  const combinators: string[] = [];
  let pending: string | null = null;
  let i = 0;
  while (i < s.length) {
    const ch = s[i] as string;
    if (/\s/.test(ch)) {
      if (compounds.length > 0 && pending === null) pending = " ";
      i++;
      continue;
    }
    if (ch === ">") {
      if (compounds.length === 0) return null;
      pending = ">";
      i++;
      continue;
    }
    const r = parseCompound(s, i);
    if (r === null) return null;
    if (compounds.length > 0) combinators.push(pending ?? " ");
    compounds.push(r.c);
    pending = null;
    i = r.end;
  }
  if (pending === ">") return null;
  if (compounds.length === 0 || compounds.length > 8) return null;
  let a = 0;
  let b = 0;
  let cc = 0;
  for (const c of compounds) {
    if (c.id !== null) a++;
    b += c.classes.length + c.attrs.length;
    if (c.tag !== null) cc++;
  }
  return { compounds, combinators, specificity: a * 10000 + b * 100 + cc };
}

const DESKTOP_WIDTH = 1024;

function cssLengthPx(v: string): number | null {
  const m = /^(-?\d*\.?\d+)(px|em|rem|pt)?$/.exec(v.trim());
  if (m === null) return null;
  const n = Number(m[1]);
  return m[2] === "em" || m[2] === "rem" ? n * 16 : m[2] === "pt" ? (n * 4) / 3 : n;
}

/** Evaluates a media query list as a desktop mail client: screen, 1024 px wide, light scheme. */
export function mediaMatchesDesktop(query: string): boolean {
  return query.split(",").some((q) => {
    let s = q.trim().toLowerCase();
    let negate = false;
    if (s.startsWith("not ")) {
      negate = true;
      s = s.slice(4);
    }
    s = s.replace(/^only\s+/, "");
    let ok = true;
    for (const part of s.split(/\s+and\s+/)) {
      const p = part.trim();
      if (p === "" || p === "all" || p === "screen") continue;
      if (p === "print" || p === "speech" || p === "tv" || p === "handheld") {
        ok = false;
        continue;
      }
      const f = /^\(\s*([a-z-]+)\s*(?::\s*([^)]+))?\)$/.exec(p);
      if (f === null) {
        ok = false;
        continue;
      }
      const name = f[1] ?? "";
      const value = (f[2] ?? "").trim();
      const px = cssLengthPx(value);
      if (name === "max-width" || name === "max-device-width") ok &&= px !== null && DESKTOP_WIDTH <= px;
      else if (name === "min-width" || name === "min-device-width") ok &&= px !== null && DESKTOP_WIDTH >= px;
      else if (name === "width" || name === "device-width") ok &&= px === DESKTOP_WIDTH;
      else if (name === "prefers-color-scheme") ok &&= value === "light";
      else if (name === "orientation") ok &&= value === "landscape";
      else if (name === "hover") ok &&= value === "hover";
      else if (name === "pointer") ok &&= value === "fine";
      else if (name === "color") ok &&= true;
      else ok = false;
    }
    return negate ? !ok : ok;
  });
}

function matchingBrace(css: string, open: number): number {
  let depth = 0;
  let quote = "";
  for (let i = open; i < css.length; i++) {
    const c = css[i];
    if (quote !== "") {
      if (c === quote) quote = "";
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return css.length;
}

class StyleSheet {
  readonly byId = new Map<string, Rule[]>();
  readonly byClass = new Map<string, Rule[]>();
  readonly byTag = new Map<string, Rule[]>();
  readonly universal: Rule[] = [];
  count = 0;
  truncated = false;
  constructor(private readonly maxRules: number) {}

  add(css: string): void {
    this.parse(css.replace(/\/\*[\s\S]*?\*\//g, " "));
  }

  private parse(css: string): void {
    let i = 0;
    while (i < css.length) {
      while (i < css.length && /[\s;}]/.test(css[i] as string)) i++;
      if (i >= css.length) return;
      const open = css.indexOf("{", i);
      if (css[i] === "@") {
        const semi = css.indexOf(";", i);
        if (open === -1 || (semi !== -1 && semi < open)) {
          i = semi === -1 ? css.length : semi + 1;
          continue;
        }
        const prelude = css.slice(i, open).trim();
        const close = matchingBrace(css, open);
        const inner = css.slice(open + 1, close);
        const name = (/^@([\w-]+)/.exec(prelude)?.[1] ?? "").toLowerCase();
        if (name === "media") {
          if (mediaMatchesDesktop(prelude.slice(6))) this.parse(inner);
        } else if (name === "supports" || name === "layer" || name === "container") {
          this.parse(inner);
        }
        i = close + 1;
        continue;
      }
      if (open === -1) return;
      const close = matchingBrace(css, open);
      const selectorText = css.slice(i, open);
      const decls = parseDeclarations(css.slice(open + 1, close));
      i = close + 1;
      if (decls.length === 0) continue;
      for (const sel of selectorText.split(",")) {
        const selector = parseSelector(sel);
        if (selector === null) continue;
        if (this.count >= this.maxRules) {
          this.truncated = true;
          return;
        }
        const rule: Rule = { selector, decls, order: this.count++ };
        const key = selector.compounds[selector.compounds.length - 1] as Compound;
        if (key.id !== null) bucket(this.byId, key.id).push(rule);
        else if (key.classes.length > 0) bucket(this.byClass, key.classes[0] as string).push(rule);
        else if (key.tag !== null) bucket(this.byTag, key.tag).push(rule);
        else this.universal.push(rule);
      }
    }
  }
}

function bucket(map: Map<string, Rule[]>, key: string): Rule[] {
  let b = map.get(key);
  if (b === undefined) {
    b = [];
    map.set(key, b);
  }
  return b;
}

interface ElementInfo {
  tag: string;
  id: string | null;
  /** The element's classes, each once (a class attribute can list hundreds of thousands). */
  classes: Set<string>;
  attrs: Map<string, string>;
  /** Lower-cased attribute values and `~=` word sets, made on first use and kept for the element's other rules. */
  lower?: Map<string, string>;
  words?: Map<string, Set<string>>;
}

function elementInfo(tag: string, attrs: Map<string, string>): ElementInfo {
  const classes = new Set<string>();
  for (const c of (attrs.get("class") ?? "").split(/\s+/)) if (c !== "") classes.add(c);
  return { tag, id: attrs.get("id") ?? null, classes, attrs };
}

/**
 * Matching steps charged for reading `n` characters of an attribute value (lower-casing it, splitting it,
 * searching it): one step per 64 characters, so a rule tried against a 2 MB attribute costs what it does,
 * and a document's work stays bounded by its step budget however long its attributes are.
 */
const charSteps = (n: number): number => 1 + (n >> 6);

function attrMatches(a: AttrSel, el: ElementInfo, work: { n: number }): boolean {
  const raw = el.attrs.get(a.name);
  if (raw === undefined) return false;
  if (a.op === "") return true;
  let v = raw;
  if (a.ci) {
    el.lower ??= new Map();
    const low = el.lower.get(a.name);
    if (low === undefined) {
      work.n -= charSteps(raw.length);
      v = raw.toLowerCase();
      el.lower.set(a.name, v);
    } else v = low;
  }
  const want = a.ci ? a.value.toLowerCase() : a.value;
  switch (a.op) {
    case "=":
      work.n -= charSteps(want.length);
      return v === want;
    case "~=": {
      if (want === "") return false;
      const key = `${a.ci ? "i" : "s"}${a.name}`;
      el.words ??= new Map();
      let set = el.words.get(key);
      if (set === undefined) {
        work.n -= charSteps(v.length);
        set = new Set(v.split(/[ \t\n\r\f]+/));
        el.words.set(key, set);
      }
      return set.has(want);
    }
    case "|=":
      work.n -= charSteps(want.length);
      return v === want || v.startsWith(`${want}-`);
    case "^=":
      work.n -= charSteps(want.length);
      return want !== "" && v.startsWith(want);
    case "$=":
      work.n -= charSteps(want.length);
      return want !== "" && v.endsWith(want);
    case "*=":
      // A substring search reads the value: charged by its length.
      work.n -= charSteps(v.length);
      return want !== "" && v.includes(want);
  }
}

/**
 * One compound against one element; every class and attribute compared is charged to `work`. The tag and
 * id comparisons are not charged on their own: a selector's id is at most 259 characters (parseCompound),
 * so comparing it costs no more than the step its caller already charged. The element's class set is built
 * once per element (elementInfo), in time linear in its class attribute, which the scan paid for when it
 * charged the part's characters; the 2-second clock remains the last-resort backstop for both.
 */
function compoundMatches(c: Compound, el: ElementInfo, work: { n: number }): boolean {
  if (c.tag !== null && c.tag !== el.tag) return false;
  if (c.id !== null && c.id !== el.id) return false;
  for (const k of c.classes) {
    work.n--;
    if (!el.classes.has(k)) return false;
  }
  for (const a of c.attrs) if (!attrMatches(a, el, work)) return false;
  return true;
}

/** Style-sheet matching steps per document (`HtmlLimits.maxMatchSteps`); at the bound a scan takes about 100 ms, and every message of the mail and content corpora fits inside it. */
export const MATCH_STEPS = 4_000_000;

/**
 * Matches a selector right to left; `ancestors` is the element's ancestor chain, nearest last. `work` is the
 * document's remaining matching steps, shared by every call: when it runs out the answer is false and the
 * caller reports the document incomplete.
 */
function selectorMatches(sel: Selector, el: ElementInfo, ancestors: readonly ElementInfo[], work: { n: number }): boolean {
  const last = sel.compounds.length - 1;
  if (--work.n < 0) return false;
  if (!compoundMatches(sel.compounds[last] as Compound, el, work)) return false;
  const step = (ci: number, from: number, budget: { n: number }): boolean => {
    if (ci < 0) return true;
    if (--budget.n < 0 || --work.n < 0) return false;
    const comb = sel.combinators[ci];
    const c = sel.compounds[ci] as Compound;
    if (comb === ">") {
      const a = ancestors[from];
      return a !== undefined && compoundMatches(c, a, work) && step(ci - 1, from - 1, budget);
    }
    for (let k = from; k >= 0; k--) {
      // Each ancestor compared is a step: a descendant combinator over a deep chain is the costly case.
      if (--budget.n < 0 || --work.n < 0) return false;
      if (compoundMatches(c, ancestors[k] as ElementInfo, work) && step(ci - 1, k - 1, budget)) return true;
    }
    return false;
  };
  return step(last - 1, ancestors.length - 1, { n: 2000 });
}

// --- colours ----------------------------------------------------------------------------------

type Rgba = [number, number, number, number];

const NAMED_COLOURS: Record<string, Rgba> = {
  white: [255, 255, 255, 1], black: [0, 0, 0, 1], red: [255, 0, 0, 1], green: [0, 128, 0, 1], blue: [0, 0, 255, 1], gray: [128, 128, 128, 1],
  grey: [128, 128, 128, 1], silver: [192, 192, 192, 1], yellow: [255, 255, 0, 1], orange: [255, 165, 0, 1], purple: [128, 0, 128, 1],
  navy: [0, 0, 128, 1], maroon: [128, 0, 0, 1], olive: [128, 128, 0, 1], teal: [0, 128, 128, 1], aqua: [0, 255, 255, 1], lime: [0, 255, 0, 1],
  fuchsia: [255, 0, 255, 1], whitesmoke: [245, 245, 245, 1], snow: [255, 250, 250, 1], ivory: [255, 255, 240, 1], ghostwhite: [248, 248, 255, 1],
  lightgray: [211, 211, 211, 1], lightgrey: [211, 211, 211, 1], gainsboro: [220, 220, 220, 1], darkgray: [169, 169, 169, 1],
  transparent: [0, 0, 0, 0],
};

export function parseColour(raw: string): Rgba | null {
  const v = raw.trim().toLowerCase();
  const named = own(NAMED_COLOURS, v);
  if (named !== undefined) return named;
  let m = /^#([0-9a-f]{3,8})$/.exec(v);
  if (m !== null) {
    const h = m[1] as string;
    if (h.length === 3 || h.length === 4) {
      const p = [...h].map((x) => parseInt(x + x, 16));
      return [p[0] as number, p[1] as number, p[2] as number, h.length === 4 ? (p[3] as number) / 255 : 1];
    }
    if (h.length === 6 || h.length === 8) {
      const p = (h.match(/../g) ?? []).map((x) => parseInt(x, 16));
      return [p[0] as number, p[1] as number, p[2] as number, h.length === 8 ? (p[3] as number) / 255 : 1];
    }
    return null;
  }
  m = /^rgba?\(\s*([\d.]+%?)[\s,]+([\d.]+%?)[\s,]+([\d.]+%?)(?:\s*[,/]\s*([\d.]+%?))?\s*\)$/.exec(v);
  if (m !== null) {
    const ch = (x: string) => (x.endsWith("%") ? (Number(x.slice(0, -1)) * 255) / 100 : Number(x));
    const a = m[4] === undefined ? 1 : m[4].endsWith("%") ? Number(m[4].slice(0, -1)) / 100 : Number(m[4]);
    return [ch(m[1] as string), ch(m[2] as string), ch(m[3] as string), a];
  }
  m = /^hsla?\(\s*([\d.]+)(?:deg)?[\s,]+([\d.]+)%[\s,]+([\d.]+)%(?:\s*[,/]\s*([\d.]+%?))?\s*\)$/.exec(v);
  if (m !== null) {
    const h = Number(m[1]) / 360;
    const s = Number(m[2]) / 100;
    const l = Number(m[3]) / 100;
    const a = m[4] === undefined ? 1 : m[4].endsWith("%") ? Number(m[4].slice(0, -1)) / 100 : Number(m[4]);
    const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
    const p = 2 * l - q;
    const hue = (t: number) => {
      const x = t < 0 ? t + 1 : t > 1 ? t - 1 : t;
      if (x < 1 / 6) return p + (q - p) * 6 * x;
      if (x < 1 / 2) return q;
      if (x < 2 / 3) return p + (q - p) * (2 / 3 - x) * 6;
      return p;
    };
    return [hue(h + 1 / 3) * 255, hue(h) * 255, hue(h - 1 / 3) * 255, a];
  }
  return null;
}

function luminance([r, g, b]: Rgba): number {
  const f = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}

/** WCAG contrast ratio of a foreground (composited over the background) against the background. */
export function contrastRatio(fg: Rgba, bg: Rgba): number {
  const a = fg[3];
  const comp: Rgba = [fg[0] * a + bg[0] * (1 - a), fg[1] * a + bg[1] * (1 - a), fg[2] * a + bg[2] * (1 - a), 1];
  const l1 = luminance(comp);
  const l2 = luminance(bg);
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
}

// --- computed context -------------------------------------------------------------------------

const WHITE: Rgba = [255, 255, 255, 1];
const BLACK: Rgba = [0, 0, 0, 1];

interface Ctx {
  /** Reasons a descendant cannot undo (display:none, clipping, off-screen, Outlook-only). */
  fixed: readonly HiddenHow[];
  fixedKey: number;
  visHidden: boolean;
  visKey: number;
  fontPx: number;
  fontKey: number;
  /** line-height is zero (inherited): with a 1px font the text collapses to nothing. */
  lineZero: boolean;
  lineKey: number;
  opacity: number;
  opKey: number;
  color: Rgba;
  colorKey: number;
  /** Nearest declared background; null when an image is behind the text (contrast unknown). */
  bg: Rgba | null;
  bgKey: number;
  inHead: boolean;
}

const ROOT_CTX: Ctx = { fixed: [], fixedKey: -1, visHidden: false, visKey: -1, fontPx: 16, fontKey: -1, lineZero: false, lineKey: -1, opacity: 1, opKey: -1, color: BLACK, colorKey: -1, bg: WHITE, bgKey: -1, inHead: false };

const FONT_KEYWORDS: Record<string, number> = { "xx-small": 9, "x-small": 10, small: 13, medium: 16, large: 18, "x-large": 24, "xx-large": 32, "xxx-large": 48 };
const FONT_TAG_SIZES = [10, 10, 13, 16, 18, 24, 32, 48];

function lengthPx(v: string | undefined, fontPx: number): number | null {
  if (v === undefined) return null;
  const m = /^(-?\d*\.?\d+)(px|pt|em|rem|ex|ch|pc|in|cm|mm)?$/.exec(v.trim());
  if (m === null) return null;
  const n = Number(m[1]);
  switch (m[2]) {
    case undefined:
      return n === 0 ? 0 : null;
    case "px":
      return n;
    case "pt":
      return (n * 4) / 3;
    case "pc":
      return n * 16;
    case "in":
      return n * 96;
    case "cm":
      return (n * 96) / 2.54;
    case "mm":
      return (n * 96) / 25.4;
    case "em":
    case "ch":
      return n * fontPx;
    case "ex":
      return (n * fontPx) / 2;
    case "rem":
      return n * 16;
    default:
      return null;
  }
}

function fontSizeFrom(value: string, parentPx: number): number | null {
  const v = value.trim();
  const kw = own(FONT_KEYWORDS, v);
  if (kw !== undefined) return kw;
  if (v === "smaller") return parentPx / 1.2;
  if (v === "larger") return parentPx * 1.2;
  const pct = /^(\d*\.?\d+)%$/.exec(v);
  if (pct !== null) return (Number(pct[1]) * parentPx) / 100;
  const n = /^(-?\d*\.?\d+)$/.exec(v);
  if (n !== null) return Number(n[1]) === 0 ? 0 : null;
  return lengthPx(v, parentPx);
}

/** The size in a `font` shorthand ("bold 0/0 a", "12px/1.4 Arial"). */
function fontShorthandSize(value: string, parentPx: number): number | null {
  for (const tok of value.split(/\s+/)) {
    const size = tok.split("/")[0] ?? "";
    if (/^(?:\d*\.?\d+(?:px|pt|em|rem|%)?|xx-small|x-small|small|medium|large|x-large|xx-large|smaller|larger)$/.test(size)) {
      if (/^\d+$/.test(size) && Number(size) !== 0 && !tok.includes("/")) continue; // a font-weight like 700
      return fontSizeFrom(size, parentPx);
    }
  }
  return null;
}

/** The line height in a `font` shorthand ("1px/0 a"), or undefined when it gives none. */
function fontShorthandLineHeight(value: string): string | undefined {
  for (const tok of value.split(/\s+/)) {
    const slash = tok.indexOf("/");
    if (slash > 0) return tok.slice(slash + 1);
  }
  return undefined;
}

const isZeroLength = (v: string): boolean => /^[+-]?(?:0+\.?0*|\.0+)(?:[a-z]{1,4}|%)?$/.test(v.trim());

/**
 * The smallest axis factor of a `transform`'s scaling functions (scale, scaleX/Y, scale3d, a matrix that
 * collapses an axis) and of the `scale` property; 1 when nothing scales.
 */
export function scaleFactor(transform: string | undefined, scale: string | undefined): number {
  let x = 1;
  let y = 1;
  const num = (t: string | undefined): number | null => {
    if (t === undefined) return null;
    const m = /^([+-]?\d*\.?\d+(?:e[+-]?\d+)?)(%?)$/i.exec(t.trim());
    if (m === null) return null;
    const n = Number(m[1]);
    return m[2] === "%" ? n / 100 : n;
  };
  for (const m of (transform ?? "").matchAll(/\b(scale3d|scalex|scaley|scale|matrix3d|matrix)\(\s*([^()]*)\)/gi)) {
    const fn = (m[1] as string).toLowerCase();
    const args = (m[2] as string).split(/[\s,]+/).filter((a) => a !== "").map(num);
    if (args.some((a) => a === null)) continue;
    const a = args as number[];
    if (fn === "scale") {
      x *= a[0] ?? 1;
      y *= a[1] ?? a[0] ?? 1;
    } else if (fn === "scalex") x *= a[0] ?? 1;
    else if (fn === "scaley") y *= a[0] ?? 1;
    else if (fn === "scale3d") {
      x *= a[0] ?? 1;
      y *= a[1] ?? 1;
    } else if (fn === "matrix" && a.length === 6) {
      x *= Math.hypot(a[0] as number, a[1] as number);
      y *= Math.hypot(a[2] as number, a[3] as number);
    } else if (fn === "matrix3d" && a.length === 16) {
      x *= Math.hypot(a[0] as number, a[1] as number);
      y *= Math.hypot(a[4] as number, a[5] as number);
    }
  }
  const sp = (scale ?? "").trim().split(/\s+/).filter((t) => t !== "");
  if (sp.length > 0 && sp[0] !== "none") {
    const sx = num(sp[0]);
    const sy = num(sp[1] ?? sp[0]);
    if (sx !== null && sy !== null) {
      x *= sx;
      y *= sy;
    }
  }
  return Math.min(Math.abs(x), Math.abs(y));
}

/** A translation that moves the box 1000px or more either way, or a whole box width to the left. */
export function translatedAway(transform: string | undefined, translate: string | undefined, fontPx: number): boolean {
  const far = (a: string | undefined): boolean => {
    const t = (a ?? "").trim();
    if (t === "") return false;
    const pct = /^([+-]?\d*\.?\d+)%$/.exec(t);
    if (pct !== null) return Number(pct[1]) <= -100;
    const n = lengthPx(t, fontPx);
    return n !== null && Math.abs(n) >= 1000;
  };
  for (const m of (transform ?? "").matchAll(/\b(translate3d|translatex|translatey|translate)\(\s*([^()]*)\)/gi)) {
    const args = (m[2] as string).split(/[\s,]+/).filter((x) => x !== "");
    const fn = (m[1] as string).toLowerCase();
    if (fn === "translate" || fn === "translate3d" ? args.slice(0, 2).some(far) : far(args[0])) return true;
  }
  const tp = (translate ?? "").trim().split(/\s+/).filter((x) => x !== "" && x !== "none");
  return tp.slice(0, 2).some(far);
}

function clipIsZero(v: string): boolean {
  const m = /^rect\(\s*([^,\s)]+)[\s,]+([^,\s)]+)[\s,]+([^,\s)]+)[\s,]+([^,\s)]+)\s*\)$/.exec(v.trim());
  if (m === null) return false;
  const [top, right, bottom, left] = [m[1], m[2], m[3], m[4]].map((x) => (x === "auto" ? null : lengthPx(x as string, 16)));
  if (top == null || right == null || bottom == null || left == null) return false;
  return bottom - top <= 0 || right - left <= 0;
}

function clipPathIsZero(v: string): boolean {
  const s = v.trim();
  const inset = /^inset\(\s*(\d*\.?\d+)(%|px)?/.exec(s);
  if (inset !== null) return inset[2] === "%" && Number(inset[1]) >= 50;
  return /^(?:circle\(\s*0(?:px|%)?\s*(?:at|\))|ellipse\(\s*0(?:px|%)?\s+0(?:px|%)?)/.test(s);
}

// --- the walk ---------------------------------------------------------------------------------

interface Frame {
  name: string;
  info: ElementInfo | null;
  ctx: Ctx;
  pseudo: boolean;
}

/**
 * Resolves which text of an HTML document is hidden from a person reading the
 * rendered message. Never throws on malformed input: unknown structure is read
 * leniently, and bounds are reported in `incomplete`.
 */
export function analyzeHtml(src: string, limits: HtmlLimits): HtmlAnalysis {
  const tz = new Tokenizer(src, limits);
  tz.run(0, src.length, false);
  const incomplete: string[] = [];
  if (tz.incomplete) incomplete.push("html_nodes");
  if (tz.timedOut) incomplete.push("time");
  const sheet = new StyleSheet(limits.maxCssRules);
  for (const css of tz.styles) sheet.add(css);
  if (sheet.truncated) incomplete.push("css_rules");

  const visibleParts: string[] = [];
  const attrParts: string[] = [];
  const visibleNodes: { text: string; range: [number, number] }[] = [];
  const spans = new Map<number, HiddenSpan & { lastBreak: number }>();
  const links: HtmlLink[] = [];
  const comments: HtmlComment[] = [];
  let breaks = 0;
  let visibleLastBreak = 0;
  let visibleSeen = false;
  let nextId = 0;
  const stack: Frame[] = [{ name: "#root", info: null, ctx: ROOT_CTX, pseudo: true }];
  const top = () => stack[stack.length - 1] as Frame;
  const maxSteps = limits.maxMatchSteps ?? MATCH_STEPS;
  const work = { n: maxSteps };
  let elements = 0;
  let cascadeCut: "css_work" | "time" | null = null;
  const ancestorsInfo = (): ElementInfo[] => {
    work.n -= stack.length;
    const out: ElementInfo[] = [];
    for (const f of stack) if (f.info !== null) out.push(f.info);
    return out;
  };

  const hiddenOf = (ctx: Ctx): { how: HiddenHow[]; key: number } | null => {
    const how: HiddenHow[] = [...ctx.fixed];
    let key = ctx.fixed.length > 0 ? ctx.fixedKey : -1;
    const add = (h: HiddenHow, k: number) => {
      if (!how.includes(h)) how.push(h);
      if (key === -1) key = k;
    };
    if (ctx.visHidden) add("visibility_hidden", ctx.visKey);
    if (ctx.fontPx < 1) add("font_size", ctx.fontKey);
    else if (ctx.fontPx <= 1 && ctx.lineZero) add("font_size", Math.max(ctx.fontKey, ctx.lineKey));
    if (ctx.opacity < 0.1) add("opacity", ctx.opKey);
    if (ctx.color[3] < 0.1) add("low_contrast", ctx.colorKey);
    else if (ctx.bg !== null && contrastRatio(ctx.color, ctx.bg) < 1.2) add("low_contrast", Math.max(ctx.colorKey, ctx.bgKey));
    return how.length === 0 ? null : { how, key };
  };

  const spanFor = (key: number, how: HiddenHow[]) => {
    let s = spans.get(key);
    if (s === undefined) {
      s = { text: "", how: [], ranges: [], lastBreak: breaks, atStart: !visibleSeen };
      spans.set(key, s);
    }
    for (const h of how) if (!s.how.includes(h)) s.how.push(h);
    return s;
  };

  const declared = (info: ElementInfo, attrs: Map<string, string>): Map<string, Decl> => {
    const candidates: { d: Decl; w: number[] }[] = [];
    let ancCache: ElementInfo[] | null = null;
    const anc = () => (ancCache ??= ancestorsInfo());
    const seen = new Set<Rule>();
    // The clock is a last resort beside the step bound; it is read every 256 elements.
    if (cascadeCut === null && (++elements & 255) === 0 && limits.expired()) cascadeCut = "time";
    const consider = (rules: Rule[] | undefined) => {
      if (rules === undefined || cascadeCut !== null) return;
      for (const r of rules) {
        if (seen.has(r)) continue;
        seen.add(r);
        const hit = selectorMatches(r.selector, info, r.selector.compounds.length > 1 ? anc() : [], work);
        if (work.n < 0) {
          // Out of steps: the rest of the document is read with inline styles only, and the result says so.
          cascadeCut = "css_work";
          return;
        }
        if (!hit) continue;
        for (const d of r.decls) candidates.push({ d, w: [d.important ? 1 : 0, 0, r.selector.specificity, r.order] });
      }
    };
    if (info.id !== null) consider(sheet.byId.get(info.id));
    if (sheet.byClass.size > 0 && cascadeCut === null) {
      // Each class looked up is a step: an element can carry hundreds of thousands of them.
      work.n -= info.classes.size;
      if (work.n < 0) cascadeCut = "css_work";
      for (const c of info.classes) consider(sheet.byClass.get(c));
    }
    consider(sheet.byTag.get(info.tag));
    consider(sheet.universal);
    const inline = attrs.get("style");
    if (inline !== undefined) parseDeclarations(inline).forEach((d, k) => candidates.push({ d, w: [d.important ? 1 : 0, 1, 0, k] }));
    const out = new Map<string, Decl>();
    const weights = new Map<string, number[]>();
    for (const { d, w } of candidates) {
      const prev = weights.get(d.prop);
      if (prev === undefined || compareWeights(w, prev) >= 0) {
        out.set(d.prop, d);
        weights.set(d.prop, w);
      }
    }
    return out;
  };

  const derive = (parent: Ctx, tag: string, attrs: Map<string, string>, info: ElementInfo, id: number): Ctx => {
    const d = declared(info, attrs);
    const v = (p: string) => d.get(p)?.value;
    const fixed: HiddenHow[] = [...parent.fixed];
    const addFixed = (h: HiddenHow) => {
      if (!fixed.includes(h)) fixed.push(h);
    };
    const display = v("display");
    if (display === "none") addFixed("display_none");
    else if (attrs.has("hidden") && display === undefined) addFixed("hidden_attribute");
    if (tag === "template") addFixed("template");
    if (v("mso-hide") === "all") addFixed("mso_hide");
    const overflowHidden = ["overflow", "overflow-x", "overflow-y"].some((p) => /\b(?:hidden|clip)\b/.test(v(p) ?? ""));
    const fontPx = (() => {
      const fs = v("font-size");
      if (fs !== undefined) return fontSizeFrom(fs, parent.fontPx);
      const f = v("font");
      if (f !== undefined) return fontShorthandSize(f, parent.fontPx);
      if (tag === "font" && attrs.has("size")) {
        const n = parseInt(attrs.get("size") ?? "", 10);
        if (Number.isFinite(n)) return FONT_TAG_SIZES[Math.max(1, Math.min(7, n))] ?? null;
      }
      return null;
    })();
    // A box of 1px or less that clips its overflow shows nothing readable (a 1px-high line is a hairline).
    if (overflowHidden && ["max-height", "height", "width", "max-width"].some((p) => {
      const n = lengthPx(v(p), parent.fontPx);
      return n !== null && n <= 1;
    })) addFixed("zero_size");
    // Scaled so small that a glyph is under a pixel on its smallest axis (scale(0), scaleY(0), scale: 0.01).
    const t = v("transform");
    const sc = v("scale");
    if ((t !== undefined || sc !== undefined) && scaleFactor(t, sc) * (fontPx ?? parent.fontPx) < 1) addFixed("zero_size");
    if (translatedAway(t, v("translate"), fontPx ?? parent.fontPx)) addFixed("offscreen");
    const clip = v("clip");
    const clipPath = v("clip-path");
    if ((clip !== undefined && clipIsZero(clip)) || (clipPath !== undefined && clipPathIsZero(clipPath))) addFixed("clip");
    const pos = v("position");
    const far = (p: string) => {
      const n = lengthPx(v(p), parent.fontPx);
      return n !== null && n <= -1000;
    };
    if ((pos === "absolute" || pos === "fixed") && ["left", "top", "right", "bottom"].some(far)) addFixed("offscreen");
    if (far("margin-left") || far("margin-top")) addFixed("offscreen");
    if (far("text-indent")) addFixed("text_indent");
    const ctx: Ctx = { ...parent, fixed };
    if (fixed.length > 0 && parent.fixed.length === 0) ctx.fixedKey = id;
    const vis = v("visibility");
    if (vis === "hidden" || vis === "collapse") {
      ctx.visHidden = true;
      ctx.visKey = id;
    } else if (vis === "visible") ctx.visHidden = false;
    if (fontPx !== null) {
      ctx.fontPx = fontPx;
      ctx.fontKey = id;
    }
    const fontShort = v("font");
    // The `font` shorthand resets line-height to normal unless it gives one ("1px/0 a").
    const lh = v("line-height") ?? (fontShort !== undefined ? (fontShorthandLineHeight(fontShort) ?? "normal") : undefined);
    if (lh !== undefined) {
      ctx.lineZero = isZeroLength(lh);
      ctx.lineKey = id;
    }
    const op = v("opacity");
    if (op !== undefined) {
      const n = op.endsWith("%") ? Number(op.slice(0, -1)) / 100 : Number(op);
      if (Number.isFinite(n)) {
        ctx.opacity = parent.opacity * Math.max(0, Math.min(1, n));
        ctx.opKey = id;
      }
    }
    const colourRaw = v("color") ?? (tag === "font" ? attrs.get("color") : undefined);
    if (colourRaw !== undefined) {
      const c = parseColour(colourRaw);
      if (c !== null) {
        ctx.color = c;
        ctx.colorKey = id;
      }
    }
    // Background: an image behind the text makes contrast unknowable, so the colour rule stops there.
    const bgImage = v("background-image");
    const bgShort = v("background");
    const hasImage = (bgImage !== undefined && /url\(/.test(bgImage)) || (bgShort !== undefined && /url\(/.test(bgShort)) || attrs.has("background");
    if (hasImage) {
      ctx.bg = null;
      ctx.bgKey = id;
    } else {
      const bgRaw = v("background-color") ?? (bgShort !== undefined ? bgShort.split(/\s+(?![^(]*\))/).find((t) => parseColour(t) !== null) : undefined) ?? attrs.get("bgcolor");
      if (bgRaw !== undefined) {
        const c = parseColour(bgRaw);
        if (c !== null && c[3] >= 0.5) {
          ctx.bg = [c[0], c[1], c[2], 1];
          ctx.bgKey = id;
        }
      }
    }
    if (tag === "head") ctx.inHead = true;
    if (tag === "body") ctx.inHead = false;
    return ctx;
  };

  const append = (text: string, range: [number, number] | null, ctx: Ctx) => {
    const hidden = hiddenOf(ctx);
    if (hidden === null) {
      if (visibleLastBreak !== breaks) {
        visibleParts.push("\n");
        visibleLastBreak = breaks;
      }
      visibleParts.push(text);
      if (range !== null) visibleNodes.push({ text, range });
      if (/[\p{L}\p{N}]/u.test(text)) visibleSeen = true;
      return;
    }
    if (text.trim() === "") return;
    const s = spanFor(hidden.key, hidden.how);
    if (s.lastBreak !== breaks && s.text !== "") s.text += "\n";
    s.lastBreak = breaks;
    s.text += text;
    if (range !== null) s.ranges.push(range);
  };

  const closeTo = (index: number) => {
    while (stack.length > index) {
      const f = stack.pop() as Frame;
      if (BLOCK.has(f.name)) breaks++;
    }
  };
  /** Implied end tags: a new paragraph, list item, row or cell closes the open one. */
  const autoClose = (name: string) => {
    const closes: Record<string, readonly string[]> = {
      p: ["p"], div: ["p"], table: ["p"], ul: ["p"], ol: ["p"], h1: ["p"], h2: ["p"], h3: ["p"], h4: ["p"], h5: ["p"], h6: ["p"], li: ["li", "p"],
      td: ["td", "th", "p"], th: ["td", "th", "p"], tr: ["tr", "td", "th", "p"], option: ["option"], dt: ["dt", "dd"], dd: ["dt", "dd"],
    };
    const which = own(closes, name);
    if (which === undefined) return;
    const boundary = name === "li" ? ["ul", "ol"] : name === "td" || name === "th" ? ["tr", "table"] : name === "tr" ? ["table", "tbody", "thead", "tfoot"] : ["table", "td", "th", "li", "div"];
    for (let k = stack.length - 1; k > 0; k--) {
      const f = stack[k] as Frame;
      if (f.pseudo) return;
      if (which.includes(f.name)) {
        closeTo(k);
        return;
      }
      if (boundary.includes(f.name)) return;
    }
  };

  for (const tok of tz.tokens) {
    switch (tok.t) {
      case "cond_start":
        stack.push({ name: "#cond", info: null, ctx: { ...top().ctx, fixed: top().ctx.fixed.includes("mso_conditional") ? top().ctx.fixed : [...top().ctx.fixed, "mso_conditional"], fixedKey: top().ctx.fixed.length > 0 ? top().ctx.fixedKey : nextId++ }, pseudo: true });
        break;
      case "cond_end": {
        let k = stack.length - 1;
        while (k > 0 && (stack[k] as Frame).name !== "#cond") k--;
        if (k > 0) closeTo(k);
        break;
      }
      case "comment":
        comments.push({ text: tok.text, range: [tok.start, tok.end] });
        break;
      case "text":
        if (!top().ctx.inHead) append(tok.text, [tok.start, tok.end], top().ctx);
        break;
      case "end": {
        if (tok.name === "br" || tok.name === "p") breaks++;
        for (let k = stack.length - 1; k > 0; k--) {
          const f = stack[k] as Frame;
          if (f.pseudo) break;
          if (f.name === tok.name) {
            closeTo(k);
            break;
          }
        }
        break;
      }
      case "start": {
        const { name, attrs } = tok;
        autoClose(name);
        if (BLOCK.has(name)) breaks++;
        const info = elementInfo(name, attrs);
        const id = nextId++;
        const ctx = derive(top().ctx, name, attrs, info, id);
        const hidden = hiddenOf(ctx) !== null;
        const url = name === "img" ? attrs.get("src") : name === "a" ? attrs.get("href") : undefined;
        if (url !== undefined && url.trim() !== "" && !ctx.inHead) {
          const w = lengthPx(attrs.get("width") ?? "", 16) ?? Number(attrs.get("width"));
          const h = lengthPx(attrs.get("height") ?? "", 16) ?? Number(attrs.get("height"));
          const styleW = /(?:^|;)\s*width\s*:\s*([\d.]+)px/i.exec(attrs.get("style") ?? "")?.[1];
          const styleH = /(?:^|;)\s*height\s*:\s*([\d.]+)px/i.exec(attrs.get("style") ?? "")?.[1];
          const pw = Number.isFinite(w) ? w : styleW !== undefined ? Number(styleW) : NaN;
          const ph = Number.isFinite(h) ? h : styleH !== undefined ? Number(styleH) : NaN;
          links.push({ url: url.trim(), kind: name === "img" ? "image" : "link", hidden, pixel: name === "img" && pw <= 1 && ph <= 1, range: [tok.start, tok.end] });
        }
        const bgAttr = attrs.get("background");
        const bgStyle = /url\(\s*['"]?([^'")]+)['"]?\s*\)/i.exec(attrs.get("style") ?? "")?.[1];
        for (const u of [bgAttr, bgStyle]) if (u !== undefined && u.trim() !== "" && !ctx.inHead) links.push({ url: u.trim(), kind: "image", hidden, pixel: false, range: [tok.start, tok.end] });
        for (const a of ["alt", "title"]) {
          const t = attrs.get(a);
          if (t === undefined || t.trim() === "" || ctx.inHead) continue;
          if (!hidden) attrParts.push(t);
          else {
            const hd = hiddenOf(ctx);
            if (hd !== null) {
              const s = spanFor(hd.key, hd.how);
              s.text += (s.text === "" ? "" : "\n") + t;
              if (VOID.has(name)) s.ranges.push([tok.start, tok.end]);
            }
          }
        }
        if (name === "br") {
          if (!ctx.inHead && hiddenOf(ctx) === null) visibleParts.push("\n");
          break;
        }
        if (VOID.has(name) || tok.selfClosing || RAW.has(name)) {
          // Raw-text elements were consumed by the tokenizer (their end tag is the next token, ignored).
          break;
        }
        stack.push({ name, info, ctx, pseudo: false });
        break;
      }
    }
  }

  return {
    visible: visibleParts.join(""),
    attributeText: attrParts.join("\n"),
    visibleNodes,
    spans: [...spans.values()].map(({ text, how, ranges, atStart }) => ({ text, how, ranges, atStart })),
    links,
    comments,
    titles: tz.titles,
    incomplete: cascadeCut === null || incomplete.includes(cascadeCut) ? incomplete : [...incomplete, cascadeCut],
    work: { matchSteps: Math.min(maxSteps, maxSteps - work.n), searchedChars: tz.searched },
  };
}

function compareWeights(a: number[], b: number[]): number {
  for (let i = 0; i < a.length; i++) {
    const d = (a[i] as number) - (b[i] as number);
    if (d !== 0) return d;
  }
  return 0;
}
