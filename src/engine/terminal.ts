/**
 * R6: text an agent or a repository controls (proposal content, reasons, summaries, MCP launch lines,
 * prompts) printed to the person's terminal. C0 and C1 control characters (ESC, CSI, OSC, BEL,
 * backspace, carriage return, DEL) can move the cursor, erase or rewrite lines, set the window title or
 * hide text: on the approval and passphrase screens that would let the agent decide what the person
 * sees. They are shown as visible escapes (`\u001b`, `\u009b`) instead. That form is also a valid JSON
 * string escape for the same character, so JSON output passed through here parses to the same value.
 * Newlines are kept (and, with `keepTabs`, tabs); everything else printable is unchanged. Direction-changing and zero-width
 * characters are shown escaped too, so a line cannot be made to read differently from what it holds.
 */

// eslint-disable-next-line no-control-regex -- matching control characters is the point
const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]|\t/g;

function escapeChar(ch: string): string {
  return `\\u${(ch.codePointAt(0) ?? 0).toString(16).padStart(4, "0")}`;
}

/** Other invisible characters a line must not hide behind: soft hyphen, grapheme joiner, Arabic letter mark, Hangul fillers, Khmer inherent vowels, Mongolian selectors, line and paragraph separators, invisible operators, deprecated format controls, braille blank, interlinear annotation. */
// eslint-disable-next-line no-misleading-character-class -- each listed code point is matched on its own; combining is what this escapes
const INVISIBLE_BMP = /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u2028\u2029\u2060-\u2065\u206a-\u206f\u2800\u3164\uffa0\ufff0-\ufffb]/g;

/** A character as JSON-compatible \u escapes (two for an astral character: its surrogate pair). */
function escapeUnits(ch: string): string {
  let out = "";
  for (let i = 0; i < ch.length; i++) out += `\\u${ch.charCodeAt(i).toString(16).padStart(4, "0")}`;
  return out;
}

const isVs = (cp: number): boolean => (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
const RGI_FLAGS = new Set(["gbeng", "gbsct", "gbwls"]);

/**
 * Tag characters (ASCII smuggling) and variation-selector runs (byte smuggling) as escapes. An RGI
 * subdivision flag (England, Scotland, Wales) and a single emoji or ideograph variation selector stay.
 */
function escapeSmuggling(s: string): string {
  if (!/[\ufe00-\ufe0f]|\udb40[\udc00-\udfff]|[\udb41-\udb43][\udc00-\udfff]|\ud834[\udd73-\udd7a]/.test(s)) return s;
  const cps = Array.from(s);
  let out = "";
  for (let i = 0; i < cps.length; i++) {
    const ch = cps[i] as string;
    const cp = ch.codePointAt(0) as number;
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      let j = i;
      let letters = "";
      while (j < cps.length && ((cps[j] as string).codePointAt(0) as number) >= 0xe0000 && ((cps[j] as string).codePointAt(0) as number) <= 0xe007f) {
        const c = (cps[j] as string).codePointAt(0) as number;
        if (c >= 0xe0020 && c <= 0xe007e) letters += String.fromCharCode(c - 0xe0000);
        j++;
      }
      const flag = i > 0 && cps[i - 1] === "\u{1F3F4}" && cps[j - 1] === "\u{E007F}" && RGI_FLAGS.has(letters);
      for (let k = i; k < j; k++) out += flag ? (cps[k] as string) : escapeUnits(cps[k] as string);
      i = j - 1;
      continue;
    }
    if (isVs(cp)) {
      let j = i;
      while (j < cps.length && isVs((cps[j] as string).codePointAt(0) as number)) j++;
      const single = j - i === 1 && cp <= 0xfe0f;
      for (let k = i; k < j; k++) out += single ? (cps[k] as string) : escapeUnits(cps[k] as string);
      i = j - 1;
      continue;
    }
    // Other default-ignorable astral characters: the rest of the tag plane and musical-symbol formatting.
    if ((cp >= 0xe0080 && cp <= 0xe0fff) || (cp >= 0x1d173 && cp <= 0x1d17a)) {
      out += escapeUnits(ch);
      continue;
    }
    out += ch;
  }
  return out;
}

/** The text with every terminal control character, and every invisible character that could hide text, shown as a visible escape. Never throws. */
export function safeText(text: unknown, opts: { keepTabs?: boolean; keepNewlines?: boolean } = {}): string {
  const s = typeof text === "string" ? text : String(text);
  const keepNl = opts.keepNewlines !== false;
  const out = escapeSmuggling(s.replace(UNSAFE, (ch) => (ch === "\t" && opts.keepTabs === true ? ch : escapeChar(ch))).replace(INVISIBLE_BMP, escapeChar));
  return keepNl ? out : out.replace(/\n/g, "\\n");
}

/** One line: newlines escaped too (a summary, a reason, a list cell). */
export function safeLine(text: unknown): string {
  return safeText(text, { keepNewlines: false });
}
