/**
 * Characters that have no business in a shell command, a path or a URL:
 * they hide text from the person reading it (zero-width, tag characters used
 * for "ASCII smuggling") or reorder what they see (bidirectional controls).
 */

const NAMES: Record<number, string> = {
  0x00ad: "soft hyphen",
  0x061c: "Arabic letter mark",
  0x180e: "Mongolian vowel separator",
  0x200b: "zero-width space",
  0x200c: "zero-width non-joiner",
  0x200d: "zero-width joiner",
  0x200e: "left-to-right mark",
  0x200f: "right-to-left mark",
  0x2060: "word joiner",
  0x2061: "invisible function application",
  0x2062: "invisible times",
  0x2063: "invisible separator",
  0x2064: "invisible plus",
  0x034f: "combining grapheme joiner",
  0x115f: "Hangul filler",
  0x1160: "Hangul filler",
  0x3164: "Hangul filler",
  0xffa0: "Hangul filler",
  0x2800: "braille blank",
  0xfeff: "zero-width no-break space",
};

function isBidi(cp: number): boolean {
  return (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
}

function isTag(cp: number): boolean {
  return cp >= 0xe0000 && cp <= 0xe007f;
}

/** Variation selectors: U+FE00-FE0F and the supplement U+E0100-E01EF. */
function isVariation(cp: number): boolean {
  return (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
}

const PICTOGRAPHIC = /\p{Extended_Pictographic}|\p{Emoji_Modifier}|\p{Regional_Indicator}/u;
const EMOJI = /\p{Emoji}/u;
const HAN = /\p{Script_Extensions=Han}/u;
/** Default-ignorable code points (and the braille blank, which draws nothing): hidden whatever their name. */
const IGNORABLE = /[\p{Default_Ignorable_Code_Point}\u2800]/u;
/** The RGI subdivision flags (England, Scotland, Wales): the only tag sequences that are emoji. */
const RGI_SUBDIVISIONS = new Set(["gbeng", "gbsct", "gbwls"]);

const test = (re: RegExp, cp: number | undefined): boolean => cp !== undefined && re.test(String.fromCodePoint(cp));
const isPictographic = (cp: number | undefined): boolean => test(PICTOGRAPHIC, cp);

/** Names of the hidden characters in a text (deduplicated). Emoji joiners, emoji variation selectors and RGI flag tags are allowed. */
export function invisibleCharacters(text: string): string[] {
  const found = new Set<string>();
  const cps = Array.from(text, (ch) => ch.codePointAt(0) as number);
  for (let i = 0; i < cps.length; i++) {
    const cp = cps[i] as number;
    if (cp < 0x80) continue;
    if (cp === 0x200d) {
      const p = cps[i - 1] === 0xfe0f ? cps[i - 2] : cps[i - 1];
      if (isPictographic(p) && isPictographic(cps[i + 1])) continue;
    }
    if (isTag(cp)) {
      // A subdivision flag: black flag, tag letters naming one of the three RGI subdivisions, CANCEL TAG.
      let a = i;
      while (a > 0 && isTag(cps[a - 1] as number)) a--;
      let b = i;
      while (b + 1 < cps.length && isTag(cps[b + 1] as number)) b++;
      let letters = "";
      for (let k = a; k <= b; k++) {
        const c = cps[k] as number;
        if (c >= 0xe0020 && c <= 0xe007e) letters += String.fromCharCode(c - 0xe0000);
      }
      if (cps[a - 1] === 0x1f3f4 && cps[b] === 0xe007f && RGI_SUBDIVISIONS.has(letters)) continue;
      found.add("Unicode tag characters");
      continue;
    }
    if (isVariation(cp)) {
      // One selector on its base is ordinary: an emoji's presentation, a keycap, an ideograph's variant.
      const prev = cps[i - 1];
      const run = isVariation(prev ?? 0) || isVariation(cps[i + 1] ?? 0);
      const ordinary =
        !run &&
        prev !== undefined &&
        ((cp >= 0xfe0e && cp <= 0xfe0f && (test(EMOJI, prev) || isPictographic(prev))) || (test(HAN, prev) && (cp >= 0xe0100 || cp <= 0xfe02)));
      if (!ordinary) found.add(cp >= 0xe0100 ? "variation selector supplement" : "variation selector");
      continue;
    }
    if (isBidi(cp)) found.add("bidirectional control");
    else if (NAMES[cp] !== undefined) {
      if (!(cp === 0xfeff && i === 0)) found.add(NAMES[cp] as string);
    } else if (IGNORABLE.test(String.fromCodePoint(cp))) found.add("invisible character");
  }
  return [...found];
}

/** Removes hidden characters, for display and for comparing text: every default-ignorable code point and the braille blank. */
export function stripInvisible(text: string): string {
  return text.replace(/[\p{Default_Ignorable_Code_Point}\u2800]/gu, "");
}
