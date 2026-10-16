/**
 * Host names as the approval surfaces show them (m12). Browsers give us hosts
 * in their ASCII form, where a look-alike internationalised name is an
 * unreadable "xn--" label; a person would not see that "xn--pple-43d.com"
 * is not apple.com, and the Unicode form alone ("аpple.com" with a Cyrillic а)
 * would look exactly like the real one. So a host with any "xn--" label is
 * shown both ways: the Unicode form, then the ASCII form in brackets, and a
 * warning when its letters mix scripts.
 */

const BASE = 36;
const T_MIN = 1;
const T_MAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;

function adapt(delta: number, numPoints: number, first: boolean): number {
  let d = first ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - T_MIN) * T_MAX) >> 1) {
    d = Math.floor(d / (BASE - T_MIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - T_MIN + 1) * d) / (d + SKEW));
}

function digitOf(cp: number): number {
  if (cp >= 0x30 && cp <= 0x39) return cp - 22; // 0-9 -> 26-35
  if (cp >= 0x41 && cp <= 0x5a) return cp - 0x41;
  if (cp >= 0x61 && cp <= 0x7a) return cp - 0x61;
  return BASE;
}

/** RFC 3492 decoding of one label's part after "xn--"; null when it is not valid Punycode. */
export function punycodeDecode(input: string): string | null {
  if (input.length > 63) return null;
  const out: number[] = [];
  const basic = input.lastIndexOf("-");
  for (let j = 0; j < Math.max(0, basic); j++) {
    const c = input.charCodeAt(j);
    if (c >= 0x80) return null;
    out.push(c);
  }
  let n = INITIAL_N;
  let bias = INITIAL_BIAS;
  let i = 0;
  for (let idx = basic >= 0 ? basic + 1 : 0; idx < input.length; ) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (idx >= input.length) return null;
      const digit = digitOf(input.charCodeAt(idx++));
      if (digit >= BASE) return null;
      i += digit * w;
      if (i > 0x10ffff * 64) return null;
      const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    if (n > 0x10ffff) return null;
    out.splice(i, 0, n);
    i++;
  }
  try {
    return String.fromCodePoint(...out);
  } catch {
    return null;
  }
}

/** The Unicode form of a host ("xn--" labels decoded); the input when a label does not decode. */
export function hostToUnicode(host: string): string {
  const labels = host.split(".");
  const out: string[] = [];
  for (const l of labels) {
    if (/^xn--/i.test(l)) {
      const d = punycodeDecode(l.slice(4).toLowerCase());
      if (d === null) return host;
      out.push(d);
    } else out.push(l);
  }
  return out.join(".");
}

const SCRIPTS: readonly [string, RegExp][] = [
  ["Latin", /\p{Script=Latin}/u],
  ["Cyrillic", /\p{Script=Cyrillic}/u],
  ["Greek", /\p{Script=Greek}/u],
  ["Armenian", /\p{Script=Armenian}/u],
  ["Hebrew", /\p{Script=Hebrew}/u],
  ["Arabic", /\p{Script=Arabic}/u],
  ["Cherokee", /\p{Script=Cherokee}/u],
];

/** Whether one label of the host mixes letters of different scripts (the usual look-alike trick). */
export function mixesScripts(unicodeHost: string): boolean {
  return unicodeHost.split(".").some((label) => SCRIPTS.filter(([, re]) => re.test(label)).length > 1);
}

/** A host for display: unchanged when plain ASCII; "Unicode (ascii)" plus a warning for an internationalised one. */
export function displayHost(host: string): string {
  if (!/(^|\.)xn--/i.test(host)) return host;
  const uni = hostToUnicode(host);
  if (uni === host) return host;
  return `${uni} (${host})${mixesScripts(uni) ? " - mixes alphabets, may imitate another site" : ""}`;
}

/** An origin or URL for display, its host shown with displayHost; anything unparsable unchanged. */
export function displayUrlHost(urlOrOrigin: string): string {
  try {
    const u = new URL(urlOrOrigin);
    if (!/(^|\.)xn--/i.test(u.hostname)) return urlOrOrigin;
    const i = urlOrOrigin.toLowerCase().indexOf(u.hostname);
    if (i < 0) return urlOrOrigin;
    return `${urlOrOrigin.slice(0, i)}${displayHost(u.hostname)}${urlOrOrigin.slice(i + u.hostname.length)}`;
  } catch {
    return urlOrOrigin;
  }
}
