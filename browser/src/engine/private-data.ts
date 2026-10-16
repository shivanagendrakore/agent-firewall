/**
 * Seen-elsewhere fingerprints (design 6.1, item 3).
 *
 * While a tab is private, sensitive-looking strings it renders are
 * fingerprinted and kept for the agent session. A fingerprint typed or pasted
 * on a different registrable domain is a leak candidate: the Brave Comet case
 * (an OTP shown on the mail site, typed into the attacker's form).
 *
 * Long strings (12+ characters: email addresses, secrets, cards, reset links,
 * account numbers) use the firewall's rolling fingerprint, which also finds
 * them inside a longer value and in decoded variants (base64, hex, URL
 * encoding). Short one-time codes use an exact-match hash table: a 6-digit
 * code is too short for the rolling fingerprint, and matching it anywhere
 * would fire on every number.
 *
 * Only one-way hashes are stored; the strings themselves never leave the
 * function that found them.
 */
import { base64Decode, hexToLatin1, sha256Hex } from "../vendor/firewall/engine/bytes.js";
import { findPersonalData } from "../vendor/firewall/engine/pii.js";
import { containsFingerprint, decodedVariants, findSecrets, fingerprint, MIN_FINGERPRINT_LENGTH } from "../vendor/firewall/engine/secrets.js";
import { registrableDomain } from "./domain.js";

export interface PrivatePrint {
  /** A rolling fingerprint ("long") or an exact-match hash ("short"). */
  fp: string;
  kind: "long" | "short";
  /** The registrable domain the string was shown on. */
  domain: string;
}

/**
 * Words that make a nearby short number a one-time code. Bare "code", "pin" or "confirm" are not enough on their
 * own (FP-5: "source code ... in 2019"); they count only bound to the number ("code: 4821", "your PIN is 4821").
 */
const OTP_CONTEXT = /\b(?:verification|verify|otp|one[- ]time|passcode|security code|2fa|two[- ]factor|multi[- ]factor|mfa|sign[- ]?in code|log[- ]?in code|access code|auth(?:entication|orization)? code|confirmation code|your (?!source )(?:\w+ )?(?:code|pin)|(?:code|pin) (?:is|was))\b/i;
/** "code", "PIN" or "passcode" right before the number, with at most "is", a colon or a dash between them. */
const OTP_BOUND = /\b(?:code|pin|passcode|otp)\s*(?:is|was|=|:|-)?\s*(?:G-)?$/i;
/** For a year-shaped number the label needs "is", "was", "=" or a colon: "Summer of Code 2026" is a name and a year. */
const OTP_BOUND_STRICT = /\b(?:code|pin|passcode|otp)\s*(?:is|was|=|:)\s*$/i;
const OTP_WINDOW = 60;

/** A plausible year (1900 to 2099): prose is full of them, so a code that looks like one counts only after "code is" or "code:". */
const YEAR = /^(?:19|20)\d\d$/;

const EMAIL = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g;
/**
 * Bounded on both sides of the keyword (page text is page-controlled): unbounded, a long run of URL characters
 * after many "http://" starts made each start scan to the end of the run (quadratic). A link is at most
 * RESET_LINK_MAX characters before the keyword and after it.
 */
export const RESET_LINK_MAX = 2000;
const RESET_LINK = new RegExp(`\\bhttps?:\\/\\/[^\\s"'<>]{8,${RESET_LINK_MAX}}?(?:reset|recover|verify|confirm|magic|token|signin|login|activate)[^\\s"'<>]{0,${RESET_LINK_MAX}}`, "gi");
const ACCOUNT_NUMBER = /\b(?:account|acct|routing|iban|member|policy|customer)\b[^0-9\n]{0,24}([0-9][0-9 -]{10,30}[0-9])/gi;

/** One-time codes: 4 to 8 digits (optionally "G-" prefixed or split by a space or dash) within reach of an OTP word. */
function otpCodesIn(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(/(?<![\w-])(?:G-)?(\d{3}[ -]?\d{3}|\d{4,8})(?![\w-])/g)) {
    const at = m.index ?? 0;
    const end = at + m[0].length;
    // Part of a larger number: a date (2019/10, 10.11.2019), a decimal, money, a percentage, a thousands group.
    if (/[$€£¥#]\s?$|\d[.,/:]$/.test(text.slice(Math.max(0, at - 2), at))) continue;
    if (/^(?:[.,/:]\d|\s?%)/.test(text.slice(end, end + 2))) continue;
    const bound = OTP_BOUND.test(text.slice(Math.max(0, at - 16), at));
    const digits = (m[1] as string).replace(/[ -]/g, "");
    if (YEAR.test(digits) && !OTP_BOUND_STRICT.test(text.slice(Math.max(0, at - 16), at))) continue;
    const around = text.slice(Math.max(0, at - OTP_WINDOW), end + OTP_WINDOW);
    if (!bound && !OTP_CONTEXT.test(around)) continue;
    if (digits.length >= 4 && digits.length <= 8) out.add(digits);
  }
  return [...out];
}

/**
 * A short code's fingerprint, salted with the agent session's random salt: a
 * 6-digit code has only a million values, so an unsalted hash read out of the
 * profile could be guessed back. The salt lives only in session memory with the
 * prints it protects, and a new session draws a new one.
 */
function shortHash(code: string, salt: string): string {
  return `otp:${sha256Hex(`launchsafe-otp:${salt.length}:${salt}:${code}`).slice(0, 32)}`;
}

/** A fresh per-session salt: 128 random bits as hex. */
export function newPrintSalt(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/**
 * The form a private string is matched in, whichever way it is written (I5): compatibility forms folded (NFKC:
 * fullwidth digits and letters), case folded, "[at]", "(at)", "{at}" and " at " read as "@" and "[dot]",
 * "(dot)", " dot " as ".", then every format character (zero-width, bidi, soft hyphen), space, and separator
 * (. - _ · • , ; : | / \ and the like) dropped. Both sides use it: the page's strings get a print of this form as
 * well as of the string itself, and a typed value is checked in this form too. What it does not undo: a string
 * split across several fields or messages, reordered, paraphrased or spelled out ("four eight two"); those are
 * residuals (threat model 4, row 6).
 */
export function canonicalText(s: string): string {
  return s
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[[({<]\s*at\s*[\])}>]|\s+at\s+/g, "@")
    .replace(/[[({<]\s*dot\s*[\])}>]|\s+dot\s+/g, ".")
    .replace(/[\p{Cf}\p{Z}\s\p{Pd}._·•‧∙,;:|/\\'"`~*+^=()[\]{}<>]+/gu, "");
}

/** The sensitive strings in a page's text, split by how they are fingerprinted. Never stored. */
export function privateStringsIn(text: string): { long: string[]; short: string[] } {
  const long = new Set<string>();
  for (const m of text.matchAll(EMAIL)) long.add(m[0]);
  for (const m of text.matchAll(RESET_LINK)) long.add(m[0]);
  for (const m of text.matchAll(ACCOUNT_NUMBER)) long.add((m[1] as string).replace(/[ -]/g, ""));
  for (const h of findSecrets(text)) long.add(h.value);
  for (const h of findPersonalData(text)) long.add(h.value.replace(/[ -]/g, ""));
  return { long: [...long].filter((s) => s.length >= MIN_FINGERPRINT_LENGTH), short: otpCodesIn(text) };
}

/**
 * Fingerprints of the private strings in a page shown on `host`. Short codes
 * need the session's `salt`; with none (no agent session yet) they are skipped,
 * since the worker keeps no prints outside a session anyway.
 */
export function printsFor(text: string, host: string, salt: string): PrivatePrint[] {
  const domain = registrableDomain(host);
  const { long, short } = privateStringsIn(text);
  const out: PrivatePrint[] = [];
  const seen = new Set<string>();
  for (const s of long) {
    // The string as shown, and its canonical form (so "Alice.Smith [at] example (dot) com" typed elsewhere matches).
    for (const v of [s, canonicalText(s)]) {
      const fp = fingerprint(v);
      if (fp === null || seen.has(fp)) continue;
      seen.add(fp);
      out.push({ fp, kind: "long", domain });
    }
  }
  if (salt !== "") for (const c of short) out.push({ fp: shortHash(c, salt), kind: "short", domain });
  return out;
}

const SHORT_SAMPLE = 4096;

/** Base32 (RFC 4648) to bytes, leniently: characters outside the alphabet end the run. */
function base32Bytes(s: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const out: number[] = [];
  let value = 0;
  let bits = 0;
  for (const ch of s.toUpperCase()) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) break;
    value = ((value << 5) | idx) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

function latin1(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return s;
}

/**
 * Decodings of short values. The vendored `decodedVariants` keeps only
 * decodings of 12 characters or more (it serves the long fingerprints), so a
 * 6-digit code sent as base64 ("NDgyOTE1"), hex ("343832393135"), base32 or
 * percent-encoding slipped through. Every alignment of each run is tried; the
 * caller takes only exact digit runs out of the result, and a run must hash to
 * a code the session saw, so garbage from decoding ordinary words cannot match.
 */
export function shortDecodings(value: string): string[] {
  const out = new Set<string>();
  const sample = value.length > SHORT_SAMPLE ? value.slice(0, SHORT_SAMPLE) : value;
  const tryUrl = (s: string): string | null => {
    try {
      return decodeURIComponent(s.replace(/\+/g, " "));
    } catch {
      return null;
    }
  };
  const once = tryUrl(sample);
  if (once !== null) {
    out.add(once);
    const twice = tryUrl(once);
    if (twice !== null) out.add(twice);
  }
  for (const m of sample.matchAll(/[A-Za-z0-9+/_-]{4,}={0,2}/g)) {
    const run = m[0].replace(/=+$/, "");
    for (let k = 0; k < 4 && run.length - k >= 4; k++) out.add(latin1(base64Decode(run.slice(k))));
  }
  for (const m of sample.matchAll(/[0-9a-fA-F]{8,}/g)) {
    for (let k = 0; k < 2; k++) out.add(hexToLatin1(m[0].slice(k)));
  }
  for (const m of sample.matchAll(/[A-Za-z2-7]{7,}={0,6}/g)) {
    const run = m[0].replace(/=+$/, "");
    for (let k = 0; k < 8 && run.length - k >= 7; k++) out.add(latin1(base32Bytes(run.slice(k))));
  }
  return [...out];
}

/** Digit runs a person or agent could have typed a code as, in the value and its decoded variants. */
function shortCandidates(value: string): Set<string> {
  const out = new Set<string>();
  for (const v of new Set([value, canonicalText(value), ...decodedVariants(value), ...shortDecodings(value)])) {
    // Exact runs only: a code inside a longer run of digits is a different number.
    for (const m of v.matchAll(/(?<!\d)\d(?:[ -]?\d){3,7}(?!\d)/g)) out.add(m[0].replace(/[ -]/g, ""));
  }
  // A short value whose digits, taken together, are a code ("4.8.2.9.1.5", "4 8 2 - 9 1 5").
  if (value.length <= 32) {
    const digits = value.replace(/\D/g, "");
    if (digits.length >= 4 && digits.length <= 8) out.add(digits);
  }
  return out;
}

/**
 * The first private print, shown on a registrable domain other than the
 * destination's, that the value carries (in the clear or encoded); null if none.
 */
export function seenElsewhere(value: string, destinationHost: string, prints: readonly PrivatePrint[], salt: string): PrivatePrint | null {
  const dest = registrableDomain(destinationHost);
  const foreign = prints.filter((p) => p.domain !== dest);
  if (foreign.length === 0 || value.length === 0) return null;
  const shorts = foreign.filter((p) => p.kind === "short");
  if (shorts.length > 0 && salt !== "") {
    const hashes = new Set([...shortCandidates(value)].map((c) => shortHash(c, salt)));
    const hit = shorts.find((p) => hashes.has(p.fp));
    if (hit !== undefined) return hit;
  }
  const longs = foreign.filter((p) => p.kind === "long");
  // Encodings only lengthen a string, so a value shorter than the minimum cannot carry one.
  if (longs.length === 0 || value.length < MIN_FINGERPRINT_LENGTH) return null;
  const fps = longs.map((p) => p.fp);
  // The value as typed, then in canonical form (case, zero-width characters, separators, "[at]" and "(dot)").
  const canon = canonicalText(value);
  const forms = canon !== value && canon.length >= MIN_FINGERPRINT_LENGTH ? [value, canon] : [value];
  const hitForm = forms.find((v) => containsFingerprint(v, fps));
  if (hitForm === undefined) return null;
  return longs.find((p) => containsFingerprint(hitForm, [p.fp])) ?? null;
}
