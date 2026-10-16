/**
 * Personal and financial data in outgoing payloads. Every detector checks a
 * checksum or a strict format, so ordinary numbers (timestamps, ids, phone
 * numbers) do not match: card numbers must pass Luhn, have a real issuer
 * prefix and not sit inside a longer hex token, IBANs must
 * pass mod-97, Aadhaar numbers must pass Verhoeff.
 */

import type { DataKind } from "../types.js";
import { own } from "../own.js";

export interface DataHit {
  kind: DataKind;
  name: string;
  value: string;
}

export function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/** Issuer prefixes and lengths of the major card networks. */
function cardNetwork(d: string): string | null {
  const n = d.length;
  const p2 = Number(d.slice(0, 2));
  const p3 = Number(d.slice(0, 3));
  const p4 = Number(d.slice(0, 4));
  const p6 = Number(d.slice(0, 6));
  if (d[0] === "4" && (n === 13 || n === 16 || n === 19)) return "Visa";
  if (((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) && n === 16) return "Mastercard";
  if ((p2 === 34 || p2 === 37) && n === 15) return "American Express";
  if ((p4 === 6011 || p2 === 65 || (p3 >= 644 && p3 <= 649) || (p6 >= 622126 && p6 <= 622925)) && n >= 16 && n <= 19) return "Discover";
  if (p4 >= 3528 && p4 <= 3589 && n >= 16 && n <= 19) return "JCB";
  if ((p2 === 36 || p2 === 38 || (p3 >= 300 && p3 <= 305)) && n >= 14 && n <= 19) return "Diners Club";
  if (p2 === 62 && n >= 16 && n <= 19) return "UnionPay";
  if (p4 >= 2200 && p4 <= 2204 && n >= 16 && n <= 19) return "Mir";
  return null;
}

const isLetter = (c: number): boolean => (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
const isAlnum = (c: number): boolean => (c >= 48 && c <= 57) || isLetter(c);

/** How far on each side of a number to read the letters and digits it is written against. */
const TOKEN_REACH = 64;
/** Other hex digits in a hex-only token (beyond an optional leading 0x), from which it is encoded data (a hash, a hex-encoded value). */
const HEX_AROUND = 8;
const HEX_ONLY = /^[0-9A-Fa-f]*$/;

/**
 * Whether the digits at [start, end) are part of a longer hex token and not a number somebody wrote out.
 * The token is the ASCII letters and digits in one piece around the digits (any character that is not an ASCII
 * letter or digit ends the piece). After an optional leading `0x` or `0X`, it is hex data when the characters around
 * the digits are hex digits only and at least HEX_AROUND of them. Hex-encoding a credential is the case that
 * matters: every digit, and every letter from a to i and p to y, becomes a pair of digits, so the encoding is full of
 * long digit runs, and about one in ten of them passes the check digit by chance. Words, field names or a single
 * letter against a card number (`ref`, the `B` of magnetic-stripe data, text with its tags and spacing stripped)
 * are not hex data, and neither is base64: letting any long mixed token hide a number let a card through when
 * stripped labels with digits touched it.
 */
function insideToken(text: string, start: number, end: number): boolean {
  let from = start;
  while (from > 0 && start - from < TOKEN_REACH && isAlnum(text.charCodeAt(from - 1))) from--;
  let to = end;
  while (to < text.length && to - end < TOKEN_REACH && isAlnum(text.charCodeAt(to))) to++;
  const raw = text.slice(from, start);
  const atTokenStart = from === 0 || !isAlnum(text.charCodeAt(from - 1));
  const before = atTokenStart && /^0[xX]/.test(raw) ? raw.slice(2) : raw;
  const after = text.slice(end, to);
  return before.length + after.length >= HEX_AROUND && HEX_ONLY.test(before) && HEX_ONLY.test(after);
}

export interface FindOptions {
  /**
   * Also report a card number inside a longer token of encoded data. For hiding numbers in text a person reads
   * (the phone item, the watch report), where hiding too much is harmless; the decision rules leave it off.
   */
  insideTokens?: boolean;
}

/** The group sizes a card number is written in, besides one unbroken run: 4-4-4-4 (and the shorter and longer forms of it), Amex 4-6-5, Diners 4-6-4. */
function cardGrouping(sizes: readonly number[]): boolean {
  if (sizes.length === 1) return true;
  const last = sizes[sizes.length - 1] as number;
  if (sizes.slice(0, -1).every((n) => n === 4) && last <= 4) return true;
  return sizes.length === 3 && sizes[0] === 4 && sizes[1] === 6 && (last === 5 || last === 4);
}

/** The sub-spans of a run of digit groups that could be a card on their own: whole groups, 13 to 19 digits, written as a card is. */
function cardWindows(raw: string): { start: number; end: number }[] {
  const groups: { start: number; end: number }[] = [];
  for (const g of raw.matchAll(/\d+/g)) groups.push({ start: g.index, end: g.index + g[0].length });
  const out: { start: number; end: number }[] = [];
  for (let a = 0; a < groups.length; a++) {
    let digits = 0;
    for (let b = a; b < groups.length; b++) {
      const g = groups[b] as { start: number; end: number };
      digits += g.end - g.start;
      if (digits > 19) break;
      if (digits < 13 || (a === 0 && b === groups.length - 1)) continue;
      if (cardGrouping(groups.slice(a, b + 1).map((x) => x.end - x.start))) out.push({ start: (groups[a] as { start: number }).start, end: g.end });
    }
  }
  return out;
}

export function findCards(text: string, o: FindOptions = {}): DataHit[] {
  const out: DataHit[] = [];
  const check = (raw: string, at: number): DataHit | null => {
    const digits = raw.replace(/[ -]/g, "");
    // Mixed separators are not how a card is written.
    if (/ /.test(raw) && /-/.test(raw)) return null;
    if (/^(\d)\1+$/.test(digits)) return null;
    const net = cardNetwork(digits);
    if (net === null || !luhnValid(digits)) return null;
    // Last, because it reads the text around the number: only a number that passes the checks is worth that.
    if (o.insideTokens !== true && insideToken(text, at, at + raw.length)) return null;
    return { kind: "card", name: `${net} card number`, value: raw };
  };
  // 13-19 digits, optionally grouped by single spaces or dashes, not part of a longer number or token. A dash
  // after a letter ("id-4242...") is a label's, not part of a longer number; after a digit it is.
  for (const m of text.matchAll(/(?<![\d.])(?<!\d-)(?:\d[ -]?){12,18}\d(?![\d])/g)) {
    const whole = check(m[0], m.index);
    if (whole !== null) {
      out.push(whole);
      continue;
    }
    // The run may start with another number's digits ("qty 12 4242 4242 4242 4242"): try the card-shaped parts of it.
    for (const w of cardWindows(m[0])) {
      const hit = check(m[0].slice(w.start, w.end), m.index + w.start);
      if (hit !== null) {
        out.push(hit);
        break;
      }
    }
  }
  return out;
}

/** IBAN lengths by country (ISO 13616 registry, the common ones). */
const IBAN_LENGTH: Record<string, number> = {
  AD: 24, AE: 23, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29, CH: 21, CR: 22, CY: 28, CZ: 24, DE: 22, DK: 18,
  DO: 28, EE: 20, EG: 29, ES: 24, FI: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18, GR: 27, GT: 28, HR: 21, HU: 28,
  IE: 22, IL: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LI: 21, LT: 20, LU: 20, LV: 21, MC: 27, MD: 24, ME: 22,
  MK: 19, MR: 27, MT: 31, MU: 30, NL: 18, NO: 15, PK: 24, PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24, SE: 24,
  SI: 19, SK: 24, SM: 27, TN: 24, TR: 26, UA: 29, VG: 24, XK: 20,
};

export function ibanValid(iban: string): boolean {
  const s = iban.replace(/ /g, "").toUpperCase();
  const len = own(IBAN_LENGTH, s.slice(0, 2));
  if (len === undefined || s.length !== len || !/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(s)) return false;
  const moved = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of moved) {
    const v = ch >= "A" && ch <= "Z" ? String(ch.charCodeAt(0) - 55) : ch;
    for (const d of v) rem = (rem * 10 + (d.charCodeAt(0) - 48)) % 97;
  }
  return rem === 1;
}

export function findIbans(text: string): DataHit[] {
  const out: DataHit[] = [];
  for (const m of text.matchAll(/\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g)) {
    // The match can run on into the next word ("IBAN: ES91 2100 ... 1332 BIC: ..."): drop trailing groups until it is one.
    const parts = m[0].split(" ");
    for (let n = parts.length; n >= 1; n--) {
      const value = parts.slice(0, n).join(" ");
      if (ibanValid(value)) {
        out.push({ kind: "iban", name: "IBAN", value });
        break;
      }
    }
  }
  return out;
}

// Verhoeff tables, for Aadhaar.
const VD = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1], [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VP = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1], [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

export function verhoeffValid(digits: string): boolean {
  let c = 0;
  const rev = digits.split("").reverse();
  for (let i = 0; i < rev.length; i++) {
    const d = Number(rev[i]);
    c = (VD[c] as number[])[(VP[i % 8] as number[])[d] as number] as number;
  }
  return c === 0;
}

export function findNationalIds(text: string): DataHit[] {
  const out: DataHit[] = [];
  // US Social Security number, written with dashes (bare nine-digit numbers are too common to judge).
  for (const m of text.matchAll(/(?<![\d-])(\d{3})-(\d{2})-(\d{4})(?![\d-])/g)) {
    const [area, group, serial] = [m[1] as string, m[2] as string, m[3] as string];
    if (area === "000" || area === "666" || area[0] === "9" || group === "00" || serial === "0000") continue;
    out.push({ kind: "national_id", name: "US Social Security number", value: m[0] });
  }
  // UK National Insurance number.
  for (const m of text.matchAll(/\b(?!BG|GB|KN|NK|NT|TN|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b/g)) {
    out.push({ kind: "national_id", name: "UK National Insurance number", value: m[0] });
  }
  // India Aadhaar: 12 digits, first 2-9, Verhoeff check digit, grouped 4-4-4 (bare 12-digit numbers,
  // such as AWS account ids, are too common to judge).
  for (const m of text.matchAll(/(?<![\d])[2-9]\d{3}([ -])\d{4}\1\d{4}(?![\d])/g)) {
    const d = m[0].replace(/[ -]/g, "");
    if (verhoeffValid(d)) out.push({ kind: "national_id", name: "Aadhaar number", value: m[0] });
  }
  // India PAN: fourth letter is the holder type.
  for (const m of text.matchAll(/\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b/g)) {
    out.push({ kind: "national_id", name: "PAN", value: m[0] });
  }
  return out;
}

/** All personal and financial data found in a text. */
export function findPersonalData(text: string, o: FindOptions = {}): DataHit[] {
  const sample = text.length > 2_000_000 ? text.slice(0, 2_000_000) : text;
  return [...findCards(sample, o), ...findIbans(sample), ...findNationalIds(sample)];
}

/**
 * Values published as test data by payment processors and standards bodies. Sending them leaks
 * nothing, so with the policy's allowTestValues (default on) they are not treated as personal data.
 * Only exact published values are listed; a real number is never matched by shape.
 */
export const TEST_CARDS: ReadonlySet<string> = new Set([
  // Stripe
  "4242424242424242", "4000056655665556", "5555555555554444", "2223003122003222", "5200828282828210", "5105105105105100",
  "378282246310005", "371449635398431", "6011111111111117", "6011000990139424", "6011981111111113", "3056930009020004",
  "36227206271667", "3566002020360505", "6200000000000005", "4000002500003155", "4000002760003184", "4000000000003220",
  "4000000000009995", "4000000000000002", "4000000000000077", "4000000000000341", "4000000000000127", "4000000000000069",
  "4000000000000119", "4000000000000101", "4000000000000259", "4000000000003055",
  // Braintree / Adyen / Visa / Mastercard documentation numbers
  "4111111111111111", "4012888888881881", "4222222222222", "5431111111111111", "5454545454545454", "4917610000000000",
  "4444333322221111", "2222400070000005", "4005519200000004", "4009348888881881", "4012000033330026", "4012000077777777",
  "5500000000000004", "340000000000009", "30000000000004", "6011000000000004",
]);

/** Example IBANs from the ISO 13616 registry and bank documentation. */
export const TEST_IBANS: ReadonlySet<string> = new Set([
  "DE89370400440532013000", "GB82WEST12345698765432", "GB29NWBK60161331926819", "GB33BUKB20201555555555",
  "FR1420041010050500013M02606", "NL91ABNA0417164300", "ES9121000418450200051332", "IT60X0542811101000000123456",
  "CH9300762011623852957", "BE68539007547034", "AT611904300234573201", "DK5000400440116243", "FI2112345600000785",
  "NO9386011117947", "SE4550000000058398257466", "PL61109010140000071219812874", "IE29AIBK93115212345678",
]);

/** Specimen national-id numbers that issuing agencies or their documentation publish. */
export const TEST_NATIONAL_IDS: ReadonlySet<string> = new Set(["078-05-1120", "219-09-9999", "123-45-6789", "QQ123456C", "AB123456C"]);

export function isKnownTestValue(hit: DataHit): boolean {
  const v = hit.value.replace(/[ -]/g, "").toUpperCase();
  if (hit.kind === "card") return TEST_CARDS.has(v);
  if (hit.kind === "iban") return TEST_IBANS.has(v);
  if (hit.kind === "national_id") return TEST_NATIONAL_IDS.has(hit.value.toUpperCase()) || TEST_NATIONAL_IDS.has(hit.value.replace(/ /g, "").toUpperCase());
  return false;
}
