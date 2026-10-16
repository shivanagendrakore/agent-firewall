/**
 * FP-5 (lower severity): in an agent session, a year or other 4 to 8 digit number within 60 characters of "code",
 * "pin", "verify" or "confirm" is fingerprinted as a one-time code and the tab is marked private. On the real
 * corpus loaded with agent mode on, 31 of 163 pages (19%) end up private, against 19 (12%, e-mail addresses) with
 * agent mode off; the extra 12 are mostly Wikipedia and docs pages that put a year near the word "code".
 * The effect is that the session turns private and a later 2019 typed on another site is held as a leak.
 * Fixed: bare "code", "pin" and "confirm" count only bound to the number ("code: 4821"), and a plausible year or a
 * number that is part of a date, a decimal, money or a percentage is not a code unless it is bound to the label.
 */
import { describe, expect, it } from "vitest";
import { privateStringsIn } from "../../../src/engine/private-data.js";

describe("FP-5: a year near the word 'code' is not a one-time code", () => {
  it("prose that mentions a release year next to 'source code' yields no short code", () => {
    expect(privateStringsIn("The source code was first released under the MIT licence in 2019.").short).toEqual([]);
  });
  it("other years, dates, prices and counts near 'code', 'PIN' or 'confirm' are not codes", () => {
    for (const text of [
      "Code of Conduct, adopted 2021, revised in 2024.",
      "Python 3.12 source code, released 2023-10-02.",
      "Confirm your order of $1299 before 10/2025.",
      "The zip code area grew 4500% since 1998.",
      "PIN pads shipped: 1,250,000 in 2022.",
      "The code base has 12000 lines of tests.",
      "Announcing Google Summer of Code 2026 selected projects",
    ]) expect(privateStringsIn(text).short, text).toEqual([]);
  });
  it("control: a real verification message still yields its code", () => {
    expect(privateStringsIn("Your verification code is 482913. It expires in ten minutes.").short).toEqual(["482913"]);
  });
  it("control: codes bound to their label, sign-in messages and year-like codes with a label still count", () => {
    expect(privateStringsIn("Code: 123 456").short).toEqual(["123456"]);
    expect(privateStringsIn("Your sign-in code is 7741").short).toEqual(["7741"]);
    expect(privateStringsIn("Your one-time passcode: 55102938").short).toEqual(["55102938"]);
    expect(privateStringsIn("Your code is 2019. Do not share it.").short).toEqual(["2019"]);
    expect(privateStringsIn("Use 884213 to verify your account").short).toEqual(["884213"]);
  });
});
