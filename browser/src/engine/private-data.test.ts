import { describe, expect, it } from "vitest";
import { sha256Hex } from "../vendor/firewall/engine/bytes.js";
import { canonicalText, newPrintSalt, printsFor, privateStringsIn, RESET_LINK_MAX, seenElsewhere } from "./private-data.js";

const SALT = "test-session-salt";

describe("private strings", () => {
  it("finds OTPs only near code words", () => {
    expect(privateStringsIn("Your verification code is 482915.").short).toEqual(["482915"]);
    expect(privateStringsIn("G-551234 is your Google verification code").short).toEqual(["551234"]);
    expect(privateStringsIn("Code: 123 456").short).toEqual(["123456"]);
    expect(privateStringsIn("Order 482915 shipped on 2026-10-11").short).toEqual([]);
  });
  it("finds emails, reset links and account numbers as long strings", () => {
    const { long } = privateStringsIn("Reply to alice.smith@mail.test or reset at https://mail.test/reset?token=abcdef123456. Account number 1234 5678 9012");
    expect(long).toContain("alice.smith@mail.test");
    expect(long.some((s) => s.startsWith("https://mail.test/reset"))).toBe(true);
    expect(long).toContain("123456789012");
  });
  it("stores only hashes", () => {
    const prints = printsFor("Your code is 482915, sent to alice.smith@mail.test", "inbox.mail.test", SALT);
    // The code, the address, and the address's canonical form.
    expect(prints.length).toBe(3);
    expect(JSON.stringify(prints)).not.toContain("482915");
    expect(JSON.stringify(prints)).not.toContain("alice");
    expect(prints.every((p) => p.domain === "mail.test")).toBe(true);
  });
});

describe("seen elsewhere", () => {
  const prints = printsFor("Your verification code is 482915. Account alice.smith@mail.test", "mail.test", SALT);

  it("matches an OTP typed on another site, alone or in a sentence", () => {
    expect(seenElsewhere("482915", "attacker.test", prints, SALT)?.kind).toBe("short");
    expect(seenElsewhere("the code is 482 915", "attacker.test", prints, SALT)?.kind).toBe("short");
  });
  it("does not match a code inside a longer number, or a different code", () => {
    expect(seenElsewhere("44829155", "attacker.test", prints, SALT)).toBeNull();
    expect(seenElsewhere("482916", "attacker.test", prints, SALT)).toBeNull();
  });
  it("matches a long string in the clear and encoded", () => {
    expect(seenElsewhere("contact: alice.smith@mail.test", "attacker.test", prints, SALT)?.kind).toBe("long");
    expect(seenElsewhere(btoa("alice.smith@mail.test"), "attacker.test", prints, SALT)?.kind).toBe("long");
    expect(seenElsewhere(encodeURIComponent("alice.smith@mail.test"), "attacker.test", prints, SALT)?.kind).toBe("long");
  });
  it("is not a leak on the same registrable domain", () => {
    expect(seenElsewhere("482915", "login.mail.test", prints, SALT)).toBeNull();
    expect(seenElsewhere("alice.smith@mail.test", "mail.test", prints, SALT)).toBeNull();
  });
  it("is null with no prints or an empty value", () => {
    expect(seenElsewhere("482915", "attacker.test", [], SALT)).toBeNull();
    expect(seenElsewhere("", "attacker.test", prints, SALT)).toBeNull();
  });
});

describe("seen elsewhere: obfuscated forms (canonical matching)", () => {
  const prints = printsFor("Your verification code is 482915. Account alice.smith@mail.test", "mail.test", SALT);

  it("folds case, zero-width characters, separators and [at]/(dot)", () => {
    expect(canonicalText("Alice.Smith [at] Mail (dot) Test")).toBe(canonicalText("alice.smith@mail.test"));
    expect(canonicalText("a​l‍i⁠ce")).toBe("alice");
    expect(canonicalText("ＡＬＩＣＥ")).toBe("alice");
  });
  it("matches an address typed with case changes, [at] and (dot), spaces or zero-width characters", () => {
    expect(seenElsewhere("ALICE.SMITH@MAIL.TEST", "attacker.test", prints, SALT)?.kind).toBe("long");
    expect(seenElsewhere("alice.smith [at] mail (dot) test", "attacker.test", prints, SALT)?.kind).toBe("long");
    expect(seenElsewhere("a​lice.smith@mail.te​st", "attacker.test", prints, SALT)?.kind).toBe("long");
    expect(seenElsewhere("a l i c e . s m i t h @ m a i l . t e s t", "attacker.test", prints, SALT)?.kind).toBe("long");
  });
  it("matches a code split by zero-width characters or written in fullwidth digits", () => {
    expect(seenElsewhere("48​29​15", "attacker.test", prints, SALT)?.kind).toBe("short");
    expect(seenElsewhere("４８２９１５", "attacker.test", prints, SALT)?.kind).toBe("short");
  });
  it("still does not match a different address", () => {
    expect(seenElsewhere("bob.smith [at] mail (dot) test", "attacker.test", prints, SALT)).toBeNull();
  });
});

describe("bounded page-text patterns (I4)", () => {
  it("bounds the reset-link pattern on both sides of the keyword", () => {
    // Many link starts in one long run of URL characters with no keyword: every match attempt is bounded, so
    // nothing matches and no match is longer than the bound.
    const run = "http://x".repeat(2_000) + "a".repeat(50_000);
    expect(privateStringsIn(run).long.filter((s) => s.startsWith("http"))).toEqual([]);
    // A keyword past the bound is not reached; one within it is, and the tail after it is cut at the bound.
    expect(privateStringsIn(`https://mail.test/${"a".repeat(5_000)}reset`).long.filter((s) => s.startsWith("http"))).toEqual([]);
    const tail = privateStringsIn(`https://mail.test/reset${"b".repeat(5_000)}`).long.filter((s) => s.startsWith("http"));
    expect(tail).toHaveLength(1);
    expect((tail[0] as string).length).toBe("https://mail.test/reset".length + RESET_LINK_MAX);
    const ok = privateStringsIn("open https://mail.test/reset?token=abcdef123456 now").long;
    expect(ok).toContain("https://mail.test/reset?token=abcdef123456");
  });
});

describe("seen elsewhere: short encodings", () => {
  const prints = printsFor("Your verification code is 482915.", "mail.test", SALT);
  it("matches a short code sent as base64, hex or percent-encoding", () => {
    expect(seenElsewhere(btoa("482915"), "attacker.test", prints, SALT)?.kind).toBe("short");
    expect(seenElsewhere("343832393135", "attacker.test", prints, SALT)?.kind).toBe("short");
    expect(seenElsewhere("%34%38%32%39%31%35", "attacker.test", prints, SALT)?.kind).toBe("short");
  });
  it("still refuses a code inside a longer number after decoding", () => {
    expect(seenElsewhere(btoa("44829155"), "attacker.test", prints, SALT)).toBeNull();
  });
});

describe("short-code fingerprints are salted", () => {
  const text = "Your verification code is 482915.";
  const short = (salt: string) => printsFor(text, "mail.test", salt).find((p) => p.kind === "short");

  it("differ per salt, and are not the unsalted hash a guess could reproduce", () => {
    const a = short("salt-a");
    const b = short("salt-b");
    expect(a).toBeDefined();
    expect(a?.fp).not.toBe(b?.fp);
    expect(a?.fp).toMatch(/^otp:[0-9a-f]{32}$/);
    // The old scheme: sha256 of a fixed prefix and the code. Reading the stored fingerprint must not match it.
    expect(a?.fp).not.toBe("otp:" + "launchsafe-otp:482915");
  });
  it("only match with the salt they were made with", () => {
    const prints = printsFor(text, "mail.test", "salt-a");
    expect(seenElsewhere("482915", "attacker.test", prints, "salt-a")?.kind).toBe("short");
    expect(seenElsewhere("482915", "attacker.test", prints, "salt-b")).toBeNull();
    expect(seenElsewhere("482915", "attacker.test", prints, "")).toBeNull();
  });
  it("an attacker who holds the stored fingerprint but not the salt cannot find the code by trying every 6-digit value under the old unsalted scheme", () => {
    const stored = short("salt-a")?.fp as string;
    let hit = false;
    for (let n = 0; n < 1_000_000 && !hit; n++) {
      const code = String(n).padStart(6, "0");
      if (`otp:${sha256Hex(`launchsafe-otp:${code}`).slice(0, 32)}` === stored) hit = true;
    }
    expect(hit).toBe(false);
  }, 60_000);
  it("makes no short print at all when there is no session salt", () => {
    expect(printsFor(text, "mail.test", "").filter((p) => p.kind === "short")).toEqual([]);
  });
  it("draws a fresh 128-bit salt each time", () => {
    const a = newPrintSalt();
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(newPrintSalt()).not.toBe(a);
  });
});
