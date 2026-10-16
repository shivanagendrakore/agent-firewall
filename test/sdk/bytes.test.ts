import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { base64Decode, hexToLatin1, sha256Hex, sha256HexBytes, utf8Decode } from "../../src/engine/bytes.js";

/** A small deterministic generator, so a failure reproduces. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

describe("engine byte helpers give exactly what the Node calls they replace gave", () => {
  it("sha256 matches node:crypto on edge lengths and random strings (including lone surrogates)", () => {
    const r = rng(1);
    const cases = ["", "a", "abc", "x".repeat(55), "x".repeat(56), "x".repeat(63), "x".repeat(64), "x".repeat(65), "é漢字🙂", "\ud800 lone", "lone \udfff"];
    for (let i = 0; i < 300; i++) {
      const n = Math.floor(r() * 300);
      let s = "";
      for (let j = 0; j < n; j++) s += String.fromCharCode(Math.floor(r() * 0xffff));
      cases.push(s);
    }
    for (const s of cases) expect(sha256Hex(s), JSON.stringify(s.slice(0, 20))).toBe(createHash("sha256").update(s, "utf8").digest("hex"));
    const big = new Uint8Array(200_003).map((_, i) => i * 31);
    expect(sha256HexBytes(big)).toBe(createHash("sha256").update(big).digest("hex"));
  });

  it("utf8Decode matches Buffer#toString('utf8') on random bytes", () => {
    const r = rng(2);
    for (let i = 0; i < 2000; i++) {
      const bytes = Uint8Array.from({ length: Math.floor(r() * 40) }, () => (r() < 0.5 ? Math.floor(r() * 128) : Math.floor(r() * 256)));
      expect(utf8Decode(bytes)).toBe(Buffer.from(bytes).toString("utf8"));
    }
  });

  it("hexToLatin1 matches Buffer.from(hex, 'hex').toString('latin1') for the hex runs the engine passes", () => {
    const r = rng(3);
    for (let i = 0; i < 500; i++) {
      let hex = "";
      const n = 8 + Math.floor(r() * 40);
      for (let j = 0; j < n * 2; j++) hex += "0123456789abcdefABCDEF"[Math.floor(r() * 22)];
      expect(hexToLatin1(hex)).toBe(Buffer.from(hex, "hex").toString("latin1"));
    }
  });

  it("base64Decode matches Buffer.from(s, 'base64') for the runs the engine passes", () => {
    const r = rng(4);
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (let i = 0; i < 2000; i++) {
      let s = "";
      const n = 16 + Math.floor(r() * 60);
      for (let j = 0; j < n; j++) s += alphabet[Math.floor(r() * 64)];
      s += "=".repeat(Math.floor(r() * 3));
      expect(Array.from(base64Decode(s)), s).toEqual(Array.from(Buffer.from(s, "base64")));
    }
  });
});
