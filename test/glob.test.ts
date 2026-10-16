/**
 * FZ11/FZ1: the glob matcher is an automaton, not a regular expression: linear time, bounded work, and the
 * caller's fail-closed answer past its bounds. It must still answer exactly as the regular expression it
 * replaced did on ordinary input.
 */
import { describe, expect, it } from "vitest";
import { globMatch, globMatchBounded, globsOverlap, MAX_PATTERN } from "../src/engine/glob.js";

/** The matcher this replaced (src/engine/glob.ts before FZ11), kept as the reference for short inputs. */
function referenceRegExp(pattern: string, caseInsensitive: boolean): RegExp {
  const hasCloser = (i: number): boolean => {
    let depth = 0;
    for (let j = i; j < pattern.length; j++) {
      if (pattern[j] === "{") depth++;
      else if (pattern[j] === "}") {
        depth--;
        if (depth === 0) return true;
      }
    }
    return false;
  };
  let re = "";
  let depth = 0;
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i] as string;
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        if (pattern[i + 2] === "/") {
          re += "(?:.*/)?";
          i += 2;
        } else {
          re += ".*";
          i += 1;
        }
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else if (c === "{" && hasCloser(i)) {
      depth++;
      re += "(?:";
    } else if (c === "}" && depth > 0) {
      depth--;
      re += ")";
    } else if (c === "," && depth > 0) re += "|";
    else re += c.replace(/[.+^$(){}|[\]\\]/g, "\\$&");
  }
  for (let d = 0; d < depth; d++) re += ")";
  return new RegExp(`^${re}$`, caseInsensitive ? "i" : "");
}

/** A small deterministic generator (mulberry32). */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe("glob matcher", () => {
  it("keeps the documented behaviour", () => {
    expect(globMatch("src/*.ts", "src/a.ts", false)).toBe(true);
    expect(globMatch("src/*.ts", "src/x/a.ts", false)).toBe(false);
    expect(globMatch("**/CLAUDE.md", "/a/b/CLAUDE.md", false)).toBe(true);
    expect(globMatch("**/CLAUDE.md", "CLAUDE.md", false)).toBe(true);
    expect(globMatch("~/.ssh/**", "~/.ssh/a/b", false)).toBe(true);
    expect(globMatch("x.{ts,js}", "x.js", false)).toBe(true);
    expect(globMatch("x.{ts,{c,m}js}", "x.mjs", false)).toBe(true);
    expect(globMatch("[ab]", "[ab]", false)).toBe(true);
    expect(globMatch("[ab]", "a", false)).toBe(false);
    expect(globMatch("x{a", "x{a", false)).toBe(true);
    expect(globMatch("**/ID_RSA*", "/home/u/.ssh/id_rsa.pub", true)).toBe(true);
    expect(globMatch("**/ID_RSA*", "/home/u/.ssh/id_rsa.pub", false)).toBe(false);
  });

  it("answers as the regular expression it replaced on random short patterns and paths", () => {
    const r = rng(20261011);
    const alphabet = ["a", "b", "/", ".", "*", "**", "**/", "?", "{", "}", ",", "A", "[", "x"];
    const pathChars = ["a", "b", "/", ".", "A", "x", "[", "{", ",", "}"];
    const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)] as T;
    for (let i = 0; i < 20000; i++) {
      const pattern = Array.from({ length: 1 + Math.floor(r() * 8) }, () => pick(alphabet)).join("");
      const path = Array.from({ length: Math.floor(r() * 10) }, () => pick(pathChars)).join("");
      const ci = r() < 0.5;
      expect(globMatch(pattern, path, ci), `${pattern} ${path} ${ci}`).toBe(referenceRegExp(pattern, ci).test(path));
    }
  });

  it("FZ11: star runs and many stars take linear time", () => {
    const t0 = performance.now();
    expect(globMatch("*".repeat(4000) + "Q", "a".repeat(4000), false)).toBe(false);
    expect(globMatch("*a".repeat(2000) + "Q", "a".repeat(4000), false)).toBe(false);
    expect(globMatch("**/".repeat(1000) + "x", "a/".repeat(2000), false)).toBe(false);
    expect(globMatch("{a,".repeat(1000) + "b" + "}".repeat(1000), "b", false)).toBe(true);
    expect(performance.now() - t0).toBeLessThan(2000);
  });

  it("FZ1: a pattern past the size bound is not compiled; the caller's answer stands", () => {
    const huge = `${"A".repeat(MAX_PATTERN)}*`;
    expect(globMatchBounded(huge, "id_rsa", false)).toBeNull();
    expect(globMatch(huge, "id_rsa", false)).toBe(true);
    expect(globMatch(huge, "id_rsa", false, false)).toBe(false);
  });
});

/** Every text over `chars` of length 0 to `max`. */
function texts(chars: readonly string[], max: number): string[] {
  const out = [""];
  let layer = [""];
  for (let n = 1; n <= max; n++) {
    layer = layer.flatMap((t) => chars.map((c) => t + c));
    out.push(...layer);
  }
  return out;
}

describe("I7: whether two globs can name the same thing (globsOverlap)", () => {
  it("a glob an agent writes against a credential store's name pattern", () => {
    expect(globsOverlap("ssh_host_*", "ssh_host_*_key", false)).toBe(true);
    expect(globsOverlap("*", "ssh_host_*_key", false)).toBe(true);
    expect(globsOverlap("*_key", "ssh_host_*_key", false)).toBe(true);
    expect(globsOverlap("ssh_host_{rsa,ed25519}_key", "ssh_host_*_key", false)).toBe(true);
    expect(globsOverlap("ssh_host_?*", "ssh_host_*_key", false)).toBe(true);
    expect(globsOverlap(".*", ".*_history", false)).toBe(true);
    // Nothing ends in both ".pub" and "_key", or starts with both "ssh_" and "moduli".
    expect(globsOverlap("ssh_host_*.pub", "ssh_host_*_key", false)).toBe(false);
    expect(globsOverlap("ssh_host_*_key.pub", "ssh_host_*_key", false)).toBe(false);
    expect(globsOverlap("moduli*", "ssh_host_*_key", false)).toBe(false);
    expect(globsOverlap("*.conf", "ssh_host_*_key", false)).toBe(false);
  });
  it("case folds only when asked, and a single-segment wildcard does not stand for a slash", () => {
    expect(globsOverlap("SSH_HOST_*", "ssh_host_*_key", true)).toBe(true);
    expect(globsOverlap("SSH_HOST_*", "ssh_host_*_key", false)).toBe(false);
    expect(globsOverlap("a/*", "a?b", false)).toBe(false);
    expect(globsOverlap("a*b", "a/b", false)).toBe(false);
    expect(globsOverlap("a**b", "a/b", false)).toBe(true);
    expect(globsOverlap("a/**", "a?b", false)).toBe(false);
  });
  it("answers as a search over every short text, on random short patterns", () => {
    const r = rng(20261015);
    const alphabet = ["a", "A", "/", "*", "?", "**", "{a,/}"];
    const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)] as T;
    const all = texts(["a", "A", "/"], 6);
    for (let i = 0; i < 400; i++) {
      const ta = Array.from({ length: 1 + Math.floor(r() * 3) }, () => pick(alphabet));
      const tb = Array.from({ length: 1 + Math.floor(r() * 3) }, () => pick(alphabet));
      const [a, b] = [ta.join(""), tb.join("")];
      const ci = r() < 0.5;
      // A shortest common text spends each character on a step outside the stars of one pattern or the other (a
      // character both patterns' stars absorb can be left out), so it is no longer than those steps together.
      const steps = [...ta, ...tb].filter((t) => t !== "*" && t !== "**").length;
      const brute = all.some((t) => t.length <= steps && globMatch(a, t, ci) && globMatch(b, t, ci));
      expect(globsOverlap(a, b, ci), `${a} ${b} ${ci}`).toBe(brute);
    }
  });
  it("is bounded: a long glob against a store's short pattern is answered exactly, two long ones within the work bound", () => {
    const long = "*a".repeat(1000) + "Q";
    const t0 = performance.now();
    // What the engine compares: a segment an agent wrote (up to a path's length) with a short store pattern.
    expect(globsOverlap(long, "ssh_host_*_key", false)).toBe(false);
    expect(globsOverlap(long, "*Q", false)).toBe(true);
    expect(globsOverlap("**/".repeat(500) + "x", "*y", false)).toBe(false);
    // Two long ones: past the work bound the caller's answer stands, so with `false` it is never a guessed overlap.
    expect(globsOverlap("*a".repeat(300) + "Q", "*a".repeat(300) + "R", false, false)).toBe(false);
    expect(performance.now() - t0).toBeLessThan(2000);
    const huge = `${"A".repeat(MAX_PATTERN)}*`;
    expect(globsOverlap(huge, "x", false)).toBe(true);
    expect(globsOverlap(huge, "x", false, false)).toBe(false);
  });
});
