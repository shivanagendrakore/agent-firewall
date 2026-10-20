import { describe, it, expect } from "vitest";
import { bindingVariants, withoutTrailingSlashes, type Collector } from "../../src/engine/effects.js";
import { hostMatches } from "../../src/engine/network.js";
import { projectId } from "../../src/runtime/learned.js";
import { toolServers } from "../../src/sdk/tools.js";

/**
 * CodeQL js/polynomial-redos fixes (#4, #5, #7, #15, #16): the same results as the regular expressions they
 * replaced, and linear time on the input shape CodeQL named.
 */

const LONG = 200_000;

function timed(fn: () => void): number {
  const t0 = performance.now();
  fn();
  return performance.now() - t0;
}

/** bindingVariants reads only the collector's bindings. */
function withBindings(b: Record<string, string[]>): Collector {
  return { bindings: new Map(Object.entries(b)) } as unknown as Collector;
}

describe("bindingVariants (#4)", () => {
  const c = withBindings({ X: ["dist"], Y: ["a", "b"] });

  it("substitutes bound $NAME and ${NAME...} references", () => {
    expect(bindingVariants(c, "$X/out")).toEqual(["dist/out"]);
    expect(bindingVariants(c, "${X}/out")).toEqual(["dist/out"]);
    expect(bindingVariants(c, "${X:-other}/out")).toEqual(["dist/out"]);
    expect(bindingVariants(c, "$X/$Y")).toEqual(["dist/a", "dist/b"]);
    expect(bindingVariants(c, "${X}${Y}")).toEqual(["dista", "distb"]);
  });

  it("leaves the word alone when a reference is unbound, HOME or PWD, or a command substitution", () => {
    expect(bindingVariants(c, "$X/$Z")).toEqual(["$X/$Z"]);
    expect(bindingVariants(c, "$HOME/$X")).toEqual(["$HOME/$X"]);
    expect(bindingVariants(c, "${PWD}/x")).toEqual(["${PWD}/x"]);
    expect(bindingVariants(c, "$(pwd)/$X")).toEqual(["$(pwd)/$X"]);
    expect(bindingVariants(withBindings({}), "$X")).toEqual(["$X"]);
    expect(bindingVariants({} as unknown as Collector, "$X")).toEqual(["$X"]);
  });

  it("finds the same references as before at the edges", () => {
    // An unclosed ${X is no reference: nothing to bind, so the word is unchanged.
    expect(bindingVariants(c, "${X/out")).toEqual(["${X/out"]);
    // A $NAME after an unclosed ${ is still one.
    expect(bindingVariants(c, "${Z$X")).toEqual(["${Zdist"]);
    // A reference inside ${...} is part of it, not a reference of its own.
    expect(bindingVariants(c, "${X:-$Z}")).toEqual(["dist"]);
    // ${1}, $$, a lone $ and $ before a digit are no references.
    expect(bindingVariants(c, "${1}$$")).toEqual(["${1}$$"]);
    expect(bindingVariants(c, "a$")).toEqual(["a$"]);
    expect(bindingVariants(c, "$1$X")).toEqual(["$1dist"]);
    // The longest name is taken ($XY is not $X).
    expect(bindingVariants(c, "$XY")).toEqual(["$XY"]);
  });

  it("is linear on '${A' followed by many '0's", () => {
    const raw = `\${A${"0".repeat(LONG)}`;
    let out: string[] = [];
    expect(timed(() => (out = bindingVariants(c, raw)))).toBeLessThan(2000);
    expect(out).toEqual([raw]);
  });

  it("is linear on many unclosed '${A's", () => {
    const raw = "${A".repeat(LONG / 3);
    let out: string[] = [];
    expect(timed(() => (out = bindingVariants(c, raw)))).toBeLessThan(2000);
    expect(out).toEqual([raw]);
  });
});

describe("withoutTrailingSlashes (#5)", () => {
  it("drops only the trailing run of '/'", () => {
    expect(withoutTrailingSlashes("/a/b///")).toBe("/a/b");
    expect(withoutTrailingSlashes("/a/b")).toBe("/a/b");
    expect(withoutTrailingSlashes("///")).toBe("");
    expect(withoutTrailingSlashes("/")).toBe("");
    expect(withoutTrailingSlashes("")).toBe("");
    expect(withoutTrailingSlashes("//a//b")).toBe("//a//b");
  });

  it("is linear on many '/'s", () => {
    const s = `${"/".repeat(LONG)}x`;
    let out = "";
    expect(timed(() => (out = withoutTrailingSlashes(s)))).toBeLessThan(2000);
    expect(out).toBe(s);
    expect(withoutTrailingSlashes("/".repeat(LONG))).toBe("");
  });
});

describe("hostMatches pattern cleaning (#7)", () => {
  it("ignores a scheme, path, query, fragment and port in the pattern", () => {
    expect(hostMatches("example.com", "example.com")).toBe(true);
    expect(hostMatches("a.example.com", "https://example.com/x")).toBe(true);
    expect(hostMatches("example.com", "example.com:8443")).toBe(true);
    expect(hostMatches("example.com", "example.com?x#y")).toBe(true);
    expect(hostMatches("example.com", "example.com#frag")).toBe(true);
    expect(hostMatches("example.com", "=example.com/path")).toBe(true);
    expect(hostMatches("a.example.com", "=example.com/path")).toBe(false);
    expect(hostMatches("a.example.com", "*.example.com#frag")).toBe(true);
    expect(hostMatches("example.com", "*.example.com")).toBe(false);
    expect(hostMatches("evil.com", "example.com/evil.com")).toBe(false);
    expect(hostMatches("example.com", ".example.com")).toBe(true);
  });

  it("keeps a path part followed by a line break, as before", () => {
    // .* stops at a line break, so /[/?#].*$/ cut only after the last one.
    expect(hostMatches("a/b\nc", "a/b\nc")).toBe(true);
    expect(hostMatches("a", "a/b\nc")).toBe(false);
    expect(hostMatches("a\nb", "a\nb/c")).toBe(true);
  });

  it("is linear on many '#'s", () => {
    let out = true;
    expect(timed(() => (out = hostMatches("example.com", "#".repeat(LONG))))).toBeLessThan(2000);
    expect(out).toBe(false);
    expect(timed(() => (out = hostMatches("example.com", `${"#".repeat(LONG)}\nx`)))).toBeLessThan(2000);
    expect(out).toBe(false);
  });
});

describe("projectId (#15)", () => {
  const missing = "/nonexistent-lsfw-codeql-fix-c";

  it("is the resolved directory without trailing '/'", () => {
    expect(projectId(`${missing}/a/b/`)).toBe(`${missing}/a/b`);
    expect(projectId(`${missing}/a//b///`)).toBe(`${missing}/a/b`);
    expect(projectId(`${missing}/a/../b`)).toBe(`${missing}/b`);
    expect(projectId("/")).toBe("/");
  });

  it("is linear on many '/'s", () => {
    let out = "";
    expect(timed(() => (out = projectId(`${missing}${"/".repeat(LONG)}x`)))).toBeLessThan(2000);
    expect(out).toBe(`${missing}/x`);
  });
});

describe("toolServers server names (#16)", () => {
  const names = (server: string | undefined, tool = "t"): string[] => Object.keys(toolServers({ [tool]: server === undefined ? { kind: "read" } : { kind: "read", server } }));

  it("collapses runs of '_' and trims them at either end", () => {
    expect(names(undefined)).toEqual(["t"]);
    expect(names(undefined, "a__b")).toEqual(["a_b"]);
    expect(names("a__b")).toEqual(["a_b"]);
    expect(names("__a___b__")).toEqual(["a_b"]);
    expect(names("a_b_c")).toEqual(["a_b_c"]);
    expect(names("_")).toEqual(["tool"]);
    expect(names("___")).toEqual(["tool"]);
    expect(names("")).toEqual(["tool"]);
  });

  it("is linear on many '_'s", () => {
    let out: string[] = [];
    expect(timed(() => (out = names(`a${"_".repeat(LONG)}b`)))).toBeLessThan(2000);
    expect(out).toEqual(["a_b"]);
    expect(names(`${"_".repeat(LONG)}x`)).toEqual(["x"]);
  });
});
