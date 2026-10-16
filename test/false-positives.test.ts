/**
 * Normal developer work must be allowed. The corpus lives in src/corpus.ts
 * (shared with the friction report). Each case must not ask, queue or deny.
 */
import { describe, expect, it } from "vitest";
import { ALWAYS_FINE, TRUSTED_ONLY, TOOL_CASES, V02_FINE } from "../src/corpus.js";
import { WS } from "./helpers.js";
import { bash, explain, run } from "./helpers.js";

function fill(v: unknown): unknown {
  if (typeof v === "string") return v.replaceAll("{WS}", WS);
  if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x)]));
  return v;
}

describe("false positives: normal work is allowed", () => {
  describe("always fine (trusted and untrusted)", () => {
    for (const c of ALWAYS_FINE) {
      it(c, () => {
        expect(bash(c).verdict, `trusted: ${explain(bash(c))}`).toBe("allow");
        expect(bash(c, { tainted: true }).verdict, `untrusted: ${explain(bash(c, { tainted: true }))}`).toBe("allow");
      });
    }
  });
  describe("v0.2 cases (trusted and untrusted)", () => {
    for (const c of V02_FINE) {
      it(c, () => {
        expect(bash(c).verdict, `trusted: ${explain(bash(c))}`).toBe("allow");
        expect(bash(c, { tainted: true }).verdict, `untrusted: ${explain(bash(c, { tainted: true }))}`).toBe("allow");
      });
    }
  });
  describe("fine when trusted", () => {
    for (const c of TRUSTED_ONLY) it(c, () => expect(bash(c).verdict, explain(bash(c))).toBe("allow"));
  });
  describe("tool calls", () => {
    for (const c of TOOL_CASES) {
      const input = fill(c.input) as Record<string, unknown>;
      it(`${c.tool} ${JSON.stringify(input).slice(0, 40)}`, () => expect(run(c.tool, input).verdict, explain(run(c.tool, input))).toBe("allow"));
    }
  });
});
