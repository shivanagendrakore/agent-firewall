/**
 * The fuzz runner's minimum: a target that reaches its time cap after only a handful of inputs fails instead of
 * passing quietly (it proved nothing). FUZZ_MIN_ITERS sets the minimum (0 turns the check off); FUZZ_SEED replays
 * one seed and is never held to it.
 */
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_MIN_ITERS, fuzz, fuzzAsync, minIters } from "./gen.js";

const saved = { min: process.env.FUZZ_MIN_ITERS, cap: process.env.FUZZ_MAX_SECONDS, seed: process.env.FUZZ_SEED };
afterEach(() => {
  for (const [k, v] of [["FUZZ_MIN_ITERS", saved.min], ["FUZZ_MAX_SECONDS", saved.cap], ["FUZZ_SEED", saved.seed]] as const) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

/** A body that takes a few milliseconds per input, so a 1 ms cap stops the run after the first one. */
const slow = (): void => {
  const until = Date.now() + 5;
  while (Date.now() < until) {
    // busy wait: the cap is wall-clock time
  }
};

function clean(): void {
  delete process.env.FUZZ_MIN_ITERS;
  delete process.env.FUZZ_MAX_SECONDS;
  delete process.env.FUZZ_SEED;
}

describe("minIters", () => {
  it("defaults to DEFAULT_MIN_ITERS, never more than the target's own count", () => {
    clean();
    expect(minIters(1000)).toBe(DEFAULT_MIN_ITERS);
    expect(minIters(3)).toBe(3);
    expect(minIters(1000, 50)).toBe(50);
  });
  it("FUZZ_MIN_ITERS overrides it; 0 turns it off; nonsense falls back", () => {
    clean();
    process.env.FUZZ_MIN_ITERS = "200";
    expect(minIters(1000)).toBe(200);
    process.env.FUZZ_MIN_ITERS = "0";
    expect(minIters(1000)).toBe(0);
    process.env.FUZZ_MIN_ITERS = "lots";
    expect(minIters(1000)).toBe(DEFAULT_MIN_ITERS);
  });
});

describe("a run cut short by its time cap", () => {
  it("fails when fewer inputs ran than the minimum", () => {
    clean();
    expect(() => fuzz("min-check", 1000, slow, { capSec: 0.001 })).toThrow(/only \d+ of 1000 inputs ran before the 0.001s time cap \(at least 10 must run\)/);
  });
  it("the async runner too", async () => {
    clean();
    await expect(fuzzAsync("min-check-async", 1000, () => Promise.resolve(slow()), { capSec: 0.001 })).rejects.toThrow(/at least 10 must run/);
  });
  it("passes with FUZZ_MIN_ITERS=0, and when enough ran", () => {
    clean();
    process.env.FUZZ_MIN_ITERS = "0";
    expect(() => fuzz("min-off", 1000, slow, { capSec: 0.001 })).not.toThrow();
    clean();
    expect(() => fuzz("min-enough", 20, () => undefined, { capSec: 5 })).not.toThrow();
  });
  it("a FUZZ_SEED replay runs one input and is not held to the minimum", () => {
    clean();
    process.env.FUZZ_SEED = "7";
    expect(() => fuzz("min-replay", 1000, slow, { capSec: 0.001 })).not.toThrow();
  });
  it("a violation is still reported as the violation, not as too few inputs", () => {
    clean();
    expect(() =>
      fuzz("min-violation", 1000, () => {
        slow();
        throw new Error("broken: x");
      }, { capSec: 0.001 }),
    ).toThrow(/distinct violation/);
  });
});
