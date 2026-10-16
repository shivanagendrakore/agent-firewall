/**
 * Fuzz: the engine's text scanners grow linearly with their input. FZ16 (the DNS-label join), FZ20 (the email
 * pattern in prompts) and the review's COPY ... PROGRAM pattern were each quadratic: a pattern tried from every
 * position of a long run backtracked over the rest of it. For random short alphabets repeated to a length n and
 * 2n, a scanner whose time more than triples from n to 2n (and is past a floor, so noise does not count) is
 * reported with its input shape. The shell analyzer is not timed here (test/fuzz/shell.test.ts covers it).
 * Every string is data given to a pure function; nothing is run.
 */
import { describe, it } from "vitest";
import { scanContent } from "../../src/engine/content-scan.js";
import { urlsIn } from "../../src/engine/network.js";
import { findPersonalData } from "../../src/engine/pii.js";
import { destinationsFromPrompt, resultText } from "../../src/engine/post.js";
import { credentialAssignments, decodedVariants, findSecrets, redactSecrets } from "../../src/engine/secrets.js";
import { classifySql } from "../../src/engine/sql.js";
import { createGuard } from "../../src/sdk/guard.js";
import { allowLongRuns, budget, fuzz, iters, type Rng } from "./gen.js";

allowLongRuns();

/** Characters and short words that patterns treat specially (word, dot, at, slash, quote, digit, space runs...). */
const PIECES = ["A", "a", "1", "0", ".", "@", "-", "_", "/", ":", "=", "+", " ", "\t", "\n", "%", "%2", "\\", '"', "'", "(", ")", "{", "}", ",", ";", "a.", "a-", "x@", "COPY ", "TO ", "http://", "https://a", "www.", "github.com/", "AKIA", "ghp_", "sk-", "key=", "4111", "DE89", "<a ", "&#", "​", "⁦", "é", "ff", "==", "base64,"];

function shape(r: Rng): string {
  const n = r.range(1, 4);
  let s = "";
  for (let i = 0; i < n; i++) s += r.pick(PIECES);
  return s;
}

const SCANNERS: Record<string, (s: string) => unknown> = {
  classifySql,
  destinationsFromPrompt,
  decodedVariants,
  findSecrets,
  credentialAssignments,
  redactSecrets: (s) => redactSecrets(s),
  findPersonalData,
  urlsIn,
  scanContent: (s) => scanContent(s),
  resultText: (s) => resultText({ a: s }),
  guardWebFetch: (s) => createGuard({ workspace: "/w", home: "/home/u", session: "rt" }).check({ tool: "WebFetch", input: { url: "https://example.com/", prompt: s } }),
  guardWrite: (s) => createGuard({ workspace: "/w", home: "/home/u", session: "rt" }).check({ tool: "Write", input: { file_path: "/w/notes.md", content: s } }),
  guardMcp: (s) => createGuard({ workspace: "/w", home: "/home/u", session: "rt" }).check({ tool: "mcp__notes__search", input: { q: s }, mcpSource: "user" }),
};

/** The faster of two runs, in ms. */
function time(f: () => unknown): number {
  let best = Number.POSITIVE_INFINITY;
  for (let i = 0; i < 2; i++) {
    const t0 = performance.now();
    f();
    best = Math.min(best, performance.now() - t0);
  }
  return best;
}

const FLOOR_MS = budget(60);

describe("fuzz: the engine's text scanners are linear in their input", () => {
  it("doubling the input never more than triples the time (past a floor)", () => {
    const names = Object.keys(SCANNERS);
    fuzz(
      "regex-timing",
      iters(30),
      (r) => {
        const name = r.pick(names);
        const f = SCANNERS[name] as (s: string) => unknown;
        const unit = shape(r);
        const n = r.pick([20_000, 40_000, 80_000]);
        const a = unit.repeat(Math.ceil(n / unit.length)).slice(0, n);
        const b = unit.repeat(Math.ceil((2 * n) / unit.length)).slice(0, 2 * n);
        const ta = time(() => f(a));
        const tb = time(() => f(b));
        if (tb > FLOOR_MS && tb > 3 * Math.max(ta, 1)) throw new Error(`superlinear: ${name} on ${JSON.stringify(unit)} repeated: ${n} chars ${ta.toFixed(0)} ms, ${2 * n} chars ${tb.toFixed(0)} ms`);
      },
      { capSec: 20 },
    );
  });
});
