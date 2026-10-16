/**
 * A small seeded generator and mutator for the robustness fuzz tests (test/fuzz/). No dependencies:
 * a mulberry32 PRNG, byte/unicode/JSON mutators, and the run loop that reports the seed of a failure.
 *
 * Scale: FUZZ_ITERS is the iteration count of the cheapest target (the shell analyzer); every other
 * target runs a fixed fraction of it (see `iters()`). The default keeps the whole fuzz run near a
 * minute; FUZZ_ITERS=30000 is "10x". Replay one failure with FUZZ_SEED=<seed> (runs that one case).
 *
 * Long runs: each target also stops at a wall-clock cap (its own default, or FUZZ_MAX_SECONDS for all), so a
 * campaign sets both, e.g. FUZZ_ITERS=1000000 FUZZ_MAX_SECONDS=300 runs every target for five minutes.
 * FUZZ_STACK=1 adds the stack to each reported exception; FUZZ_TRACE=<file> names the seed of a hang;
 * FUZZ_REPORT=<file> collects every violation's whole message (the thrown report shortens them).
 */

import { appendFileSync, writeFileSync } from "node:fs";
import { vi } from "vitest";
import { SLOW } from "../helpers.js";

/** The suite's 30 s test timeout is for ordinary tests; a fuzz target may run for its whole time cap (and FUZZ_ITERS scales it up). */
export function allowLongRuns(): void {
  vi.setConfig({ testTimeout: 30 * 60_000, hookTimeout: 5 * 60_000 });
}

export const BASE_ITERS = 3000;

export function scale(): number {
  const n = Number(process.env.FUZZ_ITERS);
  return Number.isFinite(n) && n > 0 ? n : BASE_ITERS;
}

/** The fewest inputs a target must run before its time cap counts as a pass, unless FUZZ_MIN_ITERS says otherwise. */
export const DEFAULT_MIN_ITERS = 10;

/**
 * The fewest inputs a target of `total` inputs must run: FUZZ_MIN_ITERS (0 turns the check off), else
 * `fallback` (DEFAULT_MIN_ITERS), never more than the target's own count. A target that hits its time cap
 * after a handful of inputs proved nothing, so it fails instead of passing quietly.
 */
export function minIters(total: number, fallback = DEFAULT_MIN_ITERS): number {
  const env = process.env.FUZZ_MIN_ITERS;
  const n = env !== undefined && env !== "" ? Number(env) : fallback;
  return Math.min(total, Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback);
}

function tooFew(name: string, ran: number, total: number, capMs: number, min: number): Error {
  return new Error(`fuzz ${name}: only ${ran} of ${total} inputs ran before the ${capMs / 1000}s time cap (at least ${min} must run): the run proves too little; give it more time (FUZZ_MAX_SECONDS) or lower the minimum (FUZZ_MIN_ITERS)`);
}

/** The iteration count for a target that costs `weight` times the shell analyzer (weight 1 = cheapest). */
export function iters(weight: number): number {
  return Math.max(10, Math.round(scale() / weight));
}

export class Rng {
  private a: number;
  constructor(readonly seed: number) {
    this.a = seed | 0;
  }
  /** A float in [0, 1). */
  next(): number {
    this.a |= 0;
    this.a = (this.a + 0x6d2b79f5) | 0;
    let t = Math.imul(this.a ^ (this.a >>> 15), 1 | this.a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }
  /** An integer in [0, n). */
  int(n: number): number {
    return n <= 0 ? 0 : Math.floor(this.next() * n);
  }
  range(lo: number, hi: number): number {
    return lo + this.int(hi - lo + 1);
  }
  bool(p = 0.5): boolean {
    return this.next() < p;
  }
  pick<T>(xs: readonly T[]): T {
    return xs[this.int(xs.length)] as T;
  }
}

// --- string mutation ---------------------------------------------------------------------------------

/** Awkward unicode: invisibles, bidi controls, tag characters, combining marks, astral, lone surrogates, specials. */
export const UNICODE: readonly string[] = [
  "​", "‌", "‍", "⁠", "﻿", "‮", "‭", "⁦", "⁩", "­", "؜",
  "\u{e0041}", "\u{e0020}", "\u{e007f}", "́", "̸", "\u{1f600}", "\u{1f1fa}\u{1f1f8}", "\ud800", "\udfff", "�", "￿",
  "\u0000", "\u0085", " ", " ", " ", "　", "а", "с", "ẞ", "İ", "K", "／", "；", "∕",
  "\x1b[31m", "\x1b]0;x\x07", "\r", "\r\n", "\x7f", "\x08",
];

const JUNK: readonly string[] = ["'", '"', "`", "$(", "${", "(", ")", "{", "}", "[", "]", "<<", "<<<", "<(", "\\", "\n", ";", "&&", "||", "|", "&", ">", ">>", "2>&1", "#", "$", "*", "?", "~", "!", "=", "\t", " "];

function insertAt(s: string, i: number, piece: string): string {
  return s.slice(0, i) + piece + s.slice(i);
}

/** One random edit of a string: insert, delete, duplicate, swap, unicode, NUL, invalid UTF-8, huge repeat, deep nesting. */
export function mutateString(r: Rng, s: string): string {
  const i = r.int(s.length + 1);
  switch (r.int(14)) {
    case 0:
      return insertAt(s, i, r.pick(JUNK));
    case 1:
      return s.slice(0, i) + s.slice(i + r.range(1, 8));
    case 2: {
      const j = Math.min(s.length, i + r.range(1, 40));
      return s.slice(0, j) + s.slice(i, j) + s.slice(j);
    }
    case 3:
      return insertAt(s, i, r.pick(UNICODE));
    case 4:
      return insertAt(s, i, "\u0000");
    case 5: {
      // invalid UTF-8: bytes that cannot start or continue a sequence, decoded as the reader would
      const bad = Buffer.from([r.pick([0xc0, 0xc1, 0xf5, 0xff, 0x80, 0xbf, 0xe2, 0xf0])]);
      return insertAt(s, i, bad.toString("latin1"));
    }
    case 6:
      return insertAt(s, i, r.pick(JUNK).repeat(r.range(2, 200)));
    case 7: {
      const open = r.pick(["(", "$(", "{", "[", "`", "'", '"', "<<EOF\n", "${a:-"]);
      return insertAt(s, i, open.repeat(r.range(10, 3000)));
    }
    case 8:
      return s.length > 1 ? s.slice(0, i) : s;
    case 9:
      return s.length > 1 ? s.slice(i) : s;
    case 10: {
      const j = r.int(s.length);
      const k = r.int(s.length);
      const arr = [...s];
      if (j < arr.length && k < arr.length) [arr[j], arr[k]] = [arr[k] as string, arr[j] as string];
      return arr.join("");
    }
    case 11:
      // Never past MAX_CHARS (a long run grows a string until repeat() itself throws "Invalid string length").
      return r.bool(0.1) ? s.repeat(Math.max(1, Math.min(r.range(50, 400), Math.floor(MAX_CHARS / Math.max(1, s.length))))) : s.length > MAX_CHARS ? s : s + s;
    case 12:
      return insertAt(s, i, "A".repeat(r.range(1000, 60_000)));
    default:
      return insertAt(s, i, r.pick(UNICODE).repeat(r.range(1, 500)));
  }
}

/** Strings stay under this many characters, so a single decision costs milliseconds, not minutes. */
export const MAX_CHARS = 4_000_000;

export function mutateStringN(r: Rng, s: string, maxEdits = 4): string {
  let out = s;
  const n = r.range(1, maxEdits);
  for (let k = 0; k < n; k++) {
    out = mutateString(r, out);
    if (out.length > MAX_CHARS) out = out.slice(0, MAX_CHARS);
  }
  return out;
}

/** Byte-level mutation of a buffer (insert, delete, duplicate, flip), for raw wire formats. */
export function mutateBytes(r: Rng, b: Uint8Array): Uint8Array {
  const a = [...b];
  const n = r.range(1, 5);
  for (let k = 0; k < n; k++) {
    const i = r.int(a.length + 1);
    switch (r.int(5)) {
      case 0:
        a.splice(i, 0, ...Array.from({ length: r.range(1, 20) }, () => r.int(256)));
        break;
      case 1:
        a.splice(i, r.range(1, 30));
        break;
      case 2: {
        const seg = a.slice(i, i + r.range(1, 200));
        a.splice(i, 0, ...seg);
        break;
      }
      case 3:
        if (i < a.length) a[i] = (a[i] as number) ^ (1 << r.int(8));
        break;
      default:
        a.splice(i, 0, 0);
    }
  }
  return Uint8Array.from(a);
}

// --- JSON mutation -----------------------------------------------------------------------------------

export type Json = Record<string, unknown>;

const WRONG_VALUES = (r: Rng): unknown[] => [null, true, false, 0, -1, 1e308, NaN, 1.2345678901234567e19, "", "x", "\u0000", [], {}, [1, 2], { a: 1 }, [[]], r.bool() ? "A".repeat(100_000) : "str"];

/** A deeply nested array or object. */
export function deep(depth: number, kind: "array" | "object" = "array", leaf: unknown = 1): unknown {
  let v: unknown = leaf;
  for (let i = 0; i < depth; i++) v = kind === "array" ? [v] : { a: v };
  return v;
}

/** Paths to every node of a JSON value (as key arrays), not descending past `limit` nodes. */
function paths(v: unknown, prefix: (string | number)[] = [], out: (string | number)[][] = [], limit = 400): (string | number)[][] {
  out.push(prefix);
  if (out.length >= limit || prefix.length > 40) return out;
  if (Array.isArray(v)) v.forEach((x, i) => paths(x, [...prefix, i], out, limit));
  else if (typeof v === "object" && v !== null) for (const [k, x] of Object.entries(v)) paths(x, [...prefix, k], out, limit);
  return out;
}

function setAt(root: unknown, p: (string | number)[], f: (old: unknown, parent: unknown) => unknown | typeof DELETE): unknown {
  if (p.length === 0) {
    const nv = f(root, undefined);
    return nv === DELETE ? undefined : nv;
  }
  let cur = root as Record<string | number, unknown>;
  for (let i = 0; i < p.length - 1; i++) cur = cur[p[i] as string | number] as Record<string | number, unknown>;
  const key = p[p.length - 1] as string | number;
  const nv = f(cur[key], cur);
  if (nv === DELETE) {
    if (Array.isArray(cur)) cur.splice(key as number, 1);
    else delete cur[key];
  } else cur[key] = nv;
  return root;
}

const DELETE = Symbol("delete");

/** One structural edit of a JSON value: wrong type, delete, duplicate, deep nest, rename a key, or mutate a string. Works on a copy. */
export function mutateJson<T>(r: Rng, v: T, avoid?: (path: readonly (string | number)[]) => boolean): unknown {
  const root: unknown = structuredClone(v);
  const all = avoid === undefined ? paths(root) : paths(root).filter((q) => !avoid(q));
  if (all.length === 0) return root;
  const p = r.pick(all);
  switch (r.int(8)) {
    case 0:
      return setAt(root, p, () => r.pick(WRONG_VALUES(r)));
    case 1:
      return p.length === 0 ? root : setAt(root, p, () => DELETE);
    case 2:
      return setAt(root, p, (old) => (Array.isArray(old) ? [...old, ...old] : [old, old]));
    case 3:
      return setAt(root, p, (old) => deep(r.range(20, 300), r.bool() ? "array" : "object", old));
    case 4:
      return setAt(root, p, (old, parent) => {
        if (typeof parent === "object" && parent !== null && !Array.isArray(parent) && typeof p[p.length - 1] === "string") {
          (parent as Json)[mutateString(r, p[p.length - 1] as string)] = old;
        }
        return DELETE;
      });
    case 5:
      return setAt(root, p, (old) => (typeof old === "string" ? mutateStringN(r, old) : r.pick(WRONG_VALUES(r))));
    case 6:
      return setAt(root, p, (old) => (typeof old === "string" ? old.repeat(Math.max(1, Math.min(r.range(100, 2000), Math.floor(1_000_000 / Math.max(1, old.length))))) : old));
    default:
      return setAt(root, p, (old) => (typeof old === "string" ? mutateString(r, old) : old));
  }
}

export function mutateJsonN<T>(r: Rng, v: T, maxEdits = 3, avoid?: (path: readonly (string | number)[]) => boolean): unknown {
  let out: unknown = v;
  const n = r.range(1, maxEdits);
  for (let k = 0; k < n; k++) out = mutateJson(r, out, avoid);
  return out;
}

/** JSON text, possibly with its text corrupted (truncated, bytes edited, duplicate keys, trailing junk). */
export function corruptText(r: Rng, text: string): string {
  switch (r.int(7)) {
    case 6: {
      // nesting far deeper than any structured edit builds
      const n = r.range(1000, 200_000);
      const [o, c] = r.pick([["[", "]"], ['{"a":', "}"]] as const);
      return text.replace(/\}\s*$/, `,"deep":${o.repeat(n)}${c.repeat(n)}}`);
    }
    case 0:
      return text.slice(0, r.int(text.length));
    case 1:
      return mutateStringN(r, text, 3);
    case 2:
      return text + r.pick(["}", "]", ",", "\u0000", "{}", "x", "\n{"]);
    case 3:
      return text.replace(/^\{/, `{"__proto__":{"polluted":true},"constructor":{"prototype":{"p":1}},`);
    case 4:
      return r.pick(["", " ", "null", "[]", '"s"', "1", "true", "{", "﻿" + text, text.replace(/"/g, "'")]);
    default:
      return text.replace(/:/, r.bool() ? ":\u0000" : ": ");
  }
}

// --- the run loop ------------------------------------------------------------------------------------

export interface Failure {
  seed: number;
  key: string;
  detail: string;
}

/**
 * Runs `body` for `n` seeds. `body` throws to report a violation (the message is the violation; messages up to
 * the first colon group the failures). Seeds are `base + i`. FUZZ_SEED=<n> runs exactly that seed. The thrown
 * error lists the first few distinct violations with their seeds.
 */
export function fuzz(name: string, n: number, body: (r: Rng, seed: number) => void, o: { base?: number; capSec?: number; minIters?: number } = {}): void {
  // FUZZ_BASE=<n> moves the whole seed range, so a long campaign can explore seeds the default run never reaches.
  const envBase = Number(process.env.FUZZ_BASE);
  const base = Number.isSafeInteger(envBase) && envBase > 0 ? envBase : (o.base ?? 0x5eed);
  // A wall-clock cap per target keeps the default run short on a slow disk (the hook writes files). FUZZ_MAX_SECONDS overrides it.
  const envCap = Number(process.env.FUZZ_MAX_SECONDS);
  const capMs = (Number.isFinite(envCap) && envCap > 0 ? envCap : (o.capSec ?? 20)) * 1000;
  const started = Date.now();
  // FUZZ_TRACE=<file>: the seed about to run is written there first, so a hang (which no time budget can interrupt) names its seed.
  const trace = process.env.FUZZ_TRACE ?? "";
  let ran = 0;
  const only = process.env.FUZZ_SEED !== undefined && process.env.FUZZ_SEED !== "" ? Number(process.env.FUZZ_SEED) : null;
  // Seeds are base + i, generated as the loop goes (a long run's count would not fit in an array).
  const total = only !== null ? 1 : n;
  const seedAt = (i: number): number => (only !== null ? only : base + i);
  const shorten = (m: string): string => m.replace(/(.)\1{30,}/gs, (x, c: string) => `${c}...x${x.length}`).slice(0, 700);
  const failures = new Map<string, Failure & { count: number }>();
  for (let i = 0; i < total; i++) {
    const seed = seedAt(i);
    if (only === null && Date.now() - started > capMs) break;
    ran++;
    if (trace !== "") writeFileSync(trace, `${name} ${seed}\n`);
    try {
      body(new Rng(seed), seed);
    } catch (e) {
      // FUZZ_STACK=1: the stack too, for an exception that is not a stated violation.
      const msg = e instanceof Error ? `${e.message}${process.env.FUZZ_STACK === "1" ? `\n${e.stack ?? ""}` : ""}` : String(e);
      const key = msg.split("\n")[0]?.replace(/[0-9]+/g, "N").slice(0, 100) ?? "error";
      const prior = failures.get(key);
      // FUZZ_REPORT=<file>: every violation's whole message (the report below shortens them).
      if (process.env.FUZZ_REPORT !== undefined && process.env.FUZZ_REPORT !== "") appendFileSync(process.env.FUZZ_REPORT, `${name} seed=${seed}\n${msg}\n\n`);
      if (prior === undefined) failures.set(key, { seed, key, detail: shorten(msg), count: 1 });
      else prior.count++;
    }
  }
  process.stderr.write(`[fuzz] ${name}: ${ran}/${total} inputs in ${((Date.now() - started) / 1000).toFixed(1)}s${ran < total ? " (time cap reached)" : ""}\n`);
  const min = only !== null ? 0 : minIters(total, o.minIters);
  if (failures.size === 0 && ran < min) throw tooFew(name, ran, total, capMs, min);
  if (failures.size > 0) {
    const lines = [...failures.values()].slice(0, 5).map((f) => `  [${name}] seed=${f.seed} (x${f.count}) FUZZ_SEED=${f.seed}\n    ${f.detail.replace(/\n/g, "\n    ")}`);
    throw new Error(`fuzz ${name}: ${failures.size} distinct violation(s) in ${ran} inputs (base seed 0x${base.toString(16)})\n${lines.join("\n")}`);
  }
}

// --- timing ------------------------------------------------------------------------------------------

export interface Timing {
  worst: number;
  worstSeed: number;
}

/** The wall-clock budget in ms for a decision, scaled by SLOW (coverage, CI) and FUZZ_BUDGET_FACTOR (a loaded machine). */
export function budget(ms: number): number {
  const f = Number(process.env.FUZZ_BUDGET_FACTOR);
  return ms * SLOW * (Number.isFinite(f) && f > 0 ? f : 1);
}

/**
 * Runs `f` and returns its result and duration. If it exceeded `limitMs`, runs it once more and keeps the
 * faster run (a noisy neighbour is not a backtracking bug); the caller checks `ms` against the budget.
 */
export function timed<T>(f: () => T, limitMs: number): { value: T; ms: number } {
  const t0 = performance.now();
  const value = f();
  let ms = performance.now() - t0;
  if (ms > limitMs) {
    const t1 = performance.now();
    f();
    ms = Math.min(ms, performance.now() - t1);
  }
  return { value, ms };
}

export const SEVERITY: Record<string, number> = { allow: 0, ask: 1, queue: 2, deny: 3 };

/** The first place two strings differ, with context, for a failure message. */
export function firstDiff(a: string, b: string): string {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  return `differ at ${i}: first=${JSON.stringify(a.slice(Math.max(0, i - 40), i + 80))} second=${JSON.stringify(b.slice(Math.max(0, i - 40), i + 80))}`;
}

/**
 * Runs of ten or more `*` collapsed to three. FZ11 (test/fuzz/found.test.ts): consecutive stars in a path word make the
 * glob matcher backtrack for seconds (30 stars) to minutes (40), so a generated word like that would hang the run itself,
 * which no time budget can interrupt. Everything else about the string is kept.
 */
export function noStarRuns(s: string): string {
  return s.replace(/\*{10,}/g, "***");
}

/**
 * fuzz() for an async body (the local API's targets send requests over a socket). The same seeds, cap,
 * FUZZ_SEED replay, FUZZ_TRACE and failure report; bodies run one at a time.
 */
export async function fuzzAsync(name: string, n: number, body: (r: Rng, seed: number) => Promise<void>, o: { base?: number; capSec?: number; minIters?: number } = {}): Promise<void> {
  // FUZZ_BASE=<n> moves the whole seed range, so a long campaign can explore seeds the default run never reaches.
  const envBase = Number(process.env.FUZZ_BASE);
  const base = Number.isSafeInteger(envBase) && envBase > 0 ? envBase : (o.base ?? 0x5eed);
  const envCap = Number(process.env.FUZZ_MAX_SECONDS);
  const capMs = (Number.isFinite(envCap) && envCap > 0 ? envCap : (o.capSec ?? 20)) * 1000;
  const started = Date.now();
  const trace = process.env.FUZZ_TRACE ?? "";
  let ran = 0;
  const only = process.env.FUZZ_SEED !== undefined && process.env.FUZZ_SEED !== "" ? Number(process.env.FUZZ_SEED) : null;
  // Seeds are base + i, generated as the loop goes (a long run's count would not fit in an array).
  const total = only !== null ? 1 : n;
  const seedAt = (i: number): number => (only !== null ? only : base + i);
  const shorten = (m: string): string => m.replace(/(.)\1{30,}/gs, (x, c: string) => `${c}...x${x.length}`).slice(0, 700);
  const failures = new Map<string, Failure & { count: number }>();
  for (let i = 0; i < total; i++) {
    const seed = seedAt(i);
    if (only === null && Date.now() - started > capMs) break;
    ran++;
    if (trace !== "") writeFileSync(trace, `${name} ${seed}\n`);
    try {
      await body(new Rng(seed), seed);
    } catch (e) {
      // FUZZ_STACK=1: the stack too, for an exception that is not a stated violation.
      const msg = e instanceof Error ? `${e.message}${process.env.FUZZ_STACK === "1" ? `\n${e.stack ?? ""}` : ""}` : String(e);
      const key = msg.split("\n")[0]?.replace(/[0-9]+/g, "N").slice(0, 100) ?? "error";
      const prior = failures.get(key);
      // FUZZ_REPORT=<file>: every violation's whole message (the report below shortens them).
      if (process.env.FUZZ_REPORT !== undefined && process.env.FUZZ_REPORT !== "") appendFileSync(process.env.FUZZ_REPORT, `${name} seed=${seed}\n${msg}\n\n`);
      if (prior === undefined) failures.set(key, { seed, key, detail: shorten(msg), count: 1 });
      else prior.count++;
    }
  }
  process.stderr.write(`[fuzz] ${name}: ${ran}/${total} inputs in ${((Date.now() - started) / 1000).toFixed(1)}s${ran < total ? " (time cap reached)" : ""}\n`);
  const min = only !== null ? 0 : minIters(total, o.minIters);
  if (failures.size === 0 && ran < min) throw tooFew(name, ran, total, capMs, min);
  if (failures.size > 0) {
    const lines = [...failures.values()].slice(0, 5).map((f) => `  [${name}] seed=${f.seed} (x${f.count}) FUZZ_SEED=${f.seed}\n    ${f.detail.replace(/\n/g, "\n    ")}`);
    throw new Error(`fuzz ${name}: ${failures.size} distinct violation(s) in ${ran} inputs (base seed 0x${base.toString(16)})\n${lines.join("\n")}`);
  }
}
