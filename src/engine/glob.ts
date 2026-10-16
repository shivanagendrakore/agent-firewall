/**
 * A small, strict glob matcher: `**` crosses directories, `*` and `?` do not,
 * `{a,b}` alternates. No character classes on purpose: a `[` in a pattern is literal.
 *
 * FZ11/FZ1: patterns come from commands an attacker can shape (`cat ********Q`, a 100,000-character
 * word), so this is not a regular expression. A pattern compiles to a small automaton (consecutive
 * stars collapse into one) that is run over the text one character at a time with the set of states it
 * can be in: time is linear in the text times the pattern, with no backtracking. Each call also has a
 * deterministic work bound; past it, or for a pattern longer than MAX_PATTERN, the caller's fail-closed
 * answer is returned instead of a guess.
 */

/** Patterns longer than this are not compiled: the caller's fail-closed answer stands. */
export const MAX_PATTERN = 4096;
/** State visits allowed per match (about a hundred milliseconds of work at the very worst). */
const MAX_STEPS = 4_000_000;

type State =
  | { k: "char"; ch: string; next: number }
  /** One character that is not "/" (`?`, and the step of `*`). */
  | { k: "one"; next: number }
  /** One character, "/" included (the step of `**`). */
  | { k: "any"; next: number }
  | { k: "split"; outs: number[] }
  | { k: "match" };

type Node = { t: "char"; ch: string } | { t: "q" } | { t: "star" } | { t: "globstar" } | { t: "dirs" } | { t: "alt"; alts: Node[][] };

interface Compiled {
  kind: Uint8Array;
  /** A character state's character, and its case-folded form. */
  code: Int32Array;
  folded: Int32Array;
  next: Int32Array;
  outs: (number[] | undefined)[];
  start: number;
  closures: (Int32Array | undefined)[];
  /** Literal text every match starts and ends with; `literal` when the whole pattern is that text. */
  prefix: string;
  suffix: string;
  literal: boolean;
  /** Literal runs between the pattern's wildcards, as written and case-folded: each must occur in a match. */
  inner: string[];
  innerFolded: string[];
}

const cache = new Map<string, Compiled>();
const CACHE_MAX = 2048;

/** The index of every "{" that a later "}" closes (an alternation, not a literal brace). */
function closers(pattern: string): Set<number> {
  const open: number[] = [];
  const closed = new Set<number>();
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i] === "{") open.push(i);
    else if (pattern[i] === "}" && open.length > 0) closed.add(open.pop() as number);
  }
  return closed;
}

function parse(pattern: string): Node[] {
  const alternation = closers(pattern);
  const root: Node[][] = [[]];
  const stack: Node[][][] = [];
  let seq = root;
  const cur = (): Node[] => seq[seq.length - 1] as Node[];
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i] as string;
    if (c === "*") {
      // Read in pairs, as the regular expression this replaced did: "**/" is zero or more directories, "**"
      // crosses directories, "*" does not. Adjacent stars collapse ("*" next to "**" is "**"), so a run of
      // stars costs one state however long it is.
      let node: Node;
      if (pattern[i + 1] === "*" && pattern[i + 2] === "/") {
        node = { t: "dirs" };
        i += 2;
      } else if (pattern[i + 1] === "*") {
        node = { t: "globstar" };
        i += 1;
      } else node = { t: "star" };
      const last = cur()[cur().length - 1];
      if (node.t !== "dirs" && last !== undefined && (last.t === "star" || last.t === "globstar")) {
        if (node.t === "globstar") cur()[cur().length - 1] = node;
      } else cur().push(node);
    } else if (c === "?") {
      cur().push({ t: "q" });
    } else if (c === "{" && alternation.has(i)) {
      stack.push(seq);
      seq = [[]];
    } else if (c === "}" && stack.length > 0) {
      const alts = seq;
      seq = stack.pop() as Node[][];
      cur().push({ t: "alt", alts });
    } else if (c === "," && stack.length > 0) {
      seq.push([]);
    } else {
      cur().push({ t: "char", ch: c });
    }
  }
  // A brace left open closes here.
  while (stack.length > 0) {
    const alts = seq;
    seq = stack.pop() as Node[][];
    cur().push({ t: "alt", alts });
  }
  return root[0] as Node[];
}

/** Upper-case form of one UTF-16 code unit (the fold a case-insensitive regular expression used). */
function fold(code: number): number {
  if (code < 128) return code >= 97 && code <= 122 ? code - 32 : code;
  // Lower first when that stays one character: the Kelvin sign (U+212A) is its own upper case but is "k" on APFS.
  const s = String.fromCharCode(code);
  const low = s.toLowerCase();
  const up = (low.length === 1 ? low : s).toUpperCase();
  return up.length === 1 ? up.charCodeAt(0) : code;
}

const K_MATCH = 0;
const K_CHAR = 1;
const K_ONE = 2;
const K_ANY = 3;
const K_SPLIT = 4;

function compile(pattern: string): Compiled {
  const states: State[] = [{ k: "match" }];
  const add = (s: State): number => states.push(s) - 1;
  // Built back to front: each node is compiled with the state that follows it.
  const seq = (nodes: readonly Node[], next: number): number => {
    let at = next;
    for (let i = nodes.length - 1; i >= 0; i--) at = node(nodes[i] as Node, at);
    return at;
  };
  const loop = (k: "one" | "any", next: number): number => {
    const split = add({ k: "split", outs: [] });
    const step = add({ k, next: split });
    (states[split] as { outs: number[] }).outs = [step, next];
    return split;
  };
  const node = (n: Node, next: number): number => {
    switch (n.t) {
      case "char":
        return add({ k: "char", ch: n.ch, next });
      case "q":
        return add({ k: "one", next });
      case "star":
        return loop("one", next);
      case "globstar":
        return loop("any", next);
      case "dirs": {
        // (?:.*/)? : nothing, or anything ending in "/".
        const slash = add({ k: "char", ch: "/", next });
        return add({ k: "split", outs: [next, loop("any", slash)] });
      }
      case "alt":
        return add({ k: "split", outs: n.alts.map((a) => seq(a, next)) });
    }
  };
  const nodes = parse(pattern);
  const start = seq(nodes, 0);
  const n = states.length;
  const kind = new Uint8Array(n);
  const code = new Int32Array(n);
  const folded = new Int32Array(n);
  const next = new Int32Array(n);
  const outs: (number[] | undefined)[] = new Array<number[] | undefined>(n);
  states.forEach((st, i) => {
    switch (st.k) {
      case "match":
        kind[i] = K_MATCH;
        break;
      case "char":
        kind[i] = K_CHAR;
        code[i] = st.ch.charCodeAt(0);
        folded[i] = fold(code[i] as number);
        next[i] = st.next;
        break;
      case "one":
      case "any":
        kind[i] = st.k === "one" ? K_ONE : K_ANY;
        next[i] = st.next;
        break;
      case "split":
        kind[i] = K_SPLIT;
        outs[i] = st.outs;
        break;
    }
  });
  // Literal text the pattern starts and ends with: a cheap test that turns most paths away before the automaton runs.
  let p = 0;
  while (p < nodes.length && (nodes[p] as Node).t === "char") p++;
  let q = nodes.length;
  while (q > p && (nodes[q - 1] as Node).t === "char") q--;
  const text = (from: number, to: number): string => nodes.slice(from, to).map((x) => (x as { ch: string }).ch).join("");
  const inner: string[] = [];
  let run = "";
  for (let i = p; i < q; i++) {
    const x = nodes[i] as Node;
    if (x.t === "char") run += x.ch;
    else {
      if (run.length >= 2) inner.push(run);
      run = "";
    }
  }
  if (run.length >= 2) inner.push(run);
  return { kind, code, folded, next, outs, start, closures: new Array<Int32Array | undefined>(n), prefix: text(0, p), suffix: p === nodes.length ? "" : text(q, nodes.length), literal: p === nodes.length, inner, innerFolded: inner.map(foldText) };
}

function compiled(pattern: string): Compiled {
  const hit = cache.get(pattern);
  if (hit !== undefined) return hit;
  const out = compile(pattern);
  if (cache.size >= CACHE_MAX) cache.clear();
  cache.set(pattern, out);
  return out;
}

function foldText(t: string): string {
  let out = "";
  for (let i = 0; i < t.length; i++) out += String.fromCharCode(fold(t.charCodeAt(i)));
  return out;
}

/** The last text folded (the same path is matched against many patterns in a row). */
let lastFold: { text: string; folded: string } = { text: "", folded: "" };
function foldedOf(t: string): string {
  if (lastFold.text !== t) lastFold = { text: t, folded: foldText(t) };
  return lastFold.folded;
}

function sameText(a: string, b: string, at: number, caseInsensitive: boolean): boolean {
  if (at < 0 || at + a.length > b.length) return false;
  for (let i = 0; i < a.length; i++) {
    const x = a.charCodeAt(i);
    const y = b.charCodeAt(at + i);
    if (x !== y && !(caseInsensitive && fold(x) === fold(y))) return false;
  }
  return true;
}

/** The states reachable from `s` without reading a character (splits left out), computed once per state. */
function closureOf(c: Compiled, s: number, budget: { steps: number }): Int32Array | null {
  const hit = c.closures[s];
  if (hit !== undefined) return hit;
  const out: number[] = [];
  const seen = new Set<number>();
  const stack = [s];
  while (stack.length > 0) {
    const x = stack.pop() as number;
    if (seen.has(x)) continue;
    seen.add(x);
    if (++budget.steps > MAX_STEPS) return null;
    if (c.kind[x] === K_SPLIT) {
      const o = c.outs[x] as number[];
      for (let i = o.length - 1; i >= 0; i--) stack.push(o[i] as number);
    } else out.push(x);
  }
  const arr = Int32Array.from(out);
  // Kept for small automata only, so a pathological pattern cannot hold quadratic memory.
  if (c.kind.length <= 1024) c.closures[s] = arr;
  return arr;
}

/**
 * Whether `path` matches `pattern`: true or false, or null when the pattern is too long or the work
 * bound ran out (the caller decides what failing closed means where it asks).
 */
export function globMatchBounded(pattern: string, path: string, caseInsensitive: boolean): boolean | null {
  if (pattern.length > MAX_PATTERN) return null;
  const c = compiled(pattern);
  if (c.literal) return c.prefix.length === path.length && sameText(c.prefix, path, 0, caseInsensitive);
  if (!sameText(c.prefix, path, 0, caseInsensitive) || !sameText(c.suffix, path, path.length - c.suffix.length, caseInsensitive)) return false;
  if (c.inner.length > 0) {
    const hay = caseInsensitive ? foldedOf(path) : path;
    const needles = caseInsensitive ? c.innerFolded : c.inner;
    for (const x of needles) if (!hay.includes(x)) return false;
  }
  const budget = { steps: 0 };
  const n = c.kind.length;
  const mark = new Int32Array(n);
  let gen = 1;
  let cur = new Int32Array(n);
  let nxt = new Int32Array(n);
  let count = 0;
  const first = closureOf(c, c.start, budget);
  if (first === null) return null;
  for (const t of first) cur[count++] = t;
  for (let i = 0; i < path.length; i++) {
    if (count === 0) return false;
    const ch = path.charCodeAt(i);
    const fch = caseInsensitive ? fold(ch) : ch;
    gen++;
    let m = 0;
    for (let j = 0; j < count; j++) {
      const s = cur[j] as number;
      const k = c.kind[s];
      const ok = k === K_CHAR ? c.code[s] === ch || (caseInsensitive && c.folded[s] === fch) : k === K_ONE ? ch !== 47 : k === K_ANY;
      if (!ok) continue;
      const clo = closureOf(c, c.next[s] as number, budget);
      if (clo === null) return null;
      for (const t of clo) {
        if (mark[t] === gen) continue;
        mark[t] = gen;
        nxt[m++] = t;
      }
      budget.steps += clo.length;
      if (budget.steps > MAX_STEPS) return null;
    }
    [cur, nxt] = [nxt, cur];
    count = m;
  }
  for (let j = 0; j < count; j++) if (c.kind[cur[j] as number] === K_MATCH) return true;
  return false;
}

/**
 * Whether `path` matches `pattern`. `onLimit` is the answer when that cannot be worked out within the
 * bounds: true (the default) where a match is the stricter reading (a protected path, a blocked tool).
 */
export function globMatch(pattern: string, path: string, caseInsensitive: boolean, onLimit = true): boolean {
  return globMatchBounded(pattern, path, caseInsensitive) ?? onLimit;
}

/** Whether one character can satisfy state `i` of `x` and state `j` of `y` (neither a split nor the match). */
function shareCharacter(x: Compiled, i: number, y: Compiled, j: number, caseInsensitive: boolean): boolean {
  const ki = x.kind[i];
  const kj = y.kind[j];
  if (ki === K_CHAR && kj === K_CHAR) return x.code[i] === y.code[j] || (caseInsensitive && x.folded[i] === y.folded[j]);
  // A character state against `?`/`*` (any character but "/") or `**` (any character).
  if (ki === K_CHAR) return kj === K_ANY || x.code[i] !== 47;
  if (kj === K_CHAR) return ki === K_ANY || y.code[j] !== 47;
  return true;
}

/**
 * Whether some text matches both patterns: a glob an agent wrote (`ssh_host_*`) and one of the firewall's
 * (`ssh_host_*_key`). The two automata are run side by side over the pairs of states they can be in, so the work
 * is bounded by the product of the patterns' sizes, and by the same deterministic step bound as a match; past it,
 * or for a pattern longer than MAX_PATTERN, `onLimit` is the answer (true by default: they may overlap).
 */
export function globsOverlap(a: string, b: string, caseInsensitive: boolean, onLimit = true): boolean {
  if (a.length > MAX_PATTERN || b.length > MAX_PATTERN) return onLimit;
  const x = compiled(a);
  const y = compiled(b);
  const budget = { steps: 0 };
  const width = y.kind.length;
  const seen = new Set<number>();
  const stack: number[] = [];
  const push = (xs: Int32Array, ys: Int32Array): boolean => {
    budget.steps += xs.length * ys.length;
    if (budget.steps > MAX_STEPS) return false;
    for (const i of xs) {
      for (const j of ys) {
        const k = i * width + j;
        if (seen.has(k)) continue;
        seen.add(k);
        stack.push(k);
      }
    }
    return true;
  };
  const sx = closureOf(x, x.start, budget);
  const sy = closureOf(y, y.start, budget);
  if (sx === null || sy === null || !push(sx, sy)) return onLimit;
  while (stack.length > 0) {
    const k = stack.pop() as number;
    const i = Math.floor(k / width);
    const j = k % width;
    const done = x.kind[i] === K_MATCH;
    if (done && y.kind[j] === K_MATCH) return true;
    if (done || y.kind[j] === K_MATCH || !shareCharacter(x, i, y, j, caseInsensitive)) continue;
    const nx = closureOf(x, x.next[i] as number, budget);
    const ny = closureOf(y, y.next[j] as number, budget);
    if (nx === null || ny === null || !push(nx, ny)) return onLimit;
  }
  return false;
}
