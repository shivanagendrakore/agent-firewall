/**
 * Typosquat check. A requested package name that is not a known
 * package but sits right next to a popular one: one edit away (two for long
 * names), the same after folding separators, digit/letter look-alikes, an
 * added or dropped scope, or a popular name with a common prefix or suffix
 * stuck on. Pure, deterministic, offline: the lists ship with the package
 * (src/data/popular-*.ts, regenerated at release by scripts/gen-popular.mjs).
 */

import type { Ecosystem } from "./packages.js";
import { normalizeName } from "./packages.js";
import { POPULAR, type PopularList } from "../data/popular.js";

export interface Lookalike {
  lookalike: string;
  how: string;
}

interface Index {
  targets: string[];
  targetSet: Set<string>;
  known: Set<string>;
  folded: Map<string, string>;
  confusable: Map<string, string>;
  byLength: Map<number, string[]>;
}

const cache = new Map<Ecosystem, Index | null>();

/** Separators folded away: `lodash.merge`, `lodash-merge` and `lodash_merge` compare equal. */
function fold(s: string): string {
  return s.replace(/[-_.]/g, "");
}

/** Digit/letter look-alikes mapped to one form (0/o, 1/l, rn/m, vv/w). */
function deconfuse(s: string): string {
  return s.replace(/0/g, "o").replace(/1/g, "l").replace(/rn/g, "m").replace(/vv/g, "w");
}

function build(eco: Ecosystem, list: PopularList): Index {
  const targets = [...new Set(list.targets.map((t) => normalizeName(eco, t)))];
  const targetSet = new Set(targets);
  const known = new Set([...targets, ...list.known.map((t) => normalizeName(eco, t))]);
  const folded = new Map<string, string>();
  const confusable = new Map<string, string>();
  const byLength = new Map<number, string[]>();
  for (const t of targets) {
    if (!folded.has(fold(t))) folded.set(fold(t), t);
    const d = deconfuse(fold(t));
    if (!confusable.has(d)) confusable.set(d, t);
    const l = byLength.get(t.length) ?? [];
    l.push(t);
    byLength.set(t.length, l);
  }
  return { targets, targetSet, known, folded, confusable, byLength };
}

function index(eco: Ecosystem): Index | null {
  if (!cache.has(eco)) {
    const list = POPULAR[eco];
    cache.set(eco, list === undefined ? null : build(eco, list));
  }
  return cache.get(eco) ?? null;
}

/**
 * Optimal-string-alignment distance (Damerau-Levenshtein with adjacent transpositions), stopping as
 * soon as it must exceed `max`. Returns max + 1 when over.
 */
export function editDistance(a: string, b: string, max: number): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  if (a === b) return 0;
  const n = a.length;
  const m = b.length;
  let prev2 = new Array<number>(m + 1).fill(0);
  let prev = Array.from({ length: m + 1 }, (_, j) => j);
  let cur = new Array<number>(m + 1).fill(0);
  for (let i = 1; i <= n; i++) {
    cur[0] = i;
    let rowMin = cur[0];
    for (let j = 1; j <= m; j++) {
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
      let v = Math.min((prev[j] as number) + 1, (cur[j - 1] as number) + 1, (prev[j - 1] as number) + cost);
      if (i > 1 && j > 1 && a.charCodeAt(i - 1) === b.charCodeAt(j - 2) && a.charCodeAt(i - 2) === b.charCodeAt(j - 1)) v = Math.min(v, (prev2[j - 2] as number) + 1);
      cur[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    [prev2, prev, cur] = [prev, cur, prev2];
  }
  return prev[m] as number;
}

/** Edit distance is only meaningful for names this long: short names sit one letter from many others. */
const MIN_EDIT_LENGTH = 5;

const AFFIXES: Partial<Record<Ecosystem, { prefixes: string[]; suffixes: string[] }>> = {
  npm: { prefixes: ["node-", "js-"], suffixes: ["-js", ".js", "js", "-node", "-npm"] },
  PyPI: { prefixes: ["python-", "py-", "py"], suffixes: ["-python", "-py", "py", "-lib"] },
  "crates.io": { prefixes: ["rust-"], suffixes: ["-rs", "-rust"] },
  RubyGems: { prefixes: ["ruby-"], suffixes: ["-ruby", "-rb"] },
};

/** The popular package a requested name imitates, or null. Names on the known list never match. */
export function typosquatOf(eco: Ecosystem, rawName: string): Lookalike | null {
  const idx = index(eco);
  if (idx === null) return null;
  const n = normalizeName(eco, rawName);
  if (n === "" || idx.known.has(n)) return null;

  const f = idx.folded.get(fold(n));
  if (f !== undefined && f !== n) return { lookalike: f, how: "the same name with different separators" };
  const d = idx.confusable.get(deconfuse(fold(n)));
  if (d !== undefined && d !== n) return { lookalike: d, how: "look-alike characters (0/o, 1/l, rn/m)" };

  if (eco === "npm") {
    const scoped = /^@([^/]+)\/(.+)$/.exec(n);
    if (scoped !== null) {
      const joined = `${scoped[1]}-${scoped[2]}`;
      if (idx.targetSet.has(joined)) return { lookalike: joined, how: "a scope added to the name" };
    } else {
      const dash = n.indexOf("-");
      if (dash > 0) {
        const asScope = `@${n.slice(0, dash)}/${n.slice(dash + 1)}`;
        if (idx.targetSet.has(asScope)) return { lookalike: asScope, how: "the scope dropped from the name" };
      }
    }
  }

  const aff = AFFIXES[eco];
  if (aff !== undefined) {
    for (const p of aff.prefixes) if (n.startsWith(p) && n.length > p.length + 2 && idx.targetSet.has(n.slice(p.length))) return { lookalike: n.slice(p.length), how: `the popular name with "${p}" in front` };
    for (const s of aff.suffixes) if (n.endsWith(s) && n.length > s.length + 2 && idx.targetSet.has(n.slice(0, -s.length))) return { lookalike: n.slice(0, -s.length), how: `the popular name with "${s}" added` };
  }

  if (n.length < MIN_EDIT_LENGTH) return null;
  const max = n.length >= 10 ? 2 : 1;
  for (let len = n.length - max; len <= n.length + max; len++) {
    for (const t of idx.byLength.get(len) ?? []) {
      if (t.length < MIN_EDIT_LENGTH) continue;
      const allowed = Math.min(max, t.length >= 10 ? 2 : 1);
      if (editDistance(n, t, allowed) <= allowed) return { lookalike: t, how: allowed === 1 ? "one letter different" : "two letters different" };
    }
  }
  return null;
}
