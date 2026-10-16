/**
 * SELF-016: canonical forms of paths. Pure: symlink resolution is injected through Context.realpath.
 * Kept apart from paths.ts so identity.ts can use it without an import cycle.
 */

import type { Context } from "../types.js";

/** Removes ".", "..", and repeated slashes. Input must be absolute. */
export function normalizeAbs(p: string): string {
  const out: string[] = [];
  for (const seg of p.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") out.pop();
    else out.push(seg);
  }
  return `/${out.join("/")}`;
}

// --- canonical forms (SELF-016) --------------------------------------------------------------------
// A protected location is the same place whatever name reaches it: a symlinked alias (/tmp and
// /private/tmp on macOS, a user's own link), a relative path after a cd, a program's -C/--prefix.
// Every comparison against a protected location looks at the path as written and at its canonical
// form (the realpath of its longest existing prefix plus the rest; comparisons fold case, see
// PROTECTION_FOLDS_CASE below), and the locations themselves are compared in both forms too. A path
// that cannot be resolved (a symlink loop, a directory the user may not search) is possibly
// protected: the caller fails closed.

/**
 * I1: protected locations are matched with case folded, on every platform. Whether `claude.md` and `CLAUDE.md` are
 * one file is a property of the directory, not of the operating system: WSL2 with a workspace on /mnt/c (NTFS), a
 * FAT, exFAT or SMB mount, a macOS volume mounted into a Linux container, and an ext4 or NTFS directory marked
 * case-insensitive all look like Linux to Node, and the hook cannot ask the directory. So a path is compared with
 * the firewall's lists of dangerous places (protected files, persistence points, secrets, credential stores, the
 * firewall's own directory, agent settings) ignoring case: a different spelling of a protected name is judged as
 * the protected name. The cost is a question about a look-alike that is a separate file on a case-sensitive disk
 * (`docs/agents.md` on Linux).
 *
 * Only comparisons that REFUSE or ASK use this. A comparison that grants trust (is the path inside the workspace,
 * the scratch directory or a trusted read root, did the agent write this file itself) keeps the platform's rule
 * (`Context.caseInsensitive`): folding there would let a differently-spelled directory pass as the trusted one.
 * So does a match on these lists that grants trust: a read or a listing outside the workspace of the agent's own
 * settings, a credential store or the firewall's own files is not outside content, and whether it is one is decided
 * by `classifyAsSpelled` (paths.ts), so `agents.md` in someone else's directory on Linux still taints the session;
 * and a read-only command of the firewall's own CLI runs unjudged only when the program is the installed file as
 * spelled (`program` in shell/analyze.ts).
 */
export const PROTECTION_FOLDS_CASE = true;

type Resolver = (absPath: string) => string;

/** Canonical forms of the firewall's own roots and the patterns' literal prefixes, per resolver (a context's lifetime). */
const canonCache = new WeakMap<Resolver, Map<string, string | null>>();
const CANON_CACHE_MAX = 4096;

/** The canonical form of a configured location (a root, a pattern's literal prefix), or null when it cannot be resolved. Cached. */
export function canonicalOf(p: string, ctx: Pick<Context, "realpath">): string | null {
  const rp = ctx.realpath;
  if (rp === undefined || !p.startsWith("/")) return p;
  let m = canonCache.get(rp);
  if (m === undefined) {
    m = new Map();
    canonCache.set(rp, m);
  }
  const hit = m.get(p);
  if (hit !== undefined) return hit;
  let out: string | null;
  try {
    out = normalizeAbs(rp(p));
  } catch {
    out = null;
  }
  if (m.size >= CANON_CACHE_MAX) m.clear();
  m.set(p, out);
  return out;
}

/** A list of configured locations with each one's canonical form added (where it differs and resolves). */
export function withCanonical(list: readonly string[], ctx: Pick<Context, "realpath">): string[] {
  if (ctx.realpath === undefined) return [...list];
  const out = new Set(list);
  for (const p of list) {
    const c = canonicalOf(p, ctx);
    if (c !== null) out.add(c);
  }
  return [...out];
}

export interface PathForms {
  /** The path as written first, then its canonical form(s) where they differ. */
  paths: string[];
  /** False when a form could not be resolved (a symlink loop, no permission): treat the path as possibly protected. */
  known: boolean;
}

/**
 * The forms of a target path to compare against protected locations: as written, canonical, and, for a
 * path with ".." after a name, the canonical form of the physical path. Not cached: the agent can change
 * what a link points to between two actions. Without a resolver (the engine as a library), the path as written.
 */
export function pathForms(abs: string, ctx: Pick<Context, "realpath">, physical?: string): PathForms {
  const paths = [abs];
  let known = true;
  if (ctx.realpath === undefined) return { paths, known };
  for (const p of physical !== undefined && physical !== abs ? [abs, physical] : [abs]) {
    try {
      const real = normalizeAbs(ctx.realpath(p));
      if (!paths.includes(real)) paths.push(real);
    } catch {
      known = false;
    }
  }
  return { paths, known };
}

