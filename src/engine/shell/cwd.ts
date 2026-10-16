/**
 * F-f: the directory a shell would be in at each point of one command line.
 * cd, pushd and popd move a cursor for the pipelines that follow in the same
 * scope; a subshell's cd ends with the subshell; a cd inside a multi-stage
 * pipeline does not persist (each stage is a subshell). When the target cannot
 * be known the cursor becomes unknown (UNKNOWN_CWD): relative writes are then
 * unresolvable and relative reads are judged by their names only.
 */

import { bindingVariants, type Collector } from "../effects.js";
import { isUnder, resolvePath, UNKNOWN_CWD } from "../paths.js";
import type { Word } from "./parse.js";

export interface Cwd {
  known: boolean;
  path: string;
  stack: string[];
  oldpwd: string | null;
  /**
   * After a cd joined by ";" or "||" (it may have failed), the directory the shell was in before: later
   * pipelines are judged under both and the worse reading wins.
   */
  alt: string | null;
}

export function startCwd(path: string, known = true): Cwd {
  return { known, path, stack: [], oldpwd: null, alt: null };
}

export function copyCwd(c: Cwd): Cwd {
  return { ...c, stack: [...c.stack] };
}

const unknown = (cur: Cwd): Cwd => ({ ...cur, known: false, path: UNKNOWN_CWD, oldpwd: cur.path, stack: [...cur.stack] });

/** The directory a cd argument names, or null when it cannot be known. "scratch" for a temp dir. */
function target(cur: Cwd, w: Word, c: Collector): string | "scratch" | null {
  const text = w.text;
  if (text === "-") return cur.oldpwd;
  if (/^"?\$\{?(?:TMPDIR|TMP|TEMP|RUNNER_TEMP)\}?(?:\/.*)?$/.test(text) || /^\$\(\s*mktemp\b[^)]*\)$/.test(text)) return "scratch";
  if (/^\$\(\s*git\s+rev-parse\s+--show-toplevel\s*\)$/.test(text)) {
    return c.ctx.workspaceRoots.find((r) => cur.known && isUnder(cur.path, r, c.ctx.caseInsensitive)) ?? (cur.known ? cur.path : null);
  }
  let t = text;
  if (/^\$\{?OLDPWD\}?(?=\/|$)/.test(t)) {
    if (cur.oldpwd === null) return null;
    t = t.replace(/^\$\{?OLDPWD\}?/, cur.oldpwd);
  }
  const variants = bindingVariants(c, t);
  if (variants.length !== 1) return null;
  t = variants[0] as string;
  const r = resolvePath(t, { cwd: cur.path, home: c.ctx.home });
  if (r === null || !r.exact || r.glob) return null;
  if (!cur.known && !t.startsWith("/") && !t.startsWith("~") && !/^\$\{?(?:HOME|PWD)\}?/.test(t)) return null;
  return r.abs;
}

/** The cursor after a cd/pushd/popd (args are the words after the builtin). */
export function applyCd(cur: Cwd, name: string, args: readonly Word[], c: Collector): Cwd {
  const pos = args.filter((a) => !/^-[LPe@]+$/.test(a.text) && a.text !== "--");
  const move = (to: string | "scratch" | null, extra: Partial<Cwd> = {}): Cwd => {
    if (to === null) return { ...unknown(cur), ...extra };
    if (to === "scratch") {
      const root = c.ctx.scratchRoots[0];
      return root === undefined ? { ...unknown(cur), ...extra } : { known: true, path: `${root.replace(/\/+$/, "")}/__computed_temp_dir__`, stack: [...cur.stack], oldpwd: cur.path, alt: null, ...extra };
    }
    return { known: true, path: to, stack: [...cur.stack], oldpwd: cur.path, alt: null, ...extra };
  };
  if (name === "popd") {
    if (pos.some((a) => /^[+-]\d+$/.test(a.text))) return unknown(cur);
    const top = cur.stack[cur.stack.length - 1];
    if (top === undefined) return cur;
    const next = move(top);
    next.stack = cur.stack.slice(0, -1);
    return next;
  }
  if (name === "pushd") {
    if (pos.length === 0) {
      const top = cur.stack[cur.stack.length - 1];
      if (top === undefined) return cur;
      const next = move(top);
      next.stack = [...cur.stack.slice(0, -1), cur.path];
      return next;
    }
    if (/^[+-]\d+$/.test(pos[0]?.text ?? "")) return unknown(cur);
    const w = pos[0] as Word;
    const next = move(w.dynamic && !/^\$/.test(w.text) && !/^~/.test(w.text) ? null : target(cur, w, c));
    next.stack = [...cur.stack, cur.path];
    return next;
  }
  // cd
  if (pos.length === 0) return move(c.ctx.home);
  return move(target(cur, pos[0] as Word, c));
}

/** cd, pushd, popd, also behind `builtin` or `command`. Returns the builtin and its arguments. */
export function cdCommand(words: readonly Word[]): { name: string; args: readonly Word[] } | null {
  let ws = words;
  while (ws.length > 0 && !(ws[0] as Word).quoted && ((ws[0] as Word).text === "builtin" || (ws[0] as Word).text === "command")) ws = ws.slice(1);
  const w0 = ws[0];
  if (w0 === undefined || w0.quoted) return null;
  if (w0.text === "cd" || w0.text === "pushd" || w0.text === "popd" || w0.text === "chdir") return { name: w0.text === "chdir" ? "cd" : w0.text, args: ws.slice(1) };
  return null;
}
