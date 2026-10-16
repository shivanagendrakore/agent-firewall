/** Symlink resolution for paths that may not exist yet. */

import { lstatSync, readlinkSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

/** Errors that mean "this part does not exist (yet)": the rest of the path is kept as written. */
function missing(e: unknown): boolean {
  const code = (e as NodeJS.ErrnoException).code;
  return code === "ENOENT" || code === "ENOTDIR";
}

/** How many dangling symlinks one resolution follows before it gives up (the kernel's own limit is similar). */
const MAX_LINKS = 40;

/**
 * SELF-016: the canonical form of a path that may not exist yet: the realpath of its longest existing
 * prefix plus the remaining components. A dangling symlink on the way is followed to where it points
 * (writing through it creates that file). Throws when the path cannot be resolved for any reason other
 * than a missing part (a symlink loop, a directory it may not search, a name too long), so a caller can
 * fail closed instead of judging the path as written.
 */
export function realpathStrict(p: string, links = 0): string {
  if (links > MAX_LINKS) throw Object.assign(new Error(`too many symbolic links resolving ${p}`), { code: "ELOOP" });
  let cur = p;
  const rest: string[] = [];
  for (let i = 0; i < 4096; i++) {
    try {
      const real = realpathSync.native(cur);
      return rest.length === 0 ? real : join(real, ...[...rest].reverse());
    } catch (e) {
      if (!missing(e)) throw e;
      let link: string | null = null;
      try {
        if (lstatSync(cur).isSymbolicLink()) link = readlinkSync(cur);
      } catch (e2) {
        if (!missing(e2)) throw e2;
      }
      if (link !== null) {
        // A relative target is read from the link's real directory: the kernel resolves the directory's own links first.
        const from = link.startsWith("/") ? dirname(cur) : realpathStrict(dirname(cur), links + 1);
        return realpathStrict(join(resolve(from, link), ...[...rest].reverse()), links + 1);
      }
      const parent = dirname(cur);
      if (parent === cur) return p;
      rest.push(cur.slice(parent.length + (parent.endsWith("/") ? 0 : 1)));
      cur = parent;
    }
  }
  return p;
}

/** Resolves symlinks for a path that may not exist yet; on any error, the path as written. */
export function realpathLoose(p: string): string {
  try {
    return realpathStrict(p);
  } catch {
    return p;
  }
}
