/**
 * Whether a path is the real home directory or inside it. Kept apart from cli.ts (which calls it before anything
 * else is loaded) so a test can reach it: it imports only Node's own modules.
 */

import { realpathSync } from "node:fs";
import { userInfo } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";

/**
 * Whether `p`, symlinks resolved as far as they exist, is the real home directory (from the user database, not
 * HOME) or inside it. `realHome` is given by tests; the default is the user database's.
 *
 * I1: case is folded on every platform (PROTECTION_FOLDS_CASE, engine/canonical.ts): a home on a case-insensitive
 * mount is still the home, and a refusal here can only grow. The engine is not imported, so the rule is written out.
 */
export function insideRealHome(p: string, realHome: string = userInfo().homedir): boolean {
  const real = (x: string): string => {
    try {
      return realpathSync(x);
    } catch {
      return resolve(x);
    }
  };
  const fold = (x: string): string => x.toLowerCase();
  const home = fold(real(realHome));
  // Nearest existing ancestor, so a home that does not exist yet still resolves through its parents' links.
  let at = resolve(p);
  let rest = "";
  for (;;) {
    try {
      at = realpathSync(at);
      break;
    } catch {
      const parent = dirname(at);
      if (parent === at) break;
      rest = rest === "" ? basename(at) : join(basename(at), rest);
      at = parent;
    }
  }
  const full = fold(rest === "" ? at : join(at, rest));
  return full === home || full.startsWith(home.endsWith(sep) ? home : `${home}${sep}`);
}
