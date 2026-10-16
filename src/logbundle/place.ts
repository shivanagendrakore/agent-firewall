/**
 * Where a person may put an export or an anchor: never inside the firewall's own directory. An anchor there is
 * worthless (whoever can rewrite the log can rewrite it too), and a bundle written there is a file the agent's
 * hooks protect, made by a command that is not the log's.
 */

import { resolve } from "node:path";
import { isUnder, PROTECTION_FOLDS_CASE } from "../engine/paths.js";
import type { Layout } from "../runtime/layout.js";
import { realpathLoose } from "../runtime/realpath.js";

/** Whether the path (resolved, symbolic links in existing parts followed) is inside the firewall's directory, ignoring case (I1). */
export function insideFirewallHome(l: Layout, path: string): boolean {
  const ci = PROTECTION_FOLDS_CASE;
  const home = [resolve(l.home), realpathLoose(resolve(l.home))];
  const target = [resolve(path), realpathLoose(resolve(path))];
  return target.some((t) => home.some((h) => isUnder(t, h, ci)));
}
