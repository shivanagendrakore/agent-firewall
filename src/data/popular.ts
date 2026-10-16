/**
 * The popular-package lists the typosquat check compares against, one file per
 * ecosystem. `targets` are the names worth imitating; `known` are further real
 * packages that must never be flagged (a near neighbour of a target that is
 * itself legitimate, such as preact next to react).
 *
 * Each file records its source and date. The lists are regenerated at release
 * time by scripts/gen-popular.mjs (network at build time only; the maintainers' release checklist)
 * and committed, so the decision path never needs the network.
 */

import type { Ecosystem } from "../engine/packages.js";
import { NPM } from "./popular-npm.js";
import { PYPI } from "./popular-pypi.js";
import { CRATES } from "./popular-crates.js";
import { RUBYGEMS } from "./popular-rubygems.js";

export interface PopularList {
  source: string;
  date: string;
  targets: readonly string[];
  known: readonly string[];
}

export const POPULAR: Partial<Record<Ecosystem, PopularList>> = {
  npm: NPM,
  PyPI: PYPI,
  "crates.io": CRATES,
  RubyGems: RUBYGEMS,
};
