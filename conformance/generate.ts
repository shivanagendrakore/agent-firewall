/**
 * Writes conformance/vectors/*.json: the vector skeletons in author/ run through the in-process library
 * (run.ts), with what it said recorded as each step's `expect`. Nothing is guessed: every expected value is
 * the engine's. Run `npm run conformance:generate`; --check compares without writing (exit 1 on a difference).
 */

import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { groups } from "./author/index.js";
import { runVectorRoutes, type Vector } from "./run.js";

/**
 * The file text: two-space JSON with every character outside ASCII written as a \uXXXX escape (UTF-16 code units,
 * so a character outside the BMP is its surrogate pair). Invisible and direction-changing characters in a vector
 * then show in a diff and survive any tool that rewrites text.
 */
function vectorFileText(vectors: readonly Vector[]): string {
  return `${JSON.stringify(vectors, null, 2).replace(/[^\t\n\r\x20-\x7e]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`)}\n`;
}

const here = dirname(fileURLToPath(import.meta.url));
// Compiled to dist-conformance/conformance/: the vectors live next to the sources.
const root = here.includes("dist-conformance") ? join(here, "..", "..", "conformance") : here;
const dir = join(root, "vectors");

const check = process.argv.includes("--check");
const files: Record<string, string> = {};
const ids = new Set<string>();
for (const [name, skeletons] of Object.entries(groups())) {
  const vectors: Vector[] = skeletons.map((s) => {
    if (ids.has(s.id)) throw new Error(`duplicate vector id ${s.id}`);
    ids.add(s.id);
    const { expects, api } = runVectorRoutes({ ...s, steps: s.steps.map((st) => ({ ...st, expect: {} })) });
    const last = s.steps.length - 1;
    api.forEach((x, i) => {
      // A step after one the API refuses would start from a different state on the two routes.
      if (x !== undefined && i !== last) throw new Error(`${s.id} step ${i}: the API refuses this step, so it must be the vector's last`);
    });
    return { ...s, steps: s.steps.map((st, i) => ({ ...st, expect: expects[i] ?? {}, ...(api[i] !== undefined ? { expectApi: api[i] } : {}) })) };
  });
  files[`${name}.json`] = vectorFileText(vectors);
}

if (check) {
  const have = new Set(readdirSync(dir).filter((f) => f.endsWith(".json")));
  const bad = [...new Set([...have, ...Object.keys(files)])].filter((f) => files[f] === undefined || !have.has(f) || readFileSync(join(dir, f), "utf8") !== files[f]);
  if (bad.length > 0) {
    console.error(`conformance vectors are stale: ${bad.join(", ")} (run npm run conformance:generate)`);
    process.exit(1);
  }
  console.log(`conformance vectors are current (${ids.size} vectors in ${Object.keys(files).length} files)`);
} else {
  mkdirSync(dir, { recursive: true });
  for (const f of readdirSync(dir)) if (f.endsWith(".json") && files[f] === undefined) rmSync(join(dir, f));
  for (const [f, text] of Object.entries(files)) writeFileSync(join(dir, f), text);
  console.log(`wrote ${ids.size} vectors in ${Object.keys(files).length} files to ${dir}`);
}
