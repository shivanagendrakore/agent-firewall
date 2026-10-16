#!/usr/bin/env node
/**
 * Vendors the agent-safety analyzer from the product repository into
 * src/vendor/agent-safety/, so the firewall's SessionStart scan runs the very
 * rules the product's scans and the website's free checker run.
 *
 * LaunchSafe's agent-safety package (packages/agent-safety/src in its product
 * repository, which is not public) owns the rules. The
 * firewall copies its pure, browser-safe files at one commit, each with a
 * header naming its source, its commit and its licence, and never edits them
 * here. The Node file collector (node.ts) and the tests stay in the product;
 * the firewall has its own bounded collector (src/runtime/agentfiles.ts).
 *
 * One transform is applied (until the product
 * package switches to ".js" specifiers): relative import specifiers get ".js"
 * added, because the firewall compiles with moduleResolution nodenext. The
 * header says so, and --check applies the same transform before comparing.
 *
 *   node scripts/sync-agent-safety.mjs [<commit>]   copy at <commit> (default: the app's HEAD)
 *   node scripts/sync-agent-safety.mjs --check      verify the copies match their pinned commit
 *
 * LAUNCHSAFE_APP_DIR points at a checkout of LaunchSafe's product repository (unset: no checkout); only maintainers with that checkout can run the copy or the byte comparison.
 * --check without the product checkout (CI) verifies only that the copies are
 * internally consistent (every header names the pinned commit) and says that
 * the byte comparison was skipped.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const APP = resolve(process.env.LAUNCHSAFE_APP_DIR ?? join(ROOT, ".upstream-checkout-not-set"));
const SOURCE_DIR = "packages/agent-safety/src";
const OUT = join(ROOT, "src", "vendor", "agent-safety");
/** The browser-safe files: no node.ts, no tests. The same list the marketing site vendors. */
const FILES = ["analyze.ts", "canonical.ts", "drift.ts", "index.ts", "jsonc.ts", "launch.ts", "paths.ts", "pin.ts", "receipt.ts", "rules.ts", "signals.ts", "summary.ts", "types.ts"];
const TRANSFORM = 'add ".js" to relative import specifiers';

const PIN_FILE = join(ROOT, "src", "vendor", "agent-safety-commit.ts");
const pinText = (commit) =>
  [
    "// Written by scripts/sync-agent-safety.mjs: the upstream agent-safety commit src/vendor/agent-safety/ is vendored at.",
    "// Do not edit by hand.",
    `export const AGENT_SAFETY_COMMIT = "${commit}";`,
    "",
  ].join("\n");

const header = (file, commit) =>
  [
    `// Vendored from LaunchSafe's agent-safety package (src/${file}), Apache-2.0, at commit ${commit}.`,
    "// Licence: Apache-2.0 (see NOTICE).",
    `// Transform: ${TRANSFORM}.`,
    "// Do not edit here: it is copied from the upstream package by",
    "// `node scripts/sync-agent-safety.mjs` (`--check` verifies the copy).",
    "",
    "",
  ].join("\n");

/** `from "./x"` / `import("./x")` -> "./x.js"; specifiers that already name an extension are kept. */
function addJs(source) {
  return source.replace(/(\bfrom\s+|\bimport\s*\(\s*)(["'])(\.{1,2}\/[^"']+?)\2/g, (m, lead, q, spec) => (/\.(?:js|mjs|cjs|json)$/.test(spec) ? m : `${lead}${q}${spec}.js${q}`));
}

const git = (...args) => execFileSync("git", ["-C", APP, ...args], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
const vendored = (file, commit) => header(file, commit) + addJs(git("show", `${commit}:${SOURCE_DIR}/${file}`));

function pinnedCommit() {
  const text = existsSync(join(OUT, "index.ts")) ? readFileSync(join(OUT, "index.ts"), "utf8") : "";
  return /at commit ([0-9a-f]{40})\./.exec(text)?.[1] ?? null;
}

if (process.argv[2] === "--check") {
  const pinned = pinnedCommit();
  if (pinned === null) {
    console.error("src/vendor/agent-safety/index.ts names no commit.");
    process.exit(1);
  }
  let drift = 0;
  if (!existsSync(PIN_FILE) || readFileSync(PIN_FILE, "utf8") !== pinText(pinned)) {
    console.error(`drift: src/vendor/agent-safety-commit.ts does not name ${pinned}`);
    drift += 1;
  }
  const haveApp = existsSync(join(APP, ".git"));
  for (const file of FILES) {
    const path = join(OUT, file);
    if (!existsSync(path)) {
      console.error(`drift: ${file} is missing`);
      drift += 1;
      continue;
    }
    const have = readFileSync(path, "utf8");
    if (!have.startsWith(header(file, pinned))) {
      console.error(`drift: ${file} does not carry the header for ${pinned}`);
      drift += 1;
      continue;
    }
    if (haveApp && have !== vendored(file, pinned)) {
      console.error(`drift: ${file} differs from ${SOURCE_DIR}/${file} at ${pinned} (after the transform)`);
      drift += 1;
    }
  }
  if (drift > 0) process.exit(1);
  if (haveApp) console.info(`agent-safety: ${FILES.length} files match the upstream package at ${pinned}.`);
  else console.info(`agent-safety: no upstream checkout at ${APP}; headers name ${pinned}, byte comparison skipped (set LAUNCHSAFE_APP_DIR to compare).`);
} else {
  if (!existsSync(join(APP, ".git"))) {
    console.error(`No upstream checkout at ${APP}. Set LAUNCHSAFE_APP_DIR.`);
    process.exit(1);
  }
  const commit = git("rev-parse", process.argv[2] ?? "HEAD").trim();
  mkdirSync(OUT, { recursive: true });
  for (const file of FILES) writeFileSync(join(OUT, file), vendored(file, commit));
  writeFileSync(PIN_FILE, pinText(commit));
  console.info(`agent-safety: copied ${FILES.length} files from the upstream package at ${commit}.`);
}
