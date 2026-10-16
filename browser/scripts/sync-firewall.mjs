#!/usr/bin/env node
/**
 * Vendors the browser-safe scanner modules of the LaunchSafe Agent Firewall
 * (the coding-agent firewall) into src/vendor/firewall/, so the extension's
 * content guard and leak guard run the very scanners the firewall's MCP
 * gateway and email guard run.
 *
 * The extension lives in browser/ of the Agent Firewall repository, so the
 * source is the repository root (`..`). Files are copied byte for byte from
 * one commit (read with `git show <commit>:<path>`, never from the working
 * tree), each with a header naming its source path, the commit and the
 * licence. They are never edited here. The relative layout is kept (engine/,
 * vendor/agent-safety/, own.ts), so no import specifier is rewritten. Commit a
 * change to a scanner first, then sync at that commit.
 *
 * One file is an extract, not a copy: src/types.ts in the firewall is its whole
 * policy model, and pii.ts needs only its `DataKind` type. types.ts here holds
 * just that declaration, taken verbatim; its header says so.
 *
 *   node scripts/sync-firewall.mjs [<commit>]   copy at <commit> (default: HEAD)
 *   node scripts/sync-firewall.mjs --check      verify the copies match their pinned commit
 *
 * LAUNCHSAFE_FIREWALL_DIR overrides the source checkout (default: the
 * repository root, `..`). --check always verifies that every header names the
 * pinned commit and that the vendored set is closed (every relative import
 * resolves inside it). It compares bytes with the pinned commit when that
 * commit is in the checkout, and says so when it skips (no checkout, or a
 * shallow clone without the commit). test/unit/vendor-firewall.test.ts
 * compares the copies with the working tree's src/ on every test run.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, posix, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FIREWALL = resolve(process.env.LAUNCHSAFE_FIREWALL_DIR ?? join(ROOT, ".."));
const OUT = join(ROOT, "src", "vendor", "firewall");
const PIN_FILE = join(ROOT, "src", "vendor", "firewall-commit.ts");

/** Upstream path (in the firewall repo) -> path under src/vendor/firewall/. */
const FILES = [
  ["src/own.ts", "own.ts"],
  ["src/engine/bytes.ts", "engine/bytes.ts"],
  ["src/engine/network.ts", "engine/network.ts"],
  ["src/engine/secrets.ts", "engine/secrets.ts"],
  ["src/engine/pii.ts", "engine/pii.ts"],
  ["src/engine/content-html.ts", "engine/content-html.ts"],
  ["src/engine/content-lexicon.ts", "engine/content-lexicon.ts"],
  ["src/engine/content-scan.ts", "engine/content-scan.ts"],
  ["src/vendor/agent-safety/signals.ts", "vendor/agent-safety/signals.ts"],
];
/** Extracts: upstream path -> [local path, the exported declarations taken verbatim]. */
const EXTRACTS = [["src/types.ts", "types.ts", ["DataKind"]]];

const header = (source, commit, note) =>
  [
    `// Vendored from the LaunchSafe Agent Firewall (${source}), Apache-2.0, at commit ${commit}.`,
    "// Licence: Apache-2.0 (see NOTICE).",
    ...(note ? [`// ${note}`] : []),
    "// Do not edit here: it is copied from the firewall repository by",
    "// `node scripts/sync-firewall.mjs` (`--check` verifies the copy).",
    "",
    "",
  ].join("\n");

const pinText = (commit) =>
  [
    "// Written by scripts/sync-firewall.mjs: the firewall commit src/vendor/firewall/ is vendored at.",
    "// Do not edit by hand.",
    `export const FIREWALL_COMMIT = "${commit}";`,
    "",
  ].join("\n");

const git = (...args) => execFileSync("git", ["-C", FIREWALL, ...args], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });

/** Whether the checkout holds `commit` as a commit object. */
function hasCommit(commit) {
  try {
    execFileSync("git", ["-C", FIREWALL, "cat-file", "-e", `${commit}^{commit}`], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/** One `export type|interface|const|function NAME` declaration, up to its terminating line. */
function extractDeclaration(source, name) {
  const lines = source.split("\n");
  const start = lines.findIndex((l) => new RegExp(`^export (?:type|interface|const|function) ${name}\\b`).test(l));
  if (start === -1) throw new Error(`declaration ${name} not found`);
  const out = [];
  for (let i = start; i < lines.length; i++) {
    out.push(lines[i]);
    if (/;\s*$/.test(lines[i]) || /^}\s*$/.test(lines[i])) break;
  }
  return out.join("\n");
}

function expected(commit) {
  const files = new Map();
  for (const [src, dst] of FILES) files.set(dst, header(src, commit) + git("show", `${commit}:${src}`));
  for (const [src, dst, names] of EXTRACTS) {
    const body = git("show", `${commit}:${src}`);
    const note = `Extract: only ${names.join(", ")}, verbatim; the rest of ${src} is the firewall's policy model and is not needed.`;
    files.set(dst, header(src, commit, note) + names.map((n) => extractDeclaration(body, n)).join("\n\n") + "\n");
  }
  return files;
}

function listVendored(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...listVendored(p));
    else out.push(relative(OUT, p).split("\\").join("/"));
  }
  return out.sort();
}

/** Every relative import in the vendored set resolves to a vendored file. */
function closureProblems(localPaths) {
  const have = new Set(localPaths);
  const problems = [];
  for (const file of localPaths) {
    const text = readFileSync(join(OUT, file), "utf8");
    for (const m of text.matchAll(/\bfrom\s+["'](\.{1,2}\/[^"']+)["']/g)) {
      const target = posix.normalize(posix.join(posix.dirname(file), m[1].replace(/\.js$/, ".ts")));
      if (!have.has(target)) problems.push(`${file} imports ${m[1]}, which is not vendored`);
    }
  }
  return problems;
}

const allLocal = [...FILES.map(([, d]) => d), ...EXTRACTS.map(([, d]) => d)].sort();

if (process.argv[2] === "--check") {
  const pinned = /FIREWALL_COMMIT = "([0-9a-f]{40})"/.exec(existsSync(PIN_FILE) ? readFileSync(PIN_FILE, "utf8") : "")?.[1];
  if (pinned === undefined) {
    console.error("src/vendor/firewall-commit.ts names no commit.");
    process.exit(1);
  }
  const problems = [];
  const present = listVendored(OUT);
  for (const f of present) if (!allLocal.includes(f)) problems.push(`unexpected file src/vendor/firewall/${f} (add it to FILES or remove it)`);
  for (const f of allLocal) if (!present.includes(f)) problems.push(`missing src/vendor/firewall/${f}`);
  for (const [src, dst] of FILES) {
    if (!present.includes(dst)) continue;
    if (!readFileSync(join(OUT, dst), "utf8").startsWith(header(src, pinned))) problems.push(`${dst} does not carry the header for ${pinned}`);
  }
  for (const [src, dst] of EXTRACTS) {
    if (!present.includes(dst)) continue;
    if (!readFileSync(join(OUT, dst), "utf8").includes(`(${src}), Apache-2.0, at commit ${pinned}.`)) problems.push(`${dst} does not carry the header for ${pinned}`);
  }
  problems.push(...closureProblems(present.filter((f) => allLocal.includes(f))));
  const haveCheckout = existsSync(join(FIREWALL, ".git"));
  const havePin = haveCheckout && hasCommit(pinned);
  // A shallow clone (CI's default) may not hold the pinned commit; a full one must.
  const shallow = haveCheckout && !havePin && git("rev-parse", "--is-shallow-repository").trim() === "true";
  if (haveCheckout && !havePin && !shallow) problems.push(`src/vendor/firewall-commit.ts names ${pinned}, which is not in ${FIREWALL}`);
  if (havePin && problems.length === 0) {
    for (const [dst, want] of expected(pinned)) {
      if (readFileSync(join(OUT, dst), "utf8") !== want) problems.push(`${dst} differs from the firewall at ${pinned}`);
    }
  }
  if (problems.length > 0) {
    for (const p of problems) console.error(`drift: ${p}`);
    process.exit(1);
  }
  const skipped = "headers name it and the set is closed; byte comparison with it skipped (test/unit/vendor-firewall.test.ts compares the copies with ../src)";
  if (havePin) console.info(`firewall: ${allLocal.length} files match the firewall at ${pinned}.`);
  else if (shallow) console.info(`firewall: ${FIREWALL} is a shallow clone without ${pinned}; ${skipped}.`);
  else console.info(`firewall: no checkout at ${FIREWALL} for ${pinned}; ${skipped}.`);
} else {
  if (!existsSync(join(FIREWALL, ".git"))) {
    console.error(`No git checkout of the firewall at ${FIREWALL} (is browser/ outside a clone of the repository?). Set LAUNCHSAFE_FIREWALL_DIR.`);
    process.exit(1);
  }
  const commit = git("rev-parse", process.argv[2] ?? "HEAD").trim();
  for (const [dst, text] of expected(commit)) {
    mkdirSync(dirname(join(OUT, dst)), { recursive: true });
    writeFileSync(join(OUT, dst), text);
  }
  writeFileSync(PIN_FILE, pinText(commit));
  const problems = closureProblems(allLocal);
  if (problems.length > 0) {
    for (const p of problems) console.error(`open set: ${p}`);
    process.exit(1);
  }
  console.info(`firewall: copied ${allLocal.length} files from the firewall at ${commit}.`);
}
