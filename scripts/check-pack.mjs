// The package-contents check of the release workflow (.github/workflows/release.yml, RELEASING.md):
//
//   npm pack --dry-run --ignore-scripts --json > pack.json
//   node scripts/check-pack.mjs pack.json
//
// It prints the file list and fails (exit 1, with a GitHub ::error:: line) when the package would contain
// anything from test/, conformance/, browser/ or python/, or would lack a file it needs: every file
// package.json points at (main, types, bin, exports), the hook bundle, README.md, LICENSE, NOTICE, and
// every file under docs/ (README.md and the CLI's messages link there).
//
// The Onest font's licence is also named on its own. src/ui/font.ts embeds the font, NOTICE says its
// licence is docs/licenses/Onest-OFL.txt, and the OFL requires the licence to travel with the font, so
// moving or deleting that file from docs/ must fail here rather than drop it from the package unnoticed.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const FONT_LICENCE = "docs/licenses/Onest-OFL.txt";

const listing = process.argv[2];
if (listing === undefined) {
  console.error("usage: node scripts/check-pack.mjs <the output of npm pack --dry-run --json>");
  process.exit(2);
}

/**
 * Files under dir, relative to the package root with "/" separators (none when dir is gone; the font's
 * licence is still required). Dotfiles (a Finder .DS_Store, an editor's swap file) are never packed by npm,
 * so they are not required.
 */
function walk(dir) {
  if (!existsSync(join(root, dir))) return [];
  return readdirSync(join(root, dir), { withFileTypes: true })
    .filter((e) => !e.name.startsWith("."))
    .flatMap((e) => (e.isDirectory() ? walk(`${dir}/${e.name}`) : [`${dir}/${e.name}`]));
}

const [packed] = JSON.parse(readFileSync(listing, "utf8"));
const files = packed.files.map((f) => f.path).sort();
for (const f of files) console.log(f);
console.log(`${files.length} files, ${packed.size} bytes packed, ${packed.unpackedSize} bytes unpacked`);

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const targets = [pkg.main, pkg.types, ...Object.values(pkg.bin ?? {}), ...Object.values(pkg.exports ?? {}).flatMap((e) => (typeof e === "string" ? [e] : Object.values(e)))];
const wanted = [...new Set([...targets.map((t) => t.replace(/^\.\//, "")), "dist/hook/bundle.js", "README.md", "LICENSE", "NOTICE", ...walk("docs"), FONT_LICENCE])];
const banned = files.filter((f) => /^(test|conformance|browser|python)\//.test(f));
const missing = wanted.filter((f) => !files.includes(f));
if (banned.length > 0) {
  console.log(`::error::The package would contain ${banned.join(", ")}. Fix "files" in package.json.`);
  process.exitCode = 1;
}
if (missing.length > 0) {
  console.log(`::error::The package would lack ${missing.join(", ")}.`);
  process.exitCode = 1;
}
