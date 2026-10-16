#!/usr/bin/env node
/**
 * Builds the unpacked MV3 extension into dist/:
 *   worker.js (ESM service worker), content.js (IIFE content script),
 *   sidepanel.js / popup.js (IIFE), the HTML and CSS, and manifest.json
 *   generated from src/manifest.ts (the one source of the permission list).
 *
 * No network, no remote code: everything is bundled. Stale files in dist/ are
 * removed one by one (only files this build does not write).
 */
import { build } from "esbuild";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// LAUNCHSAFE_DIST lets the build test write to a temp folder instead of dist/.
const DIST = process.env.LAUNCHSAFE_DIST ? resolve(process.env.LAUNCHSAFE_DIST) : join(ROOT, "dist");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

const common = {
  bundle: true,
  target: "chrome121",
  platform: "browser",
  legalComments: "inline",
  sourcemap: false,
  minify: false,
  logLevel: "warning",
  // The vendored scanner reads performance.now(); nothing else from the environment.
  define: { "process.env.NODE_ENV": '"production"' },
};

const entries = [
  { in: "src/worker/index.ts", out: "worker.js", format: "esm" },
  { in: "src/content/index.ts", out: "content.js", format: "iife" },
  { in: "src/ui/sidepanel.ts", out: "sidepanel.js", format: "iife" },
  { in: "src/ui/popup.ts", out: "popup.js", format: "iife" },
  { in: "src/ui/approval.ts", out: "approval.js", format: "iife" },
  { in: "src/ui/blocked.ts", out: "blocked.js", format: "iife" },
];
const statics = ["src/ui/sidepanel.html", "src/ui/popup.html", "src/ui/approval.html", "src/ui/limits.html", "src/ui/blocked.html", "src/ui/style.css"];

/** Evaluates src/manifest.ts (bundled in memory) to get the manifest object. */
async function manifest() {
  const r = await build({ ...common, entryPoints: [join(ROOT, "src/manifest.ts")], format: "esm", platform: "neutral", write: false });
  const code = r.outputFiles[0].text;
  const mod = await import(`data:text/javascript;base64,${Buffer.from(code).toString("base64")}`);
  // LAUNCHSAFE_E2E_NATIVE: the link e2e test's build only (into a temp LAUNCHSAFE_DIST, never dist/).
  const e2eNative = process.env.LAUNCHSAFE_E2E_NATIVE === "1";
  if (e2eNative && !process.env.LAUNCHSAFE_DIST) throw new Error("LAUNCHSAFE_E2E_NATIVE builds go to a temp LAUNCHSAFE_DIST only");
  return mod.buildManifest({ version: pkg.version, ...(e2eNative ? { e2eGrantNativeMessaging: true } : {}) });
}

/** The navigation policy's static ruleset, from the engine's one source (src/engine/nav-rules.ts). */
async function alwaysRules() {
  const r = await build({ ...common, entryPoints: [join(ROOT, "src/engine/nav-rules.ts")], format: "esm", platform: "neutral", write: false });
  const mod = await import(`data:text/javascript;base64,${Buffer.from(r.outputFiles[0].text).toString("base64")}`);
  return mod.ALWAYS_RULES;
}

mkdirSync(DIST, { recursive: true });
const written = new Set(["manifest.json", "rules.json"]);

for (const e of entries) {
  await build({ ...common, entryPoints: [join(ROOT, e.in)], outfile: join(DIST, e.out), format: e.format });
  written.add(e.out);
}
for (const s of statics) {
  const name = s.split("/").pop();
  copyFileSync(join(ROOT, s), join(DIST, name));
  written.add(name);
}
// Apache-2.0 requires the licence and notice to travel with a redistributed build (the bundle holds Apache-2.0 vendored code
// and the Public Suffix List data, MPL-2.0).
for (const name of ["LICENSE", "NOTICE"]) {
  copyFileSync(join(ROOT, name), join(DIST, name));
  written.add(name);
}
mkdirSync(join(DIST, "icons"), { recursive: true });
for (const f of ["icon-16.png", "icon-32.png", "icon-48.png", "icon-128.png"]) copyFileSync(join(ROOT, "icons", f), join(DIST, "icons", f));
writeFileSync(join(DIST, "manifest.json"), JSON.stringify(await manifest(), null, 2) + "\n");
writeFileSync(join(DIST, "rules.json"), JSON.stringify(await alwaysRules(), null, 2) + "\n");

for (const name of existsSync(DIST) ? readdirSync(DIST) : []) {
  const p = join(DIST, name);
  if (!written.has(name) && statSync(p).isFile()) unlinkSync(p);
}

// No remote code: refuse a bundle that names an http(s) script or calls eval-like APIs.
for (const e of entries) {
  const code = readFileSync(join(DIST, e.out), "utf8");
  if (/\bimportScripts\s*\(\s*["']https?:|\bimport\s*\(\s*["']https?:|\bnew Function\s*\(|\beval\s*\(/.test(code)) {
    console.error(`build: ${e.out} contains remote code or eval; refusing.`);
    process.exit(1);
  }
}
console.info(`build: dist/ written (${[...written].sort().join(", ")}).`);
