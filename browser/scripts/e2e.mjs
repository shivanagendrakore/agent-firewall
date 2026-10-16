#!/usr/bin/env node
/**
 * Runs Playwright with the browsers cache pinned to the OS default under the
 * real home directory (os.userInfo().homedir), so it works when HOME points at
 * a throwaway folder (the safe-run sandbox) without downloading a second copy.
 *
 *   node scripts/e2e.mjs                     playwright test
 *   node scripts/e2e.mjs install chromium    playwright install chromium
 */
import { spawnSync } from "node:child_process";
import { userInfo } from "node:os";
import { join } from "node:path";

function defaultBrowsersPath() {
  const home = userInfo().homedir;
  if (process.platform === "darwin") return join(home, "Library", "Caches", "ms-playwright");
  if (process.platform === "win32") return join(process.env.LOCALAPPDATA ?? join(home, "AppData", "Local"), "ms-playwright");
  return join(home, ".cache", "ms-playwright");
}

const env = { ...process.env, PLAYWRIGHT_BROWSERS_PATH: process.env.PLAYWRIGHT_BROWSERS_PATH ?? defaultBrowsersPath() };
const args = process.argv.slice(2);
const cmd = args[0] === "install" ? ["playwright", ...args] : ["playwright", "test", ...args];
const r = spawnSync("npx", cmd, { stdio: "inherit", env });
process.exit(r.status ?? 1);
