/**
 * Runs once before the workers start. The temporary home was created by
 * vitest.config.ts; here it is checked (the run fails if anything still
 * resolves to the real home), dist/ is built for the subprocess tests, and the
 * directory is removed at the end.
 */
import { execFileSync } from "node:child_process";
import { rmSync } from "node:fs";
import { homedir, tmpdir, userInfo } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

export default function setup(): () => void {
  const root = process.env.LAUNCHSAFE_FIREWALL_TEST_ROOT ?? "";
  const real = (() => {
    try {
      return userInfo().homedir;
    } catch {
      return null;
    }
  })();
  const problems: string[] = [];
  if (process.env.LAUNCHSAFE_FIREWALL_TEST !== "1" || root === "") problems.push("the test marker or test root is not set (vitest.config.ts must run first)");
  if (!resolve(root).startsWith(resolve(tmpdir())) && !resolve(root).startsWith("/tmp") && !resolve(root).startsWith("/private")) problems.push(`the test root ${root} is not in the temporary directory`);
  for (const k of ["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "CLAUDE_CONFIG_DIR", "LAUNCHSAFE_FIREWALL_HOME"]) {
    const v = process.env[k] ?? "";
    if (v === "" || !resolve(v).startsWith(resolve(root))) problems.push(`${k}=${v} is not inside the test root`);
  }
  if (real !== null && resolve(homedir()) === resolve(real)) problems.push("os.homedir() still returns the real home directory");
  if (problems.length > 0) throw new Error(`Refusing to run the test suite against the real home directory:\n- ${problems.join("\n- ")}`);
  const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  // Same as npm run build: an empty dist/ first, so a module whose source is gone cannot pass a subprocess test.
  execFileSync(process.execPath, ["scripts/clean-dist.mjs"], { cwd: repo, stdio: "ignore" });
  execFileSync("npx", ["tsc", "-p", "tsconfig.build.json"], { cwd: repo, stdio: "ignore" });
  // Same as npm run build: the CLI must stay a runnable binary after the suite rebuilds dist.
  execFileSync(process.execPath, ["scripts/chmod-bin.mjs"], { cwd: repo, stdio: "ignore" });
  // And the hook bundle, so the subprocess tests run the hook the way it ships.
  execFileSync(process.execPath, ["scripts/bundle-hook.mjs"], { cwd: repo, stdio: "ignore" });
  return () => rmSync(root, { recursive: true, force: true });
}
