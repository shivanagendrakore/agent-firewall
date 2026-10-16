/**
 * Builds the v0.2 firewall (git ref v0.2/final) into a temporary directory, once per process, so a test can install with the
 * old CLI and then with this one. Dependencies are this repository's own node_modules (v0.2 needs nothing more).
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, realpathSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { REPO } from "./lab.js";

export const V02_REF = process.env.LSFW_V02_REF ?? "v0.2/final";

let built: string | null | undefined;

/** Why the upgrade tests skip, or null when the ref exists in this clone. The public repository carries no v0.2 history. */
export function v02SkipReason(): string | null {
  try {
    execFileSync("git", ["rev-parse", "--verify", "--quiet", `${V02_REF}^{commit}`], { cwd: REPO, stdio: "ignore" });
    return null;
  } catch {
    return `the git ref ${V02_REF} is not in this clone: fetch it (or set LSFW_V02_REF) to run the v0.2 upgrade tests`;
  }
}

/** The path of v0.2's dist/cli.js, or null when the ref does not exist in this clone. */
export function v02Cli(): string | null {
  if (built !== undefined) return built;
  try {
    execFileSync("git", ["rev-parse", "--verify", "--quiet", `${V02_REF}^{commit}`], { cwd: REPO, stdio: "ignore" });
  } catch {
    built = null;
    return built;
  }
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "lsfw-v02-")));
  execFileSync("sh", ["-c", `git archive ${JSON.stringify(V02_REF)} | tar -x -C ${JSON.stringify(dir)}`], { cwd: REPO });
  symlinkSync(join(REPO, "node_modules"), join(dir, "node_modules"));
  execFileSync(process.execPath, [join(REPO, "node_modules", "typescript", "bin", "tsc"), "-p", "tsconfig.build.json"], { cwd: dir, stdio: "pipe" });
  const cli = join(dir, "dist", "cli.js");
  if (!existsSync(cli)) throw new Error(`the v0.2 build produced no ${cli}`);
  built = cli;
  return built;
}
