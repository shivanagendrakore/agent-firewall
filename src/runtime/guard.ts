/**
 * The test-home guard. Commands that change the machine (install, uninstall,
 * the approver key, policy files, recordings) refuse to write under the real
 * home directory while a test marker is set, so a test that forgets to pass a
 * temporary home cannot touch the developer's own Claude Code settings or the
 * firewall's real state. In production (no marker) it does nothing.
 *
 * "Real home" comes from the password database (os.userInfo), not from $HOME,
 * because a test that moved $HOME is exactly the case being checked.
 */

import { tmpdir, userInfo } from "node:os";
import { resolve } from "node:path";
import { isUnder, PROTECTION_FOLDS_CASE } from "../engine/paths.js";
import { realpathLoose } from "./realpath.js";

export class RealHomeRefused extends Error {
  constructor(readonly target: string) {
    super(`refusing to write ${target}: it is under the real home directory and a test marker (LAUNCHSAFE_FIREWALL_TEST or VITEST) is set`);
    this.name = "RealHomeRefused";
  }
}

export interface GuardDeps {
  userInfo?: () => { homedir: string };
  tmpdir?: () => string;
}

/** Whether the test marker is set: the guard is active only then. */
export function testMarker(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.LAUNCHSAFE_FIREWALL_TEST === "1" || (env.VITEST !== undefined && env.VITEST !== "");
}

function norm(p: string): string[] {
  const abs = resolve(p);
  return [...new Set([abs, realpathLoose(abs)])];
}

/** Throws RealHomeRefused when a test would write `target` under the real home directory. */
export function assertNotRealHome(target: string, env: NodeJS.ProcessEnv = process.env, deps: GuardDeps = {}): void {
  if (!testMarker(env)) return;
  const ci = process.platform === "darwin" || process.platform === "win32";
  const allowed = [(deps.tmpdir ?? tmpdir)(), ...(env.LAUNCHSAFE_FIREWALL_TEST_ROOT !== undefined && env.LAUNCHSAFE_FIREWALL_TEST_ROOT !== "" ? [env.LAUNCHSAFE_FIREWALL_TEST_ROOT] : [])].flatMap(norm);
  const targets = norm(target);
  const inAllowed = targets.every((t) => allowed.some((a) => isUnder(t, a, ci)));
  if (inAllowed) return;
  let realHome: string | null = null;
  try {
    realHome = (deps.userInfo ?? userInfo)().homedir;
  } catch {
    realHome = null;
  }
  // No password entry (containers): we cannot tell where the real home is, so only temporary
  // directories are allowed while testing. Stricter, never looser.
  if (realHome === null || realHome === "") throw new RealHomeRefused(target);
  const homes = norm(realHome);
  // I1: what counts as the real home ignores case on every platform (PROTECTION_FOLDS_CASE); what counts as the
  // temporary directory above follows the platform, so a differently-spelled path is never let through as a temp one.
  if (targets.some((t) => homes.some((h) => isUnder(t, h, PROTECTION_FOLDS_CASE)))) throw new RealHomeRefused(target);
}
