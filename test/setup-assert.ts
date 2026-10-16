/**
 * F-a: every test file starts here. If the home directory still resolves to
 * the real one (a pool that did not inherit the environment, a test that put
 * HOME back), the whole file fails before any test can write there.
 */
import { homedir, userInfo } from "node:os";
import { resolve } from "node:path";

export function realHomeProblem(home: string, real: () => string): string | null {
  let r: string;
  try {
    r = real();
  } catch {
    return process.env.LAUNCHSAFE_FIREWALL_TEST === "1" ? null : "no test marker and no password entry to compare against";
  }
  if (resolve(home) === resolve(r)) return `the home directory for this test file is the real one (${r})`;
  if (process.env.LAUNCHSAFE_FIREWALL_TEST !== "1") return "LAUNCHSAFE_FIREWALL_TEST is not set";
  return null;
}

const problem = realHomeProblem(homedir(), () => userInfo().homedir);
if (problem !== null) throw new Error(`Refusing to run against the real home directory: ${problem}. Run the suite with "npm test", which moves HOME into a temporary directory.`);
