/**
 * I1: the hook's root of trust does not come from its environment. The home directory every hook path reads
 * (agent settings, MCP lists, the default firewall home) is the user database's (os.userInfo), not HOME, which
 * an agent's settings `env` can set for the commands it starts. A HOME that differs from the user database's is
 * reported so the hook can deny the tool call (FW-TAMPER): installs pin HOME in the hook command, so a different
 * one means something rewrote the command or the environment around it.
 *
 * Tests: while a test marker is set (LAUNCHSAFE_FIREWALL_TEST, VITEST) a HOME inside the temporary directory or the
 * test root is taken as given, so the suite never reads or writes the developer's real home. Nothing else is
 * exempt: a marker with a HOME anywhere else is judged like production.
 */

import { homedir, tmpdir, userInfo } from "node:os";
import { resolve } from "node:path";
import { isUnder } from "../engine/paths.js";
import { testMarker } from "./guard.js";
import { realpathLoose } from "./realpath.js";

export interface HomeDeps {
  userInfo?: () => { homedir: string };
  tmpdir?: () => string;
}

export interface TrustedHome {
  /** The home directory the hook reads. */
  home: string;
  /** Why HOME cannot be trusted (it differs from the user database's), or null. */
  tamper: string | null;
}

const ci = process.platform === "darwin" || process.platform === "win32";

function same(a: string, b: string): boolean {
  const n = (p: string): string[] => [...new Set([resolve(p), realpathLoose(resolve(p))])].map((x) => (ci ? x.toLowerCase() : x).replace(/\/+$/, ""));
  const nb = n(b);
  return n(a).some((x) => nb.includes(x));
}

/** A test home: a test marker is set and HOME lies in the temporary directory or the test root. */
function testHome(env: NodeJS.ProcessEnv, home: string, deps: HomeDeps): boolean {
  if (!testMarker(env)) return false;
  const roots = [(deps.tmpdir ?? tmpdir)(), ...(env.LAUNCHSAFE_FIREWALL_TEST_ROOT !== undefined && env.LAUNCHSAFE_FIREWALL_TEST_ROOT !== "" ? [env.LAUNCHSAFE_FIREWALL_TEST_ROOT] : [])];
  const at = [resolve(home), realpathLoose(resolve(home))];
  return at.every((p) => roots.some((r) => isUnder(p, resolve(r), ci) || isUnder(p, realpathLoose(resolve(r)), ci)));
}

/** The home directory the hook trusts, and whether HOME disagrees with it. */
export function trustedHome(env: NodeJS.ProcessEnv = process.env, deps: HomeDeps = {}): TrustedHome {
  const envHome = env.HOME !== undefined && env.HOME !== "" ? env.HOME : undefined;
  let passwd: string | null = null;
  try {
    const h = (deps.userInfo ?? userInfo)().homedir;
    passwd = h !== "" ? h : null;
  } catch {
    passwd = null;
  }
  if (envHome !== undefined && testHome(env, envHome, deps)) return { home: envHome, tamper: null };
  // No user database entry (some containers): nothing to compare with; HOME is all there is.
  if (passwd === null) return { home: envHome ?? homedir(), tamper: null };
  if (envHome === undefined || same(envHome, passwd)) return { home: passwd, tamper: null };
  return { home: passwd, tamper: `HOME is ${envHome.slice(0, 200)}, but this user's home directory is ${passwd.slice(0, 200)}: something changed the hook's environment, which could point the firewall at other settings, keys or state` };
}
