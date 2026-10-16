#!/usr/bin/env node
/**
 * launchsafe-firewall entry point. The only place that reads process.argv;
 * everything else receives the parsed command line (see climain.ts).
 */

import module from "node:module";
import { lstatSync, mkdirSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { insideRealHome } from "./real-home.js";

/**
 * Faster start-up for a process the agent launches on every tool call: V8's compiled code is cached
 * between runs, inside the firewall's own data directory. Not Node's default (the temporary directory),
 * which the agent can write: a forged cache entry there would be code run inside the hook. Only when the
 * firewall home already exists (the firewall creates it, mode 700; this must not create it first), and
 * never a home inside the real home directory under a test marker (SR1: the resolved path decides, not
 * only whether LAUNCHSAFE_FIREWALL_HOME is set). SR2: the home, <home>/cache and <home>/cache/compile
 * must each be a real directory (not a symlink), owned by this user, that no group or other user can
 * write; a missing cache directory is created that way. Any failure means no cache, silently.
 * NODE_COMPILE_CACHE in the environment would already have enabled a cache before this runs, so the
 * installed hook command clears it (SR3, runtime/install.ts hookCommand).
 */
function enableCompileCache(env: NodeJS.ProcessEnv): void {
  try {
    const own = env.LAUNCHSAFE_FIREWALL_HOME;
    const testing = env.LAUNCHSAFE_FIREWALL_TEST === "1" || (env.VITEST ?? "") !== "";
    if ((own === undefined || own === "") && testing) return;
    const home = own !== undefined && own !== "" ? resolve(own) : join(homedir(), ".launchsafe-firewall");
    if (testing && insideRealHome(home)) return;
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    const cache = join(home, "cache");
    const dir = join(cache, "compile");
    for (const p of [home, cache, dir]) if (!privateDir(p, p !== home, uid)) return;
    (module as unknown as { enableCompileCache?: (dir: string) => unknown }).enableCompileCache?.(dir);
  } catch {
    // No firewall home yet, or the cache cannot be made: start without it.
  }
}

/** A directory only this user can change: not a symlink, owned by `uid`, not group- or other-writable (created so when `create` and absent). */
function privateDir(p: string, create: boolean, uid: number | null): boolean {
  let st = lstatSync(p, { throwIfNoEntry: false });
  if (st === undefined) {
    if (!create) return false;
    mkdirSync(p, { mode: 0o700 });
    st = lstatSync(p);
  }
  if (st.isSymbolicLink() || !st.isDirectory()) return false;
  if (uid !== null && st.uid !== uid) return false;
  return (st.mode & 0o022) === 0;
}
enableCompileCache(process.env);

const argv = process.argv.slice(2);
try {
  const { main } = await import("./climain.js");
  process.exitCode = await main(argv);
} catch (e) {
  // R6: an error message can quote a path or input; no control characters reach the terminal.
  // eslint-disable-next-line no-control-regex -- matching control characters is the point
  writeSync(2, `launchsafe-firewall: ${String((e as Error).message).replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`)}\n`);
  // The hook path fails closed (exit 2 blocks the tool); other commands fail plainly.
  process.exitCode = argv[0] === "hook" ? 2 : 1;
}
