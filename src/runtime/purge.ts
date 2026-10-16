/**
 * `uninstall --purge` deletes the firewall's data directory. That directory comes from LAUNCHSAFE_FIREWALL_HOME
 * when set, which may be anything (a relative "." is the working directory), so the delete happens only when the
 * directory is plainly the firewall's: a real directory (not a symbolic link) that holds the firewall's own files,
 * and none of the places whose loss would be a disaster (the root, a home directory, the working directory or one of
 * its parents). The caller also asks for the passphrase and a typed confirmation of the path.
 */

import { existsSync, lstatSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { join, resolve, sep } from "node:path";
import { PROTECTION_FOLDS_CASE } from "../engine/canonical.js";
import type { Layout } from "./layout.js";

/** Why `dir` must not be purged, or null when it may be. */
export function purgeRefusal(l: Layout, o: { cwd?: string; home?: string; passwdHome?: string | null } = {}): string | null {
  const dir = resolve(l.home);
  const cwd = resolve(o.cwd ?? process.cwd());
  let passwd: string | null = o.passwdHome ?? null;
  if (o.passwdHome === undefined) {
    try {
      passwd = userInfo().homedir;
    } catch {
      passwd = null;
    }
  }
  const homes = [o.home ?? homedir(), ...(passwd !== null && passwd !== "" ? [passwd] : [])].map((h) => resolve(h));
  // I1: a directory is a home or the working directory ignoring case on every platform (PROTECTION_FOLDS_CASE,
  // engine/canonical.ts): the refusal can only grow.
  const ci = PROTECTION_FOLDS_CASE;
  const eq =(a: string, b: string): boolean => (ci ? a.toLowerCase() === b.toLowerCase() : a === b);
  const within = (child: string, parent: string): boolean => eq(child, parent) || (ci ? child.toLowerCase() : child).startsWith((ci ? parent.toLowerCase() : parent).replace(/\/*$/, sep));
  if (dir === sep) return `${dir} is the root directory`;
  for (const h of homes) if (within(h, dir)) return `${dir} is a home directory or contains one`;
  if (within(cwd, dir)) return `${dir} is the working directory or one of its parents`;
  let st;
  try {
    st = lstatSync(dir);
  } catch {
    return `${dir} does not exist`;
  }
  if (st.isSymbolicLink()) return `${dir} is a symbolic link`;
  if (!st.isDirectory()) return `${dir} is not a directory`;
  const marked = existsSync(join(dir, "install.json")) && ["keys", "backups", "log", "sessions"].some((d) => existsSync(join(dir, d)));
  if (!marked) return `${dir} does not hold the firewall's files (install.json with its keys, backups, log or sessions)`;
  return null;
}
