/**
 * Loads the policy: built-in defaults, then the user's policy, then the
 * administrator's managed policy (both may change anything; the managed file
 * wins, and its MCP server entries hold under the user's), then the
 * project's own file (which may only tighten). A file that cannot be read or
 * is invalid is reported and skipped (the other layers still apply; a broken
 * managed file also drops the user's layer), plus a "policy error" that sends
 * every risky action to a person.
 */

import { closeSync, constants, existsSync, fstatSync, openSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { declaredVersion, defaultConfig, mergeManaged, mergeTighten, mergeTrusted, POLICY_VERSION, PolicyError, validatePolicy } from "../policy.js";
import type { FirewallConfig, RolloutMode } from "../types.js";
import { runMountPoint } from "./run/mountpoints.js";
import { MANAGED_POLICY_PATHS, PROJECT_POLICY_FILE, type Layout } from "./layout.js";

export interface LoadedPolicy {
  config: FirewallConfig;
  /** Set when any policy file is unreadable or invalid. */
  error?: string;
  /** Project settings that were ignored because they would loosen the policy. */
  ignored: string[];
  sources: string[];
  /** Informational lines for `policy validate` (an older schema version migrated in memory, ...). */
  notes: string[];
  /**
   * Which layer set the rollout mode in effect (src/policy-rollout.ts). A user file's "watch" counts only with a
   * signed grant (src/runtime/rollout.ts); a project file can only set "enforce".
   */
  rollout: RolloutSource;
}

export interface RolloutSource {
  mode: RolloutMode;
  layer: "default" | "user" | "managed" | "project";
  path?: string;
}

/** Item 3: a policy file larger than this is refused (a policy is a few kilobytes; the cap bounds parsing). */
export const MAX_POLICY_BYTES = 1024 * 1024;

/**
 * Item 3: the policy file's text, opened without following a symlink in its last component and only when it is a
 * regular file within the size cap (a live run's mount point, an empty directory, reads as absent). Item 7, with
 * `rootOwned`: the file and its directory must be owned by root and writable by no group or other user (the
 * machine-wide managed policy), else it is refused (an error: strict, never the looser user layer alone).
 */
export function readPolicyText(path: string, o: { rootOwned?: boolean } = {}): string | null {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    if (code === "ELOOP" || code === "EMLINK") throw new PolicyError(path, ["is a symbolic link; a policy file must be a regular file"]);
    throw e;
  }
  try {
    const st = fstatSync(fd);
    if (st.isDirectory()) {
      if (runMountPoint(path)) return null;
      throw new PolicyError(path, ["is a directory, not a policy file (EISDIR)"]);
    }
    if (!st.isFile()) throw new PolicyError(path, ["is not a regular file"]);
    if (st.size > MAX_POLICY_BYTES) throw new PolicyError(path, [`is ${st.size} bytes; a policy file may be at most ${MAX_POLICY_BYTES}`]);
    if (o.rootOwned === true) {
      const dir = statSync(dirname(path));
      if (st.uid !== 0 || dir.uid !== 0 || (st.mode & 0o022) !== 0 || (dir.mode & 0o022) !== 0) throw new PolicyError(path, ["the managed policy and its directory must be owned by root and writable by no one else"]);
    }
    return readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
}

function readPolicyFile(path: string, o: { rootOwned?: boolean } = {}): unknown {
  const text = readPolicyText(path, o);
  if (text === null) return undefined;
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new PolicyError(path, [`not valid JSON: ${(e as Error).message}`]);
  }
}

/**
 * An older schema still loads (migrated in memory, same meaning); `policy validate` says a migration is
 * available. `policy migrate` rewrites only the user's file; a managed or project file is edited by whoever
 * owns it, and a project file read by teammates on a firewall older than v0.3 is best left at version 2
 * (a version 3 file fails safe there: their firewall skips it with a policy error).
 */
function noteVersion(raw: unknown, path: string, notes: string[], userFile: boolean): void {
  const v = declaredVersion(raw);
  if (v === null || v >= POLICY_VERSION) return;
  const how = userFile ? `run "launchsafe-firewall policy migrate" to rewrite it as version ${POLICY_VERSION} (a migration is available; a backup is kept)` : `a migration is available: set "version": ${POLICY_VERSION}, nothing else changes (a firewall older than v0.3 then skips the file with a policy error)`;
  notes.push(`${path}: version ${v}, migrated in memory; ${how}`);
}

/**
 * The project policy file for a directory: its own, else the nearest one above it up to the repository's root (the
 * first directory holding .git), so an agent started in a subdirectory still gets the repository's tightening.
 * A project file can only tighten, so finding one more often is the strict direction. Stops at the home directory.
 */
export function projectPolicyPath(root: string): string {
  const own = join(root, PROJECT_POLICY_FILE);
  const stop = resolve(homedir());
  let dir = resolve(root);
  for (let i = 0; i < 32; i++) {
    const p = join(dir, PROJECT_POLICY_FILE);
    if (existsSync(p)) return p;
    if (existsSync(join(dir, ".git")) || dir === stop) break;
    const up = dirname(dir);
    if (up === dir || up === stop) break;
    dir = up;
  }
  return own;
}

export function loadPolicy(l: Layout, workspaceRoots: readonly string[], platform: NodeJS.Platform = process.platform, managedPath?: string): LoadedPolicy {
  let config = defaultConfig();
  const sources: string[] = ["defaults"];
  const ignored: string[] = [];
  const errors: string[] = [];
  const notes: string[] = [];
  let rollout: RolloutSource = { mode: "enforce", layer: "default" };
  const managed = managedPath ?? MANAGED_POLICY_PATHS[platform];
  // User first, then managed: an administrator's settings win. R17: every layer that parsed is kept. A
  // broken user file is skipped (its loosening never applies; the managed and project layers still do).
  // A broken managed file also drops the user layer, which could otherwise open what the administrator closed.
  const layers: { path: string; doc: ReturnType<typeof validatePolicy> }[] = [];
  let managedBroken = false;
  for (const path of [l.policy, managed]) {
    if (path === undefined) continue;
    try {
      // Item 7: the platform's managed policy (not one a caller names, as tests do) must be root's alone.
      const raw = readPolicyFile(path, { rootOwned: path === managed && managedPath === undefined });
      if (raw === undefined) continue;
      layers.push({ path, doc: validatePolicy(raw, path) });
      noteVersion(raw, path, notes, path === l.policy);
    } catch (e) {
      errors.push(e instanceof PolicyError ? e.message : `${path}: ${(e as Error).message}`);
      if (path === managed) managedBroken = true;
    }
  }
  for (const { path, doc } of layers) {
    if (managedBroken && path === l.policy) continue;
    if (path === managed) {
      // FM1: a managed restriction holds even where a user entry would be looked up first.
      const merged = mergeManaged(config, doc);
      config = merged.config;
      notes.push(...merged.notes.map((n) => `${l.policy}: ${n}`));
    } else config = mergeTrusted(config, doc);
    if (doc.rollout?.mode !== undefined) rollout = { mode: doc.rollout.mode, layer: path === managed ? "managed" : "user", path };
    sources.push(path);
  }
  for (const root of workspaceRoots) {
    const path = projectPolicyPath(root);
    // A live run's mount point there (no file when it started) reads as absent (readText); any other
    // directory is an error, which fails closed.
    try {
      const raw = readPolicyFile(path);
      if (raw === undefined) continue;
      const merged = mergeTighten(config, validatePolicy(raw, path));
      noteVersion(raw, path, notes, false);
      config = merged.config;
      ignored.push(...merged.ignored.map((i) => `${path}: ${i}`));
      if (config.rollout?.mode === "enforce" && rollout.mode === "watch") rollout = { mode: "enforce", layer: "project", path };
      sources.push(path);
    } catch (e) {
      errors.push(e instanceof PolicyError ? e.message : `${path}: ${(e as Error).message}`);
    }
  }
  if (errors.length > 0) {
    // Never fall through to a looser policy: the broken file's settings are not applied (strict defaults for
    // what it would have set), every layer that parsed still is, and the error sends every risky action to a person.
    return { config, error: errors.join(" | "), ignored, sources, notes, rollout };
  }
  return { config, ignored, sources, notes, rollout };
}
