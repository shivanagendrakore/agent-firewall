/**
 * File primitives that hold up under several Claude Code sessions and
 * subagents running hooks at once: a lock file per resource, atomic replace
 * (write a temp file, fsync, rename), and private permissions.
 */

import { closeSync, linkSync, readSync, fchmodSync, fstatSync, fsyncSync, ftruncateSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, rmSync, statSync, unlinkSync, writeSync, chmodSync, constants } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { stripBom } from "../bom.js";
import { isUnder, PROTECTION_FOLDS_CASE } from "../engine/paths.js";
import { own } from "../own.js";
import { firewallHome } from "./layout.js";
import { realpathLoose } from "./realpath.js";
import { runMountPoint } from "./run/mountpoints.js";

export function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
}

/**
 * Writes all of `data`, at the fd's position or at `at` (one write in practice; a short write is
 * continued, never dropped).
 */
export function writeAll(fd: number, data: string, at?: number): void {
  const buf = Buffer.from(data, "utf8");
  let off = 0;
  while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off, at === undefined ? null : at + off);
}

/** Replaces a file atomically: readers see the old or the new content, never a mix. */
export function atomicWrite(path: string, data: string, mode = 0o600): void {
  ensureDir(dirname(path));
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, mode);
  try {
    // The mode is exact, not whatever the umask leaves of it: a private file stays private.
    fchmodSync(fd, mode);
    writeAll(fd, data);
    fsyncSync(fd);
  } catch (e) {
    // E: a failed write (a full disk) leaves no half-written temporary file behind.
    closeSync(fd);
    rmSync(tmp, { force: true });
    throw e;
  }
  closeSync(fd);
  try {
    renameSync(tmp, path);
  } catch (e) {
    rmSync(tmp, { force: true });
    throw e;
  }
  fsyncDir(dirname(path));
}

/** Makes a directory's entries (a created, renamed or removed name) durable. Best effort: not supported everywhere. */
export function fsyncDir(dir: string): void {
  try {
    const dfd = openSync(dir, "r");
    try {
      fsyncSync(dfd);
    } finally {
      closeSync(dfd);
    }
  } catch {
    // Directory fsync is not supported everywhere; the rename is still atomic.
  }
}

/** Creates a file that must not exist yet (fails with EEXIST otherwise), durably: a backup never replaces another. */
export function writeNew(path: string, data: string, mode = 0o600): void {
  ensureDir(dirname(path));
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, mode);
  try {
    writeAll(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Appends `data` (whole lines) and fsyncs it. The file is opened O_APPEND and written with one write, so
 * the kernel places it at the end atomically with respect to other appenders: concurrent appends never
 * interleave or overwrite each other (local file systems; the firewall's directory is local).
 */
export function appendDurable(path: string, data: string): void {
  ensureDir(dirname(path));
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND, 0o600);
  try {
    writeAll(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * E: whether a line-oriented file can be appended to as it is: absent, empty, or ending in a newline. A torn last line
 * (a crash or a full disk mid-write) does not, and an append must start on a line of its own then.
 */
export function endsWithNewline(path: string): boolean {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY);
  } catch {
    return true;
  }
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return true;
    const b = Buffer.alloc(1);
    readSync(fd, b, 0, 1, size - 1);
    return b[0] === 0x0a;
  } catch {
    return true;
  } finally {
    closeSync(fd);
  }
}

/**
 * appendDurable for a file a person names (an anchor file): a symbolic link in its last component is refused
 * (O_NOFOLLOW, ELOOP) instead of followed, and its directory must already exist.
 */
export function appendNoFollow(path: string, data: string): void {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND | constants.O_NOFOLLOW, 0o600);
  try {
    writeAll(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * A file's text without a leading UTF-8 byte order mark (a Windows editor's, a PowerShell redirect's), so JSON
 * saved with one is read, not refused. Null when the file does not exist. A live `run`'s mount point for a
 * protected file that did not exist when it started (an empty directory, runtime/run/mountpoints.ts
 * runMountPoint) also reads as absent; any other directory still throws (EISDIR), so the caller fails closed.
 */
export function readText(path: string): string | null {
  const t = readTextExact(path);
  return t === null ? null : stripBom(t);
}

/** readText with the byte order mark kept: for a file that is about to be copied (a backup), so the copy is the file as it was. */
export function readTextExact(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    if (code === "EISDIR" && runMountPoint(path)) return null;
    throw e;
  }
}

/**
 * FZ7: readText for a state file whose reader has its own fail-closed answer for damage. A path that exists
 * but cannot be read as a file (a directory, a symlink loop, no permission) is reported as `{ unreadable }`
 * instead of thrown, so the reader treats it as it treats a corrupt file; absent is still null.
 */
export function tryReadText(path: string): string | null | { unreadable: string } {
  try {
    return readText(path);
  } catch (e) {
    return { unreadable: (e as NodeJS.ErrnoException).code ?? (e as Error).message };
  }
}

const sleeper = new Int32Array(new SharedArrayBuffer(4));
function sleepMs(ms: number): void {
  Atomics.wait(sleeper, 0, 0, ms);
}

export class LockTimeout extends Error {}

/**
 * Runs fn while holding an exclusive lock file. A lock older than staleMs is
 * from a crashed process and is broken. Synchronous on purpose: a hook is a
 * short-lived process and the critical sections are tiny.
 */
export function withLock<T>(lockPath: string, fn: () => T, opts: { timeoutMs?: number; staleMs?: number } = {}): T {
  // M1: a lock this process already holds (holdLock around a whole decision) is not taken again.
  if (heldHere.has(lockPath)) return fn();
  const fd = acquireLock(lockPath, opts);
  heldHere.add(lockPath);
  try {
    return fn();
  } finally {
    heldHere.delete(lockPath);
    releaseOwn(fd, lockPath);
  }
}

/** The lock files this process holds (the hook is synchronous, so nothing else in it runs meanwhile). */
const heldHere = new Set<string>();

/**
 * M1: takes a lock for a span that is not one function (a decision from reading the counters to recording them);
 * withLock calls on the same lock inside it run without taking it again. Returns the release, which is idempotent.
 */
export function holdLock(lockPath: string, opts: { timeoutMs?: number; staleMs?: number } = {}): () => void {
  if (heldHere.has(lockPath)) return () => undefined;
  const fd = acquireLock(lockPath, opts);
  heldHere.add(lockPath);
  let done = false;
  return () => {
    if (done) return;
    done = true;
    heldHere.delete(lockPath);
    releaseOwn(fd, lockPath);
  };
}

/**
 * M2: releases a lock only if the lock file is still the one this process created (same inode): a lock broken as
 * stale and taken by another process meanwhile is that process's, and is left alone.
 */
function releaseOwn(fd: number, lockPath: string): void {
  try {
    const mine = fstatSync(fd);
    const now = lstatSync(lockPath);
    if (mine.ino === now.ino && mine.dev === now.dev) unlinkSync(lockPath);
  } catch {
    // Gone already (broken as stale): nothing of ours to release.
  } finally {
    closeSync(fd);
  }
}

/**
 * C: an upper bound on how long any lock is waited for, set by the hook from its remaining time (a hook must answer
 * before the agent's timeout); null: no bound beyond each caller's own.
 */
let lockWaitCap: number | null = null;

/** Sets (or, with null, clears) the bound on lock waits for this process; returns the previous one. */
export function capLockWaits(ms: number | null): number | null {
  const before = lockWaitCap;
  lockWaitCap = ms === null ? null : Math.max(0, ms);
  return before;
}

/** C: whether the process that wrote a lock file is gone (its pid answers ESRCH). Unknown counts as alive. */
function holderDead(lockPath: string): boolean {
  try {
    const pid = Number(/^(\d+) /.exec(readFileSync(lockPath, "utf8"))?.[1]);
    if (!Number.isInteger(pid) || pid <= 0 || pid === process.pid) return false;
    try {
      process.kill(pid, 0);
      return false;
    } catch (e) {
      return (e as NodeJS.ErrnoException).code === "ESRCH";
    }
  } catch {
    return false;
  }
}

/**
 * withLock, where the lock file itself becomes `target` when it is released. fn returns its result and
 * the new content of `target`; the lock file is then given that content and renamed over `target`, so one
 * rename both replaces the file and frees the lock (instead of a temp file, a rename and an unlink).
 * Readers of `target` see the old or the new content, never a mix. Not durable (no fsync): after a power
 * cut `target` may be its old version, or empty on a file system that does not order data before a rename,
 * so this is only for a file the caller can rebuild (the log's head.json). With null content, or when fn
 * throws, the lock is removed as withLock does. If the lock was broken as stale meanwhile (another process
 * may hold it now), nothing is renamed and `target` keeps its old content.
 */
export function withLockReplacing<T>(lockPath: string, target: string, fn: () => { result: T; content: string | null }, opts: { timeoutMs?: number; staleMs?: number } = {}): T {
  const fd = acquireLock(lockPath, opts);
  let out: { result: T; content: string | null };
  try {
    out = fn();
  } catch (e) {
    // Released only if the lock file is still ours (same inode): one broken as stale and retaken is another's.
    releaseOwn(fd, lockPath);
    throw e;
  }
  let ours = false;
  let id: { ino: number; dev: number } | null = null;
  let written = false;
  try {
    const mine = fstatSync(fd);
    const now = lstatSync(lockPath);
    ours = mine.ino === now.ino && mine.dev === now.dev;
    id = { ino: mine.ino, dev: mine.dev };
    if (ours && out.content !== null) {
      ftruncateSync(fd, 0);
      writeAll(fd, out.content, 0);
      fchmodSync(fd, 0o600);
      written = true;
    }
  } catch {
    // The lock is gone (broken as stale), or the content could not be written: handled below.
  } finally {
    closeSync(fd);
  }
  if (!ours) return out.result;
  if (written) {
    try {
      renameSync(lockPath, target);
      return out.result;
    } catch (e) {
      // Gone: broken as stale just now, so nothing of ours to release. Otherwise release it below.
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return out.result;
    }
  }
  try {
    // Time has passed since the check above: remove the lock file only if it is still the one that was ours.
    const now = lstatSync(lockPath);
    if (id !== null && now.ino === id.ino && now.dev === id.dev) unlinkSync(lockPath);
  } catch {
    // Already broken as stale.
  }
  return out.result;
}

/** Takes a lock file (see withLock); returns its open descriptor, holding the process id and time. */
function acquireLock(lockPath: string, opts: { timeoutMs?: number; staleMs?: number }): number {
  const timeout = Math.min(opts.timeoutMs ?? 15000, lockWaitCap ?? Infinity);
  const stale = opts.staleMs ?? 30000;
  ensureDir(dirname(lockPath));
  const start = Date.now();
  let delay = 1;
  for (;;) {
    try {
      const fd = openSync(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
      try {
        writeSync(fd, `${process.pid} ${Date.now()}`);
      } catch (e) {
        closeSync(fd);
        unlinkSync(lockPath);
        throw e;
      }
      return fd;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      try {
        const examined = statSync(lockPath);
        const age = Date.now() - examined.mtimeMs;
        const dead = age <= stale && holderDead(lockPath);
        // C: a lock whose holder has exited is broken at once, not after the stale window.
        if (age > stale || dead) {
          // Break a stale lock by renaming it away first, so two breakers cannot both win.
          const moved = `${lockPath}.stale.${process.pid}.${randomBytes(4).toString("hex")}`;
          renameSync(lockPath, moved);
          // What was moved is not the file that was examined when another process broke that one and took the name
          // meanwhile: it is a live lock.
          let replaced = false;
          try {
            const got = statSync(moved);
            replaced = got.ino !== examined.ino || got.dev !== examined.dev;
          } catch {
            // Gone: nothing left to put back.
          }
          // Broken for a dead holder: if what was moved is a live process's lock (taken between the check and the
          // rename), put it back when the name is still free, so its holder keeps it.
          if (replaced || (dead && !holderDead(moved))) {
            try {
              linkSync(moved, lockPath);
            } catch {
              // Someone holds the name again: theirs stands; the moved one's holder finds its lock gone (released as not its own).
            }
          }
          unlinkSync(moved);
          continue;
        }
      } catch {
        // The lock vanished between the checks: try again.
        continue;
      }
      if (Date.now() - start > timeout) throw new LockTimeout(`timed out waiting for ${lockPath}`);
      sleepMs(delay);
      delay = Math.min(delay * 2, 25);
    }
  }
}

export function chmodPrivate(path: string): void {
  try {
    chmodSync(path, 0o600);
  } catch {
    // Best effort.
  }
}

/** Parses JSON read from `path` (a leading byte order mark is dropped); a syntax error names the file (the parser's own message never does). */
export function parseJsonFile(path: string, text: string): unknown {
  try {
    return JSON.parse(stripBom(text));
  } catch (e) {
    throw new Error(`${path} is not valid JSON (${(e as Error).message})`, { cause: e });
  }
}

/** Each agent's configuration under the home directory (home-relative), for telling one agent's files from another's. */
function agentDirs(home: string, env: NodeJS.ProcessEnv): [string, string[]][] {
  const abs = (v: string | undefined, sub = ""): string[] => (v !== undefined && v !== "" ? [join(resolve(v), sub)] : []);
  return [
    ["claude", [".claude", ".claude.json", "Library/Application Support/Claude", ".config/Claude"].map((d) => join(home, d)).concat(abs(env.CLAUDE_CONFIG_DIR))],
    ["codex", [join(home, ".codex"), ...abs(env.CODEX_HOME)]],
    ["gemini", [join(home, ".gemini"), ...abs(env.GEMINI_CLI_HOME, ".gemini")]],
    ["cursor", [".cursor", "Library/Application Support/Cursor", ".config/Cursor"].map((d) => join(home, d))],
    ["vscode", [".vscode", ".copilot", "Library/Application Support/Code", ".config/Code"].map((d) => join(home, d))],
    ["windsurf", [join(home, ".codeium")]],
  ];
}

const SEGMENT_AGENT: Record<string, string> = { ".claude": "claude", ".codex": "codex", ".gemini": "gemini", ".cursor": "cursor", ".vscode": "vscode", ".codeium": "windsurf" };

/** Which agent's configuration `p` is in (by its directory, and by the name of a directory on the way when `bySegment`), or null. */
function agentOf(p: string, home: string, env: NodeJS.ProcessEnv, ci: boolean, bySegment: boolean): string | null {
  for (const [agent, dirs] of agentDirs(home, env)) if (dirs.some((d) => isUnder(p, realpathLoose(d), ci) || isUnder(p, d, ci))) return agent;
  if (!bySegment) return null;
  for (const seg of p.split("/").reverse()) {
    const agent = own(SEGMENT_AGENT, seg);
    if (agent !== undefined) return agent;
  }
  return null;
}

/**
 * Why a settings file that is a symlink must not be written through to `real` (FA4), or null: the firewall's own
 * directory, a credential store (~/.ssh, ~/.gnupg, ~/.aws, ~/.kube, ~/.netrc, ~/.npmrc, ~/.git-credentials), another agent's configuration than the one the link
 * belongs to, or anywhere outside the person's home directory.
 */
export function linkTargetProblem(path: string, real: string, o: { home?: string; env?: NodeJS.ProcessEnv } = {}): string | null {
  const env = o.env ?? process.env;
  const ci = process.platform === "darwin";
  const home = realpathLoose(resolve(o.home ?? homedir()));
  // I1: what the link must not reach (the firewall's directory, a credential store, another agent's configuration)
  // is matched ignoring case on every platform (PROTECTION_FOLDS_CASE, engine/canonical.ts). Where the link itself
  // sits, and whether the target is inside the home directory, follow the platform: folding those would let a
  // differently-spelled place pass.
  const fold = PROTECTION_FOLDS_CASE;
  if (isUnder(real, realpathLoose(firewallHome(env)), fold) || isUnder(real, firewallHome(env), fold)) return "which is inside the firewall's own directory";
  for (const d of [".ssh", ".gnupg", ".aws", ".kube", ".netrc", ".npmrc", ".git-credentials"]) if (isUnder(real, join(home, d), fold)) return `which is inside ~/${d}, a credential store`;
  if (!isUnder(real, home, ci)) return "which is outside your home directory";
  const at = join(realpathLoose(dirname(resolve(path))), basename(path));
  const own = agentOf(at, home, env, ci, true);
  const theirs = agentOf(real, home, env, fold, false);
  if (theirs !== null && theirs !== own) return `which is in another agent's configuration (${theirs})`;
  return null;
}

/**
 * Where a write to a person's own configuration file really goes. A symlink (a dotfiles repository) is written
 * through to its target, after checking the target is a regular file the person owns, inside their home, and not
 * in the firewall's directory, a credential store or another agent's configuration (FA4); the link itself is
 * never replaced by a regular file. A target that is anything else is refused.
 */
export function writeTarget(path: string, o: { home?: string; env?: NodeJS.ProcessEnv } = {}): { target: string; linkedTo: string | null } {
  let st;
  try {
    st = lstatSync(path);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return { target: path, linkedTo: null };
    throw e;
  }
  if (!st.isSymbolicLink()) return { target: path, linkedTo: null };
  let real: string;
  try {
    real = realpathSync(path);
  } catch {
    throw new Error(`${path} is a symbolic link whose target does not exist, so it was left alone. Create the target file or remove the link, then try again.`);
  }
  const ts = statSync(real);
  if (!ts.isFile()) throw new Error(`${path} is a symbolic link to ${real}, which is not a regular file, so it was left alone.`);
  if (typeof process.getuid === "function" && ts.uid !== process.getuid()) throw new Error(`${path} is a symbolic link to ${real}, which you do not own, so it was left alone.`);
  const why = linkTargetProblem(path, real, o);
  if (why !== null) throw new Error(`${path} is a symbolic link to ${real}, ${why}, so nothing was written through it. Make ${path} a regular file (or point the link at a file of your own for this agent), then try again.`);
  return { target: real, linkedTo: real };
}

/**
 * --restore-backup through a symlink (FA4): the target must pass writeTarget's checks, and the copy saved beside
 * the settings file (FILE.before-restore.*) is never made of a file kept in another directory, which would copy
 * that file's content out of where it lives. Throws with the reason; nothing has been read or written.
 */
export function assertRestorableTarget(path: string, o: { home?: string; env?: NodeJS.ProcessEnv } = {}): void {
  const { linkedTo } = writeTarget(path, o);
  if (linkedTo === null) return;
  const own = realpathLoose(dirname(resolve(path)));
  if (dirname(linkedTo) !== own) throw new Error(`${path} is a symbolic link to ${linkedTo}, in another directory, so --restore-backup will not save a copy of it beside ${path} or write through the link. Restore by hand: copy the backup over ${linkedTo} yourself, or make ${path} a regular file and run it again.`);
}

/**
 * Writes a person's own configuration file atomically, keeping its mode (never widened; a new file is 0600) and
 * writing through a symlink instead of replacing it. Returns the symlink's target when there was one, so the caller can say so.
 */
export function writeUserFile(path: string, data: string): string | null {
  const { target, linkedTo } = writeTarget(path);
  let mode = 0o600;
  try {
    mode = statSync(target).mode & 0o777;
  } catch {
    // A new file.
  }
  atomicWrite(target, data, mode);
  return linkedTo;
}
