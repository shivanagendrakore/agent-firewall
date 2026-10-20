/**
 * v0.3 `run` on Linux: the mount points made in the workspace for protected paths that do not exist yet
 * (engine/run-profile.ts bwrapMissing, V7): the empty directories bubblewrap creates, and the file
 * stand-ins run.ts writes for files git reads (`.git/commondir`). They are removed when the last run using
 * them ends, while they are still an empty directory or a regular file holding exactly the stand-in's
 * content, and never while another run still uses one: removing a mount point
 * from outside detaches the read-only mount inside that other run's sandbox. Each path has a directory
 * of users (one claim file per live run, named by its pid, recording the process's start time, command
 * line and run id) in a private directory inside the firewall's own directory (read-only inside every run, never
 * writable through --allow-write), changed only under a lock.
 */

import { createHash } from "node:crypto";
import { chmodSync, lstatSync, mkdirSync, readdirSync, readFileSync, readlinkSync, realpathSync, rmdirSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { filePlaceholder } from "../../engine/run-profile.js";
import { firewallHome, installDir } from "../layout.js";
import { realpathLoose } from "../realpath.js";

export interface MountRegistry {
  /** Records this run as a user of each path (before the sandbox starts). */
  claim(paths: readonly string[]): void;
  /** The existing mount points among `paths` (empty directories, unchanged file stand-ins) that another live run created. */
  inUse(paths: readonly string[]): string[];
  /** Drops this run's claims and removes each path that no live run uses and that is still an empty directory or an unchanged file stand-in. */
  release(): string[];
}

function sleepMs(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function alive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

function emptyDir(p: string): boolean {
  try {
    return lstatSync(p).isDirectory() && readdirSync(p).length === 0;
  } catch {
    return false;
  }
}

/** A file stand-in (engine/run-profile.ts filePlaceholder) that nobody has changed: a regular file with exactly its content. */
export function placeholderFile(p: string): boolean {
  const want = filePlaceholder(p);
  if (want === null) return false;
  try {
    const s = lstatSync(p);
    return s.isFile() && s.nlink === 1 && s.size === Buffer.byteLength(want) && readFileSync(p, "utf8") === want;
  } catch {
    return false;
  }
}

const placeholder = (p: string): boolean => emptyDir(p) || placeholderFile(p);

/** The registry's directory: inside the firewall's own directory (`run` and the hooks agree on it; FA3: never the run's TMPDIR). */
export function defaultRegistryRoot(env: NodeJS.ProcessEnv = process.env): string {
  return join(firewallHome(env), "run-mounts");
}

/**
 * A path's directory in the registry: a fixed-length name for any mount point path. The path is not a secret
 * (a protected path such as /etc/passwd is only a file name here), and every run must derive the same name, so a
 * plain hash is the right tool.
 */
const registryKey = (root: string, mountPath: string): string => join(root, createHash("sha256").update(mountPath).digest("hex").slice(0, 32));

const uid = (): number | null => (typeof process.getuid === "function" ? process.getuid() : null);

/** A real directory (not a link) owned by this user that nobody else can write (`strict`: nobody else can even enter: 0700). */
function ownDir(p: string, strict: boolean): boolean {
  try {
    const s = lstatSync(p);
    const me = uid();
    return s.isDirectory() && (me === null || s.uid === me) && (s.mode & (strict ? 0o077 : 0o022)) === 0;
  } catch {
    return false;
  }
}

/** The registry can be trusted: its directory and its parent belong to this user, the directory is 0700 (FA3). */
function trustedRegistry(root: string): boolean {
  return ownDir(root, true) && ownDir(dirname(root), false);
}

/** A process as the registry records it: when it started and its command line (to tell it from a reused pid, and to know it is a run). */
export interface ProcessIdentity {
  start: string;
  cmd: string;
  /** Linux: the process's working directory (a relative script path in its command line resolves against it). */
  cwd?: string;
}

/** The start time and command line of a live process, or null (gone, or not knowable here: then nothing is proof). */
export function processIdentity(pid: number): ProcessIdentity | null {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  if (process.platform === "linux") {
    try {
      const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
      const start = stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19];
      const cmd = readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").filter((x, i, a) => x !== "" || i < a.length - 1).join(" ");
      if (start === undefined || cmd === "") return null;
      let cwd: string | undefined;
      try {
        cwd = readlinkSync(`/proc/${pid}/cwd`);
      } catch {
        cwd = undefined;
      }
      return { start, cmd, ...(cwd !== undefined ? { cwd } : {}) };
    } catch {
      return null;
    }
  }
  if (process.platform === "darwin") {
    const r = spawnSync("/bin/ps", ["-ww", "-o", "lstart=", "-o", "command=", "-p", String(pid)], { encoding: "utf8", env: { LC_ALL: "C", PATH: "/usr/bin:/bin" }, timeout: 5000 });
    const m = /^\s*(\S+\s+\S+\s+\d+\s+[\d:]+\s+\d+)\s+(.+?)\s*$/.exec(r.status === 0 ? (r.stdout ?? "") : "");
    return m === null ? null : { start: (m[1] as string).replace(/\s+/g, " "), cmd: m[2] as string };
  }
  return null;
}

/** This firewall's command-line entry point (the bin links resolve to it). */
const firewallCli = (): string => realpathLoose(join(installDir(), "dist", "cli.js"));

/**
 * Whether a command line is this firewall's `run`: a word that resolves to this package's dist/cli.js (also
 * through the bin link npx or a global install uses), followed by `run`. Arguments are joined by spaces in
 * a command line, so each possible start of the script path before ` run` is tried.
 */
export function isFirewallRun(cmd: string, cwd?: string, cli = firewallCli()): boolean {
  for (const m of cmd.matchAll(/ run(?= |$)/g)) {
    const before = cmd.slice(0, m.index);
    const starts = [0, ...[...before.matchAll(/ /g)].map((x) => (x.index as number) + 1)];
    for (const s of starts) {
      const word = before.slice(s);
      if (word === "") continue;
      const abs = isAbsolute(word) ? word : cwd !== undefined ? resolve(cwd, word) : null;
      if (abs !== null && realpathLoose(abs) === cli) return true;
    }
  }
  return false;
}

interface Claim {
  path: string;
  pid: number;
  start: string | null;
  cmd: string | null;
  /** The run's id (LAUNCHSAFE_FIREWALL_RUN inside it): what a reader inside that run matches its claims by. */
  run: string | null;
}

function readClaim(file: string, pid: number): Claim | null {
  try {
    const s = lstatSync(file);
    const me = uid();
    if (!s.isFile() || (me !== null && s.uid !== me) || s.size > 64 * 1024) return null;
    const c = JSON.parse(readFileSync(file, "utf8")) as Partial<Claim>;
    if (typeof c.path !== "string" || c.pid !== pid) return null;
    return { path: c.path, pid, start: typeof c.start === "string" ? c.start : null, cmd: typeof c.cmd === "string" ? c.cmd : null, run: typeof c.run === "string" && c.run !== "" ? c.run : null };
  } catch {
    return null;
  }
}

/** A claim is proof only for a live run of this firewall that is the very process that made it (same start time and command line). */
function provenRun(c: Claim): boolean {
  if (c.start === null || c.cmd === null) return false;
  const now = processIdentity(c.pid);
  return now !== null && now.start === c.start && now.cmd === c.cmd && isFirewallRun(now.cmd, now.cwd);
}

/** Undoes the octal escapes /proc/self/mountinfo uses in paths (`\040` for a space, `\134` for a backslash). */
const unescapeMount = (s: string): string => s.replace(/\\([0-7]{3})/g, (_, o: string) => String.fromCharCode(parseInt(o, 8)));

/**
 * Whether `p` is a read-only mount point in the mount namespace `mountinfo` describes (the text of
 * /proc/self/mountinfo): the topmost mount on exactly that path (the last line naming it) has the per-mount
 * option `ro`. A directory that merely lies on a tmpfs or read-only filesystem is not one.
 */
export function readOnlyMountPoint(p: string, mountinfo: string): boolean {
  let ro: boolean | null = null;
  for (const line of mountinfo.split("\n")) {
    const f = line.split(" ");
    if (f.length < 6 || unescapeMount(f[4] as string) !== p) continue;
    ro = (f[5] as string).split(",").includes("ro");
  }
  return ro === true;
}

/** This process's mount table (Linux), or null where there is none to read. */
function ownMountinfo(): string | null {
  if (process.platform !== "linux") return null;
  try {
    return readFileSync("/proc/self/mountinfo", "utf8");
  } catch {
    return null;
  }
}

/**
 * Whether `p` is an empty directory that a live `run` keeps as the mount point of a protected file that did
 * not exist when it started (`.launchsafe-firewall.json`, `.mcp.json`, ...): then the file is absent, and a
 * reader (the policy loader, a hook) can say so instead of failing on EISDIR. Deterministic, and only true
 * on proof that a live run claimed it in the registry (a 0700 directory of this user's, inside the
 * firewall's directory, read-only inside every run; FA3), whatever the filesystem:
 * - outside the sandbox: a claim made by a process that is still running, started when the claim says, and
 *   is this firewall's `run`;
 * - inside it (LAUNCHSAFE_FIREWALL_RUN set), where the run's own process is in another pid namespace and
 *   cannot be checked: a claim recorded by this very run (its id), on a path that is a read-only mount point
 *   in this mount namespace. A claim is written before the sandbox starts, and the mount exists only in that
 *   run's namespace, so neither a stale claim nor a directory the agent made (on a tmpfs or anywhere else)
 *   passes.
 * Any other empty directory is not a run's, and the caller keeps failing closed.
 */
export function runMountPoint(p: string, root = defaultRegistryRoot(), env: NodeJS.ProcessEnv = process.env, mountinfo: () => string | null = ownMountinfo): boolean {
  if (!emptyDir(p)) return false;
  let real: string;
  try {
    real = join(realpathSync(dirname(p)), p.slice(dirname(p).length + 1));
  } catch {
    return false;
  }
  if (!trustedRegistry(root)) return false;
  const dir = registryKey(root, real);
  if (!ownDir(dir, true)) return false;
  let claims: Claim[];
  try {
    claims = readdirSync(dir)
      .map((n) => readClaim(join(dir, n), Number(n)))
      .filter((c): c is Claim => c !== null && c.path === real);
  } catch {
    return false;
  }
  const runId = env.LAUNCHSAFE_FIREWALL_RUN;
  if (runId !== undefined && runId !== "" && claims.some((c) => c.run === runId)) {
    const table = mountinfo();
    if (table !== null && readOnlyMountPoint(real, table)) return true;
  }
  return claims.some(provenRun);
}

export function mountRegistry(root: string, pid = process.pid, runId: string | null = null): MountRegistry {
  const key = (p: string): string => registryKey(root, p);
  const claimed = new Set<string>();
  const locked = <T>(fn: () => T): T => {
    mkdirSync(root, { recursive: true, mode: 0o700 });
    // The registry is this user's own: a link, or a directory someone else owns, is refused (FA3).
    const st = lstatSync(root);
    const me = uid();
    if (!st.isDirectory() || (me !== null && st.uid !== me)) throw new Error(`${root} is not a directory of yours`);
    if ((st.mode & 0o077) !== 0) chmodSync(root, 0o700);
    const lock = join(root, ".lock");
    for (let i = 0; ; i++) {
      try {
        mkdirSync(lock);
        break;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
        // A lock older than 10 s belongs to a run that died holding it.
        try {
          if (Date.now() - statSync(lock).mtimeMs > 10000) rmSync(lock, { recursive: true, force: true });
        } catch {
          // Gone already.
        }
        if (i > 400) throw new Error(`could not lock ${root}`, { cause: e });
        sleepMs(5);
      }
    }
    try {
      return fn();
    } finally {
      rmSync(lock, { recursive: true, force: true });
    }
  };
  const liveUsers = (p: string): number[] => {
    let names: string[] = [];
    try {
      names = readdirSync(key(p));
    } catch {
      return [];
    }
    const out: number[] = [];
    for (const n of names) {
      const pid = Number(n);
      // A reused pid (a different start time than the claim recorded) is not the run that claimed it.
      const c = readClaim(join(key(p), n), pid);
      const now = c?.start !== null && c?.start !== undefined && alive(pid) ? processIdentity(pid) : null;
      if (alive(pid) && !(now !== null && now.start !== c?.start)) out.push(pid);
      else rmSync(join(key(p), n), { force: true });
    }
    return out;
  };
  return {
    claim(paths) {
      locked(() => {
        const id = processIdentity(pid);
        for (const p of paths) {
          mkdirSync(key(p), { recursive: true, mode: 0o700 });
          const claim: Claim = { path: p, pid, start: id?.start ?? null, cmd: id?.cmd ?? null, run: runId };
          writeFileSync(join(key(p), String(pid)), JSON.stringify(claim), { mode: 0o600 });
          claimed.add(p);
        }
      });
    },
    inUse(paths) {
      return locked(() => paths.filter((p) => placeholder(p) && liveUsers(p).some((u) => u !== pid)));
    },
    release() {
      return locked(() => {
        const removed: string[] = [];
        for (const p of claimed) {
          rmSync(join(key(p), String(pid)), { force: true });
          if (liveUsers(p).length > 0) continue;
          try {
            rmdirSync(key(p));
          } catch {
            // Not empty or gone.
          }
          try {
            if (emptyDir(p)) rmdirSync(p);
            else if (placeholderFile(p)) unlinkSync(p);
            else continue;
            removed.push(p);
          } catch {
            // Something else is there now; leave it.
          }
        }
        claimed.clear();
        return removed;
      });
    },
  };
}
