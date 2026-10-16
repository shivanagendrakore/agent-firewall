/**
 * v0.3 `launchsafe-firewall run -- <command>`: starts a command inside the
 * operating system's sandbox with network access only through the run's
 * allowlist proxy (docs/run.md). This module wires the pieces: the policy and
 * its host list (engine/netgate.ts), the profile (engine/run-profile.ts), the
 * platform (platform.ts), the proxy (proxy.ts), the signed log, and the
 * child's lifetime and signals.
 */

import { spawn, spawnSync, type ChildProcess, type StdioOptions } from "node:child_process";
import { randomBytes } from "node:crypto";
import { accessSync, constants, lstatSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { constants as osConstants } from "node:os";
import { runNetPolicy, RunBudgets, type RunNetPolicy } from "../../engine/netgate.js";
import { bwrapArgs, bwrapMissing, guardedAncestors, HOME_UNREADABLE, HOME_UNREADABLE_OPTIONAL, LINUX_DOCKER_SOCKET_DIRS, sandboxExecArgs, WORKSPACE_PROTECTED, writePathProblem, BRIDGE_MARKER, type RunPlan } from "../../engine/run-profile.js";
import { allowedEnv, passEnvProblem, printable, PRESET_PASS_ENV, socketsIn, ttyProbe as defaultTtyProbe, ttyWrapNeeded, type TtyProbe } from "./guards.js";import type { FirewallConfig } from "../../types.js";
import { approverPath } from "../approver.js";
import { loadPolicy } from "../config.js";
import { runAllowWritePaths, runPrivateHosts } from "../../policy-run.js";
import { knownHostsPolicy, type KnownHostsPolicy } from "../../policy-knownhosts.js";
import { approvedHosts, recordSeen } from "../knownhosts.js";
import { hostInList } from "../../engine/network.js";
import { UPLOAD_CAPABLE } from "../../engine/sandbox.js";
import { isUnder } from "../../engine/paths.js";
import { registeredSettingsFiles } from "../context.js";
import { assertNotRealHome } from "../guard.js";
import { readRecords } from "../install.js";
import { installDir, type Layout } from "../layout.js";
import { appendBounded, isLogUnrecorded } from "../logbound.js";
import { realpathLoose } from "../realpath.js";
import { BRIDGE_SOURCE, SEATBELT_BRIDGE_SOURCE } from "./bridge.js";
import { gitOwnedPath, runnerCommands, workspaceCodeEntries, type CodePath } from "./code-paths.js";
import { defaultRegistryRoot, mountRegistry, placeholderFile, type MountRegistry } from "./mountpoints.js";
import { detectRunPlatform, type RunPlatform } from "./platform.js";
import { startProxy, type ProxyEvent, type ProxyHostStats, type ProxyOptions, type RunningProxy } from "./proxy.js";
import { own, setOwn } from "../../own.js";
import { AGENT_PRESETS, type PresetAgent } from "../../engine/agent-presets.js";

/** Exit status when no usable sandbox exists here (EX_UNAVAILABLE). */
export const EXIT_UNAVAILABLE = 69;
/** Exit status when the command cannot be found (like a shell). */
export const EXIT_NOT_FOUND = 127;

export interface RunOptions {
  layout: Layout;
  /** The command and its arguments (after "--"). */
  command: string[];
  /** The workspace (absolute). */
  workspace: string;
  allowWrite: string[];
  sendHosts: string[];
  allowLocalhost: boolean;
  allowKeychain: boolean;
  dryRun: boolean;
  verbose: boolean;
  env: NodeJS.ProcessEnv;
  home: string;
  cwd: string;
  /** Standard output and standard error of run itself (never the child's). */
  say: (line: string) => void;
  warn: (line: string) => void;
  platform?: NodeJS.Platform;
  /** Tests only: the sandbox to use (default: detected). */
  detect?: () => RunPlatform;
  /** Tests only: the proxy's upstream dial (default: DNS with address checks). */
  dial?: ProxyOptions["dial"];
  /** Tests only: capture the child's output instead of passing the terminal through. */
  capture?: boolean;
  /** Run under /usr/bin/script with its own pseudo-terminal (macOS; default: ttyWrapNeeded, when the run can reach a terminal). */
  ttyWrap?: boolean;
  /** Tests only: what the terminal check sees (default: this process's descriptors and /dev/tty). */
  ttyProbe?: () => TtyProbe;
  /** `--pass-env NAME` (or NAME_*): variables of the person's environment passed on beyond the base list (guards.ts BASE_ENV). */
  passEnv?: string[];
  /** `--allow-home-read NAME`: entries of HOME_UNREADABLE_OPTIONAL left readable for this run. */
  allowHomeRead?: string[];
  /** `--env NAME=vault://…` values (resolved by src/runtime/run/vault-env.ts), set in the child's environment only. */
  extraEnv?: Record<string, string>;
  /** `--git-init`: when the workspace has no `.git`, run `git init` in it (outside the sandbox) before the run starts. */
  gitInit?: boolean;
  /**
   * `--agent claude|codex|gemini` (docs/run.md, "Agent presets"): the agent's model API as send hosts for this
   * run and the agent's documented switches against non-essential traffic. It adds nothing else: the file
   * rules are run's own, unchanged, so the agent's credential files stay readable (it needs them) and only
   * writes to them are refused.
   */
  agent?: PresetAgent;
}

/** A preset's effect on the options: the command, the send hosts and the child's extra variables. */
export function applyAgentPreset(o: Pick<RunOptions, "agent" | "command" | "sendHosts" | "extraEnv">): { command: string[]; sendHosts: string[]; extraEnv?: Record<string, string>; note?: string } {
  if (o.agent === undefined) return { command: o.command, sendHosts: o.sendHosts, ...(o.extraEnv !== undefined ? { extraEnv: o.extraEnv } : {}) };
  const p = AGENT_PRESETS[o.agent];
  const command = o.command;
  const first = basename(command[0] ?? p.program);
  const note = first !== p.program && !["npx", "node", "bunx", "pnpx"].includes(first) ? `launchsafe-firewall run: note: --agent ${o.agent} prepares the run for ${p.label} (${p.program}), but the command is ${first}.` : undefined;
  return {
    command,
    sendHosts: [...new Set([...p.sendHosts, ...o.sendHosts])],
    // The preset's variables first: the person's --env values win over them (and run's own over both).
    extraEnv: { ...p.env, ...(o.extraEnv ?? {}) },
    ...(note !== undefined ? { note } : {}),
  };
}

export interface RunResult {
  exitCode: number;
  runId: string;
  stdout: string;
  stderr: string;
  hosts: ProxyHostStats[];
  refusals: { host: string; why: string; reason: string }[];
}

/**
 * What git cannot do inside the run, said once at the start (docs/run.md, Limits): `.git/config` and, in a
 * workspace that is not a repository yet, `.git` itself are protected, so the messages git prints are the
 * ones quoted here.
 */
export const GIT_CONFIG_NOTICE =
  'launchsafe-firewall run: note: .git/config is read-only inside the run, so git commands that change it (git config, git remote add, git push -u, git branch --set-upstream-to, git checkout --track) fail with "could not write config file <workspace>/.git/config" ("Operation not permitted" on macOS, "Device or resource busy" on Linux; or "could not lock config file"). Run them outside run.';
export const GIT_INIT_NOTICE =
  'launchsafe-firewall run: note: this workspace is not a git repository, and .git cannot be created inside the run, so git init fails here (".git: Operation not permitted" on macOS, "Read-only file system" on Linux). Run git init outside run first, or start run with --git-init.';

/** The notice for this workspace: no `.git` at all, or a `.git` directory (a `.git` file points elsewhere: nothing to say). */
export function gitNotice(workspace: string): string | null {
  try {
    return lstatSync(join(workspace, ".git")).isDirectory() ? GIT_CONFIG_NOTICE : null;
  } catch {
    return GIT_INIT_NOTICE;
  }
}

/** Agents whose firewall hooks run as their own child processes (inside the sandbox, under run). */
const HOOKED_AGENTS: Record<string, "claude" | "codex" | "gemini" | "cursor"> = { claude: "claude", codex: "codex", gemini: "gemini", "cursor-agent": "cursor" };

function expandHome(p: string, home: string): string {
  return p === "~" ? home : p.startsWith("~/") ? join(home, p.slice(2)) : p;
}

/** The command's program: a path as given, or the first executable match on PATH. */
export function resolveProgram(name: string, env: NodeJS.ProcessEnv, cwd: string): string | null {
  const ok = (p: string): boolean => {
    try {
      accessSync(p, constants.X_OK);
      return statSync(p).isFile();
    } catch {
      return false;
    }
  };
  if (name.includes("/")) {
    const p = isAbsolute(name) ? name : resolve(cwd, name);
    return ok(p) ? p : null;
  }
  for (const dir of (env.PATH ?? "").split(delimiter)) {
    if (dir === "" || !isAbsolute(dir)) continue;
    const p = join(dir, name);
    if (ok(p)) return p;
  }
  return null;
}

/**
 * The child's environment: the person's variables on the base list (guards.ts BASE_ENV) and `pass` only (I2:
 * a token in the person's shell, GITHUB_TOKEN or AWS_SECRET_ACCESS_KEY, never reaches the command unasked),
 * then `extra` (the preset's variables and `--env` values), then the variables that send the child's traffic
 * to the proxy (and nowhere else). Sockets and proxies of the person's session are dropped even when named.
 */
export function childEnv(base: NodeJS.ProcessEnv, o: { proxyUrl: string; runTmp: string; runId: string; pass?: readonly string[]; extra?: Record<string, string> }): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  const drop = /^(?:https?_proxy|all_proxy|no_proxy|ftp_proxy|socks_proxy|DBUS_SESSION_BUS_ADDRESS|SSH_AUTH_SOCK|SSH_AGENT_PID|GPG_AGENT_INFO|DOCKER_HOST)$/i;
  for (const [k, v] of Object.entries({ ...allowedEnv(base, o.pass ?? []), ...(o.extra ?? {}) })) if (v !== undefined && !drop.test(k)) setOwn(env, k, v);
  for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]) setOwn(env, k, o.proxyUrl);
  env.NO_PROXY = "localhost,127.0.0.1,::1";
  env.no_proxy = env.NO_PROXY;
  // Node's fetch and http honour the proxy variables only with this (Node 22.21+, 24.5+).
  env.NODE_USE_ENV_PROXY = "1";
  env.TMPDIR = o.runTmp;
  env.LAUNCHSAFE_FIREWALL_RUN = o.runId;
  return env;
}

function kind(p: string): "dir" | "file" | null {
  try {
    const s = statSync(p);
    return s.isDirectory() ? "dir" : "file";
  } catch {
    return null;
  }
}

/** Every pid below `root` (Linux /proc), for passing signals to the bridge inside bubblewrap. */
function descendants(root: number): number[] {
  const out: number[] = [];
  const queue = [root];
  while (queue.length > 0 && out.length < 4096) {
    const pid = queue.shift() as number;
    let tasks: string[] = [];
    try {
      tasks = readdirSync(`/proc/${pid}/task`);
    } catch {
      continue;
    }
    for (const t of tasks) {
      try {
        for (const c of readFileSync(`/proc/${pid}/task/${t}/children`, "utf8").trim().split(/\s+/).filter((x) => x !== "")) {
          out.push(Number(c));
          queue.push(Number(c));
        }
      } catch {
        // Gone.
      }
    }
  }
  return out;
}

function bridgePid(bwrapPid: number): number | null {
  for (const pid of descendants(bwrapPid)) {
    try {
      if (readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").includes(BRIDGE_MARKER)) return pid;
    } catch {
      // Gone.
    }
  }
  return null;
}

/**
 * A path as written, every intermediate symlink hop along it, and its resolved target, so a chain of links
 * (`.claude -> link1 -> real_claude`) protects every link in the chain as well as the final target.
 */
function symlinkHops(p: string, workspace: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const walk = (start: string, baseDir: string): void => {
    let cur = resolve(start);
    for (let hop = 0; hop <= 40; hop++) {
      if (seen.has(`${baseDir}\0${cur}`)) break;
      seen.add(`${baseDir}\0${cur}`);
      out.push(cur, realpathLoose(cur));
      const useBase = baseDir !== "/" && cur.startsWith(`${baseDir}/`);
      const parts = (useBase ? cur.slice(baseDir.length + 1) : cur.slice(1)).split("/").filter((x) => x !== "");
      let prefix = useBase ? baseDir : "/";
      let next: string | null = null;
      for (let i = 0; i < parts.length; i++) {
        prefix = prefix === "/" ? `/${parts[i] as string}` : `${prefix}/${parts[i] as string}`;
        let isLink = false;
        try {
          isLink = lstatSync(prefix).isSymbolicLink();
        } catch {
          break;
        }
        if (isLink) {
          try {
            next = join(resolve(dirname(prefix), readlinkSync(prefix)), ...parts.slice(i + 1));
          } catch {
            // Broken or unreadable link.
          }
          break;
        }
      }
      if (next === null) break;
      cur = next;
    }
  };
  const wsAbs = resolve(workspace);
  const wsReal = realpathLoose(wsAbs);
  walk(p, wsAbs);
  if (wsReal !== wsAbs && resolve(p).startsWith(`${wsAbs}/`)) walk(join(wsReal, resolve(p).slice(wsAbs.length + 1)), wsReal);
  return out;
}

/** The `*.code-workspace` files at the top of a writable root (VS Code runs their tasks and settings); only those that exist, since a glob cannot be bound before it matches. */
export function workspaceGlobs(root: string): string[] {
  try {
    return readdirSync(root).filter((n) => n.endsWith(".code-workspace")).map((n) => join(root, n));
  } catch {
    return [];
  }
}

/**
 * What the plan protects: read-only and unreadable paths, from the layout, the install record and the
 * workspace (its fixed list and what it names itself, code-paths.ts). Each path is listed as written and
 * with symlinks resolved (V3): a rule on the resolved path alone would leave the link itself free to be
 * replaced (`.claude` -> elsewhere). `allowWritePaths` (the person's `run.allowWritePaths`, RN6) exempts
 * scripts the agent settings run, and only those: never the fixed list, git's files or the firewall's.
 * `scripts` are the agent-run scripts that stay read-only, for run's notice.
 */
export function protectedPaths(l: Layout, workspace: string, home: string, platform: NodeJS.Platform, allowWritePaths: readonly string[] = [], homeReadable: readonly string[] = []): { readOnly: string[]; unreadable: string[]; scripts: CodePath[]; exempted: string[] } {
  const entries = workspaceCodeEntries(workspace, home);
  const exemptRoots = allowWritePaths.flatMap((e) => {
    const abs = resolve(workspace, expandHome(e, home));
    return [abs, realpathLoose(abs)];
  });
  const ci = platform === "darwin";
  // Only a script an agent settings file runs can be exempted, and never one of git's files (FA1): the kind
  // comes from the path itself (workspaceCodeEntries reclassifies), and is checked again here.
  const exempt = (e: CodePath): boolean => e.kind === "script" && !gitOwnedPath(e.path, workspace) && exemptRoots.some((r) => isUnder(e.path, r, ci) || isUnder(realpathLoose(e.path), r, ci));
  const scripts = entries.filter((e) => e.kind === "script" && !exempt(e));
  const exempted = entries.filter(exempt).map((e) => e.path);
  const kept = entries.filter((e) => !exempt(e)).map((e) => e.path);
  const ro = [l.home, installDir(), ...registeredSettingsFiles(l, platform), ...WORKSPACE_PROTECTED.map((p) => join(workspace, p)), ...workspaceGlobs(workspace), ...kept];
  const homeUn = [...HOME_UNREADABLE, ...HOME_UNREADABLE_OPTIONAL.filter((p) => !homeReadable.includes(p)), ...(platform === "linux" ? LINUX_DOCKER_SOCKET_DIRS : [])];
  const un = [l.keys, approverPath(l), join(l.home, "vault"), ...homeUn.map((p) => join(home, p))];
  const both = (xs: string[]): string[] => [...new Set(xs.flatMap((p) => symlinkHops(p, workspace)))];
  return { readOnly: both(ro), unreadable: both(un), scripts, exempted };
}

/** run's start-up note on the scripts the workspace's agent settings run (RN6): why each is read-only and how to exempt it. */
export function scriptNotice(workspace: string, scripts: readonly CodePath[], userPolicy: string): string | null {
  if (scripts.length === 0) return null;
  const rel = (p: string): string => (p.startsWith(`${workspace}/`) ? p.slice(workspace.length + 1) : p);
  const shown = scripts.slice(0, 5).map((s) => `${rel(s.path)} (${s.source ?? "agent settings"} runs it)`);
  const more = scripts.length > 5 ? ` and ${scripts.length - 5} more` : "";
  return `launchsafe-firewall run: note: read-only inside the run because the workspace's agent settings run them outside the sandbox: ${shown.join(", ")}${more}. Writing them fails with "Operation not permitted" (macOS) or "Read-only file system" (Linux). If the agent must change one (build output an MCP server runs, for example), add its path to "run": { "allowWritePaths": [...] } in your user policy (${userPolicy}; then launchsafe-firewall policy validate); a project policy cannot.`;
}

/**
 * Linux: a protected workspace path reached through a symlink inside the workspace. bubblewrap mounts on
 * the link's target, and the link itself (in a writable directory) could then be replaced by a directory
 * holding a planted file, so the run does not start (V3).
 */
export function linkedProtectedPath(readOnly: readonly string[], workspace: string): string | null {
  for (const p of readOnly) {
    if (!p.startsWith(`${workspace}/`)) continue;
    let cur = workspace;
    for (const part of p.slice(workspace.length + 1).split("/")) {
      cur = join(cur, part);
      try {
        if (lstatSync(cur).isSymbolicLink()) return cur;
      } catch {
        break;
      }
    }
  }
  return null;
}

/** The workspace's fixed protected list and what the directory itself names (nested repositories, core.hooksPath), for a writable root other than the workspace; each path as written and with symlinks resolved. */
export function rootProtectedPaths(root: string, home: string): string[] {
  const xs = [...WORKSPACE_PROTECTED.map((p) => join(root, p)), ...workspaceGlobs(root), ...workspaceCodeEntries(root, home).map((e) => e.path)];
  return [...new Set(xs.flatMap((p) => symlinkHops(p, root)))];
}

/** Builds the plan, or says why the run cannot start. */
export function buildPlan(o: { l: Layout; workspace: string; runTmp: string; allowWrite: string[]; home: string; cwd: string; platform: "darwin" | "linux"; proxyPort: number; allowLocalhost: boolean; allowKeychain: boolean; allowWritePaths?: string[]; allowHomeRead?: string[]; sockets?: (dir: string) => string[] }): { plan: RunPlan; scripts: CodePath[]; exempted: string[]; notes: string[] } | { problem: string } {
  for (const h of o.allowHomeRead ?? []) if (!HOME_UNREADABLE_OPTIONAL.includes(h)) return { problem: `--allow-home-read ${h}: not one of ${HOME_UNREADABLE_OPTIONAL.join(", ")} (~/.ssh, ~/.aws and ~/.gnupg stay unreadable)` };
  const ci = o.platform === "darwin";
  let workspace: string;
  try {
    workspace = realpathSync(o.workspace);
  } catch {
    return { problem: `the workspace ${o.workspace} does not exist` };
  }
  if (kind(workspace) !== "dir") return { problem: `the workspace ${workspace} is not a directory` };
  const realHome = realpathLoose(o.home);
  const prot = protectedPaths(o.l, workspace, realHome, o.platform, o.allowWritePaths ?? [], o.allowHomeRead ?? []);
  if (o.platform === "linux") {
    const link = linkedProtectedPath(prot.readOnly, workspace);
    if (link !== null) return { problem: `${link} is a symlink on the way to a file the run keeps read-only (agent settings, git hooks or config). On Linux the sandbox can protect only the link's target, not the link itself, which the command could replace. Replace the link with the directory or file it points to, or run from another workspace` };
  }
  const wsProblem = writePathProblem(workspace, realHome, [], ci);
  if (wsProblem !== null) return { problem: `the workspace ${workspace} cannot be made writable: ${wsProblem}. Run from a project directory or pass --workspace DIR` };
  const extra: string[] = [];
  const notes: string[] = [];
  for (const raw of o.allowWrite) {
    const abs = realpathLoose(resolve(o.cwd, expandHome(raw, o.home)));
    if (kind(abs) !== "dir") return { problem: `--allow-write ${raw}: ${abs} is not an existing directory` };
    const why = writePathProblem(abs, realHome, [...prot.readOnly, ...prot.unreadable], ci);
    if (why !== null) return { problem: `--allow-write ${raw} refused: ${why}` };
    // I5: a directory where other programs keep their sockets (/tmp: tmux, X11, editors' servers). On Linux a
    // bound directory's sockets can be connected to from inside (a tmux socket types into your terminal); on
    // macOS the profile allows connecting only in the workspace and the run's directory, but a writable
    // directory still lets the command delete or replace them.
    const socks = (o.sockets ?? socketsIn)(abs);
    if (socks.length > 0) {
      const shown = socks.slice(0, 3).join(", ") + (socks.length > 3 ? ` and ${socks.length - 3} more` : "");
      if (o.platform === "linux") return { problem: `--allow-write ${raw} refused: it holds Unix sockets that programs outside the sandbox listen on (${shown}); the command could connect to them. Give it a directory of its own (mkdir ~/scratch/build-tmp; --allow-write ~/scratch/build-tmp)` };
      notes.push(`launchsafe-firewall run: note: --allow-write ${raw} holds Unix sockets of other programs (${shown}); the command cannot connect to them, but it can delete or replace them. A directory of its own is safer.`);
    }
    extra.push(abs);
  }
  // Every writable root gets the same protected paths as the workspace (git hooks and config, .envrc, agent
  // settings, MCP lists, editor tasks, nested repositories' rules): an --allow-write directory that is a
  // repository, or holds one, would otherwise be a place to plant a hook that runs outside the sandbox.
  const readOnly = [...prot.readOnly];
  for (const root of extra) {
    const mine = rootProtectedPaths(root, realHome);
    if (o.platform === "linux") {
      const link = linkedProtectedPath(mine, root);
      if (link !== null) return { problem: `${link} is a symlink on the way to a file the run keeps read-only (agent settings, git hooks or config). On Linux the sandbox can protect only the link's target, not the link itself, which the command could replace. Replace the link with the directory or file it points to, or drop --allow-write for ${root}` };
    }
    for (const q of mine) if (!readOnly.includes(q)) readOnly.push(q);
  }
  return {
    notes,
    scripts: prot.scripts,
    exempted: prot.exempted,
    plan: {
      platform: o.platform,
      workspace,
      runTmp: o.runTmp,
      writable: [...new Set([workspace, o.runTmp, ...extra])],
      readOnly,
      unreadable: prot.unreadable,
      socketDirs: [workspace, o.runTmp],
      proxyPort: o.proxyPort,
      allowLocalhost: o.allowLocalhost,
      allowKeychain: o.allowKeychain,
    },
  };
}

/**
 * The knownHosts settings that decide what `run`'s proxy admits: the user and managed policy only. A
 * repository's `.launchsafe-firewall.json` may switch the hooks' question on (tighter there), but here
 * "on" means admitting the approved hosts, which is looser than the policy's lists alone.
 */
export function runKnownHosts(l: Layout, platform: NodeJS.Platform = process.platform, managedPath?: string): KnownHostsPolicy {
  return knownHostsPolicy(loadPolicy(l, [], platform, managedPath).config);
}

/** Most distinct hosts one run records for knownHosts watch. */
export const RUN_WATCH_CAP = 200;

/**
 * knownHosts watch under `run`: hosts the proxy refused as not listed are collected in memory (at most
 * RUN_WATCH_CAP per run) and written in one batch every `everyMs` and when the run ends, never once per
 * connection, so a program that tries thousands of names cannot turn the proxy into a disk writer.
 */
export function runWatchBuffer(flush: (hosts: string[]) => unknown, warn: (msg: string) => void, everyMs = 30000): { add(host: string): void; close(): void; size(): number } {
  const all = new Set<string>();
  let pending: string[] = [];
  const write = (): void => {
    if (pending.length === 0) return;
    const batch = pending;
    pending = [];
    try {
      flush(batch);
    } catch (e) {
      warn(`could not record ${batch.length} host(s) for knownHosts watch (${(e as Error).message})`);
    }
  };
  const timer = setInterval(write, everyMs);
  timer.unref();
  return {
    add(host: string): void {
      if (all.has(host) || all.size >= RUN_WATCH_CAP) return;
      all.add(host);
      pending.push(host);
    },
    close(): void {
      clearInterval(timer);
      write();
    },
    size: () => all.size,
  };
}

/**
 * The workspace's approved hosts (knownHosts) for the proxy, read again at most once a second, so a host a
 * person approves while the run lasts (a yes to the agent's own hook, or `hosts allow` in another terminal)
 * is admitted from then on. A file that cannot be read is no approved hosts (refuse, never admit).
 */
export function knownHostsReader(l: Layout, workspace: string, clock: () => number = Date.now): () => readonly string[] {
  let at = -Infinity;
  let hosts: readonly string[] = [];
  return () => {
    const now = clock();
    if (now - at >= 1000) {
      at = now;
      try {
        hosts = approvedHosts(l, workspace);
      } catch {
        hosts = [];
      }
    }
    return hosts;
  };
}

/** One line per host for the summary and the dry run. */
export function describeHosts(p: RunNetPolicy): string[] {
  const out = p.allowed.map((h) => `  ${h.domain.padEnd(34)} ${h.kind}${h.uploadCapable ? ", upload-capable" : ""}`);
  for (const d of p.dropped) out.push(`  left out: ${d.pattern} (${d.reason})`);
  return out;
}

const MAX_DENY_LOGS = 20;
/** Most distinct (host, reason) pairs a run tracks for refusals; the rest share one `*other*` bucket per reason (a program that tries thousands of names cannot grow the maps). */
export const MAX_DENY_KEYS = 512;
/** Most refusal entries one run signs into the log, however many hosts it tries. */
export const MAX_DENY_LOG_TOTAL = 1000;

/**
 * The proxy's events as log entries (run_net, run_budget): a host's first allow, and the first
 * MAX_DENY_LOGS refusals per host and reason. LG1: a host's first allowed connection is made only once it is
 * recorded; when the log refuses the entry and its fallback entry the connection is refused
 * (FW-LOG-UNRECORDED) and the next one tries again. An I/O failure is reported by `record` and the
 * connection stands, as on the hook path (docs/limitations.md).
 */
export function runNetEvents(record: (event: Record<string, unknown>) => "ok" | "failed" | "unrecorded", refusals: RunResult["refusals"], verboseWarn?: (msg: string) => void): ((e: ProxyEvent) => boolean) & { refused(): number } {
  const firstAllow = new Set<string>();
  const denyCounts = new Map<string, number>();
  let denyLogged = 0;
  const onEvent = (e: ProxyEvent): boolean => {
    if (e.type === "budget") {
      record({ type: "run_budget", host: e.host, rule: e.hit.rule, key: e.hit.key, limit: e.hit.limit, used: e.hit.used });
      return true;
    }
    if (e.verdict === "allow") {
      if (firstAllow.has(e.host)) return true;
      if (record({ type: "run_net", verdict: "allow", host: e.host, port: e.port, method: e.method, ...(e.kind !== undefined ? { kind: e.kind } : {}), ...(e.known === true ? { known: true } : {}), ...(e.uploadCapable === true ? { uploadCapable: true } : {}) }) === "unrecorded") {
        const k = `${e.host}\u0000unrecorded`;
        if (!denyCounts.has(k)) refusals.push({ host: e.host, why: "unrecorded", reason: "the decision log refused to record this connection (rule FW-LOG-UNRECORDED)" });
        denyCounts.set(k, (denyCounts.get(k) ?? 0) + 1);
        return false;
      }
      firstAllow.add(e.host);
      return true;
    }
    let k = `${e.host}\u0000${e.why ?? ""}`;
    let shown = e.host;
    if (!denyCounts.has(k) && denyCounts.size >= MAX_DENY_KEYS) {
      k = `*other*\u0000${e.why ?? ""}`;
      shown = "*other*";
    }
    const n = (denyCounts.get(k) ?? 0) + 1;
    denyCounts.set(k, n);
    if (n === 1) refusals.push({ host: shown, why: e.why ?? "", reason: e.reason });
    if (n <= MAX_DENY_LOGS && denyLogged < MAX_DENY_LOG_TOTAL) {
      denyLogged++;
      record({ type: "run_net", verdict: "deny", host: e.host, port: e.port, method: e.method, why: e.why, ...(e.rule !== undefined ? { rule: e.rule } : {}), reason: e.reason });
    }
    if (verboseWarn !== undefined && n <= 3) verboseWarn(printable(`launchsafe-firewall run: refused ${e.host}:${e.port}: ${e.reason}`));
    return true;
  };
  /** Connections refused so far (by the policy, a budget, or an unrecorded entry). */
  return Object.assign(onEvent, { refused: (): number => [...denyCounts.values()].reduce((a, b) => a + b, 0) });
}


/** Kills the process group `pgid` (a child spawned detached leads its own); never throws. */
export function killGroup(pgid: number, kill: (pid: number, sig: NodeJS.Signals) => void = process.kill): void {
  if (!Number.isInteger(pgid) || pgid <= 1) return;
  try {
    kill(-pgid, "SIGKILL");
  } catch {
    // Nothing left in it.
  }
}

/**
 * I10: hooks, MCP servers and tasks the workspace's agent settings start through a runner (npm run, npx, make,
 * python -m, node_modules/.bin): the code they run is in files run cannot keep read-only (package.json's
 * scripts, a Makefile, an installed package), so what the command changes there runs later, outside the sandbox.
 */
export function runnerNotice(workspace: string): string | null {
  const found = runnerCommands(workspace);
  if (found.length === 0) return null;
  const shown = found.slice(0, 4).map((f) => `${f.runner} in ${f.source}`).join(", ");
  return `launchsafe-firewall run: warning: the workspace's agent settings start programs through a runner (${shown}${found.length > 4 ? ` and ${found.length - 4} more` : ""}). What a runner runs (package.json scripts, a Makefile, node_modules, a Python module) stays writable inside the run, so a change made there runs later outside the sandbox, when the agent next starts that hook or server. Review such changes before your next session, or name a script file in the settings instead.`;
}

/** The exit status the macOS bridge wrote before its clean-up kill; null when there is none or it is not a plain number. */
function bridgeStatus(file: string): number | null {
  try {
    if (!lstatSync(file).isFile()) return null;
    const t = readFileSync(file, "utf8").trim();
    return /^\d{1,3}$/.test(t) ? Number(t) : null;
  } catch {
    return null;
  }
}

/** Runs the command in the sandbox. Returns its exit status (128+n for a signal). */
export async function runSandboxed(opts: RunOptions): Promise<RunResult> {
  let o = opts;
  const platformName = o.platform ?? process.platform;
  const runId = `run-${new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)}-${randomBytes(4).toString("hex")}`;
  const result: RunResult = { exitCode: 0, runId, stdout: "", stderr: "", hosts: [], refusals: [] };
  const preset = applyAgentPreset(o);
  o = { ...o, command: preset.command, sendHosts: preset.sendHosts, ...(preset.extraEnv !== undefined ? { extraEnv: preset.extraEnv } : {}) };
  if (preset.note !== undefined) o.warn(preset.note);
  const fail = (code: number, msg: string): RunResult => {
    o.warn(`launchsafe-firewall run: ${msg}`);
    return { ...result, exitCode: code };
  };
  if (o.command.length === 0) return fail(64, 'give the command after "--": launchsafe-firewall run -- <command> [args...]');
  for (const p of o.passEnv ?? []) {
    const why = passEnvProblem(p);
    if (why !== null) return fail(64, why);
  }
  if (o.env.LAUNCHSAFE_FIREWALL_RUN !== undefined && o.env.LAUNCHSAFE_FIREWALL_RUN !== "") return fail(1, "this is already inside launchsafe-firewall run; a nested run would add nothing");
  const sb = (o.detect ?? (() => detectRunPlatform({ platform: platformName })))();
  if (sb.kind === "none") return fail(EXIT_UNAVAILABLE, `no usable sandbox on this machine: ${sb.reason}. ${sb.hint}. Nothing was started.`);
  const os = sb.kind === "seatbelt" ? "darwin" : "linux";
  const program = resolveProgram(o.command[0] as string, o.env, o.cwd);
  if (program === null) return fail(EXIT_NOT_FOUND, `${o.command[0] as string}: command not found (on PATH, or as a path)`);

  const pol = loadPolicy(o.layout, [o.workspace], platformName);
  if (pol.error !== undefined) o.warn(`launchsafe-firewall run: the policy is invalid (${pol.error}); running with the strict defaults.`);
  const cfg: FirewallConfig = pol.config;
  // Known hosts: what the proxy admits follows the user and managed policy only (runKnownHosts).
  const known = runKnownHosts(o.layout, platformName);
  const net = runNetPolicy(cfg, { sendHosts: o.sendHosts, knownHostsFrom: { knownHosts: known } });
  if (net.problems.length > 0) return fail(1, `${net.problems.join("; ")}. Nothing was started.`);
  const hooked = own(HOOKED_AGENTS, basename(program));
  if (hooked !== undefined) {
    let recs: ReturnType<typeof readRecords> = [];
    try {
      recs = readRecords(o.layout);
    } catch {
      recs = [];
    }
    if (recs.some((r) => (r.agent ?? "claude") === hooked)) o.warn(`launchsafe-firewall run: warning: ${basename(program)} runs the firewall's hooks as its own child processes, so they run inside this sandbox, where the firewall's files are read-only: every risky action will be blocked. ${hooked === "claude" ? 'Claude Code has its own sandbox: run "launchsafe-firewall doctor --fix" instead.' : "Prefer the agent's own sandbox, or run it without the firewall's hooks."}${o.agent !== undefined ? " To keep the hooks judging every action with the sandbox as the outer wall, run the agent in an OpenShell sandbox with the firewall's middleware (docs/sandboxes.md)." : ""}`);
  }

  // --git-init: the person asked for a repository, created here, outside the sandbox, before the plan reads .git.
  if (o.gitInit === true) {
    let hasGit = true;
    try {
      lstatSync(join(o.workspace, ".git"));
    } catch {
      hasGit = false;
    }
    if (hasGit) o.warn("launchsafe-firewall run: --git-init: the workspace already has .git; nothing to do.");
    else if (o.dryRun) o.say(`Would run git init in ${o.workspace} before the run starts (--git-init).`);
    else {
      const r = spawnSync("git", ["init", "-q", o.workspace], { env: o.env, cwd: o.cwd, encoding: "utf8" });
      if (r.status !== 0) return fail(1, `--git-init: git init failed (${(r.error?.message ?? r.stderr ?? "").trim()}). Nothing was started.`);
      o.say(`launchsafe-firewall run: --git-init: created a git repository in ${o.workspace}.`);
    }
  }

  // Directories: the run's temporary directory (writable inside) and, on Linux, the proxy socket's (read-only inside).
  const tmpRoot = realpathSync(tmpdir());
  const runTmp = realpathSync(mkdtempSync(join(tmpRoot, "lsfw-run-")));
  const sockDir = os === "linux" ? realpathSync(mkdtempSync(join(tmpRoot, "lsfw-sock-"))) : null;
  const cleanup = (): void => {
    rmSync(runTmp, { recursive: true, force: true });
    if (sockDir !== null) rmSync(sockDir, { recursive: true, force: true });
  };
  const insidePort = os === "linux" ? 3128 : 0;
  const planned = buildPlan({ l: o.layout, workspace: o.workspace, runTmp, allowWrite: o.allowWrite, home: o.home, cwd: o.cwd, platform: os, proxyPort: insidePort === 0 ? 1 : insidePort, allowLocalhost: o.allowLocalhost, allowKeychain: o.allowKeychain, allowWritePaths: runAllowWritePaths(cfg), ...(o.allowHomeRead !== undefined ? { allowHomeRead: o.allowHomeRead } : {}) });
  if ("problem" in planned) {
    cleanup();
    return fail(1, `${planned.problem}. Nothing was started.`);
  }
  const command = [program, ...o.command.slice(1)];

  if (o.dryRun) {
    const plan = { ...planned.plan, proxyPort: insidePort === 0 ? 1 : insidePort };
    o.say(`launchsafe-firewall run (dry run): ${sb.detail}`);
    o.say(`Command: ${command[0] as string} (${command.length - 1} argument${command.length === 2 ? "" : "s"})`);
    if (o.agent !== undefined) {
      const p = AGENT_PRESETS[o.agent];
      o.say(`Agent preset: ${p.label}: send hosts ${p.sendHosts.join(", ")}${Object.keys(p.env).length > 0 ? `; environment ${Object.entries(p.env).map(([k, v]) => `${k}=${v}`).join(" ")}` : ""}; ${p.stateDir} is read-only but readable: the agent's credentials there can be read by every program in the run, and ${p.sendHosts.join(", ")} receives whatever is sent there, unbudgeted`);
    }
    o.say(`Writable: ${plan.writable.join(", ")}`);
    o.say(`Read-only: ${plan.readOnly.join(", ")}`);
    o.say(`Unreadable: ${plan.unreadable.join(", ")}`);
    o.say(`Network: only through the run's proxy${os === "darwin" ? (plan.allowLocalhost ? "; other 127.0.0.1 ports allowed (--allow-localhost)" : "; no other 127.0.0.1 port") : "; the sandbox has its own loopback"}. Hosts the proxy admits (fetchAllowHosts, sendAllowHosts, --send-host):`);
    for (const line of describeHosts(net.policy)) o.say(line);
    if (net.policy.knownHosts) {
      const approved = approvedHosts(o.layout, o.workspace);
      o.say(approved.length === 0 ? "  approved for this project (knownHosts): none yet" : `  approved for this project (knownHosts), fetch-only: ${approved.map((h) => (hostInList(h, UPLOAD_CAPABLE) ? `${h} (upload-capable)` : h)).join(", ")}`);
    }
    if (os === "darwin") {
      o.say("\nSeatbelt profile (the proxy port is chosen when the run starts; 1 stands for it here):");
      const args = sandboxExecArgs(plan, command);
      const p = args.indexOf("-p");
      o.say(args[p + 1] as string);
      o.say(`Parameters: ${args.slice(0, p).filter((_, i) => i % 2 === 1).join("  ")}`);
    } else {
      o.say("\nbubblewrap arguments:");
      o.say(bwrapArgs(plan, { socketDir: sockDir as string, insideSocketDir: "/run/lsfw", socketName: "proxy.sock", nodePath: process.execPath, bridgeSource: "<bridge>", exists: kind, cwd: o.cwd }, command).join(" "));
    }
    o.say("\nDry run: nothing was started.");
    cleanup();
    return result;
  }

  // The signed log: if the start cannot be recorded, nothing starts. LG1: events are bounded, with the
  // fallback entry, as the hook writes them; "unrecorded" means the log refused both.
  assertNotRealHome(o.layout.log);
  const record = (event: Record<string, unknown>): "ok" | "failed" | "unrecorded" => {
    try {
      appendBounded(o.layout, { ...event, run: runId });
      return "ok";
    } catch (e) {
      o.warn(`launchsafe-firewall run: could not write the decision log (${(e as Error).message})`);
      return isLogUnrecorded(e) ? "unrecorded" : "failed";
    }
  };
  const log = (event: Record<string, unknown>): boolean => record(event) === "ok";

  const budgets = new RunBudgets(net.policy);
  const netEvents = runNetEvents(record, result.refusals, o.verbose ? o.warn : undefined);
  // Known hosts: the workspace's approved hosts are admitted (read when a connection opens), and in "watch"
  // mode the hosts refused as not listed are recorded for `hosts review` (listed apart: run has no taint tracking).
  const knownHosts = known.mode !== "off" ? knownHostsReader(o.layout, o.workspace) : undefined;
  const watch = known.mode === "watch" ? runWatchBuffer((hosts) => recordSeen(o.layout, o.workspace, hosts.map((host) => ({ host, tainted: false })), "run", known.watchDays, new Date()), (msg) => o.warn(`launchsafe-firewall run: ${msg}`)) : null;
  const onEvent = (e: ProxyEvent): boolean => {
    if (watch !== null && e.type === "net" && e.verdict === "deny" && e.why === "not-listed") watch.add(e.host);
    return netEvents(e);
  };

  let proxy: RunningProxy;
  try {
    proxy = await startProxy({ policy: net.policy, budgets, listen: sockDir !== null ? { path: join(sockDir, "proxy.sock") } : { host: "127.0.0.1" }, onEvent, localAnswers: { loopback: o.allowLocalhost && os === "darwin", privateHosts: runPrivateHosts(cfg) }, ...(knownHosts !== undefined ? { knownHosts } : {}), ...(o.dial !== undefined ? { dial: o.dial } : {}) });
  } catch (e) {
    watch?.close();
    cleanup();
    return fail(1, `could not start the proxy: ${(e as Error).message}`);
  }
  const port = os === "linux" ? insidePort : (proxy.port as number);
  const plan: RunPlan = { ...planned.plan, proxyPort: port };
  const started = Date.now();
  if (!log({ type: "run_start", ...(o.agent !== undefined ? { agent: o.agent } : {}), program: basename(program), args: command.length - 1, workspace: plan.workspace, sandbox: sb.kind, hosts: net.policy.allowed.length, sendHosts: net.policy.sendHosts, allowWrite: plan.writable.slice(2), localhost: plan.allowLocalhost, keychain: plan.allowKeychain })) {
    await proxy.close();
    watch?.close();
    cleanup();
    return fail(1, "the start of the run could not be recorded in the signed log, so nothing was started");
  }

  for (const n of [gitNotice(plan.workspace), scriptNotice(plan.workspace, planned.scripts, o.layout.policy), runnerNotice(plan.workspace), ...planned.notes]) if (n !== null) o.warn(n);
  if (planned.exempted.length > 0) o.warn(`launchsafe-firewall run: note: writable by your run.allowWritePaths although agent settings run them: ${planned.exempted.map((p) => (p.startsWith(`${plan.workspace}/`) ? p.slice(plan.workspace.length + 1) : p)).join(", ")}.`);

  // The run's own variables (proxy, TMPDIR, LAUNCHSAFE_FIREWALL_RUN) win over --env ones; of the person's
  // own, only the base list, --pass-env and the preset's key variables (I2).
  const pass = [...(o.passEnv ?? []), ...(o.agent !== undefined ? PRESET_PASS_ENV[o.agent] : [])];
  const env = childEnv(o.env, { proxyUrl: `http://127.0.0.1:${port}`, runTmp, runId, pass, ...(o.extraEnv !== undefined ? { extra: o.extraEnv } : {}) });
  let child: ChildProcess;
  let mounts: MountRegistry | null = null;
  const statusFile = join(runTmp, ".lsfw-exit");
  const stdio: StdioOptions = o.capture === true ? ["ignore", "pipe", "pipe"] : "inherit";
  // B1 (macOS): a pseudo-terminal of its own whenever the run can reach a terminal (any of 0, 1, 2, or /dev/tty).
  const wrap = sb.kind === "seatbelt" && (o.ttyWrap ?? (o.capture !== true && ttyWrapNeeded((o.ttyProbe ?? defaultTtyProbe)())));
  if (sb.kind === "seatbelt") {
    const args = sandboxExecArgs(plan, [process.execPath, "-e", SEATBELT_BRIDGE_SOURCE, BRIDGE_MARKER, statusFile, "--", ...command]);
    // Unwrapped (no terminal anywhere), the command gets a process group of its own, which run kills at the
    // end, so a program it left in the background does not outlive the run's proxy and directory.
    child = wrap ? spawn("/usr/bin/script", ["-q", "/dev/null", sb.path, ...args], { env, cwd: o.cwd, stdio }) : spawn(sb.path, args, { env, cwd: o.cwd, stdio, detached: true });
  } else {
    // V7: the mount points for protected paths that do not exist yet (shared with other runs in this workspace).
    try {
      // The registry the hooks inside consult (their environment is derived from o.env): firewall-owned, read-only inside (FA3).
      // The claims carry the run id, which is how a reader inside this run (another pid namespace) knows its own.
      mounts = mountRegistry(defaultRegistryRoot(o.env), process.pid, runId);
      const missing = bwrapMissing(plan, kind);
      const shared = mounts.inUse([...plan.readOnly, ...guardedAncestors(plan.readOnly, plan.writable, false)]);
      mounts.claim([...missing.created, ...shared]);
      // File stand-ins for files git reads (`.git/commondir`): written here, with the content git expects
      // when the file is absent, so git outside the run works while it lasts; bwrapArgs binds each read-only.
      for (const f of missing.files) {
        try {
          writeFileSync(f.path, f.content, { flag: "wx", mode: 0o644 });
        } catch (e) {
          // Another run in this workspace wrote the same stand-in a moment ago: it is shared like the others.
          if ((e as NodeJS.ErrnoException).code !== "EEXIST" || !placeholderFile(f.path)) throw e;
        }
      }
    } catch (e) {
      try {
        mounts?.release();
      } catch {
        // The claims expire with this process.
      }
      await proxy.close();
      watch?.close();
      cleanup();
      return fail(1, `could not prepare the sandbox's mount points (${(e as Error).message}). Nothing was started.`);
    }
    const args = bwrapArgs(plan, { socketDir: sockDir as string, insideSocketDir: "/run/lsfw", socketName: "proxy.sock", nodePath: process.execPath, bridgeSource: BRIDGE_SOURCE, exists: kind, cwd: o.cwd }, command);
    // Its own process group: a Ctrl-C at the terminal reaches run, which passes it to the bridge (bubblewrap would die of it).
    child = spawn(sb.path, args, { env, cwd: o.cwd, stdio, detached: true });
  }
  if (o.capture === true) {
    child.stdout?.on("data", (c: Buffer) => (result.stdout += c.toString("utf8")));
    child.stderr?.on("data", (c: Buffer) => (result.stderr += c.toString("utf8")));
  }

  // Signals: on macOS under script, script shares the terminal's process group and gets Ctrl-C itself.
  const forward = (sig: NodeJS.Signals): void => {
    if (child.pid === undefined) return;
    const target = sb.kind === "bwrap" ? (bridgePid(child.pid) ?? child.pid) : child.pid;
    try {
      process.kill(target, sig);
    } catch {
      // Already gone.
    }
  };
  const handlers: [NodeJS.Signals, () => void][] = (["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGWINCH"] as NodeJS.Signals[]).map((sig) => [sig, () => (wrap && (sig === "SIGINT" || sig === "SIGQUIT" || sig === "SIGWINCH") ? undefined : forward(sig))]);
  for (const [sig, h] of handlers) process.on(sig, h);

  let exit = await new Promise<{ code: number; signal: string | null }>((done) => {
    child.on("error", (e) => {
      o.warn(`launchsafe-firewall run: could not start the sandbox: ${e.message}`);
      done({ code: 126, signal: null });
    });
    child.on("close", (code, signal) => done({ code: code ?? 128 + (signal !== null ? (osConstants.signals[signal] ?? 0) : 0), signal }));
  });
  for (const [sig, h] of handlers) process.removeListener(sig, h);
  // macOS: the bridge's clean-up kill can end the bridge itself (status 137, or a SIGKILL); its own status is in the file.
  if (sb.kind === "seatbelt" && (exit.code === 137 || exit.signal === "SIGKILL")) {
    const st = bridgeStatus(statusFile);
    if (st !== null) exit = { code: st, signal: null };
  }
  // macOS, unwrapped: whatever the command left running in its process group goes before the proxy and the
  // run's directory do. (Wrapped, the pseudo-terminal's hangup ends the command's session; Linux: bubblewrap's
  // --die-with-parent and its pid namespace end everything.)
  if (sb.kind === "seatbelt" && !wrap && child.pid !== undefined) killGroup(child.pid);
  try {
    mounts?.release();
  } catch (e) {
    o.warn(`launchsafe-firewall run: could not remove the empty mount-point directories it created (${(e as Error).message})`);
  }
  await proxy.close();
  watch?.close();
  result.hosts = proxy.stats();
  result.exitCode = exit.code;
  const refusedTotal = netEvents.refused();
  log({ type: "run_end", exit: exit.code, ...(exit.signal !== null ? { signal: exit.signal } : {}), durationMs: Date.now() - started, refused: refusedTotal, hosts: result.hosts.slice(0, 50) });
  cleanup();
  if (result.refusals.length > 0) {
    o.warn(`\nlaunchsafe-firewall run: ${refusedTotal} connection${refusedTotal === 1 ? " was" : "s were"} refused (log: launchsafe-firewall log tail):`);
    // Host names and reasons come from what the command sent: no control characters reach your terminal.
    for (const r of result.refusals.slice(0, 12)) o.warn(printable(`  ${r.host}: ${r.reason}`));
    if (result.refusals.length > 12) o.warn(`  ... and ${result.refusals.length - 12} more host(s)`);
  }
  return result;
}
