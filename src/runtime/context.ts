/**
 * Builds the engine's Context from a hook's input and environment: which
 * directory is the workspace, which are scratch, how to resolve symlinks,
 * and whether a person is there to answer an approval.
 */

import { gatewayConfigs } from "../gateway/install.js";
import { readFileSync, statSync } from "node:fs";
import { realpathLoose, realpathStrict } from "./realpath.js";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { inUnattendedHours } from "../policy.js";
import type { Context, FirewallConfig } from "../types.js";
import { atomicWrite, readText, tryReadText } from "./fsutil.js";
import { runMountPoint } from "./run/mountpoints.js";
import { homedir as osHomedir } from "node:os";
import { installDir, safeId, type Layout } from "./layout.js";
import { MANAGED_SETTINGS_PATHS, readRecords } from "./install.js";
import { loadSandboxProfiles } from "./sandbox.js";
import { sandboxPolicy } from "../engine/sandbox.js";
import { registersFirewall, tomlFlatten } from "../engine/settings.js";
import { loadIdentity } from "./identity.js";
import { loadCanaryIndex } from "./canaries.js";
import { openIntel } from "./intel.js";
import { readLockfiles } from "./lockfiles.js";
import { codexHome } from "../adapters/codex.js";
import { geminiHome, geminiSystemSettings } from "../adapters/gemini.js";
import { CURSOR_ENTERPRISE_HOOKS, cursorHome } from "../adapters/cursor.js";
import { approverPublicKey } from "./approver.js";
import { loadIndex, vaultView } from "./vault/index.js";
import { loadScratch, scratchPatterns } from "./scratch.js";
import { withRotatingPrints } from "../gateway/oauth-vault.js";
import { vaultPolicy } from "../policy-vault.js";
import { own } from "../own.js";
import { testMarker } from "./guard.js";
import { processArgs, uninspectedReason, type ProcessProbe } from "./ancestry.js";

export { realpathLoose };

function withReal(paths: readonly string[]): string[] {
  const out = new Set<string>();
  for (const p of paths) {
    if (p === "") continue;
    out.add(resolve(p));
    out.add(realpathLoose(resolve(p)));
  }
  return [...out];
}

export interface HookBasics {
  sessionId: string;
  cwd: string;
  permissionMode?: string;
  scratchpadDir?: string;
  mcpSource?: string;
}

const CLAUDE_PRINT = "Claude Code is running non-interactively (-p)";

/**
 * Why the Claude Code process for this session is unattended, or null: it runs non-interactively (-p / --print),
 * or its command line could not be read at all (no /proc entry, no ps), which is taken as unattended, the strict
 * reading. An answer from a process that was read is cached per session; one that could not be read is not, so
 * a failure that passes (a ps that timed out) does not make the whole session unattended.
 */
export function nonInteractiveClaude(l: Layout, sessionId: string, env: NodeJS.ProcessEnv, probe: ProcessProbe = {}): string | null {
  const cache = join(l.sessions, `${safeId(sessionId)}.meta.json`);
  // The processes asked about. A session id outlives a process (`claude -p --resume` continues an interactive session, and the
  // other way round), so an answer is only reused for the same process ids.
  const pids = [env.CLAUDE_PID, String(process.ppid)].filter((x): x is string => x !== undefined && /^\d+$/.test(x));
  const who = pids.join(",");
  // FZ7: the cache is an optimization; one that cannot be read is detected again.
  const cached = tryReadText(cache);
  if (typeof cached === "string") {
    try {
      const c = JSON.parse(cached) as { nonInteractive?: unknown; pids?: unknown };
      if (c.pids === who && typeof c.nonInteractive === "boolean") return c.nonInteractive ? CLAUDE_PRINT : null;
    } catch {
      // Re-detect below.
    }
  }
  let result = false;
  let inspected = false;
  for (const pid of pids) {
    const args = processArgs(Number(pid), probe);
    if (args === null) continue;
    inspected = true;
    if (/(?:^|\s)(?:-p|--print)(?:\s|$)/.test(args)) {
      result = true;
      break;
    }
  }
  // processArgs runs ps alone off Linux (no pgrep fallback), and the reason says so.
  if (!inspected) return uninspectedReason("Claude Code", probe.platform, false);
  try {
    atomicWrite(cache, JSON.stringify({ nonInteractive: result, pids: who }));
  } catch {
    // Cache is an optimization only.
  }
  return result ? CLAUDE_PRINT : null;
}

export interface ContextOptions {
  l: Layout;
  cfg: FirewallConfig;
  basics: HookBasics;
  env: NodeJS.ProcessEnv;
  now?: Date;
  /** Skip the process inspection (tests). */
  detectNonInteractive?: (sessionId: string) => boolean;
  /** The home directory (tests and the scenario harness; default os.homedir()). */
  home?: string;
  /** Scratch directories, replacing the OS temporary directories (the scenario harness). */
  scratchRoots?: string[];
  /** The project directory an adapter for another agent determined (default: CLAUDE_PROJECT_DIR, else cwd). */
  projectDir?: string;
  /** Why the agent's session is unattended (another agent's adapter), replacing the Claude Code process check. */
  agentUnattended?: () => string | null;
  /** Where the Claude Code process check reads the process table (tests; default /proc on Linux, else ps). */
  processProbe?: ProcessProbe;
}

/** The system's temporary directories, wherever TMPDIR points. */
const FIXED_SCRATCH: readonly string[] = ["/tmp", "/private/tmp", "/var/tmp"];
/** Per-user temporary directories (macOS's /var/folders/...), trusted as TMPDIR only when TMPDIR resolves under them. */
const TMP_PARENTS: readonly string[] = ["/tmp", "/private/tmp", "/var/tmp", "/var/folders", "/private/var/folders"];

/**
 * Item 2: TMPDIR (os.tmpdir) is a scratch root only when it resolves under the system's temporary directories: an
 * agent's settings `env` could otherwise point it at the home directory and make every file there writable scratch.
 * While a test marker is set (cleared by the installed hook command) the test's own temporary directory counts.
 */
function trustedTmpdir(env: NodeJS.ProcessEnv): string[] {
  const t = tmpdir();
  if (testMarker(env)) return [t];
  const real = realpathLoose(resolve(t));
  return TMP_PARENTS.some((p) => real === p || real.startsWith(`${p}/`)) ? [t] : [];
}

export function buildContext(o: ContextOptions): { ctx: Context; unattendedReason: string | null } {
  const home = o.home ?? homedir();
  const project = o.projectDir !== undefined && o.projectDir !== "" ? o.projectDir : o.env.CLAUDE_PROJECT_DIR !== undefined && o.env.CLAUDE_PROJECT_DIR !== "" ? o.env.CLAUDE_PROJECT_DIR : o.basics.cwd;
  const projectAbs = resolve(project);
  // A "workspace" of / or the whole home directory would make every file a workspace file: refuse it.
  const tooBroad = projectAbs === "/" || projectAbs === resolve(home) || resolve(home).startsWith(`${projectAbs}/`);
  const workspaceRoots = tooBroad ? [] : withReal([projectAbs]);
  const scratch = withReal([...(o.scratchRoots ?? [...trustedTmpdir(o.env), ...FIXED_SCRATCH]), ...(o.basics.scratchpadDir !== undefined ? [o.basics.scratchpadDir] : [])]);
  let unattendedReason: string | null = null;
  if (o.cfg.unattended) unattendedReason = "the policy sets unattended mode";
  else if (o.env.LAUNCHSAFE_FIREWALL_UNATTENDED === "1") unattendedReason = "LAUNCHSAFE_FIREWALL_UNATTENDED=1";
  else if (inUnattendedHours(o.cfg.unattendedHours, o.now ?? new Date())) unattendedReason = "inside the configured unattended hours";
  else if (o.basics.permissionMode !== undefined && o.cfg.unattendedPermissionModes.includes(o.basics.permissionMode)) unattendedReason = `permission mode ${o.basics.permissionMode}`;
  else if (o.detectNonInteractive !== undefined) {
    if (o.detectNonInteractive(o.basics.sessionId)) unattendedReason = CLAUDE_PRINT;
  } else if (o.agentUnattended !== undefined) unattendedReason = o.agentUnattended();
  else unattendedReason = nonInteractiveClaude(o.l, o.basics.sessionId, o.env, o.processProbe);
  const registeredSettings = registeredSettingsFiles(o.l);
  const protectedSettings = protectedSettingsFiles(o.l, o.cfg, o.env, home, registeredSettings);
  const ctx: Context = {
    cwd: resolve(o.basics.cwd),
    workspaceRoots,
    home,
    scratchRoots: scratch,
    firewallHome: o.l.home,
    firewallInstallDir: installDir(),
    interactive: unattendedReason === null,
    // I1: the platform's rule, for what grants trust (the workspace, scratch). Protection folds case everywhere
    // (PROTECTION_FOLDS_CASE, engine/canonical.ts), so a Linux or WSL host on a case-insensitive mount is covered.
    caseInsensitive: process.platform === "darwin" || process.platform === "win32",
    // SELF-016: every path is resolved (its longest existing prefix), and an unresolvable one throws so the engine fails closed.
    realpath: realpathStrict,
    readFile: readSmallFile,
    fileSize,
    registeredSettings: protectedSettings.registered,
    agentSettings: protectedSettings.agents,
    // F-c: protect what the registered hook commands actually run, not anything named like the firewall.
    identity: loadIdentity(o.l, registeredSettings, { env: o.env, home }),
    packageIntel: openIntel(o.l.home),
    lockfiles: readLockfiles,
  };
  if (o.basics.mcpSource !== undefined) ctx.mcpSource = o.basics.mcpSource;
  if (protectedSettings.gatewayConfigs !== undefined) ctx.gatewayConfigs = protectedSettings.gatewayConfigs;
  if (protectedSettings.sandboxProfiles !== undefined) ctx.sandboxProfiles = protectedSettings.sandboxProfiles;
  // The decoys the person planted. A damaged registry gives no index (doctor says so); that is v0.1 behaviour.
  if (o.cfg.canaries.enabled) {
    const canaries = loadCanaryIndex(o.l, ctx.caseInsensitive, ctx.realpath);
    if (canaries !== undefined) ctx.canaries = canaries;
  }
  // The vault's names, bindings and fingerprints, verified against the approval key the hook
  // command pins (else the one on disk). No index: no view, which is v0.2 behaviour.
  if (vaultPolicy(o.cfg).enabled) {
    // Refreshed upstream OAuth tokens' fingerprints come from an unsigned side file: they only add detection.
    const view = withRotatingPrints(o.l, vaultView(loadIndex(o.l, trustedKey(o.l, o.env))));
    if (view !== undefined) ctx.vault = view;
  }
  // The person's scratch-target patterns, verified against the same key; anything else gives none.
  const scratchTargets = scratchPatterns(loadScratch(o.l, trustedKey(o.l, o.env)));
  if (scratchTargets !== undefined) ctx.scratchTargets = scratchTargets;
  return { ctx, unattendedReason };
}

/** The approver key a decision trusts: the one pinned in the hook command, else the one on disk (as hook/claude.ts). */
function trustedKey(l: Layout, env: NodeJS.ProcessEnv): string | null {
  const pinned = env.LAUNCHSAFE_FIREWALL_APPROVER;
  if (pinned !== undefined && pinned !== "") return pinned;
  try {
    return approverPublicKey(l);
  } catch {
    return null;
  }
}

const MANAGED_MCP: Record<string, string> = {
  darwin: "/Library/Application Support/ClaudeCode/managed-mcp.json",
  linux: "/etc/claude-code/managed-mcp.json",
};

function serversIn(text: string | null, pick: (o: Record<string, unknown>) => unknown): Record<string, unknown> {
  if (text === null) return {};
  try {
    const v = pick(JSON.parse(text) as Record<string, unknown>);
    return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/**
 * Where an MCP server was configured, for Claude Code versions whose hook input lacks
 * mcp_server.source (2.1.289 sends it; see docs/threat-model.md). Read from the same files Claude Code
 * reads, in its precedence order: local (per-project entry in ~/.claude.json), project (.mcp.json),
 * user (~/.claude.json), managed (managed-mcp.json). Plugin servers are named plugin_<plugin>_<server>.
 * When nothing matches, "unknown", which the engine treats like a repository-defined server.
 */
export function mcpProvenance(server: string, projectDir: string, home = osHomedir(), platform: NodeJS.Platform = process.platform): string {
  if (server.startsWith("plugin_")) return "plugin";
  const claudeJson = readText(join(home, ".claude.json"));
  const project = resolve(projectDir);
  const local = serversIn(claudeJson, (o) => (own(o.projects as Record<string, Record<string, unknown>> | undefined, project) ?? {}).mcpServers);
  // F42: own keys only ("constructor" or "toString" is not a configured server).
  if (Object.hasOwn(local, server)) return "local";
  if (Object.hasOwn(serversIn(readText(join(project, ".mcp.json")), (o) => o.mcpServers), server)) return "project";
  if (Object.hasOwn(serversIn(claudeJson, (o) => o.mcpServers), server)) return "user";
  const managed = MANAGED_MCP[platform];
  if (managed !== undefined && Object.hasOwn(serversIn(readText(managed), (o) => o.mcpServers), server)) return "managed";
  return "unknown";
}

/**
 * G6: the directories a user-configured server was started with, read from its launch arguments in
 * the file that defines it (the same files and source the provenance lookup uses). Arguments that
 * look like paths are the roots (the reference filesystem server takes its directories as arguments);
 * ${workspaceFolder}-style placeholders and "." mean the project; anything else that cannot be
 * resolved (another variable) makes the roots unknown. Returns undefined when the server is not
 * defined by the user (a repository-defined server is never confined by what it says about itself),
 * when it has no path arguments, or when a root cannot be resolved.
 */
export function mcpServerRoots(server: string, source: string | undefined, projectDir: string, home = osHomedir(), platform: NodeJS.Platform = process.platform, agent: "claude" | "codex" | "gemini" | "cursor" = "claude", env: NodeJS.ProcessEnv = process.env): string[] | undefined {
  if (source === undefined || !/^(?:user|local|managed)$/.test(source)) return undefined;
  const project = resolve(projectDir);
  // F43: Gemini CLI and Codex define their servers in their own files (G6/R21 hold for all three agents).
  if (agent === "gemini") {
    const file = source === "managed" ? geminiSystemSettings(env, platform) : source === "user" ? join(geminiHome(env, home), "settings.json") : undefined;
    const defs = file === undefined ? {} : serversIn(readText(file), (o) => o.mcpServers);
    return rootsFromArgs((own(defs, server) as { args?: unknown } | null | undefined)?.args, project, home);
  }
  if (agent === "cursor") {
    // F43 for Cursor: only the user's ~/.cursor/mcp.json (a project's .cursor/mcp.json is the repository's).
    if (source !== "user") return undefined;
    const defs = serversIn(readText(join(cursorHome(home), "mcp.json")), (o) => o.mcpServers);
    return rootsFromArgs((own(defs, server) as { args?: unknown } | null | undefined)?.args, project, home);
  }
  if (agent === "codex") {
    if (source !== "user") return undefined;
    const flat = tomlFlatten(readText(join(codexHome(env, home), "config.toml")) ?? "");
    if (flat === null) return undefined;
    const args: string[] = [];
    for (let i = 0; ; i++) {
      const v = flat.get(JSON.stringify(["mcp_servers", server, "args", String(i)]));
      if (v === undefined) break;
      try {
        const s = JSON.parse(v) as unknown;
        if (typeof s !== "string") return undefined;
        args.push(s);
      } catch {
        return undefined;
      }
    }
    return rootsFromArgs(args.length > 0 ? args : undefined, project, home);
  }
  const claudeJson = readText(join(home, ".claude.json"));
  const managed = MANAGED_MCP[platform];
  const defs =
    source === "local" ? serversIn(claudeJson, (o) => (own(o.projects as Record<string, Record<string, unknown>> | undefined, project) ?? {}).mcpServers)
    : source === "user" ? serversIn(claudeJson, (o) => o.mcpServers)
    : managed !== undefined ? serversIn(readText(managed), (o) => o.mcpServers) : {};
  const def = own(defs, server);
  return rootsFromArgs(typeof def === "object" && def !== null ? (def as { args?: unknown }).args : undefined, project, home);
}

/** G6: the roots a server's launch arguments name (paths and project placeholders), or undefined. */
export function rootsFromArgs(args: unknown, project: string, home: string): string[] | undefined {
  if (!Array.isArray(args)) return undefined;
  const roots: string[] = [];
  for (const a of args) {
    if (typeof a !== "string" || a.startsWith("-")) continue;
    let t = a.replace(/^file:\/\//, "");
    // Cursor's mcp.json also spells the home directory ${userHome}.
    t = t.replace(/^\$\{userHome\}(?=\/|$)/, home);
    t = t.replace(/^\$\{(?:workspaceFolder|workspaceRoot|PWD|CLAUDE_PROJECT_DIR)\}/, project).replace(/^\$(?:PWD|CLAUDE_PROJECT_DIR)(?=\/|$)/, project);
    if (t === "~" || t.startsWith("~/")) t = join(home, t.slice(1));
    if (/[$`%]/.test(t)) return undefined;
    if (t === "." || t.startsWith("./") || t.startsWith("../") || t.startsWith("/")) roots.push(realpathLoose(resolve(project, t)));
  }
  return roots.length > 0 ? roots : undefined;
}

/** F33: a regular file's size in bytes (null if missing or not a file). */
export function fileSize(p: string): number | null {
  try {
    const st = statSync(p);
    return st.isFile() ? st.size : null;
  } catch {
    return null;
  }
}

/**
 * The settings files judged by their result whatever they are called (F13): the registered ones (install
 * record, managed settings and files holding the sandbox profile doctor --fix installed) and
 * the agents' own by location, and the MCP client configurations the gateway wrapped. Shared by
 * the hook and the library (src/sdk/node.ts), so both judge alike.
 */
export function protectedSettingsFiles(l: Layout, cfg: FirewallConfig, env: NodeJS.ProcessEnv, home: string, registered = registeredSettingsFiles(l)): { registered: string[]; agents: string[]; sandboxProfiles?: NonNullable<Context["sandboxProfiles"]>; gatewayConfigs?: NonNullable<Context["gatewayConfigs"]> } {
  // A settings file holding the sandbox profile doctor --fix installed is protected like one holding the hooks.
  const sandboxProfiles = sandboxPolicy(cfg).protectInstalledProfile ? loadSandboxProfiles(l) : [];
  const wrapped = gatewayConfigs(l);
  return {
    registered: [...new Set([...registered, ...sandboxProfiles.flatMap((p) => [p.path, realpathLoose(p.path)])])],
    agents: agentSettingsPaths(env, home),
    ...(sandboxProfiles.length > 0 ? { sandboxProfiles: sandboxProfiles.flatMap((p) => [p, { ...p, path: realpathLoose(p.path) }]) } : {}),
    ...(wrapped.length > 0 ? { gatewayConfigs: wrapped } : {}),
  };
}

/** Current content of a small file, for judging a change by its result. Null if missing; throws if unreadable. */
export function readSmallFile(p: string): string | null {
  try {
    if (statSync(p).size > 2 * 1024 * 1024) throw new Error(`${p} is too large to check`);
    return readFileSync(p, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT" || (e as NodeJS.ErrnoException).code === "ENOTDIR") return null;
    // A live run's mount point where the file did not exist (an empty directory) is the file's absence.
    if ((e as NodeJS.ErrnoException).code === "EISDIR" && runMountPoint(p)) return null;
    throw e;
  }
}

/**
 * F13: the hook settings files the agents read from where their environment points ($CODEX_HOME, Gemini CLI's
 * system path), and Cursor's user and enterprise hooks.json; with their real paths, so a write through a
 * symlink's target (a dotfiles repository holding ~/.cursor) is recognised too.
 */
export function agentSettingsPaths(env: NodeJS.ProcessEnv, home: string, platform: NodeJS.Platform = process.platform): string[] {
  const out = [join(codexHome(env, home), "hooks.json"), join(codexHome(env, home), "config.toml"), join(geminiHome(env, home), "settings.json"), join(cursorHome(home), "hooks.json")];
  const sys = geminiSystemSettings(env);
  if (sys !== undefined) out.push(sys);
  const cursorEnterprise = CURSOR_ENTERPRISE_HOOKS[platform];
  if (cursorEnterprise !== undefined) out.push(cursorEnterprise);
  return [...new Set(out.flatMap((p) => [p, realpathLoose(p)]))];
}

/**
 * Settings files the firewall's hooks are installed in: its install record, plus managed settings that register
 * it (Claude Code's managed settings and Cursor's enterprise hooks.json, which `install --managed --print`
 * produces and an administrator places), so the identity covers the code those commands run.
 */
export function registeredSettingsFiles(l: Layout, platform: NodeJS.Platform = process.platform): string[] {
  const out: string[] = [];
  try {
    for (const r of readRecords(l)) out.push(r.path);
  } catch {
    // An unreadable record: doctor reports it; the files' own content still identifies them.
  }
  for (const managed of [MANAGED_SETTINGS_PATHS[platform], CURSOR_ENTERPRISE_HOOKS[platform]]) {
    try {
      if (managed !== undefined && registersFirewall(readSmallFile(managed))) out.push(managed);
    } catch {
      // Unreadable managed settings: only an administrator can change them anyway.
    }
  }
  return [...new Set(out.flatMap((p) => [p, realpathLoose(p)]))];
}
