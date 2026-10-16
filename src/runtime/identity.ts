/**
 * F-c: builds the firewall's identity from what is actually installed. The registered hook commands
 * name the node binary and the CLI file that run on every tool call; the CLI's package root gives the
 * runtime (dist/, node_modules/, package.json); the data directory comes from the layout and from
 * any LAUNCHSAFE_FIREWALL_HOME in a hook command. Cached in <firewallHome>/identity.json, keyed by the
 * registered settings files' size and mtime, so the hook normally reads one small file.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { FIREWALL_BIN, FIREWALL_MANAGED_DIRS, FIREWALL_PACKAGE_NAME } from "../engine/identity.js";
import { hookEntries, MARKER } from "../engine/settings.js";
import { allCommands, parseShell } from "../engine/shell/parse.js";
import type { FirewallIdentity } from "../types.js";
import { atomicWrite } from "./fsutil.js";
import { installDir, type Layout } from "./layout.js";
import { realpathLoose } from "./realpath.js";

const CACHE_VERSION = 1;

/** One hook command as installed: the node binary, the CLI file, and a data directory override. */
export interface HookCommandParts {
  node: string;
  cli: string;
  firewallHome?: string;
  /** SR3: the command sets NODE_COMPILE_CACHE empty, so a cache directory from the environment is not used. */
  clearsCompileCache: boolean;
  /** I1: the command also sets NODE_OPTIONS, NODE_PATH, LD_PRELOAD and DYLD_INSERT_LIBRARIES empty. */
  clearsLoaderEnv?: boolean;
  /** I1: the command pins HOME (installs into a settings file) or the data directory (every install). */
  pinsHome?: boolean;
}

/** I1: the loader variables a hook command must set empty. */
export const LOADER_ENV_KEYS: readonly string[] = ["NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"];

/** Parses an installed hook command (`LAUNCHSAFE_FIREWALL_HOOK=1 [VAR=…] '<node>' '<cli>' hook || exit 2`). */
export function parseHookCommand(command: string): HookCommandParts | null {
  if (!command.includes(MARKER)) return null;
  try {
    for (const cmd of allCommands(parseShell(command))) {
      if (!cmd.assigns.some((a) => a.name === "LAUNCHSAFE_FIREWALL_HOOK")) continue;
      const node = cmd.words[0];
      const cli = cmd.words[1];
      if (node === undefined || cli === undefined || node.dynamic || cli.dynamic) return null;
      const cc = cmd.assigns.find((a) => a.name === "NODE_COMPILE_CACHE");
      const out: HookCommandParts = { node: node.text, cli: cli.text, clearsCompileCache: cc !== undefined && !cc.value.dynamic && cc.value.text === "" };
      const home = cmd.assigns.find((a) => a.name === "LAUNCHSAFE_FIREWALL_HOME");
      if (home !== undefined && !home.value.dynamic && home.value.text !== "") out.firewallHome = home.value.text;
      out.clearsLoaderEnv = LOADER_ENV_KEYS.every((k) => cmd.assigns.some((a) => a.name === k && !a.value.dynamic && a.value.text === ""));
      // A user install pins both; a managed one pins the data directory empty (the hook then uses the user database's home).
      const pinsData = home !== undefined && !home.value.dynamic;
      out.pinsHome = pinsData && (home.value.text === "" || cmd.assigns.some((a) => a.name === "HOME" && !a.value.dynamic && a.value.text !== ""));
      return out;
    }
  } catch {
    // An unparseable command identifies nothing; the caller falls back.
  }
  return null;
}

/** The hook commands in one settings file's text that carry the firewall's marker. */
export function hookCommandsIn(text: string | null): string[] {
  if (text === null) return [];
  let s: unknown;
  try {
    s = JSON.parse(text);
  } catch {
    return [];
  }
  const out = new Set<string>();
  // Every event key and both shapes: Claude Code's, Codex's and Gemini CLI's groups, Cursor's flat entries.
  for (const { command } of hookEntries(s)) if (command.includes(MARKER)) out.add(command);
  return [...out];
}

function both(p: string): string[] {
  const abs = resolve(p);
  return [...new Set([abs, realpathLoose(abs)])];
}

function readJson(p: string): Record<string, unknown> | null {
  try {
    const v: unknown = JSON.parse(readFileSync(p, "utf8"));
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** The nearest ancestor of a CLI file whose package.json names the firewall's package. */
export function packageRootOf(cliFile: string): string | null {
  let dir = dirname(cliFile);
  for (let i = 0; i < 6; i++) {
    const pkg = readJson(join(dir, "package.json"));
    if (pkg !== null && pkg.name === FIREWALL_PACKAGE_NAME) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

/** Runtime of one CLI file: its package's dist/, node_modules/ and package.json, or a lone bundle. */
function runtimeOf(cliReal: string): { roots: string[]; files: string[]; pkg: string | null } {
  const root = packageRootOf(cliReal);
  if (root !== null) return { roots: [join(root, "dist"), join(root, "node_modules")], files: [join(root, "package.json")], pkg: root };
  // A single bundled file: its directory is the runtime only when nothing else lives there.
  const dir = dirname(cliReal);
  try {
    const name = basename(cliReal);
    const alone = readdirSync(dir).every((f) => f === name || f.startsWith(`${name}.`) || f.endsWith(".map"));
    if (alone) return { roots: [dir], files: [], pkg: null };
  } catch {
    // Unreadable: protect just the file.
  }
  return { roots: [], files: [], pkg: null };
}

export interface BuildOptions {
  env?: NodeJS.ProcessEnv;
  home?: string;
  /** Reads a settings file (default: the file system). */
  readFile?: (p: string) => string | null;
  /** The deprecated install directory, for the fallback (default: where this code runs from). */
  installDir?: string;
}

function readOrNull(p: string): string | null {
  try {
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

/** Builds the identity from the registered settings files (no cache). */
export function buildIdentity(l: Layout, registered: readonly string[], o: BuildOptions = {}): FirewallIdentity {
  const env = o.env ?? process.env;
  const home = o.home ?? homedir();
  const read = o.readFile ?? readOrNull;
  const data = new Set<string>([...both(l.home), ...both(join(home, ".launchsafe-firewall")), ...FIREWALL_MANAGED_DIRS]);
  if (env.LAUNCHSAFE_FIREWALL_HOME !== undefined && env.LAUNCHSAFE_FIREWALL_HOME !== "") for (const p of both(env.LAUNCHSAFE_FIREWALL_HOME)) data.add(p);
  const cli = new Set<string>();
  const roots = new Set<string>();
  const files = new Set<string>();
  const pkgs = new Set<string>();
  const nodes = new Set<string>();
  for (const s of new Set(registered)) {
    for (const command of hookCommandsIn(read(s))) {
      const parts = parseHookCommand(command);
      if (parts === null || !parts.cli.startsWith("/")) continue;
      // The recorded path is kept even when it no longer exists: re-creating it would change what runs.
      for (const p of both(parts.cli)) cli.add(p);
      if (parts.node.startsWith("/")) for (const p of both(parts.node)) nodes.add(p);
      if (parts.firewallHome !== undefined) for (const p of both(parts.firewallHome)) data.add(p);
      // Judged both as recorded and after symlinks (a path through /var or a bin symlink and its target).
      for (const c of both(parts.cli)) {
        const rt = runtimeOf(c);
        for (const r of rt.roots) for (const p of both(r)) roots.add(p);
        for (const f of rt.files) for (const p of both(f)) files.add(p);
        if (rt.pkg !== null) for (const p of both(rt.pkg)) pkgs.add(p);
      }
    }
  }
  if (cli.size === 0) {
    // Not installed, or the record and settings are unreadable: today's install directory, narrowed
    // to what runs. The data directory is protected either way.
    const dir = o.installDir ?? installDir();
    return {
      cliFiles: both(join(dir, "dist", "cli.js")),
      runtimeRoots: [...both(join(dir, "dist")), ...both(join(dir, "node_modules"))],
      runtimeFiles: both(join(dir, "package.json")),
      packageRoots: both(dir),
      nodeBinaries: [],
      dataRoots: [...data],
      binNames: [FIREWALL_BIN],
      source: "fallback-install-dir",
    };
  }
  return { cliFiles: [...cli], runtimeRoots: [...roots], runtimeFiles: [...files], packageRoots: [...pkgs], nodeBinaries: [...nodes], dataRoots: [...data], binNames: [FIREWALL_BIN], source: "hook-command" };
}

function stamp(p: string): string {
  try {
    const st = statSync(p);
    return `${st.size}:${st.mtimeMs}:${st.ino}`;
  } catch {
    return "missing";
  }
}

function cacheKey(l: Layout, registered: readonly string[], o: BuildOptions): string {
  const env = o.env ?? process.env;
  return JSON.stringify([CACHE_VERSION, l.home, o.home ?? homedir(), env.LAUNCHSAFE_FIREWALL_HOME ?? "", o.installDir ?? installDir(), [...new Set(registered)].sort().map((p) => [p, stamp(p)])]);
}

const LIST_KEYS = ["cliFiles", "runtimeRoots", "runtimeFiles", "packageRoots", "nodeBinaries", "dataRoots", "binNames"] as const;

function validIdentity(v: unknown): v is FirewallIdentity {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  if (o.source !== "hook-command" && o.source !== "fallback-install-dir") return false;
  return LIST_KEYS.every((k) => Array.isArray(o[k]) && (o[k] as unknown[]).every((x) => typeof x === "string" && (k === "binNames" || x.startsWith("/"))));
}

/**
 * The identity, from the cache when the registered settings files have not changed. A corrupt or
 * stale cache is rebuilt; a failed rebuild falls back to the narrowed install directory (which
 * still protects the data directory).
 */
export function loadIdentity(l: Layout, registered: readonly string[], o: BuildOptions = {}): FirewallIdentity {
  const cachePath = join(l.home, "identity.json");
  const key = cacheKey(l, registered, o);
  try {
    const cached = readJson(cachePath);
    if (cached !== null && cached.key === key && validIdentity(cached.identity)) return cached.identity;
  } catch {
    // Rebuild below.
  }
  let id: FirewallIdentity;
  try {
    id = buildIdentity(l, registered, o);
  } catch {
    id = buildIdentity(l, [], o);
  }
  try {
    if (existsSync(l.home)) atomicWrite(cachePath, JSON.stringify({ key, identity: id }));
  } catch {
    // The cache is an optimization only.
  }
  return id;
}
