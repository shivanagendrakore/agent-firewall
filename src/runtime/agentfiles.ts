/**
 * Collects the files that program and arm the agent, for the SessionStart
 * scan: the workspace's (agent-safety's checked paths, nested skills and
 * rules, the CLAUDE.md files of the folders above it up to the git root, and
 * the scripts its hooks and servers run), the user's own (~/.claude
 * instructions, settings, rules, agents, commands, skills, the MCP servers in
 * ~/.claude.json, the project's auto memory) and the administrator's (managed
 * settings and MCP list, read only).
 *
 * Bounded: at most MAX_FILES files, MAX_FILE_BYTES each (agent-safety skips
 * larger ones), MAX_TOTAL_BYTES in all, a wall-clock cap, and a directory
 * budget for the walk. These are the firewall's own reads in its own process,
 * not agent actions.
 *
 * Fail closed: a workspace path whose real location (any component of it a
 * symlink) is outside the workspace, a file too large to check, and an MCP
 * list that cannot be parsed are problems the scan reports and taints on,
 * never files skipped in silence. Symlinked folders inside the root are
 * walked through their real path, once each.
 *
 * Every file gets a repository-style path (agent-safety classifies by path), so
 * user-scope files are given the path they would have in a repository
 * (~/.claude/settings.json is ".claude/settings.json", the auto-memory folder
 * is ".claude/memory/") and a display path for messages.
 */

import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, realpathSync, statSync, type Stats } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { agentFileKind, isMemoryIndex, jsonValueOf, memoryLinks, parseJsoncResult } from "../vendor/agent-safety/index.js";
import { shellSplit } from "../vendor/agent-safety/launch.js";
import { MAX_IMPORT_DEPTH, parseImports, resolveImport } from "../engine/imports.js";
import { hookEntries } from "../engine/settings.js";
import { own, setOwn } from "../own.js";

export const MAX_FILES = 400;
export const MAX_FILE_BYTES = 512 * 1024;
export const MAX_TOTAL_BYTES = 8 * 1024 * 1024;
export const MAX_DIRS = 1500;
/** ~/.claude.json holds history too and can be large; only its mcpServers are used. */
const MAX_CLAUDE_JSON_BYTES = 16 * 1024 * 1024;
/** Scripts named by hook and server commands that are collected, at most. */
const MAX_REFERENCED = 50;
/** Folders above the workspace searched for CLAUDE.md and AGENTS.md (up to the git root). */
const MAX_ANCESTORS = 32;

/** workspace; user (~/.claude, ~/.claude.json); memory (the project's auto memory under ~/.claude/projects); managed. */
export type Scope = "workspace" | "user" | "memory" | "managed";

export interface AgentFileEntry {
  scope: Scope;
  /** Repository-style path agent-safety classifies by. */
  path: string;
  /** What a person reads: workspace-relative, or ~/... for user scope, or the absolute managed path. */
  display: string;
  /** The real file, or null for a synthesized one (the MCP servers of ~/.claude.json). */
  abs: string | null;
  size: number;
  mtimeMs: number;
  /** Read only when needed, except memory indexes, settings and synthesized files. */
  content?: string;
}

/** An MCP server as configured, for pinning. */
export interface ConfiguredServer {
  name: string;
  /** Claude Code's mcp_server.source vocabulary: project, local, user, managed. */
  source: "project" | "local" | "user" | "managed";
  /** Where it is configured, for messages. */
  file: string;
  config: Record<string, unknown>;
  /** Another agent's server (src/runtime/agent-mcp.ts); absent for Claude Code's. Pins are keyed per agent. */
  agent?: "codex" | "gemini" | "cursor";
  /** The folder its relative command and arguments resolve against (the workspace), for the entry-script hash. */
  base?: string;
}

/** Something the collection could not check, which the scan reports (and, outside managed files, taints on). */
export interface CollectionProblem {
  scope: Scope;
  display: string;
  why: string;
}

export interface Collection {
  files: AgentFileEntry[];
  servers: ConfiguredServer[];
  /** Why the collection stopped short (time, file or byte caps). Empty when complete. */
  incomplete: string[];
  /** Files skipped for size (agent-safety does not read them either). */
  skipped: string[];
  /** I7: agent files that are symlinks leading out of their root, so they were not read. Absent: none. */
  dropped?: string[];
  /** R7: the workspace's own agent files ran past the file or byte cap (a repository controls that). */
  workspaceCapped?: boolean;
  /** Paths that escape their root, files too large to check, MCP lists that do not parse. */
  problems: CollectionProblem[];
}

export interface CollectOptions {
  /** The workspace root, or null when the project directory is too broad to scan (/ or the home directory). */
  workspace: string | null;
  home: string;
  /** Claude Code's user config directory (CLAUDE_CONFIG_DIR, default ~/.claude). */
  configDir: string;
  /** Claude Code's global config file (default ~/.claude.json; inside CLAUDE_CONFIG_DIR when that is set). */
  claudeJson?: string;
  userScope: boolean;
  /** Only the configured MCP servers (the scan is switched off; pinning still needs them). */
  serversOnly?: boolean;
  managedSettings?: string | undefined;
  managedMcp?: string | undefined;
  budgetMs: number;
  /** Injected clock (tests). */
  clock?: () => number;
}

/** Directories never walked for nested instruction files: dependencies, build output, VCS data. */
const SKIP_DIRS = new Set(["node_modules", ".git", ".hg", ".svn", "dist", "build", "out", "target", "vendor", ".next", ".nuxt", ".turbo", "coverage", ".venv", "venv", "__pycache__", ".cache", "Pods", ".gradle", ".idea", ".terraform", ".tox", ".mypy_cache", ".pytest_cache", "bower_components", "DerivedData", ".yarn", ".pnpm-store"]);
/** The skipped folders a repository could plausibly hide an instruction file in (dependencies and VCS data are not noted: they carry thousands). */
const NOTED_SKIP_DIRS = new Set(["vendor", "dist", "build", "out", "target", "coverage"]);
/** File names (lowercase) that load as instructions wherever they are found. */
const INSTRUCTION_FILE_NAMES = new Set(["claude.md", "claude.local.md", "agents.md", "agents.override.md", "gemini.md", ".cursorrules", ".windsurfrules", ".clinerules"]);
/** Dot-folders that hold agent files wherever they are (a monorepo package's own skills and rules). */
const AGENT_DOT_DIRS = new Set([".claude", ".cursor", ".agents", ".windsurf"]);
/** How deep the walk looks for nested instruction files (CLAUDE.md, AGENTS.md, GEMINI.md, memory/MEMORY.md). */
const SHALLOW = 4;
const DEEP = 8;
/** Agent files at fixed workspace paths (agent-safety's checked paths outside the walked folders). */
// R7: the files that run code or load as instructions in every session come first, so padding elsewhere cannot push them past the caps.
const WORKSPACE_FILES = ["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENTS.override.md", "GEMINI.md", ".claude/CLAUDE.md", ".cursorrules", ".windsurfrules", ".clinerules", ".github/copilot-instructions.md", ".claude/settings.json", ".claude/settings.local.json", ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".roo/mcp.json", ".kiro/settings/mcp.json", ".gemini/settings.json", ".codex/config.toml", ".codex/hooks.json", ".cursor/hooks.json", ".cursor/environment.json", ".devcontainer/devcontainer.json", ".devcontainer.json", ".vscode/tasks.json", ".vscode/settings.json"];
/** Workspace folders whose whole subtree holds agent files (walked deep, nothing else under a dot-directory is). */
const WORKSPACE_TREES = [".claude/hooks", ".claude/agents", ".claude/commands", ".claude/skills", ".claude/rules", ".claude/output-styles", ".claude/memory", ".claude/agent-memory", ".claude/agent-memory-local", ".agents/skills", ".cursor/rules", ".github/instructions", ".github/prompts", ".github/agents", ".github/chatmodes", ".gemini/commands", ".clinerules", ".windsurf/rules", ".windsurf/workflows", ".devcontainer"];

class Budget {
  files = 0;
  bytes = 0;
  dirs = 0;
  readonly incomplete = new Set<string>();
  /** R7: the file or byte cap was reached while collecting this scope's files. */
  readonly cappedScopes = new Set<Scope>();
  private readonly deadline: number;
  constructor(
    ms: number,
    private readonly clock: () => number,
  ) {
    this.deadline = clock() + ms;
  }
  /** R7: the workspace's agent trees (not the generic walk for nested instruction files) are being collected. */
  inAgentTrees: Scope | null = null;
  timeLeft(): boolean {
    if (this.clock() <= this.deadline) return true;
    this.incomplete.add("the time budget ran out");
    // Running out of time inside the agent trees means they are large enough to hide a file behind filler.
    if (this.inAgentTrees !== null) this.cappedScopes.add(this.inAgentTrees);
    return false;
  }
  takeFile(size: number, scope?: Scope): boolean {
    if (this.files >= MAX_FILES) {
      this.incomplete.add(`more than ${MAX_FILES} agent files`);
      if (scope !== undefined) this.cappedScopes.add(scope);
      return false;
    }
    if (this.bytes + size > MAX_TOTAL_BYTES) {
      this.incomplete.add(`more than ${MAX_TOTAL_BYTES / 1024 / 1024} MB of agent files`);
      if (scope !== undefined) this.cappedScopes.add(scope);
      return false;
    }
    this.files++;
    this.bytes += size;
    return true;
  }
  takeDir(): boolean {
    if (this.dirs >= MAX_DIRS) {
      this.incomplete.add(`more than ${MAX_DIRS} directories to search for nested instruction files`);
      return false;
    }
    this.dirs++;
    return true;
  }
}

function inside(root: string, p: string): boolean {
  return p === root || p.startsWith(root.endsWith(sep) ? root : root + sep);
}

const realRoots = new Map<string, string>();
function realRoot(root: string): string {
  let r = realRoots.get(root);
  if (r === undefined) {
    try {
      r = realpathSync(root);
    } catch {
      r = root;
    }
    realRoots.set(root, r);
  }
  return r;
}

function toPosix(p: string): string {
  return p.split(sep).join("/");
}

/**
 * Text as the agents read it: UTF-16 (with a byte order mark, or without one when every other byte
 * is zero) is decoded as UTF-16, anything else as UTF-8 (a UTF-8 byte order mark is kept; the
 * analyzer drops it).
 */
export function decodeText(buf: Buffer): string {
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return new TextDecoder("utf-16le").decode(buf.subarray(2));
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) return new TextDecoder("utf-16be").decode(buf.subarray(2));
  if (buf.length >= 4) {
    let evenZero = 0;
    let oddZero = 0;
    const n = Math.min(buf.length, 4096) & ~1;
    for (let k = 0; k < n; k += 2) {
      if (buf[k] === 0) evenZero++;
      if (buf[k + 1] === 0) oddZero++;
    }
    const pairs = n / 2;
    if (oddZero > pairs * 0.4 && evenZero < pairs * 0.05) return new TextDecoder("utf-16le").decode(buf);
    if (evenZero > pairs * 0.4 && oddZero < pairs * 0.05) return new TextDecoder("utf-16be").decode(buf);
  }
  return buf.toString("utf8");
}

interface Root {
  scope: Scope;
  dir: string;
  /** Repository-style prefix for paths under dir (".claude/" for ~/.claude, "" for the workspace). */
  prefix: string;
  /** Display prefix ("~/.claude/" or ""). */
  displayPrefix: string;
  /** The folder a file's real path must stay inside (the root itself; the home directory for the user's own files). */
  limit?: string;
}

class Collector {
  readonly files: AgentFileEntry[] = [];
  readonly skipped: string[] = [];
  readonly problems: CollectionProblem[] = [];
  private readonly seen = new Set<string>();
  /** Real folders already walked (a symlinked folder is walked once, through its real path). */
  private readonly walked = new Set<string>();
  constructor(readonly budget: Budget) {}

  problem(scope: Scope, display: string, why: string): void {
    if (this.problems.some((p) => p.scope === scope && p.display === display)) return;
    this.problems.push({ scope, display, why });
  }

  /**
   * A regular file whose real path (every component resolved, so a symlinked parent folder counts
   * too) stays inside the root's limit. A path that escapes is a problem, not a file.
   */
  private fileStat(root: Root, abs: string, display: string): Stats | null {
    let l: Stats;
    try {
      l = lstatSync(abs);
    } catch {
      return null;
    }
    let real: string;
    try {
      real = realpathSync(abs);
    } catch {
      if (l.isSymbolicLink()) this.problem(root.scope, display, "it is a symlink to nothing");
      return null;
    }
    if (!inside(realRoot(root.limit ?? root.dir), real)) {
      this.problem(root.scope, display, `its real location (${real}) is outside ${root.scope === "workspace" ? "the workspace" : "its folder"}`);
      return null;
    }
    try {
      const s = statSync(real);
      return s.isFile() ? s : null;
    } catch {
      return null;
    }
  }

  /** Adds one candidate file; reads it now when it is a memory index or settings (their content names more files). */
  add(root: Root, abs: string, path: string, display: string): AgentFileEntry | null {
    const key = `${root.scope}\u0000${path}`;
    if (this.seen.has(key)) return null;
    const st = this.fileStat(root, abs, display);
    if (st === null) return null;
    this.seen.add(key);
    if (st.size > MAX_FILE_BYTES) {
      this.skipped.push(display);
      this.problem(root.scope, display, `it is larger than ${MAX_FILE_BYTES / 1024} KB, so it was not checked`);
      return null;
    }
    if (!this.budget.takeFile(st.size, root.scope)) return null;
    const entry: AgentFileEntry = { scope: root.scope, path, display, abs, size: st.size, mtimeMs: st.mtimeMs };
    if (isMemoryIndex(path)) entry.content = readText(abs);
    this.files.push(entry);
    return entry;
  }

  /** Walks `dir` (absolute, under root.dir) adding every file agent-safety reads by its path. */
  private skippedProbes = 0;
  private skippedNotes = 0;

  /** Records, without reading it, that a skipped folder directly holds an instruction file. */
  private noteSkipped(abs: string, rel: string, why: string): void {
    if (this.skippedProbes >= 200 || this.skippedNotes >= 10) return;
    this.skippedProbes++;
    try {
      // The folder itself and its direct subfolders (vendor/pkg/AGENTS.md): a bounded look, nothing is read.
      const names = readdirSync(abs, { withFileTypes: true });
      const found = (list: readonly string[]): string | undefined => list.find((n) => INSTRUCTION_FILE_NAMES.has(n.toLowerCase()));
      let at = rel;
      let hit = found(names.map((d) => d.name));
      for (const d of names.filter((x) => x.isDirectory()).slice(0, 50)) {
        if (hit !== undefined) break;
        const inner = found(readdirSync(join(abs, d.name)));
        if (inner !== undefined) {
          at = `${rel}/${d.name}`;
          hit = inner;
        }
      }
      if (hit === undefined) return;
      this.skippedNotes++;
      this.budget.incomplete.add(`${at}/${hit} was not checked (${why})`);
    } catch {
      // Unreadable: nothing to say about it.
    }
  }

  walk(root: Root, dir: string, depth: number, maxDepth: number, all: boolean): void {
    if (!this.budget.timeLeft() || !this.budget.takeDir()) return;
    let real: string;
    try {
      real = realpathSync(dir);
    } catch {
      return;
    }
    // A folder (or a parent of it) that is a symlink out of the root is a problem; one inside is walked once.
    if (!inside(realRoot(root.limit ?? root.dir), real)) {
      this.problem(root.scope, root.displayPrefix + toPosix(relative(root.dir, dir)), `its real location (${real}) is outside ${root.scope === "workspace" ? "the workspace" : "its folder"}`);
      return;
    }
    if (this.walked.has(real)) return;
    this.walked.add(real);
    let names: import("node:fs").Dirent[];
    try {
      names = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    names.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const d of names) {
      if (!this.budget.timeLeft()) return;
      const abs = join(dir, d.name);
      const rel = toPosix(relative(root.dir, abs));
      const path = root.prefix + rel;
      let isDir = d.isDirectory();
      if (d.isSymbolicLink()) {
        try {
          isDir = statSync(abs).isDirectory();
        } catch {
          isDir = false;
        }
      }
      if (isDir) {
        if (depth >= maxDepth || SKIP_DIRS.has(d.name)) {
          // Not searched, but said so when an instruction file sits right in it: a repository can hide one in a folder the walk skips.
          if (root.scope === "workspace" && !all && (NOTED_SKIP_DIRS.has(d.name) || (depth >= maxDepth && !SKIP_DIRS.has(d.name)))) this.noteSkipped(abs, rel, depth >= maxDepth ? `deeper than ${maxDepth} folders` : "a folder the search skips");
          continue;
        }
        // Agent files under dot-directories live at fixed paths (WORKSPACE_FILES, WORKSPACE_TREES), walked separately,
        // except the agent folders of a nested package (packages/x/.claude/skills).
        if (!all && d.name.startsWith(".") && !(AGENT_DOT_DIRS.has(d.name) && depth > 0)) continue;
        this.walk(root, abs, depth + 1, maxDepth, all);
      } else if (d.isFile() || d.isSymbolicLink()) {
        if (all || agentFileKind(path) !== null) this.add(root, abs, path, root.displayPrefix + rel);
      }
    }
  }

  /**
   * R10: adds the files instruction files import with `@path` (Claude Code loads them as instructions),
   * following imports of imports up to MAX_IMPORT_DEPTH hops. A workspace import must stay inside the
   * workspace; a user-scope one inside the home directory. Imported files are analyzed as instruction
   * files (importedPath) and shown under their real path.
   */
  followImports(roots: Root[], home: string): void {
    const queue: { entry: AgentFileEntry; depth: number }[] = this.files.filter((f) => f.abs !== null && (f.scope === "workspace" || f.scope === "user") && IMPORTING.has(f.path.slice(f.path.lastIndexOf("/") + 1).toLowerCase())).map((entry) => ({ entry, depth: 0 }));
    const done = new Set<string>(this.files.map((f) => f.abs ?? ""));
    while (queue.length > 0) {
      const { entry, depth } = queue.shift() as { entry: AgentFileEntry; depth: number };
      if (depth >= MAX_IMPORT_DEPTH || entry.abs === null || !this.budget.timeLeft()) continue;
      const root = roots.find((r) => r.scope === entry.scope && (r.scope !== "user" || r.prefix === ".claude/"));
      if (root === undefined) continue;
      const limit = entry.scope === "workspace" ? root.dir : home;
      for (const ref of parseImports(readEntry(entry))) {
        const abs = resolveImport(ref, toPosix(entry.abs), toPosix(home));
        if (done.has(abs) || !inside(limit, abs)) continue;
        done.add(abs);
        const rel = toPosix(relative(limit, abs));
        const display = entry.scope === "workspace" ? rel : `~/${rel}`;
        const added = this.add({ ...root, dir: limit, limit }, abs, importedPath(entry.scope === "workspace" ? rel : `~/${rel}`), display);
        if (added !== null) queue.push({ entry: added, depth: depth + 1 });
      }
    }
  }

  /** Adds the topic files every memory index links to. */
  followMemoryLinks(roots: Root[]): void {
    for (let i = 0; i < this.files.length; i++) {
      const f = this.files[i] as AgentFileEntry;
      if (f.content === undefined || !isMemoryIndex(f.path)) continue;
      // The most specific root (~/.claude/projects/<slug>/memory/ before ~/.claude/).
      const root = roots.filter((r) => r.scope === f.scope && f.path.startsWith(r.prefix)).sort((a, b) => b.prefix.length - a.prefix.length)[0];
      if (root === undefined) continue;
      for (const target of memoryLinks(f.path, f.content)) {
        if (!target.startsWith(root.prefix)) continue;
        const rel = target.slice(root.prefix.length);
        const abs = resolve(root.dir, ...rel.split("/"));
        if (!inside(root.dir, abs)) continue;
        this.add(root, abs, target, root.displayPrefix + rel);
      }
    }
  }

  /**
   * I7: the scripts the workspace's hooks, helpers and MCP servers run (`node scripts/hook.js`,
   * `"$CLAUDE_PROJECT_DIR"/tools/check.sh`), collected as agent scripts so what they do is checked too.
   */
  followReferencedScripts(ws: Root): void {
    let n = 0;
    for (const f of [...this.files]) {
      if (f.scope !== "workspace" || f.abs === null) continue;
      const kind = agentFileKind(f.path);
      if (kind !== "claude_settings" && kind !== "mcp_json" && kind !== "hooks_json" && kind !== "gemini_settings" && kind !== "cursor_environment") continue;
      for (const command of commandsIn(readEntry(f))) {
        for (const word of shellSplit(command)) {
          if (n >= MAX_REFERENCED || !this.budget.timeLeft()) return;
          const rel = word.replace(/^(?:\$\{?(?:CLAUDE_PROJECT_DIR|GEMINI_PROJECT_DIR|CURSOR_PROJECT_DIR|PWD)\}?|\$\{workspaceFolder\})[\\/]/, "").replace(/^\.\//, "");
          if (rel === "" || rel.startsWith("-") || isAbsolute(rel) || rel.startsWith("~") || rel.includes("$") || !/[/.]/.test(rel) || /^[a-z][a-z0-9+.-]*:/i.test(rel)) continue;
          const abs = resolve(ws.dir, rel);
          if (!inside(ws.dir, abs) || this.files.some((x) => x.abs === abs)) continue;
          try {
            if (!statSync(abs).isFile()) continue;
          } catch {
            continue;
          }
          const posix = toPosix(relative(ws.dir, abs));
          if (agentFileKind(posix) === "agent_script") continue; // collected under its own path already (or about to be)
          if (this.add(ws, abs, referencedPath(posix), posix) !== null) n++;
        }
      }
    }
  }

  /** I7: Claude Code reads CLAUDE.md (and Codex AGENTS.md) in every folder above the project, up to the repository root. */
  ancestors(workspace: string, home: string): void {
    let dir = workspace;
    if (exists(join(dir, ".git"))) return;
    const h = resolve(home);
    for (let k = 1; k <= MAX_ANCESTORS; k++) {
      const up = dirname(dir);
      // Never the file system's root, the home directory or anything above it (the user's own files are their own scope).
      if (up === dir || inside(up, h)) return;
      dir = up;
      const root: Root = { scope: "workspace", dir, prefix: "", displayPrefix: "" };
      const rel = toPosix(relative(workspace, dir));
      for (const name of ["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENTS.override.md"]) this.add(root, join(dir, name), `${rel}/${name}`, `${rel}/${name}`);
      if (exists(join(dir, ".git"))) return;
    }
  }
}

const IMPORTING = new Set(["claude.md", "claude.local.md", "agents.md", "gemini.md"]);

/** R10: the repository-style path an imported file is analyzed under (an instruction file, by agent-safety's paths). */
export function importedPath(rel: string): string {
  return `.github/instructions/@import/${rel.replace(/^\/+/, "")}.instructions.md`;
}

/** I7: the repository-style path a script a hook or server runs is analyzed under (an agent script, by agent-safety's paths). */
export function referencedPath(rel: string): string {
  return `.claude/hooks/@referenced/${rel.replace(/^\/+/, "")}`;
}

/** The commands a settings, hooks or MCP file names: hook commands, helpers, the status line, server commands and arguments. */
function commandsIn(text: string): string[] {
  const v = parseLoose(text);
  if (typeof v !== "object" || v === null) return [];
  const o = v as Record<string, unknown>;
  const out: string[] = [];
  for (const { command } of hookEntries(o)) if (command !== "") out.push(command);
  for (const k of ["apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "install", "start"]) {
    const v = own(o, k);
    if (typeof v === "string") out.push(v);
  }
  const status = o.statusLine;
  if (typeof status === "object" && status !== null && typeof (status as Record<string, unknown>).command === "string") out.push((status as Record<string, unknown>).command as string);
  for (const list of [o.mcpServers, o.servers]) {
    for (const s of Object.values(serverMap(list))) {
      const words = [typeof s.command === "string" ? s.command : "", ...(Array.isArray(s.args) ? s.args.filter((a): a is string => typeof a === "string") : [])].filter((w) => w !== "");
      out.push(words.map((w) => (/\s/.test(w) ? `'${w.replace(/'/g, "")}'` : w)).join(" "));
    }
  }
  return out;
}

function readText(abs: string): string {
  try {
    return decodeText(readFileSync(abs));
  } catch {
    return "";
  }
}

/** Reads a file's content for analysis (a cache miss). Missing or unreadable reads as empty. */
export function readEntry(e: AgentFileEntry): string {
  if (e.content !== undefined) return e.content;
  e.content = e.abs === null ? "" : readText(e.abs);
  return e.content;
}

/** Claude Code's folder name for a project under ~/.claude/projects (every non-alphanumeric becomes "-"). */
export function projectSlug(projectDir: string): string {
  return resolve(projectDir).replace(/[^A-Za-z0-9]/g, "-");
}

/** JSON or JSONC (comments, trailing commas) as plain values, the way the agents read their config; undefined when it does not parse. */
function parseLoose(text: string): unknown {
  const r = parseJsoncResult(text);
  return r.ok ? jsonValueOf(r.root) : undefined;
}

function jsonObject(text: string | null): Record<string, unknown> | null {
  if (text === null) return null;
  const v = parseLoose(text);
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function serverMap(v: unknown): Record<string, Record<string, unknown>> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return {};
  const out: Record<string, Record<string, unknown>> = {};
  for (const [k, x] of Object.entries(v as Record<string, unknown>)) if (typeof x === "object" && x !== null && !Array.isArray(x)) setOwn(out, k, x as Record<string, unknown>);
  return out;
}

function exists(abs: string): boolean {
  try {
    statSync(abs);
    return true;
  } catch {
    return false;
  }
}

function readSmall(abs: string, max: number): string | null {
  try {
    const st = statSync(abs);
    if (!st.isFile() || st.size > max) return null;
    return decodeText(readFileSync(abs));
  } catch {
    return null;
  }
}

/** Gemini CLI's context.fileName: the instruction files it reads instead of (or besides) GEMINI.md. */
function geminiContextFiles(workspace: string): string[] {
  const settings = jsonObject(readSmall(join(workspace, ".gemini", "settings.json"), MAX_FILE_BYTES));
  const ctx = settings?.context;
  const name = typeof ctx === "object" && ctx !== null ? (ctx as Record<string, unknown>).fileName : settings?.contextFileName;
  const names = typeof name === "string" ? [name] : Array.isArray(name) ? name.filter((x): x is string => typeof x === "string") : [];
  return names.filter((x) => x !== "" && !isAbsolute(x) && !x.includes("..")).slice(0, 10);
}

/** Collects the agent files of the workspace, the user and the administrator. */
export function collectAgentFiles(o: CollectOptions): Collection {
  const budget = new Budget(o.budgetMs, o.clock ?? (() => performance.now()));
  const c = new Collector(budget);
  const roots: Root[] = [];
  const servers: ConfiguredServer[] = [];

  if (o.workspace !== null) {
    const ws: Root = { scope: "workspace", dir: o.workspace, prefix: "", displayPrefix: "" };
    roots.push(ws);
    if (o.serversOnly !== true) {
      budget.inAgentTrees = "workspace";
      for (const rel of WORKSPACE_FILES) c.add(ws, join(o.workspace, ...rel.split("/")), rel, rel);
      for (const rel of geminiContextFiles(o.workspace)) c.add(ws, join(o.workspace, ...rel.split("/")), importedPath(rel), rel);
      for (const rel of WORKSPACE_TREES) c.walk(ws, join(o.workspace, ...rel.split("/")), 1, DEEP, false);
      c.followReferencedScripts(ws);
      budget.inAgentTrees = null;
      c.walk(ws, o.workspace, 0, SHALLOW, false);
      c.ancestors(o.workspace, o.home);
    }
    const mcpPath = join(o.workspace, ".mcp.json");
    const mcpText = readSmall(mcpPath, MAX_FILE_BYTES);
    const mcp = jsonObject(mcpText);
    // Fail closed: a server list the firewall cannot read is a server list it cannot pin.
    if (mcpText !== null && mcp === null) c.problem("workspace", ".mcp.json", "it could not be parsed, so its MCP servers could not be pinned");
    // Over the size cap (and, with the scan on, also reported by the collector): unread, so its servers are not pinned.
    if (mcpText === null && o.serversOnly === true && exists(mcpPath)) c.problem("workspace", ".mcp.json", "too large to read, so its MCP servers could not be pinned");
    for (const [name, config] of Object.entries(serverMap(mcp?.mcpServers))) servers.push({ name, source: "project", file: ".mcp.json", config, base: o.workspace });
  }

  if (o.userScope && o.serversOnly !== true) {
    // The user's own files may be symlinks into their dotfiles anywhere under the home directory.
    const userLimit = inside(resolve(o.home), resolve(o.configDir)) ? o.home : o.configDir;
    const user: Root = { scope: "user", dir: o.configDir, prefix: ".claude/", displayPrefix: "~/.claude/", limit: userLimit };
    roots.push(user);
    for (const name of ["CLAUDE.md", "settings.json"]) c.add(user, join(o.configDir, name), `.claude/${name}`, `~/.claude/${name}`);
    for (const sub of ["agents", "commands", "skills", "hooks", "rules", "output-styles"]) c.walk(user, join(o.configDir, sub), 1, DEEP, false);
    if (o.workspace !== null) {
      const memDir = join(o.configDir, "projects", projectSlug(o.workspace), "memory");
      const mem: Root = { scope: "memory", dir: memDir, prefix: ".claude/memory/", displayPrefix: `~/.claude/projects/${projectSlug(o.workspace)}/memory/`, limit: userLimit };
      roots.push(mem);
      c.walk(mem, memDir, 1, DEEP, true);
    }
  }

  // ~/.claude.json: the user's servers and this project's ("local") servers, as one synthesized MCP list.
  const claudeJsonPath = o.claudeJson ?? join(o.home, ".claude.json");
  const cj = jsonObject(readSmall(claudeJsonPath, MAX_CLAUDE_JSON_BYTES));
  if (cj !== null) {
    const global = serverMap(cj.mcpServers);
    const projects = typeof cj.projects === "object" && cj.projects !== null ? (cj.projects as Record<string, Record<string, unknown> | undefined>) : {};
    const local = o.workspace !== null ? serverMap(own(projects, resolve(o.workspace))?.mcpServers) : {};
    const base = o.workspace !== null ? { base: o.workspace } : {};
    for (const [name, config] of Object.entries(global)) servers.push({ name, source: "user", file: "~/.claude.json", config, ...base });
    for (const [name, config] of Object.entries(local)) servers.push({ name, source: "local", file: "~/.claude.json (this project)", config, ...base });
    const merged = { ...global, ...local };
    if (o.userScope && o.serversOnly !== true && Object.keys(merged).length > 0) {
      const content = `${JSON.stringify({ mcpServers: merged }, null, 2)}\n`;
      c.files.push({ scope: "user", path: ".mcp.json", display: "~/.claude.json (mcpServers)", abs: null, size: Buffer.byteLength(content), mtimeMs: 0, content });
    }
  } else if (exists(claudeJsonPath)) {
    budget.incomplete.add("~/.claude.json could not be read (too large or not JSON)");
    c.problem("user", "~/.claude.json", "it could not be read (too large or not JSON), so its MCP servers could not be checked or pinned");
  }

  const managed = (abs: string | undefined, path: string, mcp: boolean): void => {
    if (abs === undefined) return;
    const text = readSmall(abs, MAX_FILE_BYTES);
    if (text === null) return;
    if (mcp) for (const [name, config] of Object.entries(serverMap(jsonObject(text)?.mcpServers))) servers.push({ name, source: "managed", file: abs, config });
    if (o.serversOnly === true) return;
    budget.takeFile(Buffer.byteLength(text));
    c.files.push({ scope: "managed", path, display: abs, abs: null, size: Buffer.byteLength(text), mtimeMs: 0, content: text });
  };
  managed(o.managedSettings, ".claude/settings.json", false);
  managed(o.managedMcp, ".mcp.json", true);

  c.followMemoryLinks(roots);
  if (o.serversOnly !== true) c.followImports(roots, o.home);
  return { files: c.files, servers, incomplete: [...budget.incomplete], skipped: c.skipped, problems: c.problems, ...(budget.cappedScopes.has("workspace") ? { workspaceCapped: true } : {}) };
}

/**
 * The cache key of a collection: what each file holds (a hash of its content, read now), never its
 * size and modification time alone, which a file can keep while its content changes.
 */
export function collectionKey(files: readonly AgentFileEntry[]): string {
  const h = createHash("sha256");
  for (const f of files) {
    h.update(`${f.scope}\u0000${f.path}\u0000`);
    h.update(createHash("sha256").update(readEntry(f)).digest("hex"));
    h.update("\n");
  }
  return h.digest("hex");
}
