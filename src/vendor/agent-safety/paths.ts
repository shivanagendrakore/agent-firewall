// Vendored from LaunchSafe's agent-safety package (src/paths.ts), Apache-2.0, at commit fc329d4314dc07a65da266a1256b1da0d17ec97c.
// Licence: Apache-2.0 (see NOTICE).
// Transform: add ".js" to relative import specifiers.
// Do not edit here: it is copied from the upstream package by
// `node scripts/sync-agent-safety.mjs` (`--check` verifies the copy).

// DIVERGES FROM UPSTREAM (firewall audit I7, B1): more agent files are classified (.claude/rules,
// output styles, prompts and agents, Gemini commands, Cursor and Codex hooks, Cursor's environment,
// dev containers, .agents/skills, Windsurf workflows, nested skills and rules), more script
// extensions, local (untracked by convention) files are named, and memory links are found with
// bounded patterns. Upstream should take these changes.

/**
 * Which repository files program or arm a coding agent, and how each is read.
 * Pure: the browser checker classifies a pasted file by the name the person
 * picks, the runner by its path in the repository.
 */

export type AgentFileKind =
  /** Markdown the agent reads as instructions: CLAUDE.md, AGENTS.md, rules, skills, sub-agents, commands. */
  | "instructions"
  /** Claude Code's project settings: hooks, permissions, env, helpers. */
  | "claude_settings"
  /** MCP server lists in the common `mcpServers` / `servers` JSON shape. */
  | "mcp_json"
  /** Gemini CLI settings (mcpServers in the same shape). */
  | "gemini_settings"
  /** Codex CLI's TOML config. */
  | "codex_toml"
  /** VS Code tasks (folder-open tasks run on their own). */
  | "vscode_tasks"
  /** VS Code settings (agent auto-approval). */
  | "vscode_settings"
  /** A script shipped with hooks or skills, which the agent runs. */
  | "agent_script"
  /** The root package.json: scripts that start an agent with no permission prompts. */
  | "package_json"
  /** A committed environment file: read only to tell whether production credentials sit beside the agent. */
  | "env_file"
  /**
   * Agent memory: notes an agent writes for itself and loads into later
   * sessions (a MEMORY.md index and its topic files), so text it read once
   * can steer every session after.
   */
  | "memory"
  /** Hook lists outside Claude Code's settings: Cursor's and Codex's hooks.json (commands that run on their own). */
  | "hooks_json"
  /** A Gemini CLI custom command (TOML): a prompt the agent follows, which can run shell commands (`!{…}`). */
  | "gemini_command"
  /** Cursor's background-agent environment: install and start commands. */
  | "cursor_environment"
  /** A dev container definition: lifecycle commands that run when the container is created or started. */
  | "devcontainer";

const lower = (path: string) => path.toLowerCase();
const base = (path: string) => path.slice(path.lastIndexOf("/") + 1);

/** Instruction files the agents read from anywhere in the tree (nested ones load when the agent works in that directory). */
const INSTRUCTION_NAMES = new Set(["claude.md", "claude.local.md", "agents.md", "agents.override.md", "gemini.md"]);
/** Instruction files read only at the repository root. */
const ROOT_INSTRUCTIONS = new Set([".cursorrules", ".windsurfrules", ".clinerules", ".github/copilot-instructions.md"]);
const SCRIPT_EXTENSIONS = /\.(sh|bash|zsh|fish|ksh|ps1|psm1|bat|cmd|py|js|mjs|cjs|ts|mts|cts|jsx|tsx|rb|pl|php|lua)$/;
/** Files in a hooks folder that are data, not something run. */
const NOT_A_SCRIPT = /\.(md|mdx|txt|json|jsonc|ya?ml|toml|lock|png|jpe?g|gif|svg)$/;

/**
 * Files people keep out of git by convention (Claude Code writes them to .gitignore): the person's
 * own settings and notes, not the repository's. Findings in them are one step less severe.
 */
export function isLocalAgentFile(path: string): boolean {
  const p = lower(path.replace(/\\/g, "/").replace(/^\.\//, ""));
  return p === ".claude/settings.local.json" || base(p) === "claude.local.md" || /^\.claude\/agent-memory-local\//.test(p);
}
/** `.env`, `.env.production`, `.env.local`...; never the templates. */
const ENV_FILE = /^\.env(?:\.[a-z0-9_-]+)*$/;
const ENV_TEMPLATE = /\.(example|sample|template|dist|defaults?|test|ci|schema)$/;

/**
 * Memory folders, each documented or in wide use:
 * - `.claude/agent-memory/<agent>/` and `.claude/agent-memory-local/<agent>/`:
 *   a Claude Code sub-agent's memory (project scope is meant to be committed;
 *   https://code.claude.com/docs/en/sub-agents, "Enable persistent memory").
 * - `.claude/memory/`: a committed copy of Claude Code's auto memory (a
 *   MEMORY.md index and one topic file per memory, the layout
 *   https://code.claude.com/docs/en/memory describes for
 *   ~/.claude/projects/<project>/memory/; over a thousand public repositories
 *   commit one).
 */
const MEMORY_DIR = /^\.claude\/(?:agent-memory(?:-local)?|memory)\/(?:.+\/)?[^/]+\.md$/;
/**
 * A memory index: MEMORY.md at the root (a memory repository, as in
 * github.com/supermemoryai/memoryrepo) or in a folder named memory or
 * memories (Gemini CLI also names its project memory index MEMORY.md).
 */
const MEMORY_INDEX = /^(?:(?:.+\/)?(?:memory|memories)\/)?memory\.md$/;

/** The kind of agent file at a repository path, or null when the check does not read it. */
export function agentFileKind(path: string): AgentFileKind | null {
  const p = lower(path.replace(/\\/g, "/").replace(/^\.\//, ""));
  const name = base(p);
  if (MEMORY_DIR.test(p) || MEMORY_INDEX.test(p)) return "memory";
  if (INSTRUCTION_NAMES.has(name)) return "instructions";
  if (ROOT_INSTRUCTIONS.has(p)) return "instructions";
  if (/^\.github\/instructions\/.+\.instructions\.md$/.test(p)) return "instructions";
  // Rules, skills, sub-agents and commands, at the root or in a nested folder (monorepo packages).
  if (/(?:^|\/)\.cursor\/rules\/.+\.(md|mdc)$/.test(p)) return "instructions";
  if (/^\.clinerules\/.+\.md$/.test(p) || /(?:^|\/)\.windsurf\/(?:rules|workflows)\/.+\.md$/.test(p)) return "instructions";
  if (/(?:^|\/)\.claude\/(skills|agents|commands|rules|output-styles)\/.+\.md$/.test(p)) return "instructions";
  if (/(?:^|\/)\.agents\/skills\/.+\.md$/.test(p)) return "instructions";
  if (/^\.github\/(?:prompts|agents|chatmodes)\/.+\.md$/.test(p)) return "instructions";
  if (/(?:^|\/)\.claude\/hooks\/.+/.test(p) && !NOT_A_SCRIPT.test(p)) return "agent_script";
  if (/(?:^|\/)(?:\.claude|\.agents)\/skills\/.+/.test(p) && (SCRIPT_EXTENSIONS.test(p) || /\/(?:scripts|bin)\/[^/.]+$/.test(p))) return "agent_script";
  if (p === ".claude/settings.json" || p === ".claude/settings.local.json") return "claude_settings";
  if (p === ".mcp.json" || p === ".cursor/mcp.json" || p === ".vscode/mcp.json" || p === ".roo/mcp.json" || p === ".kiro/settings/mcp.json") return "mcp_json";
  if (p === ".gemini/settings.json") return "gemini_settings";
  if (/^\.gemini\/commands\/.+\.toml$/.test(p)) return "gemini_command";
  if (p === ".codex/config.toml") return "codex_toml";
  if (p === ".cursor/hooks.json" || p === ".codex/hooks.json") return "hooks_json";
  if (p === ".cursor/environment.json") return "cursor_environment";
  if (p === ".devcontainer/devcontainer.json" || p === ".devcontainer.json" || /^\.devcontainer\/[^/]+\/devcontainer\.json$/.test(p)) return "devcontainer";
  if (p === ".vscode/tasks.json") return "vscode_tasks";
  if (p === ".vscode/settings.json") return "vscode_settings";
  if (p === "package.json") return "package_json";
  if (!p.includes("/") && ENV_FILE.test(name) && !ENV_TEMPLATE.test(name)) return "env_file";
  return null;
}

/** The paths the check reads, for the docs and the result page's "what we checked". */
export const CHECKED_PATHS: readonly string[] = [
  "CLAUDE.md, CLAUDE.local.md, AGENTS.md, GEMINI.md (anywhere in the tree)",
  ".cursorrules, .cursor/rules/**, .windsurfrules, .clinerules, .windsurf/rules/**, .windsurf/workflows/**",
  ".github/copilot-instructions.md, .github/instructions/*.instructions.md, .github/prompts/**, .github/agents/**, .github/chatmodes/**",
  ".claude/settings.json, .claude/settings.local.json",
  ".claude/skills/**, .claude/agents/**, .claude/commands/**, .claude/rules/**, .claude/output-styles/**, .claude/hooks/** (also nested in sub-folders), .agents/skills/**",
  ".mcp.json, .cursor/mcp.json, .vscode/mcp.json, .roo/mcp.json, .kiro/settings/mcp.json",
  ".gemini/settings.json, .gemini/commands/**/*.toml, .codex/config.toml, .codex/hooks.json, .cursor/hooks.json, .cursor/environment.json",
  ".devcontainer/devcontainer.json, .devcontainer.json",
  ".vscode/tasks.json, .vscode/settings.json",
  "package.json scripts (root)",
  ".env files at the root (credential names and shapes only, to judge blast radius)",
  "Agent memory: .claude/memory/**, .claude/agent-memory/**, .claude/agent-memory-local/**, MEMORY.md at the root or in a memory/ or memories/ folder, and the Markdown files a MEMORY.md links to",
];

/** Whether a kind counts as agent configuration (an env file or package.json alone is not). */
export const isAgentConfig = (kind: AgentFileKind) => kind !== "env_file" && kind !== "package_json";

/** Whether a path is a memory index (MEMORY.md), whose links name more memory files. */
export const isMemoryIndex = (path: string) => base(lower(path)) === "memory.md" && agentFileKind(path) === "memory";

/** At most this many files one memory index links to are read. */
export const MAX_MEMORY_LINKS = 200;

/**
 * The repository paths of the Markdown files a memory index links to
 * (`[text](people/priya.md)` or `[[people/priya]]`), relative to the index's
 * folder. Never a URL, an absolute path or a path that climbs out of the
 * repository. Pure, so the collector, the browser tool and the analyzer agree
 * on which files are memory.
 */
export function memoryLinks(indexPath: string, content: string): string[] {
  const dir = indexPath.replace(/\\/g, "/").replace(/^\.\//, "").split("/").slice(0, -1);
  const targets: string[] = [];
  // Bounded: a file of unclosed brackets costs linear time, not quadratic.
  for (const m of content.matchAll(/\[[^[\]\n]{0,512}\]\(\s{0,16}<?([^)\s>#?]{1,1024})/g)) targets.push(m[1] ?? "");
  for (const m of content.matchAll(/\[\[([^[\]|#\n]{1,512})(?:[|#][^[\]\n]{0,512})?\]\]/g)) {
    const t = (m[1] ?? "").trim();
    targets.push(/\.md$/i.test(t) ? t : `${t}.md`);
  }
  const out = new Set<string>();
  for (const raw of targets) {
    if (out.size >= MAX_MEMORY_LINKS) break;
    let target: string;
    try {
      target = decodeURIComponent(raw);
    } catch {
      continue;
    }
    if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith("/") || target.startsWith("\\") || !/\.md$/i.test(target)) continue;
    const parts = [...dir];
    let escaped = false;
    for (const part of target.replace(/\\/g, "/").split("/")) {
      if (part === "" || part === ".") continue;
      if (part === "..") {
        if (parts.length === 0) escaped = true;
        else parts.pop();
      } else parts.push(part);
    }
    if (!escaped && parts.length > 0) out.add(parts.join("/"));
  }
  return [...out];
}

/**
 * Every given file's kind: its path's kind, or memory when a memory index
 * among the files links to it. Files neither names are left out.
 */
export function classifyAgentFiles(files: readonly { path: string; content: string }[]): Map<string, AgentFileKind> {
  const kinds = new Map<string, AgentFileKind>();
  for (const f of files) {
    const kind = agentFileKind(f.path);
    if (kind !== null) kinds.set(f.path, kind);
  }
  const linked = new Set(files.filter((f) => isMemoryIndex(f.path)).flatMap((f) => memoryLinks(f.path, f.content)));
  for (const f of files) if (!kinds.has(f.path) && linked.has(f.path)) kinds.set(f.path, "memory");
  return kinds;
}
