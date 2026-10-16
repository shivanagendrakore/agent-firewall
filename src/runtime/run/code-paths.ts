/**
 * v0.3 `run`: paths inside the workspace that the workspace itself names as code that runs later,
 * outside the sandbox, so `run` keeps them read-only on top of the fixed list
 * (engine/run-profile.ts WORKSPACE_PROTECTED):
 * - nested repositories' `.git/hooks`, `.git/config` and `.git/commondir`, and a `.git` file (a gitdir
 *   pointer) (V4);
 * - the directory `core.hooksPath` names, whether it exists or not, and files the git config names
 *   (an fsmonitor script, a filter) (V4), read from `.git/config`, `.git/config.worktree`, the person's
 *   global config and every file they include (RN5);
 * - the scripts that the workspace's agent settings run as hooks, MCP servers or editor tasks (V18), also
 *   when they do not exist yet (RN4).
 * Best effort and bounded: it reads small files and walks a limited part of the tree. docs/run.md lists
 * what it does not follow.
 */

import { lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, join, normalize, relative } from "node:path";

const MAX_FILE = 1024 * 1024;
const MAX_DEPTH = 6;
const MAX_ENTRIES = 20000;
const MAX_PATHS = 500;
/** Git config files read per workspace (the repository's, the global ones and their includes). */
const MAX_CONFIGS = 32;
/** Directories the nested-repository walk does not enter (installed packages and build output). */
const SKIP_DIRS = new Set([".git", "node_modules", ".venv", "venv", "__pycache__", "target", "dist", "build", ".next"]);

/** Agent settings in the workspace whose hook, server or task commands name scripts. */
const COMMAND_FILES: readonly { path: string; keys: readonly string[]; format: "json" | "jsonc" | "toml" | "frontmatter" }[] = [
  { path: ".claude/settings.json", keys: ["command"], format: "json" },
  { path: ".claude/settings.local.json", keys: ["command"], format: "json" },
  { path: ".codex/hooks.json", keys: ["command"], format: "json" },
  { path: ".gemini/settings.json", keys: ["command", "args"], format: "json" },
  { path: ".cursor/hooks.json", keys: ["command"], format: "json" },
  { path: ".mcp.json", keys: ["command", "args"], format: "json" },
  { path: ".cursor/mcp.json", keys: ["command", "args"], format: "json" },
  { path: ".vscode/tasks.json", keys: ["command", "args"], format: "jsonc" },
  { path: ".vscode/settings.json", keys: ["command", "args", "path", "*"], format: "jsonc" },
  { path: ".claude/skills", keys: ["command", "args"], format: "frontmatter" },
  { path: ".claude/agents", keys: ["command", "args"], format: "frontmatter" },
  { path: ".claude/commands", keys: ["command", "args"], format: "frontmatter" },
  { path: ".codex/config.toml", keys: ["command", "args", "notify"], format: "toml" },
];

function lkind(p: string): "dir" | "file" | "link" | null {
  try {
    const s = lstatSync(p);
    return s.isSymbolicLink() ? "link" : s.isDirectory() ? "dir" : s.isFile() ? "file" : null;
  } catch {
    return null;
  }
}

function readSmall(p: string): string | null {
  try {
    const s = lstatSync(p);
    if (!s.isFile() || s.size > MAX_FILE) return null;
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

function inside(p: string, ws: string): boolean {
  const r = relative(ws, p);
  return r !== "" && !r.startsWith("..") && !isAbsolute(r);
}

/** JSONC to JSON: comments and trailing commas removed, strings left alone. */
export function stripJsonc(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? text.length : end + 1;
    } else out += c;
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}

function matchCommandKey(k: string, keys: readonly string[]): boolean {
  if (keys.includes(k)) return true;
  if (!keys.includes("*")) return false;
  return /(?:^|\.)(?:command|args|path|shell|executable|interpreter|wrapper|server|script|notify)$/i.test(k) || /(?:Path|Executable|Command|Args|Wrapper|Script|Binary|Interpreter)$/.test(k);
}

/** The string values under the given keys, at any depth. */
function stringsUnder(v: unknown, keys: readonly string[], out: string[], depth = 0): void {
  if (depth > 32 || out.length > 5000) return;
  if (Array.isArray(v)) for (const x of v) stringsUnder(x, keys, out, depth + 1);
  else if (typeof v === "object" && v !== null) {
    for (const [k, x] of Object.entries(v)) {
      if (matchCommandKey(k, keys)) {
        if (typeof x === "string") out.push(x);
        else if (Array.isArray(x)) {
          for (const y of x) {
            if (typeof y === "string") out.push(y);
            else if (typeof y === "object" && y !== null && typeof (y as { value?: unknown }).value === "string") out.push((y as { value: string }).value);
          }
        }
      }
      stringsUnder(x, keys, out, depth + 1);
    }
  }
}

/** A git config value with unquoted `#` or `;` comments and surrounding quotes stripped. */
function gitConfigValue(raw: string): string {
  let out = "";
  let inQuote = false;
  let lastNonSpace = 0;
  const s = raw.trimStart();
  for (let i = 0; i < s.length; i++) {
    const c = s[i] as string;
    if (c === '"') {
      inQuote = !inQuote;
      lastNonSpace = out.length;
    } else if (!inQuote && (c === "#" || c === ";")) {
      break;
    } else if (inQuote && c === "\\" && i + 1 < s.length) {
      out += s[++i] as string;
      lastNonSpace = out.length;
    } else {
      out += c;
      if (inQuote || !/\s/.test(c)) lastNonSpace = out.length;
    }
  }
  return out.slice(0, lastNonSpace);
}

function frontmatterStrings(text: string, keys: readonly string[]): string[] {
  const m = /^\uFEFF?---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(text);
  if (m === null) return [];
  const fm = m[1] as string;
  const out: string[] = [];
  const keyPat = keys.join("|");
  const keyRe = new RegExp(`^(\\s*)(?:-\\s*)?(?:["']?(?:${keyPat})["']?)\\s*:\\s*(.*)$`);
  const flowRe = new RegExp(`[{,]\\s*(?:["']?(?:${keyPat})["']?)\\s*:\\s*("((?:[^"\\\\]|\\\\.)*)"|'([^']*)'|\\[[^\\]]*\\]|[^,}\\s#]+)`, "g");
  const lines = fm.split(/\r?\n/);
  const unquoteYaml = (raw: string): string => {
    const t = raw.trim();
    if (t.startsWith("'")) {
      const sq = /^'((?:[^']|'')*)'/.exec(t);
      if (sq !== null) return (sq[1] as string).replace(/''/g, "'");
    }
    return gitConfigValue(t);
  };
  const pushArray = (arr: string): void => {
    for (const q of arr.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'|([^,[\]\s][^,[\]]*)/g)) {
      const v = (q[1] ?? q[2] ?? (q[3] as string).replace(/\s+#.*$/, "")).trim();
      if (v !== "") out.push(v);
    }
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    const km = keyRe.exec(line);
    if (km !== null) {
      const indent = (km[1] as string).length;
      const rest = (km[2] as string).trim();
      if (rest === "" || rest.startsWith("#") || /^[|>][-+]?(?:\s+#.*)?$/.test(rest)) {
        const block = rest.startsWith("|") || rest.startsWith(">");
        while (i + 1 < lines.length) {
          const next = lines[i + 1] as string;
          if (/^\s*(?:#.*)?$/.test(next)) {
            i++;
            continue;
          }
          const ind = /^(\s*)(.*)$/.exec(next);
          const nextIndent = (ind?.[1] ?? "").length;
          const body = ind?.[2] ?? "";
          if (block) {
            if (nextIndent <= indent) break;
            i++;
            const v = unquoteYaml(body);
            if (v !== "") out.push(v);
          } else {
            const item = /^-\s+(.*)$/.exec(body);
            if (item === null || nextIndent < indent || keyRe.test(next)) break;
            i++;
            const v = unquoteYaml(item[1] as string);
            if (v !== "") out.push(v);
          }
        }
      } else if (rest.startsWith("[")) {
        pushArray(rest);
      } else {
        const v = unquoteYaml(rest);
        if (v !== "") out.push(v);
      }
      continue;
    }
    for (const fmMatch of line.matchAll(flowRe)) {
      const raw = (fmMatch[1] as string).trim();
      if (raw.startsWith("[")) pushArray(raw);
      else {
        const v = unquoteYaml(raw);
        if (v !== "") out.push(v);
      }
    }
  }
  return out;
}

/** The command strings a settings file names (hooks, MCP servers, tasks). */
export function commandStrings(text: string, keys: readonly string[], format: "json" | "jsonc" | "toml" | "frontmatter"): string[] {
  const out: string[] = [];
  if (format === "toml") {
    const re = new RegExp(`(?:^|[\\s,{])(?:[A-Za-z0-9_."-]+\\.)*(?:${keys.join("|")})\\s*=\\s*(\\[(?:[^\\]"']|"(?:[^"\\\\]|\\\\.)*"|'[^']*')*\\]|[^\\n]+)`, "gm");
    for (const m of text.matchAll(re)) for (const q of (m[1] as string).matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)) out.push(q[1] ?? q[2] ?? "");
    return out;
  }
  if (format === "frontmatter") return frontmatterStrings(text, keys);
  try {
    stringsUnder(JSON.parse(format === "jsonc" ? stripJsonc(text) : text), keys, out);
  } catch {
    // An unparsable file runs nothing; the agent reports it.
  }
  return out;
}

/** Extensions of files a command runs: a missing path with one is protected before it exists (RN4). */
const SCRIPT_EXT = /\.(?:sh|bash|zsh|fish|js|mjs|cjs|ts|mts|cts|jsx|tsx|py|rb|pl|php|ps1|lua)$/i;

/**
 * Files inside the workspace that a command string names: existing files (or symlinks), and missing paths
 * that look like a program, which the agent could otherwise create for the agent or editor to run later (a
 * gitignored, generated hook script): a script extension, `./` in front, or (with `programs`, for agent
 * settings) a path with a `/` in program position, the first word of the command or of each part of it after
 * `;`, `&&`, `|` (FA2: `"$CLAUDE_PROJECT_DIR"/.claude/hooks/guard`). Bare words (`node`, `sh`) are not paths:
 * they are looked up on PATH.
 */
export function scriptsNamed(command: string, ws: string, opts: { programs?: boolean } = {}): string[] {
  const expanded = command.replace(/\$\{?(?:CLAUDE_PROJECT_DIR|CURSOR_PROJECT_DIR|GEMINI_PROJECT_DIR|PWD)\}?|\$\{workspaceFolder\}/g, ws);
  const out: string[] = [];
  // Quotes are dropped before splitting, so "$CLAUDE_PROJECT_DIR"/.claude/hooks/x.sh stays one path.
  for (const part of expanded.replace(/["']/g, "").split(/[;&|()`\n]+/)) {
    let first = true;
    for (const word of part.split(/\s+/)) {
      if (word === "") continue;
      // Leading NAME=value assignments are not the program.
      const program = first && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(word);
      if (program) first = false;
      for (const raw of word.split(/[<>=]+/)) {
        if (raw === "" || raw.startsWith("-") || raw.includes("$") || raw.includes("://")) continue;
        const p = normalize(isAbsolute(raw) ? raw : join(ws, raw));
        if (!inside(p, ws)) continue;
        const k = lkind(p);
        if (k === "file" || k === "link" || (k === null && (SCRIPT_EXT.test(raw) || raw.startsWith("./") || (opts.programs === true && program && raw.includes("/"))))) out.push(p);
      }
    }
  }
  return [...new Set(out)];
}

/** The files a git config includes ([include] and every [includeIf], conditions ignored), resolved against `base` (the including file's directory). */
export function gitIncludes(text: string, base: string, home: string): string[] {
  const out: string[] = [];
  let section = "";
  for (let line of text.replace(/\r\n/g, "\n").split("\n")) {
    const sec = /^\s*\[\s*([A-Za-z0-9.-]+)(?:\s+"(?:[^"\\]|\\.)*")?\s*\]/.exec(line);
    if (sec !== null) {
      section = (sec[1] as string).toLowerCase();
      line = line.slice(sec[0].length);
    }
    const kv = /^\s*path\s*=\s*(.*)$/i.exec(line);
    if (kv === null || !(section === "include" || section.startsWith("includeif"))) continue;
    const value = gitConfigValue(kv[1] as string);
    if (value !== "") out.push(normalize(value.startsWith("~/") ? join(home, value.slice(2)) : isAbsolute(value) ? value : join(base, value)));
  }
  return out;
}

/** core.hooksPath and the files a git config names inside the workspace (`base`: the config file's directory, for its includes). */
export function gitConfigPaths(text: string, ws: string, home: string, base = join(ws, ".git")): string[] {
  const out: string[] = [];
  let section = "";
  for (let line of text.replace(/\r\n/g, "\n").split("\n")) {
    const sec = /^\s*\[\s*([A-Za-z0-9.-]+)(?:\s+"(?:[^"\\]|\\.)*")?\s*\]/.exec(line);
    if (sec !== null) {
      section = (sec[1] as string).toLowerCase();
      line = line.slice(sec[0].length);
    }
    const kv = /^\s*([A-Za-z][A-Za-z0-9-]*)\s*=\s*(.*)$/.exec(line);
    if (kv === null) continue;
    const key = (kv[1] as string).toLowerCase();
    const value = gitConfigValue(kv[2] as string);
    if (value === "") continue;
    if ((section === "include" || section.startsWith("includeif")) && key === "path") {
      // An included file is config too (it can set core.hooksPath); relative to the including file's directory.
      const p = normalize(value.startsWith("~/") ? join(home, value.slice(2)) : isAbsolute(value) ? value : join(base, value));
      if (inside(p, ws)) out.push(p);
      continue;
    }
    if (section === "core" && key === "hookspath") {
      const p = normalize(value.startsWith("~/") ? join(home, value.slice(2)) : isAbsolute(value) ? value : join(ws, value));
      // Protected whether it exists or not: git runs whatever appears there.
      if (inside(p, ws)) out.push(p);
      continue;
    }
    out.push(...scriptsNamed(value.replace(/^!+/, ""), ws, { programs: !/^\+?refs\//.test(value) }));
  }
  return out;
}

/** Nested repositories (not the workspace's own): their hooks, config and commondir, or their `.git` file. */
export function nestedRepoPaths(ws: string): string[] {
  const out: string[] = [];
  let seen = 0;
  const queue: [string, number][] = [[ws, 0]];
  while (queue.length > 0 && seen < MAX_ENTRIES) {
    const [dir, depth] = queue.shift() as [string, number];
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      continue;
    }
    for (const name of names) {
      if (++seen > MAX_ENTRIES) break;
      const p = join(dir, name);
      const k = lkind(p);
      if (name === ".git" && dir !== ws) {
        if (k === "dir") out.push(join(p, "hooks"), join(p, "config"), join(p, "config.worktree"), join(p, "commondir"));
        else if (k === "file") out.push(p);
        continue;
      }
      if (k === "dir" && depth + 1 < MAX_DEPTH && !SKIP_DIRS.has(name)) queue.push([p, depth + 1]);
    }
  }
  return out;
}

/**
 * Whether `p` is one of git's own files: a path with a `.git` component (the repository's `.git` directory and
 * everything in it, a submodule's or worktree's `.git` pointer file, `.git/modules/<x>/config`). Judged on the
 * path as written relative to the workspace and, when it resolves elsewhere, on its real path too.
 */
export function gitOwnedPath(p: string, ws: string): boolean {
  const has = (q: string): boolean => normalize(q).split(/[\\/]/).includes(".git");
  if (has(relative(ws, p))) return true;
  try {
    const real = realpathSync(p);
    return has(real.startsWith(`${ws}/`) ? relative(ws, real) : real);
  } catch {
    return false;
  }
}

/** A protected path the workspace names, and what names it (for run's notice). */
export interface CodePath {
  path: string;
  /** "git": the git config names it, or a git pointer; "script": an agent settings file runs it; "nested": a nested repository's git files. */
  kind: "git" | "script" | "nested";
  /** Workspace-relative name of the settings file that runs it (scripts only). */
  source?: string;
}

function commandSources(ws: string, relPath: string, format: "json" | "jsonc" | "toml" | "frontmatter"): { source: string; text: string }[] {
  const root = join(ws, relPath);
  if (format !== "frontmatter" || lkind(root) === "file") {
    const text = readSmall(root);
    return text === null ? [] : [{ source: relPath, text }];
  }
  if (lkind(root) !== "dir") return [];
  const out: { source: string; text: string }[] = [];
  let seen = 0;
  const queue: [string, number][] = [[root, 0]];
  while (queue.length > 0 && seen < MAX_ENTRIES) {
    const [dir, depth] = queue.shift() as [string, number];
    let names: string[];
    try {
      names = readdirSync(dir).sort();
    } catch {
      continue;
    }
    for (const name of names) {
      if (++seen > MAX_ENTRIES) break;
      const p = join(dir, name);
      const k = lkind(p);
      if (k === "file") {
        const text = readSmall(p);
        if (text !== null) out.push({ source: relative(ws, p).replace(/\\/g, "/"), text });
      } else if (k === "dir" && depth + 1 < MAX_DEPTH && !SKIP_DIRS.has(name)) {
        queue.push([p, depth + 1]);
      }
    }
  }
  return out;
}

/** Everything above for one workspace (absolute paths inside it), with what names each. */
export function workspaceCodeEntries(ws: string, home: string): CodePath[] {
  const out: CodePath[] = [];
  const git = (paths: string[]): void => {
    for (const path of paths) out.push({ path, kind: "git" });
  };
  // The workspace's own .git as a file (a linked worktree or a submodule): a new gitdir there brings its own hooks.
  if (lkind(join(ws, ".git")) === "file") git([join(ws, ".git")]);
  const nested = nestedRepoPaths(ws);
  const nestedConfigs: [string, string][] = [];
  for (const p of nested) {
    if (p.endsWith("/config") || p.endsWith("/config.worktree")) {
      nestedConfigs.push([p, dirname(dirname(p))]);
    } else if (p.endsWith("/.git") && lkind(p) === "file") {
      const m = /^gitdir:\s*(.+)$/m.exec(readSmall(p) ?? "");
      if (m !== null) {
        const gd = normalize(isAbsolute((m[1] as string).trim()) ? (m[1] as string).trim() : join(dirname(p), (m[1] as string).trim()));
        if (inside(gd, ws)) {
          nestedConfigs.push([join(gd, "config"), dirname(p)], [join(gd, "config.worktree"), dirname(p)]);
        }
      }
    }
  }
  // The repository's config and config.worktree, nested repositories' configs, the person's global config
  // (a relative core.hooksPath there is relative to the workspace), and every file they include, transitively (RN5).
  const queue: [string, string][] = [
    [join(ws, ".git", "config"), ws],
    [join(ws, ".git", "config.worktree"), ws],
    ...nestedConfigs,
    [join(home, ".gitconfig"), ws],
    [join(home, ".config", "git", "config"), ws],
  ];
  const seen = new Set<string>();
  while (queue.length > 0 && seen.size < MAX_CONFIGS) {
    const [f, repoRoot] = queue.shift() as [string, string];
    const key = `${f}\0${repoRoot}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const text = readSmall(f);
    if (text === null) continue;
    const base = dirname(f);
    git(gitConfigPaths(text, ws, home, base));
    if (repoRoot !== ws) {
      for (const p of gitConfigPaths(text, repoRoot, home, base)) if (inside(p, ws)) git([p]);
    }
    for (const inc of gitIncludes(text, base, home)) queue.push([inc, repoRoot]);
  }
  for (const f of COMMAND_FILES) {
    for (const src of commandSources(ws, f.path, f.format)) {
      for (const c of commandStrings(src.text, f.keys, f.format)) for (const path of scriptsNamed(c, ws, { programs: true })) out.push({ path, kind: "script", source: src.source });
    }
  }
  for (const path of nested) out.push({ path, kind: "nested" });
  // One entry per path, classified by what the path is, not by which list named it first (FA1): git's own
  // files (anything under a `.git`, a `.git` pointer) are "git" or "nested" even when an agent settings file
  // also names them, so run.allowWritePaths (which exempts only "script") can never reach them.
  const rank = { git: 0, nested: 1, script: 2 } as const;
  const byPath = new Map<string, CodePath>();
  for (const e of out) {
    const k: CodePath = e.kind === "script" && gitOwnedPath(e.path, ws) ? { path: e.path, kind: "git" } : e;
    const prev = byPath.get(k.path);
    if (prev === undefined || rank[k.kind] < rank[prev.kind]) byPath.set(k.path, k);
  }
  return [...byPath.values()].sort((a, b) => rank[a.kind] - rank[b.kind]).slice(0, MAX_PATHS);
}

/**
 * Runners: a command that starts code named elsewhere (a package.json script, a Makefile target, a module,
 * an installed package's binary) rather than a file the command names itself, which run could protect.
 */
const RUNNERS: readonly { re: RegExp; name: string }[] = [
  { re: /(?:^|[\s/;&|(])(?:npm|pnpm|yarn|bun)\s+(?:run(?:-script)?\s|exec\s|x\s|dlx\s|start\b|test\b)/, name: "npm run (package.json scripts)" },
  { re: /(?:^|[\s/;&|(])(?:yarn|pnpm)\s+(?!add\b|install\b|remove\b)[a-z][\w:-]*(?:\s|$)/, name: "yarn/pnpm <script>" },
  { re: /(?:^|[\s/;&|(])(?:npx|bunx|pnpx)\s/, name: "npx" },
  { re: /(?:^|[\s/;&|(])(?:make|gmake|just|task|rake)(?:\s|$)/, name: "make" },
  { re: /(?:^|[\s/;&|(])(?:python3?|uv\s+run\s+python|py)\s+(?:-\S+\s+)*-m\s/, name: "python -m" },
  { re: /(?:^|[\s/;&|(])(?:uvx|uv\s+run|poetry\s+run|pipx\s+run)\s/, name: "uv/poetry run" },
  { re: /node_modules\/\.bin\//, name: "node_modules/.bin" },
];

/** Agent settings commands (hooks, MCP servers, tasks) that start code through a runner (I10), for run's warning. */
export function runnerCommands(ws: string): { source: string; runner: string; command: string }[] {
  const out: { source: string; runner: string; command: string }[] = [];
  for (const f of COMMAND_FILES) {
    for (const src of commandSources(ws, f.path, f.format)) {
      // MCP server lists keep the program and its arguments apart: judge them joined, as the program sees them.
      const strings = commandStrings(src.text, f.keys, f.format);
      const joined = strings.length > 1 ? [...strings, strings.join(" ")] : strings;
      for (const c of joined) {
        for (const r of RUNNERS.filter((x) => x.re.test(c))) if (!out.some((o) => o.source === src.source && o.runner === r.name)) out.push({ source: src.source, runner: r.name, command: c.slice(0, 200) });
      }
    }
  }
  return out;
}

/** The paths of workspaceCodeEntries. */
export function workspaceCodePaths(ws: string, home: string): string[] {
  return workspaceCodeEntries(ws, home).map((e) => e.path);
}
