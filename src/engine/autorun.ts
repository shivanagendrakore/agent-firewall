/**
 * Content checks for the files that make code run later (CI, git hooks, editor tasks, dev
 * containers, environment hooks). In a trusted session a write inside the workspace to one of these
 * is allowed, unless the change adds a code-running capability ordinary edits rarely add: a task that
 * runs when the folder opens, a CI trigger that runs pull-request code with secrets, a download piped
 * to a shell, a git filter driver. Those are FW-AUTORUN (approve). The detectors are the vendored
 * agent-safety ones (commandRisks) plus a few file-specific patterns.
 *
 * Detection only: the verdicts are in decide.ts. The result is recorded on the write effect as tags:
 *   autorun-checked   the content was seen (a Write or Edit); a shell write is unchecked
 *   autorun:<what>    a capability the change adds (one tag each)
 *   autorun-form      the change touches an auto-run form (held when untrusted for editor tasks and dev containers)
 */

import type { Effect, FirewallConfig } from "../types.js";
import { commandRisks, urlsIn, type CommandRisk } from "../vendor/agent-safety/signals.js";
import { autoApproveEntries } from "./autoapprove.js";
import { addFinding, type Collector } from "./effects.js";
import { hostInList } from "./network.js";
import { classifyPath, isUnder, normalizeAbs, resolvePath, type PersistTag } from "./paths.js";
import { invisibleCharacters } from "./unicode.js";

/** The file kinds the checks know: the persistence tags, and two files judged only by their content. */
type Kind = PersistTag | "gitattributes" | "nix";

export interface AutorunFinding {
  /** Capabilities the change adds (FW-AUTORUN in a trusted session). */
  adds: string[];
  /** The change touches an auto-run form (a lifecycle command, a shellHook), even a harmless-looking one. */
  form: boolean;
}

const MAX_TEXT = 512 * 1024;

const base = (abs: string): string => abs.slice(abs.lastIndexOf("/") + 1);

function kindOf(abs: string, tag: PersistTag | undefined): Kind | null {
  const b = base(abs).toLowerCase();
  if (b === ".gitattributes") return "gitattributes";
  if (b === "flake.nix" || b === "shell.nix") return "nix";
  return tag ?? null;
}

const SERIOUS: ReadonlySet<CommandRisk> = new Set(["remote_code", "exfiltration", "obfuscated"]);
const RISK_WORDS: Record<CommandRisk, string> = {
  remote_code: "downloads code and runs it",
  exfiltration: "sends credentials off the machine",
  obfuscated: "decodes hidden text and runs it",
  network: "makes network calls",
};

/** Longer command lines are not judged (commandRisks works on one command line); one is reported, never skipped silently. */
const MAX_COMMAND_LINE = 4000;

/**
 * Risky commands in the text, line by line (commandRisks works on one command line). A command
 * continued over several lines (`\` at the end of a line) is judged whole.
 */
function risks(text: string, includeNetwork: boolean): string[] {
  const out: string[] = [];
  for (const line of text.replace(/\\\r?\n/g, " ").split(/\r?\n|\r/)) {
    // The line's start is part of the text, so a second risky command of a kind the file already had (or a
    // changed address in an existing one) is a new addition, not the same one. One entry per line: a line
    // the file now has twice counts twice (see newAdds).
    const shown = line.trim().replace(/\s+/g, " ").slice(0, 60);
    if (line.length > MAX_COMMAND_LINE) {
      out.push(`a command line too long for the firewall to check (over ${MAX_COMMAND_LINE.toLocaleString("en-US")} characters, starting: ${shown})`);
      continue;
    }
    for (const r of new Set(commandRisks(line))) if (SERIOUS.has(r) || includeNetwork) out.push(`a command that ${RISK_WORDS[r]} (${shown})`);
  }
  return out;
}

/** What `now` has that `had` does not, counting repeats: a risky line the file now holds twice is one new one. */
function newAdds(now: readonly string[], had: readonly string[]): string[] {
  const left = new Map<string, number>();
  for (const h of had) left.set(h, (left.get(h) ?? 0) + 1);
  const out: string[] = [];
  for (const a of now) {
    const n = left.get(a) ?? 0;
    if (n > 0) left.set(a, n - 1);
    else out.push(a);
  }
  return out;
}

// Git's built-in diff and merge drivers only change how a diff looks; they run nothing.
const BUILTIN_DIFF = new Set(["ada", "bash", "bibtex", "cpp", "csharp", "css", "dts", "elixir", "fortran", "fountain", "golang", "html", "java", "kotlin", "markdown", "matlab", "objc", "pascal", "perl", "php", "python", "ruby", "rust", "scheme", "tex", "astextplain"]);
const BUILTIN_MERGE = new Set(["text", "binary", "union"]);

function gitAttributes(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(/(?:^|\s)(filter|diff|merge)=([^\s#]+)/gm)) {
    const [, attr, driver] = m as unknown as [string, string, string];
    if (attr === "diff" && BUILTIN_DIFF.has(driver)) continue;
    if (attr === "merge" && BUILTIN_MERGE.has(driver)) continue;
    out.add(`a git ${attr} driver (${attr}=${driver.slice(0, 40)}), which runs a program git is configured with`);
  }
  return [...out];
}

function outsideWorkspace(value: string, roots: readonly string[], home: string, ci: boolean): boolean {
  const v = value.trim();
  if (v === "" || /\$\{workspace(?:Folder|Root)[^}]*\}/.test(v)) return false;
  if (!/^(?:\/|~|[A-Za-z]:[\\/]|\$\{(?:env:)?HOME\}|\$\{userHome\})/.test(v)) return false;
  const abs = normalizeAbs(v.replace(/^~|^\$\{(?:env:)?HOME\}|^\$\{userHome\}/, home).replace(/\\/g, "/"));
  return !roots.some((r) => isUnder(abs, r, ci));
}

/**
 * F17: a JSONC document with its comments removed and every string's escapes decoded (then written back
 * in plain JSON form), so a key spelled "run\u004fn" or with a comment before its colon reads as the
 * editor reads it. Text that is not JSONC comes back as it was.
 */
export function normalizeJsonc(text: string): string {
  let out = "";
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i] as string;
    if (ch === "/" && text[i + 1] === "/") {
      while (i < n && text[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      out += " ";
      i = end === -1 ? n : end + 2;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let raw = "";
      while (j < n && text[j] !== '"' && text[j] !== "\n") {
        if (text[j] === "\\") {
          raw += text.slice(j, j + 2);
          j += 2;
          continue;
        }
        raw += text[j];
        j++;
      }
      if (text[j] !== '"') return text;
      let decoded: string;
      try {
        decoded = JSON.parse(`"${raw}"`) as string;
      } catch {
        decoded = raw;
      }
      out += JSON.stringify(decoded);
      i = j + 1;
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

function editorTask(abs: string, raw: string, roots: readonly string[], home: string, ci: boolean): string[] {
  const out: string[] = [];
  const text = /\.(?:json|jsonc|code-workspace)$/i.test(abs) ? normalizeJsonc(raw) : raw;
  // One entry per task, so a second folder-open task in a file that has one is new.
  const folderOpen = [...text.matchAll(/"runOn"\s*:\s*"folderOpen"/g)].length;
  for (let i = 0; i < folderOpen; i++) out.push("a task that runs as soon as the folder is opened (runOn: folderOpen)");
  if (/"task\.allowAutomaticTasks"\s*:\s*(?:"on"|true)/.test(text)) out.push("automatic tasks switched on (task.allowAutomaticTasks)");
  for (const k of autoApproveEntries(text)) out.push(`an agent's own auto-approval switched on (${k.key.slice(0, 60)}: ${k.value.slice(0, 60)})`);
  for (const m of text.matchAll(/"(terminal\.integrated\.(?:env|profiles|automationProfile|shell|shellArgs)\.[A-Za-z]+)"\s*:\s*(?!null)/g)) out.push(`a terminal environment or shell profile (${m[1] as string})`);
  for (const m of text.matchAll(/"((?:git\.path|[\w.-]*[Ee]xecutablePath|python\.defaultInterpreterPath|python\.pythonPath|[\w.-]*\.serverPath))"\s*:\s*"([^"\n]*)"/g)) {
    if (outsideWorkspace(m[2] as string, roots, home, ci)) out.push(`a program path outside the workspace (${m[1] as string})`);
  }
  if (/\/(?:\.nvim\.lua|\.exrc|\.vimrc)$/i.test(abs) && /\bsystem\s*\(|^\s*:?!|\bos\.execute\b|\bio\.popen\b|\bjobstart\b|\bvim\.fn\.system\b|\bvim\.system\b/m.test(text)) {
    out.push("shell commands the editor runs when it opens the folder");
  }
  return out;
}

const UNTRUSTED_TRIGGER = /\b(?:pull_request_target|workflow_run)\b/;
const HEAD_CHECKOUT = /github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs\/pull\/|github\.event\.workflow_run\.head_(?:sha|branch)|github\.event\.pull_request\.merge_commit_sha/;
const OUTSIDER_TRIGGER = /\b(?:pull_request_target|workflow_run|issue_comment|issues|discussion_comment|pull_request_review_comment)\b/;

/**
 * F39: the events a GitHub workflow runs on (its `on:` key: a scalar, a flow list or map, or a block map).
 * Null when the file has no `on:` the parser can read (the caller then searches the whole text).
 */
export function workflowTriggers(text: string): Set<string> | null {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const idx = lines.findIndex((l) => /^["']?on["']?\s*:/.test(l));
  if (idx === -1) return null;
  const rest = (lines[idx] as string).replace(/^["']?on["']?\s*:\s*/, "").replace(/\s+#.*$/, "").trim();
  const out = new Set<string>();
  if (rest.startsWith("[") || rest.startsWith("{")) {
    for (const m of rest.matchAll(/([A-Za-z_][\w-]*)\s*(?=[,:\]}])/g)) out.add(m[1] as string);
    return out;
  }
  if (rest !== "") {
    out.add(rest.replace(/["']/g, ""));
    return out;
  }
  let indent: number | null = null;
  for (const l of lines.slice(idx + 1)) {
    if (l.trim() === "" || /^\s*#/.test(l)) continue;
    const ind = (/^(\s*)/.exec(l)?.[1] ?? "").length;
    if (ind === 0) break;
    indent ??= ind;
    if (ind !== indent) continue;
    const m = /^\s*(?:-\s*)?["']?([A-Za-z_][\w-]*)["']?\s*:?/.exec(l);
    if (m !== null) out.add(m[1] as string);
  }
  return out;
}

/** F40: GitHub expressions in one spelling: github.event['pull_request']["head"] is github.event.pull_request.head. */
function dotted(text: string): string {
  return text.replace(/\[\s*(['"])([\w-]+)\1\s*\]/g, ".$2");
}

function ciFile(raw: string, cfg: FirewallConfig): string[] {
  const out: string[] = [];
  const text = dotted(raw);
  const triggers = workflowTriggers(text);
  const has = (re: RegExp): boolean => (triggers === null ? re.test(text) : [...triggers].some((t) => re.test(t)));
  // F39: a head ref used only to name a concurrency group checks nothing out.
  const code = text.split("\n").filter((l) => !/^\s*(?:group|concurrency)\s*:/.test(l)).join("\n");
  if (has(UNTRUSTED_TRIGGER) && HEAD_CHECKOUT.test(code)) out.push("a workflow that runs pull-request code with the repository's secrets (pull_request_target or workflow_run with a checkout of the pull request's head)");
  if (has(OUTSIDER_TRIGGER) && /permissions:\s*write-all|contents:\s*write/.test(text)) out.push("write permissions on a workflow that outsiders can trigger");
  // A step that uses a secret and contacts a host that is not on an allowlist.
  for (const step of text.split(/\n\s*-\s+(?=(?:name|uses|run|id|with|env|if)\b)/)) {
    if (!/\$\{\{\s*secrets\./.test(step)) continue;
    const far = urlsIn(step).map((u) => u.host).filter((h) => h !== "" && !/^(?:localhost|127\.0\.0\.1)$/.test(h) && !hostInList(h, cfg.fetchAllowHosts) && !hostInList(h, cfg.sendAllowHosts));
    if (far.length > 0) out.push(`a step that uses a secret and contacts ${far[0] as string}`);
  }
  return out;
}

/**
 * A hook body or a hook manager's configuration: it runs on every commit, checkout or push, so an
 * untrusted session's change to it is always held. (.git/config, .gitmodules and .git/info/attributes
 * are git-hook files too, but only some of their settings run a program.)
 */
export function isHookBody(abs: string): boolean {
  if (/\/\.husky\/|\/\.githooks\/|\/\.lefthook\/|\/lefthook(?:-local)?\.yml$|\/\.pre-commit-(?:config|hooks)\.yaml$/i.test(abs)) return true;
  const segs = lowerSegments(abs);
  const dir = gitDirEnds(segs);
  for (let i = 1; i < segs.length - 1; i++) if (segs[i] === "hooks" && dir[i - 1] === true) return true;
  return false;
}

/** Git's config files: the repository's, a submodule's (.git/modules/<name>/config) and worktree config. */
export function isGitConfig(abs: string): boolean {
  const segs = lowerSegments(abs);
  const n = segs.length;
  if (segs[n - 1] !== "config" && segs[n - 1] !== "config.worktree") return false;
  if (n >= 3 && gitDirEnds(segs)[n - 2] === true) return true;
  return n >= 5 && segs[n - 2] !== "" && segs[n - 3] === "worktrees" && segs[n - 4] === ".git";
}

/** A repository's or a submodule's info/attributes, which can name filter drivers like .gitattributes. */
export function isGitInfoAttributes(abs: string): boolean {
  const segs = lowerSegments(abs);
  const n = segs.length;
  return n >= 4 && segs[n - 1] === "attributes" && segs[n - 2] === "info" && gitDirEnds(segs)[n - 3] === true;
}

/** Path segments with ASCII letters lower-cased: the same letters a /i regex folds, and no others. */
function lowerSegments(abs: string): string[] {
  return abs.replace(/[A-Z]+/g, (s) => s.toLowerCase()).split("/");
}

/**
 * For each segment, whether the path up to it names a git directory: `/.git`, or a submodule's
 * `/.git/modules/<name>` (one or more non-empty segments). One pass: a regex for this was quadratic on a
 * path that repeats `.git/modules/` (CodeQL js/polynomial-redos).
 */
function gitDirEnds(segs: readonly string[]): boolean[] {
  const out: boolean[] = [];
  // A `/.git/modules` seen earlier with no empty segment since.
  let modules = false;
  for (let i = 0; i < segs.length; i++) {
    const s = segs[i] as string;
    if (s === "") modules = false;
    out.push(s !== "" && ((s === ".git" && i >= 1) || modules));
    if (s === "modules" && i >= 2 && segs[i - 1] === ".git") modules = true;
  }
  return out;
}

/**
 * F16: the keys a git config file sets, as section.subsection.key (lower-case section and key), in any of
 * git's layouts: one key per line, a key on the section line (`[core] hooksPath = x`), `[section.sub]` and
 * `[section "sub"]` headers, comments after `#` or `;`.
 */
export function gitConfigKeys(text: string): { key: string; value: string }[] {
  const out: { key: string; value: string }[] = [];
  let section = "";
  for (const raw of text.replace(/\r\n/g, "\n").split("\n")) {
    let line = raw.trim();
    const h = /^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]\s*/.exec(line);
    if (h !== null) {
      const name = (h[1] as string).toLowerCase();
      section = h[2] !== undefined ? `${name.split(".")[0]}.${h[2]}` : name.includes(".") ? `${name.slice(0, name.indexOf("."))}.${(h[1] as string).slice(name.indexOf(".") + 1)}` : name;
      line = line.slice(h[0].length);
    }
    if (line === "" || /^[#;]/.test(line)) continue;
    const m = /^([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*))?$/.exec(line);
    if (m === null) continue;
    out.push({ key: `${section}.${(m[1] as string).toLowerCase()}`, value: (m[2] ?? "true").replace(/\s+[#;].*$/, "").trim() });
  }
  return out;
}

/** Git settings that make git run a program, read another config file, or hand data to a helper. */
const GIT_PROGRAM_KEYS: { re: RegExp; what: string }[] = [
  { re: /^core\.(?:hookspath|fsmonitor|sshcommand|askpass|pager|editor|gitproxy)$/, what: "a git setting that makes git run a program" },
  { re: /^(?:include|includeif\..*)\.path$/, what: "an included git config file, which can set any of git's program settings (include.path)" },
  { re: /^(?:filter\..*\.(?:clean|smudge|process)|diff\..*\.(?:textconv|command)|merge\..*\.driver|difftool\..*\.cmd|mergetool\..*\.cmd|credential(?:\..*)?\.helper|gpg(?:\..*)?\.program|sequence\.editor|diff\.external|uploadpack\.packobjectshook|pager\..*|ssh\.variant|http\..*\.proxy|remote\..*\.(?:uploadpack|receivepack)|protocol\..*\.allow)$/, what: "a git setting that makes git run a program" },
];

function gitConfigPrograms(text: string): string[] {
  const out = new Set<string>();
  for (const { key, value } of gitConfigKeys(text)) {
    if (/^alias\./.test(key) && value.startsWith("!")) out.add("a git alias that runs a shell command (alias with !)");
    for (const g of GIT_PROGRAM_KEYS) if (g.re.test(key)) out.add(g.what);
  }
  // Anything git might read that this parser does not understand keeps the old line check.
  if (/^\s*(?:hooksPath|fsmonitor|sshCommand|askPass|textconv|clean|smudge|process|driver|helper)\s*=/im.test(text)) out.add("a git setting that makes git run a program");
  return [...out];
}

function gitHook(abs: string, text: string): string[] {
  if (isGitConfig(abs)) return gitConfigPrograms(text);
  if (isGitInfoAttributes(abs)) return gitAttributes(text);
  // Hook bodies and hook-manager configurations: a plain lint or test hook is fine; any risky command is not.
  return risks(text, true).map((r) => `a git hook with ${r}`);
}

const LIFECYCLE = /"(?:postCreateCommand|postStartCommand|postAttachCommand|initializeCommand|onCreateCommand|updateContentCommand|init_hook)"\s*:/;
const HOST_MOUNT = /docker\.sock|source=(?:\$\{localEnv:(?:HOME|USERPROFILE)\}|~|\/)(?:,|"|$)|"source"\s*:\s*"(?:\/|~|\$\{localEnv:(?:HOME|USERPROFILE)\})"/;

function devcontainer(text: string): string[] {
  const out: string[] = [];
  if (/"privileged"\s*:\s*true|--privileged/.test(text)) out.push("a privileged container");
  if (HOST_MOUNT.test(text)) out.push("a container that mounts your home directory, the whole disk or the Docker socket");
  return out;
}

function envHook(abs: string, text: string): string[] {
  const b = base(abs).toLowerCase();
  if (b === ".npmrc") return npmrcSettings(text);
  // F41: yarn v1's .yarnrc: `yarn-path` runs another yarn program, like .yarnrc.yml's yarnPath.
  if (b === ".yarnrc") return [...npmrcSettings(text), ...(/^\s*"?yarn-path"?[\s=]/m.test(text) ? ["a different yarn program (yarn-path)"] : [])];
  if (b === ".yarnrc.yml") {
    const out: string[] = [];
    for (const m of text.matchAll(/^\s*npmRegistryServer\s*:\s*["']?([^"'\s]+)/gm)) if (!/^https:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\/?$/.test(m[1] as string)) out.push(`a different package registry (${(m[1] as string).slice(0, 80)})`);
    if (/^\s*yarnPath\s*:/m.test(text)) out.push("a different yarn program (yarnPath)");
    return out;
  }
  if (b === ".pnpmfile.cjs" && /child_process|execSync|spawnSync|\bspawn\(|\bexec\(/.test(text)) return ["install-time code that starts programs"];
  return risks(text, true).map((r) => `an environment hook with ${r}`);
}

/** `.npmrc` (and `npm config set`) settings that change what installs run or fetch from. */
export function npmrcSettings(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/^\s*((?:@[^:\s=]+:)?registry)\s*[= ]\s*"?([^\s"]+)/gm)) {
    if (!/^https:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\/?$/.test(m[2] as string)) out.push(`a different package registry (${(m[1] as string).slice(0, 40)}=${(m[2] as string).slice(0, 80)})`);
  }
  for (const m of text.matchAll(/^\s*(script-shell|node-options|shell|git|onload-script)\s*=\s*\S/gm)) out.push(`a setting that changes what installs run (${m[1] as string})`);
  if (/^\s*ignore-scripts\s*=\s*false\b/m.test(text)) out.push("install scripts switched back on (ignore-scripts=false)");
  return out;
}

function detect(kind: Kind, abs: string, text: string, c: Collector): AutorunFinding {
  const roots = c.ctx.workspaceRoots;
  switch (kind) {
    case "editor-task": {
      const adds = [...editorTask(abs, text, roots, c.ctx.home, c.ctx.caseInsensitive), ...risks(text, false).map((r) => `an editor task with ${r}`)];
      return { adds, form: adds.length > 0 };
    }
    case "ci":
      return { adds: [...ciFile(text, c.cfg), ...risks(text, false).map((r) => `a CI step with ${r}`)], form: false };
    case "git-hook": {
      const adds = gitHook(abs, text);
      return { adds, form: isHookBody(abs) || adds.length > 0 };
    }
    case "gitattributes": {
      const adds = gitAttributes(text);
      return { adds, form: adds.length > 0 };
    }
    case "devcontainer": {
      // F17: JSONC escapes and comments are read the way the dev-container tools read them.
      if (/\.(?:json|jsonc)$/i.test(abs)) text = normalizeJsonc(text);
      const lifecycle = LIFECYCLE.test(text) || /^\s*(?:-\s*)?(?:init|before|command)\s*:/m.test(text) || /^\s*(?:run|onBoot)\s*=/m.test(text);
      const adds = [...devcontainer(text), ...(lifecycle ? risks(text, false).map((r) => `a lifecycle command with ${r}`) : [])];
      return { adds, form: lifecycle || adds.length > 0 };
    }
    case "nix": {
      const hook = /\bshellHook\b/.test(text);
      return { adds: hook ? risks(text, false).map((r) => `a shellHook with ${r}`) : [], form: hook };
    }
    case "env-hook":
      return { adds: envHook(abs, text), form: false };
  }
}

/** The shellHook block of a nix file, for "did the shellHook change". */
function shellHookOf(text: string): string {
  // Everything from the first shellHook on: a later hook, or a long one, is compared in full.
  const i = text.indexOf("shellHook");
  return i === -1 ? "" : text.slice(i);
}

function readBefore(c: Collector, abs: string): string | null {
  try {
    const t = c.ctx.readFile?.(abs) ?? null;
    return t === null ? null : t.slice(0, MAX_TEXT);
  } catch {
    return null;
  }
}

function parsesAsJson(text: string): boolean {
  let out = "";
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;
    if (inStr) {
      out += ch;
      if (ch === "\\") out += text[++i] ?? "";
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') {
      inStr = true;
      out += ch;
    } else if (ch === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (ch === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i++;
    } else out += ch;
  }
  try {
    JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
    return true;
  } catch {
    return false;
  }
}

/** The write effects this action records for `abs` (Write/Edit record one). */
function writeEffects(c: Collector, abs: string): Effect[] {
  return c.effects.filter((e) => (e.cls === "write_persistence" || e.cls === "write_workspace") && e.target === abs);
}

function mark(effects: readonly Effect[], f: AutorunFinding, kind: Kind): void {
  for (const e of effects) {
    const tags = new Set(e.tags ?? []);
    tags.add("autorun-checked");
    for (const a of f.adds) tags.add(`autorun:${a}`);
    if (f.form) tags.add("autorun-form");
    // A .gitattributes driver or a shellHook makes an ordinary file a persistence point.
    if (e.cls === "write_workspace" && (kind === "gitattributes" || kind === "nix") && (f.adds.length > 0 || f.form)) {
      e.cls = "write_persistence";
      tags.add(`persist:${kind === "gitattributes" ? "git-hook" : "devcontainer"}`);
      e.detail = `${e.detail} (${kind === "gitattributes" ? "a git attribute that names a driver" : "a nix shellHook, which runs when the shell starts"})`;
    }
    e.tags = [...tags];
  }
}

/**
 * Checks a Write or Edit of a persistence file by the content it would have afterwards. `result`
 * computes that content from the current one (null when it cannot be read: an edit is then judged by
 * what it adds). Called after writePath recorded the write effect.
 */
export function checkAutorun(c: Collector, rawPath: string, result: (before: string | null) => string, wholeFile: boolean): void {
  try {
    const r = resolvePath(rawPath, c.ctx);
    if (r === null) return;
    const info = classifyPath(r, c.ctx, c.cfg);
    const kind = kindOf(info.abs, info.persistTag);
    if (kind === null) return;
    const effects = writeEffects(c, info.abs);
    if (effects.length === 0) return;
    const before = readBefore(c, info.abs);
    const full = result(before);
    const after = full.slice(0, MAX_TEXT);
    const hidden = invisibleCharacters(after).filter((h) => before === null || !invisibleCharacters(before).includes(h));
    if (hidden.length > 0) addFinding(c, "invisible_unicode", `the change to ${info.abs} contains hidden characters (${hidden.join(", ")})`);
    if (kind === "nix" && before !== null && shellHookOf(before) === shellHookOf(after)) return;
    const now = detect(kind, info.abs, after, c);
    const had = before === null ? { adds: [], form: false } : detect(kind, info.abs, before, c);
    const adds = newAdds(now.adds, had.adds);
    // The tail past the limit is not read: say so, never treat it as clean.
    if (full.length > MAX_TEXT) adds.push("a file too large for the firewall to check");
    // A whole JSON settings file the firewall cannot read: assume the worst (it cannot see what it runs).
    if ((wholeFile || before !== null) && /\.(?:json|code-workspace)$/i.test(info.abs) && (kind === "editor-task" || kind === "devcontainer") && !parsesAsJson(after)) {
      adds.push("a settings file the firewall cannot parse, so what it runs cannot be checked");
    }
    // An auto-run form the file did not have before (or any hook body) is held when the session is untrusted.
    mark(effects, { adds, form: adds.length > 0 || (kind === "git-hook" && isHookBody(info.abs)) || (kind === "nix" && now.form) || (now.form && !had.form) }, kind);
  } catch {
    // A detector failure is treated as adding the capability (approve), never as clean.
    for (const e of c.effects) if (e.cls === "write_persistence") e.tags = [...new Set([...(e.tags ?? []), "autorun-checked", "autorun:a change the firewall could not check", "autorun-form"])];
  }
}

/** `npm config set <key> <value>` (and its `key=value` form): the same .npmrc check as a Write. */
export function checkNpmConfig(c: Collector, npmrcPath: string, key: string, value: string): void {
  const r = resolvePath(npmrcPath, c.ctx);
  if (r === null) return;
  const effects = c.effects.filter((e) => e.cls === "write_persistence" && e.target === r.abs);
  mark(effects, { adds: npmrcSettings(`${key}=${value}`), form: false }, "env-hook");
}
