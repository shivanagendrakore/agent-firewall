/**
 * Paths: turn what an agent wrote into an absolute path, and say what that
 * path is (workspace, protected, a secret, a persistence point, the
 * firewall's own files). Pure: symlink resolution is injected through
 * Context.realpath.
 */

import type { Context, FirewallConfig } from "../types.js";
import { globMatch, globsOverlap } from "./glob.js";
import { canonicalOf, normalizeAbs, pathForms, PROTECTION_FOLDS_CASE } from "./canonical.js";
import { FIREWALL_MANAGED_DIRS, firewallDataKind, firewallPart } from "./identity.js";

export { canonicalOf, normalizeAbs, pathForms, PROTECTION_FOLDS_CASE, withCanonical, type PathForms } from "./canonical.js";

// --- the lists -------------------------------------------------------------------------------------
// Prefixes: "**/" matches anywhere on disk, "~/" is the home directory, "/" is absolute.
// Claude Code loads CLAUDE.md from every parent directory, so instruction files are protected anywhere.
// I1: every list below is matched ignoring case, on every platform (PROTECTION_FOLDS_CASE, canonical.ts), so a
// pattern is written the way the real path is spelled (~/.config/Claude) and also covers a lower-case alias.

/**
 * The user-level settings of VS Code and the editors built on it (VS Code, Insiders, VSCodium, Cursor, Windsurf), on
 * macOS and Linux: settings, tasks and MCP server lists, and the MCP settings of the Cline and Roo extensions
 * (kept in the editor's global storage). `tasks` and `settings` run programs; `mcp` and the extensions' files name them.
 */
const EDITOR_USER_DIRS: readonly string[] = ["Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"].flatMap((d) => [`**/Library/Application Support/${d}/User`, `**/.config/${d}/User`]);
const EDITOR_USER_PROGRAM_FILES: readonly string[] = EDITOR_USER_DIRS.flatMap((u) => [`${u}/settings.json`, `${u}/tasks.json`]);
const EDITOR_USER_AGENT_FILES: readonly string[] = EDITOR_USER_DIRS.flatMap((u) => [
  `${u}/mcp.json`,
  `${u}/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`,
  `${u}/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json`,
]);

/** The files that program coding agents: instructions, memory, settings, hooks, skills, MCP server lists. */
export const PROTECTED_PATTERNS: readonly string[] = [
  "**/CLAUDE.md",
  "**/CLAUDE.local.md",
  "**/AGENTS.md",
  "**/AGENT.md",
  "**/AGENTS.override.md",
  "**/MEMORY.md",
  "**/GEMINI.md",
  "**/.claude",
  "**/.claude/**",
  "**/.claude.json",
  "**/.claude.json.*",
  "**/.mcp.json",
  "**/.cursor",
  "**/.cursor/**",
  "**/.cursorrules",
  "**/.cursorignore",
  "**/.windsurfrules",
  "**/.windsurf",
  "**/.windsurf/**",
  "**/.codeium/**",
  "**/.clinerules",
  "**/.clinerules/**",
  "**/.roo",
  "**/.roo/**",
  "**/.roomodes",
  "**/.kiro",
  "**/.kiro/**",
  "**/.amazonq",
  "**/.amazonq/**",
  "**/.gemini",
  "**/.gemini/**",
  "**/.codex",
  "**/.codex/**",
  "**/.continue",
  "**/.continue/**",
  "**/.junie",
  "**/.junie/**",
  "**/.opencode",
  "**/.opencode/**",
  "**/opencode.json",
  "**/.goosehints",
  "**/.aider.conf.yml",
  "**/.github/copilot-instructions.md",
  "**/.github/instructions/**",
  "**/.github/prompts/**",
  "**/.github/chatmodes/**",
  "**/.github/agents/**",
  "**/.vscode/mcp.json",
  "**/.config/Claude/**",
  "**/.config/goose/**",
  "**/.config/opencode/**",
  "**/Library/Application Support/Claude/**",
  ...EDITOR_USER_PROGRAM_FILES,
  ...EDITOR_USER_AGENT_FILES,
  // Claude Code managed policy, all platforms.
  "/Library/Application Support/ClaudeCode/**",
  "/etc/claude-code/**",
  "C:/Program Files/ClaudeCode/**",
  // Codex managed configuration (requirements.toml) and Gemini CLI system settings.
  "/etc/codex/**",
  "/Library/Application Support/GeminiCli/**",
  "/etc/gemini-cli/**",
  // Cursor's enterprise hooks.json (MDM).
  "/Library/Application Support/Cursor/**",
  "/etc/cursor/**",
];

/** Agent memory and plans: the agent writes these in normal work, so a clean session may; a tainted one may not. */
export const MEMORY_PATTERNS: readonly string[] = [
  "**/.claude/projects/*/memory/**",
  "**/.claude/plans/**",
  "**/.claude/todos/**",
];

/**
 * What a persistence point is, so reasons and `explain` can be specific and the content
 * checks (src/engine/autorun.ts) know what to look for. Untagged points (shell start-up files,
 * schedulers, ~/.local/bin) keep the original rules.
 */
export type PersistTag = "ci" | "git-hook" | "editor-task" | "devcontainer" | "env-hook";

export const PERSIST_TAGS: readonly PersistTag[] = ["ci", "git-hook", "editor-task", "devcontainer", "env-hook"];

/** Files that make code run later without anyone asking, with what they are. */
export const PERSISTENCE_TAGGED: readonly { pattern: string; tag?: PersistTag }[] = [
  // CI systems, and the bots that open pull requests CI then runs.
  ...[
    "**/.github/workflows/**",
    "**/.github/actions/**",
    "**/action.yml",
    "**/action.yaml",
    "**/.gitlab-ci.yml",
    "**/.gitlab/ci/**",
    "**/.circleci/**",
    "**/bitbucket-pipelines.yml",
    "**/azure-pipelines.yml",
    "**/Jenkinsfile",
    "**/.buildkite/**",
    "**/.drone.yml",
    "**/.woodpecker.yml",
    "**/.woodpecker/**",
    "**/.travis.yml",
    "**/appveyor.yml",
    "**/cloudbuild.yaml",
    "**/cloudbuild.yml",
    "**/buildspec.yml",
    "**/codemagic.yaml",
    "**/bitrise.yml",
    "**/.tekton/**",
    "**/.github/dependabot.yml",
    "**/renovate.json",
    "**/.renovaterc*",
  ].map((pattern) => ({ pattern, tag: "ci" as const })),
  // Git hooks and hook managers. (.gitattributes is judged by content: src/engine/autorun.ts.)
  // F7: a submodule's git directory (.git/modules/<name>/...) and linked worktrees' config are git directories too.
  ...["**/.git/hooks/**", "**/.git/config", "**/.git/config.worktree", "**/.git/modules/**/hooks/**", "**/.git/modules/**/config", "**/.git/modules/**/config.worktree", "**/.git/modules/**/info/attributes", "**/.git/worktrees/*/config", "**/.git/worktrees/*/config.worktree", "**/.git/info/attributes", "**/.gitmodules", "**/.husky/**", "**/.githooks/**", "**/lefthook.yml", "**/lefthook-local.yml", "**/.lefthook/**", "**/.pre-commit-config.yaml", "**/.pre-commit-hooks.yaml"].map((pattern) => ({ pattern, tag: "git-hook" as const })),
  // Editor task runners and settings that run programs.
  ...["**/.vscode/tasks.json", "**/.vscode/settings.json", "**/.vscode/launch.json", "**/.vscode/extensions.json", "**/.idea/**", "**/.zed/tasks.json", "**/.zed/settings.json", "**/.fleet/**", "**/*.code-workspace", "**/.nvim.lua", "**/.exrc"].map((pattern) => ({ pattern, tag: "editor-task" as const })),
  // Dev containers and cloud development environments. (flake.nix and shell.nix: only a shellHook change, by content.)
  ...["**/.devcontainer/**", "**/.devcontainer.json", "**/devbox.json", "**/.gitpod.yml", "**/.replit", "**/replit.nix"].map((pattern) => ({ pattern, tag: "devcontainer" as const })),
  // Environment hooks and package-manager settings that run code (.tool-versions and .nvmrc only pin versions).
  ...["**/.envrc", "**/.mise.toml", "**/mise.toml", "**/.mise/**", "**/.npmrc", "**/.yarnrc", "**/.yarnrc.yml", "**/.pnpmfile.cjs"].map((pattern) => ({ pattern, tag: "env-hook" as const })),
  // The home directory and the system: shell start-up, schedulers, tools on PATH.
  ...[
    "~/.bashrc",
    "~/.bash_profile",
    "~/.bash_login",
    "~/.bash_logout",
    "~/.profile",
    "~/.zshrc",
    "~/.zprofile",
    "~/.zshenv",
    "~/.zlogin",
    "~/.zlogout",
    "~/.config/fish/**",
    "~/.ssh/**",
    "~/.gitconfig",
    "~/.config/git/**",
    "~/.local/bin/**",
    "~/bin/**",
    "~/.tmux.conf",
    "~/.config/pip/**",
    "~/.pip/**",
    "~/.cargo/config",
    "~/.cargo/config.toml",
    "~/Library/LaunchAgents/**",
    "~/.config/autostart/**",
    "~/.config/systemd/**",
    "/Library/LaunchAgents/**",
    "/Library/LaunchDaemons/**",
    "/etc/**",
    "/private/etc/**",
    "/usr/local/bin/**",
    "/opt/homebrew/bin/**",
    "/var/spool/cron/**",
    "/var/at/tabs/**",
    // Browser native messaging host manifests (the firewall's own browser link is one): a manifest names a
    // program the browser starts for an extension, and an edited one could hand the link to another program.
    "**/NativeMessagingHosts/**",
  ].map((pattern) => ({ pattern })),
  // Vim start-up files: the user's own, and a project-local one (read when exrc is on).
  { pattern: "~/.vimrc", tag: "editor-task" },
  { pattern: "~/.config/nvim/**", tag: "editor-task" },
  { pattern: "**/.vimrc", tag: "editor-task" },
];

/** The persistence patterns alone (the original list, completed with the tagged ones). */
export const PERSISTENCE_PATTERNS: readonly string[] = PERSISTENCE_TAGGED.map((p) => p.pattern);

/** Secret files: readable inside the workspace (the session becomes sensitive), never outside it. */
export const SECRET_PATTERNS: readonly string[] = [
  "**/.env",
  "**/.env.*",
  "**/*.env",
  "**/.dev.vars",
  "**/*.pem",
  "**/*.key",
  "**/*.p12",
  "**/*.pfx",
  "**/*.jks",
  "**/*.keystore",
  "**/*.kdbx",
  "**/id_rsa",
  "**/id_rsa_*",
  "**/id_dsa",
  "**/id_ecdsa",
  "**/id_ecdsa_*",
  "**/id_ed25519",
  "**/id_ed25519_*",
  // Key backups and variants (the public halves, *.pub, are SECRET_EXCEPTIONS).
  "**/id_rsa.*",
  "**/id_dsa.*",
  "**/id_ecdsa.*",
  "**/id_ed25519.*",
  "**/*.p8",
  "**/*.ppk",
  "**/.pgpass",
  "**/.dockercfg",
  "**/.docker/config.json",
  "**/application_default_credentials.json",
  "**/service_account*.json",
  "**/*.tfvars.json",
  "**/.npmrc",
  "**/.pypirc",
  "**/.netrc",
  "**/_netrc",
  "**/.git-credentials",
  "**/.htpasswd",
  "**/.vault-token",
  "**/credentials",
  "**/credentials.json",
  "**/credentials.yml",
  "**/*service-account*.json",
  "**/*serviceAccount*.json",
  "**/*.tfstate",
  "**/*.tfstate.backup",
  "**/*.tfvars",
  "**/secrets.yml",
  "**/secrets.yaml",
  "**/secrets.json",
  "**/.secrets",
  "**/.secrets/**",
  "**/kubeconfig",
  "**/.kube/config",
];

/** Secret-looking names that are documentation, not secrets. */
export const SECRET_EXCEPTIONS: readonly string[] = [
  "**/.env.example",
  "**/.env.sample",
  "**/.env.template",
  "**/.env.dist",
  "**/.env.schema",
  "**/*.example.env",
  "**/*.pub",
];

/** Home-relative stores that other users' homes (/root, /home/<user>, /Users/<user>) hold the same way. */
const OTHER_HOMES: readonly string[] = ["/root", "/home/*", "/Users/*"];
const OTHER_HOME_STORES: readonly string[] = [
  ".ssh/**",
  ".aws/**",
  ".config/gcloud/**",
  ".azure/**",
  ".kube/**",
  ".docker/config.json",
  ".gnupg/**",
  ".config/gh/**",
  ".netrc",
  ".git-credentials",
  ".pgpass",
  ".npmrc",
  ".pypirc",
  ".vault-token",
  ".password-store/**",
  ".claude/.credentials.json",
  ".codex/auth.json",
  ".gemini/oauth_creds.json",
];
const otherHomes = (stores: readonly string[]): string[] => OTHER_HOMES.flatMap((h) => stores.map((s) => `${h}/${s}`));

/** Where a machine keeps credentials in bulk. Never read by an agent. */
export const CREDENTIAL_STORE_PATTERNS: readonly string[] = [
  "~/.ssh/**",
  "~/.aws/**",
  "~/.config/gcloud/**",
  "~/.azure/**",
  "~/.kube/**",
  "~/.docker/config.json",
  "~/.gnupg/**",
  "~/.config/gh/**",
  "~/.config/hub",
  "~/.netrc",
  "~/_netrc",
  "~/.git-credentials",
  "~/.config/git/credentials",
  "~/.pgpass",
  "~/.my.cnf",
  "~/.mylogin.cnf",
  "~/.boto",
  "~/.s3cfg",
  "~/.config/rclone/rclone.conf",
  "~/.terraformrc",
  "~/.config/configstore/firebase-tools.json",
  "~/.config/doctl/**",
  "~/.config/hcloud/**",
  "~/.config/stripe/**",
  "~/.config/netlify/**",
  "~/.config/ngrok/**",
  "~/.ngrok2/**",
  "~/.wrangler/config/**",
  "~/.config/.wrangler/config/**",
  "~/Library/Preferences/.wrangler/config/**",
  "~/.config/composer/auth.json",
  "~/.composer/auth.json",
  "~/.nuget/NuGet/NuGet.Config",
  "~/.config/NuGet/NuGet.Config",
  "~/.sentryclirc",
  "~/.cache/huggingface/token",
  "~/.huggingface/token",
  "~/.config/github-copilot/**",
  "~/.codex/auth.json",
  "~/.gemini/oauth_creds.json",
  "~/.npmrc",
  "~/.yarnrc.yml",
  "~/.pypirc",
  "~/.password-store/**",
  "~/Library/Keychains/**",
  // Linux: the desktop secret stores (GNOME Keyring, KDE Wallet), the machine's SSH host keys, the secrets a
  // container or an orchestrator mounts as files (/var/run is /run), and the Docker socket (a program that can
  // write to it is root on the host).
  "~/.local/share/keyrings/**",
  "~/.local/share/kwalletd/**",
  "/etc/ssh/ssh_host_*_key",
  "/run/secrets/**",
  "/var/run/secrets/**",
  "/var/run/docker.sock",
  "/run/docker.sock",
  "~/.claude/.credentials.json",
  "~/.config/op/**",
  "~/.vault-token",
  "~/.cargo/credentials",
  "~/.cargo/credentials.toml",
  "~/.gem/credentials",
  "~/.m2/settings.xml",
  "~/.m2/settings-security.xml",
  "~/.gradle/gradle.properties",
  "~/.terraform.d/credentials.tfrc.json",
  "~/.fly/**",
  "~/.supabase/**",
  "~/.railway/**",
  "~/.config/heroku/**",
  "~/.netlify/**",
  "~/Library/Application Support/com.vercel.cli/**",
  "~/.local/share/com.vercel.cli/**",
  "~/.config/solana/**",
  "~/.bitcoin/**",
  "~/.ethereum/**",
  "~/.electrum/**",
  "~/.foundry/keystores/**",
  "~/Library/Application Support/Exodus/**",
  "~/Library/Application Support/Electrum/**",
  "~/Library/Application Support/Google/Chrome/**",
  "~/Library/Application Support/BraveSoftware/**",
  "~/Library/Application Support/Microsoft Edge/**",
  "~/Library/Application Support/Firefox/**",
  "~/Library/Application Support/Arc/**",
  "~/Library/Application Support/Vivaldi/**",
  "~/Library/Application Support/com.operasoftware.Opera/**",
  "~/Library/Application Support/Chromium/**",
  "~/Library/Safari/**",
  "~/Library/Containers/com.apple.Safari/Data/Library/Cookies/**",
  "~/.mozilla/**",
  "~/snap/firefox/common/.mozilla/**",
  "~/.var/app/org.mozilla.firefox/**",
  "~/.config/google-chrome/**",
  "~/.config/chromium/**",
  "~/.config/BraveSoftware/**",
  "~/.config/microsoft-edge/**",
  "~/.config/vivaldi/**",
  "~/.config/opera/**",
  "~/snap/chromium/common/chromium/**",
  "~/Library/Cookies/**",
  "~/Library/Messages/**",
  "~/Library/Mail/**",
  "~/.bash_history",
  "~/.zsh_history",
  "~/.*_history",
  "~/.local/share/fish/fish_history",
  // More stores under the home, and the same stores under another user's home (a program running as root reads them).
  "~/.dockercfg",
  "~/.databrickscfg",
  "~/.oci/**",
  "~/.config/glab-cli/**",
  "~/.pulumi/credentials.json",
  "~/.config/pulumi/**",
  "~/.config/sops/age/keys.txt",
  "~/.bundle/config",
  "~/.config/pypoetry/auth.toml",
  "~/.local/share/opencode/auth.json",
  "~/Library/Application Support/Slack/**",
  "~/Library/Application Support/discord/**",
  "~/Library/Application Support/Signal/**",
  "~/Library/Application Support/Telegram Desktop/**",
  "~/.config/Slack/**",
  "~/.config/discord/**",
  "~/.config/Signal/**",
  "~/.local/share/TelegramDesktop/**",
  ...otherHomes(OTHER_HOME_STORES),
  "/etc/shadow",
  "/etc/master.passwd",
  "/etc/sudoers",
  "/proc/*/environ",
  "/proc/self/**",
];

export const CREDENTIAL_STORE_EXCEPTIONS: readonly string[] = ["~/.ssh/*.pub", "~/.ssh/known_hosts", ...otherHomes([".ssh/*.pub", ".ssh/known_hosts"])];

/** Third-party code and caches inside or near the workspace: an outsider wrote it. */
export const UNTRUSTED_PATTERNS: readonly string[] = [
  // Where a browser or another agent drops files from the internet. Installed
  // dependencies (node_modules, vendor, .venv) are NOT here: you installed them,
  // and reading a dependency's source is ordinary work. Turn on untrustedWorkspace
  // to treat a whole checkout you are only reviewing as outside content.
  "~/Downloads/**",
];

/** The firewall's own managed config locations. Its data and runtime come from Context (F-c identity). */
export { FIREWALL_MANAGED_DIRS };

/** Base names that matter when a write target is a glob like `rm *` or `cp x ./*`. */
const SENSITIVE_BASENAMES = [
  "CLAUDE.md",
  "CLAUDE.local.md",
  "AGENTS.md",
  "MEMORY.md",
  "GEMINI.md",
  ".claude",
  ".mcp.json",
  ".cursor",
  ".cursorrules",
  ".windsurfrules",
  ".clinerules",
  ".github",
  ".vscode",
  ".git",
  ".husky",
  ".envrc",
  ".env",
  ".npmrc",
  ".bashrc",
  ".zshrc",
  ".profile",
  ".ssh",
  ".aws",
  ".gitconfig",
  ".zprofile",
  ".zshenv",
  ".zlogin",
  ".bash_profile",
  ".bash_login",
  ".gitmodules",
  ".codex",
  ".gemini",
  ".windsurf",
  ".kiro",
  ".continue",
  ".roo",
  ".roomodes",
  ".junie",
  ".opencode",
  ".amazonq",
  ".aider.conf.yml",
  "opencode.json",
  ".yarnrc",
  ".pre-commit-config.yaml",
  ".netrc",
  ".pgpass",
];

// --- resolution ------------------------------------------------------------------------------------

/** F-f: the working directory after a cd the firewall cannot follow. Relative paths under it are inexact. */
export const UNKNOWN_ROOT = "/__unknown_cwd__";
/** Deep enough that "../" in a relative path stays under UNKNOWN_ROOT. */
export const UNKNOWN_CWD = `${UNKNOWN_ROOT}/_/_/_/_/_/_/_/_`;

export function underUnknownCwd(abs: string): boolean {
  return abs === UNKNOWN_ROOT || abs.startsWith(`${UNKNOWN_ROOT}/`);
}

export interface ResolvedPath {
  /** Absolute, normalized. May still contain glob characters when `glob` is true. */
  abs: string;
  /** True when every part was known statically (no variables, no command substitution). */
  exact: boolean;
  /** True when the last segment (only) holds glob characters. */
  glob: boolean;
  /**
   * SELF-016: the absolute path before ".." was folded, when it has a ".." after a name. A program
   * resolves `link/..` physically (the parent of where link points), not lexically.
   */
  physical?: string;
}

const EXPANSION = /[$`]/;
const GLOB_CHARS = /[*?[{]/;

/**
 * Resolves what an agent wrote to an absolute path. Returns null only for an
 * empty string. A path with a variable or substitution the firewall cannot
 * know comes back with exact=false; callers treat that conservatively.
 */
export function resolvePath(raw: string, ctx: Pick<Context, "cwd" | "home">): ResolvedPath | null {
  let p = raw.trim();
  if (p === "") return null;
  if (/^file:\/\//i.test(p)) {
    try {
      p = decodeURIComponent(new URL(p).pathname);
    } catch {
      return { abs: normalizeAbs(`${ctx.cwd}/${p}`), exact: false, glob: false };
    }
  }
  let exact = true;
  // Known variables at the start.
  const home = /^(?:\$HOME|\$\{HOME\})(?=\/|$)/;
  const pwd = /^(?:\$PWD|\$\{PWD\})(?=\/|$)/;
  if (home.test(p)) p = p.replace(home, ctx.home);
  else if (pwd.test(p)) p = p.replace(pwd, ctx.cwd);
  if (p === "~" || p.startsWith("~/")) p = ctx.home + p.slice(1);
  else if (/^~[+-](?:\/|$)/.test(p)) {
    // `~+` is $PWD. `~-` is $OLDPWD, which the firewall does not track: an unknown directory, so inexact.
    if (p[1] === "-") exact = false;
    p = (p[1] === "-" ? UNKNOWN_CWD : ctx.cwd) + p.slice(2);
  } else if (/^~[A-Za-z0-9._-]+(?:\/|$)/.test(p)) {
    // Another user's home: assume the usual layout, and say the guess is a guess.
    const slash = p.indexOf("/");
    const user = slash === -1 ? p.slice(1) : p.slice(1, slash);
    const rest = slash === -1 ? "" : p.slice(slash);
    p = `${parentDir(ctx.home)}/${user}${rest}`;
    exact = false;
  }
  if (EXPANSION.test(p)) exact = false;
  if (!p.startsWith("/") && underUnknownCwd(ctx.cwd)) exact = false;
  const joined = p.startsWith("/") ? p : `${ctx.cwd}/${p}`;
  const abs = normalizeAbs(joined);
  const segs = abs.split("/");
  const last = segs[segs.length - 1] ?? "";
  const globInLast = GLOB_CHARS.test(last);
  const globEarlier = segs.slice(0, -1).some((s) => GLOB_CHARS.test(s));
  if (globEarlier) exact = false;
  const out: ResolvedPath = { abs, exact, glob: globInLast && !globEarlier };
  if (/\/\.\.(?:\/|$)/.test(joined)) out.physical = `/${joined.split("/").filter((x) => x !== "" && x !== ".").join("/")}`;
  return out;
}

function parentDir(p: string): string {
  const i = p.lastIndexOf("/");
  return i <= 0 ? "/" : p.slice(0, i);
}

/**
 * Whether `path` is `root` or inside it. `ci` folds case: a comparison that grants trust (the workspace, scratch)
 * passes the platform's rule (Context.caseInsensitive); one that refuses or asks (a protected root, the
 * firewall's directory) passes PROTECTION_FOLDS_CASE (I1, canonical.ts).
 */
export function isUnder(path: string, root: string, ci: boolean): boolean {
  const a = ci ? path.toLowerCase() : path;
  const r = (ci ? root.toLowerCase() : root).replace(/\/+$/, "");
  if (r === "") return true;
  return a === r || a.startsWith(`${r}/`);
}

// --- classification --------------------------------------------------------------------------------

export type Zone = "workspace" | "scratch" | "outside";

export interface PathInfo {
  abs: string;
  zone: Zone;
  firewall: boolean;
  protected: boolean;
  memory: boolean;
  persistence: boolean;
  /** What kind of persistence point (absent for untagged ones and for non-persistence paths). */
  persistTag?: PersistTag;
  secret: boolean;
  credentialStore: boolean;
  untrusted: boolean;
  trustedRead: boolean;
  /** SELF-016: the path could not be resolved (a symlink loop, no permission), so it is treated as protected. */
  unresolved?: boolean;
  /** I2: inside the firewall's data directory: "key" for its keys, vault and signing material, "data" for the rest. */
  firewallData?: "key" | "data";
  /**
   * I7: a glob in the path that could name a credential store when no candidate is one (`/etc/ssh/ssh_host_*` names
   * the host's private keys). Reading what it matches reads the store; a listing shows only the names.
   */
  globNamesStore?: boolean;
}

/** Expanded patterns, per resolver (a context's lifetime): the canonical prefixes cost a realpath each the first time. */
const expandCache = new WeakMap<(absPath: string) => string, Map<string, string[]>>();

function expand(pattern: string, ctx: Context): string[] {
  if (pattern.startsWith("**/") || /^[A-Za-z]:\//.test(pattern)) return [pattern];
  let base: string;
  if (pattern.startsWith("~/")) base = ctx.home + pattern.slice(1);
  else if (pattern.startsWith("/")) base = pattern;
  // Relative patterns are relative to each workspace root (the runtime lists each root in both forms).
  else return ctx.workspaceRoots.map((r) => `${r.replace(/\/+$/, "")}/${pattern}`);
  const rp = ctx.realpath;
  if (rp === undefined) return [base];
  let m = expandCache.get(rp);
  if (m === undefined) {
    m = new Map();
    expandCache.set(rp, m);
  }
  const hit = m.get(base);
  if (hit !== undefined) return hit;
  // SELF-016: also the pattern with its literal prefix canonical (~ through a symlinked home, /etc as /private/etc).
  const segs = base.split("/");
  const firstGlob = segs.findIndex((x) => GLOB_CHARS.test(x));
  const prefix = segs.slice(0, firstGlob === -1 ? segs.length : firstGlob).join("/") || "/";
  const canon = canonicalOf(prefix, ctx);
  const out = canon === null || canon === prefix ? [base] : [base, `${canon === "/" ? "" : canon}${base.slice(prefix === "/" ? 0 : prefix.length)}`];
  if (m.size >= 4096) m.clear();
  m.set(base, out);
  return out;
}

/**
 * Whether the path matches one of the firewall's lists of places (protected, persistence, secret, ...). `fold`
 * ignores case: PROTECTION_FOLDS_CASE (I1) in classifyPath, the platform's rule in classifyAsSpelled.
 */
function anyMatch(patterns: readonly string[], abs: string, ctx: Context, fold: boolean): boolean {
  for (const p of patterns) {
    for (const e of expand(p, ctx)) {
      if (globMatch(e, abs, fold)) return true;
    }
  }
  return false;
}

// --- where the credential stores are, segment by segment (I7) ---------------------------------------
// A glob an agent writes (`/etc/ssh/ssh_host_*`, `grep -r x /etc/ss*`) and a directory it reads recursively are
// compared with the stores' places one path segment at a time, so a store that is a file or a name pattern in an
// ordinary directory, and the directories that hold one (containsCredentialStores), are seen as well as the store
// directories (~/.ssh).

/**
 * A path or a store's place by segment: as written, lower-cased, whether each holds glob characters, and each as the
 * glob matcher should read it (matcherGlob).
 */
interface Segments {
  raw: string[];
  low: string[];
  glob: boolean[];
  pat: string[];
}

function segmentsOf(abs: string): Segments {
  // "**/**" names what "**" names: a run is one segment, so a path cannot spend the one exact reading of a "**" on it.
  const raw = abs.split("/").filter((s, i, all) => s !== "" && !(s === "**" && all[i - 1] === "**"));
  const glob = raw.map((s) => GLOB_CHARS.test(s));
  return { raw, low: raw.map((s) => s.toLowerCase()), glob, pat: raw.map((s, i) => (glob[i] === true ? matcherGlob(s) : s)) };
}

/**
 * A segment the agent wrote, as the glob matcher should read it. The matcher takes "[" literally, but in the shell a
 * bracket expression ([er], [!a-z], [[:alpha:]]) stands for one character: everything from the first "[" to the last
 * "]" after it is read as "*", a little wider than the shell, and found in one pass however many brackets the segment
 * holds (FZ1: an attacker shapes it).
 */
function matcherGlob(seg: string): string {
  const open = seg.indexOf("[");
  const close = seg.lastIndexOf("]");
  return open !== -1 && close > open ? `${seg.slice(0, open)}*${seg.slice(close + 1)}` : seg;
}

/** Where a path's segment (as the matcher reads it) or a store's is a glob: whether some name matches both. */
function globSegmentMayName(seg: string, segGlob: boolean, place: string, placeGlob: boolean, ci: boolean): boolean {
  if (!segGlob) return globMatch(place, seg, ci);
  return placeGlob ? globsOverlap(seg, place, ci) : globMatch(seg, place, ci);
}

/**
 * Whether a path (any of its segments a glob) can name what `place` names: segment by segment, equal (ignoring case
 * with `ci`) or, where either is a glob, matching some name both match. A "**" as the place's last segment stands for
 * anything below the directory before it. A "**" segment in the path stands for any number of directories (zsh, and
 * bash with globstar): the first one is tried at every depth of the place, and any later one is read the stricter
 * way, as anything below what matched so far, so the work stays within the place's length squared. With `above`, a
 * directory above the place counts too.
 */
function mayName(path: Segments, place: Segments, above: boolean, ci: boolean, from = 0, at = 0, exactStar = true): boolean {
  const n = place.raw.length;
  const m = path.raw.length;
  let j = at;
  for (let i = from; i < m; i++, j++) {
    if (path.raw[i] === "**") {
      if (!exactStar) return true;
      for (let k = j; k <= n; k++) if (mayName(path, place, above, ci, i + 1, k, false)) return true;
      return false;
    }
    // The path goes on below a place that is a file.
    if (j >= n) return false;
    const p = place.raw[j] as string;
    // The path names something below the place's directory. (A "**" before the place's last segment is read the
    // stricter way too: anything below what matched so far.)
    if (p === "**") return true;
    const pg = path.glob[i] === true;
    const qg = place.glob[j] === true;
    const same = pg || qg ? globSegmentMayName(path.pat[i] as string, pg, p, qg, ci) : ci ? path.low[i] === place.low[j] : path.raw[i] === p;
    if (!same) return false;
  }
  if (j >= n) return true;
  // The path ends at a directory on the way to the place.
  return above || (place.raw[j] === "**" && j < n - 1);
}

interface StorePlaces {
  home: string;
  realpath: Context["realpath"];
  /** Every credential store pattern from a fixed place (~/ or /), as written and canonical, by segment. */
  stores: Segments[];
  /** The directories a recursive read of which reads stores, and whether a directory above one counts too. */
  holders: { segs: Segments; above: boolean }[];
}

/** The last context's store places (one context per hook process; tests reuse a home). */
let placesCache: StorePlaces | null = null;

function storePlaces(ctx: Context): StorePlaces {
  if (placesCache !== null && placesCache.home === ctx.home && placesCache.realpath === ctx.realpath) return placesCache;
  const holders: StorePlaces["holders"] = [
    // The home directory and everything above it, and the directories under it that hold many stores.
    { segs: segmentsOf(ctx.home), above: true },
    ...["Library", ".config", "Library/Application Support", ".local/share"].map((s) => ({ segs: segmentsOf(`${ctx.home}/${s}`), above: false })),
  ];
  const stores: Segments[] = [];
  for (const p of CREDENTIAL_STORE_PATTERNS) {
    for (const e of expand(p, ctx)) {
      // A "**/" pattern names no place to compare with (the list has none).
      if (!e.startsWith("/")) continue;
      stores.push(segmentsOf(e));
      const dir = e.endsWith("/**") ? e.slice(0, -3) : null;
      // A store directory itself (~/.aws, /run/secrets), and a store outside the home with every directory above it
      // (/etc/ssh and /etc for the host's keys, /run and /var/run for the Docker socket). Above a store in the home
      // only the directories listed before count: the parents of the others (~/.cargo, ~/.claude) are searched in
      // ordinary work.
      if (p.startsWith("/")) holders.push({ segs: segmentsOf(dir ?? e), above: true });
      else if (dir !== null) holders.push({ segs: segmentsOf(dir), above: false });
    }
  }
  placesCache = { home: ctx.home, realpath: ctx.realpath, stores, holders };
  return placesCache;
}

/**
 * Whether a recursive read of a directory reads credential stores: the home directory or one above it; ~/.config,
 * ~/Library, ~/Library/Application Support and ~/.local/share, which hold many; a store directory itself (~/.ssh,
 * /run/secrets); and any directory above a store outside the home (/etc/ssh and /etc for the host's SSH keys, /run
 * and /var/run for mounted secrets and the Docker socket, /proc). A glob in the path counts for every directory it
 * could name (`/etc/ss*`, `~/.a*`). `ci` folds case: I1, a place that holds credentials is the same place whatever
 * its case (PROTECTION_FOLDS_CASE, canonical.ts); a read judged by the platform's own rule (readOne) passes
 * Context.caseInsensitive.
 */
export function containsCredentialStores(abs: string, ctx: Context, ci: boolean = PROTECTION_FOLDS_CASE): boolean {
  const segs = segmentsOf(abs);
  return storePlaces(ctx).holders.some((h) => mayName(segs, h.segs, h.above, ci));
}

/**
 * I7: whether a path with a glob in it (in the last segment or before it) could name a credential store, its case
 * folded with `fold` (as the lists are in classifyWith). The store's exceptions are not subtracted: a glob that could
 * name a key reads it, whatever else it names.
 */
function globNamesStore(abs: string, ctx: Context, fold: boolean): boolean {
  const segs = segmentsOf(abs);
  return storePlaces(ctx).stores.some((s) => mayName(segs, s, false, fold));
}

function classifyOne(abs: string, ctx: Context, cfg: FirewallConfig, fold: boolean): PathInfo {
  const ci = ctx.caseInsensitive;
  const inWorkspace = ctx.workspaceRoots.some((r) => isUnder(abs, r, ci));
  const inScratch = !inWorkspace && ctx.scratchRoots.some((r) => isUnder(abs, r, ci));
  // F-c: the firewall is what is installed (its runtime, CLI, node binary and data), not any file
  // whose name or folder looks like it. A source checkout's src/, docs/, test/ and .git/ are ordinary.
  const firewall = firewallPart(abs, ctx, fold) !== null;
  const memory = anyMatch(MEMORY_PATTERNS, abs, ctx, fold);
  const isProtected = memory || anyMatch(PROTECTED_PATTERNS, abs, ctx, fold) || anyMatch(cfg.protectedPaths, abs, ctx, fold);
  const credentialStore = anyMatch(CREDENTIAL_STORE_PATTERNS, abs, ctx, fold) && !anyMatch(CREDENTIAL_STORE_EXCEPTIONS, abs, ctx, fold);
  const secretShape = (anyMatch(SECRET_PATTERNS, abs, ctx, fold) || anyMatch(cfg.secretPaths, abs, ctx, fold)) && !anyMatch(SECRET_EXCEPTIONS, abs, ctx, fold);
  const persistHit = PERSISTENCE_TAGGED.find((p) => anyMatch([p.pattern], abs, ctx, fold));
  const persistence = persistHit !== undefined;
  const untrusted = cfg.untrustedWorkspace && inWorkspace ? true : anyMatch(UNTRUSTED_PATTERNS, abs, ctx, fold) || anyMatch(cfg.untrustedPaths, abs, ctx, fold);
  const trustedRead = cfg.trustedReadRoots.some((r) => isUnder(abs, expand(r, ctx)[0] ?? r, ci));
  const fwData = firewallDataKind(abs, ctx, fold);
  return {
    ...(fwData !== null ? { firewallData: fwData } : {}),
    abs,
    zone: inWorkspace ? "workspace" : inScratch ? "scratch" : "outside",
    firewall,
    protected: isProtected,
    memory,
    persistence,
    ...(persistHit?.tag !== undefined ? { persistTag: persistHit.tag } : {}),
    // A secret file outside the workspace is someone else's secret: treat it as a credential store.
    secret: secretShape,
    credentialStore: credentialStore || (secretShape && !inWorkspace && !inScratch),
    untrusted,
    trustedRead,
  };
}

const ZONE_RANK: Record<Zone, number> = { workspace: 0, scratch: 1, outside: 2 };

function worst(a: PathInfo, b: PathInfo): PathInfo {
  const fwData = a.firewallData === "key" || b.firewallData === "key" ? "key" : (a.firewallData ?? b.firewallData);
  return {
    ...(fwData !== undefined ? { firewallData: fwData } : {}),
    abs: a.abs,
    zone: ZONE_RANK[a.zone] >= ZONE_RANK[b.zone] ? a.zone : b.zone,
    firewall: a.firewall || b.firewall,
    protected: a.protected || b.protected,
    // Memory is a relaxation of protected; only keep it when both views agree.
    memory: a.memory && b.memory,
    persistence: a.persistence || b.persistence,
    ...((a.persistTag ?? b.persistTag) !== undefined ? { persistTag: (a.persistTag ?? b.persistTag) as PersistTag } : {}),
    secret: a.secret || b.secret,
    credentialStore: a.credentialStore || b.credentialStore,
    untrusted: a.untrusted || b.untrusted,
    trustedRead: a.trustedRead && b.trustedRead,
  };
}

/** Longer than PATH_MAX on Linux (4096) and macOS (1024): no system call takes such a path. */
export const MAX_PATH_CHARS = 4096;

/**
 * Classifies an absolute path, looking at both the path as written and where
 * its symlinks lead, and keeping the more dangerous answer for every flag.
 * A glob in the last segment is checked against every sensitive base name it
 * could match, so `rm *` at the root counts as touching CLAUDE.md, and a glob
 * anywhere in the path against the credential stores' places (globNamesStore).
 * The lists are matched ignoring case (I1, PROTECTION_FOLDS_CASE).
 */
export function classifyPath(resolved: ResolvedPath, ctx: Context, cfg: FirewallConfig): PathInfo {
  return classifyWith(resolved, ctx, cfg, PROTECTION_FOLDS_CASE);
}

/**
 * I1: the path classified with every list matched by the platform's own case rule (Context.caseInsensitive), as
 * the lists were matched before they folded case. Only for a decision that grants trust because of a match: a read
 * outside the workspace of the agent's own settings, a credential store or the firewall's own files is not outside
 * content, and on a case-sensitive disk a name that only folds to one of those is another file, which may be
 * someone else's. Everything that refuses or asks uses classifyPath, so folding case only ever adds a question.
 */
export function classifyAsSpelled(resolved: ResolvedPath, ctx: Context, cfg: FirewallConfig): PathInfo {
  return classifyWith(resolved, ctx, cfg, ctx.caseInsensitive);
}

/** classifyPath with the lists matched ignoring case (`fold`) or not. */
function classifyWith(resolved: ResolvedPath, ctx: Context, cfg: FirewallConfig, fold: boolean): PathInfo {
  // FZ1: a path longer than any system accepts (PATH_MAX) is not matched against every pattern: it fails closed,
  // as a protected, secret path the firewall cannot resolve.
  if (resolved.abs.length > MAX_PATH_CHARS) {
    const head = classifyOne(resolved.abs.slice(0, MAX_PATH_CHARS), ctx, cfg, fold);
    return { ...head, abs: resolved.abs, protected: true, secret: true, memory: false, unresolved: true };
  }
  const candidates: string[] = [];
  let known = true;
  let namesStore = false;
  if (resolved.glob) {
    // SELF-016: the directory is literal (only the last segment globs), so it is resolved like any path.
    const dir = parentDir(resolved.abs);
    const lastGlob = resolved.abs.slice(dir.length + 1);
    const sensitiveGlob = matcherGlob(lastGlob);
    const dirs = pathForms(dir, ctx);
    known = dirs.known;
    for (const d of dirs.paths) {
      const at = d === "/" ? "" : d;
      candidates.push(`${at}/__any__`);
      for (const name of SENSITIVE_BASENAMES) {
        // A bracket expression (CLAUDE.m[d]) is one character in the shell, but the matcher takes "[" literally.
        if (globMatch(sensitiveGlob, name, fold)) candidates.push(`${at}/${name}`);
      }
      // I7: `__any__` finds a store directory (~/.ssh/*); a store that is a file or a name pattern in an ordinary
      // directory (/etc/ssh/ssh_host_*_key, ~/.netrc) is found by comparing the glob with its name.
      if (!namesStore) namesStore = globNamesStore(`${at}/${lastGlob}`, ctx, fold);
    }
  } else {
    const forms = pathForms(resolved.abs, ctx, resolved.physical);
    known = forms.known;
    candidates.push(...forms.paths);
    // I7: a glob before the last segment (`/etc/ss*/ssh_host_rsa_key`, `/etc/**/ssh_host_rsa_key`) is not matched by
    // the patterns, which read it as a literal name: it is compared with the stores' places segment by segment.
    if (GLOB_CHARS.test(resolved.abs)) namesStore = forms.paths.some((f) => globNamesStore(f, ctx, fold));
  }
  let info: PathInfo | null = null;
  for (const c of candidates) {
    const one = classifyOne(c, ctx, cfg, fold);
    info = info === null ? one : worst(info, one);
  }
  const out: PathInfo = { ...(info as PathInfo), abs: resolved.abs };
  if (namesStore && !out.credentialStore) out.globNamesStore = true;
  // SELF-016: a path that cannot be resolved may be any protected location: fail closed.
  return known ? out : { ...out, protected: true, memory: false, unresolved: true };
}
