/**
 * `run`: the sandbox profile, pure (no I/O). One plan (where the
 * command may write, what stays read-only, what is unreadable, the proxy's
 * port) becomes a Seatbelt profile for macOS `sandbox-exec` or a bubblewrap
 * argument list for Linux. docs/run.md explains each rule.
 */

import { basename, dirname } from "node:path";
import { isUnder } from "./paths.js";
import { own } from "../own.js";

export interface RunPlan {
  platform: "darwin" | "linux";
  /** The workspace (real path). */
  workspace: string;
  /** The run's private temporary directory (real path); TMPDIR points at it. */
  runTmp: string;
  /** Writable directories: workspace, runTmp and the person's --allow-write entries (real paths). */
  writable: string[];
  /** Always read-only, even inside a writable directory (real paths; need not exist on macOS). */
  readOnly: string[];
  /** Unreadable (real paths): the firewall's keys and vault, credential stores. */
  unreadable: string[];
  /** Directories where Unix sockets may be bound and connected to (workspace, runTmp). */
  socketDirs: string[];
  /** The proxy's port on 127.0.0.1 (inside the sandbox on Linux). */
  proxyPort: number;
  /** macOS: may connect to any 127.0.0.1 port (Linux has its own loopback). */
  allowLocalhost: boolean;
  /** macOS: may use the keychain. */
  allowKeychain: boolean;
}

/**
 * Files in a workspace that program an agent, git or the firewall, or start programs later outside the
 * sandbox: read-only inside it. Git: hooks, the config (core.hooksPath, core.fsmonitor, filters and `!`
 * aliases run programs, V4), `commondir` (git takes the config and the hooks from the directory it names,
 * so `../evil` there is a new config), submodules' and linked worktrees' git directories (their own hooks,
 * config and pointer files) and husky's hooks directory. Agents: settings with hooks, MCP server lists, editor
 * tasks and settings (V18; settings name interpreters and shells the editor starts), Claude Code's skills,
 * subagents and commands, which can declare hooks too (RN7), its `.claude/hooks` directory (the canonical home
 * of hook scripts, protected before any exists, FA2), and dev containers (`initializeCommand` runs
 * on the host, RN8). Also the hook managers' configuration (pre-commit, lefthook: they install and run git hooks), mise's
 * (`mise.toml` has tasks and env hooks), the editors' launch and project settings (`.vscode/launch.json`, `.idea/`) and,
 * through listing the directory (run.ts, workspaceGlobs), the `*.code-workspace` files that exist.
 * runtime/run/code-paths.ts adds what the workspace itself names (nested repositories, core.hooksPath,
 * scripts that hooks and MCP servers run).
 */
export const WORKSPACE_PROTECTED: readonly string[] = [".launchsafe-firewall.json", ".git/hooks", ".git/config", ".git/config.worktree", ".git/commondir", ".git/modules", ".git/worktrees", ".husky", ".claude/settings.json", ".claude/settings.local.json", ".codex", ".codex/config.toml", ".codex/hooks.json", ".gemini/settings.json", ".gemini/extensions", ".gemini/commands", ".cursor/hooks.json", ".mcp.json", ".cursor/mcp.json", ".vscode/tasks.json", ".vscode/settings.json", ".claude/skills", ".claude/agents", ".claude/commands", ".claude/hooks", ".devcontainer", ".envrc", ".pre-commit-config.yaml", "lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".lefthook.yaml", "mise.toml", ".mise.toml", ".vscode/launch.json", ".idea"];

/**
 * The directories among WORKSPACE_PROTECTED (protected whole, with everything in them). On Linux a missing one
 * gets an empty read-only mount on itself, even inside an agent configuration directory (which a missing
 * file there binds read-only whole). Claude Code's skills, subagents and commands can declare hooks in
 * their frontmatter (RN7).
 */
export const WORKSPACE_PROTECTED_DIRS: readonly string[] = [".git/hooks", ".git/modules", ".git/worktrees", ".husky", ".codex", ".gemini/extensions", ".gemini/commands", ".claude/skills", ".claude/agents", ".claude/commands", ".claude/hooks", ".devcontainer", ".idea"];

/**
 * Directories inside a workspace that hold only agent configuration. On Linux, when a protected file in
 * one of them does not exist yet, the whole directory is bound read-only (nothing is created in the
 * repository for it).
 */
export const AGENT_CONFIG_DIRS: readonly string[] = [".claude", ".codex", ".gemini", ".cursor", ".vscode"];

/**
 * The directories that lead to a protected path from inside a writable one (the writable root itself
 * included), e.g. `.git` and the workspace for `.git/hooks`. Seatbelt checks the path a write names, so a
 * rename of `.git` (then a write to `.git2/hooks`, then a rename back) or a symlink planted where
 * `.claude` was missing would otherwise get around a rule on `.git/hooks` or `.claude/settings.json`
 * (V3). These directories themselves cannot be created, renamed, removed or replaced; what is inside
 * them stays writable. On Linux a read-only bind of `.git/hooks` does not stop a rename of `.git` (the
 * kernel refuses to rename or remove only a mount point itself, not a directory that holds one), so
 * bwrapArgs makes each existing one a mount point of its own (a writable bind onto itself): rename and
 * rmdir then fail with EBUSY.
 */
export function guardedAncestors(paths: readonly string[], writable: readonly string[], ci: boolean): string[] {
  const out = new Set<string>();
  for (const p of paths) {
    for (let a = dirname(p); a !== dirname(a); a = dirname(a)) if (writable.some((w) => isUnder(a, w, ci))) out.add(a);
  }
  return [...out];
}

/** Credential stores under the home directory: unreadable inside the sandbox, always. */
export const HOME_UNREADABLE: readonly string[] = [".ssh", ".aws", ".gnupg"];

/**
 * More credential stores, unreadable by default; `run --allow-home-read NAME` makes one readable for a run
 * whose command needs it (gh needs .config/gh, npm publish needs .npmrc). Tokens for GitHub, package
 * registries, container registries, Kubernetes and the clouds.
 */
export const HOME_UNREADABLE_OPTIONAL: readonly string[] = [".config/gh", ".netrc", ".npmrc", ".git-credentials", ".docker", ".kube", ".config/gcloud", ".azure"];

/**
 * Linux: Docker Desktop's sockets under the home directory, hidden even when `.docker` is made readable. A
 * Unix socket is reachable from another network namespace and through a read-only mount, and the Docker
 * socket is root on the host. (/var/run/docker.sock and $XDG_RUNTIME_DIR are under /run, which the sandbox
 * replaces with an empty tmpfs; on macOS the profile allows Unix sockets only in the workspace and the
 * run's directory.)
 */
export const LINUX_DOCKER_SOCKET_DIRS: readonly string[] = [".docker/run", ".docker/desktop"];

/**
 * macOS system services that would act for the sandboxed process outside the sandbox: LaunchServices
 * (`open` a URL or an application), the background URL-session daemon (downloads and uploads), the
 * pasteboard. The keychain is added unless --allow-keychain.
 */
export const MACH_DENY_NAMES: readonly string[] = ["com.apple.coreservices.launchservicesd", "com.apple.pasteboard.1"];
export const MACH_DENY_REGEX: readonly string[] = ["^com\\.apple\\.lsd\\.", "^com\\.apple\\.nsurlsessiond"];
export const MACH_KEYCHAIN: readonly string[] = ["com.apple.SecurityServer", "com.apple.securityd"];

/**
 * Name resolution on macOS is a service: getaddrinfo() asks mDNSResponder over Mach, and mDNSResponder sends
 * the DNS query from outside the sandbox, so `(deny network*)` alone leaves DNS (and DNS exfiltration) open.
 * The run's programs need no lookup of their own (the proxy resolves the names it admits; the proxy address
 * is 127.0.0.1), so these are denied. A tool that resolves "localhost" itself fails; use 127.0.0.1.
 * To verify on a Mac (not shown by any test): that these names cover every lookup path (`dscacheutil`, `host`, Node's dns.lookup).
 */
export const MACH_DNS_DENY: readonly string[] = ["com.apple.mDNSResponder", "com.apple.mDNSResponderHelper", "com.apple.dnssd.service"];

/**
 * cfprefsd writes preference files (~/Library/Preferences) for the process that asks, outside the sandbox's
 * file rules. Denied: a program in the run reads its defaults instead (CFPreferences falls back to them).
 * To verify on a Mac: which common tools fail without it.
 */
export const MACH_PREFS_DENY: readonly string[] = ["com.apple.cfprefsd.daemon", "com.apple.cfprefsd.agent"];

/**
 * TIOCSTI (`_IOW('t', 114, char)` = 0x80017472) pushes a character into a terminal's input queue, as if typed.
 * `run` already gives the command a pseudo-terminal of its own when it has a terminal (see ttyWrapNeeded in
 * src/runtime/run/run.ts); this rule is the second wall, for an inherited terminal descriptor.
 * SYNTAX TO VERIFY ON A MAC: `ioctl-command` as a filter of `file-ioctl` with a numeric argument. sandbox-exec
 * refuses a profile it cannot parse, so a wrong form stops every run (fails closed) rather than weakening it.
 */
export const SEATBELT_TIOCSTI_DENY = "(deny file-ioctl (ioctl-command #x80017472))";

/**
 * Hard links: Seatbelt judges a write by the path it names, so a hard link in the workspace to a read-only
 * file (a git hook) or an unreadable one (a key under ~/.ssh) would reach that file under a writable,
 * readable name. All hard-link creation is denied (git, pnpm and the like fall back to copying).
 * TO VERIFY ON A MAC: that `file-link` is the operation link(2) is checked against.
 * On Linux the protected files are bind mounts and link(2) across mounts fails with EXDEV.
 */
export const SEATBELT_HARDLINK_DENY = "(deny file-link)";

/**
 * Other processes: launchd jobs (a job submitted to launchd runs outside the sandbox, and outlives the run),
 * and inspecting or taking over a process outside the sandbox (its arguments, environment, task port).
 * TO VERIFY ON A MAC: `job-creation`, `process-info*` and `mach-priv-task-port` with `(target same-sandbox)`.
 */
export const SEATBELT_PROCESS_RULES: readonly string[] = [
  "(deny job-creation)",
  "(deny process-info*)",
  "(allow process-info* (target same-sandbox))",
  "(deny mach-priv-task-port)",
  "(allow mach-priv-task-port (target same-sandbox))",
];

const SYSTEM_TREES = ["/etc", "/usr", "/bin", "/sbin", "/System", "/Library", "/Applications", "/private/etc", "/boot", "/proc", "/sys", "/dev", "/lib", "/lib32", "/lib64", "/libx32", "/opt/homebrew", "/nix", "/snap"];
const SYSTEM_EXACT = ["/", "/Users", "/home", "/root", "/var", "/private", "/private/var", "/opt", "/Volumes", "/mnt", "/media", "/srv"];
const HOME_EXACT = [".config", ".local", ".local/share", "Library", "Library/Application Support", "Library/Preferences"];
const HOME_TREES = [".ssh", ".aws", ".gnupg", ".kube", ".docker", ".claude", ".codex", ".gemini", ".cursor", ".launchsafe-firewall", ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".bash_login", ".profile", ".gitconfig", ".git-credentials", ".netrc", ".npmrc", ".pypirc", ".config/git", ".config/gh", ".config/fish", ".config/systemd", ".config/autostart", ".local/bin", "Library/LaunchAgents", "Library/Keychains", ".vscode", ".oh-my-zsh", ".config/nvim", ".config/zsh", ".vim", ".vimrc", ".emacs.d", ".tmux", ".tmux.conf", ".config/environment.d", ".local/share/applications", ".cargo/bin", "go/bin", ".npm-global", "Library/Application Support/Code/User"];

/**
 * Why a directory must not be made writable inside the sandbox (null when it may): the disk root,
 * system directories, the home directory or above, credential stores, shell start-up files, agent
 * configuration directories (where the firewall's hooks are registered), or a path inside a
 * protected one. `entry` is absolute and already resolved.
 */
export function writePathProblem(entry: string, home: string, protectedPaths: readonly string[], ci: boolean): string | null {
  const e = entry.replace(/\/+$/, "") || "/";
  const h = home.replace(/\/+$/, "");
  if (/[\n\r\0]/.test(e)) return "it contains a line break or NUL";
  if (!e.startsWith("/")) return "it is not an absolute path";
  if (SYSTEM_EXACT.some((s) => (ci ? s.toLowerCase() === e.toLowerCase() : s === e))) return "it is the disk root or a top-level system directory";
  if (SYSTEM_TREES.some((s) => isUnder(e, s, ci))) return "it is a system directory";
  if (h !== "" && isUnder(h, e, ci)) return "it is your home directory or contains it";
  if (h !== "" && isUnder(e, h, ci)) {
    const rel = e.slice(h.length + 1);
    if (HOME_EXACT.some((x) => (ci ? x.toLowerCase() === rel.toLowerCase() : x === rel))) return `~/${rel} holds other programs' configuration; name the subdirectory the agent needs`;
    const tree = HOME_TREES.find((x) => isUnder(rel, x, ci));
    if (tree !== undefined) return `~/${tree} holds credentials, shell start-up files or an agent's configuration (where the firewall's hooks are registered)`;
  }
  // A writable directory may contain a protected path (the read-only rules win); one inside it may not.
  const inside = protectedPaths.find((p) => isUnder(e, p, ci));
  if (inside !== undefined) return `it is inside ${inside}, which the firewall keeps read-only or unreadable`;
  return null;
}

// --- macOS: Seatbelt ---------------------------------------------------------------------------------

/** A Seatbelt profile and the -D parameters it reads (paths are never quoted into the profile text). */
export function seatbeltProfile(plan: RunPlan): { text: string; params: [string, string][] } {
  if (!Number.isInteger(plan.proxyPort) || plan.proxyPort < 1 || plan.proxyPort > 65535) throw new Error(`bad proxy port ${plan.proxyPort}`);
  const params: [string, string][] = [];
  const ref = (prefix: string, values: readonly string[]): string[] =>
    values.map((v, i) => {
      if (/[\n\r\0]/.test(v)) throw new Error(`refusing a path with a line break: ${JSON.stringify(v)}`);
      params.push([`${prefix}${i}`, v]);
      return `(subpath (param "${prefix}${i}"))`;
    });
  const writable = ref("W", plan.writable);
  const sockets = ref("S", plan.socketDirs);
  const readOnly = ref("R", plan.readOnly);
  const unreadable = ref("U", plan.unreadable);
  const guarded = guardedAncestors([...plan.readOnly, ...plan.unreadable], plan.writable, true).map((v, i) => {
    if (/[\n\r\0]/.test(v)) throw new Error(`refusing a path with a line break: ${JSON.stringify(v)}`);
    params.push([`A${i}`, v]);
    return `(literal (param "A${i}"))`;
  });
  const mach = [...MACH_DENY_NAMES, ...(plan.allowKeychain ? [] : MACH_KEYCHAIN)].map((n) => `(global-name "${n}")`);
  const machRe = MACH_DENY_REGEX.map((r) => `(global-name-regex #"${r}")`);
  const lines = [
    "(version 1)",
    ";; LaunchSafe Agent Firewall: launchsafe-firewall run (docs/run.md)",
    "(allow default)",
    ";; Network: only the run's proxy, and local listening sockets.",
    "(deny network*)",
    '(allow network-bind network-inbound (local ip "localhost:*"))',
    `(allow network-outbound (remote ip "localhost:${plan.proxyPort}"))`,
    ...(plan.allowLocalhost ? ['(allow network-outbound (remote ip "localhost:*"))'] : []),
    ...(sockets.length > 0 ? [`(allow network-bind network-outbound (local unix-socket ${sockets.join(" ")}))`, `(allow network-outbound (remote unix-socket ${sockets.join(" ")}))`] : []),
    ";; Writes: the workspace, the run's temporary directory and the person's --allow-write entries.",
    "(deny file-write*)",
    `(allow file-write* ${[...writable, '(literal "/dev/null")', '(literal "/dev/zero")', '(literal "/dev/dtracehelper")', '(regex #"^/dev/tty")', '(regex #"^/dev/fd/")', '(literal "/dev/ptmx")'].join(" ")})`,
    ";; Read-only even inside a writable directory (the last matching rule wins).",
    ...(readOnly.length > 0 ? [`(deny file-write* ${readOnly.join(" ")})`] : []),
    ";; The directories leading to them cannot be created, renamed, removed or replaced by a symlink (their contents stay writable).",
    ...(guarded.length > 0 ? [`(deny file-write* ${guarded.join(" ")})`] : []),
    ...(unreadable.length > 0 ? [`(deny file-read* file-write* ${unreadable.join(" ")})`] : []),
    ";; No hard links: a link to a protected file would be writable or readable under its new name.",
    SEATBELT_HARDLINK_DENY,
    ";; No signals to processes outside the sandbox (the proxy among them).",
    "(deny signal)",
    "(allow signal (target same-sandbox))",
    ";; No launchd jobs, and no inspecting or taking over processes outside the sandbox.",
    ...SEATBELT_PROCESS_RULES,
    ";; No keystrokes pushed into a terminal (TIOCSTI).",
    SEATBELT_TIOCSTI_DENY,
    ";; Services that would act for the process outside the sandbox: LaunchServices, downloads, the pasteboard,",
    ";; the keychain, name resolution (mDNSResponder sends DNS queries for it) and preference writes (cfprefsd).",
    "(deny appleevent-send)",
    `(deny mach-lookup ${[...mach, ...machRe].join(" ")})`,
    `(deny mach-lookup ${[...MACH_DNS_DENY, ...MACH_PREFS_DENY].map((n) => `(global-name "${n}")`).join(" ")})`,
  ];
  return { text: `${lines.join("\n")}\n`, params };
}

/** The sandbox-exec argument list (after the program) for a plan and a command. */
export function sandboxExecArgs(plan: RunPlan, command: readonly string[]): string[] {
  const { text, params } = seatbeltProfile(plan);
  return [...params.flatMap(([k, v]) => ["-D", `${k}=${v}`]), "-p", text, "--", ...command];
}

// --- Linux: bubblewrap -------------------------------------------------------------------------------

export interface BwrapExtras {
  /** The host directory holding the proxy's Unix socket. */
  socketDir: string;
  /** Where it appears inside the sandbox. */
  insideSocketDir: string;
  /** The socket's file name. */
  socketName: string;
  /** The Node binary that runs the bridge (bound read-only with the root). */
  nodePath: string;
  /** The bridge program (node -e). */
  bridgeSource: string;
  /** Paths that exist (bubblewrap binds only existing sources). */
  exists: (p: string) => "dir" | "file" | null;
  cwd: string;
}

/**
 * Files git reads inside a git directory, with the content of the stand-in a run puts there on Linux
 * when one is missing. git dies on a directory there ("Is a directory"), and on an empty `commondir`
 * ("failed to read"); `.` (the git directory itself) is what git assumes when there is no `commondir`,
 * and an empty config is no config.
 */
export const GIT_DIR_FILES: Readonly<Record<string, string>> = { commondir: ".\n", config: "", "config.worktree": "" };

/** The stand-in content for a missing protected file inside a git directory (`.git/commondir`, `sub/.git/config`), else null. */
export function filePlaceholder(p: string): string | null {
  const name = basename(p);
  return basename(dirname(p)) === ".git" ? (own(GIT_DIR_FILES, name) ?? null) : null;
}

/**
 * How Linux keeps protected paths that do not exist yet from being created (V7). bubblewrap can mount only
 * on a path that exists, so:
 * - the topmost missing directory on the way (`.cursor` for `.cursor/mcp.json`) gets an empty read-only
 *   tmpfs: nothing can be created below it, and both the mount point on disk and what the run sees are an
 *   empty directory, which git ignores (file stand-ins inside it were committed by `git add .`);
 * - a missing file in an existing agent configuration directory (`.claude/settings.local.json`): that
 *   directory is bound read-only whole, so nothing is created at all;
 * - a missing file git reads in an existing git directory (`.git/commondir`, `.git/config.worktree`): a
 *   file stand-in (filePlaceholder) that run.ts writes before the sandbox starts and that is bound
 *   read-only onto itself; git never lists what is inside a git directory, and a directory there breaks git;
 * - a missing path anywhere else (`.mcp.json` at the top, `.git/hooks`): an empty read-only tmpfs on the
 *   path itself (its mount point is an empty directory, which `git add` ignores, where a file stand-in
 *   would be committed);
 * - an existing file on the way (a `.git` file in a linked worktree) is bound read-only, so it cannot be
 *   replaced by a directory.
 * `created` lists the mount points made on disk (the empty directories bubblewrap creates and the file
 * stand-ins in `files`); run.ts removes them afterwards while they are still empty or unchanged.
 */
export function bwrapMissing(plan: RunPlan, exists: (p: string) => "dir" | "file" | null): { args: string[]; created: string[]; files: { path: string; content: string }[] } {
  const ci = false;
  const roots = plan.writable.filter((w) => exists(w) === "dir");
  const roDirs = new Set<string>();
  const roFiles = new Set<string>();
  const emptyDirs = new Set<string>();
  const files = new Map<string, string>();
  for (const r of plan.readOnly) {
    if (exists(r) !== null) continue;
    const root = roots.filter((w) => isUnder(r, w, ci) && r !== w).sort((a, b) => b.length - a.length)[0];
    if (root === undefined) continue;
    // Walk down from the writable root to the first component that does not exist.
    const parts = r.slice(root.length + 1).split("/");
    let cur = root;
    let blocked = false;
    let missing: string | null = null;
    for (const part of parts) {
      cur = `${cur}/${part}`;
      const k = exists(cur);
      if (k === null) {
        missing = cur;
        break;
      }
      if (k === "file") {
        roFiles.add(cur);
        blocked = true;
        break;
      }
    }
    if (blocked || missing === null) continue;
    if (missing !== r) {
      emptyDirs.add(missing);
      continue;
    }
    const parent = dirname(r);
    const top = parent.slice(root.length + 1).split("/")[0] ?? "";
    const content = filePlaceholder(r);
    if (content !== null) files.set(r, content);
    else if (WORKSPACE_PROTECTED_DIRS.includes(r.slice(root.length + 1))) emptyDirs.add(r);
    else if (parent !== root && isUnder(parent, root, ci) && AGENT_CONFIG_DIRS.includes(top)) roDirs.add(parent);
    else emptyDirs.add(r);
  }
  // Below a directory that is read-only already (bound whole, or an existing protected one) nothing can be
  // created anyway, and bubblewrap could not make a mount point there: no mount below one.
  const roRoots = [...roDirs, ...plan.readOnly.filter((q) => exists(q) === "dir")];
  const free = (p: string): boolean => !roRoots.some((q) => q !== p && isUnder(p, q, ci));
  const dirs = [...emptyDirs].filter(free);
  const stand = [...files].filter(([p]) => free(p));
  const a: string[] = [];
  for (const f of roFiles) a.push("--ro-bind", f, f);
  for (const d of roDirs) a.push("--ro-bind", d, d);
  for (const d of dirs) a.push("--tmpfs", d, "--remount-ro", d);
  for (const [f] of stand) a.push("--ro-bind", f, f);
  return { args: a, created: [...dirs, ...stand.map(([p]) => p)], files: stand.map(([path, content]) => ({ path, content })) };
}

/** The marker the bridge carries in its arguments, so the parent can find it to pass signals. */
export const BRIDGE_MARKER = "LSFW_RUN_BRIDGE";

/** The bwrap argument list (after the program) for a plan and a command. */
export function bwrapArgs(plan: RunPlan, x: BwrapExtras, command: readonly string[]): string[] {
  const a: string[] = ["--die-with-parent", "--new-session", "--unshare-net", "--unshare-pid", "--unshare-ipc", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/run"];
  for (const w of plan.writable) if (x.exists(w) === "dir") a.push("--bind", w, w);
  // V3 on Linux: the directories on the way to a protected path (`.git`, `.claude`, a nested repository's
  // directory) become mount points, so they cannot be renamed away, removed or replaced by a prepared copy;
  // their contents stay writable. Shallow first, and before the read-only binds that sit on top of them.
  const roots = new Set(plan.writable);
  const guarded = guardedAncestors([...plan.readOnly, ...plan.unreadable], plan.writable, false)
    .filter((d) => !roots.has(d) && x.exists(d) === "dir")
    .sort((p, q) => p.split("/").length - q.split("/").length || (p < q ? -1 : 1));
  for (const d of guarded) a.push("--bind", d, d);
  for (const r of plan.readOnly) if (x.exists(r) !== null) a.push("--ro-bind", r, r);
  a.push(...bwrapMissing(plan, x.exists).args);
  for (const u of plan.unreadable) {
    const k = x.exists(u);
    if (k === "dir") a.push("--tmpfs", u, "--remount-ro", u);
    else if (k === "file") a.push("--ro-bind", "/dev/null", u);
  }
  a.push("--ro-bind", x.socketDir, x.insideSocketDir, "--chdir", x.cwd, "--", x.nodePath, "-e", x.bridgeSource, BRIDGE_MARKER, `${x.insideSocketDir}/${x.socketName}`, String(plan.proxyPort), "--", ...command);
  return a;
}
