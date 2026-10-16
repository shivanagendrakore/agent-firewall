/**
 * What a shell command does: the files it reads and writes, where it sends
 * data, what code it runs. Built on the parser's structure, never on matching
 * the raw command text, so quoting, ANSI-C escapes, wrappers (sudo, env,
 * timeout, xargs), nested shells (bash -c, eval) and substitutions cannot hide
 * an action. Anything the analyzer cannot see into is reported as opaque.
 */

import { addEffect, addFinding, createdByTrustedSession, downloadsOf, egress, externalSend, forgetJudgements, readPath, taintFetched, writePath, writtenByUntrustedSession, type Collector } from "../effects.js";
import { inlineCode } from "./inline.js";
import { parseUrlLike } from "../network.js";
import { isUnder, normalizeAbs, pathForms, PROTECTION_FOLDS_CASE, resolvePath, UNKNOWN_CWD } from "../paths.js";
import type { Context, NormalizedAction } from "../../types.js";
import { classifyAction } from "../classify.js";
import { settingsFilesUnder } from "../settings.js";
import { wrappedServerNames } from "../gateway-config.js";
import { codexPatchActions, diffActions, parseUnifiedDiff, type PathRule } from "./patches.js";
import { applyCd, cdCommand, copyCwd, startCwd, type Cwd } from "./cwd.js";
import { firewallPart, identityOf, inPackageRoot, isBinName, isPackageIdentity } from "../identity.js";
import { isCredentialVariable, issuerMatches, variableIssuers } from "../secrets.js";
import { classifySql } from "../sql.js";
import { currentBranch, gitDirDeletion, judgeCommand, judgePush, judgeSql, workspaceDeletion, type CatastropheOptions, type Judgement } from "../catastrophic.js";
import { invisibleCharacters } from "../unicode.js";
import { notePackageCommand } from "../packages.js";
import { checkNpmConfig } from "../autorun.js";
import { isReadOnlyInvocation } from "../../cliargs.js";
import { has, parseArgs, values, wrapperArgs, type ParsedArgs, type WrapperSpec } from "./args.js";
import { allCommands, allErrors, allPipelines, MAX_COMMAND_LENGTH, parseShell, type Pipeline, type Script, type SimpleCommand, type Word } from "./parse.js";
import { own } from "../../own.js";

const RESERVED = new Set(["if", "then", "else", "elif", "fi", "do", "done", "while", "until", "esac", "in", "!", "{", "}", "time", "coproc"]);
const DATA_STARTERS = new Set(["for", "select", "case", "function", "[[", "[", "test", "]]", "true", "false", ":", "export", "readonly", "declare", "typeset", "local", "unset", "shift", "return", "exit", "break", "continue", "wait", "trap", "set", "shopt", "alias", "unalias", "hash", "type", "which", "whence", "echo", "printf", "cd", "pushd", "popd", "dirs", "pwd", "umask", "ulimit", "jobs", "fg", "bg", "disown", "read", "let", "sleep", "date", "whoami", "id", "uname", "hostname", "true", "clear", "history", "fc", "getopts", "mapfile", "readarray", "complete", "compgen", "bind", "logout", "suspend", "times", "enable", "help", "seq", "yes", "basename", "dirname", "realpath", "readlink", "expr", "bc", "tput", "stty", "tty", "nproc", "uptime", "arch", "sw_vers", "locale", "cal", "ps", "pgrep", "lsof", "top", "htop", "free", "vm_stat", "df", "mount", "groups"]);

/** Environment variables that make the next program load or run attacker-chosen code. */
/**
 * Environment variables that make the next program load or run attacker-chosen code. Split in two:
 * ALWAYS_INJECTION is dangerous in any session; COMMON_ENV holds everyday settings (PATH,
 * NODE_OPTIONS...) that are fine in a trusted session unless the value itself loads code.
 * TF_CLI_ARGS and Terragrunt's plan directories (TG_OUT_DIR, TERRAGRUNT_OUT_DIR and the JSON ones) are
 * here too: they add options the command does not show, such as -destroy or a saved plan file.
 */
const ALWAYS_INJECTION = /^(?:LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|DYLD_[A-Z_]+|PYTHONSTARTUP|PYTHONHOME|PERL5OPT|PERL5LIB|RUBYOPT|RUBYLIB|BASH_ENV|ENV|PROMPT_COMMAND|PS4|GIT_SSH|GIT_SSH_COMMAND|GIT_EXTERNAL_DIFF|GIT_ASKPASS|SSH_ASKPASS|GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_CONFIG_COUNT|GIT_CONFIG_KEY_\d+|GIT_CONFIG_VALUE_\d+|GIT_DIR|GIT_EXEC_PATH|GIT_TEMPLATE_DIR|HOME|ZDOTDIR|XDG_CONFIG_HOME|npm_config_.*|NPM_CONFIG_.*|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|UV_INDEX_URL|CARGO_HOME|RUSTC_WRAPPER|ELECTRON_RUN_AS_NODE|BROWSER|TF_CLI_ARGS(?:_\w+)?|(?:TG|TERRAGRUNT)_(?:JSON_)?OUT_DIR)$/;
const COMMON_ENV = /^(?:PATH|NODE_OPTIONS|NODE_PATH|PYTHONPATH|CLASSPATH|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS|GIT_PAGER|GIT_EDITOR|EDITOR|VISUAL|PAGER)$/;
const PRELOAD_FLAG = /(?:^|\s)(?:-r|--require|--import|--loader|--experimental-loader|-javaagent|-agentpath|-agentlib)(?:[=\s:]|$)/;
const BENIGN_EDITOR = /^(?:true|:|cat|less|more|most|vim|vi|nvim|nano|emacs|micro|hx|code --wait|code -w|cursor --wait|subl -w|subl --wait|zed --wait)$/;

/** Whether setting this variable to this value can change what code runs. */
export function envInjects(name: string, value: string, tainted: boolean): boolean {
  if (ALWAYS_INJECTION.test(name)) return true;
  if (!COMMON_ENV.test(name)) return false;
  if (tainted) return true;
  if (/^(?:GIT_PAGER|GIT_EDITOR|EDITOR|VISUAL|PAGER)$/.test(name)) return !BENIGN_EDITOR.test(value.trim());
  return PRELOAD_FLAG.test(value);
}


const READERS = new Set(["cat", "tac", "less", "more", "most", "head", "tail", "nl", "od", "xxd", "hexdump", "hd", "strings", "file", "stat", "wc", "sort", "uniq", "cut", "paste", "diff", "cmp", "comm", "md5", "md5sum", "shasum", "sha1sum", "sha256sum", "sha512sum", "b2sum", "cksum", "base64", "base32", "jq", "yq", "bat", "batcat", "view", "fold", "fmt", "column", "expand", "unexpand", "iconv", "look", "tr", "rev", "csvlook", "xmllint", "plutil", "pr", "split", "csplit", "join", "zcat", "gzcat", "bzcat", "xzcat", "zless", "lz4cat", "zstdcat", "pdftotext", "otool", "nm", "objdump", "readelf", "ldd", "codesign", "spctl", "mdls", "exiftool", "identify", "ffprobe", "sqlite3", "duckdb", "awk", "gawk", "mawk", "nawk", "sed", "gsed", "perl", "dos2unix", "unix2dos", "tee", "lsattr", "getfacl", "xattr", "ls", "exa", "eza", "lsd", "tree", "du", "dust"]);
const SEARCHERS = new Set(["grep", "egrep", "fgrep", "rg", "ag", "ack", "ugrep", "git-grep", "pt", "sift"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "ash", "busybox", "csh", "tcsh", "yash", "rbash", "nu", "xonsh", "elvish"]);
const INTERPRETERS = new Set(["python", "python2", "python3", "pypy", "pypy3", "node", "nodejs", "deno", "bun", "perl", "ruby", "php", "lua", "luajit", "osascript", "pwsh", "powershell", "Rscript", "julia", "swift", "irb", "tclsh", "wish", "groovy", "scala", "kotlin", "jshell", "guile", "racket", "elixir", "erl", "escript", "awk", "gawk", "ts-node", "tsx", "jxa", "qjs", "rhino", "jjs", "cscript", "wscript"]);
const INLINE_FLAGS: Record<string, readonly string[]> = {
  python: ["c"], python2: ["c"], python3: ["c"], pypy: ["c"], pypy3: ["c"],
  node: ["e", "p", "eval", "print"], nodejs: ["e", "p", "eval", "print"], bun: ["e", "eval", "print"], "ts-node": ["e", "p", "eval", "print"], tsx: ["e", "p", "eval", "print"],
  perl: ["e", "E"], ruby: ["e"], php: ["r"], lua: ["e"], luajit: ["e"], osascript: ["e"], pwsh: ["c", "Command", "command", "EncodedCommand", "e", "ec", "enc", "encodedcommand"], powershell: ["c", "Command", "command", "EncodedCommand", "e", "ec", "enc", "encodedcommand"],
  Rscript: ["e"], julia: ["e", "E"], tclsh: [], elixir: ["e", "eval"], erl: ["eval"], groovy: ["e"], jshell: [], guile: ["c"], racket: ["e"], qjs: ["e"], irb: [],
};

const AGENT_CLIS = new Set(["claude", "claude-code", "gemini", "codex", "q", "qchat", "kiro-cli", "cursor-agent", "aider", "opencode", "goose", "amp", "crush", "copilot", "cline", "qwen", "llm", "openhands", "devin", "windsurf", "continue", "plandex", "kilocode", "roo"]);
const BYPASS_FLAGS = /^--(?:dangerously-skip-permissions|allow-dangerously-skip-permissions|dangerously-bypass-approvals-and-sandbox|yolo|trust-all-tools|full-auto|no-sandbox|approval-mode(?:=yolo)?|auto-approve|yes-always|skip-permissions|bypass-permissions|unsafe|allow-all-tools)$|^--permission-mode(?:=bypassPermissions)?$|^bypassPermissions$|^-y$|^--yes$/;

/** Tools a developer runs through npx/bunx constantly and that are normally already in devDependencies. */
const COMMON_DEV_TOOLS = new Set(["vitest", "jest", "mocha", "tsc", "tsx", "ts-node", "typescript", "prettier", "eslint", "biome", "tsup", "vite", "esbuild", "webpack", "rollup", "playwright", "cypress", "storybook", "next", "astro", "nuxt", "svelte-kit", "ng", "nest", "turbo", "nx", "lerna", "jscodeshift", "knip", "depcheck", "npm-check-updates", "ncu", "serve", "http-server", "concurrently", "nodemon", "rimraf", "cross-env", "dotenv", "husky", "lint-staged", "commitlint", "semantic-release", "changeset", "@changesets/cli", "prisma", "drizzle-kit", "supabase", "wrangler", "vercel", "netlify", "madge", "size-limit", "bundlewatch", "pkg-pr-new"]);

/** Program base names the analyzer has a dedicated model for, so a path like /bin/rm still routes to it. */
/** F19: deploy CLIs that are also common dev tools (run through npx): their commands are judged as the CLI. */
const DEPLOY_CLIS = new Set(["vercel", "netlify", "wrangler", "firebase", "railway", "flyctl", "fly", "heroku", "serverless", "sls", "cdk", "sam"]);

const KNOWN_BY_BASENAME = new Set<string>([
  "rm", "rmdir", "unlink", "shred", "srm", "trash", "wipe", "cp", "mv", "rsync", "ditto", "scp", "rclone", "ln", "dd",
  "git", "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "bash", "sh", "zsh", "dash", "python", "python3", "node",
  "sudo", "env", "chmod", "chown", "tar", "zip", "unzip", "find", "sed", "awk", "perl", "ruby", "openssl", "tee", "cat",
  "eval", "xargs", "npm", "pip", "pip3", "docker", "kubectl", "psql", "mysql", "mongosh", "aws", "gh",
]);

/** Programs that copy or archive files: handed the firewall's data directory, they carry its keys away. */
const FIREWALL_COPIERS = new Set(["cp", "rsync", "ditto", "scp", "rclone", "tar", "bsdtar", "gtar", "zip", "7z", "7za", "cpio", "ln", "install", "mv", "pax"]);
/** Interpreters that run a script file given as an argument. */
const SCRIPT_INTERPRETERS = new Set(["node", "nodejs", "bun", "deno", "tsx", "ts-node"]);
/** Package runners that fetch-or-find a package and run its command. */
const PACKAGE_RUNNERS = new Set(["npx", "bunx", "pnpx", "dlx"]);
/** GW12: agent CLIs' registry packages, and the command each one is (a package runner running one is that agent). */
const AGENT_PACKAGES: Record<string, string> = { "@anthropic-ai/claude-code": "claude", "@openai/codex": "codex", "@google/gemini-cli": "gemini", "cursor-agent": "cursor-agent" };

/** A registry package name without its version (`@scope/name@1.2.3` -> `@scope/name`). */
const packageName = (spec: string): string => spec.replace(/^(@[^/@]+\/[^@]+|[^@]+)@.*$/, "$1");

/**
 * GW12: the agent CLI a package runner runs, with that CLI's own arguments, or null. `args` follow the
 * runner (npx, bunx, pnpx, dlx) or its verb (npm exec, pnpm dlx, yarn dlx, bun x): flags, then the package
 * and its arguments, or `-p`/`--package <pkg>` and then the command and its arguments.
 */
function agentViaRunner(args: readonly Word[]): { cli: string; rest: readonly Word[] } | null {
  let pkgFlag: string | null = null;
  for (let i = 0; i < args.length; i++) {
    const t = (args[i] as Word).text;
    if (t === "--") continue;
    if (t === "-p" || t === "--package") {
      pkgFlag = args[i + 1]?.text ?? null;
      i++;
      continue;
    }
    if (t.startsWith("--package=")) {
      pkgFlag = t.slice("--package=".length);
      continue;
    }
    if (t.startsWith("-")) continue;
    if (pkgFlag !== null) {
      // The command the --package provides: the agent's arguments follow it.
      const cli = own(AGENT_PACKAGES, packageName(pkgFlag));
      return cli !== undefined ? { cli, rest: args.slice(i + 1) } : null;
    }
    const cli = own(AGENT_PACKAGES, packageName(t));
    return cli !== undefined ? { cli, rest: args.slice(i + 1) } : null;
  }
  return null;
}

/** The absolute path(s) a word names: as written and after symlinks. `known` is false when symlinks could not be resolved. */
function pathCandidates(c: Collector, text: string): { paths: string[]; known: boolean } | null {
  if (text === "" || /^-/.test(text)) return null;
  const r = resolvePath(text.replace(/^[A-Za-z_][A-Za-z0-9_-]*=/, ""), c.ctx);
  if (r === null) return null;
  // SELF-016: as written, canonical, and the physical form of a path with ".." after a link.
  const f = pathForms(r.abs, c.ctx, r.physical);
  return { paths: f.paths, known: c.ctx.realpath !== undefined && f.known };
}

/**
 * F-c: whether a path runs the installed CLI: its realpath is a CLI file a hook command names (or,
 * for a script handed to an interpreter, any file of the runtime). When symlinks cannot be resolved,
 * a file named like the CLI is assumed to be it (fail closed). `ci` folds case (see firewallInvocation).
 */
function runsInstalledCli(c: Collector, text: string, anyRuntimeFile: boolean, ci: boolean): boolean {
  const cand = pathCandidates(c, text);
  if (cand === null) return false;
  for (const p of cand.paths) {
    const part = firewallPart(p, c.ctx, ci);
    if (part === "cli" || (anyRuntimeFile && part === "runtime")) return true;
  }
  return !cand.known && /(?:^|\/)launchsafe-firewall(?:\.js)?$/.test(text);
}

/** Whether a word names something inside the firewall's data directory (its keys, approvals, state). */
function namesFirewallData(c: Collector, text: string): boolean {
  const cand = pathCandidates(c, text.replace(/^--?[A-Za-z][\w-]*=/, ""));
  return cand !== null && cand.paths.some((p) => firewallPart(p, c.ctx) === "data");
}

/** The words after a package runner's package or command when that is the firewall; otherwise null. */
function afterFirewallPackage(c: Collector, args: readonly Word[]): readonly Word[] | null {
  const idx = args.findIndex((a) => isPackageIdentity(a.text) || isBinName(a.text, c.ctx));
  if (idx === -1) {
    // npx -p @launchsafe/agent-firewall <cmd> / npx --package @launchsafe/agent-firewall <cmd>
    const flag = args.findIndex((a, i) => (a.text === "-p" || a.text === "--package") && isPackageIdentity(args[i + 1]?.text ?? ""));
    if (flag === -1) return null;
    return skipCommand(c, args.slice(flag + 2));
  }
  return skipCommand(c, args.slice(idx + 1));
}

function skipCommand(c: Collector, rest: readonly Word[]): readonly Word[] {
  let r = rest;
  while (r.length > 0 && (r[0] as Word).text.startsWith("-") && !isBinName((r[0] as Word).text, c.ctx)) {
    if ((r[0] as Word).text === "--") {
      r = r.slice(1);
      break;
    }
    r = r.slice(1);
  }
  if (r.length > 0 && isBinName((r[0] as Word).text, c.ctx)) r = r.slice(1);
  return r;
}

/**
 * When a command runs the firewall's installed CLI, the CLI's own arguments; otherwise null (F-c).
 * Recognised by identity: argv0 whose realpath is a CLI file a hook command names, the CLI's bare
 * command name, an interpreter running a runtime file, or a package runner running the package by
 * its registry name. Any other program handed a path is judged by its own model as a read or a
 * write of that path; nothing is the firewall because of its name. `ci` folds case when the installed files are
 * compared: PROTECTION_FOLDS_CASE (I1) to refuse a changing command, the platform's rule to let a read-only one run.
 */
function firewallInvocation(c: Collector, name: string, w0: Word, args: readonly Word[], ci: boolean = PROTECTION_FOLDS_CASE): readonly Word[] | null {
  if (!w0.text.includes("/")) {
    if (isBinName(w0.text, c.ctx)) return args;
  } else if (runsInstalledCli(c, w0.text, false, ci)) return args;
  if (SCRIPT_INTERPRETERS.has(name)) {
    for (let i = 0; i < args.length; i++) {
      const t = (args[i] as Word).text;
      if (t.startsWith("-") || ((name === "deno" || name === "bun") && /^(?:run|x)$/.test(t))) continue;
      return runsInstalledCli(c, t, true, ci) ? args.slice(i + 1) : null;
    }
    return null;
  }
  if (PACKAGE_RUNNERS.has(name)) return afterFirewallPackage(c, args);
  if (name === "npm" || name === "pnpm" || name === "yarn" || name === "bun") {
    const verbAt = args.findIndex((a) => !a.text.startsWith("-"));
    if (verbAt !== -1 && /^(?:exec|x|dlx)$/.test((args[verbAt] as Word).text)) return afterFirewallPackage(c, args.slice(verbAt + 1));
  }
  return null;
}

/**
 * kill/pkill/killall naming the hook process: its CLI file, its command name, or its marker variable. I1: every name is
 * compared ignoring case on every platform (PROTECTION_FOLDS_CASE, canonical.ts): `pkill -i` and Linux's `killall -I`
 * match a process whatever the case of the name they are given.
 */
function namesHookProcess(c: Collector, text: string): boolean {
  if (text === "" || text.startsWith("-")) return false;
  const lc = (s: string): string => s.toLowerCase();
  const t = lc(text);
  if (t.includes("launchsafe_firewall_hook")) return true;
  // The phone relay daemon (`relay run`, started by a login item).
  if (/(?:^|\s)relay\s+run(?:\s|$)/.test(t)) return true;
  // The local API sidecar (`serve --api`).
  if (/(?:^|\s)serve\s+(?:\S+\s+)*--api(?:[\s=]|$)/.test(t) || /(?:^|[\s/])api\.sock(?:\s|$)/.test(t)) return true;
  const id = identityOf(c.ctx);
  if (id.binNames.some((b) => t.includes(lc(b)))) return true;
  return id.cliFiles.some((f) => t.includes(lc(f)) || (text.includes("/") && text.length >= 6 && lc(f).endsWith(t)));
}

const NETWORK_FETCHERS = new Set(["curl", "wget", "http", "https", "xh", "xhs", "httpie", "curlie", "aria2c", "fetch", "lwp-request", "GET", "HEAD", "POST", "lynx", "w3m", "links", "elinks"]);
const DNS_TOOLS = new Set(["ping", "ping6", "dig", "nslookup", "host", "drill", "traceroute", "traceroute6", "tracepath", "mtr", "whois", "arping", "fping", "hping3", "delv", "kdig", "resolvectl", "dscacheutil"]);
const RAW_SENDERS = new Set(["nc", "ncat", "netcat", "socat", "telnet", "openssl", "gnutls-cli", "cryptcat", "pwncat", "websocat", "wscat", "grpcurl", "nmap", "masscan", "smbclient", "ftp", "tftp", "lftp", "sftp", "mosquitto_pub", "kcat", "kafkacat", "redis-cli", "ldapsearch", "snmpwalk", "iperf", "iperf3"]);
const MAILERS = new Set(["mail", "mailx", "sendmail", "mutt", "msmtp", "ssmtp", "swaks", "neomutt", "s-nail"]);
const TUNNELS = new Set(["ngrok", "cloudflared", "lt", "localtunnel", "bore", "frpc", "chisel", "tailscale", "zrok", "pinggy", "expose", "serveo", "tmole", "localhost.run"]);
const PACKAGE_MANAGERS = new Set(["npm", "pnpm", "yarn", "bun", "pip", "pip3", "pipx", "uv", "poetry", "pipenv", "conda", "mamba", "micromamba", "cargo", "go", "gem", "bundle", "bundler", "composer", "brew", "apt", "apt-get", "yum", "dnf", "pacman", "apk", "port", "nix", "nix-env", "dotnet", "nuget", "mvn", "gradle", "sbt", "mix", "hex", "cabal", "stack", "opam", "cpan", "cpanm", "luarocks", "rustup", "deno", "corepack", "volta", "asdf", "mise", "rye", "pdm", "hatch", "swift", "pod", "carthage", "flutter", "dart", "pub", "jbang", "coursier", "cs", "nimble", "zig", "vcpkg", "conan", "helm", "krew", "gh-extension", "pkg", "snap", "flatpak", "winget", "choco", "scoop"]);
const INSTALL_VERBS = new Set(["install", "i", "add", "ci", "update", "upgrade", "up", "get", "sync", "fetch", "restore", "require", "tap", "reinstall", "download", "dlx", "x", "create", "init", "global", "link", "rebuild", "bootstrap", "self-update", "selfupdate", "toolchain", "run-script"]);
const PUBLISH_VERBS = new Set(["publish", "push", "upload", "release", "deploy", "dist-tag", "owner", "unpublish", "deprecate", "yank", "token", "adduser", "login", "logout"]);
const CLOUD_CLIS = new Set(["aws", "gcloud", "gsutil", "bq", "az", "doctl", "flyctl", "fly", "vercel", "netlify", "heroku", "railway", "supabase", "firebase", "wrangler", "render", "linode-cli", "hcloud", "oci", "ibmcloud", "scw", "vultr-cli", "exoscale", "pulumi", "terraform", "tofu", "terragrunt", "cdk", "sam", "serverless", "sls", "eb", "ecs-cli", "copilot-cli", "kubectl", "oc", "k9s", "helm", "eksctl", "kind", "minikube", "nomad", "consul", "vault", "ansible", "ansible-playbook", "gh", "glab", "tea", "bitbucket", "stripe", "twilio", "sentry-cli", "datadog-ci", "neonctl", "planetscale", "pscale", "turso", "convex", "prisma", "drizzle-kit", "atlas", "flyway", "liquibase", "docker", "podman", "nerdctl", "skopeo", "crane", "buildah", "cosign", "mongosh", "mongo", "psql", "mysql", "mariadb", "clickhouse-client", "cqlsh", "sqlcmd", "influx", "pgcli", "mycli", "usql", "dbmate", "fastlane", "eas", "eas-cli", "expo", "codemagic-cli-tools"]);
const DESTROY_VERBS = /^(?:delete|delete-.*|del|destroy|remove|remove-.*|rm|rb|purge|terminate|terminate-.*|deregister.*|drop|wipe|erase|nuke|reset|teardown|uninstall|disable|revoke|detach-.*|cancel.*|scale-to-zero|apps:destroy|apps:delete|projects:delete|unlink|prune|truncate|flush.*|kill|evict|drain|cordon|empty|clear|force-delete|db-reset|stop-db-cluster|stop-instances|delete_.*)$/i;
const READ_VERBS = /^(?:describe.*|list.*|ls|get.*|show|status|info|whoami|logs?|tail|inspect|view|search|top|explain|version|help|plan|diff|validate|output|state|show-.*|lookup|query|history|ping|check|doctor|config-get|cat|head|stat|api-resources|events|watch|outputs|preview|graph|fmt|lint|test|env|auth)$/i;

const FIND_ACTIONS = new Set(["-exec", "-execdir", "-ok", "-okdir"]);

/** SH9: builtins that evaluate an arithmetic context (and so run a `$(...)` hidden in an array subscript). */
const ARITH_BUILTINS = new Set(["let", "declare", "typeset", "local", "readonly", "export", "read", "mapfile", "readarray", "getopts", "printf", "unset", "test", "[", "[[", "]]"]);

/** Whether a redirection target is a process substitution (`<(...)`, parsed to this placeholder). */
function isProcessSub(target: string | undefined): boolean {
  return target !== undefined && /^\/dev\/fd\/\d+$/.test(target);
}

/** The value given to a flag, as `-C cb` or `-Ccb` or `--callback=cb`; undefined when the flag is absent. */
function valueOf(args: readonly Word[], flag: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const t = (args[i] as Word).text;
    if (t === flag) return args[i + 1]?.text;
    if (flag.length === 2 && t.startsWith(flag)) return t.slice(2);
  }
  return undefined;
}

interface StageKind {
  fetches: boolean;
  decodes: boolean;
  /** Runs what arrives on standard input as code. */
  runsStdin: boolean;
}

const NO_STAGE: StageKind = { fetches: false, decodes: false, runsStdin: false };

export function analyzeShell(command: string, c: Collector, depth = 0): void {
  if (depth === 0) {
    const hidden = invisibleCharacters(command);
    if (hidden.length > 0) addFinding(c, "invisible_unicode", `the command contains invisible or direction-changing characters (${hidden.join(", ")})`);
  }
  if (command.length > MAX_COMMAND_LENGTH) {
    addFinding(c, "too_large", `the command is ${command.length} characters, more than the analyzer reads`);
    addEffect(c, { cls: "execute_opaque", target: "shell", detail: "run a shell command too large to analyze" });
    return;
  }
  if (depth > 6) {
    addFinding(c, "parse_failure", "shells nested too deeply to analyze");
    addEffect(c, { cls: "execute_opaque", target: "shell", detail: "run deeply nested shell code" });
    return;
  }
  const script = parseShell(command);
  if (depth === 0) collectBindings(script, c);
  collectFunctions(script, c);
  const errors = allErrors(script);
  if (errors.length > 0) {
    addFinding(c, "parse_failure", `the command could not be fully parsed: ${[...new Set(errors)].slice(0, 3).join("; ")}`);
  }
  const before = c.effects.length;
  const base = c.ctx;
  try {
    walkScript(script, startCwd(base.cwd, base.cwdKnown !== false), c, command, depth, base);
  } catch (e) {
    // The directory tracking failed: fail closed (a person decides) and judge with v0.1 resolution.
    c.ctx = base;
    addFinding(c, "parse_failure", `the command's working directory could not be followed (${(e as Error).message})`);
    for (const pl of allPipelines(script)) analyzePipeline(pl, c, command, depth);
  } finally {
    c.ctx = base;
  }
  if (depth === 0) checkSecretFlow(c, before);
}

/**
 * F-f: walks the pipelines in source order with a working-directory cursor, so every relative path is
 * resolved against the directory the shell would be in at that point. Returns the cursor at the end.
 */
function walkScript(script: Script, start: Cwd, c: Collector, payload: string, depth: number, base: Context): Cwd {
  let cur = start;
  for (const pl of script.pipelines) {
    const dirs: Cwd[] = [cur];
    // After a cd that may have failed (joined by ";" or "||"), also judge under the directory before it.
    if (cur.alt !== null) dirs.push({ ...startCwd(cur.alt), alt: null });
    for (const d of dirs) {
      const realpath = linkAwareRealpath(c, base);
      c.ctx = { ...base, ...(realpath !== undefined ? { realpath } : {}), cwd: d.known ? d.path : UNKNOWN_CWD, cwdKnown: d.known, cwdShifted: base.cwdShifted === true || !d.known || d.path !== base.cwd };
      analyzePipeline(pl, c, payload, depth);
      for (const cmd of pl.commands) {
        for (const w of [...cmd.words, ...cmd.assigns.map((a) => a.value), ...cmd.redirects.flatMap((r) => (r.target === null ? [] : [r.target]))]) {
          for (const sub of w.subs) for (const p of allPipelines(sub)) analyzePipeline(p, c, payload, depth);
        }
      }
    }
    c.ctx = base;
    const single = pl.commands.length === 1 && pl.next !== "&";
    for (const cmd of pl.commands) {
      if (cmd.group === undefined) continue;
      // A subshell, a stage of a pipeline or a background job keeps its own directory. A function body is
      // also judged where it is defined (in case it is called later), but its cd only happens where it is called.
      const persists = single && cmd.groupKind === "brace" && cmd.func === undefined;
      const end = walkScript(cmd.group, persists ? cur : copyCwd(cur), c, payload, depth, base);
      if (persists) cur = end;
    }
    const cd = single && pl.commands[0]?.group === undefined ? cdCommand(pl.commands[0]?.words ?? []) : null;
    if (cd !== null) {
      const prev = cur;
      cur = applyCd(cur, cd.name, cd.args, c);
      cur.alt = pl.next === "&&" || !prev.known ? null : prev.path;
    }
  }
  return cur;
}

/**
 * SELF-016: remembers a link `ln` creates, so the rest of the command line resolves paths through it as the
 * shell will (`ln -s <installed package> x && cd x && npm run build`). When the link names an existing
 * directory, ln puts the link inside it: both readings are kept.
 */
function noteLink(c: Collector, link: Word | null, targets: readonly Word[]): void {
  if (targets.length !== 1) return;
  const t = targets[0] as Word;
  const linkText = link?.text ?? basenameOf(t.text);
  const lr = resolvePath(linkText, c.ctx);
  const tr = resolvePath(t.text.startsWith("/") || t.text.startsWith("~") ? t.text : `${dirnameOf(lr?.abs ?? "/")}/${t.text}`, c.ctx);
  if (lr === null || tr === null || !lr.exact || lr.glob || !tr.exact || tr.glob) return;
  const links = c.links ?? new Map<string, string>();
  links.set(lr.abs, tr.abs);
  links.set(`${lr.abs === "/" ? "" : lr.abs}/${basenameOf(tr.abs)}`, tr.abs);
  c.links = links;
  // The resolver now follows this link, so what was judged about a path before it was made no longer holds.
  forgetJudgements(c);
}

/** The context's resolver, with the links this command line created applied first. */
function linkAwareRealpath(c: Collector, base: Context): Context["realpath"] {
  const links = c.links;
  if (links === undefined || links.size === 0) return base.realpath;
  const orig = base.realpath;
  const ci = base.caseInsensitive;
  return (p: string): string => {
    let cur = p;
    for (let i = 0; i < 8; i++) {
      let hit: [string, string] | undefined;
      for (const [l, t] of links) if (isUnder(cur, l, ci) && (hit === undefined || l.length > hit[0].length)) hit = [l, t];
      if (hit === undefined) break;
      cur = normalizeAbs(`${hit[1]}${cur.slice(hit[0].length)}`);
    }
    return orig !== undefined ? orig(cur) : cur;
  };
}

/** F-f: a program that changes its own directory (git -C, make -C, npm --prefix...) for the rest of this command. */
function shiftCwd(c: Collector, raw: string): void {
  const r = resolvePath(raw, c.ctx);
  if (r === null) return;
  let cwd: string | null = r.exact && !r.glob ? r.abs : null;
  // SELF-016: the program changes directory itself, so `link/..` is the parent of where link points.
  if (cwd !== null && r.physical !== undefined && c.ctx.realpath !== undefined) {
    try {
      cwd = normalizeAbs(c.ctx.realpath(r.physical));
    } catch {
      cwd = null;
    }
  }
  c.ctx = cwd !== null ? { ...c.ctx, cwd, cwdKnown: true, cwdShifted: true } : { ...c.ctx, cwd: UNKNOWN_CWD, cwdKnown: false, cwdShifted: true };
}

/** FZ8/FZ10: every function the command line defines, in any form and anywhere (in if/for/case bodies, subshells, substitutions). */
function collectFunctions(script: Script, c: Collector): void {
  for (const cmd of allCommands(script)) {
    if (cmd.func === undefined || cmd.group === undefined) continue;
    c.functions ??= new Map();
    const bodies = c.functions.get(cmd.func) ?? [];
    if (!bodies.includes(cmd.group)) bodies.push(cmd.group);
    c.functions.set(cmd.func, bodies);
  }
}

const MAX_FUNCTION_CALLS = 64;

/**
 * FZ8/FZ10: a call to a function the command line defines is analysed as its body, at the call: in the
 * directory the call runs in. A recursive call is the body already being analysed; past a bound on calls
 * followed the command is unclassifiable (a person decides).
 */
function callFunction(name: string, bodies: readonly Script[], c: Collector, payload: string, depth: number): void {
  const active = (c.functionsActive ??= new Set());
  if (active.has(name)) return;
  c.functionCalls = (c.functionCalls ?? 0) + 1;
  if (c.functionCalls > MAX_FUNCTION_CALLS) {
    addFinding(c, "parse_failure", "the command calls shell functions too many times to follow");
    return;
  }
  const saved = { ctx: c.ctx, piped: c.stdinPiped, file: c.stdinFile, text: c.stdinText };
  active.add(name);
  try {
    for (const body of bodies) walkScript(body, startCwd(c.ctx.cwd, c.ctx.cwdKnown !== false), c, payload, depth, c.ctx);
  } finally {
    active.delete(name);
    c.ctx = saved.ctx;
    c.stdinPiped = saved.piped;
    c.stdinFile = saved.file;
    c.stdinText = saved.text;
  }
}

/**
 * SH1/SH3/SH9: command substitutions in a string, however it was quoted. bash runs a `$(...)` or `` `...` ``
 * in an unquoted here-document body (SH3) and in an arithmetic context such as an array subscript even when
 * the whole word was single-quoted (SH9: `let 'a[$(cmd)]'`), so those are not in the word's parsed `subs`.
 * `$((...))` is arithmetic, not a command, but may itself hold a `$(...)`, so it is scanned, not skipped.
 */
function extractSubsts(text: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (c === "`") {
      let j = i + 1;
      let inner = "";
      while (j < text.length && text[j] !== "`") {
        if (text[j] === "\\" && (text[j + 1] === "`" || text[j + 1] === "\\" || text[j + 1] === "$")) {
          inner += text[j + 1];
          j += 2;
        } else inner += text[j++];
      }
      if (inner !== "") out.push(inner);
      i = j;
    } else if (c === "$" && text[i + 1] === "(" && text[i + 2] === "(") {
      // Arithmetic: step over "$(" and keep scanning (a nested $(...) inside still counts).
      i += 1;
    } else if (c === "$" && text[i + 1] === "(") {
      let depth = 0;
      let j = i + 1;
      for (; j < text.length; j++) {
        if (text[j] === "(") depth++;
        else if (text[j] === ")" && --depth === 0) break;
      }
      const inner = text.slice(i + 2, j);
      if (inner !== "") out.push(inner);
      i = j;
    }
  }
  return out;
}

/** The substitutions inside every `[ ... ]` subscript of a word's text (bash evaluates a subscript arithmetically). */
function subscriptSubsts(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/\[([^\]]*)\]/g)) out.push(...extractSubsts(m[1] as string));
  return out;
}

/** Variables bound to literal values: `for f in *.ts`, `X=dist`, `read`-free loops only. */
function collectBindings(script: Script, c: Collector): void {
  const b = new Map<string, string[]>();
  // The values each name already has, so a long `for i in 1 2 3 ...` list is not searched again for every value.
  const valuesOf = new Map<string, Set<string>>();
  const add = (n: string, v: string): void => {
    let seen = valuesOf.get(n);
    if (seen === undefined) {
      seen = new Set();
      valuesOf.set(n, seen);
    }
    if (seen.has(v)) return;
    seen.add(v);
    const list = b.get(n) ?? [];
    list.push(v);
    b.set(n, list);
  };
  const poisoned = new Set<string>();
  for (const cmd of allCommands(script)) {
    const ws = cmd.words;
    if ((ws[0]?.text === "for" || ws[0]?.text === "select") && ws[2]?.text === "in" && ws[1] !== undefined) {
      const name = ws[1].text;
      const vals = ws.slice(3);
      if (vals.length === 0 || vals.some((w) => w.dynamic)) poisoned.add(name);
      else for (const w of vals) add(name, w.text);
    }
    for (const a of cmd.assigns) {
      if (a.value.dynamic) poisoned.add(a.name);
      else add(a.name, a.value.text);
    }
    // alias name='body' defined in the same command: its body is analysed when the name runs.
    if (ws[0]?.text === "alias") {
      for (const w of ws.slice(1)) {
        const m = /^([A-Za-z0-9_.:+@%-]+)=([\s\S]*)$/.exec(w.text);
        if (m !== null) {
          c.aliases ??= new Map();
          c.aliases.set(m[1] as string, m[2] as string);
        }
      }
    }
    // read, mapfile, getopts and for-without-in bind from input: unknown values.
    if (ws[0]?.text === "read" || ws[0]?.text === "mapfile" || ws[0]?.text === "readarray" || ws[0]?.text === "getopts") for (const w of ws.slice(1)) if (!w.text.startsWith("-")) poisoned.add(w.text);
    if (ws[0]?.text === "for" && ws[2]?.text !== "in" && ws[1] !== undefined) poisoned.add(ws[1].text);
  }
  for (const p of poisoned) b.delete(p);
  if (b.size > 0) c.bindings = b;
}

/** A secret read and network traffic in the same command line is a data flow out, whatever the order. */
function checkSecretFlow(c: Collector, from: number): void {
  const mine = c.effects.slice(from);
  const secretRead = mine.find((e) => e.cls === "read_secret" && !(e.tags ?? []).includes("env-var"));
  const out = mine.find((e) => (e.cls === "egress_send" || e.cls === "egress_fetch") && e.host !== undefined);
  if (secretRead !== undefined && out !== undefined) {
    addFinding(c, "secret_flow_in_command", `the same command reads ${secretRead.target} and contacts ${out.host ?? out.target}`);
  }
}

/** The escape sequences echo -e, printf's format and printf %b interpret. `octal0`: \0NNN (echo, %b) or \NNN (a format). */
function unescape(s: string, octal0: boolean): { text: string; stop: boolean } {
  let out = "";
  const simple: Record<string, string> = { a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v", "\\": "\\", '"': '"', "'": "'" };
  for (let i = 0; i < s.length; i++) {
    const ch = s[i] as string;
    if (ch !== "\\" || i + 1 >= s.length) {
      out += ch;
      continue;
    }
    const e = s[i + 1] as string;
    const rest = s.slice(i + 2);
    if (e === "c") return { text: out, stop: true };
    const named = own(simple, e);
    if (named !== undefined) {
      out += named;
      i++;
    } else if (e === "x" && /^[0-9a-fA-F]/.test(rest)) {
      const m = /^[0-9a-fA-F]{1,2}/.exec(rest) as RegExpExecArray;
      out += String.fromCharCode(parseInt(m[0], 16));
      i += 1 + m[0].length;
    } else if (octal0 && e === "0") {
      const m = /^[0-7]{0,3}/.exec(rest) as RegExpExecArray;
      out += String.fromCharCode(parseInt(m[0] === "" ? "0" : m[0], 8) & 0xff);
      i += 1 + m[0].length;
    } else if (!octal0 && /[0-7]/.test(e)) {
      const m = /^[0-7]{0,2}/.exec(rest) as RegExpExecArray;
      out += String.fromCharCode(parseInt(e + m[0], 8) & 0xff);
      i += 1 + m[0].length;
    } else out += ch;
  }
  return { text: out, stop: false };
}

const MAX_STATIC_OUTPUT = 64 * 1024;

/** What `printf FORMAT ARGS...` prints, or null when it uses a conversion this does not model. */
function printfOutput(fmt: string, args: readonly string[]): string | null {
  let out = "";
  let at = 0;
  for (let pass = 0; pass < 1024; pass++) {
    const startAt = at;
    for (let i = 0; i < fmt.length; i++) {
      const ch = fmt[i] as string;
      if (ch === "\\") {
        const m = /^\\(?:x[0-9a-fA-F]{1,2}|[0-7]{1,3}|.)/s.exec(fmt.slice(i)) as RegExpExecArray;
        const u = unescape(m[0], false);
        out += u.text;
        if (u.stop) return out;
        i += m[0].length - 1;
        continue;
      }
      if (ch !== "%") {
        out += ch;
        continue;
      }
      const m = /^%([-+ #0]*)(\d*)(?:\.(\d*))?([sbcdiouxX%])/.exec(fmt.slice(i));
      if (m === null) return null;
      i += m[0].length - 1;
      const conv = m[4] as string;
      if (conv === "%") {
        out += "%";
        continue;
      }
      const arg = args[at] ?? "";
      if (at < args.length) at++;
      let piece: string;
      if (conv === "s") piece = arg;
      else if (conv === "b") {
        const u = unescape(arg, true);
        if (u.stop) return out + u.text;
        piece = u.text;
      } else if (conv === "c") piece = arg.slice(0, 1);
      else {
        if (arg !== "" && !/^[+-]?\d+$/.test(arg)) return null;
        const n = arg === "" ? 0 : Number(arg);
        piece = conv === "x" ? n.toString(16) : conv === "X" ? n.toString(16).toUpperCase() : conv === "o" ? n.toString(8) : String(n);
      }
      if (m[3] !== undefined && (conv === "s" || conv === "b")) piece = piece.slice(0, Number(m[3] || "0"));
      const width = Number(m[2] || "0");
      if (piece.length < width) piece = (m[1] ?? "").includes("-") ? piece.padEnd(width) : piece.padStart(width);
      out += piece;
      if (out.length > MAX_STATIC_OUTPUT) return null;
    }
    // printf reuses its format while arguments remain (and a pass consumed some).
    if (at >= args.length || at === startAt) return out;
  }
  return null;
}

/**
 * What a pipeline stage prints when it is static text: echo or printf of literal words, or cat of a
 * here-document or a literal here-string. Every reading of it (echo interprets backslashes in some shells
 * and not in others), or null when its output is only known at run time.
 */
function staticOutput(cmd: SimpleCommand): string[] | null {
  if (cmd.group !== undefined) return null;
  if (cmd.redirects.some((r) => r.heredoc === undefined && r.op !== "<<<" && r.dup === undefined && (r.fd === null || r.fd === 1) && /^(?:>|>>|>\||&>|&>>|<|<>)$/.test(r.op))) return null;
  if (cmd.redirects.some((r) => r.dup !== undefined && (r.fd === null || r.fd === 1))) return null;
  const w0 = cmd.words[0];
  if (w0 === undefined || w0.dynamic) return null;
  const args = cmd.words.slice(1);
  if (args.some((a) => a.dynamic || a.subs.length > 0)) return null;
  if (w0.text === "echo") {
    let i = 0;
    let interpret = false;
    let newline = true;
    for (; i < args.length && /^-[neE]+$/.test((args[i] as Word).text); i++) {
      const f = (args[i] as Word).text;
      if (f.includes("n")) newline = false;
      if (f.includes("e")) interpret = true;
    }
    const raw = words(args.slice(i)).join(" ");
    const end = newline ? "\n" : "";
    if (!raw.includes("\\")) return [raw + end];
    const u = unescape(raw, true);
    const cooked = u.text + (u.stop ? "" : end);
    return interpret ? [cooked] : [raw + end, cooked];
  }
  if (w0.text === "printf") {
    const fmt = args[0];
    if (fmt === undefined || fmt.text.startsWith("-")) return null;
    const out = printfOutput(fmt.text, words(args.slice(1)));
    return out === null ? null : [out];
  }
  if (w0.text === "cat" && args.every((a) => a.text === "-")) {
    const doc = [...cmd.redirects].reverse().find((r) => r.heredoc !== undefined || r.op === "<<<");
    if (doc === undefined) return null;
    if (doc.heredoc !== undefined) return [doc.heredoc.body];
    if (doc.target === null || doc.target.dynamic || doc.target.subs.length > 0) return null;
    return [`${doc.target.text}\n`];
  }
  return null;
}

function analyzePipeline(pl: Pipeline, c: Collector, payload: string, depth: number): void {
  const kinds: StageKind[] = [];
  // The first stage reads whatever the enclosing command reads (`echo x | sh -c 'bash'`: the inner bash reads the pipe).
  const textBefore = c.stdinText;
  const pipedBefore = c.stdinPiped === true;
  pl.commands.forEach((cmd, i) => {
    const prev = pl.commands[i - 1];
    c.stdinPiped = prev !== undefined || pipedBefore;
    c.stdinText = prev === undefined ? textBefore : staticOutput(prev);
    try {
      kinds.push(analyzeCommand(cmd, c, payload, depth));
    } finally {
      c.stdinPiped = pipedBefore;
      c.stdinText = textBefore;
    }
  });
  // What a download writes to stdout and the pipeline saves to a file (curl ... > f, | tee f) is
  // downloaded content: reading it later is reading outside content, running it is untrusted code.
  const firstFetch = kinds.findIndex((k) => k.fetches);
  if (firstFetch !== -1) {
    pl.commands.slice(firstFetch).forEach((cmd) => {
      const targets: string[] = [];
      for (const r of cmd.redirects) if (r.target !== null && r.heredoc === undefined && /^(?:>|>>|>\||&>|&>>)$/.test(r.op) && (r.fd === null || r.fd === 1)) targets.push(r.target.text);
      if (basename(cmd.words[0]?.text ?? "") === "tee") for (const w of cmd.words.slice(1)) if (!w.text.startsWith("-")) targets.push(w.text);
      for (const t of targets) {
        const r = resolvePath(t, c.ctx);
        if (r !== null && !/^\/dev\//.test(r.abs)) addEffect(c, { cls: "write_workspace", target: r.abs, detail: `save downloaded content to ${r.abs}`, download: r.abs });
      }
    });
  }
  // Whether any stage before this one downloads or decodes, kept as it goes: copying the earlier stages for every
  // stage that runs its input was quadratic in a long pipeline.
  let fetched = false;
  let decoded = false;
  for (let i = 0; i < kinds.length; i++) {
    const k = kinds[i] as StageKind;
    if (i > 0 && k.runsStdin) {
      if (fetched) addFinding(c, "remote_code_pipe", "the command downloads code and runs it directly");
      else if (decoded) addFinding(c, "obfuscated_exec", "the command decodes hidden text and runs it as code");
    }
    fetched ||= k.fetches;
    decoded ||= k.decodes;
  }
}

function basename(t: string): string {
  const i = t.lastIndexOf("/");
  return i === -1 ? t : t.slice(i + 1);
}

function literal(w: Word): boolean {
  return !w.dynamic || /^(?:\$HOME|\$\{HOME\}|~)(?:\/[^$`]*)?$/.test(w.text);
}

function words(ws: readonly Word[]): string[] {
  return ws.map((w) => w.text);
}

/** Secret environment variables referenced by the command, recorded once. */
function secretVariables(cmd: SimpleCommand): string[] {
  const out = new Set<string>();
  const all = [...cmd.words, ...cmd.assigns.map((a) => a.value), ...cmd.redirects.flatMap((r) => (r.target === null ? [] : [r.target]))];
  for (const w of all) for (const v of w.vars) if (isCredentialVariable(v)) out.add(v);
  for (const r of cmd.redirects) {
    if (r.heredoc?.expand === true) for (const m of r.heredoc.body.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)/g)) if (isCredentialVariable(m[1] as string)) out.add(m[1] as string);
  }
  return [...out];
}

function analyzeCommand(cmd: SimpleCommand, c: Collector, payload: string, depth: number): StageKind {
  const ctxBefore = c.ctx;
  try {
    return analyzeCommandIn(cmd, c, payload, depth);
  } finally {
    // A directory flag (git -C, env --chdir...) applies to that command only.
    c.ctx = ctxBefore;
  }
}

function analyzeCommandIn(cmd: SimpleCommand, c: Collector, payload: string, depth: number): StageKind {
  const startEffects = c.effects.length;
  for (const a of cmd.assigns) {
    noteProxy(c, a.name, a.value.text);
    if (envInjects(a.name, a.value.text, c.state.tainted)) {
      addFinding(c, "env_injection", `sets ${a.name}, which changes what code the next program loads or runs`);
      addEffect(c, { cls: "execute_opaque", target: a.name, detail: `run a program with ${a.name} changed` });
    }
  }
  let heredoc: string | null = null;
  let computedStdin: Word | null = null;
  const stdinBefore = c.stdinFile;
  const textBefore = c.stdinText;
  c.stdinFile = undefined;
  for (const r of cmd.redirects) {
    if (r.heredoc !== undefined) {
      heredoc = r.heredoc.body;
      computedStdin = null;
      // SH3: an unquoted here-document's body is expanded, so a `$(...)` or `` `...` `` in it runs.
      if (r.heredoc.expand) for (const code of extractSubsts(r.heredoc.body)) analyzeShell(code, c, depth + 1);
      continue;
    }
    if (r.op === "<" && r.target !== null) c.stdinFile = r.target.text;
    if (r.op === "<<<") {
      // A here-string built at run time is not text the firewall can read as a script: a shell reading it
      // runs code only known at run time (its substitutions are analysed as commands of their own).
      if (r.target !== null && (!literal(r.target) || r.target.subs.length > 0)) {
        heredoc = null;
        computedStdin = r.target;
      } else {
        heredoc = r.target?.text ?? "";
        computedStdin = null;
      }
      continue;
    }
    if (r.target === null) continue;
    const t = r.target.text;
    const net = /^\/dev\/(tcp|udp)\/([^/]+)\/(\d+)/.exec(t);
    if (net !== null) {
      egress(c, `${net[2]}:${net[3]}`, "send", { payload, via: `a /dev/${net[1]} redirection` });
      continue;
    }
    if (r.op === "<") readPath(c, t, { via: "input redirection" });
    else if (r.op === "<>") {
      readPath(c, t);
      writePath(c, t, { via: "redirection" });
    } else writePath(c, t, { via: "output redirection" });
  }
  const vars = secretVariables(cmd);
  for (const v of vars) addEffect(c, { cls: "read_secret", target: `$${v}`, detail: `use the secret environment variable ${v}`, tags: ["env-var"], private: true });

  // F2: a here-document saved to a file (cat > p.diff <<EOF): a later `git apply p.diff` reads that text.
  if (heredoc !== null && /^(?:cat|tee)$/.test(basename(cmd.words[0]?.text ?? ""))) {
    const outs = cmd.redirects.filter((r) => r.target !== null && r.heredoc === undefined && /^(?:>|>>|>\|)$/.test(r.op)).map((r) => ({ t: (r.target as Word).text, append: r.op === ">>" }));
    if (basename(cmd.words[0]?.text ?? "") === "tee") for (const w of cmd.words.slice(1)) if (!w.text.startsWith("-")) outs.push({ t: w.text, append: cmd.words.some((x) => x.text === "-a" || x.text === "--append") });
    for (const o of outs) {
      const r = resolvePath(o.t, c.ctx);
      if (r === null) continue;
      c.heredocFiles ??= new Map();
      c.heredocFiles.set(r.abs, o.append || !r.exact ? null : heredoc);
    }
  }
  const pipedBefore = c.stdinPiped;
  if (computedStdin !== null) {
    // Standard input is a computed here-string: to a program reading it as code, like a pipe of run-time output.
    c.stdinText = null;
    c.stdinPiped = true;
    c.stdinFile = undefined;
  }
  let stage: StageKind;
  try {
    stage = dispatch(cmd.words, c, payload, depth, heredoc);
  } finally {
    c.stdinFile = stdinBefore;
    c.stdinText = textBefore;
    c.stdinPiped = pipedBefore;
  }
  if (computedStdin !== null && stage.runsStdin && hasFetcherInside([computedStdin])) addFinding(c, "remote_code_pipe", "the command runs what a download returns, given as a here-string");

  // A secret variable handed to network traffic that is not going to the service that issued it.
  if (vars.length > 0) {
    const out = c.effects.slice(startEffects).filter((e) => e.cls === "egress_send" || e.cls === "egress_fetch");
    for (const v of vars) {
      const issuers = variableIssuers(v);
      const bad = out.filter((e) => e.host === undefined || !issuers.some((i) => issuerMatches(e.host as string, i)));
      if (bad.length > 0) addFinding(c, "secret_env_in_egress", `sends $${v} to ${bad.map((e) => e.host ?? e.destination ?? e.target).join(", ")}`);
    }
  }
  return stage;
}

/** Resolves wrappers (sudo, env, timeout, xargs...) and dispatches on the real program. */
function dispatch(input: readonly Word[], c: Collector, payload: string, depth: number, stdin: string | null, runtimeIn?: RuntimePaths): StageKind {
  let ws = [...input];
  let viaXargs = false;
  let runtime = runtimeIn;
  for (let guard = 0; guard < 32; guard++) {
    while (ws.length > 0 && RESERVED.has((ws[0] as Word).text) && !(ws[0] as Word).quoted) {
      const kw = (ws.shift() as Word).text;
      // bash's `time` reserved word takes -p (and --) before the command it times.
      if (kw === "time") while (ws[0] !== undefined && !ws[0].quoted && (ws[0].text === "-p" || ws[0].text === "--")) ws.shift();
    }
    const w0 = ws[0];
    if (w0 === undefined) return NO_STAGE;
    if (!literal(w0) || (w0.glob && w0.text !== "[" && w0.text !== "[[")) {
      // A program name built at run time: $CMD, $(echo rm), "${X}", or a glob (/bin/r? -rf ~) that the shell expands.
      addFinding(c, "unresolvable_command", `the program to run is only known at run time: ${w0.text}`);
      addEffect(c, { cls: "execute_opaque", target: w0.text, detail: `run a program whose name is computed: ${w0.text}` });
      genericArgs(ws.slice(1), c, payload, "a computed command");
      return { fetches: true, decodes: true, runsStdin: true };
    }
    const name = basename(w0.text);
    const args = ws.slice(1);
    const alias = w0.quoted ? undefined : c.aliases?.get(w0.text);
    if (alias !== undefined) {
      analyzeShell(`${alias} ${words(args).join(" ")}`, c, depth + 1);
      return { fetches: true, decodes: true, runsStdin: true };
    }
    // FZ8/FZ10: a function this command line defines runs its body. The name is still judged as a program
    // below (a function can shadow one, and `command f` reaches the program): stricter, never looser.
    const bodies = w0.quoted || w0.text.includes("/") ? undefined : c.functions?.get(w0.text);
    if (bodies !== undefined) callFunction(w0.text, bodies, c, payload, depth);
    if (!w0.quoted && DATA_STARTERS.has(name) && !/\//.test(w0.text)) {
      if (name === "export" || name === "declare" || name === "typeset" || name === "local" || name === "readonly") {
        for (const a of args) {
          const m = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(a.text);
          if (m !== null) noteProxy(c, m[1] as string, a.text.slice(m[0].length));
          if (m !== null && envInjects(m[1] as string, a.text.slice(m[0].length), c.state.tainted)) {
            addFinding(c, "env_injection", `sets ${m[1]}, which changes what code later programs load or run`);
            addEffect(c, { cls: "execute_opaque", target: m[1] as string, detail: `change ${m[1]} for later programs` });
          }
        }
        if (args.length === 0 || args.some((a) => a.text === "-p")) bulkEnv(c, name);
      }
      if (name === "set" && args.length === 0) bulkEnv(c, "set");
      if (name === "trap") {
        // SH5: `trap [-options] 'handler' SIG...`: the handler is the first non-option word (a number or `-`
        // resets the trap and runs nothing). It is shell code, run when the signal fires.
        const handler = args.find((a) => !a.text.startsWith("-"));
        if (handler !== undefined && !/^(?:-|\d+)$/.test(handler.text)) analyzeShell(handler.text, c, depth + 1);
      }
      // SH6: `hash -p <path> <name>` makes a later `<name>` run `<path>`.
      if (name === "hash") {
        const pathAt = args.findIndex((a) => a.text === "-p");
        const file = args[pathAt + 1];
        const asName = args[pathAt + 2];
        if (pathAt !== -1 && file !== undefined && asName !== undefined && !file.dynamic && !asName.dynamic) {
          c.aliases ??= new Map();
          c.aliases.set(asName.text, file.text);
        }
      }
      // SH7: `jobs -x <cmd> <args>` runs the command (its %job arguments replaced first).
      if (name === "jobs") {
        const x = args.findIndex((a) => a.text === "-x");
        if (x !== -1 && args[x + 1] !== undefined) {
          dispatch(args.slice(x + 1), c, payload, depth, null);
          return NO_STAGE;
        }
      }
      // SH8: `mapfile`/`readarray -C <callback>` runs the callback (as `callback index line`) while it reads.
      if (name === "mapfile" || name === "readarray") {
        const cb = valueOf(args, "-C");
        if (cb !== undefined) analyzeShell(cb, c, depth + 1);
      }
      // SH19 (enable -f): loading a builtin from a shared object runs that object's code.
      if (name === "enable" && args.some((a) => a.text === "-f")) {
        const soAt = args.findIndex((a) => a.text === "-f");
        addEffect(c, { cls: "execute_opaque", target: args[soAt + 1]?.text ?? "enable -f", detail: "load a shell builtin from a shared object (its code runs)" });
      }
      // SH9: builtins that evaluate an arithmetic context run a `$(...)` in an array subscript (or, for let,
      // the whole expression) even when the argument was quoted, so those substitutions are analysed here.
      if (ARITH_BUILTINS.has(name)) {
        for (const a of args) {
          for (const code of subscriptSubsts(a.text)) analyzeShell(code, c, depth + 1);
          if ((name === "let" || name === "test" || name === "[" || name === "[[" || name === "]]") && a.quoted) for (const code of extractSubsts(a.text)) analyzeShell(code, c, depth + 1);
        }
      }
      return NO_STAGE;
    }
    switch (name) {
      case "sudo":
      case "doas":
      case "pkexec":
      case "run0": {
        addEffect(c, { cls: "privilege", target: name, detail: `run a command as another user with ${name}` });
        const p = wrapperArgs(args, own(WRAPPER_SPECS, name) as WrapperSpec);
        unknownOptions(c, name, p.unknown);
        for (const dir of values(p, "D", "chdir")) shiftCwd(c, dir);
        if (has(p, "s", "i", "shell", "login") && p.rest.length === 0) return { fetches: false, decodes: false, runsStdin: true };
        ws = p.rest;
        continue;
      }
      case "su": {
        addEffect(c, { cls: "privilege", target: name, detail: "switch user with su" });
        const p = parseArgs(args, { short: "csg", long: ["command", "shell", "group"] });
        for (const code of values(p, "c", "command")) analyzeShell(code, c, depth + 1);
        return p.opts.has("c") || p.opts.has("command") ? NO_STAGE : { ...NO_STAGE, runsStdin: true };
      }
      case "env": {
        const p = wrapperArgs(args, own(WRAPPER_SPECS, "env") as WrapperSpec);
        unknownOptions(c, name, p.unknown);
        for (const dir of values(p, "C", "chdir")) shiftCwd(c, dir);
        // `env -` is `env -i`; options end there.
        let after = p.rest;
        if (after[0]?.text === "-") after = after.slice(1);
        const split = values(p, "S", "split-string");
        if (split.length > 0) {
          analyzeShell(`${split.join(" ")} ${words(after).join(" ")}`, c, depth + 1);
          return NO_STAGE;
        }
        const rest: Word[] = [];
        let i = 0;
        for (; i < after.length; i++) {
          const t = (after[i] as Word).text;
          const m = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(t);
          if (m !== null) {
            noteProxy(c, m[1] as string, t.slice(m[0].length));
            if (envInjects(m[1] as string, t.slice(m[0].length), c.state.tainted)) {
              addFinding(c, "env_injection", `sets ${m[1]}, which changes what code the next program loads or runs`);
              addEffect(c, { cls: "execute_opaque", target: m[1] as string, detail: `run a program with ${m[1]} changed` });
            }
            continue;
          }
          break;
        }
        rest.push(...after.slice(i));
        if (rest.length === 0) {
          bulkEnv(c, "env");
          return NO_STAGE;
        }
        ws = rest;
        continue;
      }
      case "printenv":
        if (args.length === 0) bulkEnv(c, "printenv");
        else for (const a of args) if (isCredentialVariable(a.text)) addEffect(c, { cls: "read_secret", target: `$${a.text}`, detail: `print the secret environment variable ${a.text}`, private: true });
        return NO_STAGE;
      case "nice":
      case "nohup":
      case "time":
      case "builtin":
      case "exec":
      case "stdbuf":
      case "ionice":
      case "unbuffer":
      case "nocorrect":
      case "noglob":
      case "caffeinate":
      case "chrt":
      case "taskset":
      case "setsid":
      case "strace":
      case "ltrace":
      case "dtruss":
      case "valgrind":
      case "catchsegv":
      case "torsocks":
      case "proxychains":
      case "proxychains4":
      case "arch":
      case "rlwrap":
      case "chronic":
      case "systemd-run":
      case "command": {
        // 7-9: each wrapper's own options (and their values) are skipped, so the program it runs is the one
        // analysed; an option it does not have makes the program uncertain (opaque), never the program's name.
        let rest: Word[];
        if (name === "arch") rest = archArgs(args, c);
        else if (name === "valgrind") {
          const at = args.findIndex((a) => !a.text.startsWith("-"));
          rest = at === -1 ? [] : args.slice(at);
        } else {
          const p = wrapperArgs(args, own(WRAPPER_SPECS, name) as WrapperSpec);
          unknownOptions(c, name, p.unknown);
          rest = p.rest;
          // A lookup (command -v), or a change to processes already running (ionice -p, chrt -p, taskset -p): nothing new runs.
          if (name === "command" && has(p, "v", "V")) return NO_STAGE;
          if ((name === "ionice" && has(p, "p", "P", "u", "pid", "pgid", "uid")) || ((name === "chrt" || name === "taskset") && has(p, "p", "pid")) || (name === "chrt" && has(p, "m", "max"))) return NO_STAGE;
          // chrt's priority and taskset's mask or CPU list come before the program.
          if (name === "chrt" && /^\d+$/.test(rest[0]?.text ?? "")) rest = rest.slice(1);
          if (name === "taskset") rest = rest.slice(1);
        }
        if (rest.length === 0) return NO_STAGE;
        ws = rest;
        continue;
      }
      case "-": {
        // SH19: zsh's `-` precommand modifier runs the rest as a command (with a login-shell argv0).
        if (args.length === 0) return NO_STAGE;
        ws = args;
        continue;
      }
      case "timeout":
      case "gtimeout": {
        const p = wrapperArgs(args, own(WRAPPER_SPECS, "timeout") as WrapperSpec);
        unknownOptions(c, name, p.unknown);
        // The duration comes before the program.
        ws = p.rest.slice(1);
        continue;
      }
      case "flock": {
        const p = parseArgs(args, { short: "wEc", long: ["timeout", "conflict-exit-code", "command"], stopAtPositional: true });
        for (const code of values(p, "c", "command")) analyzeShell(code, c, depth + 1);
        ws = p.positionals.slice(1);
        continue;
      }
      case "watch": {
        const p = parseArgs(args, { short: "nd", long: ["interval", "differences"], stopAtPositional: true });
        analyzeShell(words(p.positionals).join(" "), c, depth + 1);
        return NO_STAGE;
      }
      case "xargs": {
        const p = wrapperArgs(args, own(WRAPPER_SPECS, "xargs") as WrapperSpec);
        unknownOptions(c, name, p.unknown);
        for (const f of values(p, "a", "arg-file")) readPath(c, f, { via: "xargs" });
        if (p.rest.length === 0) return NO_STAGE;
        ws = p.rest;
        viaXargs = true;
        // 10-11: xargs appends the paths it reads, or puts them where -I/-J/-i/--replace's string is.
        const repl = [...values(p, "I", "J"), ...values(p, "i", "replace").map((v) => (v === "" ? "{}" : v))].pop();
        runtime = { replace: repl === undefined ? null : new RegExp(escapeRegExp(repl), "g"), append: repl === undefined };
        continue;
      }
      case "parallel": {
        // GNU parallel runs its command through a shell once per input, the input (quoted) at each
        // replacement string or appended. Inputs after ::: are literal; from stdin or a file (::::, -a)
        // they are known only at run time. With no command, each input is itself a command.
        const p = wrapperArgs(args, own(WRAPPER_SPECS, "parallel") as WrapperSpec);
        unknownOptions(c, name, p.unknown);
        for (const f of values(p, "a", "arg-file")) readPath(c, f, { via: "parallel" });
        const sep = p.rest.findIndex((a) => /^::::?\+?$/.test(a.text));
        const cmdWords = words(sep === -1 ? p.rest : p.rest.slice(0, sep));
        const sources = sep === -1 ? [] : p.rest.slice(sep + 1);
        const literalItems = sep !== -1 && p.rest[sep]?.text === ":::" && !has(p, "a", "arg-file") && sources.every((a) => literal(a) && a.subs.length === 0 && !/^::::?\+?$/.test(a.text)) ? sources.slice(0, 64).map((a) => a.text) : null;
        const quote = (s: string): string => `'${s.replace(/'/g, "'\\''")}'`;
        if (cmdWords.length === 0) {
          if (literalItems !== null) for (const it of literalItems) analyzeShell(it, c, depth + 1);
          else return stdinScript(name, c, depth, stdin);
          return NO_STAGE;
        }
        const placeholder = /\{(?:\/\/?|\.|\/\.|#|%|\d+)?\}/g;
        const hasPlaceholder = cmdWords.some((t) => new RegExp(placeholder.source).test(t));
        const acts = cmdWords.some((t) => actsOnPaths(basename(t)));
        const build = (item: string): string => {
          const parts = cmdWords.map((t) => t.replace(placeholder, () => item));
          return (hasPlaceholder ? parts : [...parts, item]).join(" ");
        };
        if (literalItems !== null) for (const it of literalItems.length > 0 ? literalItems : [""]) analyzeShell(build(quote(it)), c, depth + 1);
        else analyzeShell(acts ? build('"$1"') : cmdWords.join(" "), c, depth + 1);
        return { ...NO_STAGE, runsStdin: true };
      }
      case "script": {
        // Linux: script [-c cmd] [file]. BSD/macOS: script [-adkpqr] [-t time] [-F pipe] [file [command ...]].
        // Either way the inner command runs (in a pseudo-terminal), so it is analysed like any other.
        const spec = { short: "cTEIOBtF", long: ["command", "timing", "log-in", "log-out", "log-io", "log-timing", "output-limit"] };
        const p = parseArgs(args, spec);
        for (const code of values(p, "c", "command")) analyzeShell(code, c, depth + 1);
        if (has(p, "c", "command")) return NO_STAGE;
        // BSD form: options end at the file; everything after it is the command with its own flags
        // (parsing on would swallow them: `script -q f launchsafe-firewall doctor --fix`).
        const bsd = parseArgs(args, { ...spec, stopAtPositional: true });
        if (bsd.positionals.length >= 2) {
          ws = bsd.positionals.slice(1);
          continue;
        }
        return { ...NO_STAGE, runsStdin: true };
      }
      case "expect": {
        // expect -c 'spawn ...' or an expect script: the spawned commands run; the rest is opaque.
        const p = parseArgs(args, { short: "cfbD", long: [] });
        const code = values(p, "c").join("\n");
        addEffect(c, { cls: "execute_opaque", target: "expect", detail: "run an expect script" });
        if (code !== "") {
          inlineCode("expect", code, c, payload, INLINE_HOOKS);
          for (const m of code.matchAll(/\bspawn\s+(?:-\w+\s+)*([^\n;\]]+)/g)) analyzeShell(m[1] as string, c, depth + 1);
        }
        for (const f of [...values(p, "f"), ...p.positionals.slice(0, 1).map((w) => w.text)]) executeFile(c, f, "expect");
        return NO_STAGE;
      }
      case "repeat": {
        // zsh: repeat N command.
        ws = args.slice(1);
        continue;
      }
      case "faketime": {
        const rest = args.filter((a) => !a.text.startsWith("-"));
        ws = rest.slice(1);
        continue;
      }
      default:
        return program(name, w0, runtime === undefined ? args : runtimeArgs(name, args, runtime), c, payload, depth, stdin, viaXargs);
    }
  }
  addFinding(c, "parse_failure", "too many nested command wrappers");
  return NO_STAGE;
}

/**
 * 10-11: how xargs, find -exec / -execdir / -ok, fd -x and parallel hand paths to the program they run. The
 * paths are known only at run time; `replace` marks where they go (find's `{}`, xargs -I R), `append` adds
 * one at the end when no replacement is given (xargs, fd). `fallback` is what a replacement reads as for a
 * program that neither deletes nor runs code (find's search root, as before).
 */
interface RuntimePaths {
  replace: RegExp | null;
  append: boolean;
  fallback?: string;
}

/** A path known only at run time, as a word: dynamic, so a recursive delete of it is judged like `rm -rf "$X"`. */
const RUNTIME_PATH = "$<run-time path>";
const runtimeWord = (): Word => ({ text: RUNTIME_PATH, dynamic: true, glob: false, quoted: true, subs: [], vars: [] });
const DELETERS = new Set(["rm", "rmdir", "unlink", "shred", "srm", "trash", "wipe"]);

/** Programs that delete or run what they are given: on run-time paths, the paths are unknown. */
function actsOnPaths(name: string): boolean {
  return DELETERS.has(name) || SHELLS.has(name) || (INTERPRETERS.has(name) && name !== "awk" && name !== "gawk") || name === "source" || name === ".";
}

function runtimeArgs(name: string, args: readonly Word[], rt: RuntimePaths): Word[] {
  const acts = actsOnPaths(name);
  let replaced = false;
  const out = args.map((w) => {
    if (rt.replace === null) return w;
    rt.replace.lastIndex = 0;
    if (!rt.replace.test(w.text)) return w;
    replaced = true;
    if (acts) return { ...w, text: w.text.replace(rt.replace, () => RUNTIME_PATH), dynamic: true };
    return rt.fallback !== undefined ? { ...w, text: w.text.replace(rt.replace, () => rt.fallback as string) } : w;
  });
  // A shell or interpreter that already has its script or code takes the run-time path as an argument of
  // that script, not as code to run; a deleter always deletes it.
  const scriptGiven = !DELETERS.has(name) && args.some((a) => !a.text.startsWith("-"));
  if (acts && rt.append && !replaced && !scriptGiven) out.push(runtimeWord());
  return out;
}

const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** 7-9: the options each command wrapper takes before the program it runs (GNU, BSD and macOS forms). */
const WRAPPER_SPECS: Record<string, WrapperSpec> = {
  xargs: { flags: "0oprtx", values: "adEILnPsJRS", optional: "eil", longFlags: ["null", "open-tty", "interactive", "no-run-if-empty", "show-limits", "verbose", "exit", "help", "version"], longValues: ["arg-file", "delimiter", "max-args", "max-procs", "max-chars", "process-slot-var"], longOptional: ["eof", "replace", "max-lines"] },
  nice: { values: "n", numeric: true, longValues: ["adjustment"], longFlags: ["help", "version"] },
  nohup: { longFlags: ["help", "version"] },
  parallel: { flags: "0kquvmXrtpgGHZe", values: "jadEIJSnNLsC", longFlags: ["null", "keep-order", "quote", "verbose", "ungroup", "dry-run", "no-run-if-empty", "tag", "progress", "bar", "eta", "line-buffer", "group", "xargs", "pipe", "shuf", "help", "version"], longValues: ["jobs", "arg-file", "delimiter", "colsep", "sshlogin", "max-args", "max-replace-args", "max-lines", "timeout", "joblog", "results", "tmpdir", "workdir", "tagstring", "halt", "retries", "delay", "memfree", "load", "block", "env", "eof", "replace"] },
  time: { flags: "pvaqlh", values: "of", longFlags: ["portability", "verbose", "append", "quiet", "help", "version"], longValues: ["output", "format"] },
  builtin: {},
  command: { flags: "pvV" },
  exec: { flags: "cl", values: "a" },
  stdbuf: { values: "ioe", longValues: ["input", "output", "error"], longFlags: ["help", "version"] },
  ionice: { flags: "tpPu", values: "cn", longFlags: ["ignore", "pid", "pgid", "uid", "help", "version"], longValues: ["class", "classdata"] },
  chrt: { flags: "abdfimoprRv", values: "TPD", longFlags: ["all-tasks", "batch", "deadline", "fifo", "idle", "max", "other", "pid", "rr", "reset-on-fork", "verbose", "help", "version"], longValues: ["sched-runtime", "sched-period", "sched-deadline"] },
  taskset: { flags: "acp", longFlags: ["all-tasks", "cpu-list", "pid", "help", "version"] },
  setsid: { flags: "cfw", longFlags: ["ctty", "fork", "wait", "help", "version"] },
  caffeinate: { flags: "dimsu", values: "tw" },
  unbuffer: { flags: "p" },
  nocorrect: {},
  noglob: {},
  catchsegv: {},
  strace: { flags: "cCdDfFhiknqrtTvVwxyzZ", values: "abeEIoOpPsSuUX", longValues: ["output", "trace", "signal", "status", "attach", "user", "env", "string-limit"], longFlags: ["follow-forks", "summary-only", "help", "version"] },
  ltrace: { flags: "bcCdfhiLrStTV", values: "aeEFlnopsSuAwx", longValues: ["output", "library", "align", "indent"], longFlags: ["demangle", "help", "version"] },
  dtruss: { flags: "acdeflLoOsZ", values: "pntW" },
  torsocks: { flags: "idq6h", values: "upaP", longFlags: ["isolate", "debug", "quiet", "shell", "help", "version"], longValues: ["user", "pass", "address", "port"] },
  proxychains: { flags: "q", values: "f" },
  proxychains4: { flags: "q", values: "f" },
  rlwrap: { flags: "cinNoUvWrRIh", values: "bCDefgHlMOPqsStwz", optional: "amp" },
  chronic: { flags: "ev" },
  "systemd-run": { flags: "tPqGdSrh", values: "upEHM", longFlags: ["user", "system", "scope", "remain-after-exit", "send-sighup", "pty", "pipe", "quiet", "wait", "collect", "no-block", "no-ask-password", "shell", "same-dir", "help", "version"], longValues: ["unit", "property", "description", "slice", "uid", "gid", "nice", "working-directory", "setenv", "on-active", "on-boot", "on-startup", "on-unit-active", "on-unit-inactive", "on-calendar", "timer-property", "path-property", "socket-property", "machine", "host", "service-type"] },
  timeout: { flags: "v", values: "sk", longFlags: ["preserve-status", "foreground", "verbose", "help", "version"], longValues: ["signal", "kill-after"] },
  env: { flags: "i0v", values: "uCSPa", longFlags: ["ignore-environment", "null", "debug", "list-signal-handling", "help", "version"], longValues: ["unset", "chdir", "split-string", "argv0"], longOptional: ["default-signal", "ignore-signal", "block-signal"] },
  sudo: { flags: "AbEeHiKklnPSsVvBN", values: "ugCDhprtUTR", longFlags: ["askpass", "background", "bell", "edit", "set-home", "login", "remove-timestamp", "reset-timestamp", "list", "non-interactive", "preserve-groups", "stdin", "shell", "version", "validate", "help"], longValues: ["user", "group", "close-from", "chdir", "host", "prompt", "role", "type", "other-user", "command-timeout", "chroot"], longOptional: ["preserve-env"] },
  doas: { flags: "Lns", values: "uaC" },
  pkexec: { longFlags: ["disable-internal-agent", "keep-cwd", "help", "version"], longValues: ["user"] },
  run0: { flags: "iqvhV", values: "ugD", longFlags: ["slice-inherit", "no-ask-password", "pty", "pipe", "via-shell", "empower", "lightweight", "help", "version"], longValues: ["user", "group", "nice", "chdir", "setenv", "unit", "property", "description", "slice", "machine", "background", "area", "shell-prompt-prefix"] },
};
WRAPPER_SPECS.gtimeout = WRAPPER_SPECS.timeout as WrapperSpec;

/** A wrapper given an option it does not have: which program it runs is uncertain (opaque). */
function unknownOptions(c: Collector, name: string, unknown: readonly string[]): void {
  if (unknown.length === 0) return;
  addEffect(c, { cls: "execute_opaque", target: name, detail: `run ${name} with an option the firewall does not know (${unknown.slice(0, 3).join(" ")}), so the program it runs is uncertain` });
}

/** macOS arch: `-x86_64`, `-arm64`, `-arch NAME`, `-e VAR=value`, `-d VAR`, `-32`, `-64`, `-c` before the program. */
function archArgs(args: readonly Word[], c: Collector): Word[] {
  for (let i = 0; i < args.length; i++) {
    const t = (args[i] as Word).text;
    if (t === "--") return args.slice(i + 1);
    if (/^-(?:arch|e|d)$/.test(t)) {
      i++;
      continue;
    }
    if (/^-(?:x86_64h?|arm64e?|i386|ppc|32|64|c|h)$/.test(t)) continue;
    if (t.startsWith("-")) {
      unknownOptions(c, "arch", [t]);
      continue;
    }
    return args.slice(i);
  }
  return [];
}

/**
 * F4: a proxy variable (https_proxy=..., export ALL_PROXY=...) sends every later request of the
 * fetchers through that host, so the proxy is a destination of each request, whatever the URL says.
 * It is kept for the rest of the command line (stricter than the shell, never looser).
 */
const PROXY_VAR = /^(?:https?|all|ftp|wss?)_proxy$/i;
function noteProxy(c: Collector, name: string, value: string): void {
  if (!PROXY_VAR.test(name) || value.trim() === "") return;
  c.proxies ??= [];
  if (!c.proxies.includes(value)) c.proxies.push(value);
}

/** F4: the Docker, containerd and Podman API sockets: a request there can start a privileged container. */
const CONTAINER_SOCKET = /(?:^|\/)(?:docker|containerd|podman|dockershim|cri-dockerd|crio)\.sock$/i;

function bulkEnv(c: Collector, via: string): void {
  addEffect(c, { cls: "read_secret", target: "environment", detail: `print every environment variable (${via}), which includes credentials`, private: true, tags: ["bulk-env"] });
}

/** Paths and URLs in arguments of a program the analyzer has no model for. */
function genericArgs(args: readonly Word[], c: Collector, payload: string, via: string): void {
  for (const a of args) {
    const t = a.text.replace(/^--?[A-Za-z0-9-]+=/, "");
    if (/^(?:https?|wss?|ftp):\/\//i.test(t)) {
      egress(c, t, "send", { payload, via });
      continue;
    }
    if (/^(?:\/|~\/|\$HOME\/|\$\{HOME\}\/|\.\.?\/)/.test(t) || /(?:^|\/)\.(?:claude|cursor|mcp\.json|ssh|aws|env\b)/.test(t) || /(?:^|\/)(?:CLAUDE|AGENTS|MEMORY|GEMINI)\.md$/i.test(t)) {
      const r = resolvePath(t, c.ctx);
      if (r === null) continue;
      // An unknown program may write any path it is given: judge protected and firewall paths as writes.
      readPath(c, t, { via });
      // Keep the write effect only when it is a protected, persistence or firewall write; plain paths stay reads.
      // The write is judged on a copy of the collector with empty lists and only what is kept is added to the real
      // one: taking effects back out of its list made the duplicate index rebuild for every argument, which is
      // quadratic in a command that names thousands of paths (a program with no model, given a file list).
      const probe = { ...c, effects: [] as typeof c.effects, findings: [] as typeof c.findings };
      writePath(probe, t, { via });
      for (const e of probe.effects) if (e.cls !== "write_workspace" && e.cls !== "write_outside_workspace") addEffect(c, e);
      // A word written out literally (in quotes, say) is not a path "only known at run time", so this write's finding
      // is dropped. Only this one: the same text written elsewhere in the line (`> ./$D`, or the word unquoted) is
      // only known at run time there, and withdrawing that finding too let the line run without a person.
      for (const f of probe.findings) if (!(f.id === "unresolvable_write_target" && f.detail.includes(a.text) && !a.dynamic)) addFinding(c, f.id, f.detail);
    }
  }
}

function hasFetcherInside(args: readonly Word[]): boolean {
  return args.some((a) => a.subs.some((s) => allPipelines(s).some((pl) => pl.commands.some((cmd) => cmd.words.length > 0 && NETWORK_FETCHERS.has(basename((cmd.words[0] as Word).text))))));
}

const VAULT_STORE_TOOLS: ReadonlySet<string> = new Set(["security", "secret-tool", "keyctl"]);

/** `security` subcommands that read, change or delete an item's secret, selected by its attributes. */
const SECURITY_ITEM_CMDS: ReadonlySet<string> = new Set(["find-generic-password", "find-internet-password", "delete-generic-password", "delete-internet-password", "set-generic-password-partition-list", "set-internet-password-partition-list"]);
/** `security` options that take a value (so the subcommand is the first word that is neither). */
const SECURITY_GLOBAL_OPTS: ReadonlySet<string> = new Set(["-p", "--prompt"]);

/**
 * Why a secret store's own tool reaches the vault's items, or null. The vault's values live under
 * the identity's service name ("launchsafe-firewall"), with the account "<name>:<field>" and a label naming
 * the firewall. Naming the service or the label reaches them; so does a lookup that does not say which service
 * it means (an account-only or label-only query matches the vault's items too, and account names are listed by
 * `vault list`), a service the analyzer cannot read, `security dump-keychain -d` (every item's secret) and
 * `security -i` reading commands it cannot see.
 */
function vaultStoreAccess(name: string, args: readonly Word[], c: Collector, stdin: string | null): string | null {
  const services = identityOf(c.ctx).vaultServices ?? [];
  const names = (t: string): boolean => services.some((s) => t.toLowerCase().includes(s.toLowerCase())) || /launchsafe[ _-]?firewall/i.test(t);
  if (args.some((a) => names(a.text))) return `use ${name} on the firewall's vault in the system keychain`;
  if (name === "security") {
    const sub = args.find((a, i) => !a.text.startsWith("-") && !SECURITY_GLOBAL_OPTS.has(args[i - 1]?.text ?? ""));
    if (args.some((a) => a.text === "-i" || a.text === "--interactive") && sub === undefined) {
      if (stdin === null) return "run security's interactive mode on commands the firewall cannot see (they could read the vault's items)";
      for (const line of stdin.split("\n")) {
        const t = line.trim();
        if (t === "" || t.startsWith("#")) continue;
        const why = vaultStoreAccess("security", t.split(/\s+/).map((x) => ({ text: x, dynamic: false }) as Word), c, null);
        if (why !== null) return why;
      }
      return null;
    }
    if (sub === undefined) return null;
    if (sub.text === "dump-keychain" && args.some((a) => /^-[a-z]*d[a-z]*$/.test(a.text))) return "dump every keychain item's secret, the vault's included, with security dump-keychain -d";
    if (!SECURITY_ITEM_CMDS.has(sub.text)) return null;
    const at = args.findIndex((a) => a.text === "-s");
    if (at === -1) return `${sub.text} without -s: an account- or label-only query also matches the vault's items`;
    const value = args[at + 1];
    if (value === undefined || !literal(value)) return `${sub.text} with a service the firewall cannot read (it could be the vault's)`;
    return null;
  }
  if (name === "secret-tool") {
    const rest = args.filter((a) => !a.text.startsWith("-"));
    const sub = rest[0]?.text;
    if (sub !== "lookup" && sub !== "search" && sub !== "clear") return null;
    const attrs = rest.slice(1);
    const at = attrs.findIndex((a, i) => i % 2 === 0 && a.text === "service");
    if (at === -1) return `secret-tool ${sub} without a service attribute: it also matches the vault's items`;
    const value = attrs[at + 1];
    if (value === undefined || !literal(value)) return `secret-tool ${sub} with a service the firewall cannot read (it could be the vault's)`;
    return null;
  }
  return null;
}

/** The scratch allowlist and protected branches the catastrophic tables read. */
function catastropheOptions(c: Collector): CatastropheOptions {
  return { ...(c.ctx.scratchTargets !== undefined ? { scratch: c.ctx.scratchTargets } : {}), ...(c.cfg.protectedBranches !== undefined ? { protectedBranches: c.cfg.protectedBranches } : {}) };
}

/**
 * The catastrophic class (src/engine/catastrophic.ts): a deny is a finding the engine denies whatever the
 * session; an ask (a targeted teardown, a scratch target, a verb known only at run time) is an ordinary
 * destructive action a person may approve.
 */
function noteJudgement(c: Collector, j: Judgement | null, target: string): void {
  if (j === null) return;
  if (j.level === "deny") addFinding(c, "catastrophic", j.reason);
  else addEffect(c, { cls: "destructive", target, detail: j.reason });
}

function noteCatastrophic(c: Collector, name: string, args: readonly Word[]): void {
  noteJudgement(c, judgeCommand(name, args.map((a) => ({ text: a.text, dynamic: a.dynamic })), catastropheOptions(c)), name);
}

function program(name: string, w0: Word, args: readonly Word[], c: Collector, payload: string, depth: number, stdin: string | null, viaXargs: boolean): StageKind {
  noteCatastrophic(c, name, args);
  // F4/F-c: the firewall's installed CLI, however it is reached (its command name, node on its CLI file,
  // npx/dlx/bunx of the package, a symlink or path whose realpath is its CLI file).
  const fwArgs = firewallInvocation(c, name, w0, args);
  if (fwArgs !== null) {
    const pos = fwArgs.filter((a) => !a.text.startsWith("-")).map((a) => a.text);
    const sub = pos[0] ?? "";
    const sub2 = pos[1] ?? "";
    // F-a: the read-only list is derived from the CLI's declared commands (a new subcommand is
    // state-changing unless declared otherwise); any --help is read-only; doctor --fix is not.
    const readOnly = fwArgs.every((a) => !a.dynamic || a.text === "--") && isReadOnlyInvocation(fwArgs.map((a) => a.text));
    if (!readOnly) {
      addEffect(c, { cls: "firewall_tamper", target: w0.text, detail: `run the firewall's own command "${`${sub} ${sub2}`.trim()}" to change it` });
      return NO_STAGE;
    }
    // I1: a read-only command runs unjudged because it is the firewall's own CLI. A path that only folds to an
    // installed file's name is another program on a case-sensitive disk: it is judged as the program it is.
    if (c.ctx.caseInsensitive === PROTECTION_FOLDS_CASE || firewallInvocation(c, name, w0, args, c.ctx.caseInsensitive) !== null) return NO_STAGE;
  }
  // A program inside the firewall's data directory (the browser link's launcher, docs/browser-link.md) is the
  // firewall's: run by an agent, it could pose as the browser to the firewall.
  const script = SHELLS.has(name) ? args.find((a) => !a.text.startsWith("-")) : undefined;
  if ((w0.text.includes("/") && namesFirewallData(c, w0.text)) || (script !== undefined && namesFirewallData(c, script.text))) {
    addEffect(c, { cls: "firewall_tamper", target: w0.text, detail: "run a program inside the firewall's data directory" });
    return NO_STAGE;
  }
  if (/^(?:pkill|killall|kill)$/.test(name) && args.some((a) => namesHookProcess(c, a.text))) {
    addEffect(c, { cls: "firewall_tamper", target: name, detail: "stop the firewall's processes" });
    return NO_STAGE;
  }
  // F-c: a copy of the data directory carries the encrypted approver key and the log signing key.
  if (FIREWALL_COPIERS.has(name) && args.some((a) => namesFirewallData(c, a.text))) {
    addEffect(c, { cls: "firewall_tamper", target: name, detail: `copy or move the firewall's data directory (its keys and approvals) with ${name}` });
  }
  // The vault's values live in the system keychain under the identity's service name;
  // reading, changing or deleting them with the store's own tools is the firewall's data, like its home.
  if (VAULT_STORE_TOOLS.has(name)) {
    const why = vaultStoreAccess(name, args, c, stdin);
    if (why !== null) {
      addEffect(c, { cls: "firewall_tamper", target: name, detail: why });
      return NO_STAGE;
    }
  }
  if (args.some((a) => /disableAllHooks|allowManagedHooksOnly/.test(a.text))) {
    addFinding(c, "hook_disable", "the command changes whether hooks run");
    addEffect(c, { cls: "firewall_tamper", target: name, detail: "turn hooks off" });
  }

  if (AGENT_CLIS.has(name)) return agentCli(name, args, c, depth);
  // GW12: an agent CLI run through a package runner is judged as that agent too (its `mcp remove` of a
  // wrapped server is FW-TAMPER), on top of what running the package is.
  {
    let runnerArgs: readonly Word[] | null = PACKAGE_RUNNERS.has(name) ? args : null;
    if (name === "npm" || name === "pnpm" || name === "yarn" || name === "bun") {
      const verbAt = args.findIndex((a) => !a.text.startsWith("-"));
      if (verbAt !== -1 && /^(?:exec|x|dlx)$/.test((args[verbAt] as Word).text)) runnerArgs = args.slice(verbAt + 1);
    }
    const agent = runnerArgs !== null ? agentViaRunner(runnerArgs) : null;
    if (agent !== null) agentCli(agent.cli, agent.rest, c, depth);
  }
  if (SHELLS.has(name)) return shellProgram(name, args, c, payload, depth, stdin, viaXargs);
  if (INTERPRETERS.has(name) && !(name === "awk" || name === "gawk")) return interpreter(name, args, c, payload, depth, stdin);
  if (name === "eval") {
    const code = words(args).join(" ");
    if (args.every(literal)) analyzeShell(code, c, depth + 1);
    else {
      addFinding(c, "obfuscated_exec", "eval runs text that is only known at run time");
      addEffect(c, { cls: "execute_opaque", target: "eval", detail: "run computed text with eval" });
      if (hasFetcherInside(args)) addFinding(c, "remote_code_pipe", "eval runs what a download returns");
    }
    return NO_STAGE;
  }
  if (name === "source" || name === ".") {
    const f = args[0];
    if (f === undefined) return { ...NO_STAGE, runsStdin: true };
    if (f.text === "/dev/stdin" || f.text === "-") return stdinScript(name, c, depth, stdin);
    if (f.subs.length > 0) {
      // Like `bash <(...)`: the script is what a command prints.
      if (hasFetcherInside([f])) addFinding(c, "remote_code_pipe", `${name} runs a script straight from a download`);
      addEffect(c, { cls: "execute_opaque", target: name, detail: `${name} a script a command produces` });
      return NO_STAGE;
    }
    if (!literal(f)) {
      addEffect(c, { cls: "execute_opaque", target: f.text, detail: `${name} a file whose path is only known at run time: ${f.text}` });
      return NO_STAGE;
    }
    executeFile(c, f.text, "source");
    return NO_STAGE;
  }
  // A command given by path (/bin/rm, ./node_modules/.bin/x): if its base name is a program the
  // analyzer models, use that model; otherwise run it as a file.
  if (w0.text.includes("/") && !KNOWN_BY_BASENAME.has(name)) {
    executeFile(c, w0.text, "run");
    // G2: a build or task runner started by path (./gradlew, ./mvnw, bin/rails, node_modules/.bin/vitest)
    // runs the same definition files as when started by name.
    runsManifest(c, name);
    genericArgs(args, c, payload, w0.text);
    return NO_STAGE;
  }
  if (SEARCHERS.has(name)) return searcher(name, args, c);
  if (name === "find" || name === "fd" || name === "fdfind" || name === "locate" || name === "mdfind") return finder(name, args, c, payload, depth);
  if (name === "sed" || name === "gsed" || name === "perl") {
    const p = parseArgs(args, { short: name === "perl" ? "eEIlMm" : "efl", long: ["expression", "file", "line-length"] });
    const inPlace = [...p.opts.keys()].some((k) => k === "i" || k.startsWith("in-place")) || args.some((a) => /^-[a-zA-Z]*i/.test(a.text) && name === "perl" && /p|n/.test(a.text));
    if (name === "perl" && has(p, "e", "E")) return interpreter(name, args, c, payload, depth, stdin);
    const files = name === "sed" || name === "gsed" ? (has(p, "e", "expression", "f", "file") ? p.positionals : p.positionals.slice(1)) : p.positionals;
    for (const f of values(p, "f", "file")) readPath(c, f, { via: name });
    for (const f of files) {
      readPath(c, f.text, { via: name });
      if (inPlace) writePath(c, f.text, { via: `${name} -i` });
    }
    if (name === "sed" || name === "gsed") {
      // GNU sed's e command and w file.
      const script = has(p, "e", "expression") ? values(p, "e", "expression").join("\n") : (p.positionals[0]?.text ?? "");
      if (/(?:^|[;\n}])\s*(?:\d+|\/[^/]*\/)?\s*e(?:\s|$)|\/e\b/.test(script)) {
        addFinding(c, "obfuscated_exec", "sed's e command runs text as a shell command");
        addEffect(c, { cls: "execute_opaque", target: "sed", detail: "run shell commands from a sed script" });
      }
      for (const m of script.matchAll(/(?:^|[;\n}]|\/[gpI0-9]*)\s*w\s+(\S+)/g)) writePath(c, m[1] as string, { via: "sed w" });
    }
    return NO_STAGE;
  }
  if (name === "awk" || name === "gawk" || name === "mawk" || name === "nawk") {
    const p = parseArgs(args, { short: "fvF", long: ["file", "assign", "field-separator"] });
    const prog = has(p, "f", "file") ? "" : (p.positionals[0]?.text ?? "");
    const files = has(p, "f", "file") ? p.positionals : p.positionals.slice(1);
    for (const f of values(p, "f", "file")) readPath(c, f, { via: "awk" });
    for (const f of files) if (!f.text.includes("=")) readPath(c, f.text, { via: "awk" });
    if (/\bsystem\s*\(|\|\s*getline|print[^;]*\|\s*"|"\s*\|&|\/inet\//.test(prog)) {
      addFinding(c, "obfuscated_exec", "the awk program runs shell commands or opens network connections");
      addEffect(c, { cls: "execute_opaque", target: "awk", detail: "run commands from an awk program" });
    }
    for (const m of prog.matchAll(/>{1,2}\s*"([^"]+)"/g)) writePath(c, m[1] as string, { via: "awk output" });
    return NO_STAGE;
  }
  if (READERS.has(name)) {
    const p = parseArgs(args, { short: name === "head" || name === "tail" ? "nc" : name === "cut" ? "dfc" : name === "sort" ? "otkS" : name === "split" ? "lbna" : name === "jq" ? "f" : "", long: ["lines", "bytes", "output", "field-separator", "key", "from-file", "arg", "argjson", "slurpfile", "rawfile"] });
    const recursive = (name === "ls" || name === "tree" || name === "du") ? false : has(p, "r", "R", "recursive");
    let positionals = p.positionals;
    if (name === "jq" && !has(p, "f", "from-file")) positionals = positionals.slice(1);
    if (name === "tr") positionals = [];
    for (const f of positionals) {
      if (name === "ls" || name === "tree" || name === "du" || name === "stat" || name === "file") {
        // Metadata only: a listing of a credential directory is not its content.
        const info = resolvePath(f.text, c.ctx);
        if (info !== null) readListing(c, f.text, name);
        continue;
      }
      readPath(c, f.text, { via: name, recursive });
    }
    for (const f of values(p, "slurpfile", "rawfile")) readPath(c, f, { via: name });
    if (name === "tee") for (const f of p.positionals) writePath(c, f.text, { via: "tee" });
    if (name === "sort" || name === "split") for (const f of values(p, "o", "output")) writePath(c, f, { via: name });
    if ((name === "base64" || name === "base32") && has(p, "d", "D", "decode")) return { ...NO_STAGE, decodes: true };
    if ((name === "xxd" && has(p, "r", "revert")) || name === "rev" || name === "tr") return { ...NO_STAGE, decodes: true };
    if (name === "zcat" || name === "gzcat" || name === "bzcat" || name === "xzcat") return { ...NO_STAGE, decodes: true };
    if (name === "sqlite3" || name === "duckdb") {
      const sql = [...p.positionals.slice(1).map((w) => w.text), stdin ?? ""].join("\n");
      const s = classifySql(sql);
      if (s.external) addEffect(c, { cls: "execute_opaque", target: name, detail: `${name} statement that reaches outside the database` });
      if (/\.(?:shell|system|sh)\b/.test(sql)) {
        addFinding(c, "obfuscated_exec", `${name} runs shell commands`);
        addEffect(c, { cls: "execute_opaque", target: name, detail: `run shell commands through ${name}` });
      }
      if (s.writes || s.destroys) for (const f of p.positionals.slice(0, 1)) writePath(c, f.text, { via: name });
    }
    return NO_STAGE;
  }
  switch (name) {
    case "touch":
    case "mkdir":
    case "truncate":
    case "chmod":
    case "chown":
    case "chgrp":
    case "chflags":
    case "setfacl":
    case "mkfifo":
    case "install": {
      const p = parseArgs(args, { short: name === "truncate" ? "sr" : name === "install" ? "mogtS" : name === "chmod" ? "" : "", long: ["size", "reference", "mode", "owner", "group", "target-directory", "suffix"] });
      let targets = p.positionals;
      if (name === "chmod" || name === "chown" || name === "chgrp" || name === "chflags" || name === "setfacl") targets = targets.slice(1);
      if (name === "chmod" && /(?:^|[ugoa]*)[+=][^,]*s|^[2-7][0-7]{3}$/.test(p.positionals[0]?.text ?? "")) addEffect(c, { cls: "privilege", target: "chmod", detail: "set a setuid or setgid bit" });
      const recursive = has(p, "R", "recursive");
      for (const t of targets) {
        const info = writePath(c, t.text, { via: name });
        if (recursive && info !== null && wouldDestroy(c, t, info.abs)) destroy(c, info.abs, `${name} -R`, t);
      }
      return NO_STAGE;
    }
    case "rm":
    case "rmdir":
    case "unlink":
    case "shred":
    case "srm":
    case "trash":
    case "wipe": {
      const p = parseArgs(args, { short: name === "shred" ? "nsx" : "", long: ["iterations", "size", "random-source"] });
      const recursive = has(p, "r", "R", "recursive") || name === "shred" || name === "srm" || name === "wipe";
      for (const t of p.positionals) {
        const info = writePath(c, t.text, { via: name, remove: true });
        if (info === null) continue;
        if (recursive && wouldDestroy(c, t, info.abs)) destroy(c, info.abs, `${name} -r`, t);
        else if (recursive && !t.dynamic && /^\/?$/.test(t.text.replace(/\/\*?$/, ""))) destroy(c, "/", `${name} -r`, t);
        // A repository's .git directory is its whole history (and every branch never pushed).
        if (recursive && name !== "trash" && /(?:^|\/)\.git\/?$/.test(info.abs)) addFinding(c, "catastrophic", `${name} -r: ${gitDirDeletion(info.abs)}`);
      }
      return NO_STAGE;
    }
    case "cp":
    case "mv":
    case "rsync":
    case "ditto":
    case "scp":
    case "rclone":
      return copier(name, args, c, payload);
    case "ln": {
      const p = parseArgs(args, { short: "tS", long: ["target-directory", "suffix"] });
      const pos = p.positionals;
      if (pos.length === 0) return NO_STAGE;
      const link = pos.length >= 2 ? (pos[pos.length - 1] as Word) : null;
      const targets = pos.length >= 2 ? pos.slice(0, -1) : pos;
      for (const t of targets) {
        // A link that points at a protected file lets a later "workspace" write change it.
        const r = resolvePath(t.text.startsWith("/") || t.text.startsWith("~") || link === null ? t.text : `${dirnameOf(link.text)}/${t.text}`, c.ctx);
        if (r === null) continue;
        const probe = { ...c, effects: [] as typeof c.effects, findings: [] as typeof c.findings };
        writePath(probe, r.abs);
        readPath(probe, r.abs);
        if (probe.effects.some((e) => e.cls === "write_protected" || e.cls === "firewall_tamper" || e.cls === "write_persistence" || e.cls === "read_secret")) {
          addFinding(c, "symlink_to_protected", `links to ${r.abs}, so writes or reads through the link reach it`);
          for (const e of probe.effects) if (e.cls !== "read_local_workspace" && e.cls !== "write_workspace" && e.cls !== "read_external") addEffect(c, { ...e, detail: `${e.detail} (through a symbolic link)` });
        }
      }
      if (link !== null) writePath(c, link.text, { via: "ln" });
      else writePath(c, basenameOf(targets[0]?.text ?? ""), { via: "ln" });
      noteLink(c, link, targets);
      return NO_STAGE;
    }
    case "dd": {
      for (const a of args) {
        const m = /^(if|of)=(.*)$/.exec(a.text);
        if (m === null) continue;
        if (m[1] === "if") readPath(c, m[2] as string, { via: "dd" });
        else {
          if (/^\/dev\/(?:disk|rdisk|sd|nvme|hd|xvd|vd|mmcblk)/.test(m[2] as string)) destroy(c, m[2] as string, "dd", a);
          else writePath(c, m[2] as string, { via: "dd" });
        }
      }
      return NO_STAGE;
    }
    case "tar":
    case "bsdtar":
    case "gtar":
    case "zip":
    case "7z":
    case "7za":
    case "unzip":
    case "gunzip":
    case "gzip":
    case "bzip2":
    case "xz":
    case "zstd":
    case "cpio":
    case "ar":
    case "jar":
      return archiver(name, args, c);
    case "git":
      return git(args, c, payload, depth, stdin);
    case "patch":
    case "gpatch":
      return patchProgram(name, args, c, stdin);
    case "apply_patch":
    case "applypatch":
      return codexApplyPatch(name, args, c, stdin);
    case "gh":
    case "glab":
    case "tea":
      return forge(name, args, c, payload);
    case "mkfs":
    case "newfs":
    case "fdisk":
    case "sfdisk":
    case "parted":
    case "gdisk":
    case "wipefs":
    case "blkdiscard":
    case "shutdown":
    case "reboot":
    case "halt":
    case "poweroff":
    case "init":
    case "systemctl":
    case "launchctl":
    case "crontab":
    case "at":
    case "batch":
    case "diskutil":
    case "csrutil":
    case "spctl":
    case "tmutil":
    case "defaults":
    case "dscl":
    case "visudo":
    case "setcap":
    case "usermod":
    case "useradd":
    case "passwd":
    case "chsh":
    case "security":
    case "osascript":
      return system(name, args, c, payload, depth);
    default:
      break;
  }
  if (/^mkfs\./.test(name)) {
    destroy(c, args[args.length - 1]?.text ?? name, name, args[0]);
    return NO_STAGE;
  }
  if (NETWORK_FETCHERS.has(name)) return fetcher(name, args, c, payload);
  if (DNS_TOOLS.has(name)) {
    const p = parseArgs(args, { short: "cisWtpmlqfbAIgTxkey", long: ["count", "interval", "type", "class", "port"] });
    for (const a of p.positionals) {
      const t = a.text.replace(/^@/, "");
      if (/^[A-Za-z]{1,6}$/.test(t) && /^(?:A|AAAA|MX|TXT|NS|CNAME|SOA|PTR|SRV|ANY|CAA|DS|DNSKEY|IN|CH)$/i.test(t)) continue;
      egress(c, t, "fetch", { payload, via: name });
      if (a.dynamic) addFinding(c, "dns_exfil_shape", `${name} looks up a host name built at run time: ${a.text}`);
    }
    return NO_STAGE;
  }
  if (RAW_SENDERS.has(name)) return rawSender(name, args, c, payload, depth);
  if (name === "ssh" || name === "autossh" || name === "mosh") return ssh(name, args, c, payload, depth);
  if (MAILERS.has(name)) {
    const to = args.filter((a) => /@/.test(a.text) && !a.text.startsWith("-")).map((a) => a.text);
    externalSend(c, `mail:${to.join(",") || "unknown"}`, `send email${to.length > 0 ? ` to ${to.join(", ")}` : ""} with ${name}`, payload, { tags: ["message"] });
    for (const a of parseArgs(args, { short: "sacbrAFt", long: [] }).opts.get("A") ?? []) readPath(c, a, { via: "mail attachment" });
    return NO_STAGE;
  }
  if (TUNNELS.has(name)) {
    addFinding(c, "capture_host", `${name} opens a tunnel that exposes this machine to the internet`);
    externalSend(c, `tunnel:${name}`, `open a public tunnel with ${name}`, payload);
    return NO_STAGE;
  }
  if (name === "open" || name === "xdg-open" || name === "start" || name === "explorer" || name === "wslview") {
    for (const a of args) {
      if (a.text.startsWith("-")) continue;
      if (!egress(c, a.text, "fetch", { payload, via: `${name} in a browser`, scheme: "https" })) {
        if (/^[a-z][a-z0-9+.-]*:/i.test(a.text)) addEffect(c, { cls: "execute_opaque", target: a.text, detail: `open the URL handler ${a.text}` });
        else readPath(c, a.text, { via: name });
      }
    }
    return NO_STAGE;
  }
  // helm install/upgrade/rollback change a cluster (a send); only its repo and plugin commands download code.
  if (name === "helm" && !/^(?:repo|dependency|dep|pull|plugin|search|show|template|lint|package|version|env|completion|create|verify)$/.test(args.find((a) => !a.text.startsWith("-"))?.text ?? "")) return cloudCli(name, args, c, payload, stdin);
  if (PACKAGE_MANAGERS.has(name)) return packageManager(name, args, c, payload, depth);
  if (name === "npx" || name === "bunx" || name === "pnpx" || name === "uvx" || name === "pipx" || name === "dlx") {
    notePackageCommand(c, name, args);
    const pkg = args.find((a) => !a.text.startsWith("-") && a.text !== "-y" && a.text !== "--yes")?.text ?? "";
    const bare = pkg.replace(/^@[^/]+\//, "").replace(/@.*$/, "");
    // npx supabase projects delete, bunx vercel rm: the catastrophic tables apply to the CLI they run.
    noteCatastrophic(c, bare, args.slice(args.findIndex((a) => a.text === pkg) + 1));
    if (COMMON_DEV_TOOLS.has(bare)) {
      addEffect(c, { cls: "execute", target: pkg, detail: `run ${pkg} with ${name}` });
      runsManifest(c, bare);
      genericArgs(args.slice(1), c, payload, `${name} ${pkg}`);
      // F19: npx vercel / netlify / wrangler ... is the deploy CLI itself: judged as that CLI too.
      // Its local commands (a dev server, a local build) stay as they were.
      if (DEPLOY_CLIS.has(bare)) {
        const i = args.findIndex((a) => a.text === pkg);
        const rest = args.slice(i + 1);
        const verb = rest.find((a) => !a.text.startsWith("-"))?.text ?? "";
        if (!/^(?:dev|build|init|help|types|completion|generate|codegen)$/.test(verb) || rest.some((a) => /^--prod(?:uction)?$/.test(a.text))) cloudCli(bare, rest, c, payload, null);
      }
      return NO_STAGE;
    }
    addEffect(c, { cls: "execute_opaque", target: pkg, detail: `download and run the package ${pkg} with ${name}`, tags: ["install"] });
    genericArgs(args.slice(1), c, payload, `${name} ${pkg}`);
    return NO_STAGE;
  }
  if (CLOUD_CLIS.has(name)) return cloudCli(name, args, c, payload, stdin);
  // F19: twine upload publishes to a package index.
  if (name === "twine") {
    const verb = args.find((a) => !a.text.startsWith("-"))?.text ?? "";
    if (verb === "upload" || verb === "register") {
      externalSend(c, "twine:registry", `twine ${verb}: publish to a package registry`, payload);
      publishRegistry(c, name, verb, args, payload);
      for (const a of args.filter((x) => !x.text.startsWith("-")).slice(1)) readPath(c, a.text, { via: "twine upload" });
      return NO_STAGE;
    }
  }
  if (name === "make" || name === "gmake" || name === "just" || name === "task" || name === "ninja" || name === "cmake" || name === "meson" || name === "bazel" || name === "buck" || name === "pants" || name === "turbo" || name === "nx" || name === "lerna" || name === "rake" || name === "invoke" || name === "nox" || name === "tox" || name === "pytest" || name === "jest" || name === "vitest" || name === "mocha" || name === "tsc" || name === "eslint" || name === "prettier" || name === "biome" || name === "ruff" || name === "black" || name === "mypy" || name === "pyright" || name === "rustc" || name === "gcc" || name === "g++" || name === "clang" || name === "clang++" || name === "javac" || name === "java" || name === "kotlinc" || name === "xcodebuild" || name === "xcrun" || name === "swiftc" || name === "esbuild" || name === "vite" || name === "webpack" || name === "rollup" || name === "next" || name === "astro" || name === "playwright" || name === "cypress" || name === "storybook" || name === "gofmt" || name === "rustfmt" || name === "clang-format" || name === "shellcheck" || name === "hadolint" || name === "semgrep" || name === "gitleaks" || name === "trivy" || name === "osv-scanner") {
    addEffect(c, { cls: "execute", target: name, detail: `run ${name}` });
    if (name === "make" || name === "gmake" || name === "ninja") {
      const p = parseArgs(args, { short: "Cf", long: ["directory", "file", "makefile"] });
      for (const dir of values(p, "C", "directory")) shiftCwd(c, dir);
    }
    runsManifest(c, name === "gmake" ? "make" : name);
    genericArgs(args, c, payload, name);
    return NO_STAGE;
  }
  if (name === "code" || name === "cursor" || name === "subl" || name === "vim" || name === "nvim" || name === "vi" || name === "nano" || name === "emacs" || name === "pico" || name === "ed" || name === "ex") {
    for (const a of args) if (!a.text.startsWith("-") && !a.text.startsWith("+")) writePath(c, a.text, { via: name });
    if (/^(?:vim|nvim|vi|ex)$/.test(name) && args.some((a) => /^(?:-c|\+)/.test(a.text) && /!|system\(/.test(a.text))) {
      addFinding(c, "obfuscated_exec", `${name} runs shell commands from its arguments`);
      addEffect(c, { cls: "execute_opaque", target: name, detail: `run shell commands through ${name}` });
    }
    if ((name === "code" || name === "cursor") && args.some((a) => /^--(?:install-extension|add-mcp|enable-proposed-api)/.test(a.text))) {
      addEffect(c, { cls: "write_protected", target: name, detail: `change ${name}'s extensions or MCP servers`, tags: ["settings"] });
    }
    return NO_STAGE;
  }
  if (name === "pbcopy" || name === "pbpaste" || name === "xclip" || name === "xsel" || name === "wl-copy" || name === "wl-paste") {
    if (name === "pbpaste" || name === "wl-paste" || args.some((a) => a.text === "-o")) addEffect(c, { cls: "read_external", target: "clipboard", detail: "read the clipboard", taints: true });
    return NO_STAGE;
  }
  // A program the analyzer has no model for: it runs, and its arguments are still judged.
  addEffect(c, { cls: "execute", target: name, detail: `run ${name}` });
  runsManifest(c, name);
  genericArgs(args, c, payload, name);
  return NO_STAGE;
}

/**
 * The task/build definition files each runner executes. F3: a runner whose definition file was
 * changed after the session read outside content (or was downloaded) runs code an outsider may
 * have written, so it needs a person.
 */
const RUNNER_MANIFESTS: Record<string, readonly string[]> = {
  npm: ["package.json"], pnpm: ["package.json", "pnpm-workspace.yaml", ".pnpmfile.cjs"], yarn: ["package.json", ".yarnrc.yml"], bun: ["package.json", "bunfig.toml"],
  deno: ["deno.json", "deno.jsonc"], make: ["Makefile", "makefile", "GNUmakefile"], gmake: ["Makefile", "makefile", "GNUmakefile"],
  just: ["justfile", "Justfile", ".justfile"], task: ["Taskfile.yml", "Taskfile.yaml", "Taskfile.dist.yml"], rake: ["Rakefile", "rakefile"],
  invoke: ["tasks.py"], nox: ["noxfile.py"], tox: ["tox.ini", "pyproject.toml", "setup.cfg"],
  pytest: ["conftest.py", "pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini"],
  poetry: ["pyproject.toml"], pdm: ["pyproject.toml"], hatch: ["pyproject.toml", "hatch.toml"], uv: ["pyproject.toml"], pip: ["setup.py", "pyproject.toml", "setup.cfg"],
  cargo: ["build.rs", "Cargo.toml"], go: ["go.mod"], composer: ["composer.json"], gradle: ["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"],
  gradlew: ["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"], mvn: ["pom.xml"], mvnw: ["pom.xml"], bundle: ["Gemfile"], bundler: ["Gemfile"], rails: ["Gemfile", "Rakefile"], fastlane: ["fastlane/Fastfile", "Fastfile"], eas: ["eas.json"], sbt: ["build.sbt"], mix: ["mix.exs"],
  jest: ["jest.config.js", "jest.config.ts", "jest.config.mjs", "jest.config.cjs", "package.json"], vitest: ["vitest.config.ts", "vitest.config.js", "vitest.config.mts", "vite.config.ts", "vite.config.js"],
  playwright: ["playwright.config.ts", "playwright.config.js"], cypress: ["cypress.config.ts", "cypress.config.js"], vite: ["vite.config.ts", "vite.config.js"],
  turbo: ["turbo.json", "package.json"], nx: ["nx.json", "project.json", "package.json"], lerna: ["lerna.json", "package.json"],
  "pre-commit": [".pre-commit-config.yaml"], cmake: ["CMakeLists.txt"], meson: ["meson.build"], bazel: ["BUILD", "BUILD.bazel", "WORKSPACE", "MODULE.bazel"],
  docker: ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"], podman: ["Dockerfile", "Containerfile", "compose.yml"],
  git: [".git/hooks/pre-commit", ".git/hooks/commit-msg", ".git/hooks/pre-push", ".git/hooks/post-checkout", ".git/hooks/post-merge", ".git/hooks/prepare-commit-msg", ".git/hooks/post-commit", ".git/hooks/post-rewrite", ".husky/pre-commit", ".husky/pre-push", ".husky/commit-msg", ".githooks/pre-commit", ".githooks/pre-push", ".githooks/commit-msg",
    // R8: hook frameworks the installed git hook hands over to (pre-commit, lefthook) run what these configure.
    ".pre-commit-config.yaml", "lefthook.yml", "lefthook.yaml", ".lefthook.yml", "lefthook-local.yml", ".gitattributes",
    // F7: git's own config (core.hooksPath, filters, include.path) decides what it runs.
    ".git/config", ".git/config.worktree", ".git/info/attributes"],
  // Hook managers, local CI runners, dev containers and environment hooks.
  lefthook: ["lefthook.yml", "lefthook.yaml", ".lefthook.yml", "lefthook-local.yml"],
  "gitlab-runner": [".gitlab-ci.yml"],
  direnv: [".envrc"],
  mise: ["mise.toml", ".mise.toml"],
  // F18: nix-shell and nix develop run a shellHook.
  "nix-shell": ["shell.nix", "default.nix", "flake.nix"],
};

/** Runners that read every file under a directory (a tainted write anywhere below it counts). */
const RUNNER_MANIFEST_DIRS: Record<string, readonly string[]> = {
  act: [".github/workflows", ".github/actions"],
  devcontainer: [".devcontainer"],
  lefthook: [".lefthook"],
  "gitlab-runner": [".gitlab/ci"],
  // F7: every hook git may run (any hook name), a submodule's own git directory (hooks and config), and worktree config.
  git: [".git/hooks", ".git/modules", ".git/worktrees"],
};

/**
 * R3: the files an install reads to decide which code to download and run: lockfiles (a `resolved` URL
 * can point at any tarball), package-manager and registry configuration, requirement files. Checked
 * (with the runner's manifests) only when the command installs. Paths relative to where it runs.
 */
const INSTALL_INPUTS: Record<string, readonly string[]> = {
  npm: ["package-lock.json", "npm-shrinkwrap.json", ".npmrc"],
  pnpm: ["pnpm-lock.yaml", ".npmrc", "pnpm-workspace.yaml"],
  yarn: ["yarn.lock", ".yarnrc.yml", ".yarnrc", ".npmrc", ".pnp.cjs"],
  bun: ["bun.lockb", "bun.lock", "bunfig.toml", ".npmrc"],
  deno: ["deno.lock", "deno.json", "deno.jsonc"],
  pip: ["requirements.txt", "requirements-dev.txt", "requirements_dev.txt", "dev-requirements.txt", "constraints.txt", "pip.conf", ".venv/pip.conf", "venv/pip.conf"],
  uv: ["uv.lock", "uv.toml", "requirements.txt", "constraints.txt", "pip.conf", ".venv/pip.conf"],
  poetry: ["poetry.lock", "poetry.toml"], pdm: ["pdm.lock", "pdm.toml"], pipenv: ["Pipfile", "Pipfile.lock"], hatch: ["hatch.toml"], rye: ["requirements.lock", "requirements-dev.lock"],
  bundle: ["Gemfile.lock", ".bundle/config"], bundler: ["Gemfile.lock", ".bundle/config"], gem: [".gemrc"],
  go: ["go.sum", "go.work", "go.work.sum"], cargo: ["Cargo.lock", ".cargo/config.toml", ".cargo/config"], composer: ["composer.lock", "auth.json"],
  dotnet: ["packages.lock.json", "NuGet.Config", "nuget.config"], swift: ["Package.resolved"], dart: ["pubspec.yaml", "pubspec.lock"], flutter: ["pubspec.yaml", "pubspec.lock"],
  mix: ["mix.lock"], gradle: ["gradle.lockfile", "gradle.properties"], mvn: [".mvn/maven.config", ".mvn/settings.xml"],
};

/**
 * R8: config-as-code of the JavaScript tools a project script (npm test, npm run build) typically runs:
 * each is a module the tool executes. Checked for npm/pnpm/yarn/bun run|test|build|..., in the directory
 * the script runs in, because the script line in package.json can name any of them.
 */
const JS_CONFIG_EXTS = ["js", "cjs", "mjs", "ts", "cts", "mts"];
const JS_TOOL_CONFIGS: readonly string[] = [
  ...["vite", "vitest", "vitest.workspace", "jest", "playwright", "cypress", "webpack", "rollup", "eslint", "babel", "postcss", "tailwind", "next", "nuxt", "astro", "svelte", "tsup", "remix", "metro", "karma", "prettier", "stylelint", "commitlint", "lint-staged", "drizzle", "vue", "rspack", "rsbuild", "esbuild", "electron.vite", "storybook"].flatMap((t) => JS_CONFIG_EXTS.map((e) => `${t}.config.${e}`)),
  ...[".eslintrc", ".babelrc", ".prettierrc", ".mocharc", ".lintstagedrc", "gulpfile", "Gruntfile", "karma.conf", "jest.setup", "vitest.setup", ".storybook/main", ".storybook/preview"].flatMap((t) => JS_CONFIG_EXTS.map((e) => `${t}.${e}`)),
  "jest.config.json", ".mocharc.json", ".mocharc.yml", ".lintstagedrc.json", ".babelrc", "babel.config.json",
];

/** Raises an approval when a runner is about to execute a definition file written after taint or downloaded. */
function runsManifest(c: Collector, runner: string, extra: readonly string[] = []): void {
  buildsInstalledRuntime(c, runner);
  const listed = own(RUNNER_MANIFESTS, runner) ?? (own(RUNNER_MANIFEST_DIRS, runner) !== undefined ? [] : undefined);
  if (listed === undefined && extra.length === 0) return;
  const files = [...new Set([...(listed ?? []), ...extra])];
  // F-e: a definition file an untrusted session wrote, in this session or an earlier one, still matching.
  const carry = c.cfg.provenance.carryUntrustedWrites && c.ctx.provenance !== undefined;
  if (!carry && c.state.taintedWrites.size === 0 && c.state.downloaded.size === 0) return;
  const ci = c.ctx.caseInsensitive;
  // F-f: after a cd (or -C) the runner reads the definition files where it runs; git's hooks live at the
  // repository root, which is a workspace root containing that directory when there is one.
  const shifted = c.ctx.cwdShifted === true;
  const known = c.ctx.cwdKnown !== false;
  const bases = !known
    ? [...c.ctx.workspaceRoots]
    : shifted
      ? [...new Set([c.ctx.cwd, ...(runner === "git" ? c.ctx.workspaceRoots.filter((r) => isUnder(c.ctx.cwd, r, ci)) : [])])]
      : [...new Set([c.ctx.cwd, ...c.ctx.workspaceRoots])];
  const lc = (x: string): string => (ci ? x.toLowerCase() : x);
  for (const base of bases) {
    // The base is normalized once, not once per definition file: a workspace root of a million characters (a
    // malformed hook event) cost 1.6 s when every file re-split it (hook:cursor:robust seed 37713).
    const root = normalizeAbs(base);
    for (const f of files) {
      const abs = f.startsWith("/") ? normalizeAbs(f) : /(?:^|\/)\.{1,2}(?:\/|$)|\/\/|\/$/.test(f) ? normalizeAbs(`${root}/${f}`) : `${root === "/" ? "" : root}/${f}`;
      const written = [...c.state.taintedWrites].some((w) => lc(w) === lc(abs));
      const downloaded = [...c.state.downloaded].some((d) => isUnder(abs, d, ci));
      if (written || downloaded) {
        addEffect(c, { cls: "execute_untrusted", target: abs, detail: `${runner} runs ${abs}, which was ${downloaded ? "downloaded" : "changed after the session read outside content"}`, tags: ["manifest"] });
      } else if (carry && writtenByUntrustedSession(c, abs)) {
        addEffect(c, { cls: "execute_untrusted", target: abs, detail: `${runner} runs ${abs}, which an untrusted session changed`, tags: ["manifest"] });
      }
    }
    for (const dir of own(RUNNER_MANIFEST_DIRS, runner) ?? []) {
      const under = normalizeAbs(`${root}/${dir}`);
      for (const w of c.state.taintedWrites) {
        if (isUnder(w, under, ci)) addEffect(c, { cls: "execute_untrusted", target: w, detail: `${runner} runs ${w}, which was changed after the session read outside content`, tags: ["manifest"] });
      }
    }
    // Definition files the runner discovers anywhere below where it runs (pytest loads every conftest.py).
    for (const name of own(NESTED_MANIFESTS, runner) ?? []) {
      for (const w of c.state.taintedWrites) {
        if (isUnder(w, base, ci) && (ci ? w.toLowerCase() : w).endsWith(`/${ci ? name.toLowerCase() : name}`)) addEffect(c, { cls: "execute_untrusted", target: w, detail: `${runner} runs ${w}, which was changed after the session read outside content`, tags: ["manifest"] });
      }
    }
  }
}

/** Runners that build or install a JavaScript package where they run (they rewrite its dist/ or node_modules/). */
const BUILD_RUNNERS = new Set(["npm", "pnpm", "yarn", "bun", "deno", "make", "gmake", "just", "task", "turbo", "nx", "lerna", "tsc", "tsup", "esbuild", "vite", "webpack", "rollup"]);

/**
 * F-c: when the firewall runs from a package root that is a directory tree the agent can work in (a
 * dev install from a source checkout), a build there rewrites the installed runtime. A packed install
 * in its own prefix makes building the checkout ordinary work. The working directory is the hook's
 * cwd; F-f's tracking of cd/-C/--prefix refines it.
 */
function buildsInstalledRuntime(c: Collector, runner: string): void {
  if (!BUILD_RUNNERS.has(runner)) return;
  // c.ctx.cwd is F-f's tracked directory: cd/pushd earlier in the command, make -C, npm --prefix,
  // pnpm -C, yarn --cwd, env -C. When it cannot be followed (cd "$DIR") and the firewall runs from a
  // working copy, the build may be in the installed package: say so rather than allow it.
  if (c.ctx.cwdKnown === false) {
    const id = identityOf(c.ctx);
    const working = id.source === "fallback-install-dir" ? undefined : id.packageRoots.find((r) => !/\/node_modules\//.test(r));
    if (working !== undefined) addFinding(c, "unresolvable_write_target", `${runner} builds in a directory the firewall cannot follow, and the firewall is installed from the working copy ${working}`);
    return;
  }
  // SELF-016: the directory as written and canonical: a symlinked alias of the package root is the package root.
  const forms = pathForms(normalizeAbs(c.ctx.cwd), c.ctx);
  const root = forms.paths.map((p) => inPackageRoot(p, c.ctx)).find((x) => x !== null) ?? null;
  if (root !== null) addEffect(c, { cls: "firewall_tamper", target: root, detail: `build the firewall's installed code from inside the agent (${runner} in ${root}, which is the installed package)` });
  else if (!forms.known) addFinding(c, "unresolvable_write_target", `${runner} builds in ${c.ctx.cwd}, which the firewall cannot resolve (a symlink loop or a directory it may not search), so it may be the firewall's installed package`);
}

const NESTED_MANIFESTS: Record<string, readonly string[]> = { pytest: ["conftest.py"], tox: ["conftest.py"], nox: ["conftest.py"] };

function dirnameOf(p: string): string {
  const i = p.lastIndexOf("/");
  return i === -1 ? "." : i === 0 ? "/" : p.slice(0, i);
}

function basenameOf(p: string): string {
  return p.slice(p.lastIndexOf("/") + 1);
}

function readListing(c: Collector, raw: string, via: string): void {
  const r = resolvePath(raw, c.ctx);
  if (r === null) return;
  const probe = { ...c, effects: [] as typeof c.effects, findings: [] as typeof c.findings };
  readPath(probe, raw, { via, namesOnly: true });
  const cls = probe.effects[0]?.cls;
  // Listing a credential directory shows names, not keys; listing outside the workspace is still outside content.
  if (cls === "read_external" && !createdByTrustedSession(c, r.abs)) addEffect(c, probe.effects[0] as (typeof c.effects)[number]);
  else addEffect(c, { cls: "read_local_workspace", target: r.abs, detail: `list ${r.abs} (${via})` });
}

/** Whether a recursive change of this path would destroy data that is not a disposable part of the workspace. */
function wouldDestroy(c: Collector, w: Word, abs: string): boolean {
  if (w.dynamic && !literal(w)) return true;
  const ci = c.ctx.caseInsensitive;
  const norm = (p: string): string => (ci ? p.toLowerCase() : p).replace(/\/+$/, "");
  const a = norm(abs);
  const home = norm(c.ctx.home);
  if (a === "" || a === "/" || a === home || home.startsWith(`${a}/`)) return true;
  for (const root of c.ctx.workspaceRoots) {
    const r = norm(root);
    if (a === r || r.startsWith(`${a}/`)) return true;
    // `rm -rf *` (or ./*) at the workspace root removes the whole project.
    if (w.glob && norm(abs.replace(/\/[^/]*$/, "")) === r && /^\*$|^\.\/\*$|\/\*$/.test(w.text)) return true;
  }
  const inScratch = c.ctx.scratchRoots.some((r) => a === norm(r) || a.startsWith(`${norm(r)}/`));
  const inWorkspace = c.ctx.workspaceRoots.some((r) => a.startsWith(`${norm(r)}/`));
  return !inScratch && !inWorkspace;
}

function destroy(c: Collector, target: string, via: string, w: Word | undefined): void {
  const r = resolvePath(target, c.ctx);
  const a = r?.abs ?? target;
  const home = c.ctx.home.replace(/\/+$/, "");
  const ci = c.ctx.caseInsensitive;
  const eq = (x: string, y: string): boolean => (ci ? x.toLowerCase() === y.toLowerCase() : x === y);
  // Everything in the home directory or the root, however it was reached (cd ~ && rm -rf *): a glob of
  // the whole directory erases it as surely as naming the directory.
  const wholeDir = w?.glob === true && /\/\.?\*$/.test(a) ? a.replace(/\/\.?\*$/, "") || "/" : null;
  if (a === "/" || eq(a, home) || (wholeDir !== null && (wholeDir === "/" || eq(wholeDir, home))) || (home.startsWith(`${a}/`) && a !== "") || /^\/dev\//.test(a) || w?.text === "/*" || w?.text === "~/*" || w?.text === "~" || /^\$\{?HOME\}?\/?\*?$/.test(w?.text ?? "")) {
    addFinding(c, "destroy_root", `${via} would erase ${a === "/" || /^\/dev\//.test(a) ? a : "the home directory"}`);
  } else if (/^(?:rm|rmdir|unlink|shred|srm|wipe) -r$|^find -delete$/.test(via)) {
    // Deleting the whole project: a workspace root, a directory that contains one, or every file in one
    // (rm -rf *). Not chmod -R or trash (recoverable), which stay ordinary destructive actions.
    const whole = wholeDir ?? a;
    if (c.ctx.workspaceRoots.some((root) => eq(whole, root.replace(/\/+$/, "")) || (whole !== "" && (ci ? root.toLowerCase() : root).startsWith(`${ci ? whole.toLowerCase() : whole}/`)))) addFinding(c, "catastrophic", `${via}: ${workspaceDeletion(whole)}`);
  }
  addEffect(c, { cls: "destructive", target: a, detail: `${via} ${a}` });
}

const INLINE_HOOKS = { executeFile: (c: Collector, raw: string, via: string): void => executeFile(c, raw, via) };

function executeFile(c: Collector, raw: string, via: string): void {
  const r = resolvePath(raw, c.ctx);
  if (r === null) return;
  // 10-11: a file whose path is only known at run time (a variable, a path xargs or find supplies): its code is unseen.
  if (!r.exact && /[$`]/.test(raw.replace(/^(?:\$HOME|\$\{HOME\}|\$PWD|\$\{PWD\})(?=\/|$)/, ""))) {
    addEffect(c, { cls: "execute_opaque", target: raw, detail: `${via} a file whose path is only known at run time: ${raw}` });
    return;
  }
  const ci = c.ctx.caseInsensitive;
  const lc = (s: string): string => (ci ? s.toLowerCase() : s);
  const isDl = [...c.state.downloaded].some((d) => lc(r.abs) === lc(d) || lc(r.abs).startsWith(`${lc(d)}/`));
  const isTaintedWrite = [...c.state.taintedWrites].some((d) => lc(r.abs) === lc(d));
  if (isDl) addEffect(c, { cls: "execute_untrusted", target: r.abs, detail: `${via} the downloaded file ${r.abs}` });
  else if (isTaintedWrite) addEffect(c, { cls: "execute_untrusted", target: r.abs, detail: `${via} ${r.abs}, written after the session read outside content` });
  else if (writtenByUntrustedSession(c, r.abs)) addEffect(c, { cls: "execute_untrusted", target: r.abs, detail: `${via} ${r.abs}, which an untrusted session wrote` });
  else {
    const probe = { ...c, effects: [] as typeof c.effects, findings: [] as typeof c.findings };
    readPath(probe, raw);
    if (probe.effects.some((e) => e.cls === "read_external")) addEffect(c, { cls: "execute_untrusted", target: r.abs, detail: `${via} ${r.abs}, which comes from outside the workspace` });
    else addEffect(c, { cls: "execute", target: r.abs, detail: `${via} ${r.abs}` });
  }
}

/**
 * A shell (or `source /dev/stdin`) reading its script from standard input. A here-document or a literal
 * here-string is analysed as the script; so is static text piped in (echo/printf of literals, cat of a
 * here-document), in every reading of it. A file given with `<` is run like `sh file` and, because the
 * firewall does not read the file, is also opaque; so is a process substitution or a pipe of run-time output
 * (allowed in a trusted session, asked once untrusted). Never a plain allow.
 */
function stdinScript(name: string, c: Collector, depth: number, stdin: string | null): StageKind {
  if (stdin !== null) {
    analyzeShell(stdin, c, depth + 1);
    return NO_STAGE;
  }
  const file = c.stdinFile;
  if (file !== undefined) {
    // SH12: a shell reading its script from a process substitution (`sh < <(...)`) runs whatever that
    // command prints: code the firewall cannot see. The inner command itself is analysed by walkScript.
    if (isProcessSub(file)) {
      addEffect(c, { cls: "execute_opaque", target: name, detail: `run ${name} on a script a command produces` });
      return NO_STAGE;
    }
    const r = resolvePath(file, c.ctx);
    const written = r !== null ? c.heredocFiles?.get(r.abs) : undefined;
    if (typeof written === "string") {
      // F2: a file this command line wrote from a here-document: its text is known.
      analyzeShell(written, c, depth + 1);
      return NO_STAGE;
    }
    executeFile(c, file, name);
    addEffect(c, { cls: "execute_opaque", target: r?.abs ?? file, detail: `run ${name} on the script in ${file}, whose contents the firewall does not read` });
    return NO_STAGE;
  }
  if (c.stdinPiped === true) {
    const texts = c.stdinText;
    if (texts !== undefined && texts !== null) for (const t of texts) analyzeShell(t, c, depth + 1);
    else addEffect(c, { cls: "execute_opaque", target: name, detail: `run ${name} on a script piped in from another command` });
    return { ...NO_STAGE, runsStdin: true };
  }
  return { ...NO_STAGE, runsStdin: true };
}

function shellProgram(name: string, args: readonly Word[], c: Collector, payload: string, depth: number, stdin: string | null, viaXargs: boolean): StageKind {
  if (name === "busybox") {
    if (args.length === 0) return NO_STAGE;
    return dispatch(args, c, payload, depth, stdin);
  }
  const p = parseArgs(args, { short: "oO", long: ["rcfile", "init-file"], stopAtPositional: true });
  const codeFlag = [...p.opts.keys()].some((k) => k === "c" || k === "command");
  if (codeFlag) {
    // sh -c 'code' arg0 args...: the code is the first positional. Without one, read it as a shell reading
    // standard input (stricter than any shell, which refuses or reads its input).
    const code = p.positionals[0];
    if (code === undefined) return stdinScript(name, c, depth, stdin);
    if (!literal(code)) {
      addFinding(c, "obfuscated_exec", `${name} -c runs text that is only known at run time`);
      addEffect(c, { cls: "execute_opaque", target: name, detail: `run computed text with ${name} -c` });
      if (hasFetcherInside([code])) addFinding(c, "remote_code_pipe", `${name} -c runs what a download returns`);
      return NO_STAGE;
    }
    analyzeShell(code.text, c, depth + 1);
    return viaXargs ? { ...NO_STAGE, runsStdin: true } : NO_STAGE;
  }
  for (const f of values(p, "rcfile", "init-file")) executeFile(c, f, name);
  const script = p.positionals[0];
  if (script === undefined || script.text === "-" || script.text === "/dev/stdin" || has(p, "s")) return stdinScript(name, c, depth, stdin);
  if (script.subs.length > 0 && hasFetcherInside([script])) {
    addFinding(c, "remote_code_pipe", `${name} runs a script straight from a download`);
    return NO_STAGE;
  }
  if (script.subs.length > 0) {
    // SH12: `bash <(...)` runs the output of a command as its script: unseeable code.
    addEffect(c, { cls: "execute_opaque", target: name, detail: `run ${name} on a script a command produces` });
    return NO_STAGE;
  }
  executeFile(c, script.text, name);
  genericArgs(p.positionals.slice(1), c, payload, name);
  return NO_STAGE;
}

function interpreter(name: string, argv: readonly Word[], c: Collector, payload: string, depth: number, stdin: string | null): StageKind {
  // F-f, SELF-016: bun's global --cwd (before its subcommand) moves where it runs, like npm --prefix.
  let args = argv;
  if (name === "bun") {
    const kept: Word[] = [];
    let i = 0;
    for (; i < argv.length; i++) {
      const t = (argv[i] as Word).text;
      if (t === "--cwd" && argv[i + 1] !== undefined) {
        shiftCwd(c, (argv[i + 1] as Word).text);
        i++;
      } else if (t.startsWith("--cwd=")) shiftCwd(c, t.slice("--cwd=".length));
      else if (t.startsWith("-")) kept.push(argv[i] as Word);
      else break;
    }
    args = [...kept, ...argv.slice(i)];
  }
  // perl -i / ruby -i edit each file argument in place.
  if ((name === "perl" || name === "ruby") && args.some((a) => /^-[a-zA-Z]*i/.test(a.text) && !a.text.startsWith("--"))) {
    for (const a of args) if (!a.text.startsWith("-") && /[./]/.test(a.text)) writePath(c, a.text, { via: `${name} -i` });
  }
  const inline = new Set(own(INLINE_FLAGS, name) ?? ["e", "c"]);
  const valueShort = [...inline].filter((f) => f.length === 1).join("") + (name.startsWith("python") || name.startsWith("pypy") ? "mWX" : "") + (name === "node" || name === "nodejs" ? "r" : "");
  const p = parseArgs(args, { short: valueShort, long: [...inline].filter((f) => f.length > 1).concat(["require", "import", "loader", "experimental-loader"]), stopAtPositional: true });
  let code: string | null = null;
  for (const f of inline) {
    const v = p.opts.get(f);
    if (v !== undefined && v.length > 0) code = v.join("\n");
  }
  if (name === "deno" || name === "bun") {
    const sub = p.positionals[0]?.text;
    if (sub === "eval" || sub === "-e") code = p.positionals[1]?.text ?? "";
    else if (sub === "run" || sub === "x") {
      const target = p.positionals[1]?.text ?? "";
      if (/^(?:https?:|npm:|jsr:)/.test(target)) {
        addEffect(c, { cls: "execute_opaque", target, detail: `download and run ${target}`, tags: ["install"] });
        egress(c, target.replace(/^(?:npm|jsr):/, "https://registry.npmjs.org/"), "fetch", { payload, via: name });
        return NO_STAGE;
      }
      // R8: `bun run <script>` runs a package.json script (and the tools it names), like npm run.
      if (name === "bun" && /^[A-Za-z0-9:_-]+$/.test(target) && !/\.(?:[cm]?[jt]sx?)$/.test(target)) {
        addEffect(c, { cls: "execute", target: `bun run ${target}`, detail: `run the project's bun script ${target}` });
        runsManifest(c, "bun", JS_TOOL_CONFIGS);
        return NO_STAGE;
      }
      if (target !== "") executeFile(c, target, name);
      return NO_STAGE;
    } else if (name === "bun" && sub === "test") {
      addEffect(c, { cls: "execute", target: "bun test", detail: "run the project's tests with bun" });
      runsManifest(c, "bun", JS_TOOL_CONFIGS);
      return NO_STAGE;
    } else if (sub === "install" || sub === "add" || sub === "i" || sub === "update" || sub === "upgrade") return packageManager(name, args, c, payload, depth);
    else if (sub !== undefined && sub !== "") {
      if (/\.(?:[cm]?[jt]sx?)$/.test(sub)) executeFile(c, sub, name);
      else addEffect(c, { cls: "execute", target: `${name} ${sub}`, detail: `run ${name} ${sub}` });
      return NO_STAGE;
    }
  }
  for (const r of values(p, "r", "require", "import", "loader", "experimental-loader")) executeFile(c, r, `${name} preload`);
  if (name.startsWith("python") && has(p, "m")) {
    const mod = values(p, "m")[0] ?? "";
    if (/^(?:http\.server|SimpleHTTPServer|smtpd|aiosmtpd|ftplib|pyftpdlib)$/.test(mod)) externalSend(c, `listener:${mod}`, `serve files to the network with python -m ${mod}`, payload);
    else if (/^(?:pip|ensurepip|venv|virtualenv)$/.test(mod)) return packageManager("pip", p.positionals, c, payload, depth);
    else if (/^(?:urllib|http\.client|requests|smtplib|telnetlib|ftplib|webbrowser|base64)/.test(mod)) addEffect(c, { cls: "execute_opaque", target: mod, detail: `run python -m ${mod}` });
    else {
      addEffect(c, { cls: "execute", target: `python -m ${mod}`, detail: `run python -m ${mod}` });
      runsManifest(c, mod);
    }
    genericArgs(p.positionals, c, payload, `python -m ${mod}`);
    return NO_STAGE;
  }
  if (code !== null) {
    inlineCode(name, code, c, payload, INLINE_HOOKS);
    return NO_STAGE;
  }
  const script = p.positionals[0];
  if (script === undefined || script.text === "-" || script.text === "/dev/stdin") {
    if (stdin !== null) {
      inlineCode(name, stdin, c, payload, INLINE_HOOKS);
      return NO_STAGE;
    }
    return { ...NO_STAGE, runsStdin: true };
  }
  if (script.subs.length > 0 && hasFetcherInside([script])) {
    addFinding(c, "remote_code_pipe", `${name} runs a script straight from a download`);
    return NO_STAGE;
  }
  if (/^(?:https?|ftp):\/\//.test(script.text)) {
    addFinding(c, "remote_code_pipe", `${name} runs a script straight from a URL`);
    egress(c, script.text, "fetch", { payload, via: name });
    return NO_STAGE;
  }
  executeFile(c, script.text, name);
  genericArgs(p.positionals.slice(1), c, payload, name);
  return NO_STAGE;
}

function searcher(name: string, args: readonly Word[], c: Collector): StageKind {
  const p = parseArgs(args, { short: name === "rg" ? "efgtTABCmMjE" : "efABCmdDX", long: ["regexp", "file", "glob", "type", "type-not", "after-context", "before-context", "context", "max-count", "include", "exclude", "exclude-dir", "max-depth", "threads", "encoding", "type-add", "pre", "ignore-file", "sort", "max-filesize", "replace"] });
  const patternGiven = has(p, "e", "regexp", "f", "file");
  for (const f of values(p, "f", "file", "ignore-file")) readPath(c, f, { via: name });
  for (const pre of values(p, "pre")) executeFile(c, pre, `${name} --pre`);
  const paths = patternGiven ? p.positionals : p.positionals.slice(1);
  const recursive = name === "rg" || name === "ag" || name === "ack" || name === "pt" || name === "sift" || has(p, "r", "R", "recursive", "dereference-recursive");
  if (paths.length === 0) {
    readPath(c, c.ctx.cwd, { via: name, recursive });
    return NO_STAGE;
  }
  for (const f of paths) readPath(c, f.text, { via: name, recursive });
  return NO_STAGE;
}

function finder(name: string, args: readonly Word[], c: Collector, payload: string, depth: number): StageKind {
  if (name !== "find") {
    for (const a of args) if (!a.text.startsWith("-") && /^(?:\/|~|\.)/.test(a.text)) readListing(c, a.text, name);
    if (args.some((a) => a.text === "-x" || a.text === "-X" || a.text === "--exec" || a.text === "--exec-batch")) {
      const i = args.findIndex((a) => a.text === "-x" || a.text === "-X" || a.text === "--exec" || a.text === "--exec-batch");
      // fd puts each path at its placeholders ({}, {/}, {//}, {.}, {/.}), or at the end when there are none.
      dispatch(args.slice(i + 1).filter((a) => a.text !== ";"), c, payload, depth, null, { replace: /\{(?:\/\/?|\.|\/\.)?\}/g, append: true });
    }
    return NO_STAGE;
  }
  let i = 0;
  const roots: Word[] = [];
  while (i < args.length && /^-[HLP]$|^-O\d$|^-D$/.test((args[i] as Word).text)) i++;
  while (i < args.length && !/^[-(!]/.test((args[i] as Word).text)) roots.push(args[i++] as Word);
  if (roots.length === 0) roots.push({ text: ".", dynamic: false, glob: false, quoted: false, subs: [], vars: [] });
  const expr = args.slice(i);
  const reads = expr.some((a) => FIND_ACTIONS.has(a.text));
  const deletes = expr.some((a) => a.text === "-delete");
  // `find . -name '*.pyc' -delete` removes what the filters select, not the tree: never the catastrophic class.
  const filtered = expr.some((a) => a.text === "!" || /^-(?:i?name|type|i?path|i?wholename|[amc](?:time|min)|empty|newer\w*|i?regex|size|user|group|perm|prune|not|links|inum|samefile|lname|ilname|fstype|uid|gid|nouser|nogroup)$/.test(a.text));
  for (const r of roots) {
    if (deletes) {
      const info = writePath(c, r.text, { via: "find -delete", remove: true });
      if (info !== null && wouldDestroy(c, r, info.abs)) destroy(c, info.abs, filtered ? "find -delete (filtered)" : "find -delete", r);
    } else readListing(c, r.text, "find");
  }
  for (const a of expr) if (/^-(?:fprint|fprint0|fprintf|fls)$/.test(a.text)) {
    const idx = expr.indexOf(a);
    const f = expr[idx + 1];
    if (f !== undefined) writePath(c, f.text, { via: `find ${a.text}` });
  }
  for (let j = 0; j < expr.length; j++) {
    if (!FIND_ACTIONS.has((expr[j] as Word).text)) continue;
    const sub: Word[] = [];
    let k = j + 1;
    for (; k < expr.length; k++) {
      const t = (expr[k] as Word).text;
      if (t === ";" || t === "+") break;
      sub.push(expr[k] as Word);
    }
    // {} stands for each found file. 10-11: to a program that deletes or runs it, a path known only at run
    // time; to any other, a file under the search roots (as before).
    dispatch(sub, c, payload, depth, null, { replace: /\{\}/g, append: false, fallback: `${roots[0]?.text ?? "."}/x` });
    // A content-reading command over everything under home is a credential sweep.
    if (reads) for (const r of roots) readPath(c, r.text, { via: "find -exec", recursive: true });
    j = k;
  }
  return NO_STAGE;
}

function copier(name: string, args: readonly Word[], c: Collector, payload: string): StageKind {
  const p = parseArgs(args, { short: name === "scp" ? "cFiJlo" + "P" + "S" : name === "rsync" ? "eBfT" : "tS", long: ["target-directory", "suffix", "rsh", "rsync-path", "exclude", "include", "exclude-from", "include-from", "files-from", "filter", "backup-dir", "log-file", "password-file", "port", "temp-dir", "compare-dest", "copy-dest", "link-dest", "config", "chmod", "chown", "usermap", "groupmap", "out-format", "partial-dir"] });
  const pos = p.positionals.map((w) => w.text);
  if (pos.length === 0) return NO_STAGE;
  for (const e of values(p, "e", "rsh", "rsync-path")) {
    addFinding(c, "env_injection", `${name} runs a custom remote shell: ${e}`);
    addEffect(c, { cls: "execute_opaque", target: e, detail: `run ${e} as ${name}'s transport` });
  }
  if (name === "rclone") {
    const sub = pos[0] ?? "";
    const rest = pos.slice(1);
    if (/^(?:copy|sync|move|copyto|moveto|bisync)$/.test(sub)) {
      const dest = rest[rest.length - 1] ?? "";
      for (const s of rest.slice(0, -1)) if (!/^[A-Za-z0-9_-]+:/.test(s)) readPath(c, s, { via: "rclone", recursive: true });
      if (/^[A-Za-z0-9_-]+:/.test(dest)) externalSend(c, `rclone:${dest.split(":")[0]}`, `upload to the rclone remote ${dest}`, payload);
      else writePath(c, dest, { via: "rclone" });
    } else if (/^(?:delete|purge|rmdir|rmdirs|cleanup|deletefile)$/.test(sub)) addEffect(c, { cls: "destructive", target: rest[0] ?? "", detail: `rclone ${sub} ${rest[0] ?? ""}` });
    return NO_STAGE;
  }
  const remote = (s: string): string | null => {
    if (/^rsync:\/\//.test(s)) return parseUrlLike(s)?.host ?? s;
    const m = /^(?:[^@/:\s]+@)?([^/:\s]+):(?!\/\/)/.exec(s);
    return m !== null && !s.startsWith("/") && !s.startsWith(".") && !s.startsWith("~") ? (m[1] as string) : null;
  };
  const targetDir = values(p, "t", "target-directory")[0];
  const dest = targetDir ?? (pos[pos.length - 1] as string);
  const sources = targetDir !== undefined ? pos : pos.slice(0, -1);
  const recursive = has(p, "r", "R", "a", "recursive", "archive") || name === "rsync" || name === "ditto";
  const destRemote = remote(dest);
  for (const s of sources) {
    const sr = remote(s);
    if (sr !== null) {
      egress(c, sr, "fetch", { payload, via: name, scheme: "ssh" });
      const info = writePath(c, dest, { via: name });
      if (info !== null) addEffect(c, { cls: "write_workspace", target: info.abs, detail: `download into ${info.abs}`, download: info.abs });
      continue;
    }
    readPath(c, s, { via: name, recursive });
    if (name === "mv") writePath(c, s, { via: "mv", remove: true });
  }
  if (destRemote !== null) {
    egress(c, destRemote, "send", { payload, via: name, scheme: "ssh" });
  } else if (sources.every((s) => remote(s) === null)) {
    writePath(c, dest, { via: name });
    // Copying into a directory: the file keeps its name, which may be a protected one.
    for (const s of sources) {
      const base = basenameOf(s.replace(/\/+$/, ""));
      if (base !== "" && !/[*?]/.test(base)) {
        const probe = { ...c, effects: [] as typeof c.effects, findings: [] as typeof c.findings };
        writePath(probe, `${dest.replace(/\/+$/, "")}/${base}`, { via: name });
        for (const e of probe.effects) if (e.cls === "write_protected" || e.cls === "firewall_tamper" || e.cls === "write_persistence") addEffect(c, e);
      }
    }
  }
  return NO_STAGE;
}

function archiver(name: string, args: readonly Word[], c: Collector): StageKind {
  const first = args[0]?.text ?? "";
  const tarMode = name.endsWith("tar") ? (/^-?[A-Za-z]*x/.test(first) ? "x" : /^-?[A-Za-z]*[cru]/.test(first) ? "c" : /^-?[A-Za-z]*t/.test(first) ? "t" : "") : "";
  const p = parseArgs(args, { short: name.endsWith("tar") ? "fCTXI" : name === "unzip" ? "dx" : name === "zip" ? "xibt" : "o", long: ["file", "directory", "files-from", "exclude-from", "to-command", "use-compress-program", "checkpoint-action", "rsh-command", "info-script", "new-volume-script"] });
  for (const cmd of values(p, "to-command", "use-compress-program", "checkpoint-action", "rsh-command", "info-script", "new-volume-script", "I")) {
    addFinding(c, "env_injection", `${name} runs a helper program: ${cmd}`);
    addEffect(c, { cls: "execute_opaque", target: cmd, detail: `run ${cmd} from ${name}` });
  }
  if (name.endsWith("tar")) {
    const archive = values(p, "f", "file")[0] ?? (/^[A-Za-z]*f$/.test(first) && !first.startsWith("-") ? (args[1]?.text ?? "") : "");
    const dir = values(p, "C", "directory")[0];
    const files = p.positionals.filter((w) => w.text !== archive && w !== args[0] || (first.startsWith("-") && w !== args[0])).filter((w) => w.text !== archive && !(w === args[0] && !first.startsWith("-")));
    if (tarMode === "x") {
      if (archive !== "" && archive !== "-") readPath(c, archive, { via: "tar" });
      const into = dir ?? ".";
      writePath(c, into, { via: "tar extract" });
      // Extraction can drop CLAUDE.md, .claude/ or .git/hooks anywhere below the target.
      const probe = { ...c, effects: [] as typeof c.effects, findings: [] as typeof c.findings };
      for (const f of files) writePath(probe, `${into}/${f.text}`, { via: "tar extract" });
      for (const e of probe.effects) if (e.cls !== "write_workspace") addEffect(c, e);
      if (files.length === 0) untrustedExtraction(c, archive === "" || archive === "-" ? null : archive, into, "tar");
    } else if (tarMode === "c") {
      if (archive !== "" && archive !== "-") writePath(c, archive, { via: "tar create" });
      for (const f of files) readPath(c, dir !== undefined && !f.text.startsWith("/") ? `${dir}/${f.text}` : f.text, { via: "tar", recursive: true });
    } else if (archive !== "") readPath(c, archive, { via: "tar" });
    return archive === "-" && tarMode === "c" ? NO_STAGE : NO_STAGE;
  }
  if (name === "unzip") {
    const pos = p.positionals;
    if (pos[0] !== undefined) readPath(c, pos[0].text, { via: "unzip" });
    const into = values(p, "d")[0] ?? ".";
    writePath(c, into, { via: "unzip" });
    if (pos.length <= 1) untrustedExtraction(c, pos[0]?.text ?? null, into, "unzip");
    return NO_STAGE;
  }
  if (name === "zip" || name === "7z" || name === "7za" || name === "jar") {
    const pos = name === "7z" || name === "7za" || name === "jar" ? p.positionals.slice(1) : p.positionals;
    if (pos[0] !== undefined) writePath(c, pos[0].text, { via: name });
    for (const f of pos.slice(1)) readPath(c, f.text, { via: name, recursive: true });
    return NO_STAGE;
  }
  for (const f of p.positionals) {
    readPath(c, f.text, { via: name });
    if (!has(p, "c", "stdout", "l", "list", "t", "test")) writePath(c, f.text, { via: name });
  }
  return has(p, "d", "decompress") || name === "gunzip" ? { ...NO_STAGE, decodes: true } : NO_STAGE;
}

/**
 * F2: extracting a whole archive can drop CLAUDE.md, .claude/settings.json or a git hook anywhere below the
 * target, and the member names are not on the command line. In an untrusted session, an archive that came
 * from outside (downloaded, written by this untrusted session, outside the workspace, or piped in) is an
 * unresolvable write. A repository's own archive extracted as before stays allowed.
 */
function untrustedExtraction(c: Collector, archive: string | null, into: string, via: string): void {
  if (!c.state.tainted) return;
  let outside = archive === null && c.stdinPiped === true;
  if (archive !== null) {
    const r = resolvePath(archive, c.ctx);
    if (r !== null) {
      const ci = c.ctx.caseInsensitive;
      const inSet = (set: Set<string>): boolean => [...set].some((d) => isUnder(r.abs, d, ci));
      outside = inSet(c.state.downloaded) || inSet(c.state.taintedWrites) || !c.ctx.workspaceRoots.some((w) => isUnder(r.abs, w, ci)) || c.effects.some((e) => downloadsOf(e).some((d) => isUnder(r.abs, d, ci)));
    }
  }
  if (outside) addFinding(c, "unresolvable_write_target", `${via} extracts ${archive ?? "an archive from its input"}, which came from outside, into ${into}; it could create agent instructions, settings or git hooks there, and the member names are not on the command line`);
}

function fetcher(name: string, args: readonly Word[], c: Collector, payload: string): StageKind {
  let send = false;
  const urls: string[] = [];
  let outFile: string | null = null;
  let toStdout = true;
  /** F4: hosts the request really goes to besides (or instead of) the URL's host. */
  const via: { target: string; why: string }[] = (c.proxies ?? []).map((t) => ({ target: t, why: "a proxy variable" }));
  /** F15: URL words that hold an expansion; F5: the fetcher only prints help or its version. */
  const dynamicUrls = new Set<string>();
  const computedUrls = new Set<string>();
  let infoOnly = false;
  /** F33: files the request uploads (their size counts toward the byte budgets). */
  const uploads: string[] = [];
  const effectsBefore = c.effects.length;
  if (name === "curl" || name === "curlie") {
    const p = parseArgs(args, { short: "oHdXuAebcEFTKrmwxyYzCUQDtP", long: ["output", "header", "data", "data-raw", "data-binary", "data-ascii", "data-urlencode", "form", "form-string", "upload-file", "request", "user", "user-agent", "referer", "cookie", "cookie-jar", "cert", "key", "cacert", "capath", "config", "range", "max-time", "connect-timeout", "write-out", "proxy", "proxy-user", "url", "json", "resolve", "connect-to", "retry", "retry-delay", "retry-max-time", "limit-rate", "max-filesize", "output-dir", "interface", "dump-header", "trace", "trace-ascii", "stderr", "variable", "expand-url", "expand-data", "aws-sigv4", "oauth2-bearer", "unix-socket", "abstract-unix-socket", "netrc-file", "keepalive-time", "dns-servers", "doh-url", "preproxy", "socks4", "socks5", "socks5-hostname", "quote", "telnet-option", "mail-from", "mail-rcpt", "ftp-port", "pinnedpubkey", "proto", "proto-redir", "hsts", "alt-svc", "etag-save", "etag-compare", "parallel-max", "time-cond"] });
    urls.push(...p.positionals.map((w) => w.text), ...values(p, "url"));
    for (const w of p.positionals) if (w.dynamic) (w.subs.length > 0 ? computedUrls : dynamicUrls).add(w.text);
    for (const u of values(p, "url")) if (/\$|`/.test(u)) dynamicUrls.add(u);
    infoOnly = has(p, "V", "version", "h", "help", "M", "manual");
    for (const x of values(p, "x", "proxy", "preproxy", "socks4", "socks4a", "socks5", "socks5-hostname")) via.push({ target: x, why: "a proxy flag" });
    // --connect-to HOST1:PORT1:HOST2:PORT2 and --resolve [+]HOST:PORT:ADDR[,ADDR]: the connection goes to HOST2 / ADDR.
    for (const x of values(p, "connect-to")) {
      const m = /^(?:\[[^\]]*\]|[^:]*):[^:]*:(\[[^\]]*\]|[^:]*)(?::\d*)?$/.exec(x);
      const host = m?.[1] ?? "";
      if (host !== "") via.push({ target: host, why: "--connect-to" });
      else if (m === null) computedUrls.add(x);
    }
    for (const x of values(p, "resolve")) {
      const m = /^[+-]?(?:\[[^\]]*\]|[^:]*):[^:]*:(.+)$/.exec(x);
      for (const a of (m?.[1] ?? "").split(",")) if (a.trim() !== "") via.push({ target: a.trim().replace(/^\[|\]$/g, ""), why: "--resolve" });
    }
    for (const sock of values(p, "unix-socket", "abstract-unix-socket")) {
      if (CONTAINER_SOCKET.test(sock)) addEffect(c, { cls: "privilege", target: sock, detail: `send a request to the container engine's API socket ${sock}, which can start a privileged container (like docker run --privileged)` });
    }
    for (const d of values(p, "d", "data", "data-raw", "data-binary", "data-ascii", "data-urlencode", "F", "form", "form-string", "json", "T", "upload-file", "mail-rcpt", "Q", "quote")) {
      send = true;
      const at = /(?:^|=)@([^;]+)/.exec(d);
      if (at !== null && at[1] !== "-") {
        readPath(c, at[1] as string, { via: "curl upload" });
        uploads.push(at[1] as string);
      }
      if (/^-?$/.test(d) || at?.[1] === "-") toStdout = toStdout && true;
    }
    for (const f of values(p, "T", "upload-file")) if (f !== "-" && f !== ".") {
      readPath(c, f, { via: "curl upload" });
      uploads.push(f);
    }
    for (const f of values(p, "K", "config")) {
      readPath(c, f, { via: "curl config" });
      addFinding(c, "unresolvable_command", "curl reads its URL and data from a config file");
      send = true;
    }
    const method = (values(p, "X", "request")[0] ?? "").toUpperCase();
    if (method !== "" && method !== "GET" && method !== "HEAD" && method !== "OPTIONS") send = true;
    for (const f of values(p, "o", "output")) {
      if (f !== "-" && f !== "/dev/stdout") {
        outFile = f;
        toStdout = false;
      }
    }
    if (has(p, "O", "remote-name", "remote-name-all", "J")) {
      toStdout = false;
      const u = parseUrlLike(urls[0] ?? "");
      outFile = `${values(p, "output-dir")[0] ?? "."}/${basenameOf(u?.path ?? "download") || "download"}`;
    }
    for (const f of values(p, "c", "cookie-jar", "dump-header", "D", "trace", "trace-ascii", "stderr", "etag-save", "hsts", "alt-svc")) writePath(c, f, { via: "curl" });
    for (const f of values(p, "netrc-file", "E", "cert", "key")) readPath(c, f, { via: "curl credentials" });
  } else if (name === "wget") {
    const p = parseArgs(args, { short: "OoaPiBeUTtwQlAREIXDH", long: ["output-document", "output-file", "append-output", "directory-prefix", "input-file", "base", "execute", "user-agent", "timeout", "tries", "wait", "quota", "level", "accept", "reject", "domains", "exclude-domains", "post-data", "post-file", "body-data", "body-file", "method", "header", "user", "password", "http-user", "http-password", "load-cookies", "save-cookies", "certificate", "private-key", "ca-certificate", "config", "referer", "use-askpass"] });
    urls.push(...p.positionals.map((w) => w.text));
    for (const w of p.positionals) if (w.dynamic) (w.subs.length > 0 ? computedUrls : dynamicUrls).add(w.text);
    infoOnly = has(p, "V", "version", "h", "help") || has(p, "i", "input-file");
    if (has(p, "post-data", "post-file", "body-data", "body-file")) send = true;
    for (const f of values(p, "post-file", "body-file", "i", "input-file", "load-cookies", "config")) readPath(c, f, { via: "wget" });
    uploads.push(...values(p, "post-file", "body-file"));
    for (const m of values(p, "method")) if (!/^(?:GET|HEAD|OPTIONS)$/i.test(m)) send = true;
    for (const e of values(p, "e", "execute", "use-askpass")) {
      addFinding(c, "unresolvable_command", `wget runs a configuration command: ${e}`);
      addEffect(c, { cls: "execute_opaque", target: "wget", detail: `wget -e ${e}` });
    }
    if (has(p, "i", "input-file")) addFinding(c, "unresolvable_command", "wget reads the URLs to fetch from a file");
    const out = values(p, "O", "output-document")[0];
    if (out !== undefined && out !== "-") outFile = out;
    else if (out === undefined) {
      toStdout = false;
      const u = parseUrlLike(urls[0] ?? "");
      outFile = `${values(p, "P", "directory-prefix")[0] ?? "."}/${basenameOf(u?.path ?? "") || "index.html"}`;
    }
    if (has(p, "r", "recursive", "m", "mirror")) outFile = values(p, "P", "directory-prefix")[0] ?? ".";
    for (const f of values(p, "o", "output-file", "a", "append-output", "save-cookies")) writePath(c, f, { via: "wget" });
  } else if (name === "aria2c") {
    const p = parseArgs(args, { short: "odi", long: ["out", "dir", "input-file", "on-download-complete", "on-download-start"] });
    urls.push(...p.positionals.map((w) => w.text));
    outFile = values(p, "d", "dir")[0] ?? ".";
    toStdout = false;
    for (const e of values(p, "on-download-complete", "on-download-start")) executeFile(c, e, "aria2c hook");
  } else {
    // httpie-style: METHOD? URL [items]; items with = := @ send data.
    let i = 0;
    const rest = args.filter((a) => !a.text.startsWith("-"));
    if (rest[0] !== undefined && /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/i.test(rest[0].text)) {
      if (!/^(?:GET|HEAD|OPTIONS)$/i.test(rest[0].text)) send = true;
      i = 1;
    }
    if (name === "POST") send = true;
    const url = rest[i];
    if (url !== undefined) urls.push(url.text);
    for (const it of rest.slice(i + 1)) {
      if (/^[^=:@]+(?::=|=|==|@|:=@|=@)/.test(it.text)) {
        if (!/==/.test(it.text)) send = true;
        const at = /@(.+)$/.exec(it.text);
        if (at !== null) readPath(c, at[1] as string, { via: name });
      }
    }
    for (const a of args) if (a.text === "--form" || a.text === "-f" || a.text === "--json") send = send || rest.length > i + 1;
  }
  let any = false;
  const computed: string[] = [];
  for (const u of urls) {
    // F15: a host built from a variable, or a command substitution anywhere in the URL, is a computed address.
    const parsed = parseUrlLike(u);
    if (computedUrls.has(u) || (parsed !== null && /[$`]/.test(parsed.host)) || (dynamicUrls.has(u) && parsed === null)) {
      computed.push(u);
      continue;
    }
    let one = false;
    const glob = expandCurlGlob(u);
    for (const exp of glob.urls) if (egress(c, exp, send ? "send" : "fetch", { payload, via: name })) one = true;
    if (glob.truncated) addFinding(c, "too_large", `${name} expands ${u.slice(0, 200)} to more than ${MAX_CURL_GLOB} addresses, more than the firewall judges one by one`);
    if (glob.hostRange) addFinding(c, "unresolvable_command", `${name} varies the host with a [x-y] range in ${u.slice(0, 200)}: only its first value can be judged`);
    if (!one) computed.push(u);
    any = any || one;
    // F15: a variable in the path or query: the host is known, the data it carries is not (it may hold a whole
    // file). Once the session is untrusted that is a send the firewall cannot size.
    if (one && dynamicUrls.has(u) && c.state.tainted) addFinding(c, "unresolvable_command", `${name} sends a value only known at run time in the address ${u}`);
  }
  if (computed.length > 0) addFinding(c, "unresolvable_command", `${name} contacts an address only known at run time: ${computed.join(" ")}`);
  if (computed.length > 0) addEffect(c, { cls: send ? "egress_send" : "egress_fetch", target: computed.join(" "), detail: `${name} to a computed address`, payload });
  infoOnly = infoOnly || args.some((a) => /^(?:--version|--help|-V|-h)$/.test(a.text));
  // F5: no URL on the command line at all (xargs curl, a URL list on stdin): the address is only known at run time.
  if (urls.length === 0 && !infoOnly && !has0(args, "-K", "--config")) {
    addFinding(c, "unresolvable_command", `${name} has no address on its command line, so the address it contacts is only known at run time (xargs or input)`);
    addEffect(c, { cls: send ? "egress_send" : "egress_fetch", target: `${name} <address from input>`, detail: `${name} to an address read at run time`, payload });
  }
  // F4: a proxy, --connect-to or --resolve target receives the request: it is a destination for every rule.
  if (urls.length > 0 || via.length > 0) {
    for (const v of via) {
      if (/[$`]/.test(v.target)) {
        addFinding(c, "unresolvable_command", `${name} goes through ${v.why} only known at run time: ${v.target}`);
        continue;
      }
      if (!egress(c, v.target, send ? "send" : "fetch", { payload, via: `${name} through ${v.why}` })) addFinding(c, "unresolvable_command", `${name} goes through ${v.why} the firewall cannot parse: ${v.target}`);
    }
  }
  if (uploads.length > 0) {
    let size = 0;
    for (const f of uploads) {
      const r = resolvePath(f.replace(/^<|;.*$/g, ""), c.ctx);
      if (r === null) continue;
      try {
        size += c.ctx.fileSize?.(r.abs) ?? 0;
      } catch {
        // Unknown size: the command line still counts.
      }
    }
    if (size > 0) for (const e of c.effects.slice(effectsBefore)) if (e.cls === "egress_send" || e.cls === "egress_fetch") e.uploadBytes = (e.uploadBytes ?? 0) + size;
  }
  if (outFile !== null) {
    const info = writePath(c, outFile, { via: `${name} download` });
    if (info !== null) addEffect(c, { cls: "write_workspace", target: info.abs, detail: `save a download to ${info.abs}`, download: info.abs });
  }
  // What comes back is outside content, exactly like the WebFetch tool: the session becomes untrusted.
  taintFetched(c, urls.flatMap((u) => expandCurlGlob(u).urls), name);
  return { fetches: toStdout, decodes: false, runsStdin: false };
}

/** Whether a flag appears (as itself or with an attached value). */
function has0(args: readonly Word[], ...flags: string[]): boolean {
  return args.some((a) => flags.some((f) => a.text === f || a.text.startsWith(`${f}=`) || (f.length === 2 && !f.startsWith("--") && a.text.startsWith(f) && !a.text.startsWith("--"))));
}

/** The most URLs one curl glob expands to here; past it the rest are not followed (several {a,b} multiply). */
const MAX_CURL_GLOB = 256;
/** More {a,b} groups than this in one URL: only the first alternative of each is followed (and it is too_large). */
const MAX_CURL_GLOB_GROUPS = 32;

interface CurlGlob {
  urls: string[];
  /** Past MAX_CURL_GLOB addresses (or MAX_CURL_GLOB_GROUPS groups): the rest were not judged. */
  truncated: boolean;
  /** A [x-y] range in an address's host: only its first value was judged. */
  hostRange: boolean;
}

/**
 * curl URL globbing: every alternative of each {a,b} (up to MAX_CURL_GLOB addresses in total), and the first
 * value of each [x-y] range, enough to judge the host unless the range is in the host itself (hostRange).
 */
function expandCurlGlob(u: string): CurlGlob {
  const out: string[] = [];
  let truncated = false;
  let hostRange = false;
  const leaf = (s: string): void => {
    if (rangeInHost(s)) hostRange = true;
    out.push(firstOfRanges(s));
  };
  if ((u.match(/\{[^{}]*\}/g)?.length ?? 0) > MAX_CURL_GLOB_GROUPS) {
    // A replacer function: an alternative is inserted as written ("$&" and "$'" are not patterns).
    leaf(u.replace(/\{([^{}]*)\}/g, (_m, g: string) => g.split(",")[0] as string));
    return { urls: out, truncated: true, hostRange };
  }
  const walk = (s: string): void => {
    const braces = /\{([^{}]*)\}/.exec(s);
    if (braces === null) {
      leaf(s);
      return;
    }
    // Sliced around the group, never s.replace(group, alt): an alternative holding "$&" or "$'" stays itself.
    const head = s.slice(0, braces.index);
    const tail = s.slice(braces.index + braces[0].length);
    for (const alt of (braces[1] as string).split(",")) {
      if (out.length >= MAX_CURL_GLOB) {
        truncated = true;
        return;
      }
      walk(head + alt + tail);
    }
  };
  walk(u);
  return { urls: out, truncated, hostRange };
}

/** Whether a [x-y] range sits in the URL's authority (its host or port). */
function rangeInHost(u: string): boolean {
  const scheme = /^[a-z][a-z0-9+.-]*:\/\//i.exec(u);
  const rest = scheme === null ? u : u.slice(scheme[0].length);
  const end = rest.search(/[/?#]/);
  const authority = end === -1 ? rest : rest.slice(0, end);
  // In one pass (not /\[[^\]]*-[^\]]*\]/, which backtracks over many "[" with no "]"; see firstOfRanges).
  let i = 0;
  while (i < authority.length) {
    const open = authority.indexOf("[", i);
    if (open === -1) return false;
    const close = authority.indexOf("]", open + 1);
    if (close === -1) return false;
    if (authority.lastIndexOf("-", close) > open) return true;
    i = close + 1;
  }
  return false;
}

/**
 * Each `[x-y]` range replaced by what comes before its last "-" (as /\[([^\]]*)-[^\]]*\]/g would), in one pass:
 * that pattern backtracked over every "[" with no "]" after it, cubic in a URL of many "[" (shell:robust seed
 * 142930: 13,941 characters took 8 s).
 */
function firstOfRanges(u: string): string {
  let out = "";
  let i = 0;
  while (i < u.length) {
    const open = u.indexOf("[", i);
    if (open === -1) break;
    const close = u.indexOf("]", open + 1);
    // No "]" after this "[" means none after any later one either.
    if (close === -1) break;
    const inner = u.slice(open + 1, close);
    const dash = inner.lastIndexOf("-");
    if (dash === -1) {
      // Every "[" up to this "]" closes here too, with no "-" inside: none of them is a range.
      out += u.slice(i, close);
      i = close;
      continue;
    }
    out += u.slice(i, open) + inner.slice(0, dash);
    i = close + 1;
  }
  return out + u.slice(i);
}

function rawSender(name: string, args: readonly Word[], c: Collector, payload: string, depth: number): StageKind {
  if (name === "openssl") {
    const sub = args[0]?.text ?? "";
    if (sub === "s_client" || sub === "s_time") {
      for (let i = 1; i < args.length; i++) {
        if ((args[i] as Word).text === "-connect" || (args[i] as Word).text === "-proxy") egress(c, args[i + 1]?.text ?? "", "send", { payload, via: "openssl s_client" });
      }
      return NO_STAGE;
    }
    if (/^(?:enc|base64)$/.test(sub) && args.some((a) => a.text === "-d")) return { ...NO_STAGE, decodes: true };
    for (const a of args) {
      if (/^-(?:in|out|key|inkey|passin)$/.test(a.text)) continue;
    }
    const p = parseArgs(args.slice(1), { short: "", long: ["in", "out", "key", "inkey", "passin", "passout", "signkey", "CAfile", "certfile"] });
    for (const f of values(p, "in", "key", "inkey", "signkey")) readPath(c, f, { via: `openssl ${sub}` });
    for (const f of values(p, "out")) writePath(c, f, { via: `openssl ${sub}` });
    return NO_STAGE;
  }
  if (name === "redis-cli") {
    const p = parseArgs(args, { short: "hpasnu", long: ["user", "pass", "tls"] });
    const host = values(p, "h")[0];
    const url = values(p, "u")[0];
    if (url !== undefined) egress(c, url, "send", { payload, via: name, scheme: "redis" });
    else if (host !== undefined) egress(c, host, "send", { payload, via: name });
    if (p.positionals.some((w) => /^(?:FLUSHALL|FLUSHDB|SHUTDOWN|CONFIG|DEBUG|SLAVEOF|REPLICAOF|MODULE)$/i.test(w.text))) addEffect(c, { cls: "destructive", target: "redis", detail: `redis ${p.positionals.map((w) => w.text).join(" ")}` });
    return NO_STAGE;
  }
  if (name === "sftp" || name === "ftp" || name === "lftp" || name === "tftp" || name === "smbclient") {
    for (const a of args) if (!a.text.startsWith("-")) egress(c, a.text.replace(/^[^@]*@/, "").replace(/:.*$/, ""), "send", { payload, via: name });
    return NO_STAGE;
  }
  const p = parseArgs(args, { short: "pswiqxXceIOTW", long: ["source", "proxy", "exec", "sh-exec", "lua-exec"] });
  for (const e of values(p, "e", "c", "exec", "sh-exec")) {
    addFinding(c, "obfuscated_exec", `${name} runs a program on a network connection`);
    addEffect(c, { cls: "execute_opaque", target: e, detail: `${name} -e ${e}` });
  }
  if (has(p, "l", "listen") || args.some((a) => /^(?:TCP|UDP)[46]?-LISTEN:/i.test(a.text))) {
    externalSend(c, `listener:${name}`, `open a network listener with ${name}`, payload);
  }
  for (const a of p.positionals) {
    if (/^\d+$/.test(a.text)) continue;
    const socat = /^(?:TCP|UDP|SSL|OPENSSL|TCP4|TCP6|UDP4|UDP6)[46]?:([^:,]+)/i.exec(a.text);
    if (socat !== null) egress(c, socat[1] as string, "send", { payload, via: name });
    else if (/^(?:EXEC|SYSTEM):/i.test(a.text)) {
      addFinding(c, "obfuscated_exec", `${name} runs a program on a network connection`);
      addEffect(c, { cls: "execute_opaque", target: a.text, detail: `${name} ${a.text}` });
    } else if (!/^[A-Z]+:/.test(a.text) && !a.text.startsWith("-")) egress(c, a.text, "send", { payload, via: name });
  }
  if (c.effects.some((e) => e.cls === "egress_send" && e.host !== undefined)) addEffect(c, { cls: "read_external", target: name, detail: `read what ${name} receives from the network`, taints: true });
  if (name === "nmap" || name === "masscan") addEffect(c, { cls: "execute_opaque", target: name, detail: `scan networks with ${name}` });
  void depth;
  return NO_STAGE;
}

function ssh(name: string, args: readonly Word[], c: Collector, payload: string, depth: number): StageKind {
  const p = parseArgs(args, { short: "bcDEeFIiJLlmOoPpQRSWw", long: [], stopAtPositional: true });
  const target = p.positionals[0]?.text;
  for (const o of values(p, "o")) if (/^(?:ProxyCommand|LocalCommand|PermitLocalCommand|KnownHostsCommand|Match)/i.test(o)) {
    addFinding(c, "env_injection", `ssh runs a local command from an option: ${o}`);
    addEffect(c, { cls: "execute_opaque", target: o, detail: `ssh -o ${o}` });
  }
  for (const f of values(p, "F")) readPath(c, f, { via: "ssh config" });
  if (has(p, "R")) externalSend(c, `listener:ssh-R`, "expose a local port to a remote machine with ssh -R", payload);
  if (target === undefined) return NO_STAGE;
  const host = target.replace(/^ssh:\/\//, "").replace(/^[^@]*@/, "").replace(/:\d+$/, "");
  egress(c, host, "send", { payload, via: name, scheme: "ssh" });
  const remoteCmd = p.positionals.slice(1).map((w) => w.text).join(" ");
  if (remoteCmd !== "") addEffect(c, { cls: "execute_opaque", target: host, detail: `run "${remoteCmd.slice(0, 80)}" on ${host}` });
  addEffect(c, { cls: "read_external", target: host, detail: `read output from the remote machine ${host}`, taints: true });
  void depth;
  return NO_STAGE;
}

function agentCli(name: string, args: readonly Word[], c: Collector, depth: number): StageKind {
  const flags = args.filter((a) => BYPASS_FLAGS.test(a.text) || /^--permission-mode=bypassPermissions$/.test(a.text));
  const pm = args.findIndex((a) => a.text === "--permission-mode");
  if (pm !== -1 && /bypass|dontAsk|auto/i.test(args[pm + 1]?.text ?? "")) flags.push(args[pm + 1] as Word);
  if (name === "q" || name === "qchat") {
    if (args.some((a) => a.text === "--trust-all-tools" || a.text === "-a")) flags.push(args[0] as Word);
  }
  const sub = args.find((a) => !a.text.startsWith("-"))?.text ?? "";
  if ((name === "claude" || name === "codex" || name === "gemini") && (sub === "mcp" || sub === "config" || sub === "plugin" || sub === "plugins" || sub === "install" || sub === "update" || sub === "setup-token")) {
    const words = args.filter((a) => !a.text.startsWith("-"));
    const sub2 = words[1]?.text ?? "";
    if (sub === "mcp" && !/^(?:list|get|show|ls)$/.test(sub2)) {
      // V35: `claude mcp remove <server>` (or add over it) rewrites an entry the gateway wrapped, in a file
      // whose result the firewall cannot check: the server's calls would no longer go through the gateway.
      const wrapped = wrappedServerNames(c.ctx, name);
      const hit = words.slice(2).find((w) => wrapped.has(w.text));
      if (hit !== undefined) addEffect(c, { cls: "firewall_tamper", target: `${name} mcp ${sub2}`, detail: `change MCP server "${hit.text}" with ${name} mcp ${sub2}; the firewall's gateway wraps it, and its calls would no longer be checked` });
    }
    if (!/^(?:list|get|show|ls)$/.test(sub2)) addEffect(c, { cls: "write_protected", target: `${name} ${sub}`, detail: `change ${name}'s ${sub} configuration`, tags: ["settings"] });
    return NO_STAGE;
  }
  if (args.some((a) => a.text === "--settings" || a.text.startsWith("--settings=") || a.text === "--mcp-config" || a.text.startsWith("--mcp-config=") || a.text === "--plugin-dir" || a.text === "--agents")) {
    flags.push(args[0] as Word);
    addFinding(c, "hook_disable", `${name} is started with its own settings or MCP servers, which can turn the firewall's hooks off`);
  }
  if (flags.length > 0) addFinding(c, "bypass_flags", `${name} is started with its safety checks off (${flags.map((f) => f.text).join(" ")})`);
  addEffect(c, { cls: "agent_spawn", target: name, detail: `start another coding agent (${name})` });
  void depth;
  return NO_STAGE;
}

const GIT_DESTROY = (sub: string, rest: string[]): boolean => {
  if (sub === "reset" && rest.includes("--hard")) return true;
  if (sub === "clean" && rest.some((r) => /^-[a-zA-Z]*f/.test(r) || r === "--force")) return true;
  if (sub === "stash" && (rest[0] === "clear" || rest[0] === "drop")) return true;
  if (sub === "filter-branch" || sub === "filter-repo") return true;
  if (sub === "reflog" && rest[0] === "expire") return true;
  if (sub === "update-ref" && rest.includes("-d")) return true;
  if (sub === "branch" && rest.some((r) => r === "-D" || /^--delete$/.test(r)) && rest.some((r) => r === "--force" || r === "-D")) return false;
  return false;
};

/**
 * F2: the actions a patch amounts to are judged exactly like the agent's file tools (classifyAction), and
 * their effects and findings join this command's. Bounded: a patch naming many files is judged up to 200.
 */
function judgePatchActions(c: Collector, actions: readonly NormalizedAction[], via: string): void {
  for (const a of actions.slice(0, 200)) {
    const sub = classifyAction(a, c.ctx, c.cfg, c.state);
    for (const f of sub.findings) addFinding(c, f.id, `${f.detail} (${via})`);
    for (const e of sub.effects) addEffect(c, { ...e, detail: `${e.detail} (${via})` });
  }
  if (actions.length > 200) addFinding(c, "too_large", `${via} changes more files than the firewall checks (${actions.length})`);
}

/**
 * F2: a patch whose text the firewall cannot see (read from a pipe, from a file this command line writes,
 * or that does not parse): the files it writes are unknown. That is an unresolvable write in an untrusted
 * session, and in any session when the workspace holds an agent settings file (the patch could switch the
 * firewall's hooks off).
 */
function unknownPatch(c: Collector, via: string, why: string): void {
  const settings = c.ctx.workspaceRoots.some((root) => settingsFilesUnder(root).some((p) => {
    try {
      return c.ctx.readFile?.(p) != null;
    } catch {
      return true;
    }
  })) || (c.ctx.registeredSettings ?? []).some((p) => c.ctx.workspaceRoots.some((root) => isUnder(p, root, PROTECTION_FOLDS_CASE)));
  if (c.state.tainted || settings) addFinding(c, "unresolvable_write_target", `${via} applies a patch ${why}, so the files it writes are unknown${settings && !c.state.tainted ? " (the workspace holds agent settings it could change)" : ""}`);
}

/** F2: the text of a patch given as a file (null: unknown, with the reason). */
function patchFileText(c: Collector, raw: string): { text: string } | { why: string } {
  const r = resolvePath(raw, c.ctx);
  if (r === null || !r.exact) return { why: `from ${raw}, a path only known at run time` };
  const fromHeredoc = c.heredocFiles?.get(r.abs);
  if (fromHeredoc !== undefined) return fromHeredoc === null ? { why: `from ${r.abs}, which this command line appends to` } : { text: fromHeredoc };
  if (c.effects.some((e) => e.target === r.abs && /^write_|^firewall_tamper$/.test(e.cls))) return { why: `from ${r.abs}, which this command line writes` };
  let text: string | null = null;
  try {
    text = c.ctx.readFile?.(r.abs) ?? null;
  } catch {
    text = null;
  }
  return text === null ? { why: `from ${r.abs}, which the firewall cannot read` } : { text };
}

/** F2: judges a patch text (a unified diff, or a Codex patch) with the tool's path rule. */
function judgePatchText(c: Collector, text: string, rule: PathRule, via: string): void {
  if (/^\s*\*\*\* Begin Patch\s*$/m.test(text)) {
    const acts = codexPatchActions(text);
    if (acts === null) unknownPatch(c, via, "the firewall cannot parse");
    else judgePatchActions(c, acts, via);
    return;
  }
  const d = parseUnifiedDiff(text);
  if (!d.ok) {
    unknownPatch(c, via, `the firewall cannot parse (${d.reason})`);
    return;
  }
  judgePatchActions(c, diffActions(d.files, rule), via);
}

/** F2: where a patch-applying command reads its patch: a here-document, files, standard input. */
function patchSources(c: Collector, files: readonly string[], stdin: string | null, rule: PathRule, via: string): void {
  if (files.length > 0) {
    for (const f of files) {
      const t = patchFileText(c, f);
      if ("text" in t) judgePatchText(c, t.text, rule, via);
      else unknownPatch(c, via, t.why);
    }
    return;
  }
  if (stdin !== null) return judgePatchText(c, stdin, rule, via);
  if (c.stdinFile !== undefined) {
    readPath(c, c.stdinFile, { via });
    const t = patchFileText(c, c.stdinFile);
    if ("text" in t) judgePatchText(c, t.text, rule, via);
    else unknownPatch(c, via, t.why);
    return;
  }
  unknownPatch(c, via, c.stdinPiped === true ? "piped in from another command" : "read from standard input");
}

/** F2: GNU/BSD patch. `patch [opts] [originalfile [patchfile]]`, -i patchfile, -pN, -d dir. */
function patchProgram(name: string, args: readonly Word[], c: Collector, stdin: string | null): StageKind {
  const p = parseArgs(args, { short: "ipdoDBFrVxYzgL", long: ["input", "strip", "directory", "output", "reject-file", "ifdef", "basename-prefix", "prefix", "suffix", "fuzz", "backup-if-mismatch", "get", "quoting-style", "version-control", "read-only", "merge"] });
  if (has(p, "dry-run", "help", "version", "v")) return NO_STAGE;
  for (const dir of values(p, "d", "directory")) shiftCwd(c, dir);
  const strip = values(p, "p", "strip").map((v) => Number(v)).find((n) => Number.isInteger(n) && n >= 0);
  const pos = p.positionals.map((w) => w.text);
  const out = values(p, "o", "output")[0];
  const rule: PathRule = out !== undefined && out !== "-" ? { strips: [], target: out } : pos[0] !== undefined ? { strips: [], target: pos[0] } : strip !== undefined ? { strips: [strip] } : { strips: [0, 1], basename: true };
  const input = values(p, "i", "input")[0] ?? pos[1];
  addEffect(c, { cls: "write_workspace", target: name, detail: `${name}: apply a patch` });
  patchSources(c, input !== undefined ? [input] : [], stdin, rule, name);
  return NO_STAGE;
}

/** F2: Codex's apply_patch on the shell's PATH: the patch is its argument or its here-document. */
function codexApplyPatch(name: string, args: readonly Word[], c: Collector, stdin: string | null): StageKind {
  addEffect(c, { cls: "write_workspace", target: name, detail: `${name}: apply a patch` });
  const arg = args.find((a) => !a.text.startsWith("-"));
  if (arg !== undefined && /\*\*\* Begin Patch/.test(arg.text)) {
    if (arg.dynamic) unknownPatch(c, name, "built at run time");
    else judgePatchText(c, arg.text, { strips: [0] }, name);
    return NO_STAGE;
  }
  patchSources(c, arg !== undefined ? [arg.text] : [], stdin, { strips: [0] }, name);
  return NO_STAGE;
}

function git(args: readonly Word[], c: Collector, payload: string, depth: number, stdin: string | null = null): StageKind {
  // Global options before the subcommand.
  let i = 0;
  let cwdShift: string | null = null;
  for (; i < args.length; i++) {
    const t = (args[i] as Word).text;
    if (t === "-C") {
      cwdShift = args[i + 1]?.text ?? null;
      i++;
      continue;
    }
    if (t === "-c") {
      const kv = args[i + 1]?.text ?? "";
      gitConfigValue(c, kv.split("=")[0] ?? "", kv.slice(kv.indexOf("=") + 1), "git -c");
      i++;
      continue;
    }
    if (t === "--git-dir" || t === "--work-tree" || t === "--namespace" || t === "--exec-path" || t === "--config-env") {
      if (t === "--exec-path" || t === "--config-env") {
        addFinding(c, "env_injection", `git ${t} changes what git runs`);
        addEffect(c, { cls: "execute_opaque", target: "git", detail: `git ${t}` });
      }
      i++;
      continue;
    }
    if (/^--(?:git-dir|work-tree|exec-path|config-env)=/.test(t)) continue;
    if (t.startsWith("-")) continue;
    break;
  }
  const sub = args[i]?.text ?? "";
  const restW = args.slice(i + 1);
  const rest = restW.map((w) => w.text);
  if (cwdShift !== null) shiftCwd(c, cwdShift);
  void depth;
  const remoteUrlOrName = (): string[] => rest.filter((r) => !r.startsWith("-"));
  switch (sub) {
    case "push": {
      const pos = remoteUrlOrName();
      const remote = pos[0] ?? "origin";
      const dest = /:\/\/|@/.test(remote) ? (parseUrlLike(remote.replace(/^[^@]+@([^:]+):/, "ssh://$1/"))?.host ?? remote) : `git-remote:${remote}`;
      if (/:\/\/|@/.test(remote)) egress(c, remote.replace(/^([^@/]+@)?([^:/]+):(?!\/\/)/, "ssh://$2/"), "send", { payload, via: "git push" });
      else externalSend(c, `git-remote:${remote}`, `push commits to the git remote "${remote}"`, payload);
      runsManifest(c, "git");
      void dest;
      // A push that names no branch pushes the one checked out: read it from .git/HEAD (unknown: asked).
      noteJudgement(c, judgePush(restW.map((w) => ({ text: w.text, dynamic: w.dynamic })), () => (c.ctx.cwdKnown === false ? null : currentBranch(c.ctx.cwd, c.ctx.readFile)), catastropheOptions(c)), `git-remote:${remote}`);
      if (rest.some((r) => r === "--force" || r === "-f" || r === "--mirror" || r === "--delete" || r === "-d" || r === "--prune" || /^--force-with-lease/.test(r) || /^\+/.test(r)) || pos.slice(1).some((r) => r.startsWith(":"))) {
        addEffect(c, { cls: "destructive", target: `git-remote:${remote}`, detail: "rewrite or delete history on a git remote (force push / delete / mirror)" });
      }
      return NO_STAGE;
    }
    case "clone":
    case "fetch":
    case "pull":
    case "ls-remote":
    case "remote":
    case "submodule":
    case "archive": {
      for (const r of rest) if (/^--(?:upload-pack|receive-pack|exec)=?/.test(r) || r === "-u") {
        addFinding(c, "env_injection", `git ${sub} ${r} runs a custom program`);
        addEffect(c, { cls: "execute_opaque", target: r, detail: `git ${sub} ${r}` });
      }
      if (sub === "remote") {
        if (rest[0] === "add" || rest[0] === "set-url") writePath(c, ".git/config", { via: `git remote ${rest[0]}` });
        return NO_STAGE;
      }
      if (sub === "submodule" && rest[0] !== "update" && rest[0] !== "add" && rest[0] !== "sync" && rest[0] !== "init") return NO_STAGE;
      const pos = remoteUrlOrName();
      for (const p of pos) {
        if (/^ext::/.test(p)) {
          addFinding(c, "obfuscated_exec", "git ext:: transport runs a command");
          addEffect(c, { cls: "execute_opaque", target: p, detail: `git ${sub} ${p}` });
        }
        if (/^(?:https?|git|ssh|ftp):\/\//.test(p) || /^[^@\s/]+@[^:\s]+:/.test(p)) egress(c, p.replace(/^([^@/]+@)?([^:/]+):(?!\/\/)/, "ssh://$2/"), "fetch", { payload, via: `git ${sub}` });
      }
      if (sub === "clone") {
        const urls = pos.filter((p) => /:\/\/|@.*:/.test(p));
        const target = pos.find((p) => !urls.includes(p)) ?? basenameOf((urls[0] ?? "repo").replace(/\.git$/, "").replace(/\/+$/, ""));
        const info = writePath(c, target, { via: "git clone" });
        if (info !== null) addEffect(c, { cls: "write_workspace", target: info.abs, detail: `clone a repository into ${info.abs}`, download: info.abs });
      }
      if (sub === "fetch" || sub === "pull" || sub === "ls-remote" || sub === "submodule") {
        // A fetch carries no data out; keep it a fetch.
        if (!pos.some((p) => /:\/\/|@.*:/.test(p))) externalSend(c, `git-remote:${pos[0] ?? "origin"}`, `${sub} from the git remote "${pos[0] ?? "origin"}"`, "", { cls: "egress_fetch" });
      }
      return NO_STAGE;
    }
    case "config": {
      const global = rest.includes("--global") || rest.includes("--system");
      const file = rest.indexOf("--file") !== -1 ? rest[rest.indexOf("--file") + 1] : rest.find((r) => r.startsWith("--file="))?.slice(7);
      const pos = rest.filter((r) => !r.startsWith("-") && r !== file);
      const reading = rest.some((r) => /^--(?:get|get-all|get-regexp|list|show-origin|show-scope)$/.test(r) || r === "-l") || pos.length < 2;
      if (reading) return NO_STAGE;
      if (global) writePath(c, "~/.gitconfig", { via: "git config --global" });
      else if (file !== undefined) writePath(c, file, { via: "git config --file" });
      else writePath(c, ".git/config", { via: "git config" });
      gitConfigValue(c, pos[0] ?? "", pos[1] ?? "", "git config");
      return NO_STAGE;
    }
    case "hook":
      if (rest[0] === "run") addEffect(c, { cls: "execute", target: "git hook", detail: `run git hook ${rest[1] ?? ""}` });
      return NO_STAGE;
    case "apply":
    case "am":
    case "checkout":
    case "restore":
    case "switch":
    case "merge":
    case "rebase":
    case "cherry-pick":
    case "revert":
    case "commit":
    case "add":
    case "rm":
    case "mv":
    case "stash":
    case "reset":
    case "clean":
    case "init":
    case "worktree":
    case "branch":
    case "tag":
    case "notes":
    case "gc":
    case "prune":
    case "filter-branch":
    case "filter-repo":
    case "reflog":
    case "update-ref":
    case "update-index":
    case "sparse-checkout": {
      if (/^(?:commit|merge|rebase|checkout|switch|am|cherry-pick|revert)$/.test(sub)) runsManifest(c, "git");
      if (GIT_DESTROY(sub, rest)) addEffect(c, { cls: "destructive", target: "git", detail: `git ${sub} ${rest.join(" ")}`.trim() + " (discards work)" });
      else addEffect(c, { cls: "write_workspace", target: "git", detail: `git ${sub}` });
      // Paths named for git to write land in the workspace; protected ones stay protected.
      if (sub === "checkout" || sub === "restore" || sub === "rm" || sub === "mv") {
        for (const r of rest) if (!r.startsWith("-") && /[./]/.test(r) && r !== "." && r !== "--") {
          const probe = { ...c, effects: [] as typeof c.effects, findings: [] as typeof c.findings };
          writePath(probe, r, { via: `git ${sub}` });
          for (const e of probe.effects) if (e.cls === "write_protected" || e.cls === "firewall_tamper") addEffect(c, e);
        }
      }
      if (sub === "commit" && rest.some((r) => r === "--no-verify" || r === "-n")) addEffect(c, { cls: "write_workspace", target: "git", detail: "commit without running the repository's checks" });
      // F2: git apply / git am write the files their patch names; each is judged like the file tools.
      if ((sub === "apply" || sub === "am") && !rest.some((r) => /^--(?:stat|numstat|summary|check|abort|skip|quit|show-current-patch)$/.test(r))) {
        const p = parseArgs(restW, { short: "pC", long: ["directory", "exclude", "include", "whitespace", "build-fake-ancestor", "patch-format", "resolvemsg", "quoted-cr"] });
        const strip = values(p, "p").map((v) => Number(v)).find((n) => Number.isInteger(n) && n >= 0) ?? 1;
        const dir = values(p, "directory")[0];
        const rule: PathRule = { strips: [strip], ...(dir !== undefined ? { prefix: dir } : {}) };
        const files = p.positionals.map((w) => w.text).filter((t) => t !== "-");
        patchSources(c, sub === "am" && files.length === 0 && stdin === null && c.stdinFile === undefined && c.stdinPiped !== true ? [] : files, stdin, rule, `git ${sub}`);
      }
      return NO_STAGE;
    }
    case "send-email":
    case "request-pull":
    case "imap-send":
      externalSend(c, "mail:git", `git ${sub}`, payload, { tags: ["message"] });
      return NO_STAGE;
    case "daemon":
    case "http-backend":
    case "instaweb":
      externalSend(c, "listener:git", `serve the repository with git ${sub}`, payload);
      return NO_STAGE;
    case "credential":
    case "credential-store":
    case "credential-cache":
    case "credential-osxkeychain":
      if (rest[0] === "fill" || rest[0] === "get") {
        addFinding(c, "credential_store_read", "git credential fill prints stored credentials");
        addEffect(c, { cls: "read_secret", target: "git credentials", detail: "print stored git credentials", private: true });
      }
      return NO_STAGE;
    case "":
      return NO_STAGE;
    default: {
      // Read-only and unknown subcommands (status, log, diff, show, blame, grep...): workspace reads.
      if (/^(?:status|log|diff|show|blame|grep|ls-files|ls-tree|rev-parse|rev-list|describe|shortlog|cat-file|for-each-ref|show-ref|merge-base|name-rev|whatchanged|range-diff|bisect|count-objects|fsck|verify-commit|verify-tag|var|version|help|check-ignore|check-attr|symbolic-ref|cherry|difftool|mergetool|format-patch|bundle|lfs|annotate)$/.test(sub)) {
        addEffect(c, { cls: "read_local_workspace", target: "git", detail: `git ${sub}` });
        if (sub === "difftool" || sub === "mergetool") addEffect(c, { cls: "execute", target: `git ${sub}`, detail: `git ${sub}` });
        if (sub === "format-patch" || sub === "bundle") for (const r of rest) if (r.startsWith("-o") || r === "create") writePath(c, rest[rest.indexOf(r) + 1] ?? ".", { via: `git ${sub}` });
        return NO_STAGE;
      }
      // git <alias> or git-<plugin>: unknown code.
      addEffect(c, { cls: "execute", target: `git ${sub}`, detail: `run git ${sub}` });
      return NO_STAGE;
    }
  }
}

/** Git configuration keys that make git run a program. */
function gitConfigValue(c: Collector, key: string, value: string, via: string): void {
  if (/^(?:core\.(?:sshCommand|hooksPath|fsmonitor|pager|editor|askPass|gitProxy|attributesFile|excludesFile|worktree)|alias\..*|.*\.(?:helper|cmd|command|textconv|clean|smudge|process|driver)|credential\..*|diff\.external|sequence\.editor|gpg\.program|gpg\..*\.program|uploadpack\.packObjectsHook|include\.path|includeIf\..*|http\..*proxy|url\..*\.insteadOf|remote\..*\.(?:uploadpack|receivepack|url|pushurl))$/i.test(key)) {
    if (!/^alias\./i.test(key) || value.startsWith("!")) {
      addFinding(c, "env_injection", `${via} sets ${key}, which makes git run or fetch something else`);
      addEffect(c, { cls: "write_persistence", target: key, detail: `${via} ${key}=${value.slice(0, 80)}` });
    }
  }
}

function forge(name: string, args: readonly Word[], c: Collector, payload: string): StageKind {
  const pos = args.filter((a) => !a.text.startsWith("-")).map((a) => a.text);
  const p = parseArgs(args, { short: "RXfFHtpqbBjsimwdlTaeoA", long: ["repo", "method", "field", "raw-field", "header", "input", "title", "body", "body-file", "base", "head", "jq", "template", "hostname", "label", "assignee", "reviewer", "milestone", "project", "visibility", "description", "homepage", "team", "source", "remote", "notes", "notes-file", "target", "web", "public", "private", "env", "org", "secret", "app", "visibility"] });
  const repo = values(p, "R", "repo")[0];
  const dest = `${name === "gh" ? "github" : name}:${repo ?? "current-repo"}`;
  const group = pos[0] ?? "";
  const action = pos[1] ?? "";
  for (const f of values(p, "F", "body-file", "notes-file", "input")) {
    const at = f.startsWith("@") ? f.slice(1) : f.includes("=@") ? f.slice(f.indexOf("=@") + 2) : f;
    if (at !== "-" && (f.startsWith("@") || f.includes("=@") || values(p, "body-file", "notes-file", "input").includes(f))) readPath(c, at, { via: `${name} upload` });
  }
  if (group === "auth") {
    if (action === "token" || (action === "status" && has(p, "t", "show-token"))) {
      addFinding(c, "credential_store_read", `${name} auth ${action} prints the stored token`);
      addEffect(c, { cls: "read_secret", target: `${name} token`, detail: `print the ${name} token`, private: true });
    } else if (action === "login" || action === "logout" || action === "refresh" || action === "setup-git" || action === "switch") {
      addEffect(c, { cls: "write_persistence", target: `${name} auth`, detail: `${name} auth ${action}` });
    }
    return NO_STAGE;
  }
  if (group === "api") {
    const method = (values(p, "X", "method")[0] ?? (has(p, "f", "F", "field", "raw-field", "input") ? "POST" : "GET")).toUpperCase();
    const endpoint = pos[1] ?? "";
    if (method === "GET" || method === "HEAD") {
      externalSend(c, dest, `read the ${name} API ${endpoint}`, payload, { cls: "egress_fetch", taints: true, private: true });
    } else {
      externalSend(c, `${name}:api ${endpoint}`, `${method} to the ${name} API ${endpoint}`, payload);
      if (method === "DELETE") addEffect(c, { cls: "destructive", target: endpoint, detail: `DELETE ${endpoint} on ${name}` });
    }
    return NO_STAGE;
  }
  if (group === "extension" || group === "alias" || group === "config") {
    if (action === "install" || action === "set" || action === "upgrade") {
      addEffect(c, { cls: "write_persistence", target: `${name} ${group}`, detail: `${name} ${group} ${action}` });
      if (group === "extension") addEffect(c, { cls: "execute_opaque", target: pos[2] ?? "", detail: `install a ${name} extension`, tags: ["install"] });
    }
    return NO_STAGE;
  }
  const readActions = /^(?:list|view|status|checks|diff|ls|show|search|watch|download|clone|browse|log|get|issues|prs|repos|code|commits)$/;
  if (group === "repo" && action === "clone") {
    const url = pos[2] ?? "";
    egress(c, url.includes("://") ? url : `https://github.com/${url}`, "fetch", { payload, via: `${name} repo clone` });
    const target = pos[3] ?? basenameOf(url.replace(/\.git$/, ""));
    const info = writePath(c, target, { via: `${name} repo clone` });
    if (info !== null) addEffect(c, { cls: "write_workspace", target: info.abs, detail: `clone into ${info.abs}`, download: info.abs });
    return NO_STAGE;
  }
  if (group === "search" || readActions.test(action) || readActions.test(group)) {
    // Issues, PRs, comments and code from a forge are written by outsiders.
    externalSend(c, dest, `read ${group} ${action} from ${name}`.trim(), payload, { cls: "egress_fetch", taints: true, private: true });
    if (action === "download") writePath(c, values(p, "D", "dir")[0] ?? ".", { via: `${name} download` });
    return NO_STAGE;
  }
  if (/^(?:delete|archive|rename|transfer)$/.test(action) || (group === "repo" && action === "edit" && args.some((a) => /--visibility|--public/.test(a.text)))) {
    addEffect(c, { cls: "destructive", target: dest, detail: `${name} ${group} ${action} ${repo ?? ""}`.trim() });
  }
  if (group === "secret" || group === "variable") {
    externalSend(c, dest, `${name} ${group} ${action}`, payload);
    return NO_STAGE;
  }
  // Comments, reviews and new issues are messages to people; opening or merging a pull request is a send.
  const message = /^(?:comment|review)$/.test(action) || (group === "issue" && /^(?:create|edit|close|reopen)$/.test(action)) || group === "gist";
  externalSend(c, group === "gist" ? `${name}:gist` : dest, `${name} ${group} ${action}${repo !== undefined ? ` on ${repo}` : ""}`.trim(), payload, message ? { tags: ["message"] } : {});
  return NO_STAGE;
}

function packageManager(name: string, args: readonly Word[], c: Collector, payload: string, depth: number): StageKind {
  notePackageCommand(c, name, args);
  // F18: `nix develop` / `nix shell` run the flake's or shell.nix's shellHook.
  if (name === "nix" && /^(?:develop|shell|print-dev-env)$/.test(args.find((a) => !a.text.startsWith("-"))?.text ?? "")) runsManifest(c, "nix-shell");
  // F-f: the directory flags these runners take (npm --prefix/-C, pnpm -C/--dir, yarn --cwd, bun --cwd, cargo -C/--manifest-path).
  const dirFlags: Record<string, { short: string; long: string[] }> = { npm: { short: "C", long: ["prefix"] }, pnpm: { short: "C", long: ["dir"] }, yarn: { short: "", long: ["cwd"] }, bun: { short: "", long: ["cwd"] }, cargo: { short: "C", long: ["manifest-path"] } };
  const df = own(dirFlags, name);
  let rest = args;
  if (df !== undefined) {
    const p = parseArgs(args, { short: df.short, long: df.long });
    for (const k of [...df.short.split(""), ...df.long].filter((x) => x !== "")) {
      for (const v of values(p, k)) shiftCwd(c, k === "manifest-path" ? dirnameOf(v) : v);
    }
    // Drop the flags and their values so the verb is still the first positional.
    const takes = new Set([...df.short.split("").filter((x) => x !== "").map((x) => `-${x}`), ...df.long.map((x) => `--${x}`)]);
    rest = args.filter((a, i) => !takes.has(a.text) && !takes.has(args[i - 1]?.text ?? "") && ![...takes].some((t) => t.startsWith("--") && a.text.startsWith(`${t}=`)));
  }
  return packageManagerIn(name, rest, c, payload, depth);
}

/**
 * The long options that name the registry, index or package source a package command contacts in place of its
 * default: --registry and a scope's --@scope:registry (npm, pnpm, yarn, bun, cargo), --index-url, --extra-index-url,
 * --index and --default-index (pip, uv, cargo), --find-links, --trusted-host and --source (gem, dotnet, poetry).
 */
const INDEX_FLAG = /^--(?:registry|@[^\s=]+:registry|index-url|extra-index-url|index|default-index|find-links|trusted-host|source)$/;

/**
 * Whether the word after `flag` is that option's value. npm, pnpm, yarn and bun have only --registry of INDEX_FLAG
 * (NPM_VALUE_FLAGS in packages.ts): npm's option parser reads any option it does not know, and a scope's
 * --@scope:registry without "=", as a switch, so the word after it stays the command or a package
 * (`npm --source install x` installs x). The other tools take a value for each, or stop at an option they lack.
 */
function indexValueFlag(name: string, flag: string): boolean {
  return /^(?:npm|pnpm|yarn|bun)$/.test(name) ? flag === "--registry" : INDEX_FLAG.test(flag);
}

/**
 * Reads the registries and indexes a package command names by option (FW-NEW-HOST, FW-FETCH): every INDEX_FLAG as
 * --flag=value, and as --flag value where the tool takes one (indexValueFlag), every time it is given (uv's named
 * index is name=URL); and pip's -i and -f, also written -iURL, for the Python installers only: elsewhere -f is
 * --force and pnpm's -i is --interactive, and the word after them is a package name, not a host. A local directory
 * given as the index is read, as a package given as a path is.
 */
function namedIndexes(c: Collector, name: string, verb: string, args: readonly Word[], payload: string): void {
  const py = /^(?:pip3?|uv|pipx|pipenv|pdm|poetry)$/.test(name);
  for (let i = 0; i < args.length; i++) {
    const t = (args[i] as Word).text;
    const joined = /^(--[^=]+)=(.+)$/.exec(t);
    let value: string | undefined;
    if (joined !== null) value = INDEX_FLAG.test(joined[1] as string) || joined[1] === "--i" ? joined[2] : undefined;
    else if (py && /^-[if][a-z][a-z0-9+.-]*:\/\//i.test(t)) value = t.slice(2);
    else if (indexValueFlag(name, t) || (py && (t === "-i" || t === "-f"))) value = args[i + 1]?.text;
    if (value === undefined || value === "") continue;
    if (/^(?:\.|\/|~)/.test(value)) readPath(c, value, { via: `${name} ${verb}` });
    else egress(c, value.replace(/^[\w.-]+=(?=[a-z][a-z0-9+.-]*:\/\/)/i, ""), "fetch", { payload, via: `${name} ${verb}` });
  }
}

function packageManagerIn(name: string, args: readonly Word[], c: Collector, payload: string, depth: number): StageKind {
  // An index option's value is neither the command nor a package. Taken for the command, it hid the install in
  // `npm --registry URL install x` and the publish in `npm --registry URL publish`. Only where the tool reads the
  // word as the value: npm's `--source install x` is a switch and an install.
  const pos = args.filter((a, i) => !a.text.startsWith("-") && !indexValueFlag(name, args[i - 1]?.text ?? "")).map((a) => a.text);
  let verb = pos[0] ?? "";
  if ((name === "go" && (verb === "install" || verb === "get")) || (name === "cargo" && verb === "install") || (name === "gem" && verb === "install")) verb = "install";
  // G1: these run code that is already installed (a project script or binary). They are executions,
  // checked against the project's definition files, not installs; the command they run is judged too.
  const inner = installedRunner(name, verb, args);
  if (inner !== null) {
    addEffect(c, { cls: "execute", target: `${name} ${verb}`, detail: `run ${inner.length > 0 ? (inner[0] as Word).text : "a project command"} with ${name} ${verb}` });
    runsManifest(c, name === "bundler" ? "bundle" : name);
    if (inner.length === 0) return NO_STAGE;
    // uv run script.py: the script is a file that runs.
    if (name === "uv" && /\.py$/.test((inner[0] as Word).text)) {
      executeFile(c, (inner[0] as Word).text, "uv run");
      genericArgs(inner.slice(1), c, payload, "uv run");
      return NO_STAGE;
    }
    return dispatch(inner, c, payload, depth + 1, null);
  }
  if (name === "pipx" || name === "uv") {
    if (verb === "pip") verb = pos[1] ?? "";
    if (verb === "run" || verb === "tool") {
      addEffect(c, { cls: "execute_opaque", target: pos[1] ?? "", detail: `download and run ${pos[1] ?? "a tool"} with ${name}`, tags: ["install"] });
      return NO_STAGE;
    }
  }
  if (name === "npm" && (verb === "exec" || verb === "x")) {
    addEffect(c, { cls: "execute_opaque", target: pos[1] ?? "", detail: `download and run ${pos[1] ?? "a package"} with npm exec`, tags: ["install"] });
    return NO_STAGE;
  }
  if (name === "npm" || name === "pnpm" || name === "yarn" || name === "bun") {
    if (verb === "config" || verb === "set") {
      if (pos[1] === "set" || verb === "set" || pos[1] === "edit" || pos[1] === "delete") {
        // F38: npm and pnpm write the user's config (~/.npmrc) unless told --location=project; yarn v1 writes
        // ~/.yarnrc and yarn 2+ the project's .yarnrc.yml. Every file it may write is judged.
        const loc = args.find((a) => /^--location=/.test(a.text))?.text.slice(11) ?? args[args.findIndex((a) => a.text === "--location" || a.text === "-L") + 1]?.text;
        const project = loc === "project" || args.some((a) => a.text === "--project");
        const rcs = name === "yarn" ? ["~/.yarnrc", ".yarnrc.yml"] : project ? [".npmrc"] : ["~/.npmrc"];
        for (const rc of rcs) writePath(c, rc, { via: `${name} config` });
        // The same .npmrc content check as a Write (a different registry, script-shell, ignore-scripts=false).
        // F38: the value is the word after the key, even when it starts with "--" (node-options "--require x").
        const words = args.map((a) => a.text);
        const vi = words.indexOf(verb);
        const setAt = verb === "set" ? vi : words.indexOf(pos[1] ?? "set", vi + 1);
        const after = words.slice(setAt + 1).filter((w, i, all) => !/^(?:--global|-g|--location(?:=.*)?|-L|--json|--project|--user)$/.test(w) && !(i > 0 && /^(?:--location|-L)$/.test(all[i - 1] ?? "")));
        const first = after[0] ?? "";
        const [key = "", value = ""] = first.includes("=") ? [first.slice(0, first.indexOf("=")), first.slice(first.indexOf("=") + 1)] : [first, after[1] ?? ""];
        if (pos[1] !== "delete" && pos[1] !== "edit") for (const rc of rcs) checkNpmConfig(c, rc, key, value);
      }
      return NO_STAGE;
    }
    if (verb === "run" || verb === "run-script" || verb === "test" || verb === "t" || verb === "start" || verb === "build" || verb === "lint" || verb === "dev" || verb === "rebuild" || verb === "restart" || verb === "stop" || verb === "pack" || verb === "version") {
      addEffect(c, { cls: "execute", target: `${name} ${verb}`, detail: `run the project's ${name} script ${pos[1] ?? verb}` });
      // R8: a project script runs the project's JS tools, which execute their config-as-code.
      runsManifest(c, name, JS_TOOL_CONFIGS);
      return NO_STAGE;
    }
    if (verb === "" && name === "yarn") verb = "install";
    if (verb === "audit" && pos[1] === "fix") verb = "install";
    if (/^(?:ls|list|ll|la|outdated|view|info|show|why|explain|audit|doctor|root|prefix|bin|help|search|whoami|ping|query|licenses|fund|docs|bugs|repo|home)$/.test(verb)) {
      addEffect(c, { cls: "egress_fetch", target: `${name} registry`, host: "registry.npmjs.org", destination: "registry.npmjs.org", detail: `${name} ${verb}`, payload });
      // A registry named by option is the one asked (npm view x --registry URL).
      namedIndexes(c, name, verb, args, payload);
      // Registry metadata (READMEs, descriptions) is written by package authors: outside content.
      if (/^(?:view|v|info|show|search|s|se|find)$/.test(verb)) addEffect(c, { cls: "read_external", target: `${name} registry`, detail: `read package metadata written by its authors (${name} ${verb})`, taints: true });
      return NO_STAGE;
    }
  }
  if (PUBLISH_VERBS.has(verb) || (name === "twine" && verb === "upload") || (name === "docker" && verb === "push")) {
    externalSend(c, `${name}:registry`, `${name} ${verb}: publish to a package registry`, payload);
    publishRegistry(c, name, verb, args, payload);
    if (verb === "unpublish" || verb === "yank" || verb === "deprecate") addEffect(c, { cls: "destructive", target: `${name}:registry`, detail: `${name} ${verb}` });
    return NO_STAGE;
  }
  if (INSTALL_VERBS.has(verb) || pos.length === 0) {
    const pkgs = pos.slice(1).filter((p) => !/^[A-Z_]+=/.test(p));
    // Install scripts run arbitrary code from the registry.
    addEffect(c, { cls: "execute", target: `${name} ${verb}`, detail: `${name} ${verb}${pkgs.length > 0 ? ` ${pkgs.slice(0, 5).join(" ")}` : ""}: download packages and run their install scripts`, tags: ["install"] });
    const runner = name === "pip3" ? "pip" : name;
    // R3: what an install reads to decide what to fetch and run (lockfiles, registry config, requirement
    // files named with -r/-c) is as much code as package.json once an untrusted session edited it.
    const req = parseArgs(args, { short: "rc", long: ["requirement", "constraint", "requirements", "constraints"] });
    const named = runner === "pip" || runner === "uv" ? values(req, "r", "requirement", "requirements", "c", "constraint", "constraints").filter((f) => f !== "" && !/^(?:https?|file):|^~/.test(f)) : [];
    runsManifest(c, runner, [...(own(INSTALL_INPUTS, runner) ?? []), ...named]);
    for (const p of pkgs) {
      if (/^(?:https?|git\+https?|git\+ssh|git|file):/.test(p) || /^(?:github|gitlab|bitbucket):/.test(p)) egress(c, p.replace(/^git\+/, ""), "fetch", { payload, via: `${name} ${verb}` });
      else if (/^(?:\.|\/|~)/.test(p)) readPath(c, p, { via: `${name} ${verb}` });
    }
    // The registry or index an install names is contacted.
    namedIndexes(c, name, verb, args, payload);
    return NO_STAGE;
  }
  if (name === "brew" && (verb === "services" || verb === "tap")) {
    addEffect(c, { cls: "write_persistence", target: "brew", detail: `brew ${verb} ${pos.slice(1).join(" ")}` });
    return NO_STAGE;
  }
  if ((name === "go" || name === "cargo" || name === "dotnet" || name === "swift" || name === "mvn" || name === "gradle" || name === "sbt" || name === "mix" || name === "dart" || name === "flutter" || name === "zig") && verb !== "") {
    addEffect(c, { cls: "execute", target: `${name} ${verb}`, detail: `${name} ${verb}` });
    // R3: these fetch and build the locked dependencies as part of build/test/run.
    runsManifest(c, name, INSTALL_INPUTS[name] ?? []);
    if (name === "go" && verb === "run") for (const p of pos.slice(1)) if (/^[a-z0-9.-]+\.[a-z]+\//.test(p) && /@/.test(p)) addEffect(c, { cls: "execute_opaque", target: p, detail: `download and run ${p}`, tags: ["install"] });
    return NO_STAGE;
  }
  if (/^(?:uninstall|remove|rm|purge|autoremove|clean|cache)$/.test(verb)) {
    addEffect(c, { cls: "write_workspace", target: name, detail: `${name} ${verb}` });
    return NO_STAGE;
  }
  addEffect(c, { cls: "execute", target: `${name} ${verb}`, detail: `${name} ${verb}` });
  runsManifest(c, name);
  void depth;
  return NO_STAGE;
}

/**
 * G1: `bundle exec`, `pnpm exec`, `yarn exec`, `poetry run`, `pipenv run` and `uv run` of a project
 * script run code that is already installed, unlike `npm exec`/`npx`, `pnpm dlx`, `yarn dlx`, `bunx`
 * and `uvx`, which download. Returns the command they run (words after the verb), or null when the
 * invocation is not of this kind (including `uv run --with ...`, which installs).
 */
const RUNNER_VALUE_FLAGS = /^(?:--python|-p|--project|--directory|--env-file|--package|--group|--extra|--filter|-F|--workspace|--prefix|--cwd)$/;

function installedRunner(name: string, verb: string, args: readonly Word[]): Word[] | null {
  const isExec = verb === "exec" && (name === "bundle" || name === "bundler" || name === "pnpm" || name === "yarn");
  const isRun = verb === "run" && (name === "poetry" || name === "pipenv" || name === "pdm" || name === "hatch" || name === "rye" || (name === "uv" && !args.some((a) => /^--(?:with|with-requirements|with-editable|from|script|isolated)\b/.test(a.text) || a.text === "-w")));
  if (!isExec && !isRun) return null;
  const i = args.findIndex((a) => a.text === verb);
  if (i === -1) return null;
  let rest = args.slice(i + 1);
  // Options of the runner itself come before the command (pnpm exec -r, uv run --frozen, bundle exec --keep-file-descriptors).
  while (rest.length > 0 && (rest[0] as Word).text.startsWith("-") && (rest[0] as Word).text !== "--") rest = rest.slice(RUNNER_VALUE_FLAGS.test((rest[0] as Word).text) ? 2 : 1);
  if (rest[0]?.text === "--") rest = rest.slice(1);
  return rest;
}

/** A cloud/infra read that contacts the provider but sends no workspace data out. Allowed; still marks the session sensitive. */
function cloudRead(c: Collector, dest: string, detail: string): void {
  // Logs carry whatever outsiders sent to the service (request bodies, user input): outside content.
  addEffect(c, { cls: "read_external", target: dest, detail, private: true, ...(/\blogs?\b/.test(detail) ? { taints: true } : {}) });
}

/** Options of the infrastructure-as-code CLIs that take no value, so the word after one is not its value. */
const IAC_BARE_FLAGS = new Set(["--all", "--graph", "--non-interactive", "--terragrunt-non-interactive"]);
/** Subcommands that change live infrastructure. */
const IAC_CHANGE = /^(?:apply|up|deploy|import|taint|untaint|state|refresh|force-unlock)$/;
/**
 * Saving a plan to a file: terraform's -out, pulumi's --save-plan, and terragrunt's plan directories (the
 * older --terragrunt-out-dir, --out-dir, and the JSON ones, which keep the plan file beside the JSON).
 */
const SAVED_PLAN = /^--?(?:out|save-plan|(?:terragrunt-)?(?:json-)?out-dir)(?:=|$)/;

/** terragrunt's deprecated `destroy-all`, `plan-all` and `apply-all` mean `destroy`, `plan` and `apply`. */
function iacWord(name: string, w: string): string {
  return name === "terragrunt" && /^(?:destroy|plan|apply)-all$/.test(w) ? w.slice(0, -"-all".length) : w;
}

/**
 * The subcommand of an infrastructure-as-code CLI. terragrunt's `run-all` and `run` wrap terraform's own
 * (`terragrunt run-all plan`, `terragrunt run --all -- plan`). Not `sure` when an option written without `=`
 * comes right before it: the word may be that option's value (`pulumi --cwd preview up`, `terragrunt
 * --working-dir infra apply`), and the subcommand a later word.
 */
function iacVerb(name: string, args: readonly Word[]): { verb: string; sure: boolean } {
  const at = args.flatMap((a, i) => (a.text.startsWith("-") ? [] : [i]));
  const first = at[0] === undefined ? "" : (args[at[0]] as Word).text;
  const i = name === "terragrunt" && (first === "run-all" || first === "run") ? at[1] : at[0];
  if (i === undefined) return { verb: "", sure: true };
  const before = args[i - 1]?.text;
  const sure = before === undefined || !before.startsWith("-") || before === "--" || before.includes("=") || IAC_BARE_FLAGS.has(before);
  return { verb: iacWord(name, (args[i] as Word).text), sure };
}

function cloudCli(name: string, args: readonly Word[], c: Collector, payload: string, stdin: string | null): StageKind {
  const pos = args.filter((a) => !a.text.startsWith("-")).map((a) => a.text);
  const dest = `cloud:${name}`;
  if (name === "docker" || name === "podman" || name === "nerdctl") return container(name, args, c, payload);
  if (name === "psql" || name === "mysql" || name === "mariadb" || name === "pgcli" || name === "mycli" || name === "clickhouse-client" || name === "sqlcmd" || name === "mongosh" || name === "mongo" || name === "cqlsh" || name === "usql" || name === "influx") {
    const p = parseArgs(args, { short: "cehHUdpfuDQWPSs", long: ["command", "execute", "eval", "host", "username", "dbname", "port", "file", "user", "database", "query"] });
    const sql = [...values(p, "c", "command", "e", "execute", "eval", "query"), stdin ?? ""].join(";\n");
    for (const f of values(p, "f", "file")) readPath(c, f, { via: name });
    const host = values(p, "h", "host")[0] ?? (pos.find((x) => /^(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|clickhouse):\/\//.test(x)) ?? "");
    const remote = host !== "" && !/^(?:localhost|127\.|\/|::1)/.test(host.replace(/^[a-z+]+:\/\/(?:[^@]*@)?/, ""));
    const s = classifySql(sql);
    const target = remote ? `database:${host.replace(/^[a-z+]+:\/\/(?:[^@]*@)?/, "").split(/[/:?]/)[0]}` : `database:${name}`;
    if (remote) egress(c, host.includes("://") ? host : `${host}`, s.writes || s.destroys ? "send" : "fetch", { payload, via: name, scheme: "postgres" });
    if (s.destroys) addEffect(c, { cls: "destructive", target, detail: `run destructive SQL with ${name}` });
    const whole = judgeSql(sql, remote, catastropheOptions(c));
    noteJudgement(c, whole === null ? null : { ...whole, reason: `${name}: ${whole.reason}` }, target);
    if (s.external || s.opaque) addEffect(c, { cls: "execute_opaque", target, detail: `run SQL that reaches outside the database or builds SQL at run time` });
    if (s.writes && !s.destroys) externalSend(c, target, `change data in ${target} with ${name}`, payload);
    // Query results from a database are private data.
    addEffect(c, { cls: "read_external", target, detail: `read data from ${target}`, private: true, taints: remote });
    return NO_STAGE;
  }
  // Generic cloud/infra CLI: find the verb.
  const verbs = pos.slice(0, 4);
  const destroyVerb = verbs.find((v) => DESTROY_VERBS.test(v));
  if (name === "terraform" || name === "tofu" || name === "terragrunt" || name === "pulumi" || name === "cdk" || name === "sam" || name === "serverless" || name === "sls") {
    const { verb: v, sure } = iacVerb(name, args);
    // Not sure which word is the subcommand: every word may be, so a teardown or a change anywhere counts.
    const lead = sure ? [v] : pos.map((w) => iacWord(name, w));
    const destroying = args.some((a) => /^--?destroy(?:=.*)?$/.test(a.text));
    // The preview the catastrophic messages send people to (terraform plan -destroy, pulumi preview --destroy)
    // changes nothing: it is judged as the plain plan is. Only a verb read as exactly that, for sure, counts as
    // one; any other command carrying the flag stays a teardown (a wrong guess at the verb asks, never allows).
    const preview = sure && (name === "pulumi" ? v === "preview" : (name === "terraform" || name === "tofu" || name === "terragrunt") && v === "plan");
    const change = lead.find((w) => IAC_CHANGE.test(w));
    if (lead.includes("destroy") || (destroying && !preview)) addEffect(c, { cls: "destructive", target: dest, detail: `${name} destroy: delete infrastructure` });
    // Saved to a file, the preview is the first half of a teardown: applying that file takes no destroy flag
    // (terraform apply FILE), so nothing at the apply says destroy. Saving it asks, as a targeted destroy does.
    else if (destroying && args.some((a) => SAVED_PLAN.test(a.text))) addEffect(c, { cls: "destructive", target: dest, detail: `${name} ${v} -destroy with a saved plan file writes a plan that deletes every resource, and applying that file later carries no destroy flag to check` });
    else if (change !== undefined) externalSend(c, dest, `${name} ${change}: change live infrastructure`, payload);
    // Not sure of the subcommand, the read names every word, so `pulumi -C infra logs` still reads service logs.
    else cloudRead(c, dest, `${name} ${sure ? v : lead.join(" ")}`);
    return NO_STAGE;
  }
  if (name === "fastlane" || name === "eas" || name === "eas-cli" || name === "expo" || name === "codemagic-cli-tools") return mobileDeploy(name, args, pos, c, payload);
  if (name === "aws") {
    const svc = pos[0] ?? "";
    const op = pos[1] ?? "";
    if (svc === "configure" && (op === "get" || op === "export-credentials" || op === "list")) {
      addFinding(c, "credential_store_read", `aws configure ${op} may read stored credentials`);
      addEffect(c, { cls: "read_secret", target: "aws credentials", detail: `aws configure ${op}`, private: true });
      return NO_STAGE;
    }
    if ((svc === "secretsmanager" && op === "get-secret-value") || (svc === "ssm" && /get-parameters?/.test(op) && args.some((a) => a.text === "--with-decryption")) || (svc === "sts" && /get-session-token|assume-role|get-federation-token/.test(op)) || (svc === "ecr" && op === "get-login-password") || (svc === "codeartifact" && op === "get-authorization-token")) {
      addEffect(c, { cls: "read_secret", target: `aws ${svc} ${op}`, detail: `fetch a secret with aws ${svc} ${op}`, private: true });
      return NO_STAGE;
    }
    if (svc === "s3" && (op === "cp" || op === "mv" || op === "sync")) {
      const paths = pos.slice(2);
      const dst = paths[paths.length - 1] ?? "";
      for (const src of paths.slice(0, -1)) if (!src.startsWith("s3://")) readPath(c, src, { via: `aws s3 ${op}`, recursive: true });
      if (dst.startsWith("s3://")) externalSend(c, `aws:${dst.split("/")[2] ?? ""}`, `upload to ${dst}`, payload);
      else {
        writePath(c, dst, { via: `aws s3 ${op}` });
        cloudRead(c, dest, "download from S3");
      }
      if (op === "mv" || (op === "sync" && args.some((a) => a.text === "--delete"))) addEffect(c, { cls: "destructive", target: dest, detail: `aws s3 ${op} removes files` });
      return NO_STAGE;
    }
    if (svc === "s3" && (op === "rm" || op === "rb")) {
      addEffect(c, { cls: "destructive", target: pos[2] ?? "s3", detail: `aws s3 ${op} ${pos[2] ?? ""}` });
      return NO_STAGE;
    }
    if (DESTROY_VERBS.test(op)) addEffect(c, { cls: "destructive", target: `aws ${svc}`, detail: `aws ${svc} ${op}` });
    else if (READ_VERBS.test(op) || (svc === "s3" && op === "ls")) cloudRead(c, `aws ${svc}`, `aws ${svc} ${op}`);
    else externalSend(c, `aws:${svc}`, `aws ${svc} ${op}: change cloud resources`, payload);
    return NO_STAGE;
  }
  if (name === "kubectl" || name === "oc" || name === "helm") {
    const v = pos[0] ?? "";
    if (/^(?:delete|drain|cordon|uninstall|rollback)$/.test(v) || (v === "scale" && args.some((a) => /replicas=0\b/.test(a.text)))) addEffect(c, { cls: "destructive", target: dest, detail: `${name} ${v}` });
    else if (v === "get" && /secrets?/.test(pos[1] ?? "")) addEffect(c, { cls: "read_secret", target: `${name} secrets`, detail: `${name} get ${pos[1]}`, private: true });
    else if (/^(?:exec|run|attach|cp|port-forward|debug)$/.test(v)) addEffect(c, { cls: "execute_opaque", target: dest, detail: `${name} ${v}` });
    else if (READ_VERBS.test(v)) cloudRead(c, dest, `${name} ${v}`);
    else externalSend(c, dest, `${name} ${v}: change a cluster`, payload);
    return NO_STAGE;
  }
  if (name === "vault" && (pos[0] === "read" || pos[0] === "kv" && pos[1] === "get" || pos[0] === "token")) {
    addEffect(c, { cls: "read_secret", target: "vault", detail: `read a secret from vault`, private: true });
    return NO_STAGE;
  }
  if (name === "stripe" || name === "twilio") {
    externalSend(c, dest, `${name} ${pos.join(" ").slice(0, 60)}`, payload);
    if (destroyVerb !== undefined) addEffect(c, { cls: "destructive", target: dest, detail: `${name} ${destroyVerb}` });
    return NO_STAGE;
  }
  if (destroyVerb !== undefined) {
    addEffect(c, { cls: "destructive", target: dest, detail: `${name} ${pos.slice(0, 3).join(" ")}` });
    return NO_STAGE;
  }
  // F19: `vercel` with no command deploys (a preview), and --prod/--production deploys to production.
  if ((name === "vercel" && (pos.length === 0 || pos[0] === "deploy")) || args.some((a) => /^--prod(?:uction)?$/.test(a.text))) {
    externalSend(c, dest, `${name} ${pos.slice(0, 2).join(" ")}${args.some((a) => /^--prod/.test(a.text)) ? " --prod" : ""}: deploy`.replace(/\s+:/, ":"), payload);
    return NO_STAGE;
  }
  if (pos.length === 0 || (verbs.some((v) => READ_VERBS.test(v)) && !verbs.some((v) => /^(?:deploy|push|create|set|update|apply|publish|release|promote|import|put|post|send|upload|invoke|exec|run|ssh|scale|restart|rollout|secrets?)$/.test(v)))) {
    cloudRead(c, dest, `${name} ${pos.slice(0, 3).join(" ")}`.trim());
    return NO_STAGE;
  }
  if (verbs.some((v) => /^(?:secrets?|env|config:get|env:pull|vars)$/.test(v)) && verbs.some((v) => /^(?:get|list|pull|ls|show|read)$/.test(v) || /:get|:pull/.test(v))) {
    addEffect(c, { cls: "read_secret", target: dest, detail: `read deployment secrets with ${name}`, private: true });
    return NO_STAGE;
  }
  externalSend(c, dest, `${name} ${pos.slice(0, 3).join(" ")}: change a cloud service`, payload);
  return NO_STAGE;
}

/**
 * G3: mobile build and release tools (fastlane lanes, EAS, Expo, Codemagic CLI tools). A lane or a
 * build/submit/update uploads the project or a build to a vendor and can publish to an app store, so
 * it is a send; listing, status and local development commands are not.
 */
function mobileDeploy(name: string, args: readonly Word[], pos: readonly string[], c: Collector, payload: string): StageKind {
  const v = pos[0] ?? "";
  const dest = `cloud:${name === "eas-cli" ? "eas" : name}`;
  runsManifest(c, name === "eas-cli" ? "eas" : name);
  if (/(?:^|[:-])(?:delete|destroy|cancel|remove|revoke|unpublish)(?:$|[:-])/.test(v)) {
    addEffect(c, { cls: "destructive", target: dest, detail: `${name} ${pos.slice(0, 2).join(" ")}` });
    return NO_STAGE;
  }
  const local =
    name === "fastlane" ? /^(?:lanes|actions|action|env|help|list|docs|search_plugins|enable_auto_complete|version|-v|--version|-h|--help|init|new_action|new_plugin|add_plugin)$/
    : name === "expo" ? /^(?:start|prebuild|install|add|export|doctor|config|customize|lint|whoami|run:\w+|-h|--help|--version|-v|login|logout|register|init|serve|export:\w+|prebuild:\w+)$/
    : name === "codemagic-cli-tools" ? /^(?:-h|--help|--version|-v)$/
    : /^(?:build:list|build:view|build:inspect|project:info|project:init|config|diagnostics|whoami|login|logout|help|-h|--help|--version|-v|init|credentials|update:list|update:view|channel:list|channel:view|branch:list|branch:view|device:list|secret:list|env:list|webhook:list)$/;
  if (v === "" || local.test(v) || (name !== "fastlane" && args.some((a) => a.text === "--local") && v === "build")) {
    addEffect(c, { cls: "execute", target: name, detail: `run ${name} ${v}`.trim() });
    return NO_STAGE;
  }
  externalSend(c, dest, `${name} ${pos.slice(0, 3).join(" ")}: build, upload or publish through a vendor service`, payload);
  return NO_STAGE;
}

/** F34: a registry named on the command line (--registry, --repository-url, --index) is a destination of the publish. */
function publishRegistry(c: Collector, name: string, verb: string, args: readonly Word[], payload: string): void {
  const flags = /^(?:--registry|--repository-url|--index|--index-url|--source|-s|--repository)$/;
  for (let i = 0; i < args.length; i++) {
    const t = (args[i] as Word).text;
    const m = /^--(?:registry|repository-url|index|index-url|source)=(.+)$/.exec(t);
    const v = m !== null ? (m[1] as string) : flags.test(t) ? (args[i + 1]?.text ?? "") : "";
    if (v !== "" && /^[a-z][a-z0-9+.-]*:\/\//i.test(v)) egress(c, v, "send", { payload, via: `${name} ${verb}` });
  }
}

function container(name: string, args: readonly Word[], c: Collector, payload: string): StageKind {
  const pos = args.filter((a) => !a.text.startsWith("-")).map((a) => a.text);
  const v = pos[0] ?? "";
  if (v === "push") {
    externalSend(c, `${name}:registry`, `${name} push ${pos[1] ?? ""}`, payload);
    return NO_STAGE;
  }
  if (v === "login") {
    addEffect(c, { cls: "write_persistence", target: "~/.docker/config.json", detail: `${name} login stores a registry credential` });
    return NO_STAGE;
  }
  if (/^(?:rm|rmi|prune|kill|stop)$/.test(v) || (v === "system" && pos[1] === "prune") || (v === "volume" && /^(?:rm|prune)$/.test(pos[1] ?? ""))) {
    addEffect(c, { cls: v === "stop" || v === "kill" ? "execute" : "destructive", target: name, detail: `${name} ${pos.slice(0, 2).join(" ")}` });
    return NO_STAGE;
  }
  if (v === "run" || v === "create" || v === "exec" || v === "compose" || v === "build" || v === "buildx") {
    for (let i = 0; i < args.length; i++) {
      const t = (args[i] as Word).text;
      let mount: string | null = null;
      if (t === "-v" || t === "--volume") mount = args[i + 1]?.text ?? null;
      else if (t.startsWith("--volume=") || t.startsWith("-v=")) mount = t.slice(t.indexOf("=") + 1);
      else if (t === "--mount") mount = (/(?:source|src)=([^,]+)/.exec(args[i + 1]?.text ?? "")?.[1]) ?? null;
      if (mount !== null) {
        const src = mount.split(":")[0] ?? "";
        if (/^(?:\/|~|\.|\$)/.test(src)) {
          readPath(c, src, { via: `${name} volume`, recursive: true });
          if (!/:ro\b/.test(mount)) {
            const probe = { ...c, effects: [] as typeof c.effects, findings: [] as typeof c.findings };
            writePath(probe, src, { via: `${name} volume` });
            for (const e of probe.effects) if (e.cls !== "write_workspace") addEffect(c, e);
          }
        }
      }
      if (t === "--privileged" || /^--(?:pid|net|network|ipc|userns)=host$/.test(t) || t === "--cap-add" && /ALL|SYS_ADMIN/.test(args[i + 1]?.text ?? "")) addEffect(c, { cls: "privilege", target: name, detail: `${name} ${t}: container with host privileges` });
    }
    addEffect(c, { cls: "execute", target: `${name} ${v}`, detail: `${name} ${v} ${pos[1] ?? ""}`.trim(), tags: v === "run" || v === "create" ? ["install"] : [] });
    if (v === "build") {
      // F-f: the build context (the last argument) holds the Dockerfile that runs.
      const p = parseArgs(args.slice(1), { short: "tfo", long: ["tag", "file", "build-arg", "target", "platform", "label", "output", "secret", "ssh", "cache-from", "cache-to", "network", "progress"] });
      const ctxDir = p.positionals[p.positionals.length - 1]?.text;
      if (ctxDir !== undefined && !/^(?:https?|git):\/\/|^-$/.test(ctxDir)) shiftCwd(c, ctxDir);
    }
    if (v === "build" || v === "compose" || v === "buildx") runsManifest(c, name);
    return NO_STAGE;
  }
  if (v === "pull") {
    cloudRead(c, `${name}:registry`, `${name} pull ${pos[1] ?? ""}`);
    return NO_STAGE;
  }
  if (v === "cp") {
    const [src, dst] = [pos[1] ?? "", pos[2] ?? ""];
    if (!src.includes(":")) readPath(c, src, { via: `${name} cp`, recursive: true });
    if (!dst.includes(":")) writePath(c, dst, { via: `${name} cp` });
    return NO_STAGE;
  }
  addEffect(c, { cls: "execute", target: `${name} ${v}`, detail: `${name} ${v}` });
  return NO_STAGE;
}

function system(name: string, args: readonly Word[], c: Collector, payload: string, depth: number): StageKind {
  const pos = args.filter((a) => !a.text.startsWith("-")).map((a) => a.text);
  switch (name) {
    case "crontab":
      if (args.some((a) => a.text === "-r")) addEffect(c, { cls: "destructive", target: "crontab", detail: "remove every scheduled job (crontab -r)" });
      else if (args.some((a) => a.text === "-l")) addEffect(c, { cls: "read_local_workspace", target: "crontab", detail: "list scheduled jobs" });
      else addEffect(c, { cls: "write_persistence", target: "crontab", detail: "schedule commands with crontab" });
      return NO_STAGE;
    case "at":
    case "batch":
      addEffect(c, { cls: "write_persistence", target: name, detail: `schedule commands with ${name}` });
      return NO_STAGE;
    case "launchctl":
    case "systemctl": {
      const v = pos[0] ?? "";
      if (/^(?:list|print|status|show|is-active|is-enabled|list-units|cat|blame|print-disabled|managername)$/.test(v)) return NO_STAGE;
      // Stopping, unloading or changing the firewall's own login item (the phone relay daemon).
      if (args.some((a) => /launchsafe-firewall/i.test(a.text))) {
        addEffect(c, { cls: "firewall_tamper", target: name, detail: `${name} ${v}: change the firewall's own background service` });
        return NO_STAGE;
      }
      if (/^(?:load|bootstrap|enable|submit|link|daemon-reload|preset|setenv|edit|start|restart|kickstart)$/.test(v)) addEffect(c, { cls: "write_persistence", target: name, detail: `${name} ${v}: register a background service` });
      else addEffect(c, { cls: "destructive", target: name, detail: `${name} ${args.map((a) => a.text).join(" ")}` });
      return NO_STAGE;
    }
    case "security":
      if (/^(?:find|dump)-/.test(pos[0] ?? "") || pos[0] === "dump-keychain" || pos[0] === "export") {
        addFinding(c, "credential_store_read", `security ${pos[0]} reads keychain items`);
        addEffect(c, { cls: "read_secret", target: "keychain", detail: `read the keychain (security ${pos[0]})`, private: true });
      } else if (/^(?:delete|add|set|import|unlock|create|default)/.test(pos[0] ?? "")) addEffect(c, { cls: "write_persistence", target: "keychain", detail: `security ${pos[0]}` });
      return NO_STAGE;
    case "defaults":
      if (pos[0] === "write" || pos[0] === "delete" || pos[0] === "import") addEffect(c, { cls: "write_persistence", target: `defaults ${pos[1] ?? ""}`, detail: `change macOS preferences (defaults ${pos[0]} ${pos[1] ?? ""})` });
      return NO_STAGE;
    case "osascript":
      return interpreter(name, args, c, payload, depth, null);
    case "diskutil":
      if (/^(?:list|info|activity|verifyVolume|verifyDisk|apfs)$/.test(pos[0] ?? "") && !/delete|erase/i.test(pos[1] ?? "")) return NO_STAGE;
      if (/erase|partition|zero|random|secureErase|delete|reformat|unmount|eject/i.test(`${pos[0]} ${pos[1] ?? ""}`)) {
        addFinding(c, "destroy_root", `diskutil ${pos[0]} may erase or detach a disk`);
        addEffect(c, { cls: "destructive", target: "disk", detail: `diskutil ${pos.slice(0, 2).join(" ")}` });
      }
      return NO_STAGE;
    case "csrutil":
    case "spctl":
    case "tmutil":
    case "dscl":
    case "visudo":
    case "setcap":
    case "usermod":
    case "useradd":
    case "passwd":
    case "chsh":
      if (/^(?:status|--status|listbackups|latestbackup|-read|read|list)$/.test(pos[0] ?? args[0]?.text ?? "")) return NO_STAGE;
      addEffect(c, { cls: "privilege", target: name, detail: `change system security settings with ${name}` });
      return NO_STAGE;
    default:
      if (/^(?:shutdown|reboot|halt|poweroff|init)$/.test(name)) {
        addEffect(c, { cls: "destructive", target: name, detail: `${name}: stop or restart the machine` });
        return NO_STAGE;
      }
      destroy(c, pos[pos.length - 1] ?? name, name, args[args.length - 1]);
      addFinding(c, "destroy_root", `${name} may erase disks or partitions`);
      return NO_STAGE;
  }
}

export type { ParsedArgs };
