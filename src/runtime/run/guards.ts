/**
 * Small decisions `run` makes about the world around the sandbox (docs/run.md): whether the command needs a
 * pseudo-terminal of its own, which variables of the person's environment reach it, which sockets sit in a
 * directory it may write, whether an agent started `run`, and how text the command controls is printed.
 */

import { closeSync, lstatSync, openSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { PresetAgent } from "../../engine/agent-presets.js";
import { own, setOwn } from "../../own.js";
import { AGENT_COMMAND, processLine } from "../ancestry.js";

/** What ttyWrapNeeded looks at (injected in tests). */
export interface TtyProbe {
  /** isatty() of descriptors 0, 1 and 2. */
  fds: readonly [boolean, boolean, boolean];
  /** /dev/tty opens: the process has a controlling terminal, whatever its descriptors are. */
  controlling: boolean;
}

/** The probe for this process. */
export function ttyProbe(): TtyProbe {
  let controlling = false;
  try {
    closeSync(openSync("/dev/tty", "r"));
    controlling = true;
  } catch {
    controlling = false;
  }
  return { fds: [process.stdin.isTTY === true, process.stdout.isTTY === true, process.stderr.isTTY === true], controlling };
}

/**
 * B1: macOS runs the command under /usr/bin/script, with a pseudo-terminal of its own, whenever it could reach
 * the person's terminal: any of descriptors 0, 1 and 2 is a terminal (TIOCSTI works on any descriptor of the
 * terminal, not only standard input), or the process has a controlling terminal (the command could open
 * /dev/tty even with every descriptor redirected). A keystroke pushed with TIOCSTI then lands in the
 * pseudo-terminal, which goes away with the command, never in the person's shell.
 */
export function ttyWrapNeeded(p: TtyProbe): boolean {
  return p.fds.some((x) => x) || p.controlling;
}

/**
 * The variables of the person's environment a run passes on without being asked (I2): where programs and
 * the home directory are, the locale and the terminal, and the toolchains' own locations and trust settings.
 * Nothing that usually holds a credential: tokens and keys (GITHUB_TOKEN, AWS_*, NPM_TOKEN, an API key)
 * reach the command only through `--pass-env NAME` (or the agent preset's own key variables).
 */
export const BASE_ENV: readonly string[] = [
  "PATH", "HOME", "USER", "LOGNAME", "SHELL", "PWD", "SHLVL", "TERM", "TERM_PROGRAM", "TERM_PROGRAM_VERSION", "COLORTERM", "COLUMNS", "LINES", "NO_COLOR", "FORCE_COLOR", "CLICOLOR",
  "LANG", "LANGUAGE", "TZ", "EDITOR", "VISUAL", "PAGER", "LESS", "CI",
  "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
  "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
  "JAVA_HOME", "GOPATH", "GOROOT", "GOCACHE", "GOMODCACHE", "CARGO_HOME", "RUSTUP_HOME", "PYENV_ROOT", "VIRTUAL_ENV", "CONDA_PREFIX", "NVM_DIR", "VOLTA_HOME", "BUN_INSTALL", "DENO_DIR", "PNPM_HOME", "HOMEBREW_PREFIX",
];
/** Prefixes passed the same way: the locale's LC_* variables. */
export const BASE_ENV_PREFIXES: readonly string[] = ["LC_"];

/** The variables an agent preset passes on: the agent's own credentials and where it keeps its state. */
export const PRESET_PASS_ENV: Readonly<Record<PresetAgent, readonly string[]>> = {
  claude: ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX"],
  codex: ["OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_ORG_ID", "CODEX_HOME"],
  gemini: ["GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_LOCATION", "GOOGLE_GENAI_USE_VERTEXAI", "GEMINI_CLI_HOME", "GEMINI_MODEL"],
};

/** A `--pass-env` entry: a variable name, or a prefix ending in `*` (`NPM_CONFIG_*`). */
export function passEnvProblem(entry: string): string | null {
  return /^[A-Za-z_][A-Za-z0-9_]{0,127}\*?$/.test(entry) ? null : `--pass-env ${entry.slice(0, 64)}: give a variable name, or a prefix ending in * (NAME_*)`;
}

/** The person's variables a run passes on: the base list, `pass` (names and NAME_* prefixes) and nothing else. */
export function allowedEnv(base: NodeJS.ProcessEnv, pass: readonly string[] = []): Record<string, string> {
  const names = new Set([...BASE_ENV, ...pass.filter((p) => !p.endsWith("*"))]);
  const prefixes = [...BASE_ENV_PREFIXES, ...pass.filter((p) => p.endsWith("*")).map((p) => p.slice(0, -1))];
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(base)) {
    if (v === undefined) continue;
    if (names.has(k) || prefixes.some((p) => p !== "" && k.startsWith(p))) setOwn(out, k, v);
  }
  return out;
}

/** Most entries socketsIn looks at, and how deep: a bounded look, not a full walk. */
const SOCKET_SCAN_ENTRIES = 5000;
const SOCKET_SCAN_DEPTH = 3;

/** Unix sockets in a directory (a few levels down, bounded): what a program outside listens on there. */
export function socketsIn(dir: string): string[] {
  const out: string[] = [];
  let seen = 0;
  const queue: [string, number][] = [[dir, 0]];
  while (queue.length > 0 && seen < SOCKET_SCAN_ENTRIES && out.length < 20) {
    const [d, depth] = queue.shift() as [string, number];
    let names: string[];
    try {
      names = readdirSync(d);
    } catch {
      continue;
    }
    for (const n of names) {
      if (++seen > SOCKET_SCAN_ENTRIES) break;
      const p = join(d, n);
      try {
        const s = lstatSync(p);
        if (s.isSocket()) out.push(p);
        else if (s.isDirectory() && depth + 1 < SOCKET_SCAN_DEPTH) queue.push([p, depth + 1]);
      } catch {
        // Gone.
      }
    }
  }
  return out;
}

/**
 * Text the sandboxed command controls (a host name from its CONNECT line, the reason built from it), made
 * safe for the person's terminal: C0 and C1 control characters (escape sequences that move the cursor,
 * rewrite the title or the clipboard) and DEL become "?".
 */
export function printable(s: string): string {
  // eslint-disable-next-line no-control-regex -- matching control characters is the point.
  return s.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "?");
}

/**
 * I7: environment variables an agent's shell carries. `run` refuses to start from inside an agent (an agent
 * may not choose its own sandbox); Claude Code's are checked by launchedByAgent (src/runtime/approver.ts).
 * These cover the other agents the firewall hooks, and the firewall's own hook marker, which only a process
 * started by a hook carries.
 */
export function agentEnvMarker(env: NodeJS.ProcessEnv): string | null {
  const set = (k: string): boolean => (own(env, k) ?? "") !== "";
  for (const k of ["LAUNCHSAFE_FIREWALL_HOOK", "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED", "CODEX_THREAD_ID", "GEMINI_CLI", "CURSOR_AGENT", "CURSOR_TRACE_ID"]) if (set(k)) return k;
  return null;
}


/**
 * Whether an ancestor of `pid` is a coding agent (Codex, Gemini CLI, Cursor's agent, Claude Code), from /proc on
 * Linux or `ps` elsewhere. Null when no agent was found or the walk could not be made; `run` checks
 * agentLaunch() (launchedByAgent's walk) first, which refuses when the walk cannot be made.
 */
export function agentAncestor(pid = process.pid, ps: (pid: number) => string | null = (p) => processLine(p)): string | null {
  let cur = pid;
  const seen = new Set<number>();
  for (let i = 0; i < 40 && cur >= 1 && !seen.has(cur); i++) {
    seen.add(cur);
    const line = ps(cur);
    if (line === null) return null;
    const m = /^\s*(\d+)\s+(.*)$/.exec(line);
    if (m === null) return null;
    if (cur !== pid && AGENT_COMMAND.test(m[2] as string)) return (m[2] as string).slice(0, 120);
    cur = Number(m[1]);
  }
  return null;
}
