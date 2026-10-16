/**
 * The lifecycle suites' laboratory: a fresh temporary home per test with every agent's configuration directory inside it,
 * the real built CLI as a child process (never in-process), and a person's terminal for the commands that need one.
 * Nothing here ever points at the real home: `lab()` asserts it, and `run()` asserts it again before every spawn.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir, userInfo } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const CLI = join(REPO, "dist", "cli.js");
const DRIVER = join(REPO, "test", "lifecycle", "pty-driver.py");

export type Agent = "claude" | "codex" | "gemini" | "cursor";
export const AGENTS: readonly Agent[] = ["claude", "codex", "gemini", "cursor"];

export interface Lab {
  root: string;
  home: string;
  proj: string;
  fwHome: string;
  env: Record<string, string>;
  /** The agent's user-scope settings file. */
  file(agent: Agent): string;
  cleanup(): void;
}

function isUnder(p: string, dir: string): boolean {
  const r = relative(dir, p);
  return r !== "" && !r.startsWith("..") && !r.startsWith(sep);
}

/** Throws unless `dir` is inside the OS temporary directory and not inside the real home. */
export function assertTempHome(dir: string): void {
  const tmp = realpathSync(tmpdir());
  const real = realpathSync(dir);
  if (!isUnder(real, tmp)) throw new Error(`lifecycle lab: ${dir} is not under the OS temp dir ${tmp}`);
  for (const h of [homedir(), userInfo().homedir]) {
    if (h !== "" && (real === realpathSync(h) || isUnder(real, realpathSync(h)))) throw new Error(`lifecycle lab: ${dir} is under the real home`);
  }
}

export function lab(): Lab {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "lsfw-lc-")));
  const home = join(root, "home");
  const proj = join(root, "proj");
  mkdirSync(home, { recursive: true });
  mkdirSync(proj, { recursive: true });
  assertTempHome(home);
  // A clean base: nothing of the caller's environment (no agent markers, no real config directories) reaches the child.
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: home,
    USERPROFILE: home,
    TMPDIR: process.env.TMPDIR ?? "/tmp",
    XDG_CONFIG_HOME: join(home, ".config"),
    XDG_DATA_HOME: join(home, ".local", "share"),
    XDG_STATE_HOME: join(home, ".local", "state"),
    XDG_CACHE_HOME: join(home, ".cache"),
    CLAUDE_CONFIG_DIR: join(home, ".claude"),
    CODEX_HOME: join(home, ".codex"),
    GEMINI_CLI_HOME: home,
    GEMINI_CLI_SYSTEM_SETTINGS_PATH: join(home, "no-system-settings.json"),
    LAUNCHSAFE_FIREWALL_HOME: join(home, ".launchsafe-firewall"),
    LAUNCHSAFE_FIREWALL_TEST: "1",
    LAUNCHSAFE_FIREWALL_TEST_ROOT: root,
  };
  const files: Record<Agent, string> = {
    claude: join(home, ".claude", "settings.json"),
    codex: join(home, ".codex", "hooks.json"),
    gemini: join(home, ".gemini", "settings.json"),
    cursor: join(home, ".cursor", "hooks.json"),
  };
  return { root, home, proj, fwHome: env.LAUNCHSAFE_FIREWALL_HOME as string, env, file: (a) => files[a], cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

export interface Result {
  code: number;
  stdout: string;
  stderr: string;
  /** Terminal sessions: everything the terminal showed. */
  output: string;
}

function guardEnv(l: Lab): void {
  for (const k of ["HOME", "CLAUDE_CONFIG_DIR", "CODEX_HOME", "GEMINI_CLI_HOME", "LAUNCHSAFE_FIREWALL_HOME", "XDG_CONFIG_HOME"]) assertTempHome(resolve(l.env[k] as string, ".."));
  if (l.env.LAUNCHSAFE_FIREWALL_TEST !== "1") throw new Error("LAUNCHSAFE_FIREWALL_TEST is not 1");
  assertTempHome(l.home);
}

export interface RunOptions {
  /** Which build to run (default: this repository's dist/cli.js). */
  cli?: string;
  input?: string;
  cwd?: string;
  env?: Record<string, string>;
}

/** The CLI as a script or an agent runs it: no terminal. */
export function run(l: Lab, args: readonly string[], o: RunOptions = {}): Result {
  guardEnv(l);
  // eslint-disable-next-line no-restricted-syntax -- not spawnCli(): the lifecycle suites also run an older build (v0.2) and need a clean environment; guardEnv() above asserts every home variable is inside the OS temp dir.
  const r = spawnSync(process.execPath, [o.cli ?? CLI, ...args], { encoding: "utf8", env: { ...l.env, ...(o.env ?? {}) }, input: o.input ?? "", cwd: o.cwd ?? l.proj, timeout: 60000 });
  return { code: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "", output: "" };
}

/** Feeds a hook event the way an agent does and returns the result. */
export function hook(l: Lab, agent: Agent, event: Record<string, unknown>, o: RunOptions = {}): Result {
  const args = agent === "claude" ? ["hook"] : ["hook", "--agent", agent];
  return run(l, args, { ...o, input: JSON.stringify({ session_id: "lc1", cwd: l.proj, ...event }) });
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * The CLI as a person runs it in their own terminal window: a pseudo-terminal, a parent that is not a Claude Code
 * session, and scripted answers to the prompts (`inputs`: [regex of the prompt, the line to type]).
 */
export function person(l: Lab, args: readonly string[], inputs: [string, string][] = [], o: RunOptions = {}): Result {
  guardEnv(l);
  const resultFile = join(l.root, `person-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  const spec = { argv: [process.execPath, o.cli ?? CLI, ...args], env: { ...l.env, ...(o.env ?? {}) }, cwd: o.cwd ?? l.proj, inputs, timeout: 50 };
  const r = spawnSync("python3", [DRIVER, resultFile, JSON.stringify(spec)], { encoding: "utf8", timeout: 20000 });
  if (r.status !== 0) throw new Error(`pty driver failed: ${r.stderr}`);
  for (let i = 0; i < 700 && !existsSync(resultFile); i++) sleepSync(100);
  if (!existsSync(resultFile)) throw new Error(`no result from the terminal session for ${args.join(" ")}`);
  const res = JSON.parse(readFileSync(resultFile, "utf8")) as { code: number; output: string };
  return { code: res.code, stdout: "", stderr: "", output: res.output.replace(/\r\n/g, "\n") };
}

export const PASSPHRASE = "correct horse battery staple";

/** Sets the approval passphrase as a person would. */
export function setPassphrase(l: Lab): Result {
  return person(l, ["approver", "init"], [["New approval passphrase", PASSPHRASE], ["Repeat it", PASSPHRASE]]);
}

// --- files -------------------------------------------------------------------------------------------------------

export function write(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

export function readOrNull(path: string): string | null {
  return existsSync(path) ? readFileSync(path, "utf8") : null;
}

export function json(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
}

/** Every file under `dir` (relative path -> content), skipping the firewall's own state directory. */
export function tree(dir: string, skip: readonly string[] = [".launchsafe-firewall"]): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (d: string): void => {
    for (const n of readdirSync(d).sort()) {
      const p = join(d, n);
      if (skip.includes(n)) continue;
      if (statSync(p).isDirectory()) walk(p);
      else out[relative(dir, p)] = readFileSync(p, "utf8");
    }
  };
  if (existsSync(dir)) walk(dir);
  return out;
}

export const MARKER = "LAUNCHSAFE_FIREWALL_HOOK";

/** How many hook entries in a settings document carry the firewall's marker. */
export function ourEntryCount(text: string | null): number {
  return text === null ? 0 : text.split(MARKER).length - 1;
}

export function stable(v: unknown): string {
  return JSON.stringify(v, null, 2);
}
