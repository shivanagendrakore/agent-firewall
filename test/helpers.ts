import { decide } from "../src/engine/decide.js";
import { emptyState, foldEvents } from "../src/engine/state.js";
import { defaultConfig } from "../src/policy.js";
import type { Context, Decision, FirewallConfig, SessionState, StateEvent } from "../src/types.js";

// Under `npm run coverage` (V8 coverage on) code runs several times slower; these bounds guard against quadratic time, which is orders of magnitude over them.
// Shared CI runners (GitHub ubuntu-latest) measured 1.4x slower than a developer machine, so the bounds are doubled there.
/** Factor for wall-clock bounds: 4 under coverage, 2 on CI runners, 1 otherwise. Shared by every timing test (and by fuzz `budget()`). */
export const SLOW = process.env.NODE_V8_COVERAGE !== undefined || process.env.LSFW_COVERAGE !== undefined ? 4 : process.env.CI !== undefined ? 2 : 1;

/** True under `npm run coverage`: the child-process compile cache stays empty there (unexplained on CI), so those tests run only in the normal jobs. */
export const UNDER_COVERAGE = process.env.NODE_V8_COVERAGE !== undefined || process.env.LSFW_COVERAGE !== undefined;

export const HOME = "/Users/dev";
export const WS = "/Users/dev/proj";

export function ctx(over: Partial<Context> = {}): Context {
  return {
    cwd: WS,
    workspaceRoots: [WS],
    home: HOME,
    scratchRoots: ["/tmp", "/private/tmp"],
    firewallHome: `${HOME}/.launchsafe-firewall`,
    firewallInstallDir: "/opt/launchsafe-firewall",
    interactive: true,
    caseInsensitive: true,
    ...over,
  };
}

export const TAINTED: StateEvent[] = [{ type: "taint", source: "read the web page https://example.com" }];

export function state(events: StateEvent[] = []): SessionState {
  return events.length === 0 ? emptyState() : foldEvents(events);
}

export interface RunOpts {
  tainted?: boolean;
  events?: StateEvent[];
  ctx?: Partial<Context>;
  config?: Partial<FirewallConfig>;
}

export function run(tool: string, input: Record<string, unknown>, o: RunOpts = {}): Decision {
  const events = [...(o.tainted === true ? TAINTED : []), ...(o.events ?? [])];
  return decide({ action: { tool, input }, state: state(events), config: { ...defaultConfig(), ...(o.config ?? {}) }, ctx: ctx(o.ctx) });
}

export function bash(command: string, o: RunOpts = {}): Decision {
  return run("Bash", { command }, o);
}

/** A short description for failing assertions. */
export function explain(d: Decision): string {
  return `${d.verdict} [${d.rules.join(",")}] ${d.reasons.join(" | ")} effects=${d.effects.map((e) => `${e.cls}:${e.target}`).join(", ")} findings=${d.findings.map((f) => f.id).join(",")}`;
}

// --- subprocesses (F-a) -----------------------------------------------------------------------------
// The only place a test may start the built CLI: every child gets an explicit environment whose home,
// config and state directories are inside the suite's temporary root, never the developer's own.

import { spawn as _spawn, spawnSync, type SpawnSyncReturns } from "node:child_process";
import { accessSync as _access, constants as _fsc, mkdtempSync as _mkdtemp, readFileSync as _readFile, writeFileSync as _writeFile } from "node:fs";
import { join as _join, dirname as _dirname } from "node:path";
import { fileURLToPath as _fileURLToPath } from "node:url";
import type { TestContext } from "vitest";

export const REPO = _join(_dirname(_fileURLToPath(import.meta.url)), "..");
export const CLI = _join(REPO, "dist", "cli.js");

/** The suite's temporary root (created by vitest.config.ts). */
export function testRoot(): string {
  const r = process.env.LAUNCHSAFE_FIREWALL_TEST_ROOT;
  if (r === undefined || r === "") throw new Error("LAUNCHSAFE_FIREWALL_TEST_ROOT is not set: run the suite with npm test");
  return r;
}

let execBlocked: string | null | undefined;

/**
 * Why programs a test writes under the test root cannot be run here, or null when they can. With TMPDIR on a
 * noexec mount (a hardened container's tmpfs /tmp, some CI runners), the firewall rightly passes over the
 * stand-in curl, codex or claude scripts the tests put there (they are not executable), so the tests built on
 * them cannot show anything; they skip with this reason instead of failing or reaching a real program.
 */
export function noExecReason(): string | null {
  if (execBlocked === undefined) {
    const probe = _join(_mkdtemp(_join(testRoot(), "exec-probe-")), "probe.sh");
    _writeFile(probe, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    try {
      _access(probe, _fsc.X_OK);
      execBlocked = null;
    } catch {
      execBlocked = `the test root (${testRoot()}) is on a noexec mount, so the stand-in programs this test writes there cannot run; set TMPDIR to a directory on a mount that allows exec`;
    }
  }
  return execBlocked;
}

/** Skips the running test, with the reason, when the stand-in programs it writes under the test root cannot run. */
export function skipWithoutExec(ctx: TestContext): void {
  const why = noExecReason();
  if (why !== null) ctx.skip(true, why);
}

/** A fresh home directory inside the test root. */
export function tempHome(prefix = "home-"): string {
  return _mkdtemp(_join(testRoot(), prefix));
}

/** An environment for a child process: everything that names a home points inside `home`. */
export function testEnv(home: string, extra: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    XDG_CONFIG_HOME: _join(home, ".config"),
    XDG_DATA_HOME: _join(home, ".local", "share"),
    XDG_STATE_HOME: _join(home, ".local", "state"),
    XDG_CACHE_HOME: _join(home, ".cache"),
    CLAUDE_CONFIG_DIR: _join(home, ".claude"),
    // Codex and Gemini CLI locate their homes from these; empty means "use HOME" (never the real ones).
    CODEX_HOME: "",
    GEMINI_CLI_HOME: "",
    GEMINI_CLI_SYSTEM_SETTINGS_PATH: "",
    LAUNCHSAFE_FIREWALL_HOME: _join(home, ".launchsafe-firewall"),
    LAUNCHSAFE_FIREWALL_TEST: "1",
    LAUNCHSAFE_FIREWALL_TEST_ROOT: testRoot(),
  };
  for (const [k, v] of Object.entries(extra)) {
    if (v === undefined) delete env[k];
    else env[k] = v;
  }
  return env;
}

export interface SpawnCliOptions {
  home?: string;
  env?: Record<string, string | undefined>;
  input?: string;
  cwd?: string;
  /** Another copy of the built CLI (default: this repository's dist/cli.js). */
  cli?: string;
  /** Options for node itself, before the CLI path. */
  nodeArgs?: readonly string[];
}

/** Runs the built CLI in a temporary home. */
export function spawnCli(args: readonly string[], o: SpawnCliOptions = {}): SpawnSyncReturns<string> & { home: string } {
  const home = o.home ?? tempHome();
  const r = spawnSync(process.execPath, [...(o.nodeArgs ?? []), o.cli ?? CLI, ...args], { encoding: "utf8", env: testEnv(home, o.env ?? {}), input: o.input ?? "", cwd: o.cwd ?? home, timeout: 60000 });
  return Object.assign(r, { home });
}

/** Runs the built CLI in a temporary home with bytes on stdin, returning stdout as bytes (the browser link's native messaging frames). */
export function spawnCliBytes(args: readonly string[], o: { home?: string; input: Buffer; env?: Record<string, string | undefined> }): { status: number | null; stdout: Buffer; stderr: string; home: string } {
  const home = o.home ?? tempHome();
  const r = spawnSync(process.execPath, [CLI, ...args], { env: testEnv(home, o.env ?? {}), input: o.input, cwd: home, timeout: 60000 });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr.toString("utf8"), home };
}

/** Runs a launcher script the CLI wrote (sh <script> <args>) in a temporary home, with bytes on stdin; stdout as bytes. */
export function spawnLauncherBytes(script: string, args: readonly string[], o: { home: string; input: Buffer }): { status: number | null; stdout: Buffer; stderr: string } {
  const r = spawnSync("/bin/sh", [script, ...args], { env: testEnv(o.home), input: o.input, cwd: o.home, timeout: 60000 });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr.toString("utf8") };
}

/** Runs the built CLI file directly (through its shebang and executable bit), in a temporary home. */
export function spawnCliBinary(args: readonly string[], o: SpawnCliOptions = {}): SpawnSyncReturns<string> {
  const home = o.home ?? tempHome();
  return spawnSync(CLI, [...args], { encoding: "utf8", env: testEnv(home, o.env ?? {}), input: o.input ?? "", cwd: o.cwd ?? home, timeout: 60000 });
}

/**
 * A process whose command line is this firewall's `run` (node --require <sleeper> <repo>/dist/cli.js run --
 * true), blocked before the CLI loads, so a mount-point claim it makes is proof of a live run (FA3). Needs
 * the build (dist/cli.js). Call stop() when done.
 */
export function fakeRunProcess(): { pid: number; stop: () => void } {
  const sleeper = _join(_mkdtemp(_join(testRoot(), "fake-run-")), "sleep.cjs");
  _writeFile(sleeper, "Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 120000);\n");
  const child = _spawn(process.execPath, ["--require", sleeper, CLI, "run", "--", "true"], { stdio: "ignore" });
  if (child.pid === undefined) throw new Error("could not start the stand-in run process");
  const pid = child.pid;
  return {
    pid,
    stop: () => {
      child.kill("SIGKILL");
      // SIGKILL is delivered asynchronously, and on a slow runner the process can still look live (its command line
      // still readable) when the next synchronous check runs. Wait until the kernel has torn it down (Linux: the
      // command line of a dead or zombie process is empty or gone).
      if (process.platform !== "linux") return;
      const nap = new Int32Array(new SharedArrayBuffer(4));
      for (let i = 0; i < 500; i++) {
        try {
          if (_readFile(`/proc/${pid}/cmdline`, "utf8") === "") return;
        } catch {
          return;
        }
        Atomics.wait(nap, 0, 0, 10);
      }
    },
  };
}

/**
 * Starts the built CLI without waiting for it (node <repo>/dist/cli.js <args>), in a temporary home, and
 * without the variables that mark a Claude Code session (the CLI refuses `run` there). Resolves with the
 * exit code and stderr.
 */
export function startCli(args: readonly string[], o: SpawnCliOptions = {}): { pid: number | undefined; done: Promise<{ code: number | null; stderr: string }> } {
  const home = o.home ?? tempHome();
  const env = testEnv(home, { CLAUDECODE: undefined, CLAUDE_CODE_ENTRYPOINT: undefined, CLAUDE_CODE_SESSION_ID: undefined, ...(o.env ?? {}) });
  const child = _spawn(process.execPath, [...(o.nodeArgs ?? []), o.cli ?? CLI, ...args], { env, cwd: o.cwd ?? home, stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  child.stderr?.on("data", (c: Buffer) => (stderr += c.toString()));
  const done = new Promise<{ code: number | null; stderr: string }>((res) => child.on("close", (code) => res({ code, stderr })));
  return { pid: child.pid, done };
}
