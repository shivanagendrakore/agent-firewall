/**
 * Who started a command, as the CLI asks it: launchedByAgent, agentLaunch and agentAncestor read the process
 * table through processLine when no reader is given (/proc on Linux, ps elsewhere), and the commands an agent may
 * not start (approvals, `run`, the kill switch's stop, the API's and OpenShell's servers) refuse when a process
 * they were started from cannot be read. processLine is replaced here by a fake table, so the walk sees the same
 * processes on any machine; the sandbox is replaced too, so nothing is started, and no server gets past the check.
 */
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "../src/climain.js";
import { processLine } from "../src/runtime/ancestry.js";
import { agentLaunch, launchedByAgent } from "../src/runtime/approver.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { agentAncestor } from "../src/runtime/run/guards.js";
import { runSandboxed } from "../src/runtime/run/run.js";
import { stopFile } from "../src/runtime/stops.js";
import { tempHome } from "./helpers.js";

const proc = vi.hoisted(() => ({ table: new Map<number, string>() }));
vi.mock("../src/runtime/ancestry.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/runtime/ancestry.js")>();
  return { ...real, processLine: vi.fn((pid: number) => proc.table.get(pid) ?? null) };
});
vi.mock("../src/runtime/run/run.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/runtime/run/run.js")>();
  return { ...real, runSandboxed: vi.fn(async () => ({ exitCode: 0, runId: "run-test", stdout: "", stderr: "", hosts: [], refusals: [] })) };
});

// The variables agentLaunch and agentEnvMarker read: unset here, so only the process walk decides.
const AGENT_VARS = ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SESSION_ID", "CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED", "CODEX_THREAD_ID", "GEMINI_CLI", "CURSOR_AGENT", "CURSOR_TRACE_ID", "LAUNCHSAFE_FIREWALL_HOOK"];
let savedEnv: Map<string, string | undefined>;
beforeEach(() => {
  savedEnv = new Map(AGENT_VARS.map((k): [string, string | undefined] => [k, process.env[k]]));
  for (const k of AGENT_VARS) delete process.env[k];
  proc.table = new Map();
  vi.mocked(processLine).mockClear();
  vi.mocked(runSandboxed).mockClear();
});
afterEach(() => {
  for (const [k, v] of savedEnv) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

/** This test process, its parent (`parent`), then PID 1 and the top: the chain the CLI walks from process.pid. */
function chain(parent: string | null): void {
  const me = process.pid;
  proc.table = new Map([[me, `${me + 1} node vitest`]]);
  if (parent !== null) {
    proc.table.set(me + 1, `1 ${parent}`);
    proc.table.set(1, "0 /sbin/init");
  }
}

function setup(): { l: Layout; errs: string[]; outs: string[]; write: (fd: 1 | 2, s: string) => void } {
  const l = layout(join(tempHome("walk-"), ".launchsafe-firewall"));
  mkdirSync(l.home, { recursive: true, mode: 0o700 });
  const errs: string[] = [];
  const outs: string[] = [];
  return { l, errs, outs, write: (fd, s) => void (fd === 2 ? errs : outs).push(s) };
}

/** Standard input and output as terminals, for the commands that also need one. */
async function asTerminal<T>(fn: () => Promise<T>): Promise<T> {
  const streams = [process.stdin, process.stdout];
  const saved = streams.map((s) => Object.getOwnPropertyDescriptor(s, "isTTY"));
  for (const s of streams) Object.defineProperty(s, "isTTY", { value: true, configurable: true, writable: true });
  try {
    return await fn();
  } finally {
    streams.forEach((s, i) => {
      const d = saved[i];
      if (d === undefined) delete (s as { isTTY?: boolean }).isTTY;
      else Object.defineProperty(s, "isTTY", d);
    });
  }
}

describe("the default process reader", () => {
  it("launchedByAgent, agentLaunch and agentAncestor read through processLine when no reader is given", () => {
    proc.table = new Map([
      [500, "400 /bin/zsh"],
      [400, "1 node /opt/node_modules/@anthropic-ai/claude-code/cli.js"],
      [1, "0 /sbin/init"],
    ]);
    expect(launchedByAgent({}, 500)).toBe(true);
    expect(vi.mocked(processLine).mock.calls.map((c) => c[0])).toEqual([500, 400]);
    vi.mocked(processLine).mockClear();
    expect(agentLaunch({}, 500)).toBe("process");
    expect(vi.mocked(processLine).mock.calls.map((c) => c[0])).toEqual([500, 400]);
    vi.mocked(processLine).mockClear();
    expect(agentAncestor(500)).toContain("@anthropic-ai/claude-code");
    expect(vi.mocked(processLine).mock.calls.map((c) => c[0])).toEqual([500, 400]);
  });
});

describe("the CLI refuses when a process it was started from cannot be read", () => {
  it("run: refused, and it says it could not read the process, not that an agent started it", async () => {
    const s = setup();
    chain(null);
    const code = await main(["run", "--dry-run", "--", "true"], s.l, { write: s.write });
    expect(code).toBe(1);
    expect(s.errs.join("")).toMatch(/run could not read every process it was started from/);
    expect(s.errs.join("")).not.toMatch(/started from inside/);
    expect(runSandboxed).not.toHaveBeenCalled();
  });
  it("run: an agent on the way is refused as one; a readable chain without one reaches the sandbox", async () => {
    const agent = setup();
    chain("node /opt/node_modules/@anthropic-ai/claude-code/cli.js");
    expect(await main(["run", "--dry-run", "--", "true"], agent.l, { write: agent.write })).toBe(1);
    expect(agent.errs.join("")).toMatch(/run was started from inside a coding agent's session/);
    expect(runSandboxed).not.toHaveBeenCalled();

    const person = setup();
    chain("-zsh");
    expect(await main(["run", "--dry-run", "--", "true"], person.l, { write: person.write })).toBe(0);
    expect(person.errs).toEqual([]);
    expect(runSandboxed).toHaveBeenCalledTimes(1);
  });
  it("queue approve: refused in a terminal when a process cannot be read; a readable chain reaches the queue", async () => {
    const s = setup();
    chain(null);
    expect(await asTerminal(() => main(["queue", "approve", "q-1"], s.l, { write: s.write }))).toBe(1);
    expect(s.errs.join("")).toMatch(/This command could not read every process it was started from/);
    expect(s.outs.join("")).not.toMatch(/No pending queue item/);

    const agent = setup();
    chain("node /opt/node_modules/@anthropic-ai/claude-code/cli.js");
    expect(await asTerminal(() => main(["queue", "approve", "q-1"], agent.l, { write: agent.write }))).toBe(1);
    expect(agent.errs.join("")).toMatch(/started from inside a coding agent's session/);

    const person = setup();
    chain("-zsh");
    expect(await asTerminal(() => main(["queue", "approve", "q-1"], person.l, { write: person.write }))).toBe(1);
    expect(person.errs).toEqual([]);
    // Past the check: the (empty) queue answers.
    expect(person.outs.join("")).toMatch(/No pending queue item among: q-1/);
  });
  it("log export: refused at a terminal when a process cannot be read, and nothing is written", async () => {
    const s = setup();
    chain(null);
    const target = join(s.l.home, "export.jsonl");
    expect(await asTerminal(() => main(["log", "export", "--out", target], s.l, { write: s.write }))).toBe(1);
    expect(s.errs.join("")).toMatch(/log export could not read every process it was started from/);
    expect(existsSync(target)).toBe(false);
  });
  it("session stop: refused when a process cannot be read, saying so, and nothing is written; an agent is refused as one; a person stops", async () => {
    const s = setup();
    chain(null);
    expect(await main(["session", "stop", "s-1"], s.l, { write: s.write, session: { env: {} } })).toBe(1);
    expect(s.errs.join("")).toMatch(/This command could not read every process it was started from/);
    expect(s.errs.join("")).not.toMatch(/started from inside/);
    expect(existsSync(stopFile(s.l, "session", "s-1"))).toBe(false);

    const agent = setup();
    chain("node /opt/node_modules/@anthropic-ai/claude-code/cli.js");
    expect(await main(["session", "stop", "s-1"], agent.l, { write: agent.write, session: { env: {} } })).toBe(1);
    expect(agent.errs.join("")).toMatch(/session stop was started from inside an agent session/);
    expect(existsSync(stopFile(agent.l, "session", "s-1"))).toBe(false);

    const person = setup();
    chain("-zsh");
    expect(await main(["session", "stop", "s-1"], person.l, { write: person.write, session: { env: {} } })).toBe(0);
    expect(person.errs).toEqual([]);
    expect(person.outs.join("")).toMatch(/Session s-1 is stopped/);
    expect(existsSync(stopFile(person.l, "session", "s-1"))).toBe(true);
  });
  it("serve --api, the api commands and openshell serve: refused before anything is read or listens, saying the processes could not be read", async () => {
    for (const args of [["serve", "--api"], ["api", "token", "list"], ["openshell", "serve"]]) {
      const s = setup();
      chain(null);
      expect(await main(args, s.l, { write: s.write }), args.join(" ")).toBe(1);
      expect(s.errs.join(""), args.join(" ")).toMatch(/This command could not read every process it was started from/);
      expect(s.errs.join(""), args.join(" ")).not.toMatch(/started from inside/);
      expect(s.outs, args.join(" ")).toEqual([]);
    }
    const agent = setup();
    chain("node /opt/node_modules/@anthropic-ai/claude-code/cli.js");
    expect(await main(["api", "token", "list"], agent.l, { write: agent.write })).toBe(1);
    expect(agent.errs.join("")).toMatch(/api token list was started from inside an agent session/);
    expect(agent.outs).toEqual([]);

    const person = setup();
    chain("-zsh");
    expect(await main(["api", "token", "list"], person.l, { write: person.write })).toBe(0);
    expect(person.errs).toEqual([]);
    expect(person.outs.join("")).toMatch(/No API tokens/);
  });
});

describe("the approver's checks and run's know the same agents", () => {
  // A process table as processLine would print it: "<ppid> <command>".
  const table = (agent: string): ((pid: number) => string | null) => {
    const rows: Record<number, string> = { 30: "20 /usr/bin/node /usr/local/bin/launchsafe-firewall queue approve", 20: "10 /bin/sh -c queue", 10: `1 ${agent}`, 1: "0 /sbin/init" };
    return (pid) => rows[pid] ?? null;
  };
  it.each(["/usr/lib/node_modules/@openai/codex/vendor/codex-x86_64-unknown-linux-musl exec", "/opt/codex/codex-aarch64-apple-darwin", "node /home/p/.cursor/cursor-agent/index.js"])("%s above a command: both walks find it", (agent) => {
    expect(launchedByAgent({}, 30, table(agent))).toBe(true);
    expect(agentAncestor(30, table(agent))).toContain(agent.slice(0, 20));
  });
  it("a plain shell chain is the person for both", () => {
    expect(launchedByAgent({}, 30, table("-zsh"))).toBe(false);
    expect(agentAncestor(30, table("-zsh"))).toBeNull();
  });
});
