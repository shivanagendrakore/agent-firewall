/**
 * Unattended detection on Linux (portability audit I3). The agent's command line is read from /proc, not from
 * ps (Debian-slim, Alpine and busybox images have no ps, or one without -p), and a session whose agent process
 * cannot be read at all is unattended for every adapter, never taken as attended. The tests build a stand-in
 * /proc under a temporary directory: nothing here runs ps, pgrep or an agent.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { claudeAdapter, claudeUnattended } from "../../src/adapters/claude.js";
import { codexAdapter, codexUnattendedArgs, nonInteractiveCodex } from "../../src/adapters/codex.js";
import { nonInteractiveCursor } from "../../src/adapters/cursor.js";
import { geminiUnattendedArgs, nonInteractiveGemini } from "../../src/adapters/gemini.js";
import { contextOptions } from "../../src/hook/pipeline.js";
import { defaultConfig } from "../../src/policy.js";
import { ancestorArgs, processArgs, readProc, uninspectedReason, type Ancestry, type Run } from "../../src/runtime/ancestry.js";
import { buildContext, nonInteractiveClaude } from "../../src/runtime/context.js";
import { safeId } from "../../src/runtime/layout.js";
import { box, type Box } from "./harness.js";

let b: Box;
beforeEach(() => {
  b = box();
  mkdirSync(b.l.sessions, { recursive: true });
});
afterEach(() => b.cleanup());

interface FakeProcess {
  ppid: number;
  comm?: string;
  args?: string[];
}

/** A stand-in /proc: `<root>/<pid>/stat` in the kernel's format and `<root>/<pid>/cmdline`, NUL-terminated arguments. */
function fakeProc(procs: Record<number, FakeProcess>): string {
  const root = join(b.root, "proc");
  for (const [pid, p] of Object.entries(procs)) {
    mkdirSync(join(root, pid), { recursive: true });
    writeFileSync(join(root, pid, "stat"), `${pid} (${p.comm ?? "node"}) S ${p.ppid} ${pid} ${pid} 0 -1 4194560 1200 0 0 0 10 5 0 0 20 0 11 0 90210 1234567 8000 18446744073709551615\n`);
    writeFileSync(join(root, pid, "cmdline"), (p.args ?? []).map((a) => `${a}\0`).join(""));
  }
  return root;
}

/** A stand-in for ps and pgrep that records being run; on Linux nothing should run them. */
function psSpy(): { exec: Run; calls: string[][] } {
  const calls: string[][] = [];
  const exec: Run = (cmd, args) => {
    calls.push([cmd, ...args]);
    throw new Error("ps and pgrep are not run on Linux");
  };
  return { exec, calls };
}

const NOT_FOUND: Ancestry = { args: [], via: "none", inspected: false };

describe("ancestry on Linux reads /proc and never runs ps", () => {
  it("walks the parents nearest first and prints the arguments as ps does", () => {
    const procRoot = fakeProc({
      900: { ppid: 800, comm: "sh", args: ["/bin/sh", "/tmp/run/hook.sh", "BeforeTool"] },
      800: { ppid: 700, comm: "node", args: ["node", "/opt/gemini/node_modules/.bin/gemini", "-p", "fix the bug", "--approval-mode", "yolo"] },
      700: { ppid: 1, comm: "bash", args: ["-bash"] },
      1: { ppid: 0, comm: "init", args: ["/sbin/init"] },
    });
    const { exec, calls } = psSpy();
    const anc = ancestorArgs(900, { pattern: "gemini", platform: "linux", procRoot, exec });
    expect(anc).toEqual({
      args: ["/bin/sh /tmp/run/hook.sh BeforeTool", "node /opt/gemini/node_modules/.bin/gemini -p fix the bug --approval-mode yolo", "-bash", "/sbin/init"],
      via: "proc",
      inspected: true,
    });
    expect(geminiUnattendedArgs(anc.args[1] as string)).toMatch(/-p/);
    expect(calls).toEqual([]);
    expect(ancestorArgs(900, { pattern: "gemini", platform: "linux", procRoot, exec, depth: 2 }).args).toEqual(anc.args.slice(0, 2));
  });

  it("takes the parent from after the last ')', so a command name that mimics the stat fields changes nothing", () => {
    // A process may name itself (15 characters): this one spells a state and a parent pid of its own.
    const procRoot = fakeProc({
      50: { ppid: 40, comm: "a) S 1 (b", args: ["node", "gemini", "--yolo"] },
      40: { ppid: 1, comm: "bash", args: ["bash"] },
      1: { ppid: 0, comm: "init", args: ["/sbin/init"] },
    });
    expect(readProc(50, procRoot)).toEqual({ ppid: 40, args: "node gemini --yolo" });
    expect(ancestorArgs(50, { pattern: "gemini", platform: "linux", procRoot, depth: 2 }).args).toEqual(["node gemini --yolo", "bash"]);
  });

  it("reads process 1, which in a container is usually the agent itself", () => {
    const procRoot = fakeProc({
      31: { ppid: 1, comm: "sh", args: ["/bin/sh", "-c", "launchsafe-firewall hook"] },
      1: { ppid: 0, comm: "codex", args: ["codex", "exec", "fix the tests"] },
    });
    const anc = ancestorArgs(31, { pattern: "codex", platform: "linux", procRoot });
    expect(anc).toMatchObject({ via: "proc", inspected: true });
    expect(anc.args.map(codexUnattendedArgs).find((x) => x !== null)).toMatch(/codex exec/);
  });

  it("keeps what it read when a process ends mid-walk, and stops at a loop in the table", () => {
    const gone = fakeProc({ 90: { ppid: 80, args: ["/bin/sh", "hook"] } });
    expect(ancestorArgs(90, { pattern: "x", platform: "linux", procRoot: gone })).toEqual({ args: ["/bin/sh hook"], via: "proc", inspected: true });
    const loop = fakeProc({ 5: { ppid: 6, args: ["a"] }, 6: { ppid: 5, args: ["b"] } });
    expect(ancestorArgs(5, { pattern: "x", platform: "linux", procRoot: loop, depth: 10 }).args).toEqual(["a", "b"]);
  });

  it("reads an empty command line (a kernel thread, a zombie) as the command name", () => {
    const procRoot = fakeProc({ 7: { ppid: 2, comm: "kworker/0:1", args: [] } });
    expect(readProc(7, procRoot)).toEqual({ ppid: 2, args: "kworker/0:1" });
  });

  it("is not inspected when the first process cannot be read: no /proc, a hidden or malformed entry, or a parent outside the namespace", () => {
    const { exec, calls } = psSpy();
    const walk = (start: number, procRoot: string): Ancestry => ancestorArgs(start, { pattern: "gemini", platform: "linux", procRoot, exec });
    expect(walk(900, join(b.root, "no-proc"))).toEqual(NOT_FOUND);
    // The directory is there, but its stat is not (hidepid, a process that just ended).
    mkdirSync(join(b.root, "hidden", "900"), { recursive: true });
    writeFileSync(join(b.root, "hidden", "900", "cmdline"), "gemini\0-p\0");
    expect(walk(900, join(b.root, "hidden"))).toEqual(NOT_FOUND);
    // A stat line not in the kernel's format, and a stat without its command line.
    mkdirSync(join(b.root, "garbled", "900"), { recursive: true });
    writeFileSync(join(b.root, "garbled", "900", "stat"), "garbage");
    writeFileSync(join(b.root, "garbled", "900", "cmdline"), "gemini\0-p\0");
    expect(walk(900, join(b.root, "garbled"))).toEqual(NOT_FOUND);
    mkdirSync(join(b.root, "nocmd", "900"), { recursive: true });
    writeFileSync(join(b.root, "nocmd", "900", "stat"), "900 (node) S 1 900 900 0\n");
    expect(walk(900, join(b.root, "nocmd"))).toEqual(NOT_FOUND);
    // A parent pid of 0 is a parent in another pid namespace: it cannot be read, even with a process 1 beside it.
    expect(walk(0, fakeProc({ 1: { ppid: 0, args: ["/sbin/init"] } }))).toEqual(NOT_FOUND);
    expect(calls).toEqual([]);
  });

  it("reads one process's command line: /proc on Linux, ps elsewhere, null when nothing could be read", () => {
    const procRoot = fakeProc({ 321: { ppid: 1, args: ["claude", "-p", "hi"] } });
    const { exec, calls } = psSpy();
    expect(processArgs(321, { platform: "linux", procRoot, exec })).toBe("claude -p hi");
    expect(processArgs(322, { platform: "linux", procRoot, exec })).toBeNull();
    expect(calls).toEqual([]);
    const asked: string[][] = [];
    const ps: Run = (cmd, args) => {
      asked.push([cmd, ...args]);
      return "claude -p hi\n";
    };
    expect(processArgs(321, { platform: "darwin", exec: ps })).toBe("claude -p hi");
    expect(asked).toEqual([["ps", "-o", "args=", "-p", "321"]]);
    expect(processArgs(321, { platform: "darwin", exec: () => { throw new Error("Operation not permitted"); } })).toBeNull();
    expect(processArgs(321, { platform: "darwin", exec: () => "\n" })).toBeNull();
  });

  it.skipIf(process.platform !== "linux")("the real /proc: this process, its parent and its command line, in the kernel's own format", () => {
    const me = readProc(process.pid);
    expect(me?.ppid).toBe(process.ppid);
    expect(me?.args).not.toBe("");
    const anc = ancestorArgs(process.pid, { pattern: "x", platform: "linux", depth: 2 });
    expect(anc).toMatchObject({ via: "proc", inspected: true });
    expect(anc.args[0]).toBe(me?.args);
  });

  it("says why, by platform, when nothing could be read", () => {
    expect(uninspectedReason("Codex", "linux")).toBe("Codex's command line could not be read (/proc could not be read), so the session is treated as unattended");
    expect(uninspectedReason("Codex", "darwin")).toMatch(/\(ps and pgrep both failed\)/);
    expect(uninspectedReason("Codex", "freebsd")).toMatch(/\(ps failed\)/);
    // A source with no pgrep fallback (the Claude Code check) does not claim pgrep was tried.
    expect(uninspectedReason("Claude Code", "darwin", false)).toMatch(/\(ps failed\)/);
    expect(uninspectedReason("Claude Code", "linux", false)).toMatch(/\(\/proc could not be read\)/);
  });
});

describe("a session whose agent process cannot be read is unattended for every adapter", () => {
  const seen = (...args: string[]): Ancestry => ({ args, via: "proc", inspected: true });
  const event = <A extends "codex" | "cursor" | "gemini">(agent: A, sessionId: string) => ({ kind: "prompt" as const, agent, sessionId, cwd: "/w", raw: {} });
  const meta = (agent: string, id: string): string => join(b.l.sessions, `${safeId(`${agent}:${id}`)}.meta.json`);

  it("Codex: unreadable is unattended and not remembered; a process that was read is attended or not by its flags", () => {
    const env = { CODEX_HOME: join(b.root, "codex-home") };
    expect(nonInteractiveCodex(event("codex", "c1"), env, b.l, () => NOT_FOUND)).toMatch(/Codex's command line could not be read.*treated as unattended/);
    expect(existsSync(meta("codex", "c1"))).toBe(false);
    // The next hook reads again: an interactive Codex is attended, and that answer is remembered.
    expect(nonInteractiveCodex(event("codex", "c1"), env, b.l, () => seen("/bin/sh -c hook", "codex"))).toBeNull();
    expect(existsSync(meta("codex", "c1"))).toBe(true);
    expect(nonInteractiveCodex(event("codex", "c2"), env, b.l, () => seen("/bin/sh -c hook", "codex exec fix it"))).toMatch(/codex exec/);
    // The config's own word beats not knowing, and is remembered.
    mkdirSync(env.CODEX_HOME, { recursive: true });
    writeFileSync(join(env.CODEX_HOME, "config.toml"), 'approval_policy = "never"\n');
    expect(nonInteractiveCodex(event("codex", "c3"), env, b.l, () => NOT_FOUND)).toMatch(/approval_policy = "never"/);
    expect(existsSync(meta("codex", "c3"))).toBe(true);
  });

  it("Cursor: unreadable is unattended and not remembered; an interactive agent is attended", () => {
    expect(nonInteractiveCursor(event("cursor", "u1"), {}, b.l, () => NOT_FOUND)).toMatch(/Cursor's command line could not be read.*treated as unattended/);
    expect(existsSync(meta("cursor", "u1"))).toBe(false);
    expect(nonInteractiveCursor(event("cursor", "u1"), {}, b.l, () => seen("/bin/sh -c hook", "cursor-agent"))).toBeNull();
    expect(nonInteractiveCursor(event("cursor", "u2"), {}, b.l, () => seen("/bin/sh -c hook", "node /opt/cursor-agent/index.js -p hi"))).toMatch(/non-interactively/);
  });

  it("Cursor: approvalMode unrestricted beats an unreadable process, and is remembered", () => {
    // ~/.cursor is found through HOME; the box's home holds the config only for this call.
    mkdirSync(join(b.home, ".cursor"), { recursive: true });
    writeFileSync(join(b.home, ".cursor", "cli-config.json"), JSON.stringify({ approvalMode: "unrestricted" }));
    const saved = process.env.HOME;
    process.env.HOME = b.home;
    try {
      expect(nonInteractiveCursor(event("cursor", "u3"), {}, b.l, () => NOT_FOUND)).toMatch(/approvalMode is "unrestricted"/);
    } finally {
      process.env.HOME = saved;
    }
    expect(existsSync(meta("cursor", "u3"))).toBe(true);
    // With the config out of sight, the remembered answer still comes back, not the unreadable one.
    expect(nonInteractiveCursor(event("cursor", "u3"), {}, b.l, () => NOT_FOUND)).toMatch(/approvalMode is "unrestricted"/);
  });

  it("Gemini CLI: unreadable is unattended and no longer sticks to the session", () => {
    expect(nonInteractiveGemini(event("gemini", "g1"), {}, b.l, () => NOT_FOUND)).toMatch(/Gemini CLI's command line could not be read.*treated as unattended/);
    expect(existsSync(meta("gemini", "g1"))).toBe(false);
    expect(nonInteractiveGemini(event("gemini", "g1"), {}, b.l, () => seen("/bin/sh -c hook", "node /opt/gemini/bin/gemini"))).toBeNull();
  });

  it("Gemini CLI finds -p through a stand-in /proc end to end", () => {
    const procRoot = fakeProc({
      900: { ppid: 800, comm: "sh", args: ["/bin/sh", "hook.sh"] },
      800: { ppid: 1, comm: "node", args: ["node", "/opt/gemini/node_modules/.bin/gemini", "-p", "fix the bug"] },
      1: { ppid: 0, comm: "init", args: ["/sbin/init"] },
    });
    const inspect = (): Ancestry => ancestorArgs(900, { pattern: "gemini", platform: "linux", procRoot });
    expect(nonInteractiveGemini(event("gemini", "g2"), {}, b.l, inspect)).toMatch(/non-interactively \(-p\)/);
  });

  describe("Claude Code", () => {
    const procRoot = (): string =>
      fakeProc({
        7410: { ppid: 1, comm: "claude", args: ["claude", "-p", "summarise the repo"] },
        7420: { ppid: 1, comm: "claude", args: ["claude"] },
      });
    const meta1 = (id: string): string => join(b.l.sessions, `${safeId(id)}.meta.json`);

    it("-p is read from /proc, and an interactive process is attended", () => {
      const probe = { platform: "linux" as const, procRoot: procRoot() };
      expect(nonInteractiveClaude(b.l, "k1", { CLAUDE_PID: "7410" }, probe)).toMatch(/non-interactively \(-p\)/);
      expect(nonInteractiveClaude(b.l, "k2", { CLAUDE_PID: "7420" }, probe)).toBeNull();
    });

    it("a process that cannot be read is unattended, and not remembered, so a failure that passes does not stick", () => {
      const probe = { platform: "linux" as const, procRoot: procRoot() };
      const lost = { platform: "linux" as const, procRoot: join(b.root, "no-proc") };
      expect(nonInteractiveClaude(b.l, "k3", { CLAUDE_PID: "7420" }, lost)).toMatch(/Claude Code's command line could not be read \(\/proc could not be read\), so the session is treated as unattended/);
      expect(existsSync(meta1("k3"))).toBe(false);
      expect(nonInteractiveClaude(b.l, "k3", { CLAUDE_PID: "7420" }, probe)).toBeNull();
      expect(existsSync(meta1("k3"))).toBe(true);
    });

    it("an answer from a process that was read is remembered for the session", () => {
      const probe = { platform: "linux" as const, procRoot: procRoot() };
      const lost = { platform: "linux" as const, procRoot: join(b.root, "no-proc") };
      expect(nonInteractiveClaude(b.l, "k4", { CLAUDE_PID: "7410" }, probe)).toMatch(/-p/);
      expect(nonInteractiveClaude(b.l, "k4", { CLAUDE_PID: "7410" }, lost)).toMatch(/non-interactively \(-p\)/);
    });

    it("an answer is not reused for another process of the same session (claude -p --resume of an interactive session)", () => {
      const probe = { platform: "linux" as const, procRoot: procRoot() };
      expect(nonInteractiveClaude(b.l, "k5", { CLAUDE_PID: "7420" }, probe)).toBeNull();
      expect(nonInteractiveClaude(b.l, "k5", { CLAUDE_PID: "7410" }, probe)).toMatch(/non-interactively \(-p\)/);
      expect(nonInteractiveClaude(b.l, "k5", { CLAUDE_PID: "7420" }, probe)).toBeNull();
    });

    it("reaches the context: unattended with the reason when unreadable, and the injected detector still wins", () => {
      const probe = { platform: "linux" as const, procRoot: procRoot() };
      const lost = { platform: "linux" as const, procRoot: join(b.root, "no-proc") };
      const base = { l: b.l, cfg: defaultConfig(), home: b.home, scratchRoots: [join(b.root, "scratch")] };
      const at = (sessionId: string) => ({ ...base, basics: { sessionId, cwd: b.ws } });
      const unreadable = buildContext({ ...at("x1"), env: { CLAUDE_PID: "7420" }, processProbe: lost });
      expect(unreadable.ctx.interactive).toBe(false);
      expect(unreadable.unattendedReason).toMatch(/could not be read/);
      const print = buildContext({ ...at("x2"), env: { CLAUDE_PID: "7410" }, processProbe: probe });
      expect(print.ctx.interactive).toBe(false);
      expect(print.unattendedReason).toMatch(/non-interactively \(-p\)/);
      const interactive = buildContext({ ...at("x3"), env: { CLAUDE_PID: "7420" }, processProbe: probe });
      expect(interactive.ctx.interactive).toBe(true);
      expect(interactive.unattendedReason).toBeNull();
      const injected = buildContext({ ...at("x4"), env: {}, processProbe: lost, detectNonInteractive: () => false });
      expect(injected.ctx.interactive).toBe(true);
    });

    const ctxAt = (sessionId: string) => ({ l: b.l, cfg: defaultConfig(), home: b.home, scratchRoots: [join(b.root, "scratch")], basics: { sessionId, cwd: b.ws } });

    it("reaches the context for another agent: the adapter's reason makes it unattended, and an injected detector still wins", () => {
      const probe = { platform: "linux" as const, procRoot: procRoot() };
      const codexLost = uninspectedReason("Codex", "linux");
      // The Claude Code check would read 7420 as attended: only the adapter's answer makes this one unattended.
      const lost = buildContext({ ...ctxAt("y1"), env: { CLAUDE_PID: "7420" }, processProbe: probe, agentUnattended: () => codexLost });
      expect(lost.ctx.interactive).toBe(false);
      expect(lost.unattendedReason).toBe(codexLost);
      // The injected detector (tests, the adapter harness) comes before the adapter, whichever way it answers.
      const attended = buildContext({ ...ctxAt("y2"), env: {}, processProbe: probe, agentUnattended: () => codexLost, detectNonInteractive: () => false });
      expect(attended.ctx.interactive).toBe(true);
      const print = buildContext({ ...ctxAt("y3"), env: {}, processProbe: probe, agentUnattended: () => null, detectNonInteractive: () => true });
      expect(print.unattendedReason).toBe("Claude Code is running non-interactively (-p)");
      // The adapter's null is the answer: Claude Code's check (7410 runs -p) is not consulted, and caches nothing.
      const answered = buildContext({ ...ctxAt("y4"), env: { CLAUDE_PID: "7410" }, processProbe: probe, agentUnattended: () => null });
      expect(answered.ctx.interactive).toBe(true);
      expect(answered.unattendedReason).toBeNull();
      expect(existsSync(meta1("y4"))).toBe(false);
    });

    it("the hook asks another agent's adapter, and leaves Claude Code to its own process check", () => {
      const probe = { platform: "linux" as const, procRoot: procRoot() };
      const ev = { kind: "pre_tool" as const, agent: "codex" as const, sessionId: "y5", cwd: b.ws, raw: {} };
      const h = { env: { CODEX_HOME: join(b.root, "codex-home") } };
      const calls: unknown[][] = [];
      const codex: typeof codexAdapter = {
        ...codexAdapter,
        nonInteractive: (e, env, l) => {
          calls.push([e, env, l]);
          return uninspectedReason("Codex", "linux");
        },
      };
      const r = buildContext({ ...ctxAt("y5"), env: { CLAUDE_PID: "7420" }, processProbe: probe, ...contextOptions(ev, codex, h, b.l) });
      expect(r.ctx.interactive).toBe(false);
      expect(r.unattendedReason).toBe(uninspectedReason("Codex", "linux"));
      expect(calls).toEqual([[ev, h.env, b.l]]);
      expect(contextOptions({ ...ev, agent: "claude" }, claudeAdapter, h, b.l)).toEqual({});
    });

    it("reads the hook's parent when CLAUDE_PID cannot be read, or is not set", () => {
      // CLAUDE_PID names a process that is not in the table; the hook's parent runs -p.
      const probe = { platform: "linux" as const, procRoot: fakeProc({ [process.ppid]: { ppid: 1, comm: "claude", args: ["claude", "-p", "x"] } }) };
      expect(nonInteractiveClaude(b.l, "p1", { CLAUDE_PID: String(process.ppid + 1) }, probe)).toMatch(/non-interactively \(-p\)/);
      expect(nonInteractiveClaude(b.l, "p2", {}, probe)).toMatch(/non-interactively \(-p\)/);
    });

    it("on macOS a ps that fails is unattended, names only ps (this check has no pgrep fallback), and is not remembered", () => {
      const denied = { platform: "darwin" as const, exec: (): string => { throw new Error("Operation not permitted"); } };
      expect(nonInteractiveClaude(b.l, "d1", { CLAUDE_PID: "7410" }, denied)).toBe("Claude Code's command line could not be read (ps failed), so the session is treated as unattended");
      expect(existsSync(meta1("d1"))).toBe(false);
      expect(nonInteractiveClaude(b.l, "d1", { CLAUDE_PID: "7410" }, { platform: "darwin", exec: () => "claude -p hi\n" })).toMatch(/non-interactively \(-p\)/);
      expect(existsSync(meta1("d1"))).toBe(true);
    });

    it("the adapter passes the reason through: an unreadable process is not relabelled as -p", () => {
      const probe = { platform: "linux" as const, procRoot: procRoot() };
      const lost = { platform: "linux" as const, procRoot: join(b.root, "no-proc") };
      const ev = { kind: "prompt" as const, agent: "claude" as const, sessionId: "a1", cwd: b.ws, raw: {} };
      expect(claudeAdapter.nonInteractive).toBe(claudeUnattended);
      expect(claudeUnattended(ev, { CLAUDE_PID: "7420" }, b.l, lost)).toBe(uninspectedReason("Claude Code", "linux"));
      expect(claudeUnattended({ ...ev, sessionId: "a2" }, { CLAUDE_PID: "7410" }, b.l, probe)).toBe("Claude Code is running non-interactively (-p)");
      expect(claudeUnattended({ ...ev, sessionId: "a3" }, { CLAUDE_PID: "7420" }, b.l, probe)).toBeNull();
    });
  });
});
