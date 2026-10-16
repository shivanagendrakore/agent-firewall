/**
 * A line break in a command line read from /proc. `/proc/<pid>/cmdline` keeps an argument's newline, carriage
 * return or Unicode line separator, while ps printed each as "?", so the "<ppid> <command>" line that
 * launchedByAgent (the approver and `run` checks) and agentAncestor (`run`) parse was always one line. A person
 * whose command holds a multi-line argument (a prompt read from a file) must not be taken for an agent, and an
 * agent with one must still be found, PID 1 in a container included. The tests build a stand-in /proc under a
 * temporary directory: nothing here runs ps, and no command line in it is run.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { processLine, type Run } from "../src/runtime/ancestry.js";
import { launchedByAgent } from "../src/runtime/approver.js";
import { agentAncestor } from "../src/runtime/run/guards.js";

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-procnl-"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

interface FakeProcess {
  ppid: number;
  comm?: string;
  args: string[];
}

/** A stand-in /proc: `<pid>/stat` in the kernel's format and `<pid>/cmdline`, NUL-terminated arguments. */
function fakeProc(procs: Record<number, FakeProcess>): string {
  const procRoot = mkdtempSync(join(root, "proc-"));
  for (const [pid, p] of Object.entries(procs)) {
    mkdirSync(join(procRoot, pid), { recursive: true });
    writeFileSync(join(procRoot, pid, "stat"), `${pid} (${p.comm ?? "node"}) S ${p.ppid} ${pid} ${pid} 0 -1 4194560 1200 0 0 0 10 5 0 0 20 0 11 0 90210 1234567 8000\n`);
    writeFileSync(join(procRoot, pid, "cmdline"), p.args.map((a) => `${a}\0`).join(""));
  }
  return procRoot;
}

/** On Linux nothing runs ps: a call to it fails the walk. */
const noPs: Run = () => {
  throw new Error("ps is not run on Linux");
};
const reader = (procRoot: string) => (pid: number): string | null => processLine(pid, { platform: "linux", procRoot, exec: noPs });

/** The four characters that end a line for a JavaScript regular expression. */
const BREAKS: readonly [string, string][] = [["a newline", "\n"], ["a carriage return", "\r"], ["U+2028", "\u2028"], ["U+2029", "\u2029"]];

/** The person's own login chain above the process under test. */
const LOGIN: Record<number, FakeProcess> = {
  300: { ppid: 200, comm: "zsh", args: ["-zsh"] },
  200: { ppid: 1, comm: "sshd", args: ["sshd: user@pts/0"] },
  1: { ppid: 0, comm: "init", args: ["/sbin/init"] },
};

describe("processLine prints a command line on one line, as ps does", () => {
  it("turns line breaks and the other control characters of /proc's arguments into '?'", () => {
    const procRoot = fakeProc({
      400: { ppid: 300, args: ["node", "cli.js", "run", "--", "claude", "-p", "one\ntwo\r\nthree\u2028four\u2029five\u0085six\tseven\u001beight\u007fnine"] },
    });
    expect(processLine(400, { platform: "linux", procRoot, exec: noPs })).toBe("300 node cli.js run -- claude -p one?two??three?four?five?six?seven?eight?nine");
  });

  it("keeps ps's own output on one line too", () => {
    const asked: string[][] = [];
    const ps: Run = (cmd, args) => {
      asked.push([cmd, ...args]);
      return "  300 /usr/local/bin/claude -p first line\nsecond line\n";
    };
    expect(processLine(400, { platform: "darwin", exec: ps })).toBe("300 /usr/local/bin/claude -p first line?second line");
    expect(asked).toEqual([["ps", "-o", "ppid=,command=", "-p", "400"]]);
  });
});

describe("launchedByAgent and agentAncestor with a line break in a command line", () => {
  it.each(BREAKS)("at the process itself (%s): a person's run with a multi-line prompt is the person", (_name, br) => {
    const procRoot = fakeProc({
      400: { ppid: 300, args: ["node", "/usr/local/bin/launchsafe-firewall", "run", "--", "claude", "-p", `first line${br}second line`] },
      ...LOGIN,
    });
    expect(launchedByAgent({}, 400, reader(procRoot))).toBe(false);
    expect(agentAncestor(400, reader(procRoot))).toBeNull();
  });

  it("at the process itself, under an agent: the agent above it is still found", () => {
    const procRoot = fakeProc({
      400: { ppid: 300, args: ["node", "/usr/local/bin/launchsafe-firewall", "run", "--", "claude", "-p", "first line\nsecond line"] },
      300: { ppid: 100, comm: "sh", args: ["/bin/sh", "-c", "launchsafe-firewall run"] },
      100: { ppid: 1, args: ["node", "/opt/node_modules/@openai/codex/bin/codex.js"] },
      1: { ppid: 0, comm: "init", args: ["/sbin/init"] },
    });
    expect(launchedByAgent({}, 400, reader(procRoot))).toBe(true);
    expect(agentAncestor(400, reader(procRoot))).toContain("@openai/codex");
  });

  it.each(BREAKS)("mid-walk (%s): a shell started with a multi-line script under the person's login is the person", (_name, br) => {
    const procRoot = fakeProc({
      400: { ppid: 250, args: ["node", "/usr/local/bin/launchsafe-firewall", "queue", "approve"] },
      250: { ppid: 300, comm: "bash", args: ["bash", "-c", `first step${br}second step`] },
      ...LOGIN,
    });
    expect(launchedByAgent({}, 400, reader(procRoot))).toBe(false);
    expect(agentAncestor(400, reader(procRoot))).toBeNull();
  });

  it("mid-walk: an agent started with a multi-line prompt is found", () => {
    const procRoot = fakeProc({
      300: { ppid: 200, args: ["node", "/usr/local/bin/launchsafe-firewall", "run"] },
      200: { ppid: 100, comm: "sh", args: ["/bin/sh", "-c", "launchsafe-firewall run"] },
      100: { ppid: 1, comm: "claude", args: ["/usr/local/bin/claude", "-p", "first line\nsecond line"] },
      1: { ppid: 0, comm: "init", args: ["/sbin/init"] },
    });
    expect(launchedByAgent({}, 300, reader(procRoot))).toBe(true);
    expect(agentAncestor(300, reader(procRoot))).toBe("/usr/local/bin/claude -p first line?second line");
  });

  it.each(BREAKS)("at PID 1 (%s): an agent that is a container's first process is found", (_name, br) => {
    const claude = fakeProc({
      50: { ppid: 1, comm: "sh", args: ["/bin/sh", "-c", "launchsafe-firewall run"] },
      1: { ppid: 0, comm: "claude", args: ["/usr/local/bin/claude", "-p", `first line${br}second line`] },
    });
    expect(launchedByAgent({}, 50, reader(claude))).toBe(true);
    expect(agentAncestor(50, reader(claude))).toBe("/usr/local/bin/claude -p first line?second line");
    const codex = fakeProc({
      50: { ppid: 1, comm: "sh", args: ["/bin/sh", "-c", "launchsafe-firewall run"] },
      1: { ppid: 0, comm: "codex", args: ["codex", "exec", `first line${br}second line`] },
    });
    expect(launchedByAgent({}, 50, reader(codex))).toBe(true);
    expect(agentAncestor(50, reader(codex))).toBe("codex exec first line?second line");
  });

  it.each(BREAKS)("at PID 1 (%s): a first process that is not an agent is the top of the tree", (_name, br) => {
    const procRoot = fakeProc({
      50: { ppid: 1, comm: "sh", args: ["/bin/sh", "-c", "launchsafe-firewall run"] },
      1: { ppid: 0, comm: "sh", args: ["/bin/sh", "-c", `first step${br}second step`] },
    });
    expect(launchedByAgent({}, 50, reader(procRoot))).toBe(false);
    expect(agentAncestor(50, reader(procRoot))).toBeNull();
  });

  it("only a PID 1 that cannot be read is the top of the tree: one that was read but does not parse counts as an agent", () => {
    // A reader that returns the raw line, as /proc gave it before it was printed on one line.
    const raw = (pid1: string | null) => (pid: number): string | null => (pid === 50 ? "1 /bin/sh -c launchsafe-firewall run" : pid1);
    expect(launchedByAgent({}, 50, raw("0 /usr/local/bin/claude -p first line\nsecond line"))).toBe(true);
    expect(launchedByAgent({}, 50, raw("not a process line"))).toBe(true);
    expect(launchedByAgent({}, 50, raw(""))).toBe(true);
    // Hidden from other users (hidepid): nothing was read, and the walk ends there.
    expect(launchedByAgent({}, 50, raw(null))).toBe(false);
    const hidden = fakeProc({ 50: { ppid: 1, comm: "sh", args: ["/bin/sh", "-c", "launchsafe-firewall run"] } });
    expect(launchedByAgent({}, 50, reader(hidden))).toBe(false);
    // Below PID 1 a line that does not parse was always an agent.
    expect(launchedByAgent({}, 60, (pid) => (pid === 60 ? "50 node launchsafe-firewall" : "1 /bin/sh -c first\nsecond"))).toBe(true);
  });
});
