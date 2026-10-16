/**
 * The command lines of the hook's ancestor processes, for the adapters that
 * tell an unattended session from the agent's own command line (`gemini -p`,
 * `codex exec`, `cursor-agent -p`).
 *
 * On Linux the source is /proc: `/proc/<pid>/stat` names the parent (the second
 * field after the last ")" of the command name, which may hold spaces and
 * parentheses) and `/proc/<pid>/cmdline` holds the arguments, NUL-separated.
 * Nothing is run, so a minimal image without procps (Debian-slim, Alpine,
 * busybox) is read like any other. Process 1 is read too: in a container the
 * agent is often the first process.
 *
 * Elsewhere (macOS, the BSDs) the source is `ps -o ppid=,args=` walked up from
 * the hook's parent. On macOS `/bin/ps` is setuid root, and a process inside a
 * seatbelt sandbox may not run it: it fails with "Operation not permitted"
 * (captured under Gemini CLI's own sandbox, `gemini -s`, and under a
 * `sandbox-exec` wrapper). There the walk falls back to `/usr/bin/pgrep`, which
 * is not setuid and still reads same-user command lines: by default pgrep
 * leaves out itself and all of its ancestors, and with `-a` it includes them,
 * so the processes the second listing adds are exactly the ancestors that
 * match (captured, see test/fixtures/ancestry-*.txt). The fallback gives no
 * order and no depth, so every matching ancestor counts; a short-lived process
 * that matches and ends between the two listings can be taken for an ancestor
 * (only ever in the strict direction: unattended). Linux's procps pgrep has a
 * different `-a`, so the fallback is macOS only.
 *
 * `inspected` is false when no source could be read, and every adapter then
 * treats the session as unattended (see `uninspectedReason`): an unknown
 * process is never read as "attended".
 */

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export type Run = (cmd: string, args: string[]) => string;

export interface Ancestry {
  /** Command lines, nearest first (/proc, ps); unordered (pgrep). */
  args: string[];
  /** Where they came from; "none" when no source could be read. */
  via: "proc" | "ps" | "pgrep" | "none";
  inspected: boolean;
}

/** Where the process table is read from (tests): the platform, a fake /proc root, and a stand-in for running ps and pgrep. */
export interface ProcessProbe {
  platform?: NodeJS.Platform;
  /** The directory holding `<pid>/stat` and `<pid>/cmdline` (default /proc). */
  procRoot?: string;
  exec?: Run;
}

/** Item 2: system tools by absolute path, never through PATH (which an agent's settings env can set). */
/**
 * An agent's program in a command line (Claude Code, Codex, Gemini CLI, Cursor's agent), as the CLI or its wrapper is
 * started: by name, by package path, or as Codex's native release binary or Cursor's agent folder. One list for the
 * approver's checks and for `run`'s, so an agent one of them knows is known to both.
 */
export const AGENT_COMMAND = /(?:^|\/)(?:claude|codex|gemini|cursor-agent)(?:\s|$)|claude-code\/|\/claude\.app\/|@anthropic-ai\/claude-code|@openai\/codex|@google\/gemini-cli|\/codex-(?:aarch64|x86_64)|cursor-agent\//;

export function systemTool(name: "ps" | "pgrep"): string {
  for (const dir of ["/bin", "/usr/bin"]) if (existsSync(`${dir}/${name}`)) return `${dir}/${name}`;
  return `/usr/bin/${name}`;
}

const run: Run = (cmd, args) => execFileSync(cmd === "ps" || cmd === "pgrep" ? systemTool(cmd) : cmd, args, { encoding: "utf8", timeout: 1000, stdio: ["ignore", "pipe", "ignore"] });

/** `pgrep -l -f` lines ("<pid> <args>") by pid. */
export function pgrepLines(out: string): Map<number, string> {
  const m = new Map<number, string>();
  for (const line of out.split("\n")) {
    const r = /^\s*(\d+)\s+(.*)$/.exec(line);
    if (r !== null) m.set(Number(r[1]), r[2] as string);
  }
  return m;
}

/** The ancestors pgrep -a adds to the plain listing (both for the same pattern). */
export function pgrepAncestors(withAncestors: string, without: string): string[] {
  const all = pgrepLines(withAncestors);
  const others = pgrepLines(without);
  return [...all].filter(([pid, args]) => !others.has(pid) && !/^(?:\/usr\/bin\/)?pgrep\s/.test(args)).map(([, args]) => args);
}

/**
 * One process as /proc shows it: its parent and its command line (arguments joined by spaces, as ps prints
 * them, but with their control characters and line breaks kept: processLine prints them as ps does; the
 * command name when the arguments are empty, as for a kernel thread). Null when either file cannot be read
 * or the stat line is not in the kernel's format: the process is gone or hidden.
 */
export function readProc(pid: number, root = "/proc"): { ppid: number; args: string } | null {
  if (!Number.isInteger(pid) || pid < 1) return null;
  try {
    const stat = readFileSync(join(root, String(pid), "stat"), "utf8");
    const raw = readFileSync(join(root, String(pid), "cmdline"), "utf8");
    // "pid (comm) state ppid ...": the command name may hold spaces and ")", so the fields start after the last ")".
    const open = stat.indexOf("(");
    const close = stat.lastIndexOf(")");
    if (open < 0 || close < open) return null;
    const m = /^ \S (\d+)(?: |$)/.exec(stat.slice(close + 1));
    if (m === null) return null;
    const args = raw.replace(/\0+$/, "").split("\0").join(" ");
    return { ppid: Number(m[1]), args: args !== "" ? args : stat.slice(open + 1, close) };
  } catch {
    return null;
  }
}

/** The ancestors from `start` up through /proc (at most `depth`, process 1 included), nearest first. */
function procAncestors(start: number, depth: number, root: string): Ancestry {
  const out: string[] = [];
  const seen = new Set<number>();
  let pid = start;
  for (let i = 0; i < depth && pid >= 1 && !seen.has(pid); i++) {
    seen.add(pid);
    const p = readProc(pid, root);
    // A process that ends mid-walk has only been lost: what was read stands. Nothing read at all is not "attended".
    if (p === null) break;
    out.push(p.args);
    pid = p.ppid;
  }
  return out.length > 0 ? { args: out, via: "proc", inspected: true } : { args: [], via: "none", inspected: false };
}

/** The command line of one process, or null when it could not be read (so nothing is known about it). */
export function processArgs(pid: number, o: ProcessProbe = {}): string | null {
  if ((o.platform ?? process.platform) === "linux") return readProc(pid, o.procRoot)?.args ?? null;
  try {
    const line = (o.exec ?? run)("ps", ["-o", "args=", "-p", String(pid)]).trim();
    return line === "" ? null : line;
  } catch {
    return null;
  }
}

/**
 * A command line on one line, as ps prints it: control characters (C0, DEL, C1) and the Unicode line and
 * paragraph separators become "?". An argument read from /proc keeps its line breaks (a prompt read from a
 * file), and the walks that parse `<ppid> <command>` read one line.
 */
function psLine(s: string): string {
  // eslint-disable-next-line no-control-regex -- matching control characters is the point.
  return s.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, "?");
}

/**
 * One process's `<ppid> <command>` line, on one line as ps prints it: read from /proc on Linux, else
 * `ps -o ppid=,command=`. Null when the process cannot be read.
 */
export function processLine(pid: number, o: ProcessProbe = {}): string | null {
  if ((o.platform ?? process.platform) === "linux") {
    const p = readProc(pid, o.procRoot);
    return p === null ? null : psLine(`${p.ppid} ${p.args}`);
  }
  try {
    const line = (o.exec ?? run)("ps", ["-o", "ppid=,command=", "-p", String(pid)]).trim();
    return line === "" ? null : psLine(line);
  } catch {
    return null;
  }
}

/**
 * Why a session whose agent process could not be inspected is unattended: the strict reading. Unattended holds an
 * action in the queue instead of asking, applies the task scope to a trusted session too, and offers no learned
 * allow; the only thing it relaxes is the early spending warning (a note instead of a question), never a limit.
 * `pgrep` is false for a source with no pgrep fallback (the Claude Code check reads one process with ps), so the
 * reason never says pgrep was tried when it was not.
 */
export function uninspectedReason(agent: string, platform: NodeJS.Platform = process.platform, pgrep = true): string {
  const how = platform === "linux" ? "/proc could not be read" : platform === "darwin" && pgrep ? "ps and pgrep both failed" : "ps failed";
  return `${agent}'s command line could not be read (${how}), so the session is treated as unattended`;
}

/**
 * Ancestor command lines from `start` up (at most `depth`): through /proc on Linux, else through ps, falling
 * back on macOS to the ancestors pgrep finds for `pattern` when ps cannot run at all.
 */
export function ancestorArgs(start: number, o: ProcessProbe & { depth?: number; pattern: string }): Ancestry {
  if ((o.platform ?? process.platform) === "linux") return procAncestors(start, o.depth ?? 4, o.procRoot ?? "/proc");
  const exec = o.exec ?? run;
  const out: string[] = [];
  let pid = start;
  let psRan = false;
  for (let i = 0; i < (o.depth ?? 4) && pid > 1; i++) {
    let line: string;
    try {
      line = exec("ps", ["-o", "ppid=,args=", "-p", String(pid)]).trim();
    } catch {
      // ps that ran once and then fails has only lost the process (it ended): what was read stands.
      break;
    }
    psRan = true;
    const m = /^(\d+)\s+([\s\S]*)$/.exec(line);
    if (m === null) break;
    out.push(m[2] as string);
    pid = Number(m[1]);
  }
  if (psRan || start <= 1) return { args: out, via: "ps", inspected: true };
  if ((o.platform ?? process.platform) !== "darwin") return { args: [], via: "none", inspected: false };
  try {
    // "-a" first: a process that starts between the two listings then shows in the plain one only and is ignored.
    const withAncestors = pgrepOrEmpty(exec, ["-a", "-l", "-f", o.pattern]);
    const without = pgrepOrEmpty(exec, ["-l", "-f", o.pattern]);
    return { args: pgrepAncestors(withAncestors, without), via: "pgrep", inspected: true };
  } catch {
    return { args: [], via: "none", inspected: false };
  }
}

/** pgrep exits 1 when nothing matches: that is an empty listing, not a failure. */
function pgrepOrEmpty(exec: Run, args: string[]): string {
  try {
    return exec("/usr/bin/pgrep", args);
  } catch (e) {
    if ((e as { status?: number }).status === 1) return "";
    throw e;
  }
}
