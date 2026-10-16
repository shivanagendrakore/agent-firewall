/**
 * Single-use authorizations for substitutions the hook decided but another
 * process performs (see docs/vault.md):
 *
 * - **run tickets.** The hook rewrites a shell command into
 *   `launchsafe-firewall run --ticket T --env __LSV_1=vault://… -- /bin/sh -c '…'`
 *   and stores `vault/tickets/<sha256(T)>.json` with the hash of the exact
 *   environment references and argv. `run` (its own branch) calls
 *   consumeTicket() with what it is about to run: the ticket is consumed
 *   atomically, and refused when unknown, used, expired or for another argv.
 *   Only the ticket's hash is on disk, so watching the directory does not
 *   reveal it.
 * - **gateway grants.** In hook mode the client's own hook decides an MCP
 *   call, and the gateway puts the values in. The hook leaves a grant keyed by
 *   (server, tool, hash of the arguments); the gateway consumes one per call.
 *   A call with references and no grant is refused: nothing but the firewall's
 *   own decision lets a value out.
 *
 * Neither holds a value: references, destinations and hashes only.
 */

import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { linkSync, readdirSync, readFileSync, renameSync, statSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson } from "../../engine/decide.js";
import type { VaultSubstitution } from "../../types.js";
import { agentProcess } from "../approver.js";
import { assertNotRealHome } from "../guard.js";
import { atomicWrite, ensureDir, withLock } from "../fsutil.js";
import type { Layout } from "../layout.js";
import { vaultDir } from "./index.js";

export function ticketsDir(l: Layout): string {
  return join(vaultDir(l), "tickets");
}

const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

/** What a ticket is bound to: the `--env NAME=vault://…` pairs and the argv after `--`, in order. */
export function ticketArgvHash(env: readonly (readonly [string, string])[], argv: readonly string[]): string {
  return sha(canonicalJson({ env: env.map(([n, r]) => [n, r]), argv: [...argv] }));
}

export function argsHash(args: unknown): string {
  return sha(canonicalJson(args ?? {}));
}

/** A process in an ancestor chain: its pid and start time (so a reused pid never matches). */
export interface Ancestor {
  pid: number;
  start: string;
}

export type AncestorInput = number | { pid: number; start?: string };

/** A row of the process table: parent pid, start time and command line. */
export interface ProcessParent {
  ppid: number;
  start: string;
  cmd?: string;
}

interface TicketFile {
  kind: "run";
  argvHash: string;
  refs: string[];
  session: string;
  substitute: VaultSubstitution[];
  expires: number;
  /**
   * I8: the issuing hook's ancestors (process ids and start times, nearest first, bounded at the coding agent).
   * The nearest one still alive with the same start time when the ticket is spent (the agent: a wrapper shell
   * between it and the hook has exited by then) must be an ancestor of the `run` that spends it, so a process
   * elsewhere under the same user that read the ticket from the agent's command line cannot spend it. Absent or
   * empty: refused (fail closed).
   */
  ancestors?: { pid: number; start?: string }[];
}

/**
 * Shared session, terminal, multiplexer, login or init processes above the coding agent: a ticket must never
 * bind to one of these, or another process in the user's session could spend it after the agent exits.
 */
export function sharedSessionProcess(command: string): boolean {
  const c = command.trim();
  if (c === "" || agentProcess(c)) return false;
  if (/(?:^|\/)(?:launchd|systemd|init|tmux(?::|$|\s)|screen|zellij|sshd(?::|$|\s)|login|su|sudo)(?:\s|:|$)/.test(c)) return true;
  if (/\/(?:Terminal|iTerm2?|WezTerm|Alacritty|kitty|Ghostty|Hyper|Warp|Cursor|Visual Studio Code|Code|Windsurf|Zed)\.app\/|(?:^|\/)(?:gnome-terminal(?:-\S+)?|konsole|xfce4-terminal|alacritty|kitty|wezterm(?:-gui)?|ghostty|foot)(?:\s|$)/.test(c)) return true;
  if (/^-[a-z]*sh(?:\s|$)/.test(c)) return true;
  if (/^(?:\/[\w./-]+\/)?(?:ba|z|fi|da|k|tc|c)?sh(?:\s+(?:-[a-df-zA-Z]\S*|--\S+))*\s*$/.test(c)) return true;
  return false;
}

/**
 * Processes above `pid`, nearest first (pid 1 and 0 left out), bounded at the coding agent process and
 * stopping before shared session/terminal/init ancestors, from /proc on Linux, else one `ps` call.
 */
export function ancestry(pid: number, readParents: () => ReadonlyMap<number, ProcessParent | number> | null = parentTable): Ancestor[] | null {
  const parents = readParents();
  if (parents === null) return null;
  const out: Ancestor[] = [];
  const first = parents.get(pid);
  if (first === undefined) return out;
  if (typeof first === "number") {
    let cur: number | undefined = first;
    while (cur !== undefined && cur > 1 && out.length < 64 && !out.some((a) => a.pid === cur)) {
      out.push({ pid: cur, start: "" });
      const next = parents.get(cur);
      cur = typeof next === "number" ? next : next?.ppid;
    }
    return out;
  }
  let cur: number | undefined = first.ppid;
  let sawAgent = false;
  while (cur !== undefined && cur > 1 && out.length < 64 && !out.some((a) => a.pid === cur)) {
    const info = parents.get(cur);
    if (info === undefined || typeof info === "number" || info.start === "") break;
    const cmd = info.cmd ?? "";
    const isAgent = cmd !== "" && agentProcess(cmd);
    if (sawAgent && !isAgent) break;
    if (!isAgent && cmd !== "" && sharedSessionProcess(cmd)) break;
    out.push({ pid: cur, start: info.start });
    if (isAgent) sawAgent = true;
    cur = info.ppid;
  }
  return out;
}

/** pid -> parent pid, start time and command line for every process this user can see; null when it cannot be read. */
function parentTable(): Map<number, ProcessParent> | null {
  const m = new Map<number, ProcessParent>();
  try {
    for (const d of readdirSync("/proc")) {
      if (!/^\d+$/.test(d)) continue;
      try {
        const stat = readFileSync(`/proc/${d}/stat`, "utf8");
        // The command name (in parentheses) may hold spaces and ")": the fields after the last ")".
        const open = stat.indexOf("(");
        const close = stat.lastIndexOf(")");
        if (open < 0 || close < open) continue;
        const comm = stat.slice(open + 1, close);
        const fields = stat.slice(close + 2).split(" ");
        const ppid = Number(fields[1]);
        const start = fields[19];
        if (!Number.isInteger(ppid) || start === undefined || start === "") continue;
        let cmd = "";
        try {
          cmd = readFileSync(`/proc/${d}/cmdline`, "utf8").split("\0").filter((x, i, a) => x !== "" || i < a.length - 1).join(" ");
        } catch {
          // Unreadable cmdline: fall back to comm.
        }
        m.set(Number(d), { ppid, start, cmd: cmd !== "" ? cmd : comm });
      } catch {
        // Gone.
      }
    }
    if (m.size > 0) return m;
  } catch {
    // No /proc (macOS).
  }
  try {
    const out = execFileSync("ps", ["-A", "-ww", "-o", "pid=,ppid=,lstart=,command="], {
      encoding: "utf8",
      timeout: 3000,
      stdio: ["ignore", "pipe", "ignore"],
      env: { LC_ALL: "C", PATH: "/bin:/usr/bin" },
    });
    for (const line of out.split("\n")) {
      const r = /^\s*(\d+)\s+(\d+)\s+(\S+\s+\S+\s+\d+\s+[\d:]+\s+\d+)\s+(.*?)\s*$/.exec(line);
      if (r !== null) {
        m.set(Number(r[1]), { ppid: Number(r[2]), start: (r[3] as string).replace(/\s+/g, " "), cmd: r[4] as string });
      }
    }
    return m.size > 0 ? m : null;
  } catch {
    return null;
  }
}

/** The start time of a live process (matching parentTable's format), or null when gone or unreadable. */
export function processStart(pid: number): string | null {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  if (process.platform === "linux") {
    try {
      const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
      const close = stat.lastIndexOf(")");
      if (close < 0) return null;
      const start = stat.slice(close + 2).split(" ")[19];
      return start !== undefined && start !== "" ? start : null;
    } catch {
      return null;
    }
  }
  try {
    const out = execFileSync("ps", ["-ww", "-o", "lstart=", "-p", String(pid)], {
      encoding: "utf8",
      timeout: 3000,
      stdio: ["ignore", "pipe", "ignore"],
      env: { LC_ALL: "C", PATH: "/bin:/usr/bin" },
    });
    const m = /^\s*(\S+\s+\S+\s+\d+\s+[\d:]+\s+\d+)\s*$/.exec(out);
    return m === null ? null : (m[1] as string).replace(/\s+/g, " ");
  } catch {
    return null;
  }
}

/** Whether a process is alive (signal 0; EPERM means it exists under another user) and started at `start` when given. */
function alive(pid: number, start?: string, table?: ReadonlyMap<number, ProcessParent> | null): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  let running = false;
  try {
    process.kill(pid, 0);
    running = true;
  } catch (e) {
    running = (e as NodeJS.ErrnoException).code === "EPERM";
  }
  if (!running) return false;
  if (start === undefined) return true;
  const current = table?.get(pid)?.start ?? processStart(pid);
  return current !== null && current === start;
}

/** What consumeTicket checks the binding against (injected in tests). */
export interface Lineage {
  /** The spending process and its ancestors, nearest first; null when unreadable. */
  ancestors: readonly AncestorInput[] | null;
  alive: (pid: number, start?: string) => boolean;
}

export function ownLineage(readParents: () => Map<number, ProcessParent> | null = parentTable): Lineage {
  const parents = readParents();
  const self = parents?.get(process.pid);
  const up = parents === null || self === undefined ? null : ancestry(process.pid, () => parents);
  return {
    ancestors: up === null || self === undefined ? null : [{ pid: process.pid, start: self.start }, ...up],
    alive: (pid, start) => start !== undefined && start !== "" && alive(pid, start, parents),
  };
}

function toAncestor(a: AncestorInput): { pid: number; start?: string } {
  return typeof a === "number" ? { pid: a } : { pid: a.pid, ...(a.start !== undefined ? { start: a.start } : {}) };
}

/** Why the ticket's binding to its agent refuses this spender, or null (I8). */
export function lineageProblem(ticketAncestors: readonly AncestorInput[] | undefined, lineage: Lineage): string | null {
  if (ticketAncestors === undefined || ticketAncestors.length === 0) {
    return "the processes above the hook could not be read, so the ticket's agent cannot be confirmed";
  }
  const normalized = ticketAncestors.map(toAncestor);
  const anchor = normalized.find((p) => lineage.alive(p.pid, p.start));
  if (anchor === undefined) return "the agent the ticket was issued to is gone";
  if (lineage.ancestors === null || lineage.ancestors.length === 0) {
    return "the processes above this run could not be read, so the ticket's agent cannot be confirmed";
  }
  const spenders = lineage.ancestors.map(toAncestor);
  return spenders.some((s) => s.pid === anchor.pid && s.start === anchor.start) ? null : "this run was not started by the agent the ticket was issued to";
}

interface GrantFile {
  kind: "grant";
  server: string;
  tool: string;
  argsHash: string;
  session: string;
  substitute: VaultSubstitution[];
  /** How many identical calls this grant still covers. */
  count: number;
  expires: number;
}

function grantName(server: string, tool: string, hash: string): string {
  return `grant-${sha(`${server}\n${tool}\n${hash}`)}.json`;
}

/** A taken file older than this was left by a process that died between taking and reading it. */
const TAKEN_STALE_MS = 60_000;

/**
 * Drops expired files. Never throws. Race-free against the other writers (minor fix): a `.taken.` file is
 * another process's, mid-read, unless it is old; and an expired file is first taken (renamed) and read
 * again, so a fresh file renamed over the same name a moment earlier (issueGrant) is put back, never deleted.
 */
function sweep(l: Layout, now: number): void {
  let names: string[];
  try {
    names = readdirSync(ticketsDir(l));
  } catch {
    return;
  }
  for (const n of names) {
    const p = join(ticketsDir(l), n);
    try {
      if (n.includes(".taken.")) {
        if (Date.now() - statSync(p).mtimeMs > TAKEN_STALE_MS) unlinkSync(p);
        continue;
      }
      if (!n.endsWith(".json")) continue;
      const v = JSON.parse(readFileSync(p, "utf8")) as { expires?: number };
      if (typeof v.expires === "number" && v.expires >= now) continue;
      const taken = `${p}.taken.${randomBytes(6).toString("hex")}`;
      renameSync(p, taken);
      try {
        const again = JSON.parse(readFileSync(taken, "utf8")) as { expires?: number };
        // Replaced between the two reads: put it back unless an even newer one is there (link never overwrites).
        if (typeof again.expires === "number" && again.expires >= now) linkSync(taken, p);
      } catch {
        // Unreadable, or a newer file holds the name: this one goes.
      } finally {
        unlinkSync(taken);
      }
    } catch {
      // Gone already, or being written: leave it.
    }
  }
}

function write(l: Layout, name: string, v: TicketFile | GrantFile, now: number): void {
  assertNotRealHome(ticketsDir(l));
  ensureDir(ticketsDir(l));
  sweep(l, now);
  atomicWrite(join(ticketsDir(l), name), `${JSON.stringify(v)}\n`, 0o600);
}

/** Takes a file so no other process can (rename is atomic), and returns its content. */
function take<T>(l: Layout, name: string): T | null {
  const p = join(ticketsDir(l), name);
  const taken = `${p}.taken.${randomBytes(6).toString("hex")}`;
  try {
    renameSync(p, taken);
  } catch {
    return null;
  }
  try {
    return JSON.parse(readFileSync(taken, "utf8")) as T;
  } catch {
    return null;
  } finally {
    try {
      unlinkSync(taken);
    } catch {
      // Already gone.
    }
  }
}

function normalizeAncestors(input: readonly AncestorInput[] | undefined): { pid: number; start?: string }[] {
  if (input === undefined) return ancestry(process.pid) ?? [];
  const out: { pid: number; start?: string }[] = [];
  for (const a of input) {
    if (typeof a === "number") {
      if (!Number.isInteger(a) || a <= 1) continue;
      const start = processStart(a);
      out.push(start !== null ? { pid: a, start } : { pid: a });
    } else if (Number.isInteger(a.pid) && a.pid > 1) {
      const start = a.start !== undefined && a.start !== "" ? a.start : processStart(a.pid);
      out.push(start !== null ? { pid: a.pid, start } : { pid: a.pid });
    }
  }
  return out;
}

function validTicketAncestor(a: unknown): a is AncestorInput {
  if (typeof a === "number") return Number.isInteger(a) && a > 1;
  if (typeof a !== "object" || a === null) return false;
  const { pid, start } = a as { pid?: unknown; start?: unknown };
  return typeof pid === "number" && Number.isInteger(pid) && pid > 1 && (start === undefined || (typeof start === "string" && start !== ""));
}

/** Issues a run ticket for this exact environment and argv; returns the ticket (128 random bits). */
export function issueTicket(l: Layout, o: { env: readonly (readonly [string, string])[]; argv: readonly string[]; session: string; substitute: VaultSubstitution[]; seconds: number; now?: Date; ancestors?: readonly AncestorInput[] }): string {
  const now = (o.now ?? new Date()).getTime();
  // Never starting with "-": the rewritten command passes it as the word after --ticket, which the argument
  // parser would read as a flag (1 in 64 tickets otherwise).
  let ticket = randomBytes(16).toString("base64url");
  while (ticket.startsWith("-")) ticket = randomBytes(16).toString("base64url");
  // The issuer's ancestors, starting with its parent (the hook itself exits before the ticket is spent).
  const ancestors = normalizeAncestors(o.ancestors);
  write(l, `${sha(ticket)}.json`, { kind: "run", argvHash: ticketArgvHash(o.env, o.argv), refs: [...new Set(o.env.map(([, r]) => r))], session: o.session, substitute: o.substitute, expires: now + o.seconds * 1000, ancestors }, now);
  return ticket;
}

export type TicketCheck = { ok: true; session: string; refs: string[]; substitute: VaultSubstitution[] } | { ok: false; why: string };

/**
 * For `run`: consumes the ticket if it was issued for exactly this environment and argv and has not
 * expired. Any other outcome is a refusal (`run` exits 77 and logs vault_denied); the ticket is spent
 * either way, so a guess or a replay never gets a second try.
 */
export function consumeTicket(l: Layout, ticket: string, env: readonly (readonly [string, string])[], argv: readonly string[], now: Date = new Date(), lineage: () => Lineage = ownLineage): TicketCheck {
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(ticket)) return { ok: false, why: "not a ticket" };
  const t = take<TicketFile>(l, `${sha(ticket)}.json`);
  if (t === null || t.kind !== "run") return { ok: false, why: "unknown or already used ticket" };
  if (t.expires < now.getTime()) return { ok: false, why: "the ticket expired" };
  if (t.argvHash !== ticketArgvHash(env, argv)) return { ok: false, why: "the command is not the one the ticket was issued for" };
  const bound = lineageProblem(Array.isArray(t.ancestors) ? t.ancestors.filter(validTicketAncestor) : undefined, lineage());
  if (bound !== null) return { ok: false, why: bound };
  return { ok: true, session: t.session, refs: t.refs, substitute: t.substitute };
}

/** For the hook: lets the gateway put the values into this exact MCP call (once). */
export function issueGrant(l: Layout, o: { server: string; tool: string; args: unknown; session: string; substitute: VaultSubstitution[]; seconds: number; now?: Date }): void {
  const now = (o.now ?? new Date()).getTime();
  const hash = argsHash(o.args);
  const name = grantName(o.server, o.tool, hash);
  // Read, count up, write: under the grants' lock, so two hooks deciding the same call at once both count.
  withGrantLock(l, () => {
    const prior = take<GrantFile>(l, name);
    const count = prior !== null && prior.expires >= now ? prior.count + 1 : 1;
    write(l, name, { kind: "grant", server: o.server, tool: o.tool, argsHash: hash, session: o.session, substitute: o.substitute, count, expires: now + o.seconds * 1000 }, now);
  });
}

/** issueGrant and consumeGrant read a grant and write it back: one at a time (the lost-update fix). */
function withGrantLock<T>(l: Layout, fn: () => T): T {
  assertNotRealHome(ticketsDir(l));
  ensureDir(ticketsDir(l));
  return withLock(join(ticketsDir(l), "grants.lock"), fn);
}

/** For the gateway in hook mode: the substitutions the hook allowed for this call, consumed; null when none. */
export function consumeGrant(l: Layout, server: string, tool: string, args: unknown, now: Date = new Date()): { session: string; substitute: VaultSubstitution[] } | null {
  const name = grantName(server, tool, argsHash(args));
  return withGrantLock(l, () => {
    const g = take<GrantFile>(l, name);
    if (g === null || g.kind !== "grant" || g.expires < now.getTime()) return null;
    if (g.count > 1) write(l, name, { ...g, count: g.count - 1 }, now.getTime());
    return { session: g.session, substitute: g.substitute };
  });
}
