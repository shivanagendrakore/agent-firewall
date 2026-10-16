/**
 * The per-project known-hosts list (knownHosts, docs/usage.md "Known hosts"): one file per project in the
 * firewall's own directory (~/.launchsafe-firewall/known-hosts/<project hash>.json, mode 0600). It is never
 * read from the repository: a project can only tighten (src/policy-knownhosts.ts), and the agent can never
 * write the firewall's directory (FW-TAMPER), so neither a repository nor the agent can pre-approve a host.
 *
 * The file holds:
 * - `approved`: hosts a person approved for this project: a yes to FW-NEW-HOST in a trusted session (the
 *   question is noted as `pending` before the tool runs and confirmed by its PostToolUse, as the budgets
 *   do), a queue approval of such an action, or `hosts allow` / `hosts accept` in the person's terminal;
 * - `pending`: questions asked and not answered yet (dropped after an hour);
 * - `watch`: with knownHosts.mode "watch", the hosts contacted during the first `watchDays` days, for
 *   `hosts review` to propose. Hosts first seen after the session read outside content are kept apart
 *   and never proposed.
 *
 * Fail closed: an unreadable or malformed file means no approved hosts (every new host asks again), and
 * nothing is written over it until a person runs `hosts reset`.
 */

import { createHash } from "node:crypto";
import { readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { learnableHost } from "../engine/knownhosts.js";
import { normalizeHost } from "../engine/network.js";
import { atomicWrite, tryReadText, withLock } from "./fsutil.js";
import { assertNotRealHome } from "./guard.js";
import type { Check } from "./doctor.js";
import type { Layout } from "./layout.js";
import { realpathLoose } from "./realpath.js";

export type ApprovedVia = "asked" | "queue" | "cli" | "review";
export type SeenVia = "hook" | "run";

export interface ApprovedHost {
  host: string;
  at: string;
  via: ApprovedVia;
}

export interface PendingQuestion {
  session: string;
  hash: string;
  hosts: string[];
  at: string;
  via: "asked" | "queue";
  /** Whether the session had read outside content when the question was asked (never learned from then). */
  tainted: boolean;
}

export interface SeenHost {
  host: string;
  first: string;
  last: string;
  count: number;
  /** Seen only in sessions that had read outside content (never proposed). */
  tainted: boolean;
  /** Data was sent there at least once (never proposed by --all). */
  sent: boolean;
  via: SeenVia;
}

export interface KnownHostsFile {
  version: 1;
  project: string;
  approved: ApprovedHost[];
  pending: PendingQuestion[];
  watch?: { since: string; seen: SeenHost[] };
}

const PENDING_MS = 60 * 60 * 1000;
export const MAX_APPROVED = 2000;
/** The lock's timing (tests shorten it). */
export const KNOWN_HOSTS_LOCK = { timeoutMs: 15000, staleMs: 30000 };
const MAX_PENDING = 50;
const MAX_SEEN = 500;

/** The project's identity: its absolute path with symlinks resolved (a checkout reached by two paths is one project). */
export function projectKey(dir: string): string {
  return realpathLoose(resolve(dir));
}

export function knownHostsDir(l: Layout): string {
  return join(l.home, "known-hosts");
}

export function knownHostsFile(l: Layout, project: string): string {
  return join(knownHostsDir(l), `${createHash("sha256").update(projectKey(project)).digest("hex").slice(0, 32)}.json`);
}

function empty(project: string): KnownHostsFile {
  return { version: 1, project: projectKey(project), approved: [], pending: [] };
}

const isStr = (v: unknown): v is string => typeof v === "string";
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** Strict shape check: anything unexpected is a damaged file. */
function parse(text: string, project: string): KnownHostsFile | null {
  try {
    const o = JSON.parse(text) as unknown;
    if (!isObj(o) || o.version !== 1 || o.project !== projectKey(project)) return null;
    if (!Array.isArray(o.approved) || !o.approved.every((a) => isObj(a) && isStr(a.host) && learnableHost(a.host) && isStr(a.at) && ["asked", "queue", "cli", "review"].includes(a.via as string))) return null;
    if (!Array.isArray(o.pending) || !o.pending.every((p) => isObj(p) && isStr(p.session) && isStr(p.hash) && isStr(p.at) && Array.isArray(p.hosts) && p.hosts.every(isStr) && (p.via === "asked" || p.via === "queue") && typeof p.tainted === "boolean")) return null;
    if (o.watch !== undefined) {
      const w = o.watch;
      if (!isObj(w) || !isStr(w.since) || !Array.isArray(w.seen)) return null;
      if (!w.seen.every((x) => isObj(x) && isStr(x.host) && isStr(x.first) && isStr(x.last) && typeof x.count === "number" && typeof x.tainted === "boolean" && typeof x.sent === "boolean" && (x.via === "hook" || x.via === "run"))) return null;
    }
    return o as unknown as KnownHostsFile;
  } catch {
    return null;
  }
}

/** The project's file: a missing file is an empty list; an unreadable or malformed one is `damaged`. */
export function readKnownHosts(l: Layout, project: string): { file: KnownHostsFile; damaged: boolean } {
  const text = tryReadText(knownHostsFile(l, project));
  if (text === null) return { file: empty(project), damaged: false };
  if (typeof text !== "string") return { file: empty(project), damaged: true };
  const f = parse(text, project);
  return f === null ? { file: empty(project), damaged: true } : { file: f, damaged: false };
}

/** The hosts a person approved for the project (none when the file is damaged: every new host asks again). */
export function approvedHosts(l: Layout, project: string): string[] {
  return readKnownHosts(l, project).file.approved.map((a) => a.host);
}

/**
 * Read-modify-write under the file's lock. A damaged file is left as it is (fn is not called) unless
 * `replaceDamaged` is set (`hosts reset`): the damage may be someone else's doing and stays for doctor
 * and the person to see.
 */
function update<T>(l: Layout, project: string, fn: (f: KnownHostsFile) => T, opts: { replaceDamaged?: boolean } = {}): { result: T | null; damaged: boolean } {
  const path = knownHostsFile(l, project);
  assertNotRealHome(path);
  return withLock(
    `${path}.lock`,
    () => {
    const { file, damaged } = readKnownHosts(l, project);
    if (damaged && opts.replaceDamaged !== true) return { result: null, damaged: true };
    const before = JSON.stringify(file);
    const result = fn(file);
    if (JSON.stringify(file) !== before || damaged) atomicWrite(path, `${JSON.stringify(file, null, 1)}\n`);
    return { result, damaged };
    },
    KNOWN_HOSTS_LOCK,
  );
}

function addApproved(f: KnownHostsFile, hosts: readonly string[], via: ApprovedVia, now: Date): string[] {
  const added: string[] = [];
  for (const raw of hosts) {
    const host = normalizeHost(raw.trim());
    if (!learnableHost(host) || f.approved.some((a) => a.host === host) || f.approved.length >= MAX_APPROVED) continue;
    f.approved.push({ host, at: now.toISOString(), via });
    added.push(host);
  }
  return added;
}

/**
 * Notes a question about new hosts before the tool runs: a trusted, attended session's FW-NEW-HOST that is
 * asked, or a queue approval of one being used. Only learnable hosts are kept; expired questions are dropped.
 */
export function notePending(l: Layout, project: string, q: { session: string; hash: string; hosts: readonly string[]; via: "asked" | "queue"; tainted?: boolean }, now: Date): void {
  const hosts = [...new Set(q.hosts.map((h) => normalizeHost(h)).filter(learnableHost))];
  if (hosts.length === 0) return;
  update(l, project, (f) => {
    f.pending = f.pending.filter((p) => now.getTime() - Date.parse(p.at) < PENDING_MS && !(p.session === q.session && p.hash === q.hash));
    f.pending.push({ session: q.session, hash: q.hash, hosts, at: now.toISOString(), via: q.via, tainted: q.tainted === true });
    if (f.pending.length > MAX_PENDING) f.pending = f.pending.slice(-MAX_PENDING);
  });
}

/**
 * Drops any question noted for this session and action. Called on every PreToolUse of the action that may
 * not teach (the session is untrusted now, nobody can answer, or there is no new host), so an earlier
 * trusted question the person declined can never be confirmed by a later, tainted run of the same action.
 * Reads first and writes only when there is something to drop.
 */
export function clearPending(l: Layout, project: string, session: string, hash: string): void {
  const { file, damaged } = readKnownHosts(l, project);
  if (damaged || !file.pending.some((p) => p.session === session && p.hash === hash)) return;
  update(l, project, (f) => {
    f.pending = f.pending.filter((p) => !(p.session === session && p.hash === hash));
  });
}

/**
 * PostToolUse: the questioned action ran, so the person said yes (or approved it in the queue): its hosts
 * join the project's list, unless `mayLearn` is false (the session read outside content from anything but
 * this action itself) or the question was noted in a tainted session. Either way the question is used up.
 * Returns the hosts added.
 */
export function confirmPending(l: Layout, project: string, session: string, hash: string, now: Date, mayLearn = true): string[] {
  const { file, damaged } = readKnownHosts(l, project);
  if (damaged || !file.pending.some((p) => p.session === session && p.hash === hash)) return [];
  return (
    update(l, project, (f) => {
      const hit = f.pending.find((p) => p.session === session && p.hash === hash && now.getTime() - Date.parse(p.at) < PENDING_MS);
      f.pending = f.pending.filter((p) => !(p.session === session && p.hash === hash) && now.getTime() - Date.parse(p.at) < PENDING_MS);
      return hit === undefined || hit.tainted || !mayLearn ? [] : addApproved(f, hit.hosts, hit.via, now);
    }).result ?? []
  );
}

/** `hosts allow` / `hosts accept`: adds hosts for the project. Hosts that can never be learned are returned in `refused`. */
export function allowHosts(l: Layout, project: string, hosts: readonly string[], via: "cli" | "review", now: Date): { added: string[]; refused: string[]; damaged: boolean } {
  const refused = hosts.filter((h) => !learnableHost(h));
  const r = update(l, project, (f) => addApproved(f, hosts, via, now));
  return { added: r.result ?? [], refused, damaged: r.damaged };
}

/** `hosts remove`: the project's list without these hosts. */
export function removeHosts(l: Layout, project: string, hosts: readonly string[]): { removed: string[]; damaged: boolean } {
  const want = new Set(hosts.map((h) => normalizeHost(h.trim())));
  const r = update(l, project, (f) => {
    const removed = f.approved.filter((a) => want.has(a.host)).map((a) => a.host);
    f.approved = f.approved.filter((a) => !want.has(a.host));
    if (f.watch !== undefined) f.watch.seen = f.watch.seen.filter((s) => !want.has(s.host));
    return removed;
  });
  return { removed: r.result ?? [], damaged: r.damaged };
}

/** `hosts reset`: an empty list for the project (also replaces a damaged file). */
export function resetHosts(l: Layout, project: string): void {
  update(
    l,
    project,
    (f) => {
      f.approved = [];
      f.pending = [];
      delete f.watch;
    },
    { replaceDamaged: true },
  );
}

/** Whether the project's watch period has ended (or never started). */
export function watchState(f: KnownHostsFile, watchDays: number, now: Date): "not-started" | "watching" | "ended" {
  if (f.watch === undefined) return "not-started";
  return now.getTime() - Date.parse(f.watch.since) < watchDays * 86400000 ? "watching" : "ended";
}

/**
 * knownHosts.mode "watch": records the hosts contacted (not already known) during the first `watchDays`
 * days in the project. A host seen only from a session that had read outside content is marked tainted
 * and never proposed. Returns false once the watch period is over (nothing is recorded then).
 */
export function recordSeen(l: Layout, project: string, contacts: readonly { host: string; tainted: boolean; sent?: boolean }[], via: SeenVia, watchDays: number, now: Date): boolean {
  const hosts = contacts.map((c) => ({ host: normalizeHost(c.host), tainted: c.tainted, sent: c.sent === true })).filter((c) => learnableHost(c.host));
  if (hosts.length === 0) return true;
  const { file, damaged } = readKnownHosts(l, project);
  if (damaged || watchState(file, watchDays, now) === "ended") return false;
  const r = update(l, project, (f) => {
    if (watchState(f, watchDays, now) === "ended") return false;
    const at = now.toISOString();
    f.watch ??= { since: at, seen: [] };
    for (const c of hosts) {
      if (f.approved.some((a) => a.host === c.host)) continue;
      const s = f.watch.seen.find((x) => x.host === c.host);
      if (s !== undefined) {
        s.last = at;
        s.count++;
        if (!c.tainted) s.tainted = false;
        if (via === "hook" && !c.tainted) s.via = "hook";
        if (c.sent) s.sent = true;
      } else if (f.watch.seen.length < MAX_SEEN) f.watch.seen.push({ host: c.host, first: at, last: at, count: 1, tainted: c.tainted, sent: c.sent, via });
    }
    return true;
  });
  return r.result === true;
}

/**
 * What `hosts review` shows, most used first: `proposed`, hosts a trusted session's tool fetched from while
 * watching (what `hosts accept --all` adds); `sentTo`, hosts a trusted session also sent data to (accept them
 * by name if you mean it); `fromRun`, hosts only `run`'s proxy saw a program ask for (run has no taint
 * tracking, so each is listed for you to judge); `taintedOnly`, hosts seen only after a session read outside
 * content (never proposed).
 */
export function proposals(f: KnownHostsFile): { proposed: SeenHost[]; sentTo: SeenHost[]; fromRun: SeenHost[]; taintedOnly: SeenHost[] } {
  const seen = (f.watch?.seen ?? []).filter((s) => !f.approved.some((a) => a.host === s.host));
  const order = (a: SeenHost, b: SeenHost): number => b.count - a.count || a.host.localeCompare(b.host);
  const clean = seen.filter((s) => !s.tainted);
  return {
    proposed: clean.filter((s) => s.via === "hook" && !s.sent).sort(order),
    sentTo: clean.filter((s) => s.via === "hook" && s.sent).sort(order),
    fromRun: clean.filter((s) => s.via === "run").sort(order),
    taintedOnly: seen.filter((s) => s.tainted).sort(order),
  };
}

/** Doctor: project lists that cannot be read, or that are full (new approvals are no longer kept). */
export function knownHostsChecks(l: Layout): Check[] {
  let names: string[];
  try {
    names = readdirSync(knownHostsDir(l)).filter((n) => /^[0-9a-f]{32}\.json$/.test(n));
  } catch {
    return [];
  }
  const damaged: string[] = [];
  const full: string[] = [];
  for (const n of names) {
    const text = tryReadText(join(knownHostsDir(l), n));
    let project = "";
    try {
      project = typeof text === "string" ? String((JSON.parse(text) as { project?: unknown }).project ?? "") : "";
    } catch {
      project = "";
    }
    const f = typeof text === "string" && project !== "" && knownHostsFile(l, project).endsWith(n) ? parse(text, project) : null;
    if (f === null) damaged.push(n);
    else if (f.approved.length >= MAX_APPROVED) full.push(f.project);
  }
  const out: Check[] = [];
  if (damaged.length > 0) out.push({ name: "known hosts", status: "warn", detail: `${damaged.length} known-hosts file${damaged.length === 1 ? "" : "s"} in ${knownHostsDir(l)} cannot be read (${damaged.slice(0, 3).join(", ")}): no host counts as approved in that project, so every new host asks. Run "launchsafe-firewall hosts reset --project DIR" in your own terminal for the project` });
  if (full.length > 0) out.push({ name: "known hosts", status: "warn", detail: `the known-hosts list of ${full.slice(0, 3).join(", ")} holds ${MAX_APPROVED} hosts, the most it keeps: new approvals are not remembered. Remove hosts you no longer need (launchsafe-firewall hosts remove)` });
  return out;
}
