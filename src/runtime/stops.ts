/**
 * The kill switch's records: one append-only file per stopped session or
 * agent (stops/session-<name>.jsonl, stops/agent-<name>.jsonl) in the
 * firewall's data directory, which the agent may never write (FW-TAMPER).
 *
 * A stop is a tightening, so any stop record counts, whoever wrote it: the
 * person's `session stop` / `agent stop`, or the hook when the behaviour
 * monitor fires. A monitor stop is also kept in the counters file
 * (sessions/<id>.counters.json, written under the session lock), so it holds
 * when its stop record cannot be written. A resume is a loosening: it counts
 * only when it names the stop it ends and is signed with the approval key over
 * its target, scope, stop, id and time, so neither an agent nor a repository
 * file can produce one, an old resume never ends a newer stop, and a resume's
 * time (which restarts the monitor's count) cannot be moved. Anything
 * unreadable keeps the target stopped (fail closed); a person's signed resume
 * then moves the damaged file aside. A deleted record is reported by doctor,
 * which compares the signed decision log with the records.
 */

import { createHash, randomBytes } from "node:crypto";
import { readdirSync, renameSync } from "node:fs";
import { join } from "node:path";
import type { MonitorSentinel, MonitorSignal } from "../engine/budgets.js";
import { MONITOR_SIGNALS } from "../engine/budgets.js";
import type { StopState, StopView } from "../engine/stop.js";
import { verifyStateChange } from "./approver.js";
import { readCounters } from "./counters.js";
import type { Check } from "./doctor.js";
import { appendDurable, tryReadText, withLock } from "./fsutil.js";
import type { Layout } from "./layout.js";
import { tailLog } from "./log.js";

export type StopScope = "session" | "agent";

interface StopLine {
  type: "stop";
  id: string;
  at: string;
  scope: StopScope;
  target: string;
  by: "person" | "monitor";
  reason: string;
  signal?: MonitorSignal;
}

interface ResumeLine {
  type: "resume";
  id: string;
  at: string;
  stopId: string;
  sig: string;
}

/** The hook agents whose state session ids carry their name (src/hook/pipeline.ts stateSessionId). */
const PREFIXED = /^(codex|gemini|cursor|gateway):/;

/**
 * The agent a state session id belongs to, when the id says: a local API session is `<agentId>/<session>`, a
 * Codex, Gemini CLI, Cursor or gateway session `<agent>:<id>`. A Claude Code session id carries no name (the
 * hook passes "claude" itself); a library session the host named is the host's own.
 */
export function agentOfSession(sessionId: string): string | null {
  const slash = sessionId.indexOf("/");
  if (slash > 0) return sessionId.slice(0, slash);
  const m = PREFIXED.exec(sessionId);
  return m === null ? null : (m[1] as string);
}

/** The counters a scope's monitor stops are kept in: the session's own, or the agent's (`agent:<id>`, library and local API). */
export function countersKey(scope: StopScope, target: string): string {
  return scope === "session" ? target : `agent:${target}`;
}

/**
 * A file name for a target. A plain id is used as it is; any other is hashed behind "~", which a plain id cannot
 * contain, so no session can be named so that it shares another's file.
 */
function stopName(target: string): string {
  return /^[A-Za-z0-9_-]{1,100}$/.test(target) ? target : `~${createHash("sha256").update(target).digest("hex").slice(0, 40)}`;
}

export function stopFile(l: Layout, scope: StopScope, target: string): string {
  return join(l.stops, `${scope}-${stopName(target)}.jsonl`);
}

const str = (v: unknown): v is string => typeof v === "string";

function parseLine(o: unknown): StopLine | ResumeLine | null {
  if (typeof o !== "object" || o === null || Array.isArray(o)) return null;
  const r = o as Record<string, unknown>;
  if (r.type === "stop" && str(r.id) && str(r.at) && (r.scope === "session" || r.scope === "agent") && str(r.target) && (r.by === "person" || r.by === "monitor") && str(r.reason)) {
    if (r.signal !== undefined && !(MONITOR_SIGNALS as readonly unknown[]).includes(r.signal)) return null;
    return { type: "stop", id: r.id, at: r.at, scope: r.scope, target: r.target, by: r.by, reason: r.reason, ...(r.signal !== undefined ? { signal: r.signal as MonitorSignal } : {}) };
  }
  if (r.type === "resume" && str(r.id) && str(r.at) && str(r.stopId) && str(r.sig)) return { type: "resume", id: r.id, at: r.at, stopId: r.stopId, sig: r.sig };
  return null;
}

/** What a resume's signature covers (with the target): its scope, the stop it ends, its own id and its time. */
export function resumeFields(scope: StopScope, stopId: string, resumeId: string, at: string): string[] {
  return [scope, stopId, resumeId, at];
}

export interface StopRecord {
  /** Every stop in force, oldest first (an unreadable file is one stop by "unreadable"). */
  active: StopState[];
  /** Of those, the ones in the record itself (not only in the counters' sentinels). */
  recorded: StopState[];
  /** The last valid resume (ms, never later than `now`), if any. */
  resumedAt?: number;
  /** The stop ids a valid resume ended. */
  resumed: Set<string>;
  /** Resumes that were ignored (not signed by the approval key): a sign that something other than the person wrote the file. */
  ignored: number;
  /** The file could not be read or parsed. */
  damaged: boolean;
}

function sentinelState(s: MonitorSentinel): StopState {
  return { id: s.id, at: s.at, by: "monitor", scope: s.scope, target: s.target, reason: s.reason, signal: s.signal };
}

/** The monitor stops kept in the target's counters (the sentinel), whatever the stop file says. */
function sentinels(l: Layout, scope: StopScope, target: string): MonitorSentinel[] {
  try {
    return (readCounters(l, countersKey(scope, target)).counters.stops ?? []).filter((s) => s.scope === scope && s.target === target);
  } catch {
    return [];
  }
}

/**
 * Reads one target's record, with the monitor stops kept in its counters. Never throws: damage is a stop. A
 * resume's time later than `now` counts as `now` (it restarts the monitor's count, so it never lies ahead).
 */
export function readStops(l: Layout, scope: StopScope, target: string, approverKey: string | null, now: Date = new Date()): StopRecord {
  const text = tryReadText(stopFile(l, scope, target));
  const extra = sentinels(l, scope, target);
  const damaged = (why: string): StopRecord => {
    const bad: StopState = { id: "unreadable", at: "", by: "unreadable", scope, target, reason: why };
    return { active: [bad, ...extra.map(sentinelState)], recorded: [bad], resumed: new Set(), ignored: 0, damaged: true };
  };
  if (text !== null && typeof text !== "string") return damaged(`the stop record cannot be read: ${text.unreadable}`);
  const stops: StopLine[] = [];
  const resumed = new Set<string>();
  let resumedAt: number | undefined;
  let ignored = 0;
  const lines = (text ?? "").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] as string;
    if (raw.trim() === "") continue;
    let line: StopLine | ResumeLine | null;
    try {
      line = parseLine(JSON.parse(raw));
    } catch {
      line = null;
    }
    if (line === null) return damaged(`line ${i + 1} of the stop record is not a valid entry`);
    if (line.type === "stop") {
      // A record filed under another target is damage too: it could not be resumed by the name it shows.
      if (line.scope !== scope || line.target !== target) return damaged(`line ${i + 1} of the stop record names another ${line.scope} (${line.target})`);
      stops.push(line);
      continue;
    }
    const t = Date.parse(line.at);
    if (approverKey !== null && Number.isFinite(t) && verifyStateChange(approverKey, "resume", target, resumeFields(scope, line.stopId, line.id, line.at), line.sig)) {
      resumed.add(line.stopId);
      const at = Math.min(t, now.getTime());
      resumedAt = Math.max(resumedAt ?? at, at);
    } else ignored++;
  }
  const fromFile = stops.map((s): StopState => ({ id: s.id, at: s.at, by: s.by, scope: s.scope, target: s.target, reason: s.reason, ...(s.signal !== undefined ? { signal: s.signal } : {}) }));
  const known = new Set(fromFile.map((s) => s.id));
  const active = [...fromFile, ...extra.filter((s) => !known.has(s.id)).map(sentinelState)].filter((s) => !resumed.has(s.id));
  return { active, recorded: fromFile.filter((x) => !resumed.has(x.id)), ...(resumedAt !== undefined ? { resumedAt } : {}), resumed, ignored, damaged: false };
}

/** What decide() is told for a session: its own stop first, then its agent's; the later of the two resumes. */
export function stopView(l: Layout, sessionId: string, agentId: string | null, approverKey: string | null, now: Date = new Date()): StopView {
  const own = readStops(l, "session", sessionId, approverKey, now);
  const agent = agentId !== null && agentId !== "" ? readStops(l, "agent", agentId, approverKey, now) : null;
  const active = own.active[0] ?? agent?.active[0] ?? null;
  const times = [own.resumedAt, agent?.resumedAt].filter((t): t is number => t !== undefined);
  return { active, ...(times.length > 0 ? { resumedAt: Math.max(...times) } : {}) };
}

function newId(): string {
  return randomBytes(9).toString("base64url");
}

/**
 * Stops a session or an agent. Idempotent: when a stop is already in force (or the record is damaged, which
 * stops it too) nothing is written and that stop is returned with `created: false`. A monitor stop passes the
 * id its counters sentinel already carries.
 */
export function stopTarget(l: Layout, scope: StopScope, target: string, o: { by: "person" | "monitor"; reason: string; signal?: MonitorSignal; now?: Date; approverKey: string | null; id?: string }): { stop: StopState; created: boolean } {
  if (target === "") throw new Error(`no ${scope} named`);
  const file = stopFile(l, scope, target);
  return withLock(`${file}.lock`, () => {
    const cur = readStops(l, scope, target, o.approverKey, o.now);
    // Already recorded: nothing to add. A stop only in the counters' sentinel is written to the record now.
    const inFile = cur.recorded[0];
    if (inFile !== undefined) return { stop: inFile, created: false };
    const line: StopLine = { type: "stop", id: o.id ?? newId(), at: (o.now ?? new Date()).toISOString(), scope, target, by: o.by, reason: o.reason.slice(0, 500), ...(o.signal !== undefined ? { signal: o.signal } : {}) };
    appendDurable(file, `${JSON.stringify(line)}\n`);
    const { type: _t, ...stop } = line;
    return { stop, created: true };
  });
}

/**
 * A person resumes a session or an agent: every stop in force (the record's and the counters' sentinels) gets a
 * resume signed with the approval key (`sign` holds the unlocked key). A damaged record is moved aside (the
 * person decided with the passphrase). Returns the stops it ended (empty: nothing was stopped).
 */
export function resumeTarget(l: Layout, scope: StopScope, target: string, o: { sign: (fields: readonly string[]) => string; approverKey: string | null; now?: Date }): { ended: StopState[]; movedAside: string | null } {
  const file = stopFile(l, scope, target);
  return withLock(`${file}.lock`, () => {
    const now = o.now ?? new Date();
    const cur = readStops(l, scope, target, o.approverKey, now);
    let movedAside: string | null = null;
    let active = cur.active;
    if (cur.damaged) {
      movedAside = `${file}.damaged-${now.toISOString().replace(/[:.]/g, "-")}`;
      renameSync(file, movedAside);
      active = cur.active.filter((s) => s.by !== "unreadable");
    }
    if (active.length === 0) return { ended: cur.active, movedAside };
    const at = now.toISOString();
    const lines = active.map((s) => {
      const id = newId();
      const r: ResumeLine = { type: "resume", id, at, stopId: s.id, sig: o.sign(resumeFields(scope, s.id, id, at)) };
      return JSON.stringify(r);
    });
    appendDurable(file, `${lines.join("\n")}\n`);
    return { ended: cur.active, movedAside };
  });
}

export interface StopListing {
  stops: StopState[];
  /** Records holding resumes that were ignored (not signed by the approval key). */
  ignored: { scope: StopScope; target: string; count: number }[];
}

/** Every stop in force (records and counters sentinels), for `session list` and doctor. Unreadable files are listed by name. */
export function listStops(l: Layout, approverKey: string | null, now: Date = new Date()): StopListing {
  const stops: StopState[] = [];
  const ignored: StopListing["ignored"] = [];
  const seen = new Set<string>();
  const add = (scope: StopScope, target: string): void => {
    const k = `${scope}\n${target}`;
    if (seen.has(k)) return;
    seen.add(k);
    const r = readStops(l, scope, target, approverKey, now);
    stops.push(...r.active);
    if (r.ignored > 0) ignored.push({ scope, target, count: r.ignored });
  };
  let names: string[] = [];
  try {
    names = readdirSync(l.stops).filter((n) => n.endsWith(".jsonl")).sort();
  } catch {
    // No records yet.
  }
  for (const n of names) {
    const m = /^(session|agent)-(.+)\.jsonl$/.exec(n);
    if (m === null) continue;
    const scope = m[1] as StopScope;
    const text = tryReadText(join(l.stops, n));
    // The real target is in the lines (the file name may be a hash of it).
    let target: string | null = null;
    if (typeof text === "string") {
      for (const raw of text.split("\n")) {
        try {
          const line = parseLine(JSON.parse(raw));
          if (line?.type === "stop") {
            target = line.target;
            break;
          }
        } catch {
          // Damage is reported by readStops below.
        }
      }
    }
    if (target === null || stopFile(l, scope, target) !== join(l.stops, n)) {
      stops.push({ id: "unreadable", at: "", by: "unreadable", scope, target: target ?? (m[2] as string), reason: target === null ? `the stop record ${n} cannot be read` : `the stop record ${n} names another ${scope}` });
      continue;
    }
    add(scope, target);
  }
  // Monitor stops whose record could not be written are still in force: their counters say so.
  let counters: string[] = [];
  try {
    counters = readdirSync(l.sessions).filter((n) => n.endsWith(".counters.json"));
  } catch {
    // No sessions yet.
  }
  for (const n of counters) {
    const t = tryReadText(join(l.sessions, n));
    if (typeof t !== "string") continue;
    try {
      for (const s of (JSON.parse(t) as { stops?: MonitorSentinel[] }).stops ?? []) if ((s.scope === "session" || s.scope === "agent") && typeof s.target === "string") add(s.scope, s.target);
    } catch {
      // A damaged counters file is doctor's to report.
    }
  }
  return { stops, ignored };
}

/**
 * Doctor: damaged records, resumes that were ignored, and stops the signed decision log records that are no
 * longer in force although no resume was logged (a record deleted or moved: the target is no longer stopped).
 */
export function stopChecks(l: Layout, approverKey: string | null, now: Date = new Date()): Check[] {
  const checks: Check[] = [];
  const { stops, ignored } = listStops(l, approverKey, now);
  const damaged = stops.filter((s) => s.by === "unreadable");
  if (damaged.length > 0) checks.push({ name: "stop records", status: "warn", detail: `${damaged.length} stop record(s) cannot be read (${damaged.slice(0, 3).map((s) => `${s.scope} ${s.target}`).join(", ")}); they stay stopped until you resume them (launchsafe-firewall session list)` });
  if (ignored.length > 0) checks.push({ name: "stop records", status: "warn", detail: `resumes not signed by your approval key were ignored for ${ignored.slice(0, 3).map((x) => `${x.scope} ${x.target} (${x.count})`).join(", ")}: something other than you wrote ${l.stops}` });
  let entries: { event: Record<string, unknown> }[] = [];
  try {
    entries = tailLog(l, 20000) as unknown as { event: Record<string, unknown> }[];
  } catch {
    return checks;
  }
  const last = new Map<string, { type: string; id: string; scope: StopScope; target: string }>();
  for (const e of entries) {
    const ev = e.event;
    if ((ev.type !== "stop" && ev.type !== "resume") || (ev.scope !== "session" && ev.scope !== "agent") || typeof ev.target !== "string") continue;
    last.set(`${ev.scope}\n${ev.target}`, { type: ev.type, id: typeof ev.id === "string" ? ev.id : "", scope: ev.scope, target: ev.target });
  }
  const missing = [...last.values()].filter((x) => x.type === "stop" && readStops(l, x.scope, x.target, approverKey, now).active.length === 0);
  if (missing.length > 0) checks.push({ name: "stop records", status: "fail", detail: `the decision log records a stop of ${missing.slice(0, 3).map((x) => `${x.scope} ${x.target}`).join(", ")} with no resume, but the stop is no longer in force: its record was deleted or moved, so it is not stopped. Stop it again (launchsafe-firewall session stop / agent stop) and find out what changed ${l.stops}` });
  return checks;
}
