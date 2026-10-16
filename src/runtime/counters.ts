/**
 * The budget counters of a session, in a sidecar next to its event
 * log (sessions/<id>.counters.json) so that loadState() never replays
 * thousands of lines. Read before deciding (a view for the engine), updated
 * under the session lock after the decision.
 *
 * A person's approval raises the exceeded budget by the same amount again:
 * an "ask" the person answered with yes (Claude Code then runs the tool and
 * its PostToolUse arrives: confirmBudget), or a queued action approved with
 * the passphrase (the signed approval is used: FW-APPROVED). Signed
 * budget_raise events in the session log count as allowance too.
 *
 * Fail closed: an unreadable counters file makes the next egress in an
 * untrusted session ask once (at the limit), then the counters start again
 * and doctor reports the reset. The file is inside the data directory, so the
 * agent cannot write it (FW-TAMPER).
 */

import { randomBytes } from "node:crypto";
import { readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { MONITOR_SIGNALS, type BudgetUse, type BudgetView, type MonitorSentinel } from "../engine/budgets.js";
import { applyDecision, budgetView, confirmPending, emptyCounters, MAX_SENTINELS, type Counters } from "../engine/counters.js";
import { addFailure, emptyCapCounts, type CapCounts } from "../engine/caps.js";
import type { Decision, SessionState } from "../types.js";
import type { Check } from "./doctor.js";
import { ensureDir, tryReadText, withLock } from "./fsutil.js";
import { safeId, type Layout } from "./layout.js";
import { sessionFile } from "./store.js";

// The pure counter logic lives in the engine (the library, src/sdk/, keeps counters in memory too).
export { applyDecision, budgetView, emptyCounters, type Counters } from "../engine/counters.js";

export function countersFile(l: Layout, sessionId: string): string {
  return join(l.sessions, `${safeId(sessionId)}.counters.json`);
}

const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v) && v >= 0;
const isRecordOf = (v: unknown, ok: (x: unknown) => boolean): boolean => typeof v === "object" && v !== null && !Array.isArray(v) && Object.values(v).every(ok);
const isUse = (u: unknown): boolean => typeof u === "object" && u !== null && typeof (u as BudgetUse).key === "string" && isNum((u as BudgetUse).amount);

const isSentinel = (x: unknown): boolean => {
  if (typeof x !== "object" || x === null) return false;
  const o = x as Record<string, unknown>;
  return typeof o.id === "string" && typeof o.at === "string" && (o.scope === "session" || o.scope === "agent") && typeof o.target === "string" && typeof o.signal === "string" && (MONITOR_SIGNALS as readonly unknown[]).includes(o.signal) && typeof o.reason === "string";
};
/** A spending-limit counters object (a session's, or the day file's): strict, like the rest. */
export function isCapCounts(v: unknown): v is CapCounts {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const o = v as Record<string, unknown>;
  return isRecordOf(o.totals, isNum) && isRecordOf(o.fails, isNum) && Array.isArray(o.warned) && o.warned.every((w) => typeof w === "string");
}

/** Strict shape check: anything unexpected is a corrupt file. */
function parseCounters(text: string): Counters | null {
  try {
    const o = JSON.parse(text) as Record<string, unknown>;
    if (o.version !== 1) return null;
    if (!isRecordOf(o.minute, (v) => Array.isArray(v) && v.every((p) => Array.isArray(p) && p.length === 2 && isNum(p[0]) && isNum(p[1])))) return null;
    if (!isRecordOf(o.session, isNum) || !isRecordOf(o.raised, isNum)) return null;
    if (!Array.isArray(o.last) || !o.last.every((x) => typeof x === "object" && x !== null && typeof x.hash === "string" && isNum(x.count) && typeof x.firstAt === "string")) return null;
    if (!Array.isArray(o.pending) || !o.pending.every((x) => typeof x === "object" && x !== null && typeof x.hash === "string" && typeof x.at === "string" && Array.isArray(x.raises) && x.raises.every(isUse))) return null;
    if (o.resetAt !== undefined && typeof o.resetAt !== "string") return null;
    if (o.floor !== undefined && !isRecordOf(o.floor, isNum)) return null;
    if (o.ms !== undefined && !isRecordOf(o.ms, (v) => Array.isArray(v) && v.every((p) => Array.isArray(p) && p.length === 2 && isNum(p[0]) && isNum(p[1])))) return null;
    if (o.stops !== undefined && !(Array.isArray(o.stops) && o.stops.every(isSentinel))) return null;
    if (o.caps !== undefined && !isCapCounts(o.caps)) return null;
    if (o.capsDamagedAt !== undefined && typeof o.capsDamagedAt !== "string") return null;
    return o as unknown as Counters;
  } catch {
    return null;
  }
}

/**
 * The behaviour monitor's stop sentinels in a counters file that does not parse as a whole: each one that is
 * itself well formed is kept, so damage elsewhere in the file (or the counters starting again) never ends a stop.
 */
export function salvageSentinels(text: string): MonitorSentinel[] {
  try {
    const o = JSON.parse(text) as { stops?: unknown };
    return Array.isArray(o.stops) ? (o.stops.filter(isSentinel) as MonitorSentinel[]) : [];
  } catch {
    return [];
  }
}

/**
 * The session's counters; a missing file is a new session (zero), an unreadable one is `corrupt` (zero, but
 * with the monitor's stop sentinels that can still be read from it, which every rewrite then keeps).
 */
export function readCounters(l: Layout, sessionId: string): { counters: Counters; corrupt: boolean } {
  const text = tryReadText(countersFile(l, sessionId));
  if (text === null) return { counters: emptyCounters(), corrupt: false };
  // FZ7: a directory or a symlink loop where the file should be is an unreadable file: corrupt, never zero.
  if (typeof text !== "string") return { counters: emptyCounters(), corrupt: true };
  const c = parseCounters(text);
  if (c !== null) return { counters: c, corrupt: false };
  const stops = salvageSentinels(text);
  return { counters: stops.length > 0 ? { ...emptyCounters(), stops } : emptyCounters(), corrupt: true };
}

/** The view for a session (read before deciding). */
export function loadBudgetView(l: Layout, sessionId: string, state: Pick<SessionState, "budgetRaises">, now: Date): { view: BudgetView; corrupt: boolean } {
  const { counters, corrupt } = readCounters(l, sessionId);
  return { view: budgetView(counters, corrupt, state, now), corrupt };
}

const parentOf = (p: string): string => p.slice(0, p.lastIndexOf("/"));

/**
 * Replaces the file atomically (readers see the old or the new content), without fsync: a crash may
 * lose the last update, which only undercounts by one action, and the hook stays well under 1 ms.
 */
function replaceFile(path: string, data: string): void {
  ensureDir(parentOf(path));
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    writeFileSync(tmp, data, { mode: 0o600, flag: "wx" });
    renameSync(tmp, path);
  } catch (e) {
    rmSync(tmp, { force: true });
    throw e;
  }
}

/** Read-modify-write under the session's lock (the lock appendEvents takes), so concurrent hooks lose no update. */
function update(l: Layout, sessionId: string, fn: (c: Counters, wasCorrupt: boolean) => void): void {
  const file = countersFile(l, sessionId);
  withLock(`${sessionFile(l, sessionId)}.lock`, () => {
    const { counters, corrupt } = readCounters(l, sessionId);
    fn(counters, corrupt);
    replaceFile(file, JSON.stringify(counters));
  });
}

/** Whether a decision changes the counters at all (most reads do not: no lock, no write). */
function changes(l: Layout, sessionId: string, d: Decision, corrupt: boolean): boolean {
  if (d.caps !== undefined && (d.caps.always.length > 0 || d.caps.ifRuns.length > 0 || d.caps.warned.length > 0)) return true;
  const b = d.budget;
  if (b === undefined) return false;
  if (corrupt || d.verdict !== "allow" || b.usage.length > 0 || b.loopEligible || b.raises.length > 0) return true;
  // The behaviour monitor counts hosts tried and configuration changes, whatever the verdict.
  if (b.watch !== undefined && (b.watch.hosts.length > 0 || b.watch.config)) return true;
  // A write resets loop tracking: only worth a write when something is being tracked.
  return b.writes && readCounters(l, sessionId).counters.last.length > 0;
}

/**
 * Records what a decision adds to the counters: its usage when it goes ahead (allow or ask), loop
 * tracking, non-allowed verdicts, and the raise a person's approval brings. A corrupt file starts again.
 */
export function recordBudget(l: Layout, sessionId: string, d: Decision, now: Date, corrupt = false, o: { restated?: boolean } = {}): void {
  // F36: corrupt counters stay as they are until an action that sends data has faced them (asked once
  // when untrusted, or counted from zero when trusted); a read in between must not quietly reset them.
  if (corrupt && !(d.budget?.usage ?? []).some((u) => u.key.startsWith("bytes:"))) return;
  if (!changes(l, sessionId, d, corrupt)) return;
  update(l, sessionId, (c, wasCorrupt) => {
    if (wasCorrupt) {
      c.resetAt = now.toISOString();
      // The spending limits do not start again from zero with the budgets: they stay reached until a person resets them.
      c.capsDamagedAt = now.toISOString();
    }
    applyDecision(c, d, now, o);
  });
}

/** Keeps a monitor stop's sentinel in a counters file (an agent's, `agent:<id>`), so the stop holds when its record cannot be written. */
export function recordStopSentinel(l: Layout, key: string, sentinel: MonitorSentinel): void {
  update(l, key, (c) => {
    c.stops = [...(c.stops ?? []).filter((x) => x.id !== sentinel.id), sentinel].slice(-MAX_SENTINELS);
  });
}

/** A tool result that said it failed: one more identical failure of that action in this session. */
export function recordSessionFailure(l: Layout, sessionId: string, actionHash: string, fingerprints: readonly string[]): void {
  // F36: unreadable counters stay as they are until an action that sends data has faced them.
  if (readCounters(l, sessionId).corrupt) return;
  update(l, sessionId, (c) => {
    const caps = c.caps ?? emptyCapCounts();
    addFailure(caps, actionHash, fingerprints);
    c.caps = caps;
  });
}

/**
 * `caps reset --session`: a person starts a session's spending-limit counters again after they could not
 * be read. Whatever is at the counters path (an unreadable file, a directory, a symlink) is removed and
 * fresh counters are written; the budgets start again too.
 */
export function resetSessionCounters(l: Layout, sessionId: string, now: Date): void {
  const file = countersFile(l, sessionId);
  withLock(`${sessionFile(l, sessionId)}.lock`, () => {
    // The monitor's stop sentinels are not spending-limit counters: a reset keeps them (only a signed resume ends a stop).
    const stops = readCounters(l, sessionId).counters.stops ?? [];
    rmSync(file, { recursive: true, force: true });
    replaceFile(file, JSON.stringify({ ...emptyCounters(), resetAt: now.toISOString(), ...(stops.length > 0 ? { stops } : {}) }));
  });
}

/** PostToolUse: the asked action ran, so the person approved it; raise the budgets it exceeded. */
export function confirmBudget(l: Layout, sessionId: string, actionHash: string, now?: Date): void {
  if (tryReadText(countersFile(l, sessionId)) === null) return;
  const { counters } = readCounters(l, sessionId);
  if (!counters.pending.some((p) => p.hash === actionHash)) return;
  update(l, sessionId, (c) => {
    confirmPending(c, actionHash, now);
  });
}

/** Doctor: counters that are unreadable now, or were reset because they were, in the last week. */
export function counterChecks(l: Layout, now = Date.now()): Check[] {
  let names: string[];
  try {
    names = readdirSync(l.sessions).filter((n) => n.endsWith(".counters.json"));
  } catch {
    return [];
  }
  const bad: string[] = [];
  const reset: string[] = [];
  for (const n of names) {
    const p = join(l.sessions, n);
    try {
      if (now - statSync(p).mtimeMs > 7 * 86400000) continue;
    } catch {
      continue;
    }
    const id = n.replace(/\.counters\.json$/, "");
    const t = tryReadText(p);
    const c = parseCounters(typeof t === "string" ? t : "");
    if (c === null) bad.push(id);
    else if (c.resetAt !== undefined && now - Date.parse(c.resetAt) <= 7 * 86400000) reset.push(id);
  }
  if (bad.length === 0 && reset.length === 0) return [];
  const parts = [...(bad.length > 0 ? [`unreadable for session ${bad.slice(0, 3).join(", ")}`] : []), ...(reset.length > 0 ? [`reset after being unreadable for session ${reset.slice(0, 3).join(", ")}`] : [])];
  return [{ name: "budget counters", status: "warn", detail: `budget counters ${parts.join("; ")}: the next request in such a session asks once, then counting starts again. Something other than the firewall may be writing ${l.sessions}` }];
}
