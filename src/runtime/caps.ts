/**
 * Spending limits at run time (src/engine/caps.ts is the pure part). The session's counters live in its
 * counters file (src/runtime/counters.ts); the day's, for every session of this firewall home, in
 * caps/day.json, which starts from zero at local midnight. Both are in the data directory, which the
 * agent cannot write (FW-TAMPER), so they survive a restart and the agent cannot reset them.
 *
 * A person raises a cap only with `launchsafe-firewall caps raise` in their own terminal, signed with
 * the approval key: a session raise is a signed `budget_raise` event in that session's log (key
 * "cap:session:<metric>"), a day raise a signed line in caps/raises.jsonl for that day. Both are also
 * written to the decision log. A line that does not verify against the approval key raises nothing.
 */

import { randomBytes } from "node:crypto";
import { appendFileSync, existsSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { addFailure, applyCapRecord, CAP_METRICS, capPolicy, currentDaily, emptyCapCounts, emptyDaily, localDay, warningShown, type CapMetric, type CapScope, type CapView, type DailyCounters } from "../engine/caps.js";
import type { Decision, FirewallConfig, SessionState } from "../types.js";
import { verifyStateChange } from "./approver.js";
import { isCapCounts, readCounters, recordSessionFailure, resetSessionCounters } from "./counters.js";
import type { Check } from "./doctor.js";
import { ensureDir, tryReadText, withLock } from "./fsutil.js";
import type { Layout } from "./layout.js";
import { appendLog } from "./log.js";
import { appendEvents } from "./store.js";
import { own } from "../own.js";

export const capsDir = (l: Layout): string => join(l.home, "caps");
export const dayFile = (l: Layout): string => join(capsDir(l), "day.json");
export const raisesFile = (l: Layout): string => join(capsDir(l), "raises.jsonl");

function parseDaily(text: string): DailyCounters | null {
  try {
    const o = JSON.parse(text) as Record<string, unknown>;
    if (o.version !== 1 || typeof o.day !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(o.day) || !isCapCounts(o)) return null;
    if (o.resetAt !== undefined && typeof o.resetAt !== "string") return null;
    return o as unknown as DailyCounters;
  } catch {
    return null;
  }
}

/**
 * Today's counters. A missing file, or one for an earlier day, is a fresh day; a later day (the clock went
 * back) is kept, so a day never goes backwards. An unreadable file (bad JSON, a directory, a symlink
 * loop) is `corrupt`: it is never overwritten, and every call is denied until a person runs
 * `caps reset --today` (fail closed: its counts are unknown).
 */
export function readDaily(l: Layout, now: Date): { daily: DailyCounters; corrupt: boolean } {
  const text = tryReadText(dayFile(l));
  // CLI audit M2: once the day's counters were written, a missing file is a removed one, not a fresh day.
  if (text === null) return { daily: emptyDaily(now), corrupt: existsSync(startedMarker(l)) };
  const d = typeof text === "string" ? parseDaily(text) : null;
  if (d === null) return { daily: emptyDaily(now), corrupt: true };
  return { daily: currentDaily(d, now), corrupt: false };
}

function replaceFile(path: string, data: string): void {
  ensureDir(dirname(path));
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    writeFileSync(tmp, data, { mode: 0o600, flag: "wx" });
    renameSync(tmp, path);
  } catch (e) {
    rmSync(tmp, { force: true });
    throw e;
  }
}

/** Read-modify-write under the day file's lock. Throws when the file cannot be read: it is left as it is. */
function updateDaily(l: Layout, now: Date, fn: (d: DailyCounters) => void): void {
  ensureDir(capsDir(l));
  withLock(`${dayFile(l)}.lock`, () => {
    const { daily, corrupt } = readDaily(l, now);
    if (corrupt) throw new Error(`today's spending-limit counters (${dayFile(l)}) cannot be read; run launchsafe-firewall caps reset --today`);
    fn(daily);
    replaceFile(dayFile(l), JSON.stringify(daily));
    if (!existsSync(startedMarker(l))) writeFileSync(startedMarker(l), `${now.toISOString()}\n`, { mode: 0o600 });
  });
}

/** M2: written with the first day counters; from then on a missing day file is damage (caps reset --today). */
export const startedMarker = (l: Layout): string => join(capsDir(l), "started");

/**
 * Adds a decision's cap usage (and the warning it showed) to today's counters. Throws when it cannot: the
 * caller then does not let the action go ahead uncounted.
 */
export function recordDaily(l: Layout, d: Decision, now: Date): void {
  const r = d.caps;
  if (r === undefined || (r.always.length === 0 && r.ifRuns.length === 0 && r.warned.length === 0)) return;
  updateDaily(l, now, (daily) => applyCapRecord(daily, r, d.verdict === "allow" || d.verdict === "ask", warningShown(d.rules), "day"));
}

/** A tool result that said it failed: one more identical failure, in the session and today. */
export function recordFailure(l: Layout, sessionId: string, actionHash: string, fingerprints: readonly string[], now: Date): void {
  recordSessionFailure(l, sessionId, actionHash, fingerprints);
  updateDaily(l, now, (daily) => addFailure(daily, actionHash, fingerprints));
}

/** What a day raise is signed over: the day and this firewall home, so a line copied from another home or day raises nothing. */
export function dayRaiseSubject(l: Layout, day: string): string {
  return `day:${day}:${l.home}`;
}

/** The signed day raises for `day`, by metric. Lines that do not verify against `approverKey` count for nothing. */
export function dayRaises(l: Layout, approverKey: string | null, day: string): Map<CapMetric, number> {
  const out = new Map<CapMetric, number>();
  const seen = new Set<string>();
  if (approverKey === null) return out;
  const text = tryReadText(raisesFile(l));
  if (typeof text !== "string") return out;
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    try {
      const o = JSON.parse(line) as { day?: unknown; metric?: unknown; amount?: unknown; id?: unknown; sig?: unknown };
      if (o.day !== day || typeof o.metric !== "string" || !(CAP_METRICS as readonly string[]).includes(o.metric) || typeof o.amount !== "number" || !Number.isFinite(o.amount) || o.amount <= 0 || typeof o.id !== "string" || typeof o.sig !== "string") continue;
      const metric = o.metric as CapMetric;
      // A line counts once, however often it is in the file (a replayed copy raises nothing more).
      if (seen.has(`${metric}\u0000${o.id}`)) continue;
      if (!verifyStateChange(approverKey, "budget-raise", dayRaiseSubject(l, day), [`cap:day:${metric}`, String(o.amount), o.id], o.sig)) continue;
      seen.add(`${metric}\u0000${o.id}`);
      out.set(metric, (out.get(metric) ?? 0) + o.amount);
    } catch {
      // A line that is not JSON raises nothing.
    }
  }
  return out;
}

/** The session's raises of one cap: its signed budget_raise events (verified when the session was loaded). */
export function sessionRaise(state: Pick<SessionState, "budgetRaises">, metric: CapMetric): number {
  const seen = new Set<string>();
  let n = 0;
  for (const r of state.budgetRaises) {
    // An event counts once by its id (a replayed line raises nothing more).
    if (r.key !== `cap:session:${metric}` || seen.has(r.id)) continue;
    seen.add(r.id);
    n += r.amount;
  }
  return n;
}

/** The engine's view of the caps for one session at `now` (read before deciding). */
export function loadCapView(l: Layout, sessionId: string, state: Pick<SessionState, "budgetRaises">, now: Date, approverKey: string | null): CapView {
  const { counters, corrupt } = readCounters(l, sessionId);
  const day = readDaily(l, now);
  const raises = dayRaises(l, approverKey, day.daily.day);
  const damaged = { session: corrupt || counters.capsDamagedAt !== undefined, day: day.corrupt };
  return {
    sessionId,
    session: counters.caps ?? emptyCapCounts(),
    day: day.daily,
    raise: (scope, metric) => (scope === "session" ? sessionRaise(state, metric) : (raises.get(metric) ?? 0)),
    ...(damaged.session || damaged.day ? { damaged } : {}),
  };
}

export interface CapRaise {
  scope: CapScope;
  metric: CapMetric;
  /** In the metric's unit (US dollars for costUsd). */
  amount: number;
  /** The session, for a session raise. */
  session?: string;
}

/**
 * A person raises a cap (`caps raise`). `sign` holds the unlocked approver key and signs
 * (session or "day:<day>", "budget-raise", "cap:<scope>:<metric>", amount, id). Returns the raise's id.
 */
export function raiseCap(l: Layout, r: CapRaise, sign: (subject: string, fields: readonly string[]) => string, now: Date = new Date()): string {
  if (!(CAP_METRICS as readonly string[]).includes(r.metric)) throw new Error(`not a cap: ${r.metric} (one of ${CAP_METRICS.join(", ")})`);
  if (!Number.isFinite(r.amount) || r.amount <= 0 || r.amount > 1e12 || (r.metric !== "costUsd" && !Number.isInteger(r.amount))) throw new Error(`the amount must be a ${r.metric === "costUsd" ? "positive number of US dollars" : "positive whole number"}`);
  const id = `c${randomBytes(5).toString("hex")}`;
  const key = `cap:${r.scope}:${r.metric}`;
  if (r.scope === "session") {
    if (r.session === undefined || r.session === "") throw new Error("a session raise names the session");
    const sig = sign(r.session, [key, String(r.amount), id]);
    appendEvents(l, r.session, [{ type: "budget_raise", key, amount: r.amount, id, sig }]);
    appendLog(l, { type: "cap_raise", scope: "session", session: r.session, metric: r.metric, amount: r.amount, id, sig });
  } else {
    const day = localDay(now);
    const sig = sign(dayRaiseSubject(l, day), [key, String(r.amount), id]);
    ensureDir(capsDir(l));
    appendFileSync(raisesFile(l), `${JSON.stringify({ day, metric: r.metric, amount: r.amount, id, sig, at: now.toISOString() })}\n`, { mode: 0o600 });
    appendLog(l, { type: "cap_raise", scope: "day", day, metric: r.metric, amount: r.amount, id, sig });
  }
  return id;
}

/**
 * `caps reset`: a person starts counters that could not be read again (after checking what changed the data
 * directory). The day's: whatever is at caps/day.json is removed and a fresh day written. A session's: its
 * counters file likewise (src/runtime/counters.ts). Logged as `cap_reset`.
 */
export function resetCaps(l: Layout, r: { scope: CapScope; session?: string }, now: Date = new Date()): void {
  if (r.scope === "session") {
    if (r.session === undefined || r.session === "") throw new Error("a session reset names the session");
    resetSessionCounters(l, r.session, now);
    appendLog(l, { type: "cap_reset", scope: "session", session: r.session });
    return;
  }
  ensureDir(capsDir(l));
  withLock(`${dayFile(l)}.lock`, () => {
    rmSync(dayFile(l), { recursive: true, force: true });
    replaceFile(dayFile(l), JSON.stringify({ ...emptyDaily(now), resetAt: now.toISOString() }));
  });
  appendLog(l, { type: "cap_reset", scope: "day", day: localDay(now) });
}

const UNIT: Record<CapMetric, string> = { toolCalls: "tool calls", bytesOut: "bytes sent", identicalFailures: "identical failures of one action", tokens: "model tokens", costUsd: "US dollars of reported model cost" };

function used(metric: CapMetric, c: { totals: Record<string, number>; fails: Record<string, number> }): number {
  if (metric === "identicalFailures") return Object.values(c.fails).reduce((m, v) => Math.max(m, v), 0);
  const v = own(c.totals, { toolCalls: "calls", bytesOut: "bytes", tokens: "tokens", costUsd: "cost" }[metric]) ?? 0;
  return metric === "costUsd" ? v / 1e6 : v;
}

/** `caps`: the limits, what is used, and the raises, for today and (when given) one session. */
export function capStatus(l: Layout, cfg: Pick<FirewallConfig, "caps">, session: { id: string; state: Pick<SessionState, "budgetRaises"> } | null, approverKey: string | null, now: Date = new Date()): { text: string; json: Record<string, unknown> } {
  const pol = capPolicy(cfg);
  const { daily } = readDaily(l, now);
  const raises = dayRaises(l, approverKey, daily.day);
  const sc = session !== null ? (readCounters(l, session.id).counters.caps ?? emptyCapCounts()) : null;
  const rows = (scope: CapScope): Record<string, { limit: number | null; raised: number; used: number }> => {
    const out: Record<string, { limit: number | null; raised: number; used: number }> = {};
    for (const m of CAP_METRICS) {
      const raised = scope === "day" ? (raises.get(m) ?? 0) : session !== null ? sessionRaise(session.state, m) : 0;
      out[m] = { limit: pol[scope][m], raised, used: used(m, scope === "day" ? daily : (sc ?? emptyCapCounts())) };
    }
    return out;
  };
  const day = rows("day");
  const ses = session !== null ? rows("session") : null;
  const L = [`Spending limits (caps.enabled: ${pol.enabled}; warning at ${pol.warnPercent}%, ${pol.warn === "ask" ? "asks you" : "noted in the decision"})`];
  const dayBroken = readDaily(l, now).corrupt;
  const sessionBroken = session !== null && (readCounters(l, session.id).corrupt || readCounters(l, session.id).counters.capsDamagedAt !== undefined);
  if (dayBroken) L.push("Today's counters cannot be read: every call is denied until you run: launchsafe-firewall caps reset --today");
  if (sessionBroken && session !== null) L.push(`Session ${session.id}'s counters could not be read: its calls are denied until you run: launchsafe-firewall caps reset --session ${session.id}`);
  const line = (m: string, r: { limit: number | null; raised: number; used: number }): string => `  ${m.padEnd(18)} ${r.limit === null ? "no limit" : `${r.used} of ${r.limit + r.raised}${r.raised > 0 ? ` (raised by ${r.raised})` : ""}`}  ${UNIT[m as CapMetric]}`;
  L.push(`Today (${daily.day}, all sessions; resets at local midnight):`);
  for (const [m, r] of Object.entries(day)) L.push(line(m, r));
  if (ses !== null && session !== null) {
    L.push(`Session ${session.id}:`);
    for (const [m, r] of Object.entries(ses)) L.push(line(m, r));
  }
  L.push("Raise one in your own terminal: launchsafe-firewall caps raise <metric> <amount> --session <id> | --today");
  return { text: L.join("\n"), json: { enabled: pol.enabled, warnPercent: pol.warnPercent, warn: pol.warn, day: { date: daily.day, caps: day }, ...(ses !== null && session !== null ? { session: { id: session.id, caps: ses } } : {}) } };
}

/**
 * A decision stopped at a cap (FW-CAP). It is in the decision's log entry already; this adds a
 * `cap_stop` entry naming the caps.
 *
 * Suspension hook: this is the one place a cap stop is reported at run time (the hook pipeline and the
 * local API both reach it through their stores). Caps only deny the action, so the agent's next call
 * meets the same cap. The kill switch (src/runtime/stops.ts) is deliberately not called from here, and
 * the behaviour monitor does not count cap denials (monitorCountedVerdict in src/engine/caps.ts).
 *
 * TODO(caps+kill): suspending the session through the kill switch on a cap stop is not wired. It is not
 * clearly safe: a kill-switch stop needs the approval passphrase to end, so it would outlive a person's
 * `caps raise` and the day caps' midnight reset, and a day cap would leave every session that met it
 * stopped. Decide it with the owner of both features before wiring `stopTarget()` here.
 */
export function capStopped(l: Layout, sessionId: string, d: Decision): void {
  const stopped = d.caps?.stopped ?? [];
  if (stopped.length === 0 || d.verdict !== "deny") return;
  try {
    appendLog(l, { type: "cap_stop", session: sessionId, caps: stopped.map((s) => `${s.scope}:${s.metric}`), action: d.actionHash });
  } catch {
    // The decision's own entry already names FW-CAP; this one is a summary.
  }
}

/** Doctor: a day file that cannot be read, or was started again because it could not be. */
export function capChecks(l: Layout, now = new Date()): Check[] {
  const text = tryReadText(dayFile(l));
  if (text === null) return [];
  const d = typeof text === "string" ? parseDaily(text) : null;
  if (d === null) return [{ name: "spending limits", status: "warn", detail: `today's spending-limit counters (${dayFile(l)}) cannot be read, so every tool call is denied until you run launchsafe-firewall caps reset --today. Something other than the firewall may be writing ${capsDir(l)}` }];
  if (d.resetAt !== undefined && now.getTime() - Date.parse(d.resetAt) <= 7 * 86400000) return [{ name: "spending limits", status: "warn", detail: `today's spending-limit counters were started again at ${d.resetAt} (caps reset) after they could not be read` }];
  return [];
}
