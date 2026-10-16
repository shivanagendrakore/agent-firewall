/**
 * A session's budget counters and the engine's read-only view of
 * them. Pure: the hook keeps them in a sidecar file (src/runtime/counters.ts),
 * the library (src/sdk/) in its state store; both run the same functions.
 */

import type { BudgetUse, BudgetView, MonitorSentinel } from "./budgets.js";
import { applyCapRecord, emptyCapCounts, monitorCountedVerdict, warningShown, type CapCounts } from "./caps.js";
import type { Decision, SessionState } from "../types.js";
import { own, setOwn } from "../own.js";

export interface Counters {
  version: 1;
  /** key -> [minute, amount] pairs for the last 60 minutes (the 10- and 60-minute windows). */
  minute: Record<string, [number, number][]>;
  /** key -> total since the session started. */
  session: Record<string, number>;
  /** Recent loop-eligible action hashes (bounded): how often each ran in its 10-minute window with no write in between. */
  last: { hash: string; count: number; firstAt: string }[];
  /** key -> allowance a person granted by approving an action that exceeded it. */
  raised: Record<string, number>;
  /** Asked actions that exceeded a budget, waiting for their PostToolUse (the person said yes). */
  pending: { hash: string; raises: BudgetUse[]; at: string }[];
  /** When the counters were last reset because the file could not be read (doctor reports it). */
  resetAt?: string;
  /** F35: key -> the session total when a person last raised that budget (a yes gives the budget again from there). */
  floor?: Record<string, number>;
  /** The behaviour monitor's counts: key -> [ms, amount] for the last 10 minutes (to the millisecond, for a resume). */
  ms?: Record<string, [number, number][]>;
  /** Stops the monitor made, kept here too (a sentinel when the stop record cannot be written). */
  stops?: MonitorSentinel[];
  /** The session's spending-limit counters (src/engine/caps.ts); the day's are kept apart, for all sessions. */
  caps?: CapCounts;
  /**
   * When these counters were started again because they could not be read: the spending limits stay
   * "reached" for the session until a person runs `caps reset` (fail closed; the budgets ask once).
   */
  capsDamagedAt?: string;
}

const MAX_LAST = 50;
const MAX_PENDING = 20;
/** How long an asked, budget-exceeding action can still be confirmed by its PostToolUse. */
const PENDING_TTL_MS = 5 * 60 * 1000;
const WINDOW_MIN = 60;
const LOOP_WINDOW_MS = 10 * 60 * 1000;
/** The monitor's window, and how many entries one key keeps in it (more than any limit). */
const MONITOR_MS = 10 * 60 * 1000;
const MAX_MS_ENTRIES = 2000;
/** How many hosts a session remembers as tried (the oldest is forgotten first, and is then "new" again). */
export const MAX_HOSTS = 500;
export const MAX_SENTINELS = 20;

export function emptyCounters(): Counters {
  return { version: 1, minute: {}, session: {}, last: [], raised: {}, pending: [] };
}

const minuteOf = (now: Date): number => Math.floor(now.getTime() / 60000);

/** The engine's read-only view of the counters at `now`, with the signed raises from the session log. */
export function budgetView(c: Counters, corrupt: boolean, state: Pick<SessionState, "budgetRaises">, now: Date): BudgetView {
  const m = minuteOf(now);
  return {
    corrupt,
    window: (key, minutes, sinceMs) => {
      const from = Math.max(m - minutes, sinceMs === undefined ? Number.NEGATIVE_INFINITY : Math.floor(sinceMs / 60000));
      return (own(c.minute, key) ?? []).filter(([at]) => at > from).reduce((s, [, n]) => s + n, 0);
    },
    total: (key) => own(c.session, key) ?? 0,
    repeats: (hash) => {
      const e = c.last.find((x) => x.hash === hash);
      return e === undefined || now.getTime() - Date.parse(e.firstAt) > LOOP_WINDOW_MS ? 0 : e.count;
    },
    allowance: (key) => (own(c.raised, key) ?? 0) + state.budgetRaises.filter((r) => r.key === key).reduce((s, r) => s + r.amount, 0),
    floor: (key) => own(c.floor, key) ?? 0,
    recent: (key, sinceMs) => {
      const from = Math.max(now.getTime() - MONITOR_MS, sinceMs ?? Number.NEGATIVE_INFINITY);
      return (own(c.ms ?? {}, key) ?? []).filter(([at]) => at > from && at <= now.getTime()).reduce((s, [, n]) => s + n, 0);
    },
    stops: () => [...(c.stops ?? [])],
  };
}

function addMinute(c: Counters, u: BudgetUse, m: number): void {
  const list = (own(c.minute, u.key) ?? []).filter(([at]) => at > m - WINDOW_MIN);
  const cur = list.find(([at]) => at === m);
  if (cur !== undefined) cur[1] += u.amount;
  else list.push([m, u.amount]);
  setOwn(c.minute, u.key, list);
}

function addUse(c: Counters, u: BudgetUse, m: number): void {
  addMinute(c, u, m);
  setOwn(c.session, u.key, (own(c.session, u.key) ?? 0) + u.amount);
}

/**
 * The behaviour monitor's counts (src/engine/budgets.ts monitorCheck): attempts, whatever the verdict. A host
 * is remembered for the session (host:<host>, so "new" means never tried in it); the rest are minute buckets
 * only, so they leave no session totals behind.
 */
function addMs(c: Counters, key: string, amount: number, t: number): void {
  const ms = { ...(c.ms ?? {}) };
  const list = (own(ms, key) ?? []).filter(([at]) => at > t - MONITOR_MS);
  list.push([t, amount]);
  setOwn(ms, key, list.slice(-MAX_MS_ENTRIES));
  c.ms = ms;
}

function pruneMs(c: Counters, t: number): void {
  if (c.ms === undefined) return;
  for (const [k, list] of Object.entries(c.ms)) {
    const kept = list.filter(([at]) => at > t - MONITOR_MS);
    if (kept.length === 0) delete c.ms[k];
    else setOwn(c.ms, k, kept);
  }
}

/** Remembers a tried host; beyond MAX_HOSTS the oldest one is forgotten. */
function noteHost(c: Counters, host: string): void {
  const key = `host:${host}`;
  setOwn(c.session, key, (own(c.session, key) ?? 0) + 1);
  const hosts = Object.keys(c.session).filter((k) => k.startsWith("host:"));
  for (const k of hosts.slice(0, Math.max(0, hosts.length - MAX_HOSTS))) delete c.session[k];
}

function addWatch(c: Counters, d: Decision, t: number): void {
  const counted = monitorCountedVerdict(d);
  if (counted !== "allow") addMs(c, "verdict:nonallow", 1, t);
  if (counted === "deny" || counted === "queue") addMs(c, `fail:${d.counterKey ?? d.actionHash}`, 1, t);
  const w = d.budget?.watch;
  if (w !== undefined) {
    if (w.newHosts > 0) addMs(c, "watch:newhost", w.newHosts, t);
    for (const h of w.hosts) noteHost(c, h);
    if (w.config) addMs(c, "watch:config", 1, t);
  }
  const s = d.stop;
  if (s?.id !== undefined && s.target !== undefined) {
    const sentinel: MonitorSentinel = { id: s.id, at: new Date(t).toISOString(), scope: s.scope ?? "session", target: s.target, signal: s.signal, reason: s.reason };
    c.stops = [...(c.stops ?? []).filter((x) => x.id !== s.id), sentinel].slice(-MAX_SENTINELS);
  }
}

/** Adds a person's approval to the allowance of each budget it exceeded. */
export function raiseBudgets(c: Counters, raises: readonly BudgetUse[]): void {
  for (const r of raises) {
    setOwn(c.raised, r.key, (own(c.raised, r.key) ?? 0) + r.amount);
    // F35: the raise records the total at that moment, so the budget is given again from there.
    const floor = { ...(c.floor ?? {}) };
    setOwn(floor, r.key, own(c.session, r.key) ?? 0);
    c.floor = floor;
  }
}

function prune(c: Counters, m: number): void {
  for (const [k, list] of Object.entries(c.minute)) {
    const kept = list.filter(([at]) => at > m - WINDOW_MIN);
    if (kept.length === 0) delete c.minute[k];
    else setOwn(c.minute, k, kept);
  }
}

/**
 * The pure part of recordBudget (also used by the friction gate to replay a whole session in memory).
 * `restated`: the decision decides again a call already counted once (the MCP gateway's approval given in the
 * client: the call was held, a person said yes, and the same call is decided again with that approval). Its
 * usage and spending limits count, as it now goes ahead, but the behaviour monitor already saw the call: it is
 * not counted again toward repeats (loop tracking) or configuration changes.
 */
export function applyDecision(c: Counters, d: Decision, now: Date, o: { restated?: boolean } = {}): void {
  const goes = d.verdict === "allow" || d.verdict === "ask";
  if (d.caps !== undefined) {
    const caps = c.caps ?? emptyCapCounts();
    applyCapRecord(caps, d.caps, goes, warningShown(d.rules), "session");
    c.caps = caps;
  }
  const b = d.budget;
  if (b === undefined) return;
  const m = minuteOf(now);
  if (goes) for (const u of b.usage) addUse(c, u, m);
  // A decision refused only by a spending limit is not counted as non-allowed (monitorCountedVerdict).
  const counted = monitorCountedVerdict(d);
  if (counted !== "allow") addUse(c, { key: "verdict:nonallow", amount: 1 }, m);
  if (o.restated !== true) addWatch(c, d, now.getTime());
  // An edit-then-test cycle is not a loop: any write that goes ahead resets loop tracking.
  if (goes && b.writes) c.last = [];
  else if (b.loopEligible && o.restated !== true) {
    // Counted under the counter key (no cosmetic fields), as FW-LOOP reads it (budgetRules).
    const key = d.counterKey ?? d.actionHash;
    const e = c.last.find((x) => x.hash === key);
    if (e === undefined || now.getTime() - Date.parse(e.firstAt) > LOOP_WINDOW_MS) {
      c.last = [{ hash: key, count: 1, firstAt: now.toISOString() }, ...c.last.filter((x) => x.hash !== key)].slice(0, MAX_LAST);
    } else e.count += 1;
  }
  if (b.raises.length > 0) {
    // A queued action approved with the passphrase: the approval was signed, raise now.
    if (d.verdict === "allow" && d.rules.includes("FW-APPROVED")) raiseBudgets(c, b.raises);
    // Asked: raise only when the tool actually runs (the person said yes), in confirmBudget.
    if (d.verdict === "ask") c.pending = [{ hash: d.actionHash, raises: b.raises, at: now.toISOString() }, ...c.pending.filter((p) => p.hash !== d.actionHash)].slice(0, MAX_PENDING);
  }
  prune(c, m);
  pruneMs(c, now.getTime());
}

/** An asked action that exceeded a budget ran (the person said yes): raise what it exceeded. Returns whether anything was pending. */
export function confirmPending(c: Counters, actionHash: string, now?: Date): boolean {
  // An ask nobody answered must not later turn a normal run of the same action into a raise with no yes:
  // an entry older than PENDING_TTL_MS is dropped (callers pass `now`; without it nothing expires).
  if (now !== undefined) c.pending = c.pending.filter((x) => !(now.getTime() - Date.parse(x.at) > PENDING_TTL_MS));
  const p = c.pending.find((x) => x.hash === actionHash);
  if (p === undefined) return false;
  raiseBudgets(c, p.raises);
  c.pending = c.pending.filter((x) => x !== p);
  return true;
}
