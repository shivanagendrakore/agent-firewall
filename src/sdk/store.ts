/**
 * The default state store: plain maps in the process (browser-safe). Several
 * guards may share one; each session's events, counters and held items are
 * kept apart. Person-made state changes (approvals, scope widenings, budget
 * raises) enter only through settle(): appended any other way they are
 * treated as tampering, as the file store treats an unsigned approval.
 */

import type { BudgetView, MonitorSignal } from "../engine/budgets.js";
import type { StopState, StopView } from "../engine/stop.js";
import { applyDecision, budgetView, confirmPending, emptyCounters, type Counters } from "../engine/counters.js";
import { addFailure, applyCapRecord, currentDaily, emptyCapCounts, emptyDaily, warningShown, type CapView, type DailyCounters } from "../engine/caps.js";
import { redactSecrets } from "../engine/secrets.js";
import { approvalUnused, foldEvents, SIGNED_EVENT_TYPES } from "../engine/state.js";
import type { CanaryIndex, Decision, SessionState, StateEvent } from "../types.js";
import { nextEntry, verifyEntries } from "./log.js";
import type { HeldAction, HoldInput, LogEntry, LogSigner, LogVerifyResult, StateStore } from "./types.js";

export interface MemoryStoreOptions {
  /** Signs each log entry's hash. Without one the chain still proves order and integrity, unsigned. */
  signer?: LogSigner;
  /** Keep at most this many log entries (oldest dropped; verification starts from the first kept). Default 10000. */
  maxLogEntries?: number;
  /** Decoy files to watch for (rarely useful in memory; the file store loads the person's registry). */
  canaries?: CanaryIndex;
  /** The id of a new held item (tests). */
  newId?: () => string;
  /** The clock (tests). */
  now?: () => Date;
}

const MAX_STRING = 20000;

/** Credentials masked and long strings cut, as the runtime queue stores a held call's input. */
export function maskForStorage(v: unknown, depth = 0): unknown {
  if (depth > 10) return "…";
  if (typeof v === "string") {
    const r = redactSecrets(v).text;
    return r.length > MAX_STRING ? `${r.slice(0, MAX_STRING)}… [${r.length - MAX_STRING} more characters]` : r;
  }
  if (Array.isArray(v)) return v.slice(0, 200).map((x) => maskForStorage(x, depth + 1));
  if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).slice(0, 200).map(([k, x]) => [k, maskForStorage(x, depth + 1)]));
  return v;
}

/** A short id a person can type (40 bits of randomness), from the platform's crypto. */
export function newHeldId(): string {
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  const bytes = new Uint8Array(8);
  globalThis.crypto.getRandomValues(bytes);
  let s = "";
  for (const b of bytes) s += alphabet[b % alphabet.length];
  return s;
}

/** Held items a memory store keeps, at most (answered ones are dropped oldest first). */
const MAX_HELD = 10_000;

function copy<T>(v: T): T {
  return structuredClone(v);
}

export function memoryStore(o: MemoryStoreOptions = {}): StateStore {
  const events = new Map<string, StateEvent[]>();
  const counters = new Map<string, Counters>();
  // Stops the behaviour monitor made: kept for the store's life (a memory store has no person's resume).
  const stops = new Map<string, StopState>();
  const held = new Map<string, HeldAction>();
  // Today's spending-limit counters, for every session of this store (a new local day starts from zero).
  let daily: DailyCounters = emptyDaily(o.now?.() ?? new Date());
  const today = (at: Date): DailyCounters => {
    // A day never goes backwards: a clock set back keeps the later day's counters.
    daily = currentDaily(daily, at);
    return daily;
  };
  let log: LogEntry[] = [];
  const max = o.maxLogEntries ?? 10000;
  const now = o.now ?? (() => new Date());
  const newId = o.newId ?? newHeldId;
  const list = (session: string): StateEvent[] => {
    let l = events.get(session);
    if (l === undefined) {
      l = [];
      events.set(session, l);
    }
    return l;
  };
  const view = (h: HeldAction): HeldAction => copy(h);
  return {
    kind: "memory",
    firewallHome: "/__launchsafe_firewall__",
    load(session: string): SessionState {
      return foldEvents(list(session));
    },
    append(session: string, evs: readonly StateEvent[]): void {
      const l = list(session);
      for (const e of evs) {
        // Only settle() makes person-made changes; one appended directly did not come from a person.
        if (SIGNED_EVENT_TYPES.has(e.type)) l.push({ type: "corrupt", detail: `a ${e.type} event was appended without a person's decision` });
        else l.push(copy(e));
      }
    },
    consumeApproval(session: string, actionHash: string, approvalId: string): boolean {
      const l = list(session);
      if (!approvalUnused(l, actionHash, approvalId)) return false;
      l.push({ type: "approval_used", actionHash, id: approvalId });
      return true;
    },
    budgetView(session: string, state: SessionState, at: Date): BudgetView {
      return budgetView(copy(counters.get(session) ?? emptyCounters()), false, state, at);
    },
    recordBudget(session: string, d: Decision, at: Date): void {
      const c = counters.get(session) ?? emptyCounters();
      applyDecision(c, d, at);
      counters.set(session, c);
    },
    confirmBudget(session: string, actionHash: string, at?: Date): void {
      const c = counters.get(session);
      if (c !== undefined) confirmPending(c, actionHash, at);
    },
    stops(session: string, agent?: string | null): StopView {
      return { active: copy(stops.get(`session\n${session}`) ?? (agent !== undefined && agent !== null ? stops.get(`agent\n${agent}`) : undefined) ?? null) };
    },
    stop(target: string, s: { signal: MonitorSignal; reason: string; scope: "session" | "agent"; id: string }, at: Date): { created: boolean; id: string } {
      const key = `${s.scope}\n${target}`;
      const cur = stops.get(key);
      if (cur !== undefined) return { created: false, id: cur.id };
      stops.set(key, { id: s.id, at: at.toISOString(), by: "monitor", scope: s.scope, target, reason: s.reason, signal: s.signal });
      return { created: true, id: s.id };
    },
    // A memory store keeps no person's "never" choices (the host gives them with GuardOptions.nevers).
    nevers(): ReadonlyMap<string, string> {
      return new Map();
    },
    // Raises of a session cap are signed budget_raise events, which enter only through a person (none in
    // memory): a host that wants other limits sets them in the guard's policy.
    capView(session: string, state: SessionState, at: Date): CapView {
      // Each raise counts once by its id.
      const raised = (metric: string): number => [...new Map(state.budgetRaises.filter((r) => r.key === `cap:session:${metric}`).map((r) => [r.id, r.amount])).values()].reduce((n, a) => n + a, 0);
      return { sessionId: session, session: copy(counters.get(session)?.caps ?? emptyCapCounts()), day: copy(today(at)), raise: (scope, metric) => (scope === "session" ? raised(metric) : 0) };
    },
    recordCaps(_session: string, d: Decision, at: Date): void {
      if (d.caps !== undefined) applyCapRecord(today(at), d.caps, d.verdict === "allow" || d.verdict === "ask", warningShown(d.rules), "day");
    },
    recordFailure(session: string, actionHash: string, fingerprints: readonly string[], at: Date): void {
      const c = counters.get(session) ?? emptyCounters();
      const caps = c.caps ?? emptyCapCounts();
      addFailure(caps, actionHash, fingerprints);
      c.caps = caps;
      counters.set(session, c);
      addFailure(today(at), actionHash, fingerprints);
    },
    hold(item: HoldInput): HeldAction {
      for (const h of held.values()) if (h.status === "pending" && h.session === item.session && h.actionHash === item.actionHash) return view(h);
      let id = newId();
      while (held.has(id)) id = newId();
      const h: HeldAction = {
        id,
        session: item.session,
        createdAt: now().toISOString(),
        tool: item.tool,
        input: maskForStorage(item.input),
        actionHash: item.actionHash,
        rules: [...item.rules],
        reasons: [...item.reasons],
        kind: item.kind,
        ...(item.proposal !== undefined ? { proposal: { target: item.proposal.target, change: maskForStorage(item.proposal.change) as string } } : {}),
        status: "pending",
      };
      held.set(id, h);
      // Bounded: only held items already answered are forgotten (oldest first); a pending one is never dropped.
      if (held.size > MAX_HELD) {
        for (const [k, v] of held) {
          if (held.size <= MAX_HELD) break;
          if (v.status !== "pending") held.delete(k);
        }
      }
      return view(h);
    },
    held(id: string): HeldAction | null {
      const h = held.get(id);
      return h === undefined ? null : view(h);
    },
    listHeld(session?: string): HeldAction[] {
      return [...held.values()].filter((h) => session === undefined || h.session === session).sort((a, b) => a.createdAt.localeCompare(b.createdAt)).map(view);
    },
    settle(id: string, status: "approved" | "rejected", by: string): HeldAction {
      const h = held.get(id);
      if (h === undefined) throw new Error(`no held action ${id}`);
      if (h.status !== "pending") throw new Error(`held action ${id} is already ${h.status}`);
      h.status = status;
      h.decidedAt = now().toISOString();
      h.by = by;
      // V37: an approval given on a proposal (its diff shown) is the only kind that covers a proposal hold.
      if (status === "approved") list(h.session).push({ type: "approval", actionHash: h.actionHash, id: h.id, ...(h.kind === "proposal" ? { proposal: true as const } : {}) });
      return view(h);
    },
    appendLog(event: Record<string, unknown>): LogEntry {
      const e = nextEntry(log[log.length - 1], copy(event), now().toISOString(), o.signer);
      log.push(e);
      if (log.length > max) log = log.slice(log.length - max);
      return copy(e);
    },
    entries(limit?: number): LogEntry[] {
      return copy(limit === undefined ? log : log.slice(-limit));
    },
    verifyLog(): LogVerifyResult {
      return verifyEntries(log, o.signer?.verify?.bind(o.signer));
    },
    ...(o.canaries !== undefined ? { canaries: () => o.canaries } : {}),
  };
}
