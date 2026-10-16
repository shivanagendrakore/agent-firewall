/**
 * Spending limits ("caps"). Where a budget (src/engine/budgets.ts) asks a person, a cap stops the
 * agent: per session and per day, on what the firewall can see.
 *
 *   toolCalls          every tool call the firewall lets go ahead (allowed, or asked)
 *   bytesOut           data sent off the machine, counted as the byte budgets count it
 *   identicalFailures  how often this exact action failed with the same error (loop detection, extended
 *                      from "the same action again" to "the same action failing the same way")
 *   tokens, costUsd    model usage the agent reports with a call (the local API and the SDKs: an optional
 *                      `usage` field). The firewall never calls a model and keeps no price list: cost is
 *                      what the agent reports.
 *
 * At `warnPercent` (80) of a cap the firewall says so once (FW-CAP-WARN): it asks the person when
 * policy `caps.warn` is "ask" and someone can answer, else it notes it in the decision. At the cap the
 * action is denied (FW-CAP) with what to do: a person raises the cap in their own terminal
 * (`launchsafe-firewall caps raise`, signed with the approval passphrase), or the day's caps reset
 * at local midnight. Pure: the counters and the person's raises come in through a CapView.
 */

import type { BudgetUse } from "./budgets.js";
import { kb } from "./budgets.js";
import { sha256Hex } from "./bytes.js";
import type { RuleHit } from "./decide.js";
import type { FirewallConfig } from "../types.js";
import { own, setOwn } from "../own.js";

/** The spending-limit rules. */
export const CAP_RULES: ReadonlySet<string> = new Set(["FW-CAP", "FW-CAP-WARN"]);

export function isCapRule(rule: string): boolean {
  return CAP_RULES.has(rule);
}

/**
 * The verdict the behaviour monitor (src/engine/budgets.ts monitorCheck, the kill switch) counts for a decision:
 * a decision that is not "allow" only because of a spending limit counts as allowed. A cap is not the agent
 * misbehaving, and it has its own stop that a person ends with `caps raise`; counting it would make a run of cap
 * denials also trip a kill-switch stop (which needs the approval passphrase to resume). A decision that another
 * rule also refused (its rules name a rule that is not a cap) counts as it is.
 */
export function monitorCountedVerdict(d: { verdict: "allow" | "ask" | "queue" | "deny"; rules: readonly string[] }): "allow" | "ask" | "queue" | "deny" {
  return d.verdict !== "allow" && d.rules.length > 0 && d.rules.every(isCapRule) ? "allow" : d.verdict;
}

export const CAP_METRICS = ["toolCalls", "bytesOut", "identicalFailures", "tokens", "costUsd"] as const;
export type CapMetric = (typeof CAP_METRICS)[number];
export type CapScope = "session" | "day";
/** A limit per metric; null: no limit. */
export type CapLimits = Record<CapMetric, number | null>;

export interface CapPolicy {
  enabled: boolean;
  /** Warn once when a cap is this full (percent, 1 to 99). */
  warnPercent: number;
  /** "ask": the warning asks the person (when someone can answer); "note": it is noted in the decision only. */
  warn: "ask" | "note";
  session: CapLimits;
  day: CapLimits;
}

export const DEFAULT_CAPS: Readonly<CapPolicy> = Object.freeze({
  enabled: true,
  warnPercent: 80,
  warn: "ask",
  session: Object.freeze({ toolCalls: 5000, bytesOut: 64 * 1024 * 1024, identicalFailures: 10, tokens: null, costUsd: null }),
  day: Object.freeze({ toolCalls: 20000, bytesOut: 256 * 1024 * 1024, identicalFailures: 25, tokens: null, costUsd: null }),
}) as Readonly<CapPolicy>;

/** The effective caps: the policy's values over the defaults. */
export function capPolicy(cfg: Pick<FirewallConfig, "caps">): CapPolicy {
  const c = cfg.caps as Partial<CapPolicy> | undefined;
  return {
    enabled: c?.enabled ?? DEFAULT_CAPS.enabled,
    warnPercent: c?.warnPercent ?? DEFAULT_CAPS.warnPercent,
    warn: c?.warn ?? DEFAULT_CAPS.warn,
    session: { ...DEFAULT_CAPS.session, ...(c?.session ?? {}) },
    day: { ...DEFAULT_CAPS.day, ...(c?.day ?? {}) },
  };
}

/** Model usage an agent reports with a tool call (the local API's and the SDKs' optional `usage`). */
export interface ModelUsage {
  inputTokens?: number;
  outputTokens?: number;
  /** The agent's own estimate of what the model calls behind this tool call cost, in US dollars. */
  costUsd?: number;
}

/** Why a usage report is not valid (null: valid). Whole token counts, a finite cost, nothing negative. */
export function usageProblem(u: unknown): string | null {
  if (typeof u !== "object" || u === null || Array.isArray(u)) return "usage must be an object";
  for (const k of Object.keys(u)) if (k !== "inputTokens" && k !== "outputTokens" && k !== "costUsd") return `unknown field usage.${k.slice(0, 80)} (expected inputTokens, outputTokens, costUsd)`;
  const o = u as Record<string, unknown>;
  for (const k of ["inputTokens", "outputTokens"] as const) if (o[k] !== undefined && (typeof o[k] !== "number" || !Number.isSafeInteger(o[k]) || o[k] < 0 || o[k] > 1e12)) return `usage.${k} must be a whole number from 0 to 10^12`;
  if (o.costUsd !== undefined && (typeof o.costUsd !== "number" || !Number.isFinite(o.costUsd) || o.costUsd < 0 || o.costUsd > 1e9)) return "usage.costUsd must be a number from 0 (US dollars)";
  return null;
}

/** Counter keys. Cost is kept in micro-dollars so sums stay exact. */
const KEY = { toolCalls: "calls", bytesOut: "bytes", tokens: "tokens", costUsd: "cost" } as const;

/** One scope's counters (a session's, in its counters file; the day's, in the day file). */
export interface CapCounts {
  /** calls, bytes, tokens, cost (micro-dollars). */
  totals: Record<string, number>;
  /** "<action hash>:<error fingerprint>" -> how often that action failed that way. */
  fails: Record<string, number>;
  /** Warnings already given, "<scope>:<metric>@<cap>" (once per cap; a raised cap warns again near its new value). */
  warned: string[];
}

export interface DailyCounters extends CapCounts {
  version: 1;
  /** The local calendar day these counters are for (YYYY-MM-DD); another day starts from zero. */
  day: string;
  /** When the file was last started again because it could not be read. */
  resetAt?: string;
}

export function emptyCapCounts(): CapCounts {
  return { totals: {}, fails: {}, warned: [] };
}

/** The local calendar day of `now` (the day caps reset at local midnight). */
export function localDay(now: Date): string {
  const p = (n: number): string => String(n).padStart(2, "0");
  return `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}`;
}

/**
 * The day counters to use at `now`: the stored ones while it is still their day, or a later day if the
 * clock went back (a day never goes backwards, so setting the clock back does not start the counters
 * again), else a fresh day.
 */
export function currentDaily(stored: DailyCounters, now: Date): DailyCounters {
  return localDay(now) <= stored.day ? stored : emptyDaily(now);
}

export function emptyDaily(now: Date): DailyCounters {
  return { version: 1, day: localDay(now), ...emptyCapCounts() };
}

/** What the engine reads: the session's and today's counters, and the person's raises. */
export interface CapView {
  /** The session id, for the command a person runs to raise a session cap. */
  sessionId?: string;
  session: CapCounts;
  day: CapCounts;
  /** Extra allowance a person granted (signed): for costUsd in US dollars, else in the metric's unit. */
  raise(scope: CapScope, metric: CapMetric): number;
  /**
   * The scopes whose counters could not be read, or were started again after that: fail closed. Every
   * call is denied until a person runs `launchsafe-firewall caps reset` (their counters are unknown, so
   * zero would let a runaway agent go on). Absent: none.
   */
  damaged?: { session?: boolean; day?: boolean };
}

/** What a decision adds to the cap counters. */
export interface CapRecord {
  /** Counted whatever the verdict: the model was used to make the call (tokens, cost). */
  always: BudgetUse[];
  /** Counted only when the action goes ahead (allow or ask): the call itself, and the bytes that leave. */
  ifRuns: BudgetUse[];
  /** Warnings this decision gives ("<scope>:<metric>@<cap>"); recorded only when the decision shows FW-CAP-WARN. */
  warned: string[];
  /** The caps this decision stops at (for the log, a notification and a later suspension). */
  stopped: { scope: CapScope; metric: CapMetric; limit: number; used: number }[];
}

export interface CapInput {
  policy: CapPolicy;
  view: CapView;
  actionHash: string;
  /** Bytes this action sends off the machine (measureUsage's bytes:*). */
  bytes: number;
  usage?: ModelUsage;
  /** Someone can answer an ask. */
  interactive: boolean;
  /** False: the call is not a tool call (network traffic a middleware asks about) and is not counted toward toolCalls. */
  countCall?: boolean;
}

export interface CapOutcome {
  hits: RuleHit[];
  record: CapRecord;
}

/**
 * An action whose output varies from run to run (a timestamp in a word, a random port) never fails "the
 * same way" by its text. So each failure also counts under the action and its exit status, and that
 * count is held to this many times the cap: a looser second line under the precise one.
 */
export const STATUS_FACTOR = 3;

/** How often this exact action failed the same way (the most for any one error, or its exit status / STATUS_FACTOR). */
export function identicalFailures(c: CapCounts, actionHash: string): number {
  let n = 0;
  const prefix = `${actionHash}:`;
  for (const [k, v] of Object.entries(c.fails)) {
    if (!k.startsWith(prefix)) continue;
    const m = k.slice(prefix.length).startsWith("status:") ? Math.floor(v / STATUS_FACTOR) : v;
    if (m > n) n = m;
  }
  return n;
}

/** An amount in plain words ("80 tool calls", "1.5 MB sent off the machine", "$1.99 of model cost (as reported)"). */
function words(metric: CapMetric, n: number): string {
  if (metric === "bytesOut") return `${kb(n)} sent off the machine`;
  if (metric === "costUsd") return `${short(metric, n)} of model cost (as the agent reported it)`;
  if (metric === "tokens") return `${n} model tokens`;
  return `${n} tool calls`;
}

/** An amount without its unit's words ("80", "1.5 MB", "$1.99"). */
function short(metric: CapMetric, n: number): string {
  if (metric === "bytesOut") return kb(n);
  if (metric === "costUsd") return `$${(n / 1e6).toFixed(2)}`;
  return `${n}`;
}

/** The raise command a person runs, with the cap's own size as the suggested amount. */
function raiseCommand(scope: CapScope, metric: CapMetric, amount: number, sessionId: string | undefined): string {
  return `launchsafe-firewall caps raise ${metric} ${amount} ${scope === "day" ? "--today" : `--session ${shellWord(sessionId)}`}`;
}

/** The reset command for counters that could not be read. */
function resetCommand(scope: CapScope, sessionId: string | undefined): string {
  return `launchsafe-firewall caps reset ${scope === "day" ? "--today" : `--session ${shellWord(sessionId)}`}`;
}

/**
 * A session id as one shell word a person can paste: plain ids as they are, anything else in single
 * quotes (control characters, which no shell word should carry, are dropped; the message is also made
 * terminal-safe where it is shown).
 */
export function shellWord(id: string | undefined): string {
  if (id === undefined || id === "") return "<session>";
  if (/^[A-Za-z0-9._:/@+=-]{1,200}$/.test(id)) return id;
  // eslint-disable-next-line no-control-regex -- dropping control characters is the point
  const clean = id.slice(0, 200).replace(/[\u0000-\u001f\u007f-\u009f]/g, "");
  return `'${clean.replace(/'/g, `'\\''`)}'`;
}

/** The cap rules for one action. Pure. */
export function capRules(input: CapInput): CapOutcome {
  const { policy, view } = input;
  const record: CapRecord = { always: [], ifRuns: [], warned: [], stopped: [] };
  const out: CapOutcome = { hits: [], record };
  if (!policy.enabled) return out;
  // A usage report that is not whole token counts and a finite cost is refused, never counted as zero.
  const bad = input.usage !== undefined ? usageProblem(input.usage) : null;
  if (bad !== null) {
    out.hits.push({ rule: "FW-CAP", outcome: "deny", reason: `the model usage reported with this call is not valid (${bad}), so the spending limits cannot count it. The agent or its integration must report whole token counts and a finite cost` });
    return out;
  }
  for (const scope of ["session", "day"] as const) {
    if (view.damaged?.[scope] !== true) continue;
    record.stopped.push({ scope, metric: "toolCalls", limit: 0, used: 0 });
    out.hits.push({ rule: "FW-CAP", outcome: "deny", reason: `the spending-limit counters for ${scope === "session" ? "this session" : "today"} could not be read, so the firewall cannot tell how much the agent has used and treats the limits as reached. Something other than the firewall may have changed its data directory. After checking, a person can start them again in their own terminal: ${resetCommand(scope, view.sessionId)}` });
  }
  if (out.hits.length > 0) return out;
  const u = input.usage ?? {};
  const tokens = (u.inputTokens ?? 0) + (u.outputTokens ?? 0);
  const micros = Math.round((u.costUsd ?? 0) * 1e6);
  // A call counts when it goes ahead (a denied or held call does not run); the model was used either way.
  const calls = input.countCall === false ? 0 : 1;
  if (calls > 0) record.ifRuns.push({ key: KEY.toolCalls, amount: calls });
  if (tokens > 0) record.always.push({ key: KEY.tokens, amount: tokens });
  if (micros > 0) record.always.push({ key: KEY.costUsd, amount: micros });
  if (input.bytes > 0) record.ifRuns.push({ key: KEY.bytesOut, amount: input.bytes });
  const adds: Record<CapMetric, number> = { toolCalls: calls, bytesOut: input.bytes, identicalFailures: 0, tokens, costUsd: micros };
  for (const scope of ["session", "day"] as const) {
    const counts = view[scope];
    const limits = policy[scope];
    for (const metric of CAP_METRICS) {
      const limit = own(limits, metric) ?? null;
      if (limit === null) continue;
      const raised = view.raise(scope, metric);
      // In the counter's unit (micro-dollars for cost).
      const cap = metric === "costUsd" ? Math.round((limit + raised) * 1e6) : limit + raised;
      const sofar = metric === "identicalFailures" ? identicalFailures(counts, input.actionHash) : (own(counts.totals, KEY[metric]) ?? 0);
      const add = adds[metric];
      const stop =
        metric === "identicalFailures"
          ? sofar >= cap
          : metric === "bytesOut"
            ? add > 0 && sofar + add > cap
            : metric === "toolCalls"
              ? sofar + add > cap
              : sofar >= cap || sofar + add > cap;
      const where = scope === "session" ? "this session" : "today, across all sessions,";
      const reset = scope === "day" ? " The day's limits reset at local midnight." : "";
      if (stop) {
        record.stopped.push({ scope, metric, limit: cap, used: sofar });
        const what =
          metric === "identicalFailures"
            ? `this exact action has failed the same way ${sofar} times ${scope === "session" ? "in this session" : "today"}; the limit is ${cap}, so the agent seems stuck`
            : `${where} the agent has used ${words(metric, sofar)}${add > 0 && metric !== "toolCalls" ? `, and this would add ${short(metric, add)}` : ""}; the limit is ${words(metric, cap)}`;
        out.hits.push({ rule: "FW-CAP", outcome: "deny", reason: `${what}. The firewall stopped the agent here.${reset} To go on, a person can raise the limit in their own terminal: ${raiseCommand(scope, metric, limit, view.sessionId)}` });
        continue;
      }
      // Warn once per cap, when the metric is part of this action.
      const level = metric === "identicalFailures" ? sofar : sofar + add;
      const involved = metric === "bytesOut" || metric === "toolCalls" ? add > 0 : metric === "identicalFailures" ? sofar > 0 : true;
      const key = `${scope}:${metric}@${cap}`;
      if (!involved || level * 100 < cap * policy.warnPercent || counts.warned.includes(key)) continue;
      record.warned.push(key);
      const pct = Math.min(99, Math.floor((level * 100) / cap));
      const what =
        metric === "identicalFailures"
          ? `this exact action has failed the same way ${sofar} times ${scope === "session" ? "in this session" : "today"} (${pct}% of the limit of ${cap})`
          : `${where} the agent has used ${words(metric, level)}, ${pct}% of its limit of ${short(metric, cap)}`;
      out.hits.push({
        rule: "FW-CAP-WARN",
        outcome: policy.warn === "ask" && input.interactive ? "approve" : "allow",
        reason: `${what}. At the limit the firewall stops the agent.${reset} To allow more, a person can run in their own terminal: ${raiseCommand(scope, metric, limit, view.sessionId)}`,
      });
    }
  }
  return out;
}

const MAX_FAILS = 500;
const MAX_WARNED = 200;

function addTo(rec: Record<string, number>, key: string, amount: number): void {
  setOwn(rec, key, (own(rec, key) ?? 0) + amount);
}

/**
 * Adds a decision's record to one scope's counters. `goes`: the action goes ahead (allow or ask);
 * `warned`: the decision showed its warning (FW-CAP-WARN is among its rules).
 */
export function applyCapRecord(c: CapCounts, r: CapRecord, goes: boolean, warned: boolean, scope: CapScope): void {
  for (const x of r.always) addTo(c.totals, x.key, x.amount);
  if (goes) for (const x of r.ifRuns) addTo(c.totals, x.key, x.amount);
  if (warned) {
    for (const k of r.warned) if (k.startsWith(`${scope}:`) && !c.warned.includes(k)) c.warned.push(k);
    if (c.warned.length > MAX_WARNED) c.warned = c.warned.slice(-MAX_WARNED);
  }
}

/** One failure of an action, by its error's fingerprint. Bounded: the least repeated are dropped first. */
export function addFailure(c: CapCounts, actionHash: string, fingerprints: readonly string[]): void {
  for (const fp of fingerprints) addTo(c.fails, `${actionHash}:${fp}`, 1);
  const keys = Object.keys(c.fails);
  if (keys.length <= MAX_FAILS) return;
  const keep = keys.sort((a, b) => (own(c.fails, b) ?? 0) - (own(c.fails, a) ?? 0)).slice(0, MAX_FAILS);
  const next: Record<string, number> = {};
  for (const k of keep) setOwn(next, k, own(c.fails, k) ?? 0);
  c.fails = next;
}

/** Whether a decision's warning was shown (only then is it recorded as given). */
export function warningShown(rules: readonly string[]): boolean {
  return rules.includes("FW-CAP-WARN");
}

/**
 * A failure's fingerprint, for the identical-failures cap (named apart from any other repeated-failure
 * counter in the firewall): the error with numbers, addresses and spacing normalized (durations, line
 * numbers and timestamps change from run to run), so "the same failure again" is recognised.
 */
export function capFailureFingerprint(text: string): string {
  const norm = text
    .slice(0, 8192)
    .replace(/0x[0-9a-f]+/gi, "#")
    .replace(/\d+/g, "#")
    .replace(/\s+/g, " ")
    .trim();
  return sha256Hex(norm).slice(0, 16);
}

const text = (v: unknown): string => (typeof v === "string" ? v : v === undefined ? "" : JSON.stringify(v) ?? "");

/** A failed tool result: its error text and its status ("exit:1", "error", "failed"). */
export interface CapFailure {
  text: string;
  status: string;
}

/**
 * The failure a tool result reports, or null. Explicit markers only (an MCP result's isError, a non-zero
 * exit code, Cursor's {"exitCode": n} in tool_output): a tool's output is never guessed to be an error
 * from its words. `failed`: the host says it failed (library, local API).
 */
export function capFailure(output: unknown, failed = false, depth = 0): CapFailure | null {
  const explicit = depth > 2 ? null : explicitFailure(output, depth);
  if (explicit !== null) return explicit;
  return failed ? { text: typeof output === "string" ? output : text(output), status: "failed" } : null;
}

function explicitFailure(output: unknown, depth: number): CapFailure | null {
  if (typeof output === "string") {
    const t = output.trim();
    if (!t.startsWith("{") || t.length > 4 * 1024 * 1024) return null;
    try {
      return capFailure(JSON.parse(t), false, depth + 1);
    } catch {
      return null;
    }
  }
  if (typeof output !== "object" || output === null || Array.isArray(output)) return null;
  const o = output as Record<string, unknown>;
  if (o.isError === true || o.is_error === true) return { text: `error: ${text(o.content ?? o.error ?? o.output ?? o.message)}`, status: "error" };
  for (const k of ["exitCode", "exit_code", "returncode"] as const) {
    const v = o[k];
    if (typeof v === "number" && Number.isInteger(v) && v !== 0) return { text: `exit ${v}: ${text(o.stderr ?? o.output ?? o.stdout ?? o.error)}`, status: `exit:${v}` };
  }
  return null;
}

/** The failure counter keys of one failure: by its text's fingerprint, and by its status. */
export function capFailureKeys(f: CapFailure): string[] {
  return [capFailureFingerprint(f.text), `status:${f.status}`];
}
