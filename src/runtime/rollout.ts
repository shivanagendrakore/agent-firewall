/**
 * Watch mode (src/policy-rollout.ts): whether it is in effect, the person's signed grant that turns it on,
 * and the report of what enforcing would have done while it was on.
 *
 * Watch mode loosens the firewall, so it takes more than a line in a policy file:
 * - a managed (administrator) policy may set it; the agent cannot write that file;
 * - a user policy's "watch" counts only with all of: a grant in the firewall's home signed by the approval key
 *   (`launchsafe-firewall rollout watch`, which needs the passphrase); that key pinned in a hook command in an
 *   agent settings file no repository can write (the user's or the managed one, naming this firewall home),
 *   and given to this hook by that command; the latest rollout change (a signed log entry, kept beside the
 *   grant) being this grant's "watch"; the grant not revoked and not ended (14 days by default, at most 90);
 *   and a policy that loaded without errors. Anything else leaves the firewall enforcing;
 * - a project file can never turn it on (mergeTighten ignores it and reports it).
 * Each change is a signed entry in the decision log ("rollout").
 */

import { randomBytes, type KeyObject } from "node:crypto";
import { join, resolve } from "node:path";
import { rmSync } from "node:fs";
import type { Layout } from "./layout.js";
import type { LoadedPolicy } from "./config.js";
import type { Verdict } from "../types.js";
import { atomicWrite, readText, tryReadText, writeNew } from "./fsutil.js";
import { POLICY_VERSION, validatePolicy } from "../policy.js";
import { signStateChange, verifyStateChange } from "./approver.js";
import { assertNotRealHome } from "./guard.js";
import { appendLog, tailLog, verifyEntry, type LogEntry } from "./log.js";
import { credentialAssignments, findSecrets } from "../engine/secrets.js";
import { findPersonalData } from "../engine/pii.js";
import { safeLine } from "../engine/terminal.js";
import { WATCH_ENFORCED_GROUPS } from "../policy-rollout.js";
import { CLAUDE_SETTINGS } from "./install.js";
import { CODEX_MANAGED_PATHS, codexHooksPath } from "../adapters/codex.js";
import { GEMINI_SYSTEM_SETTINGS } from "../adapters/gemini.js";
import { CURSOR_ENTERPRISE_HOOKS, cursorHooksPath } from "../adapters/cursor.js";

export interface RolloutGrant {
  version: 1;
  mode: "watch";
  id: string;
  at: string;
  /** When watch mode ends on its own (ISO time). */
  until: string;
  /** The approval key's signature over stateChangeMessage("rollout-watch", "*", [id, at, until]). */
  sig: string;
}

/** Whether watch mode is in effect, and why (or why not). */
export interface WatchState {
  /** The mode the policy asks for. */
  requested: "enforce" | "watch";
  active: boolean;
  /** The layer that set the mode (default, user, managed, project) and its file. */
  layer: LoadedPolicy["rollout"]["layer"];
  path?: string;
  /** The user grant, when one is on disk and verifies. */
  grant?: RolloutGrant;
  /** Why a requested watch mode is not in effect. */
  problem?: string;
}

export const DEFAULT_DAYS = 14;
export const MAX_DAYS = 90;

export function grantPath(l: Layout): string {
  return join(l.home, "rollout.json");
}

/** The latest rollout change: a copy of its signed log entry. */
export function headPath(l: Layout): string {
  return join(l.home, "rollout-head.json");
}

/** Grant ids a person ended with `rollout enforce` (a grant file put back later does not count again). */
export function revokedPath(l: Layout): string {
  return join(l.home, "rollout-revoked.json");
}

/** What the hooks last saw (for logging changes nobody ran a command for: the managed policy, an expiry). */
function seenPath(l: Layout): string {
  return join(l.home, "rollout-seen.json");
}

function fields(g: Pick<RolloutGrant, "id" | "at" | "until">): string[] {
  return [g.id, g.at, g.until];
}

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/** The grant on disk: null when absent, a string when it is damaged. Never throws. */
export function readGrant(l: Layout): RolloutGrant | null | string {
  const t = tryReadText(grantPath(l));
  if (t === null) return null;
  if (typeof t !== "string") return `${grantPath(l)} cannot be read (${t.unreadable})`;
  try {
    const g = JSON.parse(t) as Partial<RolloutGrant>;
    const iso = (v: unknown): boolean => typeof v === "string" && ISO.test(v) && !Number.isNaN(Date.parse(v));
    if (g.version !== 1 || g.mode !== "watch" || typeof g.id !== "string" || !/^[0-9a-f]{12}$/.test(g.id) || !iso(g.at) || !iso(g.until) || typeof g.sig !== "string") return `${grantPath(l)} is not a watch-mode grant`;
    return g as RolloutGrant;
  } catch {
    return `${grantPath(l)} is not valid JSON`;
  }
}

/** Writes a new grant signed with the unlocked approval key, ending after `days` (default 14, 1 to 90). */
export function writeGrant(l: Layout, priv: KeyObject, o: { days?: number; now?: Date } = {}): RolloutGrant {
  const now = o.now ?? new Date();
  const days = o.days ?? DEFAULT_DAYS;
  if (!Number.isInteger(days) || days < 1 || days > MAX_DAYS) throw new Error(`--days must be a whole number from 1 to ${MAX_DAYS}`);
  const base = { version: 1 as const, mode: "watch" as const, id: randomBytes(6).toString("hex"), at: now.toISOString(), until: new Date(now.getTime() + days * 86_400_000).toISOString() };
  const g: RolloutGrant = { ...base, sig: signStateChange(priv, "rollout-watch", "*", fields(base)) };
  assertNotRealHome(grantPath(l));
  atomicWrite(grantPath(l), `${JSON.stringify(g, null, 2)}\n`);
  return g;
}

/** Removes the grant. Returns whether one was there. */
export function removeGrant(l: Layout): boolean {
  assertNotRealHome(grantPath(l));
  const had = tryReadText(grantPath(l)) !== null;
  rmSync(grantPath(l), { force: true });
  return had;
}

export function verifyGrant(g: RolloutGrant, key: string | null): boolean {
  return key !== null && verifyStateChange(key, "rollout-watch", "*", fields(g), g.sig);
}

export function revokedIds(l: Layout): string[] {
  try {
    const v = JSON.parse(readText(revokedPath(l)) ?? "[]") as unknown;
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

/**
 * Records a rollout change: the signed log entry, and a copy of it as the latest change. A change the log
 * cannot record throws, so the caller does not make it. A revoked grant id is kept for good.
 */
export function recordRolloutChange(l: Layout, event: { mode: "watch" | "enforce"; by: string; grant?: string; until?: string; revoked?: string[]; [k: string]: unknown }): LogEntry {
  if (event.revoked !== undefined && event.revoked.length > 0) {
    assertNotRealHome(revokedPath(l));
    atomicWrite(revokedPath(l), `${JSON.stringify([...new Set([...revokedIds(l), ...event.revoked])])}\n`);
  }
  const entry = appendLog(l, { type: "rollout", ...event });
  assertNotRealHome(headPath(l));
  atomicWrite(headPath(l), `${JSON.stringify(entry)}\n`);
  return entry;
}

/** The latest rollout change, when its copy is intact and signed by the log's key; else null. */
export function latestChange(l: Layout): LogEntry | null {
  try {
    const t = readText(headPath(l));
    if (t === null) return null;
    const e = JSON.parse(t) as unknown;
    return verifyEntry(l, e) && e.event.type === "rollout" ? e : null;
  } catch {
    return null;
  }
}

/**
 * The approval key watch mode trusts: one pinned in a hook command, naming this firewall home, in a settings
 * file no repository can write (each agent's user file under `home` and its managed or system file). Never
 * the key on disk, and never one that only came from the environment: a repository's settings `env` can set
 * variables for the hook process, not the hook command in those files. Null when there is none, or several.
 */
export function pinnedWatchKey(l: Layout, home: string, platform: NodeJS.Platform = process.platform): string | null {
  const files = [CLAUDE_SETTINGS.path("user", home, home), CLAUDE_SETTINGS.managedPaths[platform], codexHooksPath("user", home, home, {}), CODEX_MANAGED_PATHS[platform], join(home, ".gemini", "settings.json"), GEMINI_SYSTEM_SETTINGS[platform], cursorHooksPath("user", home, home), CURSOR_ENTERPRISE_HOOKS[platform]].filter((p): p is string => p !== undefined);
  const keys = new Set<string>();
  const defaultHome = resolve(join(home, ".launchsafe-firewall"));
  const re = /LAUNCHSAFE_FIREWALL_HOOK=1 (?:LAUNCHSAFE_FIREWALL_HOME='([^'\\]*)' )?LAUNCHSAFE_FIREWALL_APPROVER='([A-Za-z0-9+/=]+)'/g;
  for (const f of new Set(files)) {
    let text: string | null = null;
    try {
      text = readText(f);
    } catch {
      text = null;
    }
    if (text === null) continue;
    for (const m of text.matchAll(re)) {
      const named = m[1] !== undefined ? resolve(m[1]) : defaultHome;
      if (named === resolve(l.home) && m[2] !== undefined) keys.add(m[2]);
    }
  }
  return keys.size === 1 ? ([...keys][0] as string) : null;
}

/**
 * Whether watch mode is in effect for a loaded policy. `pinnedKey` is pinnedWatchKey's answer (for a hook,
 * only when the hook process was given that same key). Never throws: any doubt means enforce.
 */
export function watchState(l: Layout, policy: Pick<LoadedPolicy, "rollout" | "error">, pinnedKey: string | null, now: Date = new Date()): WatchState {
  const r = policy.rollout;
  const base = { requested: r.mode, layer: r.layer, ...(r.path !== undefined ? { path: r.path } : {}) };
  if (r.mode !== "watch") return { ...base, active: false };
  if (policy.error !== undefined) return { ...base, active: false, problem: "a policy file has an error, so the firewall keeps enforcing until it is fixed" };
  if (r.layer === "managed") return { ...base, active: true };
  if (r.layer !== "user") return { ...base, active: false, problem: "only a person (rollout watch) or an administrator (managed policy) can turn watch mode on" };
  const g = readGrant(l);
  if (g === null) return { ...base, active: false, problem: `${r.path ?? "the user policy"} sets rollout.mode "watch", but no signed grant exists (it was not turned on with "launchsafe-firewall rollout watch"), so the firewall keeps enforcing` };
  if (typeof g === "string") return { ...base, active: false, problem: `${g}, so the firewall keeps enforcing` };
  if (pinnedKey === null) return { ...base, active: false, problem: 'no hook command in your own or the managed agent settings pins the approval key for this firewall home (run "launchsafe-firewall install" again), so the watch-mode grant cannot be checked and the firewall keeps enforcing' };
  if (!verifyGrant(g, pinnedKey)) return { ...base, active: false, problem: "the watch-mode grant is not signed by the approval key the hook command pins (rotated, edited, or not made by rollout watch), so the firewall keeps enforcing" };
  if (revokedIds(l).includes(g.id)) return { ...base, active: false, problem: `the watch-mode grant ${g.id} was ended with rollout enforce, so the firewall keeps enforcing` };
  const head = latestChange(l);
  if (head === null || head.event.mode !== "watch" || head.event.grant !== g.id) return { ...base, active: false, problem: "the latest signed rollout change is not this grant's watch (or its record is missing or damaged), so the firewall keeps enforcing" };
  if (!(Date.parse(g.until) > now.getTime())) return { ...base, active: false, grant: g, problem: `watch mode ended at ${g.until}; the firewall is enforcing again (run "launchsafe-firewall rollout watch" to start another period)` };
  return { ...base, active: true, grant: g };
}

/**
 * Logs a change of the mode in effect that no rollout command recorded (an administrator's managed policy, a
 * grant that ended, a policy error), once, when a hook first sees it. Never throws.
 */
export function noteWatchState(l: Layout, st: WatchState): void {
  try {
    const now = { mode: st.active ? "watch" : "enforce", layer: st.layer, grant: st.grant?.id ?? null };
    const t = tryReadText(seenPath(l));
    const before = typeof t === "string" ? (JSON.parse(t) as typeof now) : { mode: "enforce", layer: "default", grant: null };
    if (before.mode === now.mode) return;
    atomicWrite(seenPath(l), `${JSON.stringify(now)}\n`);
    appendLog(l, { type: "rollout_seen", mode: now.mode, layer: now.layer, ...(now.grant !== null ? { grant: now.grant } : {}), ...(st.path !== undefined ? { path: st.path } : {}), ...(st.problem !== undefined ? { why: st.problem.slice(0, 300) } : {}) });
  } catch {
    // A record, not a gate.
  }
}

/** The always-enforced core, as lines for status, doctor and the docs. */
export function enforcedCoreLines(): string[] {
  return WATCH_ENFORCED_GROUPS.map((g) => `${g.group}: ${g.rules.join(", ")}`);
}

// --- the report ------------------------------------------------------------------------------------

/** Masks credentials, personal data and URL or -u passwords in a log line, then bounds it (the report's examples). */
export function redactExample(text: string, max = 160): string {
  let out = text;
  const values = [...findSecrets(out).map((h) => h.value), ...credentialAssignments(out), ...findPersonalData(out, { insideTokens: true }).map((d) => d.value)].filter((v) => v.length >= 4).sort((a, b) => b.length - a.length);
  for (const v of values) out = out.split(v).join("[redacted]");
  out = out.replace(/(:\/\/)[^/\s:@]+:[^/\s@]+@/g, "$1[redacted]@");
  out = out.replace(/(\s-u\s*|\s--user[=\s])(['"]?)[^\s'":]+:[^\s'"]+\2/g, "$1[redacted]");
  out = out.replace(/((?:authorization|x-api-key|api[-_]?key|token|password|secret)["']?\s*[:=]\s*["']?(?:bearer\s+|basic\s+|token\s+)?)[^\s"',;}]{6,}/gi, "$1[redacted]");
  const line = safeLine(out);
  return line.length > max ? `${line.slice(0, max - 1)}…` : line;
}

export interface WatchRuleGroup {
  rule: string;
  count: number;
  /** How many of them would have been asked, held or blocked. */
  verdicts: Partial<Record<Verdict, number>>;
  sessions: number;
  /** Up to `examples` distinct redacted summaries, newest first. */
  examples: string[];
}

export interface WatchReport {
  /** Decisions logged while watch mode was in effect. */
  decisions: number;
  /** Of those, the ones enforcing would have asked, held or blocked. */
  wouldHaveStopped: number;
  /** Of those, the ones watch mode still stopped (the always-enforced core). */
  stillEnforced: number;
  since: string | null;
  until: string | null;
  byRule: WatchRuleGroup[];
  enforcedByRule: { rule: string; count: number }[];
  /** The rollout changes (rollout entries in the signed log), oldest first. */
  changes: { ts: string; mode: string; by: string; until?: string | null }[];
}

/** The report of what enforcing would have done during watch mode, from the decision log. */
export function watchReport(l: Layout, o: { since?: Date; examples?: number; maxEntries?: number } = {}): WatchReport {
  const entries: LogEntry[] = tailLog(l, o.maxEntries ?? 500_000);
  const max = o.examples ?? 3;
  const since = o.since?.getTime();
  const groups = new Map<string, { count: number; verdicts: Partial<Record<Verdict, number>>; sessions: Set<string>; examples: string[] }>();
  const enforced = new Map<string, number>();
  const changes: WatchReport["changes"] = [];
  let decisions = 0;
  let stopped = 0;
  let still = 0;
  let first: string | null = null;
  let last: string | null = null;
  for (const e of entries) {
    const ev = e.event;
    if (since !== undefined && !(Date.parse(e.ts) >= since)) continue;
    if (ev.type === "rollout" || ev.type === "rollout_seen") {
      changes.push({ ts: e.ts, mode: String(ev.mode ?? ""), by: ev.type === "rollout" ? String(ev.by ?? "") : `seen by a hook (${String(ev.layer ?? "")} policy)`, ...(ev.until !== undefined ? { until: ev.until === null ? null : String(ev.until) } : {}) });
      continue;
    }
    if (ev.type !== "decision" || ev.rollout !== "watch") continue;
    decisions++;
    first ??= e.ts;
    last = e.ts;
    const verdict = String(ev.verdict ?? "") as Verdict;
    const w = typeof ev.watch === "object" && ev.watch !== null ? (ev.watch as { verdict?: unknown; rules?: unknown }) : null;
    if (verdict !== "allow") {
      still++;
      stopped++;
      for (const r of Array.isArray(ev.rules) ? ev.rules : []) enforced.set(String(r), (enforced.get(String(r)) ?? 0) + 1);
    }
    if (w === null) continue;
    if (verdict === "allow") stopped++;
    const wv = String(w.verdict ?? "") as Verdict;
    const rules = Array.isArray(w.rules) ? w.rules.map(String) : [];
    const what = redactExample(`${String(ev.tool ?? "")}: ${String(ev.what ?? "")}`);
    for (const rule of rules.length > 0 ? rules : ["(no rule recorded)"]) {
      const g = groups.get(rule) ?? { count: 0, verdicts: {}, sessions: new Set<string>(), examples: [] };
      g.count++;
      g.verdicts[wv] = (g.verdicts[wv] ?? 0) + 1;
      g.sessions.add(String(ev.session ?? ""));
      // Newest first: replace as later entries come.
      if (!g.examples.includes(what)) {
        g.examples.unshift(what);
        if (g.examples.length > max) g.examples.length = max;
      }
      groups.set(rule, g);
    }
  }
  const byRule = [...groups].map(([rule, g]) => ({ rule, count: g.count, verdicts: g.verdicts, sessions: g.sessions.size, examples: g.examples })).sort((a, b) => b.count - a.count || a.rule.localeCompare(b.rule));
  return { decisions, wouldHaveStopped: stopped, stillEnforced: still, since: first, until: last, byRule, enforcedByRule: [...enforced].map(([rule, count]) => ({ rule, count })).sort((a, b) => b.count - a.count || a.rule.localeCompare(b.rule)), changes };
}

/** The report as text. */
export function formatWatchReport(r: WatchReport, state: WatchState): string {
  const L: string[] = [];
  L.push(`Rollout mode: ${state.active ? "watch (risky actions are logged and allowed, except the always-enforced core)" : state.requested === "watch" ? `enforce (watch requested but not in effect: ${state.problem ?? "unknown"})` : "enforce"}`);
  if (r.decisions === 0) {
    L.push("No decisions were logged in watch mode (in the period asked for).");
    return L.join("\n");
  }
  L.push(`Decisions logged in watch mode: ${r.decisions} (${r.since ?? "?"} to ${r.until ?? "?"})`);
  L.push(`Enforcing would have asked about, held or blocked ${r.wouldHaveStopped} of them; watch mode let ${r.wouldHaveStopped - r.stillEnforced} run and still stopped ${r.stillEnforced} (the always-enforced core).`);
  if (r.byRule.length > 0) {
    L.push("", "What would have been asked, held or blocked, by rule:");
    for (const g of r.byRule) {
      const v = (["ask", "queue", "deny"] as const).filter((k) => (g.verdicts[k] ?? 0) > 0).map((k) => `${g.verdicts[k] ?? 0} ${k === "ask" ? "asked" : k === "queue" ? "held" : "blocked"}`).join(", ");
      L.push(`  ${g.rule}: ${g.count} (${v}) in ${g.sessions} session${g.sessions === 1 ? "" : "s"}`);
      for (const ex of g.examples) L.push(`      e.g. ${ex}`);
    }
  }
  if (r.enforcedByRule.length > 0) {
    L.push("", "Still stopped in watch mode:");
    for (const g of r.enforcedByRule) L.push(`  ${g.rule}: ${g.count}`);
  }
  L.push("", 'Examples are shortened and credentials and personal data are masked. Explain a rule with "launchsafe-firewall explain <rule>"; switch to enforcing with "launchsafe-firewall rollout enforce".');
  return L.join("\n");
}

// --- the user policy's rollout key -------------------------------------------------------------------

/**
 * Sets `rollout.mode` in the user's policy file (created with only that key when absent), keeping the rest of
 * the file as it is and a copy of the original beside it. Refuses a file that does not validate (nothing is
 * written). Returns the backup's path, or null when nothing changed or there was no file.
 */
export function setUserRolloutMode(l: Layout, mode: "enforce" | "watch", now: Date = new Date()): { changed: boolean; backup: string | null } {
  assertNotRealHome(l.policy);
  const text = tryReadText(l.policy);
  if (text !== null && typeof text !== "string") throw new Error(`${l.policy} cannot be read (${text.unreadable})`);
  if (text === null) {
    atomicWrite(l.policy, `${JSON.stringify({ version: POLICY_VERSION, rollout: { mode } }, null, 2)}\n`);
    return { changed: true, backup: null };
  }
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(text) as Record<string, unknown>;
  } catch (e) {
    throw new Error(`${l.policy} is not valid JSON (${(e as Error).message}); fix it first`, { cause: e });
  }
  validatePolicy(doc, l.policy);
  const cur = typeof doc.rollout === "object" && doc.rollout !== null ? (doc.rollout as Record<string, unknown>) : {};
  if (cur.mode === mode) return { changed: false, backup: null };
  const next = { ...doc, rollout: { ...cur, mode } };
  validatePolicy(next, l.policy);
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  let backup = `${l.policy}.before-rollout-${stamp}.bak`;
  for (let n = 2; ; n++) {
    assertNotRealHome(backup);
    try {
      writeNew(backup, text);
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST" || n > 100) throw e;
      backup = `${l.policy}.before-rollout-${stamp}.${n}.bak`;
    }
  }
  atomicWrite(l.policy, `${JSON.stringify(next, null, 2)}\n`);
  return { changed: true, backup };
}
