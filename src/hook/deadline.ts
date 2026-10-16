/**
 * I3: the hook's own deadline. An agent treats a hook that runs past its timeout as failed, and some let the action
 * run then (Claude Code before onFailure: "block"). So the firewall answers first: a pre-tool decision that is not
 * finished by the deadline, measured from the hook process's start, is a deny the hook writes itself. The waits
 * inside a decision (locks, the agent-configuration scan, a phone hold) are given only the time that remains.
 *
 * The deadline is cooperative: the decision is synchronous, so it is checked between steps and bounds every wait;
 * a step that never returns is left to the agent's timeout (600 s for Claude Code and Codex, 60 s for Gemini CLI,
 * 30 s for Cursor, whose entries fail closed). docs/limitations.md says so.
 */

/** Default: below Cursor's 30 s timeout, the shortest of the four. */
export const DEFAULT_DEADLINE_MS = 20_000;
/** LAUNCHSAFE_FIREWALL_HOOK_DEADLINE_MS is clamped to this range (lowering it only makes the hook deny sooner). */
export const MIN_DEADLINE_MS = 1_000;
export const MAX_DEADLINE_MS = 25_000;
/** A hook waits this long at most for any one lock (C). */
export const HOOK_LOCK_WAIT_MS = 2_500;
/** Time kept back for writing the answer after a wait. */
const MARGIN_MS = 1_500;

export interface Deadline {
  /** When it passes (ms since the epoch). */
  at: number;
  total: number;
  remaining(): number;
  passed(): boolean;
  /** What a wait may take now: the time left less the margin, never negative, at most `cap`. */
  budget(cap?: number): number;
}

export function deadlineOf(o: { startedAt?: number; deadlineMs?: number; env?: NodeJS.ProcessEnv; now?: () => number } = {}): Deadline {
  const now = o.now ?? Date.now;
  const fromEnv = Number(o.env?.LAUNCHSAFE_FIREWALL_HOOK_DEADLINE_MS);
  const total = o.deadlineMs ?? (Number.isFinite(fromEnv) && fromEnv > 0 ? Math.min(MAX_DEADLINE_MS, Math.max(MIN_DEADLINE_MS, fromEnv)) : DEFAULT_DEADLINE_MS);
  const at = (o.startedAt ?? now()) + total;
  return {
    at,
    total,
    remaining: () => at - now(),
    passed: () => now() >= at,
    budget: (cap = Infinity) => Math.max(0, Math.min(cap, at - now() - MARGIN_MS)),
  };
}

/**
 * When the hook process started, for deadlineOf: now less the process's uptime, so node's start and the module
 * loading count against the deadline. The time already used is capped so that at least MIN_LEFT_MS remains: a slow
 * start must not make the deadline zero or negative before the first check (the decision is still made, with no
 * waits: budget() keeps its margin).
 */
export const MIN_LEFT_MS = 1_000;
export function hookStartedAt(env: NodeJS.ProcessEnv, uptimeSeconds: number, now: number = Date.now()): number {
  const total = deadlineOf({ env, now: () => now }).total;
  const used = Number.isFinite(uptimeSeconds) ? Math.min(Math.max(0, uptimeSeconds * 1000), Math.max(0, total - MIN_LEFT_MS)) : 0;
  return now - used;
}

/** The deny a hook writes when its deadline passed before the decision was finished. */
export function deadlineMessage(d: Deadline): string {
  return `LaunchSafe Firewall could not finish checking this action within its ${Math.round(d.total / 1000)} s deadline and blocked it to be safe (a slow disk, a held lock or a large scan). Try again; if it keeps happening, run "launchsafe-firewall doctor".`;
}
