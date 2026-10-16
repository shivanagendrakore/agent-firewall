/**
 * Desktop notifications for held and blocked actions. Local only: a
 * native notification on this machine, nothing sent anywhere.
 *
 * Three properties matter more than the feature itself:
 *
 *  1. A notification informs and can never approve. It has no action buttons;
 *     approving still needs `launchsafe-firewall queue review` in the person's
 *     own terminal with the passphrase.
 *  2. The text is fixed sentences and counts. It never carries tool input, a
 *     file path, a URL or the agent's own words: those are attacker-reachable,
 *     and a notification is a high-trust surface (a crafted summary could read
 *     "safe to approve"). Nothing but `kind`, `count` and (for a stopped session) one of the behaviour
 *     monitor's fixed signal values reaches the text.
 *  3. It never blocks or changes a decision. The helper is spawned detached, every
 *     failure is swallowed (and logged once a day), and the verdict never depends on it.
 */

import { spawn } from "node:child_process";
import { accessSync, constants, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import type { FirewallConfig, NotifyKind } from "../types.js";
import { MONITOR_SIGNALS, signalSentence, type MonitorSignal } from "../engine/budgets.js";
import { ensureDir, readText, withLock } from "./fsutil.js";
import { testMarker } from "./guard.js";
import type { Layout } from "./layout.js";
import { appendLog } from "./log.js";

export const APP_TITLE = "LaunchSafe Firewall";
const OSASCRIPT = "/usr/bin/osascript";
/** Data blocks and canaries are urgent: they skip coalescing but never fire more than once per 10 s. */
export const URGENT_FLOOR_SEC = 10;
const URGENT: ReadonlySet<NotifyKind> = new Set(["denied_dlp", "canary", "stopped"]);
const REVIEW = "In your terminal: launchsafe-firewall queue review";

/** Starts a helper process and returns immediately. The default is detached with all stdio ignored. */
export type Spawner = (cmd: string, args: string[]) => void;

export interface NotifyDeps {
  spawn?: Spawner;
  platform?: NodeJS.Platform;
  /** Whether a file is an executable we can run (tests). */
  executable?: (path: string) => boolean;
  /**
   * R11: whether a helper is safe to run from the hook: owned by root, not writable by group, others or
   * this user, in a directory with the same properties. Tests that model the file system with
   * `executable` and no `trusted` treat the fixed system paths as trusted.
   */
  trusted?: (path: string) => boolean;
  now?: () => number;
}

export interface NotifyOptions {
  /** Whether the session is unattended (for `onlyWhenUnattended`). */
  unattended?: boolean;
  /** For "stopped": which behaviour the monitor saw (a fixed value; its sentence is fixed text). */
  signal?: MonitorSignal;
  deps?: NotifyDeps;
}

/** One state file: per-kind last send time and the count folded in from suppressed notifications. */
interface NotifyState {
  /** The notify-send path resolved by doctor (Linux). */
  tool?: string;
  lastSentAt?: number;
  kinds: Partial<Record<NotifyKind, { lastSentAt: number; suppressed: number }>>;
  lastFailureDay?: string;
}

const plural = (n: number, one: string, many: string): string => (n === 1 ? one : many);

/** The fixed sentence for a kind. The only inputs are the kind, a count and (for "stopped") a fixed signal value. */
export function notificationText(kind: NotifyKind, count: number, signal?: MonitorSignal): { title: string; body: string } {
  const n = Number.isFinite(count) ? Math.min(Math.max(1, Math.floor(count)), 9999) : 1;
  let body: string;
  switch (kind) {
    case "queued":
      body = `${n} ${plural(n, "action is", "actions are")} waiting for your review. ${REVIEW}`;
      break;
    case "proposal":
      body = `${n} proposed ${plural(n, "change", "changes")} to the agent instructions, memory or auto-run files ${plural(n, "is", "are")} waiting for your review. ${REVIEW}`;
      break;
    case "denied_dlp":
      body = n === 1 ? "Blocked: the agent tried to send a credential or personal data off this machine." : `Blocked ${n} times: the agent tried to send a credential or personal data off this machine.`;
      break;
    case "canary":
      body = n === 1 ? "A planted decoy credential was touched. Something is reading files it has no reason to read. In your terminal: launchsafe-firewall log" : `A planted decoy credential was touched ${n} times. In your terminal: launchsafe-firewall log`;
      break;
    case "loop":
      body = `${n} ${plural(n, "run was", "runs were")} held for repeating the same failing step. ${REVIEW}`;
      break;
    case "agent_config":
      // A finding in the files that program the agent, or a hook or server added since the last session.
      body = `A session started untrusted: ${n} ${plural(n, "finding or change", "findings or changes")} in the agent configuration. In your terminal: launchsafe-firewall doctor`;
      break;
    case "mcp_changed":
      // A pinned server's launch command, tools or descriptions changed; accepted only with `pins accept`.
      body = `${n} MCP ${plural(n, "server change is", "server changes are")} waiting for your review. In your terminal: launchsafe-firewall pins`;
      break;
    case "mcp_withheld":
      // The gateway withheld an MCP result carrying hidden instructions for the agent.
      body = `${n} MCP ${plural(n, "result was", "results were")} withheld for hidden text aimed at the agent. In your terminal: launchsafe-firewall gateway status`;
      break;
    case "cap":
      // A spending limit was reached (the agent was stopped) or nearly reached (said once).
      body = `${n === 1 ? "The agent is" : `${n} times the agent was`} at or near a spending limit (tool calls, data sent, repeated failures or model cost). In your terminal: launchsafe-firewall caps`;
      break;
    case "mail_quarantined":
      // Messages with hidden, agent-directed text were withheld from the agent's read path.
      body = `${n} ${plural(n, "message was", "messages were")} withheld from your agent. In your terminal: launchsafe-firewall mail quarantine`;
      break;
    case "stopped": {
      // The behaviour monitor stopped a session: nothing it does runs until you resume it. The reason is one of
      // the monitor's fixed sentences (chosen by a fixed value, never text from the agent).
      const why = signal !== undefined && (MONITOR_SIGNALS as readonly string[]).includes(signal) ? `: ${signalSentence(signal)}` : "";
      body = `${n === 1 ? "An agent session was stopped" : `${n} agent sessions were stopped`}${why}. No further tool call of it is allowed until you resume it. In your terminal: launchsafe-firewall session list`;
      break;
    }
  }
  return { title: APP_TITLE, body };
}

function isExecutable(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * R11: the only places notify-send is run from. Never a PATH lookup: the hook runs outside Claude Code's
 * OS sandbox, and a PATH directory the agent can write (a direnv PATH_add, npm's global bin) would make
 * agent-written code run as the hook, with the firewall home in reach.
 */
export const NOTIFY_SEND_PATHS: readonly string[] = ["/usr/bin/notify-send", "/usr/local/bin/notify-send", "/bin/notify-send"];

function notWritable(st: { uid: number; mode: number }): boolean {
  return st.uid === 0 && (st.mode & 0o022) === 0;
}

/** Root-owned, not group- or world-writable, not writable by this user, and the same for its directory. */
export function isTrustedSystemFile(path: string): boolean {
  try {
    if (!isAbsolute(path)) return false;
    const real = realpathSync(path);
    const st = statSync(real);
    if (!st.isFile() || !notWritable(st)) return false;
    if (!notWritable(statSync(dirname(real)))) return false;
    try {
      accessSync(real, constants.W_OK);
      return false;
    } catch {
      return true;
    }
  } catch {
    return false;
  }
}

/**
 * Like isTrustedSystemFile, for a program the agent must not be able to replace, but sound when the hook runs
 * as root (which can write any file, so "not writable by me" proves nothing there): the file and every
 * directory above it (after symlinks) are root-owned and not group- or world-writable. For anyone but root
 * the file must also not be writable by this user (catches ACLs the mode bits do not show).
 */
export function isRootProtectedFile(path: string): boolean {
  try {
    if (!isAbsolute(path)) return false;
    const real = realpathSync(path);
    const st = statSync(real);
    if (!st.isFile() || !notWritable(st)) return false;
    for (let dir = dirname(real); ; dir = dirname(dir)) {
      if (!notWritable(statSync(dir))) return false;
      if (dirname(dir) === dir) break;
    }
    if (typeof process.getuid === "function" && process.getuid() === 0) return true;
    try {
      accessSync(real, constants.W_OK);
      return false;
    } catch {
      return true;
    }
  } catch {
    return false;
  }
}

export interface Availability {
  ok: boolean;
  /** The helper to run (when ok). */
  tool?: string;
  /** Why not (when not ok). */
  reason?: string;
}

/** Whether this machine can show a notification, and with which helper. Used by notify and doctor. */
export function notifyAvailability(env: NodeJS.ProcessEnv, deps: NotifyDeps = {}, cachedTool?: string): Availability {
  const platform = deps.platform ?? process.platform;
  const exec = deps.executable ?? isExecutable;
  if (platform === "darwin") return exec(OSASCRIPT) ? { ok: true, tool: OSASCRIPT } : { ok: false, reason: `${OSASCRIPT} not found` };
  if (platform === "linux") {
    const display = (env.DISPLAY ?? "") !== "" || (env.WAYLAND_DISPLAY ?? "") !== "";
    if (!display) return { ok: false, reason: "no graphical session (DISPLAY and WAYLAND_DISPLAY are not set)" };
    const trusted = deps.trusted ?? (deps.executable !== undefined ? (): boolean => true : isTrustedSystemFile);
    const usable = (p: string): boolean => NOTIFY_SEND_PATHS.includes(p) && exec(p) && trusted(p);
    // R11: a fixed system path only, never PATH; doctor's cached copy counts only if it is one of them.
    const tool = cachedTool !== undefined && usable(cachedTool) ? cachedTool : (NOTIFY_SEND_PATHS.find((p) => exec(p) && trusted(p)) ?? null);
    if (tool !== null) return { ok: true, tool };
    const unsafe = NOTIFY_SEND_PATHS.find((p) => exec(p));
    return { ok: false, reason: unsafe !== undefined ? `${unsafe} is writable by someone other than root, so it is not run` : `notify-send is not installed in ${NOTIFY_SEND_PATHS.map((p) => dirname(p)).join(", ")} (try: sudo apt install libnotify-bin)` };
  }
  return { ok: false, reason: `${platform} is not supported (macOS and Linux only)` };
}

/** Text goes in as arguments, never into script source, so no content can become code. */
function command(tool: string, platform: NodeJS.Platform, title: string, body: string): { cmd: string; args: string[] } {
  if (platform === "darwin") {
    return { cmd: tool, args: ["-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", "--", title, body] };
  }
  return { cmd: tool, args: [`--app-name=${title}`, "--", title, body] };
}

export const defaultSpawner: Spawner = (cmd, args) => {
  // Belt and braces for the suite: with a test marker in the real process environment, never start a helper.
  if (testMarker(process.env)) return;
  const child = spawn(cmd, args, { detached: true, stdio: "ignore" });
  // An asynchronous failure (the binary vanished) must not crash the hook.
  child.on("error", () => undefined);
  child.unref();
};

function statePath(l: Layout): string {
  return join(l.home, "notify.json");
}

/**
 * Replaces the state file atomically but without fsync: this is a rate-limit counter, losing the last
 * write to a crash only means one extra or one missing notification, and the hook must not wait on a disk flush.
 */
function writeState(l: Layout, s: NotifyState): void {
  ensureDir(l.home);
  const path = statePath(l);
  const tmp = `${path}.${process.pid}.tmp`;
  try {
    writeFileSync(tmp, JSON.stringify(s), { mode: 0o600 });
    renameSync(tmp, path);
  } catch (e) {
    rmSync(tmp, { force: true });
    throw e;
  }
}

export function readNotifyState(l: Layout): NotifyState {
  try {
    const t = readText(statePath(l));
    if (t === null) return { kinds: {} };
    const o = JSON.parse(t) as NotifyState;
    if (typeof o !== "object" || o === null || typeof o.kinds !== "object" || o.kinds === null) return { kinds: {} };
    return o;
  } catch {
    return { kinds: {} };
  }
}

/** The time of the last notification, for `status`. */
export function lastNotificationAt(l: Layout): number | null {
  const t = readNotifyState(l).lastSentAt;
  return typeof t === "number" ? t : null;
}

/** Doctor: remember which of the fixed system paths holds notify-send. Returns the availability. */
export function probeAndCache(l: Layout, env: NodeJS.ProcessEnv, deps: NotifyDeps = {}): Availability {
  const a = notifyAvailability(env, deps);
  if (a.ok && a.tool !== undefined && (deps.platform ?? process.platform) === "linux" && !testMarker(env)) {
    try {
      withLock(join(l.locks, "notify.lock"), () => {
        const s = readNotifyState(l);
        if (s.tool !== a.tool) writeState(l, { ...s, tool: a.tool });
      });
    } catch {
      // The cache is an optimisation only.
    }
  }
  return a;
}

/**
 * Shows at most one notification for this event, subject to the policy, the rate limit and what
 * the machine can do. Never throws and never waits for the helper.
 */
export function notify(l: Layout, kind: NotifyKind, count: number, cfg: FirewallConfig, env: NodeJS.ProcessEnv, opts: NotifyOptions = {}): void {
  const deps = opts.deps ?? {};
  try {
    if (testMarker(env)) return;
    // Real spawning also refuses under a test marker in the real process environment.
    if (deps.spawn === undefined && testMarker(process.env)) return;
    const p = cfg.notifications;
    if (!p.enabled || !p.on.includes(kind)) return;
    if (p.onlyWhenUnattended && opts.unattended !== true) return;
    const now = (deps.now ?? Date.now)();
    const urgent = URGENT.has(kind);
    const interval = (urgent ? URGENT_FLOOR_SEC : p.minIntervalSec) * 1000;
    const platform = deps.platform ?? process.platform;
    const count1 = Number.isFinite(count) ? Math.max(1, Math.floor(count)) : 1;
    // Decide under the state as read. The common case on a busy run is "suppressed": it takes no lock
    // (a lost update only makes the next count one low), so a burst of held actions costs the hook one
    // small write each. Sending takes the lock and re-checks, so two hooks can never both send.
    const fold = (s: NotifyState): boolean => {
      const k = s.kinds[kind] ?? { lastSentAt: 0, suppressed: 0 };
      if (now - k.lastSentAt >= interval) return false;
      s.kinds[kind] = { lastSentAt: k.lastSentAt, suppressed: (Number.isFinite(k.suppressed) ? k.suppressed : 0) + count1 };
      writeState(l, s);
      return true;
    };
    const first = readNotifyState(l);
    const avail = notifyAvailability(env, deps, first.tool);
    if (!avail.ok || avail.tool === undefined) return;
    if (fold(first)) return;
    const tool = avail.tool;
    const action = withLock(join(l.locks, "notify.lock"), (): { total: number } | null => {
      const s = readNotifyState(l);
      if (fold(s)) return null;
      const k = s.kinds[kind] ?? { lastSentAt: 0, suppressed: 0 };
      const total = (Number.isFinite(k.suppressed) ? k.suppressed : 0) + count1;
      s.kinds[kind] = { lastSentAt: now, suppressed: 0 };
      s.lastSentAt = now;
      writeState(l, s);
      return { total };
    }, { timeoutMs: 250 });
    if (action === null) return;
    const { title, body } = notificationText(kind, action.total, opts.signal);
    const c = command(tool, platform, title, body);
    try {
      (deps.spawn ?? defaultSpawner)(c.cmd, c.args);
    } catch (e) {
      logFailure(l, kind, e, now);
    }
  } catch {
    // A notification problem never reaches the decision.
  }
}

/** One `notify_failed` entry per day, so a broken helper is visible without filling the log. */
function logFailure(l: Layout, kind: NotifyKind, e: unknown, now: number): void {
  try {
    const day = new Date(now).toISOString().slice(0, 10);
    const proceed = withLock(join(l.locks, "notify.lock"), () => {
      const s = readNotifyState(l);
      if (s.lastFailureDay === day) return false;
      writeState(l, { ...s, lastFailureDay: day });
      return true;
    }, { timeoutMs: 250 });
    if (proceed) appendLog(l, { type: "notify_failed", kind, reason: (e instanceof Error ? e.message : String(e)).slice(0, 200) });
  } catch {
    // Nothing more to do.
  }
}
