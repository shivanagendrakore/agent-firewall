/**
 * Shared taint between the browser and the coding agents that drive it (docs/browser-link.md, the browser
 * design's section 10). Two small append-only files in <home>/browser/:
 *
 * - links.jsonl: an agent session called a browser-driving MCP tool (the hook records it). That session is
 *   linked to the browser for LINK_WINDOW_MS after its last such call.
 * - taint.jsonl: the browser reported that its agent session read outside content.
 *
 * Both directions only ever add taint. A browser taint taints every linked agent session (now, and any
 * session that links while the taint is recent); a linked agent session that is tainted is reported to the
 * browser by the host. Nothing here can make a session trusted again. Anything unreadable counts as taint.
 */

import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import type { StateEvent } from "../../types.js";
import { appendDurable, atomicWrite, ensureDir, tryReadText, withLock } from "../fsutil.js";
import type { Layout } from "../layout.js";
import { appendEvents, loadState } from "../store.js";

/** How long a session stays linked after its last browser tool call, and how long a browser taint counts. */
export const LINK_WINDOW_MS = 12 * 60 * 60 * 1000;
/** A link already recorded this recently is not written again (the hook runs on every call). */
const RELINK_MS = 5 * 60 * 1000;
/** Past this size a file is rewritten with only the records still inside the window. */
const COMPACT_BYTES = 256 * 1024;

/**
 * MCP servers that drive a browser a person uses: Claude in Chrome, Chrome DevTools MCP, Browser MCP,
 * Playwright MCP (in its extension mode it drives the person's own browser). Matched on the server name.
 */
export const BROWSER_MCP_SERVERS: readonly string[] = ["claude-in-chrome", "chrome-devtools", "browsermcp", "browser-mcp", "playwright"];

export function isBrowserServer(server: string): boolean {
  const s = server.toLowerCase();
  return BROWSER_MCP_SERVERS.some((n) => s === n || s.startsWith(`${n}-`) || s.startsWith(`${n}_`));
}

function dir(l: Layout): string {
  return join(l.home, "browser");
}

function linksFile(l: Layout): string {
  return join(dir(l), "links.jsonl");
}

function taintFile(l: Layout): string {
  return join(dir(l), "taint.jsonl");
}

interface Link {
  ts: string;
  session: string;
}

interface Taint {
  ts: string;
  session: string;
  reason: string;
}

type Read<T> = { records: T[]; damaged: boolean };

function readRecords<T>(path: string, valid: (x: unknown) => x is T): Read<T> {
  const t = tryReadText(path);
  if (t === null) return { records: [], damaged: false };
  if (typeof t !== "string") return { records: [], damaged: true };
  const records: T[] = [];
  let damaged = false;
  for (const line of t.split("\n")) {
    if (line.trim() === "") continue;
    try {
      const v = JSON.parse(line) as unknown;
      if (valid(v)) records.push(v);
      else damaged = true;
    } catch {
      damaged = true;
    }
  }
  return { records, damaged };
}

function isLink(x: unknown): x is Link {
  const r = x as Record<string, unknown> | null;
  return typeof r === "object" && r !== null && typeof r.ts === "string" && typeof r.session === "string" && r.session.length > 0 && r.session.length <= 200;
}

function isTaint(x: unknown): x is Taint {
  const r = x as Record<string, unknown> | null;
  return typeof r === "object" && r !== null && typeof r.ts === "string" && typeof r.session === "string" && typeof r.reason === "string" && /^[a-z][a-z0-9_]{0,39}$/.test(r.reason);
}

function within(ts: string, now: Date, windowMs = LINK_WINDOW_MS): boolean {
  const t = Date.parse(ts);
  // A time in the future (a clock moved back) still counts: never drop a taint early.
  return Number.isFinite(t) && now.getTime() - t <= windowMs;
}

/** Rewrites a file with only the records still inside the window, once it grows past COMPACT_BYTES. */
function compact<T extends { ts: string }>(path: string, valid: (x: unknown) => x is T, now: Date): void {
  let size = 0;
  try {
    size = statSync(path).size;
  } catch {
    return;
  }
  if (size < COMPACT_BYTES) return;
  withLock(`${path}.lock`, () => {
    const r = readRecords(path, valid);
    // A damaged file is kept as it is: it is what makes the reader fail closed.
    if (r.damaged) return;
    atomicWrite(path, r.records.filter((x) => within(x.ts, now)).map((x) => `${JSON.stringify(x)}\n`).join(""));
  });
}

function taintSource(reason: string): string {
  return `the linked browser session read outside content (${reason})`;
}

/**
 * The hook, before deciding a browser tool call: links the session to the browser and returns the taint the
 * browser has reported recently, as events for the session (an unreadable link state is taint too).
 */
export function linkBrowserSession(l: Layout, sessionId: string, now = new Date()): StateEvent[] {
  try {
    ensureDir(dir(l));
    const links = readRecords(linksFile(l), isLink);
    if (!links.records.some((x) => x.session === sessionId && within(x.ts, now, RELINK_MS))) withLock(`${linksFile(l)}.lock`, () => appendDurable(linksFile(l), `${JSON.stringify({ ts: now.toISOString(), session: sessionId } satisfies Link)}\n`));
    compact(linksFile(l), isLink, now);
    const taint = readRecords(taintFile(l), isTaint);
    if (taint.damaged) return [{ type: "taint", source: "the browser link's taint record could not be read" }];
    const reasons = [...new Set(taint.records.filter((x) => within(x.ts, now)).map((x) => x.reason))];
    return reasons.slice(0, 5).map((r) => ({ type: "taint", source: taintSource(r) }));
  } catch (e) {
    return [{ type: "taint", source: `the browser link's state could not be read (${(e as Error).message.slice(0, 120)})` }];
  }
}

/** Agent sessions linked to the browser within the window. A damaged links file links nothing (it is reported by the host). */
export function linkedSessions(l: Layout, now = new Date()): string[] {
  const links = readRecords(linksFile(l), isLink);
  return [...new Set(links.records.filter((x) => within(x.ts, now)).map((x) => x.session))];
}

/**
 * The browser said its agent session read outside content: recorded, and every linked agent session is
 * tainted now. Returns how many agent sessions were tainted.
 */
export function recordBrowserTaint(l: Layout, browserSession: string, reason: string, now = new Date()): number {
  ensureDir(dir(l));
  // Under the lock compact takes, so a record appended during a compaction is not lost with the old file.
  withLock(`${taintFile(l)}.lock`, () => appendDurable(taintFile(l), `${JSON.stringify({ ts: now.toISOString(), session: browserSession, reason } satisfies Taint)}\n`));
  compact(taintFile(l), isTaint, now);
  const sessions = linkedSessions(l, now);
  for (const s of sessions) appendEvents(l, s, [{ type: "taint", source: taintSource(reason) }]);
  return sessions.length;
}

/** Linked agent sessions that are tainted (what the host reports to the browser). */
export function taintedLinkedSessions(l: Layout, now = new Date()): string[] {
  const out: string[] = [];
  for (const s of linkedSessions(l, now)) {
    try {
      if (loadState(l, s).tainted) out.push(s);
    } catch {
      // Unreadable state is untrusted.
      out.push(s);
    }
  }
  return out;
}

/** For doctor and tests: the files exist and parse. */
export function linkStateProblems(l: Layout): string[] {
  const out: string[] = [];
  try {
    readdirSync(dir(l));
  } catch {
    return out;
  }
  if (readRecords(linksFile(l), isLink).damaged) out.push(`${linksFile(l)} has unreadable lines (sessions it named are not linked)`);
  if (readRecords(taintFile(l), isTaint).damaged) out.push(`${taintFile(l)} has unreadable lines (every session that links is treated as tainted)`);
  return out;
}
