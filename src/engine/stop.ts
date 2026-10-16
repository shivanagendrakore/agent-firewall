/**
 * The kill switch, as the engine sees it. A person (`launchsafe-firewall
 * session stop <session>`, `agent stop <agentId>`) or the behaviour monitor
 * (FW-LOOP's stop limits, src/engine/budgets.ts) stops a session or every
 * session of an agent; until a person resumes it, every action of that
 * session is denied (FW-STOPPED). The runtime keeps the records
 * (src/runtime/stops.ts) and hands decide() what is in force; this module is
 * pure.
 */

import type { MonitorSignal } from "./budgets.js";

/** One stop in force. */
export interface StopState {
  /** The stop record's id (a resume names it, so an old resume never clears a newer stop). */
  id: string;
  /** When it was made (ISO 8601). */
  at: string;
  /** "person": the stop command; "monitor": the behaviour monitor; "unreadable": the record cannot be read (fail closed). */
  by: "person" | "monitor" | "unreadable";
  scope: "session" | "agent";
  /** The session id or the agent id. */
  target: string;
  /** The person's note, the monitor's fixed reason, or why the record cannot be read. */
  reason: string;
  signal?: MonitorSignal;
}

/** What decide() is told about stops for this session. */
export interface StopView {
  /** The stop in force (the session's own first, then its agent's), or null. */
  active: StopState | null;
  /** The last time a person resumed this session or its agent (ms): the monitor counts only after it. */
  resumedAt?: number;
}

/** The reason an action in a stopped session is denied with. */
export function stoppedReason(s: StopState, session: string): string {
  const what = s.scope === "agent" ? `every session of agent ${s.target} was stopped` : "this session was stopped";
  const who = s.by === "person" ? "by a person" : s.by === "monitor" ? "by the behaviour monitor" : "and its stop record cannot be read, so it stays stopped";
  const note = s.reason !== "" ? ` (${s.reason})` : "";
  const resume = s.scope === "agent" ? `launchsafe-firewall agent resume ${s.target}` : `launchsafe-firewall session resume ${session}`;
  return `${what} ${who}${s.at !== "" ? ` at ${s.at}` : ""}${note}; every action is blocked until a person resumes it in their own terminal (${resume}, with the approval passphrase)`;
}

/** A monitor stop's id: unique per stop (a resume names the id it ends, so a later stop is never covered by it). */
export function monitorStopId(now: Date, actionHash: string): string {
  return `m${now.getTime().toString(36)}${actionHash.slice(0, 10)}`;
}
