/**
 * Copy and formatting for the side panel's log and settings view (leak lane).
 * Pure (no chrome.*, no DOM), so it is unit-tested in Node. Same copy rule as
 * view.ts: never say "protected"; say what is on.
 */
import type { AlwaysOnClass } from "../engine/types.js";
import type { ChainedEntry, LogVerifyReply } from "../shared/messages.js";

export const ALWAYS_ON_LABELS: Record<AlwaysOnClass, string> = {
  oauth_consent: "Granting an app access to an account (OAuth consent)",
  account_security: "Changing account security (password, MFA, recovery, forwarding, API keys)",
  download_exec: "Downloading programs and installers",
};

export function verifyLine(v: LogVerifyReply): string {
  if (v.count === 0 && v.brokenAt === null) return "The log is empty.";
  if (v.brokenAt === null) return `Chain intact: ${v.count} entr${v.count === 1 ? "y" : "ies"} verified.`;
  return `Chain broken at entry ${v.brokenAt}: the log was changed outside the extension.`;
}

const EVENT_LABELS: Record<NonNullable<ChainedEntry["event"]>, string> = {
  agent_mode_on: "Agent mode on",
  agent_mode_off: "Agent mode off",
  leak: "Data leaving a page",
  settings_changed: "Settings changed",
  link_taint: "A linked coding agent read outside content",
  log_cleared: "Log deleted (earlier entries removed)",
  quarantine: "Hidden instructions found on a page",
  log_throttled: "A page made too many decisions too fast; this many log entries were dropped",
};

/**
 * One log entry as a line of text. Entries hold no values; the only page text is kept evidence, already
 * escaped and cut to 200 characters by the log, and set with textContent by the caller.
 */
export function entryLine(e: ChainedEntry): string {
  const when = new Date(e.at).toISOString().replace("T", " ").slice(0, 19);
  const what = e.event !== undefined ? EVENT_LABELS[e.event] : (e.actionClass ?? "action").replace(/_/g, " ");
  const parts = [`#${e.seq}`, when, what];
  if (e.site !== "") parts.push(e.site);
  parts.push(e.verdict);
  if (e.rules.length > 0) parts.push(e.rules.join(", "));
  if (e.detail !== undefined && e.detail.length > 0) parts.push(`(${e.detail.join(", ")})`);
  if (e.approval !== undefined) parts.push(e.approval);
  if (e.evidence !== undefined && e.evidence !== "") parts.push(`evidence: "${e.evidence}"`);
  return parts.join(" · ");
}

export function refusedLine(refused: readonly string[]): string {
  return refused.length === 0 ? "" : `Not changed while agent mode is on: ${refused.join(", ")}. Turn agent mode off first.`;
}

export function exportFileName(now: number): string {
  return `launchsafe-browser-log-${new Date(now).toISOString().slice(0, 10)}.json`;
}
