/**
 * What a person reads in the terminal: the morning queue, a proposed change as
 * a diff, and the status overview. Pure formatting (no I/O), so every layout
 * rule is tested: text wraps on word boundaries to the terminal width and is
 * never cut mid-word (a single word longer than the width gets its own line).
 * R6: everything returned passes through safeText: proposal content, reasons, summaries and previews
 * are agent- or repository-written, and must not drive the person's terminal.
 */

import { describeSource, ruleSentence, summarizeAction } from "../engine/summary.js";
import { safeText } from "../engine/terminal.js";
import type { QueueItem, SessionSummary } from "./store.js";

/** Wraps text to width columns on spaces. Never splits a word; existing newlines are kept. */
export function wrap(text: string, width: number, indent = ""): string[] {
  const out: string[] = [];
  const room = Math.max(10, width - indent.length);
  for (const para of text.split("\n")) {
    const words = para.split(/ +/).filter((w) => w !== "");
    if (words.length === 0) {
      out.push(indent.trimEnd());
      continue;
    }
    let line = "";
    for (const w of words) {
      if (line === "") line = w;
      else if (line.length + 1 + w.length <= room) line += ` ${w}`;
      else {
        out.push(indent + line);
        line = w;
      }
    }
    out.push(indent + line);
  }
  return out;
}

/** "3:14 AM" today, "yesterday 3:14 AM", or "Oct 8, 3:14 AM", in local time. */
export function localTime(d: Date, now: Date = new Date()): string {
  const time = d.toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" });
  const day = (x: Date): number => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((day(now) - day(d)) / 86400000);
  if (diff === 0) return time;
  if (diff === 1) return `yesterday ${time}`;
  return `${d.toLocaleDateString("en-US", { month: "short", day: "numeric" })}, ${time}`;
}

export function itemSummary(it: QueueItem): string {
  if (it.summary !== undefined && it.summary !== "") return it.summary;
  const input = typeof it.input === "object" && it.input !== null ? (it.input as Record<string, unknown>) : {};
  return summarizeAction(it.tool, input, it.cwd);
}

export interface FormatOptions {
  width: number;
  now?: Date;
}

/** The morning summary of everything waiting for a person. */
export function formatQueue(items: readonly QueueItem[], o: FormatOptions): string {
  const pending = items.filter((i) => i.status === "pending");
  const now = o.now ?? new Date();
  if (pending.length === 0) return "Nothing is waiting for you.";
  const n = pending.length;
  const plural = n === 1 ? "action" : "actions";
  const away = pending.every((i) => i.unattended === true || i.kind === "proposal");
  const lines: string[] = [`${n} ${plural} held ${away ? "while you were away" : "for your review"}`, ""];
  for (const it of pending) {
    const kind = it.kind === "proposal" ? "proposed change" : "needs approval";
    // The action code is what the phone shows for an approval item (the first 6 characters of the action hash):
    // it lets a person match the phone to this line.
    lines.push(...wrap(`${it.id} · code ${it.actionHash.slice(0, 6)} · ${localTime(new Date(it.createdAt), now)} · ${kind}`, o.width));
    lines.push(...wrap(itemSummary(it), o.width, "  "));
    lines.push(...wrap(ruleSentence(it.rules, it.reasons), o.width, "  "));
    const src = it.trustSources?.[it.trustSources.length - 1];
    if (src !== undefined) lines.push(...wrap(`after reading: ${describeSource(src)}`, o.width, "  "));
    lines.push("");
  }
  lines.push(...wrap("Review them one by one: launchsafe-firewall queue review", o.width));
  lines.push(...wrap("Details and proposed changes: launchsafe-firewall queue show <id>", o.width));
  return safeText(lines.join("\n"));
}

/**
 * The most characters (before and after together) lineDiff compares. Beyond it the comparison itself
 * (every pair of long lines) would cost more than the review is worth, so the change shows as a full
 * replacement, as it does past the line-count limit.
 */
export const MAX_DIFF_CHARS = 2 * 1024 * 1024;

/** A line diff (longest common subsequence). Small inputs only; big ones show as a full replacement. */
export function lineDiff(before: string, after: string): string[] {
  // A file's final newline is not a line of its own.
  const lines = (t: string): string[] => (t === "" ? [] : t.replace(/\n$/, "").split("\n"));
  const a = lines(before);
  const b = lines(after);
  if (before.length + after.length > MAX_DIFF_CHARS || a.length * b.length > 4_000_000) return [...a.map((x) => `- ${x}`), ...b.map((x) => `+ ${x}`)];
  const lcs: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) for (let j = b.length - 1; j >= 0; j--) lcs[i]![j] = a[i] === b[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
  const out: string[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      out.push(`  ${a[i]}`);
      i++;
      j++;
    } else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) out.push(`- ${a[i++]}`);
    else out.push(`+ ${b[j++]}`);
  }
  while (i < a.length) out.push(`- ${a[i++]}`);
  while (j < b.length) out.push(`+ ${b[j++]}`);
  return out;
}

/** F12: every part of a multi-action call; approving lets all of them run, so all of them are shown. */
export function formatParts(it: QueueItem): string[] {
  const parts = it.parts ?? [];
  if (parts.length <= 1) return [];
  const out = ["", `This one call does ${parts.length} things, and approving it lets all of them run:`];
  parts.forEach((p, i) => {
    out.push("", `${i + 1}. ${p.tool} ${p.target}${p.held === true ? " (held)" : ""}`);
    out.push(...p.change.split("\n").map((x) => `   ${x}`.trimEnd()));
  });
  return out;
}

/**
 * A proposal's change as diff lines ("  ", "- ", "+ " prefixes) against the file as it is now. Shared by
 * `queue show` and the dashboard's side-by-side view, so both show the change the approval would apply.
 */
export function proposalDiff(it: QueueItem, currentContent: string | null): string[] {
  const pr = it.proposal;
  if (pr === undefined) return [];
  if (pr.edits !== undefined) {
    const current = currentContent;
    // R19: replace_all (stored with the edit, or on the held input) replaces every occurrence, as the approved action will.
    const input = typeof it.input === "object" && it.input !== null ? (it.input as Record<string, unknown>) : {};
    const inputEdits = Array.isArray(input.edits) ? (input.edits as Record<string, unknown>[]) : [input];
    const all = (i: number): boolean => pr.edits?.[i]?.all === true || inputEdits[i]?.replace_all === true;
    if (current !== null && pr.edits.every((e) => current.includes(e.old))) {
      let next = current;
      pr.edits.forEach((e, i) => {
        // A function replacement: "$&" or "$1" in the new text is literal, as in the Edit tool.
        next = all(i) ? next.split(e.old).join(e.new) : next.replace(e.old, () => e.new);
      });
      return lineDiff(current, next);
    }
    return pr.edits.flatMap((e) => [...lineDiff(e.old, e.new)]);
  }
  if (pr.content !== undefined) return lineDiff(currentContent ?? "", pr.content);
  return pr.change.split("\n").map((x) => `  ${x}`);
}

/** One item in full. A proposed change is shown as a diff against the file as it is now. */
export function formatShow(it: QueueItem, o: FormatOptions & { currentContent?: string | null }): string {
  const now = o.now ?? new Date();
  const lines: string[] = [];
  lines.push(...wrap(`${it.id} · ${localTime(new Date(it.createdAt), now)} · ${it.kind === "proposal" ? "proposed change" : "needs approval"} (${it.status})`, o.width));
  lines.push(...wrap(itemSummary(it), o.width, "  "));
  lines.push(...wrap(ruleSentence(it.rules, it.reasons), o.width, "  "));
  for (const s of it.trustSources ?? []) lines.push(...wrap(`after reading: ${describeSource(s)}`, o.width, "  "));
  lines.push("", "Why, in full:");
  for (const r of it.reasons) lines.push(...wrap(`- ${r}`, o.width, "  "));
  const pr = it.proposal;
  if (pr !== undefined) {
    lines.push("", `Proposed change to ${pr.target}:`);
    const diff = proposalDiff(it, o.currentContent ?? null);
    // Diff lines are code: never re-wrapped, so nothing in them is cut or reflowed.
    lines.push(...diff.map((x) => x.trimEnd()));
    lines.push(...formatParts(it));
    lines.push("", ...wrap(`Nothing was written. To apply it as proposed: launchsafe-firewall queue approve ${it.id} (then ask the agent to try again)`, o.width));
  } else {
    lines.push("", "Input:", JSON.stringify(it.input, null, 2));
    lines.push(...formatParts(it));
    if (it.status === "pending") lines.push("", ...wrap(`To allow this exact action once: launchsafe-firewall queue approve ${it.id}`, o.width));
  }
  return safeText(lines.join("\n"));
}

export interface StatusData {
  version: string;
  stateDir: string;
  installedIn: string[];
  sessions: readonly SessionSummary[];
  held: number;
  unattended: { on: boolean; why: string };
  /** When the last desktop notification was shown (epoch ms), or null if none was. Optional for older callers. */
  lastNotification?: number | null;
  decisions: { allow: number; ask: number; queue: number; deny: number; total: number };
  /** F-d: new sessions proposed by agents (the desktop task chip) in the recent log, newest last. */
  proposedSessions?: { session: string; preview: string }[];
}

export function formatStatus(d: StatusData, o: FormatOptions): string {
  const now = o.now ?? new Date();
  const lines: string[] = [];
  lines.push(`LaunchSafe Firewall ${d.version}`);
  lines.push(...wrap(`Installed in: ${d.installedIn.length === 0 ? "nowhere (run launchsafe-firewall install)" : d.installedIn.join(", ")}`, o.width));
  lines.push(...wrap(`Unattended mode: ${d.unattended.on ? "on" : "off"} (${d.unattended.why})`, o.width));
  lines.push(`Held for you: ${d.held}${d.held > 0 ? " (launchsafe-firewall queue)" : ""}`);
  if (d.lastNotification !== undefined) lines.push(`Last desktop notification: ${d.lastNotification === null ? "none yet" : localTime(new Date(d.lastNotification), now)}`);
  lines.push("", d.sessions.length === 0 ? "No recent sessions." : "Recent sessions:");
  for (const s of d.sessions) {
    const head = `${s.id.slice(0, 12)} · last active ${localTime(s.lastActivity, now)} · ${s.trusted ? "trusted" : "UNTRUSTED"}${s.sensitive ? ", has read private data" : ""}`;
    lines.push(...wrap(head, o.width, "  "));
    if (s.canary) lines.push(...wrap("canary tripped in this session: it touched a decoy file you planted, so every send in it needs you", o.width, "    "));
    if (s.unattended !== null) lines.push(...wrap(`ran unattended (${s.unattended}): risky actions were held, not asked`, o.width, "    "));
    if (!s.trusted) {
      const since = s.untrustedSince !== null ? `since ${localTime(s.untrustedSince, now)}` : "since an earlier action";
      lines.push(...wrap(`${since}, after reading: ${s.firstSource !== null ? describeSource(s.firstSource) : "outside content"}`, o.width, "    "));
    }
  }
  const t = d.decisions;
  lines.push("", ...wrap(`Last ${t.total} decisions: ${t.allow} allowed, ${t.ask} asked, ${t.queue} held, ${t.deny} blocked`, o.width));
  const proposed = d.proposedSessions ?? [];
  if (proposed.length > 0) {
    lines.push(...wrap(`Sessions proposed by an agent (start only if you want them): ${proposed.length}`, o.width));
    for (const p of proposed.slice(-3)) lines.push(...wrap(`${p.session.slice(0, 12)} proposed: ${p.preview.replace(/\s+/g, " ").slice(0, 120)}`, o.width, "  "));
  }
  lines.push(...wrap(`State: ${d.stateDir}`, o.width));
  return safeText(lines.join("\n"));
}

/** The terminal width to wrap to: the terminal's, else $COLUMNS, else 80. */
export function terminalWidth(stdoutColumns: number | undefined, env: NodeJS.ProcessEnv = process.env): number {
  if (stdoutColumns !== undefined && stdoutColumns > 0) return stdoutColumns;
  const c = Number(env.COLUMNS);
  return Number.isFinite(c) && c > 0 ? c : 80;
}
