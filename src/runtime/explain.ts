/**
 * `launchsafe-firewall explain <id>`: what a rule, a held item, a logged
 * decision, an agent-safety rule or a finding means, in plain words. Reads
 * only; the text comes from the rule catalogue (src/rules.ts).
 */

import { frameworkName } from "../frameworks.js";
import { FINDING_RULES, INCIDENT_NAMES, ruleDoc, type RuleDoc } from "../rules.js";
import { AGENT_SAFETY_RULES } from "../vendor/agent-safety-rules.js";
import { readText } from "./fsutil.js";
import type { Layout } from "./layout.js";
import { tailLog, type LogEntry } from "./log.js";
import { formatShow, terminalWidth, wrap } from "./report.js";
import { getQueueItem } from "./store.js";
import { own } from "../own.js";

export interface ExplainOptions {
  json: boolean;
  width?: number | undefined;
  /** The log entry for a numeric id, when the caller already has it (the dashboard reads one line, not the whole log). */
  entry?: LogEntry | undefined;
}

const OUTCOME_WORDS: Record<string, string> = {
  allow: "allowed",
  approve: "needs you (asked, or queued when no one is there)",
  hold: "kept as a proposal for you to review",
  deny: "denied, cannot be approved from inside the agent",
  "n/a": "no",
};

function mapLine(d: RuleDoc): string {
  const parts: string[] = [];
  if (d.owaspLlm.length > 0) parts.push(`OWASP LLM ${d.owaspLlm.join(", ")}`);
  if (d.owaspAgentic.length > 0) parts.push(`OWASP Agentic ${d.owaspAgentic.join(", ")}`);
  const named = (ids: readonly string[]): string => ids.map((id) => `${id} ${frameworkName(id) ?? ""}`.trim()).join("; ");
  if (d.atlas.length > 0) parts.push(`MITRE ATLAS: ${named(d.atlas)}`);
  if (d.attack.length > 0) parts.push(`ATT&CK: ${named(d.attack)}`);
  if (d.mcpSpec.length > 0) parts.push(`MCP: ${d.mcpSpec.join("; ")}`);
  return parts.join(" · ");
}

/** The rule page, plain text. */
export function formatRule(d: RuleDoc, width: number): string {
  const L: string[] = [];
  const add = (label: string, text: string): void => {
    if (text !== "") L.push(...wrap(`${label}: ${text}`, width));
  };
  L.push(`${d.id}  ${d.title}${d.status === "planned" ? ` (planned: v0.2 item ${d.item ?? ""})` : ""}`);
  add("What it stops", d.why);
  const when = d.alwaysOn
    ? `always on (trusted or not): ${OUTCOME_WORDS[d.outcome.untrusted] ?? d.outcome.untrusted}`
    : `trusted session: ${OUTCOME_WORDS[d.outcome.trusted] ?? d.outcome.trusted} · untrusted: ${OUTCOME_WORDS[d.outcome.untrusted] ?? d.outcome.untrusted}`;
  add("When it applies", `${when}${d.outcome.unattended === "queue" ? " · unattended: queued for you" : ""}`);
  add("Can you approve it", d.approvableWhen !== undefined ? `${d.approvableWhen}${d.approvable ? `: ${d.approveHow ?? "launchsafe-firewall queue approve <id>"}` : ""}` : d.approvable ? `yes, once, for that exact action: ${d.approveHow ?? "launchsafe-firewall queue approve <id>"}` : "no; it cannot be approved from inside the agent. If you really intend it, run it yourself outside the agent.");
  add("Settings that change it", d.policyKeys.length > 0 ? d.policyKeys.join(", ") : "none");
  if (d.examples.length > 0) {
    L.push("Examples:");
    for (const e of d.examples) L.push(...wrap(`- ${e.action} (${e.state}): ${e.verdict}${e.row !== undefined ? ` [${e.row}]` : ""}`, width, "  "));
  }
  add("Public incidents", d.incidents.map((i) => `${i} ${own(INCIDENT_NAMES, i) ?? ""}`.trim()).join("; "));
  add("Maps to", mapLine(d));
  return L.join("\n");
}

/** One rule in a line or two. `held`: the rule held a queue item, which the person can approve whatever the rule's other outcomes. */
function shortRule(id: string, width: number, held = false): string[] {
  const d = ruleDoc(id);
  const fixed = !held && !d?.approvable && d?.approvableWhen === undefined;
  return d === null ? [`  ${id}`] : wrap(`${id}: ${d.sentence}${fixed ? " Cannot be approved from inside the agent." : ""}`, width, "  ");
}

/** What the task scope did to a logged decision (or, in log mode, would have done). */
function scopeLines(raw: unknown, width: number): string[] {
  if (typeof raw !== "object" || raw === null) return [];
  const sc = raw as { mode?: unknown; verdict?: unknown; changes?: unknown; reasons?: unknown };
  const reasons = Array.isArray(sc.reasons) ? sc.reasons.filter((r): r is string => typeof r === "string") : [];
  const verdict = String(sc.verdict ?? "");
  const head =
    sc.mode === "enforce"
      ? sc.changes === true ? `Task scope (enforced): it made this decision ${verdict}.` : "Task scope (enforced): it added reasons, the verdict was the same without it."
      : sc.changes === true ? `Task scope (log only, taskScope.mode "log"): enforcing it would have made this ${verdict}; nothing was changed.` : "Task scope (log only): enforcing it would not have changed this decision.";
  return [...wrap(head, width), ...reasons.flatMap((r) => wrap(`- FW-SCOPE: ${r}`, width, "  "))];
}

/** The text (or JSON) for an id, or null when nothing has that name. */
export function explainId(l: Layout, id: string, o: ExplainOptions): string | null {
  const width = terminalWidth(o.width);
  if (/^FW-[A-Z-]+$/.test(id)) {
    const d = ruleDoc(id);
    if (d === null) return null;
    return o.json ? JSON.stringify(d, null, 2) : formatRule(d, width);
  }
  if (id.startsWith("ls-agent-")) {
    const r = AGENT_SAFETY_RULES.find((x) => x.id === id);
    if (r === undefined) return null;
    if (o.json) return JSON.stringify(r, null, 2);
    return [`${r.id}  ${r.title}`, ...wrap(`Severity: ${r.severity}${r.cwe !== null ? ` (${r.cwe})` : ""} · family ${r.family}`, width), ...wrap(`Impact: ${r.impact}`, width), ...wrap(`Fix: ${r.fix}`, width), ...wrap("An agent-configuration check from the LaunchSafe agent-safety rules (vendored text). The firewall runs it at session start on the workspace's, your own and the administrator's agent files (and the files CLAUDE.md imports); a critical finding, or a high one under agentScan.taintOn \"high\", starts the session untrusted. Details: launchsafe-firewall doctor.", width)].join("\n");
  }
  const finding = own(FINDING_RULES, id);
  if (finding !== undefined) {
    if (o.json) return JSON.stringify({ finding: id, rule: finding, ruleDoc: ruleDoc(finding) }, null, 2);
    return [...wrap(`${id} is a finding (a fact the analyzer found in the action). It feeds ${finding}.`, width), "", formatRule(ruleDoc(finding) as RuleDoc, width)].join("\n");
  }
  if (/^\d+$/.test(id)) {
    const seq = Number(id);
    const entry = o.entry !== undefined && o.entry.seq === seq ? o.entry : tailLog(l, Number.MAX_SAFE_INTEGER).find((e) => e.seq === seq);
    if (entry === undefined) return null;
    if (o.json) return JSON.stringify({ entry, rules: (Array.isArray(entry.event.rules) ? (entry.event.rules as string[]) : []).map((r) => ruleDoc(r)) }, null, 2);
    const ev = entry.event;
    const rules = Array.isArray(ev.rules) ? (ev.rules as string[]) : [];
    const L = [`Log entry ${entry.seq} at ${entry.ts}: ${String(ev.type ?? "event")}`];
    if (ev.type === "decision") {
      L.push(...wrap(`${String(ev.tool ?? "")} in session ${String(ev.session ?? "")}: ${String(ev.verdict ?? "")}${typeof ev.what === "string" && ev.what !== "" ? ` (${ev.what})` : ""}`, width, "  "));
      if (typeof ev.queue === "string") L.push(...wrap(`Held as queue item ${ev.queue}: launchsafe-firewall explain ${ev.queue}`, width, "  "));
      if (rules.length === 0) L.push("  No rule fired: the action was allowed.");
      else {
        L.push("Rules:");
        for (const r of rules) L.push(...shortRule(r, width));
      }
      L.push(...scopeLines(ev.scope, width));
    } else L.push(JSON.stringify(ev));
    return L.join("\n");
  }
  if (/^[a-z0-9]{4,32}$/.test(id)) {
    const it = getQueueItem(l, id);
    if (it === null) return null;
    if (o.json) return JSON.stringify({ item: it, rules: it.rules.map((r) => ruleDoc(r)) }, null, 2);
    let current: string | null = null;
    try {
      current = it.proposal !== undefined && it.proposal.target.startsWith("/") ? readText(it.proposal.target) : null;
    } catch {
      current = null;
    }
    const L = [formatShow(it, { width, currentContent: current }), "", "Each rule in short:"];
    // R18: a queued item was held (approve or hold), never denied: each of its rules is approvable here.
    for (const r of it.rules) L.push(...shortRule(r, width, true));
    if ((it.trustSources ?? []).length > 0) {
      L.push("What made the session untrusted:");
      for (const s of it.trustSources ?? []) L.push(...wrap(`- ${s}`, width, "  "));
    }
    if (it.status === "pending") L.push("", ...wrap(`Approve: launchsafe-firewall queue approve ${it.id}    Reject: launchsafe-firewall queue reject ${it.id}`, width));
    return L.join("\n");
  }
  return null;
}

