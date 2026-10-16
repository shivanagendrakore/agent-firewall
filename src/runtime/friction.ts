/**
 * `launchsafe-firewall friction`: how often the firewall interrupted real work, read from the decision log
 * (and the learned-choice files for names and status). Read only. It answers: how many asks and holds,
 * by rule and by agent; which exact actions a person approved every time; which of those can become
 * "always in this project" and which never can (and why). See "Fewer prompts" in docs/usage.md.
 */

import { riskOf, rulesEligibility, type RiskClass } from "../engine/learn.js";
import type { Layout } from "./layout.js";
import { tailLog } from "./log.js";
import { readCandidates, readEntries } from "./learned.js";
import { wrap } from "./report.js";
import { redactSecrets } from "../engine/secrets.js";
import { safeLine } from "../engine/terminal.js";

/** The most log entries a report reads (the newest ones). */
export const MAX_REPORT_ENTRIES = 200_000;
/** Agent-written text, as the report shows it: secrets masked, one line, control characters escaped. */
const clean = (t: string): string => safeLine(redactSecrets(t).text).slice(0, 300);

export interface FrictionRule {
  rule: string;
  asked: number;
  held: number;
  denied: number;
  risk: RiskClass;
  learnable: boolean;
}

export interface FrictionAction {
  code: string;
  tool: string;
  what: string;
  /** Times the firewall asked or held it. */
  asked: number;
  /** Times a person said yes (an answered prompt, or a queue approval that ran). */
  approved: number;
  learnable: boolean;
  /** "always" or "never": a choice exists; "ready": it can be accepted now; "later": learnable, not enough approvals yet; "no": never offered. */
  status: "always" | "never" | "ready" | "later" | "no";
  why?: string;
}

export interface FrictionReport {
  since: string | null;
  decisions: number;
  allowed: number;
  asked: number;
  held: number;
  denied: number;
  /** Prompts a learned "always" saved. */
  learnedAllowed: number;
  byRule: FrictionRule[];
  byAgent: { agent: string; asked: number; held: number; denied: number }[];
  /** Actions asked about at least once and approved every time. */
  approvedEveryTime: FrictionAction[];
  proposeAfter: number;
}

/** Builds the report from the log. `days`: only entries this recent (default: everything the log holds). */
export function frictionReport(l: Layout, o: { days?: number; now?: Date; proposeAfter: number }): FrictionReport {
  const now = o.now ?? new Date();
  const since = o.days !== undefined ? new Date(now.getTime() - o.days * 86400000) : null;
  const entries = tailLog(l, MAX_REPORT_ENTRIES).filter((e) => since === null || Date.parse(e.ts) >= since.getTime());
  const rules = new Map<string, FrictionRule>();
  const agents = new Map<string, { agent: string; asked: number; held: number; denied: number }>();
  const actions = new Map<string, { tool: string; what: string; asked: number; learnable: boolean; rules: string[] }>();
  // Counted apart from the asks, so the order the log is read in does not matter.
  const approvals = new Map<string, number>();
  const approve = (code: string): void => void approvals.set(code, (approvals.get(code) ?? 0) + 1);
  const r: FrictionReport = { since: since?.toISOString() ?? null, decisions: 0, allowed: 0, asked: 0, held: 0, denied: 0, learnedAllowed: 0, byRule: [], byAgent: [], approvedEveryTime: [], proposeAfter: o.proposeAfter };
  for (const { event: ev } of entries) {
    const learn = typeof ev.learn === "string" ? ev.learn : undefined;
    if (ev.type === "ask_approved" && learn !== undefined) {
      approve(learn);
      continue;
    }
    if (ev.type !== "decision") continue;
    r.decisions += 1;
    const verdict = String(ev.verdict ?? "");
    const ruleIds = Array.isArray(ev.rules) ? ev.rules.filter((x): x is string => typeof x === "string") : [];
    const agent = typeof ev.agent === "string" ? clean(ev.agent).slice(0, 40) : "claude";
    if (verdict === "allow") {
      r.allowed += 1;
      if (ruleIds.includes("FW-LEARNED-ALLOW")) r.learnedAllowed += 1;
      if (ruleIds.includes("FW-APPROVED") && learn !== undefined) approve(learn);
      continue;
    }
    const k = verdict === "ask" ? "asked" : verdict === "queue" ? "held" : verdict === "deny" ? "denied" : null;
    if (k === null) continue;
    r[k] += 1;
    const ag = agents.get(agent) ?? { agent, asked: 0, held: 0, denied: 0 };
    ag[k] += 1;
    agents.set(agent, ag);
    for (const id of new Set(ruleIds)) {
      const x = rules.get(id) ?? { rule: clean(id).slice(0, 64), asked: 0, held: 0, denied: 0, risk: riskOf(id), learnable: riskOf(id) === "low" };
      x[k] += 1;
      rules.set(id, x);
    }
    if (k !== "denied" && learn !== undefined) {
      const a = actions.get(learn) ?? { tool: clean(String(ev.tool ?? "")), what: clean(String(ev.what ?? "")), asked: 0, learnable: false, rules: ruleIds };
      a.asked += 1;
      a.learnable = ev.learnable === true;
      a.rules = ruleIds;
      actions.set(learn, a);
    }
  }
  r.byRule = [...rules.values()].sort((a, b) => b.asked + b.held - (a.asked + a.held) || b.denied - a.denied || a.rule.localeCompare(b.rule));
  r.byAgent = [...agents.values()].sort((a, b) => b.asked + b.held - (a.asked + a.held) || a.agent.localeCompare(b.agent));
  const candidates = new Map(readCandidates(l).map((c) => [c.code, c]));
  const choices = new Map(readEntries(l).entries.map((e) => [e.id, e]));
  for (const [code, a] of actions) {
    const approved = approvals.get(code) ?? 0;
    if (a.asked === 0 || approved < a.asked) continue;
    const cand = candidates.get(code);
    const choice = choices.get(code);
    const byRules = rulesEligibility(a.rules);
    const why = cand?.why ?? (byRules.eligible ? undefined : byRules.why);
    const status: FrictionAction["status"] = choice !== undefined ? (choice.kind === "allow" ? "always" : "never") : !a.learnable ? "no" : approved >= o.proposeAfter ? "ready" : "later";
    r.approvedEveryTime.push({ code, tool: a.tool, what: cand !== undefined ? clean(cand.summary) : a.what, asked: a.asked, approved, learnable: a.learnable, status, ...(status === "no" && why !== undefined ? { why: clean(why) } : {}) });
  }
  r.approvedEveryTime.sort((a, b) => b.approved - a.approved || a.code.localeCompare(b.code));
  return r;
}

const pct = (n: number, d: number): string => (d === 0 ? "0%" : `${((100 * n) / d).toFixed(1)}%`);

/** The report as plain text. */
export function formatFriction(r: FrictionReport, width: number): string {
  const L: string[] = [];
  const prompts = r.asked + r.held;
  L.push(`Friction report${r.since !== null ? ` since ${r.since.slice(0, 10)}` : " (everything in the decision log)"}`);
  L.push("");
  if (r.decisions === 0) {
    L.push("No decisions are logged yet. Use your agent as usual and run this again.");
    return L.join("\n");
  }
  L.push(`${r.decisions} decisions: ${r.allowed} allowed quietly, ${r.asked} asked, ${r.held} held, ${r.denied} blocked.`);
  L.push(`Prompts (asked or held): ${prompts} of ${r.decisions} (${pct(prompts, r.decisions)}).${r.learnedAllowed > 0 ? ` Your "always in this project" choices saved ${r.learnedAllowed}.` : ""}`);
  if (r.byRule.length > 0) {
    L.push("", "By rule (asked / held / blocked), and whether \"always in this project\" can ever cover it:");
    // A table: wrap() would collapse the column padding.
    for (const x of r.byRule) L.push(`  ${x.rule.padEnd(24)} ${String(x.asked).padStart(4)} / ${String(x.held).padStart(4)} / ${String(x.denied).padStart(4)}   ${x.learnable ? "can be learned" : `never learned (${x.risk})`}`);
  }
  if (r.byAgent.length > 0) {
    L.push("", "By agent (asked / held / blocked):");
    for (const x of r.byAgent) L.push(`  ${x.agent.padEnd(10)} ${String(x.asked).padStart(4)} / ${String(x.held).padStart(4)} / ${String(x.denied).padStart(4)}`);
  }
  L.push("", `Approved every time (${r.approvedEveryTime.length}):`);
  if (r.approvedEveryTime.length === 0) L.push("  none yet.");
  for (const a of r.approvedEveryTime) {
    const status =
      a.status === "always" ? "always allowed in its project (your choice)"
        : a.status === "never" ? "never allowed in its project (your choice)"
          : a.status === "ready" ? `ready: launchsafe-firewall allow add ${a.code}`
            : a.status === "later" ? `offered after ${r.proposeAfter} approvals`
              : `not offered${a.why !== undefined ? `: ${a.why}` : ""}`;
    L.push(...wrap(`  ${a.code}  ${a.what !== "" ? a.what : a.tool}  (asked ${a.asked}, approved ${a.approved}): ${status}`, width, "      "));
  }
  L.push("", ...wrap("Only low-risk actions can become \"always in this project\", and never in a session that has read outside content or holds private data. See: launchsafe-firewall allow list", width));
  return L.join("\n");
}
