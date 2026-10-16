/**
 * "Fewer prompts": `friction` (what the firewall asked, from the decision log) and the `allow` commands
 * (the person's learned choices for one exact action in one project). `allow add` makes the firewall stop
 * asking about a low-risk action a person approved repeatedly; it runs only for a person (a real terminal,
 * not under an agent) and needs the approval passphrase, which signs the choice. `allow never` and
 * `allow remove` of an "always" only tighten; removing a "never" loosens, so it needs the passphrase too.
 * The engine refuses every changing command from inside an agent (changesState: FW-TAMPER).
 *
 * Every dependency that touches the terminal comes in through LearnedCliDeps, so tests run the real
 * handlers with scripted input.
 */

import type { Parsed } from "./cliargs.js";
import type { Layout } from "./runtime/layout.js";
import { learnedPolicy } from "./policy-learned.js";
import { rulesEligibility } from "./engine/learn.js";
import { safeLine } from "./engine/terminal.js";

type Ok = Extract<Parsed, { kind: "ok" }>;

export interface LearnedCliDeps {
  out: (s: string) => void;
  err: (s: string) => void;
  humanAtKeyboard: () => Promise<boolean>;
  /** Reads a line with echo off (the passphrase). */
  readSecret: (prompt: string) => Promise<string>;
  /** Reads a line with echo on (a "yes" confirmation). */
  ask: (prompt: string) => Promise<string>;
  cwd: string;
  width: number;
}

function flag(p: Ok, name: string): boolean {
  return p.flags.get(name) === true;
}

function opt(p: Ok, name: string): string | undefined {
  const v = p.flags.get(name);
  return typeof v === "string" ? v : undefined;
}

async function confirm(d: LearnedCliDeps, q: string): Promise<boolean> {
  return (await d.ask(`${q} Type "yes": `)).trim().toLowerCase() === "yes";
}

async function friction(p: Ok, l: Layout, d: LearnedCliDeps): Promise<number> {
  const { frictionReport, formatFriction } = await import("./runtime/friction.js");
  const { loadPolicy } = await import("./runtime/config.js");
  const days = opt(p, "--days");
  const proposeAfter = learnedPolicy(loadPolicy(l, [d.cwd]).config).proposeAfter;
  const r = frictionReport(l, { proposeAfter, ...(days !== undefined ? { days: Number(days) } : {}) });
  d.out(flag(p, "--json") ? JSON.stringify(r, null, 2) : formatFriction(r, d.width));
  return 0;
}

/** One line of an action, safe to print: agent-written text with control characters shown, one line. */
const shown = (c: { summary: string; tool: string }): string => safeLine(c.summary !== "" ? c.summary : c.tool);

async function allowList(p: Ok, l: Layout, d: LearnedCliDeps): Promise<number> {
  const { readEntries, readNevers, readCandidates, projectId, entrySigned } = await import("./runtime/learned.js");
  const { trustedApproverKey } = await import("./hook/pipeline.js");
  const { loadPolicy } = await import("./runtime/config.js");
  const all = flag(p, "--all");
  const project = projectId(opt(p, "--project") ?? d.cwd);
  const key = trustedApproverKey(l, process.env);
  const { entries, damaged } = readEntries(l);
  const nevers = readNevers(l);
  // A "never" kept only in nevers.json (allows.json damaged) still applies, so it is listed too.
  const merged = [...entries, ...nevers.entries.filter((n) => !entries.some((e) => e.project === n.project && e.key === n.key))];
  const mine = merged.filter((e) => all || e.project === project);
  const lp = learnedPolicy(loadPolicy(l, [project]).config);
  const ready = readCandidates(l).filter((c) => (all || c.project === project) && c.eligible && c.identity !== null && lp.enabled && c.approved >= lp.proposeAfter && !merged.some((e) => e.project === c.project && e.key === c.key));
  if (flag(p, "--json")) {
    d.out(JSON.stringify({ project: all ? null : project, enabled: lp.enabled, proposeAfter: lp.proposeAfter, damaged: damaged || nevers.damaged, choices: mine.map((e) => ({ ...e, signed: entrySigned(e, key) })), ready: ready.map((c) => ({ code: c.code, project: c.project, tool: c.tool, summary: c.summary, rules: c.rules, approved: c.approved, approvedAt: c.approvedAt })) }, null, 2));
    return 0;
  }
  if (damaged || nevers.damaged) d.err(`The learned choices file is damaged: no "always" choice applies until it is repaired ("never" choices still do). Remove bad entries with "launchsafe-firewall allow remove <id>", or move the file aside.`);
  d.out(all ? "Learned choices in every project:" : `Learned choices for ${safeLine(project)}:`);
  if (!lp.enabled) d.out("  Learned allows are switched off by your policy (learnedAllows.enabled); \"never\" choices still apply.");
  if (mine.length === 0) d.out("  none.");
  for (const e of mine) {
    const state = e.kind === "never" ? "never" : !damaged && entrySigned(e, key) && rulesEligibility(e.rules).eligible ? "always" : "always (NOT APPLIED: the file is damaged, its signature does not verify, or its rules are no longer learnable)";
    d.out(`  ${e.id}  ${state}  ${shown(e)}${all ? `  in ${safeLine(e.project)}` : ""}  (${safeLine(e.rules.join(", "))}; chosen ${e.createdAt.slice(0, 10)} after ${e.approvals} approvals)`);
  }
  if (ready.length > 0) {
    d.out("\nReady for \"always in this project\" (low-risk, and you approved it enough times):");
    for (const c of ready) d.out(`  ${c.code}  ${shown(c)}${all ? `  in ${safeLine(c.project)}` : ""}  (approved ${c.approved} times, on ${[...new Set(c.approvedAt.map((x) => x.slice(0, 10)))].join(", ")}): launchsafe-firewall allow add ${c.code}`);
  }
  d.out("\nAn \"always\" applies only to that exact action and tool, only in a session someone is attending that has read no outside content and holds no private data. A repository checked out again at the same path keeps the choices made for that path. Remove one with: launchsafe-firewall allow remove <id>");
  return 0;
}

async function allowAdd(p: Ok, l: Layout, d: LearnedCliDeps): Promise<number> {
  const { getCandidate, saveEntry, learnedDir, readNevers } = await import("./runtime/learned.js");
  const { approverPublicKey, unlockApprover, signLearned, learnedSealer } = await import("./runtime/approver.js");
  const { loadPolicy } = await import("./runtime/config.js");
  const { appendLog } = await import("./runtime/log.js");
  const { assertNotRealHome } = await import("./runtime/guard.js");
  assertNotRealHome(learnedDir(l));
  if (!(await d.humanAtKeyboard())) return 1;
  const code = p.positionals[0] ?? "";
  const c = getCandidate(l, code);
  if (c === null) {
    d.err(`No asked action has the code "${safeLine(code)}". Codes are shown when the firewall asks, and by "launchsafe-firewall friction".`);
    return 1;
  }
  const lp = learnedPolicy(loadPolicy(l, [c.project]).config);
  if (!lp.enabled) {
    d.err("Learned allows are switched off by your policy (learnedAllows.enabled), so this cannot be added.");
    return 1;
  }
  const byRules = rulesEligibility(c.rules);
  if (!c.eligible || !byRules.eligible || c.identity === null) {
    d.err(`"Always in this project" is not offered for this action, because ${safeLine(!byRules.eligible ? byRules.why : (c.why ?? "the tool has no identity it could be bound to"))}. Approve it once each time instead.`);
    return 1;
  }
  if (c.approved < lp.proposeAfter) {
    d.err(`You have approved this action ${c.approved} time${c.approved === 1 ? "" : "s"} in this project; "always" is offered after ${lp.proposeAfter}.`);
    return 1;
  }
  if (approverPublicKey(l) === null) {
    d.err('No approval passphrase is set, so the choice could not be signed. Run "launchsafe-firewall approver init" first.');
    return 1;
  }
  const never = readNevers(l).entries.find((e) => e.project === c.project && e.key === c.key);
  d.out(`Project: ${safeLine(c.project)}\nAction:  ${shown(c)}\nRules:   ${safeLine(c.rules.join(", "))}\nYou approved it ${c.approved} times here, on ${[...new Set(c.approvedAt.map((x) => x.slice(0, 10)))].join(", ")}.`);
  if (never !== undefined) d.out(`This replaces your "never" choice for it (${never.id}, made ${never.createdAt.slice(0, 10)}).`);
  d.out("From now on it runs without asking in this project, but only this exact action of this exact tool, and only in a session someone is attending that has read no outside content and holds no private data.");
  const priv = unlockApprover(l, await d.readSecret("Approval passphrase: "));
  if (!(await confirm(d, "Always allow this exact action in this project?"))) {
    d.out("Nothing changed.");
    return 1;
  }
  const createdAt = new Date().toISOString();
  // M1: the rules are signed with the choice, and the whole set is sealed with the key.
  const fields = { kind: "allow" as const, id: c.code, project: c.project, key: c.key, identity: c.identity, tool: c.tool, createdAt, rules: c.rules };
  const sig = signLearned(priv, fields);
  saveEntry(l, { version: 1, ...fields, summary: c.summary, rules: c.rules, approvals: c.approved, sig }, { seal: learnedSealer(priv) });
  appendLog(l, { type: "learned_choice", change: "always", id: c.code, project: c.project, key: c.key, identity: c.identity, tool: c.tool, rules: c.rules, approvals: c.approved, ...(never !== undefined ? { replaced: "never" } : {}), sig });
  d.out(`Done: always allowed in this project (${c.code}). Undo it with: launchsafe-firewall allow remove ${c.code}`);
  return 0;
}

async function allowNever(p: Ok, l: Layout, d: LearnedCliDeps): Promise<number> {
  const { getCandidate, saveEntry, learnedDir, readEntries } = await import("./runtime/learned.js");
  const { approverPublicKey, unlockApprover, signLearned, learnedSealer } = await import("./runtime/approver.js");
  const { appendLog } = await import("./runtime/log.js");
  const { assertNotRealHome } = await import("./runtime/guard.js");
  assertNotRealHome(learnedDir(l));
  if (!(await d.humanAtKeyboard())) return 1;
  const code = p.positionals[0] ?? "";
  const c = getCandidate(l, code);
  if (c === null) {
    d.err(`No asked action has the code "${safeLine(code)}". Codes are shown when the firewall asks, and by "launchsafe-firewall friction".`);
    return 1;
  }
  const always = readEntries(l).entries.find((e) => e.project === c.project && e.key === c.key && e.kind === "allow");
  d.out(`Project: ${safeLine(c.project)}\nAction:  ${shown(c)}`);
  if (always !== undefined) d.out(`This replaces your "always" choice for it (${always.id}).`);
  // A "never" is signed when a passphrase is set, like every other choice.
  const priv = approverPublicKey(l) !== null ? unlockApprover(l, await d.readSecret("Approval passphrase: ")) : null;
  if (!(await confirm(d, "Never allow this exact action in this project (it is blocked from now on)?"))) {
    d.out("Nothing changed.");
    return 1;
  }
  const createdAt = new Date().toISOString();
  const fields = { kind: "never" as const, id: c.code, project: c.project, key: c.key, identity: "", tool: c.tool, createdAt, rules: c.rules };
  const sig = priv !== null ? signLearned(priv, fields) : undefined;
  saveEntry(l, { version: 1, ...fields, summary: c.summary, rules: c.rules, approvals: c.approved, ...(sig !== undefined ? { sig } : {}) }, priv !== null ? { seal: learnedSealer(priv) } : {});
  appendLog(l, { type: "learned_choice", change: "never", id: c.code, project: c.project, key: c.key, tool: c.tool, rules: c.rules, ...(always !== undefined ? { replaced: "always" } : {}), ...(sig !== undefined ? { sig } : {}) });
  d.out(`Done: never allowed in this project (${c.code}). Undo it with: launchsafe-firewall allow remove ${c.code}`);
  return 0;
}

async function allowRemove(p: Ok, l: Layout, d: LearnedCliDeps): Promise<number> {
  const { readEntries, readNevers, removeEntry, learnedDir } = await import("./runtime/learned.js");
  const { approverPublicKey, unlockApprover, learnedSealer } = await import("./runtime/approver.js");
  const { appendLog } = await import("./runtime/log.js");
  const { assertNotRealHome } = await import("./runtime/guard.js");
  assertNotRealHome(learnedDir(l));
  if (!(await d.humanAtKeyboard())) return 1;
  const id = p.positionals[0] ?? "";
  const e = readEntries(l).entries.find((x) => x.id === id) ?? readNevers(l).entries.find((x) => x.id === id);
  if (e === undefined) {
    d.err(`No learned choice "${safeLine(id)}". Run: launchsafe-firewall allow list --all`);
    return 1;
  }
  d.out(`Project: ${safeLine(e.project)}\nAction:  ${shown(e)}\nChoice:  ${e.kind === "allow" ? "always" : "never"}`);
  // Removing "never" lets the action be asked again (a loosening), so it needs the person's passphrase; M1: any
  // removal does when a passphrase is set, so the set stays sealed (a removal without it would look like tampering).
  const priv = approverPublicKey(l) !== null ? unlockApprover(l, await d.readSecret("Approval passphrase: ")) : null;
  if (!(await confirm(d, "Remove this choice?"))) {
    d.out("Nothing changed.");
    return 1;
  }
  removeEntry(l, id, priv !== null ? { seal: learnedSealer(priv) } : {});
  appendLog(l, { type: "learned_choice", change: "removed", id: e.id, kind: e.kind, project: e.project, key: e.key, tool: e.tool });
  d.out(e.kind === "allow" ? "Removed: the firewall asks about this action again." : "Removed: this action is judged by the rules again.");
  return 0;
}

export const LEARNED_HANDLERS: Record<string, (p: Ok, l: Layout, d: LearnedCliDeps) => Promise<number>> = {
  friction,
  "friction report": friction,
  allow: allowList,
  "allow list": allowList,
  "allow add": allowAdd,
  "allow never": allowNever,
  "allow remove": allowRemove,
};
