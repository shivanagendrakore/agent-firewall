/**
 * The known-hosts commands (knownHosts, docs/usage.md "Known hosts"). `hosts list` and `hosts review` only
 * read. `hosts allow`, `remove`, `accept` and `reset` change what the firewall lets the agent contact
 * without asking, so they run only for a person at the keyboard (and the engine refuses them from inside an
 * agent: changesState).
 */

import { resolve } from "node:path";
import type { Parsed } from "./cliargs.js";
import { BUILTIN_KNOWN_HOSTS, builtinsKnownThroughLists, learnableHost } from "./engine/knownhosts.js";
import { hostInList } from "./engine/network.js";
import { knownHostsPolicy } from "./policy-knownhosts.js";
import { loadPolicy } from "./runtime/config.js";
import { allowHosts, knownHostsFile, proposals, readKnownHosts, removeHosts, resetHosts, watchState, type SeenHost } from "./runtime/knownhosts.js";
import type { Layout } from "./runtime/layout.js";
import { appendBounded } from "./runtime/logbound.js";

type Ok = Extract<Parsed, { kind: "ok" }>;

export interface HostsCliDeps {
  out: (s: string) => void;
  err: (s: string) => void;
  humanAtKeyboard: () => Promise<boolean>;
  /** Reads the approval passphrase without echo (asked for allow and accept when one is set). */
  readSecret?: (prompt: string) => Promise<string>;
  cwd: string;
  now?: () => Date;
}

/**
 * `hosts allow` and `hosts accept` widen what the agent may contact without asking, so they need the approval
 * passphrase as well as a terminal when one is set (a script that reached the person's shell cannot widen them).
 */
async function passphraseIfSet(l: Layout, d: HostsCliDeps, what: string): Promise<boolean> {
  const { approverPublicKey, unlockApprover } = await import("./runtime/approver.js");
  let key: string | null;
  try {
    key = approverPublicKey(l);
  } catch {
    key = "unreadable";
  }
  if (key === null) return true;
  try {
    unlockApprover(l, await (d.readSecret ?? (() => Promise.reject(new Error("no terminal to read it from"))))("Approval passphrase: "));
    return true;
  } catch (e) {
    d.err(`launchsafe-firewall ${what}: the approval passphrase is needed for this (${(e as Error).message}).`);
    return false;
  }
}

function flag(p: Ok, name: string): boolean {
  return p.flags.get(name) === true;
}

function projectOf(p: Ok, d: HostsCliDeps): string {
  const v = p.flags.get("--project");
  return resolve(d.cwd, typeof v === "string" ? v : ".");
}

function modeLine(l: Layout, project: string): { line: string; off: boolean } {
  const pol = loadPolicy(l, [project]);
  const k = knownHostsPolicy(pol.config);
  const what = k.mode === "ask" ? "contacting a host not known here asks you once" : k.mode === "watch" ? `hosts contacted are recorded for ${k.watchDays} days for hosts review; nothing asks` : "nothing asks and nothing is recorded";
  const off = k.mode === "off" ? `\nTo use it, set "knownHosts": { "mode": "ask" } (or "watch" to learn first) in ${l.policy}.` : "";
  return { line: `knownHosts.mode is "${k.mode}": ${what}. Built-in hosts ${k.builtins ? "on" : "off"}.${off}`, off: k.mode === "off" };
}

function damagedNote(l: Layout, project: string): string {
  return `${knownHostsFile(l, project)} cannot be read, so no host counts as approved here (every new host asks). Run "launchsafe-firewall hosts reset" in your own terminal to start again.`;
}

function log(l: Layout, d: HostsCliDeps, entry: Record<string, unknown>): void {
  try {
    appendBounded(l, entry);
  } catch (e) {
    d.err(`launchsafe-firewall could not write its decision log: ${(e as Error).message}`);
  }
}

/** `hosts` and `hosts list`: read-only, for anyone. */
async function hostsList(p: Ok, l: Layout, d: HostsCliDeps): Promise<number> {
  const project = projectOf(p, d);
  const { file, damaged } = readKnownHosts(l, project);
  const pol = loadPolicy(l, [project]).config;
  const k = knownHostsPolicy(pol);
  // With the built-in set off, the hosts the lists still name are the ones a person who turned it off may not expect.
  const kept = k.builtins ? [] : builtinsKnownThroughLists(pol);
  if (flag(p, "--json")) {
    d.out(JSON.stringify({ project: file.project, mode: k.mode, builtins: k.builtins, damaged, approved: file.approved, builtinHosts: k.builtins ? BUILTIN_KNOWN_HOSTS : [], builtinHostsKnownThroughLists: kept, fetchAllowHosts: pol.fetchAllowHosts, sendAllowHosts: pol.sendAllowHosts }, null, 2));
    return 0;
  }
  d.out(`Known hosts for ${file.project}`);
  d.out(modeLine(l, project).line);
  if (damaged) d.err(damagedNote(l, project));
  if (file.approved.length === 0) d.out("Approved for this project: none yet.");
  else {
    d.out(`Approved for this project (${file.approved.length}):`);
    for (const a of file.approved) d.out(`  ${a.host.padEnd(40)} ${a.at.slice(0, 10)}  ${a.via === "asked" ? "you said yes when asked" : a.via === "queue" ? "approved in the queue" : a.via === "review" ? "accepted from hosts review" : "hosts allow"}`);
  }
  d.out(`Also known in every project: fetchAllowHosts (${pol.fetchAllowHosts.length}) and sendAllowHosts (${pol.sendAllowHosts.length}) from your policy (a list you have not set keeps its defaults)${k.builtins ? `, and ${BUILTIN_KNOWN_HOSTS.length} built-in development hosts (registries, GitHub, the agents' model APIs; knownHosts.builtins: false turns off only these)` : ""}.`);
  if (kept.length > 0) {
    const names = kept.map((h) => h.replace(/^=/, ""));
    // The advice names every list that keeps one of them: a host only sendAllowHosts names still counts once fetchAllowHosts leaves it out.
    const lists = [["fetchAllowHosts", pol.fetchAllowHosts], ["sendAllowHosts", pol.sendAllowHosts]] as const;
    const which = lists.filter(([, list]) => names.some((h) => hostInList(h, list))).map(([n]) => n);
    d.out(`Built-in hosts are off, but ${kept.length} of them ${kept.length === 1 ? "is" : "are"} still known because fetchAllowHosts or sendAllowHosts names them: ${names.slice(0, 6).join(", ")}${names.length > 6 ? `, and ${names.length - 6} more` : ""}. To be asked about those too, set ${which.join(" and ")} without them.`);
  }
  return damaged ? 1 : 0;
}

function seenLines(xs: readonly SeenHost[]): string[] {
  return xs.map((s) => `  ${s.host.padEnd(40)} ${String(s.count).padStart(5)}x  first ${s.first.slice(0, 10)}, last ${s.last.slice(0, 10)}`);
}

/** `hosts review`: read-only, for anyone. */
async function hostsReview(p: Ok, l: Layout, d: HostsCliDeps): Promise<number> {
  const project = projectOf(p, d);
  const { file, damaged } = readKnownHosts(l, project);
  const k = knownHostsPolicy(loadPolicy(l, [project]).config);
  const now = (d.now ?? (() => new Date()))();
  const ws = watchState(file, k.watchDays, now);
  const prop = proposals(file);
  if (flag(p, "--json")) {
    d.out(JSON.stringify({ project: file.project, mode: k.mode, watch: ws, since: file.watch?.since ?? null, watchDays: k.watchDays, damaged, ...prop }, null, 2));
    return 0;
  }
  d.out(`Known-hosts review for ${file.project}`);
  d.out(modeLine(l, project).line);
  if (damaged) {
    d.err(damagedNote(l, project));
    return 1;
  }
  if (ws === "not-started") d.out(k.mode === "watch" ? "Watching has not recorded anything here yet." : "Nothing was recorded here (watching happens with knownHosts.mode \"watch\").");
  else {
    const since = file.watch?.since ?? "";
    const left = Math.max(0, Math.ceil((Date.parse(since) + k.watchDays * 86400000 - now.getTime()) / 86400000));
    d.out(ws === "watching" ? `Watching since ${since.slice(0, 10)}; ${left} day${left === 1 ? "" : "s"} left.` : `Watched from ${since.slice(0, 10)} for ${k.watchDays} days; the watch is over.`);
  }
  if (prop.proposed.length === 0) d.out("Proposed: none.");
  else {
    d.out(`Proposed (${prop.proposed.length}), fetched from by the agent's tools in sessions that had not read outside content:`);
    for (const line of seenLines(prop.proposed)) d.out(line);
    d.out('Approve them with "launchsafe-firewall hosts accept --all", or name the ones you want: hosts accept <host>...');
  }
  if (prop.sentTo.length > 0) {
    d.out(`Received data from the agent (${prop.sentTo.length}); not in --all: a host you approve is admitted by run's proxy too, and it would accept uploads. Accept one by name only if it should:`);
    for (const line of seenLines(prop.sentTo)) d.out(line);
  }
  if (prop.fromRun.length > 0) {
    d.out(`Seen only by run's proxy (${prop.fromRun.length}), which refused them; run cannot tell what the program had read, so check each before you accept it by name:`);
    for (const line of seenLines(prop.fromRun)) d.out(line);
  }
  if (prop.taintedOnly.length > 0) {
    d.out(`Not proposed (${prop.taintedOnly.length}): contacted only after the session read outside content, so outside content may have chosen them:`);
    for (const line of seenLines(prop.taintedOnly)) d.out(line);
  }
  if (ws === "ended" && k.mode === "watch") d.out('When the list looks right, set knownHosts.mode to "ask" so new hosts ask from now on.');
  return 0;
}

async function hostsAllow(p: Ok, l: Layout, d: HostsCliDeps): Promise<number> {
  if (!(await d.humanAtKeyboard())) return 1;
  if (!(await passphraseIfSet(l, d, "hosts allow"))) return 1;
  const project = projectOf(p, d);
  const r = allowHosts(l, project, p.positionals, "cli", (d.now ?? (() => new Date()))());
  if (r.damaged) {
    d.err(damagedNote(l, project));
    return 1;
  }
  for (const h of r.refused) d.err(`Not added: ${h} is not a host name that can be approved (an IP address, this machine, a cloud metadata endpoint, a request catcher or a name built to carry data).`);
  if (r.added.length > 0) {
    log(l, d, { type: "known_hosts_added", hosts: r.added, project, via: "cli" });
    d.out(`Approved for ${project}: ${r.added.join(", ")}.`);
  } else if (r.refused.length === 0) d.out("Nothing to add: those hosts are already approved here.");
  const m = modeLine(l, project);
  if (m.off) d.out(m.line);
  return r.refused.length > 0 ? 1 : 0;
}

async function hostsRemove(p: Ok, l: Layout, d: HostsCliDeps): Promise<number> {
  if (!(await d.humanAtKeyboard())) return 1;
  const project = projectOf(p, d);
  const r = removeHosts(l, project, p.positionals);
  if (r.damaged) {
    d.err(damagedNote(l, project));
    return 1;
  }
  if (r.removed.length > 0) log(l, d, { type: "known_hosts_removed", hosts: r.removed, project });
  d.out(r.removed.length > 0 ? `Removed from ${project}: ${r.removed.join(", ")}. Contacting ${r.removed.length === 1 ? "it" : "them"} asks again unless your policy lists ${r.removed.length === 1 ? "it" : "them"}.` : "None of those hosts was approved here.");
  return 0;
}

async function hostsAccept(p: Ok, l: Layout, d: HostsCliDeps): Promise<number> {
  const all = flag(p, "--all");
  if (all === (p.positionals.length > 0)) {
    d.err("hosts accept: give --all, or the hosts to accept (not both).");
    return 64;
  }
  if (!(await d.humanAtKeyboard())) return 1;
  if (!(await passphraseIfSet(l, d, "hosts accept"))) return 1;
  const project = projectOf(p, d);
  const { file, damaged } = readKnownHosts(l, project);
  if (damaged) {
    d.err(damagedNote(l, project));
    return 1;
  }
  const prop = proposals(file);
  const seen = new Set([...prop.proposed, ...prop.sentTo, ...prop.fromRun, ...prop.taintedOnly].map((s) => s.host));
  const wanted = all ? prop.proposed.map((s) => s.host) : p.positionals.map((h) => h.trim().toLowerCase());
  const notSeen = wanted.filter((h) => !seen.has(h));
  for (const h of notSeen) d.err(`Not added: ${h} is not in this project's review (use "hosts allow ${learnableHost(h) ? h : "<host>"}" to approve a host directly).`);
  const r = allowHosts(l, project, wanted.filter((h) => seen.has(h)), "review", (d.now ?? (() => new Date()))());
  if (r.added.length > 0) log(l, d, { type: "known_hosts_added", hosts: r.added, project, via: "review" });
  d.out(r.added.length > 0 ? `Approved for ${project}: ${r.added.join(", ")}.` : "Nothing was added.");
  return notSeen.length > 0 || r.refused.length > 0 ? 1 : 0;
}

async function hostsReset(p: Ok, l: Layout, d: HostsCliDeps): Promise<number> {
  if (!(await d.humanAtKeyboard())) return 1;
  const project = projectOf(p, d);
  resetHosts(l, project);
  log(l, d, { type: "known_hosts_reset", project });
  d.out(`Emptied the known hosts and the watch record for ${project}.`);
  return 0;
}

export const HOSTS_HANDLERS: Record<string, (p: Ok, l: Layout, d: HostsCliDeps) => Promise<number>> = {
  hosts: hostsList,
  "hosts list": hostsList,
  "hosts allow": hostsAllow,
  "hosts remove": hostsRemove,
  "hosts review": hostsReview,
  "hosts accept": hostsAccept,
  "hosts reset": hostsReset,
};
