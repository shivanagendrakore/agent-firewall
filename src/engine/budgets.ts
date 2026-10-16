/**
 * Budgets. Counters per session with fixed windows, kept by the runtime
 * (src/runtime/counters.ts) and handed to the engine as a read-only view, so the
 * engine stays pure. Exceeding a budget turns the next action of that kind into
 * an approval (ask, or queue when unattended). Budgets never deny: they make
 * volume visible to a person.
 *
 *   FW-BUDGET-BYTES     outbound payload per host and in total (URL bytes count too, so a stream of
 *                       data-carrying GETs to an allowed host reaches it)
 *   FW-BUDGET-REQUESTS  requests to one host in 10 minutes
 *   FW-BUDGET-MCP       calls to one MCP server in 10 minutes; sends through it when untrusted
 *   FW-LOOP             the same action again and again with no write in between, or many
 *                       non-allowed verdicts in 10 minutes ("the agent seems stuck")
 *
 * The behaviour monitor is FW-LOOP's second stage (monitorCheck below): the same counters, plus
 * new hosts, changes to configuration and identical failures, with higher limits. Crossing one
 * of those stops the session (FW-STOPPED) until a person resumes it; it is never raised by an
 * approval, only by the person's resume, which restarts its windows.
 *
 * Counter keys: bytes:<host>, bytes:*, req:<host>, mcp:<server>, mcpsend:<server>,
 * loop:<action hash>, verdict:nonallow; the monitor adds host:<host> (session total: the host was tried
 * before), watch:newhost, watch:config and fail:<action hash> (minute buckets only). Package registries and source hosts used by installs and
 * clones, the hosts in sendAllowHosts and budgets.exemptHosts are not counted.
 */

import type { Effect, FirewallConfig, NormalizedAction, SessionState } from "../types.js";
import type { RuleHit } from "./decide.js";
import { parseMcpTool } from "./mcp.js";
import { hostInList } from "./network.js";

export interface BudgetPolicy {
  enabled: boolean;
  untrusted: { bytesPerHost: number; bytesTotal: number; requestsPerHost10m: number; mcpCalls10m: number; mcpSends10m: number };
  trusted: { bytesTotal: number; requestsPerHost10m: number; mcpCalls10m: number };
  /**
   * FW-LOOP: `sameAction10m` and `nonAllow10m` make the next action need a person; the `stop*` limits are
   * the behaviour monitor's, and crossing one stops the session (FW-STOPPED) until a person resumes it.
   */
  loop: { sameAction10m: number; nonAllow10m: number; stopNonAllow10m: number; stopNewHosts10m: number; stopConfigTouches10m: number; stopSameFailure10m: number };
  /** Added to the built-in install and clone exemptions; user or managed policy only. */
  exemptHosts: string[];
  /**
   * What a behaviour monitor stop (FW-STOPPED) stops: "session" (default), the session that crossed the limit;
   * "agent", every session of that agent (the hook's agent: claude, codex, ...; the library's and local API's
   * agent id), until a person runs `agent resume`. A project file may set "agent" (stricter), never "session".
   */
  stopScope?: "session" | "agent";
}

export const DEFAULT_BUDGETS: Readonly<BudgetPolicy> = Object.freeze({
  enabled: true,
  untrusted: { bytesPerHost: 65536, bytesTotal: 262144, requestsPerHost10m: 40, mcpCalls10m: 200, mcpSends10m: 20 },
  trusted: { bytesTotal: 4194304, requestsPerHost10m: 300, mcpCalls10m: 200 },
  loop: { sameAction10m: 8, nonAllow10m: 25, stopNonAllow10m: 60, stopNewHosts10m: 40, stopConfigTouches10m: 20, stopSameFailure10m: 20 },
  exemptHosts: [],
});

/** Registries and source hosts: not counted when the traffic comes from a package manager or git. */
export const INSTALL_HOSTS: readonly string[] = [
  "registry.npmjs.org",
  "registry.yarnpkg.com",
  "npm.pkg.github.com",
  "pypi.org",
  "files.pythonhosted.org",
  "crates.io",
  "static.crates.io",
  "index.crates.io",
  "proxy.golang.org",
  "sum.golang.org",
  "rubygems.org",
  "repo.maven.apache.org",
  "repo1.maven.org",
  "plugins.gradle.org",
  "api.nuget.org",
  "packagist.org",
  "jsr.io",
  "registry-1.docker.io",
  "ghcr.io",
  "codeload.github.com",
  "=github.com",
  "=gitlab.com",
  "=bitbucket.org",
];

/** The programs whose traffic to INSTALL_HOSTS is an install or a clone (the effect's "(via)" suffix). */
const INSTALL_VIA = /\((?:git (?:clone|fetch|pull|submodule|ls-remote|remote)|(?:npm|pnpm|yarn|bun|deno|pip3?|uv|poetry|pdm|pipenv|cargo|go|gem|bundle|bundler|composer|mvn|gradle|dotnet|nuget|swift|pod|brew|docker|podman)\b)[^)]*\)$/;

/** Package-manager effects described by the command itself ("npm view", "pnpm install"). */
const INSTALL_DETAIL = /^(?:npm|pnpm|yarn|bun|deno|pip3?|uv|poetry|pdm|cargo|go|gem|bundle|composer) [a-z-]+$/;

/** What the runtime's counters say so far (read before deciding). */
export interface BudgetView {
  /** The counters file could not be read: treated as at the limit for the untrusted thresholds, once. */
  corrupt: boolean;
  /** The sum for `key` over the last `minutes` minutes (only minutes after `sinceMs` when given: the monitor after a resume). */
  window(key: string, minutes: number, sinceMs?: number): number;
  /** The sum for `key` since the session started. */
  total(key: string): number;
  /** How many times this exact action ran in the last 10 minutes with no write in between. */
  repeats(actionHash: string): number;
  /** Extra allowance a person granted for `key` in this session (approvals; signed budget_raise events). */
  allowance(key: string): number;
  /** F35: the session total for `key` when a person last raised it (0: never). */
  floor?(key: string): number;
  /**
   * The behaviour monitor's counts: the sum for `key` over the last 10 minutes, to the millisecond, counting only
   * what happened after `sinceMs` (the last resume). Absent (an older custom view): `window` is used instead.
   */
  recent?(key: string, sinceMs?: number): number;
  /** Stops the monitor recorded in these counters (the sentinel kept even when the stop record could not be written). */
  stops?(): MonitorSentinel[];
}

/** A monitor stop kept in the counters themselves, so it holds even when its stop record could not be written. */
export interface MonitorSentinel {
  id: string;
  at: string;
  scope: "session" | "agent";
  target: string;
  signal: MonitorSignal;
  reason: string;
}

export interface BudgetUse {
  key: string;
  amount: number;
}

export interface BudgetOutcome {
  hits: RuleHit[];
  /** What this action adds to the counters if it goes ahead (allow or ask). */
  usage: BudgetUse[];
  /** The allowance a person's approval of this action adds (the exceeded budgets, by the same amount again). */
  raises: BudgetUse[];
  /** The action counts toward loop detection (it runs or sends something, and writes nothing). */
  loopEligible: boolean;
  /** The action writes a file (resets loop detection when it goes ahead). */
  writes: boolean;
  /** What the behaviour monitor counts for this action, whatever its verdict (absent when budgets are off). */
  watch?: Watch;
}

/** The behaviour monitor's view of one action: attempts count, not only what ran. */
export interface Watch {
  /** Hosts this action contacts that count toward budgets (exempt hosts and MCP servers are not hosts here). */
  hosts: string[];
  /** How many of them this session had never tried before. */
  newHosts: number;
  /** It changes the agent's configuration, instructions, a file that runs code later, or the firewall. */
  config: boolean;
}

/** Which behaviour the monitor saw. Fixed values: the notification's text is chosen from them, never written by the agent. */
export type MonitorSignal = "nonallow" | "newhosts" | "config" | "failures";

export const MONITOR_SIGNALS: readonly MonitorSignal[] = ["nonallow", "newhosts", "config", "failures"];

/** A fixed sentence per signal (the stop record, the notification, `session list`). */
export function signalSentence(s: MonitorSignal): string {
  switch (s) {
    case "nonallow":
      return "too many of its actions needed a person or were blocked";
    case "newhosts":
      return "it contacted too many hosts it had not contacted before";
    case "config":
      return "it tried to change the agent's configuration, instructions or the firewall too often";
    case "failures":
      return "it repeated the same blocked or held action too often";
  }
}

/** The effective budgets: the policy's values over the defaults (a partial or missing key means the default). */
export function budgetPolicy(cfg: Pick<FirewallConfig, "budgets">): BudgetPolicy {
  const b = cfg.budgets as Partial<BudgetPolicy> | undefined;
  return {
    enabled: b?.enabled ?? DEFAULT_BUDGETS.enabled,
    untrusted: { ...DEFAULT_BUDGETS.untrusted, ...(b?.untrusted ?? {}) },
    trusted: { ...DEFAULT_BUDGETS.trusted, ...(b?.trusted ?? {}) },
    loop: { ...DEFAULT_BUDGETS.loop, ...(b?.loop ?? {}) },
    exemptHosts: b?.exemptHosts ?? [],
    ...(b?.stopScope !== undefined ? { stopScope: b.stopScope } : {}),
  };
}

const CONFIG_CLASSES: ReadonlySet<Effect["cls"]> = new Set(["write_protected", "write_persistence", "firewall_tamper"]);

const LOOP_CLASSES: ReadonlySet<Effect["cls"]> = new Set(["execute", "execute_untrusted", "execute_opaque", "egress_fetch", "egress_send", "unknown", "destructive", "privilege", "agent_spawn"]);
const WRITE_CLASSES: ReadonlySet<Effect["cls"]> = new Set(["write_workspace", "write_outside_workspace", "write_persistence", "write_protected"]);

function exempt(e: Effect, cfg: FirewallConfig, pol: BudgetPolicy): boolean {
  const host = e.host;
  if (host === undefined) return false;
  // M7: a request to this machine (asked after outside content) is not data leaving it: no budget counts it.
  if ((e.tags ?? []).includes("loopback")) return true;
  if (hostInList(host, cfg.sendAllowHosts) || hostInList(host, pol.exemptHosts)) return true;
  return hostInList(host, INSTALL_HOSTS) && (INSTALL_VIA.test(e.detail) || INSTALL_DETAIL.test(e.detail));
}

export function kb(n: number): string {
  return n < 1024 ? `${n} bytes` : n < 1024 * 1024 ? `${Math.round(n / 102.4) / 10} KB` : `${Math.round(n / 104857.6) / 10} MB`;
}

export interface BudgetInput {
  action: NormalizedAction;
  /** The key FW-LOOP counts the action under (counterKey(): cosmetic fields left out). */
  actionHash: string;
  effects: readonly Effect[];
  state: SessionState;
  config: FirewallConfig;
  view: BudgetView;
  readOnlyTool: boolean;
}

/** What an action would add to the counters, before any limit is looked at (budgets and spending limits both read it). */
export function measureUsage(action: NormalizedAction, effects: readonly Effect[], config: FirewallConfig): { usage: BudgetUse[]; hostsHit: Map<string, number> } {
  const pol = budgetPolicy(config);
  const usage: BudgetUse[] = [];
  const add = (key: string, amount: number): void => {
    const u = usage.find((x) => x.key === key);
    if (u !== undefined) u.amount += amount;
    else usage.push({ key, amount });
  };
  const mcp = parseMcpTool(action.tool);
  const hostsHit = new Map<string, number>();
  for (const e of effects) {
    if (e.cls !== "egress_fetch" && e.cls !== "egress_send") continue;
    if (mcp !== null) continue;
    // F34: a send whose destination has no host name (a registry, a git remote, a cloud service) is counted
    // under its destination.
    const host = e.host ?? (e.cls === "egress_send" ? (e.destination ?? e.target) : undefined);
    if (host === undefined || exempt(e, config, pol)) continue;
    // F33: an uploaded file's size counts, not only the command line.
    const bytes = (e.payload ?? e.target).length + (e.uploadBytes ?? 0);
    add(`bytes:${host}`, bytes);
    add("bytes:*", bytes);
    hostsHit.set(host, (hostsHit.get(host) ?? 0) + bytes);
  }
  for (const host of hostsHit.keys()) add(`req:${host}`, 1);
  if (mcp !== null) {
    add(`mcp:${mcp.server}`, 1);
    if (effects.some((e) => e.cls === "egress_send")) add(`mcpsend:${mcp.server}`, 1);
    const bytes = JSON.stringify(action.input).length;
    add(`bytes:mcp:${mcp.server}`, bytes);
    add("bytes:*", bytes);
  }
  return { usage, hostsHit };
}

/** The budget rules for one action. Pure: the counters come in through `view`. */
export function budgetRules(input: BudgetInput): BudgetOutcome {
  const { action, actionHash, effects, state, config, view } = input;
  const pol = budgetPolicy(config);
  const writes = effects.some((e) => WRITE_CLASSES.has(e.cls));
  const loopEligible = !input.readOnlyTool && !writes && effects.some((e) => LOOP_CLASSES.has(e.cls));
  const out: BudgetOutcome = { hits: [], usage: [], raises: [], loopEligible, writes };
  if (!pol.enabled) return out;
  const trusted = !state.tainted;
  // --- what this action would add ---
  const mcp = parseMcpTool(action.tool);
  const measured = measureUsage(action, effects, config);
  out.usage = measured.usage;
  const hostsHit = measured.hostsHit;
  // What the behaviour monitor counts (the hosts, how many the session never tried, a configuration change).
  const hosts = [...hostsHit.keys()];
  out.watch = { hosts, newHosts: hosts.filter((h) => view.total(`host:${h}`) === 0 && view.total(`req:${h}`) === 0).length, config: effects.some((e) => CONFIG_CLASSES.has(e.cls)) };
  // --- would it exceed a budget? ---
  const usage = (key: string): number => out.usage.find((u) => u.key === key)?.amount ?? 0;
  const over = (rule: string, key: string, sofar: number, limit: number, say: (sofar: number, limit: number) => string): void => {
    const allowance = view.allowance(key);
    // F35: a yes gives the budget again from where the person said it ("by the same amount again"), also
    // when usage was already well past the limit (bytes sent while the session was still trusted).
    const floor = key.startsWith("bytes:") ? (view.floor?.(key) ?? 0) : 0;
    if (sofar + usage(key) <= Math.max(limit + allowance, floor > 0 ? floor + limit : 0)) return;
    out.raises.push({ key, amount: limit });
    out.hits.push({ rule, outcome: "approve", reason: `${say(sofar, limit + allowance)}. Approving it raises this budget for the session by the same amount again` });
  };
  if (view.corrupt && !trusted && out.usage.some((u) => u.key.startsWith("bytes:"))) {
    out.hits.push({ rule: "FW-BUDGET-BYTES", outcome: "approve", reason: "the budget counters for this session could not be read, so the firewall treats them as at the limit (it asks once, then starts counting again)" });
  }
  const limits = trusted ? { ...pol.trusted, bytesPerHost: Number.POSITIVE_INFINITY, mcpSends10m: Number.POSITIVE_INFINITY } : pol.untrusted;
  const sentSoFar = (key: string): number => view.total(key);
  for (const [host] of hostsHit) {
    const sent = sentSoFar(`bytes:${host}`);
    const reqs = view.total(`req:${host}`);
    if (Number.isFinite(limits.bytesPerHost)) over("FW-BUDGET-BYTES", `bytes:${host}`, sent, limits.bytesPerHost, (s, l) => `this session has sent ${kb(s)} to ${host} in ${reqs} requests and this would add ${kb(usage(`bytes:${host}`))}; the budget is ${kb(l)} per host`);
    const recent = view.window(`req:${host}`, 10);
    over("FW-BUDGET-REQUESTS", `req:${host}`, recent, limits.requestsPerHost10m, (s, l) => `this session has made ${s} requests to ${host} in the last 10 minutes; the budget is ${l}`);
  }
  if (usage("bytes:*") > 0) over("FW-BUDGET-BYTES", "bytes:*", sentSoFar("bytes:*"), limits.bytesTotal, (s, l) => `this session has sent ${kb(s)} off the machine and this would add ${kb(usage("bytes:*"))}; the budget is ${kb(l)} in total${trusted ? "" : " once a session has read outside content"}`);
  if (mcp !== null) {
    over("FW-BUDGET-MCP", `mcp:${mcp.server}`, view.window(`mcp:${mcp.server}`, 10), limits.mcpCalls10m, (s, l) => `this session has called the ${mcp.server} MCP server ${s} times in the last 10 minutes; the budget is ${l}`);
    if (usage(`mcpsend:${mcp.server}`) > 0 && Number.isFinite(limits.mcpSends10m)) over("FW-BUDGET-MCP", `mcpsend:${mcp.server}`, view.window(`mcpsend:${mcp.server}`, 10), limits.mcpSends10m, (s, l) => `this session has sent ${s} messages or changes through the ${mcp.server} MCP server in the last 10 minutes; the budget is ${l} once a session has read outside content`);
  }
  // --- loops ---
  if (loopEligible) {
    const key = `loop:${actionHash}`;
    const allowance = view.allowance(key);
    const n = view.repeats(actionHash) + 1;
    if (n >= pol.loop.sameAction10m + allowance) {
      out.raises.push({ key, amount: pol.loop.sameAction10m });
      out.hits.push({ rule: "FW-LOOP", outcome: "approve", reason: `the agent seems stuck: this is the ${n}th time in 10 minutes it runs exactly this, with no change to any file in between; the limit is ${pol.loop.sameAction10m + allowance}` });
    }
  }
  if (!input.readOnlyTool) {
    const key = "verdict:nonallow";
    const allowance = view.allowance(key);
    const n = view.window(key, 10);
    if (n >= pol.loop.nonAllow10m + allowance) {
      out.raises.push({ key, amount: pol.loop.nonAllow10m });
      out.hits.push({ rule: "FW-LOOP", outcome: "approve", reason: `the agent seems stuck: ${n} of its actions in the last 10 minutes needed a person or were blocked; the limit is ${pol.loop.nonAllow10m + allowance}` });
    }
  }
  return out;
}

export interface MonitorInput {
  config: Pick<FirewallConfig, "budgets">;
  view: BudgetView;
  /** What budgetRules said about this action. */
  budget: Pick<BudgetOutcome, "watch">;
  /** The key failures are counted under (counterKey(): cosmetic fields left out). */
  actionHash: string;
  /** The verdict the action got from every other rule. */
  verdict: "allow" | "ask" | "queue" | "deny";
  /** The last time a person resumed this session or its agent (ms): earlier counts do not count. */
  sinceMs?: number;
}

/**
 * The behaviour monitor: FW-LOOP's counters with stop limits. Pure and deterministic. It fires only on
 * an action that adds to the count it crosses (a read never stops a session), counting this action, and
 * only over what happened after the last resume (to the millisecond). Returns the signal and a fixed reason, or null.
 */
export function monitorCheck(m: MonitorInput): { signal: MonitorSignal; reason: string } | null {
  const pol = budgetPolicy(m.config);
  const w = m.budget.watch;
  if (!pol.enabled || w === undefined) return null;
  const win = (key: string): number => (m.view.recent !== undefined ? m.view.recent(key, m.sinceMs) : m.view.window(key, 10, m.sinceMs));
  const nonAllow = m.verdict !== "allow";
  const failed = m.verdict === "deny" || m.verdict === "queue";
  const checks: { signal: MonitorSignal; adds: number; key: string; limit: number; what: string }[] = [
    { signal: "failures", adds: failed ? 1 : 0, key: `fail:${m.actionHash}`, limit: pol.loop.stopSameFailure10m, what: "times this exact action was blocked or held" },
    { signal: "config", adds: w.config ? 1 : 0, key: "watch:config", limit: pol.loop.stopConfigTouches10m, what: "attempts to change the agent's configuration, instructions, files that run code later or the firewall" },
    { signal: "newhosts", adds: w.newHosts, key: "watch:newhost", limit: pol.loop.stopNewHosts10m, what: "hosts contacted for the first time" },
    { signal: "nonallow", adds: nonAllow ? 1 : 0, key: "verdict:nonallow", limit: pol.loop.stopNonAllow10m, what: "actions that needed a person or were blocked" },
  ];
  for (const c of checks) {
    if (c.adds === 0) continue;
    const n = win(c.key) + c.adds;
    if (n >= c.limit) return { signal: c.signal, reason: `${signalSentence(c.signal)} (${n} ${c.what} in 10 minutes; the limit is ${c.limit})` };
  }
  return null;
}
