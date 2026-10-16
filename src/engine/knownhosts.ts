/**
 * Known hosts, pure (no I/O): which hosts an action contacts, which of them this project has never
 * contacted, and the FW-NEW-HOST rule ("ask before the agent contacts a website it has never contacted in
 * this project"). The list of hosts a person approved per project lives in the firewall's own directory
 * (src/runtime/knownhosts.ts) and reaches the engine as `ctx.knownHosts`.
 *
 * Known, for a project: a host the person approved there, a host in fetchAllowHosts or sendAllowHosts (the
 * person's own lists; a project file cannot add to them), and, unless `knownHosts.builtins` is false, the
 * built-in common development hosts below. A host the person named in this session's prompt is not asked
 * about either (it is not learned: only a yes to the question adds a host).
 *
 * `builtins: false` removes the built-in set and nothing else. fetchAllowHosts keeps its defaults until the
 * person sets it, and those defaults name the package registries and GitHub's code hosts, so those stay known
 * with `builtins: false` and no fetchAllowHosts of the person's own (docs/usage.md, "Known hosts"). A strict
 * start sets fetchAllowHosts without them. The defaults cannot be told apart from a list the person wrote, so
 * the engine does not try: a host their list names is known, whatever else is true.
 *
 * The rule only ever adds a question. It never lets through what another rule asks about or denies: in
 * an untrusted session FW-FETCH, FW-SEND and the rest apply exactly as before, and an approved host is
 * not on any allowlist they read.
 */

import type { Context, Effect, FirewallConfig, NormalizedAction, SessionState } from "../types.js";
import { knownHostsPolicy } from "../policy-knownhosts.js";
import { canonicalIpv4, hostInList, hostMatches, isCaptureHost, isDnsExfilShape, isLoopback, isMetadataEndpoint, isRawIp, normalizeHost, parseUrlLike } from "./network.js";
import { INSTALL_HOSTS } from "./budgets.js";
import { parseMcpTool } from "./mcp.js";
import { own } from "../own.js";
import type { RuleHit } from "./decide.js";
import { safeLine } from "./terminal.js";

/**
 * Common development hosts counted as known in every project unless `knownHosts.builtins` is false:
 * package registries and source hosts (the hooks' install and clone list), GitHub's API and content hosts,
 * and the model APIs of the agents the firewall supports. They are known, not allowlisted: in an untrusted
 * session every other rule still applies to them. Most of the registry and GitHub entries are also in the
 * default fetchAllowHosts, which `builtins: false` does not touch (builtinsKnownThroughLists).
 */
export const BUILTIN_KNOWN_HOSTS: readonly string[] = [
  ...INSTALL_HOSTS,
  "api.github.com",
  "raw.githubusercontent.com",
  "objects.githubusercontent.com",
  "formulae.brew.sh",
  "api.anthropic.com",
  "=claude.ai",
  "api.openai.com",
  "generativelanguage.googleapis.com",
  "api2.cursor.sh",
];

/** One host an action contacts. */
export interface Contact {
  host: string;
  /** What the action does there, in the words of the effect (for the reason a person reads). */
  detail: string;
  /** Data is sent there (an egress_send effect). A yes for such a host is never remembered: only fetches teach. */
  send: boolean;
}

const HOST_CHARS = /^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)*$/;
const URL_START = /^https?:\/\//i;
/** Argument names whose value is an address even without a scheme ("host": "api.example.dev"). */
const HOST_KEYS = /^(?:url|urls|uri|uris|href|link|links|host|hosts|hostname|endpoint|endpoints|domain|base_?url|baseurl|server_?url|target_?url|page_?url|website)$/i;
const BARE_HOST = /^[^\s/:@]+\.[^\s/:@]+(?::\d{1,5})?(?:\/\S*)?$/;
const MCP_MAX_DEPTH = 6;
const MCP_MAX_NODES = 1000;
const MCP_MAX_STRING = 4096;

/**
 * Hosts that have rules of their own and are never asked about as new: IP addresses in any spelling, this
 * machine, cloud metadata endpoints, request catchers and tunnels, names shaped to carry data.
 */
export function ownRuleHost(raw: string): boolean {
  const host = normalizeHost(raw.trim());
  return isRawIp(host) || canonicalIpv4(host) !== null || isLoopback(host) || isMetadataEndpoint(host) || isCaptureHost(host) || isDnsExfilShape(host);
}

/**
 * Whether a host can be put on a project's known list: a plain host name (letters, digits, dots, hyphens,
 * underscores; at most 253 characters) that has no rule of its own (ownRuleHost). Anything else that is
 * contacted still asks, and the question says it cannot be remembered.
 */
export function learnableHost(raw: string): boolean {
  const host = normalizeHost(raw.trim());
  if (host === "" || host.length > 253 || !HOST_CHARS.test(host)) return false;
  return !ownRuleHost(host);
}

/**
 * The hosts an MCP call names: every string anywhere in its arguments (walked with depth, node and length
 * caps) that is an http(s) URL, and host-shaped values under address-like keys (url, uri, host, endpoint,
 * href, ...), for fetch-like tools that take a bare host.
 */
function mcpUrlHosts(action: NormalizedAction): Contact[] {
  return mcpUrlScan(action).contacts;
}

/**
 * mcpUrlHosts, and whether the walk stopped short (`truncated`): arguments past its depth or node cap, or an
 * address-like string longer than it reads, were not looked at, so a host may be among them.
 */
export function mcpUrlScan(action: NormalizedAction): { contacts: Contact[]; truncated: boolean } {
  const mcp = parseMcpTool(action.tool);
  if (mcp === null) return { contacts: [], truncated: false };
  const out: Contact[] = [];
  let nodes = 0;
  let truncated = false;
  const add = (raw: string): void => {
    const p = parseUrlLike(raw);
    if (p === null) return;
    const host = normalizeHost(p.host);
    if (host !== "") out.push({ host, detail: `${mcp.server}.${mcp.tool} would contact ${host}`, send: false });
  };
  const walk = (v: unknown, key: string, depth: number): void => {
    if (++nodes > MCP_MAX_NODES || depth > MCP_MAX_DEPTH) {
      truncated = true;
      return;
    }
    if (typeof v === "string") {
      const t = v.trim();
      if (t.length === 0) return;
      if (t.length > MCP_MAX_STRING) {
        // Long text (a document, a message body) is not an address; a long value that starts like one, or sits
        // under an address-like key, is not read to the end.
        if (URL_START.test(t) || HOST_KEYS.test(key)) truncated = true;
        return;
      }
      if (URL_START.test(t)) add(t);
      else if (HOST_KEYS.test(key) && BARE_HOST.test(t)) add(t);
      return;
    }
    if (Array.isArray(v)) {
      for (const x of v) walk(x, key, depth + 1);
      return;
    }
    if (typeof v === "object" && v !== null) for (const k of Object.keys(v)) walk(own(v as Record<string, unknown>, k), k, depth + 1);
  };
  walk(action.input, "", 0);
  return { contacts: out, truncated };
}

/**
 * The hosts an action contacts, as the classification already found them: every fetch or send with a known
 * host (web fetch tools, the shell's network commands, package managers, git, host tools), plus the
 * addresses in MCP calls' arguments. A web search has no host; an address only known at run time has none
 * either (FW-UNCLASSIFIABLE asks about it already). Loopback is never a contact. A host that receives data
 * anywhere in the action is marked `send`.
 */
export function contactedHosts(action: NormalizedAction, effects: readonly Effect[]): Contact[] {
  const out: Contact[] = [];
  for (const e of effects) {
    if ((e.cls !== "egress_fetch" && e.cls !== "egress_send") || e.host === undefined) continue;
    if ((e.tags ?? []).includes("search")) continue;
    out.push({ host: normalizeHost(e.host), detail: e.detail, send: e.cls === "egress_send" });
  }
  out.push(...mcpUrlHosts(action));
  const byHost = new Map<string, Contact>();
  for (const c of out) {
    if (c.host === "" || isLoopback(c.host)) continue;
    const had = byHost.get(c.host);
    if (had === undefined) byHost.set(c.host, { ...c });
    else if (c.send) had.send = true;
  }
  return [...byHost.values()];
}

/**
 * The built-in hosts that fetchAllowHosts or sendAllowHosts also names, so they stay known when
 * `knownHosts.builtins` is false. With the default fetchAllowHosts that is the package registries and
 * GitHub's code and content hosts; a fetchAllowHosts the person set without them leaves none. Checked on the
 * host the entry names ("=github.com" is github.com), so an entry a list only partly covers still counts.
 */
export function builtinsKnownThroughLists(cfg: Pick<FirewallConfig, "fetchAllowHosts" | "sendAllowHosts">): string[] {
  return BUILTIN_KNOWN_HOSTS.filter((p) => {
    const h = p.replace(/^=/, "");
    return hostInList(h, cfg.fetchAllowHosts) || hostInList(h, cfg.sendAllowHosts);
  });
}

/** Whether a host is known in this project (approved there, in fetchAllowHosts or sendAllowHosts as in effect, or built in). */
export function isKnownHost(host: string, cfg: FirewallConfig, approved: readonly string[]): boolean {
  const h = normalizeHost(host);
  if (approved.some((a) => normalizeHost(a) === h)) return true;
  if (hostInList(h, cfg.fetchAllowHosts) || hostInList(h, cfg.sendAllowHosts)) return true;
  return knownHostsPolicy(cfg).builtins && hostInList(h, BUILTIN_KNOWN_HOSTS);
}

/** Whether the person named this host in this session's prompt. */
function namedByPerson(host: string, state: SessionState): boolean {
  return [...state.userDestinations].some((d) => hostMatches(host, d));
}

/**
 * The hosts this action would contact for the first time in this project: contacted, learnable, not known
 * and not named by the person in this session. Used for FW-NEW-HOST ("ask"), for what an answered question
 * adds, and for what "watch" records.
 */
export function newHosts(action: NormalizedAction, effects: readonly Effect[], state: SessionState, cfg: FirewallConfig, ctx: Pick<Context, "knownHosts">): Contact[] {
  const approved = ctx.knownHosts?.approved ?? [];
  return contactedHosts(action, effects).filter((c) => !ownRuleHost(c.host) && !hostInList(c.host, cfg.denyHosts) && !isKnownHost(c.host, cfg, approved) && !namedByPerson(c.host, state));
}

/** Of an action's new hosts, the ones a person's yes may teach: plain host names that are only fetched from. */
export function teachableHosts(contacts: readonly Contact[]): string[] {
  return contacts.filter((c) => !c.send && learnableHost(c.host)).map((c) => c.host);
}

/**
 * FW-NEW-HOST: with `knownHosts.mode` "ask", contacting a host this project has never contacted needs a
 * person, once. In a trusted session the person's yes adds the host to the project's list (the hook does
 * that when the tool runs). In an untrusted session it lets only that request through: nothing is learned
 * while the session may be acting on someone else's instructions.
 */
export function knownHostRules(action: NormalizedAction, effects: readonly Effect[], state: SessionState, cfg: FirewallConfig, ctx: Context, hits: RuleHit[]): void {
  if (knownHostsPolicy(cfg).mode !== "ask") return;
  // An MCP call whose arguments were not all read for addresses may contact a host nobody was asked about.
  if (mcpUrlScan(action).truncated) {
    hits.push({ rule: "FW-UNCLASSIFIABLE", outcome: "approve", reason: `the arguments of ${safeLine(action.tool.slice(0, 120))} are larger or nested deeper than the firewall reads for addresses, so it cannot tell whether this call contacts a host this project has never contacted` });
  }
  for (const c of newHosts(action, effects, state, cfg, ctx)) {
    // A host that is not a plain name is quoted and cut short: the reason reaches a person's terminal.
    const shown = learnableHost(c.host) ? c.host : JSON.stringify(c.host.slice(0, 120));
    const first = `${learnableHost(c.host) ? c.detail : "contact a host"}: this project has never contacted ${shown} before.`;
    const reason = !learnableHost(c.host)
      ? `${first} It is not a plain host name, so the firewall cannot remember it: allowing it lets only this request through`
      : state.tainted
        ? `${first} This session has read outside content, so allowing it lets only this request through; ${c.host} is not added to the project's known hosts`
        : c.send
          ? `${first} This sends data there, so allowing it lets only this request through; a host that receives data is added to the project's known hosts only by you, with launchsafe-firewall hosts allow ${c.host}`
          : `${first} If you allow it, ${c.host} is added to this project's known hosts and you are not asked about it again (launchsafe-firewall hosts list)`;
    hits.push({ rule: "FW-NEW-HOST", outcome: "approve", reason });
  }
}
