/**
 * declarativeNetRequest rules for the navigation policy (design 7), generated
 * from the same predicates `decideNavigation` uses, so the rule table lives in
 * one place:
 *
 * - `ALWAYS_RULES` ship as the static ruleset (dist/rules.json, written by the
 *   build): capture and paste hosts, chat-webhook capture URLs and cloud
 *   metadata addresses are blocked for every request but a top-level one.
 * - `sessionRules(input)` are the worker's session rules while agent mode is
 *   on: the same hosts for top-level navigations, raw IPs and DNS-exfil-shaped
 *   hosts (a coarse regex plus the exact hosts the content script saw in
 *   links), long data-carrying URLs to a domain new to a private session, and
 *   the optional agent origin set.
 *
 * Every rule blocks. A blocked top-level navigation is turned into the
 * explanation page by the worker (webNavigation.onErrorOccurred, then
 * tabs.update), so the redirect target needs no web_accessible_resources and
 * pages still cannot frame any of our pages.
 *
 * Regexes are RE2 (no lookaround, no backreferences), under DNR's 2 KB cap and
 * within its regex memory budget; the unit tests check the first two and the
 * e2e suite asks Chrome (isRegexSupported) for the third.
 */
import { hostMatches } from "../vendor/firewall/engine/network.js";
import { isPublicSuffix, TENANT_HOSTS } from "./domain.js";
import type { RuleId } from "./types.js";

/** The subset of chrome.declarativeNetRequest.Rule these rules use (the engine has no chrome types at runtime). */
export type DnrResourceType =
  | "main_frame"
  | "sub_frame"
  | "stylesheet"
  | "script"
  | "image"
  | "font"
  | "object"
  | "xmlhttprequest"
  | "ping"
  | "csp_report"
  | "media"
  | "websocket"
  | "webtransport"
  | "webbundle"
  | "other";

export interface DnrRule {
  id: number;
  priority: number;
  action: { type: "block" };
  condition: {
    requestDomains?: string[];
    excludedRequestDomains?: string[];
    regexFilter?: string;
    /** DNR's urlFilter syntax: `|` anchors at either end, `*` any characters, `^` a separator character or the end. */
    urlFilter?: string;
    resourceTypes?: DnrResourceType[];
    excludedResourceTypes?: DnrResourceType[];
    isUrlFilterCaseSensitive?: boolean;
  };
}

/**
 * The firewall's capture and paste hosts (vendored network.ts keeps its list
 * private). `nav-rules.test.ts` reads the vendored file and fails if the two
 * lists drift, and checks every entry against `isCaptureHost`.
 */
export const CAPTURE_HOSTS: readonly string[] = [
  "webhook.site",
  "requestbin.com",
  "requestbin.net",
  "pipedream.net",
  "pipedream.com",
  "ngrok.io",
  "ngrok.app",
  "ngrok.dev",
  "ngrok-free.app",
  "ngrok-free.dev",
  "trycloudflare.com",
  "interact.sh",
  "interactsh.com",
  "oast.pro",
  "oast.live",
  "oast.site",
  "oast.online",
  "oast.fun",
  "oast.me",
  "burpcollaborator.net",
  "oastify.com",
  "dnslog.cn",
  "ceye.io",
  "requestcatcher.com",
  "postb.in",
  "ptsv2.com",
  "ptsv3.com",
  "beeceptor.com",
  "hookbin.com",
  "canarytokens.com",
  "transfer.sh",
  "0x0.st",
  "file.io",
  "temp.sh",
  "termbin.com",
  "ix.io",
  "sprunge.us",
  "pastebin.com",
  "paste.ee",
  "hastebin.com",
  "dpaste.com",
  "dpaste.org",
  "ghostbin.co",
  "serveo.net",
  "localtunnel.me",
  "loca.lt",
  "localhost.run",
  "lhr.life",
  "bore.pub",
  "playit.gg",
  "tunnelmole.net",
];

/** Cloud metadata host names (vendored isMetadataEndpoint); the IP literals are in METADATA_IP_REGEX. */
export const METADATA_HOSTS: readonly string[] = ["metadata.google.internal", "metadata", "instance-data", "instance-data.ec2.internal"];

const SCHEME = "^[a-z][a-z0-9+.-]*://";
/** Credentials before the host (`https://user:pw@host/`): the host after them is where the request goes. */
const USERINFO = "(?:[^/?#@]*@)?";
const PORT_END = "(?::[0-9]+)?(?:[/?#]|$)";

export const DISCORD_WEBHOOK_REGEX = `${SCHEME}${USERINFO}(?:[^/?#@]*\\.)?discord(?:app)?\\.com\\.?(?::[0-9]+)?/api/webhooks/`;
export const TELEGRAM_BOT_REGEX = `${SCHEME}${USERINFO}api\\.telegram\\.org\\.?(?::[0-9]+)?/bot[0-9]+:`;
export const METADATA_IP_REGEX = `${SCHEME}${USERINFO}(?:169\\.254\\.169\\.254|169\\.254\\.170\\.2|100\\.100\\.100\\.200|\\[fd00:ec2::254\\])${PORT_END}`;

/** First IPv4 octet that is neither 0 nor 127 (loopback stays reachable; Chrome writes IPv4 hosts in dotted decimal). */
const OCTET1 = "(?:[1-9]|[1-9][0-9]|1[01][0-9]|12[0-68-9]|1[3-9][0-9]|2[0-4][0-9]|25[0-5])";
export const RAW_IPV4_REGEX = `${SCHEME}${USERINFO}${OCTET1}(?:\\.[0-9]{1,3}){3}${PORT_END}`;
/** IPv6 literals that start with a hex group (so [::1] and [::] stay reachable). */
export const RAW_IPV6_REGEX = `${SCHEME}${USERINFO}\\[[0-9a-f]{1,4}:[0-9a-f:.]*\\]${PORT_END}`;
/**
 * A hex label of 16 or more below at least two more labels (the CVE-2025-55284 shape). Longer or
 * higher-entropy shapes RE2 cannot express within DNR's regex memory budget come from the link scan as
 * exact hosts.
 */
export const DNS_EXFIL_REGEX = `${SCHEME}(?:[^/?#:@]*\\.)?[0-9a-f]{16,}\\.[^/?#:@.]+\\.[^/?#:@]+${PORT_END}`;
/**
 * A coarse "carries data" match. DNR compiles regexes with RE2 under a small
 * memory budget (isRegexSupported refuses a 32-character counted class here),
 * and RE2 cannot measure entropy, so this is a run of 28 or more letters and
 * digits starting a path segment or a query value: base64, hex and token
 * payloads have such runs; slugs, search phrases and short ids do not (their
 * hyphens, plus signs and percent escapes break the run). The content
 * script's link scan and the engine's exact predicate back it up.
 */
export const DATA_IN_URL_REGEX = `${SCHEME}[^/?#]+[^#]*[/=][A-Za-z0-9]{28}`;

/** Rule ids: static ruleset 1-99, session rules 1000-1999 (the worker owns that range). */
export const SESSION_RULE_MIN = 1000;
export const SESSION_RULE_MAX = 1999;

/** As `excludedResourceTypes`: every request type except a top-level navigation. */
const EXCEPT_TOP: DnrResourceType[] = ["main_frame"];

/** The static ruleset: always on, every request except top-level navigations (design 7, first and fourth rows). */
export const ALWAYS_RULES: readonly DnrRule[] = [
  { id: 1, priority: 100, action: { type: "block" }, condition: { requestDomains: [...CAPTURE_HOSTS], excludedResourceTypes: EXCEPT_TOP } },
  { id: 2, priority: 100, action: { type: "block" }, condition: { regexFilter: DISCORD_WEBHOOK_REGEX, excludedResourceTypes: EXCEPT_TOP } },
  { id: 3, priority: 100, action: { type: "block" }, condition: { regexFilter: TELEGRAM_BOT_REGEX, excludedResourceTypes: EXCEPT_TOP } },
  { id: 4, priority: 100, action: { type: "block" }, condition: { requestDomains: [...METADATA_HOSTS], excludedResourceTypes: EXCEPT_TOP } },
  { id: 5, priority: 100, action: { type: "block" }, condition: { regexFilter: METADATA_IP_REGEX, excludedResourceTypes: EXCEPT_TOP } },
];

export interface SessionRuleInput {
  agentMode: boolean;
  /** The agent session showed private data or a private origin. */
  private: boolean;
  /**
   * Registrable domains the agent session trusts as destinations for data-carrying URLs (exempt from the
   * data-in-URL rule): the domains it has shown, minus a domain that injected outside content while the
   * session is quarantined (ruleInputOf, RR6).
   */
  sessionDomains: readonly string[];
  /** Exact raw-IP and DNS-exfil hosts the content script saw in links (isRawIp / isDnsExfilShape). */
  suspiciousHosts: readonly string[];
  /** Agent origin set patterns (hostMatches syntax), or null when off. */
  originSet: readonly string[] | null;
}

/** DNR domain lists match a domain and its subdomains, so "=x" and "*.x" patterns both map to x (slightly wider than hostMatches). */
function domainOfPattern(p: string): string {
  return p.trim().toLowerCase().replace(/^=/, "").replace(/^\*\./, "").replace(/\.+$/, "");
}

/** A host DNR accepts in a domain list: dot-separated LDH labels. One entry that is not cannot take the rest of the list with it. */
const DNR_HOST = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/** Each host and its fully qualified form ("x.test."): a trailing dot names the same host and DNR does not fold it. */
function withDotted(hosts: readonly string[]): string[] {
  return [...new Set(hosts.flatMap((h) => [h, `${h}.`]))];
}

const TOP_AND_FRAMES: DnrResourceType[] = ["main_frame", "sub_frame"];
/**
 * Every type, named: a DNR rule with neither resourceTypes nor excludedResourceTypes matches everything
 * EXCEPT main_frame, which is the opposite of what these rules need.
 */
export const ALL_RESOURCE_TYPES: readonly DnrResourceType[] = ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "csp_report", "media", "websocket", "webtransport", "webbundle", "other"];
const MAX_LIST = 5_000;

export interface SessionRuleSet {
  rules: DnrRule[];
  /** The navigation rule-table row each DNR rule enforces (for the explanation page and the log). */
  meaning: Record<number, RuleId>;
}

/** Session rules for the current agent session; empty with agent mode off. Deterministic for a given input. */
export function sessionRuleSet(input: SessionRuleInput): SessionRuleSet {
  const rules: DnrRule[] = [];
  const meaning: Record<number, RuleId> = {};
  if (!input.agentMode) return { rules, meaning };
  let id = SESSION_RULE_MIN;
  const add = (navRule: RuleId, priority: number, condition: DnrRule["condition"]) => {
    meaning[id] = navRule;
    rules.push({ id: id++, priority, action: { type: "block" }, condition });
  };

  // Capture hosts and metadata addresses, top level (subresources are the static ruleset's).
  add("nav.capture_host", 100, { requestDomains: withDotted(CAPTURE_HOSTS), resourceTypes: ["main_frame"] });
  add("nav.capture_host", 100, { regexFilter: DISCORD_WEBHOOK_REGEX, resourceTypes: ["main_frame"] });
  add("nav.capture_host", 100, { regexFilter: TELEGRAM_BOT_REGEX, resourceTypes: ["main_frame"] });
  add("nav.suspicious_host", 100, { requestDomains: withDotted(METADATA_HOSTS), resourceTypes: ["main_frame"] });
  add("nav.suspicious_host", 100, { regexFilter: METADATA_IP_REGEX, resourceTypes: ["main_frame"] });
  // Raw IPs and DNS-exfil-shaped hosts, every request type (an image URL carries data as well as a page does).
  const all = [...ALL_RESOURCE_TYPES];
  add("nav.suspicious_host", 90, { regexFilter: RAW_IPV4_REGEX, resourceTypes: all });
  add("nav.suspicious_host", 90, { regexFilter: RAW_IPV6_REGEX, resourceTypes: all });
  add("nav.suspicious_host", 90, { regexFilter: DNS_EXFIL_REGEX, resourceTypes: all });
  const exact = [...new Set(input.suspiciousHosts.map((h) => h.toLowerCase().replace(/\.+$/, "")))].filter((h) => h.length <= 253 && DNR_HOST.test(h)).slice(0, MAX_LIST);
  if (exact.length > 0) add("nav.suspicious_host", 90, { requestDomains: withDotted(exact), resourceTypes: all });
  // Data in the URL, to a domain new to a private session: top level and frames.
  if (input.private) {
    const known = knownDomainList(input.sessionDomains);
    add("nav.high_entropy_new_origin", 50, { regexFilter: DATA_IN_URL_REGEX, resourceTypes: TOP_AND_FRAMES, ...(known.length > 0 ? { excludedRequestDomains: known } : {}) });
    // DNR's excludedRequestDomains also excludes every subdomain, and it wins over requestDomains in the same
    // rule. A tenant host under a known domain (docs.google.com under google.com) is a different site to the
    // engine, so it gets a rule of its own that the parent's exemption does not reach (RR1).
    const tenants = tenantHostsUnder(known);
    if (tenants.length > 0) add("nav.high_entropy_new_origin", 50, { regexFilter: DATA_IN_URL_REGEX, resourceTypes: TOP_AND_FRAMES, requestDomains: tenants });
  }
  // The optional agent origin set: any top-level navigation outside it.
  if (input.originSet !== null) {
    const allowed = [...new Set(input.originSet.map(domainOfPattern).filter((d) => d !== ""))].slice(0, MAX_LIST);
    add("nav.origin_set", 40, { resourceTypes: ["main_frame"], regexFilter: "^https?://", ...(allowed.length > 0 ? { excludedRequestDomains: allowed } : {}) });
  }
  return { rules, meaning };
}

/**
 * The session's known domains as a DNR exemption list. A public suffix is left out: excluding "github.io"
 * would exempt every site under it, while the engine counts each of them as its own domain.
 */
export function knownDomainList(domains: readonly string[]): string[] {
  return [...new Set(domains.map((d) => d.toLowerCase()).filter((d) => d !== "" && !isPublicSuffix(d)))].slice(0, MAX_LIST);
}

/** Tenant hosts (domain.ts) that sit under a known domain without being known themselves. */
export function tenantHostsUnder(known: readonly string[]): string[] {
  return TENANT_HOSTS.filter((t) => !known.includes(t) && known.some((k) => t.endsWith(`.${k}`)));
}

export function sessionRules(input: SessionRuleInput): DnrRule[] {
  return sessionRuleSet(input).rules;
}

/** The meaning of each static rule. */
export const ALWAYS_MEANING: Record<number, RuleId> = { 1: "nav.capture_host", 2: "nav.capture_host", 3: "nav.capture_host", 4: "nav.suspicious_host", 5: "nav.suspicious_host" };

// ---- a small DNR matcher (for the worker's explanation and for tests; Chrome does the real matching) ----

const domainListHas = (list: readonly string[], host: string) => list.some((d) => host === d || host.endsWith(`.${d}`));

/** Whether a rule's condition matches a request, with DNR's semantics for domains and resource types. */
export function dnrMatches(rule: DnrRule, url: string, type: DnrResourceType): boolean {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase().replace(/^\[|\]$/g, "");
  } catch {
    return false;
  }
  const c = rule.condition;
  if (c.resourceTypes !== undefined) {
    if (!c.resourceTypes.includes(type)) return false;
  } else if (c.excludedResourceTypes !== undefined) {
    if (c.excludedResourceTypes.includes(type)) return false;
  } else if (type === "main_frame") return false;
  if (c.requestDomains !== undefined && !domainListHas(c.requestDomains, host)) return false;
  if (c.excludedRequestDomains !== undefined && domainListHas(c.excludedRequestDomains, host)) return false;
  if (c.regexFilter !== undefined && !new RegExp(c.regexFilter, c.isUrlFilterCaseSensitive === true ? "" : "i").test(url)) return false;
  if (c.urlFilter !== undefined && !urlFilterRegex(c.urlFilter, c.isUrlFilterCaseSensitive === true).test(url)) return false;
  return true;
}

/** DNR's urlFilter as a regex (the subset our rules use: `|` anchors, `*`, `^`; no `||` domain anchor). */
export function urlFilterRegex(filter: string, caseSensitive: boolean): RegExp {
  let f = filter;
  const start = f.startsWith("|");
  if (start) f = f.slice(1);
  const end = f.endsWith("|");
  if (end) f = f.slice(0, -1);
  const body = [...f].map((ch) => (ch === "*" ? ".*" : ch === "^" ? "(?:[^A-Za-z0-9_.%-]|$)" : ch.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&"))).join("");
  return new RegExp(`${start ? "^" : ""}${body}${end ? "$" : ""}`, caseSensitive ? "" : "i");
}

/** The highest-priority rule that matches, or null. */
export function firstMatch(rules: readonly DnrRule[], url: string, type: DnrResourceType): DnrRule | null {
  let best: DnrRule | null = null;
  for (const r of rules) if (dnrMatches(r, url, type) && (best === null || r.priority > best.priority)) best = r;
  return best;
}

/** Whether a host is on the capture list (the same answer as vendored isCaptureHost, from this module's copy). */
export function onCaptureList(host: string): boolean {
  return CAPTURE_HOSTS.some((p) => hostMatches(host, p));
}
