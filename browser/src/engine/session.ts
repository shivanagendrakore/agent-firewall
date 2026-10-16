/**
 * Tab trust and the agent session (design 4.5).
 *
 * Plain, serializable data (arrays, not Sets) so the worker can keep it in
 * chrome.storage.session across service-worker restarts. Every function
 * returns a new state and never mutates its input.
 *
 * - A tab is `untrusted` once it showed content from outside the person's
 *   trusted hosts, or any flag/quarantine verdict, or an incomplete scan.
 * - A tab is `private` once it showed a sensitive origin or private data.
 * - A tab is `quarantined` while its document carries a quarantine verdict.
 * - Tabs inherit all three from the tab that opened them.
 * - While agent mode is on, every tab joins the session, including tabs opened
 *   with no opener (an agent's chrome.tabs.create), and no quarantine clears.
 * - While agent mode is on, the agent session holds the union over its tabs,
 *   and that taint never clears: it ends only when a person turns agent mode
 *   off, which needs an approval (`endAgentSession` takes the redeemed proof).
 */
import { hostMatches } from "../vendor/firewall/engine/network.js";
import { hostOf, registrableDomain } from "./domain.js";
import type { ActionClass, Policy } from "./types.js";
import { SESSION_GRANTABLE_CLASSES } from "./types.js";
import { newPrintSalt, type PrivatePrint } from "./private-data.js";
import { isAgentModeOffProof } from "./bindings.js";

export type TrustReason = "outside_origin" | "flag_verdict" | "quarantine_verdict" | "scan_incomplete" | "inherited" | "private_origin" | "private_data";

export interface TabTrust {
  tabId: number;
  untrusted: boolean;
  private: boolean;
  /** The current document carries a quarantine verdict (agent mode off: cleared by a top-level navigation). */
  quarantined: boolean;
  reasons: TrustReason[];
  openerTabId?: number;
  /** The tab belongs to the agent session. */
  inSession: boolean;
  /**
   * Set when the tab inherited a quarantine from its opener: its first top-level commit is the page the
   * quarantined tab opened, not the person browsing away, so that commit keeps the mark.
   */
  inheritedQuarantine?: boolean;
}

/** How the agent drives the browser, when the person declares it (design 8): "os" escalates approvals. */
export type AgentInputClass = "extension_cdp" | "built_in" | "remote_cdp" | "os" | "unknown";

export interface AgentSession {
  startedAt: number;
  declaredClass: AgentInputClass;
  untrusted: boolean;
  private: boolean;
  quarantined: boolean;
  /** Registrable domains the session's tabs have shown. */
  domains: string[];
  /**
   * Registrable domains whose page or frame got a quarantine verdict in this session: the sites that injected
   * outside content. While the session is quarantined they are not trusted destinations for data (RR6).
   * Optional so a state stored by an older build still loads.
   */
  injectors?: string[];
  /** "domain|class" grants from "approve for this site for this agent session". */
  grants: string[];
  /**
   * Fingerprints of private strings shown in the session (private-data.ts); dropped when it ends. At most
   * MAX_SESSION_PRINTS, oldest evicted first, one-time codes kept in preference (`capPrints`).
   */
  prints: PrivatePrint[];
  /** Random salt for the short-code prints above (private-data.ts); lives and dies with the session. */
  printSalt: string;
  /** Coding-agent sessions the local firewall reported as untrusted over the native link (design 10). */
  linkedAgents?: string[];
}

export interface BrowserState {
  tabs: TabTrust[];
  /** Non-null exactly while agent mode is on. */
  session: AgentSession | null;
  /**
   * Untrusted coding-agent sessions the local firewall reported while agent mode was off (design 10). The
   * next agent session starts untrusted with them; kept for the browser session (storage.session).
   */
  pendingLinkedAgents?: string[];
}

/** What a decision needs to know about a tab: its own flags, or in agent mode the session's union. */
export interface EffectiveTrust {
  agentMode: boolean;
  declaredClass: AgentInputClass | null;
  untrusted: boolean;
  private: boolean;
  quarantined: boolean;
  /** Registrable domains the agent session has shown (empty when agent mode is off). */
  sessionDomains: ReadonlySet<string>;
  /** Domains that injected outside content into a quarantined session: never a known destination for data (RR6). */
  injectorDomains?: ReadonlySet<string>;
  grants: ReadonlySet<string>;
  prints: readonly PrivatePrint[];
  /** The session's salt for short-code prints; absent with agent mode off. */
  printSalt?: string;
}

/** Sensitive origins bundled with the extension (design 4.5): mail, banks' common hosts, cloud consoles, password managers, health. */
export const BUNDLED_PRIVATE_HOSTS: readonly string[] = [
  "mail.google.com",
  "accounts.google.com",
  "myaccount.google.com",
  "drive.google.com",
  "docs.google.com",
  "outlook.live.com",
  "outlook.office.com",
  "outlook.office365.com",
  "login.microsoftonline.com",
  "account.microsoft.com",
  "mail.yahoo.com",
  "mail.proton.me",
  "app.fastmail.com",
  "icloud.com",
  "appleid.apple.com",
  "github.com",
  "gitlab.com",
  "console.aws.amazon.com",
  "signin.aws.amazon.com",
  "console.cloud.google.com",
  "portal.azure.com",
  "dash.cloudflare.com",
  "dashboard.stripe.com",
  "paypal.com",
  "vault.bitwarden.com",
  "my.1password.com",
  "lastpass.com",
  "slack.com",
  "app.slack.com",
  "web.whatsapp.com",
  "messenger.com",
  "chase.com",
  "bankofamerica.com",
  "wellsfargo.com",
  "mychart.org",
];

export function emptyState(): BrowserState {
  return { tabs: [], session: null };
}

export function isPrivateHost(host: string, policy: Policy): boolean {
  return BUNDLED_PRIVATE_HOSTS.some((p) => hostMatches(host, p)) || policy.privateHosts.some((p) => hostMatches(host, p));
}

export function isTrustedHost(host: string, policy: Policy): boolean {
  return policy.trustedHosts.some((p) => hostMatches(host, p));
}

function freshTab(tabId: number): TabTrust {
  return { tabId, untrusted: false, private: false, quarantined: false, reasons: [], inSession: false };
}

function withReason(reasons: readonly TrustReason[], r: TrustReason): TrustReason[] {
  return reasons.includes(r) ? [...reasons] : [...reasons, r];
}

function getTab(s: BrowserState, tabId: number): TabTrust {
  return s.tabs.find((t) => t.tabId === tabId) ?? freshTab(tabId);
}

function putTab(s: BrowserState, tab: TabTrust): BrowserState {
  return { ...s, tabs: [...s.tabs.filter((t) => t.tabId !== tab.tabId), tab] };
}

/**
 * The most registrable domains a session records as shown (known destinations) and as injectors. A page that
 * opens frames on thousands of domains cannot grow the state without bound. Past the cap a new domain is simply
 * not recorded as known, which is stricter (it stays "new to the session"); an injector past the cap is still
 * kept out of the known domains, so dropping it never relaxes anything.
 */
export const MAX_SESSION_DOMAINS = 500;

/** Folds a tab's flags into the session (a no-op unless the tab is in an active session). Never clears. */
function foldIntoSession(s: BrowserState, tab: TabTrust, domain?: string, injected = false): BrowserState {
  if (s.session === null || !tab.inSession) return s;
  const sess = s.session;
  const have = sess.injectors ?? [];
  const named = domain !== undefined && domain !== "";
  const injectorFull = have.length >= MAX_SESSION_DOMAINS;
  const injectors = injected && named && !have.includes(domain) && !injectorFull ? [...have, domain] : have;
  let domains = named && !sess.domains.includes(domain) && sess.domains.length < MAX_SESSION_DOMAINS ? [...sess.domains, domain] : sess.domains;
  // An injector we could not record (the list is full) must not count as a known destination either.
  if (injected && named && injectorFull && !have.includes(domain)) domains = domains.filter((d) => d !== domain);
  return {
    ...s,
    session: {
      ...sess,
      untrusted: sess.untrusted || tab.untrusted,
      private: sess.private || tab.private,
      quarantined: sess.quarantined || tab.quarantined,
      domains,
      ...(injectors.length > 0 ? { injectors } : {}),
    },
  };
}

/** The most private-string fingerprints a session keeps; the leak context the content script accepts has the same bound. */
export const MAX_SESSION_PRINTS = 2_000;

/**
 * Keeps at most `max` prints. Oldest are evicted first, long ones before one-time codes: a page that shows
 * thousands of addresses pushes out older addresses, not the code the agent just read on the mail site (RR2).
 */
export function capPrints(prints: readonly PrivatePrint[], max: number = MAX_SESSION_PRINTS): PrivatePrint[] {
  if (prints.length <= max) return [...prints];
  let excess = prints.length - max;
  const drop = new Set<number>();
  for (const kind of ["long", "short"] as const) {
    for (let i = 0; i < prints.length && excess > 0; i++) {
      if (!drop.has(i) && (prints[i] as PrivatePrint).kind === kind) {
        drop.add(i);
        excess--;
      }
    }
  }
  return prints.filter((_, i) => !drop.has(i));
}

/**
 * A tab opened. It inherits trust flags from its opener. While agent mode is on it joins the agent session
 * whatever its opener: an agent opens tabs with chrome.tabs.create (no opener), and what those tabs show
 * (mail, one-time codes) must feed the session like any other agent tab. Flags only add: the new tab's own page may already have reported (its content script can beat the
 * opener event), and the browser can report one opening twice (onCreated and onCreatedNavigationTarget).
 */
export function tabOpened(s: BrowserState, tabId: number, openerTabId?: number): BrowserState {
  let tab = getTab(s, tabId);
  if (openerTabId !== undefined && openerTabId !== tabId) {
    const opener = s.tabs.find((t) => t.tabId === openerTabId);
    tab = { ...tab, openerTabId };
    if (opener !== undefined) {
      const inherits = opener.untrusted || opener.private || opener.quarantined;
      tab = {
        ...tab,
        untrusted: tab.untrusted || opener.untrusted,
        private: tab.private || opener.private,
        quarantined: tab.quarantined || opener.quarantined,
        inSession: tab.inSession || opener.inSession,
        reasons: inherits ? withReason(tab.reasons, "inherited") : tab.reasons,
        ...(opener.quarantined && !tab.quarantined ? { inheritedQuarantine: true } : {}),
      };
    }
  }
  if (s.session !== null) tab = { ...tab, inSession: true };
  return foldIntoSession(putTab(s, tab), tab);
}

export function tabClosed(s: BrowserState, tabId: number): BrowserState {
  return { ...s, tabs: s.tabs.filter((t) => t.tabId !== tabId) };
}

export interface PageObservation {
  url: string;
  /** The content guard's verdict for the page (or frame); omitted before the scan finishes. */
  verdict?: "deliver" | "neutralize" | "flag" | "quarantine";
  scanIncomplete?: boolean;
}

/** A tab (any frame of it) showed a page. Sets flags; never clears them. */
export function pageShown(s: BrowserState, tabId: number, obs: PageObservation, policy: Policy): BrowserState {
  let tab = getTab(s, tabId);
  const host = hostOf(obs.url);
  if (host !== null) {
    if (!isTrustedHost(host, policy)) tab = { ...tab, untrusted: true, reasons: withReason(tab.reasons, "outside_origin") };
    if (isPrivateHost(host, policy)) tab = { ...tab, private: true, reasons: withReason(tab.reasons, "private_origin") };
  }
  if (obs.verdict === "flag") tab = { ...tab, untrusted: true, reasons: withReason(tab.reasons, "flag_verdict") };
  if (obs.verdict === "quarantine") tab = { ...tab, untrusted: true, quarantined: true, reasons: withReason(tab.reasons, "quarantine_verdict") };
  if (obs.scanIncomplete === true) tab = { ...tab, untrusted: true, reasons: withReason(tab.reasons, "scan_incomplete") };
  return foldIntoSession(putTab(s, tab), tab, host === null ? undefined : registrableDomain(host), obs.verdict === "quarantine");
}

/**
 * The tab's top-level document changed. With agent mode off the per-document
 * quarantine clears (a person browsing away from a bad page); untrusted and
 * private stay for the tab's life. In agent mode nothing clears, in any tab
 * (agent mode is browser-wide): the agent may carry the page's instructions with it.
 */
export function topLevelNavigated(s: BrowserState, tabId: number): BrowserState {
  const tab = getTab(s, tabId);
  if (s.session !== null) return s;
  if (tab.inheritedQuarantine === true) {
    const { inheritedQuarantine: _done, ...rest } = tab;
    return putTab(s, rest);
  }
  return putTab(s, { ...tab, quarantined: false });
}

/** The leak guard found private data on the tab's page; `prints` are its fingerprints (kept only in an agent session). */
export function privateDataShown(s: BrowserState, tabId: number, prints: readonly PrivatePrint[]): BrowserState {
  const tab = { ...getTab(s, tabId), private: true };
  tab.reasons = withReason(tab.reasons, "private_data");
  let next = foldIntoSession(putTab(s, tab), tab);
  if (next.session !== null && tab.inSession && prints.length > 0) {
    // A print shown again moves to the newest end, so what the agent is reading now is evicted last.
    const key = (p: PrivatePrint) => `${p.kind}|${p.domain}|${p.fp}`;
    const fresh = new Map<string, PrivatePrint>();
    for (const p of prints) fresh.set(key(p), p);
    const kept = next.session.prints.filter((p) => !fresh.has(key(p)));
    next = { ...next, session: { ...next.session, prints: capPrints([...kept, ...fresh.values()]) } };
  }
  return next;
}

/** Agent mode on: a new session over the given tabs, seeded with their current flags. Turning it on is never gated. */
export function startAgentSession(s: BrowserState, opts: { now: number; tabIds: readonly number[]; declaredClass?: AgentInputClass; printSalt?: string }): BrowserState {
  if (s.session !== null) {
    // Already on: the named tabs join; nothing resets.
    let next = s;
    for (const id of opts.tabIds) {
      const tab = { ...getTab(next, id), inSession: true };
      next = foldIntoSession(putTab(next, tab), tab);
    }
    return next;
  }
  const linked = s.pendingLinkedAgents ?? [];
  let next: BrowserState = {
    ...s,
    session: {
      startedAt: opts.now,
      declaredClass: opts.declaredClass ?? "unknown",
      untrusted: linked.length > 0,
      private: false,
      quarantined: false,
      domains: [],
      grants: [],
      prints: [],
      printSalt: opts.printSalt ?? newPrintSalt(),
      ...(linked.length > 0 ? { linkedAgents: [...linked] } : {}),
    },
  };
  for (const id of opts.tabIds) {
    const tab = { ...getTab(next, id), inSession: true };
    next = foldIntoSession(putTab(next, tab), tab);
  }
  return next;
}

/**
 * Proof that a person approved turning agent mode off. Only the approval ledger
 * (bindings.ts) mints one, from a redeemed approval for that purpose; endAgentSession
 * checks it by identity, so an object of the same shape built anywhere else is refused.
 */
export interface AgentModeOffProof {
  readonly ok: true;
  readonly purpose: "agent_mode_off";
}

/**
 * Agent mode off. Refuses (returns the state unchanged, `ended: false`) without
 * a proof of approval, so a page or agent cannot end the session and its taint.
 */
export function endAgentSession(s: BrowserState, proof: AgentModeOffProof | null | undefined): { state: BrowserState; ended: boolean } {
  if (s.session === null) return { state: s, ended: false };
  if (!isAgentModeOffProof(proof)) return { state: s, ended: false };
  // A linked coding-agent session the firewall reported stays untrusted after this one ends: the next agent
  // session starts with it (the firewall reports each one once per connection).
  const linked = [...new Set([...(s.pendingLinkedAgents ?? []), ...(s.session.linkedAgents ?? [])])];
  return { state: { tabs: s.tabs.map((t) => ({ ...t, inSession: false })), session: null, ...(linked.length > 0 ? { pendingLinkedAgents: linked } : {}) }, ended: true };
}

const MAX_LINKED_AGENTS = 20;

function withAgent(list: readonly string[] | undefined, agent: string): string[] {
  const l = list ?? [];
  return l.includes(agent) ? [...l] : [...l, agent].slice(-MAX_LINKED_AGENTS);
}

/**
 * The local firewall reported a linked coding-agent session as untrusted (design 10: it read outside
 * content and drives this browser). The agent session becomes untrusted; with agent mode off it is held
 * and the next agent session starts untrusted. Only ever adds taint.
 */
export function linkedAgentTainted(s: BrowserState, agent: string): BrowserState {
  if (agent === "") return s;
  if (s.session !== null) return { ...s, session: { ...s.session, untrusted: true, linkedAgents: withAgent(s.session.linkedAgents, agent) } };
  return { ...s, pendingLinkedAgents: withAgent(s.pendingLinkedAgents, agent) };
}

/**
 * What the agent session's taint is to the local firewall: the first reason a session tab gives, or null
 * when the session is trusted, or untrusted only because the firewall said so (nothing to send back).
 */
export function sessionTaintForLink(s: BrowserState): { session: string; reason: string } | null {
  const sess = s.session;
  if (sess === null || !sess.untrusted) return null;
  const tab = s.tabs.find((t) => t.inSession && t.untrusted);
  if (tab === undefined) return null;
  return { session: String(sess.startedAt), reason: tab.reasons.find((r) => r !== "inherited") ?? tab.reasons[0] ?? "outside_origin" };
}

/** A person's "approve for this site for this agent session". Refused for consent, account security, and with no session. */
export function addSessionGrant(s: BrowserState, domain: string, actionClass: ActionClass): { state: BrowserState; granted: boolean } {
  if (s.session === null || domain === "" || !SESSION_GRANTABLE_CLASSES.includes(actionClass)) return { state: s, granted: false };
  const key = grantKey(domain, actionClass);
  if (s.session.grants.includes(key)) return { state: s, granted: true };
  return { state: { ...s, session: { ...s.session, grants: [...s.session.grants, key] } }, granted: true };
}

export function grantKey(domain: string, actionClass: ActionClass): string {
  return `${registrableDomain(domain)}|${actionClass}`;
}

/** The trust a decision on this tab uses. In agent mode, a session tab sees the union of the session. */
export function effectiveTrust(s: BrowserState, tabId: number): EffectiveTrust {
  const tab = getTab(s, tabId);
  const sess = s.session;
  if (sess === null) {
    return { agentMode: false, declaredClass: null, untrusted: tab.untrusted, private: tab.private, quarantined: tab.quarantined, sessionDomains: new Set(), grants: new Set(), prints: [] };
  }
  // Agent mode is browser-wide: a tab outside the session still gets the strict column, with its own flags
  // plus the session's (an agent may act in any tab).
  return {
    agentMode: true,
    declaredClass: sess.declaredClass,
    untrusted: tab.untrusted || sess.untrusted,
    private: tab.private || sess.private,
    quarantined: tab.quarantined || sess.quarantined,
    sessionDomains: new Set(sess.domains),
    ...(sess.quarantined && (sess.injectors ?? []).length > 0 ? { injectorDomains: new Set(sess.injectors) } : {}),
    grants: new Set(sess.grants),
    prints: sess.prints,
    printSalt: sess.printSalt,
  };
}
