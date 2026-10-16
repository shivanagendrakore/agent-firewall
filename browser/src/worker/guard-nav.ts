/**
 * The worker side of the content guard and navigation policy (design 4.5, 7):
 *
 * - answers `tab.mode` (is agent mode on, for a frame that just started);
 * - keeps the hosts the content script saw in links (`nav.hosts`), checked
 *   again with the engine's predicates;
 * - keeps the agent-mode session rules (engine/nav-rules.ts) in step with the
 *   agent session, by watching the state in chrome.storage.session: whoever
 *   starts or ends the session, or adds a domain or the private flag, the
 *   rules follow without that code knowing about them;
 * - turns a top-level navigation our rules blocked into the explanation page
 *   (blocked.html), opened by the worker with tabs.update, so the page needs
 *   no web_accessible_resources;
 * - records opener tabs from chrome.tabs.onCreated, so tabs opened by middle
 *   click or the context menu inherit trust as window.open targets do;
 * - for a block whose engine verdict is approve (not deny), asks index.ts for
 *   an approval in the gate's approval service, so the person can let that one
 *   navigation through from the side panel or the approval window (never from
 *   the explanation page, which sits in the tab the agent drives). Approved,
 *   `allowOnce` adds a one-shot allow rule for that tab and that exact address
 *   (no other path or query, no subdomains) and reopens it.
 *
 * The one-time pass's bookkeeping (RR7) lives in chrome.storage.session (memory
 * only, never on disk, readable only by trusted contexts), so a worker that
 * stops between the block and the approval, or between the pass and the
 * commit, can still reopen the tab or remove the pass when it starts again:
 * which tabs show the explanation page, the address each one was blocked on
 * (held there only until the tab moves on or closes, and found by a salted
 * digest: the approval record and the log never hold it, RR9), and the live
 * passes with their expiry. At start the worker removes every allow rule in its
 * id range that is not a live pass.
 */
import { hostOf, registrableDomain } from "../engine/domain.js";
import { decideNavigation } from "../engine/navigation.js";
import { ALWAYS_MEANING, ALWAYS_RULES, firstMatch, SESSION_RULE_MAX, SESSION_RULE_MIN, sessionRuleSet, type DnrRule, type SessionRuleInput } from "../engine/nav-rules.js";
import { effectiveTrust, tabOpened, type BrowserState } from "../engine/session.js";
import type { Policy, RuleId } from "../engine/types.js";
import { sha256Hex } from "../vendor/firewall/engine/bytes.js";
import { isDnsExfilShape, isRawIp } from "../vendor/firewall/engine/network.js";
import type { GuardNavMessage, TabModeReply } from "../shared/messages.js";
import { STATE_KEY, type StateStore } from "./state.js";

export const NAV_HOSTS_KEY = "ls.navHosts";
/** The one-time pass's bookkeeping (chrome.storage.session). */
export const NAV_PASS_KEY = "ls.navPass";
/** How long a tab's blocked address is held for an approval (the approval's own lifetime). */
const EXPLAIN_TTL_MS = 5 * 60 * 1000;
const MAX_HOSTS = 2_000;
/** One-shot allow rules for approved navigations: outside the block rules' id range, above their priority. */
export const NAV_ALLOW_RULE_MIN = 2000;
export const NAV_ALLOW_RULE_MAX = 2999;
const NAV_ALLOW_PRIORITY = 10_000;
const NAV_ALLOW_TTL_MS = 30_000;

/**
 * A blocked top-level navigation the engine says a person may approve. The approval keeps the host, the
 * amount of data and the salted digest; `url` is for the worker's own use and is never stored with it.
 */
export interface NavApprovalRequest {
  tabId: number;
  url: string;
  host: string;
  chars: number;
  digest: string;
  rule: RuleId;
  reasons: string[];
}

/**
 * The one-shot allow rule for an approved navigation: that tab, top level only, and exactly the approved
 * address (m7). A urlFilter anchored at both ends (`|url|`, case-sensitive) pins scheme, host, port, path and
 * query, so neither a subdomain of the approved host (a DNS-exfil-shaped name) nor another address on the same
 * host can ride the pass. urlFilter, not a regex: DNR compiles regexes under a small memory budget that a long
 * data-carrying address would exceed. The fragment is never sent, so it is left out. Residual: a literal `*`
 * in the approved address is a wildcard to DNR, so the pass also covers addresses that differ only there.
 */
export function allowOnceRule(id: number, tabId: number, url: string): chrome.declarativeNetRequest.Rule | null {
  const host = hostOf(url);
  if (host === null || host === "") return null;
  let exact: string;
  try {
    const u = new URL(url);
    u.hash = "";
    exact = u.href;
  } catch {
    return null;
  }
  // urlFilter is ASCII only; a canonical URL always is.
  if (/[^\x21-\x7e]/.test(exact)) return null;
  return {
    id,
    priority: NAV_ALLOW_PRIORITY,
    action: { type: "allow" as chrome.declarativeNetRequest.RuleActionType },
    condition: {
      tabIds: [tabId],
      requestDomains: [host],
      urlFilter: `|${exact}|`,
      isUrlFilterCaseSensitive: true,
      resourceTypes: ["main_frame" as chrome.declarativeNetRequest.ResourceType],
    },
  };
}

/** Characters of data a URL carries in its path and query (what the explanation page and the card show). */
export function dataCharsOf(url: string): number {
  try {
    const u = new URL(url);
    return u.search.length + Math.max(0, u.pathname.length - 1);
  } catch {
    return 0;
  }
}

interface Explaining {
  tabId: number;
  /** The blocked address, held only until the tab moves on, closes, or the hold expires. */
  url: string;
  digest: string;
  at: number;
}

interface Pass {
  id: number;
  tabId: number;
  host: string;
  expiresAt: number;
}

interface NavBook {
  salt: string;
  explaining: Explaining[];
  passes: Pass[];
  nextId: number;
}

function randomSalt(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function parseBook(v: unknown): NavBook | null {
  if (typeof v !== "object" || v === null) return null;
  const x = v as Partial<NavBook>;
  if (typeof x.salt !== "string" || x.salt.length < 16 || !Array.isArray(x.explaining) || !Array.isArray(x.passes) || typeof x.nextId !== "number") return null;
  const explaining = x.explaining.filter((e): e is Explaining => typeof e === "object" && e !== null && typeof e.tabId === "number" && typeof e.url === "string" && typeof e.digest === "string" && typeof e.at === "number");
  const passes = x.passes.filter((p): p is Pass => typeof p === "object" && p !== null && typeof p.id === "number" && typeof p.tabId === "number" && typeof p.host === "string" && typeof p.expiresAt === "number");
  const nextId = Number.isInteger(x.nextId) && x.nextId >= NAV_ALLOW_RULE_MIN && x.nextId <= NAV_ALLOW_RULE_MAX ? x.nextId : NAV_ALLOW_RULE_MIN;
  return { salt: x.salt, explaining, passes, nextId };
}

/** The salted digest a navigation approval is bound to: the address itself never goes into the record. */
export function navigationDigest(salt: string, url: string): string {
  return sha256Hex(`launchsafe-nav:${salt.length}:${salt}:${url}`);
}

export interface GuardNavDeps {
  store: StateStore;
  policy: () => Promise<Policy>;
  /** Appends a decision to the log (registrable domain and rule only). */
  log: (entry: { site: string; rule: RuleId; verdict: "deny" | "approve" }) => void;
  /** An approvable block landed on the explanation page: create the approval (index.ts, the gate's approval service). */
  requestApproval?: (req: NavApprovalRequest) => Promise<void>;
  /** A tab that showed the explanation page moved on or closed: its navigation approvals are moot (index.ts expires them). */
  onExplainEnded?: (tabId: number) => void;
}

export interface GuardNav {
  install(): void;
  handle(msg: GuardNavMessage, tabId: number, senderUrl: string): Promise<unknown>;
  /** Recompute and apply the session rules now (also runs on every state change). */
  sync(): Promise<void>;
  /** A person approved this navigation: let the tab open this host once (until it commits, or 30 s), then open it. */
  allowOnce(tabId: number, url: string): Promise<boolean>;
  /** Whether the tab still shows the explanation page for the address with this digest. */
  canReopen(tabId: number, digest: string): Promise<boolean>;
  /** allowOnce for the address the tab was blocked on, found by its digest (index.ts: the approval holds only the digest). */
  reopen(tabId: number, digest: string): Promise<boolean>;
}

/** The session-rule input for a state: browser-wide, because DNR rules are. */
export function ruleInputOf(state: BrowserState, hosts: readonly string[], policy: Policy): SessionRuleInput {
  const sess = state.session;
  return {
    agentMode: sess !== null,
    private: sess !== null && (sess.private || state.tabs.some((t) => t.private)),
    // A domain that injected outside content is not a known destination while the session is quarantined (RR6).
    sessionDomains: (sess?.domains ?? []).filter((d) => !(sess?.quarantined === true && (sess.injectors ?? []).includes(d))),
    suspiciousHosts: hosts,
    originSet: policy.originSet,
  };
}

/** The explanation page's URL: the rule and the destination host, never the path or query (they may carry the data). */
export function explanationPath(rule: RuleId, url: string, approvable = false): string {
  let host = "";
  let dataChars = 0;
  try {
    const u = new URL(url);
    host = u.hostname;
    dataChars = u.search.length + Math.max(0, u.pathname.length - 1);
  } catch {
    // An unparsable URL is explained without a host.
  }
  const q = new URLSearchParams({ rule, host, chars: String(dataChars), ...(approvable ? { approval: "1" } : {}) });
  return `blocked.html?${q.toString()}`;
}

export function createGuardNav(deps: GuardNavDeps): GuardNav {
  const hosts = new Set<string>();
  let hostsLoaded: Promise<void> | null = null;
  let applied = "";
  let meaning: Record<number, RuleId> = {};
  let lastRules: DnrRule[] = [];
  let chain: Promise<void> = Promise.resolve();

  const loadHosts = (): Promise<void> =>
    (hostsLoaded ??= chrome.storage.session.get(NAV_HOSTS_KEY).then((got) => {
      const v = got[NAV_HOSTS_KEY];
      if (Array.isArray(v)) for (const h of v) if (typeof h === "string") hosts.add(h);
    }, () => undefined));

  const doSync = async (): Promise<void> => {
    await loadHosts();
    const [state, policy] = await Promise.all([deps.store.load(), deps.policy()]);
    const set = sessionRuleSet(ruleInputOf(state, [...hosts], policy));
    const key = JSON.stringify(set.rules);
    if (key === applied) return;
    const existing = await chrome.declarativeNetRequest.getSessionRules();
    const removeRuleIds = existing.map((r) => r.id).filter((id) => id >= SESSION_RULE_MIN && id <= SESSION_RULE_MAX);
    let added = set.rules;
    try {
      await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds, addRules: set.rules as chrome.declarativeNetRequest.Rule[] });
    } catch {
      // One rule Chrome refuses must not take the others down: clear, then add them one by one.
      await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds }).catch(() => undefined);
      added = [];
      for (const r of set.rules) {
        try {
          await chrome.declarativeNetRequest.updateSessionRules({ addRules: [r as chrome.declarativeNetRequest.Rule] });
          added.push(r);
        } catch {
          // Refused (regex memory, list size): left out, and the engine still explains blocks by the others.
        }
      }
    }
    applied = key;
    meaning = set.meaning;
    lastRules = added;
  };

  const sync = (): Promise<void> => {
    const next = chain.then(doSync);
    chain = next.catch(() => undefined);
    return next;
  };

  /** Which of our rules blocked a top-level navigation, if any (Chrome does not say; recompute). */
  const ourRuleFor = async (tabId: number, url: string): Promise<RuleId | null> => {
    const session = firstMatch(lastRules, url, "main_frame");
    if (session !== null) return meaning[session.id] ?? null;
    const always = firstMatch(ALWAYS_RULES, url, "main_frame");
    if (always !== null) return ALWAYS_MEANING[always.id] ?? null;
    // The rules may have changed since: ask the engine directly.
    const d = decideNavigation({ url, resourceType: "main_frame" }, effectiveTrust(await deps.store.load(), tabId), await deps.policy());
    return d.verdict === "deny" || d.verdict === "approve" ? d.rule : null;
  };

  // ---- the one-time pass (RR7) ----

  let book: NavBook | null = null;
  let bookLoaded: Promise<NavBook> | null = null;
  let bookWrites: Promise<void> = Promise.resolve();
  const timers = new Map<number, ReturnType<typeof setTimeout>>();

  const loadBook = (): Promise<NavBook> =>
    (bookLoaded ??= chrome.storage.session.get(NAV_PASS_KEY).then(
      (got) => (book = parseBook(got[NAV_PASS_KEY]) ?? { salt: randomSalt(), explaining: [], passes: [], nextId: NAV_ALLOW_RULE_MIN }),
      () => (book = { salt: randomSalt(), explaining: [], passes: [], nextId: NAV_ALLOW_RULE_MIN }),
    ));
  /** Persists the book (writes in order); callers have already changed the in-memory copy. */
  const saveBook = (): Promise<void> => {
    const snapshot = structuredClone(book);
    bookWrites = bookWrites.then(() => chrome.storage.session.set({ [NAV_PASS_KEY]: snapshot })).catch(() => undefined);
    return bookWrites;
  };

  const removeRules = (ids: number[]): Promise<void> => (ids.length === 0 ? Promise.resolve() : chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids }).catch(() => undefined));

  const dropPasses = async (pred: (p: Pass) => boolean): Promise<void> => {
    const b = await loadBook();
    const gone = b.passes.filter(pred);
    if (gone.length === 0) return;
    b.passes = b.passes.filter((p) => !pred(p));
    for (const p of gone) {
      clearTimeout(timers.get(p.id));
      timers.delete(p.id);
    }
    await Promise.all([saveBook(), removeRules(gone.map((p) => p.id))]);
  };

  const armTimer = (p: Pass): void => {
    clearTimeout(timers.get(p.id));
    timers.set(
      p.id,
      setTimeout(() => void dropPasses((x) => x.id === p.id), Math.max(0, p.expiresAt - Date.now())),
    );
  };

  /** A tab moved on (committed another page) or closed: its explanation hold and its passes end. */
  const tabMovedOn = async (tabId: number): Promise<void> => {
    const b = await loadBook();
    const was = b.explaining.some((e) => e.tabId === tabId);
    if (was) {
      b.explaining = b.explaining.filter((e) => e.tabId !== tabId);
      await saveBook();
      deps.onExplainEnded?.(tabId);
    }
    await dropPasses((p) => p.tabId === tabId);
  };

  /**
   * At worker start: a pass whose time is up, or an allow rule in our range the book does not know (a worker
   * that stopped before writing, an older build), is removed; live passes get their timers back; stale holds go.
   */
  const startupCleanup = async (): Promise<void> => {
    const b = await loadBook();
    const now = Date.now();
    b.explaining = b.explaining.filter((e) => now - e.at < EXPLAIN_TTL_MS);
    const expired = b.passes.filter((p) => p.expiresAt <= now);
    b.passes = b.passes.filter((p) => p.expiresAt > now);
    const live = new Set(b.passes.map((p) => p.id));
    const existing = await chrome.declarativeNetRequest.getSessionRules().catch(() => [] as chrome.declarativeNetRequest.Rule[]);
    const orphans = existing.map((r) => r.id).filter((id) => id >= NAV_ALLOW_RULE_MIN && id <= NAV_ALLOW_RULE_MAX && !live.has(id));
    await Promise.all([saveBook(), removeRules([...new Set([...orphans, ...expired.map((p) => p.id)])])]);
    for (const p of b.passes) armTimer(p);
  };

  const explainingFor = async (tabId: number): Promise<Explaining | undefined> => {
    const b = await loadBook();
    const e = b.explaining.find((x) => x.tabId === tabId);
    return e !== undefined && Date.now() - e.at < EXPLAIN_TTL_MS ? e : undefined;
  };

  const allowOnce = async (tabId: number, url: string): Promise<boolean> => {
    const b = await loadBook();
    // Only while the tab still shows our explanation page for this address: a tab that moved on is not reopened.
    const e = await explainingFor(tabId);
    if (e === undefined || e.digest !== navigationDigest(b.salt, url)) return false;
    const id = b.nextId;
    b.nextId = b.nextId >= NAV_ALLOW_RULE_MAX ? NAV_ALLOW_RULE_MIN : b.nextId + 1;
    const rule = allowOnceRule(id, tabId, url);
    if (rule === null) return false;
    // A tab holds at most one pass; an id being reused is cleared first.
    await dropPasses((p) => p.tabId === tabId || p.id === id);
    try {
      await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [id], addRules: [rule] });
    } catch {
      await saveBook();
      return false;
    }
    const pass: Pass = { id, tabId, host: hostOf(url) ?? "", expiresAt: Date.now() + NAV_ALLOW_TTL_MS };
    b.passes = [...b.passes, pass];
    armTimer(pass);
    await saveBook();
    try {
      await chrome.tabs.update(tabId, { url });
    } catch {
      await dropPasses((p) => p.id === id);
      return false;
    }
    return true;
  };

  return {
    install() {
      // The pass is spent once the tab commits a page on that host (or any other top-level page), or the tab closes.
      chrome.webNavigation.onCommitted.addListener((d) => {
        if (d.frameId !== 0 || d.url.startsWith(chrome.runtime.getURL("blocked.html"))) return;
        void tabMovedOn(d.tabId).catch(() => undefined);
      });
      chrome.tabs.onRemoved.addListener((tabId) => {
        void tabMovedOn(tabId).catch(() => undefined);
      });
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area === "session" && (STATE_KEY in changes || NAV_HOSTS_KEY in changes)) void sync().catch(() => undefined);
      });
      chrome.webNavigation.onErrorOccurred.addListener((d) => {
        if (d.frameId !== 0 || !/ERR_BLOCKED_BY_CLIENT/.test(d.error)) return;
        void (async () => {
          const rule = await ourRuleFor(d.tabId, d.url);
          if (rule === null) return; // another extension's block
          // Approvable only when the engine, asked now, says approve for this rule (capture hosts, metadata addresses and script URLs are denies).
          const now = decideNavigation({ url: d.url, resourceType: "main_frame" }, effectiveTrust(await deps.store.load(), d.tabId), await deps.policy());
          const approvable = deps.requestApproval !== undefined && now.verdict === "approve" && now.rule === rule;
          deps.log({ site: registrableDomain(hostOf(d.url) ?? ""), rule, verdict: rule === "nav.capture_host" ? "deny" : "approve" });
          const b = await loadBook();
          await chrome.tabs.update(d.tabId, { url: chrome.runtime.getURL(explanationPath(rule, d.url, approvable)) });
          const digest = navigationDigest(b.salt, d.url);
          // Held only for an approvable block: nothing else will ever reopen it.
          b.explaining = [...b.explaining.filter((e) => e.tabId !== d.tabId), ...(approvable ? [{ tabId: d.tabId, url: d.url, digest, at: Date.now() }] : [{ tabId: d.tabId, url: "", digest: "", at: Date.now() }])];
          void saveBook();
          if (approvable) await deps.requestApproval?.({ tabId: d.tabId, url: d.url, host: hostOf(d.url) ?? "", chars: dataCharsOf(d.url), digest, rule, reasons: [...now.reasons] });
        })().catch(() => undefined);
      });
      chrome.tabs.onCreated.addListener((tab) => {
        if (tab.id === undefined) return;
        const id = tab.id;
        const opener = tab.openerTabId;
        // A tab with no opener is recorded too: in agent mode it joins the session (an agent's chrome.tabs.create).
        void deps.store.update((s) => tabOpened(s, id, opener)).catch(() => undefined);
      });
      void startupCleanup().catch(() => undefined);
      void sync().catch(() => undefined);
    },

    async handle(msg, tabId, senderUrl) {
      switch (msg.type) {
        case "tab.mode": {
          const reply: TabModeReply = { agentMode: effectiveTrust(await deps.store.load(), tabId).agentMode };
          return reply;
        }
        case "nav.hosts": {
          await loadHosts();
          const before = hosts.size;
          for (const raw of msg.hosts) {
            const h = raw.toLowerCase().replace(/^\[|\]$/g, "");
            // The content script's word is not enough: the worker checks the shape itself.
            if (hosts.size < MAX_HOSTS && (isRawIp(h) || isDnsExfilShape(h))) hosts.add(h);
          }
          if (hosts.size !== before) await chrome.storage.session.set({ [NAV_HOSTS_KEY]: [...hosts] });
          return undefined;
        }
        case "nav.blocked": {
          deps.log({ site: registrableDomain(hostOf(senderUrl) ?? ""), rule: msg.rule, verdict: "deny" });
          return undefined;
        }
      }
    },

    sync,
    allowOnce,
    async canReopen(tabId, digest) {
      const e = await explainingFor(tabId);
      return e !== undefined && e.digest !== "" && e.digest === digest;
    },
    async reopen(tabId, digest) {
      const e = await explainingFor(tabId);
      if (e === undefined || e.digest === "" || e.digest !== digest) return false;
      return allowOnce(tabId, e.url);
    },
  };
}
