/**
 * Service worker entry. Routes messages from our own content scripts and
 * extension pages (sender-checked, then validated) to the engine, keeps tab
 * trust in chrome.storage.session, and tracks navigations and openers.
 *
 * Thin by design: the decisions are the engine's; persistence, approvals and
 * the log are their own modules (state.ts, approvals.ts, log.ts), and the
 * downloads gate is downloads.ts.
 */
import { ADAPTERS } from "../engine/adapters.js";
import { agentModeOffProof, agentModeOffSnapshot } from "../engine/bindings.js";
import { hostOf, originOf, registrableDomain } from "../engine/domain.js";
import { saltedFingerprint, snapshotOf } from "../engine/fingerprint.js";
import { decide } from "../engine/rules.js";
import { addSessionGrant, effectiveTrust, endAgentSession, linkedAgentTainted, pageShown, privateDataShown, sessionTaintForLink, startAgentSession, tabClosed, tabOpened, topLevelNavigated, type BrowserState } from "../engine/session.js";
import { DEFAULT_POLICY, SESSION_GRANTABLE_CLASSES, type Decision, type Policy, type RuleId } from "../engine/types.js";
import {
  isFromOwnContentScript,
  isFromOwnExtensionPage,
  parseContentMessage,
  parseGateContentMessage,
  parseGateUiMessage,
  parseLinkUiMessage,
  parseUiMessage,
  type ApprovalsState,
  type ApprovalView,
  type ContentMessage,
  type GateContentMessage,
  type GatePosture,
  type GateUiBroadcast,
  type GateUiMessage,
  type GateWorkerMessage,
  type LinkSetReply,
  type LinkUiMessage,
  type UiMessage,
  type UiState,
  type WorkerToContentMessage,
} from "../shared/messages.js";
import { actionMeta, agentModeOffMeta, downloadMeta, navigationMeta, navigationSnapshot, untrustedBecause, viewOf } from "./approval-view.js";
import type { ApprovalRecord } from "../engine/bindings.js";
import { createApprovalService, randomId, type ApprovalMeta } from "./approvals.js";
import { createDownloadGate, downloadSnapshot, holdOnDeterminingFilename, type OfferedDownload } from "./downloads.js";
import { createGuardNav } from "./guard-nav.js";
import { createLeakAgent } from "./leak-agent.js";
import { createIdbBackend, createLog, type DecisionLog } from "./log.js";
import { createLink, type ApprovalOffer } from "./link.js";
import { createSettingsStore, policyWith, retentionFrom } from "./settings.js";
import { createSenderLog, type SenderLog } from "./sender-log.js";
import { senderKey, TokenBuckets } from "./rate-limit.js";
import { candidates, senderFacts, strictest, type SenderFacts } from "./sender.js";
import { createStateStore, type StateStore } from "./state.js";
import { uiAllowed, uiSurfaceOf, type ApprovalWindow } from "./ui-surface.js";

const rawStore = createStateStore(chrome.storage.session);
// A pending approval retired to keep the queue bounded (RR10): its frame lets go of the held action, and the
// firewall's copy of it (native link) is closed.
const approvals = createApprovalService(chrome.storage.session, {
  onEvicted: (records) => {
    for (const r of records) {
      if (r.purpose === "action" && r.snapshot.tabId >= 0) sendToFrame(r.snapshot.tabId, r.snapshot.frameId, { type: "approval.denied", approvalId: r.id });
      link.cancelApproval(linkBinding(r));
    }
    broadcastUi();
  },
});
const downloads = createDownloadGate({ extensionId: chrome.runtime.id });
const settings = createSettingsStore(chrome.storage.local);
// The log reads the person's retention period from storage on every purge, so a purge at worker start never
// uses the default before the setting has loaded (RR8).
const baseLog = createLog({ backend: createIdbBackend(), retentionMs: retentionFrom(settings) });
void baseLog.purge().catch(() => undefined);

// ---- native link (design 10): optional, off until the person turns it on -----------------------

/**
 * The binding an approval is filed with on the firewall: its fingerprint salted with a random value that lives
 * only as long as this worker (and so this native port). The unsalted fingerprint of a held one-time code could
 * be matched against every candidate code, so, like the decision log's bindings (RR11), it never leaves the
 * browser. A restarted worker has a new salt and a new connection, and files its pending approvals again.
 */
const LINK_BINDING_SALT = randomId();
function linkBinding(r: ApprovalRecord): string {
  return saltedFingerprint(r.snapshot, LINK_BINDING_SALT);
}

const link = createLink({
  area: chrome.storage.local,
  connect: (name) => chrome.runtime.connectNative(name),
  lastError: () => chrome.runtime.lastError?.message,
  hasPermission: () => chrome.permissions.contains({ permissions: ["nativeMessaging"] }),
  entriesAfter: async (seq) => (await baseLog.list()).filter((e) => e.seq > seq),
  headSeq: async () => (await baseLog.list({ limit: 1 }))[0]?.seq ?? -1,
  currentTaint: async () => sessionTaintForLink(await rawStore.load()),
  onAgentTaint: async (agent) => {
    await store.update((s) => linkedAgentTainted(s, agent));
    await log.append({ at: Date.now(), site: "", actionClass: null, verdict: "log", rules: [], event: "link_taint", detail: [agent] });
    await leakAgent.pushContexts();
    broadcastUi();
  },
  onApprovalResult: async (binding, verdict) => {
    const rec = (await approvals.pending()).find((r) => linkBinding(r) === binding);
    if (rec === undefined) return;
    if (verdict === "approve") await approve(rec.id, false);
    else await denyApproval(rec.id);
  },
  pendingApprovals: async () => {
    const out: ApprovalOffer[] = [];
    for (const r of await approvals.pending()) {
      const m = await approvals.meta(r.id);
      if (m !== undefined) out.push(offerOf(r, m));
    }
    return out;
  },
  onChange: () => broadcastUi(),
  version: chrome.runtime.getManifest().version,
});
void link.start().catch(() => undefined);
chrome.permissions.onRemoved.addListener((p) => {
  if (p.permissions?.includes("nativeMessaging") === true) void link.permissionRemoved();
});

/**
 * What the firewall's queue shows for a pending approval: its label and site, never field values (the stored
 * metadata holds only masked previews, RR9) and never a blocked navigation's address (its label is a character
 * count and its site the destination's registrable domain).
 */
function offerOf(r: ApprovalRecord, m: ApprovalMeta): ApprovalOffer {
  const site = registrableDomain(hostOf(m.pageUrl) ?? hostOf(r.snapshot.frameOrigin) ?? hostOf(r.snapshot.targetOrigin) ?? "");
  return { binding: linkBinding(r), kind: r.purpose === "agent_mode_off" ? "agent_mode_off" : m.subject === "action" ? r.snapshot.kind : m.subject, actionClass: r.snapshot.actionClass, site, label: m.label };
}

/** Every decision is mirrored to the firewall's signed log while the link is up, and so is a deletion of the log (RR14). */
const log: DecisionLog = {
  ...baseLog,
  async append(entry) {
    const chained = await baseLog.append(entry);
    link.forward(chained);
    return chained;
  },
  async clear() {
    await baseLog.clear();
    const marker = (await baseLog.list({ limit: 1 }))[0];
    if (marker !== undefined) link.logCleared(marker);
  },
};

/**
 * Per-frame budgets. A page controls how often its frames make our content script ask: scans (leak.guard,
 * action.check) are limited in calls and in characters scanned, the log rows a frame causes are limited (I11),
 * and so are the link hosts it can add to the navigation rules. Over budget, a scan gets no answer (the content
 * script fails closed: the value stays held, the action is dropped) and a log row is counted and dropped.
 */
const scanCalls = new TokenBuckets({ capacity: 120, refillPerSecond: 40 });
const scanChars = new TokenBuckets({ capacity: 4 * 1024 * 1024, refillPerSecond: 1024 * 1024 });
const senderLog: SenderLog = createSenderLog(log, new TokenBuckets({ capacity: 60, refillPerSecond: 10 }));
const navHostBudget = new TokenBuckets({ capacity: 200, refillPerSecond: 1 });

/** The agent session's taint goes to the firewall the moment it appears (once per session). */
const store: StateStore = {
  load: () => rawStore.load(),
  async update(fn) {
    const s = await rawStore.update(fn);
    const t = sessionTaintForLink(s);
    if (t !== null) link.taint(t.session, t.reason);
    return s;
  },
};

// guard/nav: tab.mode, link hosts, navigation session rules and the explanation page (guard-nav.ts).
const guardNav = createGuardNav({
  store,
  policy: () => policy(),
  log: (e) => void log.append({ at: Date.now(), site: e.site, actionClass: null, verdict: e.verdict, rules: [e.rule] }),
  // Integration: an approvable blocked navigation becomes an approval in the gate's service, approved from our own UI.
  requestApproval: async (req) => {
    const s = await store.load();
    await requestApproval(navigationSnapshot(req.tabId, originOf(req.url) ?? "", req.digest), "action", navigationMeta(req, untrustedBecause(s, req.tabId)));
  },
  // The tab left the explanation page or closed: its navigation approval can no longer be carried out (RR14).
  onExplainEnded: (tabId) => void approvals.expireNavigations(tabId).then((n) => n > 0 && broadcastUi()),
});
guardNav.install();

/** Who may read chrome.storage.session: only extension pages and the worker, never content scripts. */
void chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
/**
 * Settings, the link state and the site lists live in chrome.storage.local, which content scripts can read and
 * write by default; a content script never needs them, so they are closed to it too (m10). Chrome versions that
 * do not support the call for this area leave it as it was (the content script still never touches it).
 */
{
  const local = chrome.storage.local as chrome.storage.StorageArea & { setAccessLevel?: (o: { accessLevel: string }) => Promise<void> };
  if (typeof local.setAccessLevel === "function") void local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" }).catch(() => undefined);
}

/** The engine policy with the person's settings (always-on rows) from chrome.storage.local. */
async function policy(): Promise<Policy> {
  return policyWith(await settings.load(), DEFAULT_POLICY);
}

export const COVERAGE_NOTE =
  "Holds for page scripts and for agents that drive this browser through another extension, on the actions it gates. " +
  "It does not hold against agents that control this browser remotely (Playwright, DevTools clients), agents that control your whole computer, or agents in the cloud.";

function sendToFrame(tabId: number, frameId: number, msg: WorkerToContentMessage | GateWorkerMessage): void {
  chrome.tabs.sendMessage(tabId, msg, { frameId }).catch(() => undefined);
}

async function broadcastAgentMode(on: boolean): Promise<void> {
  const tabs = await chrome.tabs.query({});
  for (const t of tabs) if (t.id !== undefined) chrome.tabs.sendMessage(t.id, { type: "agent.mode", on } satisfies WorkerToContentMessage).catch(() => undefined);
  broadcastUi();
}

// ---- gate/approvals: surfaces -------------------------------------------------------

/** Extension pages re-fetch their state on this; nothing else receives runtime broadcasts from the worker. */
function broadcastUi(): void {
  chrome.runtime.sendMessage({ type: "ui.changed" } satisfies GateUiBroadcast).catch(() => undefined);
}

const APPROVAL_WINDOW_KEY = "ls.approvalWindow";

/**
 * The approval window (design 5.4): an extension page in its own small
 * window, opened when an approval is requested (the side panel cannot be
 * opened without a gesture in our own UI). One window at a time; it lists
 * every pending approval and closes itself when none is left.
 */
const FOCUS_EVERY_MS = 5000;
let windowChain: Promise<void> = Promise.resolve();
let lastFocusAt = 0;

/**
 * Calls run one after another (two requests arriving together would otherwise each find no window and open
 * two), and an existing window is brought to the front at most once every FOCUS_EVERY_MS: a flood of approvals
 * must not keep taking the person's focus, and the window already lists every pending approval.
 */
function openApprovalWindow(): Promise<void> {
  windowChain = windowChain.then(openApprovalWindowNow, openApprovalWindowNow);
  return windowChain;
}

async function openApprovalWindowNow(): Promise<void> {
  try {
    const got = await chrome.storage.session.get(APPROVAL_WINDOW_KEY);
    const existing = parseApprovalWindow(got[APPROVAL_WINDOW_KEY]);
    if (existing !== undefined) {
      try {
        if (Date.now() - lastFocusAt < FOCUS_EVERY_MS) {
          await chrome.windows.get(existing.windowId);
        } else {
          lastFocusAt = Date.now();
          await chrome.windows.update(existing.windowId, { focused: true, drawAttention: true });
        }
        return;
      } catch {
        // Closed by the person: open a new one.
      }
    }
    const w = await chrome.windows.create({ url: chrome.runtime.getURL("approval.html"), type: "popup", width: 440, height: 620, focused: true });
    lastFocusAt = Date.now();
    if (w?.id !== undefined) {
      // The window's one tab is part of what marks it as ours (ui-surface.ts): its messages carry that tab's id.
      const tabId = w.tabs?.[0]?.id ?? (await chrome.tabs.query({ windowId: w.id }).catch(() => []))[0]?.id;
      if (tabId !== undefined) await chrome.storage.session.set({ [APPROVAL_WINDOW_KEY]: { windowId: w.id, tabId } satisfies ApprovalWindow });
      else await chrome.windows.remove(w.id).catch(() => undefined);
    }
  } catch {
    // No window (a headless or locked session): the side panel still lists the approval.
  }
}

function parseApprovalWindow(v: unknown): ApprovalWindow | undefined {
  if (typeof v !== "object" || v === null) return undefined;
  const x = v as Partial<ApprovalWindow>;
  return typeof x.windowId === "number" && typeof x.tabId === "number" ? { windowId: x.windowId, tabId: x.tabId } : undefined;
}

chrome.windows.onRemoved.addListener((windowId) => {
  void chrome.storage.session.get(APPROVAL_WINDOW_KEY).then((got) => {
    if (parseApprovalWindow(got[APPROVAL_WINDOW_KEY])?.windowId === windowId) return chrome.storage.session.remove(APPROVAL_WINDOW_KEY);
    return undefined;
  });
});

function postureOf(s: BrowserState, tabId: number): GatePosture {
  const t = effectiveTrust(s, tabId);
  return { agentMode: t.agentMode, quarantined: t.quarantined };
}

const windowedApprovals = new Set<string>();

async function requestApproval(...args: Parameters<typeof approvals.request>): Promise<string> {
  const rec = await approvals.request(...args);
  link.requestApproval(offerOf(rec, args[2]));
  broadcastUi();
  // A request identical to one already pending comes back as that record: it needs no new window or focus.
  if (!windowedApprovals.has(rec.id)) {
    if (windowedApprovals.size >= 1000) windowedApprovals.clear();
    windowedApprovals.add(rec.id);
    void openApprovalWindow();
  }
  return rec.id;
}

// ---- gate/approvals: downloads ---------------------------------------------------

/**
 * The tab a download came from, when the browser says so. When it does not, -1: the download is judged against
 * the whole session (the stricter view), never against a guessed tab that might be cleaner than the real one.
 */
function downloadTabId(d: OfferedDownload): number {
  return d.tabId !== undefined && d.tabId >= 0 ? d.tabId : -1;
}

async function holdDownload(d: OfferedDownload): Promise<void> {
  const p = await policy();
  const s = await store.load();
  const tabId = downloadTabId(d);
  const decision = decide({ kind: "download", ...(tabId >= 0 ? { tabId } : {}), url: d.url, filename: d.filename, mime: d.mime }, effectiveTrust(s, tabId), p, ADAPTERS);
  await log.append({ at: Date.now(), site: registrableDomain(hostOf(d.url) ?? ""), actionClass: decision.actionClass, verdict: decision.verdict, rules: [decision.rule] });
  if (decision.verdict === "approve" || (decision.verdict === "deny" && decision.override !== undefined)) {
    await requestApproval(downloadSnapshot(d), "action", downloadMeta(d, decision, s.session !== null || tabId >= 0 ? untrustedBecause(s, tabId) : []));
  } else if (decision.verdict !== "deny") {
    startApprovedDownload(d.url);
  }
}

function startApprovedDownload(url: string): void {
  downloads.allowOnce(url);
  chrome.downloads.download({ url, conflictAction: "uniquify" }).catch(() => undefined);
}

chrome.downloads.onDeterminingFilename.addListener(
  holdOnDeterminingFilename(downloads, {
    cancel: (id) => chrome.downloads.cancel(id),
    hold: (d) => void holdDownload(d),
  }),
);

const leakAgent = createLeakAgent({
  store,
  approvals,
  log,
  settings,
  policy,
  broadcastAgentMode,
  onApprovalRequested: () => {
    broadcastUi();
    void openApprovalWindow();
  },
  tabIds: async () => (await chrome.tabs.query({})).flatMap((t) => (t.id === undefined ? [] : [t.id])),
  sendToTab: (tabId, msg) => void chrome.tabs.sendMessage(tabId, msg).catch(() => undefined),
});

// ---- content scripts ----------------------------------------------------------

async function handleContent(msg: ContentMessage | GateContentMessage, from: SenderFacts): Promise<unknown> {
  const { tabId, frameId } = from;
  const key = senderKey(tabId, frameId);
  // Over this frame's scan budget: no answer, which the content script treats as unreachable (fail closed).
  if (msg.type === "leak.guard" || msg.type === "action.check") {
    const chars = msg.type === "leak.guard" ? msg.text.length + 1 : 1;
    if (!scanCalls.take(key) || !scanChars.take(key, chars)) return undefined;
  }
  const p = await policy();
  // Only Chrome's sender URL marks the tab: a body URL could name a trusted host, or add a domain to the session.
  const url = from.url;
  switch (msg.type) {
    case "frame.hello":
      await store.update((s) => pageShown(leakAgent.joinIfAgentMode(s, tabId), tabId, { url }, p));
      return undefined;
    case "page.scanned": {
      const s = await store.update((st) => pageShown(leakAgent.joinIfAgentMode(st, tabId), tabId, { url, verdict: msg.verdict, scanIncomplete: msg.scanIncomplete }, p));
      // A quarantine verdict gates every class on the tab: tell the tab's gates now.
      if (msg.verdict === "quarantine") chrome.tabs.sendMessage(tabId, { type: "gate.posture", posture: postureOf(s, tabId) } satisfies GateWorkerMessage).catch(() => undefined);
      if (msg.verdict === "quarantine" || msg.verdict === "flag") await leakAgent.pushContexts();
      if (msg.verdict === "quarantine") {
        // Logged with the hidden text's start only when the person keeps evidence (escaped and cut to 200 by the log).
        const keep = (await settings.load()).keepEvidence;
        await senderLog.append(key, {
          at: Date.now(),
          site: registrableDomain(from.host),
          actionClass: null,
          verdict: "log",
          rules: [],
          event: "quarantine",
          detail: msg.reasons.slice(0, 16),
          ...(keep && msg.preview !== undefined && msg.preview !== "" ? { evidence: msg.preview } : {}),
        });
      }
      return undefined;
    }
    case "private.prints": {
      // The strings were shown by the sender's frame, whatever domain the body claims for them.
      const domain = registrableDomain(from.host);
      const prints = msg.prints.map((pr) => ({ ...pr, domain }));
      await store.update((s) => privateDataShown(leakAgent.joinIfAgentMode(s, tabId), tabId, prints));
      await leakAgent.pushContexts();
      return undefined;
    }
    case "gate.posture":
      return postureOf(await store.load(), tabId);
    case "action.check": {
      const frame = { tabId, frameId, origin: from.origin };
      // The frame's URL from Chrome classifies the action; the tab's URL and the body's pageUrl are hints
      // that can only make the decision stricter.
      const s = await store.load();
      const trust = effectiveTrust(s, tabId);
      const judged = candidates(from.url, from.tabUrl, msg.action.context.pageUrl).map((pageUrl) => {
        const action = { ...msg.action, frame, context: { ...msg.action.context, pageUrl } };
        return { action, decision: decide(action, trust, p, ADAPTERS) };
      }) as [{ action: typeof msg.action; decision: Decision }, ...{ action: typeof msg.action; decision: Decision }[]];
      const { decision } = strictest(judged);
      // The approval shows (and binds to) the action as Chrome reports its frame.
      const action = judged[0].action;
      let approvalId: string | undefined;
      if (decision.verdict === "approve" || (decision.verdict === "deny" && decision.override !== undefined)) {
        approvalId = await requestApproval(snapshotOf(action, decision.actionClass), "action", actionMeta(action, decision, untrustedBecause(s, tabId)));
      }
      await senderLog.append(key, { at: Date.now(), site: registrableDomain(from.host), actionClass: decision.actionClass, verdict: decision.verdict, rules: [decision.rule] });
      return approvalId === undefined ? { decision } : { decision, approvalId };
    }
    case "tab.mode":
      return guardNav.handle(msg, tabId, url);
    case "nav.hosts": {
      // At most a budget of hosts per frame (m8): a page cannot fill the browser-wide list with junk hosts.
      const hosts = msg.hosts.filter(() => navHostBudget.take(key));
      return hosts.length === 0 ? undefined : guardNav.handle({ ...msg, hosts }, tabId, url);
    }
    case "nav.blocked":
      await senderLog.append(key, { at: Date.now(), site: registrableDomain(hostOf(url) ?? ""), actionClass: null, verdict: "deny", rules: [msg.rule] });
      return undefined;
    case "approval.redeem": {
      // The tab, frame and frame origin are the sender's, whatever the message says.
      const presented = { ...msg.snapshot, tabId, frameId, frameOrigin: from.origin };
      const r = await approvals.redeem(msg.token, presented);
      broadcastUi();
      return r.ok ? { ok: true } : { ok: false, reason: r.reason };
    }
    // ---- leak/agent/log (leak lane) ----
    case "leak.guard":
    case "leak.context":
    case "agent.signal":
      return leakAgent.content(msg, { tabId, frameId, origin: from.origin, host: from.host, log: { append: (e) => senderLog.append(key, e) } });
  }
}

// ---- extension UI -------------------------------------------------------------------

async function approvalsState(): Promise<ApprovalsState> {
  const s = await store.load();
  const views = [];
  for (const r of await approvals.pending()) {
    const v = viewOf(r, await approvals.meta(r.id));
    if (s.session === null) v.siteGrantable = false;
    views.push(v);
  }
  return { agentMode: s.session !== null, approvals: views, coverageNote: COVERAGE_NOTE };
}

/**
 * A blocked navigation's approval: carried out only while the tab still shows the explanation page for that
 * address, and spent only once the tab is on its way (RR7). If the tab moved on, the approval expires; if the
 * reopen fails, it goes back to pending (not consumed) for the person to try again.
 */
async function approveNavigation(rec: ApprovalRecord, nav: { tabId: number; host: string; digest: string; rule: RuleId }): Promise<{ ok: boolean }> {
  if (!(await guardNav.canReopen(nav.tabId, nav.digest))) {
    await approvals.expireNavigations(nav.tabId);
    link.cancelApproval(linkBinding(rec));
    broadcastUi();
    return { ok: false };
  }
  const token = await approvals.approve(rec.id);
  if (token === null) {
    broadcastUi();
    return { ok: false };
  }
  if (!(await guardNav.reopen(nav.tabId, nav.digest))) {
    await approvals.unapprove(rec.id);
    // Back to pending (not spent): if the firewall approved it, its queue gets the item again.
    const m = await approvals.meta(rec.id);
    if (m !== undefined) link.requestApproval(offerOf(rec, m));
    broadcastUi();
    return { ok: false };
  }
  link.cancelApproval(linkBinding(rec));
  const r = await approvals.redeem(token, rec.snapshot);
  broadcastUi();
  await log.append({ at: Date.now(), site: registrableDomain(nav.host), actionClass: null, verdict: "approve", rules: [nav.rule], approval: r.ok ? "redeemed" : "refused" });
  return { ok: true };
}

/** Approve: the token goes to the frame that holds the action (or the worker replays a download / ends agent mode). */
async function approve(approvalId: string, forSite: boolean): Promise<{ ok: boolean }> {
  const rec = await approvals.get(approvalId);
  const meta = await approvals.meta(approvalId);
  if (rec === undefined || rec.state !== "pending") return { ok: false };
  let grant: { domain: string; cls: NonNullable<typeof rec.snapshot.actionClass> } | null = null;
  if (forSite) {
    // Only for a grantable class, inside an agent session, and never for an overridden deny (design 9). The grant
    // names the site the card names: the frame's real host, never a page-named form target (RR3). A submit or
    // upload whose target is elsewhere is judged against that target too (rules.ts), so it still asks there.
    const cls = rec.snapshot.actionClass;
    const domain = registrableDomain(hostOf(rec.snapshot.frameOrigin) ?? "");
    if (cls === null || !SESSION_GRANTABLE_CLASSES.includes(cls) || meta?.overridesDeny === true || domain === "" || (await store.load()).session === null) return { ok: false };
    grant = { domain, cls };
  }
  if (meta?.subject === "navigation" && meta.navigation !== undefined) return approveNavigation(rec, meta.navigation);
  const token = await approvals.approve(approvalId);
  broadcastUi();
  if (token === null) return { ok: false };
  link.cancelApproval(linkBinding(rec));
  // The grant is saved only once the approval is confirmed (RR13).
  if (grant !== null) {
    const g = grant;
    await store.update((s) => addSessionGrant(s, g.domain, g.cls).state);
  }
  if (rec.purpose === "agent_mode_off") {
    const proof = agentModeOffProof(await approvals.redeem(token, agentModeOffSnapshot(), "agent_mode_off"));
    let ended = false;
    await store.update((s) => {
      const r = endAgentSession(s, proof);
      ended = r.ended;
      return r.state;
    });
    if (ended) {
      await broadcastAgentMode(false);
      await leakAgent.agentModeChanged(false, "person_approved");
    }
    return { ok: ended };
  }
  if (meta?.subject === "download" && meta.download !== undefined) {
    const r = await approvals.redeem(token, rec.snapshot);
    if (!r.ok) return { ok: false };
    startApprovedDownload(meta.download.url);
    await log.append({ at: Date.now(), site: registrableDomain(hostOf(meta.download.url) ?? ""), actionClass: "download_exec", verdict: "approve", rules: ["gate.always_on"], approval: "redeemed" });
    return { ok: true };
  }
  sendToFrame(rec.snapshot.tabId, rec.snapshot.frameId, { type: "approval.granted", approvalId: rec.id, token });
  return { ok: true };
}

async function denyApproval(approvalId: string): Promise<{ ok: boolean }> {
  const rec = await approvals.get(approvalId);
  const ok = await approvals.deny(approvalId);
  if (ok && rec !== undefined && rec.purpose === "action" && rec.snapshot.tabId >= 0) sendToFrame(rec.snapshot.tabId, rec.snapshot.frameId, { type: "approval.denied", approvalId: rec.id });
  if (ok && rec !== undefined) link.cancelApproval(linkBinding(rec));
  broadcastUi();
  return { ok };
}

async function handleLinkUi(msg: LinkUiMessage): Promise<unknown> {
  if (msg.type === "ui.link.state") return link.status();
  // Turning the link off weakens protection (no signed log, no shared taint): refused while agent mode is on, like other weakening settings.
  if (!msg.on && (await store.load()).session !== null) return { ok: false, reason: "agent_mode" } satisfies LinkSetReply;
  return link.setEnabled(msg.on) as Promise<LinkSetReply>;
}

async function handleUi(msg: UiMessage | GateUiMessage): Promise<unknown> {
  switch (msg.type) {
    case "ui.state": {
      const s = await store.load();
      const pending: ApprovalView[] = [];
      for (const r of await approvals.pending()) {
        if (r.purpose !== "action") continue;
        const v = viewOf(r, await approvals.meta(r.id));
        pending.push({ ...v, kind: v.kind === "download" || v.kind === "agent_mode_off" || v.kind === "navigate" ? "activate" : v.kind });
      }
      const state: UiState = { agentMode: s.session !== null, pending, coverageNote: COVERAGE_NOTE };
      return state;
    }
    case "ui.approvals":
      return approvalsState();
    case "ui.approve":
      return approve(msg.approvalId, false);
    case "ui.approveForSite":
      return approve(msg.approvalId, true);
    case "ui.deny":
      return denyApproval(msg.approvalId);
    case "ui.agentMode": {
      if (msg.on) {
        const active = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        await store.update((s) => startAgentSession(s, { now: Date.now(), tabIds: active.flatMap((t) => (t.id === undefined ? [] : [t.id])) }));
        await broadcastAgentMode(true);
        await leakAgent.agentModeChanged(true, "person");
        return { ok: true };
      }
      // Turning off is gated (design 8): the person confirms the approval this creates.
      return { ok: true, approvalId: await requestApproval(agentModeOffSnapshot(), "agent_mode_off", agentModeOffMeta()) };
    }
    // ---- leak/agent/log (leak lane) ----
    case "ui.log.list":
    case "ui.log.verify":
    case "ui.log.export":
    case "ui.log.clear":
    case "ui.settings.get":
    case "ui.settings.set":
      return leakAgent.ui(msg);
  }
}

chrome.runtime.onMessage.addListener((raw: unknown, sender, sendResponse) => {
  const id = chrome.runtime.id;
  if (isFromOwnContentScript(sender, id)) {
    const msg = parseContentMessage(raw) ?? parseGateContentMessage(raw);
    if (msg === null) return false;
    handleContent(msg, senderFacts(sender)).then(sendResponse, () => sendResponse(undefined));
    return true;
  }
  if (isFromOwnExtensionPage(sender, id)) {
    const linkMsg = parseLinkUiMessage(raw);
    const msg = linkMsg ?? parseUiMessage(raw) ?? parseGateUiMessage(raw);
    if (msg === null) return false;
    // Which of our pages sent it decides what it may ask for (ui-surface.ts): approving, denying and agent mode
    // only from the side panel or our own approval window; settings, the log and the link switch only from the
    // side panel. Our pages opened in an ordinary tab can only read.
    void chrome.storage.session
      .get(APPROVAL_WINDOW_KEY)
      .then(
        (got) => parseApprovalWindow(got[APPROVAL_WINDOW_KEY]),
        () => undefined,
      )
      .then((approvalWindow) => {
        if (!uiAllowed(msg.type, uiSurfaceOf(sender, id, approvalWindow))) return { ok: false, reason: "surface" };
        return linkMsg !== null ? handleLinkUi(linkMsg) : handleUi(msg as UiMessage | GateUiMessage);
      })
      .then(sendResponse, () => sendResponse(undefined));
    return true;
  }
  return false;
});

chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId === 0) {
    void approvals.onTabNavigated(d.tabId).then((n) => n > 0 && broadcastUi());
    void store.update((s) => topLevelNavigated(s, d.tabId));
  } else {
    void approvals.onFrameNavigated(d.tabId, d.frameId).then((n) => n > 0 && broadcastUi());
  }
});

// guard-nav records every tab from chrome.tabs.onCreated, with or without an opener: in agent mode a tab an
// agent opens with chrome.tabs.create joins the session (engine tabOpened).
chrome.webNavigation.onCreatedNavigationTarget.addListener((d) => {
  void store.update((s) => tabOpened(s, d.tabId, d.sourceTabId));
});

chrome.tabs.onRemoved.addListener((tabId) => {
  void approvals.onTabNavigated(tabId).then((n) => n > 0 && broadcastUi());
  void store.update((s) => tabClosed(s, tabId));
});
