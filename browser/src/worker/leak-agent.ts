/**
 * The worker side of the leak guard, agent mode detection and the log/settings
 * view (leak lane). index.ts routes the "leak/agent/log" messages here.
 *
 * - leak.guard: the authoritative leak decision for a value a content script
 *   held back (or let through with a warning). Logged; an approve verdict
 *   becomes a pending approval bound to the exact text, field and frame.
 * - leak.context: the context a frame decides with synchronously; pushed to
 *   every tab again whenever prints, trust or agent mode change.
 * - agent.signal (navigator.webdriver): a strong signal (design 8) that turns
 *   agent mode on when the person has detection on (the default).
 * - While agent mode is on, every tab that shows a page joins the session:
 *   agent mode is browser-wide, and an agent may open tabs with no opener.
 * - ui.log.* and ui.settings.*: the side panel's log and settings view. Deleting
 *   the log and weakening settings are refused while agent mode is on.
 */
import { saltedFingerprint } from "../engine/fingerprint.js";
import { hostOf, originOf, registrableDomain } from "../engine/domain.js";
import { decideLeak, leakContextOf, leakSnapshot, type LeakContext } from "../engine/leak.js";
import { effectiveTrust, startAgentSession, type BrowserState } from "../engine/session.js";
import type { Policy } from "../engine/types.js";
import type { LeakAgentLogContentMessage, LeakAgentLogUiMessage, LeakAgentLogWorkerMessage, LeakReply, LogEntry, Settings, SettingsReply } from "../shared/messages.js";
import { leakMeta, untrustedBecause } from "./approval-view.js";
import type { ApprovalService } from "./approvals.js";
import type { DecisionLog } from "./log.js";
import { applySettingsPatch, type SettingsStore } from "./settings.js";
import { candidates, strictest } from "./sender.js";
import type { StateStore } from "./state.js";

export interface LeakAgentDeps {
  store: StateStore;
  approvals: ApprovalService;
  log: DecisionLog;
  settings: SettingsStore;
  policy: () => Promise<Policy>;
  /** Tells every tab's content scripts that agent mode changed (index.ts's broadcast). */
  broadcastAgentMode: (on: boolean) => Promise<void>;
  /** Ids of every open tab. */
  tabIds: () => Promise<number[]>;
  /** Sends a message to every frame of a tab. */
  sendToTab: (tabId: number, msg: LeakAgentLogWorkerMessage) => void;
  /** A leak approval was created (index.ts refreshes the surfaces and opens the approval window). */
  onApprovalRequested?: () => void;
  now?: () => number;
}

export interface ContentSender {
  tabId: number;
  frameId: number;
  /** sender.origin, else the origin of sender.url. */
  origin: string;
  /** The sender frame's host (sender.ts): where typed or pasted data lands. "" when it has none. */
  host?: string;
  /** Where this sender's log rows go (index.ts: the per-sender throttled log); deps.log when absent. */
  log?: { append(entry: LogEntry): Promise<unknown> };
}

export interface LeakAgent {
  content(msg: LeakAgentLogContentMessage, from: ContentSender): Promise<unknown>;
  ui(msg: LeakAgentLogUiMessage): Promise<unknown>;
  /** While agent mode is on, the tab joins the session. Pure; index.ts applies it in the same update as the page. */
  joinIfAgentMode(s: BrowserState, tabId: number): BrowserState;
  /** Agent mode changed (switch, detection, or the approved switch-off): log it and push new contexts. */
  agentModeChanged(on: boolean, why: string): Promise<void>;
  /** Push every tab its leak context (after prints, verdicts or agent mode change). */
  pushContexts(): Promise<void>;
}

export function createLeakAgent(deps: LeakAgentDeps): LeakAgent {
  const now = deps.now ?? Date.now;

  const contextFor = async (tabId: number): Promise<LeakContext> => leakContextOf(effectiveTrust(await deps.store.load(), tabId), await deps.policy());

  const pushContexts = async (): Promise<void> => {
    const s = await deps.store.load();
    const p = await deps.policy();
    for (const id of await deps.tabIds()) deps.sendToTab(id, { type: "leak.context", context: leakContextOf(effectiveTrust(s, id), p) });
  };

  const agentModeChanged = async (on: boolean, why: string): Promise<void> => {
    await deps.log.append({ at: now(), site: "", actionClass: null, verdict: "log", rules: on ? [] : ["control.agent_mode_off"], event: on ? "agent_mode_on" : "agent_mode_off", detail: [why] });
    await pushContexts();
  };

  const leakGuard = async (msg: Extract<LeakAgentLogContentMessage, { type: "leak.guard" }>, from: ContentSender): Promise<LeakReply> => {
    const state = await deps.store.load();
    const trust = effectiveTrust(state, from.tabId);
    const p = await deps.policy();
    const merchant = msg.checkoutMerchantHost !== undefined ? { checkoutMerchantHost: msg.checkoutMerchantHost } : {};
    // The frame's host comes from Chrome (sender.ts); every judgement carries it, so a page-controlled destination
    // can only make the decision stricter (BR19b).
    const frameHost = from.host ?? hostOf(from.origin) ?? "";
    // Typed or pasted data lands in the sender's frame: judged against that host first, and against the body's
    // destinationHost only as a hint that can make the decision stricter. A submit goes to its form action, and the
    // sender's frame host is judged along with it (strictest wins).
    const senderHost = msg.via !== "submit" && from.host !== undefined ? from.host : null;
    const hosts =
      senderHost !== null ? candidates(senderHost, msg.destinationHost) : candidates(msg.destinationHost, ...(msg.via === "submit" && frameHost !== "" ? [frameHost] : []));
    const { decision, findings } = strictest(hosts.map((destinationHost) => decideLeak({ text: msg.text, destinationHost, frameHost, ...merchant }, trust, p)) as [ReturnType<typeof decideLeak>, ...ReturnType<typeof decideLeak>[]]);
    // The binding names the body's host only when it is the sender's (an honest content script presents it
    // again on redeem); a body that names another host gets a binding it cannot redeem.
    const boundHost = senderHost === null || hostOf(`https://${msg.destinationHost}/`) === senderHost ? msg.destinationHost : senderHost;
    let approvalId: string | undefined;
    let binding: string | undefined;
    if (decision.verdict === "approve") {
      const snap = leakSnapshot({ tabId: from.tabId, frameId: from.frameId, frameOrigin: from.origin, via: msg.via, elementPath: msg.elementPath, fieldName: msg.fieldName, text: msg.text, destinationHost: boundHost });
      // Stored with why it was held, so the approval card can say so (findings are masked by the engine).
      approvalId = (await deps.approvals.request(snap, "action", leakMeta({ ...msg, destinationHost: boundHost }, decision, findings, untrustedBecause(state, from.tabId)))).id;
      deps.onApprovalRequested?.();
      // Salted per agent session (RR11): never an unsalted hash over the held value on disk.
      if (state.session !== null && state.session.printSalt !== "") binding = saltedFingerprint(snap, state.session.printSalt);
    }
    if (decision.verdict !== "allow") {
      await (from.log ?? deps.log).append({
        at: now(),
        site: registrableDomain(hostOf(from.origin) ?? ""),
        actionClass: null,
        verdict: decision.verdict,
        rules: [decision.rule],
        event: "leak",
        detail: [msg.via, ...new Set(findings.map((f) => f.kind))],
        ...(binding !== undefined ? { binding } : {}),
      });
    }
    return approvalId === undefined ? { decision, findings } : { decision, findings, approvalId };
  };

  const settingsReply = (settings: Settings, refused: string[] = []): SettingsReply => (refused.length > 0 ? { ok: false, settings, refused } : { ok: true, settings });

  return {
    joinIfAgentMode(s, tabId) {
      if (s.session === null || s.tabs.some((t) => t.tabId === tabId && t.inSession)) return s;
      return startAgentSession(s, { now: now(), tabIds: [tabId] });
    },
    agentModeChanged,
    pushContexts,
    async content(msg, from) {
      switch (msg.type) {
        case "leak.guard":
          return leakGuard(msg, from);
        case "leak.context":
          return contextFor(from.tabId);
        case "agent.signal": {
          const settings = await deps.settings.load();
          if (!settings.detectWebdriver) return { agentMode: (await deps.store.load()).session !== null };
          let started = false;
          await deps.store.update((s) => {
            started = s.session === null;
            return startAgentSession(s, { now: now(), tabIds: [from.tabId], declaredClass: "remote_cdp" });
          });
          if (started) {
            await deps.broadcastAgentMode(true);
            await agentModeChanged(true, "webdriver");
          } else {
            await pushContexts();
          }
          return { agentMode: true };
        }
      }
    },
    async ui(msg) {
      switch (msg.type) {
        case "ui.log.list":
          // The person never sees an entry past the retention period, even before the hourly purge.
          await deps.log.purge(now());
          return { entries: await deps.log.list(msg.limit === undefined ? { limit: 500 } : { limit: msg.limit }) };
        case "ui.log.verify":
          return deps.log.verify();
        case "ui.log.export":
          return { json: await deps.log.exportJson() };
        case "ui.log.clear": {
          if ((await deps.store.load()).session !== null) return { ok: false, reason: "agent_mode_on" };
          await deps.log.clear();
          return { ok: true };
        }
        case "ui.settings.get":
          return settingsReply(await deps.settings.load());
        case "ui.settings.set": {
          const agentMode = (await deps.store.load()).session !== null;
          const current = await deps.settings.load();
          const { settings, refused } = applySettingsPatch(current, msg.patch, agentMode);
          await deps.settings.save(settings);
          await deps.log.append({ at: now(), site: "", actionClass: null, verdict: "log", rules: [], event: "settings_changed", detail: Object.keys(msg.patch).filter((k) => !refused.some((r) => r.split(".")[0] === k)) });
          await pushContexts();
          return settingsReply(settings, refused);
        }
      }
    },
  };
}

/** The origin a content message came from: Chrome's sender.origin, else the sender URL's origin. */
export function senderOrigin(origin: string | undefined, url: string | undefined): string {
  return origin ?? originOf(url ?? "") ?? "";
}
