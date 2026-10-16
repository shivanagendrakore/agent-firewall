/**
 * Typed sending over chrome.runtime messaging. Content scripts and UI pages
 * call `sendToWorker`; the reply type follows from the message type.
 */
import type { LeakContext } from "../engine/leak.js";
import type { ApprovalsState, ChainedEntry, LinkSetReply, LinkStatus, LinkUiMessage, ContentMessage, GateContentMessage, GatePosture, GateReply, GateUiMessage, LeakReply, LogVerifyReply, RedeemReply, SettingsReply, TabModeReply, UiMessage, UiState } from "./messages.js";

export interface ReplyMap {
  "frame.hello": void;
  "page.scanned": void;
  "action.check": GateReply;
  "private.prints": void;
  "approval.redeem": RedeemReply;
  "ui.state": UiState;
  "ui.approve": { ok: boolean };
  "ui.deny": { ok: boolean };
  "ui.agentMode": { ok: boolean; approvalId?: string };
  // ---- leak/agent/log (leak lane) ----
  "leak.guard": LeakReply;
  "leak.context": LeakContext;
  "agent.signal": { agentMode: boolean };
  "ui.log.list": { entries: ChainedEntry[] };
  "ui.log.verify": LogVerifyReply;
  "ui.log.export": { json: string };
  "ui.log.clear": { ok: boolean; reason?: string };
  "ui.settings.get": SettingsReply;
  "ui.settings.set": SettingsReply;
  // ---- gate/approvals (gate lane) ----
  "gate.posture": GatePosture;
  "ui.approvals": ApprovalsState;
  "ui.approveForSite": { ok: boolean };
  // ---- guard/nav (guard lane) ----
  "tab.mode": TabModeReply;
  "nav.hosts": void;
  "nav.blocked": void;
  // ---- native link ----
  "ui.link.state": LinkStatus;
  "ui.link.set": LinkSetReply;
}

export type AnyMessage = ContentMessage | UiMessage | GateContentMessage | GateUiMessage | LinkUiMessage;

/** Sends a message to the service worker. Rejects if the worker is unreachable (the caller fails closed). */
export function sendToWorker<M extends AnyMessage>(msg: M): Promise<ReplyMap[M["type"]]> {
  return chrome.runtime.sendMessage(msg) as Promise<ReplyMap[M["type"]]>;
}
