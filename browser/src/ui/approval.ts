/**
 * The approval window (design 5.4): an extension page the worker opens in its
 * own small window when an approval is requested. It lists every pending
 * approval and closes itself once none is left. It is reachable by the
 * person, and not by page script or by agents whose input goes to the tab.
 */
import { sendToWorker } from "../shared/bridge.js";
import { isGateUiBroadcast, type ApprovalsState } from "../shared/messages.js";
import { renderApprovals } from "./cards.js";

function byId(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (el === null) throw new Error(`missing #${id}`);
  return el;
}

let shownAny = false;
let closeTimer: ReturnType<typeof setTimeout> | undefined;

function render(s: ApprovalsState): void {
  renderApprovals(byId("pending"), s.approvals);
  byId("pending-empty").hidden = s.approvals.length > 0;
  if (s.approvals.length > 0) {
    shownAny = true;
    if (closeTimer !== undefined) clearTimeout(closeTimer);
    closeTimer = undefined;
  } else if (shownAny && closeTimer === undefined) {
    closeTimer = setTimeout(() => window.close(), 1_500);
  }
}

function refresh(): void {
  sendToWorker({ type: "ui.approvals" }).then(render, () => {
    byId("pending-empty").textContent = "The extension's worker is not responding. Reload the extension.";
  });
}

chrome.runtime.onMessage.addListener((msg: unknown, sender) => {
  if (sender.id === chrome.runtime.id && isGateUiBroadcast(msg)) refresh();
});
refresh();
setInterval(refresh, 5_000);
