/**
 * Side panel (design 5.4): the default approval surface, the agent-mode
 * switch (turning it off is itself an approval), and the link to "what this
 * does not stop". Re-renders on the worker's `ui.changed` broadcast.
 */
import { sendToWorker } from "../shared/bridge.js";
import { isGateUiBroadcast, type ApprovalsState, type LinkStatus } from "../shared/messages.js";
import { renderApprovals } from "./cards.js";
import { mountLogSettings } from "./log-settings.js";
import { linkButtonLabel, linkLine, modeLine } from "./view.js";

function byId(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (el === null) throw new Error(`missing #${id}`);
  return el;
}

function render(s: ApprovalsState): void {
  byId("mode").textContent = modeLine(s);
  byId("coverage").textContent = s.coverageNote;
  renderApprovals(byId("pending"), s.approvals);
  byId("pending-empty").hidden = s.approvals.length > 0;
  (byId("agent-on") as HTMLButtonElement).hidden = s.agentMode;
  (byId("agent-off") as HTMLButtonElement).hidden = !s.agentMode;
}

// Agent mode, settings and the decision log: the leak lane's component, below the approvals.
const logSettings = mountLogSettings(document.getElementById("ls-log-settings") ?? document.body);

let link: LinkStatus | null = null;

function renderLink(s: LinkStatus): void {
  link = s;
  byId("link-status").textContent = linkLine(s);
  byId("link-toggle").textContent = linkButtonLabel(s);
}

function refresh(): void {
  sendToWorker({ type: "ui.approvals" }).then(render, () => {
    byId("mode").textContent = "The extension's worker is not responding. Reload the extension.";
  });
  sendToWorker({ type: "ui.link.state" }).then(renderLink, () => undefined);
}

/**
 * The link switch. Turning it on asks for the optional nativeMessaging permission first (design 11): the
 * request must come from this click. Turning it off gives the permission back.
 */
async function toggleLink(): Promise<void> {
  const status = byId("link-status");
  if (link?.enabled === true) {
    const r = await sendToWorker({ type: "ui.link.set", on: false });
    if (!r.ok) status.textContent = r.reason === "agent_mode" ? "The link stays on while agent mode is on. Turn agent mode off first." : "The link could not be turned off.";
    else await chrome.permissions.remove({ permissions: ["nativeMessaging"] }).catch(() => false);
    refresh();
    return;
  }
  const granted = await chrome.permissions.request({ permissions: ["nativeMessaging"] }).catch(() => false);
  if (!granted) {
    status.textContent = "Link to the local firewall: off. The browser did not grant the permission to talk to it.";
    return;
  }
  const r = await sendToWorker({ type: "ui.link.set", on: true });
  if (!r.ok) status.textContent = "Link to the local firewall: off. The browser did not grant the permission to talk to it.";
  refresh();
}

byId("agent-on").addEventListener("click", () => void sendToWorker({ type: "ui.agentMode", on: true }).then(refresh));
byId("agent-off").addEventListener("click", () => void sendToWorker({ type: "ui.agentMode", on: false }).then(refresh));
byId("link-toggle").addEventListener("click", () => void toggleLink());
chrome.runtime.onMessage.addListener((msg: unknown, sender) => {
  if (sender.id === chrome.runtime.id && isGateUiBroadcast(msg)) {
    refresh();
    logSettings.refresh();
  }
});
refresh();
// Expiry times and lost broadcasts (a restarted worker) are caught up by a slow poll.
setInterval(refresh, 5_000);
