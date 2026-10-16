/**
 * Content script entry (document_start, every frame). Wires the four modules
 * and the worker's messages. The gate installs first so its capture
 * listeners precede any page listener.
 */
import { sendToWorker } from "../shared/bridge.js";
import { parseGateWorkerMessage, parseWorkerMessage } from "../shared/messages.js";
import { createAgentSignals } from "./agent.js";
import { createActionGate } from "./gate.js";
import { createContentGuard } from "./guard.js";
import { createLeakGuard } from "./leak.js";
import { createNavGuard } from "./nav.js";
import type { ContentDeps } from "./types.js";

let agentMode = false;
const deps: ContentDeps = { send: sendToWorker, win: window, agentMode: () => agentMode };

const gate = createActionGate(deps);
const nav = createNavGuard(deps);
const guard = createContentGuard(deps);

/** Agent mode as the worker last told this frame (agent.mode broadcasts, leak contexts, detection replies). */
function setAgentMode(on: boolean): void {
  if (on === agentMode) return;
  agentMode = on;
  guard.setAgentMode(on);
  nav.checkCurrentUrl();
}
const leak = createLeakGuard(deps, { onContext: (ctx) => setAgentMode(ctx.agentMode) });
const agentSignals = createAgentSignals(deps, setAgentMode);

gate.install();
leak.install();
nav.install();
guard.install();
agentSignals.install();

// guard/nav: a frame that starts during an agent session learns it now, not at the next broadcast.
sendToWorker({ type: "tab.mode" })
  .then((r) => {
    if (r?.agentMode === true) setAgentMode(true);
  })
  .catch(() => undefined);

chrome.runtime.onMessage.addListener((raw: unknown, sender) => {
  // Only the worker (our own extension, not a tab) may talk to content scripts.
  if (sender.id !== chrome.runtime.id || sender.tab !== undefined) return;
  const gateMsg = parseGateWorkerMessage(raw);
  if (gateMsg !== null) {
    gate.onPosture(gateMsg.posture);
    return;
  }
  const msg = parseWorkerMessage(raw);
  if (msg === null) {
    // A leak context we refuse (over a bound, malformed) must not leave the last one trusted (RR16).
    if (typeof raw === "object" && raw !== null && (raw as { type?: unknown }).type === "leak.context") leak.markStale();
    return;
  }
  switch (msg.type) {
    case "agent.mode":
      setAgentMode(msg.on);
      gate.onPosture({ agentMode: msg.on });
      break;
    case "approval.granted":
      // Each module replays only its own holds; the leak guard says whether the approval was one of its.
      if (!leak.onApprovalGranted(msg.approvalId, msg.token)) gate.onApprovalGranted(msg.approvalId, msg.token);
      break;
    case "approval.denied":
      if (!leak.onApprovalDenied(msg.approvalId)) gate.onApprovalDenied(msg.approvalId);
      break;
    case "leak.context":
      leak.setContext(msg.context);
      break;
  }
});
