/**
 * Agent detection (design 8). Advisory: it proposes or auto-enables agent
 * mode; a person decides, and turning it off is gated. v0.1 reads only the
 * signals that need no extra permission.
 */

export type AgentSignal =
  /** The person turned agent mode on (toolbar, keyboard command, side panel). */
  | { id: "person_enabled" }
  /** navigator.webdriver is true in a page (automation launch). */
  | { id: "webdriver" }
  /** chrome.debugger.getTargets() shows a tab attached by someone else (optional permission, not in v0.1). */
  | { id: "debugger_attached"; tabId: number }
  /** A known agent extension is installed and enabled (optional permission, not in v0.1). */
  | { id: "agent_extension_installed"; extensionId: string }
  /** The browser is a known agent browser (Comet, Atlas, Neon, Edge Copilot Mode). */
  | { id: "agent_browser"; name: string }
  /** Behavioural input shape: values without key events, clicks with no pointer movement. */
  | { id: "input_shape"; detail: string };

export type SignalStrength = "definitive" | "strong" | "medium" | "weak";

export function strengthOf(s: AgentSignal): SignalStrength {
  switch (s.id) {
    case "person_enabled":
      return "definitive";
    case "webdriver":
    case "debugger_attached":
      return "strong";
    case "agent_browser":
      return "medium";
    case "agent_extension_installed":
    case "input_shape":
      return "weak";
  }
}

/** Definitive and strong signals turn agent mode on (and notify); medium and weak ones only suggest it. */
export function agentModeAction(signals: readonly AgentSignal[]): "enable" | "suggest" | "none" {
  if (signals.length === 0) return "none";
  const strengths = signals.map(strengthOf);
  if (strengths.includes("definitive") || strengths.includes("strong")) return "enable";
  return "suggest";
}
