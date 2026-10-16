/**
 * Which of our own pages a UI message came from, and what each may ask for.
 *
 * Any page under our origin passes `isFromOwnExtensionPage`, including one an
 * automation client opened in an ordinary tab (chrome-extension://<id>/
 * sidepanel.html typed into a tab it drives). So the messages that decide
 * something are accepted only from the two surfaces a person uses and an agent
 * in a tab cannot open on its own:
 *
 * - the side panel (sidepanel.html with no tab: Chrome gives a side panel's
 *   sender no `tab`), and the toolbar popup (popup.html, no tab), which only
 *   reads;
 * - the approval window: approval.html in the popup window the worker opened
 *   itself, whose window id and tab id it keeps (APPROVAL_WINDOW_KEY): both must match, so another tab an
 *   automation client adds to that window is not the approval window.
 *
 *   message                                  side panel  approval window  popup  other page
 *   ui.state, ui.approvals, ui.link.state    yes         yes              yes    yes
 *   ui.approve, ui.approveForSite, ui.deny   yes         yes              no     no
 *   ui.agentMode                             yes         yes              no     no
 *   ui.settings.*, ui.log.*, ui.link.set     yes         no               no     no
 *
 * This does not stop a remote CDP client, which can drive the real side panel
 * too (threat model 3, row D).
 */

/** The approval window the worker opened: its window and its one tab. */
export interface ApprovalWindow {
  windowId: number;
  tabId: number;
}

export type UiSurface = "panel" | "popup" | "approval_window" | "other";

export interface UiSenderLike {
  id?: string;
  url?: string;
  tab?: { id?: number; windowId?: number };
}

function pagePath(url: string, extensionId: string): string | null {
  try {
    const u = new URL(url);
    if (u.protocol !== "chrome-extension:" || u.host !== extensionId) return null;
    return u.pathname;
  } catch {
    return null;
  }
}

export function uiSurfaceOf(sender: UiSenderLike, extensionId: string, approvalWindow: ApprovalWindow | undefined): UiSurface {
  if (sender.id !== extensionId) return "other";
  const path = pagePath(sender.url ?? "", extensionId);
  if (path === null) return "other";
  if (sender.tab === undefined) {
    if (path === "/sidepanel.html") return "panel";
    if (path === "/popup.html") return "popup";
    return "other";
  }
  if (path === "/approval.html" && approvalWindow !== undefined && sender.tab.windowId === approvalWindow.windowId && sender.tab.id === approvalWindow.tabId) return "approval_window";
  return "other";
}

/** Whether a UI message of this type is accepted from this surface (the table above). */
export function uiAllowed(type: string, surface: UiSurface): boolean {
  switch (type) {
    case "ui.state":
    case "ui.approvals":
    case "ui.link.state":
      return true;
    case "ui.approve":
    case "ui.approveForSite":
    case "ui.deny":
    case "ui.agentMode":
      return surface === "panel" || surface === "approval_window";
    default:
      // ui.settings.*, ui.log.*, ui.link.set, and anything new: the side panel only.
      return surface === "panel";
  }
}
