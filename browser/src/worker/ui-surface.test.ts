import { describe, expect, it } from "vitest";
import { uiAllowed, uiSurfaceOf } from "./ui-surface.js";

const ID = "abcdefghijklmnopabcdefghijklmnop";
const win = (windowId: number, tabId: number) => ({ windowId, tabId });
const page = (p: string) => `chrome-extension://${ID}/${p}`;

describe("UI surfaces (I7)", () => {
  it("tells the side panel, the popup and our approval window from our pages in ordinary tabs", () => {
    expect(uiSurfaceOf({ id: ID, url: page("sidepanel.html") }, ID, win(5, 2))).toBe("panel");
    expect(uiSurfaceOf({ id: ID, url: page("popup.html") }, ID, win(5, 2))).toBe("popup");
    expect(uiSurfaceOf({ id: ID, url: page("approval.html"), tab: { id: 2, windowId: 5 } }, ID, win(5, 2))).toBe("approval_window");
    // The same pages in a tab the agent drives.
    expect(uiSurfaceOf({ id: ID, url: page("sidepanel.html"), tab: { id: 2, windowId: 5 } }, ID, win(5, 2))).toBe("other");
    expect(uiSurfaceOf({ id: ID, url: page("approval.html"), tab: { id: 2, windowId: 6 } }, ID, win(5, 2))).toBe("other");
    // A second tab in the approval window is not the approval window.
    expect(uiSurfaceOf({ id: ID, url: page("approval.html"), tab: { id: 9, windowId: 5 } }, ID, win(5, 2))).toBe("other");
    expect(uiSurfaceOf({ id: ID, url: page("approval.html"), tab: { id: 2, windowId: 5 } }, ID, undefined)).toBe("other");
    expect(uiSurfaceOf({ id: ID, url: page("blocked.html") }, ID, win(5, 2))).toBe("other");
    expect(uiSurfaceOf({ id: "other", url: page("sidepanel.html") }, ID, win(5, 2))).toBe("other");
    expect(uiSurfaceOf({ id: ID, url: `chrome-extension://${"x".repeat(32)}/sidepanel.html` }, ID, win(5, 2))).toBe("other");
  });
  it("lets only the panel and the approval window decide, and only the panel change settings, the log or the link", () => {
    for (const t of ["ui.approve", "ui.approveForSite", "ui.deny", "ui.agentMode"]) {
      expect(uiAllowed(t, "panel")).toBe(true);
      expect(uiAllowed(t, "approval_window")).toBe(true);
      expect(uiAllowed(t, "popup")).toBe(false);
      expect(uiAllowed(t, "other")).toBe(false);
    }
    for (const t of ["ui.settings.set", "ui.settings.get", "ui.log.list", "ui.log.clear", "ui.log.export", "ui.log.verify", "ui.link.set"]) {
      expect(uiAllowed(t, "panel")).toBe(true);
      expect(uiAllowed(t, "approval_window")).toBe(false);
      expect(uiAllowed(t, "other")).toBe(false);
    }
    for (const t of ["ui.state", "ui.approvals", "ui.link.state"]) expect(uiAllowed(t, "other")).toBe(true);
  });
});
