import { describe, expect, it } from "vitest";
import { DEFAULT_POLICY } from "./types.js";
import { effectiveTrust, emptyState, pageShown, startAgentSession, tabOpened } from "./session.js";

describe("tab trust inheritance (design 4.5)", () => {
  it("a tab opened from a quarantined tab inherits untrusted and quarantined", () => {
    let s = pageShown(emptyState(), 1, { url: "https://attacker.test/", verdict: "quarantine" }, DEFAULT_POLICY);
    s = tabOpened(s, 2, 1);
    expect(effectiveTrust(s, 2)).toMatchObject({ untrusted: true, quarantined: true });
    expect(s.tabs.find((t) => t.tabId === 2)?.reasons).toContain("inherited");
  });

  it("keeps the new tab's own flags when its page reported before the opener event", () => {
    let s = pageShown(emptyState(), 1, { url: "https://shop.test/" }, DEFAULT_POLICY);
    s = pageShown(s, 2, { url: "https://attacker.test/", verdict: "quarantine" }, DEFAULT_POLICY);
    s = tabOpened(s, 2, 1);
    expect(effectiveTrust(s, 2)).toMatchObject({ untrusted: true, quarantined: true });
  });

  it("is idempotent when the browser reports one opening twice", () => {
    let s = pageShown(emptyState(), 1, { url: "https://attacker.test/", verdict: "flag" }, DEFAULT_POLICY);
    s = tabOpened(tabOpened(s, 2, 1), 2, 1);
    const tab = s.tabs.find((t) => t.tabId === 2);
    expect(tab?.reasons.filter((r) => r === "inherited")).toHaveLength(1);
    expect(s.tabs.filter((t) => t.tabId === 2)).toHaveLength(1);
  });

  it("joins the agent session with its opener", () => {
    let s = startAgentSession(emptyState(), { now: 1, tabIds: [1] });
    s = tabOpened(s, 2, 1);
    expect(s.tabs.find((t) => t.tabId === 2)?.inSession).toBe(true);
  });

  it("a tab is never its own opener", () => {
    const s = tabOpened(pageShown(emptyState(), 1, { url: "https://attacker.test/", verdict: "quarantine" }, DEFAULT_POLICY), 1, 1);
    expect(s.tabs.find((t) => t.tabId === 1)?.openerTabId).toBeUndefined();
  });
});

describe("an inherited quarantine and the first navigation", () => {
  it("survives the opened tab's first commit (the page the quarantined tab opened), and clears on the next one", async () => {
    const { topLevelNavigated } = await import("./session.js");
    let s = pageShown(emptyState(), 1, { url: "https://attacker.test/", verdict: "quarantine" }, DEFAULT_POLICY);
    s = tabOpened(s, 2, 1);
    s = topLevelNavigated(s, 2);
    expect(effectiveTrust(s, 2).quarantined).toBe(true);
    s = topLevelNavigated(s, 2);
    expect(effectiveTrust(s, 2).quarantined).toBe(false);
    expect(effectiveTrust(s, 2).untrusted).toBe(true);
  });
});
