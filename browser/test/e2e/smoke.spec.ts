/**
 * Smoke: the built extension loads in bundled Chromium with a fresh profile,
 * its manifest asks for exactly the design's permissions, its content script
 * runs on a corpus page (top frame and a cross-origin frame) and reaches the
 * worker, its side panel talks to the worker, and nothing leaves 127.0.0.1.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { HOST_PERMISSIONS, INSTALL_PERMISSIONS, OPTIONAL_PERMISSIONS } from "../../src/manifest.js";
import { DIST_DIR, expect, test } from "./fixtures.js";
import { openPanel, openPanelInTab } from "./gate-helpers.js";
import { agentModeOnWithTab, fromPanel } from "./side-panel.js";

interface StoredTab {
  tabId: number;
  untrusted: boolean;
  reasons: string[];
}
interface StoredState {
  tabs: StoredTab[];
  session: { domains: string[] } | null;
}

test("the built manifest asks for exactly the design's install-time permissions, and nativeMessaging only as optional", () => {
  const m = JSON.parse(readFileSync(join(DIST_DIR, "manifest.json"), "utf8")) as Record<string, unknown>;
  expect([...(m.permissions as string[])].sort()).toEqual([...INSTALL_PERMISSIONS].sort());
  expect(m.host_permissions).toEqual([...HOST_PERMISSIONS]);
  expect(m.optional_permissions).toEqual([...OPTIONAL_PERMISSIONS]);
});

test("the extension loads and its content script runs on a corpus page", async ({ context, serviceWorker, extensionId, corpus, blockedRequests }) => {
  expect(extensionId).toMatch(/^[a-p]{32}$/);

  const page = await context.newPage();
  await page.goto(corpus.url("shop.test", "/smoke/"));
  await expect(page.locator("h1")).toHaveText("Shop");

  // The content script announced the frame; the worker accepted it and marked the tab (every origin is outside by default).
  await expect
    .poll(async () => {
      const s = (await serviceWorker.evaluate(() => chrome.storage.session.get("ls.state")))["ls.state"] as StoredState | undefined;
      return s?.tabs.some((t) => t.untrusted && t.reasons.includes("outside_origin")) ?? false;
    })
    .toBe(true);

  expect(corpus.requests.some((r) => r.host === "shop.test" && r.path === "/smoke/")).toBe(true);
  expect(corpus.requests.some((r) => r.host === "attacker.test" && r.path === "/smoke/frame.html")).toBe(true);
  expect(blockedRequests).toEqual([]);
});

test("the side panel reaches the worker, and agent mode records the content script in a cross-origin frame", async ({ context, serviceWorker, extensionId, corpus, blockedRequests }) => {
  // Our panel page opened in an ordinary tab (as an agent could open it) reads, but cannot decide (ui-surface.ts).
  const inTab = await openPanelInTab(context, extensionId);
  await expect(inTab.locator("#mode")).toContainText("Agent mode is off");
  expect(await inTab.evaluate(() => chrome.runtime.sendMessage({ type: "ui.agentMode", on: true }))).toEqual({ ok: false, reason: "surface" });
  await inTab.close();

  const ui = await openPanel(context, extensionId);
  await expect(ui.locator("#mode")).toContainText("Agent mode is off");
  await expect(ui.locator("#coverage")).toContainText("does not hold");

  // Turn agent mode on from the real side panel (the tab in front joins the session), then browse in that tab.
  const page = await agentModeOnWithTab(context, extensionId);
  await page.goto(corpus.url("shop.test", "/smoke/"));

  // Both frames' content scripts reported in: the session saw shop.test (top) and attacker.test (the frame).
  await expect
    .poll(async () => {
      const s = (await serviceWorker.evaluate(() => chrome.storage.session.get("ls.state")))["ls.state"] as StoredState | undefined;
      return [...(s?.session?.domains ?? [])].sort();
    })
    .toEqual(["attacker.test", "shop.test"]);

  // Turning agent mode off is gated: the request creates an approval instead of ending the session.
  const offReply = await fromPanel<{ ok: boolean; approvalId?: string }>(ui, { type: "ui.agentMode", on: false });
  expect(offReply.ok).toBe(true);
  expect(typeof offReply.approvalId).toBe("string");
  const stillOn = (await serviceWorker.evaluate(async () => (await chrome.storage.session.get("ls.state"))["ls.state"])) as StoredState;
  expect(stillOn.session).not.toBeNull();

  // A web page cannot approve it: it has no channel to the worker at all (no externally_connectable).
  const fromPage = await page.evaluate(() => typeof (globalThis as { chrome?: { runtime?: { sendMessage?: unknown } } }).chrome?.runtime?.sendMessage);
  expect(fromPage).toBe("undefined");

  // The person approves in extension UI: the session ends.
  expect(await fromPanel(ui, { type: "ui.approve", approvalId: offReply.approvalId })).toEqual({ ok: true });
  const ended = (await serviceWorker.evaluate(async () => (await chrome.storage.session.get("ls.state"))["ls.state"])) as StoredState;
  expect(ended.session).toBeNull();
  expect(blockedRequests).toEqual([]);
});

test("harness: a request to any non-test host is refused and recorded, never sent", async ({ context, blockedRequests }) => {
  const page = await context.newPage();
  await expect(page.goto("http://example.com/")).rejects.toThrow();
  expect(blockedRequests).toEqual(["http://example.com/"]);
});

test("a page cannot read the worker's state storage", async ({ context, corpus }) => {
  const page = await context.newPage();
  await page.goto(corpus.url("shop.test", "/smoke/"));
  // chrome.storage is not exposed to the page's main world at all.
  expect(await page.evaluate(() => typeof (globalThis as { chrome?: { storage?: unknown } }).chrome?.storage)).toBe("undefined");
});
