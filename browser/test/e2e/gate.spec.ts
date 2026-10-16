/**
 * Gate acceptance: for every sensitive fixture and every
 * simulator class A, B and D, the action does not take effect without
 * approval (the corpus server records no request) and takes effect exactly
 * once after a person approves it in the side panel.
 *
 * A: page script (el.click(), dispatched events, script-set files).
 * B: a test extension driving the tab with chrome.debugger (Input.*, DOM.setFileInputFiles).
 * D: Playwright's own input (remote CDP).
 */
import type { BrowserContext, Page } from "@playwright/test";
import { DEBUGGER_AGENT_DIR, debuggerAgent, debuggerAgentWorker, type DebuggerAgent } from "../agents/sim-b.js";
import { cdpSetFiles } from "../agents/sim-d.js";
import type { CorpusServer, TestHost } from "./corpus-server.js";
import { expect, test } from "./fixtures.js";
import { approveFirst, countRequests, openPanel, settledCount, setAgentMode, simClick, tabIdFor, tempFile, waitForCard, type SimName } from "./gate-helpers.js";
import { markSessionPrivate } from "./guard-helpers.js";

interface Ctx {
  page: Page;
  agent?: DebuggerAgent;
  tabId?: number;
}

interface Case {
  name: string;
  host: TestHost;
  path: string;
  /** The class the side panel card must show. */
  actionClass: string;
  effect: { host: TestHost; path: string };
  act: (sim: SimName, c: Ctx) => Promise<void>;
}

const click = (selector: string, frame?: string) => (sim: SimName, c: Ctx) => simClick(sim, c.page, selector, { ...(frame !== undefined ? { frame } : {}), ...(c.agent !== undefined ? { agent: c.agent } : {}), ...(c.tabId !== undefined ? { tabId: c.tabId } : {}) });

/** Ctrl+Enter (or plain Enter) in a compose body, per simulator. */
const keySend = (selector: string, ctrl: boolean) => async (sim: SimName, c: Ctx) => {
  if (sim === "A") {
    await c.page.evaluate(([s, k]) => document.querySelector(s as string)?.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", code: "Enter", ctrlKey: k as boolean, bubbles: true, cancelable: true })), [selector, ctrl] as const);
  } else if (sim === "D") {
    await c.page.locator(selector).focus();
    await c.page.keyboard.press(ctrl ? "Control+Enter" : "Enter");
  } else {
    if (c.agent === undefined || c.tabId === undefined) throw new Error("B needs an agent");
    await c.agent.focusSelector(c.tabId, selector);
    await c.agent.pressKey(c.tabId, "Enter", ctrl ? 2 : 0);
  }
};

/** Files given to a file input, per simulator. */
const giveFiles = (selector: string) => async (sim: SimName, c: Ctx) => {
  if (sim === "A") {
    await c.page.evaluate((s) => {
      const input = document.querySelector(s) as HTMLInputElement;
      const dt = new DataTransfer();
      dt.items.add(new File(["inert"], "passport-scan.pdf", { type: "application/pdf" }));
      input.files = dt.files;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    }, selector);
  } else if (sim === "D") {
    await cdpSetFiles(c.page, selector, [{ name: "passport-scan.pdf", mimeType: "application/pdf", text: "inert" }]);
  } else {
    if (c.agent === undefined || c.tabId === undefined) throw new Error("B needs an agent");
    await c.agent.setFileInputFiles(c.tabId, selector, [tempFile("passport-scan.pdf", "inert")]);
  }
};

const CASES: Case[] = [
  { name: "checkout (card fields)", host: "shop.test", path: "/actions/checkout.html", actionClass: "Payment", effect: { host: "shop.test", path: "/actions/checkout/order" }, act: click("#place") },
  { name: "provider-style payment frame (cross-origin)", host: "shop.test", path: "/actions/pay-frame.html", actionClass: "Payment", effect: { host: "accounts.test", path: "/actions/payframe/charge" }, act: click("#pay", "pay-frame-inner") },
  { name: "mail compose, Send button", host: "mail.test", path: "/actions/compose.html", actionClass: "Send a message", effect: { host: "mail.test", path: "/actions/mail/send" }, act: click("#send") },
  { name: "mail compose, Ctrl+Enter", host: "mail.test", path: "/actions/compose.html", actionClass: "Send a message", effect: { host: "mail.test", path: "/actions/mail/send" }, act: keySend("#body", true) },
  { name: "chat composer, Enter", host: "mail.test", path: "/actions/chat.html", actionClass: "Send a message", effect: { host: "mail.test", path: "/actions/chat/send" }, act: keySend("#msg", false) },
  { name: "chat composer, Send button", host: "mail.test", path: "/actions/chat.html", actionClass: "Send a message", effect: { host: "mail.test", path: "/actions/chat/send" }, act: click("#send") },
  { name: "change password", host: "accounts.test", path: "/actions/password.html", actionClass: "Account security change", effect: { host: "accounts.test", path: "/actions/account/password" }, act: click("#change") },
  { name: "turn off two-factor", host: "accounts.test", path: "/actions/mfa.html", actionClass: "Account security change", effect: { host: "accounts.test", path: "/actions/account/mfa-off" }, act: click("#off") },
  { name: "mail forwarding rule", host: "mail.test", path: "/actions/forwarding.html", actionClass: "Account security change", effect: { host: "mail.test", path: "/actions/mail/forwarding" }, act: click("#add") },
  { name: "create API key", host: "accounts.test", path: "/actions/api-key.html", actionClass: "Account security change", effect: { host: "accounts.test", path: "/actions/account/api-key" }, act: click("#create") },
  { name: "OAuth consent", host: "accounts.test", path: "/actions/oauth2/authorize.html?client_id=attacker-app", actionClass: "Grant an app access", effect: { host: "accounts.test", path: "/actions/oauth/approve" }, act: click("#allow") },
  {
    name: "delete account behind a confirm step",
    host: "accounts.test",
    path: "/actions/delete.html",
    actionClass: "Delete",
    effect: { host: "accounts.test", path: "/actions/account/delete" },
    act: async (sim, c) => {
      await click("#manage")(sim, c);
      await click("#delete")(sim, c);
    },
  },
  // Look-alikes of the later sites. An adapter is keyed on the real host, which a .test page cannot claim, so these run
  // the generic fallback on the same DOM shapes: the adapter-covered controls are still gated on a site we do not know.
  { name: "social post composer", host: "mail.test", path: "/actions/social-post.html", actionClass: "Send a message", effect: { host: "mail.test", path: "/actions/social/post" }, act: click("#post") },
  { name: "document sharing dialog, Send", host: "mail.test", path: "/actions/share-dialog.html", actionClass: "Send a message", effect: { host: "mail.test", path: "/actions/share/send" }, act: click("#send") },
  { name: "cloud console, create access key", host: "accounts.test", path: "/actions/cloud-console.html", actionClass: "Account security change", effect: { host: "accounts.test", path: "/actions/cloud/access-key" }, act: click("#create-key") },
  {
    name: "cloud console, delete bucket behind a confirm step",
    host: "accounts.test",
    path: "/actions/cloud-console.html",
    actionClass: "Delete",
    effect: { host: "accounts.test", path: "/actions/cloud/delete-bucket" },
    act: async (sim, c) => {
      await click("#manage")(sim, c);
      await click("#delete-bucket")(sim, c);
    },
  },
  { name: "file upload to a new site", host: "shop.test", path: "/actions/upload.html", actionClass: "Upload files", effect: { host: "attacker.test", path: "/actions/upload-js" }, act: giveFiles("#file") },
];

async function runCase(sim: SimName, k: Case, deps: { context: BrowserContext; corpus: CorpusServer; extensionId: string; blockedRequests: string[] }): Promise<void> {
  const { context, corpus, extensionId, blockedRequests } = deps;
  const panel = await openPanel(context, extensionId);
  await setAgentMode(panel, true);
  const page = await context.newPage();
  // The corpus server lives for the whole run: count only this test's requests.
  const base = countRequests(corpus, k.effect.host, k.effect.path);
  const count = () => countRequests(corpus, k.effect.host, k.effect.path) - base;
  await page.goto(corpus.url(k.host, k.path));
  const c: Ctx = { page };
  if (sim === "B") {
    const agent = debuggerAgent(await debuggerAgentWorker(context));
    c.agent = agent;
    c.tabId = await tabIdFor(agent, page);
    await agent.attach(c.tabId);
  }
  await k.act(sim, c);

  // Held: the card is in the side panel and nothing reached the server.
  const card = await waitForCard(panel);
  await expect(card.locator("h3")).toContainText(k.actionClass);
  await page.waitForTimeout(400);
  expect(count()).toBe(0);

  // Approved in the side panel: it happens exactly once.
  await approveFirst(panel);
  await expect.poll(count, { timeout: 10_000 }).toBe(1);
  await page.waitForTimeout(400);
  expect(count()).toBe(1);
  await expect(panel.locator("article.card")).toHaveCount(0);
  if (c.agent !== undefined && c.tabId !== undefined) await c.agent.detach(c.tabId);
  expect(blockedRequests).toEqual([]);
}

for (const sim of ["A", "D"] as const) {
  test.describe(`simulator ${sim}`, () => {
    for (const k of CASES) {
      test(`${k.name}: held without approval, happens once after approval`, async ({ context, corpus, extensionId, blockedRequests }) => {
        await runCase(sim, k, { context, corpus, extensionId, blockedRequests });
      });
    }
  });
}

test.describe("simulator B (chrome.debugger extension)", () => {
  test.use({ extraExtensions: [DEBUGGER_AGENT_DIR] });
  for (const k of CASES) {
    test(`${k.name}: held without approval, happens once after approval`, async ({ context, corpus, extensionId, blockedRequests }) => {
      await runCase("B", k, { context, corpus, extensionId, blockedRequests });
    });
  }
});

test("drop with files (simulator A): held, then delivered once after approval", async ({ context, corpus, extensionId, serviceWorker, blockedRequests }) => {
  const panel = await openPanel(context, extensionId);
  await setAgentMode(panel, true);
  // Integration: every tab joins the agent session (leak lane), so shop.test becomes a known target once the page
  // shows; a drop (no form target) is gated because the session is private, made so the real way (a mail page with
  // a one-time code).
  await markSessionPrivate(context, corpus, serviceWorker);
  const page = await context.newPage();
  const base = countRequests(corpus, "attacker.test", "/actions/upload-js");
  await page.goto(corpus.url("shop.test", "/actions/upload.html"));
  await page.evaluate(() => {
    const dt = new DataTransfer();
    dt.items.add(new File(["inert"], "tax-return.pdf", { type: "application/pdf" }));
    document.getElementById("drop")?.dispatchEvent(new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: dt }));
  });
  await waitForCard(panel);
  expect((await settledCount(page, corpus, "attacker.test", "/actions/upload-js")) - base).toBe(0);
  await approveFirst(panel);
  await expect.poll(() => corpus.requests.filter((r) => r.path.startsWith("/actions/upload-js") && r.body === "drop:tax-return.pdf").length).toBe(1);
  expect((await settledCount(page, corpus, "attacker.test", "/actions/upload-js")) - base).toBe(1);
  expect(blockedRequests).toEqual([]);
});
