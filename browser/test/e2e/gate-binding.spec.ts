/**
 * Approval binding and the approval surfaces, end to end: an approval is for
 * one exact action, once; a changed form is refused; deny drops it; script
 * clicks, and a key on a button focused before it armed, cannot approve; agent
 * mode off keeps only the always-on classes; the approval window works; turning agent
 * mode off is itself an approval; "approve for this site" grants the session.
 */
import { scriptSetValue } from "../agents/sim-a.js";
import { expect, test } from "./fixtures.js";
import { accessibleButtons, approvalsState, approveFirst, cards, countRequests, openPanel, setAgentMode, waitForCard } from "./gate-helpers.js";
import { accessibilityText } from "./guard-helpers.js";
import { ARM_MS } from "../../src/ui/view.js";

const ORDER = "/actions/checkout/order";

test("an approval is refused for a changed form: the agent edits the card number after the request", async ({ context, corpus, extensionId }) => {
  const panel = await openPanel(context, extensionId);
  await setAgentMode(panel, true);
  const page = await context.newPage();
  const base = countRequests(corpus, "shop.test", ORDER);
  await page.goto(corpus.url("shop.test", "/actions/checkout.html"));
  await page.locator("#place").click();
  await waitForCard(panel);
  await scriptSetValue(page, "#card", "5555 5555 5555 4444");
  await approveFirst(panel);
  await page.waitForTimeout(800);
  expect(countRequests(corpus, "shop.test", ORDER) - base).toBe(0);
  // The next attempt is a new request for the new form.
  await page.locator("#place").click();
  await waitForCard(panel);
  expect(countRequests(corpus, "shop.test", ORDER) - base).toBe(0);
});

test("deny drops the action, and the page shows the notice (never an approve control)", async ({ context, corpus, extensionId }) => {
  const panel = await openPanel(context, extensionId);
  await setAgentMode(panel, true);
  const page = await context.newPage();
  const base = countRequests(corpus, "shop.test", ORDER);
  await page.goto(corpus.url("shop.test", "/actions/checkout.html"));
  await page.locator("#place").click();
  const card = await waitForCard(panel);
  // The notice lives in a closed shadow root on a plain host with a random attribute (gate-notice.ts), so no
  // selector reaches it; the browser's accessibility tree does, as a screen reader would.
  await expect.poll(() => accessibilityText(page), { timeout: 5_000 }).toContain("LaunchSafe is holding this payment until you approve it.");
  expect(await accessibilityText(page)).toContain("Nothing on this page can approve it.");
  const before = await accessibleButtons(page);
  expect(before).toContain("Close this notice");
  expect(before.filter((name) => /approve/i.test(name))).toEqual([]);
  await card.locator("button.deny").click();
  await expect(cards(panel)).toHaveCount(0);
  await expect.poll(() => accessibilityText(page), { timeout: 5_000 }).toContain("This payment was denied in LaunchSafe. It did not happen.");
  expect((await accessibleButtons(page)).filter((name) => /approve/i.test(name))).toEqual([]);
  await page.waitForTimeout(500);
  expect(countRequests(corpus, "shop.test", ORDER) - base).toBe(0);
});

test("script clicks and a key on a button focused before it armed cannot approve; a fresh focus after arming can (I9)", async ({ context, corpus, extensionId }) => {
  // Since 73ab3f5 the keyboard is an approval gesture (view.ts ApproveGesture): a trusted focus that lands after
  // the card armed, then a trusted, non-repeating Enter or Space. What must never approve: script-dispatched
  // pointer events and clicks, and a key on a button that already had focus before it armed.
  const panel = await openPanel(context, extensionId);
  await setAgentMode(panel, true);
  // A person (or a stray Tab) focuses Approve the moment the card appears, before it arms.
  await panel.evaluate(() => {
    const list = document.getElementById("pending") ?? document.body;
    const obs = new MutationObserver(() => {
      const b = list.querySelector<HTMLButtonElement>("article.card button.approve");
      if (b === null) return;
      obs.disconnect();
      b.focus();
    });
    obs.observe(list, { childList: true, subtree: true });
  });
  const page = await context.newPage();
  const base = countRequests(corpus, "shop.test", ORDER);
  await page.goto(corpus.url("shop.test", "/actions/checkout.html"));
  await page.locator("#place").click();
  const card = await waitForCard(panel);
  const approve = card.locator("button.approve");
  await expect(approve).toBeFocused();
  await panel.waitForTimeout(ARM_MS + 150);
  await panel.keyboard.press("Enter");
  await panel.keyboard.press("Space");
  await expect(card.locator(".hint")).toContainText("Press Tab to move to this button");
  await panel.evaluate(() => {
    const b = document.querySelector("button.approve") as HTMLButtonElement;
    b.dispatchEvent(new PointerEvent("pointerdown", { bubbles: true, button: 0 }));
    b.dispatchEvent(new PointerEvent("pointerup", { bubbles: true, button: 0 }));
    b.click();
  });
  await page.waitForTimeout(600);
  expect(countRequests(corpus, "shop.test", ORDER) - base).toBe(0);
  await expect(cards(panel)).toHaveCount(1);
  // Control: the same keys after a fresh, trusted focus on the armed button approve it, once.
  await approve.blur();
  await approve.focus();
  await panel.keyboard.press("Enter");
  await expect.poll(() => countRequests(corpus, "shop.test", ORDER) - base).toBe(1);
  await page.waitForTimeout(500);
  expect(countRequests(corpus, "shop.test", ORDER) - base).toBe(1);
});

test("a fast click before the card arms does not approve", async ({ context, corpus, extensionId }) => {
  const panel = await openPanel(context, extensionId);
  await setAgentMode(panel, true);
  const page = await context.newPage();
  const base = countRequests(corpus, "shop.test", ORDER);
  await page.goto(corpus.url("shop.test", "/actions/checkout.html"));
  await page.locator("#place").click();
  const card = await waitForCard(panel);
  await card.locator("button.approve").click();
  await page.waitForTimeout(500);
  expect(countRequests(corpus, "shop.test", ORDER) - base).toBe(0);
  await expect(cards(panel)).toHaveCount(1);
});

test("repeated clicks queue one approval, and one approval replays once", async ({ context, corpus, extensionId }) => {
  const panel = await openPanel(context, extensionId);
  await setAgentMode(panel, true);
  const page = await context.newPage();
  const base = countRequests(corpus, "accounts.test", "/actions/account/delete");
  await page.goto(corpus.url("accounts.test", "/actions/delete.html"));
  await page.locator("#manage").click();
  for (let i = 0; i < 3; i++) await page.locator("#delete").click();
  await waitForCard(panel);
  await page.waitForTimeout(300);
  await expect(cards(panel)).toHaveCount(1);
  await approveFirst(panel);
  await expect.poll(() => countRequests(corpus, "accounts.test", "/actions/account/delete") - base).toBe(1);
  await page.waitForTimeout(500);
  expect(countRequests(corpus, "accounts.test", "/actions/account/delete") - base).toBe(1);
  // A later click is a new action that needs a new approval.
  await page.locator("#delete").click();
  await waitForCard(panel);
  expect(countRequests(corpus, "accounts.test", "/actions/account/delete") - base).toBe(1);
});

test("agent mode off: account security, consent are held; a payment goes through untouched, once", async ({ context, corpus, extensionId }) => {
  const panel = await openPanel(context, extensionId);
  const page = await context.newPage();
  const base = countRequests(corpus, "shop.test", ORDER);
  await page.goto(corpus.url("shop.test", "/actions/checkout.html"));
  await page.locator("#place").click();
  await expect.poll(() => countRequests(corpus, "shop.test", ORDER) - base).toBe(1);
  expect((await approvalsState(panel)).approvals).toEqual([]);

  const sec = await context.newPage();
  const sbase = countRequests(corpus, "accounts.test", "/actions/account/mfa-off");
  await sec.goto(corpus.url("accounts.test", "/actions/mfa.html"));
  await sec.locator("#off").click();
  await waitForCard(panel);
  await sec.waitForTimeout(400);
  expect(countRequests(corpus, "accounts.test", "/actions/account/mfa-off") - sbase).toBe(0);
});

test("the approval window opens by itself, approves, and closes when nothing is left", async ({ context, corpus, extensionId }) => {
  const page = await context.newPage();
  const base = countRequests(corpus, "accounts.test", "/actions/account/mfa-off");
  await page.goto(corpus.url("accounts.test", "/actions/mfa.html"));
  const windowPage = context.waitForEvent("page", { predicate: (p) => p.url().startsWith(`chrome-extension://${extensionId}/approval.html`) });
  await page.locator("#off").click();
  const win = await windowPage;
  await approveFirst(win);
  await expect.poll(() => countRequests(corpus, "accounts.test", "/actions/account/mfa-off") - base).toBe(1);
  await win.waitForEvent("close", { timeout: 10_000 });
});

test("turning agent mode off waits for an approval in the side panel", async ({ context, extensionId }) => {
  const panel = await openPanel(context, extensionId);
  await setAgentMode(panel, true);
  await expect(panel.locator("#mode")).toContainText("Agent mode is on");
  await panel.locator("#agent-off").click();
  const card = await waitForCard(panel);
  await expect(card.locator("h3")).toHaveText("Turn agent mode off");
  await expect(panel.locator("#mode")).toContainText("Agent mode is on");
  await approveFirst(panel);
  await expect(panel.locator("#mode")).toContainText("Agent mode is off");
});

test("approve for this site: the next payment on the same site in this agent session goes through, once each; other sites stay ungranted", async ({ context, corpus, extensionId, serviceWorker }) => {
  const panel = await openPanel(context, extensionId);
  await setAgentMode(panel, true);
  const page = await context.newPage();
  const base = countRequests(corpus, "shop.test", ORDER);
  await page.goto(corpus.url("shop.test", "/actions/checkout.html"));
  await page.locator("#place").click();
  await approveFirst(panel, "button.approve-site");
  await expect.poll(() => countRequests(corpus, "shop.test", ORDER) - base).toBe(1);
  // Exactly one grant: this site, this class.
  const grants = await serviceWorker.evaluate(async () => ((await chrome.storage.session.get("ls.state"))["ls.state"] as { session: { grants: string[] } }).session.grants);
  expect(grants).toEqual(["shop.test|payment"]);
  await page.goto(corpus.url("shop.test", "/actions/checkout.html"));
  await page.locator("#place").click();
  await expect.poll(() => countRequests(corpus, "shop.test", ORDER) - base).toBe(2);
  expect((await approvalsState(panel)).approvals).toEqual([]);
  // The same checkout on another site is still held for a person.
  const otherBase = countRequests(corpus, "attacker.test", ORDER);
  const other = await context.newPage();
  await other.goto(corpus.url("attacker.test", "/actions/checkout.html"));
  await other.locator("#place").click();
  const card = await waitForCard(panel);
  await expect(card).toContainText("attacker.test");
  await other.waitForTimeout(300);
  expect(countRequests(corpus, "attacker.test", ORDER)).toBe(otherBase);
});

test("account security never offers 'approve for this site'", async ({ context, corpus, extensionId }) => {
  const panel = await openPanel(context, extensionId);
  await setAgentMode(panel, true);
  const page = await context.newPage();
  await page.goto(corpus.url("accounts.test", "/actions/password.html"));
  await page.locator("#change").click();
  const card = await waitForCard(panel);
  await expect(card.locator("button.approve")).toHaveCount(1);
  await expect(card.locator("button.approve-site")).toHaveCount(0);
  // Field values: passwords are masked in the card.
  await expect(card.locator(".fields")).toContainText("••••••••");
  await expect(card).not.toContainText("new-password-2");
});

test("a page loaded while agent mode is on gates from its first event (posture at document_start)", async ({ context, corpus, extensionId }) => {
  const panel = await openPanel(context, extensionId);
  await setAgentMode(panel, true);
  const page = await context.newPage();
  const base = countRequests(corpus, "mail.test", "/actions/chat/send");
  await page.goto(corpus.url("mail.test", "/actions/chat.html"), { waitUntil: "commit" });
  await page.locator("#send").click();
  await waitForCard(panel);
  await page.waitForTimeout(400);
  expect(countRequests(corpus, "mail.test", "/actions/chat/send") - base).toBe(0);
});
