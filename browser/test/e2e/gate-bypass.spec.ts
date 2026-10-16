/**
 * Known bypasses (design 5.5), tested AS bypasses:
 * each test passes when the bypass happens and the gate saw nothing (no
 * approval was queued). A change that claims to close one must update the
 * test, the threat model and the "what this does not stop" page together.
 * The contrast cases show the same agent's input path that does hold.
 */
import { scriptFetch, scriptFormSubmit } from "../agents/sim-a.js";
import { DEBUGGER_AGENT_DIR, debuggerAgent, debuggerAgentWorker } from "../agents/sim-b.js";
import { expect, test } from "./fixtures.js";
import { approvalsState, countRequests, openPanel, setAgentMode, tabIdFor, waitForCard } from "./gate-helpers.js";

test.describe("page script (A, and D's page.evaluate)", () => {
  test("KNOWN BYPASS: form.submit() raises no submit event; the order is sent and the gate never sees it", async ({ context, corpus, extensionId }) => {
    const panel = await openPanel(context, extensionId);
    await setAgentMode(panel, true);
    const page = await context.newPage();
    const base = countRequests(corpus, "shop.test", "/actions/checkout/order");
    await page.goto(corpus.url("shop.test", "/actions/checkout.html"));
    await scriptFormSubmit(page, "#pay");
    await expect.poll(() => countRequests(corpus, "shop.test", "/actions/checkout/order") - base).toBe(1);
    expect((await approvalsState(panel)).approvals).toEqual([]);
  });

  test("KNOWN BYPASS: fetch from page script sends data; the gate never sees it", async ({ context, corpus, extensionId }) => {
    const panel = await openPanel(context, extensionId);
    await setAgentMode(panel, true);
    const page = await context.newPage();
    await page.goto(corpus.url("mail.test", "/actions/compose.html"));
    const base = countRequests(corpus, "mail.test", "/actions/mail/send");
    expect(await scriptFetch(page, corpus.url("mail.test", "/actions/mail/send"), "to=friend@mail.test")).toBe(404);
    expect(countRequests(corpus, "mail.test", "/actions/mail/send") - base).toBe(1);
    expect((await approvalsState(panel)).approvals).toEqual([]);
  });

  test("contrast (holds): requestSubmit() from page script raises a submit event and is held", async ({ context, corpus, extensionId }) => {
    const panel = await openPanel(context, extensionId);
    await setAgentMode(panel, true);
    const page = await context.newPage();
    const base = countRequests(corpus, "shop.test", "/actions/checkout/order");
    await page.goto(corpus.url("shop.test", "/actions/checkout.html"));
    await page.evaluate(() => (document.getElementById("pay") as HTMLFormElement).requestSubmit());
    await waitForCard(panel);
    await page.waitForTimeout(400);
    expect(countRequests(corpus, "shop.test", "/actions/checkout/order") - base).toBe(0);
    // The page's own capture listener on window, registered in <head>, never saw the held submit.
    expect(await page.evaluate(() => (window as unknown as { __pageSawSubmit?: number }).__pageSawSubmit ?? 0)).toBe(0);
  });
});

test.describe("debugger agent running page script (B')", () => {
  test.use({ extraExtensions: [DEBUGGER_AGENT_DIR] });

  test("KNOWN BYPASS: Runtime.evaluate form.submit() sends the order without approval", async ({ context, corpus, extensionId }) => {
    const panel = await openPanel(context, extensionId);
    await setAgentMode(panel, true);
    const page = await context.newPage();
    const base = countRequests(corpus, "shop.test", "/actions/checkout/order");
    await page.goto(corpus.url("shop.test", "/actions/checkout.html"));
    const agent = debuggerAgent(await debuggerAgentWorker(context));
    const tab = await tabIdFor(agent, page);
    await agent.attach(tab);
    await agent.evaluate(tab, "document.getElementById('pay').submit()");
    await expect.poll(() => countRequests(corpus, "shop.test", "/actions/checkout/order") - base).toBe(1);
    expect((await approvalsState(panel)).approvals).toEqual([]);
    await agent.detach(tab);
  });

  test("KNOWN BYPASS: Runtime.evaluate fetch sends the message without approval", async ({ context, corpus, extensionId }) => {
    const panel = await openPanel(context, extensionId);
    await setAgentMode(panel, true);
    const page = await context.newPage();
    await page.goto(corpus.url("mail.test", "/actions/compose.html"));
    const base = countRequests(corpus, "mail.test", "/actions/mail/send");
    const agent = debuggerAgent(await debuggerAgentWorker(context));
    const tab = await tabIdFor(agent, page);
    await agent.attach(tab);
    await agent.evaluate(tab, "fetch('/actions/mail/send', { method: 'POST', body: 'exfil' }).then(r => r.status)");
    expect(countRequests(corpus, "mail.test", "/actions/mail/send") - base).toBe(1);
    expect((await approvalsState(panel)).approvals).toEqual([]);
    await agent.detach(tab);
  });

  test("contrast (holds): Runtime.evaluate el.click() on the Send control is held", async ({ context, corpus, extensionId }) => {
    const panel = await openPanel(context, extensionId);
    await setAgentMode(panel, true);
    const page = await context.newPage();
    await page.goto(corpus.url("mail.test", "/actions/compose.html"));
    const base = countRequests(corpus, "mail.test", "/actions/mail/send");
    const agent = debuggerAgent(await debuggerAgentWorker(context));
    const tab = await tabIdFor(agent, page);
    await agent.attach(tab);
    await agent.evaluate(tab, "document.getElementById('send').click()");
    await waitForCard(panel);
    await page.waitForTimeout(400);
    expect(countRequests(corpus, "mail.test", "/actions/mail/send") - base).toBe(0);
    await agent.detach(tab);
  });
});

test("the 'what this does not stop' page lists the known bypasses and is linked from the side panel", async ({ context, extensionId }) => {
  const panel = await openPanel(context, extensionId);
  await expect(panel.locator("#limits-link")).toHaveAttribute("href", "limits.html");
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/limits.html`);
  await expect(page.locator("#bypass-form-submit")).toContainText("form.submit()");
  await expect(page.locator("#bypass-fetch")).toContainText("fetch");
  await expect(page.locator("body")).toContainText("Does not hold");
  expect((await page.locator("body").innerText()).toLowerCase()).not.toContain("you are protected");
});
