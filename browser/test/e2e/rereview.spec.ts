/**
 * Re-review findings that need a real browser (test/review/rereview.test.ts has
 * the unit-level ones). Each finding was written as a `test.fail` stating the
 * correct behaviour; all are fixed and are now plain tests, each with a
 * "Fixed:" line. Each finding keeps its plain control test next to it, so a
 * broken harness cannot make a finding look fixed.
 *
 * Fixtures: test/corpus/review/. Fresh temp profiles; nothing leaves 127.0.0.1.
 */
import type { BrowserContext, Worker } from "@playwright/test";
import { scriptRequestSubmit } from "../agents/sim-a.js";
import type { CorpusServer } from "./corpus-server.js";
import { cdpType } from "../agents/sim-d.js";
import { expect, test } from "./fixtures.js";
import { approveFirst, countRequests, openPanel, setAgentMode, waitForCard } from "./gate-helpers.js";
import { agentModeOn, readState, tabIdFor, tabState } from "./guard-helpers.js";

const ORDER = "/actions/checkout/order";
const CODE = "482915";

// ---- RR3: "approve for this site" also grants the page-named form target ----

test("RR3 control: approve for this site on shop.test lets the next shop.test payment through", async ({ context, corpus, extensionId }) => {
  const panel = await openPanel(context, extensionId);
  await setAgentMode(panel, true);
  const page = await context.newPage();
  const base = countRequests(corpus, "shop.test", ORDER);
  await page.goto(corpus.url("shop.test", "/actions/checkout.html"));
  await page.locator("#place").click();
  await approveFirst(panel, "button.approve-site");
  await expect.poll(() => countRequests(corpus, "shop.test", ORDER) - base).toBe(1);
});

test("RR3: approving 'for this site' on attacker.test does not let a later payment on shop.test through unasked", async ({ context, corpus, extensionId, serviceWorker, blockedRequests }) => {
  // Fixed: the grant covers only the frame's own site, the one the card names; the card says the form's target still asks.
  const panel = await openPanel(context, extensionId);
  await setAgentMode(panel, true);
  const evil = await context.newPage();
  const base = countRequests(corpus, "shop.test", ORDER);
  await evil.goto(corpus.url("attacker.test", "/review/cross-checkout.html"));
  // The agent submits the form (implicit submission or requestSubmit): the held action is the submit, with its form target.
  await scriptRequestSubmit(evil, "#pay");
  const card = await waitForCard(panel);
  // The card names attacker.test as the site; nothing says shop.test is granted too.
  await expect(card).toContainText("attacker.test");
  await approveFirst(panel, "button.approve-site");
  await expect.poll(() => countRequests(corpus, "shop.test", ORDER) - base).toBe(1);
  const grants = await serviceWorker.evaluate(async () => ((await chrome.storage.session.get("ls.state"))["ls.state"] as { session: { grants: string[] } }).session.grants);
  test.info().annotations.push({ type: "grants", description: grants.join(", ") });
  expect(grants).toEqual(["attacker.test|payment"]);

  const shop = await context.newPage();
  await shop.goto(corpus.url("shop.test", "/actions/checkout.html"));
  await shop.locator("#place").click();
  await shop.waitForTimeout(800);
  expect(countRequests(corpus, "shop.test", ORDER) - base).toBe(1);
  await waitForCard(panel);
  expect(blockedRequests).toEqual([]);
});

// ---- RR4: the guard skips anything that wears its own marker attribute ----

test("RR4 control: a display:none instruction is removed in agent mode", async ({ context, extensionId, corpus, blockedRequests }) => {
  await agentModeOn(context, extensionId);
  const page = await context.newPage();
  await page.goto(corpus.url("attacker.test", "/attack/hidden-display-none.html"));
  await expect.poll(async () => (await page.content()).includes("AF-01"), { timeout: 5_000 }).toBe(false);
  expect(blockedRequests).toEqual([]);
});

test("RR4: the same instruction with data-launchsafe-removed on it is removed and the tab quarantined", async ({ context, extensionId, serviceWorker, corpus, blockedRequests }) => {
  // Fixed: the guard knows its own markers by identity (a private WeakSet), never by the attribute.
  await agentModeOn(context, extensionId);
  const page = await context.newPage();
  await page.goto(corpus.url("attacker.test", "/review/marker-spoof.html"));
  const tabId = (await tabIdFor(serviceWorker, corpus.url("attacker.test", "/review/marker-spoof.html"))) as number;
  await expect.poll(async () => (await page.content()).includes("AF-SPOOF"), { timeout: 5_000 }).toBe(false);
  await expect.poll(async () => (await tabState(serviceWorker, tabId))?.quarantined ?? false, { timeout: 5_000 }).toBe(true);
  expect(blockedRequests).toEqual([]);
});

// ---- RR5: a hidden instruction longer than half the page counts as visible ----

test("RR5: a hidden instruction padded past half of the page's text is still removed in agent mode", async ({ context, extensionId, serviceWorker, corpus, blockedRequests }) => {
  // Fixed: the loading-veil rule applies only to a hidden run that is benign on its own (no agent address, not quarantine-class).
  await agentModeOn(context, extensionId);
  const page = await context.newPage();
  await page.goto(corpus.url("attacker.test", "/review/oversize-hidden.html"));
  const tabId = (await tabIdFor(serviceWorker, corpus.url("attacker.test", "/review/oversize-hidden.html"))) as number;
  await expect.poll(async () => (await page.content()).includes("AF-BIG"), { timeout: 5_000 }).toBe(false);
  expect((await tabState(serviceWorker, tabId))?.quarantined).toBe(true);
  expect(blockedRequests).toEqual([]);
});

// ---- RR2: flooding the session's prints freezes every tab's leak context ----

test("RR2 control: a code shown on mail.test and typed on attacker.test is held back", async ({ context, extensionId, serviceWorker, corpus }) => {
  await agentModeOn(context, extensionId);
  const form = await context.newPage();
  await form.goto(corpus.url("attacker.test", "/leak/form.html"));
  const mail = await context.newPage();
  await mail.goto(corpus.url("mail.test", "/leak/mail.html"));
  await expect.poll(async () => (await readState(serviceWorker)).session !== null && JSON.stringify(await readState(serviceWorker)).includes('"short"'), { timeout: 5_000 }).toBe(true);
  await form.waitForTimeout(300);
  await form.bringToFront();
  await cdpType(form, "#code", CODE);
  await expect.poll(() => form.locator("#code").inputValue()).not.toBe(CODE);
});

test("RR2: after a page shows 3,000 addresses, the code typed on that page is still held back", async ({ context, extensionId, serviceWorker, corpus, blockedRequests }) => {
  // Fixed: the session keeps at most 2,000 prints (the content script's bound), evicting old addresses before codes.
  test.setTimeout(60_000);
  await agentModeOn(context, extensionId);
  const form = await context.newPage();
  await form.goto(corpus.url("attacker.test", "/review/flood-form.html"));
  const prints = async () => ((await readState(serviceWorker)) as unknown as { session: { prints: unknown[] } | null }).session?.prints.length ?? 0;
  // The session holds at most 2,000 prints however many the page shows (RR2): wait until the flood has filled it.
  await expect.poll(prints, { timeout: 10_000 }).toBe(2_000);
  const mail = await context.newPage();
  await mail.goto(corpus.url("mail.test", "/leak/mail.html"));
  await expect.poll(async () => JSON.stringify(await readState(serviceWorker)).includes('"short"'), { timeout: 5_000 }).toBe(true);
  await form.waitForTimeout(300);
  await form.bringToFront();
  await cdpType(form, "#code", CODE);
  await form.waitForTimeout(300);
  expect(await form.locator("#code").inputValue()).not.toBe(CODE);
  expect(blockedRequests).toEqual([]);
});

// ---- RR16: a refused leak context must fail toward "ask the worker" ----

/** Pushes a leak context to every frame of the tab, as the worker does (content scripts accept only the worker's messages). */
async function pushContext(sw: Worker, tabId: number, context: unknown): Promise<void> {
  await sw.evaluate(([id, c]) => chrome.tabs.sendMessage(id as number, { type: "leak.context", context: c }).catch(() => undefined), [tabId, context] as const);
}

const EMPTY_ON = { agentMode: true, untrusted: true, quarantined: false, private: true, prints: [], secretAllow: [], paymentHosts: [] };

async function codeShownThenForm(context: BrowserContext, extensionId: string, serviceWorker: Worker, corpus: CorpusServer) {
  await agentModeOn(context, extensionId);
  const form = await context.newPage();
  await form.goto(corpus.url("attacker.test", "/leak/form.html"));
  const mail = await context.newPage();
  await mail.goto(corpus.url("mail.test", "/leak/mail.html"));
  await expect.poll(async () => JSON.stringify(await readState(serviceWorker)).includes('"short"'), { timeout: 5_000 }).toBe(true);
  // Let the worker's pushes settle before the test overrides the frame's context.
  await form.waitForTimeout(800);
  const tabId = (await tabIdFor(serviceWorker, corpus.url("attacker.test", "/leak/form.html"))) as number;
  return { form, tabId };
}

test("RR16 control: a frame left with a context that lacks the code's print lets the code through locally", async ({ context, extensionId, serviceWorker, corpus }) => {
  const { form, tabId } = await codeShownThenForm(context, extensionId, serviceWorker, corpus);
  await pushContext(serviceWorker, tabId, EMPTY_ON);
  await form.bringToFront();
  await cdpType(form, "#code", CODE);
  await form.waitForTimeout(400);
  expect(await form.locator("#code").inputValue()).toBe(CODE);
});

test("RR16: after the worker sends a context the frame refuses, the frame asks the worker, and the worker's hold wins", async ({ context, extensionId, serviceWorker, corpus, blockedRequests }) => {
  // Fixed: a refused context marks the frame stale; a local allow then goes to the worker, whose stricter verdict takes the value back.
  const { form, tabId } = await codeShownThenForm(context, extensionId, serviceWorker, corpus);
  await pushContext(serviceWorker, tabId, EMPTY_ON);
  // Over the print bound: the content script refuses it.
  await pushContext(serviceWorker, tabId, { ...EMPTY_ON, prints: Array.from({ length: 2_001 }, (_, i) => ({ fp: `f${i}`, kind: "long", domain: "x.test" })) });
  await form.bringToFront();
  // With a refused (stale) context every keystroke is held and the field frozen until the worker answers
  // (content/leak.ts); a key typed before that answer is dropped, as designed. So type at a person's pace: each
  // key once the field shows the one before it, so the whole code reaches the worker.
  await form.locator("#code").click();
  for (let i = 0; i < CODE.length - 1; i++) {
    await form.keyboard.type(CODE.charAt(i));
    await expect.poll(() => form.locator("#code").inputValue(), { timeout: 5_000 }).toBe(CODE.slice(0, i + 1));
  }
  await form.keyboard.type(CODE.charAt(CODE.length - 1));
  const panel = await openPanel(context, extensionId);
  const typeHolds = async () =>
    ((await panel.evaluate(() => chrome.runtime.sendMessage({ type: "ui.state" }))) as { pending: { domain: string; kind: string }[] }).pending
      .filter((p) => p.domain === "attacker.test")
      .map((p) => p.kind);
  await expect.poll(typeHolds, { timeout: 5_000 }).toContain("type");
  expect(await form.locator("#code").inputValue()).not.toBe(CODE);
  expect(blockedRequests).toEqual([]);
});
