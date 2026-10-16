/**
 * The downloads gate for simulators A, B and D:
 * an executable is cancelled before it lands, and lands exactly once after a
 * person approves it in the side panel. A benign file is not held.
 *
 * Honest limits, asserted:
 * - the first GET for the file has already reached the server when Chrome
 *   tells the extension about the download, so "takes no effect" here means
 *   no file is saved, not that no request was sent;
 * - a DevTools client that overrides download behaviour (Playwright does by
 *   default, Browser.setDownloadBehavior allowAndName) takes file naming away
 *   from extensions, and the gate never sees the file: a class D bypass.
 *
 * The gate tests therefore reset the DevTools override first, so Chrome takes
 * its own download path (the one a person's browser takes), into the temp
 * profile's pinned download folder (fixtures.ts).
 */
import type { BrowserContext, Page, Worker } from "@playwright/test";
import type { CorpusServer } from "./corpus-server.js";
import { DEBUGGER_AGENT_DIR, debuggerAgent, debuggerAgentWorker } from "../agents/sim-b.js";
import { expect, test } from "./fixtures.js";
import { approveFirst, countRequests, openPanel, simClick, tabIdFor, waitForCard, type SimName } from "./gate-helpers.js";

interface Item {
  filename: string;
  state: string;
  url: string;
}

async function downloadsOf(sw: Worker, name: string): Promise<Item[]> {
  const all = (await sw.evaluate(() => chrome.downloads.search({}))) as Item[];
  return all.filter((d) => d.url.endsWith(`/actions/files/${name}`));
}

/** Gives downloads back to Chrome's own path (and so to extensions), as in a browser with no DevTools client. */
async function chromeOwnDownloads(context: BrowserContext, page: Page): Promise<void> {
  const cdp = await context.newCDPSession(page);
  await cdp.send("Browser.setDownloadBehavior", { behavior: "default" });
  await cdp.detach();
}

async function run(sim: SimName, deps: { context: BrowserContext; corpus: CorpusServer; extensionId: string; serviceWorker: Worker }): Promise<void> {
  const { context, corpus, extensionId, serviceWorker } = deps;
  const panel = await openPanel(context, extensionId);
  const page = await context.newPage();
  await chromeOwnDownloads(context, page);
  await page.goto(corpus.url("shop.test", "/actions/download.html"));
  const opts: Parameters<typeof simClick>[3] = {};
  if (sim === "B") {
    const agent = debuggerAgent(await debuggerAgentWorker(context));
    opts.agent = agent;
    opts.tabId = await tabIdFor(agent, page);
    await agent.attach(opts.tabId);
  }
  const gets = () => countRequests(corpus, "shop.test", "/actions/files/setup.exe", "GET");
  const base = gets();
  await simClick(sim, page, "#exe", opts);

  const card = await waitForCard(panel);
  await expect(card.locator("h3")).toContainText("Download a program or installer");
  await expect(card).toContainText("setup.exe");
  await page.waitForTimeout(500);
  const before = await downloadsOf(serviceWorker, "setup.exe");
  expect(before.filter((d) => d.state === "complete")).toEqual([]);
  expect(gets() - base).toBe(1); // the first request was already sent (listed limit)

  await approveFirst(panel);
  await expect.poll(async () => (await downloadsOf(serviceWorker, "setup.exe")).filter((d) => d.state === "complete").length, { timeout: 10_000 }).toBe(1);
  await page.waitForTimeout(500);
  expect((await downloadsOf(serviceWorker, "setup.exe")).filter((d) => d.state === "complete").length).toBe(1);
  expect(gets() - base).toBe(2);
}

for (const sim of ["A", "D"] as const) {
  test(`simulator ${sim}: an executable download is cancelled, then saved once after approval`, async ({ context, corpus, extensionId, serviceWorker }) => {
    await run(sim, { context, corpus, extensionId, serviceWorker });
  });
}

test.describe("simulator B", () => {
  test.use({ extraExtensions: [DEBUGGER_AGENT_DIR] });
  test("an executable download is cancelled, then saved once after approval", async ({ context, corpus, extensionId, serviceWorker }) => {
    await run("B", { context, corpus, extensionId, serviceWorker });
  });
});

test("a benign download is not held", async ({ context, corpus, extensionId, serviceWorker }) => {
  const panel = await openPanel(context, extensionId);
  const page = await context.newPage();
  await chromeOwnDownloads(context, page);
  await page.goto(corpus.url("shop.test", "/actions/download.html"));
  await page.locator("#txt").click();
  await expect.poll(async () => (await downloadsOf(serviceWorker, "notes.txt")).filter((d) => d.state === "complete").length, { timeout: 10_000 }).toBe(1);
  await expect(panel.locator("article.card")).toHaveCount(0);
});

test("KNOWN BYPASS (class D): with a DevTools download override in place, an executable is saved and the gate never sees it", async ({ context, corpus, extensionId, serviceWorker }) => {
  const panel = await openPanel(context, extensionId);
  const page = await context.newPage();
  // Playwright's own default: Browser.setDownloadBehavior allowAndName into its artifacts folder.
  await page.goto(corpus.url("shop.test", "/actions/download.html"));
  await page.locator("#exe").click();
  await expect.poll(async () => (await downloadsOf(serviceWorker, "setup.exe")).filter((d) => d.state === "complete").length, { timeout: 10_000 }).toBe(1);
  await page.waitForTimeout(300);
  await expect(panel.locator("article.card")).toHaveCount(0);
});
