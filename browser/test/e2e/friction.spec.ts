/**
 * Friction: on the benign corpus, quarantine verdicts on
 * 0 pages and flags on under 2% of pages; turning agent mode on changes the
 * visible page on 0 pages (the screenshot and the visible text are identical
 * before and after, and no marker appears); nothing leaves 127.0.0.1.
 */
import type { Page } from "@playwright/test";
import { agentModeOn, benignCorpus, tabIdFor, tabState } from "./guard-helpers.js";
import { expect, test } from "./fixtures.js";

const PAGES = benignCorpus();

test("benign corpus: no quarantine, flags under 2%, and agent mode changes nothing a person sees", async ({ context, extensionId, serviceWorker, corpus, blockedRequests }) => {
  test.setTimeout(180_000);
  const opened: { file: string; page: Page; tabId: number; shot: Buffer; text: string }[] = [];
  let flagged = 0;
  let quarantined = 0;
  const rows: string[] = [];
  for (const p of PAGES) {
    const page = await context.newPage();
    await page.setViewportSize({ width: 1100, height: 900 });
    await page.goto(corpus.url(p.host, p.path));
    const tabId = await tabIdFor(serviceWorker, corpus.url(p.host, `/benign/${p.file}`));
    expect(tabId, p.file).not.toBeNull();
    // Late content (comments) arrives at 300 ms; the guard rescans within 50 ms of it.
    await page.waitForTimeout(p.late === true ? 800 : 400);
    const t = await tabState(serviceWorker, tabId as number);
    const q = t?.quarantined === true;
    const f = t?.reasons.includes("flag_verdict") === true;
    if (q) quarantined++;
    else if (f) flagged++;
    rows.push(`${p.file}: ${q ? "QUARANTINE" : f ? "FLAG" : "clean"}`);
    opened.push({ file: p.file, page, tabId: tabId as number, shot: await page.screenshot(), text: await page.evaluate(() => document.body.innerText) });
  }
  console.info(`friction: ${rows.join("; ")}`);
  expect(quarantined, rows.join("\n")).toBe(0);
  expect(flagged / PAGES.length, rows.join("\n")).toBeLessThan(0.02);

  // Agent mode on: every open tab is told; the guard neutralises whatever it queued. On benign pages that must be nothing visible.
  await agentModeOn(context, extensionId);
  for (const o of opened) {
    await o.page.bringToFront();
    await o.page.waitForTimeout(250);
    expect(await o.page.locator("[data-launchsafe-removed]").count(), o.file).toBe(0);
    expect(await o.page.evaluate(() => document.body.innerText), `${o.file}: visible text changed`).toBe(o.text);
    const after = await o.page.screenshot();
    expect(after.equals(o.shot), `${o.file}: screenshot changed after agent mode`).toBe(true);
  }
  expect(blockedRequests).toEqual([]);
});

test("benign corpus loaded fresh in agent mode: still no quarantine and no markers", async ({ context, extensionId, serviceWorker, corpus, blockedRequests }) => {
  test.setTimeout(120_000);
  await agentModeOn(context, extensionId);
  for (const p of PAGES) {
    const page = await context.newPage();
    await page.goto(corpus.url(p.host, p.path));
    await page.waitForTimeout(p.late === true ? 800 : 300);
    const tabId = await tabIdFor(serviceWorker, corpus.url(p.host, `/benign/${p.file}`));
    expect((await tabState(serviceWorker, tabId as number))?.reasons.includes("quarantine_verdict") ?? false, p.file).toBe(false);
    expect(await page.locator("[data-launchsafe-removed]").count(), p.file).toBe(0);
    await page.close();
  }
  expect(blockedRequests).toEqual([]);
});
