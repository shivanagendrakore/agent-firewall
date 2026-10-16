/**
 * False-positive reproductions that need a real DOM (test/corpus/fp-cases/, docs/real-corpus-findings.md). They
 * were `test.fail()` until the guard treated display: contents as transparent; now they guard the fix.
 */
import type { Page, Worker } from "@playwright/test";
import { agentModeOn, tabIdFor, tabState } from "./guard-helpers.js";
import { expect, test } from "./fixtures.js";

async function verdictOf(page: Page, sw: Worker, url: string): Promise<"quarantine" | "flag" | "clean"> {
  await page.goto(url);
  const id = await tabIdFor(sw, url);
  expect(id).not.toBeNull();
  await page.waitForTimeout(400);
  const t = await tabState(sw, id as number);
  return t?.quarantined === true ? "quarantine" : t?.reasons.includes("flag_verdict") === true ? "flag" : "clean";
}

test("control: a visible link to a request-capture host is flagged, not quarantined", async ({ context, serviceWorker, corpus }) => {
  const v = await verdictOf(await context.newPage(), serviceWorker, corpus.url("shop.test", "/fp-cases/display-contents-control.html"));
  expect(v).toBe("flag");
});

test("FP-4: the same visible link inside a display: contents wrapper is judged visible (flag), not hidden (quarantine)", async ({ context, serviceWorker, corpus }) => {
  // element.checkVisibility() is false for display: contents (the element has no box); the guard used to take that
  // as "not rendered", so everything inside the wrapper counted as hidden. The verdict must not depend on the wrapper.
  const v = await verdictOf(await context.newPage(), serviceWorker, corpus.url("shop.test", "/fp-cases/display-contents.html"));
  expect(v).toBe("flag");
});

test("FP-4 control: hidden text inside a display: contents wrapper, and a wrapper hidden by visibility, still quarantine and are removed in agent mode", async ({ context, extensionId, serviceWorker, corpus }) => {
  const page = await context.newPage();
  const url = corpus.url("shop.test", "/fp-cases/display-contents-hidden.html");
  expect(await verdictOf(page, serviceWorker, url)).toBe("quarantine");
  await agentModeOn(context, extensionId);
  await page.bringToFront();
  await page.waitForTimeout(300);
  expect(await page.locator("#fp4-hidden").count()).toBe(0);
  expect(await page.locator("#fp4-ghost").count()).toBe(0);
  // The paragraph in a box-less wrapper with opacity 0 and clip-path is visible (neither applies), so it stays.
  await expect(page.locator("#fp4-boxless")).toBeVisible();
});
