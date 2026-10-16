/**
 * Chrome Web Store images, produced on demand (the "store screenshots" workflow); skipped in normal runs.
 *
 *   STORE_SHOTS=1 STORE_SHOTS_DIR=<folder> npm run test:e2e -- test/e2e/store-screenshots.spec.ts
 *
 * Every screenshot is exactly 1280x800 (a full-viewport capture, not fullPage), and the promo tile is 440x280.
 * The real side panel is used to turn agent mode on and to decide; the narrow panel view is then screenshotted from
 * a copy of sidepanel.html in a tab (it only reads) and centred on a 1280x800 canvas with a one-line caption.
 * Each shot is its own test, so one that cannot be reached does not stop the others. Only appearance matters here:
 * nothing asserts behaviour (the other specs do).
 */
import type { BrowserContext, Page } from "@playwright/test";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { cdpClick } from "../agents/sim-d.js";
import type { CorpusServer } from "./corpus-server.js";
import { approvalsState, openPanel, setAgentMode, waitForCard } from "./gate-helpers.js";
import { agentTab, markSessionPrivate, waitForExplanation } from "./guard-helpers.js";
import { test } from "./fixtures.js";
import { fromPanel } from "./side-panel.js";

test.skip(process.env.STORE_SHOTS !== "1", "store screenshots run on demand");

const OUT_DIR = resolve(process.env.STORE_SHOTS_DIR ?? "store-shots");
const ICON = resolve(fileURLToPath(new URL("../../icons/icon-128.png", import.meta.url)));
const W = 1280;
const H = 800;
const FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";

function outPath(name: string): string {
  const p = resolve(OUT_DIR, name);
  mkdirSync(dirname(p), { recursive: true });
  return p;
}

/** The narrow panel page as it looks in a side panel (a tab copy of sidepanel.html, which only reads), as a PNG. */
async function panelPng(context: BrowserContext, extensionId: string, height: number): Promise<Buffer> {
  const page = await context.newPage();
  try {
    await page.setViewportSize({ width: 420, height });
    await page.goto(`chrome-extension://${extensionId}/sidepanel.html`);
    await page.locator("#mode").filter({ hasNotText: "Loading…" }).waitFor();
    await page.waitForTimeout(500);
    return await page.screenshot();
  } finally {
    await page.close();
  }
}

/** Writes a 1280x800 PNG: the panel picture centred under a one-line caption, on a plain background. */
async function composeOnCanvas(context: BrowserContext, panel: Buffer, caption: string, file: string): Promise<void> {
  const page = await context.newPage();
  try {
    await page.setViewportSize({ width: W, height: H });
    const src = `data:image/png;base64,${panel.toString("base64")}`;
    await page.setContent(
      `<!doctype html><meta charset="utf-8"><body style="margin:0;width:${W}px;height:${H}px;background:#eef1f6;font-family:${FONT};display:flex;flex-direction:column;align-items:center;overflow:hidden">
        <p style="margin:0;height:80px;line-height:80px;font-size:28px;font-weight:600;color:#14213d">${caption}</p>
        <img alt="" src="${src}" style="height:700px;width:auto;border:1px solid #c5ccd8;border-radius:8px;box-shadow:0 8px 28px rgba(20,33,61,.18)">
      </body>`,
    );
    await page.screenshot({ path: file });
  } finally {
    await page.close();
  }
}

/** Agent mode on, a checkout page open, and its Place order click held: the card is in the real side panel. */
async function holdCheckout(context: BrowserContext, corpus: CorpusServer, extensionId: string): Promise<{ panel: Page; page: Page }> {
  const panel = await openPanel(context, extensionId);
  await setAgentMode(panel, true);
  const page = await context.newPage();
  await page.goto(corpus.url("shop.test", "/actions/checkout.html"));
  await cdpClick(page, "#place");
  await waitForCard(panel);
  return { panel, page };
}

test("01-approval.png: an action held for approval", async ({ context, corpus, extensionId }) => {
  test.setTimeout(60_000);
  await holdCheckout(context, corpus, extensionId);
  const panel = await panelPng(context, extensionId, 700);
  await composeOnCanvas(context, panel, "A payment is held until you approve it", outPath("01-approval.png"));
});

test("02-side-panel.png: agent mode on, with log entries", async ({ context, corpus, extensionId }) => {
  test.setTimeout(90_000);
  const { panel } = await holdCheckout(context, corpus, extensionId);
  // A decision for the log: deny the payment, then hold and deny a message send.
  const id = (await approvalsState(panel)).approvals[0]?.approvalId;
  if (id !== undefined) await fromPanel(panel, { type: "ui.deny", approvalId: id });
  const mail = await context.newPage();
  await mail.goto(corpus.url("mail.test", "/actions/compose.html"));
  await cdpClick(mail, "#send");
  await waitForCard(panel);
  const png = await panelPng(context, extensionId, 700);
  await composeOnCanvas(context, png, "Agent mode on, with a local log of what was held", outPath("02-side-panel.png"));
});

test("03-blocked.png: a blocked navigation explained", async ({ context, corpus, extensionId, serviceWorker }) => {
  test.setTimeout(60_000);
  const page = await agentTab(context, extensionId);
  await markSessionPrivate(context, corpus, serviceWorker);
  await page.setViewportSize({ width: W, height: H });
  await page.goto(corpus.url("shop.test", "/attack/nav-exfil.html"));
  await page.waitForTimeout(300);
  await cdpClick(page, "#capture");
  await waitForExplanation(page);
  await page.waitForTimeout(300);
  await page.screenshot({ path: outPath("03-blocked.png") });
});

test("04-limits.png: what it does not stop", async ({ context, extensionId }) => {
  const page = await context.newPage();
  await page.setViewportSize({ width: W, height: H });
  await page.goto(`chrome-extension://${extensionId}/limits.html`);
  await page.waitForTimeout(300);
  await page.screenshot({ path: outPath("04-limits.png") });
});

test("promo-440x280.png: small promotional tile", async ({ context }) => {
  const page = await context.newPage();
  await page.setViewportSize({ width: 440, height: 280 });
  const icon = `data:image/png;base64,${readFileSync(ICON).toString("base64")}`;
  await page.setContent(
    `<!doctype html><meta charset="utf-8"><body style="margin:0;width:440px;height:280px;background:#0f172a;color:#f8fafc;font-family:${FONT};display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;overflow:hidden">
      <img alt="" src="${icon}" width="96" height="96">
      <p style="margin:18px 24px 0;font-size:26px;font-weight:700;line-height:1.2">LaunchSafe Agent Firewall</p>
      <p style="margin:10px 32px 0;font-size:15px;line-height:1.35;color:#cbd5e1">Holds risky browser actions for your approval</p>
    </body>`,
  );
  await page.screenshot({ path: outPath("promo-440x280.png") });
});
