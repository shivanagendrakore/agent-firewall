/**
 * Helpers for the gate e2e specs: the side panel as the approval surface,
 * agent mode, request counting on the corpus server, and the three agent
 * simulators' actions on one control.
 */
import type { BrowserContext, Frame, Locator, Page } from "@playwright/test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ApprovalsState } from "../../src/shared/messages.js";
import { ARM_MS } from "../../src/ui/view.js";
import { scriptClick } from "../agents/sim-a.js";
import type { DebuggerAgent } from "../agents/sim-b.js";
import type { CorpusServer, TestHost } from "./corpus-server.js";
import { expect } from "./fixtures.js";
import { sidePanel } from "./side-panel.js";

/** The real side panel (side-panel.ts), loaded: the only page besides the approval window that may decide. */
export async function openPanel(context: BrowserContext, extensionId: string): Promise<Page> {
  const panel = await sidePanel(context, extensionId);
  await expect(panel.locator("#mode")).not.toHaveText("Loading…");
  return panel;
}

/** sidepanel.html opened in an ordinary tab, as an agent could open it: it reads, and every decision from it is refused. */
export async function openPanelInTab(context: BrowserContext, extensionId: string): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/sidepanel.html`);
  await expect(page.locator("#mode")).not.toHaveText("Loading…");
  return page;
}

export async function setAgentMode(panel: Page, on: boolean): Promise<void> {
  const r = (await panel.evaluate((v) => chrome.runtime.sendMessage({ type: "ui.agentMode", on: v }), on)) as { ok: boolean };
  expect(r.ok).toBe(true);
}

export async function approvalsState(panel: Page): Promise<ApprovalsState> {
  return (await panel.evaluate(() => chrome.runtime.sendMessage({ type: "ui.approvals" }))) as ApprovalsState;
}

export function cards(panel: Page): Locator {
  return panel.locator("article.card");
}

/** Waits for the held action's card in the side panel (proof the gate held it and the worker queued it). */
export async function waitForCard(panel: Page, n = 1): Promise<Locator> {
  await expect(cards(panel)).toHaveCount(n, { timeout: 10_000 });
  return cards(panel).first();
}

/** A person's approval: a trusted pointer click on Approve, after the card arms. */
export async function approveFirst(panel: Page, button = "button.approve"): Promise<void> {
  const card = await waitForCard(panel);
  await panel.waitForTimeout(ARM_MS + 150);
  await card.locator(button).click();
}

/**
 * The names of every button in the browser's own accessibility tree for the page. It reaches into closed shadow
 * roots (the in-page notice lives in one), which no selector does.
 */
export async function accessibleButtons(page: Page): Promise<string[]> {
  const cdp = await page.context().newCDPSession(page);
  try {
    const { nodes } = (await cdp.send("Accessibility.getFullAXTree")) as { nodes: { ignored?: boolean; role?: { value?: unknown }; name?: { value?: unknown } }[] };
    return nodes.filter((n) => n.ignored !== true && n.role?.value === "button").map((n) => (typeof n.name?.value === "string" ? n.name.value : ""));
  } finally {
    await cdp.detach();
  }
}

export function countRequests(corpus: CorpusServer, host: TestHost, path: string, method = "POST"): number {
  return corpus.requests.filter((r) => r.host === host && r.method === method && r.path.startsWith(path)).length;
}

/** Waits long enough for a request that is not held to reach the server, then returns the count. */
export async function settledCount(page: Page, corpus: CorpusServer, host: TestHost, path: string, method = "POST"): Promise<number> {
  await page.waitForTimeout(400);
  return countRequests(corpus, host, path, method);
}

/** A small file in a fresh temp folder, for DOM.setFileInputFiles (the B simulator needs a real path). */
export function tempFile(name: string, text: string): string {
  const dir = mkdtempSync(join(tmpdir(), "lsfw-upload-"));
  const p = join(dir, name);
  writeFileSync(p, text);
  return p;
}

export type SimName = "A" | "B" | "D";

/** Where the control lives: the page, or a frame of it. */
export function frameFor(page: Page, frameUrlPart?: string): Frame {
  if (frameUrlPart === undefined) return page.mainFrame();
  const f = page.frames().find((x) => x.url().includes(frameUrlPart));
  if (f === undefined) throw new Error(`no frame ${frameUrlPart}`);
  return f;
}

/** Clicks a control as one simulator: A page script el.click(), B chrome.debugger Input.dispatchMouseEvent, D Playwright's mouse. */
export async function simClick(sim: SimName, page: Page, selector: string, opts: { frame?: string; agent?: DebuggerAgent; tabId?: number } = {}): Promise<void> {
  const frame = frameFor(page, opts.frame);
  const loc = frame.locator(selector);
  await loc.waitFor({ state: "visible" });
  if (sim === "A") {
    if (opts.frame === undefined) await scriptClick(page, selector);
    else await frame.evaluate((s) => (document.querySelector(s) as HTMLElement | null)?.click(), selector);
  } else if (sim === "D") {
    await loc.click();
  } else {
    if (opts.agent === undefined || opts.tabId === undefined) throw new Error("simulator B needs the agent and a tab id");
    // The harness measures where the control is; the input itself goes through the debugger agent.
    const box = await loc.boundingBox();
    if (box === null) throw new Error(`no box for ${selector}`);
    await opts.agent.click(opts.tabId, box.x + box.width / 2, box.y + box.height / 2);
  }
}

/** The tab id of a page, as the debugger agent sees it. */
export async function tabIdFor(agent: DebuggerAgent, page: Page): Promise<number> {
  const tabs = await agent.findTabs(page.url());
  const t = tabs[0];
  if (t === undefined) throw new Error(`debugger agent cannot see ${page.url()}`);
  return t.id;
}
