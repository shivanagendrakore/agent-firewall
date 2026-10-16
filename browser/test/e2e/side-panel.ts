/**
 * The real side panel, for the specs that decide something.
 *
 * The worker accepts approving, denying, agent mode, settings, the log and the
 * link switch only from the side panel or its own approval window
 * (src/worker/ui-surface.ts); sidepanel.html opened in an ordinary tab can
 * only read. So the specs open the real panel the way the toolbar popup does:
 * popup.html calls chrome.sidePanel.open({ windowId }) inside a gesture, and
 * Playwright evaluates with a user gesture.
 *
 * Chrome reports a side panel to the DevTools protocol as a target of type
 * "other", not "page" (it is not a tab), and Playwright detaches from "other"
 * targets unless PW_CHROMIUM_ATTACH_TO_OTHER is set in the process that drives
 * the browser; with it set, Playwright attaches to the panel like a page and it
 * arrives in context.pages() as an ordinary Page (locators, keyboard, download
 * events), while the panel itself stays the real one: its messages carry no
 * tab (the "panel" surface). fixtures.ts sets the variable before any browser
 * starts. Nothing in the shipped extension changes for this.
 *
 * When no panel arrives, the error lists every DevTools target with its type
 * and url, the pages Playwright has, and the panel options, so one CI log says
 * what Chrome made of the panel.
 *
 * One panel per context (the panel is global to its window), kept open for the
 * whole test; never close it from a spec.
 */
import type { BrowserContext, Page } from "@playwright/test";

/** Playwright's switch that attaches to "other" targets (side panels) as pages. Read when a target attaches. */
export const ATTACH_TO_OTHER = "PW_CHROMIUM_ATTACH_TO_OTHER";

const panels = new WeakMap<BrowserContext, Page>();

/** Whether this page of ours is the side panel itself (no tab), not a copy of it in a tab. */
async function isRealPanel(page: Page, panelUrl: string): Promise<boolean> {
  if (page.isClosed() || !page.url().startsWith(panelUrl)) return false;
  try {
    return await page.evaluate(async () => (await chrome.tabs.getCurrent()) === undefined);
  } catch {
    return false;
  }
}

/** What the browser has, for the error when the panel never reaches Playwright. Never throws. */
async function describeTargets(context: BrowserContext, opener: Page): Promise<string> {
  const lines: string[] = [`${ATTACH_TO_OTHER}=${JSON.stringify(process.env[ATTACH_TO_OTHER] ?? null)}`];
  try {
    const cdp = await context.newCDPSession(opener);
    const { targetInfos } = (await cdp.send("Target.getTargets")) as { targetInfos: { targetId: string; type: string; url: string; attached: boolean }[] };
    await cdp.detach().catch(() => undefined);
    lines.push(`DevTools targets (${targetInfos.length}):`);
    for (const t of targetInfos) lines.push(`  type=${t.type} attached=${t.attached} url=${t.url}`);
  } catch (e) {
    lines.push(`DevTools targets: could not list (${String(e)})`);
  }
  lines.push(`Playwright pages (${context.pages().length}):`);
  for (const p of context.pages()) lines.push(`  ${p === opener ? "[opener] " : ""}${p.url()}`);
  try {
    const info = await opener.evaluate(async () => ({ options: await chrome.sidePanel.getOptions({}), windows: (await chrome.windows.getAll()).map((w) => ({ id: w.id, type: w.type, focused: w.focused })) }));
    lines.push(`sidePanel options: ${JSON.stringify(info.options)}; windows: ${JSON.stringify(info.windows)}`);
  } catch (e) {
    lines.push(`sidePanel options: could not read (${String(e)})`);
  }
  return lines.join("\n");
}

export async function sidePanel(context: BrowserContext, extensionId: string): Promise<Page> {
  const known = panels.get(context);
  if (known !== undefined && !known.isClosed()) return known;
  const panelUrl = `chrome-extension://${extensionId}/sidepanel.html`;

  const opener = await context.newPage();
  await opener.goto(`chrome-extension://${extensionId}/popup.html`);
  const windowId = await opener.evaluate(async () => (await chrome.windows.getCurrent()).id);
  if (typeof windowId !== "number") throw new Error("the popup page has no window");
  // A fresh evaluate, so the call runs inside the gesture that sidePanel.open needs.
  const refused = await opener.evaluate((id) => chrome.sidePanel.open({ windowId: id }).then(() => null, (e: unknown) => String(e)), windowId);
  if (refused !== null) throw new Error(`the side panel did not open: ${refused}`);

  let panel: Page | undefined;
  const deadline = Date.now() + 10_000;
  while (panel === undefined && Date.now() < deadline) {
    for (const p of context.pages()) if (p !== opener && (await isRealPanel(p, panelUrl))) panel = p;
    if (panel === undefined) await opener.waitForTimeout(100);
  }
  if (panel === undefined) {
    const found = await describeTargets(context, opener);
    await opener.close();
    throw new Error(`the side panel opened, but no side panel page reached Playwright (looking for ${panelUrl} without a tab)\n${found}`);
  }
  await opener.close();
  panels.set(context, panel);
  return panel;
}

/** Sends a UI message from the real side panel, as its own script does. */
export async function fromPanel<T = unknown>(panel: Page, msg: Record<string, unknown>): Promise<T> {
  return (await panel.evaluate((m) => chrome.runtime.sendMessage(m), msg)) as T;
}

/**
 * Turns agent mode on from the real side panel with a new blank tab in front, and returns that tab: it is the
 * active tab, so it joins the agent session, and navigating it is "the agent's tab" (its domains count).
 */
export async function agentModeOnWithTab(context: BrowserContext, extensionId: string): Promise<Page> {
  const panel = await sidePanel(context, extensionId);
  const tab = await context.newPage();
  await tab.bringToFront();
  const r = await fromPanel<{ ok?: boolean; reason?: string } | undefined>(panel, { type: "ui.agentMode", on: true });
  if (r?.ok !== true) throw new Error(`agent mode did not turn on: ${JSON.stringify(r)}`);
  return tab;
}
