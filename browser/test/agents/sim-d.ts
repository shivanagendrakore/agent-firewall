/**
 * Simulator D: remote CDP automation, Playwright's
 * own input. Trusted events (`isTrusted: true`), the same input path as
 * Playwright, Puppeteer, Browser Use and DevTools MCP agents.
 */
import type { Page } from "@playwright/test";

/** A trusted mouse click (Input.dispatchMouseEvent). */
export async function cdpClick(page: Page, selector: string): Promise<void> {
  await page.locator(selector).click();
}

/** Trusted key events, one per character (Input.dispatchKeyEvent). */
export async function cdpType(page: Page, selector: string, text: string): Promise<void> {
  await page.locator(selector).click();
  await page.keyboard.type(text);
}

/** locator.fill: Input.insertText after selecting the field's content. */
export async function cdpFill(page: Page, selector: string, text: string): Promise<void> {
  await page.locator(selector).fill(text);
}

/** Enter in a field (implicit submission). */
export async function cdpPressEnter(page: Page, selector: string): Promise<void> {
  await page.locator(selector).press("Enter");
}

/** DOM.setFileInputFiles on a file input. Files are created in memory, never read from disk. */
export async function cdpSetFiles(page: Page, selector: string, files: { name: string; mimeType: string; text: string }[]): Promise<void> {
  await page.locator(selector).setInputFiles(files.map((f) => ({ name: f.name, mimeType: f.mimeType, buffer: Buffer.from(f.text) })));
}
