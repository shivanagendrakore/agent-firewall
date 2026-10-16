/**
 * Simulator A: page-script automation. Every
 * action runs in the page's main world, so events are untrusted
 * (`isTrusted: false`) or bypass events entirely. Used by the gate and leak
 * lanes; the script-path helpers (`scriptFormSubmit`, `scriptFetch`) are the
 * documented known bypasses (B'/D script), asserted as bypasses.
 */
import type { Page } from "@playwright/test";

/** element.click() from page script. */
export async function scriptClick(page: Page, selector: string): Promise<void> {
  await page.evaluate((sel) => (document.querySelector(sel) as HTMLElement | null)?.click(), selector);
}

/** A synthetic event dispatched from page script (untrusted). */
export async function scriptDispatch(page: Page, selector: string, type: string, init: EventInit = { bubbles: true, cancelable: true }): Promise<void> {
  await page.evaluate(([sel, t, i]) => document.querySelector(sel as string)?.dispatchEvent(new Event(t as string, i as EventInit)), [selector, type, init] as const);
}

/** Sets a field's value with the property setter: no input or change event fires (form_input-style). */
export async function scriptSetValue(page: Page, selector: string, value: string): Promise<void> {
  await page.evaluate(([sel, v]) => {
    const el = document.querySelector(sel as string) as HTMLInputElement | HTMLTextAreaElement | null;
    if (el !== null) el.value = v as string;
  }, [selector, value] as const);
}

/** form.requestSubmit() from page script: raises a submit event the gate can cancel. */
export async function scriptRequestSubmit(page: Page, formSelector: string): Promise<void> {
  await page.evaluate((sel) => (document.querySelector(sel) as HTMLFormElement | null)?.requestSubmit(), formSelector);
}

/** KNOWN BYPASS: form.submit() raises no submit event (design 5.5). */
export async function scriptFormSubmit(page: Page, formSelector: string): Promise<void> {
  await page.evaluate((sel) => (document.querySelector(sel) as HTMLFormElement | null)?.submit(), formSelector);
}

/** KNOWN BYPASS: fetch from page script (design 5.5, 6.3). Only to the corpus server. */
export async function scriptFetch(page: Page, url: string, body: string): Promise<number> {
  return page.evaluate(async ([u, b]) => (await fetch(u as string, { method: "POST", body: b as string })).status, [url, body] as const);
}
