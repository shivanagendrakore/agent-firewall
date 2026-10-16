/**
 * Helpers for the content guard and navigation e2e specs: the worker's tab
 * state, agent mode from the real side panel (never from a web page), and
 * the browser's real accessibility tree over CDP.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { BrowserContext, Page, Worker } from "@playwright/test";
import { CORPUS_DIR, REAL_CORPUS_DIR, type CorpusServer } from "./corpus-server.js";
import { agentModeOnWithTab } from "./side-panel.js";

export interface StoredTab {
  tabId: number;
  untrusted: boolean;
  private: boolean;
  quarantined: boolean;
  reasons: string[];
  openerTabId?: number;
}
export interface StoredState {
  tabs: StoredTab[];
  session: { private: boolean; domains: string[] } | null;
}

export interface AttackPage {
  file: string;
  host: "shop.test" | "mail.test" | "attacker.test" | "accounts.test";
  path: string;
  verdict: "deliver" | "neutralize" | "flag" | "quarantine";
  token: string;
  check: "gone" | "tag_chars_gone" | "zero_width_gone" | "bidi_gone" | "kept" | "url_query" | "url_fragment" | "expected_miss";
  technique: string;
  late?: boolean;
}
export interface BenignPage {
  file: string;
  host: "shop.test" | "mail.test" | "attacker.test" | "accounts.test";
  path: string;
  kind: string;
  late?: boolean;
}

export function attackCorpus(): AttackPage[] {
  return (JSON.parse(readFileSync(join(CORPUS_DIR, "attack", "expected.json"), "utf8")) as { pages: AttackPage[] }).pages;
}
export function benignCorpus(): BenignPage[] {
  return (JSON.parse(readFileSync(join(CORPUS_DIR, "benign", "expected.json"), "utf8")) as { pages: BenignPage[] }).pages;
}

export async function readState(sw: Worker): Promise<StoredState> {
  return ((await sw.evaluate(async () => (await chrome.storage.session.get("ls.state"))["ls.state"])) as StoredState | undefined) ?? { tabs: [], session: null };
}

/** The tab id of the page whose URL starts with `prefix` (host permissions let the worker see tab URLs). */
export async function tabIdFor(sw: Worker, prefix: string): Promise<number | null> {
  return sw.evaluate(async (p) => {
    const tabs = await chrome.tabs.query({});
    return tabs.find((t) => (t.url ?? "").startsWith(p))?.id ?? null;
  }, prefix);
}

export async function tabState(sw: Worker, tabId: number): Promise<StoredTab | undefined> {
  return (await readState(sw)).tabs.find((t) => t.tabId === tabId);
}

/**
 * Turns agent mode on from the real side panel, as a person would. The blank tab in front when it turns on joins
 * the session and is then closed, so no test page is the session's own tab.
 */
export async function agentModeOn(context: BrowserContext, extensionId: string): Promise<void> {
  const tab = await agentModeOnWithTab(context, extensionId);
  await tab.close();
}

/**
 * Turns agent mode on from the real side panel and returns the tab that was in front: it is the active tab, so
 * it joins the agent session, and navigating it is "the agent's tab" (its domains count for the session).
 */
export async function agentTab(context: BrowserContext, extensionId: string): Promise<Page> {
  return agentModeOnWithTab(context, extensionId);
}

/** Waits until a tab shows our explanation page (a blocked navigation first fails, then the worker redirects). */
export async function waitForExplanation(page: Page): Promise<URL> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (/^chrome-extension:\/\/[a-p]{32}\/blocked\.html\?/.test(page.url())) return new URL(page.url());
    await page.waitForTimeout(50);
  }
  throw new Error(`no explanation page; the tab is at ${page.url()}`);
}

/**
 * Makes the agent session private the real way: a mail page showing a one-time code opens in the session, its
 * content script sends the code's prints (private.prints, the leak guard's path), and the worker marks the tab and
 * the session private. Waits until the stored session says so; the mail tab stays open (closing it changes nothing).
 */
export async function markSessionPrivate(context: BrowserContext, corpus: CorpusServer, sw: Worker): Promise<Page> {
  if ((await readState(sw)).session === null) throw new Error("no agent session");
  const mail = await context.newPage();
  await mail.goto(corpus.url("mail.test", "/leak/mail.html"));
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if ((await readState(sw)).session?.private === true) return mail;
    await mail.waitForTimeout(50);
  }
  throw new Error("the agent session did not become private");
}

/** Every name, value and description in the browser's own accessibility tree for the page (all frames). */
export async function accessibilityText(page: Page): Promise<string> {
  const cdp = await page.context().newCDPSession(page);
  try {
    const { nodes } = (await cdp.send("Accessibility.getFullAXTree")) as { nodes: { name?: { value?: unknown }; value?: { value?: unknown }; description?: { value?: unknown } }[] };
    return nodes.map((n) => [n.name?.value, n.value?.value, n.description?.value].filter((v) => typeof v === "string").join(" ")).join("\n");
  } finally {
    await cdp.detach();
  }
}

export interface RealPage {
  id: string;
  file: string;
  url: string;
  category: string;
  lang: string;
  dir: string;
  title: string;
  capturedAt: string;
  license: string;
  bytes: number;
}
/** The captured real-page corpus (scripts/capture-corpus.mjs, in LAUNCHSAFE_BROWSER_CORPUS_DIR); empty when nothing has been captured. */
export function realCorpus(): RealPage[] {
  try {
    return (JSON.parse(readFileSync(join(REAL_CORPUS_DIR, "manifest.json"), "utf8")) as { pages: RealPage[] }).pages;
  } catch {
    return [];
  }
}

export interface KnownFinding {
  verdict: "quarantine" | "flag";
  kind: "false-positive" | "by-design";
  cases: string;
}
/** Real-corpus pages that trip the guard today, each explained (known-findings.json in the real corpus directory). */
export function knownFindings(): Record<string, KnownFinding> {
  try {
    return (JSON.parse(readFileSync(join(REAL_CORPUS_DIR, "known-findings.json"), "utf8")) as { pages: Record<string, KnownFinding> }).pages;
  } catch {
    return {};
  }
}
