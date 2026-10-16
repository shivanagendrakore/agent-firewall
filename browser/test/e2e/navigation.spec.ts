/**
 * Navigation policy acceptance: in agent mode, capture
 * hosts, raw IPs, DNS-exfil-shaped hosts and (in a private session)
 * data-carrying URLs to a new origin are stopped by declarativeNetRequest and
 * land on the explanation page, for simulator A (page script) and simulator D
 * (Playwright input); javascript: links do not run in agent mode; with agent
 * mode off only subresources to capture hosts are blocked; and no request of
 * any of these ever leaves the browser (the harness records every request to
 * a non-test host, and the corpus server records every request it gets).
 */
import type { Page, Worker } from "@playwright/test";
import { cdpClick } from "../agents/sim-d.js";
import { scriptClick } from "../agents/sim-a.js";
import { ALWAYS_RULES, sessionRules } from "../../src/engine/nav-rules.js";
import { approvalsState, approveFirst, openPanel } from "./gate-helpers.js";
import { agentModeOn, agentTab, markSessionPrivate, waitForExplanation } from "./guard-helpers.js";
import { expect, test } from "./fixtures.js";
import { fromPanel } from "./side-panel.js";

const NAV_PAGE = "/attack/nav-exfil.html";

type Sim = { name: string; click: (page: Page, selector: string) => Promise<void> };
const SIMULATORS: Sim[] = [
  { name: "A (page script click)", click: scriptClick },
  { name: "D (Playwright input)", click: cdpClick },
];

const CASES: { link: string; rule: string }[] = [
  { link: "#capture", rule: "nav.capture_host" },
  { link: "#dns", rule: "nav.suspicious_host" },
  { link: "#dns-entropy", rule: "nav.suspicious_host" },
  { link: "#rawip", rule: "nav.suspicious_host" },
  { link: "#entropy", rule: "nav.high_entropy_new_origin" },
];

async function sessionRuleCount(sw: Worker): Promise<number> {
  return sw.evaluate(async () => (await chrome.declarativeNetRequest.getSessionRules()).length);
}

async function sessionHasExactHost(sw: Worker, host: string): Promise<boolean> {
  return sw.evaluate(async (h) => (await chrome.declarativeNetRequest.getSessionRules()).some((r) => r.condition.requestDomains?.includes(h) === true), host);
}

for (const sim of SIMULATORS) {
  test(`agent mode, private session: exfil navigations land on the explanation page (simulator ${sim.name})`, async ({ context, extensionId, serviceWorker, corpus, blockedRequests }) => {
    test.setTimeout(60_000);
    // The agent's tab: in the session, so the session's domains are the ones it has shown.
    const page = await agentTab(context, extensionId);
    await markSessionPrivate(context, corpus, serviceWorker);
    await expect.poll(() => sessionRuleCount(serviceWorker)).toBeGreaterThan(8);
    for (const c of CASES) {
      await page.goto(corpus.url("shop.test", NAV_PAGE));
      // The exact-host rule comes from the content script's link scan (nav.hosts): wait for it before clicking.
      if (c.link === "#dns-entropy") await expect.poll(() => sessionHasExactHost(serviceWorker, "k7q2x9w4m8z3v6b1n5c0.attacker.test")).toBe(true);
      await sim.click(page, c.link);
      const u = await waitForExplanation(page);
      expect({ link: c.link, rule: u.searchParams.get("rule") }).toEqual({ link: c.link, rule: c.rule });
      expect(u.host).toBe(extensionId);
      // The page explains, shows the host, and never the data.
      await expect(page.locator("#rule")).toHaveText(c.rule);
      expect(page.url()).not.toContain("QWxleCBSaXZlcmEg");
    }
    // None of those requests reached the corpus server or tried the network.
    expect(corpus.requests.filter((r) => r.path.startsWith("/attack/landing.html"))).toEqual([]);
    expect(blockedRequests).toEqual([]);
  });

  test(`agent mode: a javascript: link does not run, its page handler still does (simulator ${sim.name})`, async ({ context, extensionId, corpus, blockedRequests }) => {
    await agentModeOn(context, extensionId);
    const page = await context.newPage();
    await page.goto(corpus.url("shop.test", NAV_PAGE));
    await page.waitForTimeout(150);
    await sim.click(page, "#js");
    await sim.click(page, "#js-button");
    await page.waitForTimeout(150);
    expect(await page.evaluate(() => ({ js: (window as unknown as { __jsRan?: boolean }).__jsRan ?? false, handler: (window as unknown as { __handlerRan?: boolean }).__handlerRan ?? false }))).toEqual({ js: false, handler: true });
    expect(blockedRequests).toEqual([]);
  });
}

test("agent mode, private session: a plain link to a new origin, and data to a domain the session knows, are allowed; once that domain injects (quarantine), data to it is stopped again (RR6)", async ({ context, extensionId, serviceWorker, corpus, blockedRequests }) => {
  const page = await agentTab(context, extensionId);
  await markSessionPrivate(context, corpus, serviceWorker);
  await expect.poll(() => sessionRuleCount(serviceWorker)).toBeGreaterThan(8);
  await page.goto(corpus.url("shop.test", NAV_PAGE));
  await cdpClick(page, "#plain");
  await page.waitForURL(/\/attack\/landing\.html$/);
  await expect(page.locator("h1")).toHaveText("Landing page");
  // attacker.test is now part of the session: the same data-carrying link is no longer "new origin".
  await expect.poll(async () => (await serviceWorker.evaluate(async () => ((await chrome.storage.session.get("ls.state"))["ls.state"] as { session: { domains: string[] } }).session.domains))).toContain("attacker.test");
  await expect.poll(async () => serviceWorker.evaluate(async () => (await chrome.declarativeNetRequest.getSessionRules()).some((r) => r.condition.excludedRequestDomains?.includes("attacker.test") === true))).toBe(true);
  await page.goto(corpus.url("shop.test", NAV_PAGE));
  await cdpClick(page, "#entropy");
  await page.waitForURL(/\/attack\/landing\.html\?d=/);
  const landed = () => corpus.requests.filter((r) => r.host === "attacker.test" && r.path.startsWith("/attack/landing.html?d=")).length;
  const before = landed();

  // attacker.test now serves a page with a hidden instruction: the session is quarantined and attacker.test is the
  // site that injected it, so it is no longer a known destination for data (RR6).
  const evil = await context.newPage();
  await evil.goto(corpus.url("attacker.test", "/attack/hidden-display-none.html"));
  await expect.poll(async () => (await serviceWorker.evaluate(async () => ((await chrome.storage.session.get("ls.state"))["ls.state"] as { session: { quarantined: boolean; injectors?: string[] } }).session)), { timeout: 5_000 }).toMatchObject({ quarantined: true, injectors: expect.arrayContaining(["attacker.test"]) });
  await expect.poll(async () => serviceWorker.evaluate(async () => (await chrome.declarativeNetRequest.getSessionRules()).some((r) => r.condition.excludedRequestDomains?.includes("attacker.test") === true))).toBe(false);
  await page.goto(corpus.url("shop.test", NAV_PAGE));
  await cdpClick(page, "#entropy");
  const u = await waitForExplanation(page);
  expect(u.searchParams.get("rule")).toBe("nav.high_entropy_new_origin");
  expect(landed()).toBe(before);
  expect(blockedRequests).toEqual([]);
});

test("integration: an approvable blocked navigation waits in the side panel and, approved there, opens once", async ({ context, extensionId, serviceWorker, corpus, blockedRequests }) => {
  const page = await agentTab(context, extensionId);
  await markSessionPrivate(context, corpus, serviceWorker);
  await expect.poll(() => sessionRuleCount(serviceWorker)).toBeGreaterThan(8);
  const panel = await openPanel(context, extensionId);
  // The corpus server is shared by the worker's tests: count from here.
  const landed = () => corpus.requests.filter((r) => r.path.startsWith("/attack/landing.html?d=")).length;
  const before = landed();
  await page.goto(corpus.url("shop.test", NAV_PAGE));
  await cdpClick(page, "#entropy");
  const u = await waitForExplanation(page);
  expect(u.searchParams.get("approval")).toBe("1");
  await expect(page.locator("#next")).toContainText("side panel");
  // The card shows the origin and how much data, never the data itself.
  const st = await approvalsState(panel);
  const nav = st.approvals.find((a) => a.subject === "navigation");
  expect(nav).toMatchObject({ subject: "navigation", domain: "attacker.test", siteGrantable: false });
  expect(JSON.stringify(st)).not.toContain("QWxleCBSaXZlcmEg");
  await expect(panel.locator('article.card[data-subject="navigation"]')).toContainText("attacker.test");
  expect(landed()).toBe(before);
  // Approved with a person's pointer in our own page: the tab opens the address once.
  await approveFirst(panel);
  await page.waitForURL(/\/attack\/landing\.html\?d=/);
  expect(landed()).toBe(before + 1);
  // The pass is spent: the one-shot allow rule is gone once the page committed.
  await expect.poll(async () => serviceWorker.evaluate(async () => (await chrome.declarativeNetRequest.getSessionRules()).filter((r) => r.action.type === "allow").length)).toBe(0);
  expect(blockedRequests).toEqual([]);
});

test("integration: a denied navigation (capture host) offers no approval", async ({ context, extensionId, serviceWorker, corpus, blockedRequests }) => {
  const page = await agentTab(context, extensionId);
  await markSessionPrivate(context, corpus, serviceWorker);
  const panel = await openPanel(context, extensionId);
  await page.goto(corpus.url("shop.test", NAV_PAGE));
  await cdpClick(page, "#capture");
  const u = await waitForExplanation(page);
  expect(u.searchParams.get("approval")).toBeNull();
  await page.waitForTimeout(300);
  expect((await approvalsState(panel)).approvals.filter((a) => a.subject === "navigation")).toEqual([]);
  expect(blockedRequests).toEqual([]);
});

test("agent mode: a browser-initiated navigation (page.goto) to a capture host is stopped too", async ({ context, extensionId, blockedRequests }) => {
  await agentModeOn(context, extensionId);
  const page = await context.newPage();
  await page.goto("https://webhook.site/7f3e2a9c-launchsafe-test").catch(() => undefined);
  expect((await waitForExplanation(page)).searchParams.get("rule")).toBe("nav.capture_host");
  expect(blockedRequests).toEqual([]);
});

test("agent mode off: javascript: links run, top-level navigation is the person's, and capture-host subresources are still blocked", async ({ context, corpus, serviceWorker, blockedRequests }) => {
  const page = await context.newPage();
  await page.goto(corpus.url("shop.test", NAV_PAGE));
  expect(await serviceWorker.evaluate(async () => (await chrome.declarativeNetRequest.getSessionRules()).length)).toBe(0);
  // The capture-host image never loaded and never reached the network (the static ruleset blocked it).
  expect(await page.evaluate(() => (document.getElementById("capture-img") as HTMLImageElement).naturalWidth)).toBe(0);
  expect(blockedRequests.filter((u) => u.includes("webhook.site"))).toEqual([]);
  await cdpClick(page, "#js");
  await expect.poll(() => page.evaluate(() => (window as unknown as { __jsRan?: boolean }).__jsRan ?? false)).toBe(true);
  // A DNS-exfil-shaped link is not stopped with agent mode off: the navigation is the person's.
  await page.goto(corpus.url("shop.test", NAV_PAGE));
  await cdpClick(page, "#dns");
  await page.waitForTimeout(500);
  expect(page.url()).not.toContain("blocked.html");
  expect(blockedRequests).toEqual([]);
});

test("turning agent mode off (with the person's approval) removes the session rules", async ({ context, extensionId, serviceWorker }) => {
  await agentModeOn(context, extensionId);
  await expect.poll(() => sessionRuleCount(serviceWorker)).toBeGreaterThan(0);
  const panel = await openPanel(context, extensionId);
  const off = await fromPanel<{ approvalId: string }>(panel, { type: "ui.agentMode", on: false });
  expect(await sessionRuleCount(serviceWorker)).toBeGreaterThan(0);
  expect(await fromPanel(panel, { type: "ui.approve", approvalId: off.approvalId })).toEqual({ ok: true });
  await expect.poll(() => sessionRuleCount(serviceWorker)).toBe(0);
});

test("Chrome accepts every navigation rule: the static ruleset is enabled and every regex fits DNR's memory budget", async ({ serviceWorker }) => {
  const regexes = [...ALWAYS_RULES, ...sessionRules({ agentMode: true, private: true, sessionDomains: ["shop.test"], suspiciousHosts: ["k7q2x9w4m8z3v6b1n5c0.attacker.test"], originSet: ["shop.test"] })].flatMap((r) => (r.condition.regexFilter === undefined ? [] : [r.condition.regexFilter]));
  const refused = await serviceWorker.evaluate(async (list) => {
    const out: string[] = [];
    for (const regex of list) {
      const r = await chrome.declarativeNetRequest.isRegexSupported({ regex });
      if (!r.isSupported) out.push(`${regex}: ${r.reason ?? ""}`);
    }
    return out;
  }, regexes);
  expect(refused).toEqual([]);
  expect(await serviceWorker.evaluate(() => chrome.declarativeNetRequest.getEnabledRulesets())).toEqual(["always"]);
});
