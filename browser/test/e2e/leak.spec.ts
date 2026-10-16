/**
 * Leak guard, agent mode and the decision log, end to end.
 *
 * - The Brave-style flow: a one-time code shown on mail.test, then typed,
 *   filled, set by script or submitted on attacker.test, is held back in agent
 *   mode for simulators A (page script) and D (Playwright's CDP input). B (an
 *   extension driving tabs with chrome.debugger) is the hook at the end; it
 *   skips while simulator B is a stub.
 * - Secrets and Luhn-valid cards to a non-allowed origin are held back;
 *   published test cards and test keys are not.
 * - navigator.webdriver turns agent mode on (Playwright sets it); turning it
 *   off needs the confirmation in our own page.
 * - The log verifies after appends, catches an edit made in IndexedDB, drops
 *   entries past retention without breaking the chain, exports and deletes.
 *
 * Every test runs in a fresh temp profile; no request leaves 127.0.0.1.
 */
import type { BrowserContext, Page, Worker } from "@playwright/test";
import { cdpClick, cdpFill, cdpType } from "../agents/sim-d.js";
import { scriptRequestSubmit, scriptSetValue } from "../agents/sim-a.js";
import { debuggerAgent, debuggerAgentWorker, DEBUGGER_AGENT_DIR } from "../agents/sim-b.js";
import type { CorpusServer } from "./corpus-server.js";
import { approveFirst, openPanel, waitForCard } from "./gate-helpers.js";
import { expect, test } from "./fixtures.js";

// These tests are about the product default: navigator.webdriver (set by Playwright) turns agent mode on.
test.use({ detectWebdriver: true });

const CODE = "482915";
// Fake credential shapes and a Luhn-valid card that is not a published test number, assembled at run time.
const GH_TOKEN = ["gh", "p_", "Zq8".repeat(12)].join("");
const STRIPE_TEST = ["sk", "_test_", "4eC39HqLyjWDarjtT1zdp7dc"].join("");
const REAL_CARD = luhnComplete("453914880343646");

function luhnComplete(prefix: string): string {
  for (let d = 0; d <= 9; d++) {
    const n = `${prefix}${d}`;
    let sum = 0;
    let dbl = false;
    for (let i = n.length - 1; i >= 0; i--) {
      let x = Number(n[i]);
      if (dbl) x = x * 2 > 9 ? x * 2 - 9 : x * 2;
      sum += x;
      dbl = !dbl;
    }
    if (sum % 10 === 0) return n;
  }
  throw new Error("unreachable");
}

interface StoredState {
  tabs: { tabId: number; inSession: boolean }[];
  session: { declaredClass: string; prints: unknown[] } | null;
}

async function state(sw: Worker): Promise<StoredState | undefined> {
  return (await sw.evaluate(() => chrome.storage.session.get("ls.state")))["ls.state"] as StoredState | undefined;
}

/** The real side panel, to talk to the worker as the UI does (decisions, settings and the log are panel-only). */
async function uiPage(context: BrowserContext, extensionId: string): Promise<Page> {
  return openPanel(context, extensionId);
}

async function ui<T = unknown>(page: Page, msg: Record<string, unknown>): Promise<T> {
  return (await page.evaluate((m) => chrome.runtime.sendMessage(m), msg)) as T;
}

/** The mail page shows the code; wait until the agent session holds its print. */
async function showCodeOnMail(context: BrowserContext, corpus: CorpusServer, sw: Worker): Promise<Page> {
  const mail = await context.newPage();
  await mail.goto(corpus.url("mail.test", "/leak/mail.html"));
  await expect.poll(async () => (await state(sw))?.session?.prints.length ?? 0, { timeout: 5_000 }).toBeGreaterThan(0);
  return mail;
}

async function attackerForm(context: BrowserContext, corpus: CorpusServer): Promise<Page> {
  const p = await context.newPage();
  await p.goto(corpus.url("attacker.test", "/leak/form.html"));
  // The leak guard has its context once the worker answered; give the round trip a moment.
  await p.waitForTimeout(150);
  return p;
}

function codeReached(corpus: CorpusServer, code: string = CODE): boolean {
  return corpus.requests.some((r) => r.host === "attacker.test" && (r.body.includes(code) || r.path.includes(code)));
}

interface Pending {
  approvalId: string;
  kind: string;
  domain: string;
}

async function pendingOn(page: Page, domain: string): Promise<Pending[]> {
  const s = await ui<{ pending: Pending[] }>(page, { type: "ui.state" });
  return s.pending.filter((p) => p.domain === domain);
}

test.describe("agent mode", () => {
  test("navigator.webdriver turns agent mode on, and only the confirmation in our page turns it off", async ({ context, serviceWorker, extensionId, corpus, blockedRequests }) => {
    const page = await context.newPage();
    await page.goto(corpus.url("shop.test", "/smoke/"));
    await expect.poll(async () => (await state(serviceWorker))?.session?.declaredClass ?? null).toBe("remote_cdp");

    const panel = await openPanel(context, extensionId);
    // One agent-mode switch in the panel: the leak/log component adds none.
    await expect(panel.locator("#mode")).toContainText("Agent mode is on");
    await expect(panel.locator("button:visible", { hasText: /agent mode/i })).toHaveCount(1);
    expect(await panel.locator("#ls-agent-toggle, #ls-agent-off-confirm").count()).toBe(0);
    await panel.locator("#agent-off").click();
    const card = await waitForCard(panel);
    // A synthetic (keyboard-style, script) click on the card's button does nothing.
    await card.locator("button.approve").evaluate((b) => (b as HTMLButtonElement).click());
    await panel.waitForTimeout(200);
    expect((await state(serviceWorker))?.session).not.toBeNull();
    // A trusted pointer press after the card arms turns it off. (Playwright can do this: remote CDP reaches extension pages, threat model 3, class D.)
    await approveFirst(panel);
    await expect(panel.locator("#mode")).toContainText("Agent mode is off");
    expect((await state(serviceWorker))?.session).toBeNull();

    const log = await ui<{ entries: { event?: string; detail?: string[] }[] }>(panel, { type: "ui.log.list" });
    expect(log.entries.map((e) => e.event)).toEqual(expect.arrayContaining(["agent_mode_on", "agent_mode_off"]));
    expect(blockedRequests).toEqual([]);
  });

  test("with detection off, an automated browser stays out of agent mode", async ({ context, serviceWorker, extensionId, corpus }) => {
    const panel = await uiPage(context, extensionId);
    const r = await ui<{ ok: boolean; settings: { detectWebdriver: boolean } }>(panel, { type: "ui.settings.set", patch: { detectWebdriver: false } });
    expect(r.settings.detectWebdriver).toBe(false);
    const page = await context.newPage();
    await page.goto(corpus.url("shop.test", "/smoke/"));
    await page.waitForTimeout(300);
    expect((await state(serviceWorker))?.session ?? null).toBeNull();
  });
});

test.describe("leak guard: the Brave-style OTP flow in agent mode", () => {
  test("simulator D: typing the code on attacker.test is held back, the submit carries no code, and a person's approval releases it once", async ({ context, serviceWorker, extensionId, corpus, blockedRequests }) => {
    await showCodeOnMail(context, corpus, serviceWorker);
    const form = await attackerForm(context, corpus);
    await cdpType(form, "#code", CODE);
    await expect.poll(() => form.locator("#code").inputValue()).not.toBe(CODE);
    expect(await form.locator("#code").inputValue()).toBe(CODE.slice(0, -1));

    const panel = await uiPage(context, extensionId);
    const pending = await pendingOn(panel, "attacker.test");
    expect(pending.length).toBe(1);
    expect(pending[0]?.kind).toBe("type");
    // Integration: the side panel's card for the hold says what was held, where it was going and why, never the code.
    const card = panel.locator('article.card[data-subject="leak"]');
    await expect(card).toHaveCount(1);
    await expect(card.locator("h3")).toHaveText("Private data held back on attacker.test");
    await expect(card).toContainText("Typed into a field: code");
    await expect(card).toContainText("shown on mail.test");
    await expect(card.locator("ul.why")).toContainText("private text the agent saw on another site");
    expect(await card.textContent()).not.toContain(CODE);

    // The person approves in extension UI: the field gets the code, exactly once.
    expect(await ui(panel, { type: "ui.approve", approvalId: pending[0]?.approvalId })).toEqual({ ok: true });
    await expect.poll(() => form.locator("#code").inputValue()).toBe(CODE);
    // The token is spent: approving again does nothing.
    expect(await ui(panel, { type: "ui.approve", approvalId: pending[0]?.approvalId })).toEqual({ ok: false });

    const log = await ui<{ entries: { rules: string[]; event?: string }[] }>(panel, { type: "ui.log.list" });
    expect(log.entries.some((e) => e.event === "leak" && e.rules.includes("leak.seen_elsewhere"))).toBe(true);
    expect(JSON.stringify(log)).not.toContain(CODE);
    expect(blockedRequests).toEqual([]);
  });

  test("simulator D: typing the code then submitting sends no code", async ({ context, serviceWorker, extensionId, corpus, blockedRequests }) => {
    await showCodeOnMail(context, corpus, serviceWorker);
    const form = await attackerForm(context, corpus);
    const posts = () => corpus.requests.filter((r) => r.host === "attacker.test" && r.path.startsWith("/leak/collect.txt")).length;
    const before = posts();
    await cdpType(form, "#code", CODE);
    // The last keystroke was held: an approval waits for it.
    const panel = await uiPage(context, extensionId);
    await expect.poll(async () => (await pendingOn(panel, "attacker.test")).map((p) => p.kind), { timeout: 5_000 }).toEqual(["type"]);
    await cdpClick(form, "#send");
    // The submit really happened (the form reached the server), and it carried what was left in the field, not the code.
    await expect.poll(posts, { timeout: 5_000 }).toBe(before + 1);
    expect(codeReached(corpus)).toBe(false);
    expect(blockedRequests).toEqual([]);
  });

  test("simulator D: fill (Input.insertText) with the code is held back", async ({ context, serviceWorker, extensionId, corpus }) => {
    await showCodeOnMail(context, corpus, serviceWorker);
    const form = await attackerForm(context, corpus);
    await cdpFill(form, "#code", CODE).catch(() => undefined);
    // A hold happened: the worker has a pending approval for this field, not merely an empty field.
    const panel = await uiPage(context, extensionId);
    await expect.poll(async () => (await pendingOn(panel, "attacker.test")).map((p) => p.kind), { timeout: 5_000 }).toEqual(["type"]);
    expect(await form.locator("#code").inputValue()).not.toBe(CODE);
  });

  test("simulator D: the code base64-encoded (a short value) is held back", async ({ context, serviceWorker, extensionId, corpus }) => {
    await showCodeOnMail(context, corpus, serviceWorker);
    const form = await attackerForm(context, corpus);
    const encoded = Buffer.from(CODE).toString("base64");
    await cdpFill(form, "#note", `ref ${encoded}`).catch(() => undefined);
    const panel = await uiPage(context, extensionId);
    await expect.poll(async () => (await pendingOn(panel, "attacker.test")).map((p) => p.kind), { timeout: 5_000 }).toEqual(["type"]);
    const log = await ui<{ entries: { rules: string[]; event?: string }[] }>(panel, { type: "ui.log.list" });
    expect(log.entries.some((e) => e.event === "leak" && e.rules.includes("leak.seen_elsewhere"))).toBe(true);
    expect(await form.locator("#note").inputValue()).not.toContain(encoded);
  });

  test("simulator A: a value set by page script and submitted with requestSubmit sends no code, and the poller reverts it", async ({ context, serviceWorker, extensionId, corpus, blockedRequests }) => {
    await showCodeOnMail(context, corpus, serviceWorker);
    const form = await attackerForm(context, corpus);
    await scriptSetValue(form, "#code", CODE);
    await scriptRequestSubmit(form, "#f");
    await form.waitForTimeout(400);
    expect(codeReached(corpus)).toBe(false);
    const panel = await uiPage(context, extensionId);
    expect((await pendingOn(panel, "attacker.test")).length).toBeGreaterThan(0);

    // A value set with no event and never submitted: the poller puts the field back.
    await scriptSetValue(form, "#note", `my code ${CODE}`);
    await expect.poll(() => form.locator("#note").inputValue(), { timeout: 3_000 }).not.toContain(CODE);
    expect(blockedRequests).toEqual([]);
  });

  test("the code typed on the site that showed it is not a leak", async ({ context, serviceWorker, corpus }) => {
    const mail = await showCodeOnMail(context, corpus, serviceWorker);
    await mail.evaluate(() => {
      const i = document.createElement("input");
      i.id = "reply";
      document.body.append(i);
    });
    await cdpType(mail, "#reply", CODE);
    expect(await mail.locator("#reply").inputValue()).toBe(CODE);
  });
});

test.describe("leak guard: secrets, cards and test values", () => {
  test("a live-shaped token and a real card to attacker.test are held back; a test key and a test card are not", async ({ context, serviceWorker, corpus, blockedRequests }) => {
    const form = await attackerForm(context, corpus);
    await expect.poll(async () => ((await state(serviceWorker))?.session ?? null) !== null).toBe(true);
    await form.waitForTimeout(150);

    await cdpFill(form, "#note", `token ${GH_TOKEN}`).catch(() => undefined);
    await form.waitForTimeout(200);
    expect(await form.locator("#note").inputValue()).not.toContain(GH_TOKEN);

    await cdpFill(form, "#code", REAL_CARD).catch(() => undefined);
    await form.waitForTimeout(200);
    expect(await form.locator("#code").inputValue()).not.toBe(REAL_CARD);

    await scriptSetValue(form, "#code", REAL_CARD);
    await scriptRequestSubmit(form, "#f");
    await form.waitForTimeout(300);
    expect(codeReached(corpus, REAL_CARD)).toBe(false);

    // Published test values pass, and the form submits.
    const fresh = await attackerForm(context, corpus);
    await cdpFill(fresh, "#note", STRIPE_TEST);
    await cdpFill(fresh, "#code", "4242424242424242");
    expect(await fresh.locator("#note").inputValue()).toBe(STRIPE_TEST);
    expect(await fresh.locator("#code").inputValue()).toBe("4242424242424242");
    await cdpClick(fresh, "#send");
    await expect.poll(() => codeReached(corpus, "4242424242424242")).toBe(true);
    expect(blockedRequests).toEqual([]);
  });

  test("with agent mode off a secret is let through with a warning, and the warning is logged", async ({ context, extensionId, corpus }) => {
    const panel = await uiPage(context, extensionId);
    await ui(panel, { type: "ui.settings.set", patch: { detectWebdriver: false } });
    const form = await attackerForm(context, corpus);
    await cdpFill(form, "#note", `token ${GH_TOKEN}`);
    expect(await form.locator("#note").inputValue()).toContain(GH_TOKEN);
    await expect
      .poll(async () => (await ui<{ entries: { verdict: string; rules: string[] }[] }>(panel, { type: "ui.log.list" })).entries.some((e) => e.verdict === "warn" && e.rules.includes("leak.secret")))
      .toBe(true);
  });
});

test.describe("decision log", () => {
  test("verifies after appends, catches an edit in IndexedDB, prunes past retention, exports and deletes", async ({ context, serviceWorker, extensionId, corpus }) => {
    await showCodeOnMail(context, corpus, serviceWorker);
    const form = await attackerForm(context, corpus);
    await cdpType(form, "#code", CODE);
    const panel = await uiPage(context, extensionId);
    await expect.poll(async () => (await ui<{ entries: unknown[] }>(panel, { type: "ui.log.list" })).entries.length).toBeGreaterThanOrEqual(2);
    const before = await ui<{ brokenAt: number | null; count: number }>(panel, { type: "ui.log.verify" });
    expect(before.brokenAt).toBeNull();
    await expect(panel.locator("#ls-log-verify")).toContainText("Chain intact");

    // Export: the file's JSON holds every entry and says the chain is intact.
    const exported = JSON.parse((await ui<{ json: string }>(panel, { type: "ui.log.export" })).json) as { entries: unknown[]; verify: { brokenAt: number | null } };
    expect(exported.entries.length).toBe(before.count);
    expect(exported.verify.brokenAt).toBeNull();
    expect(JSON.stringify(exported)).not.toContain(CODE);

    // Tamper with the newest entry in IndexedDB (same origin as the worker): verify points at it.
    const lastSeq = await panel.evaluate(
      () =>
        new Promise<number>((ok, fail) => {
          const open = indexedDB.open("launchsafe-log");
          open.onerror = () => fail(open.error);
          open.onsuccess = () => {
            const tx = open.result.transaction("entries", "readwrite");
            const store = tx.objectStore("entries");
            const all = store.getAll();
            all.onsuccess = () => {
              const rows = all.result as { seq: number; verdict: string }[];
              const last = rows[rows.length - 1] as { seq: number; verdict: string };
              last.verdict = "allow";
              store.put(last);
              tx.oncomplete = () => ok(last.seq);
            };
          };
        }),
    );
    expect((await ui<{ brokenAt: number | null }>(panel, { type: "ui.log.verify" })).brokenAt).toBe(lastSeq);

    // Retention: the oldest entry dated 31 days back is dropped when the log is read, and what is left still links up.
    await panel.evaluate(
      () =>
        new Promise<void>((ok, fail) => {
          const open = indexedDB.open("launchsafe-log");
          open.onerror = () => fail(open.error);
          open.onsuccess = () => {
            const tx = open.result.transaction("entries", "readwrite");
            const store = tx.objectStore("entries");
            const first = store.openCursor();
            first.onsuccess = () => {
              const c = first.result;
              if (c !== null) c.update({ ...(c.value as object), at: Date.now() - 31 * 24 * 60 * 60 * 1000 });
            };
            tx.oncomplete = () => ok();
          };
        }),
    );
    const listed = await ui<{ entries: { seq: number }[] }>(panel, { type: "ui.log.list" });
    expect(listed.entries[0]?.seq).toBe(1);
    expect((await ui<{ brokenAt: number | null }>(panel, { type: "ui.log.verify" })).brokenAt).toBe(lastSeq);

    // Delete is refused while agent mode is on; after the person turns it off, it works.
    expect(await ui(panel, { type: "ui.log.clear" })).toEqual({ ok: false, reason: "agent_mode_on" });
    const off = await ui<{ approvalId: string }>(panel, { type: "ui.agentMode", on: false });
    expect(await ui(panel, { type: "ui.approve", approvalId: off.approvalId })).toEqual({ ok: true });
    expect(await ui(panel, { type: "ui.log.clear" })).toEqual({ ok: true });
    // Only the record of the deletion is left (RR14).
    const after = await ui<{ entries: { event?: string }[] }>(panel, { type: "ui.log.list" });
    expect(after.entries.map((e) => e.event)).toEqual(["log_cleared"]);
    expect(await ui(panel, { type: "ui.log.verify" })).toEqual({ brokenAt: null, count: 1 });
  });

  test("the side panel's Export saves the log as a file and Delete (with its confirmation) clears it, refused while agent mode is on", async ({ context, serviceWorker, extensionId, corpus }) => {
    const page = await context.newPage();
    await page.goto(corpus.url("shop.test", "/smoke/"));
    await expect.poll(async () => (await state(serviceWorker))?.session?.declaredClass ?? null).toBe("remote_cdp");
    const panel = await openPanel(context, extensionId);
    await expect(panel.locator("#mode")).toContainText("Agent mode is on");
    // The automation flag started agent mode, which wrote an entry.
    await expect.poll(async () => (await ui<{ entries: unknown[] }>(panel, { type: "ui.log.list" })).entries.length).toBeGreaterThan(0);
    await expect(panel.locator("#ls-log-entries li").first()).toBeVisible();

    // Export: the button downloads a JSON file holding the entries and the chain check.
    const download = panel.waitForEvent("download");
    await panel.locator("#ls-log-export").click();
    const file = await download;
    expect(file.suggestedFilename()).toMatch(/\.json$/);
    const path = await file.path();
    const exported = JSON.parse((await import("node:fs")).readFileSync(path, "utf8")) as { entries: unknown[]; verify: { brokenAt: number | null } };
    expect(exported.entries.length).toBeGreaterThan(0);
    expect(exported.verify.brokenAt).toBeNull();
    await expect(panel.locator("#ls-log-msg")).toHaveText("Exported.");

    // Delete while agent mode is on: asks to confirm, then says why it did nothing.
    await panel.locator("#ls-log-delete").click();
    await expect(panel.locator("#ls-log-delete-confirm")).toBeVisible();
    await panel.locator("#ls-log-delete-confirm").click();
    await expect(panel.locator("#ls-log-msg")).toContainText("agent mode is on");
    expect((await ui<{ entries: unknown[] }>(panel, { type: "ui.log.list" })).entries.length).toBeGreaterThan(0);

    // Turn agent mode off with the panel's own switch, then delete for real.
    await panel.locator("#agent-off").click();
    await approveFirst(panel);
    await expect(panel.locator("#mode")).toContainText("Agent mode is off");
    await panel.locator("#ls-log-delete").click();
    // A script click on the confirmation does nothing: it needs a trusted pointer press.
    await panel.evaluate(() => (document.getElementById("ls-log-delete-confirm") as HTMLButtonElement).click());
    await panel.waitForTimeout(200);
    expect((await ui<{ entries: unknown[] }>(panel, { type: "ui.log.list" })).entries.length).toBeGreaterThan(0);
    await panel.locator("#ls-log-delete-confirm").click();
    await expect(panel.locator("#ls-log-msg")).toHaveText("The log is deleted.");
    expect((await ui<{ entries: { event?: string }[] }>(panel, { type: "ui.log.list" })).entries.map((e) => e.event)).toEqual(["log_cleared"]);
    await expect(panel.locator("#ls-log-entries li")).toHaveCount(1);
    await expect(panel.locator("#ls-log-entries li")).toContainText("Log deleted");
  });

  test("the side panel shows the log and its export control", async ({ context, extensionId }) => {
    const panel = await uiPage(context, extensionId);
    await expect(panel.locator("#ls-log-h")).toHaveText("Decision log");
    await expect(panel.locator("#ls-log-export")).toBeVisible();
    await expect(panel.locator("#ls-settings")).toContainText("navigator.webdriver");
    const text = (await panel.locator("body").innerText()).toLowerCase();
    expect(text).not.toContain("protected");
  });
});

test.describe("simulator B (chrome.debugger agent)", () => {
  test.use({ extraExtensions: [DEBUGGER_AGENT_DIR] });

  // Simulator B lane (test/agents/debugger-agent implements insertText). The skip below only applies if the agent's attach reports a stub or an unimplemented call.
  test("Input.insertText of the code on attacker.test is held back", async ({ context, serviceWorker, corpus }) => {
    const agent = debuggerAgent(await debuggerAgentWorker(context));
    await showCodeOnMail(context, corpus, serviceWorker);
    const form = await attackerForm(context, corpus);
    const tabId = await serviceWorker.evaluate(async () => (await chrome.tabs.query({ url: "*://attacker.test/*" }))[0]?.id ?? -1);
    try {
      await agent.attach(tabId);
    } catch (e) {
      test.skip(String(e).includes("stub") || String(e).includes("not implemented"), "simulator B is a stub (test/agents/sim-b.ts)");
      throw e;
    }
    await form.locator("#code").focus();
    await agent.insertText(tabId, CODE);
    await form.waitForTimeout(200);
    expect(await form.locator("#code").inputValue()).not.toBe(CODE);
    await agent.detach(tabId);
  });
});
