/**
 * The native link to the local firewall (design 10), end to end in bundled Chromium. The host is a
 * stand-in (link-host.ts) registered only in this test's temporary profile: Chromium reads host manifests
 * from <user data dir>/NativeMessagingHosts, so nothing is written to the person's browser or home.
 *
 * This build grants nativeMessaging at install (LAUNCHSAFE_E2E_NATIVE, into a temp folder): Playwright
 * cannot answer the browser's permission prompt. The product build asks for it only from the side panel's
 * switch (manifest.test.ts, build.test.ts, smoke.spec.ts).
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";
import { expect, hostResolverRules, isAllowedHost, test as base } from "./fixtures.js";
import { registerInProfile, writeTestHost } from "./link-host.js";
import { openPanel } from "./gate-helpers.js";
import { agentModeOnWithTab, fromPanel } from "./side-panel.js";

const ROOT = resolve(fileURLToPath(new URL("../../", import.meta.url)));
const runDir = mkdtempSync(join(tmpdir(), "lsfw-link-e2e-"));
let dist: string | null = null;

/** The extension built with nativeMessaging granted at install, into the temp folder (never dist/). */
function e2eDist(): string {
  if (dist !== null) return dist;
  const out = join(runDir, "dist");
  const r = spawnSync(process.execPath, [join(ROOT, "scripts", "build.mjs")], { env: { ...process.env, LAUNCHSAFE_DIST: out, LAUNCHSAFE_E2E_NATIVE: "1" }, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`e2e build failed: ${r.stderr}${r.stdout}`);
  const m = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8")) as { permissions: string[] };
  if (!m.permissions.includes("nativeMessaging")) throw new Error("the e2e build does not grant nativeMessaging");
  dist = out;
  return out;
}

interface LinkFixtures {
  profile: string;
}

const test = base.extend<LinkFixtures>({
  profile: async ({}, use) => {
    const dir = mkdtempSync(join(runDir, "profile-"));
    if (!resolve(dir).startsWith(resolve(tmpdir()))) throw new Error("the test profile must be in the temp directory");
    mkdirSync(join(dir, "Default"), { recursive: true });
    await use(dir);
  },
  context: async ({ profile, blockedRequests }, use) => {
    const ext = e2eDist();
    const context = await chromium.launchPersistentContext(profile, {
      channel: "chromium",
      headless: true,
      args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, `--host-resolver-rules=${hostResolverRules()}`, "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-default-apps", "--metrics-recording-only", "--no-pings"],
    });
    await context.route("**/*", (route) => {
      const url = new URL(route.request().url());
      if (url.protocol === "chrome-extension:" || url.protocol === "data:" || url.protocol === "blob:" || isAllowedHost(url.hostname)) return route.fallback();
      blockedRequests.push(url.href);
      return route.abort("blockedbyclient");
    });
    const sw = context.serviceWorkers().find((w) => w.url().endsWith("/worker.js")) ?? (await context.waitForEvent("serviceworker", { predicate: (w) => w.url().endsWith("/worker.js") }));
    // As in fixtures.ts: agent mode only when the test turns it on.
    await sw.evaluate(async () => {
      const key = "ls.settings";
      const cur = ((await chrome.storage.local.get(key))[key] ?? {}) as Record<string, unknown>;
      await chrome.storage.local.set({ [key]: { ...cur, detectWebdriver: false } });
    });
    await use(context);
    await context.close();
  },
});

interface StoredState {
  session: { untrusted: boolean; linkedAgents?: string[] } | null;
  pendingLinkedAgents?: string[];
}

test("with no firewall installed, turning the link on says so and the extension keeps working", async ({ context, extensionId, corpus, blockedRequests }) => {
  const panel = await openPanel(context, extensionId);
  await expect(panel.locator("#link-status")).toHaveText("Link to the local firewall: off.");
  await panel.locator("#link-toggle").click();
  await expect(panel.locator("#link-status")).toContainText("not connected");
  await expect(panel.locator("#link-status")).toContainText("not installed for this browser");
  // Decisions go on as before.
  const page = await agentModeOnWithTab(context, extensionId);
  await page.goto(corpus.url("shop.test", "/smoke/"));
  await expect(page.locator("h1")).toHaveText("Shop");
  expect(blockedRequests).toEqual([]);
});

test("connected: decisions are mirrored, taint goes both ways, and a firewall approval completes a pending approval", async ({ context, serviceWorker, extensionId, profile, corpus, blockedRequests }) => {
  const host = writeTestHost(join(runDir, `host-${Date.now()}`), { capabilities: ["log", "taint", "approval"], agentTaint: true, approve: true });
  registerInProfile(profile, extensionId, host.launcher);

  const panel = await openPanel(context, extensionId);
  await panel.locator("#link-toggle").click();
  await expect(panel.locator("#link-status")).toContainText("Link to the local firewall: connected.");
  await expect(panel.locator("#link-toggle")).toHaveText("Turn the link off");

  // Chrome started the host for our origin, and the first message was the hello.
  await expect.poll(() => host.messages().map((m) => m.type)).toContain("hello");
  const msgs = host.messages();
  expect(msgs[0]).toEqual({ type: "_started", origin: `chrome-extension://${extensionId}/` });
  expect(msgs[1]).toMatchObject({ type: "hello", version: 1, capabilities: expect.arrayContaining(["gate", "log"]) });

  // The linked agent's taint, reported by the "firewall" with agent mode off, is held for the next agent session.
  await expect
    .poll(async () => ((await serviceWorker.evaluate(() => chrome.storage.session.get("ls.state")))["ls.state"] as StoredState | undefined)?.pendingLinkedAgents ?? [])
    .toEqual(["agent-0123456789abcdef"]);

  // Agent mode on: the session starts untrusted (the linked agent), its decisions are mirrored.
  const agentPage = await agentModeOnWithTab(context, extensionId);
  const s1 = (await serviceWorker.evaluate(() => chrome.storage.session.get("ls.state")))["ls.state"] as StoredState;
  expect(s1.session).toMatchObject({ untrusted: true, linkedAgents: ["agent-0123456789abcdef"] });
  await expect.poll(() => host.messages().filter((m) => m.type === "log.append").map((m) => (m.entry as { event?: string }).event)).toContain("agent_mode_on");
  // Nothing sent carries page text or evidence.
  for (const m of host.messages().filter((x) => x.type === "log.append")) expect(Object.keys(m.entry as object)).not.toContain("evidence");

  // The browser's own taint: an agent-session tab shows an outside page, and the firewall hears of it once.
  await agentPage.goto(corpus.url("shop.test", "/smoke/"));
  await expect.poll(() => host.messages().filter((m) => m.type === "state.taint")).toHaveLength(1);
  expect(host.messages().find((m) => m.type === "state.taint")).toMatchObject({ reason: "outside_origin", session: expect.stringMatching(/^\d+$/) });

  // A pending approval (turning agent mode off) is filed with the firewall; its approval ends the session.
  const off = await fromPanel<{ ok: boolean; approvalId?: string }>(panel, { type: "ui.agentMode", on: false });
  expect(off.ok).toBe(true);
  await expect.poll(() => host.messages().filter((m) => m.type === "approval.request")).toHaveLength(1);
  expect(host.messages().find((m) => m.type === "approval.request")).toMatchObject({ surface: "firewall", action: { kind: "agent_mode_off" } });
  await expect.poll(async () => ((await serviceWorker.evaluate(() => chrome.storage.session.get("ls.state")))["ls.state"] as StoredState).session).toBeNull();
  expect(blockedRequests).toEqual([]);
});

test("the host is only the one registered for this extension: another id's manifest does not connect", async ({ context, extensionId, profile }) => {
  const host = writeTestHost(join(runDir, `host-other-${Date.now()}`), { capabilities: ["log"], agentTaint: false, approve: false });
  const other = extensionId === "a".repeat(32) ? "b".repeat(32) : "a".repeat(32);
  registerInProfile(profile, other, host.launcher);
  const panel = await openPanel(context, extensionId);
  await panel.locator("#link-toggle").click();
  await expect(panel.locator("#link-status")).toContainText("not connected");
  expect(host.messages()).toEqual([]);
});

/**
 * Against the real firewall, when a built checkout is named (LAUNCHSAFE_FIREWALL_CLI=<firewall>/dist/cli.js;
 * skipped otherwise). The firewall's own `install --browser chromium --user-data-dir` registers its host in
 * this test's temporary profile, with its data directory in the temp folder too.
 */
test("with the real firewall: decisions land in its signed log and log verify passes", async ({ context, extensionId, profile, corpus }) => {
  const cli = process.env.LAUNCHSAFE_FIREWALL_CLI ?? "";
  test.skip(cli === "", "set LAUNCHSAFE_FIREWALL_CLI to a built firewall's dist/cli.js");
  const home = mkdtempSync(join(runDir, "fw-home-"));
  const env = { ...process.env, HOME: home, LAUNCHSAFE_FIREWALL_HOME: join(home, ".launchsafe-firewall"), LAUNCHSAFE_FIREWALL_TEST: "1" };
  const fw = (...args: string[]): ReturnType<typeof spawnSync> => spawnSync(process.execPath, [cli, ...args], { env, encoding: "utf8", cwd: home });
  const installed = fw("install", "--browser", "chromium", "--user-data-dir", profile, "--extension-id", extensionId);
  expect(installed.status, String(installed.stderr)).toBe(0);

  const panel = await openPanel(context, extensionId);
  await panel.locator("#link-toggle").click();
  await expect(panel.locator("#link-status")).toContainText("Link to the local firewall: connected.");
  const agentPage = await agentModeOnWithTab(context, extensionId);
  await agentPage.goto(corpus.url("shop.test", "/smoke/"));
  await expect.poll(() => String(fw("log", "tail", "50").stdout)).toContain('"type":"browser_decision"');
  await expect.poll(() => String(fw("log", "tail", "50").stdout)).toContain('"type":"browser_taint"');
  const verify = fw("log", "verify");
  expect(verify.status, String(verify.stdout) + String(verify.stderr)).toBe(0);
  // The link stayed up through it all (no message the host refused).
  expect(await fromPanel(panel, { type: "ui.link.state" })).toMatchObject({ state: "connected", capabilities: ["log", "taint"] });
});
