/**
 * Playwright fixtures for the extension.
 *
 * - `corpus`: the static corpus server on 127.0.0.1 (one per worker).
 * - `context`: Playwright's bundled Chromium in a persistent context with a
 *   fresh profile under the OS temp directory, our extension (dist/) loaded
 *   with --load-extension and every other extension disabled, headless.
 *   Host names resolve only through --host-resolver-rules (the .test hosts
 *   map to 127.0.0.1, everything else fails), and every request whose host is
 *   not loopback or a test host is routed to a failing handler and recorded
 *   in `blockedRequests` (tests assert it stays empty).
 * - `extensionId` and `serviceWorker`: read from the extension's worker.
 * - `detectWebdriver` (option, default false): the leak lane's setting that
 *   turns agent mode on when navigator.webdriver is set. Playwright always
 *   sets it, so specs written for "agent mode off until the test turns it on"
 *   run with it off (written to the settings before any test page loads);
 *   the leak spec opts in with test.use({ detectWebdriver: true }), which is
 *   the product default.
 *
 * The side panel is reached as a Page through Playwright's
 * PW_CHROMIUM_ATTACH_TO_OTHER, set below (see side-panel.ts).
 *
 * Profiles live in one temp folder per run (lsfw-e2e-*) and are left to the
 * OS temp cleanup; nothing is written outside the temp directory.
 */
import { test as base, chromium, type BrowserContext, type Worker } from "@playwright/test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { startCorpusServer, TEST_HOSTS, type CorpusServer } from "./corpus-server.js";
import { ATTACH_TO_OTHER } from "./side-panel.js";

// The real side panel is a DevTools target of type "other"; this makes Playwright (which runs in this worker
// process) attach to it as a page instead of detaching (side-panel.ts). Set before any browser starts.
process.env[ATTACH_TO_OTHER] = "1";

export const DIST_DIR = resolve(fileURLToPath(new URL("../../dist/", import.meta.url)));

let runDir: string | null = null;
function profileDir(): string {
  runDir ??= mkdtempSync(join(tmpdir(), "lsfw-e2e-"));
  const dir = mkdtempSync(join(runDir, "profile-"));
  // Pin the profile's download folder inside the temp profile, so a download that takes Chrome's own path
  // (not Playwright's) can never land in the real ~/Downloads.
  const downloads = join(dir, "downloads");
  mkdirSync(join(dir, "Default"), { recursive: true });
  mkdirSync(downloads);
  writeFileSync(join(dir, "Default", "Preferences"), JSON.stringify({ download: { default_directory: downloads, directory_upgrade: true, prompt_for_download: false }, savefile: { default_directory: downloads } }));
  return dir;
}

/** Resolver rules: the test hosts (and their subdomains) to 127.0.0.1, every other name fails. */
export function hostResolverRules(): string {
  const maps = TEST_HOSTS.flatMap((h) => [`MAP ${h} 127.0.0.1`, `MAP *.${h} 127.0.0.1`]);
  return [...maps, "MAP * ~NOTFOUND", "EXCLUDE 127.0.0.1"].join(", ");
}

export function isAllowedHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return h === "127.0.0.1" || h === "localhost" || TEST_HOSTS.some((t) => h === t || h.endsWith(`.${t}`));
}

export interface ExtensionOptions {
  /** More unpacked extensions to load next to ours (the B simulator, test/agents/debugger-agent). */
  extraExtensions: string[];
  /** The "turn agent mode on under automation" setting for this test (the product default is on). */
  detectWebdriver: boolean;
}

export interface ExtensionFixtures {
  corpus: CorpusServer;
  context: BrowserContext;
  serviceWorker: Worker;
  extensionId: string;
  blockedRequests: string[];
}

export const test = base.extend<ExtensionOptions & Omit<ExtensionFixtures, "corpus">, { corpus: CorpusServer }>({
  extraExtensions: [[], { option: true }],
  detectWebdriver: [false, { option: true }],
  corpus: [
    async ({}, use) => {
      const server = await startCorpusServer();
      await use(server);
      await server.close();
    },
    { scope: "worker" },
  ],
  blockedRequests: async ({}, use) => {
    await use([]);
  },
  context: async ({ extraExtensions, blockedRequests, detectWebdriver }, use) => {
    const extensions = [DIST_DIR, ...extraExtensions].join(",");
    const context = await chromium.launchPersistentContext(profileDir(), {
      channel: "chromium",
      headless: true,
      args: [
        `--disable-extensions-except=${extensions}`,
        `--load-extension=${extensions}`,
        `--host-resolver-rules=${hostResolverRules()}`,
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--disable-default-apps",
        "--disable-domain-reliability",
        "--metrics-recording-only",
        "--no-pings",
      ],
    });
    await context.route("**/*", (route) => {
      const url = new URL(route.request().url());
      if (url.protocol === "chrome-extension:" || url.protocol === "data:" || url.protocol === "blob:" || isAllowedHost(url.hostname)) return route.fallback();
      blockedRequests.push(url.href);
      return route.abort("blockedbyclient");
    });
    if (!detectWebdriver) {
      // Before any test page loads: the setting the worker reads on every agent.signal.
      const sw = context.serviceWorkers().find((w) => w.url().endsWith("/worker.js")) ?? (await context.waitForEvent("serviceworker", { predicate: (w) => w.url().endsWith("/worker.js") }));
      await sw.evaluate(async () => {
        const key = "ls.settings";
        const cur = ((await chrome.storage.local.get(key))[key] ?? {}) as Record<string, unknown>;
        await chrome.storage.local.set({ [key]: { ...cur, detectWebdriver: false } });
      });
      // The profile's first blank page must not have started a session before the setting landed.
      const session = await sw.evaluate(async () => ((await chrome.storage.session.get("ls.state"))["ls.state"] as { session: unknown } | undefined)?.session ?? null);
      if (session !== null) throw new Error("agent mode was already on before the test started");
    }
    await use(context);
    await context.close();
  },
  serviceWorker: async ({ context }, use) => {
    const sw = context.serviceWorkers().find((w) => w.url().endsWith("/worker.js")) ?? (await context.waitForEvent("serviceworker", { predicate: (w) => w.url().endsWith("/worker.js") }));
    await use(sw);
  },
  extensionId: async ({ serviceWorker }, use) => {
    await use(new URL(serviceWorker.url()).host);
  },
});

export const expect = test.expect;
