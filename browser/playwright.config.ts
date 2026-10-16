import { defineConfig } from "@playwright/test";

/**
 * Extension end-to-end tests. Every test gets a fresh persistent profile in
 * the OS temp directory (test/e2e/fixtures.ts); nothing touches a real
 * browser profile, and no request leaves 127.0.0.1. Run with `npm run test:e2e`
 * after `npm run build`.
 */
export default defineConfig({
  testDir: "test/e2e",
  timeout: 30_000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: { trace: "off", screenshot: "off", video: "off" },
});
