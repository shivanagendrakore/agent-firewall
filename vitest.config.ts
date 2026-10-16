import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defineConfig } from "vitest/config";

/**
 * F-a: the suite never runs against the developer's real home. A temporary
 * home is created here (the config is evaluated once in the main process,
 * before the global setup and the workers) and every variable that points at
 * a home or config directory is moved into it. test/global-setup.ts checks the
 * result and removes the directory afterwards; test/setup-assert.ts fails any
 * test file whose home still resolves to the real one.
 */
function testHome(): Record<string, string> {
  const existing = process.env.LAUNCHSAFE_FIREWALL_TEST_ROOT;
  const root = existing !== undefined && existing !== "" && process.env.LAUNCHSAFE_FIREWALL_TEST === "1" ? existing : mkdtempSync(join(tmpdir(), "lsfw-test-"));
  const home = join(root, "home");
  const env = {
    HOME: home,
    USERPROFILE: home,
    XDG_CONFIG_HOME: join(home, ".config"),
    XDG_DATA_HOME: join(home, ".local", "share"),
    XDG_STATE_HOME: join(home, ".local", "state"),
    XDG_CACHE_HOME: join(home, ".cache"),
    CLAUDE_CONFIG_DIR: join(home, ".claude"),
    // Item 8: Codex and Gemini CLI locate their homes from these; empty means "use HOME" (never the real ones).
    CODEX_HOME: "",
    GEMINI_CLI_HOME: "",
    GEMINI_CLI_SYSTEM_SETTINGS_PATH: "",
    LAUNCHSAFE_FIREWALL_HOME: join(home, ".launchsafe-firewall"),
    LAUNCHSAFE_FIREWALL_TEST: "1",
    LAUNCHSAFE_FIREWALL_TEST_ROOT: root,
  };
  mkdirSync(home, { recursive: true });
  Object.assign(process.env, env);
  return env;
}

const env = testHome();

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts", "test/**/*.test.ts"],
    // browser/ and python/ are separate packages with their own test runners (browser/vitest.config.ts, pytest).
    exclude: ["test/fixtures/**", "node_modules/**", "dist/**", "browser/**", "python/**"],
    globalSetup: ["test/global-setup.ts"],
    setupFiles: ["test/setup-assert.ts"],
    env,
    testTimeout: 30000,
  },
});
