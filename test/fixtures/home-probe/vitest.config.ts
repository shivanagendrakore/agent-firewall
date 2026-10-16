// A21 probe: the suite's setup assertion without the home forcing of the main config. Run only by
// test/guard.test.ts, with HOME set to the real home, to prove such a file fails before any test runs.
import { join } from "node:path";
import { defineConfig } from "vitest/config";

const here = import.meta.dirname;
export default defineConfig({
  test: {
    root: here,
    include: ["probe.test.ts"],
    setupFiles: [join(here, "..", "..", "setup-assert.ts")],
  },
});
