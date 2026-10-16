import { defineConfig } from "vitest/config";

// Unit tests only: the pure engine and the adapters' pure helpers, in Node. The e2e suite is Playwright's (test/e2e).
export default defineConfig({
  test: {
    include: ["src/**/*.test.ts", "test/unit/**/*.test.ts", "test/review/**/*.test.ts", "test/corpus/fp-cases/**/*.test.ts", "scripts/**/*.test.ts"],
    environment: "node",
  },
});
