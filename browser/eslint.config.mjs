// Lint with zero warnings (`eslint . --max-warnings 0`). Strict TypeScript rules; a bare `any` is an error.
import js from "@eslint/js";
import tseslint from "typescript-eslint";

/** Browser and extension globals the pure engine must never touch: it runs in Node for tests. */
const BROWSER_GLOBALS = ["chrome", "browser", "window", "document", "navigator", "location", "localStorage", "sessionStorage", "indexedDB", "fetch", "XMLHttpRequest"].map((name) => ({
  name,
  message: "src/engine/ is pure: no browser or extension APIs. Pass what you need in from an adapter (src/content, src/worker, src/ui).",
}));

export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**", "test-results/**", "playwright-report/**", "src/vendor/**", "test/agents/debugger-agent/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: { parserOptions: { projectService: { allowDefaultProject: ["eslint.config.mjs", "scripts/*.mjs"] }, tsconfigRootDir: import.meta.dirname } },
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "@typescript-eslint/consistent-type-imports": "error",
      eqeqeq: ["error", "always", { null: "ignore" }],
      "no-var": "error",
      "prefer-const": "error",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
    },
  },
  {
    files: ["scripts/**/*.mjs"],
    languageOptions: { globals: { console: "readonly", process: "readonly", Buffer: "readonly", fetch: "readonly", setTimeout: "readonly", AbortSignal: "readonly", URL: "readonly", document: "readonly" } },
    rules: { "@typescript-eslint/consistent-type-imports": "off" },
  },
  {
    // Playwright reads a fixture's dependencies from its destructuring pattern; a fixture with none must write `{}`.
    files: ["test/e2e/**/*.ts"],
    rules: { "no-empty-pattern": "off" },
  },
  {
    // The pure engine: no browser APIs, no Node built-ins, no adapters.
    files: ["src/engine/**/*.ts"],
    rules: {
      "no-restricted-globals": ["error", ...BROWSER_GLOBALS],
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            { group: ["node:*", "fs", "path", "crypto", "child_process", "os"], message: "src/engine/ is pure: no Node built-ins (tests may use them)." },
            { group: ["**/content/**", "**/worker/**", "**/ui/**"], message: "The engine never imports an adapter." },
          ],
        },
      ],
    },
  },
  {
    files: ["src/engine/**/*.test.ts"],
    rules: { "no-restricted-imports": "off" },
  },
  {
    // Adapters talk to each other only through src/shared/ messages, so the three lanes stay independent.
    files: ["src/content/**/*.ts"],
    rules: { "no-restricted-imports": ["error", { patterns: [{ group: ["**/worker/**", "**/ui/**"], message: "Content scripts reach the worker only through src/shared/messages.ts." }] }] },
  },
  {
    files: ["src/worker/**/*.ts"],
    rules: { "no-restricted-imports": ["error", { patterns: [{ group: ["**/content/**", "**/ui/**"], message: "The worker reaches content scripts and UI only through src/shared/messages.ts." }] }] },
  },
  {
    files: ["src/ui/**/*.ts"],
    rules: { "no-restricted-imports": ["error", { patterns: [{ group: ["**/content/**", "**/worker/**"], message: "The UI reaches the worker only through src/shared/messages.ts." }] }] },
  },
);
