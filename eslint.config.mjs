// Lint with zero warnings. Strict TypeScript rules; a bare `any` is an error.
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import ts from "typescript";

/**
 * FB3: a computed string key on a plain object map reads Object.prototype for names such as
 * "constructor", "toString" or "__proto__", and a write of "__proto__" changes the prototype. Names
 * from outside (servers, tools, hosts, agents, entries) are looked up with own()/setOwn() from
 * src/own.ts, or kept in a Map. Deleting is allowed (it never reaches the prototype).
 */
const ownKeys = {
  meta: { type: "problem", schema: [], messages: { read: "Read a string-keyed map with own(map, key) from src/own.ts (or use a Map): a plain index returns Object.prototype members for names like \"constructor\".", write: "Write a string-keyed map with setOwn(map, key, value) from src/own.ts (or use a Map): assigning \"__proto__\" changes the prototype." } },
  create(context) {
    const services = context.sourceCode.parserServices;
    if (services?.program == null) return {};
    const checker = services.program.getTypeChecker();
    const isWrite = (node) => {
      const p = node.parent;
      if (p.type === "AssignmentExpression" && p.left === node) return true;
      if (p.type === "UpdateExpression") return true;
      return false;
    };
    return {
      MemberExpression(node) {
        if (!node.computed) return;
        if (node.parent.type === "UnaryExpression" && node.parent.operator === "delete") return;
        const objT = checker.getNonNullableType(services.getTypeAtLocation(node.object));
        if (checker.isArrayType(objT) || checker.isTupleType(objT) || (objT.flags & ts.TypeFlags.StringLike) !== 0) return;
        if (objT.getStringIndexType() === undefined) return;
        const keyT = services.getTypeAtLocation(node.property);
        if ((keyT.flags & ts.TypeFlags.String) === 0) return;
        context.report({ node, messageId: isWrite(node) ? "write" : "read" });
      },
    };
  },
};

export default tseslint.config(
  // browser/ and python/ are separate packages with their own lint (browser/eslint.config.mjs, ruff); this config never reaches them.
  { ignores: ["dist/**", "dist-check/**", "dist-conformance/**", "coverage/**", "node_modules/**", "scripts/**", "eslint.config.mjs", "vitest.config.ts", "browser/**", "python/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: { parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname } },
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "no-console": "off",
      eqeqeq: ["error", "always", { null: "ignore" }],
      "no-var": "error",
      "prefer-const": "error",
      "no-useless-assignment": "off",
      "@typescript-eslint/no-unused-expressions": ["error", { allowShortCircuit: true, allowTernary: true }],
    },
  },
  {
    files: ["src/**/*.ts"],
    ignores: ["src/vendor/**", "src/own.ts"],
    plugins: { local: { rules: { "own-keys": ownKeys } } },
    rules: { "local/own-keys": "error" },
  },
  {
    // F-a: handlers receive the parsed command line; only the entry point reads raw argv.
    files: ["src/**/*.ts"],
    ignores: ["src/cli.ts"],
    rules: { "no-restricted-properties": ["error", { object: "process", property: "argv", message: "Only src/cli.ts reads process.argv; handlers get the parsed command line (src/cliargs.ts)." }] },
  },
  {
    // F-a: tests start the built CLI only through test/helpers.ts (spawnCli), which forces a temporary home.
    files: ["test/**/*.ts"],
    ignores: ["test/helpers.ts"],
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector: "CallExpression[callee.name=/^(spawnSync|execFileSync|spawn|execFile|execSync|exec|fork)$/] :matches(Literal[value=/cli\\.js/], TemplateElement[value.raw=/cli\\.js/], Identifier[name=/^(cli|CLI)$/])",
          message: "Start the CLI with spawnCli() from test/helpers.ts, which forces a temporary home.",
        },
      ],
    },
  },
  {
    files: ["test/**/*.ts", "scripts/**/*.mjs"],
    rules: { "@typescript-eslint/no-explicit-any": "off", "@typescript-eslint/no-require-imports": "off", "@typescript-eslint/no-unused-expressions": "off" },
  },
);
