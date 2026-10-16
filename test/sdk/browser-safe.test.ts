/**
 * The core library is dependency-free and browser-safe (docs/library.md, principle 3): every module
 * src/sdk/index.ts reaches imports only relative modules (no node:, no package), and the whole graph
 * type-checks against the browser's library without Node's types (a Buffer, process or require fails it).
 */

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { REPO } from "../helpers.js";

function graph(entry: string): Map<string, string[]> {
  const seen = new Map<string, string[]>();
  const todo = [entry];
  while (todo.length > 0) {
    const file = todo.pop() as string;
    if (seen.has(file)) continue;
    const text = readFileSync(file, "utf8");
    const specs: string[] = [];
    // Static imports and re-exports, type-only ones excluded (they vanish at run time).
    for (const m of text.matchAll(/^\s*(import|export)\s+(?!type\b)[^;]*?from\s+"([^"]+)"/gms)) specs.push(m[2] as string);
    for (const m of text.matchAll(/import\(\s*"([^"]+)"\s*\)/g)) specs.push(m[1] as string);
    seen.set(file, specs);
    for (const s of specs) if (s.startsWith(".")) todo.push(resolve(dirname(file), s.replace(/\.js$/, ".ts")));
  }
  return seen;
}

describe("the core library is browser-safe", () => {
  const g = graph(join(REPO, "src/sdk/index.ts"));

  it("reaches the engine and nothing outside the repository", () => {
    expect(g.size).toBeGreaterThan(20);
    const outside = [...g].flatMap(([f, specs]) => specs.filter((s) => !s.startsWith(".")).map((s) => `${f.slice(REPO.length + 1)} imports ${s}`));
    expect(outside).toEqual([]);
  });

  it("never reaches the runtime, the hook or the CLI (the file system lives there)", () => {
    const bad = [...g.keys()].map((f) => f.slice(REPO.length + 1)).filter((f) => /^src\/(?:runtime|hook|adapters)\/|^src\/cli(?:main)?\.ts$/.test(f));
    expect(bad).toEqual([]);
  });

  it("type-checks with the browser's library and no Node types (so it uses no Node global)", () => {
    const program = ts.createProgram([join(REPO, "src/sdk/index.ts")], {
      target: ts.ScriptTarget.ES2023,
      module: ts.ModuleKind.NodeNext,
      moduleResolution: ts.ModuleResolutionKind.NodeNext,
      lib: ["lib.es2023.d.ts", "lib.dom.d.ts"],
      types: [],
      strict: true,
      noEmit: true,
      skipLibCheck: true,
    });
    const problems = ts.getPreEmitDiagnostics(program).map((d) => `${d.file?.fileName.slice(REPO.length + 1) ?? ""}: ${ts.flattenDiagnosticMessageText(d.messageText, "\n")}`);
    expect(problems).toEqual([]);
  }, 60_000);
});
