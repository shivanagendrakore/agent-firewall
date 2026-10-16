import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { ATTACK, FRAMEWORKS } from "../src/frameworks.js";
import { MAPPED_RULE_IDS, RULES } from "../src/rules.js";

/**
 * The coverage map has one source: each rule's mapping in src/rules.ts and the framework items in
 * src/frameworks.ts. docs/coverage.json and docs/coverage.md are generated from them (gen-coverage,
 * checked in CI by check:docs); these tests hold the generated files to the code.
 */
const root = join(dirname(fileURLToPath(import.meta.url)), "..");

interface Item { id: string; name: string; status: string; rules: string[]; gap: string; mitigation: string }
interface RuleEntry { title: string; kind?: string; owaspLlm?: string[]; owaspAgentic?: string[]; atlas?: string[]; attack?: string[]; mcp?: string[] }
const coverage = JSON.parse(readFileSync(join(root, "docs", "coverage.json"), "utf8")) as {
  rules: Record<string, RuleEntry>;
  planned: Record<string, RuleEntry & { item: string | null }>;
  frameworks: Record<string, Item[]>;
};
const markdown = readFileSync(join(root, "docs", "coverage.md"), "utf8");

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? sourceFiles(p) : p.endsWith(".ts") ? [p] : [];
  });
}

/**
 * Every FW- rule id written anywhere in src/ (code and comments), except the catalogue itself and
 * the scenario data, which name planned rules on purpose. A prefix such as "FW-DLP-" is not an id.
 */
function idsInCode(): Set<string> {
  const ids = new Set<string>();
  for (const f of sourceFiles(join(root, "src"))) {
    if (/(?:^|\/)(?:rules|frameworks|catalogue-scenarios|catalogue|scenarios)\.ts$/.test(f)) continue;
    for (const m of readFileSync(f, "utf8").matchAll(/\bFW-[A-Z0-9]+(?:-[A-Z0-9]+)*\b(?!-)/g)) ids.add(m[0]);
  }
  return ids;
}

const FIELDS: [keyof RuleEntry, string][] = [["owaspLlm", "owaspLlm2025"], ["owaspAgentic", "owaspAgentic2026"], ["atlas", "mitreAtlas"], ["mcp", "mcpSpec"]];

describe("the mapping source (src/rules.ts, src/frameworks.ts)", () => {
  it("every catalogue rule has exactly one mapping entry, and no entry names a rule outside the catalogue", () => {
    expect([...MAPPED_RULE_IDS].sort()).toEqual(Object.keys(RULES).sort());
  });

  it("only FW-APPROVED and FW-LEARNED-ALLOW (markers of a person's choice, not controls) map to nothing", () => {
    const empty = Object.values(RULES).filter((r) => [r.owaspLlm, r.owaspAgentic, r.atlas, r.attack, r.mcpSpec].every((x) => x.length === 0)).map((r) => r.id);
    expect(empty).toEqual(["FW-APPROVED", "FW-LEARNED-ALLOW"]);
  });

  it("every mapping, active or planned, names an item of that framework (or of the ATT&CK table)", () => {
    for (const r of Object.values(RULES)) {
      for (const f of FRAMEWORKS) for (const id of r[f.field]) expect(f.items.some((i) => i.id === id), `${r.id} -> ${id}`).toBe(true);
      for (const id of r.attack) expect(ATTACK[id], `${r.id} -> ${id}`).toBeDefined();
    }
  });

  it("every item an active rule maps to has an assessed coverage claim", () => {
    for (const f of FRAMEWORKS) for (const i of f.items) {
      const by = Object.values(RULES).filter((r) => r.status === "active" && r[f.field].includes(i.id));
      if (by.length > 0) expect(i.claim, `${i.id} (${by.map((r) => r.id).join(", ")})`).toBeDefined();
    }
  });
});

describe("docs/coverage.json", () => {
  it("lists every active catalogue rule, and planned ones apart", () => {
    expect(Object.keys(coverage.rules).sort()).toEqual(Object.values(RULES).filter((r) => r.status === "active").map((r) => r.id).sort());
    expect(Object.keys(coverage.planned).sort()).toEqual(Object.values(RULES).filter((r) => r.status === "planned").map((r) => r.id).sort());
  });

  it("has a mapping entry for every rule id in the code", () => {
    const missing = [...idsInCode()].filter((id) => coverage.rules[id] === undefined);
    expect(missing).toEqual([]);
  });

  it("maps no rule that does not exist in the code", () => {
    const code = idsInCode();
    expect(Object.keys(coverage.rules).filter((id) => !code.has(id))).toEqual([]);
  });

  it("only references framework items that are defined", () => {
    for (const [id, rule] of Object.entries(coverage.rules)) {
      for (const [field, fw] of FIELDS) {
        const known = new Set(coverage.frameworks[fw]!.map((i) => i.id));
        for (const ref of rule[field] as string[] | undefined ?? []) expect(known.has(ref), `${id} -> ${ref}`).toBe(true);
      }
    }
  });

  it("lists, on each item, exactly the rules that reference it", () => {
    for (const [field, fw] of FIELDS) {
      for (const item of coverage.frameworks[fw]!) {
        const referencing = Object.entries(coverage.rules).filter(([, r]) => (r[field] as string[] | undefined ?? []).includes(item.id)).map(([id]) => id).sort();
        expect([...item.rules].sort(), `${fw} ${item.id}`).toEqual(referencing);
        for (const r of item.rules) expect(coverage.rules[r], `${item.id} -> ${r}`).toBeDefined();
      }
    }
  });

  it("gives every item a valid status, and honest gaps", () => {
    for (const items of Object.values(coverage.frameworks)) {
      for (const item of items) {
        expect(["covered", "partly", "not covered"]).toContain(item.status);
        // Not covered means no rule claims it; covered or partly needs at least one rule.
        expect(item.status === "not covered" ? item.rules.length === 0 : item.rules.length > 0, item.id).toBe(true);
        expect(item.gap.length, `${item.id} gap`).toBeGreaterThan(10);
        expect(item.mitigation.length, `${item.id} mitigation`).toBeGreaterThan(5);
      }
    }
  });

  it("has unique item ids", () => {
    const all = Object.values(coverage.frameworks).flat().map((i) => i.id);
    expect(new Set(all).size).toBe(all.length);
  });
});

describe("docs/coverage.md", () => {
  it("mentions every rule id and every framework item id", () => {
    for (const id of Object.keys(coverage.rules)) expect(markdown, id).toContain(`\`${id}\``);
    for (const item of Object.values(coverage.frameworks).flat()) expect(markdown, item.id).toContain(`**${item.id}**`);
  });

  it("states the same counts as the JSON", () => {
    for (const items of Object.values(coverage.frameworks)) {
      const n = (s: string) => items.filter((i) => i.status === s).length;
      expect(markdown).toContain(`| ${n("covered")} | ${n("partly")} | ${n("not covered")} |`);
    }
  });
});
