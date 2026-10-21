/**
 * Generates docs/coverage.md and docs/coverage.json from the rule catalogue
 * (src/rules.ts: each rule's mapping) and src/frameworks.ts (the verified
 * framework items, the coverage claimed, the gaps), so the mapping cannot
 * drift from the code. Which rules cover an item is derived, never typed:
 * an item no active rule maps to is "not covered". `--check` exits 1 when
 * either file is out of date (CI). Build first.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { ATTACK, FRAMEWORKS, VERIFICATION } from "../dist/frameworks.js";
import { RULES } from "../dist/rules.js";
import { VERSION } from "../dist/version.js";

const check = process.argv.includes("--check");
const rules = Object.values(RULES);
const active = rules.filter((r) => r.status === "active");
const planned = rules.filter((r) => r.status === "planned");
const FIELDS = ["owaspLlm", "owaspAgentic", "atlas", "mcpSpec"];
const unmapped = (r) => [...FIELDS, "attack"].every((f) => r[f].length === 0);

const problems = [];
const known = new Map(FRAMEWORKS.map((f) => [f.field, new Set(f.items.map((i) => i.id))]));
for (const r of rules) {
  for (const f of FIELDS) for (const id of r[f]) if (!known.get(f).has(id)) problems.push(`${r.id}: ${f} names ${id}, which is not an item of that framework`);
  for (const id of r.attack) if (ATTACK[id] === undefined) problems.push(`${r.id}: ATT&CK ${id} is not in the ATTACK table`);
}

const frameworks = FRAMEWORKS.map((f) => ({
  ...f,
  items: f.items.map((i) => {
    const by = active.filter((r) => r[f.field].includes(i.id)).map((r) => r.id);
    if (by.length > 0 && i.claim === undefined) problems.push(`${i.id}: active rules map to it (${by.join(", ")}) but frameworks.ts claims no coverage; assess it`);
    return { id: i.id, name: i.name, status: by.length === 0 ? "not covered" : i.claim, rules: by, gap: i.gap, mitigation: i.mitigation };
  }),
}));
if (problems.length > 0) {
  console.error(problems.join("\n"));
  process.exit(1);
}

const json = {
  schema: 2,
  generatedFrom: "src/rules.ts and src/frameworks.ts by scripts/gen-coverage.mjs",
  firewallVersion: VERSION,
  verification: VERIFICATION,
  rules: Object.fromEntries(active.map((r) => [r.id, unmapped(r) ? { title: r.title, kind: "marker" } : { title: r.title, owaspLlm: r.owaspLlm, owaspAgentic: r.owaspAgentic, atlas: r.atlas, attack: r.attack, mcp: r.mcpSpec }])),
  planned: Object.fromEntries(planned.map((r) => [r.id, { title: r.title, item: r.item ?? null, owaspLlm: r.owaspLlm, owaspAgentic: r.owaspAgentic, atlas: r.atlas, attack: r.attack, mcp: r.mcpSpec }])),
  frameworks: Object.fromEntries(frameworks.map((f) => [f.key, f.items])),
};

// The backslash first: otherwise a `\` before a `|` would cancel the escape and split the cell.
const cell = (s) => String(s).replace(/[\\|]/g, "\\$&");
const ids = (xs) => (xs.length === 0 ? "-" : xs.map((x) => x.replace(/:2025$/, "")).join(", "));
const count = (f, s) => f.items.filter((i) => i.status === s).length;
const markers = active.filter(unmapped);
const v = VERIFICATION;
const verRow = (title, x) => `| ${title} | ${cell(x.status)} | ${cell(x.note)} Source: ${cell(x.source)} |`;

const L = [
  "# Coverage: what the firewall does and does not cover",
  "",
  "<!-- Generated from src/rules.ts and src/frameworks.ts by scripts/gen-coverage.mjs (npm run gen:docs); do not edit by hand. CI runs npm run check:docs. -->",
  "",
  "This maps every rule the firewall emits to four public frameworks, and states,",
  "for each framework item, whether the firewall covers it, covers it partly, or",
  "does not cover it. Each rule's mapping lives with the rule in `src/rules.ts`;",
  "the items, their verification, the coverage claimed and the gaps live in",
  "`src/frameworks.ts`. This page and the machine-readable [`coverage.json`](coverage.json)",
  "are generated from both. `test/coverage-mapping.test.ts` fails if a rule id in",
  "the code has no mapping, if a mapping names a rule or an item that does not",
  "exist, or if this page and the JSON disagree. `launchsafe-firewall explain <rule>`",
  "shows one rule's mapping.",
  "",
  "How to read the status:",
  "",
  "- **covered**: the firewall deterministically gates the agent-side attack path",
  "  the item describes. The \"gap\" column still lists what remains.",
  "- **partly**: some of the item's attack paths are gated; the gap says which are not.",
  "- **not covered**: no rule in effect addresses it. We say so rather than",
  "  stretch a rule to fit.",
  "",
  "A rule that \"maps\" to an item reduces risk on one path of it; it does not make",
  "the item go away. The firewall governs a coding agent's actions through hooks. It",
  "does not stop a model being fooled, and it is not a sandbox. Where the honest",
  "mitigation is a sandbox, managed settings or a planned item, the table says so.",
  "Planned rules (roadmap items, not in the code yet) are listed at the end with",
  "their intended mapping and are not counted.",
  "",
  "## Summary",
  "",
  "| Framework | covered | partly | not covered |",
  "|---|---|---|---|",
  ...frameworks.map((f) => `| ${f.title} | ${count(f, "covered")} | ${count(f, "partly")} | ${count(f, "not covered")} |`),
  "",
  `Rule count: ${active.length - markers.length} rules emitted by the engine${markers.length > 0 ? `, plus ${markers.map((r) => `the \`${r.id}\` marker (${r.title.replace(/^Marker: /, "")}; it is not a control and maps to nothing)`).join(", ")}` : ""}; ${planned.length} planned.`,
  "",
  "## Verification status",
  "",
  `Checked on ${v.checkedOn} against primary sources.`,
  "",
  "| Source | Status | Notes |",
  "|---|---|---|",
  verRow(FRAMEWORKS[0].title, v.owaspLlm2025),
  verRow(FRAMEWORKS[1].title, v.owaspAgentic2026),
  verRow(FRAMEWORKS[2].title, v.mitreAtlas),
  verRow("MITRE ATT&CK (supplementary)", v.attack),
  verRow(FRAMEWORKS[3].title, v.mcpSpec),
  "",
  "**Could not be verified:**",
  "",
  ...v.unverified.map((u) => `- ${u}`),
  "",
];
for (const f of frameworks) {
  L.push(`## ${f.title}`, "", "| Item | Status | Rules | Gap | Mitigation |", "|---|---|---|---|---|");
  for (const i of f.items) L.push(`| **${i.id}** ${cell(i.name)} | ${i.status} | ${i.rules.length === 0 ? "none" : i.rules.map((r) => `\`${r}\``).join(", ")} | ${cell(i.gap)} | ${cell(i.mitigation)} |`);
  L.push("");
}
L.push(
  "## Rule index",
  "",
  "Every rule in effect, with its mappings. ATT&CK ids are supplementary (ATLAS has no agent-specific technique for these) and are not counted above.",
  "",
  "| Rule | What it stops | OWASP LLM | OWASP Agentic | ATLAS | ATT&CK | MCP |",
  "|---|---|---|---|---|---|---|",
  ...active.map((r) => `| \`${r.id}\` | ${cell(r.title)} | ${ids(r.owaspLlm)} | ${ids(r.owaspAgentic)} | ${ids(r.atlas)} | ${ids(r.attack)} | ${ids(r.mcpSpec)} |`),
  "",
  "## Planned rules (not in the code yet, so not counted)",
  "",
  "| Rule | Roadmap item | What it will stop | OWASP LLM | OWASP Agentic | ATLAS | ATT&CK | MCP |",
  "|---|---|---|---|---|---|---|---|",
  ...planned.map((r) => `| \`${r.id}\` | ${r.item ?? ""} | ${cell(r.title)} | ${ids(r.owaspLlm)} | ${ids(r.owaspAgentic)} | ${ids(r.atlas)} | ${ids(r.attack)} | ${ids(r.mcpSpec)} |`),
  "",
  "When one ships, its status in `src/rules.ts` becomes active and the items it maps to are re-assessed in `src/frameworks.ts` (the generator refuses an item that gains a rule without a coverage claim).",
  "",
  "## What no mapping fixes",
  "",
  "- A fooled agent working inside its allowed envelope. Use an OS sandbox.",
  "- A repository that disables the hook. Use managed settings (`launchsafe-firewall install --managed`; see [usage.md](usage.md)).",
  "- Agents without hook support. Claude Code, Codex, Gemini CLI and Cursor are covered through their hooks; agents built with the OpenAI Agents SDK, Claude Agent SDK, LangGraph or the Vercel AI SDK through the library (`docs/library.md`). Other agents are not covered.",
  "- Anything the model provider, the MCP server or the package registry does on its own side.",
  "",
  "See also [`threat-model.md`](threat-model.md) and [`incidents.md`](incidents.md).",
  "",
);

const outputs = { "docs/coverage.md": L.join("\n"), "docs/coverage.json": `${JSON.stringify(json, null, 2)}\n` };
let stale = false;
for (const [path, text] of Object.entries(outputs)) {
  let cur = "";
  try {
    cur = readFileSync(path, "utf8");
  } catch {
    cur = "";
  }
  if (check) {
    if (cur !== text) {
      console.error(`${path} is out of date: run npm run gen:docs`);
      stale = true;
    }
  } else writeFileSync(path, text);
}
if (stale) process.exit(1);
