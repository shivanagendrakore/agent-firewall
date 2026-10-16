/**
 * Task scope: in log mode the task scope changes no decision. The proof: the friction
 * suite (the known-good corpus and the catalogue rows expected to be allowed) and the incident suite
 * (the 16 replayed incidents and the INC rows of the catalogue) give identical verdicts, rules and
 * reasons with taskScope.mode "off" and "log", under a prompt that narrows the scope. Each comparison
 * also checks that log mode did compute scope effects, so it is not equal only because nothing ran.
 */
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { frictionRows, runnable, runRow, type RowRun } from "../src/catalogue.js";
import { CATALOGUE, type CatalogueRow, type RowState } from "../src/catalogue-scenarios.js";
import { ALWAYS_FINE, TOOL_CASES, TRUSTED_ONLY, V02_FINE } from "../src/corpus.js";
import { runScenario, type StepResult } from "../src/demo.js";
import { decide } from "../src/engine/decide.js";
import type { ScopeMode } from "../src/engine/scope.js";
import { foldEvents } from "../src/engine/state.js";
import { defaultConfig } from "../src/policy.js";
import { layout } from "../src/runtime/layout.js";
import { tailLog } from "../src/runtime/log.js";
import { SCENARIOS } from "../src/scenarios.js";
import type { StateEvent } from "../src/types.js";
import { ctx, testRoot, WS } from "./helpers.js";

/** A prompt that narrows the scope in every tree: packages/web exists in the catalogue's and the replayer's setup. */
const NARROWING = "fix the failing test in `packages/web`";
/** The replayer's workspace is empty, so its narrowing prompt narrows by intent (deploy) instead of by path. */
const NARROWING_BY_INTENT = "fix the failing test in `packages/web`, then deploy";

describe("log mode changes no decision of the friction corpus (engine level)", () => {
  const scope: StateEvent = { type: "scope", scope: { prompt: "a".repeat(64), at: "2026-10-10T00:00:00.000Z", paths: [`${WS}/packages/web`], repos: [], hosts: [], intents: [], narrowed: true } };
  const states = { trusted: foldEvents([scope]), untrusted: foldEvents([{ type: "taint", source: "read a web page" }, scope]) };
  const fill = (v: unknown): unknown => (typeof v === "string" ? v.replaceAll("{WS}", WS) : typeof v === "object" && v !== null ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x)])) : v);
  const actions = [...ALWAYS_FINE, ...TRUSTED_ONLY, ...V02_FINE].map((command) => ({ tool: "Bash", input: { command } as Record<string, unknown> })).concat(TOOL_CASES.map((c) => ({ tool: c.tool, input: fill(c.input) as Record<string, unknown> })));
  it(`${actions.length} actions x trusted/untrusted x interactive/unattended`, () => {
    const cfg = (mode: ScopeMode): ReturnType<typeof defaultConfig> => ({ ...defaultConfig(), taskScope: { mode, unattendedIntents: true } });
    let compared = 0;
    let effects = 0;
    let wouldChange = 0;
    for (const a of actions) {
      for (const st of Object.values(states)) {
        for (const interactive of [true, false]) {
          const c = ctx({ interactive });
          const off = decide({ action: a, state: st, config: cfg("off"), ctx: c });
          const log = decide({ action: a, state: st, config: cfg("log"), ctx: c });
          expect({ verdict: log.verdict, rules: log.rules, reasons: log.reasons, events: log.events }, `${a.tool} ${JSON.stringify(a.input)}`).toEqual({ verdict: off.verdict, rules: off.rules, reasons: off.reasons, events: off.events });
          expect(off.scope).toBeUndefined();
          compared++;
          if (log.scope !== undefined) effects++;
          if (log.scope?.changes === true) wouldChange++;
        }
      }
    }
    expect(compared).toBe(actions.length * 4);
    // Non-vacuous: the scope was evaluated and would have changed some of these decisions.
    expect(effects).toBeGreaterThan(0);
    expect(wouldChange).toBeGreaterThan(0);
  });
});

/** A row with the narrowing prompt (unless it has its own) and the mode; rows of the task-scope tests exercise enforce itself. */
function withMode(row: CatalogueRow, mode: ScopeMode): CatalogueRow {
  return { ...row, prompt: row.prompt ?? NARROWING, policy: { ...(row.policy ?? {}), taskScope: { mode } } };
}

function runKept(row: CatalogueRow, state: RowState): { run: RowRun; scoped: number } {
  const parent = mkdtempSync(join(testRoot(), "eq-"));
  try {
    const run = runRow(row, state, { parent, keep: true });
    const tree = readdirSync(parent).find((n) => n.startsWith("lsfw-cat-"));
    const l = layout(join(parent, tree ?? "missing", "home", ".launchsafe-firewall"));
    const scoped = tailLog(l, 10000).filter((e) => e.event.type === "decision" && e.event.scope !== undefined).length;
    return { run, scoped };
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
}

/** Queue ids and the throwaway tree's directory names are random per run; everything else must match exactly. */
const noIds = (v: unknown): unknown =>
  JSON.parse(
    JSON.stringify(v)
      .replace(/queue (approve|show) [a-z0-9]{4,32}/g, "queue $1 <id>")
      // "Fewer prompts": an action's code is derived from its project directory, which differs per run.
      .replace(/allow (add|never) [a-z0-9]{8,32}/g, "allow $1 <code>")
      .replace(/\/(lsfw-demo|lsfw-cat|eq)-[A-Za-z0-9]+/g, "/$1-<tmp>"),
  ) as unknown;

/** One row-state in both modes: identical steps; returns how many decisions log mode attached a scope effect to. */
function compareRow(row: CatalogueRow, state: RowState): number {
  const off = runKept(withMode(row, "off"), state);
  const log = runKept(withMode(row, "log"), state);
  expect(noIds(log.run.steps), `${row.id} [${state}]`).toEqual(noIds(off.run.steps));
  expect(off.scoped, `${row.id} [${state}] logged a scope effect in mode off`).toBe(0);
  return log.scoped;
}

/** One test per row-state (each runs the row twice in fresh trees), then the non-vacuity check over all of them. */
function compareRows(label: string, pairs: { row: CatalogueRow; state: RowState }[]): void {
  let scoped = 0;
  let compared = 0;
  for (const { row, state } of pairs) {
    it(`${row.id} [${state}]`, () => {
      scoped += compareRow(row, state);
      compared++;
    });
  }
  it(`${label}: all ${pairs.length} row-states compared, and log mode evaluated the scope in some of them`, () => {
    expect(compared).toBe(pairs.length);
    expect(scoped).toBeGreaterThan(0);
  });
}

describe("log mode changes no decision of the friction gate's catalogue rows (hook level)", () => {
  compareRows("friction rows", frictionRows().filter(({ row }) => row.item !== "2"));
});

describe("log mode changes no decision of the incident suite (hook level)", () => {
  it(`the ${SCENARIOS.length} replayed incidents give identical decisions with mode off and log`, () => {
    let scoped = 0;
    const strip = (r: StepResult[]): unknown => r.map((x) => ({ step: x.step, tool: x.tool, verdict: x.verdict, rules: x.rules, reason: x.reason, passed: x.passed }));
    for (const s of SCENARIOS) {
      const before = [{ hook_event_name: "UserPromptSubmit", prompt: NARROWING_BY_INTENT }];
      const off = runScenario(s, { policy: { taskScope: { mode: "off" } }, before });
      let logged = 0;
      const log = runScenario(s, { policy: { taskScope: { mode: "log" } }, before, inspect: (l) => (logged = tailLog(l, 10000).filter((e) => e.event.type === "decision" && e.event.scope !== undefined).length) });
      expect(noIds(strip(log)), s.id).toEqual(noIds(strip(off)));
      expect(log.filter((r) => r.expect !== undefined).every((r) => r.passed), s.id).toBe(true);
      scoped += logged;
    }
    expect(scoped).toBeGreaterThan(0);
    // 36 full hook replays (about 4 s alone); under full-suite load on a busy machine they passed the default
    // 30 s timeout, so it is raised like G14 and N9 (d574b74).
  }, 120_000);
});

describe("log mode changes no decision of the INC rows of the catalogue (hook level)", () => {
  compareRows("INC rows", CATALOGUE.filter((r) => r.category === "INC" && runnable(r) && r.item !== "2").flatMap((row) => row.states.map((state) => ({ row, state }))));
});
