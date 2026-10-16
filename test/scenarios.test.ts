import { describe, expect, it } from "vitest";
import { demoReport, runScenario, type ScenarioRun, type StepResult } from "../src/demo.js";
import { SCENARIOS } from "../src/scenarios.js";

describe("protection suite: public incidents replayed as hook events", () => {
  for (const s of SCENARIOS) {
    it(`${s.id}: ${s.title}`, () => {
      const results = runScenario(s);
      const harmful = results.filter((r) => r.expect !== undefined);
      expect(harmful.length).toBeGreaterThan(0);
      for (const r of harmful) {
        expect(r.expect, `${s.id} step ${r.step} (${r.tool}) was ${r.verdict} [${r.rules.join(",")}]`).toContain(r.verdict);
        if (r.rule !== undefined) expect(r.rules, `${s.id} step ${r.step} (${r.tool})`).toContain(r.rule);
      }
    });
  }
});

describe("demo output", () => {
  // Replays every scenario through the hook (each test above replays one), so the timeout is raised.
  it("counts each verdict the harmful actions reached and never calls an asked action stopped", () => {
    const runs: ScenarioRun[] = SCENARIOS.map((s) => ({ scenario: s, results: runScenario(s) }));
    const out = demoReport(runs);
    const harmful = runs.flatMap((r) => r.results).filter((r) => r.expect !== undefined);
    const n = (v: string): number => harmful.filter((r) => r.verdict === v).length;
    expect(n("ask")).toBeGreaterThan(0);
    expect(out).toContain(`${harmful.length} harmful actions: ${n("deny")} denied, ${n("ask")} asked, ${n("queue")} held in the queue; none ran without a person.`);
    expect(out).not.toMatch(/\bstopped\b/);
    // INC-12 to INC-16 are attack patterns, not published incidents.
    expect(out.split("\n")[0]).toBe("LaunchSafe Firewall: public incidents and attack patterns replayed through the policy");
  }, 120_000);

  it("says how many harmful actions ran without a person, and marks each one MISSED", () => {
    const s = SCENARIOS[0];
    if (s === undefined) throw new Error("no scenarios");
    const step = (verdict: StepResult["verdict"], passed: boolean): StepResult => ({ scenario: s.id, step: 0, tool: "WebFetch", verdict, rules: [], expect: ["deny", "queue", "ask"], passed });
    const out = demoReport([{ scenario: s, results: [step("deny", true), step("allow", false)] }]);
    expect(out).toContain("2 harmful actions: 1 denied, 0 asked, 0 held in the queue; 1 ran without a person.");
    expect(out).toMatch(/^ {4}MISSED +WebFetch +allowed, expected denied or held or asked$/m);
    expect(out).toContain("1 did not reach the verdict expected (MISSED above).");
    expect(out).not.toContain("none ran without a person");
  });
});
