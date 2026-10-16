/**
 * The Tier 1 features together (the fw/integration merge): rules one branch added stay enforced by the
 * others. Watch mode (rollout) keeps every new rule enforced; a learned "always" (fewer prompts) never
 * covers one; the behaviour monitor (kill switch) does not count spending-limit denials (caps), so a cap
 * stop never also becomes a kill-switch stop; a stop and a person's "never" hold on the library's
 * read-only fallback too.
 */
import { describe, expect, it } from "vitest";
import { RULES } from "../src/rules.js";
import { enforcedInWatch, WATCH_ENFORCED_RULES, WATCH_RELAXABLE_RULES } from "../src/policy-rollout.js";
import { riskOf, rulesEligibility } from "../src/engine/learn.js";
import { decide } from "../src/engine/decide.js";
import { emptyCapCounts, isCapRule, monitorCountedVerdict, type CapView } from "../src/engine/caps.js";
import { applyDecision, budgetView, emptyCounters } from "../src/engine/counters.js";
import type { BudgetView } from "../src/engine/budgets.js";
import { defaultConfig } from "../src/policy.js";
import type { Decision } from "../src/types.js";
import { ctx, explain, state, WS } from "./helpers.js";

/** Every rule id the ten merged branches added to the catalogue. */
const NEW_RULES = [
  "FW-INPUT-SHAPE",
  "FW-RESULT-UNRECORDED",
  "FW-CATASTROPHIC",
  "FW-CREDENTIAL-FLOW",
  "FW-NEW-HOST",
  "FW-STOPPED",
  "FW-CAP",
  "FW-CAP-WARN",
  "FW-LEARNED-ALLOW",
  "FW-LEARNED-DENY",
  "FW-OUTSIDE-COMMAND",
  "FW-HIDDEN-OUTPUT",
];

function budgets(win: Record<string, number> = {}): BudgetView {
  return { corrupt: false, total: () => 0, window: (k) => win[k] ?? 0, repeats: () => 0, allowance: () => 0 };
}

/** Spending-limit counters with the session's tool-call cap already reached. */
function capsAtLimit(): CapView {
  return { sessionId: "s1", session: { ...emptyCapCounts(), totals: { calls: defaultConfig().caps?.session?.toolCalls ?? 5000 } }, day: emptyCapCounts(), raise: () => 0 };
}

describe("integration: every new rule is catalogued", () => {
  it("each rule the branches added is in the catalogue", () => {
    for (const id of NEW_RULES) expect(Object.keys(RULES), id).toContain(id);
  });
});

describe("integration: watch mode keeps the new rules enforced", () => {
  it("none of the new rules is on the reviewed relaxable list; each stays enforced", () => {
    for (const id of NEW_RULES) {
      expect(WATCH_RELAXABLE_RULES.has(id), id).toBe(false);
      expect(WATCH_ENFORCED_RULES.has(id), id).toBe(true);
      expect(enforcedInWatch(id), id).toBe(true);
    }
  });

  it("a catastrophic action is denied in watch mode", () => {
    const d = decide({ action: { tool: "Bash", input: { command: "git push --force origin main" } }, state: state(), config: defaultConfig(), ctx: ctx(), watch: true });
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toContain("FW-CATASTROPHIC");
  });

  it("a spending limit is enforced in watch mode", () => {
    const d = decide({ action: { tool: "Bash", input: { command: "npm test" } }, state: state(), config: defaultConfig(), ctx: ctx(), caps: capsAtLimit(), watch: true, sessionId: "s1" });
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toEqual(["FW-CAP"]);
  });

  it("a kill-switch stop is enforced in watch mode", () => {
    const d = decide({ action: { tool: "Read", input: { file_path: `${WS}/a.ts` } }, state: state(), config: defaultConfig(), ctx: ctx(), watch: true, sessionId: "s1", stop: { active: { id: "x1", at: new Date(0).toISOString(), by: "person", scope: "session", target: "s1", reason: "stopped by a person" } } });
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toEqual(["FW-STOPPED"]);
  });
});

describe("integration: a learned allow never covers the new rules", () => {
  it("each new rule has a risk class other than low, so no learned allow covers it, alone or with a low rule", () => {
    for (const id of NEW_RULES) {
      expect(riskOf(id), id).not.toBe("low");
      expect(rulesEligibility([id]).eligible, id).toBe(false);
      expect(rulesEligibility(["FW-UNKNOWN-TOOL", id]).eligible, id).toBe(false);
    }
  });
});

describe("integration: the behaviour monitor does not count spending-limit denials", () => {
  const nearStop = (): BudgetView => budgets({ "verdict:nonallow": defaultConfig().budgets.loop.stopNonAllow10m - 1 });

  it("a cap denial one short of the monitor's non-allowed limit is FW-CAP, not a kill-switch stop", () => {
    const d = decide({ action: { tool: "Bash", input: { command: "npm test" } }, state: state(), config: defaultConfig(), ctx: ctx(), budgets: nearStop(), caps: capsAtLimit(), sessionId: "s1" });
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toEqual(["FW-CAP"]);
    expect(d.stop).toBeUndefined();
  });

  it("control: a denial by another rule at the same count does stop the session", () => {
    const d = decide({ action: { tool: "Bash", input: { command: "curl http://169.254.169.254/latest/meta-data/" } }, state: state(), config: defaultConfig(), ctx: ctx(), budgets: nearStop(), sessionId: "s1" });
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toEqual(["FW-STOPPED"]);
    expect(d.stop?.signal).toBe("nonallow");
  });

  it("a decision refused only by a cap is counted as allowed; one another rule also refused is counted as it is", () => {
    expect(isCapRule("FW-CAP") && isCapRule("FW-CAP-WARN")).toBe(true);
    expect(monitorCountedVerdict({ verdict: "deny", rules: ["FW-CAP"] })).toBe("allow");
    expect(monitorCountedVerdict({ verdict: "ask", rules: ["FW-CAP-WARN"] })).toBe("allow");
    expect(monitorCountedVerdict({ verdict: "deny", rules: ["FW-CAP", "FW-METADATA"] })).toBe("deny");
    expect(monitorCountedVerdict({ verdict: "deny", rules: [] })).toBe("deny");
  });

  it("the counters do not add a cap denial to the non-allowed or same-failure counts", () => {
    const now = new Date("2026-10-13T12:00:00Z");
    const base: Decision = { verdict: "deny", primaryClass: "execute", reasons: ["cap"], rules: ["FW-CAP"], effects: [], findings: [], events: [], actionHash: "h1", budget: { usage: [], raises: [], loopEligible: false, writes: false, watch: { hosts: [], newHosts: 0, config: false } } };
    const c = emptyCounters();
    for (let i = 0; i < 5; i += 1) applyDecision(c, base, now);
    const v = budgetView(c, false, state(), now);
    expect(v.window("verdict:nonallow", 10)).toBe(0);
    expect(v.recent?.("verdict:nonallow") ?? 0).toBe(0);
    expect(v.recent?.("fail:h1") ?? 0).toBe(0);
    // The same decision denied by another rule is counted.
    applyDecision(c, { ...base, rules: ["FW-METADATA"] }, now);
    const w = budgetView(c, false, state(), now);
    expect(w.window("verdict:nonallow", 10)).toBe(1);
  });
});
