/**
 * Replays the incident scenarios through the real hook, in a throwaway state
 * directory and workspace, and reports what the firewall decided.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { runHook } from "./hook/claude.js";
import { POLICY_VERSION } from "./policy.js";
import { layout, type Layout } from "./runtime/layout.js";
import { SCENARIOS, type Scenario } from "./scenarios.js";
import type { Verdict } from "./types.js";

export interface StepResult {
  scenario: string;
  step: number;
  tool: string;
  verdict: Verdict | "n/a";
  rules: string[];
  expect?: Verdict[];
  rule?: string;
  passed: boolean;
  /** The message the person (and the agent) read; empty when allowed. */
  reason?: string;
}

/** Test options: a user policy file, events sent before the scenario (a prompt), and a look at the state before cleanup. */
export interface ScenarioOptions {
  policy?: Record<string, unknown>;
  before?: Record<string, unknown>[];
  inspect?: (l: Layout, workspace: string) => void;
}

function fill(v: unknown, ws: string, home: string): unknown {
  if (typeof v === "string") return v.replaceAll("{WS}", ws).replaceAll("{HOME}", home);
  if (Array.isArray(v)) return v.map((x) => fill(x, ws, home));
  if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x, ws, home)]));
  return v;
}

export function verdictOf(stdout: string, exitCode: number): { verdict: Verdict; reason: string } {
  if (exitCode === 2) return { verdict: "deny", reason: "exit 2" };
  if (stdout.trim() === "") return { verdict: "allow", reason: "" };
  const o = JSON.parse(stdout) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
  const d = o.hookSpecificOutput?.permissionDecision;
  const reason = o.hookSpecificOutput?.permissionDecisionReason ?? "";
  if (d === "ask") return { verdict: "ask", reason };
  if (d === "deny") return { verdict: /held this for review/.test(reason) ? "queue" : "deny", reason };
  return { verdict: "allow", reason };
}

export function runScenario(s: Scenario, o: ScenarioOptions = {}): StepResult[] {
  const root = mkdtempSync(join(tmpdir(), "lsfw-demo-"));
  const ws = join(root, "workspace");
  mkdirSync(ws, { recursive: true });
  const l = layout(join(root, "state"));
  const sessionId = `demo-${s.id}`;
  const results: StepResult[] = [];
  try {
    if (o.policy !== undefined) {
      mkdirSync(l.home, { recursive: true });
      writeFileSync(l.policy, JSON.stringify({ version: POLICY_VERSION, ...o.policy }));
    }
    [...(o.before ?? []).map((event) => ({ event })), ...s.steps].forEach((step: Scenario["steps"][number], i) => {
      const event = fill({ session_id: sessionId, cwd: ws, permission_mode: "default", ...step.event }, ws, homedir()) as Record<string, unknown>;
      // The replay must not depend on the person's own agent setup: the session-start scan reads an empty config directory.
      const res = runHook(JSON.stringify(event), { env: { CLAUDE_PROJECT_DIR: ws, CLAUDE_CONFIG_DIR: join(root, "claude-config") }, layout: l, detectNonInteractive: () => s.unattended === true });
      if (event.hook_event_name !== "PreToolUse") return;
      const { verdict, reason } = verdictOf(res.stdout, res.exitCode);
      const rules = (/\(rule ([A-Z0-9, -]+)\)\s*$/.exec(reason)?.[1] ?? "").split(", ").filter((x) => x !== "");
      const r: StepResult = { scenario: s.id, step: i, tool: String(event.tool_name), verdict, rules, passed: true, reason };
      if (step.expect !== undefined) {
        r.expect = step.expect;
        r.passed = step.expect.includes(verdict);
      }
      if (step.rule !== undefined) r.rule = step.rule;
      results.push(r);
    });
    o.inspect?.(l, ws);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  return results;
}

/** What the demo calls each verdict a harmful action reached. An ask goes to a person; it is not called a stop. */
const REACHED: Record<StepResult["verdict"], string> = { deny: "denied", ask: "asked", queue: "held", allow: "allowed", "n/a": "not decided" };

/** One scenario and what its replay decided. */
export interface ScenarioRun {
  scenario: Scenario;
  results: StepResult[];
}

export function runDemo(): string {
  return demoReport(SCENARIOS.map((s) => ({ scenario: s, results: runScenario(s) })));
}

/** The demo's text for replays already run: each harmful step's verdict and rules, then a count by verdict. */
export function demoReport(runs: readonly ScenarioRun[]): string {
  const lines: string[] = ["LaunchSafe Firewall: public incidents and attack patterns replayed through the policy", ""];
  const reached = new Map<StepResult["verdict"], number>();
  let missed = 0;
  let total = 0;
  for (const { scenario: s, results } of runs) {
    lines.push(`${s.id}  ${s.title}`);
    for (const r of results) {
      if (r.expect === undefined) continue;
      total++;
      reached.set(r.verdict, (reached.get(r.verdict) ?? 0) + 1);
      if (!r.passed) missed++;
      const what = r.passed ? r.rules.join(", ") : `${REACHED[r.verdict]}, expected ${r.expect.map((v) => REACHED[v]).join(" or ")}`;
      lines.push(`    ${(r.passed ? REACHED[r.verdict] : "MISSED").padEnd(7)}  ${r.tool.padEnd(36)} ${what}`.trimEnd());
    }
    lines.push(`    source: ${s.source}`, "");
  }
  const n = (v: StepResult["verdict"]): number => reached.get(v) ?? 0;
  lines.push("These are modelled events, not recordings of the attacks.", "");
  const ran = total - n("deny") - n("ask") - n("queue");
  lines.push(`${total} harmful actions: ${n("deny")} denied, ${n("ask")} asked, ${n("queue")} held in the queue; ${ran === 0 ? "none ran without a person" : `${ran} ran without a person`}.`);
  if (missed > 0) lines.push(`${missed} did not reach the verdict expected (MISSED above).`);
  return lines.join("\n");
}
