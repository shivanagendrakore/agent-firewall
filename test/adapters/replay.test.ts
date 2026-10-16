/**
 * Adapter acceptance: the incident scenarios and the friction corpus, replayed
 * through each adapter, give the same decisions as through the Claude Code
 * adapter wherever the agent has the capability. An agent whose hook protocol
 * cannot ask the person (Codex, Gemini CLI, Cursor) holds the action instead of
 * asking (the adapters' coverage says so).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adapterFor } from "../../src/adapters/index.js";
import type { AgentId } from "../../src/adapters/types.js";
import { expectedFor, runScenarioAs, toNative } from "../../src/agent-replay.js";
import { ALWAYS_FINE, TOOL_CASES, TRUSTED_ONLY, V02_FINE } from "../../src/corpus.js";
import { SCENARIOS } from "../../src/scenarios.js";
import { testRoot } from "../helpers.js";
import { box, send, verdict, type Box } from "./harness.js";

const AGENTS: AgentId[] = ["codex", "gemini", "cursor"];

describe("incident scenarios: same decisions through every adapter", () => {
  for (const s of SCENARIOS) {
    const claude = runScenarioAs("claude", s, testRoot());
    for (const agent of AGENTS) {
      const r = runScenarioAs(agent, s, testRoot());
      if ("notApplicable" in r) {
        it.skip(`${agent} ${s.id}: not applicable (${r.notApplicable})`, () => undefined);
        continue;
      }
      it(`${agent} ${s.id}: ${s.title}`, () => {
        if ("notApplicable" in claude) throw new Error("the Claude Code replay must always apply");
        const ask = adapterFor(agent).supportsAsk;
        expect(r.results.length).toBe(claude.results.length);
        r.results.forEach((x, i) => {
          const c = claude.results[i];
          if (c === undefined) throw new Error("step missing");
          expect(x.verdict, `${s.id} step ${x.step} (${x.tool}; Claude Code ${c.tool} was ${c.verdict} [${c.rules.join(",")}], ${agent} [${x.rules.join(",")}])`).toBe(expectedFor(agent, c.verdict, ask));
          if (x.expect !== undefined) {
            expect(x.expect.map((v) => expectedFor(agent, v, ask))).toContain(x.verdict);
            if (x.rule !== undefined) expect(x.rules, `${s.id} step ${x.step}`).toContain(x.rule);
          }
        });
      });
    }
  }
});

describe("friction corpus: normal work is never interrupted, through every adapter", () => {
  for (const agent of AGENTS) {
    describe(agent, () => {
      let b: Box;
      let untrusted: Box;
      let untrustedFetch: Record<string, unknown> = {};
      let n = 0;
      /** Every case in its own session, like the Claude Code friction gate (a case never inherits another's state). */
      const fresh = (bx: Box, event: Record<string, unknown>): ReturnType<typeof send> => {
        const session_id = `f${++n}`;
        if (bx === untrusted) send(bx, agent, { ...untrustedFetch, session_id });
        return send(bx, agent, { ...event, session_id });
      };
      beforeAll(() => {
        b = box();
        untrusted = box();
        const fetch = toNative(agent, { hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: { url: "https://blog.example.org/post", prompt: "read" }, tool_response: "(outside content placeholder)" });
        if (fetch === null) throw new Error("no fetch");
        untrustedFetch = fetch;
      });
      afterAll(() => {
        b.cleanup();
        untrusted.cleanup();
      });
      const pre = (tool: string, input: Record<string, unknown>): Record<string, unknown> => {
        const e = toNative(agent, { hook_event_name: "PreToolUse", permission_mode: "default", tool_name: tool, tool_input: input });
        if (e === null) throw new Error(`${tool} has no ${agent} equivalent`);
        return e;
      };
      for (const c of [...ALWAYS_FINE, ...V02_FINE]) {
        it(`trusted and untrusted: ${c}`, () => {
          expect(verdict(agent, fresh(b, pre("Bash", { command: c })))).toBe("allow");
          expect(verdict(agent, fresh(untrusted, pre("Bash", { command: c })))).toBe("allow");
        });
      }
      for (const c of TRUSTED_ONLY) it(`trusted: ${c}`, () => expect(verdict(agent, fresh(b, pre("Bash", { command: c })))).toBe("allow"));
      for (const c of TOOL_CASES) {
        const fill = (v: unknown): unknown => (typeof v === "string" ? v.replaceAll("{WS}", b.ws) : typeof v === "object" && v !== null ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x)])) : v);
        const input = (): Record<string, unknown> => fill(c.input) as Record<string, unknown>;
        const native = toNative(agent, { hook_event_name: "PreToolUse", tool_name: c.tool, tool_input: c.input });
        if (native === null) it.skip(`${c.tool}: no ${agent} equivalent`, () => undefined);
        else it(`tool ${c.tool} ${JSON.stringify(c.input).slice(0, 50)}`, () => expect(verdict(agent, fresh(b, pre(c.tool, input())))).toBe("allow"));
      }
    });
  }
});
