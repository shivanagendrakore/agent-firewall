/**
 * Gateway acceptance: every incident scenario whose tool steps are all MCP
 * calls is replayed through the gateway in full mode (one client session, each
 * server its own wrapped instance) and must give the hook's verdict, with
 * "ask" held in the queue as for any agent that cannot ask (the gateway queues
 * by default). Prompt steps have no gateway equivalent and are skipped; a
 * scenario with a native (non-MCP) tool step is not applicable.
 */
import { describe, expect, it } from "vitest";
import { expectedFor, runScenarioAs } from "../../src/agent-replay.js";
import { parseMcpTool } from "../../src/engine/mcp.js";
import { SCENARIOS } from "../../src/scenarios.js";
import type { Json } from "../../src/gateway/jsonrpc.js";
import { testRoot } from "../helpers.js";
import { gw, newHome, textOf, type Gw } from "./harness.js";

for (const s of SCENARIOS) {
  const tools = s.steps.map((st) => st.event).filter((e) => e.hook_event_name === "PreToolUse" || e.hook_event_name === "PostToolUse").map((e) => String(e.tool_name));
  const applicable = tools.length > 0 && tools.every((t) => parseMcpTool(t) !== null);
  if (!applicable) continue;
  describe(`gateway replay ${s.id}`, () => {
    it(s.title, () => {
      const claude = runScenarioAs("claude", s, testRoot());
      if ("notApplicable" in claude) throw new Error("the Claude Code replay always applies");
      const { l, home } = newHome();
      const gws = new Map<string, Gw>();
      const results: { verdict: string; rules: string }[] = [];
      s.steps.forEach((st) => {
        const e = st.event;
        if (e.hook_event_name !== "PreToolUse") return;
        const mcp = parseMcpTool(String(e.tool_name)) as { server: string; tool: string };
        let g = gws.get(mcp.server);
        if (g === undefined) {
          // The tool outputs are neutral placeholders: what taints is the server's policy, as in the hook.
          g = gw({ l, home, server: mcp.server, session: `replay-${s.id}`, cfg: { era: "modern", tools: [...new Set(tools.map((t) => parseMcpTool(t)).filter((x) => x?.server === mcp.server).map((x) => (x as { tool: string }).tool))].map((name) => ({ name, description: `${name}.`, inputSchema: { type: "object" } })) } });
          g.call("tools/list");
          gws.set(mcp.server, g);
        }
        const r = g.call("tools/call", { name: mcp.tool, arguments: e.tool_input as Json });
        const text = textOf(r);
        const verdict = r.result?.isError !== true ? "allow" : /blocked this/.test(text) ? "deny" : /held this/.test(text) ? "queue" : "deny";
        results.push({ verdict, rules: /\(rule ([A-Z0-9, -]+)\)\s*$/.exec(text)?.[1] ?? "" });
      });
      expect(results.length).toBe(claude.results.length);
      results.forEach((x, k) => {
        const c = claude.results[k];
        if (c === undefined) throw new Error("step missing");
        expect(x.verdict, `${s.id} step ${c.step} ${c.tool}: Claude Code ${c.verdict} [${c.rules.join(",")}], gateway [${x.rules}]`).toBe(expectedFor("cursor", c.verdict, false));
        if (c.rule !== undefined && x.verdict !== "allow") expect(x.rules).toContain(c.rule);
      });
    });
  });
}
