/**
 * context.traffic "network" skips the toolCalls limit, the agent-wide monitor and agent stops, so the API takes
 * it only from a network middleware's token (`api token add <agentId> --traffic network`) and only for the
 * middleware's request shape (an engine-format HttpRequest, or the unreadable wrapper of one).
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { translateDecide } from "../../src/api/contract.js";
import { tokensPath } from "../../src/api/files.js";
import { middlewareDecideContext } from "../../src/api/request.js";
import type { ApiServer } from "../../src/api/server.js";
import { readTokens } from "../../src/api/tokens.js";
import { NETWORK_REFUSED_TOOL, UNPARSEABLE_TOOL } from "../../src/engine/classify.js";
import { readCounters } from "../../src/runtime/counters.js";
import { verifyLog } from "../../src/runtime/log.js";
import { agent, apiTree, call, removeApiTree, startServer, type ApiTree } from "./harness.js";

const NET = middlewareDecideContext(true);
const HTTP = { format: "engine", tool: "HttpRequest", input: { url: "https://docs.example.com/p", method: "GET" } };
const logText = (t: ApiTree): string => (existsSync(join(t.l.log, "decisions.jsonl")) ? readFileSync(join(t.l.log, "decisions.jsonl"), "utf8") : "");
/** What the OpenShell middleware sends for a request it refused before asking (src/openshell/middleware.ts, refused()). */
const REFUSED = { format: "engine", tool: NETWORK_REFUSED_TOOL, input: { url: "https://api.partner.example/x", method: "GET", code: "launchsafe_deny_host_mismatch", reason: "the Host header names evil.example, not the target" } };

describe("the contract: traffic network only for the middleware's shape", () => {
  it("an engine HttpRequest and the unreadable wrapper of one are accepted", () => {
    expect(translateDecide({ session: "s", action: HTTP, context: NET }, []).ok).toBe(true);
    const wrapped = translateDecide({ session: "s", action: { format: "engine", tool: UNPARSEABLE_TOOL, input: { tool: "HttpRequest", reason: "GET x with a body" } }, context: NET }, []);
    expect(wrapped.ok && wrapped.traffic).toBe("network");
  });
  it("the middleware's record of a request it refused is accepted as network traffic", () => {
    const t = translateDecide({ session: "s", action: REFUSED, context: NET }, []);
    expect(t.ok, t.ok ? "" : t.detail).toBe(true);
    expect(t.ok && t.call.tool).toBe(NETWORK_REFUSED_TOOL);
  });
  it("the refusal record is refused as anything but network traffic: no agent can write middleware refusals into its own log", () => {
    for (const body of [
      { session: "s", action: REFUSED },
      { session: "s", action: REFUSED, context: { traffic: "tool" } },
      { session: "s", action: { format: "native", tool: NETWORK_REFUSED_TOOL, input: REFUSED.input } },
      { session: "s", action: { format: "anthropic", raw: { type: "tool_use", id: "t1", name: NETWORK_REFUSED_TOOL, input: REFUSED.input } } },
    ]) {
      const t = translateDecide(body, [NETWORK_REFUSED_TOOL]);
      expect(t.ok, JSON.stringify(body)).toBe(false);
      if (!t.ok) {
        expect(t.status).toBe(400);
        expect(t.detail).toMatch(/only with context\.traffic "network"/);
      }
    }
  });
  it("a Bash call, another tool's wrapper, or another format is refused", () => {
    for (const action of [
      { format: "engine", tool: "Bash", input: { command: "curl https://x.example" } },
      { format: "engine", tool: "WebFetch", input: { url: "https://x.example" } },
      { format: "engine", tool: UNPARSEABLE_TOOL, input: { tool: "Bash", reason: "no command" } },
      { format: "native", tool: "HttpRequest", input: { url: "https://x.example" } },
      { format: "mcp", tool: "HttpRequest", input: {}, mcp: { server: "net" } },
    ]) {
      const t = translateDecide({ session: "s", action, context: NET }, ["HttpRequest"]);
      expect(t.ok, JSON.stringify(action)).toBe(false);
      if (!t.ok) expect(t.detail).toMatch(/only for a network middleware's request/);
    }
  });
});

describe("the token store keeps a middleware token's traffic", () => {
  let t: ApiTree;
  beforeEach(() => {
    t = apiTree();
  });
  afterEach(() => removeApiTree(t));

  it("stored and read back; an unknown value is a damaged file", () => {
    agent(t, "openshell", null, "network");
    agent(t, "bot", null);
    expect(readTokens(t.l).map((r) => [r.agent, r.traffic])).toEqual([
      ["openshell", "network"],
      ["bot", undefined],
    ]);
    const f = JSON.parse(readFileSync(tokensPath(t.l), "utf8")) as { tokens: { traffic?: string }[] };
    (f.tokens[1] as { traffic?: string }).traffic = "everything";
    writeFileSync(tokensPath(t.l), JSON.stringify(f));
    expect(() => readTokens(t.l)).toThrow(/damaged/);
  });
});

describe("the local API binds traffic network to the middleware's token", () => {
  let t: ApiTree;
  let s: ApiServer;
  let plain: string;
  let net: string;
  beforeEach(async () => {
    t = apiTree();
    mkdirSync(t.l.home, { recursive: true, mode: 0o700 });
    writeFileSync(t.l.policy, JSON.stringify({ version: 3, fetchAllowHosts: ["docs.example.com"], caps: { enabled: true, session: { toolCalls: 1 } } }));
    plain = agent(t, "bot", null);
    net = agent(t, "openshell", null, "network");
    s = await startServer(t);
  });
  afterEach(async () => {
    await s.close();
    removeApiTree(t);
  });

  it("a Bash call declared as network traffic is refused, from either token", async () => {
    for (const token of [plain, net]) {
      const r = await call(s, { path: "/v1/decide", token, body: { session: "x", action: { format: "engine", tool: "Bash", input: { command: "ls" } }, context: NET } });
      expect(r.status, JSON.stringify(r.body)).toBe(400);
      expect(String(r.body.detail)).toMatch(/traffic/);
    }
  });

  it("an HttpRequest declared as network traffic from an ordinary token is refused", async () => {
    const r = await call(s, { path: "/v1/decide", token: plain, body: { session: "x", action: HTTP, context: NET } });
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(String(r.body.detail)).toMatch(/--traffic network/);
    // Nothing was decided or counted.
    expect(readCounters(t.l, "bot/x").counters.caps?.totals.calls ?? 0).toBe(0);
  });

  it("a refusal record from an ordinary token is a 400, with or without traffic network, and nothing is logged", async () => {
    const before = logText(t);
    for (const body of [{ session: "x", action: REFUSED }, { session: "x", action: REFUSED, context: NET }]) {
      const r = await call(s, { path: "/v1/decide", token: plain, body });
      expect(r.status, JSON.stringify(r.body)).toBe(400);
    }
    expect(logText(t)).toBe(before);
  });

  it("from the middleware's token, a refusal record is decided (deny, FW-NET-REFUSED) and its signed log entry says so", async () => {
    const r = await call(s, { path: "/v1/decide", token: net, body: { session: "sbx", action: REFUSED, context: NET } });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.verdict).toBe("deny");
    expect(((r.body.rules ?? []) as { id: string }[]).map((x) => x.id)).toEqual(["FW-NET-REFUSED"]);
    expect(verifyLog(t.l)).toMatchObject({ ok: true });
    const last = JSON.parse(readFileSync(join(t.l.log, "decisions.jsonl"), "utf8").trim().split("\n").pop() as string) as { event: Record<string, unknown> };
    expect(last.event).toMatchObject({ type: "decision", session: "openshell/sbx", tool: NETWORK_REFUSED_TOOL, verdict: "deny", rules: ["FW-NET-REFUSED"], traffic: "network" });
  });

  it("from the middleware's token it is accepted, not counted, and the signed log says so", async () => {
    for (let i = 0; i < 3; i++) {
      const r = await call(s, { path: "/v1/decide", token: net, body: { session: "sbx", action: HTTP, context: NET } });
      expect(r.status, JSON.stringify(r.body)).toBe(200);
      expect(((r.body.rules ?? []) as { id: string }[]).map((x) => x.id)).not.toContain("FW-CAP");
    }
    expect(readCounters(t.l, "openshell/sbx").counters.caps?.totals.calls ?? 0).toBe(0);
    expect(readCounters(t.l, "agent:openshell").counters.caps?.totals.calls ?? 0).toBe(0);
    expect(verifyLog(t.l)).toMatchObject({ ok: true });
    const last = JSON.parse(readFileSync(join(t.l.log, "decisions.jsonl"), "utf8").trim().split("\n").pop() as string) as { event: Record<string, unknown> };
    expect(last.event).toMatchObject({ type: "decision", session: "openshell/sbx", traffic: "network" });
  });
});
