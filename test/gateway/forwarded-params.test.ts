/**
 * A decided request forwards `_meta`, `task` and `inputResponses`, which the engine does not read. Inside
 * them only what the protocol defines goes on: the progress token and the modern protocol keys in `_meta`, the
 * ttl of `task`, and in `inputResponses` only answers to input requests the gateway passed on for this call,
 * each with only its method's result fields. Anything else is dropped and logged, never forwarded unread.
 */
import { describe, expect, it } from "vitest";
import type { Json, Response } from "../../src/gateway/jsonrpc.js";
import { tailLog } from "../../src/runtime/log.js";
import { gw, MODERN, type Gw } from "./harness.js";

const SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const MODERN_META = { "io.modelcontextprotocol/protocolVersion": MODERN, "io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/clientInfo": { name: "test-client", version: "1.0" } };

function elicitingServer(): Gw {
  return gw({
    server: "web-search",
    cfg: {
      era: "modern",
      tools: [{ name: "search", description: "Search.", inputSchema: { type: "object" } }],
      inputRequired: { search: { resultType: "input_required", inputRequests: { e1: { method: "elicitation/create", params: { mode: "form", message: "Which account?", requestedSchema: { type: "object", properties: { account: { type: "string" } } } } } }, requestState: "abc" } },
    },
  });
}

/** A client request with a `_meta` of its own (the harness's call() replaces `_meta`). */
function raw(g: Gw, id: number, params: Json): Response {
  g.core.fromClient({ jsonrpc: "2.0", id, method: "tools/call", params });
  const r = g.inbox.find((m) => "id" in m && m.id === id && !("method" in m));
  if (r === undefined) throw new Error("no answer");
  return r as Response;
}

const dropLog = (g: Gw): string => tailLog(g.l, 100).filter((e) => e.event.type === "gateway_protocol").map((e) => String(e.event.problem)).join("\n");

describe("forwarded parameters inside _meta, task and inputResponses", () => {
  it("only the answer to the input request passed on, with its result fields, and only the defined _meta and task keys reach the server", () => {
    const g = elicitingServer();
    g.call("tools/list");
    const first = g.call("tools/call", { name: "search", arguments: { q: "x" } });
    expect(first.result?.resultType).toBe("input_required");
    raw(g, 1000, {
      name: "search",
      arguments: { q: "x" },
      requestState: "abc",
      inputResponses: { e1: { action: "accept", content: { account: "work" }, smuggled: SECRET }, e2: { action: "accept", content: { stolen: SECRET } } },
      _meta: { ...MODERN_META, progressToken: "p-1", "com.example/notes": SECRET },
      task: { ttl: 60000, label: SECRET },
    });
    const sent = g.received("tools/call") as Json;
    const p = sent.params as Json;
    expect(p.inputResponses).toEqual({ e1: { action: "accept", content: { account: "work" } } });
    expect(p.task).toEqual({ ttl: 60000 });
    expect((p._meta as Json).progressToken).toBe("p-1");
    expect(Object.keys(p._meta as Json).sort()).toEqual([...Object.keys(MODERN_META), "progressToken"].sort());
    expect(JSON.stringify(sent)).not.toContain(SECRET);
    const log = dropLog(g);
    expect(log).toMatch(/inputResponses\.e1\.smuggled/);
    expect(log).toMatch(/inputResponses\.e2/);
    expect(log).toMatch(/_meta\.com\.example\/notes/);
    expect(log).toMatch(/task\.label/);
  });

  it("inputResponses on a call the gateway passed no input request for are dropped whole; a long or structured progress token is dropped", () => {
    const g = gw({ server: "web-search", cfg: { era: "modern", tools: [{ name: "search", description: "Search.", inputSchema: { type: "object" } }] } });
    g.call("tools/list");
    raw(g, 2000, { name: "search", arguments: { q: "y" }, inputResponses: { a: { action: "accept", content: { k: SECRET } } }, _meta: { ...MODERN_META, progressToken: { nested: SECRET } } });
    const p = (g.received("tools/call") as Json).params as Json;
    expect(p.inputResponses).toBeUndefined();
    expect((p._meta as Json).progressToken).toBeUndefined();
    raw(g, 2001, { name: "search", arguments: { q: "y" }, _meta: { ...MODERN_META, progressToken: "x".repeat(300) } });
    expect((((g.received("tools/call") as Json).params as Json)._meta as Json).progressToken).toBeUndefined();
    raw(g, 2002, { name: "search", arguments: { q: "y" }, _meta: { ...MODERN_META, progressToken: 7 } });
    expect((((g.received("tools/call") as Json).params as Json)._meta as Json).progressToken).toBe(7);
  });

  it("an answer for another call's input request is not carried by this one (the keys are per call)", () => {
    const g = elicitingServer();
    g.call("tools/list");
    g.call("tools/call", { name: "search", arguments: { q: "x" } });
    raw(g, 3000, { name: "search", arguments: { q: "other" }, requestState: "abc", inputResponses: { e1: { action: "accept", content: { account: SECRET } } }, _meta: MODERN_META });
    const p = (g.received("tools/call") as Json).params as Json;
    expect(p.inputResponses).toBeUndefined();
    expect(p.requestState).toBeUndefined();
  });

  it("an unissued or altered requestState is dropped, and forwarded inputResponses are inspected by the engine", () => {
    const g = elicitingServer();
    g.call("tools/list");
    raw(g, 4000, { name: "search", arguments: { q: "clean" }, requestState: SECRET, _meta: MODERN_META });
    const p = (g.received("tools/call") as Json).params as Json;
    expect(p.requestState).toBeUndefined();
    expect(dropLog(g)).toMatch(/requestState/);

    const first = g.call("tools/call", { name: "search", arguments: { q: "x" } });
    expect(first.result?.resultType).toBe("input_required");
    const before = g.up.received.filter((m) => m.method === "tools/call").length;
    const denied = raw(g, 4001, {
      name: "search",
      arguments: { q: "x" },
      requestState: "abc",
      inputResponses: { e1: { action: "accept", content: { account: SECRET } } },
      _meta: MODERN_META,
    });
    expect(denied.result?.isError).toBe(true);
    expect(JSON.stringify(denied.result)).toContain("FW-DLP-CREDENTIAL");
    expect(g.up.received.filter((m) => m.method === "tools/call")).toHaveLength(before);
  });
});
