/**
 * LR12: a server-to-client request (elicitation/create, sampling/createMessage, roots/list) is passed to the
 * client only once its log entry is recorded. When the decision log refuses the entry and its fallback
 * entry, the server's legacy request is answered with an error, a 2026-07-28 input request ends the call
 * with a refusal, and why goes to the diagnostics (stderr). Temporary homes only; no network.
 */

import { appendFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Json, Message } from "../../src/gateway/jsonrpc.js";
import { MAX_TAIL_SEARCH } from "../../src/runtime/log.js";
import type { Layout } from "../../src/runtime/layout.js";
import { gw, NOTES_TOOLS, textOf } from "./harness.js";

const breakLog = (l: Layout): void => appendFileSync(join(l.log, "decisions.jsonl"), `${"q".repeat(MAX_TAIL_SEARCH + 5)}\n`);

const LEGACY_REQUESTS: Json[] = [
  { method: "roots/list" },
  { method: "elicitation/create", params: { message: "Pick one", requestedSchema: { type: "object", properties: {} } } },
  { method: "sampling/createMessage", params: { messages: [], maxTokens: 1 } },
];

describe("LR12: input requests are not passed on unrecorded", () => {
  for (const req of LEGACY_REQUESTS) {
    it(`legacy ${String(req.method)}: passed on when recorded, answered with an error when the log refuses it`, () => {
      // Sampling is allowed by policy here so that only the log decides.
      const g = gw({ cfg: { era: "legacy", tools: NOTES_TOOLS }, clientEra: "legacy", policy: { gateway: { sampling: "allow" } } });
      const toClient = (id: string): Message | undefined => g.inbox.find((m) => "method" in m && "id" in m && m.id === id);
      const answer = (id: string): Json | undefined => g.up.received.find((m) => m.id === id && m.method === undefined);

      g.core.fromUpstream({ jsonrpc: "2.0", id: "srv-ok", ...req } as Message);
      expect(toClient("srv-ok")).toBeDefined();

      breakLog(g.l);
      g.core.fromUpstream({ jsonrpc: "2.0", id: "srv-x", ...req } as Message);
      expect(toClient("srv-x")).toBeUndefined();
      const err = answer("srv-x")?.error as Json | undefined;
      expect(String(err?.message)).toMatch(/FW-LOG-UNRECORDED/);
      expect(g.diag.join("\n")).toMatch(new RegExp(`refused the ${String(req.method)} request.*FW-LOG-UNRECORDED`));
    });
  }

  it("2026-07-28 roots/list input request: the call ends with a refusal naming FW-LOG-UNRECORDED", () => {
    const g = gw({ cfg: { era: "modern", tools: [{ name: "search", description: "Search.", inputSchema: { type: "object" } }], inputRequired: { search: { resultType: "input_required", inputRequests: { r1: { method: "roots/list", params: {} } }, requestState: "abc" } } } });
    g.call("tools/list");
    const ok = g.call("tools/call", { name: "search", arguments: { q: "a" } });
    expect(ok.result?.inputRequests).toBeDefined();
    breakLog(g.l);
    const r = g.call("tools/call", { name: "search", arguments: { q: "b" } });
    expect(r.result?.inputRequests).toBeUndefined();
    expect(r.result?.isError).toBe(true);
    expect(textOf(r)).toMatch(/FW-LOG-UNRECORDED/);
  });
});
