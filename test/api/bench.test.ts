/**
 * A latency micro-benchmark for POST /v1/decide over the unix socket (an allowed read and a send that asks,
 * each in its own session). It prints p50 and p95; it does not gate on them (machines and load differ).
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ApiServer } from "../../src/api/server.js";
import { agent, apiTree, call, removeApiTree, startServer, type ApiTree } from "./harness.js";

function pct(xs: number[], p: number): number {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))] as number;
}

describe("decide latency over the socket", () => {
  let t: ApiTree;
  let s: ApiServer;
  let token: string;
  beforeAll(async () => {
    t = apiTree();
    token = agent(t, "bench");
    s = await startServer(t);
  });
  afterAll(async () => {
    await s.close();
    removeApiTree(t);
  });

  for (const [name, action] of [
    ["engine Read in the workspace (allow)", { format: "engine", tool: "Read", input: { file_path: "/srv/app/src/index.ts" } }],
    ["native send_email (ask, queued)", { format: "native", tool: "send_email", input: { to: "a@b.example", body: "x" } }],
  ] as const) {
    it(name, async () => {
      const ms: number[] = [];
      for (let i = 0; i < 220; i++) {
        const body = { session: `b-${name.slice(0, 6)}`, action: { ...action, input: { ...action.input, n: i } }, context: { workspace: ["/srv/app"] } };
        const t0 = process.hrtime.bigint();
        const r = await call(s, { path: "/v1/decide", token, body });
        const dt = Number(process.hrtime.bigint() - t0) / 1e6;
        expect(r.status).toBe(200);
        if (i >= 20) ms.push(dt);
      }
      console.log(`[bench] decide over the socket, ${name}: p50 ${pct(ms, 50).toFixed(2)} ms, p95 ${pct(ms, 95).toFixed(2)} ms (n=${ms.length})`);
    }, 120_000);
  }
});
