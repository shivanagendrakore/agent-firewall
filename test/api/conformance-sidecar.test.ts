/**
 * Every conformance vector (conformance/README.md) against the sidecar over a real unix socket: one fresh
 * firewall home, agent and server per vector, its registry set as `api tools set` sets it, in the reference
 * environment (home /home/agent, no scratch, no file access, the default policy, the fixed clock). An
 * `approve` step is the person's approval in the firewall's queue (what `queue approve` does). A vector with
 * `setup` runs in its prepared tree (conformance/setup.ts): the server's firewall home is the tree's (with the
 * setup's policy and decoys), its home is the tree's home, and it has file access, as the hook has.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { pinEnvironment, REFERENCE, type Expect, type Step, type Vector } from "../../conformance/run.js";
import { dispose, prepare, substitute, type Prepared } from "../../conformance/setup.js";
import { addToken } from "../../src/api/tokens.js";
import { serverNameProblem, trustedSource, writeRegistry } from "../../src/api/registry.js";
import { startApiServer } from "../../src/api/server.js";
import { approvalSigner, initApprover, unlockApprover } from "../../src/runtime/approver.js";
import { decideQueueItem } from "../../src/runtime/store.js";
import { REPO } from "../helpers.js";
import { apiTree, call, removeApiTree } from "./harness.js";

const dir = join(REPO, "conformance", "vectors");
const vectors: Vector[] = readdirSync(dir)
  .filter((f) => f.endsWith(".json"))
  .sort()
  .flatMap((f) => JSON.parse(readFileSync(join(dir, f), "utf8")) as Vector[]);

const PASS = "conformance passphrase";
const ENDPOINT = { result: "results", input: "inputs", prompt: "prompts" } as const;

async function runOverSocket(vector: Vector): Promise<Expect[]> {
  const t = apiTree();
  let p: Prepared | undefined;
  try {
    p = vector.setup !== undefined ? prepare(vector.setup) : undefined;
  } catch (e) {
    removeApiTree(t);
    throw e;
  }
  const v = p !== undefined ? { ...vector, steps: substitute(vector.steps, p) } : vector;
  const l = p?.l ?? t.l;
  const needsApprover = v.steps.some((s) => s.kind === "approve");
  if (needsApprover) initApprover(l, PASS);
  // I2: the sidecar honours a trusted MCP source (user, sdk) only for a server the person registered with it; the
  // vectors' sources stand for the person's configuration, so their servers are registered as the person would.
  const mcpServers: Record<string, { source: string }> = {};
  for (const step of v.steps) {
    // A request may be any JSON (the invalid-body-* vectors send null and an array).
    const a = step.kind === "decide" ? (step.request as { action?: { format?: unknown; mcp?: { server?: unknown; source?: unknown } } } | null)?.action : undefined;
    const server = a?.mcp?.server;
    const source = a?.mcp?.source;
    if (a?.format === "mcp" && typeof server === "string" && typeof source === "string" && trustedSource(source) && serverNameProblem(server) === null && /^[A-Za-z][A-Za-z0-9_-]{0,31}$/.test(source) && !Object.hasOwn(mcpServers, server)) mcpServers[server] = { source };
  }
  writeRegistry(l, REFERENCE.agent, Object.keys(mcpServers).length > 0 ? { ...(v.agentTools as object), mcpServers } : v.agentTools);
  // The vectors' prompts are the person's (the library applies them): tokens with the prompt role (I1).
  const roles = ["decide", "report", "prompt"] as const;
  const agentToken = addToken(l, REFERENCE.agent, new Date(REFERENCE.now), undefined, roles);
  // The agent's network middleware's token (`api token add <agentId> --traffic network`), for steps with token "network".
  const networkToken = addToken(l, REFERENCE.agent, new Date(REFERENCE.now), "network", roles);
  const tokenOf = (s: Step): string => (s.token === "network" ? networkToken : agentToken);
  const token = agentToken;
  const s = await startApiServer({ l, env: {}, home: p?.home ?? REFERENCE.home, scratch: [], fileAccess: p !== undefined, now: () => new Date(REFERENCE.now), socket: join(t.sockDir, "api.sock") });
  const decisions = new Map<number, Record<string, unknown>>();
  const ref = (x: unknown): unknown => {
    const m = typeof x === "string" ? /^@step:(\d+)$/.exec(x) : null;
    return m === null ? x : decisions.get(Number(m[1]))?.decisionId;
  };
  const sessionFlags = async (session: string): Promise<Pick<Expect, "sessionUntrusted" | "holdsPrivateData">> => {
    const g = await call(s, { path: `/v1/sessions/${encodeURIComponent(session)}`, token });
    return { sessionUntrusted: g.body.untrusted as boolean, holdsPrivateData: g.body.holdsPrivateData as boolean };
  };
  const out: Expect[] = [];
  try {
    for (const [i, step] of v.steps.entries()) {
      if (step.kind === "decide") {
        const r = await call(s, { path: "/v1/decide", token: tokenOf(step), body: step.request });
        if (r.status === 400) {
          out.push({ error: 400 });
          continue;
        }
        expect(r.status, `${v.id} step ${i}: ${JSON.stringify(r.body)}`).toBe(200);
        decisions.set(i, r.body);
        const ids = [...new Set((r.body.rules as { id: string }[]).map((x) => x.id))].sort();
        const sess = r.body.session as { untrusted: boolean; holdsPrivateData: boolean };
        out.push({ verdict: r.body.verdict as Expect["verdict"], ruleIds: ids, ...(step.request.dryRun === true ? {} : { sessionUntrusted: sess.untrusted, holdsPrivateData: sess.holdsPrivateData }) });
        continue;
      }
      if (step.kind === "approve") {
        const d = decisions.get(Number(/^@step:(\d+)$/.exec(String(step.request.decisionId))?.[1]));
        const id = (d?.approval as { id?: string } | undefined)?.id;
        expect(id, `${v.id} step ${i}: the decision to approve has no queue item`).toBeDefined();
        const priv = unlockApprover(l, PASS);
        decideQueueItem(l, id as string, "approved", approvalSigner(priv));
        out.push({});
        continue;
      }
      // The session is the URL path in the API; a request without a usable one keeps it in the body (refused there).
      const { session, ...rest } = step.request;
      const usable = typeof session === "string" && session !== "";
      const body: Record<string, unknown> = usable ? rest : step.request;
      if ("decisionId" in body) body.decisionId = ref(body.decisionId);
      const path = `/v1/sessions/${encodeURIComponent(usable ? session : "_")}/${ENDPOINT[step.kind]}`;
      const r = await call(s, { path, token: tokenOf(step), body });
      if (r.status === 400) {
        out.push({ error: 400 });
        continue;
      }
      expect(r.status, `${v.id} step ${i}: ${JSON.stringify(r.body)}`).toBe(200);
      out.push({ ...(await sessionFlags(session as string)), ...(typeof r.body.output === "string" ? { redacted: r.body.output } : {}) });
    }
  } finally {
    await s.close();
    removeApiTree(t);
    if (p !== undefined) dispose(p);
  }
  return out;
}

describe("conformance vectors against the sidecar over its socket", () => {
  // The prepared environment's pins (conformance/README.md): variables that move agents' settings files are unset.
  let restore: () => void = () => undefined;
  beforeAll(() => {
    restore = pinEnvironment();
  });
  afterAll(() => restore());

  it("there are vectors to run", () => expect(vectors.length).toBeGreaterThanOrEqual(150));
  for (const v of vectors) {
    it(v.id, async () => {
      // The API's own answer where it differs from the library's by design (Step.expectApi).
      expect(await runOverSocket(v)).toEqual(v.steps.map((s) => s.expectApi ?? s.expect));
    });
  }
});
