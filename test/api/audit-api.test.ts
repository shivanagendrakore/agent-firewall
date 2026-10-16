/**
 * Audit fixes for the local API (I1, I2, I3, I9 and the minor items): each test fails without its fix.
 */

import { readFileSync, writeFileSync, mkdirSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ApiServer } from "../../src/api/server.js";
import { parseRoles, readTokens } from "../../src/api/tokens.js";
import { main } from "../../src/climain.js";
import { learnKey } from "../../src/engine/learn.js";
import { approvalSigner, initApprover, unlockApprover } from "../../src/runtime/approver.js";
import { allowHosts } from "../../src/runtime/knownhosts.js";
import { codeOf, projectId, saveEntry } from "../../src/runtime/learned.js";
import { decideQueueItem, getQueueItem, sessionFile } from "../../src/runtime/store.js";

const PASS = "correct horse battery staple";
import { agent, ALL_ROLES, apiTree, call, decideBody, REGISTRY, removeApiTree, startServer, type ApiTree } from "./harness.js";

function events(t: ApiTree, session: string): { type: string }[] {
  let text = "";
  try {
    text = readFileSync(sessionFile(t.l, session), "utf8");
  } catch {
    return [];
  }
  return text
    .split("\n")
    .filter((x) => x.trim() !== "")
    .map((x) => JSON.parse(x) as { type: string });
}

describe("I2: the person's registry pins MCP sources and workspace roots", () => {
  let t: ApiTree;
  let s: ApiServer;
  beforeEach(async () => {
    t = apiTree();
    s = await startServer(t);
  });
  afterEach(async () => {
    await s.close();
    removeApiTree(t);
  });
  const TIME = (source: string): Record<string, unknown> => ({ format: "mcp", tool: "get_time", input: {}, mcp: { server: "time", source } });

  it('a "user" source for a server the registry does not list is judged as "unknown" (its results are outside content)', async () => {
    const token = agent(t, "bot");
    const r = await call(s, { path: "/v1/decide", token, body: decideBody("m1", TIME("user")) });
    expect(r.status).toBe(200);
    expect(r.body.verdict).toBe("allow");
    expect((r.body.session as { untrusted: boolean }).untrusted).toBe(true);
    expect((r.body.problems as string[]).join("\n")).toMatch(/judged as "unknown"/);
  });

  it("a server the person registered as user keeps its source; one registered as project refuses a looser claim", async () => {
    const token = agent(t, "bot", { ...REGISTRY, mcpServers: { time: { source: "user" }, repo: { source: "project" } } });
    const ok = await call(s, { path: "/v1/decide", token, body: decideBody("m2", TIME("user")) });
    expect(ok.body.verdict).toBe("allow");
    expect((ok.body.session as { untrusted: boolean }).untrusted).toBe(false);
    expect(ok.body.problems).toBeUndefined();
    const bad = await call(s, { path: "/v1/decide", token, body: decideBody("m3", { format: "mcp", tool: "get_file", input: {}, mcp: { server: "repo", source: "user" } }) });
    expect(bad.status).toBe(403);
    expect(String(bad.body.detail)).toMatch(/lists MCP server repo as "project"/);
    // A stricter claim than the registry's is taken as it is.
    expect((await call(s, { path: "/v1/decide", token, body: decideBody("m4", { format: "mcp", tool: "get_file", input: {}, mcp: { server: "repo", source: "unknown" } }) })).status).toBe(200);
    // Omitted mcp.source and engine-format mcp__<server>__<tool> calls apply the registry's mcpServers source.
    const omitted = await call(s, { path: "/v1/decide", token, body: decideBody("m5", { format: "mcp", tool: "get_time", input: {}, mcp: { server: "time" } }) });
    expect(omitted.body.verdict).toBe("allow");
    expect((omitted.body.session as { untrusted: boolean }).untrusted).toBe(false);
    const engineMcp = await call(s, { path: "/v1/decide", token, body: decideBody("m6", { format: "engine", tool: "mcp__time__get_time", input: {} }) });
    expect(engineMcp.body.verdict).toBe("allow");
    expect((engineMcp.body.session as { untrusted: boolean }).untrusted).toBe(false);
  });

  it("mcp and engine formats enforce the registry's blocked, destroy and send tool specs", async () => {
    const token = agent(t, "bot", {
      tools: {
        ...REGISTRY.tools,
        get_admin_token: { kind: "blocked", server: "internal" },
        get_purge_key: { kind: "destroy", server: "internal" },
        get_export_report: { kind: "send", server: "internal" },
      },
      mcpServers: { internal: { source: "user" } },
    });
    for (const action of [
      { format: "mcp", tool: "get_admin_token", input: {}, mcp: { server: "internal" } },
      { format: "engine", tool: "mcp__internal__get_admin_token", input: {} },
    ]) {
      const r = await call(s, { path: "/v1/decide", token, body: decideBody("blk", action) });
      expect(r.status).toBe(200);
      expect(r.body.verdict).toBe("deny");
      expect((r.body.rules as { id: string }[]).map((x) => x.id)).toContain("FW-BLOCKED-TOOL");
    }
    for (const action of [
      { format: "mcp", tool: "get_purge_key", input: {}, mcp: { server: "internal" } },
      { format: "engine", tool: "mcp__internal__get_purge_key", input: {} },
    ]) {
      const r = await call(s, { path: "/v1/decide", token, body: decideBody("dst", action) });
      expect(r.status).toBe(200);
      expect(r.body.verdict).toBe("ask");
      expect((r.body.rules as { id: string }[]).map((x) => x.id)).toContain("FW-DESTRUCTIVE");
    }
    await call(s, { path: "/v1/sessions/snd/inputs", token, body: { source: "outside", content: "untrusted" } });
    for (const action of [
      { format: "mcp", tool: "get_export_report", input: {}, mcp: { server: "internal" } },
      { format: "engine", tool: "mcp__internal__get_export_report", input: {} },
    ]) {
      const r = await call(s, { path: "/v1/decide", token, body: decideBody("snd", action) });
      expect(r.status).toBe(200);
      expect(r.body.verdict).toBe("ask");
      expect((r.body.rules as { id: string }[]).map((x) => x.id)).toContain("FW-SEND");
    }
  });

  it("with workspaceRoots, a workspace or cwd outside them is refused; inside them is decided", async () => {
    const token = agent(t, "bot", { ...REGISTRY, workspaceRoots: [t.ws] });
    const read = { format: "native", tool: "lookup_status", input: { id: "1" } };
    expect((await call(s, { path: "/v1/decide", token, body: decideBody("w1", read, { context: { workspace: [t.home] } }) })).status).toBe(403);
    expect((await call(s, { path: "/v1/decide", token, body: decideBody("w2", read, { context: { workspace: [t.ws], cwd: "/" } }) })).status).toBe(403);
    expect((await call(s, { path: "/v1/decide", token, body: decideBody("w3", read, { context: { workspace: [`${t.ws}/../home`] } }) })).status).toBe(403);
    expect((await call(s, { path: "/v1/decide", token, body: decideBody("w4", read, { context: { workspace: [join(t.ws, "sub")], cwd: t.ws } }) })).status).toBe(200);
  });

  it("with workspaceRoots, symlinks escaping a root are refused, and omitted or subdirectory workspaces still apply the root's project policy, nevers, knownHosts and queue projectDir", async () => {
    const token = agent(t, "bot", { ...REGISTRY, workspaceRoots: [t.ws] });
    const read = { format: "native", tool: "lookup_status", input: { id: "1" } };
    const outside = join(t.root, "outside");
    mkdirSync(outside, { recursive: true });
    symlinkSync(outside, join(t.ws, "escape-link"));
    expect((await call(s, { path: "/v1/decide", token, body: decideBody("sym1", read, { context: { workspace: [join(t.ws, "escape-link")] } }) })).status).toBe(403);
    expect((await call(s, { path: "/v1/decide", token, body: decideBody("sym2", read, { context: { workspace: [join(t.ws, "escape-link", "sub")] } }) })).status).toBe(403);
    expect((await call(s, { path: "/v1/decide", token, body: decideBody("sym3", read, { context: { workspace: [t.ws], cwd: join(t.ws, "escape-link") } }) })).status).toBe(403);

    const sub = join(t.ws, "sub");
    mkdirSync(join(sub, ".git"), { recursive: true });
    writeFileSync(join(t.ws, ".launchsafe-firewall.json"), JSON.stringify({ version: 3, denyHosts: ["blocked-by-project.example"], knownHosts: { mode: "ask" } }));
    allowHosts(t.l, t.ws, ["approved-in-root.example"], "cli", new Date());
    const neverKey = learnKey({ tool: "Bash", input: { command: "echo never-here" } });
    saveEntry(t.l, {
      version: 1,
      id: codeOf(projectId(t.ws), neverKey),
      kind: "never",
      project: projectId(t.ws),
      key: neverKey,
      identity: "",
      tool: "Bash",
      summary: "echo never-here",
      rules: ["FW-UNKNOWN-TOOL"],
      approvals: 0,
      createdAt: new Date().toISOString(),
    });

    for (const [label, extra] of [
      ["omitted", {}],
      ["sub", { context: { workspace: [sub], cwd: sub } }],
    ] as const) {
      const deniedHost = await call(s, { path: "/v1/decide", token, body: decideBody(`dh-${label}`, { format: "native", tool: "http_get", input: { url: "https://blocked-by-project.example/x" } }, extra) });
      expect(deniedHost.status).toBe(200);
      expect(deniedHost.body.verdict).toBe("deny");
      expect((deniedHost.body.rules as { id: string }[]).map((x) => x.id)).toContain("FW-CAPTURE-HOST");

      const allowedHost = await call(s, { path: "/v1/decide", token, body: decideBody(`ah-${label}`, { format: "native", tool: "http_get", input: { url: "https://approved-in-root.example/x" } }, extra) });
      expect(allowedHost.status).toBe(200);
      expect(allowedHost.body.verdict).toBe("allow");

      const neverRes = await call(s, { path: "/v1/decide", token, body: decideBody(`nv-${label}`, { format: "native", tool: "run_shell", input: { cmd: "echo never-here" } }, extra) });
      expect(neverRes.status).toBe(200);
      expect(neverRes.body.verdict).toBe("deny");
      expect((neverRes.body.rules as { id: string }[]).map((x) => x.id)).toContain("FW-LEARNED-DENY");
    }

    const held = await call(s, { path: "/v1/decide", token, body: decideBody("hold-sub", { format: "native", tool: "delete_account", input: { id: "1" } }, { context: { attended: false, workspace: [sub], cwd: sub } }) });
    expect(held.body.verdict).toBe("hold");
    const id = (held.body.approval as { id: string }).id;
    expect(getQueueItem(t.l, id)?.projectDir).toBe(t.ws);
  });

  it("the registry refuses a bad server name, source or root", () => {
    expect(() => agent(t, "bot", { ...REGISTRY, mcpServers: { crm_: { source: "user" } } })).toThrow(/cannot end with "_"/);
    expect(() => agent(t, "bot", { ...REGISTRY, mcpServers: { a__b: { source: "user" } } })).toThrow(/"__"/);
    expect(() => agent(t, "bot", { ...REGISTRY, mcpServers: { crm: { source: "" } } })).toThrow(/source/);
    expect(() => agent(t, "bot", { ...REGISTRY, workspaceRoots: ["relative"] })).toThrow(/absolute/);
  });
});

describe("I3 and I9: policy errors and approvals bound to the request's context", () => {
  let t: ApiTree;
  let s: ApiServer;
  beforeEach(async () => {
    t = apiTree();
    s = await startServer(t);
  });
  afterEach(async () => {
    await s.close();
    removeApiTree(t);
  });

  it("I3: an unreadable policy file is FW-POLICY-ERROR on risky calls, and every decision's problems say why", async () => {
    const token = agent(t, "bot");
    mkdirSync(t.l.home, { recursive: true });
    writeFileSync(t.l.policy, "{ this is not json");
    const r = await call(s, { path: "/v1/decide", token, body: decideBody("pe", { format: "engine", tool: "Bash", input: { command: "ls" } }) });
    expect(r.status).toBe(200);
    expect(r.body.verdict).toBe("ask");
    expect((r.body.rules as { id: string }[]).map((x) => x.id)).toContain("FW-POLICY-ERROR");
    expect((r.body.problems as string[]).join("\n")).toMatch(/policy problem/);
  });

  it("I9: a held call approved under one cwd is not allowed under another; under its own it is, once", async () => {
    initApprover(t.l, PASS);
    const token = agent(t, "bot");
    const del = { format: "native", tool: "delete_account", input: { id: "42" } };
    const ctx = (cwd: string): Record<string, unknown> => ({ context: { attended: false, workspace: [t.ws], cwd } });
    const held = await call(s, { path: "/v1/decide", token, body: decideBody("ap", del, ctx(t.ws)) });
    expect(held.body.verdict).toBe("hold");
    const id = (held.body.approval as { id: string }).id;
    const priv = unlockApprover(t.l, PASS);
    decideQueueItem(t.l, id, "approved", approvalSigner(priv));
    const elsewhere = await call(s, { path: "/v1/decide", token, body: decideBody("ap", del, ctx(join(t.ws, "other"))) });
    expect(elsewhere.body.verdict).toBe("hold");
    expect((elsewhere.body.rules as { id: string }[]).map((x) => x.id)).not.toContain("FW-APPROVED");
    const here = await call(s, { path: "/v1/decide", token, body: decideBody("ap", del, ctx(t.ws)) });
    expect(here.body.verdict).toBe("allow");
    expect((here.body.rules as { id: string }[]).map((x) => x.id)).toContain("FW-APPROVED");
    expect((await call(s, { path: "/v1/decide", token, body: decideBody("ap", del, ctx(t.ws)) })).body.verdict).toBe("hold");
  });
});

describe("CLI and token store: a person makes tokens and registries; reserved ids; revoke past a bad record", () => {
  let t: ApiTree;
  beforeEach(() => {
    t = apiTree();
  });
  afterEach(() => removeApiTree(t));
  async function cli(argv: string[], o: { human?: boolean; secret?: string } = {}): Promise<{ code: number; out: string; err: string }> {
    let out = "";
    let err = "";
    const code = await main(argv, t.l, { write: (fd, s) => void (fd === 1 ? (out += s) : (err += s)), humanAtKeyboard: async () => o.human ?? true, readSecret: async () => o.secret ?? "" });
    return { code, out, err };
  }

  it("token add and tools set need the approval passphrase when one is set", async () => {
    initApprover(t.l, PASS);
    expect((await cli(["api", "token", "add", "bot"], { secret: "wrong" })).code).toBe(1);
    expect(readTokens(t.l)).toEqual([]);
    const ok = await cli(["api", "token", "add", "bot", "--role", "decide,prompt"], { secret: PASS });
    expect(ok.code, ok.err).toBe(0);
    expect(readTokens(t.l)[0]?.roles).toEqual(["decide", "prompt"]);
    const file = join(t.root, "tools.json");
    writeFileSync(file, JSON.stringify(REGISTRY));
    expect((await cli(["api", "tools", "set", "bot", file], { secret: "wrong" })).code).toBe(1);
    expect((await cli(["api", "tools", "set", "bot", file], { secret: PASS })).code).toBe(0);
    expect((await cli(["api", "token", "add", "bot", "--role", "admin"], { secret: PASS })).code).toBe(64);
  });

  it("M6: the firewall's own agent names are reserved, and ids differing only in case are one agent", async () => {
    expect((await cli(["api", "token", "add", "Claude"])).err).toMatch(/reserved/);
    expect((await cli(["api", "token", "add", "bot"])).code).toBe(0);
    const r = await cli(["api", "token", "add", "BOT"]);
    expect(r.code).toBe(64);
    expect(r.err).toMatch(/only in case/);
  });

  it("M8: revoke works past a damaged record, which it leaves as it was", async () => {
    agent(t, "bot", null);
    agent(t, "other", null);
    const file = join(t.l.home, "api", "tokens.json");
    const doc = JSON.parse(readFileSync(file, "utf8")) as { version: 1; tokens: Record<string, unknown>[] };
    doc.tokens.push({ agent: "broken", hash: "not-a-hash" });
    writeFileSync(file, JSON.stringify(doc));
    expect(() => readTokens(t.l)).toThrow(/damaged/);
    const r = await cli(["api", "token", "revoke", "bot"]);
    expect(r.code, r.err).toBe(0);
    const after = JSON.parse(readFileSync(file, "utf8")) as { tokens: { agent: string }[] };
    expect(after.tokens.map((x) => x.agent)).toEqual(["other", "broken"]);
  });
});

describe("I6: request limits", () => {
  let t: ApiTree;
  let s: ApiServer;
  afterEach(async () => {
    await s.close();
    removeApiTree(t);
  });

  it("past its burst an agent gets 429 with Retry-After; another agent is still answered", async () => {
    t = apiTree();
    s = await startServer(t, { limits: { perAgentPerSecond: 0.001, perAgentBurst: 2 } });
    const a = agent(t, "a");
    const b = agent(t, "b");
    const get = (token: string) => call(s, { path: "/v1/sessions/none", token });
    expect((await get(a)).status).toBe(404);
    expect((await get(a)).status).toBe(404);
    const third = await get(a);
    expect(third.status).toBe(429);
    expect(third.body.title).toBe("Too many requests");
    expect((await get(b)).status).toBe(404);
  });

  it("past the server's limit on requests in flight, 503 with Retry-After", async () => {
    t = apiTree();
    s = await startServer(t, { limits: { maxInFlight: 0 } });
    const r = await call(s, { path: "/v1/health" });
    expect(r.status).toBe(503);
  });
});

describe("minor: replayed holds, session caps, unauthenticated 500s", () => {
  let t: ApiTree;
  let s: ApiServer;
  afterEach(async () => {
    await s.close();
    removeApiTree(t);
  });

  it("a replayed hold reports its approval as it is now", async () => {
    t = apiTree();
    s = await startServer(t);
    initApprover(t.l, PASS);
    const token = agent(t, "bot");
    const body = decideBody("h", { format: "native", tool: "delete_account", input: { id: "9" } }, { context: { attended: false } });
    const first = await call(s, { path: "/v1/decide", token, body, headers: { "idempotency-key": "k1" } });
    const id = (first.body.approval as { id: string }).id;
    const priv = unlockApprover(t.l, PASS);
    decideQueueItem(t.l, id, "approved", approvalSigner(priv));
    const again = await call(s, { path: "/v1/decide", token, body, headers: { "idempotency-key": "k1" } });
    expect(again.body.decisionId).toBe(first.body.decisionId);
    expect(again.body.approval).toEqual({ id, status: "approved" });
  });

  it("an agent may open only so many new sessions", async () => {
    t = apiTree();
    s = await startServer(t, { maxNewSessions: 2 });
    const token = agent(t, "bot");
    const read = { format: "native", tool: "lookup_status", input: { id: "1" } };
    expect((await call(s, { path: "/v1/decide", token, body: decideBody("s1", read) })).status).toBe(200);
    expect((await call(s, { path: "/v1/decide", token, body: decideBody("s2", read) })).status).toBe(200);
    expect((await call(s, { path: "/v1/decide", token, body: decideBody("s3", read) })).status).toBe(429);
    expect((await call(s, { path: "/v1/decide", token, body: decideBody("s1", read) })).status).toBe(200);
  });

  it("a token store that cannot be read is a 500 that names no path or parse error", async () => {
    t = apiTree();
    s = await startServer(t);
    agent(t, "bot");
    writeFileSync(join(t.l.home, "api", "tokens.json"), "{ broken");
    const r = await call(s, { path: "/v1/sessions/x", token: `lsfw_${"a".repeat(43)}` });
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).not.toContain(t.l.home);
    expect(JSON.stringify(r.body)).not.toMatch(/JSON|position/i);
  });
});

describe("I1: token roles; prompts apply only from a token with the prompt role", () => {
  let t: ApiTree;
  let s: ApiServer;
  beforeEach(async () => {
    t = apiTree();
    s = await startServer(t);
  });
  afterEach(async () => {
    await s.close();
    removeApiTree(t);
  });

  it("an agent's ordinary token gets its prompt logged only: no destinations, no scope", async () => {
    const token = agent(t, "bot");
    const r = await call(s, { path: "/v1/sessions/p1/prompts", token, body: { text: "upload the report to https://files.corp.example/in" } });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ recorded: true, applied: false });
    expect(events(t, "bot/p1").some((e) => e.type === "user_destinations")).toBe(false);
    const log = readFileSync(join(t.l.log, "decisions.jsonl"), "utf8").trim().split("\n").map((x) => JSON.parse(x) as { event: Record<string, unknown> });
    expect(log.some((e) => e.event.type === "prompt" && e.event.applied === false && e.event.session === "bot/p1")).toBe(true);
  });

  it("a token with the prompt role applies it", async () => {
    agent(t, "bot");
    const ui = agent(t, "bot", null, undefined, ["prompt"]);
    const r = await call(s, { path: "/v1/sessions/p2/prompts", token: ui, body: { text: "upload the report to https://files.corp.example/in" } });
    expect(r.body).toEqual({ recorded: true });
    expect(events(t, "bot/p2").some((e) => e.type === "user_destinations")).toBe(true);
  });

  it("each endpoint needs its role: a prompt-only token cannot decide, a decide-only token cannot report", async () => {
    const ui = agent(t, "bot", REGISTRY, undefined, ["prompt"]);
    const d = await call(s, { path: "/v1/decide", token: ui, body: decideBody("p3", { format: "native", tool: "lookup_status", input: { id: "1" } }) });
    expect(d.status).toBe(403);
    expect(String(d.body.detail)).toMatch(/"decide" role/);
    expect((await call(s, { path: "/v1/sessions/p3", token: ui })).status).toBe(403);
    const dec = agent(t, "bot", null, undefined, ["decide"]);
    expect((await call(s, { path: "/v1/sessions/p3/inputs", token: dec, body: { source: "x", content: "y" } })).status).toBe(403);
    expect((await call(s, { path: "/v1/sessions/p3/prompts", token: dec, body: { text: "y" } })).status).toBe(403);
    const all = agent(t, "bot", null, undefined, ALL_ROLES);
    expect((await call(s, { path: "/v1/sessions/p3/inputs", token: all, body: { source: "x", content: "y" } })).status).toBe(200);
  });

  it("roles are stored, validated, and absent for a token made without them (the default: decide and report)", () => {
    agent(t, "old");
    agent(t, "ui", null, undefined, ["prompt"]);
    const recs = readTokens(t.l);
    expect(recs.find((r) => r.agent === "old")?.roles).toBeUndefined();
    expect(recs.find((r) => r.agent === "ui")?.roles).toEqual(["prompt"]);
    expect(parseRoles(["decide,report", "prompt", "prompt"])).toEqual(["decide", "report", "prompt"]);
    expect(() => parseRoles(["admin"])).toThrow(/not a role/);
    const file = join(t.l.home, "api", "tokens.json");
    const doc = JSON.parse(readFileSync(file, "utf8")) as { tokens: { roles?: unknown }[] };
    (doc.tokens[0] as { roles?: unknown }).roles = ["root"];
    mkdirSync(join(t.l.home, "api"), { recursive: true });
    writeFileSync(file, JSON.stringify(doc));
    expect(() => readTokens(t.l)).toThrow(/damaged/);
  });
});
