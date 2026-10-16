/**
 * The gateway fixes for the review (V5, V8, V9, V10, V11, V12, V15, V22, V31,
 * V32, V34, V35): the edges and controls next to the review's own cases. Placeholders
 * only: Unicode tag characters encoding harmless words.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { GatewayCore } from "../../src/gateway/pipeline.js";
import type { Json, Message, Response } from "../../src/gateway/jsonrpc.js";
import { applyPlan, planWrap } from "../../src/gateway/clients.js";
import { checkClientHeaders } from "../../src/gateway/headers.js";
import { gatewayConfigs } from "../../src/gateway/install.js";
import { refreshTokens, secureEndpoint } from "../../src/gateway/oauth.js";
import { loadPolicy } from "../../src/runtime/config.js";
import { installDir, type Layout } from "../../src/runtime/layout.js";
import { listRecords } from "../../src/runtime/quarantine.js";
import { toolCallPins } from "../../src/runtime/pins.js";
import { bash, explain } from "../helpers.js";
import { gw, MODERN, newHome, textOf, writePolicy } from "./harness.js";

const TAG = (s: string): string => [...s].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join("");
const HIDDEN = TAG("placeholder hidden words");
const HAS_TAG = /[\u{E0000}-\u{E007F}]/u;
const TRUSTED_NOTES = { mcpServers: { notes: { results: "trusted", privateData: false } } };
const NOTES_TOOL = { name: "search", description: "Search your notes.", inputSchema: { type: "object", properties: { q: { type: "string" } } } };

/** A gateway whose upstream answers are written by the test (modern client and server). */
function rig(o: { policy?: Json; discover?: Json } = {}) {
  const { l, home } = newHome();
  if (o.policy !== undefined) writePolicy(l, o.policy);
  const ws = join(home, "ws");
  mkdirSync(ws, { recursive: true });
  const toClient: Message[] = [];
  const toUp: Message[] = [];
  const core = new GatewayCore(
    { l, env: {}, client: "claude-desktop", server: "notes", mode: "full", source: "user", pinSource: "gw-claude-desktop", session: () => "rv03fx", cwd: ws, workspaceRoots: [], transport: "stdio", home, detectNonInteractive: () => true, notifyDeps: { spawn: () => undefined }, setTimer: () => () => undefined, diag: () => undefined },
    { client: (m) => void toClient.push(m), upstream: (m) => void toUp.push(m) },
  );
  const meta = { _meta: { "io.modelcontextprotocol/protocolVersion": MODERN, "io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/clientInfo": { name: "test-client", version: "1.0" } } };
  let probed = false;
  const send = (id: number, method: string, params: Json = {}): void => {
    core.fromClient({ jsonrpc: "2.0", id, method, params: { ...params, ...meta } } as Message);
    if (!probed) {
      probed = true;
      const p = toUp.find((m) => "method" in m && m.method === "server/discover") as { id: string };
      core.fromUpstream({ jsonrpc: "2.0", id: p.id, result: o.discover ?? { resultType: "complete", supportedVersions: [MODERN], capabilities: { tools: {}, resources: {}, prompts: {} }, _meta: { "io.modelcontextprotocol/serverInfo": { name: "fake", version: "1.0.0" } } } } as Message);
    }
  };
  const reply = (id: number, body: { result?: Json; error?: Json }): void => core.fromUpstream({ jsonrpc: "2.0", id, ...body } as unknown as Message);
  const answers = (id: number): Response[] => toClient.filter((m) => !("method" in m) && (m as Response).id === id) as Response[];
  const callSearch = (id: number): void => {
    send(1, "tools/list");
    reply(1, { result: { resultType: "complete", tools: [NOTES_TOOL] } });
    send(id, "tools/call", { name: "search", arguments: { q: "groceries" } });
  };
  return { l, toUp, send, reply, answers, callSearch };
}

describe("V10: JSON-RPC errors", () => {
  it("a withheld error keeps its code and carries the notice and a quarantine record; a clean error passes unchanged", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.callSearch(5);
    g.reply(5, { error: { code: -32000, message: `Search failed.${HIDDEN}` } });
    const a = g.answers(5)[0] as Response;
    expect(a.error?.code).toBe(-32000);
    expect(a.error?.message).toContain("FW-MCP-WITHHELD");
    expect(JSON.stringify(a)).not.toMatch(HAS_TAG);
    expect(listRecords(g.l).records.length).toBe(1);
    g.send(6, "tools/call", { name: "search", arguments: { q: "x" } });
    g.reply(6, { error: { code: -32001, message: "Rate limited.", data: { retryAfter: 3 } } });
    expect(g.answers(6)[0]?.error).toEqual({ code: -32001, message: "Rate limited.", data: { retryAfter: 3 } });
  });
});

describe("V11: server instructions", () => {
  it("withheld instructions are replaced by the notice; clean instructions pass", () => {
    const g = rig({ discover: { resultType: "complete", supportedVersions: [MODERN], capabilities: { tools: {} }, instructions: `Use these tools.${HIDDEN}` } });
    g.send(1, "server/discover");
    const r = g.answers(1)[0]?.result as Json;
    expect(String(r.instructions)).toContain("FW-MCP-WITHHELD");
    const c = rig({ discover: { resultType: "complete", supportedVersions: [MODERN], capabilities: { tools: {} }, instructions: "Use these tools for notes." } });
    c.send(1, "server/discover");
    expect((c.answers(1)[0]?.result as Json).instructions).toBe("Use these tools for notes.");
  });

  it("a legacy server's initialize instructions are scanned too", () => {
    // A legacy client and server, answered by the test (the probe times out at once).
    const { l, home } = newHome();
    const ws = join(home, "ws");
    mkdirSync(ws, { recursive: true });
    const out: Message[] = [];
    const up: Message[] = [];
    const core = new GatewayCore({ l, env: {}, client: "claude-desktop", server: "notes", mode: "full", source: "user", pinSource: "gw-claude-desktop", session: () => "lg", cwd: ws, workspaceRoots: [], transport: "stdio", home, detectNonInteractive: () => true, notifyDeps: { spawn: () => undefined }, setTimer: (fn) => (fn(), () => undefined), diag: () => undefined }, { client: (m) => void out.push(m), upstream: (m) => void up.push(m) });
    core.fromClient({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "c", version: "1" } } } as Message);
    const probe = up.find((m) => "method" in m && m.method === "server/discover") as { id: string } | undefined;
    if (probe !== undefined) core.fromUpstream({ jsonrpc: "2.0", id: probe.id, error: { code: -32601, message: "no" } } as Message);
    const init = up.find((m) => "method" in m && m.method === "initialize") as { id: number };
    core.fromUpstream({ jsonrpc: "2.0", id: init.id, result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "s", version: "1" }, instructions: `Notes server.${HIDDEN}` } } as Message);
    const a = out.find((m) => !("method" in m) && (m as Response).id === 1) as Response;
    expect(JSON.stringify(a)).not.toMatch(HAS_TAG);
    expect(String(a.result?.instructions)).toContain("FW-MCP-WITHHELD");
  });
});

describe("V31: list results", () => {
  it("only the entry with hidden text is left out of resources/list; the others are delivered", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.send(3, "resources/list");
    g.reply(3, { result: { resultType: "complete", resources: [{ uri: "file:///a.md", name: "a.md" }, { uri: "file:///b.md", name: "b.md", description: `B.${HIDDEN}` }, { uri: "file:///c.md", name: "c.md" }] } });
    const r = g.answers(3)[0]?.result as Json;
    expect((r.resources as Json[]).map((x) => x.name)).toEqual(["a.md", "c.md"]);
  });

  it("completion values with hidden text are withheld (no suggestions)", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.send(3, "completion/complete", { ref: { type: "ref/prompt", name: "p" }, argument: { name: "a", value: "x" } });
    g.reply(3, { result: { resultType: "complete", completion: { values: ["xa", `xb${HIDDEN}`] } } });
    expect(JSON.stringify(g.answers(3)[0])).not.toMatch(HAS_TAG);
    expect((g.answers(3)[0]?.result as Json).completion).toEqual({ values: [], hasMore: false });
  });
});

describe("V5: input requests on every method", () => {
  it("an input-required answer carries only its protocol fields: a tools list or content beside it is dropped", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.send(2, "tools/list");
    g.reply(2, { result: { resultType: "input_required", inputRequests: { e1: { method: "elicitation/create", params: { mode: "form", message: "Which account?", requestedSchema: { type: "object", properties: {} } } } }, requestState: "s1", tools: [{ name: "unpinned", description: `x${HIDDEN}`, inputSchema: { type: "object" } }] } });
    const r = g.answers(2)[0]?.result as Json;
    expect(Object.keys(r).sort()).toEqual(["inputRequests", "requestState", "resultType"]);
    expect(JSON.stringify(r)).toContain("[MCP server notes]");
  });

  it("sampling on prompts/list from an untrusted server is refused (FW-MCP-SAMPLING)", () => {
    const g = rig();
    g.send(4, "prompts/list");
    g.reply(4, { result: { resultType: "input_required", inputRequests: { s: { method: "sampling/createMessage", params: { messages: [], maxTokens: 1 } } } } });
    expect(g.answers(4)[0]?.error?.message).toContain("FW-MCP-SAMPLING");
  });
});

describe("V32: request ids", () => {
  it("a reused in-flight id is refused and never reaches the server; the id is free again once answered", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.callSearch(7);
    const before = g.toUp.length;
    g.send(7, "resources/list");
    expect(g.toUp.length).toBe(before);
    expect(g.answers(7)[0]?.error?.message).toContain("still in flight");
    g.reply(7, { result: { resultType: "complete", content: [{ type: "text", text: "ok" }] } });
    g.send(7, "resources/list");
    expect(g.toUp.length).toBe(before + 1);
  });
});

describe("V12 and V22: pins", () => {
  it("V12: hidden text in a tool's title or a schema enum is hidden on first sight; ordinary tools stay", () => {
    const tools = [
      { name: "a", title: `A${HIDDEN}`, description: "A.", inputSchema: { type: "object" } },
      { name: "b", description: "B.", inputSchema: { type: "object", properties: { mode: { type: "string", enum: ["x", `y${HIDDEN}`] } } } },
      { name: "c", description: "C.", inputSchema: { type: "object", properties: { q: { type: "string", description: "The query." } } } },
    ];
    const g = gw({ cfg: { era: "modern", tools } });
    expect((g.call("tools/list").result?.tools as Json[]).map((t) => t.name)).toEqual(["c"]);
  });

  function hookSetup() {
    const { l, home } = newHome();
    const ws = join(home, "ws");
    mkdirSync(ws, { recursive: true });
    const cfg = loadPolicy(l, [ws]).config;
    toolCallPins(l, "github", "get_issue", "user", cfg, new Date(Date.now() - 48 * 3600_000));
    return { l, home };
  }

  it("V22: in hook mode a call to a tool the hook rule kept visible is passed on, not held as a hidden tool", () => {
    const { l, home } = hookSetup();
    const tools = ["get_issue", "list_issues"].map((name) => ({ name, description: `GitHub ${name}.`, inputSchema: { type: "object" } }));
    const g = gw({ l, home, mode: "hook", server: "github", pinSource: "user", cfg: { era: "modern", tools } });
    g.call("tools/list");
    const r = g.call("tools/call", { name: "list_issues", arguments: {} });
    expect(textOf(r)).not.toContain("FW-MCP-TOOL-HELD");
    expect(g.received("tools/call")).toBeDefined();
    // Listed again: still visible (the hook's record is kept, not turned into a hiding change).
    expect((g.call("tools/list").result?.tools as Json[]).map((t) => t.name)).toEqual(["get_issue", "list_issues"]);
  });

  it("V22 control: in hook mode a tool that appears after the gateway's first look is hidden (gateway rule)", () => {
    const { l, home } = hookSetup();
    const tools: Json[] = [{ name: "get_issue", description: "GitHub get_issue.", inputSchema: { type: "object" } }];
    const g = gw({ l, home, mode: "hook", server: "github", pinSource: "user", cfg: () => ({ era: "modern", tools }) });
    g.call("tools/list");
    tools.push({ name: "delete_repo", description: "Delete.", inputSchema: { type: "object" } });
    expect((g.call("tools/list").result?.tools as Json[]).map((t) => t.name)).toEqual(["get_issue"]);
    expect(textOf(g.call("tools/call", { name: "delete_repo", arguments: {} }))).toContain("FW-MCP-TOOL-HELD");
  });

  it("V22 control: in full mode the hook-style exemption does not apply (a gateway pin's new tool stays hidden)", () => {
    const tools: Json[] = [{ name: "search", description: "Search.", inputSchema: { type: "object" } }];
    const { l, home } = newHome();
    writePolicy(l, { mcpPinning: { newToolGraceHours: 0 } });
    const g = gw({ l, home, cfg: () => ({ era: "modern", tools }) });
    g.call("tools/list");
    tools.push({ name: "export_all", description: "Export.", inputSchema: { type: "object" } });
    expect((g.call("tools/list").result?.tools as Json[]).map((t) => t.name)).toEqual(["search"]);
  });
});

// --- configuration rewriting and its protection -------------------------------------------------------

const CLI = join(installDir(), "dist", "cli.js");
const fe = (home: string) => ({ home, platform: "darwin" as NodeJS.Platform, env: {} });
function write(p: string, text: string): void {
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, text);
}
function wrap(l: Layout, home: string, client: "cursor" | "gemini" | "claude-code") {
  const plans = planWrap({ l, client, node: process.execPath, cli: CLI, port: 8473 }, fe(home));
  for (const p of plans) applyPlan(l, p);
  return plans;
}
function ctxFor(l: Layout, home: string, path: string) {
  const text = readFileSync(path, "utf8");
  return { home, workspaceRoots: [join(home, "ws")], cwd: join(home, "ws"), gatewayConfigs: gatewayConfigs(l), readFile: (p: string) => (p === path ? text : null), caseInsensitive: false };
}

describe("V8: ambiguous entries are not wrapped", () => {
  it("a command next to a URL, or URL keys naming different servers, are left as they are, with the reason", () => {
    const { l, home } = newHome();
    const file = join(home, ".gemini", "settings.json");
    write(file, JSON.stringify({ mcpServers: { both: { command: "npx", args: ["-y", "x-mcp@1.0.0"], httpUrl: "https://mcp.example.com/mcp" }, split: { httpUrl: "https://a.example.com/mcp", url: "https://b.example.com/sse" }, plain: { httpUrl: "https://mcp.example.com/mcp" } } }));
    const [plan] = wrap(l, home, "gemini");
    expect(plan?.wrapped.map((w) => w.server)).toEqual(["plain"]);
    expect(plan?.skipped.map((s) => s.server).sort()).toEqual(["both", "split"]);
    const doc = JSON.parse(readFileSync(file, "utf8")) as { mcpServers: Record<string, Json> };
    expect(doc.mcpServers.split).toEqual({ httpUrl: "https://a.example.com/mcp", url: "https://b.example.com/sse" });
  });
});

describe("V9 and V35: the wrapped file's directory and the agents' mcp commands", () => {
  it("V9 control: a shell write to another file in the same directory is not tampering", () => {
    const { l, home } = newHome();
    const file = join(home, ".cursor", "mcp.json");
    write(file, JSON.stringify({ mcpServers: { files: { command: "npx", args: ["-y", "fs-mcp@1.0.0"] } } }));
    wrap(l, home, "cursor");
    const d = bash(`echo x > '${join(home, ".cursor", "notes.txt")}'`, { ctx: ctxFor(l, home, file) });
    expect(d.rules, explain(d)).not.toContain("FW-TAMPER");
    const rm = bash(`rm -rf '${home}'`, { ctx: ctxFor(l, home, file) });
    expect(rm.rules, explain(rm)).toContain("FW-TAMPER");
  });

  it("V35 controls: claude mcp remove of an unwrapped server asks (FW-AGENT-SETTINGS); claude mcp add over a wrapped one is FW-TAMPER; list is fine", () => {
    const { l, home } = newHome();
    const file = join(home, ".claude.json");
    write(file, JSON.stringify({ mcpServers: { docs: { command: "npx", args: ["-y", "docs-mcp@1.2.3"] } } }));
    wrap(l, home, "claude-code");
    const c = ctxFor(l, home, file);
    const other = bash("claude mcp remove other", { ctx: c });
    expect(other.rules, explain(other)).not.toContain("FW-TAMPER");
    expect(other.rules, explain(other)).toContain("FW-AGENT-SETTINGS");
    expect(bash("claude mcp add -s user docs -- npx docs-mcp@9", { ctx: c }).rules).toContain("FW-TAMPER");
    expect(bash("claude mcp list", { ctx: c }).rules).not.toContain("FW-TAMPER");
    // Another agent's command does not edit Claude Code's file.
    expect(bash("gemini mcp remove docs", { ctx: c }).rules).not.toContain("FW-TAMPER");
  });
});

describe("V34 and V15", () => {
  it("V34: under a legacy MCP-Protocol-Version header, a disagreeing Mcp-Method is a mismatch; a plain legacy request is not", () => {
    const req = { jsonrpc: "2.0" as const, id: 1, method: "tools/call", params: { name: "search", arguments: {} } };
    expect(checkClientHeaders({ "mcp-protocol-version": "2025-06-18" }, req)).toBeNull();
    expect(checkClientHeaders({ "mcp-protocol-version": "2025-06-18", "mcp-method": "tools/list" }, req)).toMatch(/Mcp-Method/);
    expect(checkClientHeaders({ "mcp-protocol-version": "2025-06-18", "mcp-name": "search" }, req)).toBeNull();
  });

  it("V15: endpoints must be https, except on loopback; a stored http token endpoint is refused at refresh", async () => {
    expect(() => secureEndpoint("token endpoint", "http://as.example/token")).toThrow(/https/);
    expect(() => secureEndpoint("token endpoint", "http://127.0.0.1:9000/token")).not.toThrow();
    expect(() => secureEndpoint("token endpoint", "https://as.example/token")).not.toThrow();
    let called = false;
    const f = (async () => {
      called = true;
      return new Response("{}");
    }) as typeof fetch;
    await expect(refreshTokens(f, { tokenEndpoint: "http://as.example/token", resource: "https://mcp.example/mcp" }, "cid", "rt")).rejects.toThrow(/https/);
    expect(called).toBe(false);
  });
});
