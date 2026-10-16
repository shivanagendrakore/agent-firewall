/**
 * Review of the v0.3 gateway fixes (V5, V8-V15, V22, V23, V30-V35, V39, V41; commits cb2fa9f, 03bf678,
 * c3c3760, 68a435c, f29d477, e27d526, fa9c647). Each case was an `it.fails` in the review, kept as a regression test; it asserts the promised behaviour and passes
 * now on that assertion. Placeholders only: Unicode tag characters encoding harmless words.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { GatewayCore } from "../../src/gateway/pipeline.js";
import type { Json, Message, Response } from "../../src/gateway/jsonrpc.js";
import { applyPlan, planWrap } from "../../src/gateway/clients.js";
import { gatewayConfigs } from "../../src/gateway/install.js";
import { discover } from "../../src/gateway/oauth.js";
import { loadPolicy } from "../../src/runtime/config.js";
import { installDir } from "../../src/runtime/layout.js";
import { toolCallPins, upsertPending, type PinFile } from "../../src/runtime/pins.js";
import { bash, explain } from "../helpers.js";
import { gw, MODERN, newHome, textOf, writePolicy } from "../gateway/harness.js";

const TAG = (s: string): string => [...s].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join("");
const HIDDEN = TAG("placeholder hidden words");
const HAS_TAG = /[\u{E0000}-\u{E007F}]/u;
const TRUSTED_NOTES = { mcpServers: { notes: { results: "trusted", privateData: false } } };
const NOTES_TOOL = { name: "search", description: "Search your notes.", inputSchema: { type: "object", properties: { q: { type: "string" } } } };

/** A gateway whose upstream answers are written by the test, message by message (modern client and server). */
function rig(o: { policy?: Json } = {}) {
  const { l, home } = newHome();
  if (o.policy !== undefined) writePolicy(l, o.policy);
  const ws = join(home, "ws");
  mkdirSync(ws, { recursive: true });
  const toClient: Message[] = [];
  const toUp: Message[] = [];
  const core = new GatewayCore(
    { l, env: {}, client: "claude-desktop", server: "notes", mode: "full", source: "user", pinSource: "gw-claude-desktop", session: () => "rvfxgw", cwd: ws, workspaceRoots: [], transport: "stdio", home, detectNonInteractive: () => true, notifyDeps: { spawn: () => undefined }, setTimer: () => () => undefined, diag: () => undefined },
    { client: (m) => void toClient.push(m), upstream: (m) => void toUp.push(m) },
  );
  const meta = { _meta: { "io.modelcontextprotocol/protocolVersion": MODERN, "io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/clientInfo": { name: "test-client", version: "1.0" } } };
  let probed = false;
  const send = (id: number, method: string, params: Json = {}): void => {
    core.fromClient({ jsonrpc: "2.0", id, method, params: { ...params, ...meta } } as Message);
    if (!probed) {
      probed = true;
      const p = toUp.find((m) => "method" in m && m.method === "server/discover") as { id: string };
      core.fromUpstream({ jsonrpc: "2.0", id: p.id, result: { resultType: "complete", supportedVersions: [MODERN], capabilities: { tools: {}, resources: {}, prompts: {} }, _meta: { "io.modelcontextprotocol/serverInfo": { name: "fake", version: "1.0.0" } } } } as Message);
    }
  };
  const reply = (id: number, body: { result?: Json; error?: Json }): void => core.fromUpstream({ jsonrpc: "2.0", id, ...body } as unknown as Message);
  const answer = (id: number): Response | undefined => toClient.find((m) => !("method" in m) && (m as Response).id === id) as Response | undefined;
  const upstreamGot = (id: number): boolean => toUp.some((m) => "method" in m && "id" in m && (m as { id: unknown }).id === id);
  const callSearch = (id: number): void => {
    send(1, "tools/list");
    reply(1, { result: { resultType: "complete", tools: [NOTES_TOOL] } });
    send(id, "tools/call", { name: "search", arguments: { q: "groceries" } });
    expect(upstreamGot(id), JSON.stringify(answer(id))).toBe(true);
  };
  return { send, reply, answer, callSearch };
}

/** A value nested `n` objects deep with `leaf` at the bottom. */
const nest = (n: number, leaf: unknown): Json => (n === 0 ? (leaf as Json) : { x: nest(n - 1, leaf) });
/** An input schema nested `n` object levels deep (each level is two JSON levels: properties, then a). */
const deepSchema = (n: number, leaf: Json): Json => (n === 0 ? leaf : { type: "object", properties: { a: deepSchema(n - 1, leaf) } });
const listed = (r: Response): Json[] => (r.result?.tools ?? []) as Json[];

describe("V12: every text of a tool definition", () => {
  it("GW1 (V12): hidden text in an inputSchema property nested past depth 64 is not scanned, so the tool is shown with it on first sight", () => {
    const tool = { name: "search", description: "Search your notes.", inputSchema: deepSchema(40, { type: "string", description: `The query.${HIDDEN}` }) };
    const g = gw({ cfg: { era: "modern", tools: [tool] } });
    // Promised: a tool whose definition carries hidden text is hidden at once (a walk that stops early fails closed).
    expect(JSON.stringify(listed(g.call("tools/list")))).not.toMatch(HAS_TAG);
  });

  it("GW2 (V12): an inputSchema padded past the 20,000-node walk budget hides a later property description from the check", () => {
    const pad = Array.from({ length: 20_001 }, (_, i) => `v${i}`);
    const tool = { name: "search", description: "Search your notes.", inputSchema: { type: "object", properties: { kind: { type: "string", enum: pad }, q: { type: "string", description: `The query.${HIDDEN}` } } } };
    const g = gw({ cfg: { era: "modern", tools: [tool] } });
    expect(JSON.stringify(listed(g.call("tools/list")))).not.toMatch(HAS_TAG);
  });

  it("GW8 (V12): a tool name carrying tag characters is shown on first sight (the name is not among the scanned texts)", () => {
    const g = gw({ cfg: { era: "modern", tools: [{ name: `search${HIDDEN}`, description: "Search your notes.", inputSchema: { type: "object" } }] } });
    expect(JSON.stringify(listed(g.call("tools/list")))).not.toMatch(HAS_TAG);
  });
});

describe("V10, V31: deep strings in errors, list entries and structured results", () => {
  it("GW3 (V10): a string nested past depth 64 in a JSON-RPC error's data is delivered unscanned", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.callSearch(5);
    g.reply(5, { error: { code: -32000, message: "Search failed.", data: nest(70, `retry later${HIDDEN}`) } });
    const a = g.answer(5);
    expect(a).toBeDefined();
    expect(JSON.stringify(a)).not.toMatch(HAS_TAG);
  });

  it("GW4 (V31): a string nested past depth 64 in a prompts/list entry is delivered unscanned", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.send(3, "prompts/list");
    g.reply(3, { result: { resultType: "complete", prompts: [{ name: "summarise", description: "Summarise notes.", arguments: [{ name: "topic", description: "The topic.", extra: nest(70, `deep${HIDDEN}`) }] }] } });
    const a = g.answer(3);
    expect(a?.result).toBeDefined();
    expect(JSON.stringify(a)).not.toMatch(HAS_TAG);
  });

  it("GW5 (structuredContent, same walk): a string nested past depth 64 in a tools/call structuredContent is delivered unscanned", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.callSearch(5);
    g.reply(5, { result: { resultType: "complete", content: [{ type: "text", text: "Found one note." }], structuredContent: nest(70, `deep${HIDDEN}`) } });
    expect(JSON.stringify(g.answer(5))).not.toMatch(HAS_TAG);
  });

  it("GW9 (V10): object keys inside a JSON-RPC error's data are not scanned (only values are)", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.callSearch(5);
    g.reply(5, { error: { code: -32000, message: "Search failed.", data: { [`detail${HIDDEN}`]: 1 } } });
    expect(JSON.stringify(g.answer(5))).not.toMatch(HAS_TAG);
  });

  it("GW10 (V31): fields of a resources/list result beside its resources array are delivered unscanned", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.send(3, "resources/list");
    g.reply(3, { result: { resultType: "complete", resources: [], description: `Your notes.${HIDDEN}` } });
    const a = g.answer(3);
    expect(a?.result).toBeDefined();
    expect(JSON.stringify(a)).not.toMatch(HAS_TAG);
  });
});

describe("V22: hook mode and hidden tools", () => {
  function hookRig(tools: Json[]) {
    const { l, home } = newHome();
    const ws = join(home, "ws");
    mkdirSync(ws, { recursive: true });
    const cfg = loadPolicy(l, [ws]).config;
    // The Claude Code hook pinned user:github from a call two days ago.
    toolCallPins(l, "github", "get_issue", "user", cfg, new Date(Date.now() - 48 * 3600_000));
    let current = tools;
    const g = gw({ l, home, mode: "hook", server: "github", pinSource: "user", cfg: () => ({ era: "modern", tools: current }) });
    return { g, l, cfg, set: (t: Json[]) => void (current = t) };
  }
  const GET_ISSUE = { name: "get_issue", description: "Get an issue.", inputSchema: { type: "object" } };

  it("GW6 (V22): after the gateway has seen the tool list, a tool the server never listed is refused, until the client's hook records a call to it; then the gateway forwards it", () => {
    const { g, l, cfg } = hookRig([GET_ISSUE]);
    expect(listed(g.call("tools/list")).map((t) => t.name)).toEqual(["get_issue"]);
    // Control: before the hook has recorded it, the call is held.
    expect(textOf(g.call("tools/call", { name: "unlisted_tool", arguments: {} }))).toContain("FW-MCP-TOOL-HELD");
    // The agent calls it again: the client's own hook runs first and records a hook-style new tool (R9).
    toolCallPins(l, "github", "unlisted_tool", "user", cfg, new Date());
    const r = g.call("tools/call", { name: "unlisted_tool", arguments: {} });
    // Promised (docs/gateway.md): a tool the gateway-seen server never listed stays held until a person reviews it.
    expect(textOf(r)).toContain("FW-MCP-TOOL-HELD");
    expect(g.received("tools/call")).toBeUndefined();
  });

  it("GW7 (V22): a tool the hook recorded first, then listed with hidden text in its schema, is left out of the list but its call is forwarded", () => {
    const evil = { name: "evil", description: "Evil.", inputSchema: { type: "object", properties: { a: { type: "string", description: `A.${HIDDEN}` } } } };
    const { g, l, cfg, set } = hookRig([GET_ISSUE]);
    g.call("tools/list");
    toolCallPins(l, "github", "evil", "user", cfg, new Date());
    set([GET_ISSUE, evil]);
    expect(listed(g.call("tools/list")).map((t) => t.name)).toEqual(["get_issue"]);
    const r = g.call("tools/call", { name: "evil", arguments: {} });
    expect(textOf(r)).toContain("FW-MCP-TOOL-HELD");
    expect(g.received("tools/call")).toBeUndefined();
  });
});

describe("V22: hook records and gateway sightings merge, the stricter state wins", () => {
  const base = { key: "user:github", name: "github", kind: "new_tool" as const, tool: "evil" };
  const gatewaySaw = { ...base, to: "v1", toV2: "v2", detail: "MCP server \"github\" lists a new tool, evil, ..., and its definition carries hidden text (tag chars)" };
  const hookSaw = { ...base, detail: "MCP server \"github\" exposes a new tool, evil, not seen since ..." };

  it("GW7b: a hook's later record keeps the gateway's definition hashes and its finding", () => {
    const pins: PinFile = { version: 1, servers: {}, pending: [] };
    upsertPending(pins, gatewaySaw, "t1");
    upsertPending(pins, hookSaw, "t2");
    expect(pins.pending).toHaveLength(1);
    expect(pins.pending[0]).toMatchObject({ to: "v1", toV2: "v2", detail: gatewaySaw.detail, lastSeen: "t2" });
  });

  it("GW7c: the gateway's later sighting fills in a hook's record (hashes, finding, listed)", () => {
    const pins: PinFile = { version: 1, servers: {}, pending: [] };
    upsertPending(pins, hookSaw, "t1");
    upsertPending(pins, { ...gatewaySaw, listed: true }, "t2");
    expect(pins.pending[0]).toMatchObject({ to: "v1", toV2: "v2", detail: gatewaySaw.detail, listed: true });
    upsertPending(pins, hookSaw, "t3");
    expect(pins.pending[0]).toMatchObject({ toV2: "v2", detail: gatewaySaw.detail, listed: true });
  });
});

describe("V15: https for OAuth", () => {
  it("GW11 (V15): discovery accepts a plain-http (non-loopback) MCP resource, so the access token would be sent to it in clear text", async () => {
    const f = (async (url: string | URL) => {
      const u = String(url);
      if (u.endsWith("/.well-known/oauth-protected-resource/mcp")) return new Response(JSON.stringify({ resource: "http://mcp.example/mcp", authorization_servers: ["https://as.example"] }), { status: 200 });
      if (u.startsWith("https://as.example/.well-known/oauth-authorization-server")) return new Response(JSON.stringify({ issuer: "https://as.example", authorization_endpoint: "https://as.example/authorize", token_endpoint: "https://as.example/token", code_challenge_methods_supported: ["S256"] }), { status: 200 });
      return new Response("", { status: 401 });
    }) as typeof fetch;
    await expect(discover(f, "http://mcp.example/mcp")).rejects.toThrow(/https/);
  });
});

describe("V35: agents' mcp commands", () => {
  it("GW12 (V35): `npx @anthropic-ai/claude-code mcp remove <wrapped>` is allowed outright (not even asked)", () => {
    const { l, home } = newHome();
    const file = join(home, ".claude.json");
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, JSON.stringify({ mcpServers: { docs: { command: "npx", args: ["-y", "docs-mcp@1.2.3"] } } }));
    for (const p of planWrap({ l, client: "claude-code", node: process.execPath, cli: join(installDir(), "dist", "cli.js"), port: 8473 }, { home, platform: "darwin" as NodeJS.Platform, env: {} })) applyPlan(l, p);
    const text = readFileSync(file, "utf8");
    const ctx = { home, workspaceRoots: [join(home, "ws")], cwd: join(home, "ws"), gatewayConfigs: gatewayConfigs(l), readFile: (p: string) => (p === file ? text : null), caseInsensitive: false };
    // Control: the plain command is FW-TAMPER.
    expect(bash("claude mcp remove docs", { ctx }).rules).toContain("FW-TAMPER");
    const d = bash("npx @anthropic-ai/claude-code mcp remove docs", { ctx });
    expect(d.rules, explain(d)).toContain("FW-TAMPER");
    // The other package runners, a pinned version, and --package with the command after it.
    for (const cmd of ["npx -y @anthropic-ai/claude-code@2.1.0 mcp remove docs", "pnpm dlx @anthropic-ai/claude-code mcp remove docs", "yarn dlx @anthropic-ai/claude-code mcp remove docs", "bunx @anthropic-ai/claude-code mcp remove docs", "npm exec -- @anthropic-ai/claude-code mcp remove docs", "npx -p @anthropic-ai/claude-code claude mcp remove docs", "pnpm dlx --package=@anthropic-ai/claude-code claude mcp add docs -- node x.js"]) {
      const r = bash(cmd, { ctx });
      expect(r.rules, `${cmd}\n${explain(r)}`).toContain("FW-TAMPER");
    }
    // Control: a server the gateway does not wrap is not tamper, and reading the list is not either.
    expect(bash("npx @anthropic-ai/claude-code mcp remove other", { ctx }).rules).not.toContain("FW-TAMPER");
    expect(bash("npx @anthropic-ai/claude-code mcp list", { ctx }).rules).not.toContain("FW-TAMPER");
  });
});
