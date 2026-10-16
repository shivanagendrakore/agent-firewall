/**
 * Independent review of v0.3, lane "gateway core" (src/gateway/pipeline.ts, pins.ts, scan.ts,
 * src/engine/gateway-config.ts). Each case was an `it.fails` in the review, kept as a regression test; it asserts the PROMISED behaviour and now passes on
 * that assertion. Payloads are placeholders: Unicode tag characters encoding harmless words.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { GatewayCore } from "../../src/gateway/pipeline.js";
import type { Json, Message, Response } from "../../src/gateway/jsonrpc.js";
import { applyPlan, planWrap } from "../../src/gateway/clients.js";
import { gatewayConfigs } from "../../src/gateway/install.js";
import { loadPolicy } from "../../src/runtime/config.js";
import { installDir } from "../../src/runtime/layout.js";
import { toolCallPins } from "../../src/runtime/pins.js";
import { explain, run } from "../helpers.js";
import { gw, MODERN, newHome, textOf, writePolicy } from "../gateway/harness.js";

const TAG = (s: string): string => [...s].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join("");
const HIDDEN = TAG("placeholder hidden words");
const HAS_TAG = /[\u{E0000}-\u{E007F}]/u;
const TRUSTED_NOTES = { mcpServers: { notes: { results: "trusted", privateData: false } } };
const NOTES_TOOL = { name: "search", description: "Search your notes.", inputSchema: { type: "object", properties: { q: { type: "string" } } } };

/** A gateway whose upstream answers are written by the test, message by message (modern client and server). */
function rig(o: { policy?: Json; server?: string; discover?: Json } = {}) {
  const { l, home } = newHome();
  if (o.policy !== undefined) writePolicy(l, o.policy);
  const ws = join(home, "ws");
  mkdirSync(ws, { recursive: true });
  const toClient: Message[] = [];
  const toUp: Message[] = [];
  const core = new GatewayCore(
    { l, env: {}, client: "claude-desktop", server: o.server ?? "notes", mode: "full", source: "user", pinSource: "gw-claude-desktop", session: () => "rv03gc", cwd: ws, workspaceRoots: [], transport: "stdio", home, detectNonInteractive: () => true, notifyDeps: { spawn: () => undefined }, setTimer: () => () => undefined, diag: () => undefined },
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
  const answer = (id: number): Response | undefined => toClient.find((m) => !("method" in m) && (m as Response).id === id) as Response | undefined;
  const upstreamGot = (id: number): boolean => toUp.some((m) => "method" in m && "id" in m && (m as { id: unknown }).id === id);
  /** tools/list (pins the tool), then a tools/call the engine allows; returns once it reached the upstream. */
  const callSearch = (id: number): void => {
    send(1, "tools/list");
    reply(1, { result: { resultType: "complete", tools: [NOTES_TOOL] } });
    send(id, "tools/call", { name: "search", arguments: { q: "groceries" } });
    expect(upstreamGot(id), JSON.stringify(answer(id))).toBe(true);
  };
  return { core, l, toClient, toUp, send, reply, answer, callSearch };
}

describe("gateway core: result scanning covers every text channel", () => {
  it("V10 gateway (GC1): a JSON-RPC error answer to tools/call is delivered unscanned (hidden text reaches the model)", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.callSearch(5);
    g.reply(5, { error: { code: -32000, message: `Search failed.${HIDDEN}`, data: { detail: `retry later${HIDDEN}` } } });
    const a = g.answer(5);
    expect(a).toBeDefined();
    // Promised: every text channel is scanned and hidden instructions are withheld before the model sees them.
    expect(JSON.stringify(a)).not.toMatch(HAS_TAG);
  });

  it("V11 gateway (GC2): server/discover (and initialize) instructions are passed to the client unscanned", () => {
    const g = rig({ discover: { resultType: "complete", supportedVersions: [MODERN], capabilities: { tools: {} }, instructions: `Use these tools for notes.${HIDDEN}`, _meta: { "io.modelcontextprotocol/serverInfo": { name: "fake", version: "1.0.0" } } } });
    g.send(1, "server/discover");
    const a = g.answer(1);
    expect(a?.result).toBeDefined();
    expect(JSON.stringify(a)).not.toMatch(HAS_TAG);
  });

  it("V13 gateway (GC3): a resource_link's name/description in a tools/call result is not scanned (only its uri is)", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.callSearch(5);
    g.reply(5, { result: { resultType: "complete", content: [{ type: "text", text: "Found one note." }, { type: "resource_link", uri: "file:///notes/a.md", name: "a.md", description: `A note.${HIDDEN}` }] } });
    expect(JSON.stringify(g.answer(5))).not.toMatch(HAS_TAG);
  });

  it("V30 gateway (GC4): an embedded resource whose mimeType is not text-like is not scanned, though its text reaches the model", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.callSearch(5);
    g.reply(5, { result: { resultType: "complete", content: [{ type: "resource", resource: { uri: "file:///notes/a.bin", mimeType: "application/octet-stream", text: `note body${HIDDEN}` } }] } });
    expect(JSON.stringify(g.answer(5))).not.toMatch(HAS_TAG);
  });

  it("V31 gateway (GC5): prompts/list and resources/list descriptions are passed unscanned", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.send(3, "prompts/list");
    g.reply(3, { result: { resultType: "complete", prompts: [{ name: "summarise", description: `Summarise notes.${HIDDEN}` }] } });
    expect(g.answer(3)?.result).toBeDefined();
    expect(JSON.stringify(g.answer(3))).not.toMatch(HAS_TAG);
  });

  it("V12 gateway (GC6): first sight of a tool with hidden text in an inputSchema property description: shown, not hidden", () => {
    const tool = { name: "search", description: "Search your notes.", inputSchema: { type: "object", properties: { q: { type: "string", description: `The query.${HIDDEN}` } } } };
    const g = gw({ cfg: { era: "modern", tools: [tool, { name: "create_note", description: "Create a note.", inputSchema: { type: "object" } }] } });
    const r = g.call("tools/list");
    // Promised: a tool whose definition carries hidden text is hidden at once; nothing hidden reaches the model.
    expect(JSON.stringify(r)).not.toMatch(HAS_TAG);
  });
});

describe("gateway core: input requests", () => {
  it("V5 gateway (GC7): an untrusted server's sampling request inside a resources/list (non-scanned method) InputRequiredResult reaches the client", () => {
    const g = rig(); // "notes" with no policy: its results are untrusted, so sampling is deny_untrusted
    g.send(4, "resources/list");
    g.reply(4, { result: { resultType: "input_required", inputRequests: { s1: { method: "sampling/createMessage", params: { messages: [{ role: "user", content: { type: "text", text: "placeholder prompt" } }], maxTokens: 10 } } }, requestState: "srv-state" } });
    const a = g.answer(4);
    expect(a).toBeDefined();
    // Promised: sampling from an untrusted server is refused (FW-MCP-SAMPLING).
    expect(JSON.stringify(a)).not.toContain("sampling/createMessage");
  });
});

describe("gateway core: JSON-RPC ids", () => {
  it("V32 gateway (GC8): a client request reusing an in-flight id rebinds the pending entry: the tools/call answer is delivered as a resources/list answer, unscanned", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.callSearch(7);
    g.send(7, "resources/list"); // same id while the tools/call is in flight
    g.reply(7, { result: { resultType: "complete", content: [{ type: "text", text: `Meeting at 10.${HIDDEN}` }] } });
    const first = g.answer(7);
    expect(first).toBeDefined();
    // Promised (jsonrpc.ts): a result is matched to the request, and the decision, that let it through.
    expect(JSON.stringify(first)).not.toMatch(HAS_TAG);
  });
});

describe("gateway core: pins and false positives", () => {
  it("V22 gateway (GC9): hook mode after weeks of hook use: every tool the person never called is hidden as a new tool (ordinary GitHub server)", () => {
    const { l, home } = newHome();
    const ws = join(home, "ws");
    mkdirSync(ws, { recursive: true });
    const cfg = loadPolicy(l, [ws]).config;
    // The Claude Code hook pinned user:github from a call two days ago (it never sees tools/list).
    toolCallPins(l, "github", "get_issue", "user", cfg, new Date(Date.now() - 48 * 3600_000));
    const tools = ["get_issue", "list_issues", "get_file_contents"].map((name) => ({ name, description: `GitHub ${name}.`, inputSchema: { type: "object" } }));
    const g = gw({ l, home, mode: "hook", server: "github", pinSource: "user", cfg: { era: "modern", tools } });
    const listed = (g.call("tools/list").result?.tools as Json[]).map((t) => t.name);
    // Promised: "The wrapper is not a change"; hook and gateway share one pin.
    expect(listed).toEqual(["get_issue", "list_issues", "get_file_contents"]);
  });

  it("V41 gateway (GC10): a server-chosen tool name with terminal control characters reaches the wrapper's stderr unescaped", () => {
    const g = gw({ cfg: { era: "modern", tools: [{ name: "x\u001b[2Jy", description: `Tool.${HIDDEN}`, inputSchema: { type: "object" } }] } });
    g.call("tools/list");
    expect(g.diag.join("\n")).toMatch(/hidden/);
    expect(g.diag.join("\n")).not.toContain("\u001b");
  });

  it("control: a call to a case variant of a listed tool name is held (unknown to the pin)", () => {
    const g = gw({ cfg: { era: "modern", tools: [NOTES_TOOL] }, policy: TRUSTED_NOTES });
    g.call("tools/list");
    const r = g.call("tools/call", { name: "Search", arguments: { q: "x" } });
    expect(textOf(r)).toContain("FW-MCP-TOOL-HELD");
    expect(g.received("tools/call")).toBeUndefined();
  });

  it("control: tag characters in an ordinary tools/call text block are withheld (FW-MCP-WITHHELD)", () => {
    const g = rig({ policy: TRUSTED_NOTES });
    g.callSearch(5);
    g.reply(5, { result: { resultType: "complete", content: [{ type: "text", text: `Meeting at 10.${HIDDEN}` }] } });
    const a = g.answer(5) as Response;
    expect(JSON.stringify(a)).not.toMatch(HAS_TAG);
    expect(textOf(a)).toContain("FW-MCP-WITHHELD");
  });
});

describe("gateway core: wrapped configuration protection", () => {
  const DESKTOP = (home: string) => join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
  function setup() {
    const { l, home } = newHome();
    const path = DESKTOP(home);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify({ mcpServers: { files: { command: "npx", args: ["-y", "fs-mcp@1.0.0"] } } }, null, 2));
    for (const p of planWrap({ l, client: "claude-desktop", node: process.execPath, cli: join(installDir(), "dist", "cli.js"), port: 8473 }, { home, platform: "darwin" as NodeJS.Platform, env: {} })) applyPlan(l, p);
    const text = readFileSync(path, "utf8");
    const c = { home, workspaceRoots: [join(home, "ws")], cwd: join(home, "ws"), gatewayConfigs: gatewayConfigs(l), readFile: (p: string) => (p === path ? text : null), caseInsensitive: false };
    return { path, text, c };
  }

  it("control: a server disguised as a wrapper (wrapper words in args, another command) is still asked: the whole file is agent settings (isWrapper() is loose, but not the only gate)", () => {
    const { path, text, c } = setup();
    const doc = JSON.parse(text);
    doc.mcpServers.extra = { command: "placeholder-server", args: ["launchsafe-firewall", "mcp", "wrap", "--"] };
    const d = run("Write", { file_path: path, content: JSON.stringify(doc, null, 2) }, { ctx: c });
    expect(d.rules, explain(d)).toContain("FW-AGENT-SETTINGS");
    expect(d.verdict).not.toBe("allow");
  });

  it("control: adding a plainly unwrapped server is FW-AGENT-SETTINGS", () => {
    const { path, text, c } = setup();
    const doc = JSON.parse(text);
    doc.mcpServers.extra = { command: "placeholder-server", args: [] };
    const d = run("Write", { file_path: path, content: JSON.stringify(doc, null, 2) }, { ctx: c });
    expect(d.rules, explain(d)).toContain("FW-AGENT-SETTINGS");
  });
});
