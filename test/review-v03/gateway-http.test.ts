/**
 * Independent review of v0.3, lane gw-http: the MCP gateway's HTTP side, OAuth and config rewriting
 * (src/gateway/http.ts, oauth.ts, clients.ts, install.ts, codex-toml.ts, src/gateway-cli.ts,
 * src/engine/gateway-config.ts). Each case was an `it.fails` in the review; kept as a regression test now the finding is fixed.
 * Loopback servers only; placeholder values, no real payloads.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type ServerResponse } from "node:http";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { applyPlan, planWrap } from "../../src/gateway/clients.js";
import { startGatewayServer } from "../../src/gateway/http.js";
import { entryHash, gatewayConfigs, updateGatewayInstall } from "../../src/gateway/install.js";
import { discover } from "../../src/gateway/oauth.js";
import { clientToken } from "../../src/gateway/tokens.js";
import type { Json } from "../../src/gateway/jsonrpc.js";
import { installDir, type Layout } from "../../src/runtime/layout.js";
import { FakeUpstream, type FakeConfig } from "../fixtures/mcp-upstream/server.js";
import { MODERN, newHome, NOTES_TOOLS, writePolicy } from "../gateway/harness.js";
import { bash, explain } from "../helpers.js";

const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const c of closers.splice(0)) await c();
});

const CLI = join(installDir(), "dist", "cli.js");
const NODE = process.execPath;
const fe = (home: string) => ({ home, platform: "darwin" as NodeJS.Platform, env: {} });

function write(p: string, text: string): void {
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, text);
}

function wrap(l: Layout, home: string, client: "cursor" | "gemini" | "claude-code") {
  const plans = planWrap({ l, client, node: NODE, cli: CLI, port: 8473 }, fe(home));
  for (const p of plans) applyPlan(l, p);
  return plans;
}

/** The engine context a hook would build for a wrapped file. */
function engineCtx(l: Layout, home: string, path: string) {
  const text = readFileSync(path, "utf8");
  return { text, c: { home, workspaceRoots: [join(home, "ws")], cwd: join(home, "ws"), gatewayConfigs: gatewayConfigs(l), readFile: (p: string) => (p === path ? text : null), caseInsensitive: false } };
}

// --- a loopback upstream and the gateway in front of it ------------------------------------------

/** Lets a test answer a message itself (return true), else the fake upstream answers it as JSON. */
type Raw = (m: Json, res: ServerResponse) => boolean;

async function upstream(cfg: FakeConfig, raw?: Raw): Promise<{ url: string }> {
  const fake = new FakeUpstream(cfg);
  const s = createServer((req, res) => {
    let body = "";
    req.on("data", (c: Buffer) => (body += c.toString()));
    req.on("end", () => {
      const m = JSON.parse(body === "" ? "{}" : body) as Json;
      if (raw !== undefined && raw(m, res)) return;
      const out = fake.handle(m);
      if (m.id === undefined) return void res.writeHead(202).end();
      const r = out.find((x) => x.id === m.id);
      if (r === undefined) return void res.writeHead(400, { "content-type": "text/plain" }).end("bad request");
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(r));
    });
  });
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  closers.push(
    () =>
      new Promise<void>((r) => {
        s.closeAllConnections();
        s.close(() => r());
      }),
  );
  return { url: `http://127.0.0.1:${(s.address() as { port: number }).port}/mcp` };
}

async function gateway(up: { url: string }) {
  const { home, l } = newHome();
  writePolicy(l, { mcpServers: { notes: { results: "trusted", privateData: false } } });
  const original = { url: up.url, headers: { Authorization: "Bearer upstream-static-placeholder" } };
  const token = clientToken(l, "cursor");
  updateGatewayInstall(l, (g) => {
    g.entries.push({ client: "cursor", server: "notes", file: "/nonexistent/mcp.json", scope: "user", mode: "full", upstream: { kind: "http", url: up.url, headerKeys: ["Authorization"] }, originalHash: entryHash(original), wrappedHash: "x", original, location: ["mcpServers", "notes"], wrappedAt: new Date().toISOString() });
  });
  const s = await startGatewayServer({ l, env: {}, port: 0, cwd: home, home, core: { detectNonInteractive: () => true, notifyDeps: { spawn: () => undefined }, probeTimeoutMs: 2000 } });
  closers.push(s.close);
  const base = `http://127.0.0.1:${s.port}/c/cursor/u/notes`;
  let id = 0;
  /** POSTs one request; a request the gateway never answers comes back as status -1 after timeoutMs. */
  const post = async (method: string, params: Json = {}, headers: Record<string, string> = {}, timeoutMs = 8000): Promise<{ status: number; json: Json }> => {
    const body = { jsonrpc: "2.0", id: ++id, method, params: { ...params, _meta: { "io.modelcontextprotocol/protocolVersion": MODERN, "io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/clientInfo": { name: "t", version: "1" } } } };
    const h: Record<string, string> = { "content-type": "application/json", accept: "application/json", "mcp-protocol-version": MODERN, "mcp-method": method, ...(typeof params.name === "string" ? { "mcp-name": params.name } : {}), authorization: `Bearer ${token}`, ...headers };
    try {
      const r = await fetch(base, { method: "POST", headers: h, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) });
      const text = await r.text();
      return { status: r.status, json: (text.startsWith("{") ? JSON.parse(text) : {}) as Json };
    } catch {
      return { status: -1, json: {} };
    }
  };
  return { l, post };
}

const toolError = (r: { status: number; json: Json }): boolean => r.status === 200 && (r.json.result as Json | undefined)?.isError === true;

// ---------------------------------------------------------------------------------------------------

describe("gw-http review: config rewriting", () => {
  it("V8 gateway (GH1): a Gemini entry with both httpUrl and url is wrapped on every URL key; no URL key keeps the remote server next to the gateway bearer", () => {
    const { l, home } = newHome();
    const file = join(home, ".gemini", "settings.json");
    write(file, JSON.stringify({ mcpServers: { remote: { httpUrl: "https://mcp.example.com/mcp", url: "https://mcp.example.com/sse", headers: { Authorization: "Bearer placeholder" } } } }));
    const [plan] = wrap(l, home, "gemini");
    expect(plan?.wrapped.map((w) => w.server)).toEqual(["remote"]);
    const entry = (JSON.parse(readFileSync(file, "utf8")) as { mcpServers: Record<string, Json> }).mcpServers.remote as Json;
    // Gemini CLI prefers httpUrl over url: every URL key must point at the local gateway, or the
    // "wrapped" server is reached directly (unguarded) and the lsgw_ bearer goes to the remote host.
    for (const k of ["url", "httpUrl", "serverUrl"]) if (typeof entry[k] === "string") expect(entry[k], k).toMatch(/^http:\/\/127\.0\.0\.1:8473\/c\/gemini\/u\/remote$/);
  });

  it("V9 gateway (GH2): a shell write that reaches a wrapped file through its directory (mv the directory out, cp -R / tar -C into it) is FW-TAMPER", () => {
    const { l, home } = newHome();
    const file = join(home, ".cursor", "mcp.json");
    write(file, JSON.stringify({ mcpServers: { files: { command: "npx", args: ["-y", "fs-mcp@1.0.0"] } } }));
    wrap(l, home, "cursor");
    const { c } = engineCtx(l, home, file);
    const dir = join(home, ".cursor");
    // Write /tmp/c/mcp.json is allowed (not a wrapped path); then each command replaces the wrapped file.
    for (const cmd of [`mv '${dir}' /tmp/c`, `cp -R /tmp/c/. '${dir}/'`, `tar -xf /tmp/c.tar -C '${dir}'`]) {
      const d = bash(cmd, { ctx: c });
      expect(d.rules, `${cmd}: ${explain(d)}`).toContain("FW-TAMPER");
    }
  });

  it("V35 gateway (GH7): `claude mcp remove <wrapped server>` (a shell write removing a wrapped entry) is FW-TAMPER, not an askable settings change", () => {
    const { l, home } = newHome();
    const file = join(home, ".claude.json");
    write(file, JSON.stringify({ mcpServers: { docs: { command: "npx", args: ["-y", "docs-mcp@1.2.3"] } } }));
    wrap(l, home, "claude-code");
    const { c } = engineCtx(l, home, file);
    const d = bash("claude mcp remove docs", { ctx: c });
    expect(d.rules, explain(d)).toContain("FW-TAMPER");
    expect(d.verdict).toBe("deny");
  });
});

describe("gw-http review: the HTTP gateway", () => {
  it("V14 gateway (GH3): an upstream that resets the connection mid-answer gets the client a tool error, with no unhandled rejection (which would crash `mcp serve`)", async () => {
    const rejections: unknown[] = [];
    const onRej = (e: unknown): void => void rejections.push(e);
    process.on("unhandledRejection", onRej);
    try {
      const up = await upstream({ era: "modern", tools: NOTES_TOOLS }, (m, res) => {
        if (m.method !== "tools/call") return false;
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write("event: message\ndata: {");
        setTimeout(() => res.destroy(), 30);
        return true;
      });
      const g = await gateway(up);
      await g.post("tools/list");
      const r = await g.post("tools/call", { name: "search", arguments: {} }, {}, 2500);
      await new Promise((x) => setTimeout(x, 100));
      expect(rejections.map(String)).toEqual([]);
      expect(toolError(r), JSON.stringify(r)).toBe(true);
    } finally {
      process.off("unhandledRejection", onRej);
    }
  });

  it("V33 gateway (GH5): an SSE answer that ends without a complete event fails closed with a tool error instead of leaving the request hanging", async () => {
    const up = await upstream({ era: "modern", tools: NOTES_TOOLS }, (m, res) => {
      if (m.method !== "tools/call") return false;
      res.writeHead(200, { "content-type": "text/event-stream" });
      // The last event has no terminating blank line, so SSE discards it at end of stream.
      res.end(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { resultType: "complete", content: [{ type: "text", text: "placeholder" }] } })}`);
      return true;
    });
    const g = await gateway(up);
    await g.post("tools/list");
    const r = await g.post("tools/call", { name: "search", arguments: {} }, {}, 3000);
    expect(r.status, "the gateway never answered").not.toBe(-1);
    expect(toolError(r)).toBe(true);
  });

  it("V34 gateway (GH6): a modern body (_meta protocolVersion 2026-07-28) under a legacy MCP-Protocol-Version header, with a wrong Mcp-Name, is 400 -32020", async () => {
    const up = await upstream({ era: "modern", tools: NOTES_TOOLS });
    const g = await gateway(up);
    await g.post("tools/list");
    const r = await g.post("tools/call", { name: "search", arguments: {} }, { "mcp-protocol-version": "2025-06-18", "mcp-name": "delete_repo" });
    expect(r.status).toBe(400);
    expect((r.json.error as Json | undefined)?.code).toBe(-32020);
  });
});

describe("gw-http review: OAuth client side", () => {
  it("V15 gateway (GH4): discovery refuses an authorization server whose issuer and endpoints are plain http on a non-loopback host", async () => {
    const map: Record<string, { status: number; headers?: Record<string, string>; body?: unknown }> = {
      "https://mcp.example/mcp": { status: 401, headers: { "www-authenticate": 'Bearer resource_metadata="https://mcp.example/.well-known/oauth-protected-resource/mcp"' } },
      "https://mcp.example/.well-known/oauth-protected-resource/mcp": { status: 200, body: { resource: "https://mcp.example/mcp", authorization_servers: ["http://as.example"] } },
      "http://as.example/.well-known/oauth-authorization-server": { status: 200, body: { issuer: "http://as.example", authorization_endpoint: "http://as.example/authorize", token_endpoint: "http://as.example/token", registration_endpoint: "http://as.example/register", code_challenge_methods_supported: ["S256"] } },
    };
    const f = (async (input: string | URL | Request) => {
      const r = map[String(input)] ?? { status: 404 };
      return new Response(r.body === undefined ? null : JSON.stringify(r.body), { status: r.status, headers: { "content-type": "application/json", ...(r.headers ?? {}) } });
    }) as typeof fetch;
    // Codes, PKCE verifiers, access and refresh tokens would all travel in clear text to http://as.example.
    await expect(discover(f, "https://mcp.example/mcp")).rejects.toThrow();
  });
});
