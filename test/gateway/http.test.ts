/**
 * Item G acceptance, the Streamable HTTP half (GW14-GW19 over HTTP): the
 * local gateway on 127.0.0.1 in front of a fake upstream HTTP server, both on
 * the loopback interface only.
 */
import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { startGatewayServer } from "../../src/gateway/http.js";
import { entryHash, updateGatewayInstall } from "../../src/gateway/install.js";
import { authorizationUrl, canonicalResource, checkAuthorizationResponse, discover, exchangeCode, pkce, saveLogin } from "../../src/gateway/oauth.js";
import { clientToken } from "../../src/gateway/tokens.js";
import type { Json } from "../../src/gateway/jsonrpc.js";
import { tailLog } from "../../src/runtime/log.js";
import { FakeUpstream, type FakeConfig } from "../fixtures/mcp-upstream/server.js";
import { MODERN, newHome, NOTES_TOOLS, writePolicy } from "./harness.js";

const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const c of closers.splice(0)) await c();
});

interface Up {
  url: string;
  headers: IncomingHttpHeaders[];
  bodies: Json[];
}

async function listen(s: Server): Promise<number> {
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  closers.push(() => new Promise<void>((r) => s.close(() => r())));
  return (s.address() as { port: number }).port;
}

/** A fake upstream over HTTP (modern: per-request; legacy: Mcp-Session-Id). `redirectTo` answers every call with a 307. */
async function upstream(cfg: FakeConfig, o: { redirectTo?: string; status401?: boolean } = {}): Promise<Up> {
  const fake = new FakeUpstream(cfg);
  const up: Up = { url: "", headers: [], bodies: [] };
  const s = createServer((req, res) => {
    let body = "";
    req.on("data", (c: Buffer) => (body += c.toString()));
    req.on("end", () => {
      up.headers.push(req.headers);
      const m = JSON.parse(body === "" ? "{}" : body) as Json;
      up.bodies.push(m);
      if (o.redirectTo !== undefined && m.method === "tools/call") return void res.writeHead(307, { location: o.redirectTo }).end();
      if (o.status401 === true && m.method === "tools/call") return void res.writeHead(401, { "www-authenticate": 'Bearer resource_metadata="x"' }).end();
      const out = fake.handle(m);
      if (m.id === undefined) return void res.writeHead(202).end();
      const r = out.find((x) => x.id === m.id);
      if (r === undefined) return void res.writeHead(400, { "content-type": "text/plain" }).end("bad request");
      if (cfg.era === "legacy" && (r.error as Json | undefined) !== undefined && m.method === "server/discover") return void res.writeHead(400, { "content-type": "text/plain" }).end("unknown method");
      res.writeHead(200, { "content-type": "application/json", ...(cfg.era === "legacy" && m.method === "initialize" ? { "mcp-session-id": "sess-1" } : {}) }).end(JSON.stringify(r));
    });
  });
  up.url = `http://127.0.0.1:${await listen(s)}/mcp`;
  return up;
}

async function gateway(up: Up, policy?: Json, server = "notes") {
  const { home, l } = newHome();
  if (policy !== undefined) writePolicy(l, policy);
  const original = { url: up.url, headers: { Authorization: "Bearer upstream-static-token" } };
  const token = clientToken(l, "cursor");
  updateGatewayInstall(l, (g) => {
    g.entries.push({ client: "cursor", server, file: "/nonexistent/mcp.json", scope: "user", mode: "full", upstream: { kind: "http", url: up.url, headerKeys: ["Authorization"] }, originalHash: entryHash(original), wrappedHash: "x", original, location: ["mcpServers", server], wrappedAt: new Date().toISOString() });
  });
  const s = await startGatewayServer({ l, env: {}, port: 0, cwd: home, home, core: { detectNonInteractive: () => true, notifyDeps: { spawn: () => undefined }, probeTimeoutMs: 2000 } });
  closers.push(s.close);
  const base = `http://127.0.0.1:${s.port}/c/cursor/u/${server}`;
  let id = 0;
  const post = async (method: string, params: Json = {}, headers: Record<string, string> = {}, o: { meta?: boolean; auth?: string | null } = {}) => {
    const body = { jsonrpc: "2.0", id: ++id, method, params: o.meta === false ? params : { ...params, _meta: { "io.modelcontextprotocol/protocolVersion": MODERN, "io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/clientInfo": { name: "t", version: "1" } } } };
    const name = method === "resources/read" ? params.uri : params.name;
    const h: Record<string, string> = { "content-type": "application/json", accept: "application/json", "mcp-protocol-version": MODERN, "mcp-method": method, ...(typeof name === "string" ? { "mcp-name": name } : {}), ...(o.auth !== null ? { authorization: o.auth ?? `Bearer ${token}` } : {}), ...headers };
    const r = await fetch(base, { method: "POST", headers: h, body: JSON.stringify(body) });
    const text = await r.text();
    return { status: r.status, json: (text === "" ? {} : JSON.parse(text)) as Json };
  };
  return { l, home, base, post, token, port: s.port };
}

const TRUSTED = { mcpServers: { notes: { results: "trusted", privateData: false } } };

describe("GW14-GW16: the client side of the HTTP gateway", () => {
  it("a modern request with matching headers is forwarded; the upstream receives regenerated headers", async () => {
    const up = await upstream({ era: "modern", tools: NOTES_TOOLS });
    const g = await gateway(up, TRUSTED);
    expect((await g.post("tools/list")).json.result).toMatchObject({ tools: [{ name: "search" }, { name: "create_note" }] });
    const r = await g.post("tools/call", { name: "search", arguments: { q: "x" } });
    expect(r.json.result).toMatchObject({ content: [{ text: "ok search" }] });
    const h = up.headers[up.headers.length - 1] as IncomingHttpHeaders;
    expect(h["mcp-method"]).toBe("tools/call");
    expect(h["mcp-name"]).toBe("search");
    expect(h["mcp-protocol-version"]).toBe(MODERN);
  });

  it("GW14: Mcp-Name says search, the body says delete_repo: 400 -32020 and nothing forwarded", async () => {
    const up = await upstream({ era: "modern", tools: NOTES_TOOLS });
    const g = await gateway(up, TRUSTED);
    await g.post("tools/list");
    const before = up.bodies.length;
    const r = await g.post("tools/call", { name: "delete_repo", arguments: {} }, { "mcp-name": "search" });
    expect(r.status).toBe(400);
    expect((r.json.error as Json).code).toBe(-32020);
    expect(up.bodies.length).toBe(before);
    // A missing Mcp-Method is a mismatch too.
    const r2 = await fetch(g.base, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${g.token}`, "mcp-protocol-version": MODERN }, body: JSON.stringify({ jsonrpc: "2.0", id: 99, method: "tools/list", params: { _meta: { "io.modelcontextprotocol/protocolVersion": MODERN } } }) });
    expect(r2.status).toBe(400);
  });

  it("GW15: no per-client bearer is 401; Origin https://evil.example is 403; a foreign Host is 403", async () => {
    const up = await upstream({ era: "modern", tools: NOTES_TOOLS });
    const g = await gateway(up, TRUSTED);
    expect((await g.post("tools/list", {}, {}, { auth: null })).status).toBe(401);
    expect((await g.post("tools/list", {}, {}, { auth: "Bearer lsgw_notthetokenatallnotthetoken" })).status).toBe(401);
    expect((await g.post("tools/list", {}, { origin: "https://evil.example" })).status).toBe(403);
    const { request } = await import("node:http");
    const status = await new Promise<number>((resolve) => {
      const req = request({ host: "127.0.0.1", port: g.port, path: "/c/cursor/u/notes", method: "POST", headers: { host: "evil.example", authorization: `Bearer ${g.token}` } }, (res) => resolve(res.statusCode ?? 0));
      req.end("{}");
    });
    expect(status).toBe(403);
    expect(up.bodies.length).toBe(0);
  });

  it("GW16: the client's own Authorization is dropped; the upstream receives only its own token", async () => {
    const up = await upstream({ era: "modern", tools: NOTES_TOOLS });
    const g = await gateway(up, TRUSTED);
    saveLogin(g.l, { server: "notes", issuer: "https://as.example", resource: canonicalResource(up.url), clientId: "c", tokenEndpoint: "https://as.example/token", tokens: { accessToken: "upstream-oauth-token" } });
    await g.post("tools/list");
    for (const h of up.headers) {
      expect(h.authorization).toBe("Bearer upstream-oauth-token");
      expect(JSON.stringify(h)).not.toContain(g.token);
    }
  });
});

describe("GW18, 401: upstream audience rules", () => {
  it("GW18: an upstream redirect to another origin is not followed; the token is not sent; FW-MCP-AUTH; tool error", async () => {
    const other = await upstream({ era: "modern", tools: NOTES_TOOLS });
    const up = await upstream({ era: "modern", tools: NOTES_TOOLS }, { redirectTo: other.url });
    const g = await gateway(up, TRUSTED);
    await g.post("tools/list");
    const r = await g.post("tools/call", { name: "search", arguments: {} });
    expect(r.json.result).toMatchObject({ isError: true });
    expect(JSON.stringify(r.json)).toContain("FW-MCP-AUTH");
    expect(other.bodies.length).toBe(0);
    expect(tailLog(g.l, 50).some((e) => e.event.type === "gateway_auth" && e.event.rule === "FW-MCP-AUTH")).toBe(true);
  });

  it("a 401 from the upstream becomes a tool error naming mcp login; the client is never asked to authenticate through the proxy", async () => {
    const up = await upstream({ era: "modern", tools: NOTES_TOOLS }, { status401: true });
    const g = await gateway(up, TRUSTED);
    await g.post("tools/list");
    const r = await g.post("tools/call", { name: "search", arguments: {} });
    expect(r.status).toBe(200);
    expect(JSON.stringify(r.json)).toContain("mcp login notes");
  });
});

describe("GW19 over HTTP: eras", () => {
  it("a modern client through the gateway to a legacy HTTP upstream: initialize, its session id kept", async () => {
    const up = await upstream({ era: "legacy", tools: NOTES_TOOLS });
    const g = await gateway(up, TRUSTED);
    expect((await g.post("tools/list")).json.result).toMatchObject({ tools: [{ name: "search" }, { name: "create_note" }] });
    expect(up.bodies.map((b) => b.method)).toEqual(["server/discover", "initialize", "notifications/initialized", "tools/list"]);
    expect(up.headers[3]?.["mcp-session-id"]).toBe("sess-1");
    // Legacy upstream: no modern routing headers are invented for it.
    expect(up.headers[3]?.["mcp-method"]).toBeUndefined();
  });
});

describe("GW17: the OAuth client side", () => {
  async function authServer(o: { iss: boolean }) {
    const seen: { token: URLSearchParams[] } = { token: [] };
    const s = createServer((req, res) => {
      let body = "";
      req.on("data", (c: Buffer) => (body += c.toString()));
      req.on("end", () => {
        const u = new URL(req.url ?? "/", "http://x");
        const self = `http://127.0.0.1:${port}`;
        if (u.pathname === "/.well-known/oauth-protected-resource/mcp") return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ resource: `${self}/mcp`, authorization_servers: [self] }));
        if (u.pathname === "/.well-known/oauth-authorization-server") return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ issuer: self, authorization_endpoint: `${self}/authorize`, token_endpoint: `${self}/token`, code_challenge_methods_supported: ["S256"], authorization_response_iss_parameter_supported: o.iss }));
        if (u.pathname === "/token") {
          seen.token.push(new URLSearchParams(body));
          return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ access_token: "at", refresh_token: "rt", expires_in: 3600 }));
        }
        if (u.pathname === "/mcp") return void res.writeHead(401, { "www-authenticate": `Bearer resource_metadata="${self}/.well-known/oauth-protected-resource/mcp"` }).end();
        res.writeHead(404).end();
      });
    });
    const port = await listen(s);
    return { url: `http://127.0.0.1:${port}/mcp`, seen, issuer: `http://127.0.0.1:${port}` };
  }

  it("the token request carries resource = the canonical upstream URI; an authorization response without iss is rejected when the metadata advertises it", async () => {
    const as = await authServer({ iss: true });
    const d = await discover(fetch, as.url);
    expect(d.resource).toBe(as.url);
    const { verifier, challenge } = pkce();
    const url = new URL(authorizationUrl(d, "client-1", "http://127.0.0.1:1/callback", "st", challenge));
    expect(url.searchParams.get("resource")).toBe(as.url);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    const used = new Set<string>();
    expect(() => checkAuthorizationResponse(d, new URLSearchParams({ code: "c", state: "st" }), "st", used)).toThrow(/RFC 9207/);
    expect(() => checkAuthorizationResponse(d, new URLSearchParams({ code: "c", state: "st2", iss: "https://evil.example" }), "st2", new Set())).toThrow(/issuer/);
    const code = checkAuthorizationResponse(d, new URLSearchParams({ code: "c", state: "st3", iss: as.issuer }), "st3", used);
    expect(() => checkAuthorizationResponse(d, new URLSearchParams({ code: "c", state: "st3", iss: as.issuer }), "st3", used)).toThrow(/state/);
    await exchangeCode(fetch, d, "client-1", code, "http://127.0.0.1:1/callback", verifier);
    expect(as.seen.token[0]?.get("resource")).toBe(as.url);
    expect(as.seen.token[0]?.get("code_verifier")).toBe(verifier);
  });

  it("protected resource metadata naming another resource is refused", async () => {
    const as = await authServer({ iss: false });
    await expect(discover(fetch, `${as.url}/other`)).rejects.toThrow();
  });
});
