/**
 * The vault through the MCP gateway (acceptance V7, VFP5): the
 * gateway reads a value only after the verdict is allow, puts it into the arguments it sends upstream,
 * and scrubs every answer back to the reference before the scanner, the quarantine store, the post-tool
 * step or the client sees it. Hook mode needs the hook's single-use grant. Upstream OAuth tokens live in
 * the vault and are refreshed there. The upstream is the in-repo fake MCP server, in process and over
 * HTTP on 127.0.0.1; the store is in memory.
 */
import { createServer, type IncomingHttpHeaders } from "node:http";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { startGatewayServer } from "../../src/gateway/http.js";
import { entryHash, updateGatewayInstall } from "../../src/gateway/install.js";
import type { Json } from "../../src/gateway/jsonrpc.js";
import { canonicalResource, loadLoginMeta, loginInteractive, saveLoginMeta } from "../../src/gateway/oauth.js";
import { readVaultTokens, storeLoginInVault } from "../../src/gateway/oauth-vault.js";
import { clientToken } from "../../src/gateway/tokens.js";
import { approverPublicKey, initApprover, unlockApprover } from "../../src/runtime/approver.js";
import type { Layout } from "../../src/runtime/layout.js";
import { tailLog } from "../../src/runtime/log.js";
import { indexPath } from "../../src/runtime/vault/index.js";
import { addSecret, allowBinding } from "../../src/runtime/vault/store.js";
import { issueGrant } from "../../src/runtime/vault/tickets.js";
import { FakeUpstream, type FakeConfig } from "../fixtures/mcp-upstream/server.js";
import { gw, MODERN, newHome, textOf, type Gw } from "../gateway/harness.js";
import { fakeBackend, IBAN, type FakeStore } from "./fake.js";

const PASS = "correct horse battery";
const LINEAR = "lin_api_TESTvalue0123456789abcdefABCDEF";
const TOOLS: Json[] = ["create_issue", "create_dump", "create_enc", "delete_issue", "search"].map((name) => ({ name, description: `The ${name} tool.`, inputSchema: { type: "object", properties: { title: { type: "string" }, token: { type: "string" }, iban: { type: "string" } } } }));
const CFG: FakeConfig = { era: "modern", tools: TOOLS, echo: ["create_issue"], echo64: ["create_dump"], echoEncoded: ["create_enc"], results: { search: { content: [{ type: "text", text: `found a note: token=${LINEAR}` }] } } };
// A private Linear workspace the person exempts from the outsider-writable class (otherwise its results taint, and vault.approveWhenUntrusted would ask).
const POLICY = { mcpServers: { linear: { results: "trusted", privateData: false } }, outsiderWritable: { exempt: ["linear"] } };

function vaultHome(): { home: string; l: Layout; store: FakeStore; reads: string[] } {
  const { home, l } = newHome();
  writeFileSync(l.policy, JSON.stringify({ version: 2, ...POLICY }));
  initApprover(l, PASS);
  const priv = unlockApprover(l, PASS);
  const store = fakeBackend();
  const reads: string[] = [];
  const read = store.read.bind(store);
  store.read = (account) => {
    reads.push(account);
    return read(account);
  };
  addSecret(l, priv, { name: "linear/key", kind: "credential", fields: ["value"], values: { value: LINEAR }, confirm: "never", backend: store });
  allowBinding(l, priv, "linear/key", { kind: "mcp", server: "linear", tool: "create_*" });
  addSecret(l, priv, { name: "bank/primary", kind: "iban", fields: ["iban"], values: { iban: IBAN }, confirm: "always", backend: store });
  allowBinding(l, priv, "bank/primary", { kind: "mcp", server: "linear" });
  return { home, l, store, reads };
}

function start(mode: "full" | "hook" = "full"): Gw & { store: FakeStore; reads: string[] } {
  const v = vaultHome();
  const g = gw({ cfg: CFG, server: "linear", mode, l: v.l, home: v.home, core: { vaultBackend: () => v.store } });
  g.call("tools/list");
  return { ...g, store: v.store, reads: v.reads };
}

/** Every file under a directory, as one string. */
function everything(dir: string): string {
  let out = "";
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    out += statSync(p).isDirectory() ? everything(p) : readFileSync(p, "utf8");
  }
  return out;
}

const encoded = (v: string): string[] => [v, Buffer.from(v).toString("base64"), Buffer.from(v).toString("hex"), encodeURIComponent(v)];

describe("full mode", () => {
  it("V7: the upstream receives the value; the client never does; the echo comes back as the reference", () => {
    const g = start();
    const r = g.call("tools/call", { name: "create_issue", arguments: { title: "t", token: "vault://linear/key" } });
    expect((g.received("tools/call")?.params as Json).arguments).toEqual({ title: "t", token: LINEAR });
    expect(textOf(r)).toContain('"token":"vault://linear/key"');
    expect((r.result?.structuredContent as Json).received).toEqual({ title: "t", token: "vault://linear/key" });
    for (const m of g.inbox) for (const e of encoded(LINEAR)) expect(JSON.stringify(m)).not.toContain(e);
    const uses = tailLog(g.l, 100).map((e) => e.event).filter((e) => e.type === "vault_use");
    expect(uses).toEqual([expect.objectContaining({ ref: "vault://linear/key", kind: "credential", via: "gateway", destination: "mcp:linear:create_issue", binding: "mcp linear:create_*", verdict: "allow", client: "claude-desktop", server: "linear" })]);
    // Never on disk: log, queue, session state, quarantine, pins.
    for (const e of encoded(LINEAR)) expect(everything(g.home)).not.toContain(e);
  });
  it("encoded echoes (base64, hex, URL) are replaced by the reference too", () => {
    const g = start();
    const r = g.call("tools/call", { name: "create_enc", arguments: { token: "vault://linear/key" } });
    expect(textOf(r)).toBe("b64 vault://linear/key\nhex vault://linear/key\nurl vault://linear/key");
  });
  it("a value that cannot be scrubbed (inside a larger base64 blob) withholds the whole answer", () => {
    const g = start();
    const r = g.call("tools/call", { name: "create_dump", arguments: { token: "vault://linear/key" } });
    expect(r.result?.isError).toBe(true);
    expect(textOf(r)).toMatch(/withheld this answer from MCP server linear/);
    for (const e of encoded(LINEAR)) expect(JSON.stringify(r)).not.toContain(e);
  });
  it("a vaulted value in a later, unrelated result is replaced by its reference (by fingerprint)", () => {
    const g = start();
    expect(textOf(g.call("tools/call", { name: "search", arguments: { title: "x" } }))).toBe("found a note: token=vault://linear/key");
  });
  it("V3 analogue: a tool the secret is not bound to is denied, nothing read, nothing forwarded", () => {
    const g = start();
    const r = g.call("tools/call", { name: "delete_issue", arguments: { token: "vault://linear/key" } });
    expect(r.result?.isError).toBe(true);
    expect(textOf(r)).toMatch(/FW-VAULT-UNBOUND/);
    expect(g.up.received.some((m) => m.method === "tools/call")).toBe(false);
    expect(g.reads).toEqual([]);
  });
  it("V5 through the gateway: an IBAN is queued (no one to ask), not read, not forwarded; never in the queue, log or notification", () => {
    const v = vaultHome();
    const notes: string[] = [];
    const g = { ...gw({ cfg: CFG, server: "linear", l: v.l, home: v.home, core: { vaultBackend: () => v.store, notifyDeps: { platform: "darwin", executable: () => true, spawn: (_c: string, args: readonly string[]) => void notes.push(args.join(" ")) } } }), reads: v.reads };
    g.call("tools/list");
    const r = g.call("tools/call", { name: "create_issue", arguments: { iban: "vault://bank/primary" } });
    expect(textOf(r)).toMatch(/held this for review[\s\S]*FW-VAULT-APPROVE/);
    expect(textOf(r)).not.toContain(IBAN);
    expect(notes.length).toBeGreaterThan(0);
    expect(notes.join(" ")).not.toContain(IBAN);
    expect(everything(g.home)).toContain("vault://bank/primary");
    expect(everything(g.home)).not.toContain(IBAN);
    expect(g.reads).toEqual([]);
    expect(g.up.received.some((m) => m.method === "tools/call")).toBe(false);
  });
  it("a store that cannot be read denies at substitution time; the reference is never sent", () => {
    const g = start();
    g.store.values.delete("linear/key:value");
    const r = g.call("tools/call", { name: "create_issue", arguments: { token: "vault://linear/key" } });
    expect(textOf(r)).toMatch(/could not use vault:\/\/linear\/key/);
    expect(g.up.received.some((m) => m.method === "tools/call")).toBe(false);
    expect(tailLog(g.l, 50).map((e) => e.event).some((e) => e.type === "vault_denied")).toBe(true);
  });
  it("V9 through the gateway: an index edited on disk turns the vault off (denied, nothing read)", () => {
    const g = start();
    const doc = JSON.parse(readFileSync(indexPath(g.l), "utf8")) as { entries: { bindings: Json[] }[] };
    doc.entries[0]?.bindings.push({ kind: "mcp", server: "evil" });
    writeFileSync(indexPath(g.l), JSON.stringify(doc));
    const r = g.call("tools/call", { name: "create_issue", arguments: { token: "vault://linear/key" } });
    expect(textOf(r)).toMatch(/FW-VAULT-UNBOUND/);
    expect(g.reads).toEqual([]);
  });
  it("the wrapped server's stderr is scrubbed of vaulted values", () => {
    const g = start();
    expect(g.core.scrubDiagnostic(`received token=${LINEAR}\n`)).toBe("received token=vault://linear/key\n");
  });
  it("VFP5: a bound credential used 200 times: no vault asks, every call substituted", () => {
    const g = start();
    for (let i = 0; i < 200; i++) {
      const r = g.call("tools/call", { name: "create_issue", arguments: { title: `n${i}`, token: "vault://linear/key" } });
      expect(r.result?.isError, textOf(r)).not.toBe(true);
    }
    expect(tailLog(g.l, 1000).map((e) => e.event).filter((e) => e.type === "decision" && (e.rules as string[]).some((x) => x.startsWith("FW-VAULT")))).toEqual([]);
    expect(tailLog(g.l, 1000).map((e) => e.event).filter((e) => e.type === "vault_use").length).toBe(200);
  }, 180_000);
});

describe("hook mode", () => {
  it("without the hook's grant a call with references is refused and nothing is read", () => {
    const g = start("hook");
    const r = g.call("tools/call", { name: "create_issue", arguments: { token: "vault://linear/key" } });
    expect(textOf(r)).toMatch(/no decision of the firewall's hook allowed/);
    expect(g.reads).toEqual([]);
    expect(g.up.received.some((m) => m.method === "tools/call")).toBe(false);
  });
  it("with the grant the value goes upstream once; a replay is refused", () => {
    const g = start("hook");
    const args = { token: "vault://linear/key" };
    issueGrant(g.l, { server: "linear", tool: "create_issue", args, session: "s", seconds: 30, substitute: [{ ref: "vault://linear/key", name: "linear/key", field: "value", kind: "credential", via: "gateway", destination: "mcp:linear:create_issue", binding: "mcp linear:create_*", path: "token" }] });
    const r = g.call("tools/call", { name: "create_issue", arguments: args });
    expect((g.received("tools/call")?.params as Json).arguments).toEqual({ token: LINEAR });
    expect(textOf(r)).toContain("vault://linear/key");
    expect(JSON.stringify(r)).not.toContain(LINEAR);
    expect(textOf(g.call("tools/call", { name: "create_issue", arguments: args }))).toMatch(/no decision of the firewall's hook allowed/);
  });
  it("V17: the value goes in only at the argument path the decision checked; the same reference elsewhere stays text", () => {
    const g = start("hook");
    const args = { token: "vault://linear/key", description: "vault://linear/key", nested: { token: "vault://linear/key" } };
    issueGrant(g.l, { server: "linear", tool: "create_issue", args, session: "s", seconds: 30, substitute: [{ ref: "vault://linear/key", name: "linear/key", field: "value", kind: "credential", via: "gateway", destination: "mcp:linear:create_issue", binding: "mcp linear:create_*", path: "token" }] });
    g.call("tools/call", { name: "create_issue", arguments: args });
    expect((g.received("tools/call")?.params as Json).arguments).toEqual({ token: LINEAR, description: "vault://linear/key", nested: { token: "vault://linear/key" } });
  });
  it("V17: a grant that does not name an argument path puts nothing in and is refused", () => {
    const g = start("hook");
    const args = { token: "vault://linear/key" };
    issueGrant(g.l, { server: "linear", tool: "create_issue", args, session: "s", seconds: 30, substitute: [{ ref: "vault://linear/key", name: "linear/key", field: "value", kind: "credential", via: "gateway", destination: "mcp:linear:create_issue", binding: "mcp linear:create_*" }] });
    expect(textOf(g.call("tools/call", { name: "create_issue", arguments: args }))).toMatch(/does not say which argument/);
    expect(g.received("tools/call")).toBeUndefined();
  });
  it("a grant whose binding was revoked since is not honoured", () => {
    const g = start("hook");
    const args = { token: "vault://linear/key" };
    issueGrant(g.l, { server: "linear", tool: "create_issue", args, session: "s", seconds: 30, substitute: [{ ref: "vault://linear/key", name: "linear/key", field: "value", kind: "credential", via: "gateway", destination: "mcp:linear:create_issue", binding: "mcp linear:other", path: "token" }] });
    expect(textOf(g.call("tools/call", { name: "create_issue", arguments: args }))).toMatch(/no longer bound/);
  });
});

describe("over HTTP on 127.0.0.1, and upstream OAuth tokens in the vault", () => {
  const closers: (() => Promise<void>)[] = [];
  afterEach(async () => {
    for (const c of closers.splice(0)) await c();
  });

  async function setup(o: { status401Once?: boolean } = {}) {
    const v = vaultHome();
    const fake = new FakeUpstream(CFG);
    const seen: { headers: IncomingHttpHeaders; body: Json }[] = [];
    let failed = false;
    let tokenCalls = 0;
    const s = createServer((req, res) => {
      let body = "";
      req.on("data", (c: Buffer) => (body += c.toString()));
      req.on("end", () => {
        if (req.url === "/token") {
          tokenCalls++;
          return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ access_token: `at-refreshed-${"r".repeat(24)}`, refresh_token: `rt-refreshed-${"r".repeat(24)}`, expires_in: 3600 }));
        }
        const m = JSON.parse(body === "" ? "{}" : body) as Json;
        seen.push({ headers: req.headers, body: m });
        if (o.status401Once === true && !failed && m.method === "tools/call") {
          failed = true;
          return void res.writeHead(401).end();
        }
        const out = fake.handle(m);
        if (m.id === undefined) return void res.writeHead(202).end();
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(out.find((x) => x.id === m.id)));
      });
    });
    await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
    closers.push(() => new Promise<void>((r) => s.close(() => r())));
    const port = (s.address() as { port: number }).port;
    const url = `http://127.0.0.1:${port}/mcp`;
    const original = { url };
    updateGatewayInstall(v.l, (g) => {
      g.entries.push({ client: "cursor", server: "linear", file: "/nonexistent/mcp.json", scope: "user", mode: "full", upstream: { kind: "http", url, headerKeys: [] }, originalHash: entryHash(original), wrappedHash: "x", original, location: ["mcpServers", "linear"], wrappedAt: new Date().toISOString() });
    });
    const priv = unlockApprover(v.l, PASS);
    const name = storeLoginInVault(v.l, priv, "linear", { accessToken: `at-initial-${"i".repeat(26)}`, refreshToken: `rt-initial-${"i".repeat(26)}` }, v.store, "never");
    saveLoginMeta(v.l, { server: "linear", issuer: `http://127.0.0.1:${port}`, resource: canonicalResource(url), clientId: "c", tokenEndpoint: `http://127.0.0.1:${port}/token`, vault: name });
    const gwS = await startGatewayServer({ l: v.l, env: {}, port: 0, cwd: v.home, home: v.home, vaultBackend: () => v.store, core: { detectNonInteractive: () => true, notifyDeps: { spawn: () => undefined }, probeTimeoutMs: 2000, vaultBackend: () => v.store } });
    closers.push(gwS.close);
    const token = clientToken(v.l, "cursor");
    let id = 0;
    const post = async (method: string, params: Json = {}) => {
      const body = { jsonrpc: "2.0", id: ++id, method, params: { ...params, _meta: { "io.modelcontextprotocol/protocolVersion": MODERN, "io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/clientInfo": { name: "t", version: "1" } } } };
      const name = params.name;
      const r = await fetch(`http://127.0.0.1:${gwS.port}/c/cursor/u/linear`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json", "mcp-protocol-version": MODERN, "mcp-method": method, ...(typeof name === "string" ? { "mcp-name": name } : {}), authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
      const text = await r.text();
      return { status: r.status, text, json: (text === "" ? {} : JSON.parse(text)) as Json };
    };
    return { ...v, seen, post, name, tokenCalls: () => tokenCalls, url };
  }

  it("V7 over HTTP: argument substituted, Authorization from the vault, answer scrubbed", async () => {
    const t = await setup();
    await t.post("tools/list");
    const r = await t.post("tools/call", { name: "create_issue", arguments: { token: "vault://linear/key" } });
    const call = t.seen.find((x) => x.body.method === "tools/call");
    expect((call?.body.params as Json).arguments).toEqual({ token: LINEAR });
    expect(call?.headers.authorization).toBe(`Bearer at-initial-${"i".repeat(26)}`);
    expect(r.text).toContain("vault://linear/key");
    expect(r.text).not.toContain(LINEAR);
    // The login file keeps no token, only the entry's name.
    const meta = loadLoginMeta(t.l, "linear", canonicalResource(t.url));
    expect(meta?.vault).toBe("mcp/linear");
    expect(meta?.tokens).toBeUndefined();
    expect(everything(t.home)).not.toContain("at-initial-");
  });
  it("a 401 refreshes the token into the vault (store and fingerprints, no re-signing) and retries", async () => {
    const t = await setup({ status401Once: true });
    await t.post("tools/list");
    const r = await t.post("tools/call", { name: "create_issue", arguments: { title: "x" } });
    expect(r.json.result).toBeDefined();
    expect(t.tokenCalls()).toBe(1);
    const calls = t.seen.filter((x) => x.body.method === "tools/call");
    expect(calls[calls.length - 1]?.headers.authorization).toBe(`Bearer at-refreshed-${"r".repeat(24)}`);
    expect(readVaultTokens(t.l, t.name, "linear", approverPublicKey(t.l), () => t.store)).toEqual({ accessToken: `at-refreshed-${"r".repeat(24)}`, refreshToken: `rt-refreshed-${"r".repeat(24)}` });
    expect(everything(t.home)).not.toContain("at-refreshed-");
    expect(tailLog(t.l, 100).map((e) => e.event)).toContainEqual(expect.objectContaining({ type: "vault_change", op: "refresh", name: "mcp/linear", kind: "oauth" }));
  });
  it("the OAuth token is never usable as an argument reference", async () => {
    const t = await setup();
    await t.post("tools/list");
    const r = await t.post("tools/call", { name: "create_issue", arguments: { token: "vault://mcp/linear#access_token" } });
    expect(r.text).toMatch(/FW-VAULT-UNSUPPORTED/);
    expect(r.text).not.toContain("at-initial-");
    expect(t.seen.some((x) => x.body.method === "tools/call")).toBe(false);
  });
});

describe("mcp login stores the token in the vault", () => {
  const closers: (() => Promise<void>)[] = [];
  afterEach(async () => {
    for (const c of closers.splice(0)) await c();
  });
  it("person-run login: the tokens go into vault://mcp/<server>, signed and bound; the login file keeps none", async () => {
    const v = vaultHome();
    let port = 0;
    const s = createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://x");
      const self = `http://127.0.0.1:${port}`;
      if (u.pathname === "/.well-known/oauth-protected-resource/mcp") return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ resource: `${self}/mcp`, authorization_servers: [self] }));
      if (u.pathname === "/.well-known/oauth-authorization-server") return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ issuer: self, authorization_endpoint: `${self}/authorize`, token_endpoint: `${self}/token`, code_challenge_methods_supported: ["S256"] }));
      if (u.pathname === "/token") return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ access_token: `at-login-${"l".repeat(28)}`, refresh_token: `rt-login-${"l".repeat(28)}`, expires_in: 3600 }));
      res.writeHead(404).end();
    });
    await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
    closers.push(() => new Promise<void>((r) => s.close(() => r())));
    port = (s.address() as { port: number }).port;
    const url = `http://127.0.0.1:${port}/mcp`;
    updateGatewayInstall(v.l, (g) => {
      g.entries.push({ client: "cursor", server: "linear", file: "/nonexistent/mcp.json", scope: "user", mode: "full", upstream: { kind: "http", url, headerKeys: [] }, originalHash: entryHash({ url }), wrappedHash: "x", original: { url }, location: ["mcpServers", "linear"], wrappedAt: new Date().toISOString() });
    });
    const out: string[] = [];
    const code = await loginInteractive(v.l, "linear", {
      out: (x) => void out.push(x),
      err: (x) => void out.push(x),
      readSecret: async () => PASS,
      ask: async () => "client-1",
      env: {},
      vault: { openBackend: () => v.store, available: () => ({ ok: true }), platform: "darwin" },
      openUrl: async (authUrl) => {
        const a = new URL(authUrl);
        await fetch(`${a.searchParams.get("redirect_uri") ?? ""}?code=c1&state=${a.searchParams.get("state") ?? ""}`);
      },
    });
    expect(code, out.join("\n")).toBe(0);
    expect(out.join("\n")).toMatch(/kept in the vault as vault:\/\/mcp\/linear/);
    expect(v.store.values.get("mcp/linear:access_token")?.value).toBe(`at-login-${"l".repeat(28)}`);
    expect(readVaultTokens(v.l, "mcp/linear", "linear", approverPublicKey(v.l), () => v.store)?.refreshToken).toBe(`rt-login-${"l".repeat(28)}`);
    expect(loadLoginMeta(v.l, "linear", canonicalResource(url))).toMatchObject({ vault: "mcp/linear" });
    expect(everything(v.home)).not.toContain("at-login-");
  });
});
