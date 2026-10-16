/**
 * `launchsafe-firewall mcp serve`: the local Streamable HTTP gateway
 * (MCP 2026-07-28
 * basic/transports/streamable-http).
 *
 * Client side:
 * - binds 127.0.0.1 only; validates `Host` (DNS rebinding) and `Origin`
 *   (403), and requires the per-client bearer `lsgw_…` (401). The gateway
 *   publishes no protected resource metadata, so no client starts an OAuth
 *   flow against it, and it drops every other Authorization and Cookie;
 * - `POST /c/<client>/u/<server>`; a modern request whose MCP-Protocol-Version,
 *   Mcp-Method or Mcp-Name (or a Mcp-Param-* header) disagrees with the body
 *   is rejected with 400 and -32020 HeaderMismatch, as the MCP spec requires of a
 *   server that reads the body; GET and DELETE answer 405 (2026-07-28 has no
 *   GET stream or sessions; a legacy client's standalone GET stream is not
 *   supported in v0.3);
 * - responses are JSON, or SSE when the upstream streamed and the client
 *   accepts it; `subscriptions/listen` streams are relayed event by event.
 *
 * Upstream side:
 * - every header is regenerated from the body the gateway sends (never
 *   copied); Authorization carries only the upstream's own token (the login
 *   stored by `mcp login`, else the static header recorded at wrap time), and
 *   only to the origin of the resource it was issued for: a redirect to
 *   another origin is not followed and drops the token (FW-MCP-AUTH);
 * - a 401 becomes a tool error naming `mcp login`; the client never
 *   authenticates through the proxy;
 * - a legacy upstream's Mcp-Session-Id is kept per gateway instance.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { loadPolicy } from "../runtime/config.js";
import type { Layout } from "../runtime/layout.js";
import { appendBounded as appendLog } from "../runtime/logbound.js";
import { gatewayPolicy } from "../policy-gateway.js";
import { readGatewayInstall, isClient, type GatewayEntry } from "./install.js";
import { errorResponse, HEADER_MISMATCH, isRequest, isResponse, MAX_MESSAGE_BYTES, parseMessage, type Json, type Message, type Request } from "./jsonrpc.js";
import { checkClientHeaders, upstreamHeaders } from "./headers.js";
import { canonicalResource, loadLoginMeta, originOf, refreshTokens, saveLogin, secureEndpoint, RULE_AUTH, type Fetch, type LoginMeta, type TokenSet } from "./oauth.js";
import { readVaultTokens, refreshVaultTokens } from "./oauth-vault.js";
import { trustedApproverKey } from "../hook/pipeline.js";
import { defaultBackendFor, type BackendFor } from "../runtime/vault/substitute.js";
import { GatewayCore, type CoreOptions } from "./pipeline.js";
import { HttpSessions } from "./session.js";
import { coreOptionsFor } from "./stdio.js";
import { clientOfToken } from "./tokens.js";
import { setOwn } from "../own.js";
import { logSafe } from "../sdk/guard.js";

export interface ServeOptions {
  l: Layout;
  env: NodeJS.ProcessEnv;
  port: number;
  cwd: string;
  home?: string;
  diag?: (s: string) => void;
  fetch?: Fetch;
  /** Tests: extra core options (a fake clock, a fixed session...). */
  core?: Partial<CoreOptions>;
  /** The vault's stores, for upstream OAuth tokens kept there (tests pass an in-memory one). */
  vaultBackend?: BackendFor;
  /** How long an upstream may take for its whole answer (ms; default UPSTREAM_TIMEOUT_MS). Not for subscriptions/listen. */
  upstreamTimeoutMs?: number;
}

interface Waiter {
  res: ServerResponse;
  sse: boolean;
  started: boolean;
  listen: boolean;
  /** Set once the upstream fetch for a subscriptions/listen stream exists: ends it when the client goes away. */
  abort?: () => void;
}

/** One wrapped HTTP server for one client: a pipeline and its upstream connection. */
class Route {
  readonly core: GatewayCore;
  private readonly waiters = new Map<string, Waiter>();
  private sessionId: string | null = null;
  private readonly upstreamUrl: string;
  constructor(
    private readonly o: ServeOptions,
    readonly entry: GatewayEntry,
    sessions: HttpSessions,
    /** What the install record looked like when this route was built (wrappedAt, originalHash): a changed record needs a new route. */
    readonly stamp: string = "",
  ) {
    if (entry.upstream.kind !== "http") throw new Error("not an HTTP entry");
    this.upstreamUrl = entry.upstream.url;
    const { options } = coreOptionsFor({ l: o.l, env: o.env, client: entry.client, server: entry.server, mode: entry.mode, cwd: o.cwd, transport: "http", ...(o.home !== undefined ? { home: o.home } : {}) });
    this.core = new GatewayCore({ ...options, session: () => sessions.sessionFor(entry.client), ...(o.diag !== undefined ? { diag: o.diag } : {}), ...(o.core ?? {}) }, { client: (m) => this.toClient(m), upstream: (m) => void this.send(m).catch((e: unknown) => this.diag(`LaunchSafe Firewall gateway: an internal error was caught (${(e as Error).message})`)) });
  }

  private key(id: unknown): string {
    return `${typeof id}:${String(id)}`;
  }

  /** Registers the client's open response for a request id; false when that id already has one (it is never replaced). */
  wait(id: unknown, w: Waiter): boolean {
    const k = this.key(id);
    if (this.waiters.has(k)) return false;
    this.waiters.set(k, w);
    return true;
  }

  /** The client's connection closed: its waiter goes, and a subscriptions/listen stream upstream is ended. */
  drop(id: unknown, w: Waiter): void {
    const k = this.key(id);
    if (this.waiters.get(k) === w) this.waiters.delete(k);
    if (!w.res.writableFinished) w.abort?.();
  }

  private write(w: Waiter, m: Message): void {
    if (w.sse) {
      if (!w.started) {
        w.res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", "x-accel-buffering": "no" });
        w.started = true;
      }
      w.res.write(`event: message\ndata: ${JSON.stringify(m)}\n\n`);
    } else {
      w.res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(m));
      w.started = true;
    }
  }

  private toClient(m: Message): void {
    if ("id" in m && m.id !== undefined && m.id !== null && (isResponse(m) || isRequest(m))) {
      const k = this.key(m.id);
      const w = this.waiters.get(k);
      if (w === undefined) return;
      if (isResponse(m)) {
        // The final answer (a result or an error), of a listen stream too: it ends the stream.
        this.waiters.delete(k);
        this.write(w, m);
        if (w.sse) w.res.end();
      } else this.write(w, m);
      return;
    }
    // A notification: to the listen stream if there is one, else to the only request in flight that streams.
    const open = [...this.waiters.values()];
    const target = open.find((w) => w.listen) ?? (open.length === 1 && open[0]?.sse === true ? open[0] : undefined);
    if (target !== undefined) this.write(target, m);
  }

  /**
   * `unreachable`: the failure says nothing about the server's protocol (no connection, a timeout, 401, a server
   * error). The era probe and the gateway's own initialize then leave the era undecided instead of reading the
   * failure as "legacy" (which would then brick the route); other requests are answered as always.
   */
  private fail(m: Message, message: string, unreachable = false): void {
    if (!isRequest(m)) return;
    if (unreachable && this.core.upstreamUnavailable(m.id, message)) return;
    // A tool call gets a tool error the model and the person can read; anything else a JSON-RPC error
    // (which also drives the era probe's fallback).
    if (m.method === "tools/call") this.core.fromUpstream({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: message }], isError: true } });
    else this.core.fromUpstream(errorResponse(m.id, -32000, message));
  }

  /** Tokens read from the vault, kept in memory for this route until a refresh replaces them. */
  private vaultTokens: TokenSet | null = null;

  private backendFor(): BackendFor {
    return this.o.vaultBackend ?? this.o.core?.vaultBackend ?? defaultBackendFor(this.o.l);
  }

  /** The login's tokens: from its vault entry (only while the signed index binds it to this server) or its file. */
  private tokensOf(login: LoginMeta): TokenSet | null {
    if (login.vault === undefined) return login.tokens ?? null;
    this.vaultTokens ??= readVaultTokens(this.o.l, login.vault, this.entry.server, trustedApproverKey(this.o.l, this.o.env), this.backendFor());
    return this.vaultTokens;
  }

  private authHeader(): string | null {
    const login = loadLoginMeta(this.o.l, this.entry.server, canonicalResource(this.upstreamUrl));
    if (login !== null) {
      // GW11: an OAuth token never goes to a plain-http upstream off this machine (mcp login refuses one too).
      try {
        secureEndpoint("MCP server", this.upstreamUrl);
      } catch {
        return null;
      }
      // A login whose vault entry is gone or no longer bound sends no token: the person signs in again.
      const t = this.tokensOf(login);
      return t !== null ? `Bearer ${t.accessToken}` : null;
    }
    const orig = this.entry.original.headers;
    if (typeof orig === "object" && orig !== null) {
      for (const [k, v] of Object.entries(orig as Json)) if (k.toLowerCase() === "authorization" && typeof v === "string") return v;
    }
    return null;
  }

  private refreshing: Promise<boolean> | null = null;

  /**
   * Concurrent 401s share one refresh (a rotating refresh token is good for one use), and a request whose 401
   * answered an access token that has been replaced since goes straight to its retry with the new one.
   */
  private refreshShared(sent: string | null): Promise<boolean> {
    const now = this.authHeader();
    if (now !== null && now !== sent) return Promise.resolve(true);
    this.refreshing ??= this.refresh().finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private async refresh(): Promise<boolean> {
    const resource = canonicalResource(this.upstreamUrl);
    const login = loadLoginMeta(this.o.l, this.entry.server, resource);
    if (login === null) return false;
    const current = this.tokensOf(login);
    if (current?.refreshToken === undefined) return false;
    try {
      const tokens = await refreshTokens(this.o.fetch ?? fetch, { tokenEndpoint: login.tokenEndpoint, resource }, login.clientId, current.refreshToken);
      if (login.vault !== undefined) {
        refreshVaultTokens(this.o.l, login.vault, this.entry.server, { ...tokens, ...(tokens.refreshToken === undefined ? { refreshToken: current.refreshToken } : {}) }, trustedApproverKey(this.o.l, this.o.env), this.backendFor());
        this.vaultTokens = null;
      } else saveLogin(this.o.l, { server: login.server, issuer: login.issuer, resource: login.resource, clientId: login.clientId, tokenEndpoint: login.tokenEndpoint, tokens });
      appendLog(this.o.l, { type: "gateway_auth", event: "refresh", server: this.entry.server });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * One message to the upstream. Fails closed (V14, V33): a reset or a read error mid-answer, a stream that
   * ends without a complete answer, or an answer with another id gets the request a tool error (a JSON-RPC
   * error for other methods) instead of leaving it unanswered; nothing here rejects unhandled.
   */
  private async send(m: Message): Promise<void> {
    try {
      await this.toUpstream(m);
    } catch (e) {
      this.diag(`LaunchSafe Firewall gateway: the answer from MCP server ${this.entry.server} broke off (${(e as Error).message})`);
      if (isRequest(m) && this.core.awaiting(m.id)) this.fail(m, `LaunchSafe Firewall gateway: the connection to MCP server ${this.entry.server} broke off before it answered, so there is no result.`, true);
      return;
    }
    if (isRequest(m) && this.core.awaiting(m.id)) this.fail(m, `LaunchSafe Firewall gateway: MCP server ${this.entry.server} ended its answer without a complete result, so there is no result.`, true);
  }

  private diag(line: string): void {
    try {
      this.o.diag?.(line);
    } catch {
      // Diagnostics never break the request.
    }
  }

  /**
   * An upstream that never answers would keep the client's request (and its socket) open for ever: every call but
   * a subscriptions/listen stream has upstreamTimeoutMs (default UPSTREAM_TIMEOUT_MS) for its whole answer.
   */
  private async toUpstream(m: Message): Promise<void> {
    const listen = isRequest(m) && m.method === "subscriptions/listen";
    const ms = this.o.upstreamTimeoutMs ?? UPSTREAM_TIMEOUT_MS;
    const ctl = new AbortController();
    if (listen && isRequest(m)) {
      const w = this.waiters.get(this.key(m.id));
      if (w !== undefined) w.abort = () => ctl.abort(new Error("the client closed the stream"));
      else ctl.abort(new Error("the client closed the stream"));
    }
    const timer = listen ? undefined : setTimeout(() => ctl.abort(new Error(`MCP server ${this.entry.server} did not answer within ${Math.round(ms / 1000)} s`)), ms);
    timer?.unref?.();
    try {
      await this.toUpstreamOnce(m, false, ctl.signal);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  private async toUpstreamOnce(m: Message, retried: boolean, signal: AbortSignal): Promise<void> {
    const f = this.o.fetch ?? fetch;
    const body = m as Request;
    const name = isRequest(m) && m.method === "tools/call" && typeof m.params?.name === "string" ? m.params.name : undefined;
    const headers: Record<string, string> = upstreamHeaders(body, name !== undefined ? this.core.toolSchema(name) : undefined);
    const auth = this.authHeader();
    // Never transit: the token was issued for this resource (loadLogin matches it) and goes only to its
    // URL: redirects are never followed (below), and the client's own Authorization never gets here.
    if (auth !== null) headers.authorization = auth;
    for (const [k, v] of Object.entries((this.entry.original.headers ?? {}) as Json)) if (typeof v === "string" && !/^(?:authorization|cookie|host|content-length|connection|transfer-encoding|mcp-.*)$/i.test(k)) setOwn(headers, k.toLowerCase(), v);
    if (this.sessionId !== null) headers["mcp-session-id"] = this.sessionId;
    let r: Response;
    try {
      r = await f(this.upstreamUrl, { method: "POST", headers, body: JSON.stringify(m), redirect: "manual", signal });
    } catch (e) {
      this.fail(m, `LaunchSafe Firewall gateway: could not reach MCP server ${this.entry.server} (${(e as Error).message})`, true);
      return;
    }
    if (r.status >= 300 && r.status < 400) {
      const loc = r.headers.get("location") ?? "";
      let other = true;
      try {
        other = originOf(new URL(loc, this.upstreamUrl).toString()) !== originOf(this.upstreamUrl);
      } catch {
        other = true;
      }
      appendLog(this.o.l, { type: "gateway_auth", event: "redirect_refused", server: this.entry.server, to: logSafe(loc).slice(0, 200), otherOrigin: other, rule: RULE_AUTH });
      this.fail(m, `LaunchSafe Firewall gateway: MCP server ${this.entry.server} redirected the call to ${other ? "another origin" : "another address"}; the gateway does not follow redirects, so its token was not sent there. (rule ${RULE_AUTH})`, true);
      return;
    }
    if (r.status === 401) {
      if (!retried && (await this.refreshShared(auth))) return this.toUpstreamOnce(m, true, signal);
      appendLog(this.o.l, { type: "gateway_auth", event: "unauthorized", server: this.entry.server });
      this.fail(m, `LaunchSafe Firewall gateway: MCP server ${this.entry.server} needs you to sign in. Run in your own terminal: launchsafe-firewall mcp login ${this.entry.server}`, true);
      return;
    }
    const sid = r.headers.get("mcp-session-id");
    if (sid !== null && /^[\x21-\x7e]{1,256}$/.test(sid)) this.sessionId = sid;
    if (r.status === 202) return;
    const type = r.headers.get("content-type") ?? "";
    if (type.includes("text/event-stream") && r.body !== null) {
      const reader = r.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        if (buf.length > MAX_MESSAGE_BYTES) {
          this.core.upstreamOversize();
          await reader.cancel();
          break;
        }
        let at = buf.search(/\r?\n\r?\n/);
        while (at !== -1) {
          const event = buf.slice(0, at);
          buf = buf.slice(at).replace(/^\r?\n\r?\n/, "");
          const data = event.split(/\r?\n/).filter((x) => x.startsWith("data:")).map((x) => x.slice(5).replace(/^ /, "")).join("\n");
          if (data !== "") this.core.upstreamText(data);
          at = buf.search(/\r?\n\r?\n/);
        }
      }
      return;
    }
    // Read with the cap applied as the bytes arrive: a body far larger than 16 MiB is never held whole.
    const text = await readCapped(r, MAX_MESSAGE_BYTES);
    if (text === null) {
      this.core.upstreamOversize();
      this.fail(m, "LaunchSafe Firewall gateway: the server's answer was larger than 16 MiB", true);
      return;
    }
    const p = parseMessage(text);
    if (p.ok && isResponse(p.msg)) {
      this.core.fromUpstream(p.msg);
      return;
    }
    // A refusal or a server that is down (403, 408, 429, 5xx) says nothing about its protocol; a plain 4xx for an
    // unknown method is how an older server answers the era probe.
    this.fail(m, `LaunchSafe Firewall gateway: MCP server ${this.entry.server} answered HTTP ${r.status}`, r.status >= 500 || r.status === 403 || r.status === 408 || r.status === 429);
  }
}

/** How long an upstream may take for its whole answer (ms). */
export const UPSTREAM_TIMEOUT_MS = 300_000;

/** A response body as text, or null once it passes `max` bytes (the rest is not read). */
async function readCapped(r: Response, max: number): Promise<string | null> {
  if (r.body === null) return "";
  const reader = r.body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    n += value.byteLength;
    if (n > max) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function readBody(req: IncomingMessage): Promise<string | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let n = 0;
    req.on("data", (c: Buffer) => {
      n += c.length;
      if (n > MAX_MESSAGE_BYTES) {
        resolve(null);
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => resolve(null));
  });
}

function reject(res: ServerResponse, status: number, message: string, code = -32600, id: unknown = null): void {
  res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }));
}

/** Host and Origin checks against DNS rebinding: only this machine's loopback names on this port. */
export function hostAllowed(host: string | undefined, port: number): boolean {
  return host === `127.0.0.1:${port}` || host === `localhost:${port}`;
}

export function originAllowed(origin: string | undefined, port: number): boolean {
  return origin === undefined || origin === `http://127.0.0.1:${port}` || origin === `http://localhost:${port}`;
}

export async function startGatewayServer(o: ServeOptions): Promise<{ port: number; server: Server; close: () => Promise<void> }> {
  const routes = new Map<string, Route>();
  const sessions = new HttpSessions(o.l, () => gatewayPolicy(loadPolicy(o.l, [o.cwd]).config).httpSessionIdleMinutes);
  let port = o.port;
  const route = (client: string, server: string): Route | null => {
    const k = `${client}\u0000${server}`;
    let entry: GatewayEntry | undefined;
    try {
      entry = readGatewayInstall(o.l).entries.find((e) => e.client === client && e.server === server && e.upstream.kind === "http");
    } catch {
      // An install record that cannot be read: nothing is served from a route built on an older one.
      return null;
    }
    // The record is gone (unwrapped): its route goes too. A re-wrap or an edit has another wrappedAt or originalHash.
    if (entry === undefined) {
      routes.delete(k);
      return null;
    }
    const stamp = `${entry.wrappedAt}\u0000${entry.originalHash}`;
    const existing = routes.get(k);
    if (existing !== undefined && existing.stamp === stamp) return existing;
    const r = new Route(o, entry, sessions, stamp);
    routes.set(k, r);
    return r;
  };
  const server = createServer((req, res) => {
    void (async () => {
      if (!hostAllowed(req.headers.host, port)) return reject(res, 403, "LaunchSafe Firewall gateway: wrong Host");
      if (!originAllowed(req.headers.origin, port)) return reject(res, 403, "LaunchSafe Firewall gateway: requests from web pages are refused (Origin)");
      const m = /^\/c\/([^/]+)\/u\/([^/?#]+)$/.exec((req.url ?? "").split("?")[0] ?? "");
      if (m === null) return reject(res, 404, "LaunchSafe Firewall gateway: no such endpoint");
      const client = decodeURIComponent(m[1] as string);
      const name = decodeURIComponent(m[2] as string);
      const auth = req.headers.authorization ?? "";
      const token = /^Bearer (lsgw_[A-Za-z0-9_-]{20,})$/.exec(auth)?.[1];
      if (!isClient(client) || token === undefined || clientOfToken(o.l, token) !== client) return reject(res, 401, "LaunchSafe Firewall gateway: this client's gateway token is missing or wrong");
      if (req.method === "GET" || req.method === "DELETE") return reject(res, 405, "LaunchSafe Firewall gateway: only POST (MCP 2026-07-28 Streamable HTTP)");
      if (req.method !== "POST") return reject(res, 405, "LaunchSafe Firewall gateway: only POST");
      const r = route(client, name);
      if (r === null) return reject(res, 404, `LaunchSafe Firewall gateway: ${name} is not a wrapped HTTP server of ${client}`);
      const text = await readBody(req);
      if (text === null) return reject(res, 413, "LaunchSafe Firewall gateway: larger than 16 MiB");
      const p = parseMessage(text);
      if (!p.ok) return reject(res, 400, `LaunchSafe Firewall gateway: ${p.reason}`, p.code, p.id);
      const msg = p.msg;
      if (isResponse(msg)) return reject(res, 400, "LaunchSafe Firewall gateway: clients do not send responses over Streamable HTTP");
      if (isRequest(msg)) {
        const name2 = msg.method === "tools/call" && typeof msg.params?.name === "string" ? msg.params.name : undefined;
        const mismatch = checkClientHeaders(req.headers, msg, name2 !== undefined ? r.core.toolSchema(name2) : undefined);
        if (mismatch !== null) {
          appendLog(o.l, { type: "gateway_protocol", from: "client", problem: `header mismatch: ${mismatch}`.slice(0, 300), client, server: name });
          return reject(res, 400, `Header mismatch: ${mismatch}`, HEADER_MISMATCH, msg.id);
        }
        const accept = req.headers.accept ?? "";
        const w: Waiter = { res, sse: accept.includes("text/event-stream"), started: false, listen: msg.method === "subscriptions/listen" };
        // An id that already has an open response is refused here: registering it would replace that waiter.
        if (!r.wait(msg.id, w)) return reject(res, 400, "LaunchSafe Firewall gateway: a request with this id is still in flight; each request needs its own id, so this one was not passed on", -32600, msg.id);
        res.on("close", () => r.drop(msg.id, w));
        r.core.fromClient(msg);
        return;
      }
      r.core.fromClient(msg);
      res.writeHead(202).end();
    })().catch((e: unknown) => {
      o.diag?.(`LaunchSafe Firewall gateway: ${(e as Error).message}`);
      if (!res.headersSent) reject(res, 500, "LaunchSafe Firewall gateway: internal error");
    });
  });
  await new Promise<void>((resolve) => server.listen(o.port, "127.0.0.1", resolve));
  port = (server.address() as { port: number }).port;
  return { port, server, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}
