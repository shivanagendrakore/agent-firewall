/**
 * `launchsafe-firewall serve --api`: the local API sidecar's transport (docs/api.md, docs/api-v0.md).
 *
 * - A unix socket at <firewall home>/api.sock (mode 0600, created under a umask that never leaves it
 *   wider), or `--listen 127.0.0.1:<port>`; any other address is refused before anything listens.
 * - The MCP gateway's hardening (src/gateway/http.ts hostAllowed): on TCP, Host must be 127.0.0.1:<port> or
 *   localhost:<port> (DNS rebinding). On both, any request with an Origin header is refused (403): no web
 *   page may call the API. Cookie is never read.
 * - Bodies are JSON of at most 1 MiB (413); errors are application/problem+json.
 * - Every /v1 call except GET /v1/health needs a per-agent bearer token (core.ts authenticate).
 */

import { lstatSync, chmodSync, unlinkSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { connect } from "node:net";
import { hostAllowed } from "../gateway/http.js";
import { ensureDir } from "../runtime/fsutil.js";
import type { Layout } from "../runtime/layout.js";
import { ApiCore, problem, roleRefused, type ApiCoreOptions, type Caller, type Reply } from "./core.js";
import { socketPath } from "./files.js";
import { BadRequest } from "./request.js";

export const MAX_BODY_BYTES = 1024 * 1024;

export interface ApiServerOptions extends ApiCoreOptions {
  l: Layout;
  /** Listen on TCP instead of the socket (see parseListen). */
  listen?: { host: "127.0.0.1"; port: number };
  /** The socket path (default <firewall home>/api.sock). */
  socket?: string;
  diag?: (s: string) => void;
  /** I6: request limits (DEFAULT_LIMITS for anything not given). */
  limits?: Partial<ApiLimits>;
}

/**
 * I6: one agent's traffic must not starve another's (decisions are made one at a time, each fsynced to the log).
 * Past its own limits an agent gets 429 with Retry-After (the SDKs wait, and decide nothing in that time); past
 * the server's limit on requests in flight, everyone gets 503 with Retry-After (overload, not a refusal).
 */
export interface ApiLimits {
  /** Requests one agent may have in flight at once. */
  perAgentConcurrent: number;
  /** Requests per second one agent may send, sustained (a token bucket)... */
  perAgentPerSecond: number;
  /** ...and in a burst. */
  perAgentBurst: number;
  /** Requests in flight on the whole server (authenticated or not). */
  maxInFlight: number;
}

export const DEFAULT_LIMITS: ApiLimits = { perAgentConcurrent: 32, perAgentPerSecond: 100, perAgentBurst: 300, maxInFlight: 256 };

/** The per-agent buckets and counts (I6). Agents are those with a token, so the map is bounded by the token file. */
export class Limiter {
  private inFlight = 0;
  private readonly agents = new Map<string, { active: number; tokens: number; at: number }>();
  constructor(
    private readonly lim: ApiLimits,
    private readonly now: () => number = Date.now,
  ) {}

  /** A request arrives: false (503) when the server already has maxInFlight. */
  enter(): boolean {
    if (this.inFlight >= this.lim.maxInFlight) return false;
    this.inFlight += 1;
    return true;
  }

  leave(): void {
    this.inFlight = Math.max(0, this.inFlight - 1);
  }

  /** An authenticated agent's request: null when it may go on (call agentDone after), else seconds to wait (429). */
  agent(agent: string): number | null {
    const t = this.now();
    let a = this.agents.get(agent);
    if (a === undefined) {
      a = { active: 0, tokens: this.lim.perAgentBurst, at: t };
      this.agents.set(agent, a);
    }
    a.tokens = Math.min(this.lim.perAgentBurst, a.tokens + (Math.max(0, t - a.at) / 1000) * this.lim.perAgentPerSecond);
    a.at = t;
    if (a.active >= this.lim.perAgentConcurrent) return 1;
    if (a.tokens < 1) return Math.max(1, Math.ceil((1 - a.tokens) / this.lim.perAgentPerSecond));
    a.tokens -= 1;
    a.active += 1;
    return null;
  }

  agentDone(agent: string): void {
    const a = this.agents.get(agent);
    if (a !== undefined) a.active = Math.max(0, a.active - 1);
  }
}

export interface ApiServer {
  /** "unix:<path>" or "http://127.0.0.1:<port>". */
  address: string;
  socket?: string;
  port?: number;
  server: Server;
  core: ApiCore;
  close: () => Promise<void>;
}

/** `--listen` values: only this machine's loopback. Throws for anything else. */
export function parseListen(s: string): { host: "127.0.0.1"; port: number } {
  const m = /^(127\.0\.0\.1|localhost):(\d{1,5})$/.exec(s);
  const port = m === null ? NaN : Number(m[2]);
  if (m === null || !(port >= 0 && port <= 65535)) throw new Error(`--listen ${s.slice(0, 100)} is refused: the API listens only on this machine's loopback, as 127.0.0.1:<port> or localhost:<port>`);
  return { host: "127.0.0.1", port };
}

function send(res: ServerResponse, r: Reply): void {
  const isProblem = r.status >= 400;
  res.writeHead(r.status, { "content-type": isProblem ? "application/problem+json" : "application/json", "cache-control": "no-store", ...(r.retryAfter !== undefined ? { "retry-after": String(r.retryAfter) } : {}) }).end(JSON.stringify(r.body));
}

/** The body as text, or a 413 reply when it is larger than the limit. */
function readBody(req: IncomingMessage): Promise<string | Reply> {
  const tooLarge = problem(413, "too-large", "Payload too large", `the body is larger than ${MAX_BODY_BYTES} bytes`);
  const declared = Number(req.headers["content-length"] ?? "0");
  if (declared > MAX_BODY_BYTES) {
    req.resume();
    return Promise.resolve(tooLarge);
  }
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let n = 0;
    let over = false;
    req.on("data", (c: Buffer) => {
      if (over) return;
      n += c.length;
      if (n > MAX_BODY_BYTES) {
        over = true;
        chunks.length = 0;
        resolve(tooLarge);
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (!over) resolve(Buffer.concat(chunks).toString("utf8"));
    });
    req.on("error", () => {
      if (!over) resolve(problem(400, "bad-request", "Bad request", "the body could not be read"));
    });
    // An aborted request can close without "end" or "error": settle, so the in-flight slots are released.
    const aborted = (): void => {
      if (!over) resolve(problem(400, "bad-request", "Bad request", "the body could not be read"));
    };
    req.on("aborted", aborted);
    req.on("close", () => {
      if (!req.complete) aborted();
    });
  });
}

function segment(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    throw new BadRequest("the path is not valid percent-encoding");
  }
}

/** One request, after the transport checks; an authenticated agent's within its limits (I6). */
async function route(core: ApiCore, req: IncomingMessage, limiter: Limiter): Promise<Reply> {
  const path = (req.url ?? "").split("?")[0] ?? "";
  const method = req.method ?? "";
  if (path === "/v1/health") return method === "GET" ? core.health() : problem(405, "method-not-allowed", "Method not allowed", "use GET");
  const decide = path === "/v1/decide";
  const sessionPost = /^\/v1\/sessions\/([^/]+)\/(results|inputs|prompts)$/.exec(path);
  const sessionGet = /^\/v1\/sessions\/([^/]+)$/.exec(path);
  const approval = /^\/v1\/approvals\/([^/]+)$/.exec(path);
  if (!decide && sessionPost === null && sessionGet === null && approval === null) return problem(404, "not-found", "Not found", "no such endpoint");
  const wantPost = decide || sessionPost !== null;
  if (method !== (wantPost ? "POST" : "GET")) return problem(405, "method-not-allowed", "Method not allowed", `use ${wantPost ? "POST" : "GET"}`);
  const auth = core.authenticate(req.headers.authorization);
  if ("status" in auth) return auth;
  const agent = auth.agent;
  // I1: each endpoint needs its role (src/api/tokens.ts), checked before the body is read.
  const kind = sessionPost?.[2];
  const refused = kind === "prompts" ? (auth.roles.includes("prompt") ? null : roleRefused(auth, "report")) : roleRefused(auth, kind === "results" || kind === "inputs" ? "report" : "decide");
  if (refused !== null) return refused;
  const wait = limiter.agent(agent);
  if (wait !== null) {
    req.resume();
    return { ...problem(429, "rate-limited", "Too many requests", `agent ${agent} is over its request limits; retry after ${wait} s`), retryAfter: wait };
  }
  try {
    return await routeAs(core, req, agent, auth, { decide, sessionPost, sessionGet, approval, wantPost });
  } finally {
    limiter.agentDone(agent);
  }
}

async function routeAs(core: ApiCore, req: IncomingMessage, agent: string, auth: Caller, m0: { decide: boolean; sessionPost: RegExpExecArray | null; sessionGet: RegExpExecArray | null; approval: RegExpExecArray | null; wantPost: boolean }): Promise<Reply> {
  const { decide, sessionPost, sessionGet, approval, wantPost } = m0;
  if (!wantPost) {
    if (sessionGet !== null) return core.session(agent, segment(sessionGet[1] as string));
    return core.approval(agent, segment((approval as RegExpExecArray)[1] as string));
  }
  const text = await readBody(req);
  if (typeof text !== "string") return text;
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return problem(400, "bad-json", "Bad request", "the body is not valid JSON");
  }
  if (decide) {
    const key = req.headers["idempotency-key"];
    if (key !== undefined && (typeof key !== "string" || !/^[\x21-\x7e]{1,255}$/.test(key))) return problem(400, "bad-request", "Bad request", "Idempotency-Key must be 1 to 255 visible ASCII characters");
    return core.decide(agent, body, text, key, auth.networkTraffic);
  }
  const m = sessionPost as RegExpExecArray;
  const session = segment(m[1] as string);
  if (m[2] === "results") return core.result(agent, session, body);
  if (m[2] === "inputs") return core.input(agent, session, body);
  return core.prompt(agent, session, body, auth.roles.includes("prompt"));
}

/** Whether something already answers on the socket path. */
function socketInUse(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const c = connect(path);
    c.once("connect", () => {
      c.destroy();
      resolve(true);
    });
    c.once("error", () => resolve(false));
  });
}

/** Removes a stale socket file; refuses a live one or anything that is not a socket. */
async function clearSocket(path: string): Promise<void> {
  const st = lstatSync(path, { throwIfNoEntry: false });
  if (st === undefined) return;
  if (!st.isSocket()) throw new Error(`${path} exists and is not a socket; move it away first`);
  if (await socketInUse(path)) throw new Error(`another API server is already listening on ${path}`);
  unlinkSync(path);
}

export async function startApiServer(o: ApiServerOptions): Promise<ApiServer> {
  const core = new ApiCore(o);
  const limiter = new Limiter({ ...DEFAULT_LIMITS, ...(o.limits ?? {}) });
  let port = o.listen?.port ?? 0;
  const tcp = o.listen !== undefined;
  const server = createServer((req, res) => {
    let entered = false;
    void (async () => {
      // Hardening first, before anything is read or authenticated.
      if (req.headers.origin !== undefined) return send(res, problem(403, "forbidden", "Forbidden", "requests from web pages are refused (Origin)"));
      if (tcp && !hostAllowed(req.headers.host, port)) return send(res, problem(403, "forbidden", "Forbidden", "wrong Host: use 127.0.0.1:<port> or localhost:<port>"));
      if (!limiter.enter()) {
        req.resume();
        return send(res, { ...problem(503, "overloaded", "Service unavailable", "the firewall has too many requests in flight; retry after 1 s"), retryAfter: 1 });
      }
      entered = true;
      try {
        send(res, await route(core, req, limiter));
      } finally {
        limiter.leave();
        entered = false;
      }
    })().catch((e: unknown) => {
      if (entered) limiter.leave();
      if (e instanceof BadRequest) {
        if (!res.headersSent) send(res, problem(400, e.slug, "Bad request", e.message));
        return;
      }
      try {
        o.diag?.(`LaunchSafe Firewall API: ${(e as Error).message}`);
      } catch {
        // Diagnostics never break the reply.
      }
      if (!res.headersSent) send(res, problem(500, "internal", "Internal error", "the firewall could not handle this request"));
    });
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  if (tcp) {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    port = (server.address() as { port: number }).port;
    return { address: `http://127.0.0.1:${port}`, port, server, core, close: () => closeServer(server) };
  }
  const path = o.socket ?? socketPath(o.l);
  // Unix socket paths are limited to about 104 bytes (macOS) or 108 (Linux).
  if (Buffer.byteLength(path) > 100) throw new Error(`the socket path ${path} is too long for a unix socket (over 100 bytes): use a shorter LAUNCHSAFE_FIREWALL_HOME, or --listen 127.0.0.1:<port>`);
  ensureDir(o.l.home);
  await clearSocket(path);
  // The socket is created 0600 (never briefly wider), then set so explicitly.
  const old = process.umask(0o177);
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(path, () => {
        server.off("error", reject);
        resolve();
      });
    });
  } finally {
    process.umask(old);
  }
  chmodSync(path, 0o600);
  return {
    address: `unix:${path}`,
    socket: path,
    server,
    core,
    close: async () => {
      await closeServer(server);
      try {
        unlinkSync(path);
      } catch {
        // Already gone.
      }
    },
  };
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections();
  });
}
