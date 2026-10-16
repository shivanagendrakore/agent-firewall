/**
 * The local API in a throwaway tree: its own firewall home, workspace, home and scratch (inside the suite's
 * temporary root), and a socket there too, or in a short directory under /tmp only when the root is too deep
 * for a unix socket path (limited to about 100 bytes). Requests go over the socket (or TCP) with node:http, as an SDK sends them. Nothing here starts a
 * shell; every command in a test is a string the engine judges.
 */

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { request } from "node:http";
import type { Socket } from "node:net";
import { join } from "node:path";
import { addToken, type TokenRole } from "../../src/api/tokens.js";
import { writeRegistry } from "../../src/api/registry.js";
import { startApiServer, type ApiServer, type ApiServerOptions } from "../../src/api/server.js";
import { layout, type Layout } from "../../src/runtime/layout.js";
import { testRoot } from "../helpers.js";

export interface ApiTree {
  root: string;
  sockDir: string;
  ws: string;
  home: string;
  scratch: string;
  l: Layout;
}

/** A unix socket path must stay under about 104 bytes (sun_path); keep a margin. */
const MAX_SOCKET_PATH = 100;

/**
 * The socket's directory: inside the suite's temporary root (removed with it by the global setup), unless
 * that root is so deep the socket path would not fit; only then a short directory under /tmp.
 */
function socketDir(): string {
  const managed = mkdtempSync(join(testRoot(), "s-"));
  if (join(managed, "api.sock").length <= MAX_SOCKET_PATH) return managed;
  rmSync(managed, { recursive: true, force: true });
  return mkdtempSync("/tmp/lsfwapi-");
}

export function apiTree(): ApiTree {
  const root = mkdtempSync(join(testRoot(), "api-"));
  const sockDir = socketDir();
  const ws = join(root, "workspace");
  const home = join(root, "home");
  const scratch = join(root, "scratch");
  for (const d of [ws, home, scratch]) mkdirSync(d, { recursive: true });
  return { root, sockDir, ws, home, scratch, l: layout(join(root, "state")) };
}

export function removeApiTree(t: ApiTree): void {
  rmSync(t.root, { recursive: true, force: true });
  rmSync(t.sockDir, { recursive: true, force: true });
}

export const REGISTRY = {
  tools: {
    search_docs: { kind: "read", results: "untrusted" },
    get_customer: { kind: "read", results: "trusted", privateData: true, server: "crm" },
    lookup_status: { kind: "read", results: "trusted", privateData: false, server: "status" },
    send_email: { kind: "send" },
    delete_account: { kind: "destroy" },
    run_shell: { as: "Bash", map: { command: "$.cmd" } },
    http_get: { as: "WebFetch", map: { url: "$.url" } },
  },
};

export async function startServer(t: ApiTree, o: Partial<ApiServerOptions> = {}): Promise<ApiServer> {
  // The fuzzers send one agent's requests as fast as the server answers: no rate limit unless a test sets one (I6).
  return startApiServer({ l: t.l, env: {}, home: t.home, scratch: [t.scratch], socket: join(t.sockDir, "api.sock"), limits: { perAgentPerSecond: 1e9, perAgentBurst: 1e9 }, ...o });
}

/** A token for the agent, and its registry. */
export function agent(t: ApiTree, id: string, registry: unknown = REGISTRY, traffic?: "network", roles?: readonly TokenRole[]): string {
  if (registry !== null) writeRegistry(t.l, id, registry);
  return addToken(t.l, id, new Date(), traffic, roles);
}

/** Every role: a token that may also apply prompts (the person's UI and the agent in one process, as in the library). */
export const ALL_ROLES: readonly TokenRole[] = ["decide", "report", "prompt"];

export interface Res {
  status: number;
  type: string;
  body: Record<string, unknown>;
}

export interface Req {
  method?: string;
  path: string;
  token?: string;
  body?: unknown;
  raw?: string | Buffer;
  headers?: Record<string, string>;
}

/**
 * The only errors tolerated, and only once the whole answer has arrived: the server may answer before it has
 * read the body (a 413 by Content-Length, a 401 before the body) and close the connection, so a write still in
 * flight fails with a broken pipe or a reset. The answer is what the test checks.
 */
const LATE_BREAK: ReadonlySet<string> = new Set(["EPIPE", "ECONNRESET"]);

/** What a request saw on its socket while it owned it. */
interface Owner {
  error?: NodeJS.ErrnoException;
}

const owners = new WeakMap<Socket, Owner>();
const guarded = new WeakSet<Socket>();

/**
 * node:http's keep-alive agent leaves a socket with no 'error' listener at all for a moment when it hands it
 * back to the pool or to the next request (node's own TODO(ronag) notes in lib/_http_client.js responseKeepAlive
 * and onSocket, and lib/_http_agent.js on 'free'); an EPIPE from a write still in flight lands there as an
 * uncaught exception, which fails the whole run (CI, Node 22) though every test passed. Every socket a request
 * gets carries this listener for its life: while a request owns it the error is kept for that request (call
 * decides), afterwards only a late broken pipe or reset is ignored, and anything else is rethrown.
 */
export function guardSocket(sock: Socket): void {
  if (guarded.has(sock)) return;
  guarded.add(sock);
  sock.on("error", (e: NodeJS.ErrnoException) => {
    const owner = owners.get(sock);
    if (owner !== undefined) {
      owner.error ??= e;
      return;
    }
    if (LATE_BREAK.has(e.code ?? "")) return;
    throw e;
  });
}

/**
 * One request to the server (its socket, or its TCP port). It settles only when the request is closed, never
 * while its body is still being written, so no write outlives the test that made it (the server is closed in
 * afterEach, and a write still in flight then broke in the next test).
 */
export function call(s: ApiServer, r: Req): Promise<Res> {
  const payload = r.raw !== undefined ? r.raw : r.body !== undefined ? JSON.stringify(r.body) : undefined;
  const headers: Record<string, string> = { ...(r.token !== undefined ? { authorization: `Bearer ${r.token}` } : {}), ...(payload !== undefined ? { "content-type": "application/json" } : {}), ...(r.headers ?? {}) };
  const target = s.socket !== undefined ? { socketPath: s.socket } : { host: "127.0.0.1", port: s.port };
  return new Promise((resolve, reject) => {
    let answer: Res | undefined;
    let failure: Error | undefined;
    let sock: Socket | undefined;
    const owner: Owner = {};
    const req = request({ ...target, method: r.method ?? (payload !== undefined ? "POST" : "GET"), path: r.path, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("error", (e: Error) => {
        failure ??= e;
      });
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let body: Record<string, unknown> = {};
        try {
          body = JSON.parse(text) as Record<string, unknown>;
        } catch {
          body = { text };
        }
        answer = { status: res.statusCode ?? 0, type: String(res.headers["content-type"] ?? ""), body };
      });
    });
    req.on("socket", (s0: Socket) => {
      sock = s0;
      guardSocket(s0);
      owners.set(s0, owner);
    });
    req.on("error", (e: Error) => {
      failure ??= e;
    });
    req.on("close", () => {
      if (sock !== undefined && owners.get(sock) === owner) owners.delete(sock);
      const e = failure ?? owner.error;
      try {
        if (answer !== undefined && (e === undefined || LATE_BREAK.has((e as NodeJS.ErrnoException).code ?? ""))) resolve(answer);
        else reject(e ?? new Error("the connection closed before the whole answer arrived"));
      } finally {
        // A no-op for a socket kept alive in the pool (node marks the request destroyed when it frees it).
        req.destroy();
      }
    });
    if (payload !== undefined) req.end(payload);
    else req.end();
  });
}

export function decideBody(session: string, action: Record<string, unknown>, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { session, action, ...extra };
}
