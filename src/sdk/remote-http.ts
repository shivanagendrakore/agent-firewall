/**
 * The remote guard's transport: one JSON request to the local API sidecar over a unix socket or
 * loopback TCP, with Node's built-in http (no dependency). Every failure is a RemoteHttpError whose
 * kind is a row of the contract's fail-closed table (docs/api-v0.md); nothing else is thrown.
 */

import { randomUUID } from "node:crypto";
import { lstatSync } from "node:fs";
import http from "node:http";

/** The contract's request cap (413 over it), mirrored so an oversized body is never sent. */
export const MAX_REQUEST_BYTES = 1024 * 1024;

export type RemoteHttpErrorKind = "unavailable" | "timeout" | "server" | "rate-limited" | "api-error" | "protocol";

export class RemoteHttpError extends Error {
  constructor(
    readonly kind: RemoteHttpErrorKind,
    message: string,
    readonly status?: number,
    /** For 429: how long to wait before the next request (ms), when the sidecar said. */
    readonly retryAfterMs?: number,
  ) {
    super(message);
    this.name = "RemoteHttpError";
  }
}

export type Target = { socketPath: string } | { host: string; port: number; hostHeader?: string };

/** `http://127.0.0.1:<port>` or `http://localhost:<port>` only: the sidecar never listens elsewhere. */
export function loopbackTarget(baseUrl: string): Target {
  let u: URL;
  try {
    u = new URL(baseUrl);
  } catch {
    throw new Error(`baseUrl ${JSON.stringify(baseUrl)} is not a URL`);
  }
  if (u.protocol !== "http:") throw new Error("baseUrl must be http://127.0.0.1:<port> or http://localhost:<port>");
  if (u.hostname !== "127.0.0.1" && u.hostname !== "localhost") throw new Error(`baseUrl host ${u.hostname} is not loopback; the sidecar listens only on 127.0.0.1`);
  if (u.username !== "" || u.password !== "" || (u.pathname !== "/" && u.pathname !== "") || u.search !== "" || u.hash !== "") throw new Error("baseUrl must be only http://127.0.0.1:<port>");
  if (u.port === "") throw new Error("baseUrl needs a port");
  // localhost is pinned to 127.0.0.1, so a resolver cannot send the token elsewhere; the Host header keeps the name.
  return { host: "127.0.0.1", port: Number(u.port), ...(u.hostname === "localhost" ? { hostHeader: `localhost:${u.port}` } : {}) };
}

export interface HttpRequest {
  method: "GET" | "POST";
  path: string;
  token?: string;
  body?: unknown;
  /** Sent on every POST; a retry of the same report reuses its key. */
  idempotencyKey?: string;
  timeoutMs: number;
  maxResponseBytes: number;
}

export function newIdempotencyKey(): string {
  return randomUUID();
}

function retryAfter(v: string | string[] | undefined): number | undefined {
  const s = Array.isArray(v) ? v[0] : v;
  if (s === undefined) return undefined;
  const secs = Number(s);
  if (Number.isFinite(secs) && secs >= 0) return Math.min(secs, 3600) * 1000;
  const at = Date.parse(s);
  return Number.isFinite(at) ? Math.max(0, Math.min(at - Date.now(), 3_600_000)) : undefined;
}

/** The problem document's text, short and single-line, or the status alone. */
function problemText(status: number, raw: string): string {
  try {
    const p = JSON.parse(raw) as { title?: unknown; detail?: unknown };
    const t = typeof p.detail === "string" && p.detail !== "" ? p.detail : typeof p.title === "string" ? p.title : "";
    if (t !== "") return `${status}: ${t.replace(/\s+/g, " ").slice(0, 200)}`;
  } catch {
    // Not a problem document.
  }
  return String(status);
}

/**
 * I7: the socket must be the firewall's: a socket, owned by this user, reachable by no one else (mode 0600). Anything
 * else (a socket another user made, one left world-writable) could be a process answering "allow" that is then
 * also sent the token. Returns why it is refused, or null. A missing socket is an outage, decided by the caller.
 */
export function socketProblem(path: string, uid: number | undefined = typeof process.getuid === "function" ? process.getuid() : undefined): string | null {
  let st: ReturnType<typeof lstatSync> | undefined;
  try {
    st = lstatSync(path, { throwIfNoEntry: false });
  } catch (e) {
    return `the socket ${path} cannot be checked (${(e as NodeJS.ErrnoException).code ?? (e as Error).message})`;
  }
  if (st === undefined) return null;
  if (!st.isSocket()) return `${path} is not a socket`;
  if (uid !== undefined && st.uid !== uid) return `the socket ${path} belongs to user ${st.uid}, not this user (${uid}); it is not this user's firewall`;
  if ((st.mode & 0o077) !== 0) return `the socket ${path} is mode ${(st.mode & 0o777).toString(8)}, not 600: other users could have made or reach it`;
  return null;
}

/** Sends one request and returns the parsed JSON of a 2xx answer. Throws only RemoteHttpError. */
export function requestJson(target: Target, req: HttpRequest): Promise<unknown> {
  if ("socketPath" in target) {
    const why = socketProblem(target.socketPath);
    if (why !== null) return Promise.reject(new RemoteHttpError("api-error", `refused to use the sidecar: ${why}`));
  }
  let payload: string | undefined;
  if (req.body !== undefined) {
    try {
      payload = JSON.stringify(req.body);
    } catch (e) {
      return Promise.reject(new RemoteHttpError("api-error", `the request could not be encoded: ${(e as Error).message}`));
    }
    if (Buffer.byteLength(payload, "utf8") > MAX_REQUEST_BYTES) return Promise.reject(new RemoteHttpError("api-error", "the request is larger than the API's 1 MiB limit (not sent)", 413));
  }
  const headers: Record<string, string> = { accept: "application/json" };
  if (payload !== undefined) {
    headers["content-type"] = "application/json";
    headers["content-length"] = String(Buffer.byteLength(payload, "utf8"));
  }
  if (req.token !== undefined) headers.authorization = `Bearer ${req.token}`;
  if (req.idempotencyKey !== undefined) headers["idempotency-key"] = req.idempotencyKey;
  if ("hostHeader" in target && target.hostHeader !== undefined) headers.host = target.hostHeader;

  return new Promise<unknown>((resolve, reject) => {
    let done = false;
    // Declared before finish() so a request that throws before the timer exists can still finish.
    // eslint-disable-next-line prefer-const -- read by finish() before the request exists, assigned after it is made
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (err: RemoteHttpError | null, value?: unknown): void => {
      if (done) return;
      done = true;
      if (timer !== undefined) clearTimeout(timer);
      if (err !== null) reject(err);
      else resolve(value);
    };
    let r: http.ClientRequest;
    try {
      r = http.request({
        ...("socketPath" in target ? { socketPath: target.socketPath } : { host: target.host, port: target.port }),
        method: req.method,
        path: req.path,
        headers,
        // One connection per call: no pooled socket outlives the guard or leaks between targets.
        agent: false,
      });
    } catch (e) {
      // A header Node refuses (a token with a line break) or a bad option: a request error, not an outage.
      finish(new RemoteHttpError("api-error", `the request could not be made: ${(e as Error).message}`));
      return;
    }
    timer = setTimeout(() => {
      finish(new RemoteHttpError("timeout", `no answer within ${req.timeoutMs} ms`));
      r.destroy();
    }, req.timeoutMs);
    r.on("error", (e: NodeJS.ErrnoException) => finish(new RemoteHttpError("unavailable", `the sidecar could not be reached (${e.code ?? e.message})`)));
    r.on("response", (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (c: Buffer) => {
        size += c.length;
        if (size > req.maxResponseBytes) {
          finish(new RemoteHttpError("protocol", `the answer is larger than ${req.maxResponseBytes} bytes`, res.statusCode));
          res.destroy();
          r.destroy();
          return;
        }
        chunks.push(c);
      });
      res.on("error", () => finish(new RemoteHttpError("unavailable", "the connection broke while reading the answer", res.statusCode)));
      res.on("end", () => {
        const status = res.statusCode ?? 0;
        const raw = Buffer.concat(chunks).toString("utf8");
        if (status === 429) return finish(new RemoteHttpError("rate-limited", `rate limited (${problemText(status, raw)})`, status, retryAfter(res.headers["retry-after"])));
        if (status >= 500) return finish(new RemoteHttpError("server", `the sidecar failed (${problemText(status, raw)})`, status));
        if (status < 200 || status >= 300) return finish(new RemoteHttpError("api-error", `the sidecar refused the request (${problemText(status, raw)})`, status));
        try {
          finish(null, JSON.parse(raw) as unknown);
        } catch {
          finish(new RemoteHttpError("protocol", "the answer is not JSON", status));
        }
      });
    });
    r.end(payload);
  });
}
