/**
 * A minimal gRPC server over Node's own HTTP/2 (no dependency): unary calls and bidirectional streams with
 * the standard length-prefixed framing, `grpc-status` trailers, and no message compression (a compressed
 * message is refused with UNIMPLEMENTED; we never advertise an encoding, so a conforming client never sends
 * one). It serves the OpenShell supervisor middleware (middleware.ts), plaintext (h2c) or TLS.
 */

import http2 from "node:http2";
import type { AddressInfo } from "node:net";
import { own } from "../own.js";

/** gRPC status codes used here. */
export const Status = { OK: 0, CANCELLED: 1, INVALID_ARGUMENT: 3, DEADLINE_EXCEEDED: 4, NOT_FOUND: 5, PERMISSION_DENIED: 7, RESOURCE_EXHAUSTED: 8, FAILED_PRECONDITION: 9, UNIMPLEMENTED: 12, INTERNAL: 13, UNAVAILABLE: 14, UNAUTHENTICATED: 16 } as const;

export class GrpcError extends Error {
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(message);
    this.name = "GrpcError";
  }
}

export interface CallContext {
  path: string;
  headers: http2.IncomingHttpHeaders;
  /** What `authorize` established about the caller (the middleware stores the verified token's caller here). */
  auth?: unknown;
}

export type UnaryHandler = (req: Buffer, ctx: CallContext) => Promise<Buffer>;

/** A stream handler: gets each request message in order (awaited one at a time) and sends replies with `send`. */
export interface StreamHandler {
  (ctx: CallContext, send: (msg: Buffer) => void): { message(msg: Buffer): Promise<void>; end(): Promise<void> };
}

export interface GrpcServerOptions {
  host: string;
  port: number;
  tls?: { cert: Buffer; key: Buffer };
  /** Largest request message accepted (RESOURCE_EXHAUSTED over it). */
  maxMessageBytes: number;
  unary: Record<string, UnaryHandler>;
  streams: Record<string, StreamHandler>;
  /** Checked before any handler runs; throw a GrpcError to refuse the call. */
  authorize?: (ctx: CallContext) => void;
  /** A handler's unexpected failure (never sent to the caller beyond INTERNAL). */
  onError?: (e: Error, path: string) => void;
  /** Streams one connection may have open at once (default 100, HTTP/2's SETTINGS_MAX_CONCURRENT_STREAMS). */
  maxConcurrentStreams?: number;
  /** A connection with no activity for this long is closed (default 15 minutes). */
  sessionIdleMs?: number;
  /** A call with no data in either direction for this long fails with DEADLINE_EXCEEDED (default 10 minutes; a WebSocket session's stream lasts as long as the WebSocket). */
  streamIdleMs?: number;
  /** Bytes one call may send in all (default 64 MiB) and messages (default 100000): RESOURCE_EXHAUSTED over either. */
  maxStreamBytes?: number;
  maxStreamMessages?: number;
}

export const GRPC_DEFAULTS = { maxConcurrentStreams: 100, sessionIdleMs: 15 * 60_000, streamIdleMs: 10 * 60_000, maxStreamBytes: 64 * 1024 * 1024, maxStreamMessages: 100_000 } as const;

export interface RunningGrpcServer {
  address: string;
  port: number;
  close(): Promise<void>;
}

/** One gRPC message frame. */
export function frame(msg: Buffer): Buffer {
  const head = Buffer.alloc(5);
  head.writeUInt8(0, 0);
  head.writeUInt32BE(msg.length, 1);
  return Buffer.concat([head, msg]);
}

/** Splits incoming bytes into gRPC messages. */
export class Deframer {
  private buf: Buffer = Buffer.alloc(0);
  constructor(private readonly max: number) {}

  push(chunk: Buffer): Buffer[] {
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
    const out: Buffer[] = [];
    while (this.buf.length >= 5) {
      const compressed = this.buf.readUInt8(0);
      const len = this.buf.readUInt32BE(1);
      if (compressed !== 0) throw new GrpcError(Status.UNIMPLEMENTED, "compressed messages are not supported");
      if (len > this.max) throw new GrpcError(Status.RESOURCE_EXHAUSTED, `message of ${len} bytes is over the ${this.max}-byte limit`);
      if (this.buf.length < 5 + len) break;
      out.push(this.buf.subarray(5, 5 + len));
      this.buf = this.buf.subarray(5 + len);
    }
    return out;
  }

  /** Bytes of an unfinished message left at the end of the stream. */
  pending(): number {
    return this.buf.length;
  }
}

function grpcMessage(s: string): string {
  // grpc-message is percent-encoded; keep it short and ASCII.
  return encodeURIComponent(s.slice(0, 300));
}

export async function startGrpcServer(o: GrpcServerOptions): Promise<RunningGrpcServer> {
  const lim = {
    maxConcurrentStreams: o.maxConcurrentStreams ?? GRPC_DEFAULTS.maxConcurrentStreams,
    sessionIdleMs: o.sessionIdleMs ?? GRPC_DEFAULTS.sessionIdleMs,
    streamIdleMs: o.streamIdleMs ?? GRPC_DEFAULTS.streamIdleMs,
    maxStreamBytes: o.maxStreamBytes ?? GRPC_DEFAULTS.maxStreamBytes,
    maxStreamMessages: o.maxStreamMessages ?? GRPC_DEFAULTS.maxStreamMessages,
  };
  const settings = { maxConcurrentStreams: lim.maxConcurrentStreams };
  const server = o.tls !== undefined ? http2.createSecureServer({ cert: o.tls.cert, key: o.tls.key, allowHTTP1: false, settings }) : http2.createServer({ settings });
  const sessions = new Set<http2.ServerHttp2Session>();
  server.on("session", (s) => {
    sessions.add(s);
    s.on("close", () => sessions.delete(s));
    s.on("error", () => undefined);
    s.setTimeout(lim.sessionIdleMs, () => s.destroy());
  });
  server.on("stream", (stream, headers) => {
    const path = String(headers[":path"] ?? "");
    const ctx: CallContext = { path, headers };
    let responded = false;
    const respondHeaders = (): void => {
      if (responded || stream.destroyed) return;
      responded = true;
      stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
    };
    const finish = (code: number, message = ""): void => {
      if (stream.destroyed || stream.closed) return;
      if (!responded) {
        // Trailers-only response.
        responded = true;
        stream.respond({ ":status": 200, "content-type": "application/grpc", "grpc-status": String(code), ...(message !== "" ? { "grpc-message": grpcMessage(message) } : {}) }, { endStream: true });
        return;
      }
      stream.once("wantTrailers", () => stream.sendTrailers({ "grpc-status": String(code), ...(message !== "" ? { "grpc-message": grpcMessage(message) } : {}) }));
      stream.end();
    };
    const fail = (e: unknown): void => {
      if (e instanceof GrpcError) finish(e.code, e.message);
      else {
        o.onError?.(e as Error, path);
        finish(Status.INTERNAL, "internal error");
      }
    };
    stream.on("error", () => undefined);
    if (headers[":method"] !== "POST" || !String(headers["content-type"] ?? "").startsWith("application/grpc")) {
      stream.respond({ ":status": 415 }, { endStream: true });
      return;
    }
    try {
      o.authorize?.(ctx);
    } catch (e) {
      fail(e);
      stream.resume();
      return;
    }
    const deframer = new Deframer(o.maxMessageBytes);
    // Per-call caps: bytes and messages in all, and an idle deadline (a stalled caller cannot hold a call open).
    let received = 0;
    let count = 0;
    const take = (c: Buffer): Buffer[] => {
      received += c.length;
      if (received > lim.maxStreamBytes) throw new GrpcError(Status.RESOURCE_EXHAUSTED, `the call sent more than ${lim.maxStreamBytes} bytes`);
      const out = deframer.push(c);
      count += out.length;
      if (count > lim.maxStreamMessages) throw new GrpcError(Status.RESOURCE_EXHAUSTED, `the call sent more than ${lim.maxStreamMessages} messages`);
      return out;
    };
    stream.setTimeout(lim.streamIdleMs, () => {
      fail(new GrpcError(Status.DEADLINE_EXCEEDED, "the call was idle too long"));
      // The trailers go first; then the stream is reset whether or not the caller ends its side.
      setTimeout(() => {
        if (!stream.destroyed) stream.close(http2.constants.NGHTTP2_CANCEL);
      }, 1000).unref();
    });
    const unary = own(o.unary, path);
    const streamHandler = own(o.streams, path);
    if (unary === undefined && streamHandler === undefined) {
      finish(Status.UNIMPLEMENTED, `unknown method ${path.slice(0, 200)}`);
      stream.resume();
      return;
    }
    if (unary !== undefined) {
      const msgs: Buffer[] = [];
      let broken = false;
      stream.on("data", (c: Buffer) => {
        if (broken) return;
        try {
          msgs.push(...take(c));
          if (msgs.length > 1) throw new GrpcError(Status.INVALID_ARGUMENT, "a unary call takes exactly one message");
        } catch (e) {
          broken = true;
          fail(e);
        }
      });
      stream.on("end", () => {
        if (broken) return;
        if (msgs.length !== 1 || deframer.pending() !== 0) return fail(new GrpcError(Status.INVALID_ARGUMENT, "a unary call takes exactly one message"));
        unary(msgs[0] as Buffer, ctx).then(
          (reply) => {
            respondHeaders();
            stream.write(frame(reply));
            finish(Status.OK);
          },
          (e: unknown) => fail(e),
        );
      });
      return;
    }
    // A bidirectional stream: messages are handled strictly in order.
    const send = (msg: Buffer): void => {
      respondHeaders();
      if (!stream.destroyed) stream.write(frame(msg));
    };
    const h = (streamHandler as StreamHandler)(ctx, send);
    let chain: Promise<void> = Promise.resolve();
    let broken = false;
    stream.on("data", (c: Buffer) => {
      if (broken) return;
      let msgs: Buffer[];
      try {
        msgs = take(c);
      } catch (e) {
        broken = true;
        fail(e);
        return;
      }
      for (const m of msgs) chain = chain.then(() => (broken ? undefined : h.message(m)));
      chain = chain.catch((e: unknown) => {
        broken = true;
        fail(e);
      });
    });
    stream.on("end", () => {
      chain = chain
        .then(async () => {
          if (broken) return;
          if (deframer.pending() !== 0) throw new GrpcError(Status.INVALID_ARGUMENT, "the stream ended inside a message");
          await h.end();
          finish(Status.OK);
        })
        .catch((e: unknown) => {
          broken = true;
          fail(e);
        });
    });
  });
  await new Promise<void>((done, reject) => {
    server.once("error", reject);
    server.listen(o.port, o.host, () => {
      server.removeListener("error", reject);
      done();
    });
  });
  const addr = server.address() as AddressInfo;
  return {
    address: `${o.tls !== undefined ? "https" : "http"}://${addr.family === "IPv6" ? `[${addr.address}]` : addr.address}:${addr.port}`,
    port: addr.port,
    close: () =>
      new Promise<void>((done) => {
        for (const s of sessions) s.destroy();
        server.close(() => done());
      }),
  };
}

// --- a client, for tests and the stand-in supervisor --------------------------------------------------

export interface GrpcClient {
  unary(path: string, msg: Buffer, headers?: Record<string, string>): Promise<{ status: number; message: string; reply: Buffer | null }>;
  stream(path: string, msgs: Buffer[], headers?: Record<string, string>): Promise<{ status: number; message: string; replies: Buffer[] }>;
  close(): void;
}

export function grpcClient(url: string, opts: { ca?: Buffer; rejectUnauthorized?: boolean } = {}): GrpcClient {
  const session = http2.connect(url, { ...(opts.ca !== undefined ? { ca: opts.ca } : {}), ...(opts.rejectUnauthorized !== undefined ? { rejectUnauthorized: opts.rejectUnauthorized } : {}) });
  session.on("error", () => undefined);
  const call = (path: string, msgs: Buffer[], headers: Record<string, string>): Promise<{ status: number; message: string; replies: Buffer[] }> =>
    new Promise((resolve, reject) => {
      const req = session.request({ ":method": "POST", ":path": path, "content-type": "application/grpc", te: "trailers", ...headers });
      const d = new Deframer(64 * 1024 * 1024);
      const replies: Buffer[] = [];
      let status = -1;
      let message = "";
      const take = (h: http2.IncomingHttpHeaders): void => {
        if (h["grpc-status"] !== undefined) {
          status = Number(h["grpc-status"]);
          message = decodeURIComponent(String(h["grpc-message"] ?? ""));
        }
      };
      req.on("response", take);
      req.on("trailers", take);
      req.on("data", (c: Buffer) => replies.push(...d.push(c)));
      req.on("end", () => resolve({ status, message, replies }));
      req.on("error", reject);
      for (const m of msgs) req.write(frame(m));
      req.end();
    });
  return {
    unary: async (path, msg, headers = {}) => {
      const r = await call(path, [msg], headers);
      return { status: r.status, message: r.message, reply: r.replies[0] ?? null };
    },
    stream: (path, msgs, headers = {}) => call(path, msgs, headers),
    close: () => session.close(),
  };
}
