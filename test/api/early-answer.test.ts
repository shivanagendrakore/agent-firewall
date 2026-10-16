/**
 * A server that answers before it has read the body (413 by Content-Length, 401 or 403 before the body), and a
 * client that is still writing it. On CI (Node 22) the root suite passed every test yet exited 1 on one uncaught
 * "write EPIPE" from test/api/server.test.ts: the 413 test's call settled at the answer while its 1 MiB body was
 * still being written, afterEach closed every connection, and the write broke on a socket node:http had left
 * without an 'error' listener. These tests force that order with a raw server, so they do not depend on timing,
 * and check the sidecar side: a client that hangs up never crashes it and never keeps its in-flight slot.
 */

import { createServer, connect, Socket, type Server } from "node:net";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ApiServer } from "../../src/api/server.js";
import { agent, apiTree, call, decideBody, guardSocket, removeApiTree, startServer, type ApiTree } from "./harness.js";

const ANSWER = '{"type":"about:blank#too-large","title":"Payload too large","status":413,"detail":"too big"}';
const HTTP_413 = `HTTP/1.1 413 Payload Too Large\r\ncontent-type: application/problem+json\r\nconnection: keep-alive\r\ncontent-length: ${Buffer.byteLength(ANSWER)}\r\n\r\n${ANSWER}`;
/** Far more than a unix socket's buffers hold, so the write is still in flight while the server does not read. */
const BIG = "x".repeat(8 * 1024 * 1024);

const pause = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function errnoError(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(`write ${code}`), { code, syscall: "write" });
}

describe("an answer before the body, against a raw server", () => {
  let t: ApiTree;
  let raw: Server;
  let path: string;
  const conns: Socket[] = [];
  beforeEach(() => {
    t = apiTree();
    path = join(t.sockDir, "raw.sock");
  });
  afterEach(async () => {
    for (const c of conns.splice(0)) c.destroy();
    await new Promise<void>((r) => raw.close(() => r()));
    removeApiTree(t);
  });

  /** A server that answers `reply` on the first bytes of a request, stops reading, and hands the connection back. */
  async function rawServer(reply: string | null): Promise<{ conn: Promise<Socket>; target: ApiServer }> {
    let got: (s: Socket) => void = () => undefined;
    const conn = new Promise<Socket>((r) => {
      got = r;
    });
    raw = createServer((c) => {
      conns.push(c);
      c.on("error", () => undefined);
      c.once("data", () => {
        c.pause();
        if (reply !== null) c.write(reply);
        got(c);
      });
    });
    await new Promise<void>((r) => raw.listen(path, r));
    return { conn, target: { socket: path } as unknown as ApiServer };
  }

  it("the call settles only once the request is closed, and a broken pipe after the whole answer is tolerated", async () => {
    const { conn, target } = await rawServer(HTTP_413);
    let settled = false;
    const p = call(target, { path: "/v1/decide", token: "t", raw: BIG }).finally(() => {
      settled = true;
    });
    const c = await conn;
    await pause(300);
    // The answer has arrived, but the body is still being written: the call must not have settled. (It did before,
    // in res 'end'; this line fails if call resolves there again.)
    expect(settled).toBe(false);
    // The server closes without reading the rest: the client's write breaks (EPIPE or ECONNRESET).
    c.destroy();
    const r = await p;
    expect(r.status).toBe(413);
    expect(r.type).toMatch(/^application\/problem\+json/);
    expect(r.body).toMatchObject({ status: 413, title: "Payload too large" });
  });

  it("a connection closed before any answer is still an error", async () => {
    const { conn, target } = await rawServer(null);
    const p = call(target, { path: "/v1/decide", token: "t", raw: BIG });
    (await conn).destroy();
    await expect(p).rejects.toThrow();
  });

  it("a connection closed in the middle of the answer is still an error", async () => {
    const { conn, target } = await rawServer(HTTP_413.slice(0, -10));
    const p = call(target, { path: "/v1/decide", token: "t", raw: BIG });
    const c = await conn;
    await pause(100);
    c.destroy();
    await expect(p).rejects.toThrow();
  });
});

describe("guardSocket: the listener a request's socket keeps for its whole life", () => {
  it("without it an 'error' on a socket is thrown (an uncaught exception in the run); with it a late EPIPE or ECONNRESET is not", () => {
    const bare = new Socket();
    expect(() => bare.emit("error", errnoError("EPIPE"))).toThrow(/EPIPE/);
    const sock = new Socket();
    guardSocket(sock);
    guardSocket(sock);
    expect(sock.listenerCount("error")).toBe(1);
    expect(() => sock.emit("error", errnoError("EPIPE"))).not.toThrow();
    expect(() => sock.emit("error", errnoError("ECONNRESET"))).not.toThrow();
  });

  it("any other error still surfaces", () => {
    const sock = new Socket();
    guardSocket(sock);
    expect(() => sock.emit("error", errnoError("EACCES"))).toThrow(/EACCES/);
    expect(() => sock.emit("error", new Error("something else"))).toThrow(/something else/);
  });
});

describe("the sidecar when a client hangs up", () => {
  let t: ApiTree;
  let s: ApiServer;
  let token: string;
  beforeEach(async () => {
    t = apiTree();
    token = agent(t, "bot");
    // One request in flight at a time: a slot a hang-up kept would turn every later request into a 503.
    s = await startServer(t, { limits: { maxInFlight: 1, perAgentPerSecond: 1e9, perAgentBurst: 1e9 } });
  });
  afterEach(async () => {
    await s.close();
    removeApiTree(t);
  });

  async function hangUp(head: string, after: string, waitMs: number): Promise<void> {
    const c = connect(s.socket as string);
    c.on("error", () => undefined);
    await new Promise<void>((r) => c.once("connect", () => r()));
    c.write(head + after);
    await pause(waitMs);
    c.destroy();
    await pause(50);
  }

  it("in the middle of a body, before the answer, and right after sending a request: no crash, and the slot is freed", async () => {
    const body = JSON.stringify(decideBody("hang", { format: "native", tool: "lookup_status", input: { id: "1" } }));
    for (let i = 0; i < 3; i++) {
      // Half a body: the server is reading it when the client goes.
      await hangUp(`POST /v1/decide HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer ${token}\r\ncontent-type: application/json\r\ncontent-length: 100000\r\n\r\n`, "{\"session\":", 150);
      // A whole request, and gone before the answer is written.
      await hangUp(`POST /v1/decide HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer ${token}\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(body)}\r\n\r\n`, body, 0);
      // Over the limit by Content-Length: answered 413 at once, and the client goes while "sending" the rest.
      await hangUp(`POST /v1/decide HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer ${token}\r\ncontent-type: application/json\r\ncontent-length: ${8 * 1024 * 1024}\r\n\r\n`, "x".repeat(64 * 1024), 20);
    }
    expect((await call(s, { path: "/v1/health" })).status).toBe(200);
    const r = await call(s, { path: "/v1/decide", token, body: JSON.parse(body) as unknown });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.verdict).toBe("allow");
  });

  it("a real 413 while the client is still writing: the answer is checked, and nothing is left writing afterwards", async () => {
    const big = JSON.stringify(decideBody("a", { format: "engine", tool: "Write", input: { file_path: "/tmp/x", content: "x".repeat(4 * 1024 * 1024) } }));
    for (let i = 0; i < 5; i++) {
      const r = await call(s, { path: "/v1/decide", token, raw: big });
      expect(r.status).toBe(413);
      expect(r.type).toMatch(/^application\/problem\+json/);
      expect(r.body).toMatchObject({ status: 413, title: "Payload too large" });
    }
    expect((await call(s, { path: "/v1/health" })).status).toBe(200);
  });
});
