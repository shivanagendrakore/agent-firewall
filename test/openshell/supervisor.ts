/**
 * A stand-in OpenShell supervisor and gateway for tests: builds the protobuf messages OpenShell sends a
 * supervisor middleware (proto/supervisor_middleware.proto, OpenShell v0.1.4) and reads the results, over a
 * real HTTP/2 gRPC connection. No OpenShell is needed.
 */

import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { grpcClient, type GrpcClient } from "../../src/openshell/grpc.js";
import { RESPONSE_SERVICE, SERVICE } from "../../src/openshell/middleware.js";
import { bytes, decode, jsonToStruct, msg, msgs, str, uint, Writer, type Fields } from "../../src/openshell/proto.js";

export interface Req {
  requestId?: string;
  sandboxId: string;
  scheme?: string;
  host: string;
  port?: number;
  method?: string;
  path?: string;
  query?: string;
  body?: string | Buffer;
  config?: Record<string, unknown>;
  /** Request headers (default: content-type application/json). */
  headers?: [string, string][];
  /** The evaluation phase (default 1, pre-credentials). */
  phase?: number;
}

function context(requestId: string, sandboxId: string): Writer {
  return new Writer().str(1, requestId).str(2, sandboxId).str(4, "demo-sandbox").str(5, "default");
}

function target(r: Pick<Req, "scheme" | "host" | "port" | "method" | "path" | "query">): Writer {
  return new Writer().str(1, r.scheme ?? "https").str(2, r.host).uint(3, r.port ?? 443).str(4, r.method ?? "GET").str(5, r.path ?? "/").str(6, r.query ?? "");
}

export function httpRequest(r: Req): Buffer {
  const w = new Writer().enum(1, r.phase ?? 1).msg(2, context(r.requestId ?? "", r.sandboxId));
  if (r.config !== undefined) w.msg(3, jsonToStruct(r.config));
  w.msg(4, target(r));
  const hs: [string, string][] = r.headers ?? [["content-type", "application/json"]];
  for (const [k, v] of hs) w.msg(5, new Writer().str(1, k).str(2, v));
  if (r.body !== undefined) w.bytes(6, typeof r.body === "string" ? Buffer.from(r.body, "utf8") : r.body);
  return w.str(7, "launchsafe-firewall").finish();
}

export interface RequestResult {
  decision: number;
  reasonCode: string;
  findings: string[];
  metadata: Record<string, string>;
}

export function readRequestResult(b: Buffer): RequestResult {
  const m = decode(b);
  const meta: Record<string, string> = {};
  for (const e of msgs(m, 7)) meta[str(e, 1)] = str(e, 2);
  return { decision: uint(m, 1), reasonCode: str(m, 8), findings: msgs(m, 6).map((f) => str(f, 2)), metadata: meta };
}

export function responsePreflight(r: Req & { status?: number; modes?: number[]; headers?: [string, string][] }): Buffer {
  const p = new Writer().msg(1, context(r.requestId ?? "", r.sandboxId)).msg(2, target(r)).uint(3, r.status ?? 200);
  for (const [k, v] of r.headers ?? []) p.msg(4, new Writer().str(1, k).str(2, v));
  p.str(5, "launchsafe-firewall");
  if (r.config !== undefined) p.msg(6, jsonToStruct(r.config));
  p.uint(7, 512 * 1024);
  // Packed repeated enum, as prost encodes it.
  const modes = r.modes ?? [1, 2, 3];
  p.bytes(8, Buffer.from(modes));
  return new Writer().msg(1, p).finish();
}

export function responseBody(seq: number, data: string | Buffer, eos = true): Buffer {
  return new Writer().msg(2, new Writer().uint(1, seq).bytes(2, typeof data === "string" ? Buffer.from(data, "utf8") : data, true).bool(3, eos)).finish();
}

export function responseTrailers(): Buffer {
  return new Writer().msg(4, new Writer()).finish();
}

export function sessionEnd(field: number): Buffer {
  return new Writer().msg(field, new Writer().enum(1, 1)).finish();
}

export function wsPreflight(r: Req): Buffer {
  return new Writer().msg(1, new Writer().str(1, "ws-1").enum(2, 1).msg(3, context(r.requestId ?? "", r.sandboxId)).msg(4, target({ ...r, scheme: r.scheme ?? "wss" })).str(6, "launchsafe-firewall")).finish();
}

export function wsMessage(seq: number, text: string): Buffer {
  return new Writer().msg(3, new Writer().uint(1, seq).str(2, text)).finish();
}

export function wsStart(): Buffer {
  return new Writer().msg(2, new Writer()).finish();
}

export function describeRequest(required: string[] = [], major = 1): Buffer {
  const peer = new Writer().msg(1, new Writer().uint(1, major).uint(2, 0)).str(2, "openshell/gateway").str(3, "0.1.4").str(4, "openshell.supervisor-middleware.contract");
  for (const r of required) peer.str(5, r);
  return new Writer().msg(1, peer).finish();
}

export function validateConfig(config: Record<string, unknown>): Buffer {
  return new Writer().msg(1, jsonToStruct(config)).str(2, "launchsafe-firewall").finish();
}

export interface Supervisor {
  client: GrpcClient;
  describe(required?: string[], major?: number): Promise<{ status: number; message: string; manifest: Fields | null }>;
  validate(config: Record<string, unknown>): Promise<{ valid: boolean; reason: string }>;
  request(r: Req, headers?: Record<string, string>): Promise<{ status: number; message: string; result: RequestResult | null }>;
  response(events: Buffer[], headers?: Record<string, string>): Promise<{ status: number; message: string; results: Fields[] }>;
  websocket(events: Buffer[], headers?: Record<string, string>): Promise<{ status: number; message: string; results: Fields[] }>;
  close(): void;
}

export function supervisor(url: string): Supervisor {
  const client = grpcClient(url);
  return {
    client,
    describe: async (required = [], major = 1) => {
      const r = await client.unary(`/${SERVICE}/Describe`, describeRequest(required, major));
      return { status: r.status, message: r.message, manifest: r.reply === null ? null : decode(r.reply) };
    },
    validate: async (config) => {
      const r = await client.unary(`/${SERVICE}/ValidateConfig`, validateConfig(config));
      const m = decode(r.reply ?? Buffer.alloc(0));
      return { valid: uint(m, 1) === 1, reason: str(m, 2) };
    },
    request: async (req, headers = {}) => {
      const r = await client.unary(`/${SERVICE}/EvaluateHttpRequest`, httpRequest(req), headers);
      return { status: r.status, message: r.message, result: r.reply === null ? null : readRequestResult(r.reply) };
    },
    response: async (events, headers = {}) => {
      const r = await client.stream(`/${RESPONSE_SERVICE}/Evaluate`, events, headers);
      return { status: r.status, message: r.message, results: r.replies.map((x) => decode(x)) };
    },
    websocket: async (events, headers = {}) => {
      const r = await client.stream(`/${SERVICE}/EvaluateWebSocketSession`, events, headers);
      return { status: r.status, message: r.message, results: r.replies.map((x) => decode(x)) };
    },
    close: () => client.close(),
  };
}

/** A gateway's signing key and a token minted the way OpenShell's gateway mints them. */
export function gatewayKeys(): { publicKey: KeyObject; mint(claims: Record<string, unknown>, header?: Record<string, unknown>): string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey,
    mint: (claims, header = { typ: "openshell-ext+jwt", alg: "EdDSA" }) => {
      const h = Buffer.from(JSON.stringify(header)).toString("base64url");
      const p = Buffer.from(JSON.stringify(claims)).toString("base64url");
      const s = sign(null, Buffer.from(`${h}.${p}`), privateKey).toString("base64url");
      return `${h}.${p}.${s}`;
    },
  };
}

export { bytes, msg, msgs, str, uint, decode };
