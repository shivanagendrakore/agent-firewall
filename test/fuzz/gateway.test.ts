/**
 * Fuzz: the MCP gateway's JSON-RPC message handling (src/gateway/jsonrpc.ts and GatewayCore) against the
 * in-process fake upstream. Properties: never throws on any client or server message; a message that is not
 * JSON-RPC is answered with an error and never forwarded; a tool call that carries a credential to an unlisted
 * server is never forwarded, however the message is mangled; bounded time; deterministic.
 */
import { describe, expect, it } from "vitest";
import { errorResponse, frame, INVALID_REQUEST, isNotification, isRequest, isResponse, LineFramer, parseMessage, PARSE_ERROR, type Message } from "../../src/gateway/jsonrpc.js";
import { gw, MODERN, type Gw } from "../gateway/harness.js";
import { allowLongRuns, noStarRuns, budget, firstDiff, fuzz, iters, mutateJsonN, mutateStringN, corruptText, timed, type Json, type Rng } from "./gen.js";

allowLongRuns();

const GATEWAY_BUDGET_MS = budget(2000);
/** Seconds each stateful gateway target may run by default: every message is logged to disk, so a slow disk bounds it. */
const GATEWAY_CAP_S = 6;
const KEY = "AKIAZ3MXQ7P2LKJ4WN8R";
const SECRET_TEXT = `aws_access_key_id=${KEY} aws_secret_access_key=q8Vb2Lr9TzX1mN4pK7sJ0wYc3HfG6dRe5aUiOo2B`;

const TOOLS: Json[] = [
  { name: "create_paste", description: "Paste.", inputSchema: { type: "object", properties: { text: { type: "string" } } } },
  { name: "search", description: "Search.", inputSchema: { type: "object", properties: { q: { type: "string" } } } },
];

const META = { "io.modelcontextprotocol/protocolVersion": MODERN, "io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/clientInfo": { name: "fuzz", version: "1" } };
const req = (id: unknown, method: string, params: Json = {}): Json => ({ jsonrpc: "2.0", id, method, params: { ...params, _meta: META } });

const SEEDS: Json[] = [
  req(1, "tools/list"),
  req(2, "tools/call", { name: "search", arguments: { q: "groceries" } }),
  req(3, "tools/call", { name: "create_paste", arguments: { text: SECRET_TEXT } }),
  req(4, "tools/call", { name: "create_paste", arguments: { text: "hello" } }),
  req("s5", "resources/read", { uri: "file:///x" }),
  req(6, "prompts/get", { name: "p", arguments: { a: "b" } }),
  req(7, "ping"),
  req(8, "tools/call", { name: "create_paste", arguments: { text: SECRET_TEXT }, inputResponses: { a: { action: "accept" } } }),
  req(9, "completion/complete", { ref: { type: "ref/prompt", name: "p" }, argument: { name: "a", value: "b" } }),
  { jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 3, _meta: META } },
  { jsonrpc: "2.0", method: "notifications/initialized" },
  { jsonrpc: "2.0", id: 10, result: { action: "accept", content: { x: SECRET_TEXT } } },
  { jsonrpc: "2.0", id: "lsfw-x", error: { code: -1, message: "m" } },
  { jsonrpc: "2.0", id: 11, method: "sampling/createMessage", params: { messages: [] } },
];

function mkGateway(era: "modern" | "legacy"): Gw {
  return gw({ server: "pastebin", clientEra: era, cfg: { era: "modern", tools: TOOLS } });
}

/** The client-facing messages, with request ids of the queue and record normalized. */
function seen(g: Gw, from: number): string {
  return JSON.stringify(g.inbox.slice(from)).replace(/queue approve [a-z0-9]+/g, "queue approve ID").replace(/\b[a-z0-9]{8}\b/g, "ID").split(g.home).join("HOME");
}

/** frame(m): since FZ3, anything parseMessage accepts can be framed, so this never tolerates an exception. */
function framed(m: Message): string | null {
  return frame(m);
}

const noCr = (s: string): string => s.replace(/\r/g, "");

const forwardedKey = (g: Gw): boolean => g.up.received.some((m) => JSON.stringify(m).includes(KEY));

function text(r: Rng): { raw: string; valid: boolean } {
  const base = structuredClone(r.pick(SEEDS));
  switch (r.int(10)) {
    case 0:
      return { raw: noStarRuns(corruptText(r, JSON.stringify(base))), valid: false };
    case 1:
      return { raw: noStarRuns(mutateStringN(r, r.pick(["", "{}", "[]", "null", "{\"jsonrpc\":\"2.0\"}", JSON.stringify(base)]), 3)), valid: false };
    default:
      return { raw: noStarRuns(JSON.stringify(mutateJsonN(r, base, 4)) ?? "null"), valid: true };
  }
}

describe("fuzz: gateway JSON-RPC", () => {
  it("parseMessage never throws and only accepts what the protocol defines", () => {
    fuzz("gateway:parseMessage", iters(0.5), (r) => {
      const { raw } = text(r);
      const p = parseMessage(raw);
      if (p.ok) {
        const m = p.msg;
        if (!(isRequest(m) || isNotification(m) || isResponse(m))) throw new Error(`accepted a message that is none of request, notification, response: ${raw.slice(0, 200)}`);
        const v = JSON.parse(raw) as Json;
        if (v.jsonrpc !== "2.0") throw new Error(`accepted a message without jsonrpc 2.0: ${raw.slice(0, 200)}`);
        framed(m);
      } else if (p.code !== PARSE_ERROR && p.code !== INVALID_REQUEST) throw new Error(`rejection with an unexpected code ${p.code}: ${raw.slice(0, 200)}`);
      errorResponse(p.ok ? null : p.id, -1, "x");
    });
  });

  it("LineFramer: the lines out do not depend on how the bytes are cut, and nothing throws", () => {
    fuzz("gateway:LineFramer", iters(1), (r) => {
      const max = r.range(8, 200);
      // FZ12 is fixed: the streams carry CRs again, so a CRLF at a maximum-size line's end is exercised.
      const stream = (r.bool(0.5) ? noCr : (x: string) => x)(mutateStringN(r, r.pick(["a\nb\n", '{"x":1}\r\n{"y":2}\n', "\n\n\n", "x".repeat(300) + "\nshort\n", "é\u0000\n"]).repeat(r.range(1, 6)), 3));
      const run = (cut: () => number): { lines: string[]; oversize: number } => {
        const lines: string[] = [];
        let oversize = 0;
        const f = new LineFramer((l) => void lines.push(l), () => void oversize++, max);
        for (let i = 0; i < stream.length; ) {
          const n = cut();
          f.push(stream.slice(i, i + n));
          i += n;
        }
        return { lines, oversize };
      };
      const whole = run(() => stream.length + 1);
      const bytewise = run(() => 1);
      const random = run(() => r.range(1, 40));
      if (JSON.stringify(whole) !== JSON.stringify(bytewise) || JSON.stringify(whole) !== JSON.stringify(random)) throw new Error(`framing depends on chunking (max ${max}): ${JSON.stringify(stream.slice(0, 120))} whole=${JSON.stringify(whole).slice(0, 160)} bytewise=${JSON.stringify(bytewise).slice(0, 160)}`);
      for (const l of whole.lines) if (Buffer.byteLength(l) > max) throw new Error(`a line over the maximum (${Buffer.byteLength(l)} > ${max}) was delivered`);
    });
  });

  for (const era of ["modern", "legacy"] as const) {
    it(`${era} client: never throws; malformed input is answered and not forwarded; a credential is never forwarded; deterministic`, () => {
      let g1 = mkGateway(era);
      let g2 = mkGateway(era);
      let n = 0;
      fuzz(`gateway:${era}`, iters(30), (r) => {
        if (n++ % 40 === 39) {
          g1 = mkGateway(era);
          g2 = mkGateway(era);
        }
        const { raw } = text(r);
        const label = `${JSON.stringify(raw.length > 300 ? `${raw.slice(0, 300)}...(${raw.length})` : raw)}`;
        const before = { inbox: g1.inbox.length, up: g1.up.received.length };
        const parsed = parseMessage(raw);
        const t = (() => {
          try {
            return timed(() => g1.core.clientText(raw), GATEWAY_BUDGET_MS);
          } catch (e) {
            throw new Error(`threw ${(e as Error).message.slice(0, 120)}: ${label}`, { cause: e });
          }
        })();
        if (t.ms > GATEWAY_BUDGET_MS) throw new Error(`slow (${Math.round(t.ms)} ms): ${label}`);
        if (!parsed.ok) {
          const answers = g1.inbox.slice(before.inbox);
          if (g1.up.received.length !== before.up) throw new Error(`a malformed message was forwarded upstream: ${label}`);
          const e = answers[answers.length - 1] as Message | undefined;
          if (answers.length !== 1 || e === undefined || !isResponse(e) || (e as { error?: { code?: number } }).error?.code !== parsed.code) throw new Error(`a malformed message was not answered with exactly one error (${answers.length} answers, expected code ${parsed.code}): ${label}`);
        }
        if (forwardedKey(g1)) throw new Error(`a credential was forwarded to the unlisted server: ${label}`);
        const mark = g2.inbox.length;
        g2.core.clientText(raw);
        const a = seen(g1, before.inbox);
        const b = seen(g2, mark);
        if (a !== b) throw new Error(`not deterministic (${firstDiff(a, b)}): ${label}`);
      }, { capSec: GATEWAY_CAP_S });
    });
  }

  it("a server's mangled messages never throw and never reach the client unframed", () => {
    let g = mkGateway("modern");
    let n = 0;
    fuzz("gateway:upstream", iters(20), (r) => {
      if (n++ % 40 === 39) g = mkGateway("modern");
      // A call in flight, then the server answers it (or something else) with mangled content.
      const id = 100 + n;
      g.core.clientText(JSON.stringify(req(id, "tools/call", { name: "search", arguments: { q: "x" } })));
      const answer = { jsonrpc: "2.0", id, result: { resultType: "complete", content: [{ type: "text", text: `ok ${"\u{e0041}".repeat(3)} hello` }], structuredContent: { a: [1, { b: "x" }] } } };
      const raw = r.bool(0.3) ? corruptText(r, JSON.stringify(answer)) : (JSON.stringify(mutateJsonN(r, r.pick<Json>([answer, { jsonrpc: "2.0", id: 5, method: "sampling/createMessage", params: {} }, { jsonrpc: "2.0", method: "notifications/tools/list_changed" }, { jsonrpc: "2.0", id, error: { code: -1, message: "e" } }]), 4)) ?? "null");
      const mark = g.inbox.length;
      try {
        timed(() => g.core.upstreamText(raw), GATEWAY_BUDGET_MS);
      } catch (e) {
        throw new Error(`threw ${(e as Error).message.slice(0, 120)}: ${JSON.stringify(raw.slice(0, 300))}`, { cause: e });
      }
      for (const m of g.inbox.slice(mark)) {
        const f = framed(m);
        if (f !== null && !parseMessage(f.trim()).ok) throw new Error(`the client was sent something that is not JSON-RPC: ${String(f).slice(0, 200)} for ${JSON.stringify(raw.slice(0, 200))}`);
      }
    }, { capSec: GATEWAY_CAP_S });
  });

  it("fixtures: the unmangled seeds behave", () => {
    const g = mkGateway("modern");
    g.core.clientText(JSON.stringify(SEEDS[2]));
    expect(forwardedKey(g)).toBe(false);
    expect(g.inbox.length).toBeGreaterThan(0);
  });
});
