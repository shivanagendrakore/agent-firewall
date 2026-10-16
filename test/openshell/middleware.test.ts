/**
 * The firewall as an OpenShell supervisor middleware (docs/sandboxes.md), end to end without OpenShell: a
 * stand-in supervisor (./supervisor.ts) speaks the middleware protocol over real HTTP/2 gRPC to the
 * middleware service, which asks the real local API sidecar (serve --api: engine, session state, queue,
 * signed log) in a throwaway firewall home.
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import http2 from "node:http2";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { ApiServer } from "../../src/api/server.js";
import { frame, GrpcError, startGrpcServer, Status, type RunningGrpcServer } from "../../src/openshell/grpc.js";
import { translateDecide } from "../../src/api/contract.js";
import { apiClient, dataHeaders, isLoopbackTarget, maskCredentials, middlewareService, normalRequestTarget, pseudoMismatch, reasonCode, refusedTarget, targetUrl, unreadableBody, validSessionId, CONTRACT_CAPABILITY, HOST_MISMATCH_CODE, INTERNAL_CODE, LOOPBACK_CODE, REFUSAL_WINDOW_MS, REFUSALS_PER_WINDOW, RefusalThrottle, RESPONSE_SERVICE, SERVICE, TARGET_MISMATCH_CODE, type DecisionClient } from "../../src/openshell/middleware.js";
import { Writer } from "../../src/openshell/proto.js";
import { verifyLog } from "../../src/runtime/log.js";
import { listQueue } from "../../src/runtime/store.js";
import { readCounters } from "../../src/runtime/counters.js";
import { agent, apiTree, call, removeApiTree, startServer, type ApiTree } from "../api/harness.js";
import { bytes, gatewayKeys, httpRequest, msg, msgs, responseBody, responsePreflight, responseTrailers, sessionEnd, str, supervisor, uint, wsMessage, wsPreflight, wsStart, type Supervisor } from "./supervisor.js";

const ALLOW = 1;
const DENY = 2;
// A live-shaped payment key (the fixture test/host-tools.test.ts uses), not a real one.
const LIVE_KEY = "sk_li" + "ve_51Hc7TqLmXv2NpQ8RtYw3ZsKdF6gJh9BnM4aVe0CxWu";

async function middleware(client: DecisionClient, extra: Partial<Parameters<typeof middlewareService>[0]> = {}): Promise<RunningGrpcServer> {
  const svc = middlewareService({ client, ...extra });
  return startGrpcServer({ host: "127.0.0.1", port: 0, maxMessageBytes: svc.maxMessageBytes, unary: svc.unary, streams: svc.streams, authorize: svc.authorize });
}

describe("OpenShell middleware against the real local API", () => {
  let t: ApiTree;
  let api: ApiServer;
  let token: string;
  let mw: RunningGrpcServer;
  let sup: Supervisor;
  let unrecorded: string[];
  const session = async (id: string): Promise<Record<string, unknown>> => (await call(api, { path: `/v1/sessions/${encodeURIComponent(id)}`, token })).body;

  beforeEach(async () => {
    t = apiTree();
    mkdirSync(t.l.home, { recursive: true, mode: 0o700 });
    writeFileSync(t.l.policy, JSON.stringify({ version: 3, fetchAllowHosts: ["docs.example.com"], sendAllowHosts: ["api.partner.example"], denyHosts: ["evil.example"] }));
    token = agent(t, "openshell", null, "network");
    api = await startServer(t);
    unrecorded = [];
    mw = await middleware(apiClient({ target: { socketPath: api.socket as string }, token, timeoutMs: 5000 }), { onRefusalUnrecorded: (m) => unrecorded.push(m) });
    sup = supervisor(mw.address);
  });
  afterEach(async () => {
    sup.close();
    await mw.close();
    await api.close();
    removeApiTree(t);
  });

  it("a refused request (domain fronting, a loopback target) is recorded through the real API as FW-NET-REFUSED in the signed log, with nothing failing to record", async () => {
    const r = await sup.request({ requestId: "f1", sandboxId: "sbx-f", host: "api.partner.example", path: "/x", query: `k=${LIVE_KEY}`, headers: [["host", `${LIVE_KEY}.evil.example`]] });
    expect(r.status, r.message).toBe(Status.OK);
    expect(r.result?.decision).toBe(DENY);
    expect(r.result?.reasonCode).toBe(HOST_MISMATCH_CODE);
    expect(r.result?.findings).toContain("FW-NET-REFUSED");
    expect(r.result?.metadata.decision_id).toMatch(/^dec_/);
    const lo = await sup.request({ requestId: "f2", sandboxId: "sbx-f", host: "127.0.0.1", scheme: "http", port: 8080 });
    expect(lo.result?.reasonCode).toBe(LOOPBACK_CODE);
    expect(lo.result?.findings).toContain("FW-NET-REFUSED");
    expect(unrecorded).toEqual([]);
    expect(verifyLog(t.l)).toMatchObject({ ok: true });
    const text = readFileSync(join(t.l.log, "decisions.jsonl"), "utf8");
    const events = text.trim().split("\n").map((x) => (JSON.parse(x) as { event: Record<string, unknown> }).event);
    const refusals = events.filter((e) => e.tool === "launchsafe:network-refused");
    expect(refusals.length).toBe(2);
    for (const e of refusals) expect(e).toMatchObject({ type: "decision", session: "openshell/sbx-f", verdict: "deny", rules: ["FW-NET-REFUSED"], traffic: "network" });
    // The credential in the URL and the Host header is not in the log.
    expect(text).not.toContain(LIVE_KEY);
  });

  it("a private or special-purpose address target is refused and recorded as FW-NET-REFUSED; a cloud metadata address is the engine's, denied under FW-METADATA", async () => {
    for (const host of ["10.0.0.1", "192.168.1.20", "fd12:3456::1", "::ffff:172.16.0.9", "203.0.113.7"]) {
      const r = await sup.request({ requestId: `i-${host}`, sandboxId: "sbx-i", host, scheme: "http", port: 8080 });
      expect(r.status, `${host}: ${r.message}`).toBe(Status.OK);
      expect(r.result?.decision, host).toBe(DENY);
      expect(r.result?.reasonCode, host).toBe(INTERNAL_CODE);
      expect(r.result?.findings, host).toContain("FW-NET-REFUSED");
    }
    // The same address in the spellings the loopback check reads is no way round it.
    for (const host of ["0xa.0.0.1", "012.0.0.1", "10.1", "::ffff:a00:1", "0:0:0:0:0:ffff:a00:1", "64:ff9b::a00:1"]) {
      const r = await sup.request({ sandboxId: "sbx-i", host, scheme: "http", port: 8080 });
      expect(r.result?.reasonCode, host).toBe(INTERNAL_CODE);
    }
    // The metadata service is judged, and the engine says what it is.
    for (const host of ["169.254.169.254", "0xa9.0xfe.0xa9.0xfe", "::ffff:a9fe:a9fe"]) {
      const r = await sup.request({ sandboxId: "sbx-md", host, scheme: "http", port: 80, path: "/latest/meta-data/" });
      expect(r.result?.decision, host).toBe(DENY);
      expect(r.result?.reasonCode, host).not.toBe(INTERNAL_CODE);
      expect(r.result?.findings, host).toContain("FW-METADATA");
      expect(r.result?.findings, host).not.toContain("FW-NET-REFUSED");
    }
    expect(unrecorded).toEqual([]);
    expect(verifyLog(t.l)).toMatchObject({ ok: true });
    const text = readFileSync(join(t.l.log, "decisions.jsonl"), "utf8");
    const events = text.trim().split("\n").map((x) => (JSON.parse(x) as { event: Record<string, unknown> }).event);
    const refusals = events.filter((e) => e.tool === "launchsafe:network-refused");
    expect(refusals.length).toBe(11);
    for (const e of refusals) expect(e).toMatchObject({ type: "decision", session: "openshell/sbx-i", verdict: "deny", rules: ["FW-NET-REFUSED"], traffic: "network" });
    expect(events.filter((e) => Array.isArray(e.rules) && (e.rules as string[]).includes("FW-METADATA")).length).toBe(3);
  });

  it("every other metadata address and spelling the middleware leaves to the engine is denied there under FW-METADATA", async () => {
    // Read as plain addresses, these are link-local or unique local (ECS, EC2 over IPv6, the spellings of
    // 169.254.169.254), shared (Alibaba) or special-purpose (Oracle), which the middleware would refuse, or public
    // (Azure), which would be held as a bare IP a person can approve. The engine denies each, and says what it is.
    const hosts = ["169.254.170.2", "fd00:ec2::254", "100.100.100.200", "168.63.129.16", "192.0.0.192", "0251.0376.0251.0376", "169.254.43518", "[::ffff:169.254.169.254]", "metadata.google.internal"];
    for (const host of hosts) {
      const r = await sup.request({ sandboxId: "sbx-md2", host, scheme: "http", port: 80, path: "/latest/meta-data/" });
      expect(r.status, `${host}: ${r.message}`).toBe(Status.OK);
      expect(r.result?.decision, host).toBe(DENY);
      expect(r.result?.reasonCode, host).not.toBe(INTERNAL_CODE);
      expect(r.result?.findings, host).toContain("FW-METADATA");
      expect(r.result?.findings, host).not.toContain("FW-NET-REFUSED");
    }
    expect(unrecorded).toEqual([]);
    expect(verifyLog(t.l)).toMatchObject({ ok: true });
    const events = readFileSync(join(t.l.log, "decisions.jsonl"), "utf8").trim().split("\n").map((x) => (JSON.parse(x) as { event: Record<string, unknown> }).event);
    expect(events.filter((e) => e.tool === "launchsafe:network-refused")).toEqual([]);
    expect(events.filter((e) => Array.isArray(e.rules) && (e.rules as string[]).includes("FW-METADATA")).length).toBe(hosts.length);
  });

  it("assignment-style credentials and userinfo in a refused request's URL and Host are masked in the signed log", async () => {
    const r = await sup.request({ requestId: "m1", sandboxId: "sbx-m", host: "api.partner.example", path: "/x", query: "password=pA55w0rd-Q7zK2mLx&access_token=ya29Tok3nQ8vR2nZ", headers: [["host", "alice:S3cr3tPassw0rdZ9@evil.example"]] });
    expect(r.result?.reasonCode).toBe(HOST_MISMATCH_CODE);
    expect(r.result?.findings).toContain("FW-NET-REFUSED");
    expect(unrecorded).toEqual([]);
    const text = readFileSync(join(t.l.log, "decisions.jsonl"), "utf8");
    expect(text).toContain("launchsafe:network-refused");
    for (const secret of ["pA55w0rd-Q7zK2mLx", "ya29Tok3nQ8vR2nZ", "S3cr3tPassw0rdZ9"]) expect(text).not.toContain(secret);
  });

  it("Describe: the three bindings, protocol 1.0 and the contract capability; an unknown required capability or major version is refused", async () => {
    const d = await sup.describe();
    expect(d.status).toBe(Status.OK);
    const m = d.manifest as NonNullable<typeof d.manifest>;
    const bindings = msgs(m, 3).map((b) => [uint(b, 1), uint(b, 2), uint(b, 3)]);
    expect(bindings).toEqual([
      [1, 1, 512 * 1024],
      [3, 2, 512 * 1024],
      [2, 1, 512 * 1024],
    ]);
    const ext = msg(m, 5) as NonNullable<ReturnType<typeof msg>>;
    expect(uint(msg(ext, 1) as NonNullable<ReturnType<typeof msg>>, 1)).toBe(1);
    expect(str(ext, 2)).toBe("launchsafe/agent-firewall");
    expect(str(ext, 4)).toBe(CONTRACT_CAPABILITY);
    expect((await sup.describe(["openshell.supervisor-middleware.future"])).status).toBe(Status.FAILED_PRECONDITION);
    expect((await sup.describe([], 2)).status).toBe(Status.FAILED_PRECONDITION);
  });

  it("ValidateConfig accepts the documented keys and refuses anything else", async () => {
    expect(await sup.validate({})).toEqual({ valid: true, reason: "" });
    expect(await sup.validate({ attended: false, inspectResponses: true, session: "team-run" })).toEqual({ valid: true, reason: "" });
    expect((await sup.validate({ mode: "redact" })).valid).toBe(false);
    expect((await sup.validate({ attended: "no" })).valid).toBe(false);
    expect((await sup.validate({ session: "bad session" })).valid).toBe(false);
  });

  it("a GET to a listed host passes, and makes the sandbox's session untrusted (it read outside content)", async () => {
    const r = await sup.request({ requestId: "r1", sandboxId: "sbx-1", host: "docs.example.com", path: "/guide" });
    expect(r.status, r.message).toBe(Status.OK);
    expect(r.result?.decision).toBe(ALLOW);
    expect(r.result?.metadata.decision_id).toMatch(/^dec_/);
    expect(await session("sbx-1")).toMatchObject({ untrusted: true });
    expect(verifyLog(t.l)).toMatchObject({ ok: true });
  });

  it("given what the session read: a send to an unlisted host from a session that read outside content is held in the queue, with a reason code", async () => {
    // The same send from a sandbox that has read nothing yet passes (its own response then makes it untrusted).
    const clean = await sup.request({ requestId: "c1", sandboxId: "sbx-clean", host: "paste.example.org", method: "POST", path: "/new", body: '{"text":"notes"}' });
    expect(clean.status, clean.message).toBe(Status.OK);
    expect(clean.result?.decision).toBe(ALLOW);
    await sup.request({ requestId: "r1", sandboxId: "sbx-2", host: "docs.example.com", path: "/guide" });
    const r = await sup.request({ requestId: "r2", sandboxId: "sbx-2", host: "paste.example.org", method: "POST", path: "/new", body: '{"text":"notes"}' });
    expect(r.status, r.message).toBe(Status.OK);
    expect(r.result?.decision).toBe(DENY);
    expect(r.result?.reasonCode).toMatch(/^launchsafe_hold_/);
    expect(r.result?.findings.length).toBeGreaterThan(0);
    expect(listQueue(t.l).items.some((i) => i.id === r.result?.metadata.approval_id && i.sessionId === "openshell/sbx-2" && i.status === "pending")).toBe(true);
  });

  it("a credential in a request body never leaves for a host that did not issue it, whatever the host lists say", async () => {
    const r = await sup.request({ requestId: "k1", sandboxId: "sbx-3", host: "api.partner.example", method: "POST", path: "/upload", body: JSON.stringify({ key: LIVE_KEY }) });
    expect(r.status, r.message).toBe(Status.OK);
    expect(r.result?.decision).toBe(DENY);
    expect(r.result?.findings).toContain("FW-DLP-CREDENTIAL");
    expect(r.result?.reasonCode).toBe("launchsafe_deny_fw_dlp_credential");
  });

  it("a credential in a request header (a custom API-key header, Authorization, Cookie or Referer) is scanned like a body", async () => {
    for (const h of [["x-api-key", LIVE_KEY], ["user-agent", `curl/8.4.0 ${LIVE_KEY}`], ["authorization", `Bearer ${LIVE_KEY}`], ["cookie", `sid=${LIVE_KEY}`], ["referer", `https://x.example/?k=${LIVE_KEY}`]] as [string, string][]) {
      const r = await sup.request({ requestId: `h-${h[0]}`, sandboxId: "sbx-h", host: "api.partner.example", path: "/v1/items", headers: [h] });
      expect(r.status, r.message).toBe(Status.OK);
      expect(r.result?.decision, h[0]).toBe(DENY);
      expect(r.result?.findings, h[0]).toContain("FW-DLP-CREDENTIAL");
    }
  });

  it("a compressed request body is held as unreadable, never judged as if it were empty", async () => {
    const r = await sup.request({ requestId: "z1", sandboxId: "sbx-z", host: "api.partner.example", method: "POST", path: "/upload", headers: [["content-encoding", "gzip"]], body: Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02]) });
    expect(r.status, r.message).toBe(Status.OK);
    expect(r.result?.decision).toBe(DENY);
    expect(r.result?.findings).toContain("FW-UNCLASSIFIABLE");
  });

  it("a host on the deny list is refused even when OpenShell's policy admitted it (a wildcard OpenShell cannot subtract from)", async () => {
    const r = await sup.request({ requestId: "d1", sandboxId: "sbx-4", host: "evil.example", path: "/" });
    expect(r.status, r.message).toBe(Status.OK);
    expect(r.result?.decision).toBe(DENY);
  });

  it("responses: the body is recorded as the request's result; one with no request the service knows is recorded as outside content", async () => {
    await sup.request({ requestId: "q1", sandboxId: "sbx-5", host: "docs.example.com", path: "/a" });
    const r = await sup.response([responsePreflight({ requestId: "q1", sandboxId: "sbx-5", host: "docs.example.com", path: "/a" }), responseBody(1, "hello from the docs"), responseTrailers(), sessionEnd(3)]);
    expect(r.status, r.message).toBe(Status.OK);
    expect(r.results.length).toBe(3);
    expect(uint(msg(msg(r.results[0] as never, 1) as never, 2) as never, 1)).toBe(2); // inspect WHOLE_BODY_BYTES
    const body = msg(r.results[1] as never, 2) as NonNullable<ReturnType<typeof msg>>;
    expect(uint(body, 1)).toBe(1);
    expect(msg(body, 2)).not.toBeNull(); // pass_through
    expect(msg(r.results[2] as never, 3)).not.toBeNull(); // trailers result

    const unknown = await sup.response([responsePreflight({ requestId: "never-seen", sandboxId: "sbx-6", host: "docs.example.com", modes: [1], headers: [["content-encoding", "gzip"]] })]);
    expect(unknown.status, unknown.message).toBe(Status.OK);
    expect(msg(msg(unknown.results[0] as never, 1) as never, 1)).not.toBeNull(); // skip, after recording
    expect(await session("sbx-6")).toMatchObject({ untrusted: true });
  });

  it("WebSocket: the session is inspected and each text message the sandbox sends is judged like a body", async () => {
    const r = await sup.websocket([wsPreflight({ sandboxId: "sbx-7", host: "api.partner.example", path: "/live" }), wsStart(), wsMessage(1, '{"op":"ping"}'), wsMessage(3, `key ${LIVE_KEY}`), sessionEnd(4)]);
    expect(r.status, r.message).toBe(Status.OK);
    expect(r.results.length).toBe(3);
    expect(uint(msg(r.results[0] as never, 1) as never, 1)).toBe(1); // INSPECT
    const first = msg(r.results[1] as never, 2) as NonNullable<ReturnType<typeof msg>>;
    expect([uint(first, 1), uint(first, 2)]).toEqual([1, ALLOW]);
    const second = msg(r.results[2] as never, 2) as NonNullable<ReturnType<typeof msg>>;
    expect([uint(second, 1), uint(second, 2)]).toEqual([3, DENY]);
  });

  it("fails closed: with the local API gone every evaluation is a gRPC error (OpenShell's on_error: fail_closed blocks the traffic)", async () => {
    await api.close();
    const r = await sup.request({ requestId: "x", sandboxId: "sbx-8", host: "docs.example.com" });
    expect(r.status).toBe(Status.UNAVAILABLE);
    expect(r.result).toBeNull();
    api = await startServer(t);
  });

  it("a malformed message, a bad sandbox id or an unsupported scheme is a gRPC error, never an allow", async () => {
    const bad = await sup.client.unary("/openshell.middleware.v1.SupervisorMiddleware/EvaluateHttpRequest", Buffer.from([0x0a, 0xff]));
    expect(bad.status).toBe(Status.INVALID_ARGUMENT);
    expect((await sup.request({ sandboxId: "bad id!", host: "docs.example.com" })).status).toBe(Status.INVALID_ARGUMENT);
    expect((await sup.request({ sandboxId: "sbx-9", host: "docs.example.com", scheme: "ftp" })).status).toBe(Status.INVALID_ARGUMENT);
    expect((await sup.client.unary("/openshell.middleware.v1.SupervisorMiddleware/Nope", Buffer.alloc(0))).status).toBe(Status.UNIMPLEMENTED);
  });
});

describe("middleware traffic is not the agent's tool calls", () => {
  let t: ApiTree;
  let api: ApiServer;
  let token: string;
  let mw: RunningGrpcServer;
  let sup: Supervisor;
  beforeEach(async () => {
    t = apiTree();
    mkdirSync(t.l.home, { recursive: true, mode: 0o700 });
    writeFileSync(t.l.policy, JSON.stringify({ version: 3, fetchAllowHosts: ["docs.example.com"], caps: { enabled: true, session: { toolCalls: 2 } } }));
    token = agent(t, "openshell", null, "network");
    api = await startServer(t);
    mw = await middleware(apiClient({ target: { socketPath: api.socket as string }, token, timeoutMs: 5000 }));
    sup = supervisor(mw.address);
  });
  afterEach(async () => {
    sup.close();
    await mw.close();
    await api.close();
    removeApiTree(t);
  });

  it("requests past the session's toolCalls limit still pass, the agent-wide counters stay empty, and the session's own tool calls keep their full limit", async () => {
    for (let i = 0; i < 4; i++) {
      const r = await sup.request({ requestId: `n${i}`, sandboxId: "sbx-n", host: "docs.example.com", path: `/p${i}` });
      expect(r.status, r.message).toBe(Status.OK);
      expect(r.result?.decision, `request ${i}`).toBe(ALLOW);
      expect(r.result?.findings ?? []).not.toContain("FW-CAP");
    }
    // The agent-wide behaviour monitor's counters (under "agent:<id>") saw none of it; the sandbox session's did.
    const agentWide = readCounters(t.l, "agent:openshell").counters;
    expect(agentWide.session).toEqual({});
    expect(agentWide.minute).toEqual({});
    expect(agentWide.caps?.totals.calls ?? 0).toBe(0);
    expect(readCounters(t.l, "openshell/sbx-n").counters.caps?.totals.calls ?? 0).toBe(0);
    // The same session's own tool calls: two go ahead, the third meets the limit.
    const rules: string[][] = [];
    for (let i = 0; i < 3; i++) {
      const d = await call(api, { path: "/v1/decide", token, body: { session: "sbx-n", action: { format: "engine", tool: "Read", input: { file_path: `${t.ws}/f${i}.ts` } } } });
      expect(d.status, JSON.stringify(d.body)).toBe(200);
      rules.push(((d.body.rules ?? []) as { id: string }[]).map((r) => r.id));
    }
    expect(rules[0]).not.toContain("FW-CAP");
    expect(rules[1]).not.toContain("FW-CAP");
    expect(rules[2]).toContain("FW-CAP");
  });
});

describe("caller authentication with the gateway's tokens", () => {
  const keys = gatewayKeys();
  const jwt = { publicKey: keys.publicKey, gatewayId: "gw-1", audience: "urn:openshell:extension:middleware:launchsafe-firewall" };
  const now = Math.floor(Date.now() / 1000);
  const claims = (o: Record<string, unknown> = {}): Record<string, unknown> => ({ iss: "openshell-gateway:gw-1", aud: jwt.audience, exp: now + 300, caller_kind: "supervisor", sandbox_id: "sbx-a", jti: "j1", ...o });
  const asked: string[] = [];
  const stub: DecisionClient = {
    decide: async (b) => {
      asked.push(String(b.session));
      return { decisionId: "dec_stub", verdict: "allow", rules: [] };
    },
    result: async () => ({}),
    input: async () => undefined,
  };
  let mw: RunningGrpcServer;
  let sup: Supervisor;
  beforeAll(async () => {
    mw = await middleware(stub, { jwt, expectedAudience: jwt.audience });
    sup = supervisor(mw.address);
  });
  afterAll(async () => {
    sup.close();
    await mw.close();
  });
  const bearer = (tok: string): Record<string, string> => ({ authorization: `Bearer ${tok}` });

  it("the supervisor of the sandbox the request names is answered", async () => {
    const r = await sup.request({ sandboxId: "sbx-a", host: "docs.example.com" }, bearer(keys.mint(claims())));
    expect(r.status, r.message).toBe(Status.OK);
    expect(asked).toContain("sbx-a");
  });

  it("refused: no token, another sandbox's token, the gateway's token for an evaluation, an expired one, another audience, issuer or algorithm, a forged signature", async () => {
    const req = { sandboxId: "sbx-a", host: "docs.example.com" };
    expect((await sup.request(req)).status).toBe(Status.UNAUTHENTICATED);
    expect((await sup.request(req, bearer(keys.mint(claims({ sandbox_id: "sbx-b" }))))).status).toBe(Status.PERMISSION_DENIED);
    expect((await sup.request(req, bearer(keys.mint(claims({ caller_kind: "gateway", sandbox_id: undefined }))))).status).toBe(Status.PERMISSION_DENIED);
    expect((await sup.request(req, bearer(keys.mint(claims({ exp: now - 120 }))))).status).toBe(Status.UNAUTHENTICATED);
    expect((await sup.request(req, bearer(keys.mint(claims({ aud: "urn:other" }))))).status).toBe(Status.UNAUTHENTICATED);
    expect((await sup.request(req, bearer(keys.mint(claims({ iss: "openshell-gateway:gw-2" }))))).status).toBe(Status.UNAUTHENTICATED);
    expect((await sup.request(req, bearer(keys.mint(claims(), { typ: "openshell-ext+jwt", alg: "none" })))).status).toBe(Status.UNAUTHENTICATED);
    expect((await sup.request(req, bearer(gatewayKeys().mint(claims())))).status).toBe(Status.UNAUTHENTICATED);
    expect(asked.filter((s) => s !== "sbx-a")).toEqual([]);
  });

  it("the gateway's own token may describe the service", async () => {
    const d = await sup.client.unary("/openshell.middleware.v1.SupervisorMiddleware/Describe", Buffer.alloc(0), bearer(keys.mint(claims({ caller_kind: "gateway", sandbox_id: undefined }))));
    expect(d.status, d.message).toBe(Status.OK);
  });
});

describe("helpers", () => {
  it("normalRequestTarget and pseudoMismatch: unreserved escapes decoded, hex in upper case, a bare ? dropped, a fragment never matches", () => {
    expect(normalRequestTarget("/a%2db%7e%2f?")).toBe("/a-b~%2F");
    expect(normalRequestTarget("/a?b?")).toBe("/a?b?");
    const t = { scheme: "https", method: "GET", path: "/v1/x", query: "a=1" };
    expect(pseudoMismatch([{ name: ":path", value: "/v1/%78?a=%31" }], t)).toBeNull();
    expect(pseudoMismatch([{ name: ":path", value: "/v1/x?a=1#k" }], t)).toBe(":path: /v1/x?a=1#k");
    expect(pseudoMismatch([{ name: ":path", value: "/v1%2Fx?a=1" }], t)).not.toBeNull();
    expect(pseudoMismatch([{ name: ":path", value: "/v1/x?" }], { ...t, query: "" })).toBeNull();
  });
  it("RefusalThrottle: one record per kind per window, the count carried; past the budget, new hosts together", () => {
    const th = new RefusalThrottle(1000, 2, 100);
    expect(th.admit("s", "c", "a", 0)).toMatchObject({ record: true, repeated: 0, aggregate: false });
    expect(th.admit("s", "c", "a", 10).record).toBe(false);
    expect(th.admit("s", "c", "a", 20).record).toBe(false);
    expect(th.admit("s2", "c", "a", 20).record).toBe(true);
    expect(th.admit("s", "c", "a", 1000)).toMatchObject({ record: true, repeated: 2, aggregate: false });
    expect(th.admit("s", "c", "b", 1001)).toMatchObject({ record: true, repeated: 0, aggregate: false });
    expect(th.admit("s", "c", "d", 1002)).toMatchObject({ record: true, repeated: 0, aggregate: true });
    expect(th.admit("s", "c", "e", 1003).record).toBe(false);
    expect(th.admit("s", "c", "f", 2002)).toMatchObject({ record: true, repeated: 0, aggregate: false });
  });
  it("RefusalThrottle.release: a failed record reopens the kind's window with its count (plus the failed one) and returns the budget slot", () => {
    const th = new RefusalThrottle(1000, 1, 100);
    expect(th.admit("s", "c", "a", 0).record).toBe(true);
    expect(th.admit("s", "c", "a", 10).record).toBe(false);
    const again = th.admit("s", "c", "a", 1000);
    expect(again).toMatchObject({ record: true, repeated: 1, aggregate: false });
    th.release("s", "c", "a", again);
    // Within the window: tries again, carrying the one counted before and the one that failed.
    expect(th.admit("s", "c", "a", 1001)).toMatchObject({ record: true, repeated: 2, aggregate: false });
    // The budget (1) is still the sandbox's: another kind is past it.
    expect(th.admit("s", "c", "b", 1002).aggregate).toBe(true);
  });
  it("RefusalThrottle.release keeps the refusals counted while the failed record was in flight (r6, item 4)", () => {
    const th = new RefusalThrottle(1000, 1, 100);
    const first = th.admit("s", "c", "a", 0);
    expect(first.record).toBe(true);
    // Two identical refusals arrive while the decide is in flight: counted against the kind admitted above.
    expect(th.admit("s", "c", "a", 10).record).toBe(false);
    expect(th.admit("s", "c", "a", 20).record).toBe(false);
    th.release("s", "c", "a", first);
    // The failed one and the two counted in flight are all carried by the next record.
    expect(th.admit("s", "c", "a", 30)).toMatchObject({ record: true, repeated: 3, aggregate: false });
  });
  it("RefusalThrottle: the sandbox's budget is a sliding window, so two windows back to back do not allow twice as many (r6, item 5)", () => {
    const th = new RefusalThrottle(1000, 2, 100);
    expect(th.admit("s", "c", "a", 0)).toMatchObject({ record: true, aggregate: false });
    expect(th.admit("s", "c", "b", 999)).toMatchObject({ record: true, aggregate: false });
    // At 1000 the record at 0 has left the window, the one at 999 has not: one slot, not a fresh two.
    expect(th.admit("s", "c", "c", 1000)).toMatchObject({ record: true, aggregate: false });
    expect(th.admit("s", "c", "d", 1001)).toMatchObject({ record: true, aggregate: true });
    // At 1999 the record at 999 leaves the window: a slot again.
    expect(th.admit("s", "c", "e", 1998).record).toBe(false);
    expect(th.admit("s", "c", "f", 1999)).toMatchObject({ record: true, aggregate: false });
  });
  it("maskCredentials: '/' separates like '?' and '&', short values of password, secret and token keys, userinfo to the last '@' (r6, items 2 and 3)", () => {
    const m1 = maskCredentials("https://evil.example/x/password=hunter2longer");
    expect(m1).not.toContain("hunter2longer");
    const m2 = maskCredentials(":path /api_key=abcdefgh1234");
    expect(m2).not.toContain("abcdefgh1234");
    expect(maskCredentials("/x?password=hunter2&id=7")).toBe("/x?password=[masked]&id=7");
    expect(maskCredentials("/x?db_password=pw&access_token=abc&secret=s3&passwd=1")).toBe("/x?db_password=[masked]&access_token=[masked]&secret=[masked]&passwd=[masked]");
    expect(maskCredentials('reason: token: "abc"')).toBe('reason: token: "[masked]"');
    // Other keys, and names that only contain the word, keep their short values.
    expect(maskCredentials("/x?id=7&page=2&passwordless=1&mytoken=abc")).toBe("/x?id=7&page=2&passwordless=1&mytoken=abc");
    expect(maskCredentials("//bob:p@ss@evil/x")).toBe("//[userinfo masked]@evil/x");
    expect(maskCredentials("https://bob:p@ss@evil.example/x?y=1")).toBe("https://[userinfo masked]@evil.example/x?y=1");
  });
  it("maskCredentials: a password, secret or token value is masked whole, through a '/' or '?', and a quoted one to its closing quote (r7, item 6)", () => {
    expect(maskCredentials("/x?password=ab/cd&id=7")).toBe("/x?password=[masked]&id=7");
    expect(maskCredentials("/x?password=ab/cd")).toBe("/x?password=[masked]");
    expect(maskCredentials("/x/token=a?b#c")).toBe("/x/token=[masked]");
    expect(maskCredentials('reason: password: "my pass" end')).toBe('reason: password: "[masked]" end');
    expect(maskCredentials("reason: secret: 'two words'")).toBe("reason: secret: '[masked]'");
    expect(maskCredentials('{"db_password":"a b/c","id":7}')).toBe('{"db_password":"[masked]","id":7}');
    // An unclosed quote: masked to the end of the line.
    expect(maskCredentials('password: "my pass')).toBe('password: "[masked]');
    // A long value with a "/" in it: nothing after the "/" is left either.
    const long = maskCredentials("/x?access_token=abcdefghijklmnop/qrstuvwxyz&page=2");
    expect(long).not.toMatch(/abcdefgh|qrstuv/);
    expect(long).toContain("&page=2");
    // Other keys keep their values.
    expect(maskCredentials("/x?id=ab/cd&page=2")).toBe("/x?id=ab/cd&page=2");
  });
  it("maskCredentials: a quoted value honours backslash escapes, an unquoted one runs through ',' and ';' (r8, item 3)", () => {
    const json = maskCredentials('{"password":"a\\"b c","id":7}');
    expect(json).toBe('{"password":"[masked]","id":7}');
    expect(json).not.toContain("b c");
    expect(maskCredentials("reason: secret: 'it\\'s mine' end")).toBe("reason: secret: '[masked]' end");
    // An escaped backslash before the quote: the quote closes the value.
    expect(maskCredentials('{"token":"ab\\\\","id":7}')).toBe('{"token":"[masked]","id":7}');
    expect(maskCredentials("/x?password=ab,cd&id=7")).toBe("/x?password=[masked]&id=7");
    expect(maskCredentials("password=ab;cd end")).toBe("password=[masked] end");
    expect(maskCredentials("password=ab,cd")).not.toContain("cd");
  });
  it("maskCredentials: input holding the sentinel's characters is not masked by them (r8, item 4)", () => {
    expect(maskCredentials("id=a\u0000m\u0000b")).toBe("id=a�m�b");
    expect(maskCredentials("/x?q=\u0000m\u0000&password=pw")).toBe("/x?q=�m�&password=[masked]");
  });
  it("targetUrl: default ports dropped, ws and wss as http and https, IPv6 in brackets", () => {
    const t = { scheme: "https", host: "docs.example.com", port: 443, method: "GET", path: "/a", query: "x=1" };
    expect(targetUrl(t)).toBe("https://docs.example.com/a?x=1");
    expect(targetUrl({ ...t, scheme: "wss", port: 8443, query: "" })).toBe("https://docs.example.com:8443/a");
    expect(targetUrl({ ...t, scheme: "ws", port: 80, host: "::1" })).toBe("http://[::1]/a?x=1");
  });
  it("reasonCode: OpenShell's format (lowercase, digits, underscores, at most 64 bytes)", () => {
    expect(reasonCode("hold", [{ id: "FW-SEND" }])).toBe("launchsafe_hold_fw_send");
    expect(reasonCode("deny", [])).toBe("launchsafe_deny");
    const long = reasonCode("deny", [{ id: "FW-".concat("X".repeat(100)) }]);
    expect(long.length).toBeLessThanOrEqual(64);
    expect(long).toMatch(/^[a-z][a-z0-9_]*$/);
  });
});

/** A stand-in for the local API that records what it is asked and answers as a test says. */
function stubApi(o: { verdict?: (body: Record<string, unknown>) => string; redact?: (text: string) => string } = {}): DecisionClient & { decided: Record<string, unknown>[]; results: { session: string; decisionId: string; output: string }[]; inputs: string[] } {
  const decided: Record<string, unknown>[] = [];
  const results: { session: string; decisionId: string; output: string }[] = [];
  const inputs: string[] = [];
  let n = 0;
  return {
    decided,
    results,
    inputs,
    decide: async (b) => {
      // The real API's reading of the request, from a network middleware's token: a body it would answer with 400
      // fails here too, so a refusal record the API would reject cannot pass a test against the stand-in.
      const t = translateDecide(b, []);
      if (!t.ok) throw new Error(`the local API answered 400: ${t.detail}`);
      decided.push(b);
      const verdict = o.verdict?.(b) ?? "allow";
      return { decisionId: `dec_${++n}`, verdict, rules: verdict === "allow" ? [] : [{ id: "FW-TEST" }], ...(verdict === "hold" ? { approval: { id: "apr_1" } } : {}) };
    },
    result: async (session, decisionId, output) => {
      results.push({ session, decisionId, output });
      const out = o.redact?.(output);
      return out === undefined ? {} : { output: out };
    },
    input: async (_s, _src, content) => {
      inputs.push(content);
    },
  };
}

const actionOf = (b: Record<string, unknown>): { tool: string; input: Record<string, string> } => b.action as { tool: string; input: Record<string, string> };

describe("requests: what is judged, and what is refused before anything is asked", () => {
  let api: ReturnType<typeof stubApi>;
  let mw: RunningGrpcServer;
  let sup: Supervisor;
  let unrecorded: string[];
  let clock: number;
  beforeEach(async () => {
    api = stubApi({ verdict: (b) => (actionOf(b).tool === "HttpRequest" ? "allow" : "hold") });
    unrecorded = [];
    clock = Date.now();
    mw = await middleware(api, { onRefusalUnrecorded: (m) => unrecorded.push(m), now: () => clock, clock: () => clock });
    sup = supervisor(mw.address);
  });
  afterEach(async () => {
    sup.close();
    await mw.close();
    // Every refusal the stand-in API was asked to record was a request the real API accepts.
    expect(unrecorded).toEqual([]);
  });

  it("data-carrying headers go to the engine with the body; standard ones only when their value fits the header's strict shape are left out", async () => {
    const r = await sup.request({ sandboxId: "s1", host: "api.partner.example", method: "GET", headers: [["accept", "*/*"], ["user-agent", "curl/8.4.0"], ["host", "api.partner.example"], ["x-custom-token", "abc123"], ["cookie", "sid=1"], ["accept-language", "u".repeat(300)]] });
    expect(r.status, r.message).toBe(Status.OK);
    const body = actionOf(api.decided[0] as Record<string, unknown>).input.body ?? "";
    expect(body).toContain("[request headers]");
    expect(body).toContain("x-custom-token: abc123");
    expect(body).toContain("cookie: sid=1");
    expect(body).toContain(`accept-language: ${"u".repeat(300)}`);
    expect(body).not.toContain("accept: */*");
    expect(body).not.toContain("curl/8");
    expect(body).not.toContain("host:");
    // Every decide the middleware sends is marked as network traffic (middlewareDecideContext).
    expect((api.decided[0] as Record<string, unknown>).context).toEqual({ attended: false, traffic: "network" });
    // A GET with only standard headers of their usual shape stays a plain fetch: no body at all.
    await sup.request({ sandboxId: "s1", host: "api.partner.example", headers: [["accept", "application/json, text/plain;q=0.9"], ["user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"], ["accept-encoding", "gzip, deflate, br"], ["host", "api.partner.example:443"]] });
    expect(actionOf(api.decided[1] as Record<string, unknown>).input.body).toBeUndefined();
  });

  it("every standard header value is scanned unless it fits its shape: a key in the User-Agent, a repeated header, data spread over many headers", async () => {
    const bodyOf = async (headers: [string, string][]): Promise<string> => {
      api.decided.length = 0;
      const r = await sup.request({ sandboxId: "s1", host: "api.partner.example", headers });
      expect(r.status, r.message).toBe(Status.OK);
      return actionOf(api.decided[0] as Record<string, unknown>).input.body ?? "";
    };
    expect(await bodyOf([["user-agent", `curl/8.4.0 ${LIVE_KEY}`]])).toContain(LIVE_KEY);
    expect(await bodyOf([["user-agent", "Mozilla/5.0 (AKIAIOSFODNN7EXAMPLE)"]])).toContain("AKIAIOSFODNN7EXAMPLE");
    expect(await bodyOf([["content-type", "application/json; boundary=c2VjcmV0"]])).toContain("c2VjcmV0");
    expect(await bodyOf([["content-length", "12x"]])).toContain("content-length: 12x");
    // The same header twice: both values are data.
    const twice = await bodyOf([["accept-language", "en"], ["accept-language", "dGhlIHNlY3JldA"]]);
    expect(twice).toContain("accept-language: en");
    expect(twice).toContain("dGhlIHNlY3JldA");
    // Values that each fit a shape, spread over many headers: together past the limit, all of them are data.
    const word = (n: number): string => Array.from({ length: n }, (_, i) => `l${"abcdefgh"[i % 8]}`).join(", ");
    // (Language and charset lists stay within their 10 items, so each still fits its shape on its own.)
    const n = (k: number, v: string): string => Array.from({ length: k }, () => v).join(", ");
    const spread = await bodyOf([["accept-language", word(10)], ["accept-charset", n(10, "utf-8")], ["accept", n(45, "text/html")], ["te", n(50, "trailers")], ["cache-control", n(50, "no-cache")], ["accept-encoding", n(80, "gzip")], ["connection", n(40, "keep-alive")]]);
    for (const h of ["accept-language:", "accept-charset:", "accept:", "te:", "cache-control:", "accept-encoding:", "connection:"]) expect(spread, h).toContain(h);
    // Digits split over many User-Agent products, past 40 in all: scanned. A browser's own (about 30) is not.
    const split = "x/4111 y/1111 z/1111 w/1111 v/4111 u/1111 t/1111 s/1111 r/4111 q/1111 p/1111";
    expect(await bodyOf([["user-agent", split]])).toContain(split);
    expect(await bodyOf([["user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Safari/537.36"]])).toBe("");
    // A language list past 10 items, or a numeric region other than 419: scanned. A short list with es-419 is not.
    const langs = "en, fr, de, es, it, pt, nl, sv, da, fi, nb";
    expect(await bodyOf([["accept-language", langs]])).toContain(langs);
    expect(await bodyOf([["accept-language", "en-123"]])).toContain("en-123");
    expect(await bodyOf([["accept-language", "es-419, es;q=0.9, en;q=0.8"]])).toBe("");
    const charsets = Array.from({ length: 11 }, () => "utf-8").join(", ");
    expect(await bodyOf([["accept-charset", charsets]])).toContain("accept-charset:");
  });

  it("a Host header naming another host than the target is denied, and the refusal is recorded as a decision (domain fronting)", async () => {
    for (const host of ["evil.example", "api.partner.example.evil.example", "api.partner.example:8443"]) {
      api.decided.length = 0;
      // One sandbox each: identical refusals in one sandbox are throttled (below).
      const r = await sup.request({ sandboxId: `s1-${host}`, host: "api.partner.example", headers: [["host", host]] });
      expect(r.status, r.message).toBe(Status.OK);
      expect(r.result?.decision, host).toBe(DENY);
      expect(r.result?.reasonCode).toBe(HOST_MISMATCH_CODE);
      // Never judged by its target: the one decision asked for is the refusal, for the signed log.
      expect(api.decided.length).toBe(1);
      const a = actionOf(api.decided[0] as Record<string, unknown>);
      expect(a.tool).toBe("launchsafe:network-refused");
      expect(a.input.code).toBe(HOST_MISMATCH_CODE);
      expect(a.input.reason).toContain(host);
      expect((api.decided[0] as Record<string, unknown>).context).toMatchObject({ traffic: "network" });
      expect(r.result?.metadata.decision_id).toMatch(/^dec_\d+$/);
    }
  });

  it(":scheme, :method or :path pseudo-headers that do not restate the target are denied and recorded; matching ones pass", async () => {
    for (const [i, hs] of ([[[":path", "/other?k=AKIAIOSFODNN7EXAMPLE"]], [[":scheme", "http"]], [[":method", "POST"]], [[":protocol", "x"]], [[":secret", "AKIAIOSFODNN7EXAMPLE"]], [[":path", "/v1/x?a=1#frag"]]] as [string, string][][]).entries()) {
      api.decided.length = 0;
      const r = await sup.request({ sandboxId: `s1-${i}`, host: "api.partner.example", path: "/v1/x", query: "a=1", headers: hs });
      expect(r.status, r.message).toBe(Status.OK);
      expect(r.result?.decision, JSON.stringify(hs)).toBe(DENY);
      expect(r.result?.reasonCode).toBe(TARGET_MISMATCH_CODE);
      expect(actionOf(api.decided[0] as Record<string, unknown>).tool).toBe("launchsafe:network-refused");
    }
    api.decided.length = 0;
    const ok = await sup.request({ sandboxId: "s1", host: "api.partner.example", path: "/v1/x", query: "a=1", headers: [[":method", "GET"], [":scheme", "https"], [":path", "/v1/x?a=1"], [":authority", "api.partner.example"]] });
    expect(ok.result?.decision).toBe(ALLOW);
    expect(actionOf(api.decided[0] as Record<string, unknown>).tool).toBe("HttpRequest");
    // The same target, written the ways a client may: escapes of unreserved characters, lower-case hex, a bare "?".
    for (const [path, query, p] of [["/v1/x", "a=1", "/v1/%78?a=1"], ["/v1/a%2Fb", "", "/v1/a%2fb"], ["/v1/x", "", "/v1/x?"], ["/v1/~x", "q=%7E", "/v1/%7ex?q=~"]] as [string, string, string][]) {
      const same = await sup.request({ sandboxId: "s1", host: "api.partner.example", path, query, headers: [[":path", p]] });
      expect(same.result?.decision, p).toBe(ALLOW);
    }
  });

  it("identical refusals in one sandbox are recorded once per window, with the count of the ones in between; WebSocket loopback messages too", async () => {
    const fronted = (): ReturnType<Supervisor["request"]> => sup.request({ sandboxId: "loop", host: "api.partner.example", headers: [["host", "evil.example"]] });
    for (let i = 0; i < 5; i++) {
      const r = await fronted();
      expect(r.result?.decision).toBe(DENY);
      expect(r.result?.reasonCode).toBe(HOST_MISMATCH_CODE);
    }
    expect(api.decided.length).toBe(1);
    // Another sandbox's refusals are its own.
    await sup.request({ sandboxId: "other", host: "api.partner.example", headers: [["host", "evil.example"]] });
    expect(api.decided.length).toBe(2);
    clock += REFUSAL_WINDOW_MS;
    await fronted();
    expect(api.decided.length).toBe(3);
    const third = actionOf(api.decided[2] as Record<string, unknown>).input as Record<string, unknown>;
    expect(third.repeated).toBe(4);
    expect(String(third.reason)).toContain("4 more identical refusals");
    // A sandbox looping WebSocket messages to a loopback target: every message denied, one recorded.
    api.decided.length = 0;
    const msgs = [wsPreflight({ sandboxId: "ws-loop", host: "127.0.0.1", scheme: "ws", port: 8080 }), wsStart(), ...Array.from({ length: 6 }, (_, i) => wsMessage(i + 1, "ping")), sessionEnd(4)];
    const ws = await sup.websocket(msgs);
    expect(ws.status, ws.message).toBe(Status.OK);
    for (let i = 1; i <= 6; i++) expect(uint(msg(ws.results[i] as never, 2) as never, 2)).toBe(DENY);
    expect(api.decided.length).toBe(1);
  });

  it("a sandbox past its refusals per window has its new hosts counted together, so random hosts cannot flood the log", async () => {
    for (let i = 0; i < REFUSALS_PER_WINDOW + 5; i++) {
      const r = await sup.request({ sandboxId: "many", host: `h${i}.localhost`, scheme: "http", port: 80 });
      expect(r.result?.reasonCode).toBe(LOOPBACK_CODE);
    }
    // One per host up to the limit, then one entry standing for the rest.
    expect(api.decided.length).toBe(REFUSALS_PER_WINDOW + 1);
    expect(String(actionOf(api.decided[REFUSALS_PER_WINDOW] as Record<string, unknown>).input.reason)).toContain("counted together");
  });

  it("the URL and the reason of a recorded refusal have credentials masked", async () => {
    await sup.request({ sandboxId: "mask", host: "api.partner.example", path: "/x", query: `k=${LIVE_KEY}`, headers: [["host", `${LIVE_KEY}.evil.example`]] });
    const input = actionOf(api.decided[0] as Record<string, unknown>).input;
    expect(input.url).not.toContain(LIVE_KEY);
    expect(input.reason).not.toContain(LIVE_KEY);
    expect(input.reason).toContain("redacted");
  });

  it("a different fronted Host or pseudo-header value is its own kind: each is recorded, a repeat (normalised) is counted", async () => {
    const send = (headers: [string, string][]): ReturnType<Supervisor["request"]> => sup.request({ sandboxId: "kinds", host: "api.partner.example", path: "/v1/x", headers });
    await send([["host", "evil2.example"]]);
    await send([["host", "evil3.example"]]);
    expect(api.decided.length).toBe(2);
    await send([["host", "EVIL2.example."]]);
    expect(api.decided.length).toBe(2);
    await send([[":path", "/a"]]);
    await send([[":path", "/b"]]);
    expect(api.decided.length).toBe(4);
    await send([[":path", "/%61"]]);
    expect(api.decided.length).toBe(4);
    expect(api.decided.map((b) => actionOf(b).input.reason).join("\n")).toMatch(/evil2[\s\S]*evil3[\s\S]*:path: \/a[\s\S]*:path: \/b/);
  });

  it("assignment-style credentials, userinfo and a credential straddling the 200-character cut are masked in what is sent to the API", async () => {
    const cases: { query?: string; headers: [string, string][]; secrets: string[] }[] = [
      { query: "password=pA55w0rd-Q7zK2mLx&access_token=ya29Tok3nQ8vR2nZ", headers: [["host", "evil.example"]], secrets: ["pA55w0rd-Q7zK2mLx", "ya29Tok3nQ8vR2nZ"] },
      { headers: [["host", "alice:S3cr3tPassw0rdZ9@evil.example"]], secrets: ["S3cr3tPassw0rdZ9", "alice:"] },
      { headers: [[":path", "https://bob:An0therPassw0rd@evil.example/x"]], secrets: ["An0therPassw0rd"] },
      { headers: [[":path", "/x?password=pA55w0rd-Q7zK2mLx"]], secrets: ["pA55w0rd-Q7zK2mLx"] },
      // Cut at 200 characters before masking, these would leave the key's first characters in the record.
      { headers: [["host", `${"a".repeat(189)}.${LIVE_KEY}.evil.example`]], secrets: [LIVE_KEY.slice(0, 8)] },
      { headers: [[":path", `/${"a".repeat(180)}?k=${LIVE_KEY}`]], secrets: [LIVE_KEY.slice(0, 8)] },
    ];
    for (const [i, c] of cases.entries()) {
      api.decided.length = 0;
      const r = await sup.request({ sandboxId: `mask-${i}`, host: "api.partner.example", path: "/x", ...(c.query !== undefined ? { query: c.query } : {}), headers: c.headers });
      expect(r.result?.decision).toBe(DENY);
      expect(api.decided.length, String(i)).toBe(1);
      const sent = JSON.stringify(api.decided[0]);
      for (const secret of c.secrets) expect(sent, `${i}: ${secret}`).not.toContain(secret);
    }
  });

  it("a refusal whose record failed is tried again by the next identical one, with the count", async () => {
    let calls = 0;
    const flaky: DecisionClient = { ...api, decide: async (b) => (++calls === 1 ? Promise.reject(new Error("down")) : api.decide(b)) };
    const failed: string[] = [];
    const mw2 = await middleware(flaky, { onRefusalUnrecorded: (m) => failed.push(m), clock: () => clock });
    const sup2 = supervisor(mw2.address);
    const fronted = (): ReturnType<Supervisor["request"]> => sup2.request({ sandboxId: "flaky", host: "api.partner.example", headers: [["host", "evil.example"]] });
    expect((await fronted()).result?.decision).toBe(DENY);
    expect(failed.length).toBe(1);
    const second = await fronted();
    expect(second.result?.decision).toBe(DENY);
    expect(second.result?.metadata.decision_id).toMatch(/^dec_\d+$/);
    expect(api.decided.length).toBe(1);
    expect(actionOf(api.decided[0] as Record<string, unknown>).input).toMatchObject({ repeated: 1 });
    // Recorded now: the next one in the window is counted again.
    await fronted();
    expect(calls).toBe(2);
    sup2.close();
    await mw2.close();
  });

  it("an exception in the throttle still ends in a clean deny, reported", async () => {
    const boom = { admit: () => { throw new Error("boom"); }, release: () => undefined } as unknown as RefusalThrottle;
    const failed: string[] = [];
    const mw2 = await middleware(api, { onRefusalUnrecorded: (m) => failed.push(m), refusals: boom });
    const sup2 = supervisor(mw2.address);
    const r = await sup2.request({ sandboxId: "boom", host: "api.partner.example", headers: [["host", "evil.example"]] });
    expect(r.status, r.message).toBe(Status.OK);
    expect(r.result?.decision).toBe(DENY);
    expect(r.result?.reasonCode).toBe(HOST_MISMATCH_CODE);
    expect(failed[0]).toMatch(/boom/);
    sup2.close();
    await mw2.close();
  });

  it("the throttle's window is on a monotonic clock: a wall-clock step does not reopen it", async () => {
    const mw2 = await middleware(api, {});
    const sup2 = supervisor(mw2.address);
    const fronted = (): ReturnType<Supervisor["request"]> => sup2.request({ sandboxId: "mono", host: "api.partner.example", headers: [["host", "evil.example"]] });
    await fronted();
    expect(api.decided.length).toBe(1);
    const wall = Date.now() + 10 * REFUSAL_WINDOW_MS;
    const spy = vi.spyOn(Date, "now").mockReturnValue(wall);
    try {
      expect((await fronted()).result?.decision).toBe(DENY);
    } finally {
      spy.mockRestore();
    }
    expect(api.decided.length).toBe(1);
    sup2.close();
    await mw2.close();
  });

  it("the unrecorded-refusal report is rate-limited: once per reason code per window, then with the count of the ones not reported (r6, item 4)", async () => {
    const down: DecisionClient = { decide: async () => Promise.reject(new Error("down")), result: async () => ({}), input: async () => undefined };
    const failed: string[] = [];
    let now = 0;
    const mw2 = await middleware(down, { onRefusalUnrecorded: (m) => failed.push(m), clock: () => now });
    const sup2 = supervisor(mw2.address);
    for (let i = 0; i < 5; i++) {
      const r = await sup2.request({ sandboxId: "loop", host: "api.partner.example", headers: [["host", `evil${i}.example`]] });
      expect(r.result?.decision).toBe(DENY);
    }
    expect(failed.length).toBe(1);
    now = REFUSAL_WINDOW_MS + 1;
    await sup2.request({ sandboxId: "loop", host: "api.partner.example", headers: [["host", "evil.example"]] });
    expect(failed.length).toBe(2);
    expect(failed[1]).toContain("4 more refused requests");
    sup2.close();
    await mw2.close();
  });

  it("a refusal the API cannot record is still a deny", async () => {
    const down: DecisionClient = { decide: async () => Promise.reject(new Error("down")), result: async () => ({}), input: async () => undefined };
    const failed: string[] = [];
    const mw2 = await middleware(down, { onRefusalUnrecorded: (m) => failed.push(m) });
    const sup2 = supervisor(mw2.address);
    const r = await sup2.request({ sandboxId: "s1", host: "api.partner.example", headers: [["host", "evil.example"]] });
    expect(r.status, r.message).toBe(Status.OK);
    expect(r.result?.decision).toBe(DENY);
    expect(r.result?.reasonCode).toBe(HOST_MISMATCH_CODE);
    // Not swallowed: the failure is reported (and counted in the service's stats).
    expect(failed.length).toBe(1);
    expect(failed[0]).toMatch(/could not be recorded.*down/);
    sup2.close();
    await mw2.close();
  });

  it("the hold for an unreadable body is bound to the whole request: another header or a longer URL is another action", async () => {
    api.decided.length = 0;
    const base = { sandboxId: "s-bind", host: "api.partner.example", method: "POST", body: Buffer.from([0x1f, 0x8b, 0x08, 0x00]) };
    const long = `/${"a".repeat(500)}`;
    const send = (headers: [string, string][], path = "/upload"): Promise<unknown> => sup.request({ ...base, path, headers: [["content-encoding", "gzip"], ...headers] });
    await send([["x-api-key", "one"]]);
    await send([["x-api-key", "two"]]);
    await send([], `${long}1`);
    await send([], `${long}2`);
    const holds = api.decided.filter((b) => actionOf(b as Record<string, unknown>).tool === "launchsafe:unparseable").map((b) => JSON.stringify(actionOf(b as Record<string, unknown>).input));
    expect(holds.length).toBe(4);
    expect(new Set(holds).size).toBe(4);
    expect(holds[0]).toMatch(/request sha256 [0-9a-f]{64}/);
  });

  it("compressed, binary and non-UTF-8 bodies: a dry run for the host lists, then a hold bound to the exact bytes", async () => {
    for (const [hs, body] of [
      [[["content-encoding", "br"]], Buffer.from("plain")],
      [[["content-type", "application/octet-stream"]], Buffer.from("plain")],
      [[["content-type", "text/plain"]], Buffer.from([0xff, 0xfe, 0x41])],
    ] as [[string, string][], Buffer][]) {
      api.decided.length = 0;
      const r = await sup.request({ sandboxId: "s2", host: "api.partner.example", method: "POST", headers: hs, body });
      expect(r.status, r.message).toBe(Status.OK);
      expect(r.result?.decision).toBe(DENY);
      expect(r.result?.reasonCode).toBe("launchsafe_hold_fw_test");
      expect(api.decided.length).toBe(2);
      expect((api.decided[0] as Record<string, unknown>).dryRun).toBe(true);
      expect(actionOf(api.decided[0] as Record<string, unknown>).input.body).toMatch(/cannot read: .*sha256 [0-9a-f]{64}/);
      expect(actionOf(api.decided[1] as Record<string, unknown>).tool).toBe("launchsafe:unparseable");
      for (const b of api.decided) expect((b as Record<string, unknown>).context).toMatchObject({ traffic: "network" });
    }
    // A deny from the dry run (the host lists) stays a deny, with no hold to approve.
    const strict = stubApi({ verdict: () => "deny" });
    const mw2 = await middleware(strict);
    const sup2 = supervisor(mw2.address);
    const r = await sup2.request({ sandboxId: "s2", host: "evil.example", method: "POST", headers: [["content-encoding", "gzip"]], body: Buffer.from([1, 2, 3]) });
    expect(r.result?.reasonCode).toBe("launchsafe_deny_fw_test");
    expect(strict.decided.length).toBe(1);
    sup2.close();
    await mw2.close();
  });

  it("loopback targets are denied without judging, and each refusal is recorded as a decision", async () => {
    api.decided.length = 0;
    for (const host of ["127.0.0.1", "localhost", "api.localhost", "::1", "0.0.0.0", "2130706433"]) {
      const r = await sup.request({ sandboxId: "s3", host, scheme: "http", port: 8080 });
      expect(r.status, `${host}: ${r.message}`).toBe(Status.OK);
      expect(r.result?.decision, host).toBe(DENY);
      expect(r.result?.reasonCode).toBe(LOOPBACK_CODE);
    }
    expect(api.decided.map((b) => actionOf(b).tool)).toEqual(Array(6).fill("launchsafe:network-refused"));
    expect(api.decided.map((b) => actionOf(b).input.code)).toEqual(Array(6).fill(LOOPBACK_CODE));
  });

  it("targets that are not on the public internet are denied without judging, and each refusal is recorded as a decision", async () => {
    api.decided.length = 0;
    const hosts = [
      // Private networks, and the blocks no public host lives in.
      "10.0.0.1", "172.16.0.1", "192.168.0.1", "100.64.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255", "192.0.0.8", "198.18.0.1", "203.0.113.7",
      // Short, hex and octal IPv4.
      "0xa.0.0.1", "012.0.0.1", "10.1",
      // IPv6, and IPv4 inside IPv6 (mapped, written out in full, NAT64).
      "fc00::1", "fd12:3456::1", "fec0::1", "fe80::1", "ff02::1", "2001:db8::1", "::ffff:10.0.0.1", "::ffff:c0a8:1", "0:0:0:0:0:ffff:a00:1", "64:ff9b::a00:1", "64:ff9b::a9fe:a9fe",
    ];
    for (const host of hosts) {
      const r = await sup.request({ sandboxId: "s3_internal", host, scheme: "http", port: 8080 });
      expect(r.status, `${host}: ${r.message}`).toBe(Status.OK);
      expect(r.result?.decision, host).toBe(DENY);
      expect(r.result?.reasonCode, host).toBe(INTERNAL_CODE);
    }
    expect(api.decided.map((b) => actionOf(b).tool)).toEqual(Array(hosts.length).fill("launchsafe:network-refused"));
    expect(api.decided.map((b) => actionOf(b).input.code)).toEqual(Array(hosts.length).fill(INTERNAL_CODE));
    expect(actionOf(api.decided[0] as Record<string, unknown>).input.reason).toBe("the target 10.0.0.1 is a private address, not an address on the public internet");
  });

  it("what is left to the engine is judged, not refused: public addresses just outside each block, names that only look like addresses, a metadata address", async () => {
    api.decided.length = 0;
    const hosts = [
      // One step outside 172.16/12, 192.168/16, 100.64/10, 198.18/15, 192.0.0/24 and the documentation blocks.
      "172.15.255.255", "172.32.0.1", "192.167.0.1", "192.169.0.1", "100.63.255.255", "100.128.0.1", "198.17.255.255", "198.20.0.1", "192.0.1.1", "203.0.112.1", "11.0.0.1",
      "8.8.8.8", "2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808", "2001:db9::1",
      // A name is not an address, whatever it starts with.
      "10.example.com", "192.168.0.1.example.com", "fc00.example.com", "fd00.example.com", "1.example",
      // Metadata is the engine's (FW-METADATA says what it is).
      "169.254.169.254", "0xa9.0xfe.0xa9.0xfe", "::ffff:a9fe:a9fe", "100.100.100.200", "metadata.google.internal",
    ];
    for (const host of hosts) {
      const r = await sup.request({ sandboxId: "s3_judged", host, scheme: "http", port: 8080 });
      expect(r.status, `${host}: ${r.message}`).toBe(Status.OK);
      expect(r.result?.decision, host).toBe(ALLOW);
    }
    expect(api.decided.map((b) => actionOf(b).tool)).toEqual(Array(hosts.length).fill("HttpRequest"));
  });

  it("WebSocket messages to a private address are denied with the same code, and a looping sandbox records one", async () => {
    api.decided.length = 0;
    const msgs = [wsPreflight({ sandboxId: "ws-internal", host: "10.0.0.1", scheme: "ws", port: 8080 }), wsStart(), ...Array.from({ length: 6 }, (_, i) => wsMessage(i + 1, "ping")), sessionEnd(4)];
    const ws = await sup.websocket(msgs);
    expect(ws.status, ws.message).toBe(Status.OK);
    for (let i = 1; i <= 6; i++) {
      const result = msg(ws.results[i] as never, 2) as never;
      expect(uint(result, 2)).toBe(DENY);
      expect(str(result, 6)).toBe(INTERNAL_CODE);
    }
    expect(api.decided.length).toBe(1);
    expect(actionOf(api.decided[0] as Record<string, unknown>)).toMatchObject({ tool: "launchsafe:network-refused", input: { method: "WEBSOCKET", code: INTERNAL_CODE } });
    // A message to a public address is judged as before.
    const open = await sup.websocket([wsPreflight({ sandboxId: "ws-public", host: "8.8.8.8", scheme: "ws", port: 8080 }), wsStart(), wsMessage(1, "ping"), sessionEnd(4)]);
    expect(uint(msg(open.results[1] as never, 2) as never, 2)).toBe(ALLOW);
  });

  it("refused as malformed: no scheme, host or method, a wrong wire type, another phase, a '.' or '..' session", async () => {
    for (const bad of [{ scheme: "" }, { host: "" }, { method: "" }, { method: "GE T" }, { phase: 2 }, { sandboxId: ".." }, { sandboxId: "a/../b" }, { sandboxId: "." }, { config: { session: ".." } }]) {
      const r = await sup.request({ sandboxId: "s4", host: "docs.example.com", ...bad });
      expect(r.status, JSON.stringify(bad)).toBe(Status.INVALID_ARGUMENT);
    }
    // The host written as a varint (wire type 0) instead of a string: an error, not an empty host.
    const wrong = new Writer().enum(1, 1).msg(2, new Writer().str(2, "s4")).msg(4, new Writer().str(1, "https").uint(2, 7).str(4, "GET")).finish();
    expect((await sup.client.unary(`/${SERVICE}/EvaluateHttpRequest`, wrong)).status).toBe(Status.INVALID_ARGUMENT);
    expect(await sup.validate({ session: ".." })).toMatchObject({ valid: false });
    expect(api.decided).toEqual([]);
    // The stand-in's own message is well formed.
    expect(httpRequest({ sandboxId: "s4", host: "docs.example.com" }).length).toBeGreaterThan(0);
  });
});

describe("responses: a redaction the service cannot apply withholds the body", () => {
  const SECRET = "vault-secret-value";
  const redact = (t: string): string => t.split(SECRET).join("[REDACTED]");
  let api: ReturnType<typeof stubApi>;
  let mw: RunningGrpcServer;
  let sup: Supervisor;
  beforeEach(async () => {
    api = stubApi({ redact, verdict: (b) => (String(actionOf(b).input.url).includes("denied.example") ? "deny" : "allow") });
    mw = await middleware(api, { maxPayloadBytes: 1024 });
    sup = supervisor(mw.address);
  });
  afterEach(async () => {
    sup.close();
    await mw.close();
  });
  const pre = (requestId: string, host = "docs.example.com"): Buffer => responsePreflight({ requestId, sandboxId: "r1", host });
  const replaced = (r: { results: Parameters<typeof msg>[0][] }, i: number): string | null => {
    const b = msg(r.results[i] as never, 2) as NonNullable<ReturnType<typeof msg>>;
    const rep = msg(b, 3);
    return rep === null ? null : (bytes(rep, 1) as Buffer).toString("utf8");
  };

  it("one unit of UTF-8 with a redaction is rewritten; a clean body with control characters is passed through untouched", async () => {
    await sup.request({ requestId: "a", sandboxId: "r1", host: "docs.example.com" });
    const r = await sup.response([pre("a"), responseBody(1, `token ${SECRET} end`)]);
    expect(r.status, r.message).toBe(Status.OK);
    expect(replaced(r, 1)).toBe("token [REDACTED] end");
    await sup.request({ requestId: "b", sandboxId: "r1", host: "docs.example.com" });
    const clean = await sup.response([pre("b"), responseBody(1, "bell\u0007 and tab\u0001")]);
    expect(clean.status, clean.message).toBe(Status.OK);
    expect(replaced(clean, 1)).toBeNull();
    expect(msg(msg(clean.results[1] as never, 2) as never, 2)).not.toBeNull(); // pass_through
  });

  it("several units, not UTF-8, or a redacted body over the limit: the stream fails (fail_closed withholds it), never pass_through", async () => {
    await sup.request({ requestId: "m", sandboxId: "r1", host: "docs.example.com" });
    const multi = await sup.response([pre("m"), responseBody(1, `part ${SECRET.slice(0, 5)}`, false), responseBody(2, `${SECRET.slice(5)} end`)]);
    expect(multi.status).toBe(Status.PERMISSION_DENIED);
    expect(multi.message).toContain("not delivered");
    await sup.request({ requestId: "u", sandboxId: "r1", host: "docs.example.com" });
    const nonUtf8 = await sup.response([pre("u"), responseBody(1, Buffer.concat([Buffer.from(`${SECRET} `), Buffer.from([0xff])]))]);
    expect(nonUtf8.status).toBe(Status.PERMISSION_DENIED);
    const big = stubApi({ redact: (t) => (t.includes(SECRET) ? "x".repeat(2000) : t) });
    const mw2 = await middleware(big, { maxPayloadBytes: 1024 });
    const sup2 = supervisor(mw2.address);
    await sup2.request({ requestId: "g", sandboxId: "r1", host: "docs.example.com" });
    expect((await sup2.response([pre("g"), responseBody(1, SECRET)])).status).toBe(Status.PERMISSION_DENIED);
    sup2.close();
    await mw2.close();
  });

  it("no remembered request (an empty or unknown id, or one evicted): a fresh read decision, so the body is still redacted; refused when that read is not allowed", async () => {
    for (const id of ["", "never-sent"]) {
      const r = await sup.response([pre(id), responseBody(1, `x ${SECRET}`)]);
      expect(r.status, r.message).toBe(Status.OK);
      expect(replaced(r, 1)).toBe("x [REDACTED]");
    }
    const small = stubApi({ redact });
    const mw2 = await middleware(small, { recentRequests: 1 });
    const sup2 = supervisor(mw2.address);
    await sup2.request({ requestId: "old", sandboxId: "r1", host: "docs.example.com" });
    await sup2.request({ requestId: "new", sandboxId: "r1", host: "docs.example.com" });
    const evicted = await sup2.response([pre("old"), responseBody(1, SECRET)]);
    expect(evicted.status, evicted.message).toBe(Status.OK);
    expect(replaced(evicted, 1)).toBe("[REDACTED]");
    expect(actionOf(small.decided[2] as Record<string, unknown>).input).toMatchObject({ method: "GET" });
    sup2.close();
    await mw2.close();
    const denied = await sup.response([pre("nope", "denied.example"), responseBody(1, "anything")]);
    expect(denied.status).toBe(Status.PERMISSION_DENIED);
  });

  it("a response that ends without its final part is recorded as unread and fails the stream", async () => {
    await sup.request({ requestId: "e1", sandboxId: "r1", host: "docs.example.com" });
    const cut = await sup.response([pre("e1"), responseBody(1, "first part", false)]);
    expect(cut.status).toBe(Status.FAILED_PRECONDITION);
    expect(cut.message).toContain("final part");
    const unread = (): boolean => [...api.inputs, ...api.results.map((r) => r.output)].some((x) => x.includes("without its final part"));
    expect(unread()).toBe(true);
    api.inputs.length = 0;
    api.results.length = 0;
    await sup.request({ requestId: "e2", sandboxId: "r1", host: "docs.example.com" });
    const ended = await sup.response([pre("e2"), responseBody(1, "first part", false), sessionEnd(3)]);
    expect(ended.status).toBe(Status.FAILED_PRECONDITION);
    expect(unread()).toBe(true);
    // A complete response, and one that never sent a body, are not that.
    await sup.request({ requestId: "e3", sandboxId: "r1", host: "docs.example.com" });
    expect((await sup.response([pre("e3"), responseBody(1, "a", false), responseBody(2, "b"), sessionEnd(3)])).status).toBe(Status.OK);
    expect((await sup.response([pre("e4"), sessionEnd(3)])).status).toBe(Status.OK);
  });

  it("a body over the limit, or compressed or binary per its headers, is not taken as text", async () => {
    await sup.request({ requestId: "o", sandboxId: "r1", host: "docs.example.com" });
    expect((await sup.response([pre("o"), responseBody(1, "y".repeat(600), false), responseBody(2, "y".repeat(600))])).status).toBe(Status.RESOURCE_EXHAUSTED);
    const gz = await sup.response([responsePreflight({ requestId: "c", sandboxId: "r1", host: "docs.example.com", headers: [["content-encoding", "gzip"]] })]);
    expect(msg(msg(gz.results[0] as never, 1) as never, 1)).not.toBeNull(); // skip, recorded as unread
    expect(api.inputs.some((x) => x.includes("compressed (gzip)"))).toBe(true);
  });
});

describe("the gRPC server's limits", () => {
  const echo = { [`/${RESPONSE_SERVICE}/Evaluate`]: (_c: unknown, send: (m: Buffer) => void) => ({ message: async (m: Buffer) => send(m), end: async () => undefined }) };
  const raw = (url: string, path: string, chunks: Buffer[], endStream: boolean): Promise<{ status: number }> =>
    new Promise((resolve, reject) => {
      const s = http2.connect(url);
      s.on("error", () => undefined);
      const req = s.request({ ":method": "POST", ":path": path, "content-type": "application/grpc", te: "trailers" });
      let status = -1;
      const take = (h: http2.IncomingHttpHeaders): void => {
        if (h["grpc-status"] !== undefined) status = Number(h["grpc-status"]);
      };
      req.on("response", take);
      req.on("trailers", take);
      req.on("data", () => undefined);
      req.on("close", () => {
        s.close();
        resolve({ status });
      });
      req.on("error", reject);
      for (const c of chunks) req.write(c);
      if (endStream) req.end();
    });

  it("caps messages and bytes per call, refuses a stream that ends inside a message, and ends an idle call", async () => {
    const srv = await startGrpcServer({ host: "127.0.0.1", port: 0, maxMessageBytes: 1024, unary: {}, streams: echo, maxStreamMessages: 2, maxStreamBytes: 4096, streamIdleMs: 200 });
    try {
      const path = `/${RESPONSE_SERVICE}/Evaluate`;
      expect((await raw(srv.address, path, [frame(Buffer.from("a")), frame(Buffer.from("b"))], true)).status).toBe(Status.OK);
      expect((await raw(srv.address, path, [frame(Buffer.from("a")), frame(Buffer.from("b")), frame(Buffer.from("c"))], true)).status).toBe(Status.RESOURCE_EXHAUSTED);
      expect((await raw(srv.address, path, [frame(Buffer.alloc(1000)), frame(Buffer.alloc(1000)), Buffer.alloc(3000)], true)).status).toBe(Status.RESOURCE_EXHAUSTED);
      expect((await raw(srv.address, path, [frame(Buffer.from("abc")).subarray(0, 6)], true)).status).toBe(Status.INVALID_ARGUMENT);
      expect((await raw(srv.address, path, [frame(Buffer.from("a"))], false)).status).toBe(Status.DEADLINE_EXCEEDED);
    } finally {
      await srv.close();
    }
  });

  it("advertises a limit on concurrent streams", async () => {
    const srv = await startGrpcServer({ host: "127.0.0.1", port: 0, maxMessageBytes: 1024, unary: {}, streams: echo, maxConcurrentStreams: 7 });
    const s = http2.connect(srv.address);
    try {
      const settings = await new Promise<http2.Settings>((resolve) => s.once("remoteSettings", resolve));
      expect(settings.maxConcurrentStreams).toBe(7);
    } finally {
      s.close();
      await srv.close();
    }
  });
});

describe("request helpers", () => {
  it("validSessionId refuses '.', '..' and empty parts", () => {
    expect(validSessionId("sbx-1") && validSessionId("team/run.1")).toBe(true);
    for (const s of [".", "..", "a/..", "../a", "a//b", "a/./b", "/a", "a/"]) expect(validSessionId(s), s).toBe(false);
  });
  it("isLoopbackTarget", () => {
    for (const h of ["localhost", "x.localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "broadcasthost", "127.0.0.2", "[::1]", "::ffff:127.0.0.1", "0x7f000001", "0.0.0.0"]) expect(isLoopbackTarget(h), h).toBe(true);
    // Short, hex and octal IPv4 spellings, and IPv4 inside IPv6 (mapped, compatible, NAT64, written out in full).
    for (const h of ["127.1", "127.0.1", "0x7f.0.0.1", "0177.0.0.1", "0x7f.1", "0.0", "[::ffff:7f00:1]", "0:0:0:0:0:ffff:7f00:1", "::ffff:0:1", "[::127.0.0.1]", "64:ff9b::7f00:1", "0:0:0:0:0:0:0:1", "0000::0001", "::"]) expect(isLoopbackTarget(h), h).toBe(true);
    for (const h of ["docs.example.com", "10.0.0.1", "localhost.example.com", "1.example", "127.0.0.1.example.com", "0x7f.example", "::ffff:a00:1", "2001:db8::1", "128.0.0.1", "[2001:db8::2]"]) expect(isLoopbackTarget(h), h).toBe(false);
  });
  it("refusedTarget: loopback has its own code; private and special-purpose addresses are refused in every spelling, one step outside each block is not", () => {
    const code = (h: string): string | null => refusedTarget(h)?.code ?? null;
    for (const h of ["127.0.0.1", "localhost", "[::1]", "0.0.0.0", "0x7f.1", "::ffff:127.0.0.1"]) expect(code(h), h).toBe(LOOPBACK_CODE);
    const why = (h: string): string => {
      const r = refusedTarget(h);
      expect(r?.code, h).toBe(INTERNAL_CODE);
      return r?.reason ?? "";
    };
    for (const h of ["10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.0.1", "192.168.255.255", "[fc00::1]", "fd12:3456::1", "10.0.0.1.", "::10.0.0.1", "::ffff:10.0.0.1"]) expect(why(h), h).toMatch(/is a private (?:\(unique local\) )?address,/);
    for (const h of ["100.64.0.1", "100.127.255.255"]) expect(why(h), h).toContain("a carrier-grade NAT (shared) address");
    expect(why("fec0::1")).toContain("a site-local address");
    for (const h of ["169.254.1.1", "169.254.0.1", "fe80::1", "[fe80::abcd]"]) expect(why(h), h).toContain("a link-local address");
    for (const h of ["224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255", "ff02::1"]) expect(why(h), h).toMatch(/a multicast (?:or reserved )?address/);
    expect(why("192.0.0.8")).toContain("an IETF protocol-assignment address");
    for (const h of ["192.0.2.1", "198.51.100.7", "203.0.113.9"]) expect(why(h), h).toContain("a documentation (TEST-NET) address");
    expect(why("2001:db8::1")).toContain("a documentation address");
    for (const h of ["198.18.0.1", "198.19.255.255"]) expect(why(h), h).toContain("a benchmarking address");
    // Short, hex and octal IPv4, and IPv4 inside IPv6 (mapped, written out in full, compatible, NAT64).
    for (const h of ["10.1", "0xa.0.0.1", "012.0.0.1", "0xc0.0xa8.1", "192.168.1", "[::ffff:a00:1]", "0:0:0:0:0:ffff:a00:1", "::ffff:0:a00:1", "64:ff9b::a00:1", "64:ff9b::c0a8:1", "::ffff:192.168.0.1"]) expect(code(h), h).toBe(INTERNAL_CODE);
    // NAT64 around the metadata address is refused: the engine only reads the plain and mapped spellings as metadata.
    expect(why("64:ff9b::a9fe:a9fe")).toContain("a cloud metadata address");
    // One step outside each block, public addresses, names that only look like addresses: judged.
    for (const h of ["172.15.255.255", "172.32.0.1", "192.167.255.255", "192.169.0.1", "100.63.255.255", "100.128.0.1", "198.17.255.255", "198.20.0.1", "192.0.1.1", "203.0.112.255", "11.0.0.1", "9.255.255.255", "168.63.129.15"]) expect(code(h), h).toBeNull();
    for (const h of ["8.8.8.8", "2606:4700::1111", "::ffff:8.8.8.8", "[::ffff:808:808]", "64:ff9b::808:808", "2001:db9::1", "fb00::1", "fe00::1", "ec0::1"]) expect(code(h), h).toBeNull();
    for (const h of ["docs.example.com", "10.example.com", "10.0.0.1.example.com", "192.168.0.1.example.com", "fc00.example.com", "1.example", "0xa.example", "localhost.example.com", "a".repeat(120)]) expect(code(h), h).toBeNull();
    // Metadata addresses, in the spellings the engine reads as metadata, are its to deny under FW-METADATA.
    for (const h of ["169.254.169.254", "0xa9.0xfe.0xa9.0xfe", "0251.0376.0251.0376", "169.254.43518", "::ffff:a9fe:a9fe", "[::ffff:169.254.169.254]", "100.100.100.200", "192.0.0.192", "168.63.129.16", "metadata.google.internal"]) expect(code(h), h).toBeNull();
    // The reason quotes the target cut to 120 characters, so a long host cannot make a long record.
    expect(refusedTarget(`${"1".repeat(130)}.localhost`)?.reason).toBe(`the target ${`${"1".repeat(130)}.localhost`.slice(0, 120)} is this machine (loopback)`);
  });
  it("refusedTarget: loopback in the translated IPv6 form (::ffff:0:a.b.c.d) is loopback; other addresses in that form keep their class", () => {
    for (const h of ["::ffff:0:7f00:1", "[::ffff:0:127.0.0.1]", "0:0:0:0:ffff:0:7f00:1", "::ffff:0:7f12:3456", "::ffff:0:0:0"]) {
      expect(isLoopbackTarget(h), h).toBe(true);
      expect(refusedTarget(h)?.code, h).toBe(LOOPBACK_CODE);
    }
    expect(refusedTarget("::ffff:0:a00:1")?.code).toBe(INTERNAL_CODE);
    expect(refusedTarget("::ffff:0:808:808")).toBeNull();
  });
  it("refusedTarget: an IPv6 address with a trailing dot is refused, and a long address is quoted cut to 120 characters", () => {
    for (const h of ["fc00::1.", "fe80::1.", "fd12:3456::1."]) expect(refusedTarget(h)?.code, h).toBe(INTERNAL_CODE);
    // 10.0.0.1, its first part in hex padded with 200 zeros: 209 characters, a host targetUrl accepts.
    const h = `0x${"0".repeat(200)}a.0.0.1`;
    expect(refusedTarget(h)).toEqual({ code: INTERNAL_CODE, reason: `the target ${h.slice(0, 120)} is a private address, not an address on the public internet` });
  });
  it("unreadableBody and dataHeaders", () => {
    expect(unreadableBody(Buffer.from("{}"), [{ name: "content-type", value: "application/json" }])).toBeNull();
    expect(unreadableBody(Buffer.from("{}"), [{ name: "content-encoding", value: "gzip" }])).toContain("compressed");
    expect(unreadableBody(Buffer.from("{}"), [{ name: "content-type", value: "image/png" }])).toContain("binary");
    expect(unreadableBody(Buffer.from([0x61, 0x00]), [])).toBe("not UTF-8 text");
    expect(dataHeaders([{ name: "referer", value: "https://a.example/" }, { name: "host", value: "a" }], { host: "a", port: 443 })).toEqual(["referer: https://a.example/"]);
    // Without a target to compare with, a Host value is data.
    expect(dataHeaders([{ name: "host", value: "a" }])).toEqual(["host: a"]);
    expect(dataHeaders([{ name: "user-agent", value: "python-requests/2.31.0" }, { name: "content-length", value: "42" }, { name: "content-type", value: "application/json; charset=utf-8" }])).toEqual([]);
  });
  it("header shapes are closed: a secret in a MIME subtype, a charset, a language tag or a User-Agent word is scanned", () => {
    const scanned = (name: string, value: string): string[] => dataHeaders([{ name, value }]);
    const ghp = `ghp_${"aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gH3jK5"}`;
    for (const [name, value] of [
      ["content-type", "application/AKIAIOSFODNN7EXAMPLE"],
      ["content-type", `application/json; charset=${ghp}`],
      ["content-type", "application/x-akiaiosfodnnexampleakiaiosfodnn"],
      ["content-type", "application/akia1234+json"],
      ["accept", "text/html, application/AKIAIOSFODNN7EXAMPLE;q=0.9"],
      ["accept-charset", `utf-8, ${ghp}`],
      ["accept-language", "en-AKIAIOSFODNN7EXAMPLE"],
      ["accept-language", "en-US, dGhlIHNlY3JldA;q=0.5"],
      ["user-agent", "curl/8.4.0 (key1a2b3c4d)"],
      ["user-agent", "Mozilla/5.0 (X11; AKIAIOSFODNN7EXAMPLE)"],
      ["user-agent", "curl/4111.1111.1111.1111"],
      ["user-agent", "tool/1.0-AKIAIOSFODNN7EXAMPLE"],
      ["sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ"],
      ["sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==extra"],
    ] as [string, string][]) expect(scanned(name, value), `${name}: ${value}`).toEqual([`${name}: ${value}`]);
    // The usual values stay out of the scan.
    for (const [name, value] of [
      ["content-type", "application/json; charset=UTF-8"],
      ["content-type", "application/vnd.api+json"],
      ["content-type", "text/plain; charset=\"iso-8859-15\""],
      ["accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"],
      ["accept-charset", "utf-8, windows-1252;q=0.5, *;q=0.1"],
      ["accept-language", "en-US,en;q=0.9,zh-Hant;q=0.8,es-419;q=0.7"],
      ["user-agent", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"],
      ["user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Safari/537.36"],
      ["user-agent", "python-requests/2.31.0"],
      ["sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="],
    ] as [string, string][]) expect(scanned(name, value), `${name}: ${value}`).toEqual([]);
  });
  it("GrpcError carries its status", () => {
    expect(new GrpcError(Status.DEADLINE_EXCEEDED, "x").code).toBe(4);
  });
});
