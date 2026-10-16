/**
 * The remote guard against a fake sidecar (test/sdk/remote-sidecar.ts) speaking docs/api-v0.md: every
 * method, every row of the fail-closed table, idempotency keys, the request cap, approval waits and
 * reports kept for resending. Sockets are temporary; nothing outside the temp directory is touched.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createRemoteGuard, MAX_REQUEST_BYTES, type RemoteGuardOptions, type ToolSpec } from "../../src/sdk/node.js";
import { requestJson } from "../../src/sdk/remote-http.js";
import { closedPort, deadSocket, startSidecar, type FakeSidecar } from "./remote-sidecar.js";

const TOOLS: Record<string, ToolSpec> = {
  search_docs: { kind: "read", results: "trusted", privateData: false },
  web_search: { kind: "read" },
  send_email: { kind: "send" },
};
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const read = { tool: "search_docs", input: { q: "refunds" } };
const send = { tool: "send_email", input: { to: "a@example.com", body: "hi" } };

function opts(s: FakeSidecar, extra: RemoteGuardOptions = {}): RemoteGuardOptions {
  return { ...(s.socketPath !== undefined ? { socketPath: s.socketPath } : { baseUrl: s.baseUrl as string, allowTcp: true }), token: s.token, session: "run-1", tools: TOOLS, approvalPollMs: 10, onError: () => {}, ...extra };
}

const decides = (s: FakeSidecar) => s.seen.filter((r) => r.path === "/v1/decide");

for (const kind of ["socket", "tcp"] as const) {
  describe(`remote guard over ${kind}`, () => {
    let s: FakeSidecar;
    beforeEach(async () => {
      s = await startSidecar(kind);
    });
    afterEach(async () => {
      await s.close();
    });

    it("health answers without a token", async () => {
      const g = createRemoteGuard(opts(s, { token: undefined }));
      expect(await g.health()).toEqual({ ok: true, engine: { version: "0.3.0-test" } });
      expect(s.seen[0]?.headers.authorization).toBeUndefined();
    });

    it("decide sends the contract's request with a token and a fresh idempotency key", async () => {
      const g = createRemoteGuard(opts(s, { workspace: "/srv/app", cwd: "/srv/app" }));
      const d = await g.decide({ ...send, callId: "call_1" });
      expect(d).toMatchObject({ verdict: "allow", decisionId: "dec_1", id: "dec_1", format: "native", rules: [], engine: { version: "0.3.0-test" }, log: { seq: 1 } });
      await g.decide(send);
      const [a, b] = decides(s);
      expect(a?.headers.authorization).toBe(`Bearer ${s.token}`);
      expect(a?.headers["idempotency-key"]).toMatch(UUID);
      expect(b?.headers["idempotency-key"]).toMatch(UUID);
      expect(a?.headers["idempotency-key"]).not.toBe(b?.headers["idempotency-key"]);
      expect(a?.body).toEqual({ session: "run-1", action: { format: "native", tool: "send_email", input: send.input, callId: "call_1" }, context: { attended: true, workspace: ["/srv/app"], cwd: "/srv/app" }, dryRun: false });
      if (kind === "tcp") expect(a?.headers.host).toMatch(/^127\.0\.0\.1:\d+$/);
    });

    it("check is a dry run and records nothing", async () => {
      s.verdicts.set("send_email", "ask");
      const g = createRemoteGuard(opts(s));
      const d = await g.check(send);
      expect(d.verdict).toBe("ask");
      expect((decides(s)[0]?.body as { dryRun: boolean }).dryRun).toBe(true);
      expect(s.approvals.size).toBe(0);
    });

    it("mcp__ tools go as format mcp; undeclared tools follow the format option; dontAsk is unattended", async () => {
      s.verdicts.set("Bash", "ask");
      const g = createRemoteGuard(opts(s, { format: "engine" }));
      await g.decide({ tool: "mcp__gmail__send__now", input: { to: "x" }, mcpSource: "user" });
      const d = await g.decide({ tool: "Bash", input: { command: "ls" }, permissionMode: "dontAsk" });
      const [m, b] = decides(s).map((r) => r.body as { action: Record<string, unknown>; context: Record<string, unknown> });
      expect(m?.action).toEqual({ format: "mcp", tool: "send__now", input: { to: "x" }, mcp: { server: "gmail", source: "user" } });
      expect(b?.action.format).toBe("engine");
      expect(b?.context.attended).toBe(false);
      expect(d.verdict).toBe("hold");
    });

    it("authorize: an ask waits for the queue's approval and decides the identical call again", async () => {
      s.verdicts.set("send_email", "ask");
      const pending: string[] = [];
      const g = createRemoteGuard(opts(s, { onPending: (d) => pending.push(d.approval?.id ?? "") }));
      const p = g.authorize(send);
      await new Promise((r) => setTimeout(r, 40));
      // The ask has no queue item (api-v0.md); the guard queues it by deciding it again unattended (a hold).
      expect(pending).toEqual(["", "apr_2"]);
      s.settle("apr_2", "approved");
      const a = await p;
      expect(a.allowed).toBe(true);
      expect(a.decision.verdict).toBe("ask");
      expect(a.decision.approval).toBeUndefined();
      expect(a.retry?.verdict).toBe("allow");
      expect(a.approval?.by).toContain("apr_2");
      const sent = decides(s).map((r) => (r.body as { context: { attended: boolean } }).context.attended);
      expect(sent).toEqual([true, false, true]);
      // Single use: the same call asks again.
      expect((await g.decide(send)).verdict).toBe("ask");
    });

    it("authorize: a denied, expired or unanswered approval is a no", async () => {
      s.verdicts.set("send_email", "ask");
      const g = createRemoteGuard(opts(s, { approvalTimeoutMs: 60 }));
      const p = g.authorize(send);
      await new Promise((r) => setTimeout(r, 20));
      s.settle("apr_2", "denied");
      expect((await p).allowed).toBe(false);
      const p2 = g.authorize(send);
      await new Promise((r) => setTimeout(r, 20));
      s.settle("apr_4", "expired");
      expect(await p2).toMatchObject({ allowed: false, approval: { approved: false } });
      const t = await g.authorize(send);
      expect(t.allowed).toBe(false);
      expect(t.approval?.note).toContain("pending");
    });

    it("authorize: hold and deny are never waited on", async () => {
      s.verdicts.set("send_email", "hold");
      s.verdicts.set("delete_account", "deny");
      const g = createRemoteGuard(opts(s));
      const h = await g.authorize(send);
      expect(h).toMatchObject({ allowed: false, decision: { verdict: "hold", held: { id: "apr_1" }, approval: { id: "apr_1", status: "pending" } } });
      const d = await g.authorize({ tool: "delete_account", input: {} });
      expect(d).toMatchObject({ allowed: false, decision: { verdict: "deny", rules: ["FW-SECRET-EGRESS"] } });
      expect(s.seen.filter((r) => r.path.startsWith("/v1/approvals"))).toHaveLength(0);
    });

    it("waitForApproval polls until decided, and stops on an unknown approval", async () => {
      s.verdicts.set("send_email", "hold");
      const g = createRemoteGuard(opts(s));
      const d = await g.decide(send);
      setTimeout(() => s.settle("apr_1", "approved"), 30);
      expect(await g.waitForApproval(d)).toEqual({ id: "apr_1", status: "approved" });
      expect((await g.decide(send)).verdict).toBe("allow");
      const w = await g.waitForApproval("apr_nope");
      expect(w.status).toBe("pending");
      expect(w.error).toContain("404");
    });

    it("requestApproval and approveAsked: only this guard's unanswered asks; a no never waits", async () => {
      s.verdicts.set("send_email", "ask");
      const g = createRemoteGuard(opts(s));
      const d = await g.decide(send);
      const forged = { ...d, id: "dec_forged" };
      expect((await g.requestApproval(forged)).approved).toBe(false);
      expect(await g.approveAsked(d, false)).toEqual({ approved: false });
      expect((await g.approveAsked(d, true)).approved).toBe(false); // already answered
      const d2 = await g.decide(send);
      expect(d2.approval).toBeUndefined();
      // The yes queues the ask (apr_3, a hold of the same action), then waits for the queue.
      setTimeout(() => s.settle("apr_3", "approved"), 20);
      const yes = await g.approveAsked(d2, { approved: true, by: "alice" });
      expect(yes.approved).toBe(true);
      expect(yes.by).toContain("alice");
      // Only the yes was ever waited on.
      expect(s.seen.filter((r) => r.path.startsWith("/v1/approvals/")).every((r) => r.path === "/v1/approvals/apr_3")).toBe(true);
    });

    it("recordResult sends the decision's id, hands back the redacted copy and notes new taint", async () => {
      const g = createRemoteGuard(opts(s));
      const d = await g.decide({ ...read, callId: "c1" });
      const n = await g.recordResult({ ...read, callId: "c1" }, "key SECRETVALUE here");
      expect(n).toMatchObject({ recorded: true, redacted: "key [masked] here", becameUntrusted: false, secretsSeen: 0 });
      const post = s.seen.find((r) => r.path === "/v1/sessions/run-1/results");
      expect(post?.body).toEqual({ decisionId: d.decisionId, output: "key SECRETVALUE here" });
      expect(post?.headers["idempotency-key"]).toMatch(UUID);
      await g.decide(read);
      const n2 = await g.recordResult(read, { page: "outside text" });
      expect(n2.becameUntrusted).toBe(true);
      expect(n2.note).toContain("outside content");
    });

    it("recordResult without a sidecar decision reports the output as untrusted input", async () => {
      const g = createRemoteGuard(opts(s));
      const n = await g.recordResult(read, "text");
      expect(n.recorded).toBe(true);
      expect(n.becameUntrusted).toBe(true);
      expect(s.seen.at(-1)?.path).toBe("/v1/sessions/run-1/inputs");
    });

    it("reportInput, recordPrompt and state", async () => {
      const g = createRemoteGuard(opts(s, { session: "run/2" }));
      expect(await g.reportInput({ source: "email from x@example.com", content: "body", private: true })).toEqual({ recorded: true });
      await g.recordPrompt("send the report to ops@example.com");
      expect(s.seen.map((r) => r.path)).toEqual(["/v1/sessions/run%2F2/inputs", "/v1/sessions/run%2F2/prompts"]);
      expect(s.seen[1]?.body).toEqual({ text: "send the report to ops@example.com" });
      expect(await g.state()).toEqual({ session: "run/2", untrusted: true, untrustedBecause: ["email from x@example.com"], holdsPrivateData: true, privateBecause: ["email from x@example.com"] });
    });

    it("state rejects when the sidecar does not know the session", async () => {
      const g = createRemoteGuard(opts(s, { session: "never-seen" }));
      await expect(g.state()).rejects.toMatchObject({ name: "RemoteHttpError", kind: "api-error", status: 404 });
    });

    describe("fail closed", () => {
      const cases: { name: string; o: () => void; readVerdict: "allow" | "deny"; rule: string; guard?: RemoteGuardOptions }[] = [
        { name: "timeout", o: () => s.overrides.push({ delayMs: 200 }), readVerdict: "allow", rule: "FW-UNAVAILABLE", guard: { timeoutMs: 50 } },
        // I6: a 500 means the sidecar took the request and failed on it (a crafted request can cause that): reads too are denied.
        { name: "500", o: () => s.overrides.push({ status: 500, raw: '{"title":"boom"}' }), readVerdict: "deny", rule: "FW-UNAVAILABLE" },
        { name: "503", o: () => s.overrides.push({ status: 503 }), readVerdict: "allow", rule: "FW-UNAVAILABLE" },
        { name: "429", o: () => s.overrides.push({ status: 429, headers: { "retry-after": "0" } }), readVerdict: "allow", rule: "FW-RATE-LIMITED" },
        { name: "400", o: () => s.overrides.push({ status: 400 }), readVerdict: "deny", rule: "FW-API-ERROR" },
        { name: "401", o: () => s.overrides.push({ status: 401 }), readVerdict: "deny", rule: "FW-API-ERROR" },
        { name: "403", o: () => s.overrides.push({ status: 403 }), readVerdict: "deny", rule: "FW-API-ERROR" },
        { name: "404", o: () => s.overrides.push({ status: 404 }), readVerdict: "deny", rule: "FW-API-ERROR" },
        { name: "malformed JSON", o: () => s.overrides.push({ status: 200, raw: "{not json" }), readVerdict: "deny", rule: "FW-API-ERROR" },
        { name: "wrong shape", o: () => s.overrides.push({ status: 200, raw: '{"decisionId":"d","verdict":"maybe","rules":[],"message":"","actionHash":""}' }), readVerdict: "deny", rule: "FW-API-ERROR" },
        { name: "hold without a queue item", o: () => s.overrides.push({ status: 200, raw: '{"decisionId":"d","verdict":"hold","rules":[],"message":"","actionHash":"sha256:x"}' }), readVerdict: "deny", rule: "FW-API-ERROR" },
        { name: "oversized response", o: () => s.overrides.push({ status: 200, raw: `{"pad":"${"x".repeat(5000)}"}` }), readVerdict: "deny", rule: "FW-API-ERROR", guard: { maxResponseBytes: 1000 } },
      ];
      for (const c of cases) {
        it(`${c.name}: a trusted read is ${c.readVerdict}, anything else is denied (${c.rule}); never throws`, async () => {
          const g = createRemoteGuard(opts(s, c.guard));
          c.o();
          const r = await g.authorize(read);
          expect(r.allowed).toBe(c.readVerdict === "allow");
          expect(r.decision).toMatchObject({ verdict: c.readVerdict, decisionId: null });
          expect(r.decision.failure).toBeDefined();
          if (c.readVerdict === "deny") expect(r.decision.rules).toEqual([c.rule]);
          await new Promise((res) => setTimeout(res, c.name === "429" ? 1100 : 0));
          c.o();
          const w = await g.authorize(send);
          expect(w).toMatchObject({ allowed: false, decision: { verdict: "deny", rules: [c.rule] } });
          expect(w.decision.message).toContain(c.rule);
          // A read that is not trusted and non-private is never let through an outage.
          c.o();
          await new Promise((res) => setTimeout(res, c.name === "429" ? 1100 : 0));
          expect((await g.decide({ tool: "web_search", input: {} })).verdict).toBe("deny");
        }, 10_000);
      }

      it("failOpenReads false denies trusted reads too", async () => {
        const g = createRemoteGuard(opts(s, { failOpenReads: false }));
        s.overrides.push({ status: 502 });
        expect((await g.decide(read)).verdict).toBe("deny");
      });

      it("429 is honoured: no request until Retry-After has passed", async () => {
        const g = createRemoteGuard(opts(s));
        s.overrides.push({ status: 429, headers: { "retry-after": "30" } });
        await g.decide(send);
        const d = await g.decide(send);
        expect(d.rules).toEqual(["FW-RATE-LIMITED"]);
        expect(decides(s)).toHaveLength(1);
      });

      it("a request over 1 MiB is never sent and is denied", async () => {
        const g = createRemoteGuard(opts(s));
        const d = await g.decide({ tool: "search_docs", input: { q: "x".repeat(MAX_REQUEST_BYTES) } });
        expect(d).toMatchObject({ verdict: "deny", rules: ["FW-API-ERROR"], failure: { status: 413 } });
        expect(s.seen).toHaveLength(0);
      });

      it("an unsent untrusted input fails decisions closed until it is resent, with the same key", async () => {
        const g = createRemoteGuard(opts(s));
        s.overrides.push({ status: 503 });
        const r = await g.reportInput({ source: "web page", content: "text" });
        expect(r.recorded).toBe(false);
        s.overrides.push({ status: 503 });
        const d = await g.decide(send);
        expect(d).toMatchObject({ verdict: "deny", rules: ["FW-UNAVAILABLE"] });
        expect(decides(s)).toHaveLength(0);
        const ok = await g.decide(send);
        expect(ok.verdict).toBe("allow");
        const inputs = s.seen.filter((x) => x.path === "/v1/sessions/run-1/inputs");
        expect(inputs).toHaveLength(3);
        expect(new Set(inputs.map((x) => x.headers["idempotency-key"])).size).toBe(1);
        expect(ok.session?.untrusted).toBe(true);
      });

      it("a refused report makes the guard fail closed for good", async () => {
        const g = createRemoteGuard(opts(s));
        s.overrides.push({ status: 400 });
        expect((await g.reportInput({ source: "web page", content: "text" })).recorded).toBe(false);
        expect((await g.decide(send)).rules).toEqual(["FW-API-ERROR"]);
        expect((await g.decide(read)).verdict).toBe("deny");
      });

      it("an oversized input is cut to fit and says so", async () => {
        const g = createRemoteGuard(opts(s));
        const r = await g.reportInput({ source: "big", content: "y".repeat(MAX_REQUEST_BYTES + 10) });
        expect(r.recorded).toBe(true);
        expect(r.problems?.[0]).toContain("1 MiB");
        expect(String((s.seen[0]?.body as { content: string }).content)).toContain("cut here");
      });

      it("recordResult never throws when the sidecar is down, and queues failed results so decisions fail closed until resent", async () => {
        const g = createRemoteGuard(opts(s));
        const d = await g.decide(read);
        s.overrides.push({ status: 500 });
        const n = await g.recordResult(read, "outside text", d);
        expect(n).toMatchObject({ recorded: false, becameUntrusted: false });
        expect(n.problems?.[0]).toContain("could not be recorded");
        // While the result is still unsent, decisions (including trusted reads) fail closed.
        s.overrides.push({ status: 503 });
        expect((await g.decide(read)).verdict).toBe("deny");
        // Once the sidecar answers, the queued result is flushed with the same Idempotency-Key before the next decision.
        const ok = await g.decide(send);
        expect(ok.verdict).toBe("allow");
        expect(ok.session?.untrusted).toBe(true);
        const results = s.seen.filter((x) => x.path === "/v1/sessions/run-1/results");
        expect(results).toHaveLength(3);
        expect(new Set(results.map((x) => x.headers["idempotency-key"])).size).toBe(1);
      });

      it("a refused recordResult (4xx) makes the guard fail closed for good, and an oversized result reports scan_incomplete and pre-computed failure", async () => {
        const g = createRemoteGuard(opts(s));
        const d = await g.decide(read);
        const n = await g.recordResult(read, { pad: "x".repeat(MAX_REQUEST_BYTES), isError: true }, d);
        expect(n).toMatchObject({ recorded: true, becameUntrusted: true });
        expect(n.problems?.[0]).toContain("1 MiB");
        const post = s.seen.find((r) => r.path === "/v1/sessions/run-1/results");
        expect(post?.body).toMatchObject({ decisionId: d.decisionId, failed: true });
        expect(String((post?.body as { output: string }).output)).toContain("cut here");
        const st = await g.state();
        expect(st.untrusted).toBe(true);
        expect(st.untrustedBecause.join(" ")).toContain("scan_incomplete");
        expect(st.holdsPrivateData).toBe(true);

        const g2 = createRemoteGuard(opts(s, { session: "run-refused" }));
        const d2 = await g2.decide(read);
        s.overrides.push({ status: 404 });
        expect((await g2.recordResult(read, "out", d2)).recorded).toBe(false);
        expect((await g2.decide(read)).verdict).toBe("deny");
        expect((await g2.decide(send)).rules).toEqual(["FW-API-ERROR"]);
      });
    });
  });
}

describe("remote guard: unreachable sidecar", () => {
  it("no socket: trusted reads go ahead, everything else is denied", async () => {
    const dead = deadSocket();
    try {
      const g = createRemoteGuard({ socketPath: dead.path, tools: TOOLS, onError: () => {} });
      expect((await g.authorize(read)).allowed).toBe(true);
      const w = await g.authorize(send);
      expect(w).toMatchObject({ allowed: false, decision: { verdict: "deny", rules: ["FW-UNAVAILABLE"], failure: { kind: "unavailable" } } });
      await expect(g.health()).rejects.toMatchObject({ kind: "unavailable" });
    } finally {
      dead.done();
    }
  });

  it("connection refused on 127.0.0.1", async () => {
    const port = await closedPort();
    const g = createRemoteGuard({ baseUrl: `http://127.0.0.1:${port}`, allowTcp: true, tools: TOOLS, onError: () => {} });
    expect((await g.decide(send)).rules).toEqual(["FW-UNAVAILABLE"]);
    expect((await g.decide(read)).verdict).toBe("allow");
  });

  it("errors are reported to onError", async () => {
    const dead = deadSocket();
    const errors: string[] = [];
    try {
      await createRemoteGuard({ socketPath: dead.path, onError: (m) => errors.push(m) }).decide(send);
      expect(errors[0]).toContain("FW-UNAVAILABLE");
    } finally {
      dead.done();
    }
  });
});

describe("remote guard: options", () => {
  it("refuses a non-loopback or malformed baseUrl, and both targets at once", () => {
    expect(() => createRemoteGuard({ baseUrl: "http://10.0.0.5:8080" })).toThrow(/not loopback/);
    expect(() => createRemoteGuard({ baseUrl: "https://127.0.0.1:8080" })).toThrow(/http:/);
    expect(() => createRemoteGuard({ baseUrl: "http://127.0.0.1" })).toThrow(/port/);
    expect(() => createRemoteGuard({ baseUrl: "http://127.0.0.1:1/v1" })).toThrow(/only/);
    expect(() => createRemoteGuard({ baseUrl: "http://127.0.0.1:1", socketPath: "/x" })).toThrow(/not both/);
    expect(() => createRemoteGuard({ session: "" })).toThrow(/session/);
  });

  it("defaults the socket to the firewall home's api.sock (the test home)", async () => {
    const errors: string[] = [];
    const g = createRemoteGuard({ onError: (m) => errors.push(m) });
    expect(g.session).toMatch(/^sdk-[0-9a-f]{24}$/);
    expect((await g.decide(send)).verdict).toBe("deny");
  });

  it("refuses a token that is not printable ASCII (a line break would add headers)", () => {
    expect(() => createRemoteGuard({ socketPath: "/x", token: "a\r\nX-Evil: 1" })).toThrow(/token/);
    expect(() => createRemoteGuard({ socketPath: "/x", token: "" })).toThrow(/token/);
  });
});

describe("remote guard: defaults and a request that cannot be made", () => {
  it("bypassPermissions and auto are unattended by default, as in the policy", async () => {
    const s = await startSidecar("socket");
    try {
      s.verdicts.set("Bash", "ask");
      const g = createRemoteGuard(opts(s));
      for (const permissionMode of ["bypassPermissions", "auto"]) {
        const d = await g.decide({ tool: "Bash", input: { command: "ls" }, permissionMode });
        expect(d.verdict, permissionMode).toBe("hold");
      }
      const b = decides(s).map((r) => r.body as { context: Record<string, unknown> });
      expect(b.map((x) => x.context.attended)).toEqual([false, false]);
    } finally {
      await s.close();
    }
  });

  it("a request that throws before it is sent is an api-error (a deny), not a TypeError", async () => {
    // A path with a space makes http.request throw synchronously (ERR_UNESCAPED_CHARACTERS).
    await expect(requestJson({ host: "127.0.0.1", port: 9 }, { method: "GET", path: "/a b", timeoutMs: 100, maxResponseBytes: 1000 })).rejects.toMatchObject({ name: "RemoteHttpError", kind: "api-error" });
  });
});
