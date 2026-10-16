/**
 * The browser link's host, driven in-process by a fake browser: the hello comes first and must speak this
 * version; browser decisions land in the signed log and `log verify` covers them; taint goes both ways;
 * approvals go through the firewall's queue and come back only when a person signed them; anything that
 * does not fit the protocol ends the link.
 */

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { approvalSigner, initApprover, unlockApprover } from "../../src/runtime/approver.js";
import { layout, type Layout } from "../../src/runtime/layout.js";
import { tailLog, verifyLog } from "../../src/runtime/log.js";
import { installHost } from "../../src/runtime/native/browsers.js";
import { HostSession, runNativeHost } from "../../src/runtime/native/host.js";
import { linkBrowserSession } from "../../src/runtime/native/link.js";
import { MAX_INCOMING_BYTES, ProtocolError, type HostMessage } from "../../src/runtime/native/protocol.js";
import { appendEvents, decideQueueItem, getQueueItem, listQueue, loadState } from "../../src/runtime/store.js";
import { atomicWrite } from "../../src/runtime/fsutil.js";

const ID = "c".repeat(32);
const ORIGIN = `chrome-extension://${ID}/`;
const PASS = "correct horse battery";
const H = (c: string): string => c.repeat(64);

let root: string;
let l: Layout;
let sent: HostMessage[];

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-host-"));
  mkdirSync(join(root, "user"));
  l = layout(join(root, "user", ".launchsafe-firewall"));
  sent = [];
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

function decode(frame: Buffer): HostMessage {
  expect(frame.readUInt32LE(0)).toBe(frame.length - 4);
  return JSON.parse(frame.subarray(4).toString("utf8")) as HostMessage;
}

function session(env: NodeJS.ProcessEnv = {}): HostSession {
  return new HostSession({ layout: l, env, origin: ORIGIN, version: "0.3.0", write: (f) => sent.push(decode(f)) });
}

const hello = { type: "hello", nonce: "hello-001", version: 1, capabilities: ["gate"], extension: "0.0.1" };

function entry(seq: number, over: Record<string, unknown> = {}): Record<string, unknown> {
  return { seq, hash: H(String(seq % 10)), prevHash: H("0"), at: 1760000000000 + seq, site: "shop.test", actionClass: "payment", verdict: "approve", rules: ["gate.payment"], ...over };
}

describe("the hello", () => {
  it("must come first", () => {
    expect(() => session().handle({ type: "state.taint", nonce: "taint-001", session: "1", reason: "outside_origin" })).toThrow(/first message must be hello/);
  });

  it("must speak this protocol version", () => {
    expect(() => session().handle({ ...hello, version: 2 })).toThrow(ProtocolError);
  });

  it("is answered with the capabilities: approvals only when a person can approve", () => {
    const s = session();
    s.handle(hello);
    expect(sent[0]).toEqual({ type: "hello", re: "hello-001", version: 1, capabilities: ["log", "taint"], firewall: "0.3.0" });
    expect(() => s.handle(hello)).toThrow(/already/);
    initApprover(l, PASS);
    sent = [];
    session().handle(hello);
    expect(sent[0]).toMatchObject({ capabilities: ["log", "taint", "approval"] });
  });
});

describe("browser decisions in the signed log", () => {
  it("appends each entry, acknowledges it with the firewall's sequence number, and log verify covers them", () => {
    const s = session();
    s.handle(hello);
    s.handle({ type: "log.append", nonce: "log-00001", entry: entry(0) });
    s.handle({ type: "log.append", nonce: "log-00002", entry: entry(1, { verdict: "deny", actionClass: null, site: "", event: "agent_mode_on" }) });
    const acks = sent.filter((m) => m.type === "log.ack");
    expect(acks.map((a) => (a as { re: string }).re)).toEqual(["log-00001", "log-00002"]);
    const browser = tailLog(l, 50).filter((e) => e.event.type === "browser_decision");
    expect(browser).toHaveLength(2);
    expect(browser[0]?.event).toMatchObject({ extension: ID, site: "shop.test", action_class: "payment", verdict: "approve", rules: ["gate.payment"], browser_seq: 0, browser_hash: H("0") });
    expect(acks.map((a) => (a as { seq: number }).seq)).toEqual(browser.map((e) => e.seq));
    const v = verifyLog(l);
    expect(v.ok).toBe(true);
    expect(v.problems).toEqual([]);
  });

  it("records the link itself (connected, then disconnected)", () => {
    const s = session();
    s.handle(hello);
    s.close();
    expect(tailLog(l, 10).filter((e) => e.event.type === "browser_link").map((e) => e.event.event)).toEqual(["connected", "disconnected"]);
  });
});

describe("taint, both ways", () => {
  it("a browser taint taints every linked agent session", () => {
    linkBrowserSession(l, "agent-1");
    const s = session();
    s.handle(hello);
    s.handle({ type: "state.taint", nonce: "taint-001", session: "1760000000000", reason: "quarantine_verdict" });
    expect(sent.at(-1)).toEqual({ type: "ack", re: "taint-001" });
    expect(loadState(l, "agent-1").taintSources).toContain("the linked browser session read outside content (quarantine_verdict)");
  });

  it("a tainted linked agent session is reported to the browser once per connection, under a short name", () => {
    linkBrowserSession(l, "agent-2");
    const s = session();
    s.handle(hello);
    expect(sent.filter((m) => m.type === "state.taint")).toEqual([]);
    appendEvents(l, "agent-2", [{ type: "taint", source: "read the web page https://example.test" }]);
    s.tick();
    s.tick();
    const t = sent.filter((m) => m.type === "state.taint");
    expect(t).toHaveLength(1);
    expect(t[0]).toMatchObject({ reason: "agent_session_untrusted", session: expect.stringMatching(/^agent-[0-9a-f]{16}$/) });
    expect(JSON.stringify(t)).not.toContain("agent-2\"");
  });
});

describe("approvals through the firewall's queue", () => {
  const request = { type: "approval.request", nonce: "appr-0001", binding: "ef".repeat(32), action: { kind: "submit", actionClass: "payment", site: "shop.test", label: "Pay on shop.test" }, surface: "firewall" };

  function queued(s: HostSession): string {
    s.handle(request);
    const q = sent.find((m) => m.type === "approval.queued") as { id: string } | undefined;
    if (q === undefined) throw new Error("not queued");
    return q.id;
  }

  it("refuses when no approval passphrase is set (nobody could approve)", () => {
    const s = session();
    s.handle(hello);
    s.handle(request);
    expect(sent.at(-1)).toMatchObject({ type: "error", re: "appr-0001", code: "unavailable" });
    expect(listQueue(l).items).toEqual([]);
  });

  it("holds at most 16 waiting approvals: the 17th is refused with too_many, and nothing is queued for it", () => {
    initApprover(l, PASS);
    const s = session();
    s.handle(hello);
    for (let i = 0; i < 16; i++) s.handle({ ...request, nonce: `appr-${String(i).padStart(4, "0")}`, binding: i.toString(16).padStart(64, "0") });
    expect(listQueue(l).items).toHaveLength(16);
    s.handle({ ...request, nonce: "appr-9999", binding: "ab".repeat(32) });
    expect(sent.at(-1)).toMatchObject({ type: "error", re: "appr-9999", code: "too_many" });
    expect(listQueue(l).items).toHaveLength(16);
    // A request already waiting may be asked again; and a cancelled one frees a place.
    s.handle({ ...request, nonce: "appr-0016", binding: "0".repeat(64) });
    expect(sent.at(-1)).toMatchObject({ type: "approval.queued", re: "appr-0016" });
    s.handle({ type: "approval.cancel", nonce: "canc-0001", binding: "1".padStart(64, "0") });
    s.handle({ ...request, nonce: "appr-0017", binding: "ab".repeat(32) });
    expect(sent.at(-1)).toMatchObject({ type: "approval.queued", re: "appr-0017" });
  });

  it("an approval signed with the passphrase goes back as approve, with its signature", () => {
    initApprover(l, PASS);
    const s = session();
    s.handle(hello);
    const id = queued(s);
    const it0 = getQueueItem(l, id);
    expect(it0).toMatchObject({ tool: "browser", status: "pending", summary: "browser: Pay on shop.test on shop.test" });
    s.tick();
    expect(sent.some((m) => m.type === "approval.result")).toBe(false);
    const key = unlockApprover(l, PASS);
    decideQueueItem(l, id, "approved", approvalSigner(key));
    s.tick();
    const r = sent.find((m) => m.type === "approval.result");
    expect(r).toMatchObject({ type: "approval.result", binding: "ef".repeat(32), verdict: "approve", sig: expect.any(String) });
  });

  it("a rejection goes back as deny", () => {
    initApprover(l, PASS);
    const s = session();
    s.handle(hello);
    decideQueueItem(l, queued(s), "rejected");
    s.tick();
    expect(sent.find((m) => m.type === "approval.result")).toMatchObject({ verdict: "deny" });
  });

  it("an item marked approved without a signed approval (written by something other than a person) is a deny", () => {
    initApprover(l, PASS);
    const s = session();
    s.handle(hello);
    const id = queued(s);
    const item = getQueueItem(l, id);
    atomicWrite(join(l.queue, `${id}.json`), JSON.stringify({ ...item, status: "approved" }));
    s.tick();
    expect(sent.find((m) => m.type === "approval.result")).toMatchObject({ verdict: "deny" });
    expect(tailLog(l, 20).some((e) => e.event.type === "browser_approval" && e.event.event === "unverified")).toBe(true);
  });

  it("a cancel from the browser, or the link closing, closes the queue item", () => {
    initApprover(l, PASS);
    const s = session();
    s.handle(hello);
    const id = queued(s);
    s.handle({ type: "approval.cancel", nonce: "cancel-01", binding: "ef".repeat(32) });
    expect(getQueueItem(l, id)?.status).toBe("rejected");
    const s2 = session();
    sent = [];
    s2.handle(hello);
    const id2 = queued(s2);
    s2.close();
    expect(getQueueItem(l, id2)?.status).toBe("rejected");
  });
});

describe("runNativeHost", () => {
  function frame(v: unknown): Buffer {
    const body = Buffer.from(JSON.stringify(v), "utf8");
    const head = Buffer.alloc(4);
    head.writeUInt32LE(body.length, 0);
    return Buffer.concat([head, body]);
  }

  function run(origin: string | undefined, input: Buffer[]): Promise<{ code: number; out: HostMessage[] }> {
    const stdin = new PassThrough();
    const chunks: Buffer[] = [];
    const p = runNativeHost(stdin, { layout: l, env: {}, origin, version: "0.3.0", write: (f) => chunks.push(f), pollMs: 20 });
    for (const b of input) stdin.write(b);
    stdin.end();
    return p.then((code) => {
      // The host's frames, split by their length prefixes.
      const all = Buffer.concat(chunks);
      const out: HostMessage[] = [];
      let at = 0;
      while (at < all.length) {
        const n = all.readUInt32LE(at);
        out.push(JSON.parse(all.subarray(at + 4, at + 4 + n).toString("utf8")) as HostMessage);
        at += 4 + n;
      }
      return { code, out };
    });
  }

  it("refuses an origin no install allowed", async () => {
    const r = await run(ORIGIN, [frame(hello)]);
    expect(r.code).toBe(1);
    expect(r.out).toEqual([{ type: "error", code: "refused", message: expect.stringContaining("not allowed") }]);
  });

  it("serves an allowed origin until the browser closes the link", async () => {
    installHost(l, "chromium", [ID], { userDataDir: join(root, "profile") });
    const r = await run(ORIGIN, [frame(hello), frame({ type: "log.append", nonce: "log-00001", entry: entry(0) })]);
    expect(r.code).toBe(0);
    expect(r.out.map((m) => m.type)).toEqual(["hello", "log.ack"]);
    expect(verifyLog(l).ok).toBe(true);
  });

  it("ends the link on an oversized frame, without reading it", async () => {
    installHost(l, "chromium", [ID], { userDataDir: join(root, "profile") });
    const head = Buffer.alloc(4);
    head.writeUInt32LE(MAX_INCOMING_BYTES + 1, 0);
    const r = await run(ORIGIN, [frame(hello), head]);
    expect(r.code).toBe(1);
    expect(r.out.at(-1)).toMatchObject({ type: "error", code: "too_large" });
  });

  it("ends the link on a message that does not fit the schema", async () => {
    installHost(l, "chromium", [ID], { userDataDir: join(root, "profile") });
    const r = await run(ORIGIN, [frame(hello), frame({ type: "log.append", nonce: "log-00001", entry: entry(0, { evidence: "hidden text" }) }), frame({ type: "state.taint", nonce: "taint-001", session: "1", reason: "outside_origin" })]);
    expect(r.code).toBe(1);
    expect(r.out.map((m) => m.type)).toEqual(["hello", "error"]);
    expect(tailLog(l, 10).some((e) => e.event.type === "browser_decision" || e.event.type === "browser_taint")).toBe(false);
  });

  it("ends the link when the browser closes mid-message", async () => {
    installHost(l, "chromium", [ID], { userDataDir: join(root, "profile") });
    const r = await run(ORIGIN, [frame(hello), frame(hello).subarray(0, 6)]);
    expect(r.code).toBe(1);
  });
});
