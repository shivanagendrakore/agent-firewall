import { describe, expect, it } from "vitest";
import type { ChainedEntry } from "../shared/messages.js";
import { createLink, LINK_KEY, RETRY_MS, type LinkDeps, type NativePort } from "./link.js";

/** A host stand-in: records what the extension posts; the test plays the host's replies. */
class FakePort implements NativePort {
  posted: Record<string, unknown>[] = [];
  disconnected = false;
  private msg: ((m: unknown) => void)[] = [];
  private disc: (() => void)[] = [];
  onMessage = { addListener: (fn: (m: unknown) => void) => void this.msg.push(fn) };
  onDisconnect = { addListener: (fn: () => void) => void this.disc.push(fn) };
  postMessage(m: unknown): void {
    this.posted.push(structuredClone(m) as Record<string, unknown>);
  }
  disconnect(): void {
    this.disconnected = true;
  }
  reply(m: unknown): void {
    for (const f of this.msg) f(m);
  }
  hostExits(): void {
    for (const f of this.disc) f();
  }
  last(type: string): Record<string, unknown> | undefined {
    return [...this.posted].reverse().find((m) => m.type === type);
  }
}

function memoryArea(): LinkDeps["area"] & { data: Record<string, unknown> } {
  const data: Record<string, unknown> = {};
  return { data, get: async (k: string) => (k in data ? { [k]: data[k] } : {}), set: async (items: Record<string, unknown>) => void Object.assign(data, items) };
}

function entry(seq: number): ChainedEntry {
  return { seq, prevHash: "0".repeat(64), hash: String(seq % 10).repeat(64), at: 1760000000000 + seq, site: "shop.test", actionClass: "payment", verdict: "approve", rules: [] };
}

const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

interface Harness {
  link: ReturnType<typeof createLink>;
  port: FakePort;
  area: ReturnType<typeof memoryArea>;
  ports: FakePort[];
  taints: string[];
  results: [string, string][];
  log: ChainedEntry[];
  clock: { t: number };
  setPermission(v: boolean): void;
  setConnectError(e: string | null): void;
  lastError: { v: string | undefined };
}

function harness(o: { permission?: boolean; entries?: ChainedEntry[]; taint?: { session: string; reason: string } | null } = {}): Harness {
  const area = memoryArea();
  const ports: FakePort[] = [];
  const taints: string[] = [];
  const results: [string, string][] = [];
  const log = o.entries ?? [];
  let permission = o.permission ?? true;
  let connectError: string | null = null;
  const clock = { t: 1_000_000 };
  const lastError = { v: undefined as string | undefined };
  const link = createLink({
    area,
    connect: () => {
      if (connectError !== null) throw new Error(connectError);
      const p = new FakePort();
      ports.push(p);
      return p;
    },
    lastError: () => lastError.v,
    hasPermission: async () => permission,
    entriesAfter: async (seq) => log.filter((e) => e.seq > seq),
    headSeq: async () => log.at(-1)?.seq ?? -1,
    currentTaint: async () => o.taint ?? null,
    onAgentTaint: async (s) => void taints.push(s),
    onApprovalResult: async (b, v) => void results.push([b, v]),
    pendingApprovals: async () => [],
    onChange: () => undefined,
    version: "0.0.1",
    now: () => clock.t,
  });
  return {
    link,
    get port() {
      const p = ports.at(-1);
      if (p === undefined) throw new Error("no port");
      return p;
    },
    area,
    ports,
    taints,
    results,
    log,
    clock,
    setPermission: (v) => void (permission = v),
    setConnectError: (e) => void (connectError = e),
    lastError,
  };
}

async function connected(h: Harness, caps: string[] = ["log", "taint", "approval"]): Promise<void> {
  expect((await h.link.setEnabled(true)).ok).toBe(true);
  const hello = h.port.last("hello");
  expect(hello).toMatchObject({ type: "hello", version: 1, extension: "0.0.1" });
  h.port.reply({ type: "hello", re: hello?.nonce, version: 1, capabilities: caps, firewall: "0.3.0" });
  await flush();
  await flush();
}

describe("turning the link on", () => {
  it("is off by default and never connects without the permission", async () => {
    const h = harness({ permission: false });
    await h.link.start();
    expect(h.ports).toHaveLength(0);
    expect(await h.link.setEnabled(true)).toEqual({ ok: false, reason: "permission" });
    expect(h.ports).toHaveLength(0);
    expect((await h.link.status()).enabled).toBe(false);
  });

  it("connects with a hello, and reconnects on the next start when it was left on", async () => {
    const h = harness();
    await connected(h);
    expect((await h.link.status())).toMatchObject({ enabled: true, state: "connected", capabilities: ["log", "taint", "approval"], firewall: "0.3.0" });
    expect(h.area.data[LINK_KEY]).toMatchObject({ enabled: true });
  });

  it("turning it off disconnects", async () => {
    const h = harness();
    await connected(h);
    await h.link.setEnabled(false);
    expect(h.port.disconnected).toBe(true);
    expect((await h.link.status())).toMatchObject({ enabled: false, state: "off" });
  });
});

describe("degrading cleanly", () => {
  it("a host that is not installed leaves a status line and nothing else", async () => {
    const h = harness();
    await h.link.setEnabled(true);
    h.lastError.v = "Specified native messaging host not found.";
    h.port.hostExits();
    const s = await h.link.status();
    expect(s.state).toBe("unavailable");
    expect(s.detail).toMatch(/not installed for this browser/);
    // Decisions go on; the next one after the retry delay tries again.
    h.link.forward(entry(0));
    expect(h.ports).toHaveLength(1);
    h.clock.t += RETRY_MS;
    h.link.forward(entry(1));
    await flush();
    expect(h.ports).toHaveLength(2);
  });

  it("connectNative throwing (no permission at the API level) is a status, not a crash", async () => {
    const h = harness();
    h.setConnectError("Access to the specified native messaging host is forbidden.");
    await h.link.setEnabled(true);
    expect((await h.link.status()).detail).toMatch(/does not allow this extension/);
  });

  it("a message the extension does not understand drops the link (fail closed)", async () => {
    const h = harness();
    await connected(h);
    h.port.reply({ type: "approval.result", nonce: "n-0000001", binding: "c".repeat(64), verdict: "approve_everything" });
    await flush();
    expect(h.port.disconnected).toBe(true);
    expect((await h.link.status()).state).toBe("error");
    expect(h.results).toEqual([]);
  });

  it("a hello with another version, or out of order, drops the link", async () => {
    const h = harness();
    await h.link.setEnabled(true);
    h.port.reply({ type: "hello", re: h.port.last("hello")?.nonce, version: 2, capabilities: [], firewall: "9.0.0" });
    await flush();
    expect((await h.link.status())).toMatchObject({ state: "error", detail: expect.stringMatching(/version 2/) });
    const h2 = harness();
    await h2.link.setEnabled(true);
    h2.port.reply({ type: "hello", re: "n-wrong-01", version: 1, capabilities: [], firewall: "0.3.0" });
    await flush();
    expect((await h2.link.status()).state).toBe("error");
  });

  it("the permission being removed turns the link off", async () => {
    const h = harness();
    await connected(h);
    await h.link.permissionRemoved();
    expect(h.port.disconnected).toBe(true);
    expect(await h.link.status()).toMatchObject({ enabled: false, state: "off" });
  });
});

describe("mirroring the log", () => {
  it("sends entries made while the link was down, then each new one, and remembers what was acknowledged", async () => {
    const h = harness({ entries: [entry(0), entry(1)] });
    await connected(h);
    const sent = h.port.posted.filter((m) => m.type === "log.append");
    expect(sent.map((m) => (m.entry as { seq: number }).seq)).toEqual([0, 1]);
    for (const [i, m] of sent.entries()) h.port.reply({ type: "log.ack", re: m.nonce, seq: 10 + i });
    await flush();
    expect(h.area.data[LINK_KEY]).toMatchObject({ ackedSeq: 1 });
    expect((await h.link.status()).mirrored).toBe(2);
    h.log.push(entry(2));
    h.link.forward(entry(2));
    expect(h.port.last("log.append")).toMatchObject({ entry: { seq: 2 } });
    // A new connection starts after the last acknowledged entry.
    h.port.hostExits();
    h.clock.t += RETRY_MS;
    await h.link.start();
    h.port.reply({ type: "hello", re: h.port.last("hello")?.nonce, version: 1, capabilities: ["log"], firewall: "0.3.0" });
    await flush();
    await flush();
    expect(h.port.posted.filter((m) => m.type === "log.append").map((m) => (m.entry as { seq: number }).seq)).toEqual([2]);
  });

  it("starts again from the first entry when the browser's log was cleared", async () => {
    const h = harness({ entries: [entry(0)] });
    h.area.data[LINK_KEY] = { enabled: false, ackedSeq: 40 };
    await connected(h);
    expect(h.port.posted.filter((m) => m.type === "log.append").map((m) => (m.entry as { seq: number }).seq)).toEqual([0]);
  });

  it("mirrors the log-deleted marker and counts acknowledgements from the new chain (RR14)", async () => {
    const h = harness({ entries: [entry(0), entry(1), entry(2)] });
    await connected(h);
    const old = h.port.posted.filter((m) => m.type === "log.append");
    h.port.reply({ type: "log.ack", re: old[2]?.nonce, seq: 2 });
    await flush();
    expect(h.area.data[LINK_KEY]).toMatchObject({ ackedSeq: 2 });
    // The log is deleted: the new chain starts with the marker at seq 0, with a salted binding kept as is.
    h.log.length = 0;
    const marker: ChainedEntry = { seq: 0, prevHash: "0".repeat(64), hash: "a".repeat(64), at: 1760000001000, site: "", actionClass: null, verdict: "log", rules: [], event: "log_cleared" };
    h.log.push(marker);
    h.link.logCleared(marker);
    await flush();
    await flush();
    const sent = h.port.last("log.append");
    expect(sent).toMatchObject({ entry: { seq: 0, event: "log_cleared" } });
    // A late ack for the old chain does not move the new count forward; the marker's ack does.
    h.port.reply({ type: "log.ack", re: old[1]?.nonce, seq: 1 });
    h.port.reply({ type: "log.ack", re: sent?.nonce, seq: 3 });
    await flush();
    expect(h.area.data[LINK_KEY]).toMatchObject({ ackedSeq: 0 });
    const salted = "b".repeat(64);
    h.link.forward({ ...entry(1), binding: salted });
    expect(h.port.last("log.append")).toMatchObject({ entry: { seq: 1, binding: salted } });
  });

  it("never sends the evidence snippet", async () => {
    const h = harness({ entries: [{ ...entry(0), evidence: "hidden page text" }] });
    await connected(h);
    expect(JSON.stringify(h.port.posted)).not.toContain("hidden page text");
  });
});

describe("taint, both ways", () => {
  it("sends the agent session's taint once per session, and on connect", async () => {
    const h = harness({ taint: { session: "1760000000000", reason: "outside_origin" } });
    await connected(h);
    expect(h.port.posted.filter((m) => m.type === "state.taint")).toEqual([{ type: "state.taint", nonce: expect.any(String), session: "1760000000000", reason: "outside_origin" }]);
    h.link.taint("1760000000000", "outside_origin");
    h.link.taint("1760000000001", "quarantine_verdict");
    expect(h.port.posted.filter((m) => m.type === "state.taint").map((m) => m.session)).toEqual(["1760000000000", "1760000000001"]);
  });

  it("hands a linked agent's taint to the worker", async () => {
    const h = harness();
    await connected(h);
    h.port.reply({ type: "state.taint", nonce: "n-0000009", session: "agent-0123456789abcdef", reason: "agent_session_untrusted" });
    await flush();
    expect(h.taints).toEqual(["agent-0123456789abcdef"]);
  });
});

describe("approvals through the firewall", () => {
  const offer = { binding: "d".repeat(64), kind: "submit", actionClass: "payment", site: "shop.test", label: "Pay on shop.test" };

  it("files a pending approval only when the firewall takes approvals", async () => {
    const h = harness();
    await connected(h, ["log", "taint"]);
    h.link.requestApproval(offer);
    expect(h.port.last("approval.request")).toBeUndefined();
    const h2 = harness();
    await connected(h2);
    h2.link.requestApproval(offer);
    expect(h2.port.last("approval.request")).toMatchObject({ binding: "d".repeat(64), action: { kind: "submit", actionClass: "payment", site: "shop.test", label: "Pay on shop.test" }, surface: "firewall" });
  });

  it("passes the firewall's answer on only for a binding it filed", async () => {
    const h = harness();
    await connected(h);
    h.port.reply({ type: "approval.result", nonce: "n-0000010", binding: "e".repeat(64), verdict: "approve" });
    await flush();
    expect(h.results).toEqual([]);
    h.link.requestApproval(offer);
    h.port.reply({ type: "approval.result", nonce: "n-0000011", binding: "d".repeat(64), verdict: "approve", sig: "c2ln" });
    await flush();
    expect(h.results).toEqual([["d".repeat(64), "approve"]]);
    // The same answer again does nothing.
    h.port.reply({ type: "approval.result", nonce: "n-0000012", binding: "d".repeat(64), verdict: "approve" });
    await flush();
    expect(h.results).toHaveLength(1);
  });

  it("cancels the firewall's queue item when the person decides here first", async () => {
    const h = harness();
    await connected(h);
    h.link.requestApproval(offer);
    h.link.cancelApproval("d".repeat(64));
    expect(h.port.last("approval.cancel")).toMatchObject({ binding: "d".repeat(64) });
    h.port.reply({ type: "approval.result", nonce: "n-0000013", binding: "d".repeat(64), verdict: "approve" });
    await flush();
    expect(h.results).toEqual([]);
  });
});
