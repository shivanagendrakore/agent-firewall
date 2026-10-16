/**
 * Item P, the relay daemon and offline behaviour (docs/phone.md "Offline behaviour" and "Failure
 * modes"): the relay down (backoff, status, terminal unaffected), the machine offline past an item's
 * TTL (uploaded with its real expiresAt), the device unpaired in the app (the daemon stops, doctor
 * says so), the fair-use refusal (logged, shown, terminal still works: P22 on the firewall side),
 * malformed relay answers, the daemon not running, and the full loop running as `relay run`.
 */
import { describe, expect, it } from "vitest";
import { HttpRelayClient, allowedBase } from "../../src/runtime/relay/client.js";
import { pollOnce, runDaemon, syncOutbox } from "../../src/runtime/relay/daemon.js";
import { readRelayState, relayStatusLine, updateRelayState } from "../../src/runtime/relay/files.js";
import { readDevice } from "../../src/runtime/relay/keys.js";
import { parseDecisions, parsePairingStatus, RelayProtocolError, parseDecisionMessage } from "../../src/runtime/relay/protocol.js";
import { phoneChecks } from "../../src/runtime/relay/doctor.js";
import { defaultConfig } from "../../src/policy.js";
import { getQueueItem } from "../../src/runtime/store.js";
import { approvalSigner, unlockApprover } from "../../src/runtime/approver.js";
import { decideQueueItem } from "../../src/runtime/store.js";
import { machine, PASS, queueSend, retry } from "./harness.js";

const MIN = 60_000;

describe("the relay daemon", () => {
  it("relay down: the daemon records it (status shows unreachable since), doctor warns, the terminal still approves", async () => {
    const m = await machine();
    const { item } = queueSend(m);
    m.relay.down = true;
    const ac = new AbortController();
    const sleeps: number[] = [];
    const run = runDaemon(m.daemon({ sleep: async (ms) => { sleeps.push(ms); if (sleeps.length >= 6) ac.abort(); await new Promise((r) => setTimeout(r, 1)); } }), { signal: ac.signal, waitSeconds: 0 });
    expect(await run).toBe("stopped");
    const st = readRelayState(m.l);
    expect(st.unreachableSince).toBeDefined();
    expect(st.lastError).toMatch(/unavailable/);
    // Backoff doubles (per loop) up to the cap.
    expect(Math.max(...sleeps)).toBeGreaterThanOrEqual(2000);
    expect(relayStatusLine(m.l, true)).toMatch(/phone relay unreachable since/);
    expect(phoneChecks(m.l, defaultConfig(), { alive: () => true }).find((c) => c.name === "phone relay")).toMatchObject({ status: "warn" });
    const priv = unlockApprover(m.l, PASS);
    decideQueueItem(m.l, item.id, "approved", approvalSigner(priv));
    expect(retry(m).d).toBe("allow");
    // Back up: the next contact clears it.
    m.relay.down = false;
    const ac2 = new AbortController();
    let n = 0;
    await runDaemon(m.daemon({ sleep: async () => { if (++n >= 2) ac2.abort(); await new Promise((r) => setTimeout(r, 1)); } }), { signal: ac2.signal, waitSeconds: 0 });
    expect(readRelayState(m.l).unreachableSince).toBeUndefined();
    expect(readRelayState(m.l).lastContactAt).toBeDefined();
    await m.relay.close();
  });

  it("machine offline past the TTL: the item is uploaded with its real expiresAt (the phone shows it expired), then withdrawn as expired", async () => {
    const m = await machine();
    const { item } = queueSend(m);
    const later = new Date(Date.parse(item.createdAt) + 45 * MIN);
    await syncOutbox(m.daemon({ now: () => later }));
    const [entry] = m.phone.inbox(m.relay);
    expect(entry?.item.expiresAt).toBe(new Date(Date.parse(item.createdAt) + 30 * MIN).toISOString());
    expect(m.relay.withdraws).toContainEqual({ itemRef: entry?.ref, reason: "expired" });
    expect(getQueueItem(m.l, item.id)?.status).toBe("pending");
    await m.relay.close();
  });

  it("device unpaired in the app: uploads refused, the daemon stops, doctor says this machine was unpaired", async () => {
    const m = await machine();
    queueSend(m);
    m.relay.revokeAll();
    const ac = new AbortController();
    const r = await runDaemon(m.daemon({ sleep: async () => void (await new Promise((x) => setTimeout(x, 1))) }), { signal: ac.signal, waitSeconds: 0 });
    expect(r).toBe("revoked");
    expect(readRelayState(m.l).revoked).toBeDefined();
    expect(phoneChecks(m.l, defaultConfig(), { alive: () => true }).find((c) => c.name === "phone relay")?.detail).toMatch(/unpaired in the LaunchSafe app/);
    // A restart stops at once.
    expect(await runDaemon(m.daemon(), { signal: new AbortController().signal })).toBe("revoked");
    await m.relay.close();
  });

  it("P22 (firewall side): items over the fair-use limit are refused; logged in state, doctor warns, the terminal still works", async () => {
    const m = await machine();
    m.relay.maxItems = 1;
    queueSend(m, "s1", "git push origin a");
    const { item } = queueSend(m, "s2", "git push origin b");
    const r = await syncOutbox(m.daemon());
    expect(r.uploaded).toBe(1);
    expect(readRelayState(m.l).fairUse?.message).toMatch(/more than 1 items/);
    expect(phoneChecks(m.l, defaultConfig(), { alive: () => true }).find((c) => c.name === "phone relay")).toMatchObject({ status: "warn" });
    // Refused items are not retried every loop.
    await syncOutbox(m.daemon());
    expect(m.relay.items).toHaveLength(1);
    const priv = unlockApprover(m.l, PASS);
    decideQueueItem(m.l, item.id, "approved", approvalSigner(priv));
    expect(retry(m, "s2", "git push origin b").d).toBe("allow");
    await m.relay.close();
  });

  it("malformed relay answers are refused by the parsers (and the daemon backs off)", () => {
    expect(() => parseDecisions({ decisions: "x" })).toThrow(RelayProtocolError);
    expect(() => parseDecisions({ decisions: [{ id: "1", itemRef: "not base64url!", credentialId: "a", m: "{}", authenticatorData: "a", clientDataJSON: "a", signature: "a" }] })).toThrow(RelayProtocolError);
    expect(() => parsePairingStatus({ status: "claimed", answer: {} })).toThrow(RelayProtocolError);
    expect(() => parsePairingStatus({ status: "odd" })).toThrow(RelayProtocolError);
    expect(() => parseDecisionMessage('{"v":1}')).toThrow(RelayProtocolError);
    expect(() => parseDecisionMessage('{ "v": 1 }')).toThrow(/canonical/);
  });

  it("the client contacts only https, or http to this machine", () => {
    expect(allowedBase("https://approve.launchsafe.com")).toBe(true);
    expect(allowedBase("http://127.0.0.1:8080")).toBe(true);
    expect(allowedBase("http://approve.launchsafe.com")).toBe(false);
    expect(allowedBase("file:///etc/passwd")).toBe(false);
    expect(() => new HttpRelayClient({ base: "http://evil.example", device: () => { throw new Error("x"); } })).toThrow(/https only/);
  });

  it("doctor: the daemon not running fails; a stale heartbeat fails; a live one is ok", async () => {
    const m = await machine();
    const name = "phone relay daemon";
    expect(phoneChecks(m.l, defaultConfig()).find((c) => c.name === name)).toMatchObject({ status: "fail", detail: expect.stringMatching(/not running/) });
    updateRelayState(m.l, (s) => ({ ...s, pid: 4242, loopAt: new Date().toISOString() }));
    expect(phoneChecks(m.l, defaultConfig(), { alive: (p) => p === 4242 }).find((c) => c.name === name)).toMatchObject({ status: "ok" });
    expect(phoneChecks(m.l, defaultConfig(), { alive: () => false }).find((c) => c.name === name)).toMatchObject({ status: "fail" });
    expect(phoneChecks(m.l, defaultConfig(), { alive: () => true, now: new Date(Date.now() + 10 * MIN) }).find((c) => c.name === name)).toMatchObject({ status: "fail" });
    await m.relay.close();
  });

  it("relay run: the real loop through main() sends the item and applies the phone's approval; relay status reports it", async () => {
    const m = await machine();
    const { item } = queueSend(m);
    const ac = new AbortController();
    const run = m.cli(["relay", "run"], { deps: { signal: ac.signal, daemon: { syncEveryMs: 5, waitSeconds: 1 } } });
    for (let i = 0; i < 400 && m.phone.inbox(m.relay).length === 0; i++) await new Promise((r) => setTimeout(r, 5));
    const [entry] = m.phone.inbox(m.relay);
    if (entry === undefined) throw new Error("not sent");
    m.relay.addDecision(m.phone.decide(entry, "approve"));
    for (let i = 0; i < 400 && getQueueItem(m.l, item.id)?.status === "pending"; i++) await new Promise((r) => setTimeout(r, 5));
    ac.abort();
    expect((await run).status).toBe(0);
    expect(getQueueItem(m.l, item.id)?.status).toBe("approved");
    expect(retry(m).d).toBe("allow");
    const st = await m.cli(["relay", "status", "--json"], { secrets: [] });
    expect(JSON.parse(st.stdout)).toMatchObject({ registered: true, revoked: null });
    const once = await m.cli(["relay", "run", "--once"], { secrets: [] });
    expect(once.stdout).toMatch(/Sent 0 item\(s\)/);
    await m.relay.close();
  });

  it("relay run without a pairing says so and exits 1; nothing is contacted", async () => {
    const m = await machine({ pair: false });
    const r = await m.cli(["relay", "run", "--once"], { secrets: [] });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/No phone is paired/);
    expect(m.relay.requests).toHaveLength(0);
    expect(readDevice(m.l)).toBeNull();
    await m.relay.close();
  });

  it("no network in the hook: queueing with a paired phone makes no relay request", async () => {
    const m = await machine();
    const before = m.relay.requests.length;
    queueSend(m);
    retry(m);
    expect(m.relay.requests.length).toBe(before);
    await pollOnce(m.daemon(), 0);
    expect(m.relay.requests.length).toBe(before + 1);
    await m.relay.close();
  });
});
