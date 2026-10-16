/**
 * Phone approvals against the app relay's contract (the relay's API doc): refusals as problem+json
 * with error { code, message } (401 unpaired, 429 rate limit), uploads capped at 50 items and 768 KB a
 * request, per-item refusals (not_phone_approvable) that leave the rest of the batch standing, and a device
 * unpaired in the app: the old registration is reset on its 401 and pairing again takes the relay's new
 * device id, while a different id without that reset is still refused.
 */
import { describe, expect, it } from "vitest";
import { HttpRelayClient } from "../../src/runtime/relay/client.js";
import { runDaemon, syncOutbox } from "../../src/runtime/relay/daemon.js";
import { listOutbox, readRelayState } from "../../src/runtime/relay/files.js";
import { readDevice, updateDevice } from "../../src/runtime/relay/keys.js";
import { RelayHttpError, UPLOAD_MAX_BYTES, UPLOAD_MAX_ITEMS, uploadBatches, type UploadItem } from "../../src/runtime/relay/protocol.js";
import { enqueue } from "../../src/runtime/store.js";
import { machine, pairWith, queueSend, TestPhone } from "./harness.js";

function fakeFetch(status: number, body: unknown, type = "application/problem+json"): typeof fetch {
  return (async () => new Response(JSON.stringify(body), { status, headers: { "content-type": type } })) as typeof fetch;
}

describe("the app relay's contract", () => {
  it("(1) problem+json refusals: the reason comes from error.code; 401 means unpaired, 429 a rate limit", async () => {
    const m = await machine();
    const dev = () => readDevice(m.l) ?? (() => { throw new Error("no device"); })();
    const call = async (status: number, body: unknown): Promise<RelayHttpError> => {
      const c = new HttpRelayClient({ base: m.relay.url, device: dev, fetch: fakeFetch(status, body) });
      try {
        await c.summary({ waitingInTerminal: 0 });
      } catch (e) {
        return e as RelayHttpError;
      }
      throw new Error("no error");
    };
    const e401 = await call(401, { type: "about:blank", title: "Unauthorized", status: 401, reason: "firewall_device_unknown", error: { code: "firewall_device_unknown", message: "This machine is not paired." } });
    expect(e401).toBeInstanceOf(RelayHttpError);
    expect(e401).toMatchObject({ status: 401, code: "firewall_device_unknown", message: "This machine is not paired." });
    expect(e401.revoked).toBe(true);
    const e429 = await call(429, { title: "Too Many Requests", status: 429, reason: "rate_limited", error: { code: "rate_limited", message: "Slow down." } });
    expect(e429.fairUse).toBe(true);
    expect(e429.revoked).toBe(false);
    // A problem without the error member: its reason and detail are used.
    expect(await call(409, { title: "Conflict", status: 409, reason: "firewall_relay_item_expired", detail: "The item expired." })).toMatchObject({ code: "firewall_relay_item_expired", message: "The item expired." });
    // Through the stub relay over HTTP (problem+json as well).
    m.relay.down = true;
    await expect(new HttpRelayClient({ base: m.relay.url, device: dev }).summary({ waitingInTerminal: 1 })).rejects.toMatchObject({ status: 503, code: "unavailable" });
    await m.relay.close();
  });

  it("(2) uploads are chunked: at most 50 items and 768 KB a request", async () => {
    const m = await machine();
    // One item through the real hook, then 59 more like it straight into the queue (60 hook runs are slow under load).
    const { item: first } = queueSend(m, "s0", "git push origin b0");
    const { id: _id, createdAt: _c, status: _s, version: _v, ...rest } = first;
    for (let i = 1; i < 60; i++) enqueue(m.l, { ...rest, sessionId: `s${i}`, actionHash: `${first.actionHash.slice(0, -4)}${String(i).padStart(4, "0")}` });
    const r = await syncOutbox(m.daemon());
    expect(r.uploaded).toBe(60);
    expect(m.relay.uploadRequests.length).toBeGreaterThanOrEqual(2);
    expect(m.relay.uploadRequests.every((u) => u.items <= 50 && u.bytes <= 768 * 1024)).toBe(true);
    expect(m.relay.items).toHaveLength(60);
    // The splitter alone: by count and by size; an item too large for any request is set apart.
    const item = (n: number, size: number): UploadItem => ({ itemRef: `r${n}`, credentialId: "c", sealed: "x".repeat(size), expiresAt: "2026-10-10T00:00:00Z", kind: "approval" });
    expect(uploadBatches(Array.from({ length: 120 }, (_, i) => item(i, 10))).batches.map((b) => b.length)).toEqual([UPLOAD_MAX_ITEMS, UPLOAD_MAX_ITEMS, 20]);
    const big = uploadBatches(Array.from({ length: 5 }, (_, i) => item(i, 300 * 1024)));
    expect(big.batches.map((b) => b.length)).toEqual([2, 2, 1]);
    for (const b of big.batches) expect(Buffer.byteLength(JSON.stringify({ items: b }))).toBeLessThanOrEqual(UPLOAD_MAX_BYTES);
    expect(uploadBatches([item(0, UPLOAD_MAX_BYTES)]).oversize).toHaveLength(1);
    await m.relay.close();
  }, 120_000);

  it("(3) a per-item refusal (not_phone_approvable) leaves the batch standing; that copy is not retried", async () => {
    const m = await machine();
    queueSend(m, "a", "git push origin a");
    queueSend(m, "b", "git push origin b");
    queueSend(m, "c", "git push origin c");
    let refusedRef: string | null = null;
    m.relay.refuseItem = (it) => {
      if (refusedRef === null) refusedRef = it.itemRef;
      return it.itemRef === refusedRef ? "not_phone_approvable" : null;
    };
    const r = await syncOutbox(m.daemon());
    expect(r.uploaded).toBe(2);
    expect(m.relay.items.every((x) => x.kind === "approval")).toBe(true);
    const slots = listOutbox(m.l).flatMap((rec) => Object.values(rec.phones));
    expect(slots.filter((s) => s.refused === "not_phone_approvable")).toHaveLength(1);
    expect(readRelayState(m.l).lastRefusal?.code).toBe("not_phone_approvable");
    const before = m.relay.uploadRequests.length;
    await syncOutbox(m.daemon());
    expect(m.relay.uploadRequests.length).toBe(before);
    // The relay refuses any kind but approval per item, and the client reports it per item too.
    const dev = readDevice(m.l);
    const c = new HttpRelayClient({ base: m.relay.url, device: () => dev ?? (() => { throw new Error("no device"); })() });
    const res = await c.uploadItems([{ itemRef: "AAAAAAAAAAAAAAAAAAAAAA", credentialId: "c", sealed: "e30", expiresAt: new Date(Date.now() + 60000).toISOString(), kind: "proposal" as never }]);
    expect(res.refused).toEqual([expect.objectContaining({ code: "not_phone_approvable" })]);
    await m.relay.close();
  });

  it("(4) unpaired in the app: the 401 resets the registration, and pairing again takes the relay's new device id", async () => {
    const m = await machine();
    const oldId = readDevice(m.l)?.deviceId;
    expect(oldId).toBeDefined();
    queueSend(m);
    m.relay.revokeAll();
    expect(await runDaemon(m.daemon({ sleep: async () => void (await new Promise((x) => setTimeout(x, 1))) }), { signal: new AbortController().signal, waitSeconds: 0 })).toBe("revoked");
    const reset = readDevice(m.l);
    expect(reset?.deviceId).toBeUndefined();
    expect(reset?.token).toBeUndefined();
    expect(reset?.signPub).toBeDefined();
    const again = await pairWith(m, new TestPhone("Pixel 2", "ES256", false, "https://approve.launchsafe.com"));
    expect(again.status, again.stderr).toBe(0);
    const fresh = readDevice(m.l);
    expect(fresh?.deviceId).toBeDefined();
    expect(fresh?.deviceId).not.toBe(oldId);
    expect(readRelayState(m.l).revoked).toBeUndefined();
    await m.relay.close();
  });

  it("(4) without that reset, a relay answering with a different device id is refused and nothing is written", async () => {
    const m = await machine();
    updateDevice(m.l, { deviceId: "some-other-device" });
    const r = await pairWith(m, new TestPhone("Pixel 3", "ES256", false, "https://approve.launchsafe.com"));
    expect(r.status).not.toBe(0);
    expect(`${r.stdout}${r.stderr}`).toMatch(/another device id/);
    expect(readDevice(m.l)?.deviceId).toBe("some-other-device");
    await m.relay.close();
  });
});
