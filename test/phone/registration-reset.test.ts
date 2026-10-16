/**
 * V38: a relay 401 resets this machine's registration, but the device id it held moves to the device
 * record's history: phone approvals already verified and stored under it stay this machine's. New
 * decisions still need the current registration, and an approval signed for a device id this machine
 * never held is still "signed for another machine".
 */
import { describe, expect, it } from "vitest";
import { trustedKeys } from "../../src/hook/claude.js";
import { appendEvents, getQueueItem, loadState } from "../../src/runtime/store.js";
import { syncOutbox } from "../../src/runtime/relay/daemon.js";
import { handleDecision } from "../../src/runtime/relay/decision.js";
import { deviceIdHistoryOf, readDevice, resetRegistration } from "../../src/runtime/relay/keys.js";
import { machine, queueSend, type Machine } from "./harness.js";

async function sent(m: Machine, session = "s1") {
  const { item } = queueSend(m, session);
  await syncOutbox(m.daemon());
  const entry = m.phone.inbox(m.relay).find((e) => e.item.itemId === item.id);
  if (entry === undefined) throw new Error("the item did not reach the phone");
  return { item, entry };
}

describe("registration reset and past phone approvals (V38)", () => {
  it("the reset keeps the old device id in the history, and a new pairing's id joins it", async () => {
    const m = await machine();
    try {
      const old = readDevice(m.l)?.deviceId as string;
      resetRegistration(m.l);
      expect(readDevice(m.l)?.deviceId).toBeUndefined();
      expect(readDevice(m.l)?.token).toBeUndefined();
      expect(readDevice(m.l)?.formerDeviceIds).toEqual([old]);
      expect(deviceIdHistoryOf(m.l)).toEqual([old]);
      resetRegistration(m.l);
      expect(readDevice(m.l)?.formerDeviceIds).toEqual([old]);
    } finally {
      await m.relay.close();
    }
  });

  it("after a reset, a new decision signed for the old device id is refused (the item stays pending)", async () => {
    const m = await machine();
    try {
      const { item, entry } = await sent(m);
      resetRegistration(m.l);
      const o = handleDecision(m.l, { id: "d1", ...m.phone.decide(entry, "approve") }, { pin: m.pin(), cfg: {} });
      expect(o.applied).toBeNull();
      expect(o.refusal?.step).toBe("device");
      expect(getQueueItem(m.l, item.id)?.status).toBe("pending");
    } finally {
      await m.relay.close();
    }
  });

  it("after a reset, an approval signed for a device id this machine never held is still tampering", async () => {
    const m = await machine();
    try {
      const { item, entry } = await sent(m, "s2");
      const d = m.phone.decide(entry, "approve", { m: { deviceId: "another-device" } });
      resetRegistration(m.l);
      appendEvents(m.l, "s2", [{ type: "phone_approval", actionHash: item.actionHash, id: item.id, credentialId: d.credentialId, m: d.m, authData: d.authenticatorData, clientData: d.clientDataJSON, sig: d.signature, exp: new Date(Date.now() + 30 * 60_000).toISOString() }]);
      const st = loadState(m.l, "s2", trustedKeys(m.l, m.hookEnv().env));
      expect(st.taintSources.some((x) => /phone approval .* was signed for another machine/.test(x))).toBe(true);
      expect(st.approvals.has(item.actionHash)).toBe(false);
    } finally {
      await m.relay.close();
    }
  });
});
