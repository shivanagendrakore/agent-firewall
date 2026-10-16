/**
 * checkPhoneApproval (src/runtime/relay/trust.ts), the hook's check of a stored phone_approval, on the cases
 * the other phone suites do not reach directly: a signed rejection stored as an approval, an older signature
 * counter replayed after a newer one in the same session, and an event whose time cannot be read. Each is
 * corrupt (the session turns untrusted), never an approval. A paired machine in a temporary home, a stub
 * relay on 127.0.0.1 and a software authenticator; no network beyond it.
 */
import { describe, expect, it } from "vitest";
import { checkPhoneApproval, type PhoneTrust } from "../../src/runtime/relay/trust.js";
import { syncOutbox } from "../../src/runtime/relay/daemon.js";
import type { StateEvent } from "../../src/types.js";
import { machine, queueSend, type Machine } from "./harness.js";

type PhoneApproval = Extract<StateEvent, { type: "phone_approval" }>;

async function sent(m: Machine, session: string, command = "git push origin main") {
  const { item } = queueSend(m, session, command);
  await syncOutbox(m.daemon());
  const entry = m.phone.inbox(m.relay).find((e) => e.item.itemId === item.id);
  if (entry === undefined) throw new Error("the item did not reach the phone");
  return { item, entry };
}

function stored(item: { actionHash: string; id: string }, d: { credentialId: string; m: string; authenticatorData: string; clientDataJSON: string; signature: string }, exp = new Date(Date.now() + 30 * 60_000).toISOString()): PhoneApproval {
  return { type: "phone_approval", actionHash: item.actionHash, id: item.id, credentialId: d.credentialId, m: d.m, authData: d.authenticatorData, clientData: d.clientDataJSON, sig: d.signature, exp };
}

const trust = (m: Machine, now = new Date()): PhoneTrust => ({ pin: m.pin(), enabled: true, useWithinMinutes: 30, clockSkewMinutes: 2, now });

describe("checkPhoneApproval", () => {
  it("control: a fresh approval for this item and session is ok", async () => {
    const m = await machine();
    try {
      const { item, entry } = await sent(m, "pc0");
      const r = checkPhoneApproval(m.l, "pc0", stored(item, m.phone.decide(entry, "approve")), trust(m), new Map());
      expect(r).toEqual({ result: "ok" });
    } finally {
      await m.relay.close();
    }
  });

  it("a signed rejection stored as an approval is corrupt", async () => {
    const m = await machine();
    try {
      const { item, entry } = await sent(m, "pc1");
      const r = checkPhoneApproval(m.l, "pc1", stored(item, m.phone.decide(entry, "reject")), trust(m), new Map());
      expect(r.result).toBe("corrupt");
      expect(r.result === "corrupt" ? r.detail : "").toMatch(/is a signed rejection, not an approval/);
    } finally {
      await m.relay.close();
    }
  });

  it("an older signature counter after a newer one in the same session is corrupt", async () => {
    const m = await machine();
    try {
      const a = await sent(m, "pc2", "git push origin main");
      const b = await sent(m, "pc2", "git push origin release-notes");
      const counters = new Map<string, number>();
      const newer = stored(a.item, m.phone.decide(a.entry, "approve", { counter: 50 }));
      expect(checkPhoneApproval(m.l, "pc2", newer, trust(m), counters)).toEqual({ result: "ok" });
      expect(counters.get(m.phone.credentialId)).toBe(50);
      const older = stored(b.item, m.phone.decide(b.entry, "approve", { counter: 20 }));
      const r = checkPhoneApproval(m.l, "pc2", older, trust(m), counters);
      expect(r.result).toBe("corrupt");
      expect(r.result === "corrupt" ? r.detail : "").toMatch(/repeats an older signature counter/);
      // The same counter again is a replay too.
      const same = stored(b.item, m.phone.decide(b.entry, "approve", { counter: 50 }));
      expect(checkPhoneApproval(m.l, "pc2", same, trust(m), counters).result).toBe("corrupt");
      // The map keeps the highest counter seen.
      expect(counters.get(m.phone.credentialId)).toBe(50);
    } finally {
      await m.relay.close();
    }
  });

  it("an unreadable time is corrupt, never treated as unexpired", async () => {
    const m = await machine();
    try {
      const { item, entry } = await sent(m, "pc3");
      const d = m.phone.decide(entry, "approve");
      for (const exp of ["not a time", "", "2026-13-45T99:99:99Z"]) {
        const r = checkPhoneApproval(m.l, "pc3", stored(item, d, exp), trust(m), new Map());
        expect(r.result, exp).toBe("corrupt");
        expect(r.result === "corrupt" ? r.detail : "", exp).toMatch(/has an unreadable time/);
      }
    } finally {
      await m.relay.close();
    }
  });

  it("an approval signed long ago lapses by its signed time, whatever the stored exp says", async () => {
    const m = await machine();
    try {
      const { item, entry } = await sent(m, "pc4");
      const d = m.phone.decide(entry, "approve");
      const later = new Date(Date.now() + 2 * 3600_000);
      const r = checkPhoneApproval(m.l, "pc4", stored(item, d, new Date(Date.now() + 24 * 3600_000).toISOString()), trust(m, later), new Map());
      expect(r).toEqual({ result: "expired" });
    } finally {
      await m.relay.close();
    }
  });
});
