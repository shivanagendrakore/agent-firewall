/**
 * V21: a phone policy tightened after an item reached the phone reaches that item. The daemon's withdrawal
 * pass pulls items the current policy no longer lets a phone decide (phone.approvable, phone.excludeRules,
 * a shorter phone.itemTtlMinutes), and a decision that still arrives for one is refused (the item stays
 * pending for the terminal).
 */
import { describe, expect, it } from "vitest";
import { writeFileSync } from "node:fs";
import { getQueueItem } from "../../src/runtime/store.js";
import { pollOnce, syncOutbox } from "../../src/runtime/relay/daemon.js";
import { readOutbox } from "../../src/runtime/relay/files.js";
import { machine, queueSend } from "./harness.js";

async function sent(m: Awaited<ReturnType<typeof machine>>) {
  const { item } = queueSend(m);
  await syncOutbox(m.daemon());
  const entry = m.phone.inbox(m.relay).find((e) => e.item.itemId === item.id);
  if (entry === undefined) throw new Error("the item did not reach the phone");
  return { id: item.id, entry };
}

describe("phone policy re-checked after sending (V21)", () => {
  it("withdraws an item whose rule was excluded after it was sent; the item stays pending", async () => {
    const m = await machine();
    try {
      const { id, entry } = await sent(m);
      writeFileSync(m.l.policy, JSON.stringify({ version: 2, phone: { excludeRules: ["FW-SEND"] } }));
      const r = await syncOutbox(m.daemon());
      expect(r.withdrawn).toBe(1);
      expect(m.relay.withdraws).toContainEqual({ itemRef: entry.ref, reason: "refused" });
      expect(readOutbox(m.l, id)?.withdrawn?.sent).toBe(true);
      expect(getQueueItem(m.l, id)?.status).toBe("pending");
      // A decision the relay still delivers is refused.
      m.relay.addDecision(m.phone.decide(entry, "approve"));
      expect((await pollOnce(m.daemon(), 0)).applied).toBe(0);
      expect(getQueueItem(m.l, id)?.status).toBe("pending");
    } finally {
      await m.relay.close();
    }
  });

  it("withdraws an item once approvable is emptied", async () => {
    const m = await machine();
    try {
      const { entry } = await sent(m);
      writeFileSync(m.l.policy, JSON.stringify({ version: 2, phone: { approvable: [] } }));
      expect((await syncOutbox(m.daemon())).withdrawn).toBe(1);
      expect(m.relay.withdraws).toContainEqual({ itemRef: entry.ref, reason: "refused" });
    } finally {
      await m.relay.close();
    }
  });

  it("a shorter itemTtlMinutes expires an item sent under a longer one: withdrawn, and its decision refused", async () => {
    const m = await machine();
    try {
      const { id, entry } = await sent(m);
      const later = new Date(Date.now() + 6 * 60_000);
      writeFileSync(m.l.policy, JSON.stringify({ version: 2, phone: { itemTtlMinutes: 5 } }));
      m.relay.addDecision(m.phone.decide(entry, "approve", { issuedAt: later }));
      const p = await pollOnce(m.daemon({ now: () => later }), 0);
      expect(p.applied).toBe(0);
      expect(getQueueItem(m.l, id)?.status).toBe("pending");
      expect(m.relay.withdraws).toContainEqual({ itemRef: entry.ref, reason: "expired" });
    } finally {
      await m.relay.close();
    }
  });

  it("an item still sendable under the current policy is left on the phone", async () => {
    const m = await machine();
    try {
      await sent(m);
      writeFileSync(m.l.policy, JSON.stringify({ version: 2, phone: { excludeRules: ["FW-SOMETHING-ELSE"] } }));
      expect((await syncOutbox(m.daemon())).withdrawn).toBe(0);
      expect(m.relay.withdraws).toEqual([]);
    } finally {
      await m.relay.close();
    }
  });
});
