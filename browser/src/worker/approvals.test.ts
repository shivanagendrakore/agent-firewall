import { describe, expect, it } from "vitest";
import { agentModeOffSnapshot, APPROVAL_TTL_MS } from "../engine/bindings.js";
import { actionFingerprint, snapshotOf, STORED_FIELD_NAME_CHARS, STORED_FIELD_NAMES, type ActionSnapshot } from "../engine/fingerprint.js";
import { activate, submit } from "../engine/test-helpers.js";
import { APPROVALS_KEY, clampMeta, createApprovalService, MAX_PENDING_PER_TAB, type ApprovalMeta } from "./approvals.js";
import type { KeyValueArea } from "./state.js";

function memoryArea(): KeyValueArea & { data: Map<string, unknown>; writes: number } {
  const data = new Map<string, unknown>();
  const area = {
    data,
    writes: 0,
    get: async (k: string) => (data.has(k) ? { [k]: structuredClone(data.get(k)) } : {}),
    set: async (items: Record<string, unknown>) => {
      area.writes++;
      for (const [k, v] of Object.entries(items)) data.set(k, structuredClone(v));
    },
  };
  return area;
}

const META: ApprovalMeta = { subject: "action", label: "Place order", target: "https://shop.test/order", pageUrl: "https://shop.test/checkout", fields: [{ name: "card", masked: "•••• 4242" }], reasons: ["agent_mode"], untrustedBecause: ["outside_origin"], overridesDeny: false };

let n = 0;
const ids = () => `id${++n}`.padEnd(32, "0");
const pay: ActionSnapshot = snapshotOf(submit([{ name: "card", type: "text", autocomplete: "cc-number", value: "4242424242424242" }]), "payment");

describe("approval service (persistent)", () => {
  it("persists a request with its metadata, and a restarted worker sees it pending", async () => {
    const area = memoryArea();
    const a = createApprovalService(area, { randomId: ids });
    const rec = await a.request(pay, "action", META);
    expect((area.data.get(APPROVALS_KEY) as { ledger: { records: unknown[] } }).ledger.records).toHaveLength(1);
    const b = createApprovalService(area, { randomId: ids });
    expect((await b.pending()).map((r) => r.id)).toEqual([rec.id]);
    expect(await b.meta(rec.id)).toEqual(META);
  });

  it("a token issued before a restart redeems once after it, and never twice", async () => {
    const area = memoryArea();
    const a = createApprovalService(area, { randomId: ids });
    const rec = await a.request(pay, "action", META);
    const token = await a.approve(rec.id);
    expect(token).not.toBeNull();
    const b = createApprovalService(area, { randomId: ids });
    expect((await b.redeem(token as string, pay)).ok).toBe(true);
    // Neither the restarted service nor a third one can redeem it again.
    expect(await b.redeem(token as string, pay)).toEqual({ ok: false, reason: "used" });
    const c = createApprovalService(area, { randomId: ids });
    expect((await c.redeem(token as string, pay)).ok).toBe(false);
  });

  it("refuses a changed action, burns the token, and the burn survives a restart", async () => {
    const area = memoryArea();
    const a = createApprovalService(area, { randomId: ids });
    const rec = await a.request(pay, "action", META);
    const token = (await a.approve(rec.id)) as string;
    const changed = snapshotOf(submit([{ name: "card", type: "text", autocomplete: "cc-number", value: "5555555555554444" }]), "payment");
    expect(await a.redeem(token, changed)).toEqual({ ok: false, reason: "changed" });
    const b = createApprovalService(area, { randomId: ids });
    expect((await b.redeem(token, pay)).ok).toBe(false);
  });

  it("refuses a different tab, frame or element", async () => {
    for (const [presented, reason] of [
      [{ ...pay, tabId: 9 }, "tab_mismatch"],
      [{ ...pay, frameId: 3 }, "frame_mismatch"],
      [{ ...pay, elementPath: "html>body>form:nth-of-type(2)" }, "element_mismatch"],
    ] as const) {
      const a = createApprovalService(memoryArea(), { randomId: ids });
      const rec = await a.request(pay, "action", META);
      const token = (await a.approve(rec.id)) as string;
      expect(await a.redeem(token, presented)).toEqual({ ok: false, reason });
    }
  });

  it("expires with time, on navigation, and on frame navigation", async () => {
    let t = 1_000;
    const a = createApprovalService(memoryArea(), { randomId: ids, now: () => t });
    const r1 = await a.request(pay, "action", META);
    t += APPROVAL_TTL_MS;
    expect(await a.approve(r1.id)).toBeNull();
    const r2 = await a.request(pay, "action", META);
    expect(await a.onTabNavigated(pay.tabId)).toBe(1);
    expect(await a.approve(r2.id)).toBeNull();
    const sub = snapshotOf(activate("Pay", { frame: { tabId: 1, frameId: 4, origin: "https://pay.test" } }), "payment");
    const r3 = await a.request(sub, "action", META);
    expect(await a.onFrameNavigated(1, 0)).toBe(0);
    expect(await a.onFrameNavigated(1, 4)).toBe(1);
    expect(await a.approve(r3.id)).toBeNull();
  });

  it("deny ends it; a denied approval cannot be approved later", async () => {
    const a = createApprovalService(memoryArea(), { randomId: ids });
    const rec = await a.request(pay, "action", META);
    expect(await a.deny(rec.id)).toBe(true);
    expect(await a.approve(rec.id)).toBeNull();
    expect(await a.deny(rec.id)).toBe(false);
  });

  it("serializes concurrent requests so none is lost", async () => {
    const area = memoryArea();
    const a = createApprovalService(area, { randomId: ids });
    await Promise.all([1, 2, 3, 4, 5].map((i) => a.request({ ...pay, elementPath: `${pay.elementPath}#${i}` }, "action", META)));
    const b = createApprovalService(area, { randomId: ids });
    expect(await b.pending()).toHaveLength(5);
  });

  it("ignores a corrupt stored queue and starts empty (never trusts it)", async () => {
    for (const bad of ["x", { ledger: { records: [{ id: 1 }] }, meta: {} }, { ledger: { records: [] } }, { ledger: { records: [{ ...{ id: "a", purpose: "action", state: "approved", fingerprint: "f", createdAt: 0, expiresAt: 9e15 }, token: "t", snapshot: "nope" }] }, meta: {} }]) {
      const area = memoryArea();
      area.data.set(APPROVALS_KEY, bad);
      const a = createApprovalService(area, { randomId: ids });
      expect(await a.pending()).toEqual([]);
      expect((await a.redeem("t", pay)).ok).toBe(false);
    }
  });

  it("drops metadata with the records it belongs to", async () => {
    let t = 0;
    const area = memoryArea();
    const a = createApprovalService(area, { randomId: ids, now: () => t });
    const rec = await a.request(pay, "action", META);
    await a.deny(rec.id);
    t += 3 * APPROVAL_TTL_MS;
    await a.pending();
    expect(await a.meta(rec.id)).toBeUndefined();
    expect(Object.keys((area.data.get(APPROVALS_KEY) as { meta: object }).meta)).toEqual([]);
  });

  it("never stores a raw field value", async () => {
    const area = memoryArea();
    const a = createApprovalService(area, { randomId: ids });
    await a.request(pay, "action", META);
    expect(JSON.stringify(area.data.get(APPROVALS_KEY))).not.toContain("4242424242424242");
  });
});

describe("approval storage is bounded", () => {
  const wide = snapshotOf(
    submit(Array.from({ length: 500 }, (_, i) => ({ name: `${"n".repeat(250)}${i}`, type: "text", value: `v${i}` }))),
    "send",
  );

  it("keeps a few capped field names per record, yet still redeems the full action", async () => {
    const area = memoryArea();
    const a = createApprovalService(area, { randomId: ids });
    const rec = await a.request(wide, "action", META);
    const stored = (area.data.get(APPROVALS_KEY) as { ledger: { records: { snapshot: { fieldNames: string[] }; fingerprint: string }[] } }).ledger.records[0];
    expect(stored?.snapshot.fieldNames).toHaveLength(STORED_FIELD_NAMES);
    expect(stored?.snapshot.fieldNames.every((n) => n.length <= STORED_FIELD_NAME_CHARS)).toBe(true);
    expect(stored?.fingerprint).toBe(actionFingerprint(wide));
    const token = (await a.approve(rec.id)) as string;
    expect((await a.redeem(token, wide)).ok).toBe(true);
  });

  it("clamps page-controlled metadata strings", () => {
    const m = clampMeta({ ...META, target: "t".repeat(9000), pageUrl: "p".repeat(9000), fields: Array.from({ length: 80 }, () => ({ name: "n".repeat(300), masked: "m".repeat(400) })) });
    expect(m.target).toHaveLength(2048);
    expect(m.pageUrl).toHaveLength(2048);
    expect(m.fields).toHaveLength(40);
    expect(m.fields[0]).toEqual({ name: "n".repeat(128), masked: "m".repeat(160) });
  });

  it("sheds the oldest records past the size cap, tells their frames, and never sheds agent-mode-off", async () => {
    const evicted: string[] = [];
    const a = createApprovalService(memoryArea(), { randomId: ids, maxStoredChars: 6000, onEvicted: (rs) => evicted.push(...rs.map((r) => r.id)) });
    const off = await a.request(agentModeOffSnapshot(), "agent_mode_off", { ...META, subject: "agent_mode_off" });
    const first = await a.request({ ...pay, elementPath: "e0" }, "action", META);
    for (let i = 1; i < 30; i++) await a.request({ ...pay, elementPath: `e${i}` }, "action", META);
    const pending = await a.pending();
    expect(pending.some((r) => r.id === off.id)).toBe(true);
    expect(pending.some((r) => r.id === first.id)).toBe(false);
    expect(evicted).toContain(first.id);
    expect(pending.length).toBeLessThan(30);
  });

  it("on a quota error sheds the older half and writes again once; a second failure is an error, not a silent drop", async () => {
    const area = memoryArea();
    const a0 = createApprovalService(area, { randomId: ids });
    for (let i = 0; i < 6; i++) await a0.request({ ...pay, elementPath: `q${i}` }, "action", META);
    const realSet = area.set;
    let calls = 0;
    area.set = async (items) => {
      if (++calls === 1) throw new Error("QUOTA_BYTES quota exceeded");
      return realSet(items);
    };
    const a = createApprovalService(area, { randomId: ids });
    const newest = await a.request({ ...pay, elementPath: "q-new" }, "action", META);
    const left = await a.pending();
    expect(calls).toBeGreaterThanOrEqual(2);
    expect(left.some((r) => r.id === newest.id)).toBe(true);
    expect(left.length).toBeLessThan(7);
    area.set = async () => {
      throw new Error("QUOTA_BYTES quota exceeded");
    };
    await expect(a.request({ ...pay, elementPath: "q-fail" }, "action", META)).rejects.toThrow();
  });

  it("flooding one tab never retires the agent-mode-off approval, and downloads count in their own bucket", async () => {
    const a = createApprovalService(memoryArea(), { randomId: ids });
    const off = await a.request(agentModeOffSnapshot(), "agent_mode_off", { ...META, subject: "agent_mode_off" });
    const dl = { ...pay, tabId: -1, frameId: -1, kind: "download" as const, elementPath: "download:https://x.test/a.exe" };
    for (let i = 0; i < MAX_PENDING_PER_TAB + 5; i++) await a.request({ ...dl, elementPath: `download:https://x.test/${i}.exe` }, "action", { ...META, subject: "download" });
    const pending = await a.pending();
    expect(pending.some((r) => r.id === off.id)).toBe(true);
    expect(pending.filter((r) => r.purpose === "action")).toHaveLength(MAX_PENDING_PER_TAB);
  });
});

