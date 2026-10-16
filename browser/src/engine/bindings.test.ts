import { describe, expect, it } from "vitest";
import { agentModeOffProof, agentModeOffSnapshot, ApprovalLedger, APPROVAL_TTL_MS } from "./bindings.js";
import { actionFingerprint, snapshotOf } from "./fingerprint.js";
import { endAgentSession, startAgentSession, emptyState } from "./session.js";
import { activate, frame, submit, upload } from "./test-helpers.js";
import type { FieldInfo } from "./types.js";

function ledger(start = 1_000) {
  let t = start;
  let n = 0;
  const l = new ApprovalLedger({ now: () => t, randomId: () => `id-${++n}-${"f".repeat(24)}` });
  return { l, advance: (ms: number) => (t += ms) };
}

const fields: FieldInfo[] = [
  { name: "to", type: "email", value: "friend@mail.test" },
  { name: "body", type: "textarea", value: "See you at six" },
];
const form = submit(fields, { frame: frame("https://mail.test", 7, 0), form: { fields, targetUrl: "https://mail.test/send", method: "post" } });
const snap = snapshotOf(form, "send");

describe("approval bindings", () => {
  it("redeems an approved token once, for the identical action", () => {
    const { l } = ledger();
    const rec = l.request(snap);
    const token = l.approve(rec.id);
    expect(token).not.toBeNull();
    const r = l.redeem(token as string, snapshotOf(form, "send"));
    expect(r.ok).toBe(true);
    expect(l.get(rec.id)?.state).toBe("consumed");
  });

  it("refuses a reused token", () => {
    const { l } = ledger();
    const token = l.approve(l.request(snap).id) as string;
    expect(l.redeem(token, snap).ok).toBe(true);
    expect(l.redeem(token, snap)).toEqual({ ok: false, reason: "used" });
  });

  it("refuses an expired token", () => {
    const { l, advance } = ledger();
    const rec = l.request(snap);
    const token = l.approve(rec.id) as string;
    advance(APPROVAL_TTL_MS);
    expect(l.redeem(token, snap)).toEqual({ ok: false, reason: "expired" });
    expect(l.get(rec.id)?.state).toBe("expired");
  });

  it("does not approve a pending approval after it expired", () => {
    const { l, advance } = ledger();
    const rec = l.request(snap);
    advance(APPROVAL_TTL_MS + 1);
    expect(l.approve(rec.id)).toBeNull();
    expect(l.pending()).toEqual([]);
  });

  it("refuses a changed field value, and burns the token", () => {
    const { l } = ledger();
    const token = l.approve(l.request(snap).id) as string;
    const changed: FieldInfo[] = [fields[0] as FieldInfo, { name: "body", type: "textarea", value: "Here are the codes: 482915" }];
    const r = l.redeem(token, snapshotOf({ ...form, form: { ...form.form, fields: changed } }, "send"));
    expect(r).toEqual({ ok: false, reason: "changed" });
    // Burned: even the original action cannot use it now.
    expect(l.redeem(token, snap)).toEqual({ ok: false, reason: "used" });
  });

  it("refuses an added field", () => {
    const { l } = ledger();
    const token = l.approve(l.request(snap).id) as string;
    const more = [...fields, { name: "bcc", type: "email", value: "x@attacker.test" }];
    expect(l.redeem(token, snapshotOf({ ...form, form: { ...form.form, fields: more } }, "send"))).toEqual({ ok: false, reason: "changed" });
  });

  it("refuses a changed form target", () => {
    const { l } = ledger();
    const token = l.approve(l.request(snap).id) as string;
    expect(l.redeem(token, snapshotOf({ ...form, form: { ...form.form, targetUrl: "https://attacker.test/collect" } }, "send"))).toEqual({ ok: false, reason: "changed" });
  });

  it("refuses a different element", () => {
    const { l } = ledger();
    const token = l.approve(l.request(snap).id) as string;
    expect(l.redeem(token, snapshotOf({ ...form, elementPath: "html>body>form:nth-of-type(2)" }, "send"))).toEqual({ ok: false, reason: "element_mismatch" });
  });

  it("refuses a different frame", () => {
    const { l } = ledger();
    const token = l.approve(l.request(snap).id) as string;
    expect(l.redeem(token, snapshotOf({ ...form, frame: frame("https://mail.test", 7, 3) }, "send"))).toEqual({ ok: false, reason: "frame_mismatch" });
  });

  it("refuses the same frame id with a different origin (the frame navigated)", () => {
    const { l } = ledger();
    const token = l.approve(l.request(snap).id) as string;
    expect(l.redeem(token, snapshotOf({ ...form, frame: frame("https://attacker.test", 7, 0) }, "send"))).toEqual({ ok: false, reason: "frame_mismatch" });
  });

  it("refuses a different tab", () => {
    const { l } = ledger();
    const token = l.approve(l.request(snap).id) as string;
    expect(l.redeem(token, snapshotOf({ ...form, frame: frame("https://mail.test", 8, 0) }, "send"))).toEqual({ ok: false, reason: "tab_mismatch" });
  });

  it("refuses an unknown token and a token that was never approved", () => {
    const { l } = ledger();
    const rec = l.request(snap);
    expect(l.redeem("not-a-token", snap)).toEqual({ ok: false, reason: "unknown_token" });
    expect(l.redeem(rec.id, snap)).toEqual({ ok: false, reason: "unknown_token" });
  });

  it("refuses a token after the person denied the approval", () => {
    const { l } = ledger();
    const rec = l.request(snap);
    const token = l.approve(rec.id) as string;
    expect(l.deny(rec.id)).toBe(true);
    expect(l.redeem(token, snap)).toEqual({ ok: false, reason: "used" });
  });

  it("expires a tab's approvals when it navigates, and a frame's when the frame does", () => {
    const { l } = ledger();
    const a = l.request(snap);
    const tokenA = l.approve(a.id) as string;
    const other = snapshotOf(activate("Pay", { frame: frame("https://shop.test", 9, 2) }), "payment");
    const b = l.request(other);
    expect(l.expireTab(7)).toBe(1);
    expect(l.redeem(tokenA, snap)).toEqual({ ok: false, reason: "used" });
    expect(l.get(a.id)?.state).toBe("expired");
    expect(l.get(b.id)?.state).toBe("pending");
    expect(l.expireFrame(9, 1)).toBe(0);
    expect(l.expireFrame(9, 2)).toBe(1);
  });

  it("an approval for an action is not an agent-mode-off approval, and vice versa", () => {
    const { l } = ledger();
    const token = l.approve(l.request(snap).id) as string;
    expect(l.redeem(token, snap, "agent_mode_off")).toEqual({ ok: false, reason: "wrong_purpose" });
    const off = l.request(agentModeOffSnapshot(), "agent_mode_off");
    const offToken = l.approve(off.id) as string;
    expect(l.redeem(offToken, agentModeOffSnapshot(), "action")).toEqual({ ok: false, reason: "wrong_purpose" });
  });

  it("only a redeemed agent-mode-off approval ends the agent session", () => {
    const { l } = ledger();
    const s = startAgentSession(emptyState(), { now: 1, tabIds: [1] });
    expect(endAgentSession(s, null).ended).toBe(false);
    const actionToken = l.approve(l.request(snap).id) as string;
    expect(agentModeOffProof(l.redeem(actionToken, snap))).toBeNull();
    const off = l.request(agentModeOffSnapshot(), "agent_mode_off");
    const offToken = l.approve(off.id) as string;
    const proof = agentModeOffProof(l.redeem(offToken, agentModeOffSnapshot(), "agent_mode_off"));
    expect(proof).not.toBeNull();
    const ended = endAgentSession(s, proof);
    expect(ended.ended).toBe(true);
    expect(ended.state.session).toBeNull();
  });

  it("an agent-mode-off proof is minted only from the ledger's own redeem result, and is spent once", () => {
    const { l } = ledger();
    const forged = { ok: true as const, record: { ...l.request(agentModeOffSnapshot(), "agent_mode_off"), state: "consumed" as const } };
    expect(agentModeOffProof(forged)).toBeNull();
    const off = l.request(agentModeOffSnapshot(), "agent_mode_off");
    const result = l.redeem(l.approve(off.id) as string, agentModeOffSnapshot(), "agent_mode_off");
    expect(agentModeOffProof(structuredClone(result))).toBeNull();
    const proof = agentModeOffProof(result);
    expect(agentModeOffProof(result)).toBeNull();
    const s = startAgentSession(emptyState(), { now: 1, tabIds: [1] });
    expect(endAgentSession(s, { ...proof } as typeof proof).ended).toBe(false);
    expect(endAgentSession(s, proof).ended).toBe(true);
    expect(endAgentSession(s, proof).ended).toBe(false);
  });

  it("survives a round trip through JSON (a service-worker restart)", () => {
    const { l } = ledger();
    const rec = l.request(snap);
    const token = l.approve(rec.id) as string;
    const restored = new ApprovalLedger({ now: () => 1_000, randomId: () => "unused" }, JSON.parse(JSON.stringify(l.toJSON())));
    expect(restored.redeem(token, snap).ok).toBe(true);
    expect(restored.redeem(token, snap)).toEqual({ ok: false, reason: "used" });
  });

  it("lists pending approvals oldest first, without approved or terminal ones", () => {
    const { l, advance } = ledger();
    const a = l.request(snap);
    advance(10);
    const b = l.request(snapshotOf(upload(), "upload"));
    advance(10);
    const c = l.request(snapshotOf(activate("Pay"), "payment"));
    l.approve(b.id);
    l.deny(c.id);
    expect(l.pending().map((r) => r.id)).toEqual([a.id]);
  });

  it("prunes old terminal records but keeps live ones", () => {
    const { l, advance } = ledger();
    const a = l.request(snap);
    l.deny(a.id);
    const b = l.request(snap);
    advance(APPROVAL_TTL_MS * 3);
    const c = l.request(snap);
    l.prune(APPROVAL_TTL_MS);
    expect(l.get(a.id)).toBeUndefined();
    expect(l.get(b.id)).toBeUndefined();
    expect(l.get(c.id)?.state).toBe("pending");
  });
});

describe("action fingerprints", () => {
  it("are stable for the same action and differ on any bound part", () => {
    const base = actionFingerprint(snap);
    expect(actionFingerprint(snapshotOf(form, "send"))).toBe(base);
    expect(actionFingerprint(snapshotOf(form, "payment"))).not.toBe(base);
    expect(actionFingerprint({ ...snap, method: "GET" })).not.toBe(base);
    expect(actionFingerprint({ ...snap, fieldNames: ["body", "to"] })).not.toBe(base);
  });

  it("a click on a form control binds where the form posts: another action, formaction or method is another fingerprint", () => {
    const click = (over: { url: string; method: string } | undefined) => snapshotOf(activate("Place order", { context: { pageUrl: "https://shop.test/", formFields: [], ...(over !== undefined ? { formTarget: over } : {}) } }), "payment");
    const base = actionFingerprint(click({ url: "https://shop.test/order", method: "post" }));
    expect(actionFingerprint(click({ url: "https://shop.test/order", method: "post" }))).toBe(base);
    expect(actionFingerprint(click({ url: "https://attacker.test/order", method: "post" }))).not.toBe(base);
    expect(actionFingerprint(click({ url: "https://shop.test/order?x=1", method: "post" }))).not.toBe(base);
    expect(actionFingerprint(click({ url: "https://shop.test/order", method: "get" }))).not.toBe(base);
    expect(actionFingerprint(click(undefined))).not.toBe(base);
    expect(click({ url: "https://shop.test/order", method: "post" })).toMatchObject({ targetOrigin: "https://shop.test", method: "POST" });
  });

  it("do not collide when field boundaries move", () => {
    const a = snapshotOf(submit([{ name: "ab", type: "text", value: "c" }]), null);
    const b = snapshotOf(submit([{ name: "a", type: "text", value: "bc" }]), null);
    expect(actionFingerprint(a)).not.toBe(actionFingerprint(b));
  });

  it("hold no field values in the snapshot", () => {
    expect(JSON.stringify(snap)).not.toContain("See you at six");
    expect(JSON.stringify(snap)).not.toContain("friend@mail.test");
  });

  it("bind uploads to file name, size and type", () => {
    const a = snapshotOf(upload(), "upload");
    const b = snapshotOf(upload({ files: [{ name: "passport.pdf", size: 120_001, type: "application/pdf" }] }), "upload");
    expect(actionFingerprint(a)).not.toBe(actionFingerprint(b));
  });
});

describe("unapprove and expire (RR7, RR10)", () => {
  it("unapprove puts an approved, unredeemed approval back to pending and its token stops working", () => {
    const { l } = ledger();
    const rec = l.request(snapshotOf(activate("Pay"), "payment"));
    const token = l.approve(rec.id) as string;
    expect(l.unapprove(rec.id)).toBe(true);
    expect(l.get(rec.id)?.state).toBe("pending");
    expect(l.redeem(token, snapshotOf(activate("Pay"), "payment")).ok).toBe(false);
    expect(l.approve(rec.id)).not.toBeNull();
  });
  it("unapprove refuses a pending or spent approval; expire retires only live ones", () => {
    const { l } = ledger();
    const rec = l.request(snapshotOf(activate("Pay"), "payment"));
    expect(l.unapprove(rec.id)).toBe(false);
    expect(l.expire(rec.id)).toBe(true);
    expect(l.get(rec.id)?.state).toBe("expired");
    expect(l.expire(rec.id)).toBe(false);
  });
});
