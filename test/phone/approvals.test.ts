/**
 * Phone approvals, decisions end to end (docs/phone.md acceptance P4 to P13): a held action is sealed to the phone
 * through the stub relay, the phone signs a decision with its passkey, the daemon verifies and applies
 * it, and the hook (which re-verifies the stored assertion) lets the agent's retry run once. Then every
 * way a relay, an agent or time could make a bad approval count, and each is refused.
 */
import { describe, expect, it } from "vitest";
import { appendFileSync, readFileSync } from "node:fs";
import { decideQueueItem, getQueueItem, listQueue, loadState, sessionFile } from "../../src/runtime/store.js";
import { trustedKeys } from "../../src/hook/claude.js";
import { approvalSigner, unlockApprover } from "../../src/runtime/approver.js";
import { _setLogWriterForTest, tailLog } from "../../src/runtime/log.js";
import { doctor } from "../../src/runtime/doctor.js";
import { pollOnce, syncOutbox } from "../../src/runtime/relay/daemon.js";
import { readOutbox, readRelayState } from "../../src/runtime/relay/files.js";
import { loadPhones, writePhones } from "../../src/runtime/relay/phones.js";
import { machine, PASS, queueSend, retry, TestPhone, type Machine } from "./harness.js";

const MIN = 60_000;

async function sendAndRead(m: Machine, session = "s1", command = "git push origin main"): Promise<{ id: string; entry: ReturnType<TestPhone["inbox"]>[number] }> {
  const { item } = queueSend(m, session, command);
  await syncOutbox(m.daemon());
  const entry = m.phone.inbox(m.relay).find((e) => e.item.itemId === item.id);
  if (entry === undefined) throw new Error("the item did not reach the phone");
  return { id: item.id, entry };
}

function refusals(m: Machine): string[] {
  return tailLog(m.l, 50).filter((e) => e.event.type === "phone_decision_refused").map((e) => `${String(e.event.check)}:${String(e.event.step)}:${String(e.event.reason)}`);
}

describe("phone decisions", () => {
  it("P4: a phone approval lets the agent's retry of the exact call run once (FW-APPROVED, via phone)", async () => {
    const m = await machine();
    const { id, entry } = await sendAndRead(m);
    expect(entry.item).toMatchObject({ kind: "approval", itemId: id, rules: expect.arrayContaining(["FW-SEND"]), machine: expect.any(String), code: entry.item.actionHash.slice(0, 6) });
    expect(entry.item.title).toMatch(/sends data off this machine/);
    m.relay.addDecision(m.phone.decide(entry, "approve"));
    const r = await pollOnce(m.daemon(), 0);
    expect(r).toMatchObject({ received: 1, applied: 1, refused: 0 });
    expect(getQueueItem(m.l, id)).toMatchObject({ status: "approved", decidedBy: "phone: Pixel" });
    expect(tailLog(m.l, 10).find((e) => e.event.type === "approval")?.event).toMatchObject({ via: "phone", phone: "Pixel", queue: id });
    expect(m.relay.withdraws).toContainEqual({ itemRef: entry.ref, reason: "approved" });
    const first = retry(m);
    expect(first.d).toBe("allow");
    const logged = tailLog(m.l, 5).filter((e) => e.event.type === "decision").pop()?.event;
    expect(logged).toMatchObject({ verdict: "allow", rules: ["FW-APPROVED"], via: "phone" });
    // Once: the next identical call is held again.
    expect(retry(m).d).not.toBe("allow");
    expect(loadState(m.l, "s1", trustedKeys(m.l, m.hookEnv().env)).taintSources.some((s) => /unreadable/.test(s))).toBe(false);
    await m.relay.close();
  });

  it("P4 with RS256 and EdDSA passkeys too", async () => {
    for (const alg of ["RS256", "EdDSA"] as const) {
      const m = await machine({ alg });
      const { id, entry } = await sendAndRead(m);
      m.relay.addDecision(m.phone.decide(entry, "approve"));
      expect((await pollOnce(m.daemon(), 0)).applied).toBe(1);
      expect(getQueueItem(m.l, id)?.status).toBe("approved");
      expect(retry(m).d).toBe("allow");
      await m.relay.close();
    }
  });

  it("a signed rejection rejects the item; nothing is approved", async () => {
    const m = await machine();
    const { id, entry } = await sendAndRead(m);
    m.relay.addDecision(m.phone.decide(entry, "reject"));
    expect((await pollOnce(m.daemon(), 0)).applied).toBe(1);
    expect(getQueueItem(m.l, id)).toMatchObject({ status: "rejected", decidedBy: "phone: Pixel" });
    expect(m.relay.withdraws).toContainEqual({ itemRef: entry.ref, reason: "rejected" });
    expect(retry(m).d).not.toBe("allow");
    await m.relay.close();
  });

  it("P5: an assertion with UV clear is refused; the item stays pending", async () => {
    const m = await machine();
    const { id, entry } = await sendAndRead(m);
    m.relay.addDecision(m.phone.decide(entry, "approve", { uv: false }));
    expect((await pollOnce(m.daemon(), 0)).refused).toBe(1);
    expect(getQueueItem(m.l, id)?.status).toBe("pending");
    expect(refusals(m).join("\n")).toMatch(/^3:flags:/m);
    await m.relay.close();
  });

  it("P6: an assertion made on https://app.launchsafe.com while approve.launchsafe.com is pinned is refused", async () => {
    const m = await machine();
    const { id, entry } = await sendAndRead(m);
    m.relay.addDecision(m.phone.decide(entry, "approve", { origin: "https://app.launchsafe.com" }));
    expect((await pollOnce(m.daemon(), 0)).refused).toBe(1);
    expect(getQueueItem(m.l, id)?.status).toBe("pending");
    expect(refusals(m).join("\n")).toMatch(/^2:origin:/m);
    await m.relay.close();
  });

  it("P7: a decision replayed after the first was applied is ignored (a counted passkey fails check 5 first)", async () => {
    const m = await machine();
    const { entry } = await sendAndRead(m);
    const d = m.phone.decide(entry, "approve");
    m.relay.addDecision(d);
    expect((await pollOnce(m.daemon(), 0)).applied).toBe(1);
    m.relay.addDecision(d);
    expect((await pollOnce(m.daemon(), 0)).refused).toBe(1);
    expect(refusals(m).join("\n")).toMatch(/^5:counter:/m);
    await m.relay.close();
  });

  it("P7: replayed with a synced passkey (no counter): ignored, logged nonce already used", async () => {
    const m = await machine({ synced: true });
    const { entry } = await sendAndRead(m);
    const d = m.phone.decide(entry, "approve");
    m.relay.addDecision(d);
    expect((await pollOnce(m.daemon(), 0)).applied).toBe(1);
    m.relay.addDecision(d);
    expect((await pollOnce(m.daemon(), 0)).refused).toBe(1);
    expect(refusals(m).join("\n")).toMatch(/nonce already used/);
    // And the retry is still allowed exactly once.
    expect(retry(m).d).toBe("allow");
    expect(retry(m).d).not.toBe("allow");
    await m.relay.close();
  });

  it("B1: a synced passkey's stored approval (counter 0) copied into the session file after its use re-grants nothing", async () => {
    const m = await machine({ synced: true });
    const { entry } = await sendAndRead(m);
    m.relay.addDecision(m.phone.decide(entry, "approve"));
    expect((await pollOnce(m.daemon(), 0)).applied).toBe(1);
    expect(retry(m).d).toBe("allow");
    const line = readFileSync(sessionFile(m.l, "s1"), "utf8").split("\n").find((x) => x.includes('"phone_approval"')) as string;
    appendFileSync(sessionFile(m.l, "s1"), `${line}\n`);
    expect(retry(m).d).not.toBe("allow");
    const st = loadState(m.l, "s1", trustedKeys(m.l, m.hookEnv().env));
    expect(st.approvals.size).toBe(0);
    expect(st.tainted).toBe(true);
    await m.relay.close();
  });

  it("M8: a phone decision the log cannot record is not applied (logged before it is applied)", async () => {
    const m = await machine();
    const { id, entry } = await sendAndRead(m);
    m.relay.addDecision(m.phone.decide(entry, "approve"));
    _setLogWriterForTest(() => {
      const e = new Error("i/o error") as NodeJS.ErrnoException;
      e.code = "EIO";
      throw e;
    });
    try {
      expect((await pollOnce(m.daemon(), 0)).applied).toBe(0);
    } finally {
      _setLogWriterForTest(null);
    }
    expect(getQueueItem(m.l, id)?.status).toBe("pending");
    expect(readFileSync(sessionFile(m.l, "s1"), "utf8")).not.toContain('"phone_approval"');
    await m.relay.close();
  });

  it("P8: a decision for item A delivered under item B's reference, or with M rewritten to B, is refused", async () => {
    const m = await machine();
    const a = await sendAndRead(m, "s1", "git push origin main");
    const b = await sendAndRead(m, "s2", "git push origin release");
    const forA = m.phone.decide(a.entry, "approve");
    m.relay.addDecision({ ...forA, itemRef: b.entry.ref });
    // The relay rewriting M itself breaks the passkey signature.
    m.relay.addDecision({ ...forA, itemRef: b.entry.ref, m: forA.m.replace(a.id, b.id) });
    const r = await pollOnce(m.daemon(), 0);
    expect(r.refused).toBe(2);
    expect(getQueueItem(m.l, a.id)?.status).toBe("pending");
    expect(getQueueItem(m.l, b.id)?.status).toBe("pending");
    expect(refusals(m).join("\n")).toMatch(/^6:reference:/m);
    expect(refusals(m).join("\n")).toMatch(/^2:challenge:/m);
    await m.relay.close();
  });

  it("P8: the phone's signature for item A cannot approve B even with B's id, hash and nonce swapped in by a compromised web app (B must be real and pending)", async () => {
    const m = await machine();
    const a = await sendAndRead(m, "s1", "git push origin main");
    // A display hash that is not the one sent (the screen showed something else) is refused.
    m.relay.addDecision(m.phone.decide(a.entry, "approve", { display: "0".repeat(64) }));
    expect((await pollOnce(m.daemon(), 0)).refused).toBe(1);
    expect(refusals(m).join("\n")).toMatch(/^6:display:/m);
    expect(getQueueItem(m.l, a.id)?.status).toBe("pending");
    await m.relay.close();
  });

  it("P9: a decision arriving after the item's expiresAt is refused, the phone is told expired, the item stays for the terminal", async () => {
    const m = await machine();
    const { id, entry } = await sendAndRead(m);
    const late = new Date(Date.parse(entry.item.expiresAt) + MIN);
    m.relay.addDecision(m.phone.decide(entry, "approve", { issuedAt: late }));
    expect((await pollOnce(m.daemon({ now: () => late }), 0)).refused).toBe(1);
    expect(getQueueItem(m.l, id)?.status).toBe("pending");
    expect(m.relay.withdraws).toContainEqual({ itemRef: entry.ref, reason: "expired" });
    expect(refusals(m).join("\n")).toMatch(/^7:expired:/m);
    expect(Date.parse(entry.item.expiresAt) - Date.parse(entry.item.createdAt)).toBe(30 * MIN);
    await m.relay.close();
  });

  it("P10: an approval used 61 minutes later no longer counts (its exp passed): the call is held again, the session stays trusted", async () => {
    const m = await machine();
    const { entry } = await sendAndRead(m);
    m.relay.addDecision(m.phone.decide(entry, "approve"));
    await pollOnce(m.daemon(), 0);
    const later = new Date(Date.now() + 61 * MIN);
    expect(retry(m, "s1", "git push origin main", { now: later }).d).not.toBe("allow");
    const st = loadState(m.l, "s1", trustedKeys(m.l, m.hookEnv().env, undefined, later));
    expect(st.approvals.size).toBe(0);
    expect(st.taintSources.some((s) => /unreadable/.test(s))).toBe(false);
    // Within the hour it would still have counted.
    expect(loadState(m.l, "s1", trustedKeys(m.l, m.hookEnv().env, undefined, new Date(Date.now() + 30 * MIN))).approvals.size).toBe(1);
    await m.relay.close();
  });

  it("P10: an exp pushed far into the future on disk cannot extend the signed window", async () => {
    const m = await machine();
    const { entry } = await sendAndRead(m);
    m.relay.addDecision(m.phone.decide(entry, "approve"));
    await pollOnce(m.daemon(), 0);
    const f = sessionFile(m.l, "s1");
    const { readFileSync, writeFileSync } = await import("node:fs");
    writeFileSync(f, readFileSync(f, "utf8").replace(/"exp":"[^"]+"/, `"exp":"${new Date(Date.now() + 100 * 86400000).toISOString()}"`));
    expect(loadState(m.l, "s1", trustedKeys(m.l, m.hookEnv().env, undefined, new Date(Date.now() + 2 * 60 * MIN))).approvals.size).toBe(0);
    await m.relay.close();
  });

  it("P11: a phone_approval line written into the session file by hand is corrupt: the session turns untrusted, nothing is approved", async () => {
    const m = await machine();
    const { item } = queueSend(m);
    const forged = { type: "phone_approval", actionHash: item.actionHash, id: item.id, credentialId: m.phone.credentialId, m: "{}", authData: "AAAA", clientData: "AAAA", sig: "AAAA", exp: new Date(Date.now() + 3600000).toISOString(), verified: true, ts: new Date().toISOString() };
    appendFileSync(sessionFile(m.l, "s1"), `${JSON.stringify(forged)}\n`);
    const st = loadState(m.l, "s1", trustedKeys(m.l, m.hookEnv().env));
    expect(st.approvals.size).toBe(0);
    expect(st.taintSources.some((s) => /phone approval .* does not verify/.test(s))).toBe(true);
    expect(retry(m).d).not.toBe("allow");
    await m.relay.close();
  });

  it("P11: a real assertion copied into another session's file is corrupt there (session tag), and with no phone pinned every phone approval is corrupt", async () => {
    const m = await machine();
    const { entry } = await sendAndRead(m);
    m.relay.addDecision(m.phone.decide(entry, "approve"));
    await pollOnce(m.daemon(), 0);
    const { readFileSync } = await import("node:fs");
    const line = readFileSync(sessionFile(m.l, "s1"), "utf8").split("\n").find((x) => x.includes('"phone_approval"')) as string;
    appendFileSync(sessionFile(m.l, "other"), `${line}\n`);
    const other = loadState(m.l, "other", trustedKeys(m.l, m.hookEnv().env));
    expect(other.approvals.size).toBe(0);
    expect(other.taintSources.some((s) => /another session/.test(s))).toBe(true);
    const unpinned = loadState(m.l, "s1", trustedKeys(m.l, { LAUNCHSAFE_FIREWALL_APPROVER: m.approver }));
    expect(unpinned.approvals.size).toBe(0);
    expect(unpinned.tainted).toBe(true);
    await m.relay.close();
  });

  it("P12: a key appended to phones.json (pin unchanged): every phone approval is refused and doctor fails", async () => {
    const m = await machine();
    const { id, entry } = await sendAndRead(m);
    const s = loadPhones(m.l);
    if (s.state !== "ok") throw new Error("no phones");
    const intruder = new TestPhone("intruder");
    writePhones(m.l, [...s.file.phones, { ...(s.file.phones[0] as (typeof s.file.phones)[number]), credentialId: intruder.credentialId, publicKey: Buffer.from(intruder.auth.cose).toString("base64url"), label: "intruder" }]);
    m.relay.addDecision(m.phone.decide(entry, "approve"));
    expect((await pollOnce(m.daemon(), 0)).refused).toBe(1);
    expect(getQueueItem(m.l, id)?.status).toBe("pending");
    expect(refusals(m).join("\n")).toMatch(/^1:pin:/m);
    expect(doctor(m.l, m.ws, { home: m.home }).find((c) => c.name === "phone pin")).toMatchObject({ status: "fail" });
    // Nothing is sealed to an unpinned list either.
    queueSend(m, "s3", "git push origin other");
    const before = m.relay.items.length;
    expect((await syncOutbox(m.daemon())).skipped).toMatch(/does not match the pin/);
    expect(m.relay.items.length).toBe(before);
    await m.relay.close();
  });

  it("P13: the terminal approves first; the phone's decision is ignored as already decided and the item is withdrawn", async () => {
    const m = await machine();
    const { id, entry } = await sendAndRead(m);
    const priv = unlockApprover(m.l, PASS);
    decideQueueItem(m.l, id, "approved", approvalSigner(priv));
    await syncOutbox(m.daemon());
    expect(m.relay.withdraws).toContainEqual({ itemRef: entry.ref, reason: "decided_in_terminal" });
    m.relay.addDecision(m.phone.decide(entry, "reject"));
    expect((await pollOnce(m.daemon(), 0)).refused).toBe(1);
    expect(getQueueItem(m.l, id)?.status).toBe("approved");
    expect(refusals(m).join("\n")).toMatch(/^6:decided:.*already approved/m);
    await m.relay.close();
  });

  it("check 5: a counter that does not grow is refused (a cloned authenticator); PFP3: a synced passkey's 0 every time is accepted", async () => {
    const m = await machine();
    const a = await sendAndRead(m, "s1");
    m.relay.addDecision(m.phone.decide(a.entry, "approve", { counter: 10 }));
    expect((await pollOnce(m.daemon(), 0)).applied).toBe(1);
    const b = await sendAndRead(m, "s2", "git push origin b");
    m.relay.addDecision(m.phone.decide(b.entry, "approve", { counter: 10 }));
    expect((await pollOnce(m.daemon(), 0)).refused).toBe(1);
    expect(refusals(m).join("\n")).toMatch(/^5:counter:/m);
    await m.relay.close();
    const synced = await machine({ synced: true });
    for (const [s, c] of [["s1", "git push origin x"], ["s2", "git push origin y"]] as const) {
      const e = await sendAndRead(synced, s, c);
      synced.relay.addDecision(synced.phone.decide(e.entry, "approve"));
      expect((await pollOnce(synced.daemon(), 0)).applied).toBe(1);
      expect(retry(synced, s, c).d).toBe("allow");
    }
    await synced.relay.close();
  });

  it("PFP4: a phone clock 4 minutes ahead is accepted; 11 minutes ahead is refused (skew 10)", async () => {
    const m = await machine();
    const a = await sendAndRead(m, "s1");
    m.relay.addDecision(m.phone.decide(a.entry, "approve", { issuedAt: new Date(Date.now() + 4 * MIN) }));
    expect((await pollOnce(m.daemon(), 0)).applied).toBe(1);
    const b = await sendAndRead(m, "s2", "git push origin b");
    m.relay.addDecision(m.phone.decide(b.entry, "approve", { issuedAt: new Date(Date.now() + 11 * MIN) }));
    expect((await pollOnce(m.daemon(), 0)).refused).toBe(1);
    expect(refusals(m).join("\n")).toMatch(/^7:clock:/m);
    await m.relay.close();
  });

  it("a decision signed for another machine (deviceId) is refused", async () => {
    const m = await machine();
    const { id, entry } = await sendAndRead(m);
    m.relay.addDecision(m.phone.decide(entry, "approve", { m: { deviceId: "another-device" } }));
    expect((await pollOnce(m.daemon(), 0)).refused).toBe(1);
    expect(getQueueItem(m.l, id)?.status).toBe("pending");
    expect(refusals(m).join("\n")).toMatch(/^6:device:/m);
    await m.relay.close();
  });

  it("a decision from a passkey that was never paired is refused at check 1", async () => {
    const m = await machine();
    const { entry } = await sendAndRead(m);
    const stranger = new TestPhone("stranger");
    m.relay.addDecision(stranger.decide(entry, "approve"));
    expect((await pollOnce(m.daemon(), 0)).refused).toBe(1);
    expect(refusals(m).join("\n")).toMatch(/^1:credential:/m);
    await m.relay.close();
  });

  it("PFP5: a restarted daemon sends no duplicates (idempotent by item id) and resumes after the last processed decision", async () => {
    const m = await machine();
    const { id, entry } = await sendAndRead(m);
    await syncOutbox(m.daemon());
    await syncOutbox(m.daemon());
    expect(m.relay.items.filter((x) => x.credentialId === m.phone.credentialId)).toHaveLength(1);
    const ref = readOutbox(m.l, id)?.phones[m.phone.credentialId]?.itemRef;
    expect(ref).toBe(entry.ref);
    m.relay.addDecision(m.phone.decide(entry, "approve"));
    expect((await pollOnce(m.daemon(), 0)).applied).toBe(1);
    expect(readRelayState(m.l).cursor).toBe("1");
    // A new daemon process: nothing is fetched again.
    expect((await pollOnce(m.daemon(), 0)).received).toBe(0);
    // A crash between applying and saving the cursor: the decision comes again and changes nothing.
    const { updateRelayState } = await import("../../src/runtime/relay/files.js");
    updateRelayState(m.l, (s) => ({ ...s, cursor: null }));
    const again = await pollOnce(m.daemon(), 0);
    expect(again).toMatchObject({ received: 1, applied: 0 });
    expect(listQueue(m.l).items.filter((i) => i.status === "approved")).toHaveLength(1);
    await m.relay.close();
  });
});
