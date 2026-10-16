/**
 * The worker side of the leak guard, agent detection and the log/settings view,
 * with in-memory stores (no chrome.*).
 */
import { describe, expect, it } from "vitest";
import { printsFor } from "../engine/private-data.js";
import { pageShown, privateDataShown, startAgentSession } from "../engine/session.js";
import { realLookingCard } from "../engine/test-helpers.js";
import { DEFAULT_POLICY } from "../engine/types.js";
import type { LeakAgentLogWorkerMessage, LeakReply, LogVerifyReply, SettingsReply } from "../shared/messages.js";
import { createApprovalService } from "./approvals.js";
import { createLeakAgent } from "./leak-agent.js";
import { createLog, createMemoryBackend } from "./log.js";
import { createSettingsStore, policyWith } from "./settings.js";
import { createStateStore, type KeyValueArea } from "./state.js";

function memoryArea(): KeyValueArea {
  const data = new Map<string, unknown>();
  return {
    get: async (k) => (data.has(k) ? { [k]: structuredClone(data.get(k)) } : {}),
    set: async (items) => {
      for (const [k, v] of Object.entries(items)) data.set(k, structuredClone(v));
    },
  };
}

function setup() {
  const store = createStateStore(memoryArea());
  const approvals = createApprovalService(memoryArea());
  const log = createLog({ backend: createMemoryBackend() });
  const settings = createSettingsStore(memoryArea());
  const sent: { tabId: number; msg: LeakAgentLogWorkerMessage }[] = [];
  const broadcasts: boolean[] = [];
  const la = createLeakAgent({
    store,
    approvals,
    log,
    settings,
    policy: async () => policyWith(await settings.load(), DEFAULT_POLICY),
    broadcastAgentMode: async (on) => void broadcasts.push(on),
    tabIds: async () => [1, 2],
    sendToTab: (tabId, msg) => void sent.push({ tabId, msg }),
  });
  return { store, approvals, log, settings, sent, broadcasts, la };
}

const MAIL = 1;
const ATTACKER = 2;
const attackerFrame = { tabId: ATTACKER, frameId: 0, origin: "http://attacker.test:8080" };
const guard = (text: string) => ({ type: "leak.guard" as const, via: "type" as const, text, destinationHost: "attacker.test", elementPath: "input#code", fieldName: "code" });

async function otpSession() {
  const s = setup();
  await s.store.update((st) => startAgentSession(st, { now: 1, tabIds: [MAIL, ATTACKER], printSalt: "test-session-salt" }));
  await s.store.update((st) => privateDataShown(pageShown(st, MAIL, { url: "http://mail.test/" }, DEFAULT_POLICY), MAIL, printsFor("Your verification code is 482915", "mail.test", "test-session-salt")));
  return s;
}

describe("leak.guard", () => {
  it("the Brave flow: an OTP shown on mail.test, typed for attacker.test in agent mode, needs approval, is logged, and the approval is bound", async () => {
    const s = await otpSession();
    const r = (await s.la.content(guard("482915"), attackerFrame)) as LeakReply;
    expect(r.decision.verdict).toBe("approve");
    expect(r.decision.rule).toBe("leak.seen_elsewhere");
    expect(typeof r.approvalId).toBe("string");
    const rec = await s.approvals.get(r.approvalId as string);
    expect(rec?.snapshot).toMatchObject({ tabId: ATTACKER, frameId: 0, frameOrigin: "http://attacker.test:8080", kind: "type", elementPath: "input#code", targetOrigin: "attacker.test" });
    const [entry] = await s.log.list();
    expect(entry).toMatchObject({ site: "attacker.test", verdict: "approve", rules: ["leak.seen_elsewhere"], event: "leak", detail: ["type", "seen_elsewhere"] });
    expect(entry?.binding).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(await s.log.list())).not.toContain("482915");
  });

  it("the same value redeemed with a different text is refused", async () => {
    const s = await otpSession();
    const r = (await s.la.content(guard("482915"), attackerFrame)) as LeakReply;
    const token = (await s.approvals.approve(r.approvalId as string)) as string;
    const rec = await s.approvals.get(r.approvalId as string);
    if (rec === undefined) throw new Error("no approval");
    const changed = { ...rec.snapshot, valuesDigest: "0".repeat(64) };
    expect(await s.approvals.redeem(token, changed)).toEqual({ ok: false, reason: "changed" });
  });

  it("allows ordinary text without logging it", async () => {
    const s = await otpSession();
    const r = (await s.la.content(guard("hello"), attackerFrame)) as LeakReply;
    expect(r.decision.verdict).toBe("allow");
    expect(r.approvalId).toBeUndefined();
    expect(await s.log.list()).toEqual([]);
  });

  it("with agent mode off a card warns, is logged, and creates no approval", async () => {
    const s = setup();
    const r = (await s.la.content(guard(realLookingCard()), attackerFrame)) as LeakReply;
    expect(r.decision.verdict).toBe("warn");
    expect(r.approvalId).toBeUndefined();
    expect((await s.log.list())[0]?.rules).toEqual(["leak.card_or_id"]);
  });
});

describe("leak.guard frame host (sender-derived, BR19a and BR19b together)", () => {
  const GH_TOKEN = `ghp_${"R8mK2vQ9xL4nT7pW3sZ6yB1cD5fH0jG8kN2aQ".slice(0, 36)}`;
  const evilFrame = { tabId: ATTACKER, frameId: 0, origin: "https://evil.test", host: "evil.test" };
  const agentOn = async () => {
    const s = setup();
    await s.store.update((st) => startAgentSession(st, { now: 1, tabIds: [MAIL, ATTACKER] }));
    return s;
  };

  it("a submit from an evil.test frame whose form action names the token's issuer still needs approval, bound to the form action", async () => {
    const s = await agentOn();
    const msg = { type: "leak.guard" as const, via: "submit" as const, text: GH_TOKEN, destinationHost: "api.github.com", elementPath: "form#f", fieldName: "" };
    const r = (await s.la.content(msg, evilFrame)) as LeakReply;
    expect(r.decision.verdict).toBe("approve");
    const rec = await s.approvals.get(r.approvalId as string);
    expect(rec?.snapshot).toMatchObject({ kind: "submit", frameOrigin: "https://evil.test", targetOrigin: "api.github.com" });
  });

  it("typed into an evil.test frame, a body naming the issuer cannot clear the token, and the binding names the sender's host", async () => {
    const s = await agentOn();
    const msg = { type: "leak.guard" as const, via: "type" as const, text: GH_TOKEN, destinationHost: "api.github.com", elementPath: "input#t", fieldName: "t" };
    const r = (await s.la.content(msg, evilFrame)) as LeakReply;
    expect(r.decision.verdict).toBe("approve");
    const rec = await s.approvals.get(r.approvalId as string);
    expect(rec?.snapshot).toMatchObject({ kind: "type", targetOrigin: "evil.test" });
  });
});

describe("leak.context", () => {
  it("gives a frame agent mode, trust and the session's print hashes", async () => {
    const s = await otpSession();
    const c = (await s.la.content({ type: "leak.context" }, attackerFrame)) as { agentMode: boolean; prints: unknown[] };
    expect(c.agentMode).toBe(true);
    expect(c.prints.length).toBe(1);
  });
  it("pushes every tab its context", async () => {
    const s = await otpSession();
    await s.la.pushContexts();
    expect(s.sent.map((x) => x.tabId)).toEqual([1, 2]);
    expect(s.sent.every((x) => x.msg.type === "leak.context" && x.msg.context.agentMode)).toBe(true);
  });
});

describe("agent detection (navigator.webdriver)", () => {
  it("turns agent mode on for the tab, logs it and tells every tab", async () => {
    const s = setup();
    expect(await s.la.content({ type: "agent.signal", signal: "webdriver" }, attackerFrame)).toEqual({ agentMode: true });
    const st = await s.store.load();
    expect(st.session?.declaredClass).toBe("remote_cdp");
    expect(st.tabs.find((t) => t.tabId === ATTACKER)?.inSession).toBe(true);
    expect(s.broadcasts).toEqual([true]);
    expect((await s.log.list())[0]).toMatchObject({ event: "agent_mode_on", detail: ["webdriver"] });
  });
  it("a second signal joins the tab without a new session or broadcast", async () => {
    const s = setup();
    await s.la.content({ type: "agent.signal", signal: "webdriver" }, attackerFrame);
    await s.la.content({ type: "agent.signal", signal: "webdriver" }, { ...attackerFrame, tabId: MAIL });
    expect(s.broadcasts).toEqual([true]);
    expect((await s.store.load()).tabs.filter((t) => t.inSession).map((t) => t.tabId).sort()).toEqual([1, 2]);
  });
  it("does nothing when the person turned detection off", async () => {
    const s = setup();
    await s.settings.save({ ...(await s.settings.load()), detectWebdriver: false });
    expect(await s.la.content({ type: "agent.signal", signal: "webdriver" }, attackerFrame)).toEqual({ agentMode: false });
    expect((await s.store.load()).session).toBeNull();
  });
});

describe("joining the session", () => {
  it("while agent mode is on, a tab that shows a page joins", async () => {
    const s = await otpSession();
    const st = s.la.joinIfAgentMode(await s.store.load(), 9);
    expect(st.tabs.find((t) => t.tabId === 9)?.inSession).toBe(true);
  });
  it("with agent mode off nothing changes", async () => {
    const s = setup();
    const st = await s.store.load();
    expect(s.la.joinIfAgentMode(st, 9)).toBe(st);
  });
});

describe("log and settings view", () => {
  it("lists, verifies and exports", async () => {
    const s = await otpSession();
    await s.la.content(guard("482915"), attackerFrame);
    expect(((await s.la.ui({ type: "ui.log.list" })) as { entries: unknown[] }).entries.length).toBe(1);
    expect((await s.la.ui({ type: "ui.log.verify" })) as LogVerifyReply).toEqual({ brokenAt: null, count: 1 });
    expect(JSON.parse(((await s.la.ui({ type: "ui.log.export" })) as { json: string }).json).entries.length).toBe(1);
  });
  it("refuses to delete the log while agent mode is on", async () => {
    const s = await otpSession();
    await s.la.content(guard("482915"), attackerFrame);
    expect(await s.la.ui({ type: "ui.log.clear" })).toEqual({ ok: false, reason: "agent_mode_on" });
    expect((await s.log.list()).length).toBe(1);
  });
  it("deletes the log with agent mode off", async () => {
    const s = setup();
    await s.la.content(guard(realLookingCard()), attackerFrame);
    expect(await s.la.ui({ type: "ui.log.clear" })).toEqual({ ok: true });
    // Only the record of the deletion is left (RR14).
    expect((await s.log.list()).map((e) => e.event)).toEqual(["log_cleared"]);
  });
  it("refuses weakening settings in agent mode, applies them off, and logs the change", async () => {
    const s = await otpSession();
    const r = (await s.la.ui({ type: "ui.settings.set", patch: { detectWebdriver: false, keepEvidence: true } })) as SettingsReply;
    expect(r.ok).toBe(false);
    expect(r.refused).toEqual(["detectWebdriver"]);
    expect(r.settings.detectWebdriver).toBe(true);
    expect(r.settings.keepEvidence).toBe(true);
    expect((await s.log.list()).at(-1)).toMatchObject({ event: "settings_changed", detail: ["keepEvidence"] });

    const off = setup();
    const r2 = (await off.la.ui({ type: "ui.settings.set", patch: { alwaysOn: { oauth_consent: false } } })) as SettingsReply;
    expect(r2.ok).toBe(true);
    expect(r2.settings.alwaysOn.oauth_consent).toBe(false);
  });
});
