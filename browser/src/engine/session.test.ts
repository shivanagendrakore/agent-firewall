import { describe, expect, it } from "vitest";
import { agentModeOffProof, agentModeOffSnapshot, ApprovalLedger } from "./bindings.js";
import { printsFor } from "./private-data.js";
import { addSessionGrant, capPrints, effectiveTrust, MAX_SESSION_DOMAINS, MAX_SESSION_PRINTS, emptyState, endAgentSession, grantKey, linkedAgentTainted, pageShown, privateDataShown, sessionTaintForLink, startAgentSession, tabClosed, tabOpened, topLevelNavigated } from "./session.js";
import { DEFAULT_POLICY, type Policy } from "./types.js";

const P = DEFAULT_POLICY;
const trusting = (hosts: string[]): Policy => ({ ...P, trustedHosts: hosts });

describe("tab trust", () => {
  it("marks a tab untrusted when it shows an origin outside the trusted set (default: every origin)", () => {
    const s = pageShown(emptyState(), 1, { url: "https://shop.test/" }, P);
    expect(effectiveTrust(s, 1).untrusted).toBe(true);
  });

  it("keeps a tab trusted on a trusted host with a clean verdict", () => {
    const s = pageShown(emptyState(), 1, { url: "https://www.shop.test/", verdict: "deliver" }, trusting(["shop.test"]));
    expect(effectiveTrust(s, 1).untrusted).toBe(false);
  });

  it("a flag or quarantine verdict marks even a trusted tab untrusted; quarantine marks it quarantined", () => {
    const flagged = pageShown(emptyState(), 1, { url: "https://shop.test/", verdict: "flag" }, trusting(["shop.test"]));
    expect(effectiveTrust(flagged, 1)).toMatchObject({ untrusted: true, quarantined: false });
    const q = pageShown(emptyState(), 1, { url: "https://shop.test/", verdict: "quarantine" }, trusting(["shop.test"]));
    expect(effectiveTrust(q, 1)).toMatchObject({ untrusted: true, quarantined: true });
  });

  it("an incomplete scan marks the tab untrusted, never trusted", () => {
    const s = pageShown(emptyState(), 1, { url: "https://shop.test/", scanIncomplete: true }, trusting(["shop.test"]));
    expect(effectiveTrust(s, 1).untrusted).toBe(true);
  });

  it("marks bundled and person-listed sensitive origins private", () => {
    expect(effectiveTrust(pageShown(emptyState(), 1, { url: "https://mail.google.com/mail/u/0" }, P), 1).private).toBe(true);
    expect(effectiveTrust(pageShown(emptyState(), 1, { url: "https://mail.test/inbox" }, P), 1).private).toBe(false);
    expect(effectiveTrust(pageShown(emptyState(), 1, { url: "https://mail.test/inbox" }, { ...P, privateHosts: ["mail.test"] }), 1).private).toBe(true);
  });

  it("tabs inherit trust flags from their opener", () => {
    let s = pageShown(emptyState(), 1, { url: "https://attacker.test/", verdict: "quarantine" }, P);
    s = tabOpened(s, 2, 1);
    expect(effectiveTrust(s, 2)).toMatchObject({ untrusted: true, quarantined: true });
    expect(effectiveTrust(tabOpened(emptyState(), 3), 3)).toMatchObject({ untrusted: false, private: false, quarantined: false });
  });

  it("agent mode off: a top-level navigation clears the per-document quarantine but not untrusted", () => {
    let s = pageShown(emptyState(), 1, { url: "https://attacker.test/", verdict: "quarantine" }, P);
    s = topLevelNavigated(s, 1);
    expect(effectiveTrust(s, 1)).toMatchObject({ untrusted: true, quarantined: false });
  });

  it("closing a tab forgets it", () => {
    const s = tabClosed(pageShown(emptyState(), 1, { url: "https://attacker.test/" }, P), 1);
    expect(s.tabs).toEqual([]);
  });

  it("never mutates its input", () => {
    const s0 = emptyState();
    const frozen = JSON.stringify(s0);
    pageShown(s0, 1, { url: "https://attacker.test/", verdict: "quarantine" }, P);
    expect(JSON.stringify(s0)).toBe(frozen);
  });
});

describe("agent session", () => {
  it("is the union over its tabs, and other tabs see it too", () => {
    let s = startAgentSession(emptyState(), { now: 1, tabIds: [1] });
    s = pageShown(s, 1, { url: "https://attacker.test/", verdict: "quarantine" }, P);
    s = pageShown(s, 1, { url: "https://mail.google.com/" }, P);
    const t5 = effectiveTrust(s, 5);
    expect(t5).toMatchObject({ agentMode: true, untrusted: true, private: true, quarantined: true });
    expect([...t5.sessionDomains].sort()).toEqual(["attacker.test", "google.com"]);
  });

  it("taint never clears within the session: navigation and trusted pages do not reset it", () => {
    let s = startAgentSession(emptyState(), { now: 1, tabIds: [1] });
    s = pageShown(s, 1, { url: "https://attacker.test/", verdict: "quarantine" }, P);
    s = topLevelNavigated(s, 1);
    s = pageShown(s, 1, { url: "https://www.shop.test/", verdict: "deliver" }, trusting(["shop.test"]));
    expect(effectiveTrust(s, 1)).toMatchObject({ untrusted: true, quarantined: true });
  });

  it("a tab opened from a session tab joins the session", () => {
    let s = startAgentSession(emptyState(), { now: 1, tabIds: [1] });
    s = tabOpened(s, 2, 1);
    s = pageShown(s, 2, { url: "https://attacker.test/", verdict: "quarantine" }, P);
    expect(s.session?.quarantined).toBe(true);
  });

  it("seeds the session with the joining tabs' existing flags", () => {
    let s = pageShown(emptyState(), 1, { url: "https://mail.google.com/" }, P);
    s = startAgentSession(s, { now: 1, tabIds: [1] });
    expect(s.session?.private).toBe(true);
  });

  it("starting it again only adds tabs; it does not reset", () => {
    let s = startAgentSession(emptyState(), { now: 1, tabIds: [1] });
    s = pageShown(s, 1, { url: "https://attacker.test/", verdict: "quarantine" }, P);
    s = startAgentSession(s, { now: 2, tabIds: [2] });
    expect(s.session?.startedAt).toBe(1);
    expect(s.session?.quarantined).toBe(true);
  });

  it("keeps private-string fingerprints only inside a session", () => {
    const prints = printsFor("Your code is 482915", "mail.test", "salt-a");
    expect(prints.length).toBe(1);
    const off = privateDataShown(emptyState(), 1, prints);
    expect(effectiveTrust(off, 1).prints).toEqual([]);
    expect(effectiveTrust(off, 1).private).toBe(true);
    const on = privateDataShown(startAgentSession(emptyState(), { now: 1, tabIds: [1] }), 1, prints);
    expect(effectiveTrust(on, 1).prints).toEqual(prints);
    expect(privateDataShown(on, 1, prints).session?.prints.length).toBe(1);
  });

  it("refuses to end without an approval proof; a forged object is refused", () => {
    const s = startAgentSession(emptyState(), { now: 1, tabIds: [1] });
    expect(endAgentSession(s, null).ended).toBe(false);
    expect(endAgentSession(s, undefined).ended).toBe(false);
    expect(endAgentSession(s, { ok: true, purpose: "action" } as unknown as never).ended).toBe(false);
    // The right shape is not enough: only a proof the approval ledger minted counts (bindings.test.ts).
    expect(endAgentSession(s, { ok: true, purpose: "agent_mode_off" }).ended).toBe(false);
    expect(endAgentSession(s, Object.freeze({ ok: true as const, purpose: "agent_mode_off" as const })).ended).toBe(false);
  });

  it("grants: only grantable classes, only with a session", () => {
    expect(addSessionGrant(emptyState(), "shop.test", "payment").granted).toBe(false);
    const s = startAgentSession(emptyState(), { now: 1, tabIds: [1] });
    expect(addSessionGrant(s, "shop.test", "oauth_consent").granted).toBe(false);
    expect(addSessionGrant(s, "shop.test", "account_security").granted).toBe(false);
    const g = addSessionGrant(s, "www.shop.test", "payment");
    expect(g.granted).toBe(true);
    expect(effectiveTrust(g.state, 1).grants.has(grantKey("shop.test", "payment"))).toBe(true);
  });
});

describe("agent session print salt", () => {
  it("each session draws its own random salt, handed to decisions, and a new one after the session ends", () => {
    const a = startAgentSession(emptyState(), { now: 1, tabIds: [1] });
    const b = startAgentSession(emptyState(), { now: 1, tabIds: [1] });
    expect(a.session?.printSalt).toMatch(/^[0-9a-f]{32}$/);
    expect(a.session?.printSalt).not.toBe(b.session?.printSalt);
    expect(effectiveTrust(a, 1).printSalt).toBe(a.session?.printSalt);
    expect(effectiveTrust(emptyState(), 1).printSalt).toBeUndefined();
    // Only a proof minted from a redeemed agent-mode-off approval ends the session (bindings.ts).
    const l = new ApprovalLedger({ now: () => 1, randomId: () => `id-${"f".repeat(29)}` });
    const off = l.request(agentModeOffSnapshot(), "agent_mode_off");
    const proof = agentModeOffProof(l.redeem(l.approve(off.id) as string, agentModeOffSnapshot(), "agent_mode_off"));
    const r = endAgentSession(a, proof);
    expect(r.ended).toBe(true);
    expect(effectiveTrust(r.state, 1).printSalt).toBeUndefined();
  });
});

describe("taint shared over the native link (design 10)", () => {
  const proof = (): ReturnType<typeof agentModeOffProof> => {
    const ledger = new ApprovalLedger({ now: () => 1, randomId: (() => { let n = 0; return () => `id-${n++}-xxxxxxxxxxxxxxxx`; })() });
    const rec = ledger.request(agentModeOffSnapshot(), "agent_mode_off");
    const token = ledger.approve(rec.id) as string;
    return agentModeOffProof(ledger.redeem(token, agentModeOffSnapshot(), "agent_mode_off"));
  };

  it("a linked agent's taint makes the agent session untrusted, on every tab", () => {
    const s = linkedAgentTainted(startAgentSession(emptyState(), { now: 1, tabIds: [1] }), "agent-0123456789abcdef");
    expect(effectiveTrust(s, 1).untrusted).toBe(true);
    expect(effectiveTrust(s, 99).untrusted).toBe(true);
    expect(s.session?.linkedAgents).toEqual(["agent-0123456789abcdef"]);
  });

  it("with agent mode off it is held, and the next agent session starts untrusted", () => {
    const off = linkedAgentTainted(emptyState(), "agent-a");
    expect(effectiveTrust(off, 1).untrusted).toBe(false);
    const on = startAgentSession(off, { now: 2, tabIds: [] });
    expect(on.session).toMatchObject({ untrusted: true, linkedAgents: ["agent-a"] });
  });

  it("survives the session ending (the firewall reports each agent once per connection)", () => {
    const s = linkedAgentTainted(startAgentSession(emptyState(), { now: 1, tabIds: [1] }), "agent-b");
    const ended = endAgentSession(s, proof());
    expect(ended.ended).toBe(true);
    expect(ended.state.pendingLinkedAgents).toEqual(["agent-b"]);
    expect(startAgentSession(ended.state, { now: 3, tabIds: [] }).session?.untrusted).toBe(true);
  });

  it("is bounded and never duplicated", () => {
    let s = startAgentSession(emptyState(), { now: 1, tabIds: [] });
    for (let i = 0; i < 30; i++) s = linkedAgentTainted(linkedAgentTainted(s, `agent-${i}`), `agent-${i}`);
    expect(s.session?.linkedAgents).toHaveLength(20);
  });

  it("is sent to the firewall only for taint the browser saw itself, never echoed back", () => {
    expect(sessionTaintForLink(emptyState())).toBeNull();
    const clean = startAgentSession(emptyState(), { now: 5, tabIds: [1] });
    expect(sessionTaintForLink(clean)).toBeNull();
    expect(sessionTaintForLink(linkedAgentTainted(clean, "agent-c"))).toBeNull();
    const seen = pageShown(clean, 1, { url: "https://shop.test/", verdict: "quarantine" }, P);
    expect(sessionTaintForLink(seen)).toEqual({ session: "5", reason: "outside_origin" });
  });
});

describe("RR2: the session's private prints are capped", () => {
  const long = (i: number) => ({ fp: `long-${i}`, kind: "long" as const, domain: "flood.test" });
  const short = (i: number) => ({ fp: `otp:${i}`, kind: "short" as const, domain: "mail.test" });

  it("keeps at most MAX_SESSION_PRINTS, evicting the oldest long prints before any one-time code", () => {
    const prints = [short(0), ...Array.from({ length: MAX_SESSION_PRINTS }, (_, i) => long(i)), short(1)];
    const kept = capPrints(prints);
    expect(kept).toHaveLength(MAX_SESSION_PRINTS);
    expect(kept.filter((p) => p.kind === "short").map((p) => p.fp)).toEqual(["otp:0", "otp:1"]);
    expect(kept.some((p) => p.fp === "long-0")).toBe(false);
    expect(kept.at(-2)?.fp).toBe(`long-${MAX_SESSION_PRINTS - 1}`);
  });

  it("with only codes over the bound, the oldest codes go first", () => {
    const kept = capPrints(Array.from({ length: 5 }, (_, i) => short(i)), 3);
    expect(kept.map((p) => p.fp)).toEqual(["otp:2", "otp:3", "otp:4"]);
  });

  it("privateDataShown never grows the session past the bound, and a print shown again moves to the newest end", () => {
    let s = startAgentSession(emptyState(), { now: 1, tabIds: [1], printSalt: "salt" });
    s = privateDataShown(s, 1, [short(9)]);
    s = privateDataShown(s, 1, Array.from({ length: MAX_SESSION_PRINTS }, (_, i) => long(i)));
    s = privateDataShown(s, 1, Array.from({ length: MAX_SESSION_PRINTS }, (_, i) => long(i + MAX_SESSION_PRINTS)));
    expect(s.session?.prints).toHaveLength(MAX_SESSION_PRINTS);
    expect(s.session?.prints.some((p) => p.fp === "otp:9")).toBe(true);
    s = privateDataShown(s, 1, [long(MAX_SESSION_PRINTS)]);
    expect(s.session?.prints.at(-1)?.fp).toBe(`long-${MAX_SESSION_PRINTS}`);
    expect(s.session?.prints).toHaveLength(MAX_SESSION_PRINTS);
  });
});

describe("RR6: the site that injected outside content", () => {
  it("a quarantine verdict records the page's domain as an injector; effective trust excludes it only while quarantined", () => {
    let s = startAgentSession(emptyState(), { now: 1, tabIds: [1], printSalt: "salt" });
    s = pageShown(s, 1, { url: "https://shop.test/" }, P);
    expect(effectiveTrust(s, 1).injectorDomains).toBeUndefined();
    s = pageShown(s, 1, { url: "https://attacker.test/post", verdict: "quarantine" }, P);
    expect(s.session?.injectors).toEqual(["attacker.test"]);
    expect([...(effectiveTrust(s, 1).injectorDomains ?? [])]).toEqual(["attacker.test"]);
    expect(effectiveTrust(s, 1).sessionDomains.has("shop.test")).toBe(true);
  });
});

describe("session domain caps (I11)", () => {
  it("records at most MAX_SESSION_DOMAINS known domains; a domain past the cap stays new to the session", () => {
    let s = startAgentSession(emptyState(), { now: 1, tabIds: [1] });
    for (let i = 0; i < MAX_SESSION_DOMAINS + 50; i++) s = pageShown(s, 1, { url: `https://site${i}.test/` }, P);
    expect(s.session?.domains.length).toBe(MAX_SESSION_DOMAINS);
    expect(effectiveTrust(s, 1).sessionDomains.has(`site${MAX_SESSION_DOMAINS + 10}.test`)).toBe(false);
  });
  it("an injector that cannot be recorded (list full) is not a known destination either", () => {
    let s = startAgentSession(emptyState(), { now: 1, tabIds: [1] });
    for (let i = 0; i < MAX_SESSION_DOMAINS; i++) s = pageShown(s, 1, { url: `https://inj${i}.test/`, verdict: "quarantine" }, P);
    expect(s.session?.injectors?.length).toBe(MAX_SESSION_DOMAINS);
    s = pageShown(s, 1, { url: "https://late.test/", verdict: "quarantine" }, P);
    expect(s.session?.injectors?.length).toBe(MAX_SESSION_DOMAINS);
    expect(effectiveTrust(s, 1).sessionDomains.has("late.test")).toBe(false);
  });
});
