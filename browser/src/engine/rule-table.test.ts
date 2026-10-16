/**
 * Every row of the rule table (types.ts RULE_TABLE: design 5.3, 6.2, 7) has at
 * least one allow case and one refusal case. The last test fails if a row is
 * added without both.
 */
import { describe, expect, it } from "vitest";
import { decodedVariants, fingerprint } from "../vendor/firewall/engine/secrets.js";
import { decideLeak } from "./leak.js";
import { decideNavigation } from "./navigation.js";
import { printsFor } from "./private-data.js";
import { decide, decideAgentModeChange, decideGate } from "./rules.js";
import { grantKey } from "./session.js";
import { activate, agentTrust, ctx, download, frame, realLookingCard, submit, trust, upload } from "./test-helpers.js";
import { DEFAULT_POLICY, RULE_IDS, type Decision, type Policy, type RuleId, type Verdict } from "./types.js";

interface Case {
  row: RuleId;
  name: string;
  run: () => Decision;
  verdict: Verdict;
  /** The rule the decision must name; defaults to `row`. */
  rule?: RuleId;
  override?: "side_panel_with_reason";
}

const P = DEFAULT_POLICY;
const policy = (over: Partial<Policy>): Policy => ({ ...P, ...over });

// Fake credential shapes, assembled at run time so no scanner mistakes this file for a leak.
const GH_TOKEN = ["gh", "p_", "Zq8".repeat(12)].join("");
const STRIPE_TEST = ["sk", "_test_", "4eC39HqLyjWDarjtT1zdp7dc"].join("");
const CARD = realLookingCard();

const SALT = "test-session-salt";
const mailPrints = printsFor("Your verification code is 482915. It expires in 10 minutes.", "mail.test", SALT);

const placeOrder = activate("Place order");
const consent = activate("Allow", { frame: frame("https://accounts.google.com"), context: ctx("https://accounts.google.com/o/oauth2/v2/auth?client_id=x") });
const changePassword = submit([
  { name: "current", type: "password", autocomplete: "current-password" },
  { name: "new", type: "password", autocomplete: "new-password" },
]);
const exe = download("setup.exe");
const send = activate("Send", { context: ctx("https://mail.test/compose", { compose: { hasRecipient: true, hasBody: true } }) });
const deleteRepo = activate("Delete this repository");
const next = activate("Next");

const cases: Case[] = [
  // gate.unclassified
  { row: "gate.unclassified", name: "a plain button is allowed in agent mode", run: () => decide(next, agentTrust(), P), verdict: "allow" },
  { row: "gate.unclassified", name: "a sensitive label leaves the unclassified row", run: () => decide(placeOrder, agentTrust(), P), verdict: "approve", rule: "gate.agent_mode" },

  // gate.quarantine
  { row: "gate.quarantine", name: "agent mode on: any class on a quarantined tab is denied, overridable in the side panel", run: () => decide(placeOrder, agentTrust({ quarantined: true, untrusted: true }), P), verdict: "deny", override: "side_panel_with_reason" },
  { row: "gate.quarantine", name: "agent mode off: a payment on a quarantined tab needs approval", run: () => decide(placeOrder, trust({ quarantined: true }), P), verdict: "approve" },
  { row: "gate.quarantine", name: "agent mode off: an upload on a quarantined tab needs approval", run: () => decide(upload(), trust({ quarantined: true }), P), verdict: "approve" },
  { row: "gate.quarantine", name: "an unclassified action on a quarantined tab is allowed", run: () => decide(next, agentTrust({ quarantined: true }), P), verdict: "allow", rule: "gate.unclassified" },

  // gate.always_on
  { row: "gate.always_on", name: "OAuth consent needs approval with agent mode off", run: () => decide(consent, trust(), P), verdict: "approve" },
  { row: "gate.always_on", name: "a password change needs approval with agent mode off", run: () => decide(changePassword, trust(), P), verdict: "approve" },
  { row: "gate.always_on", name: "an executable download needs approval with agent mode off", run: () => decide(exe, trust(), P), verdict: "approve" },
  { row: "gate.always_on", name: "OAuth consent needs approval in agent mode", run: () => decide(consent, agentTrust(), P), verdict: "approve" },
  { row: "gate.always_on", name: "turned off by the person, consent is allowed with agent mode off", run: () => decide(consent, trust(), policy({ alwaysOn: { ...P.alwaysOn, oauth_consent: false } })), verdict: "allow" },
  { row: "gate.always_on", name: "turned off by the person, consent still needs approval in agent mode", run: () => decide(consent, agentTrust(), policy({ alwaysOn: { ...P.alwaysOn, oauth_consent: false } })), verdict: "approve" },
  { row: "gate.always_on", name: "a benign download is allowed", run: () => decide(download("report.pdf", "application/pdf"), agentTrust(), P), verdict: "allow", rule: "gate.unclassified" },

  // gate.agent_mode
  { row: "gate.agent_mode", name: "agent mode off: a payment is allowed", run: () => decide(placeOrder, trust(), P), verdict: "allow" },
  { row: "gate.agent_mode", name: "agent mode off: a send is allowed", run: () => decide(send, trust(), P), verdict: "allow" },
  { row: "gate.agent_mode", name: "agent mode off: a delete is allowed", run: () => decide(deleteRepo, trust(), P), verdict: "allow" },
  { row: "gate.agent_mode", name: "agent mode on: a payment needs approval", run: () => decide(placeOrder, agentTrust(), P), verdict: "approve" },
  { row: "gate.agent_mode", name: "agent mode on: a send needs approval", run: () => decide(send, agentTrust(), P), verdict: "approve" },
  { row: "gate.agent_mode", name: "agent mode on: a delete needs approval", run: () => decide(deleteRepo, agentTrust(), P), verdict: "approve" },

  // gate.upload
  { row: "gate.upload", name: "agent mode off: an upload is allowed", run: () => decide(upload(), trust({ private: true }), P), verdict: "allow" },
  { row: "gate.upload", name: "agent mode on: an upload to a known target in a public session is allowed", run: () => decide(upload(), agentTrust({ sessionDomains: new Set(["shop.test"]) }), P), verdict: "allow" },
  { row: "gate.upload", name: "agent mode on: an upload in a private session needs approval", run: () => decide(upload(), agentTrust({ private: true, sessionDomains: new Set(["shop.test"]) }), P), verdict: "approve" },
  { row: "gate.upload", name: "agent mode on: an upload to a target new to the session needs approval", run: () => decide(upload({ targetUrl: "https://attacker.test/upload" }), agentTrust({ sessionDomains: new Set(["shop.test"]) }), P), verdict: "approve" },

  // gate.session_grant
  { row: "gate.session_grant", name: "a payment on a granted site is allowed in agent mode", run: () => decide(placeOrder, agentTrust({ grants: new Set([grantKey("shop.test", "payment")]) }), P), verdict: "allow" },
  { row: "gate.session_grant", name: "a submit to another site needs a grant for the frame's site and the target's", run: () => decide(submit([], { label: "Place order", frame: frame("https://shop.test"), form: { fields: [], targetUrl: "https://psp.test/charge", method: "post" } }), agentTrust({ grants: new Set([grantKey("shop.test", "payment"), grantKey("psp.test", "payment")]) }), P), verdict: "allow" },
  { row: "gate.session_grant", name: "a grant for the frame's site alone does not cover a submit to another site", run: () => decide(submit([], { label: "Place order", frame: frame("https://shop.test"), form: { fields: [], targetUrl: "https://psp.test/charge", method: "post" } }), agentTrust({ grants: new Set([grantKey("shop.test", "payment")]) }), P), verdict: "approve", rule: "gate.agent_mode" },
  { row: "gate.session_grant", name: "a grant for another site does not apply", run: () => decide(placeOrder, agentTrust({ grants: new Set([grantKey("other.test", "payment")]) }), P), verdict: "approve", rule: "gate.agent_mode" },
  { row: "gate.session_grant", name: "a grant never applies to OAuth consent", run: () => decideGate({ actionClass: "oauth_consent", targetHost: "accounts.google.com" }, agentTrust({ grants: new Set([grantKey("accounts.google.com", "oauth_consent")]) }), P), verdict: "approve", rule: "gate.always_on" },
  { row: "gate.session_grant", name: "a grant never applies to account security", run: () => decideGate({ actionClass: "account_security", targetHost: "shop.test" }, agentTrust({ grants: new Set([grantKey("shop.test", "account_security")]) }), P), verdict: "approve", rule: "gate.always_on" },
  { row: "gate.session_grant", name: "a grant never lifts a quarantine deny", run: () => decide(placeOrder, agentTrust({ quarantined: true, grants: new Set([grantKey("shop.test", "payment")]) }), P), verdict: "deny", rule: "gate.quarantine", override: "side_panel_with_reason" },

  // control.agent_mode_off
  { row: "control.agent_mode_off", name: "turning agent mode on is never gated", run: () => decideAgentModeChange(true), verdict: "allow" },
  { row: "control.agent_mode_off", name: "turning agent mode off needs approval", run: () => decideAgentModeChange(false), verdict: "approve" },

  // leak.none
  { row: "leak.none", name: "ordinary text is allowed", run: () => decideLeak({ text: "Deliver to the side door, thanks", destinationHost: "attacker.test" }, agentTrust(), P).decision, verdict: "allow" },
  { row: "leak.none", name: "a secret leaves the clean row", run: () => decideLeak({ text: `token ${GH_TOKEN}`, destinationHost: "attacker.test" }, agentTrust(), P).decision, verdict: "approve", rule: "leak.secret" },

  // leak.secret
  { row: "leak.secret", name: "agent mode on: a secret to a non-allowed host needs approval", run: () => decideLeak({ text: `token ${GH_TOKEN}`, destinationHost: "attacker.test" }, agentTrust(), P).decision, verdict: "approve" },
  { row: "leak.secret", name: "agent mode on: a base64-encoded secret needs approval", run: () => decideLeak({ text: btoa(`key=${GH_TOKEN}`), destinationHost: "attacker.test" }, agentTrust(), P).decision, verdict: "approve" },
  { row: "leak.secret", name: "agent mode off: a secret to a non-allowed host warns", run: () => decideLeak({ text: `token ${GH_TOKEN}`, destinationHost: "attacker.test" }, trust(), P).decision, verdict: "warn" },
  { row: "leak.secret", name: "a secret to its issuer is allowed", run: () => decideLeak({ text: GH_TOKEN, destinationHost: "github.com" }, agentTrust(), P).decision, verdict: "allow", rule: "leak.none" },
  { row: "leak.secret", name: "a published test key is allowed", run: () => decideLeak({ text: STRIPE_TEST, destinationHost: "attacker.test" }, agentTrust(), P).decision, verdict: "allow", rule: "leak.none" },
  {
    row: "leak.secret",
    name: "a secret on the per-secret allow list is allowed there",
    run: () => decideLeak({ text: GH_TOKEN, destinationHost: "ci.shop.test" }, agentTrust(), policy({ secretAllow: [{ fingerprint: fingerprint(GH_TOKEN) as string, hosts: ["shop.test"] }] })).decision,
    verdict: "allow",
    rule: "leak.none",
  },

  // leak.card_or_id
  { row: "leak.card_or_id", name: "agent mode on: a real card to a non-payment host needs approval", run: () => decideLeak({ text: CARD, destinationHost: "attacker.test" }, agentTrust(), P).decision, verdict: "approve" },
  { row: "leak.card_or_id", name: "agent mode off: a real card to a non-payment host warns", run: () => decideLeak({ text: CARD, destinationHost: "attacker.test" }, trust(), P).decision, verdict: "warn" },
  { row: "leak.card_or_id", name: "a published test card is allowed", run: () => decideLeak({ text: "4242 4242 4242 4242", destinationHost: "attacker.test" }, agentTrust(), P).decision, verdict: "allow", rule: "leak.none" },
  { row: "leak.card_or_id", name: "a real card into a payment provider frame is allowed", run: () => decideLeak({ text: CARD, destinationHost: "js.stripe.com" }, agentTrust(), P).decision, verdict: "allow", rule: "leak.none" },
  { row: "leak.card_or_id", name: "a real card to a known checkout merchant is allowed", run: () => decideLeak({ text: CARD, destinationHost: "www.amazon.com", frameHost: "www.amazon.com", checkoutMerchantHost: "www.amazon.com" }, agentTrust(), P).decision, verdict: "allow", rule: "leak.none" },
  { row: "leak.card_or_id", name: "a page that names itself the merchant still needs approval", run: () => decideLeak({ text: CARD, destinationHost: "pay.shop.test", checkoutMerchantHost: "shop.test" }, agentTrust(), P).decision, verdict: "approve" },
  { row: "leak.card_or_id", name: "a person-added payment host counts as a merchant", run: () => decideLeak({ text: CARD, destinationHost: "pay.shop.test", checkoutMerchantHost: "shop.test" }, agentTrust(), { ...P, paymentHosts: ["shop.test"] }).decision, verdict: "allow", rule: "leak.none" },
  { row: "leak.card_or_id", name: "a card form in a non-payment frame posting to a payment host still needs approval", run: () => decideLeak({ text: CARD, destinationHost: "js.stripe.com", frameHost: "evil.test" }, agentTrust(), P).decision, verdict: "approve" },

  // leak.seen_elsewhere
  { row: "leak.seen_elsewhere", name: "agent mode on: an OTP from mail.test typed on attacker.test needs approval", run: () => decideLeak({ text: "482915", destinationHost: "attacker.test" }, agentTrust({ prints: mailPrints, printSalt: SALT }), P).decision, verdict: "approve" },
  { row: "leak.seen_elsewhere", name: "agent mode off: the same is logged", run: () => decideLeak({ text: "482915", destinationHost: "attacker.test" }, trust({ prints: mailPrints, printSalt: SALT }), P).decision, verdict: "log" },
  { row: "leak.seen_elsewhere", name: "the OTP typed on the site that showed it is allowed", run: () => decideLeak({ text: "482915", destinationHost: "login.mail.test" }, agentTrust({ prints: mailPrints, printSalt: SALT }), P).decision, verdict: "allow", rule: "leak.none" },

  // leak.seen_elsewhere_quarantine
  { row: "leak.seen_elsewhere_quarantine", name: "on an untrusted quarantined tab in agent mode, the OTP is denied", run: () => decideLeak({ text: "code: 482915", destinationHost: "attacker.test" }, agentTrust({ prints: mailPrints, printSalt: SALT, untrusted: true, quarantined: true }), P).decision, verdict: "deny" },
  { row: "leak.seen_elsewhere_quarantine", name: "a value that was not shown elsewhere is allowed on that tab", run: () => decideLeak({ text: "123456", destinationHost: "attacker.test" }, agentTrust({ prints: mailPrints, printSalt: SALT, untrusted: true, quarantined: true }), P).decision, verdict: "allow", rule: "leak.none" },

  // nav.none
  { row: "nav.none", name: "an ordinary page is allowed in agent mode", run: () => decideNavigation({ url: "https://news.test/today", resourceType: "main_frame" }, agentTrust(), P), verdict: "allow" },
  { row: "nav.none", name: "a capture host leaves the clean row", run: () => decideNavigation({ url: "https://webhook.site/abc", resourceType: "other" }, trust(), P), verdict: "deny", rule: "nav.capture_host" },

  // nav.capture_host
  { row: "nav.capture_host", name: "a capture-host subresource is blocked with agent mode off", run: () => decideNavigation({ url: "https://webhook.site/abc?d=1", resourceType: "other" }, trust(), P), verdict: "deny" },
  { row: "nav.capture_host", name: "a capture-host main frame is blocked in agent mode", run: () => decideNavigation({ url: "https://pastebin.com/raw/x", resourceType: "main_frame" }, agentTrust(), P), verdict: "deny" },
  { row: "nav.capture_host", name: "a Discord webhook URL is a capture URL", run: () => decideNavigation({ url: "https://discord.com/api/webhooks/1/abc", resourceType: "other" }, trust(), P), verdict: "deny" },
  { row: "nav.capture_host", name: "a person may open a capture host with agent mode off", run: () => decideNavigation({ url: "https://pastebin.com/raw/x", resourceType: "main_frame" }, trust(), P), verdict: "allow" },

  // nav.script_url
  { row: "nav.script_url", name: "a javascript: top-level navigation is blocked in agent mode", run: () => decideNavigation({ url: "javascript:fetch('//attacker.test')", resourceType: "main_frame" }, agentTrust(), P), verdict: "deny" },
  { row: "nav.script_url", name: "a data: top-level navigation is blocked in agent mode", run: () => decideNavigation({ url: "data:text/html,<p>x</p>", resourceType: "main_frame" }, agentTrust(), P), verdict: "deny" },
  { row: "nav.script_url", name: "agent mode off: a javascript: link is allowed", run: () => decideNavigation({ url: "javascript:void(0)", resourceType: "main_frame" }, trust(), P), verdict: "allow" },

  // nav.high_entropy_new_origin
  {
    row: "nav.high_entropy_new_origin",
    name: "a data-carrying URL to a new domain from a private session needs approval",
    run: () => decideNavigation({ url: `https://collect.attacker.test/p?d=${"aZ3kQ9xV7mW2pL8rT4yB6nC1"}`, resourceType: "other" }, agentTrust({ private: true, sessionDomains: new Set(["mail.test"]) }), P),
    verdict: "approve",
  },
  {
    row: "nav.high_entropy_new_origin",
    name: "the same URL to a domain the session already showed is allowed",
    run: () => decideNavigation({ url: `https://mail.test/p?d=${"aZ3kQ9xV7mW2pL8rT4yB6nC1"}`, resourceType: "other" }, agentTrust({ private: true, sessionDomains: new Set(["mail.test"]) }), P),
    verdict: "allow",
    rule: "nav.none",
  },
  {
    row: "nav.high_entropy_new_origin",
    name: "the same URL from a session that is not private is allowed",
    run: () => decideNavigation({ url: `https://collect.attacker.test/p?d=${"aZ3kQ9xV7mW2pL8rT4yB6nC1"}`, resourceType: "other" }, agentTrust({ sessionDomains: new Set(["mail.test"]) }), P),
    verdict: "allow",
    rule: "nav.none",
  },

  // nav.suspicious_host
  { row: "nav.suspicious_host", name: "a raw IP needs approval in agent mode", run: () => decideNavigation({ url: "http://203.0.113.9/x", resourceType: "main_frame" }, agentTrust(), P), verdict: "approve" },
  { row: "nav.suspicious_host", name: "a DNS-exfil-shaped host needs approval in agent mode", run: () => decideNavigation({ url: "https://4f9a8b7c6d5e4f3a2b1c0d9e.attacker.test/", resourceType: "other" }, agentTrust(), P), verdict: "approve" },
  { row: "nav.suspicious_host", name: "a cloud metadata address is blocked as a subresource even with agent mode off", run: () => decideNavigation({ url: "http://169.254.169.254/latest/meta-data/", resourceType: "other" }, trust(), P), verdict: "deny" },
  { row: "nav.suspicious_host", name: "loopback is not a raw IP", run: () => decideNavigation({ url: "http://127.0.0.1:8080/", resourceType: "main_frame" }, agentTrust(), P), verdict: "allow", rule: "nav.none" },
  { row: "nav.suspicious_host", name: "agent mode off: a raw IP is allowed", run: () => decideNavigation({ url: "http://203.0.113.9/x", resourceType: "main_frame" }, trust(), P), verdict: "allow", rule: "nav.none" },

  // nav.origin_set
  { row: "nav.origin_set", name: "with an origin set, a main frame outside it needs approval", run: () => decideNavigation({ url: "https://elsewhere.test/", resourceType: "main_frame" }, agentTrust(), policy({ originSet: ["shop.test"] })), verdict: "approve" },
  { row: "nav.origin_set", name: "with an origin set, a main frame inside it is allowed", run: () => decideNavigation({ url: "https://www.shop.test/cart", resourceType: "main_frame" }, agentTrust(), policy({ originSet: ["shop.test"] })), verdict: "allow", rule: "nav.none" },
];

describe("rule table", () => {
  for (const c of cases) {
    it(`${c.row}: ${c.name}`, () => {
      const d = c.run();
      expect(d.verdict).toBe(c.verdict);
      expect(d.rule).toBe(c.rule ?? c.row);
      if (c.override !== undefined) expect(d.override).toBe(c.override);
      else expect(d.override).toBeUndefined();
    });
  }

  it("every row has at least one allow case and one refusal case", () => {
    const missing: string[] = [];
    for (const id of RULE_IDS) {
      const mine = cases.filter((c) => c.row === id);
      if (!mine.some((c) => c.verdict === "allow")) missing.push(`${id}: no allow case`);
      if (!mine.some((c) => c.verdict === "approve" || c.verdict === "deny")) missing.push(`${id}: no refusal case`);
    }
    expect(missing).toEqual([]);
  });

  it("names only rows that exist", () => {
    for (const c of cases) {
      expect(RULE_IDS).toContain(c.row);
      if (c.rule !== undefined) expect(RULE_IDS).toContain(c.rule);
    }
  });

  it("decoded test strings round-trip (guards the fixtures themselves)", () => {
    expect(decodedVariants(btoa(`key=${GH_TOKEN}`)).some((v) => v.includes(GH_TOKEN))).toBe(true);
  });
});
