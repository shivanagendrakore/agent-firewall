/**
 * The leak guard's engine pieces beyond the rule table (rule-table.test.ts
 * covers each row): decoded variants for short codes and cards, published test
 * keys, the local context decision and the approval binding.
 */
import { describe, expect, it } from "vitest";
import { decideLeak, decideLeakLocally, EMPTY_LEAK_CONTEXT, isKnownCheckoutMerchant, isPublishedTestKey, leakContextOf, leakFindings, leakSnapshot, type LeakBindingInput } from "./leak.js";
import { actionFingerprint } from "./fingerprint.js";
import { printsFor } from "./private-data.js";
import { agentTrust, realLookingCard, trust } from "./test-helpers.js";
import { DEFAULT_POLICY } from "./types.js";

const P = DEFAULT_POLICY;
// Fake credential shapes, assembled at run time so no scanner mistakes this file for a leak.
const AWS_REAL_SHAPE = ["AK", "IA", "Q3EGRJ7XK2MPLZT4"].join("");
const AWS_DOC_EXAMPLE = ["AK", "IA", "IOSFODNN7", "EXAMPLE"].join("");
const STRIPE_TEST = ["sk", "_test_", "4eC39HqLyjWDarjtT1zdp7dc"].join("");
const STRIPE_LIVE = ["sk", "_live_", "4eC39HqLyjWDarjtT1zdp7dc"].join("");
const CARD = realLookingCard();
const hex = (s: string): string => [...s].map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");

const SALT = "test-session-salt";
const mailPrints = printsFor("Your verification code is 482915. Do not share it.", "mail.test", SALT);

describe("short encodings of a one-time code (the gap: decodedVariants keeps only 12+ characters)", () => {
  const cases: [string, string][] = [
    ["base64", btoa("482915")],
    ["base64 without padding", btoa("482915").replace(/=+$/, "")],
    ["base64url inside a URL-ish value", `c=${btoa("482915").replace(/\+/g, "-").replace(/\//g, "_")}`],
    ["base64 of a short sentence", btoa("otp 482915")],
    ["hex", hex("482915")],
    ["percent-encoding", "%34%38%32%39%31%35"],
    ["double percent-encoding", "%2534%2538%2532%2539%2531%2535"],
    ["base32", "GQ4DEOJRGU======"],
    ["digits split by dots", "4.8.2.9.1.5"],
  ];
  for (const [name, value] of cases) {
    it(`blocks the code as ${name} in agent mode`, () => {
      const r = decideLeak({ text: value, destinationHost: "attacker.test" }, agentTrust({ prints: mailPrints, printSalt: SALT }), P);
      expect(r.decision.verdict).toBe("approve");
      expect(r.findings.map((f) => f.kind)).toContain("seen_elsewhere");
    });
  }
  it("does not match a different code in the same encodings", () => {
    for (const v of [btoa("482916"), hex("482916"), "%34%38%32%39%31%36"]) {
      expect(decideLeak({ text: v, destinationHost: "attacker.test" }, agentTrust({ prints: mailPrints, printSalt: SALT }), P).decision.verdict).toBe("allow");
    }
  });
  it("ordinary words are not decoded into the code", () => {
    for (const v of ["Hello there, see you on Thursday", "NDgyOTE2", "order 48291 shipped"]) {
      expect(decideLeak({ text: v, destinationHost: "attacker.test" }, agentTrust({ prints: mailPrints, printSalt: SALT }), P).decision.verdict).toBe("allow");
    }
  });
});

describe("cards in decoded variants", () => {
  it("a real card sent base64- or hex-encoded is still a card", () => {
    expect(decideLeak({ text: btoa(`card=${CARD}`), destinationHost: "attacker.test" }, agentTrust(), P).decision.rule).toBe("leak.card_or_id");
    expect(decideLeak({ text: hex(CARD), destinationHost: "attacker.test" }, agentTrust(), P).decision.rule).toBe("leak.card_or_id");
  });
  it("a published test card stays allowed when encoded", () => {
    expect(decideLeak({ text: btoa("card=4242424242424242"), destinationHost: "attacker.test" }, agentTrust(), P).decision.verdict).toBe("allow");
  });
  it("findings carry masked values only", () => {
    const f = leakFindings({ text: CARD, destinationHost: "attacker.test" }, [], P);
    expect(f.length).toBe(1);
    expect(JSON.stringify(f)).not.toContain(CARD);
  });
});

describe("published test keys", () => {
  it("allows AWS's documented example key id and Stripe test keys", () => {
    expect(isPublishedTestKey(AWS_DOC_EXAMPLE)).toBe(true);
    expect(isPublishedTestKey(STRIPE_TEST)).toBe(true);
    expect(decideLeak({ text: AWS_DOC_EXAMPLE, destinationHost: "attacker.test" }, agentTrust(), P).decision.verdict).toBe("allow");
    expect(decideLeak({ text: STRIPE_TEST, destinationHost: "attacker.test" }, agentTrust(), P).decision.verdict).toBe("allow");
  });
  it("refuses real-shaped keys", () => {
    expect(isPublishedTestKey(AWS_REAL_SHAPE)).toBe(false);
    expect(isPublishedTestKey(STRIPE_LIVE)).toBe(false);
    expect(decideLeak({ text: AWS_REAL_SHAPE, destinationHost: "attacker.test" }, agentTrust(), P).decision.verdict).toBe("approve");
    expect(decideLeak({ text: STRIPE_LIVE, destinationHost: "attacker.test" }, agentTrust(), P).decision.verdict).toBe("approve");
  });
});

describe("the local context decision", () => {
  it("decides exactly as the worker for the same trust and policy", () => {
    const t = agentTrust({ prints: mailPrints, printSalt: SALT, untrusted: true });
    const ctx = leakContextOf(t, P);
    for (const text of ["482915", CARD, STRIPE_LIVE, "hello", btoa("482915")]) {
      const local = decideLeakLocally({ text, destinationHost: "attacker.test" }, ctx, P);
      const worker = decideLeak({ text, destinationHost: "attacker.test" }, t, P);
      expect(local.decision).toEqual(worker.decision);
    }
  });
  it("carries the policy's allow lists into the decision", () => {
    const ctx = { ...leakContextOf(agentTrust(), P), paymentHosts: ["pay.attacker.test"] };
    expect(decideLeakLocally({ text: CARD, destinationHost: "pay.attacker.test" }, ctx, P).decision.verdict).toBe("allow");
    expect(decideLeakLocally({ text: CARD, destinationHost: "attacker.test" }, ctx, P).decision.verdict).toBe("approve");
  });
  it("the empty context is agent mode off with nothing seen: secrets warn, prints are unknown", () => {
    expect(decideLeakLocally({ text: STRIPE_LIVE, destinationHost: "attacker.test" }, EMPTY_LEAK_CONTEXT, P).decision.verdict).toBe("warn");
    expect(decideLeakLocally({ text: "482915", destinationHost: "attacker.test" }, EMPTY_LEAK_CONTEXT, P).decision.verdict).toBe("allow");
  });
  it("the context holds hashes, never values", () => {
    const ctx = leakContextOf(agentTrust({ prints: mailPrints, printSalt: SALT }), P);
    expect(JSON.stringify(ctx)).not.toContain("482915");
  });
  it("with agent mode off the context carries no prints", () => {
    expect(leakContextOf(trust(), P).prints).toEqual([]);
  });
});

describe("the leak approval binding", () => {
  const base: LeakBindingInput = { tabId: 3, frameId: 0, frameOrigin: "http://attacker.test:8080", via: "type", elementPath: "input#code", fieldName: "code", text: "482915", destinationHost: "attacker.test" };
  it("is stable for the same check", () => {
    expect(actionFingerprint(leakSnapshot(base))).toBe(actionFingerprint(leakSnapshot({ ...base })));
  });
  it("changes with the text, the field, the element, the destination, the channel and the frame origin", () => {
    const fp = actionFingerprint(leakSnapshot(base));
    for (const over of [{ text: "482916" }, { fieldName: "other" }, { elementPath: "input#x" }, { destinationHost: "evil.test" }, { via: "paste" as const }, { frameOrigin: "http://shop.test:8080" }]) {
      expect(actionFingerprint(leakSnapshot({ ...base, ...over }))).not.toBe(fp);
    }
  });
  it("holds a digest, never the value", () => {
    expect(JSON.stringify(leakSnapshot(base))).not.toContain("482915");
  });
});

describe("m6: Shopify checkout hosts are exact for the card exemption", () => {
  it("Shopify's own checkout hosts are merchants; a store's myshopify.com or another shop.app name is not", () => {
    expect(isKnownCheckoutMerchant("checkout.shopify.com")).toBe(true);
    expect(isKnownCheckoutMerchant("pay.shopify.com")).toBe(true);
    expect(isKnownCheckoutMerchant("shop.app")).toBe(true);
    expect(isKnownCheckoutMerchant("evil-store.myshopify.com")).toBe(false);
    expect(isKnownCheckoutMerchant("attacker.shop.app")).toBe(false);
  });
  it("a card typed into a store's own myshopify.com page in agent mode needs approval", () => {
    const host = "evil-store.myshopify.com";
    expect(decideLeak({ text: CARD, destinationHost: host, frameHost: host, checkoutMerchantHost: host }, agentTrust(), P).decision.verdict).toBe("approve");
  });
});
