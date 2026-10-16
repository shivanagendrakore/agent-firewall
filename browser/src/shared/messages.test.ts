import { describe, expect, it } from "vitest";
import { snapshotOf } from "../engine/fingerprint.js";
import { activate, submit } from "../engine/test-helpers.js";
import { isFromOwnContentScript, isFromOwnExtensionPage, LIMITS, parseContentMessage, parseUiMessage, parseWorkerMessage, withinMessageBounds } from "./messages.js";

const ID = "abcdefghijklmnopabcdefghijklmnop";

describe("sender checks", () => {
  it("accepts our own content script, with a tab and frame", () => {
    expect(isFromOwnContentScript({ id: ID, tab: { id: 4 }, frameId: 0, url: "https://shop.test/" }, ID)).toBe(true);
  });
  it("refuses another extension, a message with no tab or frame, and our own pages", () => {
    expect(isFromOwnContentScript({ id: "other", tab: { id: 4 }, frameId: 0 }, ID)).toBe(false);
    expect(isFromOwnContentScript({ id: ID, frameId: 0 }, ID)).toBe(false);
    expect(isFromOwnContentScript({ id: ID, tab: { id: 4 } }, ID)).toBe(false);
    expect(isFromOwnContentScript({ id: ID, tab: { id: -1 }, frameId: 0 }, ID)).toBe(false);
    expect(isFromOwnContentScript({ id: ID, tab: { id: 4 }, frameId: 0, url: `chrome-extension://${ID}/approval.html` }, ID)).toBe(false);
  });
  it("accepts our extension pages (side panel, popup, an approval window in a tab), and nothing else", () => {
    expect(isFromOwnExtensionPage({ id: ID, url: `chrome-extension://${ID}/sidepanel.html` }, ID)).toBe(true);
    expect(isFromOwnExtensionPage({ id: ID, url: `chrome-extension://${ID}/approval.html`, tab: { id: 3 } }, ID)).toBe(true);
    expect(isFromOwnExtensionPage({ id: ID, url: "https://shop.test/", tab: { id: 3 }, frameId: 0 }, ID)).toBe(false);
    expect(isFromOwnExtensionPage({ id: ID, url: "https://shop.test/" }, ID)).toBe(false);
    expect(isFromOwnExtensionPage({ id: ID, url: `chrome-extension://${ID}evil/x.html` }, ID)).toBe(false);
    expect(isFromOwnExtensionPage({ id: "other", url: `chrome-extension://${ID}/sidepanel.html` }, ID)).toBe(false);
  });
});

describe("content messages", () => {
  it("accepts well-formed messages", () => {
    expect(parseContentMessage({ type: "frame.hello", url: "https://shop.test/", top: true })).not.toBeNull();
    expect(parseContentMessage({ type: "page.scanned", url: "https://shop.test/", verdict: "quarantine", reasons: ["hidden_instruction"], scanIncomplete: false })).not.toBeNull();
    expect(parseContentMessage({ type: "action.check", action: activate("Pay") })).not.toBeNull();
    expect(parseContentMessage({ type: "action.check", action: submit([{ name: "a", type: "text", value: "b" }]) })).not.toBeNull();
    const withTarget = (formTarget: unknown) => ({ type: "action.check", action: { ...activate("Pay"), context: { pageUrl: "https://shop.test/", formTarget } } });
    expect(parseContentMessage(withTarget({ url: "https://shop.test/order", method: "post" }))).not.toBeNull();
    for (const bad of [{ url: 3, method: "post" }, { url: "https://x.test/", method: "p".repeat(17) }, { url: "u".repeat(LIMITS.url + 1), method: "post" }, { method: "post" }, "https://x.test/"]) expect(parseContentMessage(withTarget(bad))).toBeNull();
    expect(parseContentMessage({ type: "leak.guard", via: "paste", text: "x", destinationHost: "shop.test", elementPath: "input", fieldName: "q" })).not.toBeNull();
    expect(parseContentMessage({ type: "approval.redeem", token: "t".repeat(32), snapshot: snapshotOf(activate("Pay"), "payment") })).not.toBeNull();
  });

  it("refuses unknown types, wrong types, and bad enums", () => {
    for (const m of [
      null,
      "frame.hello",
      [],
      { type: "nope" },
      { type: "frame.hello", url: 3, top: true },
      { type: "page.scanned", url: "u", verdict: "fine", reasons: [], scanIncomplete: false },
      { type: "leak.guard", via: "fetch", text: "x", destinationHost: "h", elementPath: "", fieldName: "" },
      // The old unbound leak.check path is gone: only leak.guard (which logs and creates the approval) is accepted.
      { type: "leak.check", via: "type", text: "x", destinationHost: "h" },
      { type: "action.check", action: { ...activate("Pay"), kind: "navigate" } },
      { type: "action.check", action: { ...activate("Pay"), frame: { tabId: "1", frameId: 0, origin: "o" } } },
      { type: "approval.redeem", token: "", snapshot: snapshotOf(activate("Pay"), "payment") },
      { type: "approval.redeem", token: "t", snapshot: { ...snapshotOf(activate("Pay"), "payment"), actionClass: "everything" } },
      { type: "private.prints", prints: [{ fp: "x", kind: "medium", domain: "d" }] },
    ]) {
      expect(parseContentMessage(m)).toBeNull();
    }
  });

  it("refuses over-size fields", () => {
    expect(parseContentMessage({ type: "frame.hello", url: "u".repeat(LIMITS.url + 1), top: true })).toBeNull();
    expect(parseContentMessage({ type: "leak.guard", via: "type", text: "x".repeat(LIMITS.text + 1), destinationHost: "h", elementPath: "", fieldName: "" })).toBeNull();
    expect(parseContentMessage({ type: "action.check", action: activate("x".repeat(LIMITS.label + 1)) })).toBeNull();
  });
});

describe("UI and worker messages", () => {
  it("parses UI messages and refuses malformed ones", () => {
    expect(parseUiMessage({ type: "ui.approve", approvalId: "a1" })).toEqual({ type: "ui.approve", approvalId: "a1" });
    expect(parseUiMessage({ type: "ui.approve", approvalId: "" })).toBeNull();
    expect(parseUiMessage({ type: "ui.agentMode", on: "yes" })).toBeNull();
    expect(parseUiMessage({ type: "action.check" })).toBeNull();
  });
  it("parses worker messages and refuses malformed ones", () => {
    expect(parseWorkerMessage({ type: "agent.mode", on: true })).toEqual({ type: "agent.mode", on: true });
    expect(parseWorkerMessage({ type: "approval.granted", approvalId: "a", token: 5 })).toBeNull();
    expect(parseWorkerMessage({ type: "ui.state" })).toBeNull();
  });
});

describe("leak/agent/log messages", () => {
  const guardMsg = { type: "leak.guard", via: "type", text: "482915", destinationHost: "attacker.test", elementPath: "input#code", fieldName: "code" };
  it("accepts well-formed messages", () => {
    expect(parseContentMessage(guardMsg)).toEqual(guardMsg);
    expect(parseContentMessage({ ...guardMsg, checkoutMerchantHost: "shop.test" })).toEqual({ ...guardMsg, checkoutMerchantHost: "shop.test" });
    expect(parseContentMessage({ type: "leak.context" })).toEqual({ type: "leak.context" });
    expect(parseContentMessage({ type: "agent.signal", signal: "webdriver" })).toEqual({ type: "agent.signal", signal: "webdriver" });
    expect(parseUiMessage({ type: "ui.log.list", limit: 50 })).toEqual({ type: "ui.log.list", limit: 50 });
    expect(parseUiMessage({ type: "ui.log.verify" })).toEqual({ type: "ui.log.verify" });
    expect(parseUiMessage({ type: "ui.settings.set", patch: { retentionDays: 60, alwaysOn: { oauth_consent: false } } })).toEqual({ type: "ui.settings.set", patch: { retentionDays: 60, alwaysOn: { oauth_consent: false } } });
    const ctx = { agentMode: true, untrusted: false, quarantined: false, private: true, prints: [{ fp: "otp:abc", kind: "short", domain: "mail.test" }], printSalt: "0011", secretAllow: [], paymentHosts: [] };
    expect(parseWorkerMessage({ type: "leak.context", context: ctx })).toEqual({ type: "leak.context", context: ctx });
  });
  it("refuses malformed, mistyped and oversized ones", () => {
    expect(parseContentMessage({ ...guardMsg, via: "fetch" })).toBeNull();
    expect(parseContentMessage({ ...guardMsg, elementPath: undefined })).toBeNull();
    expect(parseContentMessage({ ...guardMsg, text: "x".repeat(LIMITS.text + 1) })).toBeNull();
    expect(parseContentMessage({ ...guardMsg, destinationHost: 5 })).toBeNull();
    expect(parseContentMessage({ type: "agent.signal", signal: "debugger" })).toBeNull();
    expect(parseUiMessage({ type: "ui.log.list", limit: 0 })).toBeNull();
    expect(parseUiMessage({ type: "ui.log.list", limit: 1.5 })).toBeNull();
    expect(parseUiMessage({ type: "ui.settings.set", patch: { retentionDays: 0 } })).toBeNull();
    expect(parseUiMessage({ type: "ui.settings.set", patch: { retentionDays: 366 } })).toBeNull();
    expect(parseUiMessage({ type: "ui.settings.set", patch: { alwaysOn: { payment: false } } })).toBeNull();
    expect(parseUiMessage({ type: "ui.settings.set", patch: { trustedHosts: ["attacker test/"] } })).toBeNull();
    expect(parseUiMessage({ type: "ui.settings.set", patch: { privateHosts: Array.from({ length: 201 }, (_, i) => `h${i}.test`) } })).toBeNull();
    expect(parseUiMessage({ type: "ui.settings.set", patch: { trustedHosts: [" Intranet.Example. ", "*.corp.example"] } })).toEqual({ type: "ui.settings.set", patch: { trustedHosts: ["intranet.example", "*.corp.example"] } });
    expect(parseUiMessage({ type: "ui.settings.set", patch: { detectWebdriver: "no" } })).toBeNull();
    expect(parseWorkerMessage({ type: "leak.context", context: { agentMode: true } })).toBeNull();
    expect(parseWorkerMessage({ type: "leak.context", context: { agentMode: true, untrusted: false, quarantined: false, private: false, prints: [{ fp: 1 }], secretAllow: [], paymentHosts: [] } })).toBeNull();
  });
  it("a content script cannot send UI messages, nor the UI content ones", () => {
    expect(parseContentMessage({ type: "ui.log.clear" })).toBeNull();
    expect(parseUiMessage(guardMsg)).toBeNull();
  });
});

describe("total message bounds", () => {
  it("accepts one full-size text, refuses several", () => {
    expect(parseContentMessage({ type: "leak.guard", via: "paste", text: "a".repeat(LIMITS.text), destinationHost: "x.test", elementPath: "", fieldName: "" })).not.toBeNull();
    expect(withinMessageBounds({ a: "a".repeat(LIMITS.text), b: "b".repeat(LIMITS.text), c: "c".repeat(LIMITS.text) })).toBe(false);
  });

  it("refuses non-finite numbers, deep nesting and non-JSON values anywhere", () => {
    expect(withinMessageBounds({ a: [1, 2, Infinity] })).toBe(false);
    expect(withinMessageBounds({ a: Number.NaN })).toBe(false);
    let deep: unknown = "x";
    for (let i = 0; i < LIMITS.depth + 1; i++) deep = { deep };
    expect(withinMessageBounds(deep)).toBe(false);
    expect(withinMessageBounds({ f: () => 1 })).toBe(false);
    expect(withinMessageBounds({ ok: true, n: 3, s: "x", a: [null] })).toBe(true);
  });

  it("an oversized UI message is refused", () => {
    expect(parseUiMessage({ type: "ui.state", pad: "a".repeat(LIMITS.message) })).toBeNull();
  });
});
