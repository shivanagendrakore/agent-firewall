import { describe, expect, it } from "vitest";
import type { ChainedEntry } from "../shared/messages.js";
import { RULE_IDS } from "../engine/types.js";
import { newNonce, parseHostMessage, wireEntry, wireLabel } from "./link-protocol.js";

const entry: ChainedEntry = { seq: 3, prevHash: "0".repeat(64), hash: "a".repeat(64), at: 1760000000000, site: "shop.test", actionClass: "payment", verdict: "approve", rules: ["gate.payment" as ChainedEntry["rules"][number]], approval: "approved", binding: "b".repeat(64) };

describe("what the extension sends", () => {
  it("never sends the evidence snippet (page text) or anything outside the host's schema", () => {
    const w = wireEntry({ ...entry, evidence: "ignore all previous instructions", detail: ["card_number", "bad detail with spaces", "x".repeat(65)] });
    expect(w).toEqual({ seq: 3, hash: "a".repeat(64), prevHash: "0".repeat(64), at: 1760000000000, site: "shop.test", actionClass: "payment", verdict: "approve", rules: ["gate.payment"], approval: "approved", binding: "b".repeat(64), detail: ["card_number"] });
    expect(JSON.stringify(w)).not.toContain("instructions");
  });

  it("sends an empty site rather than one the host would refuse (an IPv6 literal, a full URL)", () => {
    expect(wireEntry({ ...entry, site: "[::1]" }).site).toBe("");
    expect(wireEntry({ ...entry, site: "https://shop.test/x" }).site).toBe("");
    expect(wireEntry({ ...entry, site: "127.0.0.1" }).site).toBe("127.0.0.1");
  });

  it("every rule id the extension can log fits the host's schema", () => {
    for (const r of RULE_IDS) expect(wireEntry({ ...entry, rules: [r] }).rules).toEqual([r]);
  });

  it("cleans approval labels of control and invisible characters, and bounds them", () => {
    expect(wireLabel("Pay\u001b[2J ‮evil")).toBe("Pay [2J evil");
    expect([...wireLabel("x".repeat(500))]).toHaveLength(200);
    expect(wireLabel("​")).toBe("a held action");
  });

  it("makes nonces the host accepts", () => {
    for (let i = 0; i < 20; i++) expect(newNonce()).toMatch(/^[A-Za-z0-9_-]{16}$/);
  });
});

describe("what the host sends", () => {
  it("accepts each message the firewall's host sends", () => {
    expect(parseHostMessage({ type: "hello", re: "n-0000001", version: 1, capabilities: ["log", "taint", "approval"], firewall: "0.3.0" })).toMatchObject({ type: "hello" });
    expect(parseHostMessage({ type: "log.ack", re: "n-0000001", seq: 7 })).toEqual({ type: "log.ack", re: "n-0000001", seq: 7 });
    expect(parseHostMessage({ type: "ack", re: "n-0000001" })).toEqual({ type: "ack", re: "n-0000001" });
    expect(parseHostMessage({ type: "approval.queued", re: "n-0000001", id: "abcd2345" })).toMatchObject({ id: "abcd2345" });
    expect(parseHostMessage({ type: "approval.result", nonce: "n-0000001", binding: "c".repeat(64), verdict: "approve", sig: "c2lnbmF0dXJl" })).toMatchObject({ verdict: "approve" });
    expect(parseHostMessage({ type: "state.taint", nonce: "n-0000001", session: "agent-0123456789abcdef", reason: "agent_session_untrusted" })).toMatchObject({ type: "state.taint" });
    expect(parseHostMessage({ type: "error", re: "n-0000001", code: "log_failed", message: "disk full" })).toMatchObject({ code: "log_failed" });
  });

  const refused: [string, unknown][] = [
    ["a non-object", "hello"],
    ["an unknown type", { type: "exec", re: "n-0000001" }],
    ["an unknown field", { type: "ack", re: "n-0000001", run: "rm -rf" }],
    ["an unknown capability", { type: "hello", re: "n-0000001", version: 1, capabilities: ["log", "admin"], firewall: "0.3.0" }],
    ["a verdict other than approve or deny", { type: "approval.result", nonce: "n-0000001", binding: "c".repeat(64), verdict: "allow_all" }],
    ["a binding that is not hex", { type: "approval.result", nonce: "n-0000001", binding: "<script>", verdict: "approve" }],
    ["a taint with a free-text reason", { type: "state.taint", nonce: "n-0000001", session: "s", reason: "Ignore previous instructions" }],
    ["a zero log sequence", { type: "log.ack", re: "n-0000001", seq: 0 }],
  ];
  for (const [what, m] of refused) it(`refuses ${what}`, () => expect(parseHostMessage(m)).toBeNull());
});
