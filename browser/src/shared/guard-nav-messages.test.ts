import { describe, expect, it } from "vitest";
import { GUARD_NAV_LIMITS, parseContentMessage } from "./messages.js";

describe("guard/nav messages", () => {
  it("accepts tab.mode, nav.hosts and nav.blocked in their shapes", () => {
    expect(parseContentMessage({ type: "tab.mode" })).toEqual({ type: "tab.mode" });
    expect(parseContentMessage({ type: "nav.hosts", hosts: ["192.0.2.1", "abcdef0123456789aa.attacker.test", "[2001:db8::1]"] })).toEqual({ type: "nav.hosts", hosts: ["192.0.2.1", "abcdef0123456789aa.attacker.test", "[2001:db8::1]"] });
    expect(parseContentMessage({ type: "nav.blocked", rule: "nav.script_url", scheme: "javascript" })).toEqual({ type: "nav.blocked", rule: "nav.script_url", scheme: "javascript" });
  });

  it("refuses hosts that are not host names (paths, queries, spaces, upper bounds)", () => {
    for (const hosts of [["attacker.test/x?d=secret"], ["a b"], [""], [1], "attacker.test", Array.from({ length: GUARD_NAV_LIMITS.hosts + 1 }, () => "a.test"), ["a".repeat(254)], ["UPPER.test"]]) {
      expect(parseContentMessage({ type: "nav.hosts", hosts })).toBeNull();
    }
  });

  it("refuses nav.blocked for any other rule or scheme", () => {
    expect(parseContentMessage({ type: "nav.blocked", rule: "nav.capture_host", scheme: "javascript" })).toBeNull();
    expect(parseContentMessage({ type: "nav.blocked", rule: "nav.script_url", scheme: "http" })).toBeNull();
  });

  it("still refuses unknown types", () => {
    expect(parseContentMessage({ type: "nav.unblock" })).toBeNull();
    expect(parseContentMessage({ type: "tab.setMode", on: false })).toBeNull();
  });
});
