import { describe, expect, it } from "vitest";
import { emptyState, pageShown, startAgentSession } from "../engine/session.js";
import { DEFAULT_POLICY } from "../engine/types.js";
import { allowOnceRule, explanationPath, NAV_ALLOW_RULE_MAX, NAV_ALLOW_RULE_MIN, ruleInputOf } from "./guard-nav.js";
import { SESSION_RULE_MAX } from "../engine/nav-rules.js";

describe("guard/nav worker helpers", () => {
  it("builds the session-rule input from the agent session", () => {
    expect(ruleInputOf(emptyState(), [], DEFAULT_POLICY).agentMode).toBe(false);
    let s = startAgentSession(emptyState(), { now: 1, tabIds: [1] });
    s = pageShown(s, 1, { url: "https://mail.google.com/mail/u/0/" }, DEFAULT_POLICY);
    const input = ruleInputOf(s, ["192.0.2.1"], DEFAULT_POLICY);
    expect(input).toMatchObject({ agentMode: true, private: true, suspiciousHosts: ["192.0.2.1"], originSet: null });
    expect(input.sessionDomains).toContain("google.com");
  });

  it("a private tab outside the session still makes the browser-wide rules private", () => {
    let s = pageShown(emptyState(), 7, { url: "https://mail.google.com/" }, DEFAULT_POLICY);
    s = startAgentSession(s, { now: 1, tabIds: [1] });
    expect(ruleInputOf(s, [], DEFAULT_POLICY).private).toBe(true);
  });

  it("the explanation URL carries the rule, the host and a length, never the path or query", () => {
    const p = explanationPath("nav.high_entropy_new_origin", "https://attacker.test/c/OTP-482917?d=QWxpY2U&e=alice%40mail.test");
    expect(p.startsWith("blocked.html?")).toBe(true);
    const q = new URLSearchParams(p.slice("blocked.html?".length));
    expect(q.get("rule")).toBe("nav.high_entropy_new_origin");
    expect(q.get("host")).toBe("attacker.test");
    expect(Number(q.get("chars"))).toBeGreaterThan(10);
    expect(p).not.toMatch(/482917|QWxpY2U|alice/);
    expect(explanationPath("nav.capture_host", "not a url")).toContain("host=&");
  });

  it("an approvable block says so in the explanation URL (and only then)", () => {
    expect(new URLSearchParams(explanationPath("nav.suspicious_host", "http://192.0.2.1/x", true).split("?")[1]).get("approval")).toBe("1");
    expect(explanationPath("nav.suspicious_host", "http://192.0.2.1/x")).not.toContain("approval");
  });

  it("an approved navigation's pass is one tab, one host, top level, above every block rule, outside their id range", () => {
    const r = allowOnceRule(NAV_ALLOW_RULE_MIN, 7, "https://attacker.test/c?d=1");
    expect(r).toMatchObject({ id: NAV_ALLOW_RULE_MIN, action: { type: "allow" }, condition: { tabIds: [7], requestDomains: ["attacker.test"], resourceTypes: ["main_frame"] } });
    expect(r?.priority).toBeGreaterThan(1000);
    expect(NAV_ALLOW_RULE_MIN).toBeGreaterThan(SESSION_RULE_MAX);
    expect(NAV_ALLOW_RULE_MAX).toBeGreaterThan(NAV_ALLOW_RULE_MIN);
    expect(allowOnceRule(NAV_ALLOW_RULE_MIN, 7, "not a url")).toBeNull();
  });
});
