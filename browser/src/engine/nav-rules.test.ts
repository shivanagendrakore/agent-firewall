import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { isCaptureHost } from "../vendor/firewall/engine/network.js";
import { decideNavigation } from "./navigation.js";
import {
  ALWAYS_MEANING,
  ALWAYS_RULES,
  CAPTURE_HOSTS,
  DATA_IN_URL_REGEX,
  dnrMatches,
  firstMatch,
  knownDomainList,
  SESSION_RULE_MAX,
  SESSION_RULE_MIN,
  sessionRuleSet,
  sessionRules,
  tenantHostsUnder,
  type DnrRule,
  type SessionRuleInput,
} from "./nav-rules.js";
import type { EffectiveTrust } from "./session.js";
import { DEFAULT_POLICY } from "./types.js";

const ON: SessionRuleInput = { agentMode: true, private: true, sessionDomains: ["mail.test", "shop.test"], suspiciousHosts: [], originSet: null };

function trust(over: Partial<EffectiveTrust> = {}): EffectiveTrust {
  return { agentMode: true, declaredClass: null, untrusted: true, private: true, quarantined: false, sessionDomains: new Set(["mail.test", "shop.test"]), grants: new Set(), prints: [], ...over };
}

const blocks = (rules: readonly DnrRule[], url: string, type: Parameters<typeof dnrMatches>[2] = "main_frame") => firstMatch(rules, url, type) !== null;

describe("navigation rules: the capture list", () => {
  it("matches the vendored firewall list exactly (the vendored module keeps it private)", () => {
    const src = readFileSync(fileURLToPath(new URL("../vendor/firewall/engine/network.ts", import.meta.url)), "utf8");
    const block = /const CAPTURE_HOSTS: readonly string\[\] = \[([\s\S]*?)\];/.exec(src)?.[1] ?? "";
    const vendored = [...block.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    expect(vendored.length).toBeGreaterThan(20);
    expect([...CAPTURE_HOSTS].sort()).toEqual([...vendored].sort());
    for (const h of CAPTURE_HOSTS) expect(isCaptureHost(h)).toBe(true);
  });
});

describe("navigation rules: RE2 and DNR limits", () => {
  const all = [...ALWAYS_RULES, ...sessionRules({ ...ON, suspiciousHosts: ["192.0.2.7"], originSet: ["shop.test"] })];
  it("every regex is RE2-safe (no lookaround or backreferences) and under 2 KB", () => {
    for (const r of all) {
      const re = r.condition.regexFilter;
      if (re === undefined) continue;
      expect(re).not.toMatch(/\(\?[=!<]|\\[1-9]/);
      expect(new TextEncoder().encode(re).length).toBeLessThan(2048);
      expect(() => new RegExp(re)).not.toThrow();
    }
  });
  it("uses only block actions, ids in their ranges, and names a type set for every session rule", () => {
    for (const r of ALWAYS_RULES) {
      expect(r.id).toBeLessThan(100);
      expect(r.action.type).toBe("block");
      expect(ALWAYS_MEANING[r.id]).toBeDefined();
    }
    const set = sessionRuleSet(ON);
    for (const r of set.rules) {
      expect(r.id).toBeGreaterThanOrEqual(SESSION_RULE_MIN);
      expect(r.id).toBeLessThanOrEqual(SESSION_RULE_MAX);
      // Without a type list a DNR rule skips main_frame, which is the opposite of what these rules need.
      expect(r.condition.resourceTypes ?? r.condition.excludedResourceTypes).toBeDefined();
      expect(set.meaning[r.id]).toMatch(/^nav\./);
    }
  });
  it("is deterministic for one input", () => {
    expect(JSON.stringify(sessionRules(ON))).toEqual(JSON.stringify(sessionRules(ON)));
  });
});

describe("navigation rules: always on (static ruleset)", () => {
  it("blocks capture hosts, webhook URLs and metadata addresses for subresources and frames", () => {
    for (const url of ["https://webhook.site/abc", "https://x.ngrok-free.app/c", "https://discord.com/api/webhooks/1/abc", "https://api.telegram.org/bot123:abc/sendMessage", "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/"]) {
      expect(blocks(ALWAYS_RULES, url, "image")).toBe(true);
      expect(blocks(ALWAYS_RULES, url, "sub_frame")).toBe(true);
      expect(blocks(ALWAYS_RULES, url, "xmlhttprequest")).toBe(true);
    }
  });
  it("leaves top-level navigations to the agent-mode rules (a person may open a paste site)", () => {
    expect(blocks(ALWAYS_RULES, "https://pastebin.com/raw/x")).toBe(false);
  });
  it("leaves look-alikes and ordinary hosts alone", () => {
    for (const url of ["https://notwebhook.site/", "https://discord.com/channels/1/2", "https://api.telegram.org/file/x", "https://shop.test/", "http://127.0.0.1:8080/"]) expect(blocks(ALWAYS_RULES, url, "image")).toBe(false);
  });
});

describe("navigation rules: agent mode (session rules)", () => {
  it("are empty with agent mode off", () => {
    expect(sessionRules({ ...ON, agentMode: false })).toEqual([]);
  });

  it("agree with decideNavigation on the cases the rules exist for", () => {
    const rules = [...ALWAYS_RULES, ...sessionRules(ON)];
    const t = trust();
    const cases: { url: string; blocked: boolean }[] = [
      { url: "https://webhook.site/1234", blocked: true },
      { url: "https://requestbin.net/r/abc?x=1", blocked: true },
      { url: "https://discordapp.com/api/webhooks/9/zz", blocked: true },
      { url: "http://169.254.169.254/latest/", blocked: true },
      { url: "http://203.0.113.9/collect", blocked: true },
      { url: "http://203.0.113.9:8080/", blocked: true },
      { url: "http://[2001:db8::1]/x", blocked: true },
      { url: "http://4a6f686e2e446f65406d61696c2e74657374.attacker.test/", blocked: true },
      { url: `https://attacker.test/c?d=${"QWxpY2UgPGFsaWNlQG1haWwudGVzdD4gT1RQIDQ4MjkxNyByZXNldA".repeat(1)}`, blocked: true },
      { url: `https://attacker.test/${"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6"}`, blocked: true },
      { url: `https://attacker.test/s?q=${"x".repeat(600)}`, blocked: true },
      // Known domains in the session are exempt from the data rule.
      { url: `https://mail.test/c?d=${"QWxpY2UgPGFsaWNlQG1haWwudGVzdD4gT1RQIDQ4MjkxNyByZXNldA"}`, blocked: false },
      // Ordinary navigation.
      { url: "https://docs.test/guide/installing-the-cli-on-ubuntu-22-04-and-later", blocked: false },
      { url: "https://news.test/search?q=red+running+shoes", blocked: false },
      { url: "http://127.0.0.1:3000/", blocked: false },
      { url: "http://[::1]:3000/", blocked: false },
      { url: "http://localhost:3000/", blocked: false },
      { url: "https://www.example.test/", blocked: false },
    ];
    for (const c of cases) {
      const d = decideNavigation({ url: c.url, resourceType: "main_frame" }, t, DEFAULT_POLICY);
      const engineBlocks = d.verdict === "deny" || d.verdict === "approve";
      expect({ url: c.url, engine: engineBlocks }).toEqual({ url: c.url, engine: c.blocked });
      expect({ url: c.url, dnr: blocks(rules, c.url) }).toEqual({ url: c.url, dnr: c.blocked });
    }
  });

  it("a session domain is not exempt from the capture, raw IP and DNS-exfil rules", () => {
    const rules = sessionRules({ ...ON, sessionDomains: ["attacker.test", "webhook.site"] });
    expect(blocks(rules, "https://webhook.site/x")).toBe(true);
    expect(blocks(rules, "http://0123456789abcdef0123.attacker.test/")).toBe(true);
  });

  it("the data rule applies only in a private session", () => {
    const url = "https://attacker.test/c?d=QWxpY2UgPGFsaWNlQG1haWwudGVzdD4gT1RQIDQ4MjkxNyByZXNldA";
    expect(blocks(sessionRules(ON), url)).toBe(true);
    expect(blocks(sessionRules({ ...ON, private: false }), url)).toBe(false);
    expect(decideNavigation({ url, resourceType: "main_frame" }, trust({ private: false }), DEFAULT_POLICY).verdict).toBe("allow");
  });

  it("the data rule covers frames but not images (benign pages send long ids to analytics)", () => {
    const url = "https://attacker.test/c?d=QWxpY2UgPGFsaWNlQG1haWwudGVzdD4gT1RQIDQ4MjkxNyByZXNldA";
    expect(blocks(sessionRules(ON), url, "sub_frame")).toBe(true);
    expect(blocks(sessionRules(ON), url, "image")).toBe(false);
  });

  it("raw IP and DNS-exfil rules cover every request type, including images", () => {
    expect(blocks(sessionRules(ON), "http://198.51.100.4/p.gif", "image")).toBe(true);
    expect(blocks(sessionRules(ON), "http://0123456789abcdef0123.attacker.test/p.gif", "image")).toBe(true);
  });

  it("exact hosts seen in links are blocked even when the coarse regex misses them", () => {
    const host = "k7q2x9w4m8z3v6b1n5c0.attacker.test";
    expect(blocks(sessionRules(ON), `http://${host}/`)).toBe(false);
    expect(blocks(sessionRules({ ...ON, suspiciousHosts: [host] }), `http://${host}/`)).toBe(true);
  });

  it("drops malformed exact hosts instead of handing Chrome an invalid rule", () => {
    const r = sessionRules({ ...ON, suspiciousHosts: ["bad host", "ok.example.test", "x/y"] });
    const exact = r.find((x) => x.condition.requestDomains?.includes("ok.example.test"));
    expect(exact?.condition.requestDomains).toEqual(["ok.example.test", "ok.example.test."]);
  });

  it("keeps the good exact hosts when others are malformed, and names a host and its trailing-dot form once each", () => {
    const r = sessionRules({ ...ON, suspiciousHosts: ["-bad.test", "a..b.test", "good.test.", "good.test", "x".repeat(300)] });
    const exact = r.find((x) => x.condition.requestDomains?.includes("good.test"));
    expect(exact?.condition.requestDomains).toEqual(["good.test", "good.test."]);
  });

  it("blocks a capture or metadata host written with a trailing dot (session rules)", () => {
    const rules = sessionRules(ON);
    expect(blocks(rules, "https://webhook.site./x")).toBe(true);
    expect(blocks(rules, "http://metadata.google.internal./computeMetadata/v1/")).toBe(true);
  });

  it("the Discord, Telegram, metadata-IP and raw-IP rules see through credentials in the address and a trailing dot", () => {
    const all = [...ALWAYS_RULES, ...sessionRules(ON)];
    for (const u of [
      "https://discord.com/api/webhooks/1/abc",
      "https://user:pw@discord.com/api/webhooks/1/abc",
      "https://discord.com./api/webhooks/1/abc",
      "https://x@canary.discordapp.com:443/api/webhooks/1/abc",
      "https://x@api.telegram.org/bot123456:ABC/sendMessage",
      "https://api.telegram.org./bot123456:ABC/sendMessage",
      "http://x@169.254.169.254/latest/meta-data/",
      "http://x:y@93.184.216.34/p",
    ]) expect(blocks(all, u, "xmlhttprequest"), u).toBe(true);
    // Credentials that only look like the host do not make a different host match.
    expect(blocks(all, "https://discord.com@shop.test/api/webhooks/1/abc", "xmlhttprequest")).toBe(false);
  });

  it("the agent origin set blocks top-level navigations outside it, and only top-level ones", () => {
    const rules = sessionRules({ ...ON, private: false, originSet: ["shop.test", "*.docs.test"] });
    expect(blocks(rules, "https://shop.test/cart")).toBe(false);
    expect(blocks(rules, "https://api.docs.test/")).toBe(false);
    expect(blocks(rules, "https://news.test/")).toBe(true);
    expect(blocks(rules, "https://news.test/a.png", "image")).toBe(false);
  });

  it("the coarse data regex does not match slugs, search phrases or short ids", () => {
    const re = new RegExp(DATA_IN_URL_REGEX, "i");
    for (const url of ["https://docs.test/how-to-configure-the-reverse-proxy-for-websocket-connections", "https://shop.test/search?q=waterproof+hiking+boots+for+women+size+8+wide", "https://news.test/2026/10/11/story?id=8f3a2c", "https://mail.test/#inbox"]) expect(re.test(url)).toBe(false);
  });
});

describe("the DNR matcher used for explanations", () => {
  it("follows DNR's default: no type list means every type but main_frame", () => {
    const r: DnrRule = { id: 1, priority: 1, action: { type: "block" }, condition: { requestDomains: ["attacker.test"] } };
    expect(dnrMatches(r, "https://attacker.test/", "main_frame")).toBe(false);
    expect(dnrMatches(r, "https://x.attacker.test/", "image")).toBe(true);
    expect(dnrMatches(r, "https://notattacker.test/", "image")).toBe(false);
    expect(dnrMatches(r, "not a url", "image")).toBe(false);
  });
  it("picks the highest-priority match", () => {
    const a: DnrRule = { id: 1, priority: 1, action: { type: "block" }, condition: { regexFilter: "^https://", resourceTypes: ["main_frame"] } };
    const b: DnrRule = { id: 2, priority: 9, action: { type: "block" }, condition: { regexFilter: "attacker", resourceTypes: ["main_frame"] } };
    expect(firstMatch([a, b], "https://attacker.test/", "main_frame")?.id).toBe(2);
  });
});

describe("RR1: tenant hosts and public suffixes in the data-in-URL rule", () => {
  const input = (domains: string[]): SessionRuleInput => ({ agentMode: true, private: true, sessionDomains: domains, suspiciousHosts: [], originSet: null });
  const DATA = "QWxleCBSaXZlcmEgPGFsZXhAbWFpbC50ZXN0PiBPVFAgNDgyOTE3";

  it("a known google.com still leaves Forms, Apps Script, Sites and Groups blocked; mail.google.com stays exempt", () => {
    const rules = sessionRules(input(["google.com"]));
    for (const h of ["docs.google.com", "script.google.com", "sites.google.com", "groups.google.com", "colab.research.google.com"]) {
      expect(firstMatch(rules, `https://${h}/x?d=${DATA}`, "main_frame"), h).not.toBeNull();
    }
    expect(firstMatch(rules, `https://mail.google.com/x?d=${DATA}`, "main_frame")).toBeNull();
  });

  it("a tenant host the session itself showed is exempt like any known domain", () => {
    const rules = sessionRules(input(["google.com", "docs.google.com"]));
    expect(firstMatch(rules, `https://docs.google.com/forms/x?d=${DATA}`, "main_frame")).toBeNull();
    expect(firstMatch(rules, `https://script.google.com/x?d=${DATA}`, "main_frame")).not.toBeNull();
  });

  it("no tenant rule when no known domain has tenant hosts", () => {
    expect(tenantHostsUnder(["shop.test"])).toEqual([]);
    expect(sessionRules(input(["shop.test"])).filter((r) => r.condition.requestDomains !== undefined && r.condition.regexFilter === DATA_IN_URL_REGEX)).toEqual([]);
  });

  it("a known public suffix is never an exemption (it would exempt every site under it)", () => {
    expect(knownDomainList(["github.io", "shop.test", ""])).toEqual(["shop.test"]);
    const rules = sessionRules(input(["github.io"]));
    expect(firstMatch(rules, `https://attacker.github.io/x?d=${DATA}`, "main_frame")).not.toBeNull();
  });
});
