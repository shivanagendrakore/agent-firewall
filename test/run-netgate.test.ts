/**
 * v0.3 `run`: the network policy (pure). The host list is the one doctor --fix derives for Claude
 * Code's sandbox; the proxy's judgement refuses everything else, including the refusal cases a
 * listed pattern cannot override; the run's budgets refuse once reached.
 */
import { describe, expect, it } from "vitest";
import { classifyAnswer, internalAddress, judgeHost, RunBudgets, runNetPolicy } from "../src/engine/netgate.js";
import { profileFromPolicy } from "../src/engine/sandbox.js";
import { defaultConfig } from "../src/policy.js";
import type { FirewallConfig } from "../src/types.js";

const cfg = (over: Partial<FirewallConfig> = {}): FirewallConfig => ({ ...defaultConfig(), ...over });

describe("runNetPolicy: the same hosts as Claude Code's sandbox profile", () => {
  it("default policy: exactly profileFromPolicy's allowedDomains", () => {
    const c = cfg();
    const { policy, problems } = runNetPolicy(c);
    expect(problems).toEqual([]);
    expect(policy.allowed.map((h) => h.domain)).toEqual(profileFromPolicy(c).profile.network.allowedDomains);
    expect(policy.allowed.length).toBeGreaterThan(10);
  });
  it("--send-host adds send hosts and makes them budget-exempt", () => {
    const { policy } = runNetPolicy(cfg(), { sendHosts: ["api.anthropic.com"] });
    expect(policy.allowed.find((h) => h.domain === "api.anthropic.com")?.kind).toBe("send");
    expect(policy.exempt).toContain("api.anthropic.com");
  });
  it("refuses a --send-host the derivation would leave out (IP, loopback, metadata, capture, denyHosts, not a name)", () => {
    for (const bad of ["10.0.0.1", "127.0.0.1", "localhost", "169.254.169.254", "metadata.google.internal", "webhook.site", "evil.example", "not a host"]) {
      const { problems } = runNetPolicy(cfg({ denyHosts: ["evil.example"] }), { sendHosts: [bad] });
      expect(problems.length, bad).toBe(1);
      expect(problems[0]).toContain(`--send-host ${bad}`);
    }
  });
  it("policy entries the derivation drops are reported, not admitted", () => {
    const { policy } = runNetPolicy(cfg({ fetchAllowHosts: ["ok.example", "192.168.1.5", "*.google.internal"] }));
    expect(policy.allowed.map((h) => h.domain)).toEqual(["*.ok.example", "ok.example"]);
    expect(policy.dropped.map((d) => d.pattern).sort()).toEqual(["*.google.internal", "192.168.1.5"]);
  });
});

describe("judgeHost", () => {
  const { policy } = runNetPolicy(cfg({ fetchAllowHosts: ["=github.com", "registry.npmjs.org", "*.example.org"], sendAllowHosts: ["api.example.net"], denyHosts: ["bad.example.org"] }));
  it("admits listed hosts in the sandbox's syntax", () => {
    expect(judgeHost(policy, "github.com", 443)).toMatchObject({ verdict: "allow", kind: "fetch-only" });
    expect(judgeHost(policy, "GitHub.com.", 443).verdict).toBe("allow");
    expect(judgeHost(policy, "registry.npmjs.org", 443).verdict).toBe("allow");
    expect(judgeHost(policy, "a.registry.npmjs.org", 443).verdict).toBe("allow");
    expect(judgeHost(policy, "x.example.org", 80).verdict).toBe("allow");
    expect(judgeHost(policy, "api.example.net", 443)).toMatchObject({ verdict: "allow", kind: "send" });
  });
  it("refuses what is not listed (=exact does not cover subdomains, *.x does not cover x)", () => {
    expect(judgeHost(policy, "api.github.com", 443)).toMatchObject({ verdict: "deny", why: "not-listed" });
    expect(judgeHost(policy, "example.org", 443)).toMatchObject({ verdict: "deny", why: "not-listed" });
    expect(judgeHost(policy, "attacker.example", 443).reason).toContain("fetchAllowHosts");
  });
  it("denyHosts wins over an allowed wildcard", () => {
    expect(judgeHost(policy, "bad.example.org", 443)).toMatchObject({ verdict: "deny", why: "denied-host" });
    expect(judgeHost(policy, "x.bad.example.org", 443)).toMatchObject({ verdict: "deny", why: "denied-host" });
  });
  it("refuses ports other than 443 and 80", () => {
    for (const p of [22, 8080, 0, 65536, 3.5]) expect(judgeHost(policy, "github.com", p)).toMatchObject({ verdict: "deny", why: "port" });
  });
  it("refuses IP addresses in every spelling, loopback, metadata and capture hosts with their rules", () => {
    for (const ip of ["140.82.112.3", "0x8c.0x52.0x70.0x3", "2354212867", "0214.0122.0160.03", "[2606:4700::1111]", "2606:4700::1111"]) expect(judgeHost(policy, ip, 443), ip).toMatchObject({ verdict: "deny", why: "raw-ip", rule: "FW-RAW-IP" });
    for (const lo of ["localhost", "127.0.0.1", "app.localhost", "[::1]", "0.0.0.0"]) expect(judgeHost(policy, lo, 80), lo).toMatchObject({ verdict: "deny", why: "loopback" });
    for (const md of ["169.254.169.254", "0xa9fea9fe", "metadata.google.internal", "100.100.100.200"]) expect(judgeHost(policy, md, 80), md).toMatchObject({ verdict: "deny", why: "metadata", rule: "FW-METADATA" });
    expect(judgeHost(policy, "abc.ngrok.io", 443)).toMatchObject({ verdict: "deny", why: "capture", rule: "FW-CAPTURE-HOST" });
  });
  it("refuses malformed host names", () => {
    for (const h of ["", "a b", "x/y", "a\u0000b", "é.example", "a".repeat(254)]) expect(judgeHost(policy, h, 443).why, JSON.stringify(h)).toBe("bad-host");
  });
  it("a capture host listed in fetchAllowHosts is still refused", () => {
    const { policy: p } = runNetPolicy(cfg({ fetchAllowHosts: ["webhook.site"] }));
    expect(judgeHost(p, "webhook.site", 443).verdict).toBe("deny");
  });
});

describe("internalAddress (DNS answers the proxy refuses)", () => {
  it("refuses loopback, unspecified, link-local, multicast and metadata, in v4, v6 and mapped forms", () => {
    for (const a of ["127.0.0.1", "127.1.2.3", "0.0.0.0", "0.1.2.3", "169.254.1.1", "169.254.169.254", "224.0.0.1", "255.255.255.255", "::1", "::", "fe80::1", "febf::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:0:127.0.0.1", "::127.0.0.1", "fd00:ec2::254", "100.100.100.200"]) expect(internalAddress(a), a).not.toBeNull();
  });
  it("refuses private, CGNAT and unique-local answers by default (DNS rebinding to a company network)", () => {
    for (const a of ["10.1.2.3", "10.255.255.255", "172.16.5.4", "172.31.0.1", "192.168.0.10", "100.64.0.1", "100.127.255.254", "fc00::1", "fd12:3456::1", "::ffff:10.0.0.1", "::ffff:c0a8:1", "::ffff:0:192.168.1.1", "::ffff:100.64.1.1"]) expect(internalAddress(a, "public.example"), a).toMatch(/private|carrier-grade|unique local/);
  });
  it("allows public addresses, including the neighbours of the private ranges", () => {
    for (const a of ["140.82.112.3", "8.8.8.8", "172.15.255.255", "172.32.0.1", "192.169.0.1", "100.63.255.255", "100.128.0.1", "11.0.0.1", "2606:4700::1111", "fbff::1", "fe00::1", "::ffff:8.8.8.8"]) expect(internalAddress(a), a).toBeNull();
  });
  it("run.privateHosts lets a listed name resolve to a private address, and nothing more", () => {
    const local = { loopback: false, privateHosts: ["corp.example", "=git.other.example"] };
    expect(internalAddress("10.1.2.3", "git.corp.example", local)).toBeNull();
    expect(internalAddress("fd00::5", "corp.example", local)).toBeNull();
    expect(internalAddress("192.168.1.1", "git.other.example", local)).toBeNull();
    expect(internalAddress("192.168.1.1", "x.git.other.example", local)).not.toBeNull();
    expect(internalAddress("10.1.2.3", "github.com", local)).not.toBeNull();
    // A private host's name does not unlock loopback, link-local or metadata answers.
    for (const a of ["127.0.0.1", "169.254.169.254", "fe80::1", "0.0.0.0"]) expect(internalAddress(a, "git.corp.example", local), a).not.toBeNull();
  });
  it("--allow-localhost (loopback: true) admits loopback answers only", () => {
    const local = { loopback: true, privateHosts: [] };
    for (const a of ["127.0.0.1", "::1", "::ffff:127.0.0.1"]) expect(internalAddress(a, "dev.example", local), a).toBeNull();
    for (const a of ["10.0.0.1", "169.254.169.254", "fe80::1"]) expect(internalAddress(a, "dev.example", local), a).not.toBeNull();
  });
  it("classifyAnswer names the class", () => {
    expect(classifyAnswer("10.0.0.1").kind).toBe("private");
    expect(classifyAnswer("127.0.0.1").kind).toBe("loopback");
    expect(classifyAnswer("169.254.169.254").kind).toBe("never");
    expect(classifyAnswer("1.1.1.1").kind).toBe("public");
    expect(classifyAnswer("300.1.1.1").kind).toBe("never");
  });
  it("garbage is not an address", () => {
    expect(internalAddress("example.com")).toBe("not an address");
    expect(internalAddress("1:2:3")).toBe("not an address");
  });
});

describe("RunBudgets", () => {
  const mk = (over: Partial<FirewallConfig> = {}): RunBudgets => new RunBudgets(runNetPolicy(cfg({ fetchAllowHosts: ["a.example", "b.example", "registry.npmjs.org", "=github.com"], sendAllowHosts: ["send.example"], ...over }), { sendHosts: ["model.example"] }).policy);
  it("tiers: exempt (send hosts, --send-host, exemptHosts), registry, other", () => {
    const b = new RunBudgets(runNetPolicy(cfg({ sendAllowHosts: ["send.example"], budgets: { ...defaultConfig().budgets, exemptHosts: ["cdn.example"] } }), { sendHosts: ["model.example"] }).policy);
    expect(b.tier("send.example")).toBe("exempt");
    expect(b.tier("model.example")).toBe("exempt");
    expect(b.tier("cdn.example")).toBe("exempt");
    expect(b.tier("registry.npmjs.org")).toBe("registry");
    expect(b.tier("github.com")).toBe("registry");
    expect(b.tier("api.github.com")).toBe("other");
    expect(b.tier("a.example")).toBe("other");
  });
  it("64 KB per other host: the byte that crosses it is a hit, and the host stays blocked", () => {
    const b = mk();
    expect(b.addBytes("a.example", 65536)).toBeNull();
    const hit = b.addBytes("a.example", 1);
    expect(hit).toMatchObject({ rule: "FW-BUDGET-BYTES", key: "bytes:a.example", limit: 65536 });
    expect(b.blocked("a.example")?.key).toBe("bytes:a.example");
    expect(b.admitRequest("a.example", 0)?.key).toBe("bytes:a.example");
    expect(b.blocked("b.example")).toBeNull();
  });
  it("256 KB across other hosts blocks them all; registries and exempt hosts are unaffected", () => {
    const b = mk();
    for (const h of ["h1.example", "h2.example", "h3.example", "h4.example"]) expect(b.addBytes(h, 65536)).toBeNull();
    expect(b.addBytes("h5.example", 10)?.key).toBe("bytes:*");
    expect(b.blocked("a.example")?.key).toBe("bytes:*");
    expect(b.blocked("registry.npmjs.org")).toBeNull();
    expect(b.addBytes("send.example", 10_000_000)).toBeNull();
  });
  it("registries and code hosts share the trusted total (4 MB)", () => {
    const b = mk();
    expect(b.addBytes("registry.npmjs.org", 3 * 1024 * 1024)).toBeNull();
    expect(b.addBytes("github.com", 1024 * 1024)).toBeNull();
    expect(b.addBytes("github.com", 1)).toMatchObject({ key: "bytes:registries", limit: 4194304 });
    expect(b.blocked("registry.npmjs.org")?.key).toBe("bytes:registries");
    expect(b.blocked("a.example")).toBeNull();
  });
  it("requests per host in a sliding 10 minutes: 40 for other hosts, 300 for registries", () => {
    const b = mk();
    for (let i = 0; i < 40; i++) expect(b.admitRequest("a.example", i)).toBeNull();
    expect(b.admitRequest("a.example", 41)).toMatchObject({ rule: "FW-BUDGET-REQUESTS", key: "req:a.example", limit: 40 });
    // Once reached it stays reached for the run, even after the window.
    expect(b.admitRequest("a.example", 11 * 60 * 1000)?.key).toBe("req:a.example");
    for (let i = 0; i < 300; i++) expect(b.admitRequest("registry.npmjs.org", i)).toBeNull();
    expect(b.admitRequest("registry.npmjs.org", 301)?.limit).toBe(300);
  });
  it("old requests leave the window", () => {
    const b = mk();
    for (let i = 0; i < 40; i++) expect(b.admitRequest("b.example", i * 1000)).toBeNull();
    expect(b.admitRequest("b.example", 10 * 60 * 1000 + 5000)).toBeNull();
  });
  it("budgets.enabled false counts nothing", () => {
    const b = mk({ budgets: { ...defaultConfig().budgets, enabled: false } });
    expect(b.addBytes("a.example", 10_000_000)).toBeNull();
    for (let i = 0; i < 100; i++) expect(b.admitRequest("a.example", i)).toBeNull();
  });
  it("policy limits are honoured", () => {
    const b = mk({ budgets: { ...defaultConfig().budgets, untrusted: { ...defaultConfig().budgets.untrusted, bytesPerHost: 10 } } });
    expect(b.addBytes("a.example", 11)?.limit).toBe(10);
  });
});
