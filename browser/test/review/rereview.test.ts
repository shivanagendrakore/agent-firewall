/**
 * Independent enforcement re-review of the merged v0.1 build (main d6f4353),
 * after the 27 engine-review findings were fixed. Focus: the integration seams
 * and the new code (sender-derived leak hosts, salted OTP prints, PSL/tenant
 * hosts, approvals across worker restarts, the blocked-navigation approval, the
 * agent-mode switch, the log, message bounds, the privacy policy's promises).
 *
 * Every test states the correct behaviour. Each finding was first written as
 * an `it.fails` with a one-line reason; every one is now fixed and is a plain
 * `it`, with its "Fixed:" line saying how. RR8 and RR11 were restated against
 * the fixed code path (the original tests exercised the faulty call itself).
 *
 * Finding ids (RR1..) match the re-review report. Browser-only findings are in
 * test/e2e/rereview.spec.ts.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { registrableDomain } from "../../src/engine/domain.js";
import { actionFingerprint } from "../../src/engine/fingerprint.js";
import { decideLeakLocally, leakContextOf, leakSnapshot } from "../../src/engine/leak.js";
import { decideNavigation } from "../../src/engine/navigation.js";
import { dnrMatches, firstMatch, sessionRules, type DnrRule } from "../../src/engine/nav-rules.js";
import { printsFor } from "../../src/engine/private-data.js";
import { effectiveTrust, emptyState, pageShown, privateDataShown, startAgentSession, type BrowserState } from "../../src/engine/session.js";
import { submit } from "../../src/engine/test-helpers.js";
import { DEFAULT_POLICY, type Decision, type Policy } from "../../src/engine/types.js";
import { parseContentMessage, parseUiMessage, parseWorkerMessage, withinMessageBounds } from "../../src/shared/messages.js";
import { actionMeta, navigationMeta } from "../../src/worker/approval-view.js";
import { createApprovalService, MAX_PENDING_TOTAL } from "../../src/worker/approvals.js";
import { allowOnceRule, createGuardNav, NAV_ALLOW_RULE_MIN, NAV_PASS_KEY, ruleInputOf, type NavApprovalRequest } from "../../src/worker/guard-nav.js";
import { createLeakAgent } from "../../src/worker/leak-agent.js";
import { createLog, createMemoryBackend, type LogEntry } from "../../src/worker/log.js";
import { applySettingsPatch, createSettingsStore, DEFAULT_SETTINGS, policyWith, retentionFrom } from "../../src/worker/settings.js";
import { createStateStore, type KeyValueArea } from "../../src/worker/state.js";

const P: Policy = DEFAULT_POLICY;
const SALT = "rereview-session-salt";
const DAY = 24 * 60 * 60 * 1000;
const DATA = "QWxleCBSaXZlcmEgPGFsZXhAbWFpbC50ZXN0PiBPVFAgNDgyOTE3";
const OTP = "482915";
const OTP_PAGE = `Your verification code is ${OTP}. It expires in 10 minutes.`;
const ROOT = resolve(fileURLToPath(new URL("../../", import.meta.url)));

/** An in-memory chrome.storage area (values kept by reference, like the session area's structured clone for our purposes). */
function memoryArea(): KeyValueArea & { data: Record<string, unknown> } {
  const data: Record<string, unknown> = {};
  return {
    data,
    get: async (k) => ({ [k]: data[k] }),
    set: async (items) => {
      Object.assign(data, structuredClone(items));
    },
  };
}

/** An agent session whose tab 1 read a mail page (private) with the given extra pages shown. */
function privateSession(): BrowserState {
  let s = startAgentSession(emptyState(), { now: 1, tabIds: [1, 2], printSalt: SALT });
  s = pageShown(s, 1, { url: "https://mail.google.com/mail/u/0/" }, P);
  s = privateDataShown(s, 1, printsFor(OTP_PAGE, "mail.google.com", SALT).map((p) => ({ ...p, domain: "google.com" })));
  return s;
}

// ---------------------------------------------------------------------------
// RR1. Navigation: the DNR rule and the engine disagree on tenant hosts
// ---------------------------------------------------------------------------

describe("RR1: the data-in-URL rule honours tenant hosts", () => {
  const s = privateSession();
  const rules = sessionRules(ruleInputOf(s, [], P));
  const appsScript = `https://script.google.com/macros/s/AKfycbz0attacker/exec?d=${DATA}`;
  const form = `https://docs.google.com/forms/d/e/1FAIpQLSattacker/formResponse?entry.1=${DATA}`;

  it("the engine says a data-carrying URL to Apps Script or a Google Form is new to a session that read Gmail (approve)", () => {
    expect(registrableDomain("script.google.com")).not.toBe(registrableDomain("mail.google.com"));
    expect(decideNavigation({ url: appsScript, resourceType: "main_frame" }, effectiveTrust(s, 1), P).verdict).toBe("approve");
    expect(decideNavigation({ url: form, resourceType: "main_frame" }, effectiveTrust(s, 1), P).verdict).toBe("approve");
  });

  it("RR1: a session rule blocks it (Chrome enforces DNR, not the engine)", () => {
    // Fixed: tenant hosts under a known domain get their own rule (requestDomains), which the parent's exclusion does not reach.
    expect(firstMatch(rules, appsScript, "main_frame")).not.toBeNull();
    expect(firstMatch(rules, form, "main_frame")).not.toBeNull();
  });

  it("control: the same URL on an unrelated host is blocked by the session rule", () => {
    expect(firstMatch(rules, `https://attacker.test/c?d=${DATA}`, "main_frame")).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// RR2. Leak guard: a page can flood the session's prints past the context bound
// ---------------------------------------------------------------------------

describe("RR2: the leak context still reaches every tab when a page shows thousands of private-looking strings", () => {
  const emails = Array.from({ length: 3000 }, (_, i) => `member${i}@flood${i}.example`).join(" ");

  function flooded(): BrowserState {
    let s = startAgentSession(emptyState(), { now: 1, tabIds: [1, 2], printSalt: SALT });
    s = pageShown(s, 2, { url: "https://attacker.test/form" }, P);
    // What the content script sends: printsFor over the page text, at most 2,000 per message.
    const prints = printsFor(emails, "attacker.test", SALT);
    s = privateDataShown(s, 2, prints.slice(0, 2000));
    s = privateDataShown(s, 2, prints.slice(2000));
    // Then the agent reads the code on mail.
    return privateDataShown(s, 1, printsFor(OTP_PAGE, "mail.test", SALT).map((p) => ({ ...p, domain: "mail.test" })));
  }

  it("RR2: the context pushed to the attacker tab after the code was shown parses in the content script", () => {
    // Fixed: the session keeps at most MAX_SESSION_PRINTS (the content script's bound), oldest long prints evicted first.
    const ctx = leakContextOf(effectiveTrust(flooded(), 2), P);
    expect(parseWorkerMessage({ type: "leak.context", context: ctx })).not.toBeNull();
  });

  it("why it mattered: a context without the code's print lets the code through locally; the capped context has it and holds it", () => {
    let s = startAgentSession(emptyState(), { now: 1, tabIds: [1, 2], printSalt: SALT });
    s = privateDataShown(s, 2, printsFor(emails, "attacker.test", SALT).slice(0, 2000));
    const stale = leakContextOf(effectiveTrust(s, 2), P);
    expect(parseWorkerMessage({ type: "leak.context", context: stale })).not.toBeNull();
    expect(decideLeakLocally({ text: OTP, destinationHost: "attacker.test", frameHost: "attacker.test" }, stale, P).decision.verdict).toBe("allow");
    // The capped session context carries the code's print. (And a refused context now marks the frame stale, so it asks the worker: RR16.)
    expect(decideLeakLocally({ text: OTP, destinationHost: "attacker.test", frameHost: "attacker.test" }, leakContextOf(effectiveTrust(flooded(), 2), P), P).decision.verdict).toBe("approve");
  });
});

// ---------------------------------------------------------------------------
// RR6. Navigation: the domain that served the injection is never "new"
// ---------------------------------------------------------------------------

describe("RR6: data in the URL back to the site that injected the agent", () => {
  it("RR6: a private session that was quarantined by attacker.test still needs approval to send data to attacker.test", () => {
    // Fixed: a domain whose page got a quarantine verdict is an injector; while the session is quarantined it is never a known destination.
    let s = privateSession();
    s = pageShown(s, 2, { url: "https://attacker.test/post", verdict: "quarantine" }, P);
    const d = decideNavigation({ url: `https://attacker.test/c?d=${DATA}`, resourceType: "main_frame" }, effectiveTrust(s, 2), P);
    expect(d.verdict).not.toBe("allow");
    // The browser's rule agrees: attacker.test is not on the rule's exemption list.
    expect(firstMatch(sessionRules(ruleInputOf(s, [], P)), `https://attacker.test/c?d=${DATA}`, "main_frame")).not.toBeNull();
  });

  it("control: a site that only showed a page (no quarantine) stays a known destination", () => {
    let s = privateSession();
    s = pageShown(s, 2, { url: "https://shop.test/" }, P);
    expect(decideNavigation({ url: `https://shop.test/c?d=${DATA}`, resourceType: "main_frame" }, effectiveTrust(s, 2), P).verdict).toBe("allow");
  });
});

// ---------------------------------------------------------------------------
// RR7. The one-time navigation pass
// ---------------------------------------------------------------------------

type Listener = (...args: unknown[]) => unknown;

/** Just enough of chrome for guard-nav: DNR session rules and session storage survive a "worker restart"; listeners do not. */
function fakeChrome() {
  const rules = new Map<number, chrome.declarativeNetRequest.Rule>();
  const sessionArea = memoryArea();
  let listeners: Record<string, Listener[]> = {};
  const tabUpdates: { tabId: number; url: string }[] = [];
  const on = (name: string) => ({ addListener: (fn: Listener) => void (listeners[name] ??= []).push(fn) });
  const api = {
    runtime: { id: "abcdefghijklmnopabcdefghijklmnop", getURL: (p: string) => `chrome-extension://abcdefghijklmnopabcdefghijklmnop/${p}` },
    declarativeNetRequest: {
      getSessionRules: async () => [...rules.values()],
      updateSessionRules: async (o: { removeRuleIds?: number[]; addRules?: chrome.declarativeNetRequest.Rule[] }) => {
        for (const id of o.removeRuleIds ?? []) rules.delete(id);
        for (const r of o.addRules ?? []) rules.set(r.id, r);
      },
    },
    tabs: {
      update: async (tabId: number, p: { url: string }) => {
        tabUpdates.push({ tabId, url: p.url });
        return {};
      },
      onRemoved: on("tabs.onRemoved"),
      onCreated: on("tabs.onCreated"),
    },
    webNavigation: { onCommitted: on("onCommitted"), onErrorOccurred: on("onErrorOccurred") },
    storage: { session: sessionArea, onChanged: on("storage.onChanged") },
  };
  return {
    api,
    rules,
    tabUpdates,
    sessionArea,
    fire: (name: string, ...args: unknown[]) => (listeners[name] ?? []).forEach((fn) => fn(...args)),
    /** The worker is stopped: its listeners and memory go, Chrome's rules and session storage stay. */
    restart: () => {
      listeners = {};
    },
  };
}

const flush = async (): Promise<void> => {
  for (let i = 0; i < 50; i++) await Promise.resolve();
};

describe("RR7: the approved navigation's one-time pass", () => {
  const url = `http://attacker.test/landing?d=${DATA}`;
  let fake: ReturnType<typeof fakeChrome>;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    fake = fakeChrome();
    vi.stubGlobal("chrome", fake.api);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  async function blockedThenApproved() {
    const store = createStateStore(fake.sessionArea);
    await store.update(() => privateSession());
    const deps = { store, policy: async () => P, log: () => undefined, requestApproval: async () => undefined };
    const gn = createGuardNav(deps);
    gn.install();
    await gn.sync();
    fake.fire("onErrorOccurred", { frameId: 0, tabId: 1, url, error: "net::ERR_BLOCKED_BY_CLIENT" });
    await flush();
    expect(fake.tabUpdates.at(-1)?.url).toContain("blocked.html");
    return { gn, deps };
  }

  it("holds: the pass is added for that tab only and spent when the tab commits", async () => {
    const { gn } = await blockedThenApproved();
    expect(await gn.allowOnce(1, url)).toBe(true);
    const allow = [...fake.rules.values()].filter((r) => r.action.type === "allow");
    expect(allow).toHaveLength(1);
    expect(allow[0]?.condition.tabIds).toEqual([1]);
    expect(await gn.allowOnce(2, url)).toBe(false);
    fake.fire("onCommitted", { frameId: 0, tabId: 1, url });
    await flush();
    expect([...fake.rules.values()].filter((r) => r.action.type === "allow")).toHaveLength(0);
  });

  it("RR7a: the pass covers only the approved host, not every subdomain of it", () => {
    // Fixed: the allow rule pins the exact address (requestDomains alone matches subdomains).
    const rule = allowOnceRule(NAV_ALLOW_RULE_MIN, 1, url) as unknown as DnrRule;
    expect(dnrMatches(rule, "http://4a6f686e2e446f65406d61696c2e74657374.attacker.test/x", "main_frame")).toBe(false);
    expect(dnrMatches(rule, url, "main_frame")).toBe(true);
    expect(dnrMatches(rule, "http://attacker.test.evil.example/x", "main_frame")).toBe(false);
  });

  it("m7: the pass covers only the approved address, not another path, query or port on the same host", () => {
    const rule = allowOnceRule(NAV_ALLOW_RULE_MIN, 1, url) as unknown as DnrRule;
    expect(dnrMatches(rule, "http://attacker.test:8080/other", "main_frame")).toBe(false);
    expect(dnrMatches(rule, `${url}&more=1`, "main_frame")).toBe(false);
    expect(dnrMatches(rule, url.replace(/\/[^/]*$/, "/other"), "main_frame")).toBe(false);
    expect(dnrMatches(rule, url.toUpperCase(), "main_frame")).toBe(false);
  });

  it("RR7b: a pass left by a worker that stopped before the tab committed is removed when the worker starts again", async () => {
    // Fixed: the passes and the explaining tabs are kept in chrome.storage.session; the new worker spends the pass on commit.
    const { gn, deps } = await blockedThenApproved();
    expect(await gn.allowOnce(1, url)).toBe(true);
    fake.restart();
    const again = createGuardNav(deps);
    again.install();
    await again.sync();
    fake.fire("onCommitted", { frameId: 0, tabId: 1, url });
    await flush();
    expect([...fake.rules.values()].filter((r) => r.action.type === "allow")).toHaveLength(0);
  });

  it("RR7b: at start, the worker removes an allow rule in its range that no live pass accounts for, and an expired one", async () => {
    fake.rules.set(NAV_ALLOW_RULE_MIN + 7, { id: NAV_ALLOW_RULE_MIN + 7, priority: 10_000, action: { type: "allow" as chrome.declarativeNetRequest.RuleActionType }, condition: { tabIds: [3] } });
    fake.sessionArea.data[NAV_PASS_KEY] = { salt: "0123456789abcdef0123456789abcdef", explaining: [], passes: [{ id: NAV_ALLOW_RULE_MIN + 8, tabId: 4, host: "x.test", expiresAt: Date.now() - 1 }], nextId: NAV_ALLOW_RULE_MIN };
    fake.rules.set(NAV_ALLOW_RULE_MIN + 8, { id: NAV_ALLOW_RULE_MIN + 8, priority: 10_000, action: { type: "allow" as chrome.declarativeNetRequest.RuleActionType }, condition: { tabIds: [4] } });
    const store = createStateStore(fake.sessionArea);
    createGuardNav({ store, policy: async () => P, log: () => undefined }).install();
    await flush();
    expect([...fake.rules.values()].filter((r) => r.action.type === "allow")).toHaveLength(0);
  });

  it("RR7: the address is kept only in the worker's session bookkeeping, and the approval request carries host, length and digest", async () => {
    const store = createStateStore(fake.sessionArea);
    await store.update(() => privateSession());
    const requests: NavApprovalRequest[] = [];
    const gn = createGuardNav({ store, policy: async () => P, log: () => undefined, requestApproval: async (r) => void requests.push(r) });
    gn.install();
    await gn.sync();
    fake.fire("onErrorOccurred", { frameId: 0, tabId: 1, url, error: "net::ERR_BLOCKED_BY_CLIENT" });
    await flush();
    expect(requests).toHaveLength(1);
    const meta = navigationMeta(requests[0] as NavApprovalRequest, []);
    expect(JSON.stringify(meta)).not.toContain(DATA);
    expect(meta.navigation).toMatchObject({ tabId: 1, host: "attacker.test", digest: (requests[0] as NavApprovalRequest).digest });
    expect(await gn.canReopen(1, (requests[0] as NavApprovalRequest).digest)).toBe(true);
    expect(await gn.canReopen(1, "not-the-digest")).toBe(false);
    // Closing the tab drops the held address.
    fake.fire("tabs.onRemoved", 1);
    await flush();
    expect(JSON.stringify(fake.sessionArea.data[NAV_PASS_KEY])).not.toContain(DATA);
  });

  it("RR7c: an approval given after a worker restart still reopens the tab that shows the explanation page", async () => {
    // Fixed: the explaining tabs are persisted; index.ts approves, reopens, and only then redeems (unapprove on failure).
    const { deps } = await blockedThenApproved();
    fake.restart();
    const again = createGuardNav(deps);
    again.install();
    await again.sync();
    expect(await again.allowOnce(1, url)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// RR8. Log retention at worker start
// ---------------------------------------------------------------------------

describe("RR8: the log keeps entries for the period the person chose", () => {
  it("RR8: a worker start does not purge with the 30-day default before the person's 90 days are read", async () => {
    // Fixed: index.ts passes retentionFrom(settings), which reads the stored period inside each purge.
    const NOW = 1_800_000_000_000;
    const backend = createMemoryBackend();
    const seed = createLog({ backend, now: () => NOW - 40 * DAY, retentionMs: () => 365 * DAY });
    await seed.append({ at: NOW - 40 * DAY, site: "attacker.test", actionClass: "payment", verdict: "approve", rules: ["gate.agent_mode"] });
    // chrome.storage.local answers on a later task, like the real area.
    const local: KeyValueArea = { get: (k) => new Promise((ok) => setTimeout(() => ok({ [k]: { ...DEFAULT_SETTINGS, retentionDays: 90 } }), 0)), set: async () => undefined };
    // index.ts, as written now: the purge at worker start, then the first append's purge.
    const log = createLog({ backend, now: () => NOW, retentionMs: retentionFrom(createSettingsStore(local)) });
    await log.purge();
    expect(backend.entries).toHaveLength(1);
    await log.append({ at: NOW, site: "shop.test", actionClass: null, verdict: "log", rules: [] });
    expect(backend.entries).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// RR9. The privacy policy's promises
// ---------------------------------------------------------------------------

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name);
    if (e.isDirectory()) return e.name === "vendor" ? [] : sourceFiles(p);
    return e.name.endsWith(".ts") && !e.name.endsWith(".test.ts") ? [p] : [];
  });
}

describe("RR9: what store/privacy-policy.md promises is what the code does", () => {
  it("RR9a: 'Trusted and sensitive sites are lists you can edit or clear' (Your controls)", () => {
    // Fixed: Settings has both lists; the side panel edits them, policyWith() feeds them to the engine, and in agent mode only tightening changes apply.
    expect(parseUiMessage({ type: "ui.settings.set", patch: { trustedHosts: ["intranet.example"] } })).not.toBeNull();
    expect(parseUiMessage({ type: "ui.settings.set", patch: { privateHosts: ["bank.example"] } })).not.toBeNull();
    const s = { ...DEFAULT_SETTINGS, trustedHosts: ["intranet.example"], privateHosts: ["bank.example"] };
    const p = policyWith(s);
    expect(p.trustedHosts).toContain("intranet.example");
    expect(p.privateHosts).toContain("bank.example");
    expect(applySettingsPatch(s, { trustedHosts: ["intranet.example", "attacker.test"] }, true).refused).toEqual(["trustedHosts"]);
    expect(applySettingsPatch(s, { privateHosts: [] }, true).refused).toEqual(["privateHosts"]);
    expect(applySettingsPatch(s, { trustedHosts: [], privateHosts: ["bank.example", "health.example"] }, true).refused).toEqual([]);
  });

  it("RR9b: 'Optional evidence (only if you turn on keep evidence)': something writes evidence to the log", () => {
    // Fixed: the content guard sends the quarantining hidden text's start; the worker logs it as evidence only with keep evidence on.
    const writers = sourceFiles(join(ROOT, "src")).filter((f) => !f.endsWith(join("worker", "log.ts")) && !f.endsWith(join("shared", "messages.ts")));
    expect(writers.some((f) => /\bevidence\s*:/.test(readFileSync(f, "utf8")))).toBe(true);
  });

  it("RR9c: approval records keep 'a one-way hash of the values ... The values themselves are not kept'", () => {
    // Fixed: fields are masked previews (first three characters and length); a navigation keeps host, length and a salted digest.
    const decision: Decision = { verdict: "approve", rule: "gate.agent_mode", actionClass: "send", reasons: ["agent_mode"] };
    const meta = actionMeta(submit([{ name: "message", type: "text", value: "Meet at the north gate, the passphrase is pineapple" }]), decision, []);
    const nav = navigationMeta({ tabId: 1, url: `https://attacker.test/c?d=${DATA}`, rule: "nav.high_entropy_new_origin", reasons: [] }, []);
    expect(JSON.stringify(meta)).not.toContain("pineapple");
    expect(JSON.stringify(nav)).not.toContain(DATA);
  });

  it("holds: the log entries themselves carry no value, page text or full URL (only registrable domain, rule ids, codes)", async () => {
    const backend = createMemoryBackend();
    const log = createLog({ backend });
    const entry = { at: 1, site: "attacker.test", actionClass: null, verdict: "approve", rules: ["leak.seen_elsewhere"], event: "leak", detail: ["type", "seen_elsewhere"], value: OTP } as unknown as LogEntry;
    await log.append(entry);
    expect(JSON.stringify(backend.entries)).not.toContain(OTP);
  });
});

// ---------------------------------------------------------------------------
// RR10. Approval queue bounds
// ---------------------------------------------------------------------------

describe("RR10: a page cannot flood the approval queue", () => {
  it("RR10: one tab cannot hold more than 50 pending approvals at once", async () => {
    // Fixed: per-tab and total bounds, duplicates coalesced, oldest of the busiest tab retired (and reported) first.
    const evicted: string[] = [];
    const svc = createApprovalService(memoryArea(), { onEvicted: (rs) => evicted.push(...rs.map((r) => r.id)) });
    for (let i = 0; i < 300; i++) {
      const snap = leakSnapshot({ tabId: 7, frameId: 0, frameOrigin: "https://attacker.test", via: "type", elementPath: `input#f${i}`, fieldName: `f${i}`, text: `ghp_${"x".repeat(36)}${i}`, destinationHost: "attacker.test" });
      await svc.request(snap, "action", { subject: "leak", label: "", target: "", pageUrl: "", fields: [], reasons: [], untrustedBecause: [], overridesDeny: false });
    }
    expect((await svc.pending()).filter((r) => r.snapshot.tabId === 7).length).toBeLessThanOrEqual(50);
    expect(evicted.length).toBe(250);
  });

  it("RR10: the newest request stays visible, another tab's request survives a flood, and duplicates coalesce", async () => {
    const meta = { subject: "leak" as const, label: "", target: "", pageUrl: "", fields: [], reasons: [], untrustedBecause: [], overridesDeny: false };
    const svc = createApprovalService(memoryArea());
    const mine = leakSnapshot({ tabId: 3, frameId: 0, frameOrigin: "https://mail.test", via: "type", elementPath: "input#to", fieldName: "to", text: OTP, destinationHost: "mail.test" });
    const legit = await svc.request(mine, "action", meta);
    expect((await svc.request(mine, "action", meta)).id).toBe(legit.id);
    let last = "";
    for (let i = 0; i < 400; i++) {
      const snap = leakSnapshot({ tabId: 100 + (i % 8), frameId: 0, frameOrigin: "https://attacker.test", via: "type", elementPath: `input#f${i}`, fieldName: `f${i}`, text: `v${i}`, destinationHost: "attacker.test" });
      last = (await svc.request(snap, "action", meta)).id;
    }
    const ids = (await svc.pending()).map((r) => r.id);
    expect(ids.length).toBeLessThanOrEqual(MAX_PENDING_TOTAL);
    expect(ids).toContain(last);
    expect(ids).toContain(legit.id);
  });

  it("holds: a single message over the total budget, or nested too deep, is dropped", () => {
    const deep: Record<string, unknown> = {};
    let cur = deep;
    for (let i = 0; i < 12; i++) cur = cur.x = {};
    expect(withinMessageBounds(deep)).toBe(false);
    expect(parseContentMessage({ type: "leak.guard", via: "type", text: "a".repeat(1024 * 1024 + 1), destinationHost: "x.test", elementPath: "", fieldName: "" })).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// RR11. Salted prints, unsalted log binding
// ---------------------------------------------------------------------------

describe("RR11: a held value cannot be guessed back from what is kept on disk", () => {
  it("holds: short-code prints differ between agent sessions (per-session salt)", () => {
    const a = printsFor(OTP_PAGE, "mail.test", "salt-session-a").find((p) => p.kind === "short");
    const b = printsFor(OTP_PAGE, "mail.test", "salt-session-b").find((p) => p.kind === "short");
    expect(a?.fp).toBeDefined();
    expect(a?.fp).not.toBe(b?.fp);
    expect(printsFor(OTP_PAGE, "mail.test", "").some((p) => p.kind === "short")).toBe(false);
  });

  it("RR11: the leak log's `binding` for a held 6-digit code is not the same in every session (it is in IndexedDB for 30 days and in every export)", async () => {
    // Fixed: the log keeps saltedFingerprint(snapshot, session salt), never the unsalted actionFingerprint.
    const snap = leakSnapshot({ tabId: 2, frameId: 0, frameOrigin: "https://attacker.test", via: "type", elementPath: "input#code", fieldName: "code", text: OTP, destinationHost: "attacker.test" });
    const bindingIn = async (salt: string): Promise<string | undefined> => {
      let s = startAgentSession(emptyState(), { now: 1, tabIds: [1, 2], printSalt: salt });
      s = pageShown(s, 1, { url: "https://mail.google.com/mail/u/0/" }, P);
      s = privateDataShown(s, 1, printsFor(OTP_PAGE, "mail.google.com", salt).map((p) => ({ ...p, domain: "google.com" })));
      const store = createStateStore(memoryArea());
      await store.update(() => s);
      const backend = createMemoryBackend();
      const la = createLeakAgent({ store, approvals: createApprovalService(memoryArea()), log: createLog({ backend }), settings: createSettingsStore(memoryArea()), policy: async () => P, broadcastAgentMode: async () => undefined, tabIds: async () => [1, 2], sendToTab: () => undefined });
      await la.content({ type: "leak.guard", via: "type", text: OTP, destinationHost: "attacker.test", elementPath: "input#code", fieldName: "code" }, { tabId: 2, frameId: 0, origin: "https://attacker.test", host: "attacker.test" });
      return backend.entries.find((e) => e.event === "leak")?.binding;
    };
    const a = await bindingIn("salt-session-a-0000000000000000");
    const b = await bindingIn("salt-session-b-0000000000000000");
    expect(a).toBeDefined();
    expect(a).not.toBe(b);
    expect(a).not.toBe(actionFingerprint(snap));
  });
});

// ---------------------------------------------------------------------------
// RR12. Tenant hosts
// ---------------------------------------------------------------------------

describe("RR12: first-party hosts that serve pages anyone writes", () => {
  it("holds: Forms, Apps Script, Sites and gists are their own sites", () => {
    for (const h of ["docs.google.com", "script.google.com", "sites.google.com", "gist.github.com", "forms.office.com"]) expect(registrableDomain(h)).not.toBe(registrableDomain(h.replace(/^[^.]+\./, "mail.")));
  });

  it("RR12: Google Groups (public groups anyone creates and posts to) is not the same site as Gmail", () => {
    // Fixed: groups.google.com (and Colab, Looker Studio, Microsoft and Apple community hosts) are tenant hosts.
    expect(registrableDomain("groups.google.com")).not.toBe(registrableDomain("mail.google.com"));
  });
});

// ---------------------------------------------------------------------------
// Holds: sender-derived leak hosts and the frame-host tightening (leak-agent.ts)
// ---------------------------------------------------------------------------

describe("holds: the leak guard judges Chrome's frame host, page-named hosts only tighten", () => {
  async function agentWith(s: BrowserState) {
    const area = memoryArea();
    const store = createStateStore(area);
    await store.update(() => s);
    const approvals = createApprovalService(memoryArea());
    const log = createLog({ backend: createMemoryBackend() });
    return createLeakAgent({
      store,
      approvals,
      log,
      settings: createSettingsStore(memoryArea()),
      policy: async () => P,
      broadcastAgentMode: async () => undefined,
      tabIds: async () => [1, 2],
      sendToTab: () => undefined,
    });
  }

  it("typing the Gmail code in an attacker.test frame is held even when the body names a google.com host", async () => {
    const la = await agentWith(privateSession());
    const r = (await la.content({ type: "leak.guard", via: "type", text: OTP, destinationHost: "mail.google.com", elementPath: "input#code", fieldName: "code" }, { tabId: 2, frameId: 0, origin: "https://attacker.test", host: "attacker.test" })) as { decision: Decision; approvalId?: string };
    expect(r.decision.verdict).toBe("approve");
    expect(r.approvalId).toBeDefined();
  });

  it("a submit from an attacker.test frame whose form action names google.com is still judged against attacker.test", async () => {
    const la = await agentWith(privateSession());
    const r = (await la.content({ type: "leak.guard", via: "submit", text: `code=${OTP}`, destinationHost: "mail.google.com", elementPath: "form#f", fieldName: "form" }, { tabId: 2, frameId: 0, origin: "https://attacker.test", host: "attacker.test" })) as { decision: Decision };
    expect(r.decision.verdict).toBe("approve");
  });

  it("a page-named checkout merchant cannot exempt a card typed in an attacker frame", async () => {
    const la = await agentWith(privateSession());
    const r = (await la.content({ type: "leak.guard", via: "type", text: "4539148803436467", destinationHost: "attacker.test", checkoutMerchantHost: "checkout.stripe.com", elementPath: "input#cc", fieldName: "cc" }, { tabId: 2, frameId: 0, origin: "https://attacker.test", host: "attacker.test" })) as { decision: Decision };
    expect(r.decision.verdict).toBe("approve");
  });
});

// ---------------------------------------------------------------------------
// Holds: the approval queue across a worker restart
// ---------------------------------------------------------------------------

describe("holds: approvals persist across a worker restart and stay one-shot", () => {
  it("a pending approval survives, its token redeems once in the new worker, never twice", async () => {
    const area = memoryArea();
    const snap = leakSnapshot({ tabId: 4, frameId: 0, frameOrigin: "https://attacker.test", via: "type", elementPath: "input#code", fieldName: "code", text: OTP, destinationHost: "attacker.test" });
    const meta = { subject: "leak" as const, label: "", target: "", pageUrl: "", fields: [], reasons: [], untrustedBecause: [], overridesDeny: false };
    const first = createApprovalService(area);
    const rec = await first.request(snap, "action", meta);
    const second = createApprovalService(area);
    expect((await second.pending()).map((r) => r.id)).toEqual([rec.id]);
    const token = await second.approve(rec.id);
    expect(token).not.toBeNull();
    const third = createApprovalService(area);
    expect((await third.redeem(token as string, snap)).ok).toBe(true);
    const fourth = createApprovalService(area);
    expect(await fourth.redeem(token as string, snap)).toEqual({ ok: false, reason: "used" });
  });

  it("a corrupt stored queue is ignored, never trusted", async () => {
    const area = memoryArea();
    area.data["ls.approvals"] = { ledger: { records: [{ id: "x", state: "approved", token: "t" }] }, meta: {} };
    const svc = createApprovalService(area);
    expect(await svc.pending()).toEqual([]);
    expect((await svc.redeem("t", leakSnapshot({ tabId: 1, frameId: 0, frameOrigin: "", via: "type", elementPath: "", fieldName: "", text: "", destinationHost: "" }))).ok).toBe(false);
  });
});
