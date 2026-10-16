/**
 * The `emailGuard` policy key (src/policy-email.ts): validation and
 * the tighten-only table for project files.
 */
import { describe, expect, it } from "vitest";
import { defaultConfig, mergeTighten, mergeTrusted, PolicyError, validatePolicy } from "../../src/policy.js";
import { emailGuardPolicy, isMailServer } from "../../src/policy-email.js";
import { guardApplies } from "../../src/runtime/mail/guard.js";

const doc = (emailGuard: unknown) => validatePolicy({ version: 2, emailGuard }, "test");

describe("emailGuard policy", () => {
  it("defaults: on, read path enforced, mailbox log, all five quarantine rules", () => {
    expect(emailGuardPolicy(defaultConfig())).toEqual({ enabled: true, readPath: "enforce", mailbox: "log", servers: [], pollSeconds: 15, authservIds: [], quarantineOn: ["tag_chars", "hidden_instruction", "dense_zero_width_instruction", "hidden_exfil_link", "auth_fail_instruction"] });
  });
  it("validates every key; unknown keys and bad values are errors", () => {
    expect(() => doc({ readPath: "sometimes" })).toThrow(PolicyError);
    expect(() => doc({ pollSeconds: 2 })).toThrow(/5 to 600/);
    expect(() => doc({ quarantineOn: ["everything"] })).toThrow(PolicyError);
    expect(() => doc({ servers: [1] })).toThrow(PolicyError);
    expect(() => doc({ surprise: true })).toThrow(/not a known setting/);
    expect(doc({ readPath: "log", servers: ["fastmail"], authservIds: ["mx.fastmail.example"], pollSeconds: 30 }).emailGuard).toEqual({ readPath: "log", servers: ["fastmail"], authservIds: ["mx.fastmail.example"], pollSeconds: 30 });
  });
  it("user or managed policy may loosen anything", () => {
    const cfg = mergeTrusted(defaultConfig(), doc({ enabled: false, readPath: "off", mailbox: "enforce", quarantineOn: ["tag_chars"] }));
    expect(emailGuardPolicy(cfg)).toMatchObject({ enabled: false, readPath: "off", mailbox: "enforce", quarantineOn: ["tag_chars"] });
  });
  it("a project may only tighten: enable, move the read path towards enforce, add servers and rules", () => {
    const user = mergeTrusted(defaultConfig(), doc({ readPath: "log", quarantineOn: ["tag_chars"] }));
    const { config, ignored } = mergeTighten(user, doc({ enabled: true, readPath: "enforce", servers: ["corp-mail-bridge"], quarantineOn: ["hidden_instruction"] }));
    expect(emailGuardPolicy(config)).toMatchObject({ enabled: true, readPath: "enforce", servers: ["corp-mail-bridge"], quarantineOn: ["tag_chars", "hidden_instruction"] });
    expect(ignored).toEqual([]);
  });
  it("a project cannot switch it off, loosen the read path, move mail, change polling or trust mail servers", () => {
    const { config, ignored } = mergeTighten(defaultConfig(), doc({ enabled: false, readPath: "log", mailbox: "enforce", pollSeconds: 5, authservIds: ["mx.attacker.example"] }));
    expect(emailGuardPolicy(config)).toEqual(emailGuardPolicy(defaultConfig()));
    expect(ignored.join("\n")).toMatch(/emailGuard.enabled[\s\S]*emailGuard.readPath[\s\S]*emailGuard.mailbox[\s\S]*emailGuard.pollSeconds[\s\S]*emailGuard.authservIds/);
  });
  it("mail servers: by name (the preset match) and by the policy's list", () => {
    const p = emailGuardPolicy(defaultConfig());
    for (const s of ["gmail", "claude_ai_Gmail", "outlook-mail", "imap", "email", "e-mail", "fastmail", "smtp-relay", "plugin_x_gmail"]) expect(isMailServer(s, p), s).toBe(true);
    for (const s of ["github", "linear", "filesystem"]) expect(isMailServer(s, p), s).toBe(false);
    expect(isMailServer("corp-bridge", { servers: ["corp-bridge"] })).toBe(true);
  });
  it("mail servers: m365, o365, exchange, outlook, jmap, imap, inbox and mailbox as words of the name, any case", () => {
    const p = emailGuardPolicy(defaultConfig());
    for (const s of ["m365", "M365", "ms-m365", "m365_connector", "o365", "exchange", "Exchange", "ms-exchange", "exchange-online", "MsExchange", "ExchangeOnline", "outlook", "Outlook365", "jmap", "fastmail-jmap", "JMAP", "imap", "imap-bridge", "inbox", "my_inbox", "SharedInbox", "mailbox", "Mailbox-Server", "plugin_x_m365", "inbox-zero", "inbox-zero-todo"]) expect(isMailServer(s, p), s).toBe(true);
  });
  it("mail-word false positives: exchange as a market, and words that only contain the letters", () => {
    const p = emailGuardPolicy(defaultConfig());
    // exchange next to a market word is not mail (currency rates, crypto and stock exchanges).
    for (const s of ["exchange-rates", "ExchangeRates", "currency-exchange", "crypto-exchange", "stock-exchange-api", "fx-exchange", "coin_exchange", "exchange-prices", "token-exchange"]) expect(isMailServer(s, p), s).toBe(false);
    // The letters inside another word are not the word.
    for (const s of ["inboxer", "jmapper", "m3650", "exchanger", "sandbox", "xinbox", "github", "linear"]) expect(isMailServer(s, p), s).toBe(false);
  });
  it("a tool whose name says mail makes a vendor-named server's results mail", () => {
    const p = emailGuardPolicy(defaultConfig());
    expect(isMailServer("microsoft", p, "outlook_list_messages")).toBe(true);
    expect(isMailServer("fastmail-api", p, "jmap_query")).toBe(true);
    expect(isMailServer("workspace", p, "list_inbox")).toBe(true);
    expect(isMailServer("workspace", p, "list_files")).toBe(false);
    expect(isMailServer("rates", p, "get_exchange_rates")).toBe(false);
  });
  it("the guard applies to the new names, and not when it is switched off", () => {
    expect(guardApplies(defaultConfig(), "m365")).toBe("mail");
    expect(guardApplies(defaultConfig(), "microsoft", "outlook_get_message")).toBe("mail");
    expect(guardApplies(defaultConfig(), "exchange-rates")).toBeNull();
    const off = mergeTrusted(defaultConfig(), doc({ enabled: false }));
    expect(guardApplies(off, "m365")).toBeNull();
  });
});
