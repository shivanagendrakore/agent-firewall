import { describe, expect, it } from "vitest";
import { agentModeOffSnapshot, ApprovalLedger } from "../engine/bindings.js";
import { snapshotOf } from "../engine/fingerprint.js";
import { activate, ctx, submit, upload } from "../engine/test-helpers.js";
import type { Decision } from "../engine/types.js";
import { actionMeta, agentModeOffMeta, downloadMeta, leakMeta, maskField, navigationMeta, navigationSnapshot, viewOf } from "./approval-view.js";
import { downloadSnapshot } from "./downloads.js";
import { navigationDigest } from "./guard-nav.js";

const approve: Decision = { verdict: "approve", rule: "gate.agent_mode", actionClass: "payment", reasons: ["agent_mode", "card_fields"] };

describe("maskField", () => {
  it("masks passwords, card numbers, CVCs and one-time codes", () => {
    expect(maskField({ name: "p", type: "password", value: "hunter2hunter2" })).toBe("••••••••");
    expect(maskField({ name: "c", type: "text", autocomplete: "cc-number", value: "4242 4242 4242 4242" })).toBe("•••• 4242");
    expect(maskField({ name: "v", type: "text", autocomplete: "cc-csc", value: "123" })).toBe("•••");
    expect(maskField({ name: "o", type: "text", autocomplete: "one-time-code", value: "123456" })).toBe("••••••••");
  });
  it("masks a card number or a secret typed into an ordinary field", () => {
    expect(maskField({ name: "note", type: "text", value: "card 4539148803436467 thanks" })).toBe("•••• 6467");
    expect(maskField({ name: "note", type: "textarea", value: "ghp_" + "a".repeat(36) })).toBe("(secret, hidden)");
  });
  it("shows ordinary values only as a masked preview: the first three characters and the length (RR9)", () => {
    expect(maskField({ name: "to", type: "email", value: "friend@mail.test" })).toBe("fri… (16 characters)");
    expect(maskField({ name: "body", type: "textarea", value: "x".repeat(500) })).toBe("xxx… (500 characters)");
    expect(maskField({ name: "s", type: "text", value: "ab" })).toBe("•••• (2 characters)");
    expect(maskField({ name: "e", type: "text", value: "" })).toBe("(empty)");
    expect(maskField({ name: "m", type: "text", value: "Meet at the north gate, the passphrase is pineapple" })).not.toContain("pineapple");
  });
});

describe("actionMeta and viewOf", () => {
  it("a click on a form control shows where the form posts as the target", () => {
    const a = activate("Place order", { context: ctx("https://shop.test/", { formFields: [], formTarget: { url: "https://pay.example.test/charge", method: "post" } }) });
    expect(actionMeta(a, approve, []).target).toBe("https://pay.example.test/charge");
    expect(actionMeta(activate("Open", { href: "https://shop.test/a", context: ctx("https://shop.test/", { formTarget: { url: "https://pay.example.test/charge", method: "post" } }) }), approve, []).target).toBe("https://shop.test/a");
  });

  const ledger = new ApprovalLedger({ now: () => 1_000, randomId: () => Math.random().toString(16).slice(2).padEnd(32, "0") });

  it("a checkout: label, destination, masked fields and reasons; no raw card number anywhere", () => {
    const a = submit([{ name: "cardnumber", type: "text", autocomplete: "cc-number", label: "Card number", value: "4242424242424242" }], { label: "Place order" });
    const m = actionMeta(a, approve, ["outside_origin"]);
    expect(m).toMatchObject({ subject: "action", label: "Place order", target: "https://shop.test/order", fields: [{ name: "Card number", masked: "•••• 4242" }], reasons: ["agent_mode", "card_fields"], untrustedBecause: ["outside_origin"], overridesDeny: false });
    const v = viewOf(ledger.request(snapshotOf(a, "payment")), m);
    expect(v).toMatchObject({ subject: "action", actionClass: "payment", kind: "submit", origin: "https://shop.test", domain: "shop.test", siteGrantable: true });
    expect(JSON.stringify({ m, v })).not.toContain("4242424242424242");
  });

  it("hidden fields are not listed; an upload lists its file names", () => {
    const a = submit([{ name: "csrf", type: "hidden", value: "tok" }, { name: "to", type: "email", value: "a@b.test" }]);
    expect(actionMeta(a, approve, []).fields.map((f) => f.name)).toEqual(["to"]);
    const u = actionMeta(upload(), { ...approve, actionClass: "upload" }, []);
    expect(u.label).toBe("1 file: passport.pdf");
    expect(u.fields).toEqual([{ name: "passport.pdf", masked: "passport.pdf" }]);
  });

  it("consent and account security are never offered for the site; neither is an overridden deny", () => {
    const consent = activate("Allow", { context: ctx("https://accounts.test/oauth2/authorize") });
    expect(viewOf(ledger.request(snapshotOf(consent, "oauth_consent")), actionMeta(consent, { ...approve, actionClass: "oauth_consent" }, [])).siteGrantable).toBe(false);
    expect(viewOf(ledger.request(snapshotOf(consent, "account_security")), actionMeta(consent, { ...approve, actionClass: "account_security" }, [])).siteGrantable).toBe(false);
    const deny: Decision = { verdict: "deny", rule: "gate.quarantine", actionClass: "payment", reasons: ["quarantine_verdict"], override: "side_panel_with_reason" };
    const pay = activate("Pay");
    const v = viewOf(ledger.request(snapshotOf(pay, "payment")), actionMeta(pay, deny, ["quarantine_verdict"]));
    expect(v.overridesDeny).toBe(true);
    expect(v.siteGrantable).toBe(false);
  });

  it("a download shows the file and the URL's site; agent-mode-off has no site", () => {
    const d = { url: "https://files.test/setup.exe", filename: "setup.exe", mime: "application/x-msdownload" };
    const v = viewOf(ledger.request(downloadSnapshot(d)), downloadMeta(d, { ...approve, actionClass: "download_exec" }, []));
    expect(v).toMatchObject({ subject: "download", kind: "download", actionClass: "download_exec", origin: "https://files.test", domain: "files.test", filename: "setup.exe" });
    const off = viewOf(ledger.request(agentModeOffSnapshot(), "agent_mode_off"), agentModeOffMeta());
    expect(off).toMatchObject({ subject: "agent_mode_off", kind: "agent_mode_off", origin: "", domain: "", siteGrantable: false });
  });
});

describe("integration: leak and navigation approvals say why they wait", () => {
  const ledger = new ApprovalLedger({ now: () => 1_000, randomId: () => Math.random().toString(16).slice(2).padEnd(32, "0") });

  it("a leak hold shows how it was going out, the field, the destination, the masked findings and the rule's reasons", () => {
    const decision: Decision = { verdict: "approve", rule: "leak.seen_elsewhere", actionClass: null, reasons: ["seen_elsewhere"] };
    const m = leakMeta({ via: "type", fieldName: "code", destinationHost: "attacker.test" }, decision, [{ kind: "seen_elsewhere", name: "private string", masked: "", seenOn: "mail.test" }], ["agent_session_private"]);
    expect(m).toMatchObject({ subject: "leak", label: "Typed into a field: code", target: "attacker.test", reasons: ["seen_elsewhere"], untrustedBecause: ["agent_session_private"], overridesDeny: false });
    expect(m.fields).toEqual([{ name: "private string", masked: "shown on mail.test" }]);
    const secret = leakMeta({ via: "paste", fieldName: "", destinationHost: "attacker.test" }, { ...decision, rule: "leak.secret", reasons: ["secret_shape"] }, [{ kind: "secret", name: "GitHub token", masked: "ghp_…Zq" }], []);
    expect(secret.label).toBe("Pasted into a field");
    expect(JSON.stringify(secret)).not.toMatch(/ghp_[A-Za-z0-9]{10}/);
  });

  it("a blocked navigation binds to the tab and the address's salted digest, and neither the record nor the view holds the address", () => {
    const url = "https://attacker.test/c/OTP-482917?d=QWxpY2U";
    const digest = navigationDigest("0123456789abcdef0123456789abcdef", url);
    const snap = navigationSnapshot(7, "https://attacker.test", digest);
    expect(snap).toMatchObject({ tabId: -1, frameId: -1, kind: "navigate", targetOrigin: "https://attacker.test", elementPath: "navigate:tab:7" });
    expect(navigationSnapshot(7, "https://attacker.test", navigationDigest("0123456789abcdef0123456789abcdef", `${url}x`)).valuesDigest).not.toBe(snap.valuesDigest);
    expect(navigationSnapshot(8, "https://attacker.test", digest).valuesDigest).not.toBe(snap.valuesDigest);
    expect(navigationDigest("another-salt-another-salt-000000", url)).not.toBe(digest);
    const m = navigationMeta({ tabId: 7, url, digest, rule: "nav.high_entropy_new_origin", reasons: ["data_in_url", "new_origin", "private_session"] }, []);
    expect(m.navigation).toEqual({ tabId: 7, host: "attacker.test", chars: 22, digest, rule: "nav.high_entropy_new_origin" });
    expect(JSON.stringify({ m, snap })).not.toMatch(/482917|QWxpY2U/);
    const v = viewOf(ledger.request(snap, "action"), m);
    expect(v).toMatchObject({ subject: "navigation", kind: "navigate", origin: "https://attacker.test", domain: "attacker.test", target: "https://attacker.test", siteGrantable: false });
    expect(v.label).toMatch(/^\d+ characters of data in the address/);
    expect(JSON.stringify(v)).not.toMatch(/482917|QWxpY2U/);
  });
});
