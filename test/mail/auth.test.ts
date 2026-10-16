/**
 * v0.3 E1: sender authentication as the mailbox provider reported it
 * (src/engine/mail/auth.ts). Only the provider's own, top-most header counts;
 * headers a sender wrote further down are ignored (EM6); a listed forwarder's
 * ARC seal cancels a DMARC failure (EFP6); sender notes never withhold.
 */
import { describe, expect, it } from "vitest";
import { SLOW } from "../helpers.js";
import { parseAuthResults, readAuth, registrableDomain, senderNotes } from "../../src/engine/mail/auth.js";
import type { MailHeader } from "../../src/engine/mail/mime.js";

const h = (...pairs: [string, string][]): MailHeader[] => pairs.map(([name, value]) => ({ name, value }));

describe("Authentication-Results", () => {
  it("parses authserv-id, methods and results, ignoring comments", () => {
    const p = parseAuthResults("mx.google.com; dkim=pass (good sig) header.i=@x.example; spf=fail (bad ip) smtp.mailfrom=x.example; dmarc=fail (p=REJECT) header.from=x.example");
    expect(p.authservId).toBe("mx.google.com");
    expect(p.results.map((r) => `${r.method}=${r.result}`)).toEqual(["dkim=pass", "spf=fail", "dmarc=fail"]);
  });
  it("Exchange Online's header has no authserv-id", () => {
    expect(parseAuthResults("spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=x.example; dkim=none; dmarc=pass action=none header.from=x.example").authservId).toBe("");
  });
  it("EM5: the provider's dmarc=fail is a failure", () => {
    const a = readAuth(h(["Authentication-Results", "mx.google.com; spf=fail smtp.mailfrom=bank.example; dkim=none; dmarc=fail header.from=bank.example"]));
    expect(a.fail).toBe(true);
    expect(a.detail).toContain("dmarc=fail");
  });
  it("spf=fail with a passing DKIM signature is not a failure; without one it is", () => {
    expect(readAuth(h(["Authentication-Results", "mx.google.com; spf=fail; dkim=pass header.d=x.example"])).fail).toBe(false);
    expect(readAuth(h(["Authentication-Results", "mx.google.com; spf=fail; dkim=fail"])).fail).toBe(true);
  });
  it("EM6: a dmarc=fail header below the provider's dmarc=pass is ignored", () => {
    const a = readAuth(h(["Authentication-Results", "mx.google.com; spf=pass; dkim=pass; dmarc=pass"], ["Authentication-Results", "mx.google.com; dmarc=fail"]));
    expect(a.fail).toBe(false);
  });
  it("a sender's own header from an unknown authserv-id is ignored: unknown, not pass or fail", () => {
    expect(readAuth(h(["Authentication-Results", "evil.example; dmarc=fail"])).fail).toBeNull();
    expect(readAuth(h(["Authentication-Results", "spf=pass; dmarc=pass"])).fail).toBeNull();
    expect(readAuth([]).fail).toBeNull();
  });
  it("Outlook: *.prod.outlook.com and *.protection.outlook.com ids, and mx.microsoft.com in ARC-Authentication-Results", () => {
    expect(readAuth(h(["Authentication-Results", "AM0PR01MB1234.eurprd01.prod.outlook.com; dmarc=fail"])).fail).toBe(true);
    expect(readAuth(h(["Authentication-Results", "x.protection.outlook.com; dmarc=pass"])).fail).toBe(false);
    const arc = readAuth(h(["ARC-Authentication-Results", "i=2; mx.microsoft.com 1; spf=fail; dmarc=fail header.from=x.example"], ["ARC-Authentication-Results", "i=1; mx.microsoft.com 1; dmarc=pass"], ["Authentication-Results", "spf=fail; dmarc=fail"]));
    expect(arc.fail).toBe(true);
    expect(arc.via).toBe("arc-authentication-results");
  });
  it("V28: on Microsoft 365, Exchange's id-less header and Microsoft's ARC result are the verdict; a sender's headers below cannot pass it", () => {
    const exch = (r: string) => ["Authentication-Results", `spf=${r} (sender IP is 192.0.2.1) smtp.mailfrom=bank.example; dkim=none; dmarc=${r} action=none header.from=bank.example`] as [string, string];
    const msArc = (i: number, r: string) => ["ARC-Authentication-Results", `i=${i}; mx.microsoft.com 1; spf=${r}; dkim=none; dmarc=${r}`] as [string, string];
    const forgedAr = ["Authentication-Results", "mx.google.com; spf=pass; dkim=pass; dmarc=pass"] as [string, string];
    // Microsoft says fail: no forged header lower down turns it into a pass.
    expect(readAuth(h(exch("fail"), msArc(1, "fail"))).fail).toBe(true);
    expect(readAuth(h(exch("fail"), msArc(1, "fail"), forgedAr)).fail).toBe(true);
    expect(readAuth(h(exch("fail"), msArc(1, "fail"), msArc(7, "pass"))).fail).toBe(true);
    expect(readAuth(h(exch("fail"), msArc(1, "pass"))).fail).toBe(true);
    // A forged low instance below Microsoft's own (real) higher one does not win either.
    expect(readAuth(h(msArc(2, "fail"), msArc(1, "pass"))).fail).toBe(true);
    expect(readAuth(h(msArc(1, "fail"), msArc(7, "pass"))).fail).toBe(true);
    // A header added above Exchange's after delivery (another id) does not hide it.
    expect(readAuth(h(["Authentication-Results", "gateway.corp.example; spf=pass"], exch("fail"), msArc(1, "fail"), forgedAr)).fail).toBe(true);
    // Microsoft says pass: a pass, and the detail names Exchange Online's result.
    const pass = readAuth(h(exch("pass"), msArc(1, "pass")));
    expect(pass.fail).toBe(false);
    expect(pass.detail).toContain("mx.microsoft.com");
    expect(readAuth(h(exch("pass"))).fail).toBeNull();
    // Without Microsoft's ARC, an id-less failure still counts and cannot be overridden by a forged header below.
    expect(readAuth(h(exch("fail"))).fail).toBe(true);
    expect(readAuth(h(exch("fail"), forgedAr)).fail).toBe(true);
  });
  it("authserv-ids the person configures are trusted too; a lookalike is not", () => {
    expect(readAuth(h(["Authentication-Results", "mx.fastmail.example; dmarc=fail"]), ["mx.fastmail.example"]).fail).toBe(true);
    expect(readAuth(h(["Authentication-Results", "mx.google.com.evil.example; dmarc=fail"])).fail).toBeNull();
    expect(readAuth(h(["Authentication-Results", "prod.outlook.com.evil.example; dmarc=fail"])).fail).toBeNull();
  });
  it("EFP6: a passing ARC chain sealed by a mailing-list host cancels the failure", () => {
    const a = readAuth(
      h(
        ["ARC-Authentication-Results", "i=1; googlegroups.com; spf=pass; dkim=pass; dmarc=pass"],
        ["ARC-Seal", "i=1; a=rsa-sha256; cv=none; d=googlegroups.com; s=arc; b=x"],
        ["Authentication-Results", "mx.google.com; arc=pass (i=1); spf=pass; dmarc=fail (arc=pass) header.from=corp.example"],
      ),
    );
    expect(a.fail).toBe(false);
    expect(a.arcPass).toBe(true);
  });
  it("an ARC seal by the sender's own domain (or a mailbox provider) does not cancel it", () => {
    for (const d of ["attacker.example", "microsoft.com", "google.com"]) {
      const a = readAuth(h(["ARC-Seal", `i=1; a=rsa-sha256; cv=none; d=${d}; s=arc; b=x`], ["Authentication-Results", "mx.google.com; arc=pass; dmarc=fail"]));
      expect(a.fail, d).toBe(true);
    }
  });
  it("semicolons inside quoted strings, unverified ARC forwarder seals, and id-less Exchange headers without ARC cannot bypass readAuth", () => {
    // 1. Semicolons inside quoted pvalue tokens are not parsed as separate method results.
    const quotedDkim = parseAuthResults('mx.google.com; spf=fail smtp.mailfrom="a; dkim=pass"@evil.example; dmarc=fail');
    expect(quotedDkim.results.map((r) => `${r.method}=${r.result}`)).toEqual(["spf=fail", "dmarc=fail"]);
    expect(readAuth(h(["Authentication-Results", 'mx.google.com; spf=fail smtp.mailfrom="a; dkim=pass"@evil.example'])).fail).toBe(true);
    expect(
      readAuth(
        h(
          ["ARC-Authentication-Results", "i=1; googlegroups.com; spf=pass; dkim=pass; dmarc=pass"],
          ["ARC-Seal", "i=1; a=rsa-sha256; cv=none; d=googlegroups.com; s=arc; b=x"],
          ["Authentication-Results", 'mx.google.com; dmarc=fail header.i="a; arc=pass"; spf=fail'],
        ),
      ).fail,
    ).toBe(true);

    // 2. A listed forwarder's ARC seal does not cancel dmarc=fail when i=1 failed or is unverified.
    expect(
      readAuth(
        h(
          ["ARC-Authentication-Results", "i=1; duck.com; spf=fail; dmarc=fail header.from=bank.example"],
          ["ARC-Seal", "i=1; a=rsa-sha256; cv=none; d=duck.com; s=arc; b=x"],
          ["Authentication-Results", "mx.google.com; arc=pass (i=1); spf=pass smtp.mailfrom=duck.com; dmarc=fail header.from=bank.example"],
        ),
      ).fail,
    ).toBe(true);
    expect(
      readAuth(
        h(
          ["ARC-Seal", "i=1; a=rsa-sha256; cv=none; d=simplelogin.com; s=arc; b=x"],
          ["Authentication-Results", "mx.google.com; arc=pass; spf=pass smtp.mailfrom=simplelogin.com; dmarc=fail header.from=bank.example"],
        ),
      ).fail,
    ).toBe(true);

    // 3. Exchange's top-most id-less header without ARC still reports failures and blocks lower forged headers.
    const exchFail: [string, string] = ["Authentication-Results", "spf=fail (sender IP is 192.0.2.1) smtp.mailfrom=bank.example; dkim=none; dmarc=fail action=none header.from=bank.example"];
    const forgedPass: [string, string] = ["Authentication-Results", "mx.google.com; spf=pass; dkim=pass; dmarc=pass"];
    expect(readAuth(h(exchFail)).fail).toBe(true);
    expect(readAuth(h(exchFail, forgedPass)).fail).toBe(true);
  });
});

describe("sender notes (reported, never a reason to withhold alone)", () => {
  it("registrable domains with two-level suffixes", () => {
    expect(registrableDomain("a.b.example.co.uk")).toBe("example.co.uk");
    expect(registrableDomain("mail.example.com")).toBe("example.com");
  });
  it("a display name naming another domain, a Reply-To elsewhere, punycode and mixed scripts", () => {
    const notes = senderNotes(h(["From", '"service@paypal.example" <help@other.example>'], ["Reply-To", "x@third.example"]));
    expect(notes.map((n) => n.id)).toEqual(["display_name_domain", "reply_to_domain"]);
    expect(senderNotes(h(["From", "Shop <s@xn--bcher-kva.example>"])).map((n) => n.id)).toEqual(["punycode_domain"]);
    expect(senderNotes(h(["From", "Pay <p@pаypal.example>"])).map((n) => n.id)).toEqual(["mixed_script_domain"]);
  });
  it("a very long display name is read in linear time, and an address inside it is still seen (mail:scanMail 30964)", () => {
    const pad = "A".repeat(100_000);
    for (const name of [pad, `${pad} service@paypal.example ${pad}`, `${pad}.paypal.example`, "a-".repeat(50_000), "a.".repeat(50_000)]) {
      const t0 = performance.now();
      senderNotes(h(["From", `"${name}" <help@other.example>`]));
      expect(performance.now() - t0, name.slice(0, 20)).toBeLessThan(500 * SLOW);
    }
    expect(senderNotes(h(["From", `"${pad} service@paypal.example ${pad}" <help@other.example>`])).map((n) => n.id)).toEqual(["display_name_domain"]);
    expect(senderNotes(h(["From", `"${pad} paypal.com" <help@other.example>`])).map((n) => n.id)).toEqual(["display_name_domain"]);
  });
  it("an ordinary sender has no notes", () => {
    expect(senderNotes(h(["From", "PayPal <service@paypal.example>"], ["Reply-To", "help@mail.paypal.example"]))).toEqual([]);
  });
});

describe("hostile Authentication-Results stays linear", () => {
  it("a long unclosed arc=pass comment is read in bounded time and does not count as a pass", () => {
    const t0 = Date.now();
    const a = readAuth(h(["Authentication-Results", `mx.example; arc=pass (i=1 ${"x ".repeat(100_000)}`]));
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(a.fail).not.toBe(true); // no provider header: unknown (null), and certainly not a cancelled failure
    expect(a.arcPass).toBe(false);
  });
});
