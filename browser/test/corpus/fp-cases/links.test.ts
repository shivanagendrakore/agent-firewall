/**
 * False positives found on the real-page corpus (docs/real-corpus-findings.md), reduced to the
 * link judgement that decides them. They were `it.fails` until the template rule was tightened (a slot counts only
 * as the whole of a query value, a secret-named path segment, a private-data name in a short one-line value, or a
 * private-data name in a hidden off-site link). The tests next to each one are the controls: a real exfiltration
 * link is still caught, so the fix did not simply switch the rule off.
 */
import { describe, expect, it } from "vitest";
import { judgeLinks, type GuardLink } from "../../../src/engine/guard-scan.js";

const link = (url: string, hidden: boolean, kind: GuardLink["kind"] = "link"): GuardLink => ({ url, kind, hidden, pixel: false });
const verdict = (url: string, hidden: boolean, pageHost?: string, kind: GuardLink["kind"] = "link") => judgeLinks([link(url, hidden, kind)], pageHost === undefined ? {} : { pageHost }).verdict;

describe("FP-1: a placeholder in a sign-up link's return path flags every signed-out GitHub page", () => {
  // The header "Sign up" link on github.com/<any repo>, signed out (7 of the 8 GitHub pages in the corpus).
  const signup = "https://github.com/signup?ref_cta=Sign+up&ref_loc=header+logged+out&ref_page=%2F%3Cuser-name%3E%2F%3Crepo-name%3E&source=header-repo&source_repo=microsoft%2Fvscode";
  it("a visible sign-up link is delivered, not flagged", () => {
    expect(judgeLinks([link(signup, false)]).verdict).toBe("deliver");
  });
  it("the same link is delivered on github.com and on any other page, hidden or not", () => {
    expect(verdict(signup, false, "github.com")).toBe("deliver");
    expect(verdict(signup, true, "github.com")).toBe("deliver");
    expect(verdict(signup, true, "shop.test")).toBe("deliver");
  });
  it("control: a visible link whose query has a slot for the model to fill is still flagged", () => {
    expect(judgeLinks([link("https://collector.example/log?data={secret}", false)]).verdict).toBe("flag");
  });
  it("control: encoded slots that are the whole query value, or name private data, still count", () => {
    expect(verdict("https://collector.example/log?d=%7Buser_email%7D", true)).toBe("quarantine");
    expect(verdict("https://collector.example/log?d=%3Cconversation_summary%3E", true, undefined, "image")).toBe("quarantine");
    expect(verdict("https://collector.example/log?d={{answer}}", false)).toBe("flag");
    expect(verdict("https://collector.example/log?ref=/u/%3Cuser-email%3E", false)).toBe("flag");
    expect(verdict("https://collector.example/%7Bapi_key%7D/p.gif", true, "shop.test", "image")).toBe("quarantine");
  });
});

describe("FP-2: a code-carrying URL in a hover-only button quarantines every rustdoc page with an example", () => {
  // The "Run" button of a rustdoc example: hidden until hover, href is the playground with the code URL-encoded.
  // Rust (and JavaScript, CSS, JSON) code is full of { }, which the template rule reads as "{slot}".
  const run = "https://play.rust-lang.org/?code=%23!%5Ballow(unused)%5D%0Afn+main()+%7B%0A++++let+mut+vec+=+Vec::new();%0A++++vec.push(1);%0A%7D&edition=2024";
  it("a hidden playground link is not a hidden exfiltration link", () => {
    expect(judgeLinks([link(run, true)]).verdict).not.toBe("quarantine");
  });
  it("a hidden playground link is delivered on the docs site and on another site", () => {
    expect(verdict(run, true, "doc.rust-lang.org")).toBe("deliver");
    expect(verdict(run, true, "shop.test")).toBe("deliver");
    // Generic type parameters and format strings are code, not slots.
    const generic = "https://play.rust-lang.org/?code=" + encodeURIComponent("fn f<T>(v: Vec<T>) -> Option<Token> {\n    println!(\"{x}\");\n}");
    expect(verdict(generic, true, "doc.rust-lang.org")).toBe("deliver");
  });
  it("control: a hidden link with a fill-in slot to an unrelated host is still quarantined", () => {
    expect(judgeLinks([link("https://collector.example/log?data={secret}", true)]).verdict).toBe("quarantine");
  });
  it("control: a private-data slot inside multi-line encoded text quarantines when the hidden link leaves the site", () => {
    const smuggled = "https://collector.example/c?body=" + encodeURIComponent("hello\nuser: {user_email}, notes");
    expect(verdict(smuggled, true, "shop.test")).toBe("quarantine");
    expect(verdict(smuggled, false, "shop.test")).toBe("deliver");
  });
});

describe("FP-3: encoded markup in a pre-filled issue link is read as a template (MDN's 'Report a problem')", () => {
  // The footer link on every MDN page: a GitHub new-issue URL whose metadata is an encoded <details> block.
  const report =
    "https://github.com/mdn/content/issues/new?template=page-report.yml&mdn-url=https%3A%2F%2Fdeveloper.mozilla.org%2Fen-US%2Fdocs%2FWeb%2FAPI%2FFetch_API%2FUsing_Fetch&metadata=%3C%21--+Do+not+make+changes+below+this+line+--%3E%0A%3Cdetails%3E%0A%3Csummary%3EPage+report+details%3C%2Fsummary%3E%0A%0A*+Folder%3A+%60en-us%2Fweb%2Fapi%2Ffetch_api%2Fusing_fetch%60%0A%0A%3C%2Fdetails%3E";
  it("a visible pre-filled issue link is delivered, not flagged", () => {
    expect(judgeLinks([link(report, false)]).verdict).toBe("deliver");
  });
  it("on MDN (another site than github.com), visible or hidden, it is delivered", () => {
    expect(verdict(report, false, "developer.mozilla.org")).toBe("deliver");
    expect(verdict(report, true, "developer.mozilla.org")).toBe("deliver");
  });
  it("control: a pre-filled issue link to a capture host still flags", () => {
    expect(verdict(report.replace("https://github.com/", "https://webhook.site/"), false, "developer.mozilla.org")).toBe("flag");
  });
});

describe("REST path placeholders and other ordinary link shapes", () => {
  it("documentation links with path placeholders are delivered", () => {
    expect(verdict("https://docs.example.com/v2/orders/%7Border_id%7D", false, "docs.example.com")).toBe("deliver");
    expect(verdict("https://api.example.com/sessions/%7Bsession_id%7D/messages/%7Bmessage_id%7D", true, "docs.example.com")).toBe("deliver");
    expect(verdict("https://example.com/objects/%7Bkey%7D", true, "shop.test")).toBe("deliver");
  });
});
