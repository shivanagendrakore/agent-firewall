import { describe, expect, it } from "vitest";
import { decideNavigation } from "./navigation.js";
import { isMetadataEndpoint } from "./network.js";
import { agentTrust, trust } from "./test-helpers.js";
import { DEFAULT_POLICY } from "./types.js";
import { hostOf, OPAQUE_HOST, originOf, registrableDomain, sameSite } from "./domain.js";

describe("registrable domains", () => {
  it("takes the last two labels by default", () => {
    expect(registrableDomain("inbox.mail.test")).toBe("mail.test");
    expect(registrableDomain("WWW.Example.COM.")).toBe("example.com");
  });
  it("keeps three labels under a generic second level of a country TLD", () => {
    expect(registrableDomain("www.bbc.co.uk")).toBe("bbc.co.uk");
    expect(registrableDomain("shop.example.com.au")).toBe("example.com.au");
    expect(registrableDomain("a.b.ne.jp")).toBe("b.ne.jp");
  });
  it("treats each tenant of a platform suffix as its own site", () => {
    expect(registrableDomain("alice.github.io")).toBe("alice.github.io");
    expect(registrableDomain("x.alice.github.io")).toBe("alice.github.io");
    expect(sameSite("alice.github.io", "mallory.github.io")).toBe(false);
    expect(sameSite("store-a.myshopify.com", "store-b.myshopify.com")).toBe(false);
  });
  it("IPs and single labels are their own domain; empty never matches", () => {
    expect(registrableDomain("203.0.113.9")).toBe("203.0.113.9");
    expect(registrableDomain("[::1]")).toBe("::1");
    expect(registrableDomain("localhost")).toBe("localhost");
    expect(sameSite("", "")).toBe(false);
  });
  it("hosts and origins of URLs", () => {
    expect(hostOf("https://Shop.Test:8443/x")).toBe("shop.test");
    expect(hostOf("javascript:alert(1)")).toBeNull();
    expect(hostOf("not a url")).toBeNull();
    expect(originOf("https://shop.test:8443/x?y")).toBe("https://shop.test:8443");
    expect(originOf("data:text/html,x")).toBeNull();
  });
});

describe("Public Suffix List rules", () => {
  it("applies wildcard and exception rules", () => {
    expect(registrableDomain("a.b.foo.ck")).toBe("b.foo.ck");
    expect(registrableDomain("www.ck")).toBe("www.ck");
    expect(registrableDomain("a.www.ck")).toBe("www.ck");
    expect(registrableDomain("a.b.kobe.jp")).toBe("a.b.kobe.jp");
    expect(registrableDomain("a.city.kobe.jp")).toBe("city.kobe.jp");
  });
  it("a host that is itself a public suffix is its own domain; unknown TLDs use the last two labels", () => {
    expect(registrableDomain("co.uk")).toBe("co.uk");
    expect(registrableDomain("a.b.unknowntld")).toBe("b.unknowntld");
    expect(registrableDomain("münchen.example.xn--p1ai")).toBe("münchen.example.xn--p1ai".split(".").slice(-2).join("."));
  });
  it("keeps known multi-tenant first-party hosts apart from the rest of their domain", () => {
    expect(sameSite("mail.google.com", "www.google.com")).toBe(true);
    for (const h of ["docs.google.com", "script.google.com", "sites.google.com", "gist.github.com", "forms.office.com"]) {
      expect(sameSite(h, "mail.google.com") && sameSite(h, "github.com"), h).toBe(false);
      expect(registrableDomain(`x.${h}`)).toBe(h);
    }
  });
});

describe("opaque frames", () => {
  it("a blob: URL has its creator's host; data: and about:srcdoc have the opaque stand-in", () => {
    expect(hostOf("blob:https://evil.test/6f1c0a52-0000-4000-8000-000000000000")).toBe("evil.test");
    expect(hostOf("blob:null/6f1c0a52")).toBe(OPAQUE_HOST);
    expect(hostOf("data:text/html,<p>x")).toBe(OPAQUE_HOST);
    expect(hostOf("about:srcdoc")).toBe(OPAQUE_HOST);
    expect(hostOf("about:blank")).toBeNull();
  });
});

describe("metadata address spellings", () => {
  it("blocks every spelling, allows neighbours", () => {
    for (const h of ["169.254.169.254", "[::ffff:169.254.169.254]", "::ffff:a9fe:a9fe", "0:0:0:0:0:ffff:a9fe:a9fe", "::a9fe:a9fe", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1", "fd00:ec2::254", "FD00:EC2:0:0:0:0:0:254", "0xa9fea9fe", "metadata.google.internal.", "::ffff:100.100.100.200"]) {
      expect(isMetadataEndpoint(h), h).toBe(true);
    }
    for (const h of ["169.254.169.253", "::ffff:8.8.8.8", "::1", "example.com", "2001:db8::1"]) expect(isMetadataEndpoint(h), h).toBe(false);
  });
  it("the URL parser's own spellings are denied as subresources", () => {
    for (const u of ["http://[::ffff:169.254.169.254]/", "http://[::ffff:a9fe:a9fe]/", "http://2852039166/", "http://0xa9.0xfe.0xa9.0xfe/"]) {
      expect(decideNavigation({ url: u, resourceType: "other" }, trust(), DEFAULT_POLICY).verdict, u).toBe("deny");
    }
  });
});

describe("URL text the browser normalises", () => {
  it("control characters and tabs cannot hide a javascript: or data: scheme", () => {
    for (const u of ["\u0001javascript:1", " \n javascript:1", "java\tscript:1", "jav\r\nascript:1", "\u0000data:text/html,x", "da\tta:text/html,x"]) {
      expect(decideNavigation({ url: u, resourceType: "main_frame" }, agentTrust(), DEFAULT_POLICY).verdict, JSON.stringify(u)).toBe("deny");
    }
  });
  it("a tab inside a web URL does not hide a capture host", () => {
    expect(decideNavigation({ url: "https://web\thook.site/x", resourceType: "other" }, trust(), DEFAULT_POLICY).verdict).toBe("deny");
  });
  it("an unreadable web URL is denied as a subresource and in agent mode, left to the person otherwise", () => {
    expect(decideNavigation({ url: "https://a.test/?q=a b", resourceType: "other" }, trust(), DEFAULT_POLICY).verdict).toBe("deny");
    expect(decideNavigation({ url: "https://a.test/?q=a b", resourceType: "main_frame" }, agentTrust(), DEFAULT_POLICY).verdict).toBe("deny");
    expect(decideNavigation({ url: "https://a.test/?q=a b", resourceType: "main_frame" }, trust(), DEFAULT_POLICY).verdict).toBe("allow");
  });
});
