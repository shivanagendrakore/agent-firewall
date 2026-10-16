import { describe, expect, it } from "vitest";
import { ADAPTERS, normalLabel } from "./adapters.js";
import { classify } from "./classify.js";
import { activate, ctx, frame, submit } from "./test-helpers.js";
import type { NormalizedAction } from "./types.js";

const viaAdapters = (a: NormalizedAction) => classify(a, ADAPTERS);
const on = (url: string, origin = new URL(url).origin) => ({ frame: frame(origin), context: ctx(url) });

describe("normalLabel", () => {
  it("drops bidi and zero-width marks and collapses whitespace", () => {
    expect(normalLabel(activate("Send \u202a(Ctrl-Enter)\u202c"))).toBe("Send (Ctrl-Enter)");
    expect(normalLabel(activate("  Pay\u200b   now "))).toBe("Pay now");
  });
});

describe("Gmail", () => {
  const compose = (label: string, role = "button") => activate(label, { role, tag: "div", frame: frame("https://mail.google.com"), context: ctx("https://mail.google.com/mail/u/0/#inbox?compose=new", { compose: { hasRecipient: true, hasBody: true } }) });
  it("the real send button label (with its shortcut hint) is a send, where the generic heuristic misses it", () => {
    expect(viaAdapters(compose("Send \u202a(⌘Enter)\u202c"))).toMatchObject({ actionClass: "send", source: "adapter" });
    expect(classify(compose("Send \u202a(⌘Enter)\u202c")).actionClass).toBeNull();
  });
  it("Ctrl+Enter in a compose body is a send", () => {
    expect(viaAdapters(compose("Send", "shortcut")).actionClass).toBe("send");
  });
  it("forwarding and filter settings are account security; delete forever is a delete", () => {
    expect(viaAdapters(activate("Add a forwarding address", on("https://mail.google.com/mail/u/0/#settings/fwdandpop"))).actionClass).toBe("account_security");
    expect(viaAdapters(activate("Save Changes", on("https://mail.google.com/mail/u/0/#settings/fwdandpop"))).actionClass).toBe("account_security");
    expect(viaAdapters(activate("Create filter", on("https://mail.google.com/mail/u/0/#search/x"))).actionClass).toBe("account_security");
    expect(viaAdapters(activate("Delete forever", on("https://mail.google.com/mail/u/0/#trash"))).actionClass).toBe("delete");
  });
  it("refuses: send feedback, send with no compose, settings navigation", () => {
    expect(viaAdapters(activate("Send feedback", { ...on("https://mail.google.com/mail/u/0/"), context: ctx("https://mail.google.com/mail/u/0/", { compose: { hasRecipient: false, hasBody: true } }) })).actionClass).toBeNull();
    expect(viaAdapters(activate("Send", on("https://mail.google.com/mail/u/0/#inbox"))).actionClass).toBeNull();
    expect(viaAdapters(activate("See all settings", on("https://mail.google.com/mail/u/0/#settings/fwdandpop"))).actionClass).toBeNull();
  });
  it("does not apply on another host", () => {
    expect(viaAdapters(activate("Send \u202a(⌘Enter)\u202c", { ...on("https://mail.example.com/"), role: "shortcut" })).actionClass).toBeNull();
  });
});

describe("Outlook web", () => {
  it("Send with its title hint and compose, rules and forwarding, empty folder", () => {
    expect(viaAdapters(activate("Send (Ctrl+Enter)", on("https://outlook.office.com/mail/deeplink/compose"))).actionClass).toBe("send");
    expect(viaAdapters(activate("Save", on("https://outlook.live.com/mail/0/options/mail/forwarding"))).actionClass).toBe("account_security");
    expect(viaAdapters(activate("Add new rule", on("https://outlook.office365.com/mail/"))).actionClass).toBe("account_security");
    expect(viaAdapters(activate("Empty folder", on("https://outlook.live.com/mail/0/deleteditems"))).actionClass).toBe("delete");
  });
  it("refuses: Send without compose or hint, settings navigation", () => {
    expect(viaAdapters(activate("Send", on("https://outlook.live.com/mail/0/"))).actionClass).toBeNull();
    expect(viaAdapters(activate("View all Outlook settings", on("https://outlook.live.com/mail/0/options/mail/forwarding"))).actionClass).toBeNull();
  });
});

describe("Google Account", () => {
  it("commits on password, 2SV, recovery and app passwords pages are account security", () => {
    expect(viaAdapters(activate("Change password", on("https://myaccount.google.com/signinoptions/password"))).actionClass).toBe("account_security");
    expect(viaAdapters(activate("Turn off", on("https://myaccount.google.com/signinoptions/two-step-verification"))).actionClass).toBe("account_security");
    expect(viaAdapters(submit([{ name: "email", type: "email" }], on("https://myaccount.google.com/recovery/email"))).actionClass).toBe("account_security");
    expect(viaAdapters(activate("Create", on("https://myaccount.google.com/apppasswords"))).actionClass).toBe("account_security");
    expect(viaAdapters(activate("Delete account", on("https://myaccount.google.com/deleteaccount"))).actionClass).toBe("delete");
  });
  it("refuses: navigation on those pages, and other pages", () => {
    expect(viaAdapters(activate("Learn more", on("https://myaccount.google.com/signinoptions/password"))).actionClass).toBeNull();
    expect(viaAdapters(activate("Save", on("https://myaccount.google.com/personal-info"))).actionClass).toBeNull();
  });
});

describe("GitHub", () => {
  it("OAuth authorize and app installs are consent", () => {
    expect(viaAdapters(activate("Authorize attacker-app", on("https://github.com/login/oauth/authorize?client_id=x"))).actionClass).toBe("oauth_consent");
    expect(viaAdapters(activate("Install & Authorize", on("https://github.com/apps/some-app/installations/new/permissions?target_id=1"))).actionClass).toBe("oauth_consent");
  });
  it("token, key and security settings are account security; repo deletion is a delete", () => {
    expect(viaAdapters(activate("Generate token", on("https://github.com/settings/tokens/new"))).actionClass).toBe("account_security");
    expect(viaAdapters(activate("Add SSH key", on("https://github.com/settings/ssh/new"))).actionClass).toBe("account_security");
    expect(viaAdapters(activate("Add webhook", on("https://github.com/owner/repo/settings/hooks/new"))).actionClass).toBe("account_security");
    expect(viaAdapters(activate("Add secret", on("https://github.com/owner/repo/settings/secrets/actions/new"))).actionClass).toBe("account_security");
    expect(viaAdapters(activate("I want to delete this repository", on("https://github.com/owner/repo/settings"))).actionClass).toBe("delete");
    expect(viaAdapters(activate("Delete this repository", on("https://github.com/owner/repo/settings"))).actionClass).toBe("delete");
  });
  it("refuses: cancel on authorize, settings navigation, ordinary repo buttons", () => {
    expect(viaAdapters(activate("Cancel", on("https://github.com/login/oauth/authorize?client_id=x"))).actionClass).toBeNull();
    expect(viaAdapters(activate("Fine-grained tokens", { ...on("https://github.com/settings/tokens"), tag: "a", role: "link", href: "https://github.com/settings/personal-access-tokens" })).actionClass).toBeNull();
    expect(viaAdapters(activate("Star", on("https://github.com/owner/repo"))).actionClass).toBeNull();
  });
});

describe("Microsoft consent", () => {
  it("Accept on the consent prompt is consent; security proofs are account security", () => {
    expect(viaAdapters(activate("Accept", on("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x"))).actionClass).toBe("oauth_consent");
    expect(viaAdapters(activate("Yes", on("https://login.live.com/oauth20_authorize.srf?client_id=x"))).actionClass).toBe("oauth_consent");
    expect(viaAdapters(activate("Next", on("https://account.live.com/proofs/Add"))).actionClass).toBe("account_security");
  });
  it("refuses: Cancel on consent, sign-in pages", () => {
    expect(viaAdapters(activate("Cancel", on("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x"))).actionClass).toBeNull();
    expect(viaAdapters(activate("Use another account", on("https://login.live.com/login.srf"))).actionClass).toBeNull();
  });
});

describe("checkout adapters", () => {
  it("Stripe Checkout: Pay, Subscribe and a submit; not Back", () => {
    expect(viaAdapters(activate("Subscribe", on("https://checkout.stripe.com/c/pay/cs_test_x"))).actionClass).toBe("payment");
    expect(viaAdapters(submit([], on("https://buy.stripe.com/test_x"))).actionClass).toBe("payment");
    // A non-payment control in the hosted page: the frame-host heuristic still calls any activation there a payment, the adapter does not.
    expect(stripeOnly(activate("Back", on("https://checkout.stripe.com/c/pay/cs_test_x")))).toBeNull();
  });
  it("Shopify: Pay now in the checkout path; not outside it", () => {
    expect(viaAdapters(activate("Pay now", on("https://store.myshopify.com/checkouts/cn/abc"))).actionClass).toBe("payment");
    expect(viaAdapters(activate("Complete order", on("https://checkout.shopify.com/123/checkouts/abc"))).actionClass).toBe("payment");
    expect(shopifyOnly(activate("Pay now", on("https://store.myshopify.com/products/hat")))).toBeNull();
  });
  it("Amazon: Place your order and Buy Now on any listed storefront; not Add to cart", () => {
    expect(viaAdapters(activate("Place your order", on("https://www.amazon.com/gp/buy/spc/handlers/display.html"))).actionClass).toBe("payment");
    expect(viaAdapters(activate("Buy Now", on("https://www.amazon.co.uk/dp/B000"))).actionClass).toBe("payment");
    expect(viaAdapters(activate("Add to Cart", on("https://www.amazon.de/dp/B000"))).actionClass).toBeNull();
  });
});

function only(id: string, a: NormalizedAction): string | null {
  const ad = ADAPTERS.find((x) => x.id === id);
  if (ad === undefined) throw new Error(id);
  return ad.classify(a)?.actionClass ?? null;
}
const stripeOnly = (a: NormalizedAction) => only("stripe_checkout", a);
const shopifyOnly = (a: NormalizedAction) => only("shopify_checkout", a);

describe("adapter set", () => {
  it("covers the v0.1 sites and the later ones, each with at least one host", () => {
    expect(ADAPTERS.map((a) => a.id)).toEqual(["gmail", "outlook", "google_account", "github", "microsoft_consent", "stripe_checkout", "shopify_checkout", "amazon_checkout", "slack", "linkedin", "x", "reddit", "google_drive", "microsoft365_sharing", "apple_id", "aws_console"]);
    for (const a of ADAPTERS) expect(a.hosts.length).toBeGreaterThan(0);
  });
  it("ignores navigations and downloads", () => {
    for (const a of ADAPTERS) {
      expect(a.classify({ kind: "download", url: "https://github.com/x.exe", filename: "x.exe", mime: "" })).toBeNull();
      expect(a.classify({ kind: "navigate", tabId: 1, frameId: 0, url: "https://github.com/settings/tokens", resourceType: "main_frame" })).toBeNull();
    }
  });
});
