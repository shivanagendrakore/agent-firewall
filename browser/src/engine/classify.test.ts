import { describe, expect, it } from "vitest";
import { classify, isExecutableDownload, type SiteAdapter } from "./classify.js";
import { activate, ctx, download, frame, submit, upload } from "./test-helpers.js";
import type { NormalizedAction } from "./types.js";

const cls = (a: NormalizedAction) => classify(a).actionClass;

describe("classify: payment", () => {
  it("card autocomplete fields make a submit a payment", () => {
    expect(cls(submit([{ name: "n", type: "text", autocomplete: "cc-number" }]))).toBe("payment");
  });
  it("a submit inside a payment provider frame is a payment", () => {
    expect(cls(submit([], { frame: frame("https://js.stripe.com", 1, 4) }))).toBe("payment");
  });
  it("checkout labels, localized", () => {
    for (const l of ["Place order", "Place your order", "Pay now", "Pay $12.00", "Buy now", "Confirm purchase", "Zahlungspflichtig bestellen", "Comprar"]) expect(cls(activate(l))).toBe("payment");
  });
  it("does not fire on look-alike labels", () => {
    for (const l of ["Payment methods", "Proceed to checkout", "Add to cart", "Paypal help", "Buyer protection"]) expect(cls(activate(l))).toBeNull();
  });
});

describe("classify: send", () => {
  const compose = { compose: { hasRecipient: true, hasBody: true } };
  it("a send control in a compose surface is a send", () => {
    expect(cls(activate("Send", { context: ctx("https://mail.test/", compose) }))).toBe("send");
    expect(cls(activate("Post", { context: ctx("https://social.test/", { compose: { hasRecipient: false, hasBody: true } }) }))).toBe("send");
  });
  it("a send label with no compose body is not", () => {
    expect(cls(activate("Send"))).toBeNull();
    expect(cls(activate("Send feedback about this page", { context: ctx("https://mail.test/", compose) }))).toBeNull();
  });
});

describe("classify: account security", () => {
  it("a new-password field", () => {
    expect(cls(submit([{ name: "p", type: "password", autocomplete: "new-password" }]))).toBe("account_security");
  });
  it("security labels", () => {
    for (const l of ["Change password", "Turn on 2-Step Verification", "Add recovery email", "Create filter", "Generate new token", "Add SSH key", "Sign out of all sessions", "Enable forwarding"]) expect(cls(activate(l))).toBe("account_security");
  });
  it("a submit on a security settings path", () => {
    expect(cls(submit([{ name: "x", type: "text" }], { context: ctx("https://github.test/settings/tokens") }))).toBe("account_security");
    expect(cls(submit([{ name: "x", type: "text" }], { context: ctx("https://mail.test/#settings/fwdandpop") }))).toBe("account_security");
  });
  it("a sign-in form (current-password only) is not account security", () => {
    expect(cls(submit([{ name: "p", type: "password", autocomplete: "current-password" }]))).toBeNull();
  });
});

describe("classify: oauth consent", () => {
  it("the adapter providers' consent endpoints are precise", () => {
    const c = classify(activate("Allow", { context: ctx("https://accounts.google.com/signin/oauth/consent?x=1") }));
    expect(c).toMatchObject({ actionClass: "oauth_consent", source: "adapter" });
    expect(cls(activate("Authorize attacker-app", { context: ctx("https://github.com/login/oauth/authorize?client_id=1") }))).toBe("oauth_consent");
    expect(cls(submit([], { context: ctx("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?x") }))).toBe("oauth_consent");
  });
  it("a generic consent path with an allow label is a heuristic match", () => {
    expect(classify(activate("Allow", { context: ctx("https://idp.test/oauth/authorize?x") }))).toMatchObject({ actionClass: "oauth_consent", source: "heuristic" });
  });
  it("the same label elsewhere is not consent", () => {
    expect(cls(activate("Allow", { context: ctx("https://shop.test/cookies") }))).toBeNull();
  });
  it("a look-alike host is not the precise adapter match, but is still gated as a generic consent page", () => {
    expect(classify(activate("Allow", { context: ctx("https://github.com.attacker.test/login/oauth/authorize") }))).toMatchObject({ actionClass: "oauth_consent", source: "heuristic" });
  });
});

describe("classify: delete, upload, downloads", () => {
  it("destructive labels", () => {
    for (const l of ["Delete this repository", "Delete account", "Empty trash", "Permanently delete"]) expect(cls(activate(l))).toBe("delete");
    expect(cls(activate("Delete draft"))).toBeNull();
  });
  it("every file input change is an upload", () => {
    expect(cls(upload())).toBe("upload");
  });
  it("executable downloads by extension or MIME", () => {
    for (const f of ["setup.exe", "Installer.DMG", "run.sh", "app.apk", "report.docm", "x.AppImage"]) expect(isExecutableDownload(f, "")).toBe(true);
    expect(isExecutableDownload("blob", "application/x-msdownload")).toBe(true);
    expect(isExecutableDownload("report.pdf", "application/pdf")).toBe(false);
    expect(isExecutableDownload("photo.exe.jpg", "image/jpeg")).toBe(false);
    expect(cls(download("setup.exe"))).toBe("download_exec");
    expect(cls({ kind: "download", url: "https://evil.test/payload.exe", filename: "notes.txt", mime: "text/plain" })).toBe("download_exec");
    expect(cls(download("notes.txt", "text/plain"))).toBeNull();
  });
  it("typing, pasting and navigating are not classes (the leak guard and navigation policy judge them)", () => {
    expect(cls({ kind: "paste", frame: frame(), elementPath: "x", text: "Place order", context: ctx() })).toBeNull();
    expect(cls({ kind: "navigate", tabId: 1, frameId: 0, url: "https://shop.test/", resourceType: "main_frame" })).toBeNull();
  });
  it("a plain link with a sensitive label is a navigation, not a control", () => {
    expect(cls(activate("Delete account", { tag: "a", role: "link", href: "https://shop.test/help/delete" }))).toBeNull();
    expect(cls(activate("Delete account", { tag: "a", role: "button", href: "#" }))).toBe("delete");
  });
  it("a link that stays on the page is a control; a link to another page with a fragment is still a navigation", () => {
    expect(cls(activate("Buy now", { tag: "a", role: "link", href: "https://shop.test/#" }))).toBe("payment");
    expect(cls(activate("Buy now", { tag: "a", role: "link", href: "javascript:void(0)" }))).toBe("payment");
    expect(cls(activate("Buy now", { tag: "a", role: "link", href: "https://shop.test/product#reviews" }))).toBeNull();
  });
  it("labels are compared as a person reads them (fullwidth letters, no-break spaces, format characters)", () => {
    expect(cls(activate("Ｐｌａｃｅ ｏｒｄｅｒ"))).toBe("payment");
    expect(cls(activate("Delete\u00a0my\u2009account"))).toBe("delete");
    expect(cls(activate("Change pass\u00adword"))).toBe("account_security");
  });
  it("executable names with trailing dots or spaces, and MIME types with parameters", () => {
    expect(isExecutableDownload("setup.exe. . ", "")).toBe(true);
    expect(isExecutableDownload("x", " Application/X-MSDownload ; charset=binary")).toBe(true);
    expect(isExecutableDownload("report.pdf.", "application/pdf; name=x.exe")).toBe(false);
  });
});

describe("classify: adapters", () => {
  const adapter: SiteAdapter = {
    id: "mail-test",
    hosts: ["mail.test"],
    classify: (a) => (a.kind === "activate" && a.label === "⏎" ? { actionClass: "send", signal: "icon_send" } : null),
  };
  it("an adapter match is precise and wins", () => {
    expect(classify(activate("⏎", { context: ctx("https://mail.test/") }), [adapter])).toEqual({ actionClass: "send", source: "adapter", signals: ["adapter:mail-test:icon_send"] });
  });
  it("an adapter only runs on its hosts, and falls back to heuristics", () => {
    expect(classify(activate("⏎", { context: ctx("https://other.test/") }), [adapter]).actionClass).toBeNull();
    expect(classify(activate("Pay now", { context: ctx("https://mail.test/") }), [adapter]).actionClass).toBe("payment");
  });
});
