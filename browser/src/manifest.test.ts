import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { buildManifest, DESCRIPTION, ICON_SIZES, HOST_PERMISSIONS, INSTALL_PERMISSIONS, OPTIONAL_PERMISSIONS } from "./manifest.js";

/** Design section 11, copied here on purpose: a change to the manifest must also change this test. */
const DESIGN_PERMISSIONS = ["declarativeNetRequest", "downloads", "sidePanel", "storage", "webNavigation"];
/** Design section 11, optional permissions built so far (requested at the moment of use): the native link's. */
const DESIGN_OPTIONAL = ["nativeMessaging"];

describe("manifest", () => {
  const m = buildManifest({ version: "0.0.1" }) as unknown as Record<string, unknown>;

  it("requests exactly the design's install-time permissions", () => {
    expect([...(m.permissions as string[])].sort()).toEqual(DESIGN_PERMISSIONS);
    expect([...INSTALL_PERMISSIONS].sort()).toEqual(DESIGN_PERMISSIONS);
  });

  it("requests <all_urls> host access and nothing else", () => {
    expect(m.host_permissions).toEqual(["<all_urls>"]);
    expect([...HOST_PERMISSIONS]).toEqual(["<all_urls>"]);
  });

  it("requests nativeMessaging as an optional permission only, and no optional hosts", () => {
    expect(m.optional_permissions).toEqual(DESIGN_OPTIONAL);
    expect([...OPTIONAL_PERMISSIONS]).toEqual(DESIGN_OPTIONAL);
    expect(m.permissions as string[]).not.toContain("nativeMessaging");
    expect(m.optional_host_permissions).toBeUndefined();
  });

  it("grants nativeMessaging at install only in the link e2e test build", () => {
    const e2e = buildManifest({ version: "0.0.1", e2eGrantNativeMessaging: true }) as unknown as Record<string, unknown>;
    expect([...(e2e.permissions as string[])].sort()).toEqual([...DESIGN_PERMISSIONS, "nativeMessaging"].sort());
    expect(e2e.optional_permissions).toEqual([]);
  });

  it("never lets pages or other extensions message it", () => {
    expect(m.externally_connectable).toBeUndefined();
    expect(m.web_accessible_resources).toBeUndefined();
  });

  it("names none of the permissions the design rules out", () => {
    const all = JSON.stringify(m);
    for (const p of ["\"tabs\"", "webRequest", "cookies", "history", "clipboardRead", "scripting", "debugger", "management", "tabGroups"]) expect(all).not.toContain(p);
  });

  it("runs the content script first, in every frame, including about:blank and srcdoc frames", () => {
    const cs = (m.content_scripts as Record<string, unknown>[])[0] as Record<string, unknown>;
    expect(cs).toMatchObject({ matches: ["<all_urls>"], run_at: "document_start", all_frames: true, match_origin_as_fallback: true });
  });

  it("allows no remote code in extension pages", () => {
    const csp = (m.content_security_policy as { extension_pages: string }).extension_pages;
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toMatch(/https?:|unsafe-eval|unsafe-inline/);
  });

  it("m11: extension pages load only our own files, make no requests, submit no forms and cannot be framed", () => {
    const csp = (m.content_security_policy as { extension_pages: string }).extension_pages;
    for (const d of ["default-src 'none'", "style-src 'self'", "connect-src 'none'", "form-action 'none'", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'"]) expect(csp).toContain(d);
  });

  it("m11: the pages carry no inline style or script the CSP would refuse", () => {
    for (const page of ["sidepanel.html", "popup.html", "approval.html", "limits.html", "blocked.html"]) {
      const html = readFileSync(new URL(`./ui/${page}`, import.meta.url), "utf8");
      expect(html, page).not.toMatch(/\sstyle\s*=|<style[\s>]|\son[a-z]+\s*=|<script(?![^>]*\ssrc=)[^>]*>/i);
    }
  });

  it("ships the navigation policy's always-on rows as one static ruleset, and nothing web accessible for the redirect", () => {
    expect(m.declarative_net_request).toEqual({ rule_resources: [{ id: "always", enabled: true, path: "rules.json" }] });
    expect(m.web_accessible_resources).toBeUndefined();
  });

  it("is MV3 with a module service worker", () => {
    expect(m.manifest_version).toBe(3);
    expect(m.background).toEqual({ service_worker: "worker.js", type: "module" });
  });

  it("is named for the store listing and describes itself with the honest summary, not a protection promise", () => {
    expect(m.name).toBe("LaunchSafe Agent Firewall for browsers");
    expect(m.description).toBe(DESCRIPTION);
    expect((m.description as string).length).toBeLessThanOrEqual(132);
    expect(m.description).not.toMatch(/\b(stops|prevents|protects|100%|safe)\b/i);
    const listing = readFileSync(new URL("../store/listing.md", import.meta.url), "utf8");
    expect(listing).toContain(DESCRIPTION);
  });

  it("declares 16, 32, 48 and 128 px PNG icons that exist and have those dimensions", () => {
    expect([...ICON_SIZES]).toEqual([16, 32, 48, 128]);
    const icons = m.icons as Record<string, string>;
    expect(Object.keys(icons).sort()).toEqual(["128", "16", "32", "48"]);
    expect((m.action as { default_icon: unknown }).default_icon).toEqual(icons);
    for (const [size, path] of Object.entries(icons)) {
      const png = readFileSync(new URL(`../${path}`, import.meta.url));
      expect(png.subarray(1, 4).toString("latin1")).toBe("PNG");
      expect([png.readUInt32BE(16), png.readUInt32BE(20)]).toEqual([Number(size), Number(size)]);
    }
  });
});
