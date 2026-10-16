/**
 * The built extension makes no network requests and evaluates no strings
 * (docs/design.md section 12; the store review's "remote code" item). Builds
 * into a temp folder with the real build script, then scans every output file.
 * The allowlist is empty: there is nothing to allow.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { ALLOWLIST, disallowed, remoteReferencesInHtml, scanSource } from "./bundle-scan.js";

const ROOT = join(import.meta.dirname, "..");
let out = "";

beforeAll(() => {
  out = mkdtempSync(join(tmpdir(), "ls-build-"));
  const r = spawnSync(process.execPath, [join(ROOT, "scripts", "build.mjs")], { env: { ...process.env, LAUNCHSAFE_DIST: out, LAUNCHSAFE_E2E_NATIVE: "" }, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`build failed: ${r.stderr}${r.stdout}`);
}, 60_000);

const files = (ext: string): string[] => readdirSync(out).filter((f) => f.endsWith(ext));

describe("built extension", () => {
  it("ships every script, page and icon the manifest names", () => {
    const m = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8")) as { background: { service_worker: string }; icons: Record<string, string> };
    expect(files(".js")).toEqual(expect.arrayContaining(["worker.js", "content.js", "sidepanel.js", "popup.js", "approval.js", "blocked.js"]));
    expect(readdirSync(join(out, "icons")).sort()).toEqual(["icon-128.png", "icon-16.png", "icon-32.png", "icon-48.png"]);
    for (const p of Object.values(m.icons)) expect(readdirSync(join(out, "icons"))).toContain(p.replace("icons/", ""));
  });

  it("ships its licence and notice next to the bundle", () => {
    for (const name of ["LICENSE", "NOTICE"]) expect(readFileSync(join(out, name), "utf8")).toBe(readFileSync(join(ROOT, name), "utf8"));
  });

  it("has no eval, new Function, fetch, XMLHttpRequest, WebSocket, EventSource or sendBeacon outside the allowlist", () => {
    const found = files(".js").flatMap((f) => scanSource(f, readFileSync(join(out, f), "utf8")));
    expect(disallowed(found)).toEqual([]);
  });

  it("has an empty allowlist: nothing in the bundle is allowed to touch the network", () => {
    expect(ALLOWLIST).toEqual([]);
  });

  it("has no remote or inline script, stylesheet or frame in any page", () => {
    const found = files(".html").flatMap((f) => remoteReferencesInHtml(f, readFileSync(join(out, f), "utf8")));
    expect(found).toEqual([]);
  });

  it("declares no web accessible resources and no host beyond <all_urls>", () => {
    const m = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8")) as Record<string, unknown>;
    expect(m.web_accessible_resources).toBeUndefined();
    expect(m.host_permissions).toEqual(["<all_urls>"]);
  });

  it("asks for nativeMessaging only as an optional permission (the link e2e build is the only exception)", () => {
    const m = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8")) as { permissions: string[]; optional_permissions: string[] };
    expect(m.permissions).not.toContain("nativeMessaging");
    expect(m.optional_permissions).toEqual(["nativeMessaging"]);
  });

  it("refuses the link e2e build into dist/", () => {
    const r = spawnSync(process.execPath, [join(ROOT, "scripts", "build.mjs")], { env: { ...process.env, LAUNCHSAFE_DIST: "", LAUNCHSAFE_E2E_NATIVE: "1" }, encoding: "utf8" });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/temp LAUNCHSAFE_DIST only/);
  });
});
