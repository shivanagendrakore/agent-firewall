/**
 * install --browser: the host manifest goes only into the browser's per-user NativeMessagingHosts
 * directory (inside a temporary home here), allowed for the given extension id only; uninstall removes
 * exactly what install wrote; doctor reports a missing, edited or widened manifest.
 */

import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { layout, type Layout } from "../../src/runtime/layout.js";
import { allowedOrigins, BROWSERS, browserLinkChecks, hostManifestDir, installHost, launcherPath, readHostInstalls, uninstallHost } from "../../src/runtime/native/browsers.js";
import { RealHomeRefused } from "../../src/runtime/guard.js";

const ID = "a".repeat(32);
const ID2 = "b".repeat(32);
let root: string;
let home: string;
let l: Layout;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-native-"));
  home = join(root, "home");
  mkdirSync(home);
  l = layout(join(home, ".launchsafe-firewall"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("where the manifest goes", () => {
  it("is each browser's per-user directory on macOS and Linux, never a system one", () => {
    expect(hostManifestDir("chrome", { home, platform: "darwin" })).toBe(join(home, "Library/Application Support/Google/Chrome/NativeMessagingHosts"));
    expect(hostManifestDir("chromium", { home, platform: "darwin" })).toBe(join(home, "Library/Application Support/Chromium/NativeMessagingHosts"));
    expect(hostManifestDir("edge", { home, platform: "darwin" })).toBe(join(home, "Library/Application Support/Microsoft Edge/NativeMessagingHosts"));
    expect(hostManifestDir("brave", { home, platform: "darwin" })).toBe(join(home, "Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"));
    expect(hostManifestDir("chrome", { home, platform: "linux" })).toBe(join(home, ".config/google-chrome/NativeMessagingHosts"));
    expect(hostManifestDir("brave", { home, platform: "linux" })).toBe(join(home, ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts"));
    for (const b of BROWSERS) for (const platform of ["darwin", "linux"] as const) expect(hostManifestDir(b, { home, platform }).startsWith(home)).toBe(true);
  });

  it("is <user data dir>/NativeMessagingHosts for a profile started with --user-data-dir", () => {
    expect(hostManifestDir("chromium", { userDataDir: join(root, "profile") })).toBe(join(root, "profile", "NativeMessagingHosts"));
  });

  it("refuses Windows (the registry is never written)", () => {
    expect(() => hostManifestDir("chrome", { home, platform: "win32" })).toThrow(/macOS and Linux/);
  });
});

describe("installHost", () => {
  it("writes the manifest pinned to the extension id and a launcher that pins the firewall's home", () => {
    const r = installHost(l, "chrome", [ID], { home, platform: "darwin", nodePath: "/usr/local/bin/node", cli: "/opt/fw/dist/cli.js" });
    expect(r.changed).toBe(true);
    const m = JSON.parse(readFileSync(r.manifest, "utf8")) as Record<string, unknown>;
    expect(m).toEqual({ name: "com.launchsafe.agent_firewall", description: expect.any(String), path: launcherPath(l), type: "stdio", allowed_origins: [`chrome-extension://${ID}/`] });
    const script = readFileSync(r.launcher, "utf8");
    expect(script.startsWith("#!/bin/sh\n")).toBe(true);
    expect(script).toContain(`LAUNCHSAFE_FIREWALL_HOME='${l.home}'`);
    expect(script).toContain("NODE_COMPILE_CACHE= NODE_OPTIONS= NODE_PATH= LD_PRELOAD= DYLD_INSERT_LIBRARIES= exec '/usr/local/bin/node' '/opt/fw/dist/cli.js' native-host \"$@\"");
    expect(statSync(r.launcher).mode & 0o777).toBe(0o700);
    expect(allowedOrigins(l)).toEqual([`chrome-extension://${ID}/`]);
  });

  it("is idempotent, and records each browser separately", () => {
    installHost(l, "chrome", [ID], { home, platform: "darwin" });
    expect(installHost(l, "chrome", [ID], { home, platform: "darwin" }).changed).toBe(false);
    installHost(l, "brave", [ID2], { home, platform: "darwin" });
    expect(readHostInstalls(l).map((r) => r.browser).sort()).toEqual(["brave", "chrome"]);
    expect(allowedOrigins(l).sort()).toEqual([`chrome-extension://${ID}/`, `chrome-extension://${ID2}/`]);
  });

  it("refuses a missing or malformed extension id", () => {
    expect(() => installHost(l, "chrome", [], { home, platform: "darwin" })).toThrow(/--extension-id/);
    expect(() => installHost(l, "chrome", ["not-an-id"], { home, platform: "darwin" })).toThrow(/not an extension id/);
    expect(() => installHost(l, "chrome", ["A".repeat(32)], { home, platform: "darwin" })).toThrow(/not an extension id/);
    expect(existsSync(hostManifestDir("chrome", { home, platform: "darwin" }))).toBe(false);
  });

  it("does not overwrite a manifest another program wrote under the same name", () => {
    const dir = hostManifestDir("chrome", { home, platform: "darwin" });
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "com.launchsafe.agent_firewall.json"), JSON.stringify({ name: "com.launchsafe.agent_firewall", path: "/tmp/evil" }));
    expect(() => installHost(l, "chrome", [ID], { home, platform: "darwin" })).toThrow(/not written by this firewall/);
  });

  it("refuses the real home directory while a test marker is set", () => {
    expect(() => installHost(l, "chrome", [ID], { home: userInfo().homedir, platform: process.platform === "darwin" ? "darwin" : "linux" })).toThrow(RealHomeRefused);
  });
});

describe("uninstallHost", () => {
  it("removes the manifests install wrote, and the launcher with the last one", () => {
    const a = installHost(l, "chrome", [ID], { home, platform: "darwin" });
    const b = installHost(l, "edge", [ID], { home, platform: "darwin" });
    expect(uninstallHost(l, "chrome")).toEqual([{ manifest: a.manifest, action: "removed" }]);
    expect(existsSync(a.manifest)).toBe(false);
    expect(existsSync(launcherPath(l))).toBe(true);
    expect(uninstallHost(l)).toEqual([{ manifest: b.manifest, action: "removed" }]);
    expect(existsSync(launcherPath(l))).toBe(false);
    expect(readHostInstalls(l)).toEqual([]);
  });

  it("leaves a manifest that was edited to run something else", () => {
    const a = installHost(l, "chrome", [ID], { home, platform: "darwin" });
    writeFileSync(a.manifest, JSON.stringify({ name: "com.launchsafe.agent_firewall", path: "/tmp/other", type: "stdio", allowed_origins: [] }));
    expect(uninstallHost(l, "chrome")).toEqual([{ manifest: a.manifest, action: "left-edited" }]);
    expect(existsSync(a.manifest)).toBe(true);
  });
});

describe("doctor checks", () => {
  it("says the link is optional when nothing is installed", () => {
    expect(browserLinkChecks(l)).toEqual([{ name: "browser link", status: "ok", detail: expect.stringContaining("not set up") }]);
  });

  it("passes for a fresh install", () => {
    installHost(l, "chrome", [ID], { home, platform: "darwin" });
    expect(browserLinkChecks(l)).toEqual([{ name: "browser link (chrome)", status: "ok", detail: expect.stringContaining(`allowed for ${ID} only`) }]);
  });

  it("fails for a missing manifest, a widened allowed_origins, another launcher, and a launcher others can write", () => {
    const r = installHost(l, "chrome", [ID], { home, platform: "darwin" });
    const m = JSON.parse(readFileSync(r.manifest, "utf8")) as Record<string, unknown>;
    writeFileSync(r.manifest, JSON.stringify({ ...m, allowed_origins: [`chrome-extension://${ID}/`, `chrome-extension://${ID2}/`] }));
    expect(browserLinkChecks(l)[0]).toMatchObject({ status: "fail", detail: expect.stringContaining("allows other extensions") });
    writeFileSync(r.manifest, JSON.stringify({ ...m, path: "/tmp/other" }));
    expect(browserLinkChecks(l)[0]).toMatchObject({ status: "fail", detail: expect.stringContaining("does not run this firewall's launcher") });
    writeFileSync(r.manifest, JSON.stringify(m));
    chmodSync(r.launcher, 0o722);
    expect(browserLinkChecks(l)[0]).toMatchObject({ status: "fail", detail: expect.stringContaining("other users") });
    rmSync(r.manifest);
    expect(browserLinkChecks(l)[0]).toMatchObject({ status: "fail", detail: expect.stringContaining("missing") });
  });

  it("fails on a damaged install record instead of reading it as nothing installed", () => {
    mkdirSync(join(l.home, "native-host"), { recursive: true });
    writeFileSync(join(l.home, "native-host", "installs.json"), "{broken");
    expect(browserLinkChecks(l)[0]).toMatchObject({ status: "fail" });
    expect(() => allowedOrigins(l)).toThrow();
  });
});
