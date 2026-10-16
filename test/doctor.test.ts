/** doctor's checks: hooks present/first/fail-closed, disableAllHooks, policy, log, managed recommendation. */
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { doctor } from "../src/runtime/doctor.js";
import { install } from "../src/runtime/install.js";
import { atomicWrite } from "../src/runtime/fsutil.js";
import { layout } from "../src/runtime/layout.js";
import { settingsPath } from "../src/runtime/install.js";
import { initApprover, rotateApprover } from "../src/runtime/approver.js";

let root: string, l: ReturnType<typeof layout>;
beforeEach(() => { root = mkdtempSync(join(tmpdir(), "lsfw-dr-")); l = layout(join(root, "home")); });
afterEach(() => rmSync(root, { recursive: true, force: true }));
const find = (cs: ReturnType<typeof doctor>, name: string) => cs.find((c) => c.name.startsWith(name));

describe("doctor", () => {
  it("reports hooks not installed", () => {
    const c = doctor(l, root, { home: root, platform: "darwin", claudeVersion: "2.1.289" });
    expect(find(c, "hooks")?.status).toBe("fail");
  });
  it("reports a clean install as ok and recommends managed settings", () => {
    install(l, "user", root, "0.1.0", { home: root, platform: "darwin" });
    const c = doctor(l, root, { home: root, platform: "darwin", claudeVersion: "2.1.289" });
    expect(find(c, "hooks (user)")?.status).toBe("ok");
    expect(find(c, "managed settings")?.status).toBe("warn");
    expect(find(c, "managed settings")?.detail).toMatch(/allowManagedHooksOnly|managed/i);
  });
  it("flags disableAllHooks", () => {
    install(l, "user", root, "0.1.0", { home: root, platform: "darwin" });
    atomicWrite(settingsPath("project", root, root), JSON.stringify({ disableAllHooks: true }));
    const c = doctor(l, root, { home: root, platform: "darwin", claudeVersion: "2.1.289" });
    expect(find(c, "disableAllHooks")?.status).toBe("fail");
  });
  it("flags an invalid policy", () => {
    atomicWrite(l.policy, JSON.stringify({ version: 1, denyHosts: "nope" }));
    const c = doctor(l, root, { home: root, platform: "darwin", claudeVersion: "2.1.289" });
    expect(find(c, "policy")?.status).toBe("fail");
  });
  it("flags an outdated Claude Code version", () => {
    install(l, "user", root, "0.1.0", { home: root, platform: "darwin" });
    const c = doctor(l, root, { home: root, platform: "darwin", claudeVersion: "1.0.0" });
    expect(find(c, "Claude Code")?.status).toBe("fail");
  });
  it("approval passphrase: missing -> warn, pinned -> ok, rotated without reinstall -> fail", () => {
    install(l, "user", root, "0.1.0", { home: root, platform: "darwin" });
    expect(find(doctor(l, root, { home: root, platform: "darwin", claudeVersion: "2.1.289" }), "approval passphrase")?.status).toBe("warn");
    initApprover(l, "correct horse battery");
    install(l, "user", root, "0.1.0", { home: root, platform: "darwin" });
    expect(find(doctor(l, root, { home: root, platform: "darwin", claudeVersion: "2.1.289" }), "approval passphrase")?.status).toBe("ok");
    rotateApprover(l, "correct horse battery", "another long passphrase");
    expect(find(doctor(l, root, { home: root, platform: "darwin", claudeVersion: "2.1.289" }), "approval passphrase")?.status).toBe("fail");
  });
  it("SR3: a hook command that does not clear NODE_COMPILE_CACHE fails; installing again fixes it", () => {
    install(l, "user", root, "0.1.0", { home: root, platform: "darwin" });
    const hookCheck = () => doctor(l, root, { home: root, platform: "darwin", claudeVersion: "2.1.289" }).filter((c) => c.name === "hook command" && /NODE_COMPILE_CACHE/.test(c.detail));
    expect(hookCheck()).toEqual([]);
    const p = settingsPath("user", root, root);
    atomicWrite(p, readFileSync(p, "utf8").replaceAll("NODE_COMPILE_CACHE= ", ""));
    expect(hookCheck().map((c) => c.status)).toEqual(["fail"]);
    install(l, "user", root, "0.1.0", { home: root, platform: "darwin" });
    expect(readFileSync(p, "utf8")).toContain("NODE_COMPILE_CACHE= ");
    expect(hookCheck()).toEqual([]);
  });
});
