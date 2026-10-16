/**
 * F-a: the test-home guard and the suite's own protection. Acceptance rows A13-A16, A21.
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir, tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { assertNotRealHome, RealHomeRefused } from "../src/runtime/guard.js";
import { install, uninstall } from "../src/runtime/install.js";
import { initApprover } from "../src/runtime/approver.js";
import { layout } from "../src/runtime/layout.js";
import { realHomeProblem } from "./setup-assert.js";
import { REPO, tempHome } from "./helpers.js";

const REAL = userInfo().homedir;
const MARKED = { LAUNCHSAFE_FIREWALL_TEST: "1" } as NodeJS.ProcessEnv;

describe("assertNotRealHome", () => {
  it("A13: with the test marker, a target under the real home is refused", () => {
    expect(() => assertNotRealHome(join(REAL, ".claude", "settings.json"), MARKED)).toThrow(RealHomeRefused);
    expect(() => assertNotRealHome(join(REAL, ".launchsafe-firewall"), { VITEST: "true" })).toThrow(RealHomeRefused);
  });
  it("A13: install() with HOME pointing at the real home is refused and writes nothing", () => {
    const fw = layout(join(tempHome(), ".launchsafe-firewall"));
    expect(() => install(fw, "user", tmpdir(), "0.2.0-dev", { home: REAL, platform: "darwin" })).toThrow(RealHomeRefused);
    expect(existsSync(join(fw.home, "install.json"))).toBe(false);
    // The firewall's state directory itself under the real home is refused too.
    expect(() => install(layout(join(REAL, ".launchsafe-firewall")), "user", tmpdir(), "0.2.0-dev", { home: tempHome(), platform: "darwin" })).toThrow(RealHomeRefused);
    expect(() => uninstall(layout(join(REAL, ".launchsafe-firewall")))).toThrow(RealHomeRefused);
    expect(() => initApprover(layout(join(REAL, ".launchsafe-firewall")), "correct horse battery")).toThrow(RealHomeRefused);
  });
  it("A14: with the test marker and a temporary home, install proceeds", () => {
    const home = tempHome();
    const fw = layout(join(home, ".launchsafe-firewall"));
    const r = install(fw, "user", home, "0.2.0-dev", { home, platform: "darwin" });
    expect(r.path).toBe(join(home, ".claude", "settings.json"));
    expect(existsSync(r.path)).toBe(true);
  });
  it("A15: without the test marker the guard is inactive (production)", () => {
    expect(() => assertNotRealHome(join(REAL, ".claude", "settings.json"), {})).not.toThrow();
  });
  it("A16: when the password database has no entry, only temporary paths are allowed", () => {
    const noEntry = { userInfo: (): { homedir: string } => { throw new Error("no passwd entry"); } };
    expect(() => assertNotRealHome("/Users/x/.claude/settings.json", MARKED, noEntry)).toThrow(RealHomeRefused);
    expect(() => assertNotRealHome(join(tmpdir(), "a", "settings.json"), MARKED, noEntry)).not.toThrow();
  });
});

describe("the suite's own home (A21, INST-015)", () => {
  it("this worker's home is the temporary one", () => {
    expect(homedir()).not.toBe(REAL);
    expect(process.env.LAUNCHSAFE_FIREWALL_TEST).toBe("1");
    expect(realHomeProblem(homedir(), () => REAL)).toBeNull();
  });
  it("the setup assertion reports a real home", () => {
    expect(realHomeProblem(REAL, () => REAL)).toMatch(/real one/);
  });
  it("A21: a test file run with HOME equal to the real home fails immediately", () => {
    const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, HOME: REAL, TMPDIR: process.env.TMPDIR };
    const r = spawnSync(process.execPath, [join(REPO, "node_modules", "vitest", "vitest.mjs"), "run", "--config", "test/fixtures/home-probe/vitest.config.ts"], { cwd: REPO, encoding: "utf8", env, timeout: 60000 });
    expect(r.status, r.stdout + r.stderr).not.toBe(0);
    expect(r.stdout + r.stderr).toContain("Refusing to run against the real home directory");
  }, 60000);
});
