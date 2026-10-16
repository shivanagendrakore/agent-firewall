/**
 * Package-manager cooldown checks in doctor (P13, INST-016) and the
 * user-level fix `doctor --fix` writes after showing the diff (P14). Every
 * home and project here is a temporary directory.
 */

import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { applyCooldownFix, cooldownStatus, detectManagers, planCooldownFixes, pnpmGlobalRc } from "../src/runtime/cooldown.js";
import { doctor } from "../src/runtime/doctor.js";
import { layout } from "../src/runtime/layout.js";
import { cooldownCheck } from "../src/runtime/package-doctor.js";
import { testRoot } from "./helpers.js";

function dir(files: Record<string, string> = {}, prefix = "cd-"): string {
  const d = mkdtempSync(join(testRoot(), prefix));
  for (const [f, text] of Object.entries(files)) {
    mkdirSync(join(d, f, ".."), { recursive: true });
    writeFileSync(join(d, f), text);
  }
  return d;
}

describe("cooldown detection", () => {
  it("P13 / INST-016: a pnpm project without minimumReleaseAge warns", () => {
    const home = dir({}, "home-");
    const proj = dir({ "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" });
    const c = cooldownCheck(proj, { home, platform: "linux", env: {} });
    expect(c.status).toBe("warn");
    expect(c.detail).toContain("pnpm: no minimumReleaseAge");
  });
  it("P13: the check shows up in doctor with a warning", () => {
    const home = dir({}, "home-");
    const proj = dir({ "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" });
    const checks = doctor(layout(join(home, ".launchsafe-firewall")), proj, { home, platform: "linux", claudeVersion: null });
    const c = checks.find((x) => x.name === "package cooldown");
    expect(c?.status).toBe("warn");
    expect(checks.find((x) => x.name === "malicious-package data")?.status).toBe("warn");
  });
  it("configured in the project or the user config counts", () => {
    const home = dir({}, "home-");
    expect(cooldownStatus(dir({ "pnpm-lock.yaml": "", "pnpm-workspace.yaml": "packages:\n  - 'apps/*'\nminimumReleaseAge: 1440\n" }), { home, platform: "linux", env: {} })[0]?.state).toBe("configured");
    expect(cooldownStatus(dir({ "pnpm-lock.yaml": "", ".npmrc": "minimum-release-age=4320\n" }), { home, platform: "linux", env: {} })[0]?.state).toBe("configured");
    const homeRc = dir({ ".config/pnpm/rc": "minimum-release-age=4320\n" }, "home-");
    expect(cooldownStatus(dir({ "pnpm-lock.yaml": "" }), { home: homeRc, platform: "linux", env: {} }).find((s) => s.manager === "pnpm")?.state).toBe("configured");
    expect(cooldownStatus(dir({ "pnpm-lock.yaml": "", "pnpm-workspace.yaml": "minimumReleaseAge: 0\n" }), { home, platform: "linux", env: {} })[0]?.state).toBe("missing");
  });
  it("Yarn Berry, Bun and uv settings", () => {
    const home = dir({}, "home-");
    const e = { home, platform: "linux" as const, env: {} };
    expect(cooldownStatus(dir({ "yarn.lock": "__metadata:\n  version: 8\n", ".yarnrc.yml": "npmMinimalAgeGate: 4320\n" }), e)[0]?.state).toBe("configured");
    expect(cooldownStatus(dir({ "yarn.lock": "__metadata:\n  version: 8\n" }), e)[0]?.state).toBe("missing");
    expect(cooldownStatus(dir({ "yarn.lock": "# yarn lockfile v1\n" }), e)[0]?.state).toBe("unavailable");
    expect(cooldownStatus(dir({ "bun.lock": "{}", "bunfig.toml": "[install]\nminimumReleaseAge = 259200\n" }), e)[0]?.state).toBe("configured");
    expect(cooldownStatus(dir({ "bun.lock": "{}", "bunfig.toml": "[test]\nminimumReleaseAge = 259200\n" }), e)[0]?.state).toBe("missing");
    expect(cooldownStatus(dir({ "uv.lock": "", "pyproject.toml": '[project]\nname = "x"\n\n[tool.uv]\nexclude-newer = "3 days"\n' }), e)[0]?.state).toBe("configured");
    expect(cooldownStatus(dir({ "uv.lock": "" }), e)[0]?.state).toBe("missing");
  });
  it("npm and pip have no rolling cooldown and say so", () => {
    const home = dir({}, "home-");
    const st = cooldownStatus(dir({ "package-lock.json": "{}", "requirements.txt": "" }), { home, platform: "linux", env: {} });
    expect(st.map((s) => `${s.manager}:${s.state}`).sort()).toEqual(["npm:unavailable", "pip:unavailable"]);
    expect(st.find((s) => s.manager === "npm")?.detail).toContain("no rolling");
  });
  it("no package manager: ok", () => {
    const home = dir({}, "home-");
    expect(detectManagers(dir({ "README.md": "x" }), { home, platform: "linux", env: {} })).toEqual([]);
    expect(cooldownCheck(dir({ "README.md": "x" }), { home, platform: "linux", env: {} }).status).toBe("ok");
  });
});

describe("doctor --fix: user-level cooldowns (P14)", () => {
  it("P14: pnpm: shows a diff, writes the user-level rc (never the project), keeps a backup", () => {
    const home = dir({ ".config/pnpm/rc": "store-dir=/x\n" }, "home-");
    const proj = dir({ "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" });
    const projBefore = readFileSync(join(proj, "pnpm-lock.yaml"), "utf8");
    const e = { home, platform: "linux" as const, env: {} };
    const fixes = planCooldownFixes(proj, e);
    expect(fixes.map((f) => f.manager)).toEqual(["pnpm"]);
    const fix = fixes[0];
    if (fix === undefined) throw new Error("no fix");
    expect(fix.path).toBe(pnpmGlobalRc(e));
    expect(fix.diff).toContain("+ minimum-release-age=4320");
    expect(fix.after).toBe("store-dir=/x\nminimum-release-age=4320\n");
    const backups = join(home, ".launchsafe-firewall", "backups");
    const backup = applyCooldownFix(fix, backups);
    expect(backup).not.toBeNull();
    expect(readFileSync(backup as string, "utf8")).toBe("store-dir=/x\n");
    expect(readFileSync(fix.path, "utf8")).toContain("minimum-release-age=4320");
    expect(readFileSync(join(proj, "pnpm-lock.yaml"), "utf8")).toBe(projBefore);
    expect(existsSync(join(proj, ".npmrc"))).toBe(false);
    expect(cooldownStatus(proj, e)[0]?.state).toBe("configured");
    expect(planCooldownFixes(proj, e)).toEqual([]);
  });
  it("macOS puts pnpm's global rc under Library/Preferences", () => {
    expect(pnpmGlobalRc({ home: "/Users/x", platform: "darwin" })).toBe("/Users/x/Library/Preferences/pnpm/rc");
  });
  it("Yarn, Bun and uv files are created or edited in place", () => {
    const home = dir({ ".bunfig.toml": '[install]\nregistry = "https://registry.npmjs.org"\n\n[test]\ncoverage = true\n' }, "home-");
    const proj = dir({ "yarn.lock": "__metadata:\n  version: 8\n", "bun.lock": "{}", "uv.lock": "" });
    const e = { home, platform: "linux" as const, env: {} };
    const fixes = planCooldownFixes(proj, e);
    const by = Object.fromEntries(fixes.map((f) => [f.manager, f]));
    expect(by.yarn?.after).toBe("npmMinimalAgeGate: 4320\n");
    expect(by.bun?.after).toBe('[install]\nregistry = "https://registry.npmjs.org"\nminimumReleaseAge = 259200\n\n[test]\ncoverage = true\n');
    expect(by.uv?.after).toBe('exclude-newer = "3 days"\n');
    expect(by.uv?.path).toBe(join(home, ".config", "uv", "uv.toml"));
    for (const f of fixes) applyCooldownFix(f, join(home, "backups"));
    expect(cooldownStatus(proj, e).every((s) => s.state === "configured")).toBe(true);
  });
  it("an existing zero value is replaced, not duplicated", () => {
    const home = dir({ ".yarnrc.yml": "nodeLinker: node-modules\nnpmMinimalAgeGate: 0\n" }, "home-");
    const fixes = planCooldownFixes(dir({ "yarn.lock": "__metadata:\n" }), { home, platform: "linux", env: {} });
    expect(fixes[0]?.after).toBe("nodeLinker: node-modules\nnpmMinimalAgeGate: 4320\n");
  });
  it("a rc file that exists but could not be read is not planned over, and a fix keeps the file's mode and writes through a symlink", () => {
    const e = (home: string) => ({ home, platform: "linux" as const, env: {} });
    const big = dir({ ".yarnrc.yml": `# ${"x".repeat(1024 * 1024 + 10)}\n` }, "home-");
    expect(planCooldownFixes(dir({ "yarn.lock": "__metadata:\n" }), e(big))).toEqual([]);
    const home = dir({ ".bunfig.toml": "[install]\n" }, "home-");
    chmodSync(join(home, ".bunfig.toml"), 0o600);
    const proj = dir({ "bun.lock": "{}" });
    const fix = planCooldownFixes(proj, e(home))[0];
    if (fix === undefined) throw new Error("no fix");
    applyCooldownFix(fix, join(home, "backups"));
    expect(statSync(join(home, ".bunfig.toml")).mode & 0o777).toBe(0o600);
    const linked = dir({ "dotfiles/yarnrc.yml": "nodeLinker: node-modules\n" }, "home-");
    symlinkSync(join(linked, "dotfiles", "yarnrc.yml"), join(linked, ".yarnrc.yml"));
    const yfix = planCooldownFixes(dir({ "yarn.lock": "__metadata:\n" }), e(linked))[0];
    if (yfix === undefined) throw new Error("no fix");
    applyCooldownFix(yfix, join(linked, "backups"));
    expect(lstatSync(join(linked, ".yarnrc.yml")).isSymbolicLink()).toBe(true);
    expect(readFileSync(join(linked, "dotfiles", "yarnrc.yml"), "utf8")).toContain("npmMinimalAgeGate: 4320");
  });
  it("the guard refuses to write under the real home while testing", () => {
    const fix = { manager: "pnpm" as const, path: join(require("node:os").userInfo().homedir as string, ".config", "pnpm", "rc-lsfw-test"), before: null, after: "x\n", diff: [] };
    expect(() => applyCooldownFix(fix, join(testRoot(), "b"))).toThrow(/real home/);
  });
});
