/**
 * CodeQL fixes (set D): keys placed in a RegExp are escaped whole, the backslash included
 * (js/incomplete-sanitization), and the settings-key lookups read the same as before for the
 * keys the firewall uses. Every home and project here is a temporary directory.
 */

import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { tomlTopLevel } from "../../src/adapters/codex.js";
import { cooldownStatus, planCooldownFixes } from "../../src/runtime/cooldown.js";
import { testRoot } from "../helpers.js";

function dir(files: Record<string, string> = {}, prefix = "cql-d-"): string {
  const d = mkdtempSync(join(testRoot(), prefix));
  for (const [f, text] of Object.entries(files)) {
    mkdirSync(join(d, f, ".."), { recursive: true });
    writeFileSync(join(d, f), text);
  }
  return d;
}

describe("tomlTopLevel escapes the key", () => {
  it("reads plain and dotted keys as before", () => {
    expect(tomlTopLevel('approval_policy = "never"\n', "approval_policy")).toBe("never");
    expect(tomlTopLevel("a.b = 'x'\n", "a.b")).toBe("x");
    expect(tomlTopLevel('aXb = "x"\n', "a.b")).toBeNull();
    expect(tomlTopLevel('[t]\napproval_policy = "never"\n', "approval_policy")).toBeNull();
  });
  it("a backslash in the key is a literal backslash, not the start of a regex escape", () => {
    // Before the fix the key a\d became the pattern a\d (a digit), so it matched a1 and missed a\d.
    expect(tomlTopLevel('a1 = "wrong"\n', "a\\d")).toBeNull();
    expect(tomlTopLevel('a\\d = "right"\n', "a\\d")).toBe("right");
    // A trailing backslash used to swallow the \s that follows it.
    expect(tomlTopLevel('x\\ = "v"\n', "x\\")).toBe("v");
  });
  it("other metacharacters in the key are literal", () => {
    expect(tomlTopLevel('aaa = "wrong"\n', "a+")).toBeNull();
    expect(tomlTopLevel('a+ = "right"\n', "a+")).toBe("right");
  });
});

describe("cooldown settings keep their keys after the escape change", () => {
  const env = (home: string) => ({ home, platform: "linux" as const, env: {} });

  it("pnpm: a configured rc is read, a zero one is replaced in place", () => {
    const home = dir({ ".config/pnpm/rc": "minimum-release-age=4320\n" }, "home-");
    const proj = dir({ "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" });
    expect(cooldownStatus(proj, env(home)).find((s) => s.manager === "pnpm")?.state).toBe("configured");

    const home2 = dir({ ".config/pnpm/rc": "minimum-release-age=0\nother=1\n" }, "home-");
    const fix = planCooldownFixes(proj, env(home2)).find((f) => f.manager === "pnpm");
    expect(fix?.after).toBe("minimum-release-age=4320\nother=1\n");
  });
  it("yarn: npmMinimalAgeGate is replaced in place", () => {
    const home = dir({ ".yarnrc.yml": "npmMinimalAgeGate: 0\nenableTelemetry: false\n" }, "home-");
    const proj = dir({ "yarn.lock": "__metadata:\n  version: 8\n" });
    const fix = planCooldownFixes(proj, env(home)).find((f) => f.manager === "yarn");
    expect(fix?.after).toBe("npmMinimalAgeGate: 4320\nenableTelemetry: false\n");
  });
  it("bun: install.minimumReleaseAge is replaced in its table only", () => {
    const home = dir({ ".bunfig.toml": "minimumReleaseAge = 1\n[install]\nminimumReleaseAge = 0\n" }, "home-");
    const proj = dir({ "bun.lock": "{}\n" });
    const fix = planCooldownFixes(proj, env(home)).find((f) => f.manager === "bun");
    expect(fix?.after).toBe("minimumReleaseAge = 1\n[install]\nminimumReleaseAge = 259200\n");
  });
  it("uv: a configured exclude-newer is read", () => {
    const home = dir({ ".config/uv/uv.toml": 'exclude-newer = "3 days"\n' }, "home-");
    const proj = dir({ "uv.lock": "version = 1\n" });
    expect(cooldownStatus(proj, env(home)).find((s) => s.manager === "uv")?.state).toBe("configured");
  });
});
