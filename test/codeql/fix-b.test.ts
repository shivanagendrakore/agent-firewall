import { describe, it, expect } from "vitest";
import { isUnder } from "../../src/engine/paths.js";
import { settingsRank } from "../../src/engine/sandbox.js";
import { settingsFilesUnder } from "../../src/engine/settings.js";
import { fallbackIdentity } from "../../src/engine/identity.js";
import { summarizeAction } from "../../src/engine/summary.js";

// CodeQL js/polynomial-redos: trailing slashes were stripped with /\/+$/, which retries from every slash of a long
// run that is not at the end. Each function now strips them in one pass; these pin the old results and the time.

const N = 200_000;
const slashes = "/".repeat(N);

function timed(fn: () => void): number {
  const t0 = performance.now();
  fn();
  return performance.now() - t0;
}

describe("isUnder (paths.ts)", () => {
  it("keeps its results", () => {
    expect(isUnder("/a/b", "/a/", false)).toBe(true);
    expect(isUnder("/a", "/a//", false)).toBe(true);
    expect(isUnder("/ab", "/a", false)).toBe(false);
    expect(isUnder("/a//b", "/a", false)).toBe(true);
    expect(isUnder("/A/b", "/a/", true)).toBe(true);
    expect(isUnder("/A/b", "/a/", false)).toBe(false);
    expect(isUnder("/x", "/", false)).toBe(true);
    expect(isUnder("/x", "", false)).toBe(true);
  });

  it("is linear on a long run of slashes", () => {
    let mid = true;
    let end = false;
    const ms = timed(() => {
      mid = isUnder("/x", `${slashes}a`, false);
      end = isUnder("/a/b", `/a${slashes}`, true);
    });
    expect(mid).toBe(false);
    expect(end).toBe(true);
    expect(ms).toBeLessThan(2000);
  });
});

describe("settingsRank (sandbox.ts)", () => {
  it("keeps its results", () => {
    expect(settingsRank("/p/.claude/settings.local.json", "/home/u")).toBe(3);
    expect(settingsRank("/p/.claude/settings.json", "/home/u")).toBe(2);
    expect(settingsRank("/home/u/.claude/settings.json", "/home/u")).toBe(1);
    expect(settingsRank("/home/u/.claude/settings.json", "/home/u//")).toBe(1);
    expect(settingsRank("/HOME/U/.claude/settings.json", "/home/u")).toBe(1);
    expect(settingsRank("/.claude/settings.json", "/")).toBe(1);
    expect(settingsRank("/p/x.json", "/home/u")).toBe(1);
  });

  it("is linear on a long run of slashes", () => {
    let rank = 0;
    const ms = timed(() => {
      rank = settingsRank("/p/.claude/settings.json", `${slashes}h`);
    });
    expect(rank).toBe(2);
    expect(ms).toBeLessThan(2000);
  });
});

describe("settingsFilesUnder (settings.ts)", () => {
  it("keeps its results", () => {
    expect(settingsFilesUnder("/p")[0]).toBe("/p/settings.json");
    expect(settingsFilesUnder("/p/")[0]).toBe("/p/settings.json");
    expect(settingsFilesUnder("/p//")[3]).toBe("/p/.claude/settings.local.json");
    expect(settingsFilesUnder("/")[0]).toBe("/settings.json");
    expect(settingsFilesUnder("/p")).toHaveLength(12);
  });

  it("is linear on a long run of slashes", () => {
    const dir = `${slashes}x`;
    let first = "";
    const ms = timed(() => {
      first = settingsFilesUnder(dir)[0] ?? "";
    });
    expect(first).toBe(`${dir}/settings.json`);
    expect(ms).toBeLessThan(2000);
  });
});

describe("fallbackIdentity (identity.ts trimSlash)", () => {
  it("keeps its results", () => {
    expect(fallbackIdentity("/opt/fw/").cliFiles).toEqual(["/opt/fw/dist/cli.js"]);
    expect(fallbackIdentity("/opt/fw//").packageRoots).toEqual(["/opt/fw"]);
    expect(fallbackIdentity("/opt/fw").runtimeRoots).toEqual(["/opt/fw/dist", "/opt/fw/node_modules"]);
    // A lone "/" is kept; a longer all-slash path trims to nothing.
    expect(fallbackIdentity("/").cliFiles).toEqual(["//dist/cli.js"]);
    expect(fallbackIdentity("//").cliFiles).toEqual([]);
    expect(fallbackIdentity("").cliFiles).toEqual([]);
  });

  it("is linear on a long run of slashes", () => {
    const dir = `${slashes}x`;
    let roots: string[] = [];
    const ms = timed(() => {
      roots = fallbackIdentity(dir).packageRoots;
    });
    expect(roots).toEqual([dir]);
    expect(ms).toBeLessThan(2000);
  });
});

describe("summarizeAction relative paths (summary.ts)", () => {
  it("keeps its results", () => {
    expect(summarizeAction("Read", { file_path: "/w/src/a.ts" }, "/w/")).toBe("Read src/a.ts");
    expect(summarizeAction("Read", { file_path: "/w/src/a.ts" }, "/w")).toBe("Read src/a.ts");
    expect(summarizeAction("Read", { file_path: "/w/src/a.ts" }, "/w//")).toBe("Read src/a.ts");
    expect(summarizeAction("Read", { file_path: "/w/src/a.ts" }, "")).toBe("Read /w/src/a.ts");
    expect(summarizeAction("Read", { file_path: "/w/src/a.ts" }, "/")).toBe("Read w/src/a.ts");
    expect(summarizeAction("Write", { file_path: "/wx/a.ts" }, "/w")).toBe("Change /wx/a.ts");
  });

  it("is linear on a long run of slashes", () => {
    let line = "";
    const ms = timed(() => {
      line = summarizeAction("Read", { file_path: "/w/a" }, `${slashes}x`);
    });
    expect(line).toBe("Read /w/a");
    expect(ms).toBeLessThan(2000);
  });
});
