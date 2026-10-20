import { describe, it, expect } from "vitest";
import { isGitConfig, isGitInfoAttributes, isHookBody } from "../../src/engine/autorun.js";
import type { Collector } from "../../src/engine/effects.js";
import { notedPackages, notePackageCommand } from "../../src/engine/packages.js";
import { destinationsFromPrompt } from "../../src/engine/post.js";
import type { Word } from "../../src/engine/shell/parse.js";

/** The regexes these functions used before the CodeQL fixes: the new code must agree with them. */
const OLD_HOOK_BODY = /\/\.git\/hooks\/|\/\.git\/modules\/(?:[^/]+\/)+hooks\/|\/\.husky\/|\/\.githooks\/|\/\.lefthook\/|\/lefthook(?:-local)?\.yml$|\/\.pre-commit-(?:config|hooks)\.yaml$/i;
const OLD_GIT_CONFIG = /\/\.git\/(?:modules\/(?:[^/]+\/)+)?config(?:\.worktree)?$|\/\.git\/worktrees\/[^/]+\/config(?:\.worktree)?$/i;
const OLD_INFO_ATTRIBUTES = /\/\.git\/(?:modules\/(?:[^/]+\/)+)?info\/attributes$/i;
const OLD_GO = /^([a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s@]+)*)(?:@(.+))?$/i;

const N = 200_000;

function timed(fn: () => void): number {
  const t = performance.now();
  fn();
  return performance.now() - t;
}

const PATHS = [
  "/r/.git/hooks/pre-commit",
  "/r/.git/hooks/",
  "/r/.git/hooks",
  "/r/.GIT/Hooks/post-checkout",
  ".git/hooks/pre-commit",
  "/r/.git/modules/sub/hooks/pre-commit",
  "/r/.git/modules/a/b/hooks/x",
  "/r/.git/modules/hooks/x",
  "/r/.git/modules/hooks/hooks/x",
  "/r/.git/modules//hooks/x",
  "/r/.git/modules/a//hooks/x",
  "/r/.git/modules/.git/modules/hooks/x",
  "/r/.git/modules/x/.git/hooks/y",
  "/r/x.git/hooks/y",
  "/r/.husky/pre-commit",
  "/r/.githooks/x",
  "/r/.lefthook/x",
  "/r/lefthook.yml",
  "/r/lefthook-local.yml",
  "/r/.pre-commit-config.yaml",
  "/r/.pre-commit-hooks.yaml",
  "/r/.git/config",
  "/r/.git/CONFIG",
  "/r/.git/config.worktree",
  "/r/.git/config/",
  "/r/.git/configx",
  ".git/config",
  "/.git/config",
  "/r/.git/modules/sub/config",
  "/r/.git/modules/a/b/config.worktree",
  "/r/.git/modules/config",
  "/r/.git/modules//config",
  "/r/.git/worktrees/w/config",
  "/r/.git/worktrees/w/config.worktree",
  "/r/.git/worktrees//config",
  "/r/.git/worktrees/config",
  "/r/.git/info/attributes",
  "/r/.git/INFO/Attributes",
  "/r/.git/modules/sub/info/attributes",
  "/r/.git/modules/info/attributes",
  "/r/.git/modules/a//info/attributes",
  "/r/.git/info/attributes/",
  ".git/info/attributes",
  "/r/src/index.ts",
  "C:\\r\\.git\\hooks\\pre-commit",
  "/r/.git/modules/a\\b/hooks/x",
  "",
  "/",
  "//",
];

describe("git hook and config paths (CodeQL #1, #2, #3)", () => {
  it("isHookBody agrees with the old regex", () => {
    for (const p of PATHS) expect(isHookBody(p), p).toBe(OLD_HOOK_BODY.test(p));
  });

  it("isGitConfig agrees with the old regex", () => {
    for (const p of PATHS) expect(isGitConfig(p), p).toBe(OLD_GIT_CONFIG.test(p));
  });

  it("isGitInfoAttributes agrees with the old regex", () => {
    for (const p of PATHS) expect(isGitInfoAttributes(p), p).toBe(OLD_INFO_ATTRIBUTES.test(p));
  });

  it("keeps the known answers", () => {
    expect(isHookBody("/r/.git/modules/sub/hooks/pre-commit")).toBe(true);
    expect(isHookBody("/r/.git/modules/hooks/x")).toBe(false);
    expect(isGitConfig("/r/.git/modules/sub/config")).toBe(true);
    expect(isGitConfig("/r/.git/worktrees/w/config.worktree")).toBe(true);
    expect(isGitConfig("/r/.git/modules/config")).toBe(false);
    expect(isGitInfoAttributes("/r/.git/modules/sub/info/attributes")).toBe(true);
  });

  it("is linear on a path that repeats .git/modules/", () => {
    const evil = `/.git/modules/${"./.git/modules/.".repeat(Math.ceil(N / 16))}`.slice(0, N);
    expect(timed(() => isHookBody(evil))).toBeLessThan(2000);
    expect(timed(() => isGitConfig(`${evil}//config`))).toBeLessThan(2000);
    expect(timed(() => isGitInfoAttributes(`${evil}//info/attributes`))).toBeLessThan(2000);
    expect(isHookBody(evil)).toBe(false);
    expect(isGitConfig(`${evil}//config`)).toBe(false);
  });
});

function words(...texts: string[]): Word[] {
  return texts.map((text) => ({ text, dynamic: false, glob: false, quoted: false, subs: [], vars: [] }));
}

/** The Go requests `go <args>` records. */
function goRequests(...args: string[]): { name: string; version: string | null; range: string | null }[] {
  const c = {} as unknown as Collector;
  notePackageCommand(c, "go", words(...args));
  return notedPackages(c).requests.map((r) => ({ name: r.name, version: r.version, range: r.range }));
}

describe("go package specs (CodeQL #17)", () => {
  const SPECS = ["golang.org/x/tools", "golang.org/x/tools@v0.1.0", "github.com/a/b/c@latest", "example.com/a@b@c", "example.com/", "example.com", "a.b.cc/x//y@v1.2.3", "Example.COM/Foo@master", "./local", "a.c/x", "example.com/a b", "example.com//", "github.com/!/!/x"];

  it("parses the same names and versions as the old regex", () => {
    for (const s of SPECS) {
      const old = OLD_GO.exec(s);
      const now = goRequests("get", s);
      if (old === null) expect(now, s).toEqual([]);
      else {
        expect(now.length, s).toBe(1);
        expect(now[0]?.name, s).toBe(old[1]);
      }
    }
  });

  it("keeps the known answers", () => {
    expect(goRequests("get", "golang.org/x/tools@v0.1.0")).toEqual([{ name: "golang.org/x/tools", version: "v0.1.0", range: null }]);
    expect(goRequests("install", "example.com/cmd@master")).toEqual([{ name: "example.com/cmd", version: null, range: "master" }]);
    expect(goRequests("run", "example.com/cmd")).toEqual([]);
  });

  it("is linear on a spec that repeats !/ and does not match", () => {
    const evil = `example.com/${"!/".repeat(N / 2)} `;
    expect(timed(() => goRequests("get", evil))).toBeLessThan(2000);
    expect(goRequests("get", evil)).toEqual([]);
  });
});

describe("URLs in a prompt (CodeQL #10)", () => {
  it("drops trailing punctuation after a URL as before", () => {
    const d = destinationsFromPrompt("see (https://github.com/acme/widget).");
    expect(d).toContain("github.com");
    expect(d).toContain("github:acme/widget");
    expect(destinationsFromPrompt("at https://example.com/x)]};,.")).toContain("example.com");
    expect(destinationsFromPrompt("https://github.com/acme/widget)x")).not.toContain("github:acme/widget");
    expect(destinationsFromPrompt("https://github.com/acme/web.app...")).toContain("github:acme/web.app");
  });

  it("is linear on a URL with a long run of ) that does not end it", () => {
    const prompt = `https://example.com/${")".repeat(N)}x`;
    expect(timed(() => destinationsFromPrompt(prompt))).toBeLessThan(2000);
    expect(destinationsFromPrompt(prompt)).toContain("example.com");
  });
});
