/**
 * What a release relies on besides the code (RELEASING.md): the version the CLI reports is the package's,
 * the build starts from an empty dist/ so a module whose source is gone cannot ship, the package-contents
 * check requires the docs and the font's licence, a tarball npm pack writes is not committed, and the
 * release workflow runs every command CI runs, so no suite skips during a release for want of a tool.
 *
 * Nothing here runs a workflow, npm or a build: the workflow files are read as text, and the two scripts
 * run on copies in a temporary package (scripts/clean-dist.mjs removes a dist/, so never this repository's).
 */
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, lstatSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { VERSION } from "../src/version.js";
import { REPO, tempHome, testEnv } from "./helpers.js";

const NAME = "@launchsafe/agent-firewall";
const read = (p: string): string => readFileSync(join(REPO, p), "utf8");
const pkg = JSON.parse(read("package.json")) as { name: string; version: string; scripts: Record<string, string> };

/** A package in a temporary directory: this package.json, copies of the named scripts, and the given files. */
function tempPackage(manifest: Record<string, unknown>, scripts: readonly string[], files: Record<string, string> = {}): string {
  const dir = join(tempHome("pkg-"), "agent-firewall");
  mkdirSync(join(dir, "scripts"), { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify(manifest));
  for (const s of scripts) cpSync(join(REPO, "scripts", s), join(dir, "scripts", s));
  for (const [f, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, f)), { recursive: true });
    writeFileSync(join(dir, f), text);
  }
  return dir;
}

/** Runs a node script from another directory, so nothing it does can depend on the working directory. */
function runScript(script: string, args: readonly string[] = []) {
  const cwd = tempHome("cwd-");
  return spawnSync(process.execPath, [script, ...args], { encoding: "utf8", cwd, env: testEnv(cwd), timeout: 30000 });
}

describe("version", () => {
  it("VERSION (what --version, the dashboard and log exports report) is package.json's version, and the lockfile's", () => {
    expect(VERSION).toBe(pkg.version);
    const lock = JSON.parse(read("package-lock.json")) as { version: string; packages: Record<string, { version?: string }> };
    expect(lock.version).toBe(pkg.version);
    expect(lock.packages[""]?.version).toBe(pkg.version);
  });
});

describe(".gitignore", () => {
  it("ignores the tarball npm pack writes into the repository root", () => {
    expect(read(".gitignore").split("\n").map((l) => l.trim())).toContain("*.tgz");
  });
});

describe("the build", () => {
  it("empties dist/ first, then compiles, makes the CLI executable and bundles the hook; prepack runs it", () => {
    expect(pkg.scripts.build?.split(" && ")).toEqual(["node scripts/clean-dist.mjs", "tsc -p tsconfig.build.json", "node scripts/chmod-bin.mjs", "node scripts/bundle-hook.mjs"]);
    expect(pkg.scripts.prepack).toBe("npm run build");
  });
});

describe("scripts/clean-dist.mjs (on a copy)", () => {
  const clean = (dir: string) => runScript(join(dir, "scripts", "clean-dist.mjs"));

  it("removes dist/ with a module whose source is gone, wherever it is run from, and nothing beside it", () => {
    const dir = tempPackage({ name: NAME }, ["clean-dist.mjs"], { "dist/engine/gone.js": "export {};\n", "dist/cli.js": "#!/usr/bin/env node\n", "src/cli.ts": "export {};\n" });
    const r = clean(dir);
    expect(r.status, r.stderr).toBe(0);
    expect(existsSync(join(dir, "dist"))).toBe(false);
    for (const kept of ["src/cli.ts", "package.json", "scripts/clean-dist.mjs"]) expect(existsSync(join(dir, kept))).toBe(true);
  });

  it("succeeds when there is no dist/ yet (a fresh clone)", () => {
    const dir = tempPackage({ name: NAME }, ["clean-dist.mjs"]);
    const r = clean(dir);
    expect(r.status, r.stderr).toBe(0);
  });

  it("removes nothing when package.json is another package's, and says why", () => {
    const dir = tempPackage({ name: "some-other-package" }, ["clean-dist.mjs"], { "dist/keep.js": "export {};\n" });
    const r = clean(dir);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("dist/ was not removed");
    expect(existsSync(join(dir, "dist", "keep.js"))).toBe(true);
  });

  it("removes a dist/ that is a symbolic link as a link, and leaves what it points to alone", () => {
    const target = tempHome("elsewhere-");
    writeFileSync(join(target, "keep.js"), "export {};\n");
    const dir = tempPackage({ name: NAME }, ["clean-dist.mjs"]);
    symlinkSync(target, join(dir, "dist"));
    const r = clean(dir);
    expect(r.status, r.stderr).toBe(0);
    expect(() => lstatSync(join(dir, "dist"))).toThrow();
    expect(existsSync(join(target, "keep.js"))).toBe(true);
  });
});

describe("scripts/check-pack.mjs (the release's package-contents check, on a copy)", () => {
  const FONT = "docs/licenses/Onest-OFL.txt";
  const manifest = {
    name: NAME,
    main: "dist/sdk/index.js",
    types: "dist/sdk/index.d.ts",
    bin: { "launchsafe-firewall": "dist/cli.js" },
    exports: { ".": { types: "./dist/sdk/index.d.ts", default: "./dist/sdk/index.js" }, "./sdk/node": { types: "./dist/sdk/node.d.ts", default: "./dist/sdk/node.js" } },
  };
  const DOCS = ["docs/usage.md", "docs/agents/overview.md", FONT];
  const COMPLETE = ["package.json", "README.md", "LICENSE", "NOTICE", "dist/cli.js", "dist/hook/bundle.js", "dist/sdk/index.js", "dist/sdk/index.d.ts", "dist/sdk/node.js", "dist/sdk/node.d.ts", ...DOCS];

  /** Checks an npm pack listing of `packed` against a package whose docs/ holds `docs`. */
  function check(packed: readonly string[], docs: readonly string[] = DOCS) {
    const dir = tempPackage(manifest, ["check-pack.mjs"], Object.fromEntries(docs.map((d) => [d, "text\n"])));
    const listing = join(dir, "pack.json");
    writeFileSync(listing, JSON.stringify([{ files: packed.map((path) => ({ path })), size: 1, unpackedSize: 2 }]));
    return runScript(join(dir, "scripts", "check-pack.mjs"), [listing]);
  }

  it("passes a complete package and prints its file list", () => {
    const r = check(COMPLETE);
    expect(r.status, r.stdout + r.stderr).toBe(0);
    expect(r.stdout).toContain(`${FONT}\n`);
    expect(r.stdout).toContain(`${COMPLETE.length} files, 1 bytes packed, 2 bytes unpacked`);
    expect(r.stdout).not.toContain("::error::");
  });

  it.each([
    ["the Onest font's licence", FONT],
    ["a page in a subdirectory of docs/", "docs/agents/overview.md"],
    ["the hook bundle", "dist/hook/bundle.js"],
    ["an export's types", "dist/sdk/node.d.ts"],
    ["NOTICE", "NOTICE"],
  ])("fails a package without %s, naming it", (_what, file) => {
    const r = check(COMPLETE.filter((f) => f !== file));
    expect(r.status).toBe(1);
    expect(r.stdout).toContain(`::error::The package would lack ${file}.`);
  });

  it("requires the font's licence even when docs/ no longer has it (moved or deleted)", () => {
    const r = check(COMPLETE.filter((f) => f !== FONT), ["docs/usage.md", "docs/agents/overview.md"]);
    expect(r.status).toBe(1);
    expect(r.stdout).toContain(`::error::The package would lack ${FONT}.`);
  });

  it("does not require a dotfile in docs/ (npm never packs a Finder .DS_Store)", () => {
    const r = check(COMPLETE, [...DOCS, "docs/.DS_Store"]);
    expect(r.status, r.stdout + r.stderr).toBe(0);
  });

  it("fails a package that would contain tests, naming them", () => {
    const r = check([...COMPLETE, "test/release.test.ts"]);
    expect(r.status).toBe(1);
    expect(r.stdout).toContain("::error::The package would contain test/release.test.ts.");
  });
});

interface Step {
  name?: string;
  if?: string;
  uses?: string;
  /** The command, one trimmed line per line, blank lines dropped. */
  run?: string[];
}

/**
 * The steps of one job of a workflow file, read as text: each step's name, condition, action and command.
 * Enough for the layout of these workflows (jobs at two spaces, steps at six, keys at eight, a block's lines
 * deeper); not a YAML parser.
 */
function jobSteps(file: string, job: string): Step[] {
  const lines = read(file).split("\n");
  const start = lines.indexOf(`  ${job}:`);
  if (start < 0) throw new Error(`${file} has no job ${job}`);
  const after = lines.slice(start + 1);
  const end = after.findIndex((l) => /^ {0,2}\S/.test(l));
  const steps: Step[] = [];
  let block: string[] | null = null;
  for (const line of end < 0 ? after : after.slice(0, end)) {
    if (block !== null) {
      if (line.trim() === "" || /^ {10}/.test(line)) {
        if (line.trim() !== "") block.push(line.trim());
        continue;
      }
      block = null;
    }
    if (/^\s*#/.test(line)) continue;
    if (/^ {6}- /.test(line)) steps.push({});
    const kv = /^ {6}(?:- | {2})(name|if|uses|run): (.*)$/.exec(line);
    const step = steps.at(-1);
    if (kv === null || step === undefined) continue;
    const [, key, raw] = kv;
    const value = (raw ?? "").trim();
    if (key === "run") {
      block = value === "|" ? [] : null;
      step.run = block ?? [value];
    } else if (key === "name" || key === "if" || key === "uses") step[key] = value;
  }
  return steps;
}

describe("the release workflow", () => {
  const commands = (steps: readonly Step[]): string[] => steps.flatMap((s) => (s.run === undefined ? [] : [s.run.join("\n")]));
  const ci = jobSteps(".github/workflows/ci.yml", "test");
  const verify = jobSteps(".github/workflows/release.yml", "verify");

  it("reads the two jobs (a guard for the reader above)", () => {
    const ciCommands = commands(ci);
    expect(ciCommands).toContain("npm test");
    expect(ciCommands).toContain("node scripts/sync-agent-safety.mjs --check");
    expect(ciCommands.some((c) => c.split("\n").includes("sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"))).toBe(true);
    expect(ci.find((s) => s.name === "Install ripgrep (macOS)")?.if).toBe("runner.os == 'macOS'");
    expect(commands(verify)).toContain("npm test");
  });

  it("its verify job runs every command CI's test job runs on Linux: the agent-safety check, and the tools and ref that keep suites from skipping", () => {
    const linux = ci.filter((s) => s.if !== "runner.os == 'macOS'");
    const missing = commands(linux).filter((c) => !commands(verify).includes(c));
    expect(missing).toEqual([]);
  });

  it("its package-contents step checks npm pack's listing with scripts/check-pack.mjs", () => {
    const step = verify.find((s) => s.name === "Package contents");
    expect(step?.run).toEqual(['npm pack --dry-run --ignore-scripts --json > "${RUNNER_TEMP}/pack.json"', 'node scripts/check-pack.mjs "${RUNNER_TEMP}/pack.json"']);
  });
});
