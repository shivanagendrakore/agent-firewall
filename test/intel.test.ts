/**
 * Package vetting acceptance: the P1-P16 and FP1-FP7 tables, the package rows of
 * scenarios.md (PKG-001..005, INC-26..28, DEV-021/023, INST-012), the policy
 * keys and the snapshot's failure modes. The snapshot is built by the real
 * `update` code from a local fixture directory; no test touches the network
 * (P15 uses a loopback server that drops the connection on purpose).
 */

import { createServer, type Server } from "node:http";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { normalizeName, type Ecosystem } from "../src/engine/packages.js";
import { mergeTighten, mergeTrusted, validatePolicy, defaultConfig, PolicyError } from "../src/policy.js";
import { inspectIntel, intelDir, openIntel, readManifest, runUpdate } from "../src/runtime/intel.js";
import { readLockfiles } from "../src/runtime/lockfiles.js";
import { intelCheck } from "../src/runtime/package-doctor.js";
import type { Context, Decision, FirewallConfig } from "../src/types.js";
import { bash, explain, testRoot } from "./helpers.js";
import { FIXTURE, FIXTURE_ECOS, fixtureHome, fixtureSource, makeZip, osv } from "./intel-fixture.js";

let fwHome = "";
let ws = "";

beforeAll(async () => {
  fwHome = await fixtureHome();
  ws = mkdtempSync(join(testRoot(), "ws-"));
});

function pctx(over: Partial<Context> = {}, home = fwHome): Partial<Context> {
  return { cwd: ws, workspaceRoots: [ws], packageIntel: openIntel(home), lockfiles: readLockfiles, ...over };
}

function cmd(command: string, o: { tainted?: boolean; home?: string; cwd?: string; config?: Partial<FirewallConfig> } = {}): Decision {
  return bash(command, { ...(o.tainted === true ? { tainted: true } : {}), ctx: pctx(o.cwd !== undefined ? { cwd: o.cwd, workspaceRoots: [o.cwd] } : {}, o.home ?? fwHome), ...(o.config !== undefined ? { config: o.config } : {}) });
}

function expectV(d: Decision, verdict: string, rule?: string): void {
  expect(d.verdict, explain(d)).toBe(verdict);
  if (rule !== undefined) expect(d.rules, explain(d)).toContain(rule);
}

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(testRoot(), "proj-"));
  for (const [f, text] of Object.entries(files)) writeFileSync(join(dir, f), text);
  return dir;
}

function packageLock(deps: Record<string, string>): string {
  const packages: Record<string, unknown> = { "": { name: "app", version: "1.0.0" } };
  for (const [n, v] of Object.entries(deps)) packages[`node_modules/${n}`] = { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz` };
  return JSON.stringify({ name: "app", lockfileVersion: 3, requires: true, packages });
}

describe("package vetting acceptance", () => {
  it("P1: npm install of a listed version is denied in a trusted session", () => {
    const d = cmd("npm install evil-fixture@1.0.0");
    expectV(d, "deny", "FW-MALICIOUS-PACKAGE");
    expect(d.findings.map((f) => f.id)).toContain("malicious_package");
    expect(d.reasons.join(" ")).toContain("MAL-2099-0001");
  });
  it("P2: every version listed, no version given: denied", () => expectV(cmd("npm install evil-fixture"), "deny", "FW-MALICIOUS-PACKAGE"));
  it("P3: some versions listed and none given: a person decides", () => {
    const d = cmd("npm install partly-bad");
    expectV(d, "ask", "FW-MALICIOUS-PACKAGE");
    expect(d.findings.map((f) => f.id)).toContain("malicious_package_maybe");
  });
  it("P4: a version that is not listed is allowed", () => expectV(cmd("npm install partly-bad@2.0.0"), "allow"));
  it("P5: PEP 503 normalisation (Evil_Fixture == evil-fixture)", () => expectV(cmd("pip install Evil_Fixture==1.0"), "deny", "FW-MALICIOUS-PACKAGE"));
  it("P5: PyPI version equivalence (1.0 == 1.0.0)", () => expectV(cmd("pip install evil.fixture==1.0.0"), "deny", "FW-MALICIOUS-PACKAGE"));
  it("P6: npm ci with a lockfile that pins a listed version is denied", () => {
    const dir = project({ "package-lock.json": packageLock({ react: "18.3.1", "evil-fixture": "1.0.0" }) });
    const d = cmd("npm ci", { cwd: dir });
    expectV(d, "deny", "FW-MALICIOUS-PACKAGE");
    expect(d.findings.map((f) => f.id)).toContain("lockfile_malicious");
    expect(d.reasons.join(" ")).toContain("evil-fixture@1.0.0");
  });
  it("P7: npx of a listed package is denied", () => expectV(cmd("npx evil-fixture"), "deny", "FW-MALICIOUS-PACKAGE"));
  it("P8: a one-letter typo of a popular package needs a person, trusted", () => {
    const d = cmd("npm install reacct");
    expectV(d, "ask", "FW-TYPOSQUAT");
    expect(d.reasons.join(" ")).toContain("react");
  });
  it("P9: a typo in an untrusted session: FW-TYPOSQUAT and FW-INSTALL", () => {
    const d = cmd("pip install reqeusts", { tainted: true });
    expectV(d, "ask", "FW-TYPOSQUAT");
    expect(d.rules).toContain("FW-INSTALL");
  });
  it("P10: no snapshot: the malicious check is skipped (allowed); doctor warns", () => {
    const empty = mkdtempSync(join(testRoot(), "fwempty-"));
    expectV(cmd("npm install evil-fixture@1.0.0", { home: empty }), "allow");
    const c = intelCheck(empty, defaultConfig());
    expect(c.status).toBe("warn");
    expect(c.detail).toContain("launchsafe-firewall update");
  });
  it("P11: a corrupt bucket: the lookup is unknown (allowed, logged) and doctor fails", () => {
    const copy = mkdtempSync(join(testRoot(), "fwcorrupt-"));
    cpSync(fwHome, copy, { recursive: true });
    const m = readManifest(copy);
    const { createHash } = require("node:crypto") as typeof import("node:crypto");
    const bucket = createHash("sha256").update(normalizeName("npm", "evil-fixture")).digest("hex").slice(0, 2);
    writeFileSync(join(intelDir(copy), m?.dir ?? "", "npm", `${bucket}.json`), "{garbage");
    const d = cmd("npm install evil-fixture@1.0.0", { home: copy });
    expectV(d, "allow");
    expect(d.findings.map((f) => f.id)).toContain("intel_unreadable");
    const c = intelCheck(copy, defaultConfig());
    expect(c.status).toBe("fail");
    expect(c.detail).toContain("intel damaged");
  });
  it("P12: the agent running `update` is FW-TAMPER (it writes the firewall's state)", () => {
    expectV(cmd("launchsafe-firewall update"), "deny", "FW-TAMPER");
    expectV(cmd("npx @launchsafe/agent-firewall update --source /tmp/x"), "deny", "FW-TAMPER");
    expectV(cmd("launchsafe-firewall update --help"), "allow");
  });
  it("P16: a 40-day-old snapshot: doctor fails, the checks still apply", async () => {
    const old = await fixtureHome({ now: new Date(Date.now() - 40 * 86_400_000) });
    const c = intelCheck(old, defaultConfig());
    expect(c.status).toBe("fail");
    expect(c.detail).toContain("maxSnapshotAgeDays");
    expectV(cmd("npm install evil-fixture@1.0.0", { home: old }), "deny", "FW-MALICIOUS-PACKAGE");
    // Between 7 and 30 days: a warning.
    const mid = await fixtureHome({ now: new Date(Date.now() - 10 * 86_400_000) });
    expect(intelCheck(mid, defaultConfig()).status).toBe("warn");
    expect(intelCheck(fwHome, defaultConfig()).status).toBe("ok");
  });
});

describe("P15 / INST-012: an interrupted update keeps the previous snapshot", () => {
  let server: Server;
  let base = "";
  beforeAll(async () => {
    const full = makeZip(FIXTURE.npm ?? []);
    server = createServer((req, res) => {
      if (req.url === "/npm/all.zip") {
        res.writeHead(200, { "content-type": "application/zip", "content-length": String(full.length * 4) });
        res.write(full.subarray(0, 40));
        setTimeout(() => res.destroy(), 10);
      } else if (req.url === "/PyPI/all.zip") {
        res.writeHead(503);
        res.end();
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const addr = server.address();
    base = `http://127.0.0.1:${typeof addr === "object" && addr !== null ? addr.port : 0}`;
  });
  afterAll(() => {
    server.closeAllConnections();
    return new Promise<void>((r) => server.close(() => r()));
  });

  it("a connection dropped mid-download fails and leaves the old manifest and buckets", async () => {
    const home = await fixtureHome();
    const before = readFileSync(join(intelDir(home), "manifest.json"), "utf8");
    await expect(runUpdate(home, { source: base, ecosystems: ["npm"], timeoutMs: 5000 })).rejects.toThrow();
    expect(readFileSync(join(intelDir(home), "manifest.json"), "utf8")).toBe(before);
    expect(inspectIntel(home).state).toBe("ok");
    expectV(cmd("npm install evil-fixture@1.0.0", { home }), "deny", "FW-MALICIOUS-PACKAGE");
  });
  it("an HTTP error fails the whole update (all or nothing)", async () => {
    const home = await fixtureHome();
    const before = readFileSync(join(intelDir(home), "manifest.json"), "utf8");
    await expect(runUpdate(home, { source: base, ecosystems: ["PyPI"] })).rejects.toThrow(/HTTP 503/);
    expect(readFileSync(join(intelDir(home), "manifest.json"), "utf8")).toBe(before);
  });
  it("a truncated local archive fails the same way", async () => {
    const home = await fixtureHome();
    const src = fixtureSource();
    const zip = join(src, "npm", "all.zip");
    writeFileSync(zip, readFileSync(zip).subarray(0, 60));
    const before = readFileSync(join(intelDir(home), "manifest.json"), "utf8");
    await expect(runUpdate(home, { source: src, ecosystems: ["npm"] })).rejects.toThrow(/zip|archive/i);
    expect(readFileSync(join(intelDir(home), "manifest.json"), "utf8")).toBe(before);
  });
  it("the CLI refuses without a terminal and exits non-zero, writing nothing", async () => {
    const { spawnCli } = await import("./helpers.js");
    const r = spawnCli(["update", "--source", base]);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain("interactive terminal");
    expect(readManifest(join(r.home, ".launchsafe-firewall"))).toBeNull();
  });
  it("a bad --ecosystem is a usage error", async () => {
    const { spawnCli } = await import("./helpers.js");
    expect(spawnCli(["update", "--ecosystem", "npm,cobol"]).status).toBe(64);
  });
});

describe("package vetting false positives (allowed, snapshot present, trusted)", () => {
  it("FP1: npm install react react-dom next@15", () => expectV(cmd("npm install react react-dom next@15"), "allow"));
  it("FP2: npm install preact (a target itself, one letter from react)", () => expectV(cmd("npm install preact"), "allow"));
  it("FP3: pip install requests numpy pandas", () => expectV(cmd("pip install requests numpy pandas"), "allow"));
  it("FP4: cargo add serde serde_json tokio", () => expectV(cmd("cargo add serde serde_json tokio"), "allow"));
  it("FP5: npm install @types/node", () => expectV(cmd("npm install @types/node"), "allow"));
  it("FP6: npm ci with a clean 2 MB lockfile, within the latency budget", () => {
    const deps: Record<string, string> = {};
    for (let i = 0; i < 16_000; i++) deps[`pkg-${i.toString(36)}-fixture-name`] = `1.${i % 50}.${i % 7}`;
    const text = packageLock(deps);
    expect(text.length).toBeGreaterThan(2_000_000);
    const dir = project({ "package-lock.json": text });
    expectV(cmd("npm ci", { cwd: dir }), "allow");
    const times: number[] = [];
    for (let i = 0; i < 7; i++) {
      const t0 = performance.now();
      cmd("npm ci", { cwd: dir });
      times.push(performance.now() - t0);
    }
    times.sort((a, b) => a - b);
    // The 50 ms budget is measured by `npm run bench` (package-check case) on a quiet machine; inside the
    // parallel suite only a loose ceiling is stable enough to catch a regression (an accidental O(n^2)).
    expect(times[3], `median ${times[3]} ms`).toBeLessThan(250);
  });
  it("FP7: pnpm add -D vitest", () => expectV(cmd("pnpm add -D vitest"), "allow"));
  it("ordinary commands never read the snapshot", () => {
    let reads = 0;
    const spy = { covers: () => (reads++, true), lookup: () => (reads++, { kind: "clean" as const }), lookupMany: () => (reads++, new Map()), fetchedAt: () => undefined };
    for (const c of ["git status", "npm test", "ls -la", "npm run build", "cargo test"]) bash(c, { ctx: { packageIntel: spy, lockfiles: () => [] } });
    expect(reads).toBe(0);
  });
});

describe("scenarios.md package rows", () => {
  it("PKG-001: npm ci with a clean lockfile is allowed", () => expectV(cmd("npm ci", { cwd: project({ "package-lock.json": packageLock({ react: "18.3.1", lodash: "4.17.21" }) }) }), "allow"));
  it("PKG-002: npm ci whose lockfile pins a listed version is denied", () => expectV(cmd("npm ci", { cwd: project({ "package-lock.json": packageLock({ "partly-bad": "1.0.1" }) }) }), "deny", "FW-MALICIOUS-PACKAGE"));
  it("PKG-003: a one-letter typo of a top package asks", () => expectV(cmd("npm install lodahs"), "ask", "FW-TYPOSQUAT"));
  it("PKG-004: a listed PyPI version is denied", () => expectV(cmd("pip install fixture-llm-proxy==1.82.7"), "deny", "FW-MALICIOUS-PACKAGE"));
  it("PKG-005: a listed package through a runner is denied", () => {
    for (const c of ["npx evil-fixture", "npx -y evil-fixture@2.0.0", "pnpm dlx evil-fixture", "yarn dlx evil-fixture", "bunx evil-fixture", "npm exec evil-fixture", "npx -p evil-fixture some-bin"]) expectV(cmd(c), "deny", "FW-MALICIOUS-PACKAGE");
    expectV(cmd("uvx fixture-llm-proxy@1.82.8"), "deny", "FW-MALICIOUS-PACKAGE");
    expectV(cmd("pipx run --spec fixture-llm-proxy==1.82.8 proxy"), "deny", "FW-MALICIOUS-PACKAGE");
  });
  it("INC-26: a listed MCP server version launched with npx is denied", () => expectV(cmd("npx mcp-mail-fixture@1.0.16"), "deny", "FW-MALICIOUS-PACKAGE"));
  it("INC-27: a compromised build-tool version in the lockfile (range) is denied", () => {
    expectV(cmd("npm ci", { cwd: project({ "package-lock.json": packageLock({ "build-tool-fixture": "21.5.1" }) }) }), "deny", "FW-MALICIOUS-PACKAGE");
    expectV(cmd("npm ci", { cwd: project({ "package-lock.json": packageLock({ "build-tool-fixture": "21.5.2" }) }) }), "allow");
  });
  it("INC-28: a backdoored PyPI version is denied, a later one allowed", () => {
    expectV(cmd("pip install fixture-llm-proxy==1.82.8"), "deny", "FW-MALICIOUS-PACKAGE");
    expectV(cmd("pip install fixture-llm-proxy==1.83.0"), "allow");
  });
  it("DEV-021: cargo add serde after outside content asks for FW-INSTALL only", () => {
    const d = cmd("cargo add serde", { tainted: true });
    expectV(d, "ask", "FW-INSTALL");
    expect(d.rules).not.toContain("FW-TYPOSQUAT");
  });
  it("DEV-023: cargo install cargo-edit passes the typosquat check", () => expectV(cmd("cargo install cargo-edit"), "allow"));
  it("malicious outranks FW-INSTALL in an untrusted session", () => expectV(cmd("npm install evil-fixture", { tainted: true }), "deny", "FW-MALICIOUS-PACKAGE"));
});

describe("more managers and lockfiles", () => {
  const lockCases: [string, Record<string, string>, string][] = [
    ["pnpm install --frozen-lockfile", { "pnpm-lock.yaml": "lockfileVersion: '9.0'\n\npackages:\n\n  react@18.3.1:\n    resolution: {integrity: sha512-x}\n\n  evil-fixture@3.0.0:\n    resolution: {integrity: sha512-y}\n" }, "deny"],
    ["pnpm install", { "pnpm-lock.yaml": "lockfileVersion: 5.4\n\npackages:\n\n  /react/18.3.1:\n    dev: false\n  /partly-bad/1.0.0_react@18.3.1:\n    dev: false\n" }, "deny"],
    ["yarn install --immutable", { "yarn.lock": '__metadata:\n  version: 8\n\n"evil-fixture@npm:^1.0.0":\n  version: 1.2.0\n  resolution: "evil-fixture@npm:1.2.0"\n' }, "deny"],
    ["yarn", { "yarn.lock": '# yarn lockfile v1\n\n"partly-bad@^1.0.0", partly-bad@^1.0.1:\n  version "1.0.1"\n  resolved "https://registry.yarnpkg.com/x"\n' }, "deny"],
    ["yarn", { "yarn.lock": '# yarn lockfile v1\n\npartly-bad@^2.0.0:\n  version "2.0.0"\n' }, "allow"],
    ["pip install -r requirements.txt", { "requirements.txt": "requests==2.32.3\nEvil_Fixture==1.0 --hash=sha256:abc\n" }, "deny"],
    ["pip install -r requirements.txt", { "requirements.txt": "-r base.txt\nflask==3.0.0\n", "base.txt": "fixture-llm-proxy==1.82.7\n" }, "deny"],
    ["uv sync", { "uv.lock": 'version = 1\n\n[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "fixture-llm-proxy"\nversion = "1.82.8"\nsource = { registry = "https://pypi.org/simple" }\n' }, "deny"],
    ["poetry install", { "poetry.lock": '[[package]]\nname = "evil-fixture"\nversion = "1.0"\n\n[metadata]\nlock-version = "2.0"\n' }, "deny"],
    ["bundle install", { "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n    evil-gem-fixture (0.1.0)\n\nPLATFORMS\n  ruby\n" }, "deny"],
    ["cargo build", { "Cargo.lock": 'version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\n\n[[package]]\nname = "evil-crate-fixture"\nversion = "0.0.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n' }, "deny"],
    ["cargo build", { "Cargo.lock": 'version = 3\n\n[[package]]\nname = "evil_crate_fixture"\nversion = "0.0.1"\n' }, "allow"],
  ];
  for (const [c, files, v] of lockCases) it(`${c} with ${Object.keys(files).join(", ")} -> ${v}`, () => expectV(cmd(c, { cwd: project(files) }), v));

  it("installs with explicit names do not read the lockfile", () => expectV(cmd("npm install react", { cwd: project({ "package-lock.json": packageLock({ "evil-fixture": "1.0.0" }) }) }), "allow"));
  it("npm install --prefix reads the lockfile there", () => {
    const dir = project({});
    const sub = project({ "package-lock.json": packageLock({ "evil-fixture": "1.0.0" }) });
    expectV(cmd(`npm install --prefix ${sub}`, { cwd: dir }), "deny", "FW-MALICIOUS-PACKAGE");
  });
  it("a lockfile that cannot be parsed is skipped and logged, not denied", () => {
    const d = cmd("npm ci", { cwd: project({ "package-lock.json": "{ broken" }) });
    expectV(d, "allow");
    expect(d.findings.map((f) => f.id)).toContain("lockfile_unreadable");
  });
  it("wrappers and nesting still reach the package checks", () => {
    for (const c of ["sudo npm install evil-fixture", "bash -c 'npm i evil-fixture'", "env CI=1 npm add evil-fixture", "python3 -m pip install Evil-Fixture==1.0", "true && npx evil-fixture"]) expectV(cmd(c), "deny", "FW-MALICIOUS-PACKAGE");
  });
  it("other managers and spec forms", () => {
    expectV(cmd("gem install evil-gem-fixture -v 0.1.0"), "deny", "FW-MALICIOUS-PACKAGE");
    expectV(cmd("gem install evil-gem-fixture"), "ask", "FW-MALICIOUS-PACKAGE");
    expectV(cmd("cargo install evil_crate_fixture"), "deny", "FW-MALICIOUS-PACKAGE");
    expectV(cmd("uv add 'Evil-Fixture==1.0'"), "deny", "FW-MALICIOUS-PACKAGE");
    expectV(cmd("uv pip install evil_fixture==1.0"), "deny", "FW-MALICIOUS-PACKAGE");
    expectV(cmd("poetry add evil-fixture@1.0"), "deny", "FW-MALICIOUS-PACKAGE");
    expectV(cmd("npm install alias@npm:evil-fixture@1.0.0"), "deny", "FW-MALICIOUS-PACKAGE");
    expectV(cmd("yarn global add evil-fixture"), "deny", "FW-MALICIOUS-PACKAGE");
    expectV(cmd("npm install partly-bad@^1.0.0"), "ask", "FW-MALICIOUS-PACKAGE");
  });
  it("names only known at run time get no package verdict (today's unresolvable handling)", () => {
    const d = cmd('npm i "$PKG"');
    expect(d.rules).not.toContain("FW-MALICIOUS-PACKAGE");
    expect(d.rules).not.toContain("FW-TYPOSQUAT");
  });
  it("non-registry specs are not looked up", () => {
    for (const c of ["npm install ./evil-fixture", "npm install github:x/evil-fixture", "npm install https://example.com/evil-fixture.tgz", "pip install ./Evil-Fixture"]) expect(cmd(c).rules).not.toContain("FW-MALICIOUS-PACKAGE");
  });
  it("withdrawn and non-MAL advisories are not in the snapshot", () => {
    expectV(cmd("npm install withdrawn-fixture@1.0.0"), "allow");
    expectV(cmd("npm install ordinary-vuln-fixture@1.0.0"), "allow");
  });
});

describe("packageIntel policy", () => {
  it("malicious: approve turns the deny into a person's decision; off disables it", () => {
    expectV(cmd("npm install evil-fixture", { config: { packageIntel: { malicious: "approve" } } }), "ask", "FW-MALICIOUS-PACKAGE");
    expectV(cmd("npm install evil-fixture", { config: { packageIntel: { malicious: "off" } } }), "allow");
  });
  it("typosquat: off", () => expectV(cmd("npm install reacct", { config: { packageIntel: { typosquat: "off" } } }), "allow"));
  it("lockfiles: false skips lockfile reading", () => expectV(cmd("npm ci", { cwd: project({ "package-lock.json": packageLock({ "evil-fixture": "1.0.0" }) }), config: { packageIntel: { lockfiles: false } } }), "allow"));
  it("validation rejects bad values and unknown keys", () => {
    expect(() => validatePolicy({ version: 1, packageIntel: { malicious: "maybe" } }, "t")).toThrow(PolicyError);
    expect(() => validatePolicy({ version: 1, packageIntel: { typosquat: "deny" } }, "t")).toThrow(PolicyError);
    expect(() => validatePolicy({ version: 1, packageIntel: { lockfiles: "yes" } }, "t")).toThrow(PolicyError);
    expect(() => validatePolicy({ version: 1, packageIntel: { maxSnapshotAgeDays: 0 } }, "t")).toThrow(PolicyError);
    expect(() => validatePolicy({ version: 1, packageIntel: { other: 1 } }, "t")).toThrow(PolicyError);
    expect(validatePolicy({ version: 1, packageIntel: { malicious: "approve", maxSnapshotAgeDays: 14 } }, "t").packageIntel).toEqual({ malicious: "approve", maxSnapshotAgeDays: 14 });
  });
  it("a user policy may loosen, merging key by key", () => {
    const c = mergeTrusted(defaultConfig(), { packageIntel: { typosquat: "off" } });
    expect(c.packageIntel).toEqual({ malicious: "deny", typosquat: "off", lockfiles: true, maxSnapshotAgeDays: 30 });
  });
  it("a project policy may only tighten; loosening is ignored and reported", () => {
    const loose = mergeTighten(defaultConfig(), { packageIntel: { malicious: "off", typosquat: "off", lockfiles: false, maxSnapshotAgeDays: 90 } });
    expect(loose.config.packageIntel).toEqual({ malicious: "deny", typosquat: "approve", lockfiles: true, maxSnapshotAgeDays: 30 });
    expect(loose.ignored.join(" ")).toContain("packageIntel");
    const userLoose = mergeTrusted(defaultConfig(), { packageIntel: { malicious: "approve", typosquat: "off" } });
    const tight = mergeTighten(userLoose, { packageIntel: { malicious: "deny", typosquat: "approve", maxSnapshotAgeDays: 7 } });
    expect(tight.config.packageIntel).toEqual({ malicious: "deny", typosquat: "approve", lockfiles: true, maxSnapshotAgeDays: 7 });
    expect(tight.ignored).toEqual([]);
  });
});

describe("snapshot format", () => {
  it("records sources with hashes and counts, and keeps only MAL- entries", () => {
    const m = readManifest(fwHome);
    expect(m?.format).toBe(1);
    const npm = m?.sources.find((s) => s.eco === "npm");
    expect(npm?.entries).toBe(4); // evil-fixture, partly-bad, mcp-mail-fixture, build-tool-fixture
    expect(npm?.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(npm?.url.startsWith("file:")).toBe(true);
    expect(inspectIntel(fwHome).state).toBe("ok");
  });
  it("a ZIP64 export builds the same snapshot", async () => {
    const home = mkdtempSync(join(testRoot(), "fw64-"));
    await runUpdate(home, { source: fixtureSource(FIXTURE, { zip64: true }), ecosystems: FIXTURE_ECOS });
    expectV(cmd("npm install evil-fixture", { home }), "deny", "FW-MALICIOUS-PACKAGE");
  });
  it("a second update replaces the first and prunes older generations", async () => {
    const home = await fixtureHome();
    const extra: Record<string, typeof FIXTURE.npm> = { npm: [...(FIXTURE.npm ?? []), { name: "MAL-2099-0099.json", data: osv("MAL-2099-0099", "npm", "late-fixture", { all: true }) }] };
    for (let i = 0; i < 3; i++) await runUpdate(home, { source: fixtureSource(extra as Partial<Record<Ecosystem, NonNullable<typeof FIXTURE.npm>>>), ecosystems: ["npm"] });
    expectV(cmd("npm install late-fixture", { home }), "deny", "FW-MALICIOUS-PACKAGE");
    const { readdirSync } = await import("node:fs");
    expect(readdirSync(intelDir(home)).filter((d) => d.startsWith("g-")).length).toBeLessThanOrEqual(2);
    expect(readdirSync(intelDir(home)).filter((d) => d.startsWith("tmp-"))).toEqual([]);
    // A partial update keeps the other ecosystems of the snapshot: PyPI is still covered.
    expectV(cmd("pip install Evil_Fixture==1.0", { home }), "deny", "FW-MALICIOUS-PACKAGE");
    expect(readManifest(home)?.sources.map((x) => x.eco).sort()).toEqual([...FIXTURE_ECOS].sort());
  });
  it("a partial update of an ecosystem the snapshot lacks adds it and keeps the rest", async () => {
    const home = mkdtempSync(join(testRoot(), "fwpart-"));
    await runUpdate(home, { source: fixtureSource(), ecosystems: ["npm"] });
    await runUpdate(home, { source: fixtureSource(), ecosystems: ["PyPI"] });
    expect(readManifest(home)?.sources.map((x) => x.eco).sort()).toEqual(["PyPI", "npm"]);
    expectV(cmd("npm install evil-fixture", { home }), "deny", "FW-MALICIOUS-PACKAGE");
    expectV(cmd("pip install Evil_Fixture==1.0", { home }), "deny", "FW-MALICIOUS-PACKAGE");
  });
  it("a damaged manifest makes every lookup unknown, never a verdict", () => {
    const copy = mkdtempSync(join(testRoot(), "fwman-"));
    cpSync(fwHome, copy, { recursive: true });
    writeFileSync(join(intelDir(copy), "manifest.json"), '{"format": 99}');
    const d = cmd("npm install evil-fixture", { home: copy });
    expectV(d, "allow");
    expect(d.findings.map((f) => f.id)).toContain("intel_unreadable");
    expect(inspectIntel(copy).state).toBe("damaged");
  });
});
