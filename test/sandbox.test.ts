/**
 * Claude Code sandbox and egress wiring. The acceptance table (S1-S17), its false
 * positives (FP1, FP2, FP4), the profile derivation (fetch-only vs send, upload-capable, denyHosts),
 * the effective-settings reader, the policy key and uninstall.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { profileFromPolicy, sandboxDomains, sandboxViolations, SANDBOX_KEYS, SANDBOX_NETWORK_KEYS, SANDBOX_FILESYSTEM_KEYS } from "../src/engine/sandbox.js";
import { runHook } from "../src/hook/claude.js";
import { defaultConfig, mergeTighten, validatePolicy } from "../src/policy.js";
import { initApprover } from "../src/runtime/approver.js";
import { doctor, type Check } from "../src/runtime/doctor.js";
import { atomicWrite } from "../src/runtime/fsutil.js";
import { install, settingsPath, uninstall } from "../src/runtime/install.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { applySandboxFix, lineDiff, planSandboxFix, profileHash, readSandbox, readSandboxRecords, removeSandboxProfiles, runSandboxFix, sandboxRecordsPath, type FixIO } from "../src/runtime/sandbox.js";
import { bash, explain, run, spawnCli, tempHome, WS, HOME } from "./helpers.js";

const PASS = "correct horse battery staple";
let root: string;
let home: string;
let ws: string;
let l: Layout;
const NO_MANAGED = (): string => join(root, "no-managed-settings.json");
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-sb-"));
  home = join(root, "home");
  ws = join(home, "proj");
  mkdirSync(ws, { recursive: true });
  l = layout(join(home, ".launchsafe-firewall"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const userSettings = (): string => settingsPath("user", ws, home);
const writeJson = (p: string, v: unknown): void => {
  mkdirSync(join(p, ".."), { recursive: true });
  writeFileSync(p, `${JSON.stringify(v, null, 2)}\n`);
};
const readJson = (p: string): Record<string, unknown> => JSON.parse(readFileSync(p, "utf8")) as Record<string, unknown>;
const plan = (scope: "user" | "project" | "local" = "user", cfg = defaultConfig()) => planSandboxFix(l, ws, cfg, { scope, home, platform: "darwin", claudeVersion: "2.1.289", managedPath: NO_MANAGED() });
const docOpts = (over: Partial<Parameters<typeof doctor>[2]> = {}) => ({ home, platform: "darwin" as const, claudeVersion: "2.1.289", ...over });
const find = (cs: Check[], name: string): Check | undefined => cs.find((c) => c.name === name);

function io(answers: { passphrase?: string; yes?: boolean } = {}): FixIO & { lines: string[]; asked: number } {
  const lines: string[] = [];
  const o = {
    lines,
    asked: 0,
    passphrase: async () => {
      o.asked++;
      return answers.passphrase ?? PASS;
    },
    confirm: async () => answers.yes ?? true,
    say: (s: string) => lines.push(s),
  };
  return o;
}

/** Installs hooks and the profile the way a person would (install, then doctor --fix). */
function installAll(): void {
  install(l, "user", ws, "0.2.0", { home, platform: "darwin" });
  applySandboxFix(l, plan());
}

// --- the profile -----------------------------------------------------------------------------------

describe("profileFromPolicy", () => {
  it("S6: the default policy gives registry, PyPI and GitHub hosts, no capture hosts, no unsandboxed escape", () => {
    const { profile, hosts } = profileFromPolicy(defaultConfig());
    expect(profile.network.allowedDomains).toEqual(expect.arrayContaining(["registry.npmjs.org", "pypi.org", "github.com"]));
    expect(profile.network.allowedDomains.some((d) => /webhook\.site|ngrok|pastebin|transfer\.sh/.test(d))).toBe(false);
    expect(profile.allowUnsandboxedCommands).toBe(false);
    expect(profile.enabled).toBe(true);
    expect(profile.autoAllowBashIfSandboxed).toBe(false);
    expect(profile.excludedCommands).toEqual([]);
    expect(profile.network.allowUnixSockets).toEqual([]);
    expect(profile.network.allowLocalBinding).toBe(true);
    expect(profile.network.strictAllowlist).toBe(true);
    // sendAllowHosts is empty by default: every host is fetch-only.
    expect(hosts.every((h) => h.kind === "fetch-only")).toBe(true);
    expect(hosts.find((h) => h.domain === "github.com")?.uploadCapable).toBe(true);
    expect(hosts.find((h) => h.domain === "docs.python.org")?.uploadCapable).toBe(false);
  });
  it("S7: a host in denyHosts is left out, and becomes a denied domain", () => {
    const { profile, dropped } = profileFromPolicy({ ...defaultConfig(), denyHosts: ["pypi.org"] });
    expect(profile.network.allowedDomains).not.toContain("pypi.org");
    expect(profile.network.allowedDomains).not.toContain("*.pypi.org");
    expect(profile.network.deniedDomains).toEqual(expect.arrayContaining(["pypi.org", "*.pypi.org"]));
    expect(dropped.find((d) => d.pattern === "pypi.org")?.reason).toMatch(/denyHosts/);
  });
  it("converts host syntax: =exact, suffix (host and *.host), *.wildcard; refuses non-hosts", () => {
    expect(sandboxDomains("=github.com")).toEqual(["github.com"]);
    expect(sandboxDomains("crates.io")).toEqual(["crates.io", "*.crates.io"]);
    expect(sandboxDomains("*.example.org")).toEqual(["*.example.org"]);
    expect(sandboxDomains("https://x.example.org/path")).toBeNull();
    expect(sandboxDomains("localhost")).toBeNull();
  });
  it("never includes raw IPs, metadata endpoints or capture hosts, even when the policy lists them", () => {
    const cfg = { ...defaultConfig(), fetchAllowHosts: ["=169.254.169.254", "=10.0.0.5", "webhook.site", "metadata.google.internal", "=api.example.com"], sendAllowHosts: ["ngrok.io"] };
    const { profile, dropped } = profileFromPolicy(cfg);
    expect(profile.network.allowedDomains).toEqual(["api.example.com"]);
    expect(dropped.map((d) => d.pattern).sort()).toEqual(["=10.0.0.5", "=169.254.169.254", "metadata.google.internal", "ngrok.io", "webhook.site"].sort());
  });
  it("labels send hosts and upload-capable hosts", () => {
    const { hosts } = profileFromPolicy({ ...defaultConfig(), fetchAllowHosts: ["=docs.example.com"], sendAllowHosts: ["=api.example.com", "=upload.pypi.org"] });
    expect(hosts).toEqual([
      { domain: "api.example.com", kind: "send", uploadCapable: false },
      { domain: "docs.example.com", kind: "fetch-only", uploadCapable: false },
      { domain: "upload.pypi.org", kind: "send", uploadCapable: true },
    ]);
  });
  it("policy sandbox.strictAllowlist false leaves the strict allowlist out", () => {
    expect(profileFromPolicy({ ...defaultConfig(), sandbox: { strictAllowlist: false } }).profile.network.strictAllowlist).toBeUndefined();
  });
});

// --- the schema fixture ----------------------------------------------------------------------------

describe("the captured settings schema (Claude Code 2.1.289)", () => {
  const fx = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "fixtures", "claude-2.1.289-sandbox-schema.json"), "utf8")) as { sandbox: string[]; network: string[]; filesystem: string[]; defaults: Record<string, unknown> };
  it("the key lists match the fixture captured from the installed binary", () => {
    expect([...SANDBOX_KEYS].sort()).toEqual([...fx.sandbox].sort());
    expect([...SANDBOX_NETWORK_KEYS].sort()).toEqual([...fx.network].sort());
    expect([...SANDBOX_FILESYSTEM_KEYS].sort()).toEqual([...fx.filesystem].sort());
  });
  it("every key the profile writes is in the schema", () => {
    const { profile } = profileFromPolicy(defaultConfig());
    for (const k of Object.keys(profile)) expect(fx.sandbox).toContain(k);
    for (const k of Object.keys(profile.network)) expect(fx.network).toContain(k);
  });
  it("the profile sets explicitly every key whose Claude Code default is the weak value", () => {
    expect(fx.defaults["allowUnsandboxedCommands"]).toBe(true);
    expect(fx.defaults["autoAllowBashIfSandboxed"]).toBe(true);
    const { profile } = profileFromPolicy(defaultConfig());
    expect(profile.allowUnsandboxedCommands).toBe(false);
    expect(profile.autoAllowBashIfSandboxed).toBe(false);
  });
});

// --- reading the effective settings ----------------------------------------------------------------

describe("readSandbox", () => {
  it("merges scopes: scalars from the highest scope, lists across scopes", () => {
    writeJson(userSettings(), { sandbox: { enabled: true, excludedCommands: ["docker *"], network: { allowedDomains: ["a.example.com"] } } });
    writeJson(settingsPath("project", ws, home), { sandbox: { enabled: false, network: { allowedDomains: ["b.example.com"] } } });
    writeJson(settingsPath("local", ws, home), { sandbox: { network: { allowedDomains: ["c.example.com"] } } });
    const v = readSandbox(ws, home, "darwin", { managedPath: NO_MANAGED() });
    expect(v.enabled).toBe(false); // project beats user
    expect(v.excludedCommands).toEqual(["docker *"]);
    expect(v.allowedDomains?.sort()).toEqual(["a.example.com", "b.example.com", "c.example.com"]);
    expect(v.repoDomains.sort()).toEqual(["b.example.com", "c.example.com"]);
    expect(v.source.length).toBe(3);
  });
  it("managed settings win, and their drop-ins are read", () => {
    const managed = join(root, "managed", "managed-settings.json");
    writeJson(managed, { sandbox: { enabled: true } });
    writeJson(join(root, "managed", "managed-settings.d", "10-net.json"), { sandbox: { network: { allowedDomains: ["corp.example.com"] } } });
    writeJson(userSettings(), { sandbox: { enabled: false } });
    const v = readSandbox(ws, home, "darwin", { managedPath: managed });
    expect(v.enabled).toBe(true);
    expect(v.managedLocked).toBe(true);
    expect(v.allowedDomains).toEqual(["corp.example.com"]);
  });
  it("Claude Code's defaults apply when nothing is set: unsandboxed commands allowed, bash auto-allowed", () => {
    const v = readSandbox(ws, home, "darwin", { managedPath: NO_MANAGED() });
    expect(v).toMatchObject({ enabled: false, allowUnsandboxed: true, autoAllowBash: true, allowedDomains: null, strictAllowlist: false });
  });
  it("strictAllowlist from user settings leaves the repository's domains and WebFetch rules out", () => {
    writeJson(userSettings(), { sandbox: { enabled: true, network: { strictAllowlist: true, allowedDomains: ["a.example.com"] } } });
    writeJson(settingsPath("project", ws, home), { sandbox: { network: { allowedDomains: ["evil.example.net"] } }, permissions: { allow: ["WebFetch(domain:evil2.example.net)"] } });
    const v = readSandbox(ws, home, "darwin", { managedPath: NO_MANAGED() });
    expect(v.allowedDomains).toEqual(["a.example.com"]);
    expect(v.repoDomains).toEqual([]);
    expect(v.webFetchDomains).toEqual([]);
  });
  it("counts WebFetch(domain:...) allow rules (Claude Code merges them into the allowlist)", () => {
    writeJson(userSettings(), { sandbox: { enabled: true }, permissions: { allow: ["WebFetch(domain:docs.example.com)", "Bash(npm test)"] } });
    expect(readSandbox(ws, home, "darwin", { managedPath: NO_MANAGED() }).webFetchDomains).toEqual(["docs.example.com"]);
  });
  it("reports a boolean sandbox, wrong types, unknown keys and unparseable files", () => {
    writeJson(userSettings(), { sandbox: true });
    expect(readSandbox(ws, home, "darwin", { managedPath: NO_MANAGED() }).problems.join(" ")).toMatch(/must be an object/);
    writeJson(userSettings(), { sandbox: { enabled: "yes", futureKey: 1, network: { tunnel: true } } });
    const v = readSandbox(ws, home, "darwin", { managedPath: NO_MANAGED() });
    expect(v.problems.join(" ")).toMatch(/sandbox.enabled" must be a boolean/);
    expect(v.unknownKeys).toEqual(["futureKey", "network.tunnel"]);
    writeFileSync(userSettings(), "{ not json");
    expect(readSandbox(ws, home, "darwin", { managedPath: NO_MANAGED() }).problems.join(" ")).toMatch(/not valid JSON/);
  });
});

// --- doctor scoring --------------------------------------------------------------------------------

describe("doctor: the protection score", () => {
  it("S1 / INST-007: no sandbox key anywhere: the sandbox checks score 0, the score is shown, nothing fails because of it", () => {
    install(l, "user", ws, "0.2.0", { home, platform: "darwin" });
    const cs = doctor(l, ws, docOpts());
    for (const n of ["sandbox", "sandbox network", "sandbox escape"]) {
      expect(find(cs, n)?.points, n).toBe(0);
      expect(find(cs, n)?.status, n).not.toBe("fail");
    }
    expect(find(cs, "sandbox")?.weight).toBe(15);
    expect(find(cs, "sandbox network")?.weight).toBe(10);
    expect(find(cs, "sandbox escape")?.weight).toBe(5);
    expect(find(cs, "sandbox hooks")).toMatchObject({ status: "ok", weight: 5, points: 5 });
    const score = find(cs, "protection score");
    expect(score?.score).toBeGreaterThan(0);
    expect(score?.score).toBeLessThan(100);
    expect(find(cs, "hooks (user)")).toMatchObject({ weight: 25, points: 25 });
    expect(cs.some((c) => c.name === "OS sandbox")).toBe(false);
  });
  it("S2: sandbox on, network unrestricted: enabled full points, network 0", () => {
    writeJson(userSettings(), { sandbox: { enabled: true } });
    const cs = doctor(l, ws, docOpts());
    expect(find(cs, "sandbox")).toMatchObject({ status: "ok", points: 15 });
    expect(find(cs, "sandbox network")).toMatchObject({ points: 0 });
    expect(find(cs, "sandbox network")?.detail).toMatch(/not restricted/);
    // Claude Code's default lets commands ask to run unsandboxed.
    expect(find(cs, "sandbox escape")).toMatchObject({ points: 0 });
    expect(find(cs, "sandbox escape")?.detail).toMatch(/allowUnsandboxedCommands/);
  });
  it("the installed profile earns every sandbox point and labels the hosts", () => {
    installAll();
    const cs = doctor(l, ws, docOpts());
    expect(find(cs, "sandbox")?.points).toBe(15);
    expect(find(cs, "sandbox network")).toMatchObject({ status: "ok", points: 10 });
    expect(find(cs, "sandbox network")?.detail).toMatch(/fetch-only/);
    expect(find(cs, "sandbox network")?.detail).toMatch(/upload-capable.*github\.com/);
    expect(find(cs, "sandbox escape")).toMatchObject({ status: "ok", points: 5 });
    expect(find(cs, "sandbox profile")?.status).toBe("ok");
  });
  it("network restricted to hosts outside the policy, or added by the repository: half points, named", () => {
    writeJson(userSettings(), { sandbox: { enabled: true, allowUnsandboxedCommands: false, network: { allowedDomains: ["github.com"] } } });
    writeJson(settingsPath("project", ws, home), { sandbox: { network: { allowedDomains: ["collector.example.net"] } } });
    const c = find(doctor(l, ws, docOpts()), "sandbox network");
    expect(c).toMatchObject({ status: "warn", points: 5 });
    expect(c?.detail).toMatch(/collector\.example\.net/);
    expect(c?.detail).toMatch(/from the repository/);
  });
  it("escapes: excluded commands, the Docker socket, all Unix sockets, weakened isolation; safe commands from policy do not count", () => {
    writeJson(userSettings(), { sandbox: { enabled: true, allowUnsandboxedCommands: false, excludedCommands: ["docker *"], network: { allowUnixSockets: ["/var/run/docker.sock"] }, enableWeakerNestedSandbox: true } });
    const d = find(doctor(l, ws, docOpts()), "sandbox escape")?.detail ?? "";
    expect(d).toMatch(/excludedCommands.*docker \*/);
    expect(d).toMatch(/container engine socket/);
    expect(d).toMatch(/enableWeakerNestedSandbox/);
    writeJson(userSettings(), { sandbox: { enabled: true, allowUnsandboxedCommands: false, excludedCommands: ["watchman *"] } });
    atomicWrite(l.policy, JSON.stringify({ version: 2, sandbox: { safeExcludedCommands: ["watchman *"] } }));
    expect(find(doctor(l, ws, docOpts()), "sandbox escape")).toMatchObject({ status: "ok", points: 5 });
  });
  it("S16: the probe write fails with the sandbox on: doctor fails, hooks would run inside the sandbox", () => {
    writeJson(userSettings(), { sandbox: { enabled: true } });
    const c = find(doctor(l, ws, docOpts({ probe: () => false })), "sandbox hooks");
    expect(c?.status).toBe("fail");
    expect(c?.detail).toMatch(/cannot write its state/);
    expect(c?.detail).toMatch(/hooks would run inside the sandbox/);
    expect(c?.points).toBe(0);
  });
  it("S15 (doctor): unknown sandbox schema scores 0 with an explanation naming the Claude Code version", () => {
    writeJson(userSettings(), { sandbox: { enabled: true, futureSwitch: false } });
    const c = find(doctor(l, ws, docOpts()), "sandbox");
    expect(c).toMatchObject({ status: "warn", points: 0 });
    expect(c?.detail).toMatch(/could not read the sandbox settings for Claude Code 2\.1\.289/);
    expect(c?.detail).toMatch(/sandbox\.futureSwitch/);
  });
  it("FP4: on a machine without Claude Code the sandbox checks are left out of the score, not failed", () => {
    const cs = doctor(l, ws, docOpts({ claudeVersion: null }));
    const sb = find(cs, "sandbox");
    expect(sb?.status).toBe("ok");
    expect(sb?.weight).toBeUndefined();
    expect(find(cs, "sandbox network")).toBeUndefined();
    expect(find(cs, "sandbox escape")).toBeUndefined();
  });
  it("a cooldown check that does not apply is left out of the denominator; no decoys counts 0 of 5", () => {
    const cs = doctor(l, ws, docOpts());
    expect(find(cs, "package cooldown")?.weight).toBeUndefined();
    expect(find(cs, "canary files")).toMatchObject({ weight: 5, points: 0 });
  });
  it("the approval key: pinned 10, set but not pinned 5, missing 0", () => {
    install(l, "user", ws, "0.2.0", { home, platform: "darwin" });
    expect(find(doctor(l, ws, docOpts()), "approval passphrase")?.points).toBe(0);
    initApprover(l, PASS);
    expect(find(doctor(l, ws, docOpts()), "approval passphrase")?.points).toBe(5);
    install(l, "user", ws, "0.2.0", { home, platform: "darwin" });
    expect(find(doctor(l, ws, docOpts()), "approval passphrase")?.points).toBe(10);
  });
  it("a profile edited outside the firewall is reported until doctor --fix records it again", () => {
    installAll();
    const s = readJson(userSettings());
    (s.sandbox as Record<string, unknown>).excludedCommands = ["make *"];
    writeJson(userSettings(), s);
    expect(find(doctor(l, ws, docOpts()), "sandbox profile")?.status).toBe("warn");
  });
});

// --- doctor --fix ----------------------------------------------------------------------------------

describe("doctor --fix (the sandbox profile)", () => {
  it("S5 / INST-008: right passphrase and yes: sandbox key merged, hooks untouched, backup written, record entry", async () => {
    install(l, "user", ws, "0.2.0", { home, platform: "darwin" });
    initApprover(l, PASS);
    const before = readJson(userSettings());
    const o = io();
    expect(await runSandboxFix(l, plan(), o)).toBe("written");
    const after = readJson(userSettings());
    expect(after.hooks).toEqual(before.hooks);
    expect((after.sandbox as Record<string, unknown>).enabled).toBe(true);
    expect(((after.sandbox as Record<string, Record<string, unknown>>).network?.allowedDomains as string[]).includes("registry.npmjs.org")).toBe(true);
    const recs = readSandboxRecords(l);
    expect(recs).toHaveLength(1);
    expect(recs[0]).toMatchObject({ kind: "sandbox", scope: "user", path: userSettings() });
    expect(recs[0]?.profileHash).toBe(profileHash(after.sandbox));
    expect(existsSync(recs[0]?.backup as string)).toBe(true);
    expect(JSON.parse(JSON.parse(readFileSync(recs[0]?.backup as string, "utf8")).content as string)).toEqual(before);
    expect(o.lines.join("\n")).toMatch(/fetch-only/);
  });
  it("only the sandbox key changes: permissions, env and other sandbox keys the person set are kept", async () => {
    initApprover(l, PASS);
    writeJson(userSettings(), { permissions: { allow: ["Bash(npm test)"] }, env: { FOO: "1" }, sandbox: { filesystem: { denyRead: ["~/secrets"] }, network: { allowMachLookup: ["com.apple.coresimulator.*"] } } });
    await runSandboxFix(l, plan(), io());
    const s = readJson(userSettings());
    expect(s.permissions).toEqual({ allow: ["Bash(npm test)"] });
    expect(s.env).toEqual({ FOO: "1" });
    const sb = s.sandbox as Record<string, Record<string, unknown>>;
    expect(sb.filesystem).toEqual({ denyRead: ["~/secrets"] });
    expect(sb.network?.allowMachLookup).toEqual(["com.apple.coresimulator.*"]);
  });
  it("S4: wrong passphrase: no write, no record", async () => {
    install(l, "user", ws, "0.2.0", { home, platform: "darwin" });
    initApprover(l, PASS);
    const text = readFileSync(userSettings(), "utf8");
    const o = io({ passphrase: "not the passphrase" });
    expect(await runSandboxFix(l, plan(), o)).toBe("bad-passphrase");
    expect(readFileSync(userSettings(), "utf8")).toBe(text);
    expect(existsSync(sandboxRecordsPath(l))).toBe(false);
    expect(o.lines.join(" ")).toMatch(/wrong approval passphrase/);
  });
  it("without an approval passphrase: refused with the approver init instruction", async () => {
    const o = io();
    expect(await runSandboxFix(l, plan(), o)).toBe("no-approver");
    expect(o.asked).toBe(0);
    expect(existsSync(userSettings())).toBe(false);
    expect(o.lines.join(" ")).toMatch(/approver init/);
  });
  it("declining at the prompt writes nothing", async () => {
    initApprover(l, PASS);
    expect(await runSandboxFix(l, plan(), io({ yes: false }))).toBe("declined");
    expect(existsSync(userSettings())).toBe(false);
  });
  it("S15: unknown sandbox schema: --fix refuses with an explanation and writes nothing", async () => {
    initApprover(l, PASS);
    writeJson(userSettings(), { sandbox: { enabled: true, futureSwitch: false } });
    const text = readFileSync(userSettings(), "utf8");
    const p = plan();
    expect(p.refused).toMatch(/could not read the sandbox settings for Claude Code 2\.1\.289.*sandbox\.futureSwitch/);
    const o = io();
    expect(await runSandboxFix(l, p, o)).toBe("refused");
    expect(o.asked).toBe(0);
    expect(readFileSync(userSettings(), "utf8")).toBe(text);
    expect(() => applySandboxFix(l, p)).toThrow(/could not read/);
  });
  it("an unparseable settings file: --fix refuses", () => {
    mkdirSync(join(home, ".claude"), { recursive: true });
    writeFileSync(userSettings(), "{ broken");
    expect(plan().refused).toMatch(/not valid JSON|cannot be read as JSON/);
  });
  it("FP2: the person edits the profile in their editor, then doctor --fix: re-recorded, no warnings", async () => {
    installAll();
    initApprover(l, PASS);
    const s = readJson(userSettings());
    (s.sandbox as Record<string, Record<string, unknown>>).network!.allowedDomains = ["github.com"];
    writeJson(userSettings(), s);
    expect(find(doctor(l, ws, docOpts()), "sandbox profile")?.status).toBe("warn");
    expect(await runSandboxFix(l, plan(), io())).toBe("written");
    const cs = doctor(l, ws, docOpts());
    expect(find(cs, "sandbox profile")?.status).toBe("ok");
    expect(cs.filter((c) => c.name.startsWith("sandbox") && c.status !== "ok")).toEqual([]);
  });
  it("a second run with nothing to change asks nothing", async () => {
    installAll();
    initApprover(l, PASS);
    const o = io();
    expect(await runSandboxFix(l, plan(), o)).toBe("unchanged");
    expect(o.asked).toBe(0);
  });
  it("the file changing between plan and write is refused", () => {
    const p = plan();
    writeJson(userSettings(), { permissions: {} });
    expect(() => applySandboxFix(l, p)).toThrow(/changed while the fix was being confirmed/);
  });
  it("keeps the first backup across runs (the file before the firewall ever wrote a profile)", async () => {
    initApprover(l, PASS);
    writeJson(userSettings(), { permissions: { allow: [] } });
    await runSandboxFix(l, plan(), io());
    const first = readSandboxRecords(l)[0]?.backup;
    atomicWrite(l.policy, JSON.stringify({ version: 2, fetchAllowHosts: ["=api.example.com"] }));
    const cfg = { ...defaultConfig(), fetchAllowHosts: ["=api.example.com"] };
    await runSandboxFix(l, plan("user", cfg), io());
    expect(readSandboxRecords(l)[0]?.backup).toBe(first);
    expect(((readJson(userSettings()).sandbox as Record<string, Record<string, unknown>>).network?.allowedDomains)).toEqual(["api.example.com"]);
  });
  it("project scope does not write strictAllowlist (Claude Code ignores it there) and says so", () => {
    const p = plan("project");
    expect(p.path).toBe(settingsPath("project", ws, home));
    expect((p.sandbox.network as Record<string, unknown>).strictAllowlist).toBeUndefined();
    expect(p.notes.join(" ")).toMatch(/only honoured from user and managed settings/);
  });
  it("the diff shows added and removed lines with context", () => {
    const d = lineDiff('{\n  "a": 1\n}\n', '{\n  "a": 1,\n  "b": 2\n}\n');
    expect(d).toContain('-   "a": 1');
    expect(d).toContain('+   "a": 1,');
    expect(d).toContain('+   "b": 2');
    expect(d).toContain("  {");
    expect(lineDiff("", '{\n  "sandbox": {}\n}\n').every((x) => x.startsWith("+ "))).toBe(true);
  });
});

describe("doctor --fix through the CLI", () => {
  it("S3: --dry-run prints the diff, writes nothing, never asks for the passphrase, exits 0", () => {
    const h = tempHome();
    initApprover(layout(join(h, ".launchsafe-firewall")), PASS);
    const proj = join(h, "proj");
    mkdirSync(proj, { recursive: true });
    writeJson(join(h, ".claude", "settings.json"), { permissions: { allow: ["Bash(npm test)"] } });
    const text = readFileSync(join(h, ".claude", "settings.json"), "utf8");
    const r = spawnCli(["doctor", "--fix", "--dry-run", "--project", proj], { home: h });
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/\+\s+"sandbox": \{/);
    expect(r.stdout).toMatch(/registry\.npmjs\.org\s+fetch-only, upload-capable/);
    expect(r.stdout).toMatch(/Dry run: nothing was written/);
    expect(r.stdout + r.stderr).not.toMatch(/Approval passphrase/);
    expect(readFileSync(join(h, ".claude", "settings.json"), "utf8")).toBe(text);
    expect(existsSync(join(h, ".launchsafe-firewall", "sandbox-install.json"))).toBe(false);
  });
  it("--fix without a terminal is refused before anything is written", () => {
    const r = spawnCli(["doctor", "--fix"]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/interactive terminal/);
    expect(existsSync(join(r.home, ".claude", "settings.json"))).toBe(false);
  });
  it("--dry-run and --scope without --fix are usage errors", () => {
    expect(spawnCli(["doctor", "--dry-run"]).status).toBe(64);
    expect(spawnCli(["doctor", "--scope", "project"]).status).toBe(64);
    expect(spawnCli(["doctor", "--fix", "--scope", "everywhere"]).status).toBe(64);
  });
  it("S17: doctor --json includes the score and per-check points", () => {
    const r = spawnCli(["doctor", "--json"]);
    const cs = JSON.parse(r.stdout) as Check[];
    const score = cs.find((c) => c.name === "protection score");
    expect(typeof score?.score).toBe("number");
    expect(cs.some((c) => typeof c.points === "number" && typeof c.weight === "number")).toBe(true);
  });
  it("the text output ends with the score and each check's contribution", () => {
    const r = spawnCli(["doctor"]);
    expect(r.stdout).toMatch(/Setup score: \d+\/100/);
    expect(r.stdout).toMatch(/hooks\s+0\/25/);
  });
});

// --- protecting the recorded profile (hook decisions) -------------------------------------------

const SETTINGS = `${HOME}/.claude/settings.json`;
const INSTALLED_SANDBOX = profileFromPolicy(defaultConfig()).profile as unknown as Record<string, unknown>;
const FILE = { permissions: { allow: ["Bash(npm test)"] }, sandbox: INSTALLED_SANDBOX };
const TEXT = JSON.stringify(FILE, null, 2);
const recorded = (over: Record<string, unknown> = {}) => ({ readFile: (p: string) => (p === SETTINGS ? TEXT : null), registeredSettings: [SETTINGS], sandboxProfiles: [{ path: SETTINGS, installed: INSTALLED_SANDBOX }], ...over });
const unrecorded = { readFile: (p: string) => (p === SETTINGS ? TEXT : null), registeredSettings: [] as string[] };
const edit = (old_string: string, new_string: string) => ["Edit", { file_path: SETTINGS, old_string, new_string }] as const;

describe("a sandbox profile the firewall installed (weakening it is FW-TAMPER)", () => {
  const deny = (d: ReturnType<typeof run>): void => {
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules, explain(d)).toContain("FW-TAMPER");
  };
  for (const tainted of [false, true]) {
    const st = tainted ? "untrusted" : "trusted";
    it(`S8: Write setting sandbox.enabled false (${st})`, () => deny(run("Write", { file_path: SETTINGS, content: JSON.stringify({ ...FILE, sandbox: { ...INSTALLED_SANDBOX, enabled: false } }) }, { tainted, ctx: recorded() })));
    it(`S9: Edit adding example.net to allowedDomains (${st})`, () => deny(run(...edit('"allowedDomains": [', '"allowedDomains": [\n        "example.net",'), { tainted, ctx: recorded() })));
    it(`Edit setting allowUnsandboxedCommands true (${st})`, () => deny(run(...edit('"allowUnsandboxedCommands": false', '"allowUnsandboxedCommands": true'), { tainted, ctx: recorded() })));
    it(`Edit adding an excluded command (${st})`, () => deny(run(...edit('"excludedCommands": []', '"excludedCommands": ["curl *"]'), { tainted, ctx: recorded() })));
    it(`Write removing the sandbox key (${st})`, () => deny(run("Write", { file_path: SETTINGS, content: JSON.stringify({ permissions: FILE.permissions }) }, { tainted, ctx: recorded() })));
    it(`Edit adding a WebFetch(domain:...) allow rule for a host outside the policy (${st})`, () => deny(run(...edit('"Bash(npm test)"', '"Bash(npm test)", "WebFetch(domain:collector.example.net)"'), { tainted, ctx: recorded() })));
    it(`Edit turning off the strict allowlist (${st})`, () => deny(run(...edit('"strictAllowlist": true', '"strictAllowlist": false'), { tainted, ctx: recorded() })));
    it(`Edit allowing every Unix socket (${st})`, () => deny(run(...edit('"allowLocalBinding": true', '"allowLocalBinding": true, "allowAllUnixSockets": true'), { tainted, ctx: recorded() })));
  }
  it("Bash rewriting the file (result cannot be computed) is denied", () => deny(bash(`sed -i '' 's/"enabled": true/"enabled": false/' ${SETTINGS}`, { ctx: recorded() })));
  it("rm of a settings file that holds only the recorded profile is denied", () => deny(bash(`rm ${WS}/.claude/settings.json`, { ctx: { readFile: () => JSON.stringify({ sandbox: INSTALLED_SANDBOX }), registeredSettings: [`${WS}/.claude/settings.json`], sandboxProfiles: [{ path: `${WS}/.claude/settings.json`, installed: INSTALLED_SANDBOX }] } })));
  it("S10: Edit removing a host from allowedDomains (narrowing) is an ordinary settings change: ask FW-AGENT-SETTINGS", () => {
    const d = run(...edit('"pypi.org",\n', ""), { ctx: recorded() });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-AGENT-SETTINGS");
    expect(d.rules).not.toContain("FW-TAMPER");
  });
  it("adding a host the policy already lists is not tampering", () => {
    const d = run(...edit('"allowedDomains": [', '"allowedDomains": [\n        "static.crates.io",'), { ctx: recorded() });
    expect(d.rules, explain(d)).not.toContain("FW-TAMPER");
  });
  it("FP1: adding a permissions.allow rule (no sandbox change) asks FW-AGENT-SETTINGS, as in v0.1", () => {
    const d = run(...edit('"Bash(npm test)"', '"Bash(npm test)", "Bash(npm run lint)"'), { ctx: recorded() });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-AGENT-SETTINGS");
    expect(d.rules).not.toContain("FW-TAMPER");
  });
  it("a weakness already on disk (the person's own edit) is not the agent's: an unrelated edit asks", () => {
    const personal = JSON.stringify({ ...FILE, sandbox: { ...INSTALLED_SANDBOX, excludedCommands: ["make *"] } }, null, 2);
    const d = run(...edit('"Bash(npm test)"', '"Bash(npm test)", "Bash(npm run lint)"'), { ctx: recorded({ readFile: (p: string) => (p === SETTINGS ? personal : null) }) });
    expect(d.rules, explain(d)).not.toContain("FW-TAMPER");
  });
  it("S11: sandbox.enabled false without a record (the person's own sandbox), untrusted: held FW-INSTRUCTIONS-HELD", () => {
    const d = run(...edit('"enabled": true', '"enabled": false'), { tainted: true, ctx: unrecorded });
    expect(d.verdict, explain(d)).toBe("queue");
    expect(d.rules).toContain("FW-INSTRUCTIONS-HELD");
  });
  it("without a record, trusted: ask FW-AGENT-SETTINGS", () => {
    const d = run(...edit('"enabled": true', '"enabled": false'), { ctx: unrecorded });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-AGENT-SETTINGS");
  });
  it("Protection off (policy sandbox.protectInstalledProfile false): weakening a recorded profile is an ordinary settings change", () => {
    const d = run(...edit('"enabled": true', '"enabled": false'), { ctx: recorded(), config: { sandbox: { protectInstalledProfile: false } } });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).not.toContain("FW-TAMPER");
  });
  it("sandboxViolations: an addition the recorded profile already has is fine; a removed denied domain is a weakening", () => {
    const installed = { ...INSTALLED_SANDBOX, network: { ...(INSTALLED_SANDBOX.network as object), allowedDomains: ["x.example.com"], deniedDomains: ["bad.example.com"] } };
    const g = { installed, policyDomains: [], safeExcluded: [] };
    expect(sandboxViolations({ sandbox: { ...installed, network: { ...installed.network, allowedDomains: [] } } }, { sandbox: installed }, g)).toEqual([]);
    expect(sandboxViolations({ sandbox: installed }, { sandbox: { ...installed, network: { ...installed.network, deniedDomains: [] } } }, g).join(" ")).toMatch(/deniedDomains/);
  });
});

describe("agent running the fix", () => {
  it("S12 / INST-009: launchsafe-firewall doctor --fix from an agent is denied FW-TAMPER", () => {
    for (const c of ["launchsafe-firewall doctor --fix", "launchsafe-firewall doctor --fix --scope project", "launchsafe-firewall doctor --fix --dry-run"]) {
      const d = bash(c);
      expect(d.verdict, `${c}: ${explain(d)}`).toBe("deny");
      expect(d.rules).toContain("FW-TAMPER");
    }
  });
  it("S13: launchsafe-firewall doctor (and --json) from an untrusted session is allowed", () => {
    for (const c of ["launchsafe-firewall doctor", "launchsafe-firewall doctor --json"]) {
      const d = bash(c, { tainted: true });
      expect(d.verdict, `${c}: ${explain(d)}`).toBe("allow");
    }
  });
});

// --- ConfigChange --------------------------------------------------------------------------------

describe("ConfigChange with a recorded profile", () => {
  const configChange = () => runHook(JSON.stringify({ hook_event_name: "ConfigChange", session_id: "s1", cwd: ws }), { env: {}, layout: l, home });
  it("S14: settings changed outside the agent to disable the recorded sandbox: blocked with a message (exit 2)", () => {
    installAll();
    expect(configChange().exitCode).toBe(0);
    const s = readJson(userSettings());
    (s.sandbox as Record<string, unknown>).enabled = false;
    writeJson(userSettings(), s);
    const r = configChange();
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toMatch(/switches the sandbox off/);
  });
  it("a narrowing outside the agent passes", () => {
    installAll();
    const s = readJson(userSettings());
    (s.sandbox as Record<string, Record<string, unknown>>).network!.allowedDomains = ["github.com"];
    writeJson(userSettings(), s);
    expect(configChange().exitCode).toBe(0);
  });
  it("protection off: not checked", () => {
    installAll();
    atomicWrite(l.policy, JSON.stringify({ version: 2, sandbox: { protectInstalledProfile: false } }));
    writeJson(userSettings(), { ...readJson(userSettings()), sandbox: { enabled: false } });
    expect(configChange().exitCode).toBe(0);
  });
});

// --- hook context (end to end through runHook) ---------------------------------------------------

describe("through the hook, with the profile installed by the fix", () => {
  const pre = (tool_input: Record<string, unknown>, tool_name = "Edit") => runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s2", cwd: ws, permission_mode: "default", tool_name, tool_input }), { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, home, detectNonInteractive: () => false, notifyDeps: { spawn: () => undefined } });
  it("a sandbox-only settings file (profile at project scope, hooks at user scope) is protected too", async () => {
    install(l, "user", ws, "0.2.0", { home, platform: "darwin" });
    initApprover(l, PASS);
    await runSandboxFix(l, plan("project"), io());
    const p = settingsPath("project", ws, home);
    const r = pre({ file_path: p, old_string: '"enabled": true', new_string: '"enabled": false' });
    expect(r.exitCode === 2 || /"deny"/.test(r.stdout), r.stdout + r.stderr).toBe(true);
  });
});

// --- policy ---------------------------------------------------------------------------------------

describe("policy key sandbox (schema v2, its own module)", () => {
  it("validates", () => {
    expect(validatePolicy({ version: 2, sandbox: { protectInstalledProfile: false, strictAllowlist: false, safeExcludedCommands: ["watchman *"] } }, "p").sandbox).toEqual({ protectInstalledProfile: false, strictAllowlist: false, safeExcludedCommands: ["watchman *"] });
    expect(() => validatePolicy({ version: 2, sandbox: { protect: true } }, "p")).toThrow(/sandbox.protect" is not a known setting/);
    expect(() => validatePolicy({ version: 2, sandbox: { strictAllowlist: "yes" } }, "p")).toThrow(/must be true or false/);
    expect(() => validatePolicy({ version: 2, sandbox: [] }, "p")).toThrow(/must be an object/);
    expect(() => validatePolicy({ version: 2, sandbox: { safeExcludedCommands: [""] } }, "p")).toThrow(/non-empty strings/);
  });
  it("defaults: protection on, strict allowlist on, no safe excluded commands", () => {
    expect(defaultConfig().sandbox).toEqual({ protectInstalledProfile: true, strictAllowlist: true, safeExcludedCommands: [] });
  });
  it("a project may only tighten", () => {
    const base = { ...defaultConfig(), sandbox: { protectInstalledProfile: false, strictAllowlist: false, safeExcludedCommands: ["make *"] } };
    const up = mergeTighten(base, validatePolicy({ version: 2, sandbox: { protectInstalledProfile: true, strictAllowlist: true } }, "proj"));
    expect(up.config.sandbox).toMatchObject({ protectInstalledProfile: true, strictAllowlist: true, safeExcludedCommands: ["make *"] });
    const down = mergeTighten(defaultConfig(), validatePolicy({ version: 2, sandbox: { protectInstalledProfile: false, safeExcludedCommands: ["curl *"] } }, "proj"));
    expect(down.config.sandbox).toMatchObject({ protectInstalledProfile: true, safeExcludedCommands: [] });
    expect(down.ignored.join(" ")).toMatch(/sandbox settings that switch protections off/);
    expect(down.ignored.join(" ")).toMatch(/safeExcludedCommands/);
  });
  it("a version 1 file with sandbox is migrated in memory", () => {
    expect(validatePolicy({ version: 1, sandbox: { strictAllowlist: false } }, "p").sandbox).toEqual({ strictAllowlist: false });
  });
});

// --- uninstall ------------------------------------------------------------------------------------

describe("uninstall and the sandbox profile", () => {
  it("plain uninstall keeps the sandbox (a person may want it)", () => {
    installAll();
    uninstall(l, {});
    expect((readJson(userSettings()).sandbox as Record<string, unknown>).enabled).toBe(true);
  });
  it("--remove-sandbox removes the profile, or puts back the person's earlier sandbox settings", async () => {
    initApprover(l, PASS);
    writeJson(userSettings(), { sandbox: { filesystem: { denyRead: ["~/x"] } }, permissions: {} });
    await runSandboxFix(l, plan(), io());
    expect(removeSandboxProfiles(l)).toEqual([{ path: userSettings(), action: "restored" }]);
    expect(readJson(userSettings())).toEqual({ sandbox: { filesystem: { denyRead: ["~/x"] } }, permissions: {} });
    expect(readSandboxRecords(l)).toEqual([]);
    rmSync(userSettings());
    writeJson(userSettings(), { permissions: {} });
    await runSandboxFix(l, plan(), io());
    expect(removeSandboxProfiles(l)[0]?.action).toBe("removed");
    expect(readJson(userSettings())).toEqual({ permissions: {} });
  });
  it("--restore-backup: the hooks' own backup already restores the file; the sandbox record is dropped", () => {
    writeJson(userSettings(), { permissions: { allow: [] } });
    const original = readFileSync(userSettings(), "utf8");
    installAll();
    const res = uninstall(l, { restoreBackup: true });
    removeSandboxProfiles(l, { skipPaths: res.filter((r) => r.restored === "restored-backup").map((r) => r.path) });
    expect(readFileSync(userSettings(), "utf8")).toBe(original);
    expect(readSandboxRecords(l)).toEqual([]);
  });
});
