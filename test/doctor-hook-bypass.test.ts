/**
 * An install a repository cannot switch off: doctor FAILS (not warns) when the effective agent
 * configuration switches the firewall's hooks off or reaches into the hook process, names the file and
 * the fix; a managed install turns a repository's switch into a warning; `doctor --ci` runs only these
 * checks with a CI exit code. Temporary homes only.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { doctor, doctorCi, type Check } from "../src/runtime/doctor.js";
import { codexHooksOff, hookEnvProblems } from "../src/runtime/hook-bypass.js";
import { hookCommand, install, managedSettingsSnippet, settingsPath } from "../src/runtime/install.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { initApprover, unlockApprover } from "../src/runtime/approver.js";
import { recordRolloutChange, writeGrant } from "../src/runtime/rollout.js";
import { main } from "../src/climain.js";
import { adapterFor } from "../src/adapters/index.js";

let root: string;
let l: Layout;
let ws: string;
let home: string;
let managed: string;
let geminiSys: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-bypass-"));
  home = join(root, "u");
  l = layout(join(home, ".launchsafe-firewall"));
  ws = join(root, "ws");
  mkdirSync(ws, { recursive: true });
  mkdirSync(home, { recursive: true });
  managed = join(root, "managed-settings.json");
  geminiSys = join(root, "gemini-system.json");
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const env = (): NodeJS.ProcessEnv => ({ CODEX_HOME: join(home, ".codex"), GEMINI_CLI_HOME: home });
const opts = () => ({ home, platform: "linux" as const, claudeVersion: "2.1.289", claudeManagedPath: managed, geminiSystemPath: geminiSys, env: env(), findBinary: () => null });
const ci = (): Check[] => doctorCi(l, ws, opts());
const full = (): Check[] => doctor(l, ws, opts());
const named = (cs: Check[], name: string): Check[] => cs.filter((c) => c.name === name);
const fails = (cs: Check[]): Check[] => cs.filter((c) => c.status === "fail");

function put(path: string, value: unknown): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value));
}

function installUser(): void {
  install(l, "user", ws, "t", { home, platform: "linux" });
}

function managedInstall(lock = false): void {
  put(managed, managedSettingsSnippet(hookCommand(l), lock));
}

describe("Claude Code: settings that switch the hooks off", () => {
  it("a repository's disableAllHooks fails, names the file, the fix, and the headless case", () => {
    installUser();
    put(settingsPath("project", ws, home), { disableAllHooks: true });
    for (const cs of [ci(), full()]) {
      const c = named(cs, "disableAllHooks");
      expect(c.map((x) => x.status)).toEqual(["fail"]);
      expect(c[0]?.detail).toContain(settingsPath("project", ws, home));
      expect(c[0]?.detail).toMatch(/claude -p/);
      expect(c[0]?.detail).toMatch(/Fix: remove disableAllHooks/);
      expect(c[0]?.detail).toMatch(/install --managed/);
    }
  });
  it("settings saved with a UTF-8 byte order mark are read, so a switch in them is seen (it was only an unreadable-file warning); damage after the mark is still reported", () => {
    installUser();
    const project = settingsPath("project", ws, home);
    put(project, `\uFEFF${JSON.stringify({ disableAllHooks: true })}`);
    for (const cs of [ci(), full()]) {
      expect(named(cs, "disableAllHooks").map((x) => x.status)).toEqual(["fail"]);
      expect(named(cs, "Claude Code settings")).toEqual([]);
    }
    put(project, '\uFEFF{"disableAllHooks": ');
    expect(named(ci(), "disableAllHooks")).toEqual([]);
    expect(named(ci(), "Claude Code settings").map((x) => x.status)).toEqual(["warn"]);
  });
  it("settings.local.json and the user's own settings fail too", () => {
    installUser();
    put(settingsPath("local", ws, home), { disableAllHooks: true });
    expect(named(ci(), "disableAllHooks").map((c) => c.status)).toEqual(["fail"]);
    rmSync(settingsPath("local", ws, home));
    put(settingsPath("user", ws, home), { ...JSON.parse('{"disableAllHooks": true}') as object });
    expect(named(ci(), "disableAllHooks").map((c) => c.status)).toEqual(["fail"]);
  });
  it("with the managed install, a repository's switch is a warning: the managed hooks still run", () => {
    managedInstall(true);
    put(settingsPath("project", ws, home), { disableAllHooks: true });
    const c = named(ci(), "disableAllHooks");
    expect(c.map((x) => x.status)).toEqual(["warn"]);
    expect(c[0]?.detail).toMatch(/managed hooks still run/);
    expect(named(ci(), "managed settings")[0]?.status).toBe("ok");
    expect(fails(ci())).toEqual([]);
  });
  it("managed settings that set disableAllHooks fail, even with the firewall registered there", () => {
    put(managed, { ...managedSettingsSnippet(hookCommand(l), false), disableAllHooks: true });
    const c = named(ci(), "Claude Code managed settings");
    expect(c.map((x) => x.status)).toEqual(["fail"]);
    expect(c[0]?.detail).toContain(managed);
  });
  it("managed allowManagedHooksOnly without the firewall drops a user-level install: fail", () => {
    installUser();
    put(managed, { allowManagedHooksOnly: true });
    const c = named(ci(), "Claude Code managed settings");
    expect(c.map((x) => x.status)).toEqual(["fail"]);
    expect(c[0]?.detail).toMatch(/never run/);
  });
  it("a settings file's env that reaches the hook process fails; ordinary NODE_OPTIONS does not", () => {
    installUser();
    put(settingsPath("project", ws, home), { env: { NODE_OPTIONS: "--require ./x.js" } });
    expect(named(ci(), "Claude Code settings env").map((c) => c.status)).toEqual(["fail"]);
    put(settingsPath("project", ws, home), { env: { LAUNCHSAFE_FIREWALL_HOME: "/tmp/elsewhere" } });
    expect(named(ci(), "Claude Code settings env")[0]?.detail).toMatch(/LAUNCHSAFE_FIREWALL_HOME/);
    put(settingsPath("project", ws, home), { env: { NODE_OPTIONS: "--max-old-space-size=4096" } });
    expect(named(ci(), "Claude Code settings env")).toEqual([]);
    expect(hookEnvProblems({ env: { NODE_OPTIONS: "--import=./a.mjs" } })).toHaveLength(1);
    expect(hookEnvProblems({ env: { NODE_OPTIONS: "-r ./a.js" } })).toHaveLength(1);
  });
  for (const k of ["HOME", "NODE_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "NODE_COMPILE_CACHE", "NODE_EXTRA_CA_CERTS", "LAUNCHSAFE_FIREWALL_APPROVER"]) {
    it(`a settings env that sets ${k} fails`, () => {
      installUser();
      put(settingsPath("project", ws, home), { env: { [k]: "/tmp/x" } });
      const c = named(ci(), "Claude Code settings env");
      expect(c.map((x) => x.status)).toEqual(["fail"]);
      expect(c[0]?.detail).toContain(`env.${k}`);
    });
  }
  it("a settings env PATH counts only when a hook command starts node by name", () => {
    expect(hookEnvProblems({ env: { PATH: "/tmp/bin" } })).toEqual([]);
    expect(hookEnvProblems({ env: { PATH: "/tmp/bin" } }, { bareNode: true })).toHaveLength(1);
    expect(hookEnvProblems({ env: { EDITOR: "vim", TZ: "UTC" } })).toEqual([]);
  });
  it("the protection score gives no hook points while a switch is on", () => {
    installUser();
    const before = full().find((c) => c.name.startsWith("hooks ("));
    put(settingsPath("project", ws, home), { disableAllHooks: true });
    const after = full().find((c) => c.name.startsWith("hooks ("));
    expect(before?.points).toBe(before?.weight);
    expect(after?.points).toBe(0);
  });
});

describe("Codex and Gemini CLI", () => {
  it("codexHooksOff reads the three TOML spellings and ignores other tables and comments", () => {
    expect(codexHooksOff("[features]\nhooks = false\n")).toBe(true);
    expect(codexHooksOff("model = 'x'\nfeatures.hooks = false\n")).toBe(true);
    expect(codexHooksOff("features = { hooks = false }\n")).toBe(true);
    expect(codexHooksOff("[features]\nhooks = true\n")).toBe(false);
    expect(codexHooksOff("[other]\nhooks = false\n")).toBe(false);
    expect(codexHooksOff("[features]\n# hooks = false\n")).toBe(false);
    expect(codexHooksOff(null)).toBe(false);
  });
  it("a project's [features] hooks = false fails with the file and the fix", () => {
    put(join(ws, ".codex", "config.toml"), "[features]\nhooks = false\n");
    const c = named(ci(), "Codex project hooks");
    expect(c.map((x) => x.status)).toEqual(["fail"]);
    expect(c[0]?.detail).toContain(join(ws, ".codex", "config.toml"));
    expect(c[0]?.detail).toMatch(/Fix:/);
    expect(named(full(), "Codex project hooks").map((x) => x.status)).toEqual(["fail"]);
  });
  it("the user's own config.toml switching hooks off fails when Codex is installed", () => {
    install(l, "user", ws, "t", { home, agent: "codex", settings: adapterFor("codex").settings });
    put(join(home, ".codex", "config.toml"), "features.hooks = false\n");
    expect(named(ci(), "Codex user hooks").map((c) => c.status)).toEqual(["fail"]);
  });
  it("a project's Gemini hooksConfig fails; system settings with the firewall make it a warning", () => {
    put(join(ws, ".gemini", "settings.json"), { hooksConfig: { enabled: false } });
    expect(named(ci(), "Gemini CLI project settings").map((c) => c.status)).toEqual(["fail"]);
    put(geminiSys, JSON.parse(adapterFor("gemini").settings.managedSnippet(hookCommand(l, undefined, undefined, "gemini"), false).text) as object);
    expect(named(ci(), "Gemini CLI project settings").map((c) => c.status)).toEqual(["warn"]);
  });
  it("the user's Gemini settings switching hooks off fail when nothing overrides them", () => {
    put(join(home, ".gemini", "settings.json"), { hooksConfig: { disabled: ["launchsafe-firewall"] } });
    expect(named(ci(), "Gemini CLI user settings").map((c) => c.status)).toEqual(["fail"]);
  });
});

describe("doctor --ci", () => {
  const cli = async (argv: string[]): Promise<{ status: number; text: string }> => {
    const lines: string[] = [];
    const status = await main(argv, l, { write: (_fd, s) => void lines.push(s) });
    return { status, text: lines.join("") };
  };
  it("strict: a machine without the firewall fails", () => {
    expect(named(ci(), "hooks")[0]?.status).toBe("fail");
  });
  it("an install with a clean repository passes", () => {
    installUser();
    expect(fails(ci())).toEqual([]);
  });
  it("managed hooks without the fail-closed wrapper fail", () => {
    const snippet = JSON.stringify(managedSettingsSnippet(hookCommand(l), true)).replaceAll(" || exit 2", "");
    put(managed, snippet);
    const c = named(ci(), "hooks (managed)");
    expect(c.map((x) => x.status)).toEqual(["fail"]);
    expect(c[0]?.detail).toMatch(/fail-closed/);
  });
  it("hook commands that do not pin the approval key are a warning", () => {
    installUser();
    expect(named(ci(), "hook approval pin").map((c) => c.status)).toEqual(["warn"]);
    initApprover(l, "bypass test passphrase");
    installUser();
    expect(named(ci(), "hook approval pin")).toEqual([]);
  });
  it("runs no probes: no score entry", () => {
    expect(ci().some((c) => c.name === "protection score")).toBe(false);
  });
  it("exit 1 on a repository that switches hooks off, 0 when clean; --json; usage errors", async () => {
    const saved = process.env.HOME;
    process.env.HOME = home;
    try {
      await cliCases();
    } finally {
      process.env.HOME = saved;
    }
  });
  const cliCases = async (): Promise<void> => {
    expect((await cli(["doctor", "--ci", "--project", ws])).status).toBe(1);
    installUser();
    const clean = await cli(["doctor", "--ci", "--project", ws]);
    // The CLI reads this platform's managed files (read-only; none in the test container) and the test home.
    put(settingsPath("project", ws, process.env.HOME ?? home), { disableAllHooks: true });
    put(join(ws, ".codex", "config.toml"), "[features]\nhooks = false\n");
    const bad = await cli(["doctor", "--ci", "--project", ws]);
    expect(bad.status).toBe(1);
    expect(bad.text).toMatch(/FAIL {2}Codex project hooks/);
    expect(bad.text).toMatch(/failed/);
    const j = await cli(["doctor", "--ci", "--json", "--project", ws]);
    expect(j.status).toBe(1);
    expect((JSON.parse(j.text) as { ok: boolean }).ok).toBe(false);
    expect(clean.status, clean.text).toBe(0);
    expect(clean.text).toMatch(/No check failed/);
    expect((await cli(["doctor", "--ci", "--fix"])).status).toBe(64);
    expect((await cli(["doctor", "--ci", "--repair-state"])).status).toBe(64);
  };
  it("watch mode on fails under --ci and is a warning in plain doctor", () => {
    initApprover(l, "bypass test passphrase");
    installUser();
    const g = writeGrant(l, unlockApprover(l, "bypass test passphrase"));
    recordRolloutChange(l, { mode: "watch", by: "person", grant: g.id, until: g.until });
    put(l.policy, { version: 3, rollout: { mode: "watch" } });
    const r = named(ci(), "rollout mode");
    expect(r[0]?.status).toBe("fail");
    expect(r[0]?.detail).toMatch(/^watch/);
    expect(named(full(), "rollout mode")[0]?.status).toBe("warn");
  });
  it("a watch line without a grant is reported as not in effect", () => {
    put(l.policy, { version: 3, rollout: { mode: "watch" } });
    expect(named(ci(), "rollout mode")[0]?.detail).toMatch(/^enforce: .*no signed grant/);
  });
});
