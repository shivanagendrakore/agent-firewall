/**
 * Finding ids (F1...F43) are the ones in the CHANGELOG.
 * Final review of v0.2: the Claude Code sandbox profile, doctor's score, doctor --fix, the
 * protection of the installed profile, uninstall. Each finding case asserts the decision the README /
 * docs promise; it was an `it.fails` in the review and is kept as a regression test now that the finding
 * is fixed. The controls are documented behaviour that holds. Tool calls and command shapes only; placeholders, no payloads. Everything runs in the suite's
 * temporary home.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { profileFromPolicy } from "../../src/engine/sandbox.js";
import { runHook } from "../../src/hook/claude.js";
import { defaultConfig } from "../../src/policy.js";
import { doctor, type Check } from "../../src/runtime/doctor.js";
import { install, settingsPath, uninstall } from "../../src/runtime/install.js";
import { layout, type Layout } from "../../src/runtime/layout.js";
import { applySandboxFix, planSandboxFix, readSandboxRecords, removeSandboxProfiles } from "../../src/runtime/sandbox.js";
import { send, verdict, rules } from "../adapters/harness.js";
import { bash, explain, HOME, run, testRoot, WS } from "../helpers.js";

// --- in-process decisions against a recorded user-scope profile -----------------------------------

const SETTINGS = `${HOME}/.claude/settings.json`;
const LOCAL = `${WS}/.claude/settings.local.json`;
const PROJ = `${WS}/.claude/settings.json`;
const INSTALLED = profileFromPolicy(defaultConfig()).profile as unknown as Record<string, unknown>;
const FILE = { permissions: { allow: ["Bash(npm test)"] }, model: "opus", sandbox: INSTALLED };
const TEXT = JSON.stringify(FILE, null, 2);
const recorded = { readFile: (p: string) => (p === SETTINGS ? TEXT : null), registeredSettings: [SETTINGS], sandboxProfiles: [{ path: SETTINGS, installed: INSTALLED }] };
const tamper = (d: ReturnType<typeof run>): void => {
  expect(d.verdict, explain(d)).toBe("deny");
  expect(d.rules, explain(d)).toContain("FW-TAMPER");
};

describe("F9: a higher-precedence settings layer weakens the recorded profile without FW-TAMPER", () => {
  // Claude Code (and the firewall's own readSandbox) take sandbox scalars from local > project > user.
  it("Write .claude/settings.local.json with sandbox.enabled false while the profile is in ~/.claude/settings.json: FW-TAMPER", () => {
    tamper(run("Write", { file_path: LOCAL, content: '{"sandbox":{"enabled":false}}' }, { ctx: recorded }));
  });
  it("Write .claude/settings.json (project) with sandbox.allowUnsandboxedCommands true: FW-TAMPER", () => {
    tamper(run("Write", { file_path: PROJ, content: '{"sandbox":{"allowUnsandboxedCommands":true}}' }, { ctx: recorded }));
  });
  it("Write .claude/settings.json (project) adding sandbox.excludedCommands (lists merge across scopes): FW-TAMPER", () => {
    tamper(run("Write", { file_path: PROJ, content: '{"sandbox":{"excludedCommands":["curl *"]}}' }, { ctx: recorded }));
  });
  it("control: the same write to the recorded file itself is FW-TAMPER", () => {
    tamper(run("Edit", { file_path: SETTINGS, old_string: '"enabled": true', new_string: '"enabled": false' }, { ctx: recorded }));
  });
  it("control: a shell write to the local settings file is denied (result cannot be checked)", () => {
    tamper(bash(`echo '{"sandbox":{"enabled":false}}' > ${LOCAL}`, { ctx: recorded }));
  });
});

describe("F9 response: ordinary layer changes stay ordinary", () => {
  it("a project settings file adding a permission, or a WebFetch rule under a strict user profile, is not FW-TAMPER", () => {
    for (const content of ['{"permissions":{"allow":["Bash(npm test)"]}}', '{"permissions":{"allow":["WebFetch(domain:docs.example.com)"]}}', '{"sandbox":{"network":{"allowedDomains":["docs.example.com"]}}}']) {
      const d = run("Write", { file_path: PROJ, content }, { ctx: recorded });
      expect(d.rules, `${content}: ${explain(d)}`).not.toContain("FW-TAMPER");
    }
  });
  it("a project settings file of another project does not interact with a project-level profile", () => {
    const other = "/Users/dev/other/.claude/settings.local.json";
    const ctxP = { readFile: (p: string) => (p === PROJ ? TEXT : null), registeredSettings: [PROJ], sandboxProfiles: [{ path: PROJ, installed: INSTALLED }] };
    expect(run("Write", { file_path: other, content: '{"sandbox":{"enabled":false}}' }, { ctx: ctxP }).rules).not.toContain("FW-TAMPER");
    tamper(run("Write", { file_path: LOCAL, content: '{"sandbox":{"enabled":false}}' }, { ctx: ctxP }));
  });
});

describe("F29: known sandbox keys that weaken the profile are not compared", () => {
  it("Edit adding sandbox.bwrapPath pointing at an agent-written binary: FW-TAMPER", () => {
    tamper(run("Edit", { file_path: SETTINGS, old_string: '"enabled": true', new_string: '"enabled": true, "bwrapPath": "/tmp/placeholder-bwrap"' }, { ctx: recorded }));
  });
  it("Edit adding sandbox.filesystem.allowRead that re-opens what denyRead closed: FW-TAMPER", () => {
    const withDeny = { ...INSTALLED, filesystem: { denyRead: ["~/.ssh"] } };
    const text = JSON.stringify({ ...FILE, sandbox: withDeny }, null, 2);
    const ctx = { readFile: (p: string) => (p === SETTINGS ? text : null), registeredSettings: [SETTINGS], sandboxProfiles: [{ path: SETTINGS, installed: withDeny }] };
    tamper(run("Edit", { file_path: SETTINGS, old_string: '"denyRead": [', new_string: '"allowRead": ["~/.ssh"],\n      "denyRead": [' }, { ctx }));
  });
});

describe("controls: weakenings of the recorded file that are caught", () => {
  it("Edit adding \"*\" to allowedDomains", () => tamper(run("Edit", { file_path: SETTINGS, old_string: '"allowedDomains": [', new_string: '"allowedDomains": [\n "*",' }, { ctx: recorded })));
  it("MultiEdit switching the sandbox off", () => tamper(run("MultiEdit", { file_path: SETTINGS, edits: [{ old_string: '"enabled": true', new_string: '"enabled": false' }] }, { ctx: recorded })));
  it("Edit with replace_all true -> false", () => tamper(run("Edit", { file_path: SETTINGS, old_string: "true", new_string: "false", replace_all: true }, { ctx: recorded })));
  it("a duplicate key that wins (JSON.parse takes the last)", () => tamper(run("Edit", { file_path: SETTINGS, old_string: '"enabled": true', new_string: '"enabled": true, "enabled": false' }, { ctx: recorded })));
  it("WebFetch(domain:*) allow rule", () => tamper(run("Edit", { file_path: SETTINGS, old_string: '"Bash(npm test)"', new_string: '"Bash(npm test)", "WebFetch(domain:*)"' }, { ctx: recorded })));
  for (const c of [
    `jq '.sandbox.enabled=false' ${SETTINGS} > /tmp/s && mv /tmp/s ${SETTINGS}`,
    `python3 -c "import json;p='${SETTINGS}';d=json.load(open(p));d['sandbox']['enabled']=False;json.dump(d,open(p,'w'))"`,
    `node -e "require('fs').writeFileSync('${SETTINGS}','{}')"`,
    `perl -pi -e 's/true/false/' ~/.claude/settings.json`,
    `cd ~/.claude && sed -i '' 's/true/false/' settings.json`,
  ]) it(`shell: ${c.slice(0, 50)}`, () => tamper(bash(c, { ctx: recorded })));
  it("an ordinary model change in the recorded file asks FW-AGENT-SETTINGS, not FW-TAMPER", () => {
    const d = run("Edit", { file_path: SETTINGS, old_string: '"model": "opus"', new_string: '"model": "sonnet"' }, { ctx: recorded });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).not.toContain("FW-TAMPER");
  });
});

describe("F30: the derived profile can admit IP literals and wildcards over metadata/loopback", () => {
  it("non-canonical IPv4 forms of the metadata address are never written to allowedDomains", () => {
    const cfg = { ...defaultConfig(), fetchAllowHosts: ["=0251.0376.0251.0376", "=0xa9.0xfe.0xa9.0xfe", "=169.254.43518", "=10.1"], sendAllowHosts: [], denyHosts: [] };
    expect(profileFromPolicy(cfg).profile.network.allowedDomains).toEqual([]);
  });
  it("a suffix entry never yields a wildcard that covers a metadata host or an IP", () => {
    const cfg = { ...defaultConfig(), fetchAllowHosts: ["google.internal", "254.169.254"], sendAllowHosts: [], denyHosts: [] };
    const allowed = profileFromPolicy(cfg).profile.network.allowedDomains;
    expect(allowed).not.toContain("*.google.internal"); // admits metadata.google.internal
    expect(allowed).not.toContain("*.254.169.254"); // admits 169.254.169.254
  });
  it("control: canonical IPs, IPv6, metadata names, capture hosts and loopback are dropped", () => {
    const cfg = { ...defaultConfig(), fetchAllowHosts: ["=169.254.169.254", "=[fd00:ec2::254]", "=metadata.google.internal", "webhook.site", "=127.0.0.1", "=a.localhost", "*.ngrok.io", "=api.example.com"], sendAllowHosts: [], denyHosts: [] };
    expect(profileFromPolicy(cfg).profile.network.allowedDomains).toEqual(["api.example.com"]);
  });
});

// --- on disk: doctor, doctor --fix, ConfigChange, uninstall -----------------------------------------

let root: string;
let home: string;
let ws: string;
let l: Layout;
beforeEach(() => {
  root = mkdtempSync(join(testRoot(), "lsfw-rf-sb-"));
  home = join(root, "home");
  ws = join(home, "proj");
  mkdirSync(ws, { recursive: true });
  l = layout(join(home, ".launchsafe-firewall"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const NO_MANAGED = (): string => join(root, "no-managed-settings.json");
const userSettings = (): string => settingsPath("user", ws, home);
const writeJson = (p: string, v: unknown): void => {
  mkdirSync(join(p, ".."), { recursive: true });
  writeFileSync(p, `${JSON.stringify(v, null, 2)}\n`);
};
const readJson = (p: string): Record<string, unknown> => JSON.parse(readFileSync(p, "utf8")) as Record<string, unknown>;
const plan = (scope: "user" | "project" | "local" = "user") => planSandboxFix(l, ws, defaultConfig(), { scope, home, platform: "darwin", claudeVersion: "2.1.289", managedPath: NO_MANAGED() });
const find = (cs: Check[], name: string): Check | undefined => cs.find((c) => c.name === name);
const docOpts = (): { home: string; platform: "darwin"; claudeVersion: string } => ({ home, platform: "darwin", claudeVersion: "2.1.289" });
// doctor() reads managed settings from the system path (it has no override); this machine has none, and it is only read.
const configChange = () => runHook(JSON.stringify({ hook_event_name: "ConfigChange", session_id: "s1", cwd: ws }), { env: {}, layout: l, home });
function installAll(): void {
  install(l, "user", ws, "0.2.0", { home, platform: "darwin" });
  applySandboxFix(l, plan());
}

describe("F9 (ConfigChange): a local-settings override that switches the recorded sandbox off", () => {
  it("settings.local.json sets sandbox.enabled false: ConfigChange blocks (exit 2)", () => {
    installAll();
    expect(configChange().exitCode).toBe(0);
    writeJson(settingsPath("local", ws, home), { sandbox: { enabled: false } });
    // The firewall's own reader agrees the effective sandbox is now off.
    expect(doctor(l, ws, docOpts()).find((c) => c.name === "sandbox")?.points).toBe(0);
    expect(configChange().exitCode).toBe(2);
  });
  it("control: the same override in the recorded file is blocked", () => {
    installAll();
    writeJson(userSettings(), { ...readJson(userSettings()), sandbox: { ...(readJson(userSettings()).sandbox as object), enabled: false } });
    expect(configChange().exitCode).toBe(2);
  });
});

describe("F9 response (ConfigChange): ordinary project settings pass", () => {
  it("a project settings file that only adds permissions passes ConfigChange", () => {
    installAll();
    writeJson(settingsPath("project", ws, home), { permissions: { allow: ["Bash(npm test)", "WebFetch(domain:docs.example.com)"] } });
    const r = configChange();
    expect(r.exitCode, r.stderr).toBe(0);
  });
  it("a project settings file adding excludedCommands blocks ConfigChange", () => {
    installAll();
    writeJson(settingsPath("project", ws, home), { sandbox: { excludedCommands: ["curl *"] } });
    expect(configChange().exitCode).toBe(2);
  });
});

describe("F10: ConfigChange false positive from the person's own WebFetch(domain:...) rule", () => {
  it("a WebFetch rule the person had before doctor --fix does not block every later ConfigChange", () => {
    writeJson(userSettings(), { permissions: { allow: ["WebFetch(domain:docs.example.com)"] } });
    installAll();
    // doctor calls the recorded profile intact ...
    expect(find(doctor(l, ws, docOpts()), "sandbox profile")?.status).toBe("ok");
    // ... and an unrelated change by the person (a model switch) must pass ConfigChange.
    writeJson(userSettings(), { ...readJson(userSettings()), model: "sonnet" });
    const r = configChange();
    expect(r.exitCode, r.stderr).toBe(0);
  });
  it("control: the same rule judged on an agent Edit (before = the file) is not FW-TAMPER", () => {
    const text = JSON.stringify({ ...FILE, permissions: { allow: ["WebFetch(domain:docs.example.com)"] } }, null, 2);
    const d = run("Edit", { file_path: SETTINGS, old_string: '"model": "opus"', new_string: '"model": "sonnet"' }, { ctx: { ...recorded, readFile: (p: string) => (p === SETTINGS ? text : null) } });
    expect(d.rules, explain(d)).not.toContain("FW-TAMPER");
  });
});

describe("F27: doctor --fix keeps weakening sandbox keys already in the file", () => {
  it("allowAllUnixSockets true is not in the profile doctor --fix writes (\"no Unix sockets\")", () => {
    writeJson(userSettings(), { sandbox: { network: { allowAllUnixSockets: true } } });
    const p = plan();
    expect((p.sandbox.network as Record<string, unknown>).allowAllUnixSockets).not.toBe(true);
  });
  it("after doctor --fix, the sandbox escape check (whose hint is to run doctor --fix) scores full points", () => {
    writeJson(userSettings(), { sandbox: { enableWeakerNetworkIsolation: true, filesystem: { disabled: true } } });
    installAll();
    expect(find(doctor(l, ws, docOpts()), "sandbox escape")?.points).toBe(5);
  });
});

describe("F28: doctor's sandbox escape check ignores filesystem.allowWrite", () => {
  it("allowWrite [\"/\"] is not scored as \"nothing weakened\"", () => {
    writeJson(userSettings(), { sandbox: { enabled: true, allowUnsandboxedCommands: false, network: { allowedDomains: ["github.com"] }, filesystem: { allowWrite: ["/"] } } });
    const c = find(doctor(l, ws, docOpts()), "sandbox escape");
    expect(c?.points, c?.detail).toBe(0);
  });
  it("control: allowAllUnixSockets is scored as an escape", () => {
    writeJson(userSettings(), { sandbox: { enabled: true, allowUnsandboxedCommands: false, network: { allowAllUnixSockets: true } } });
    expect(find(doctor(l, ws, docOpts()), "sandbox escape")?.points).toBe(0);
  });
});

describe("F27/F28 response: what doctor --fix says it removes, and narrow writable paths", () => {
  it("the plan names the weakening keys it removes", () => {
    writeJson(userSettings(), { sandbox: { network: { allowAllUnixSockets: true }, filesystem: { allowWrite: ["/", "/tmp/build"] } } });
    const p = plan();
    expect(p.notes.join(" ")).toMatch(/allowAllUnixSockets/);
    expect((p.sandbox.filesystem as Record<string, unknown>).allowWrite).toEqual(["/tmp/build"]);
  });
  it("an allowWrite entry for a build directory is not an escape", () => {
    writeJson(userSettings(), { sandbox: { enabled: true, allowUnsandboxedCommands: false, network: { allowedDomains: ["github.com"] }, filesystem: { allowWrite: [join(ws, "tmp"), "/tmp/build"] } } });
    expect(find(doctor(l, ws, docOpts()), "sandbox escape")?.points).toBe(5);
  });
  it("F29: changing bwrapPath is FW-TAMPER, keeping the recorded one is not", () => {
    const withB = { ...INSTALLED, bwrapPath: "/usr/bin/bwrap" };
    const text = JSON.stringify({ ...FILE, sandbox: withB }, null, 2);
    const ctx = { readFile: (p: string) => (p === SETTINGS ? text : null), registeredSettings: [SETTINGS], sandboxProfiles: [{ path: SETTINGS, installed: withB }] };
    expect(run("Edit", { file_path: SETTINGS, old_string: '"model": "opus"', new_string: '"model": "sonnet"' }, { ctx }).rules).not.toContain("FW-TAMPER");
    tamper(run("Edit", { file_path: SETTINGS, old_string: '"/usr/bin/bwrap"', new_string: '"/tmp/x"' }, { ctx }));
  });
});

describe("F31: uninstall --restore-backup when doctor --fix ran before install", () => {
  it("--restore-backup leaves no sandbox profile behind", () => {
    writeJson(userSettings(), { permissions: { allow: [] } });
    applySandboxFix(l, plan()); // doctor --fix first (documented standalone)
    install(l, "user", ws, "0.2.0", { home, platform: "darwin" }); // hooks' first backup now holds the profile
    const res = uninstall(l, { restoreBackup: true });
    removeSandboxProfiles(l, { skipPaths: res.filter((r) => r.restored === "restored-backup").map((r) => r.path) });
    expect(readSandboxRecords(l)).toEqual([]);
    expect(readJson(userSettings()).sandbox).toBeUndefined();
  });
  it("control: --remove-sandbox after install-then-fix removes the profile and the record", () => {
    writeJson(userSettings(), { permissions: { allow: [] } });
    installAll();
    uninstall(l, {});
    expect(removeSandboxProfiles(l)[0]?.action).toBe("removed");
    expect(readJson(userSettings()).sandbox).toBeUndefined();
    expect(readSandboxRecords(l)).toEqual([]);
  });
});

describe("controls: other agents' file tools against ~/.claude/settings.json with a recorded profile", () => {
  const boxOf = () => ({ root, home, ws, l, cleanup: () => undefined });
  it("Codex apply_patch flipping sandbox.enabled is FW-TAMPER", () => {
    installAll();
    const p = userSettings();
    const line = readFileSync(p, "utf8").split("\n").find((x) => /"enabled": true/.test(x)) as string;
    const patch = `*** Begin Patch\n*** Update File: ${p}\n@@\n-${line}\n+${line.replace("true", "false")}\n*** End Patch`;
    const r = send(boxOf(), "codex", { hook_event_name: "PreToolUse", permission_mode: "default", tool_name: "apply_patch", tool_input: { command: patch } });
    expect(verdict("codex", r)).toBe("deny");
    expect(rules("codex", r)).toContain("FW-TAMPER");
  });
  it("Gemini replace removing the sandbox's strict allowlist is FW-TAMPER", () => {
    installAll();
    const r = send(boxOf(), "gemini", { hook_event_name: "BeforeTool", tool_name: "replace", tool_input: { file_path: userSettings(), old_string: '"strictAllowlist": true', new_string: '"strictAllowlist": false' } });
    expect(verdict("gemini", r)).toBe("deny");
    expect(rules("gemini", r)).toContain("FW-TAMPER");
  });
});
