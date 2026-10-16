/**
 * Policy schema version 3 (v0.3): the v0.3 keys move from "accepted under version 2"
 * to their own schema version. Version 2 files keep loading with the same meaning, `policy migrate`
 * rewrites one losslessly (backup first), version 3 files are validated strictly, a project file only
 * tightens whichever version each layer declares, and a file newer than the firewall fails safe.
 */
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { defaultConfig, mergeTighten, mergeTrusted, migrate, OLDEST_POLICY_VERSION, planMigration, POLICY_VERSION, PolicyError, validatePolicy } from "../src/policy.js";
import { loadPolicy } from "../src/runtime/config.js";
import { layout, PROJECT_POLICY_FILE, type Layout } from "../src/runtime/layout.js";
import { runHook } from "../src/hook/claude.js";
import { resolvePolicy } from "../src/sdk/guard.js";
import { main } from "../src/climain.js";
import { serverPolicy } from "../src/engine/mcp.js";
import { spawnCli, tempHome, testRoot } from "./helpers.js";

type Raw = Record<string, unknown>;

/** A user policy that sets every key family, the v0.3 ones included, mostly in the loosening direction. */
const RICH_USER: Raw = {
  version: 2,
  $schema: "https://launchsafe.com/schemas/firewall-policy.json",
  fetchAllowHosts: ["registry.npmjs.org", "=github.com"],
  sendAllowHosts: ["api.example.com"],
  denyHosts: ["collect.example"],
  dataAllowHosts: { credential: ["api.example.com"], card: [] },
  mcpServers: { docs: { results: "trusted", privateData: false, readTools: ["search"] }, "corp-*": { results: "untrusted", privateData: true, blockedTools: ["delete_repo"] } },
  mcpDefault: { results: "untrusted", privateData: true },
  untrustedPaths: ["/tmp/downloads"],
  protectedPaths: [".launchsafe-firewall.json", "infra/"],
  secretPaths: ["secrets/"],
  trustedReadRoots: ["/usr/include"],
  untrustedWorkspace: false,
  redactSecretsInOutput: true,
  allowTestValues: true,
  allowInstructionWritesWhenTrusted: true,
  unattended: false,
  unattendedHours: [{ from: "22:00", to: "07:00" }],
  unattendedPermissionModes: ["dontAsk"],
  userOutputTools: ["SendFancyFile"],
  notUserOutputTools: ["Upload"],
  provenance: { trustSelfAuthored: true, carryUntrustedWrites: true, maxHashBytes: 1048576 },
  agentScan: { enabled: true, taintOn: "critical", userScope: true },
  mcpPinning: { enabled: true, newToolGraceHours: 48, taintOnChange: false },
  canaries: { enabled: true, tripOnRecursive: false, offerAtInstall: false, homeDecoys: true },
  notifications: { enabled: true, on: ["queued", "canary"], onlyWhenUnattended: true, minIntervalSec: 600 },
  taskScope: { mode: "log", unattendedIntents: false },
  packageIntel: { malicious: "approve", typosquat: "off", lockfiles: false, maxSnapshotAgeDays: 30 },
  sandbox: { protectInstalledProfile: false, strictAllowlist: false, safeExcludedCommands: ["watchman *"] },
  persistence: { trustedContentChecks: false, holdWhenUntrusted: ["git-hook"] },
  budgets: { enabled: true, untrusted: { bytesPerHost: 4096, mcpCalls10m: 50 }, trusted: { bytesTotal: 99999999 }, loop: { sameAction10m: 12 }, exemptHosts: ["mirror.example.com"] },
  vault: { enabled: true, confirmDefault: { credential: "never", card: "always" }, fileFallback: true, approveKinds: ["card", "iban"], approveWhenUntrusted: false, shellRewrite: "auto", ticketSeconds: 90, listInContext: true },
  gateway: { enabled: true, mode: "hook", askVia: "elicitation", toolChanges: "taint", responses: { stripHidden: false, withhold: "never", annotate: false, maxScanBytes: 2097152, oversize: "deliver" }, sampling: "allow", unknownMethods: "allow", httpSessionIdleMinutes: 15, clients: { "claude-desktop": { workspaceRoots: ["/Users/someone/work"] } } },
  emailGuard: { enabled: true, readPath: "log", mailbox: "enforce", servers: ["corpmail"], pollSeconds: 60, authservIds: ["mx.example.com"], quarantineOn: ["tag_chars", "hidden_instruction"] },
  phone: { enabled: true, itemTtlMinutes: 120, useWithinMinutes: 240, clockSkewMinutes: 20, requireUserVerification: true, approvable: ["approval"], excludeRules: ["FW-TAMPER"], holdSeconds: 60, relayOrigin: "https://relay.example.com" },
};

/** A project file that tries to loosen every key family it can name. */
const LOOSENING_PROJECT: Raw = {
  version: 2,
  fetchAllowHosts: ["evil.example"],
  sendAllowHosts: ["evil.example"],
  dataAllowHosts: { credential: ["evil.example"] },
  trustedReadRoots: ["/"],
  mcpServers: { docs: { results: "trusted", privateData: false, readTools: ["everything"] } },
  mcpDefault: { results: "trusted", privateData: false, readTools: ["x"] },
  userOutputTools: ["Exfil"],
  untrustedWorkspace: false,
  redactSecretsInOutput: false,
  allowTestValues: true,
  allowInstructionWritesWhenTrusted: true,
  provenance: { trustSelfAuthored: true, carryUntrustedWrites: false, maxHashBytes: 64 * 1024 * 1024 },
  agentScan: { enabled: false, taintOn: "never", userScope: false },
  mcpPinning: { enabled: false, newToolGraceHours: 720, taintOnChange: false },
  canaries: { enabled: false, tripOnRecursive: false, offerAtInstall: true, homeDecoys: true },
  notifications: { enabled: false, onlyWhenUnattended: false, minIntervalSec: 86400 },
  taskScope: { mode: "off", unattendedIntents: false },
  packageIntel: { malicious: "off", typosquat: "off", lockfiles: false, maxSnapshotAgeDays: 3650 },
  sandbox: { protectInstalledProfile: false, strictAllowlist: false, safeExcludedCommands: ["curl *"] },
  persistence: { trustedContentChecks: false, holdWhenUntrusted: [] },
  budgets: { enabled: false, untrusted: { bytesPerHost: 1073741824 }, exemptHosts: ["evil.example"] },
  vault: { enabled: false, fileFallback: true, confirmDefault: { card: "never" }, approveKinds: [], approveWhenUntrusted: false, ticketSeconds: 120 },
  gateway: { enabled: false, mode: "hook", askVia: "elicitation", toolChanges: "taint", sampling: "allow", unknownMethods: "allow", httpSessionIdleMinutes: 5, responses: { stripHidden: false, withhold: "never", annotate: false, maxScanBytes: 1024, oversize: "deliver" }, clients: { x: { workspaceRoots: ["/"] } } },
  emailGuard: { enabled: false, readPath: "off", mailbox: "off", pollSeconds: 5, authservIds: ["evil.example"] },
  phone: { enabled: true, itemTtlMinutes: 720, useWithinMinutes: 1440, clockSkewMinutes: 30, holdSeconds: 600, relayOrigin: "https://evil.example" },
};

/** A project file that tightens every key family. */
const TIGHTENING_PROJECT: Raw = {
  version: 2,
  denyHosts: ["more.example"],
  protectedPaths: ["deploy/"],
  secretPaths: ["keys/"],
  untrustedPaths: ["vendor/"],
  untrustedWorkspace: true,
  redactSecretsInOutput: true,
  unattended: true,
  allowTestValues: false,
  allowInstructionWritesWhenTrusted: false,
  notUserOutputTools: ["Share"],
  mcpServers: { docs: { results: "untrusted", privateData: true, blockedTools: ["write"] } },
  provenance: { trustSelfAuthored: false, carryUntrustedWrites: true, maxHashBytes: 1024 },
  agentScan: { enabled: true, taintOn: "high", userScope: true },
  mcpPinning: { enabled: true, newToolGraceHours: 1, taintOnChange: true },
  canaries: { enabled: true, tripOnRecursive: true },
  notifications: { enabled: true, on: ["loop"] },
  taskScope: { mode: "enforce", unattendedIntents: true },
  packageIntel: { malicious: "deny", typosquat: "approve", lockfiles: true, maxSnapshotAgeDays: 7 },
  sandbox: { protectInstalledProfile: true, strictAllowlist: true },
  persistence: { trustedContentChecks: true, holdWhenUntrusted: ["git-hook", "ci", "editor-task", "devcontainer"] },
  budgets: { enabled: true, untrusted: { bytesPerHost: 1024 }, loop: { sameAction10m: 3 } },
  vault: { fileFallback: false, confirmDefault: { credential: "always" }, approveKinds: ["card", "iban", "national_id", "personal", "credential"], approveWhenUntrusted: true, shellRewrite: "off", ticketSeconds: 10, listInContext: false },
  gateway: { mode: "full", askVia: "queue", toolChanges: "hide", sampling: "deny", httpSessionIdleMinutes: 120, responses: { stripHidden: true, withhold: "strong", annotate: true, maxScanBytes: 8388608, oversize: "withhold" } },
  emailGuard: { enabled: true, readPath: "enforce", servers: ["projmail"], quarantineOn: ["auth_fail_instruction"] },
  phone: { enabled: false, itemTtlMinutes: 5, useWithinMinutes: 10, clockSkewMinutes: 1, holdSeconds: 0, approvable: [], excludeRules: ["FW-SEND"] },
};

const as = (doc: Raw, version: number): Raw => ({ ...doc, version });

interface Fixture {
  home: string;
  l: Layout;
  ws: string;
  managed: string;
}

function fixture(): Fixture {
  const home = tempHome("policy3-");
  const l = layout(join(home, ".launchsafe-firewall"));
  mkdirSync(l.home, { recursive: true });
  const ws = join(home, "ws");
  mkdirSync(ws, { recursive: true });
  return { home, l, ws, managed: join(home, "managed.json") };
}

function write(f: Fixture, files: { user?: Raw | string; managed?: Raw | string; project?: Raw | string }): void {
  const text = (v: Raw | string): string => (typeof v === "string" ? v : JSON.stringify(v, null, 2));
  if (files.user !== undefined) writeFileSync(f.l.policy, text(files.user));
  if (files.managed !== undefined) writeFileSync(f.managed, text(files.managed));
  if (files.project !== undefined) writeFileSync(join(f.ws, PROJECT_POLICY_FILE), text(files.project));
}

const load = (f: Fixture): ReturnType<typeof loadPolicy> => loadPolicy(f.l, [f.ws], "darwin", f.managed);
/** The ignored lines without the file path in front (the paths differ between fixtures). */
const reasons = (ignored: string[]): string[] => ignored.map((i) => i.replace(/^.*?\.launchsafe-firewall\.json: /, ""));

describe("schema version 3 is current", () => {
  it("POLICY_VERSION is 3, the defaults carry it, versions 1 and 2 still read", () => {
    expect(POLICY_VERSION).toBe(3);
    expect(OLDEST_POLICY_VERSION).toBe(1);
    expect(defaultConfig().version).toBe(3);
    expect(mergeTrusted(defaultConfig(), {}).version).toBe(3);
    expect(mergeTighten(defaultConfig(), {}).config.version).toBe(3);
    for (const v of [1, 2, 3]) expect(validatePolicy({ version: v }, "p")).toEqual({});
  });
  it("a missing, malformed or too-new version is refused", () => {
    expect(() => validatePolicy({}, "p")).toThrow(/missing "version" \(this release reads versions 1 to 3\)/);
    for (const v of [0, -1, 2.5, "3", null]) expect(() => validatePolicy({ version: v }, "p"), JSON.stringify(v)).toThrow(/positive integer/);
    expect(() => validatePolicy({ version: 4 }, "p")).toThrow(/policy version 4 is newer than this firewall understands \(3\); upgrade/);
  });
});

describe("version 2 files load unchanged", () => {
  it("a rich version 2 file validates to exactly what the same file says as version 3", () => {
    const v2 = validatePolicy(RICH_USER, "u");
    expect(v2).toEqual(validatePolicy(as(RICH_USER, 3), "u"));
    // The v0.3 keys are still read from a version 2 file, field by field.
    expect(v2.gateway).toEqual(RICH_USER.gateway);
    expect(v2.vault).toEqual(RICH_USER.vault);
    expect(v2.emailGuard).toEqual(RICH_USER.emailGuard);
    expect(v2.phone).toEqual(RICH_USER.phone);
    expect(v2.budgets).toEqual(RICH_USER.budgets);
  });
  it("loading a version 2 user file gives the same effective policy as version 3, with a note that a migration is available", () => {
    const f2 = fixture();
    write(f2, { user: RICH_USER });
    const f3 = fixture();
    write(f3, { user: as(RICH_USER, 3) });
    const p2 = load(f2);
    const p3 = load(f3);
    expect(p2.error).toBeUndefined();
    expect(p2.config).toEqual(p3.config);
    expect(p2.config.version).toBe(3);
    expect(p2.notes).toEqual([`${f2.l.policy}: version 2, migrated in memory; run "launchsafe-firewall policy migrate" to rewrite it as version 3 (a migration is available; a backup is kept)`]);
    expect(p3.notes).toEqual([]);
  });
  it("policy validate says a migration is available (exit 0)", () => {
    const f = fixture();
    write(f, { user: RICH_USER });
    const r = spawnCli(["policy", "validate"], { home: f.home });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/^Valid: /m);
    expect(r.stdout).toMatch(/version 2, migrated in memory; run "launchsafe-firewall policy migrate".*a migration is available/);
  });
  it("unknown keys stay errors in a version 2 file, as before", () => {
    expect(() => validatePolicy({ version: 2, gateway: { modes: "full" } }, "p")).toThrow(/"gateway.modes" is not a known setting/);
    expect(() => validatePolicy({ version: 2, bogus: true }, "p")).toThrow(/"bogus" is not a known setting/);
  });
});

describe("version 3 validates every key strictly", () => {
  it("accepts the rich file", () => {
    expect(() => validatePolicy(as(RICH_USER, 3), "p")).not.toThrow();
  });
  it("rejects an unknown top-level key", () => {
    expect(() => validatePolicy({ version: 3, gatway: {} }, "p")).toThrow(/"gatway" is not a known setting/);
    expect(() => validatePolicy({ version: 3, fetchAllowHost: [] }, "p")).toThrow(/"fetchAllowHost" is not a known setting/);
  });
  const unknownSubKeys: [string, unknown, RegExp][] = [
    ["provenance", { trustSelf: true }, /"provenance.trustSelf" is not a known setting/],
    ["dataAllowHosts", { password: [] }, /"dataAllowHosts.password" is not a data kind/],
    ["mcpServers", { x: { results: "untrusted", privateData: true, writeTools: [] } }, /"mcpServers.x.writeTools" is not a known setting/],
    ["mcpDefault", { results: "untrusted", privateData: true, extra: 1 }, /"mcpDefault.extra" is not a known setting/],
    ["agentScan", { on: true }, /"agentScan.on" is not a known setting/],
    ["mcpPinning", { grace: 1 }, /"mcpPinning.grace" is not a known setting/],
    ["canaries", { decoys: true }, /"canaries.decoys" is not a known setting/],
    ["notifications", { sound: true }, /"notifications.sound" is not a known setting/],
    ["taskScope", { strict: true }, /"taskScope.strict" is not a known setting/],
    ["packageIntel", { cooldown: 1 }, /"packageIntel.cooldown" is not a known setting/],
    ["sandbox", { network: "off" }, /"sandbox.network" is not a known setting/],
    ["persistence", { ci: true }, /"persistence.ci" is not a known setting/],
    ["budgets", { trusted: { bytesPerHost: 5 } }, /"budgets.trusted.bytesPerHost" is not a known setting/],
    ["vault", { backend: "file" }, /"vault.backend" is not a known setting/],
    ["vault", { confirmDefault: { ssh: "always" } }, /"vault.confirmDefault.ssh" is not a vault kind/],
    ["gateway", { port: 1 }, /"gateway.port" is not a known setting/],
    ["gateway", { responses: { scan: true } }, /"gateway.responses.scan" is not a known setting/],
    ["gateway", { clients: { c: { roots: [] } } }, /"gateway.clients.c" must be/],
    ["emailGuard", { imap: true }, /"emailGuard.imap" is not a known setting/],
    ["phone", { push: true }, /"phone.push" is not a known setting/],
  ];
  it.each(unknownSubKeys)("rejects an unknown setting inside %s", (key, value, message) => {
    expect(() => validatePolicy({ version: 3, [key]: value }, "p")).toThrow(message);
  });
  const badValues: [string, unknown][] = [
    ["gateway", { mode: "proxy" }],
    ["gateway", { responses: { maxScanBytes: 1 } }],
    ["vault", { ticketSeconds: 1 }],
    ["emailGuard", { readPath: "strict" }],
    ["phone", { requireUserVerification: false }],
    ["phone", { relayOrigin: "http://relay.example.com" }],
    ["budgets", { untrusted: { bytesPerHost: 0 } }],
    ["notifications", { on: ["everything"] }],
    ["unattendedHours", [{ from: "25:00", to: "07:00" }]],
  ];
  it.each(badValues)("rejects a bad value for %s", (key, value) => {
    expect(() => validatePolicy({ version: 3, [key]: value }, "p")).toThrow(PolicyError);
  });
  it("reports every problem at once", () => {
    try {
      validatePolicy({ version: 3, nope: 1, vault: { nope: 1 }, phone: { nope: 1 } }, "p");
      expect.unreachable();
    } catch (e) {
      expect((e as PolicyError).problems).toHaveLength(3);
    }
  });
});

describe("policy migrate: lossless, backup first", () => {
  it("the 2 -> 3 step keeps every key, value and key order; only the number changes", () => {
    const next = migrate(RICH_USER, "u");
    expect(next).toEqual(as(RICH_USER, 3));
    expect(Object.keys(next)).toEqual(Object.keys(RICH_USER));
    expect(JSON.stringify(next)).toBe(JSON.stringify(RICH_USER).replace('"version":2', '"version":3'));
  });
  it("planMigration: v2 and v1 files rewrite to v3 with the same settings; v3 needs nothing; bad files are refused", () => {
    const plan = planMigration(RICH_USER, "u");
    expect(plan?.from).toBe(2);
    expect(plan?.doc).toEqual(as(RICH_USER, 3));
    const { vault: _v, gateway: _g, emailGuard: _e, phone: _p, ...v02 } = RICH_USER;
    const v1 = planMigration(as(v02, 1), "u");
    expect(v1?.from).toBe(1);
    expect(v1?.doc).toEqual(as(v02, 3));
    expect(planMigration(as(RICH_USER, 3), "u")).toBeNull();
    expect(() => planMigration({ version: 2, bogus: 1 }, "u")).toThrow(PolicyError);
    expect(() => planMigration({ version: 4 }, "u")).toThrow(/newer than this firewall/);
  });
  const migrateCli = (l: Layout): Promise<{ status: number; lines: string[] }> => {
    const lines: string[] = [];
    return main(["policy", "migrate"], l, { write: (_fd, s) => void lines.push(s), humanAtKeyboard: () => Promise.resolve(true) }).then((status) => ({ status, lines }));
  };
  it("round-trip on the rich file: backup holds the original bytes, the rewrite loads to the same policy", async () => {
    const f = fixture();
    write(f, { user: RICH_USER, managed: as(TIGHTENING_PROJECT, 2), project: as(TIGHTENING_PROJECT, 3) });
    const original = readFileSync(f.l.policy, "utf8");
    const before = load(f);
    const r = await migrateCli(f.l);
    expect(r.status).toBe(0);
    expect(r.lines.join("")).toMatch(/as policy version 3 \(from version 2; same settings\)\. The original is in .*policy\.json\.v2\.bak/);
    expect(readFileSync(`${f.l.policy}.v2.bak`, "utf8")).toBe(original);
    const rewritten = JSON.parse(readFileSync(f.l.policy, "utf8")) as Raw;
    expect(rewritten).toEqual(as(RICH_USER, 3));
    expect(Object.keys(rewritten)).toEqual(Object.keys(RICH_USER));
    const after = load(f);
    expect(after.config).toEqual(before.config);
    expect(after.ignored).toEqual(before.ignored);
    expect(after.error).toBeUndefined();
    // The managed file is still version 2 and is noted (but not rewritten: it is not the user's file).
    // FM1: the user's trusted "docs" entry is under the administrator's untrusted one, and says so.
    expect(after.notes).toEqual([
      `${f.managed}: version 2, migrated in memory; a migration is available: set "version": 3, nothing else changes (a firewall older than v0.3 then skips the file with a policy error)`,
      `${f.l.policy}: mcpServers.docs: the managed policy covers this server; the user policy's loosening (trusted results, privateData false or readTools) is not applied`,
    ]);
    // Running it again changes nothing and keeps no second backup.
    const again = await migrateCli(f.l);
    expect(again.status).toBe(0);
    expect(again.lines.join("")).toMatch(/already version 3/);
    expect(readdirSync(f.l.home).filter((n) => n.includes(".bak"))).toEqual(["policy.json.v2.bak"]);
  });
  it("a version 1 file migrates too; an earlier backup is never replaced", async () => {
    const f = fixture();
    write(f, { user: { version: 1, denyHosts: ["evil.example.com"] } });
    writeFileSync(`${f.l.policy}.v1.bak`, "an earlier backup");
    const r = await migrateCli(f.l);
    expect(r.status).toBe(0);
    expect(readFileSync(`${f.l.policy}.v1.bak`, "utf8")).toBe("an earlier backup");
    expect(JSON.parse(readFileSync(`${f.l.policy}.v1.2.bak`, "utf8"))).toEqual({ version: 1, denyHosts: ["evil.example.com"] });
    expect(JSON.parse(readFileSync(f.l.policy, "utf8"))).toEqual({ version: 3, denyHosts: ["evil.example.com"] });
  });
  it.each([
    ["an invalid file", JSON.stringify({ version: 2, gateway: { mode: "proxy" } }), /Not migrated: .*gateway\.mode/],
    ["a newer file", JSON.stringify({ version: 4, gateway: {} }), /Not migrated: .*newer than this firewall understands/],
    ["broken JSON", "{ nope", /Not migrated: .*not valid JSON/],
  ])("%s is refused and nothing is written", async (_name, text, message) => {
    const f = fixture();
    write(f, { user: text });
    const r = await migrateCli(f.l);
    expect(r.status).toBe(1);
    expect(r.lines.join("")).toMatch(message);
    expect(readFileSync(f.l.policy, "utf8")).toBe(text);
    expect(readdirSync(f.l.home).filter((n) => n.includes(".bak"))).toEqual([]);
  });
  it("stays person-only: the binary refuses without a terminal and leaves the file alone", () => {
    const f = fixture();
    write(f, { user: RICH_USER });
    const original = readFileSync(f.l.policy, "utf8");
    const r = spawnCli(["policy", "migrate"], { home: f.home });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/interactive terminal/);
    expect(readFileSync(f.l.policy, "utf8")).toBe(original);
    expect(existsSync(`${f.l.policy}.v2.bak`)).toBe(false);
  });
});

describe("a project file only tightens, whatever version each layer declares", () => {
  const user = mergeTrusted(defaultConfig(), validatePolicy(RICH_USER, "u"));
  it.each([2, 3])("a loosening version %i project changes nothing and every loosening is reported the same way", (pv) => {
    const { config, ignored } = mergeTighten(user, validatePolicy(as(LOOSENING_PROJECT, pv), "proj"));
    const ref = mergeTighten(user, validatePolicy(as(LOOSENING_PROJECT, 2), "proj"));
    expect(config).toEqual(ref.config);
    expect(ignored).toEqual(ref.ignored);
    // Nothing the project tried to open is open (spot checks across the families).
    expect(config.sendAllowHosts).toEqual(user.sendAllowHosts);
    expect(config.fetchAllowHosts).toEqual(user.fetchAllowHosts);
    expect(config.mcpDefault.results).toBe("untrusted");
    expect(config.gateway?.enabled).toBe(true);
    expect(config.vault?.enabled).toBe(true);
    expect(config.vault?.ticketSeconds).toBe(90);
    expect(config.emailGuard?.enabled).toBe(true);
    expect(config.phone?.relayOrigin).toBe("https://relay.example.com");
    expect(config.budgets.exemptHosts).toEqual(["mirror.example.com"]);
    for (const family of ["fetchAllowHosts", "sendAllowHosts", "dataAllowHosts", "userOutputTools", "provenance.trustSelfAuthored", "agentScan.enabled", "mcpPinning", "canaries", "notifications", "taskScope.mode", "packageIntel", "sandbox", "persistence", "budgets", "vault.enabled", "gateway.enabled", "emailGuard.enabled", "phone.relayOrigin"]) {
      expect(ignored.some((i) => i.includes(family)), family).toBe(true);
    }
  });
  it.each([2, 3])("a tightening version %i project tightens exactly as the other version does", (pv) => {
    const a = mergeTighten(user, validatePolicy(as(TIGHTENING_PROJECT, pv), "proj"));
    const b = mergeTighten(user, validatePolicy(as(TIGHTENING_PROJECT, pv === 2 ? 3 : 2), "proj"));
    expect(a).toEqual(b);
    expect(a.config.gateway?.mode).toBe("full");
    expect(a.config.vault?.ticketSeconds).toBe(10);
    expect(a.config.phone?.enabled).toBe(false);
    expect(a.config.emailGuard?.readPath).toBe("enforce");
    expect(a.config.taskScope.mode).toBe("enforce");
  });
  it.each([
    [2, 2],
    [2, 3],
    [3, 2],
    [3, 3],
  ])("loaded from disk: user version %i, project version %i give the same policy and the same ignored list", (uv, pv) => {
    const f = fixture();
    write(f, { user: as(RICH_USER, uv), project: { ...LOOSENING_PROJECT, ...TIGHTENING_PROJECT, version: pv } });
    const ref = fixture();
    write(ref, { user: as(RICH_USER, 3), project: { ...LOOSENING_PROJECT, ...TIGHTENING_PROJECT, version: 3 } });
    const p = load(f);
    const r = load(ref);
    expect(p.error).toBeUndefined();
    expect(p.config).toEqual(r.config);
    expect(reasons(p.ignored)).toEqual(reasons(r.ignored));
    expect(p.notes).toHaveLength((uv === 2 ? 1 : 0) + (pv === 2 ? 1 : 0));
  });
});

describe("mixed-version user, managed and project layers", () => {
  const managedDoc: Raw = { version: 3, denyHosts: ["blocked.example"], gateway: { unknownMethods: "deny", sampling: "deny" }, vault: { fileFallback: false }, phone: { relayOrigin: "https://approve.launchsafe.com" } };
  const projectDoc: Raw = { version: 2, denyHosts: ["proj.example"], gateway: { mode: "full" }, vault: { ticketSeconds: 10 } };
  const all = [2, 3] as const;
  const combos = all.flatMap((u) => all.flatMap((m) => all.map((p) => [u, m, p] as const)));
  it.each(combos)("user v%i, managed v%i, project v%i: one effective policy, the administrator wins, the project only tightens", (uv, mv, pv) => {
    const f = fixture();
    write(f, { user: as(RICH_USER, uv), managed: as(managedDoc, mv), project: as(projectDoc, pv) });
    const ref = fixture();
    write(ref, { user: as(RICH_USER, 3), managed: as(managedDoc, 3), project: as(projectDoc, 3) });
    const p = load(f);
    expect(p.error).toBeUndefined();
    expect(p.config).toEqual(load(ref).config);
    expect(p.config.version).toBe(3);
    expect(p.config.gateway?.unknownMethods).toBe("deny");
    expect(p.config.gateway?.sampling).toBe("deny");
    expect(p.config.gateway?.mode).toBe("full");
    expect(p.config.vault?.fileFallback).toBe(false);
    expect(p.config.vault?.ticketSeconds).toBe(10);
    expect(p.config.phone?.relayOrigin).toBe("https://approve.launchsafe.com");
    // A managed list replaces the user's (lists replace); the project adds to it.
    expect(p.config.denyHosts).toEqual(["blocked.example", "proj.example"]);
    expect(p.sources).toEqual(["defaults", f.l.policy, f.managed, join(f.ws, PROJECT_POLICY_FILE)]);
    expect(p.notes).toHaveLength([uv, mv, pv].filter((v) => v === 2).length);
    if (uv === 2) expect(p.notes.join("\n")).toMatch(/policy migrate/);
  });
});

describe("a file newer than the firewall fails safe (how an older firewall treats a version 3 file)", () => {
  // Every release since v0.1 refuses a version above its own in migrate(); v0.2 (POLICY_VERSION 2)
  // reading a version 3 file is therefore exactly this firewall reading a version 4 file.
  const future = (doc: Raw): Raw => ({ ...doc, version: POLICY_VERSION + 1 });
  it("a newer user file is skipped: strict defaults for what it set, the managed and project layers still apply, and a policy error", () => {
    const f = fixture();
    write(f, { user: future(RICH_USER), managed: { version: 2, denyHosts: ["blocked.example"] }, project: { version: 3, untrustedWorkspace: true } });
    const p = load(f);
    expect(p.error).toMatch(/policy version 4 is newer than this firewall understands \(3\); upgrade/);
    expect(p.config.sendAllowHosts).toEqual([]);
    expect(p.config.fetchAllowHosts).toEqual(defaultConfig().fetchAllowHosts);
    expect(p.config.gateway).toBeUndefined();
    expect(p.config.vault).toBeUndefined();
    expect(p.config.denyHosts).toContain("blocked.example");
    expect(p.config.untrustedWorkspace).toBe(true);
    expect(p.sources).not.toContain(f.l.policy);
  });
  it("a newer managed file also drops the user's layer", () => {
    const f = fixture();
    write(f, { user: as(RICH_USER, 2), managed: future({ denyHosts: ["x.example"] }) });
    const p = load(f);
    expect(p.error).toMatch(/newer than this firewall/);
    expect(p.config.sendAllowHosts).toEqual([]);
    expect(p.sources).toEqual(["defaults"]);
  });
  it("a newer project file is not applied, and the error still sends risky actions to a person", () => {
    const f = fixture();
    write(f, { user: as(RICH_USER, 3), project: future({ denyHosts: ["proj.example"] }) });
    const p = load(f);
    expect(p.error).toMatch(/newer than this firewall/);
    expect(p.config.denyHosts).not.toContain("proj.example");
  });
  it("end to end: with a newer user file a workspace write that is normally allowed asks (FW-POLICY-ERROR)", () => {
    const f = fixture();
    const hook = (): string => runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: "fs", cwd: f.ws, permission_mode: "default", tool_name: "Write", tool_input: { file_path: join(f.ws, "notes.md"), content: "# notes\n" } }), { env: { CLAUDE_PROJECT_DIR: f.ws }, layout: f.l, home: f.home, detectNonInteractive: () => false, notifyDeps: { spawn: () => undefined } }).stdout;
    expect(hook()).not.toMatch(/"ask"/);
    write(f, { user: future({}) });
    const out = hook();
    expect(out).toMatch(/"ask"/);
    expect(out).toMatch(/policy/i);
  });
});

describe("the library's policy option", () => {
  it("a full config built under schema 2 still counts as a full config and reads as version 3", () => {
    const v2Full = { ...defaultConfig(), version: 2 } as unknown as Parameters<typeof resolvePolicy>[0];
    const r = resolvePolicy(v2Full);
    expect(r).toEqual(defaultConfig());
    expect(r.version).toBe(3);
    expect(resolvePolicy({ vault: { ticketSeconds: 10 } }).vault?.ticketSeconds).toBe(10);
  });
});

describe("FB2: a project's mcpServers entry never hides an earlier layer's pattern entry", () => {
  const user = (servers: Raw): ReturnType<typeof defaultConfig> => mergeTrusted(defaultConfig(), validatePolicy({ version: 3, mcpServers: servers }, "u"));
  const project = (servers: Raw) => validatePolicy({ version: 3, mcpServers: servers }, "p");
  const CORP = { "corp-*": { results: "untrusted", privateData: true, blockedTools: ["delete_repo"], sendTools: ["export_*"], destructiveTools: ["purge_*"] } };

  it("an exact project name keeps the user's pattern lists (blocked, send, destructive) and adds its own", () => {
    const cfg = mergeTighten(user(CORP), project({ "corp-mail": { results: "untrusted", privateData: true, blockedTools: ["send_all"] } })).config;
    const p = serverPolicy("corp-mail", cfg);
    expect(p.blockedTools).toEqual(expect.arrayContaining(["delete_repo", "send_all"]));
    expect(p.sendTools).toContain("export_*");
    expect(p.destructiveTools).toContain("purge_*");
    // Other servers under the pattern are unchanged.
    expect(serverPolicy("corp-chat", cfg).blockedTools).toEqual(["delete_repo"]);
  });

  it("an exact project name under a trusted user pattern is untrusted and private, and a repository server stays untrusted", () => {
    const cfg = mergeTighten(user({ "docs-*": { results: "trusted", privateData: false, readTools: ["search"] } }), project({ "docs-x": { results: "trusted", privateData: false } })).config;
    expect(serverPolicy("docs-x", cfg)).toMatchObject({ results: "untrusted", privateData: true, readTools: ["search"] });
    expect(serverPolicy("docs-x", cfg, "project").results).toBe("untrusted");
    expect(serverPolicy("docs-y", cfg).results).toBe("trusted");
  });

  it("a project pattern tightens the user's exact entries it covers", () => {
    const cfg = mergeTighten(user({ "corp-mail": { results: "trusted", privateData: false } }), project({ "corp-*": { results: "untrusted", privateData: true, blockedTools: ["delete_repo"] } })).config;
    expect(serverPolicy("corp-mail", cfg)).toMatchObject({ results: "untrusted", privateData: true, blockedTools: ["delete_repo"] });
    expect(serverPolicy("other", cfg).blockedTools).toBeUndefined();
  });

  it("a project pattern tightens an earlier user pattern that matches the same servers (the earlier one is found first)", () => {
    const cfg = mergeTighten(user({ "corp-*": { results: "trusted", privateData: false }, "docs-*": { results: "trusted", privateData: false } }), project({ "corp-mail*": { results: "untrusted", privateData: true, blockedTools: ["x"] } })).config;
    expect(serverPolicy("corp-mail-eu", cfg)).toMatchObject({ results: "untrusted", blockedTools: ["x"] });
    expect(serverPolicy("docs-a", cfg).results).toBe("trusted");
  });

  it("a managed pattern merged under the user's layer is kept when the project names the server", () => {
    const root = mkdtempSync(join(testRoot(), "fb2-"));
    const l = layout(join(root, "fw"));
    mkdirSync(l.home, { recursive: true });
    const managed = join(root, "managed.json");
    writeFileSync(managed, JSON.stringify({ version: 3, mcpServers: CORP }));
    const ws = join(root, "ws");
    mkdirSync(ws, { recursive: true });
    writeFileSync(join(ws, PROJECT_POLICY_FILE), JSON.stringify({ version: 3, mcpServers: { "corp-mail": { results: "untrusted", privateData: true } } }));
    const p = loadPolicy(l, [ws], "darwin", managed);
    expect(p.error).toBeUndefined();
    expect(serverPolicy("corp-mail", p.config).blockedTools).toContain("delete_repo");
  });
});
