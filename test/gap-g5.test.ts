/**
 * G5: the approver key is pinned in the hook command. Install pins it when one is set; setting or
 * rotating the passphrase afterwards re-pins every installed hook, so the hook never falls back to the
 * key on disk. Everything runs in a temporary home.
 */
import { existsSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { initApprover, rotateApprover } from "../src/runtime/approver.js";
import { HOOK_EVENTS } from "../src/engine/settings.js";
import { hookCommand, install, pinnedApprover, readRecords, repinApprover, withApproverPin } from "../src/runtime/install.js";
import { layout } from "../src/runtime/layout.js";
import { spawnCli, tempHome } from "./helpers.js";

const fw = (home: string): string => join(home, ".launchsafe-firewall");
const settings = (home: string): string => join(home, ".claude", "settings.json");
type Check = { name: string; status: string; detail: string };
const approval = (home: string): Check | undefined => (JSON.parse(spawnCli(["doctor", "--json", "--project", home], { home }).stdout) as Check[]).find((c) => c.name === "approval passphrase");
const commands = (home: string): string[] => {
  const s = JSON.parse(readFileSync(settings(home), "utf8")) as { hooks: Record<string, { hooks: { command: string }[] }[]> };
  return Object.values(s.hooks).flatMap((g) => g.flatMap((x) => x.hooks.map((h) => h.command)));
};
const PASS = "correct horse battery";

describe("withApproverPin", () => {
  const base = "LAUNCHSAFE_FIREWALL_HOOK=1 '/usr/bin/node' '/opt/fw/dist/cli.js' hook || exit 2";
  it("pins, replaces and removes a pin, keeping the rest of the command", () => {
    const pinned = withApproverPin(base, "AAA=");
    expect(pinned).toBe("LAUNCHSAFE_FIREWALL_HOOK=1 LAUNCHSAFE_FIREWALL_APPROVER='AAA=' '/usr/bin/node' '/opt/fw/dist/cli.js' hook || exit 2");
    expect(pinnedApprover(pinned)).toBe("AAA=");
    expect(withApproverPin(pinned, "BBB=")).toBe(withApproverPin(base, "BBB="));
    expect(withApproverPin(pinned, null)).toBe(base);
    expect(withApproverPin(pinned, "AAA=")).toBe(pinned);
  });
  it("keeps a custom data directory (with a quote in it) in front of the pin", () => {
    const withHome = "LAUNCHSAFE_FIREWALL_HOOK=1 LAUNCHSAFE_FIREWALL_HOME='/tmp/it'\\''s' '/usr/bin/node' '/x/cli.js' hook || exit 2";
    const pinned = withApproverPin(withHome, "AAA=");
    expect(pinned).toContain("LAUNCHSAFE_FIREWALL_HOME='/tmp/it'\\''s' LAUNCHSAFE_FIREWALL_APPROVER='AAA=' '/usr/bin/node'");
  });
  it("leaves a command that is not the firewall's alone", () => expect(withApproverPin("echo hi", "AAA=")).toBe("echo hi"));
});

describe("install pins the key", () => {
  it("when a passphrase is set before install", () => {
    const home = tempHome();
    initApprover(layout(fw(home)), PASS);
    const r = spawnCli(["install"], { home, input: "" });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/The hook pins your approval key/);
    expect(approval(home)?.status).toBe("ok");
  });
  it("and says nothing about a pin when there is no passphrase", () => {
    const home = tempHome();
    const r = spawnCli(["install", "--no-approver"], { home });
    expect(r.stdout).not.toMatch(/pins your approval key/);
    expect(approval(home)?.status).toBe("warn");
  });
});

describe("setting or rotating the passphrase after install re-pins the hook (the 9 Oct state)", () => {
  it("init after an unpinned install: doctor goes from 'not pinned' to ok", () => {
    const home = tempHome();
    expect(spawnCli(["install", "--no-approver"], { home }).status).toBe(0);
    const l = layout(fw(home));
    initApprover(l, PASS);
    expect(approval(home)?.detail).toMatch(/set, but not pinned/);
    const r = repinApprover(l);
    expect(r.updated).toEqual([settings(home)]);
    expect(r.skipped).toEqual([]);
    expect(commands(home).length).toBeGreaterThan(0);
    for (const c of commands(home)) expect(pinnedApprover(c)).not.toBeNull();
    expect(approval(home)?.status).toBe("ok");
  });
  it("rotate moves the pin to the new key", () => {
    const home = tempHome();
    const l = layout(fw(home));
    initApprover(l, PASS);
    spawnCli(["install"], { home, input: "" });
    const old = pinnedApprover(commands(home)[0] as string);
    const next = rotateApprover(l, PASS, "another long passphrase");
    expect(approval(home)?.status).toBe("fail");
    repinApprover(l);
    expect(pinnedApprover(commands(home)[0] as string)).toBe(next);
    expect(next).not.toBe(old);
    expect(approval(home)?.status).toBe("ok");
  });
  it("is idempotent and changes nothing else in the file", () => {
    const home = tempHome();
    spawnCli(["install", "--no-approver"], { home });
    const file = JSON.parse(readFileSync(settings(home), "utf8")) as Record<string, unknown>;
    file.theme = "dark";
    (file.hooks as Record<string, unknown[]>).PreToolUse?.push({ matcher: "Bash", hooks: [{ type: "command", command: "echo mine" }] });
    writeFileSync(settings(home), JSON.stringify(file, null, 2));
    const l = layout(fw(home));
    initApprover(l, PASS);
    expect(repinApprover(l).updated).toHaveLength(1);
    expect(repinApprover(l).updated).toEqual([]);
    const after = JSON.parse(readFileSync(settings(home), "utf8")) as Record<string, unknown>;
    expect(after.theme).toBe("dark");
    expect(JSON.stringify(after)).toContain("echo mine");
    expect(commands(home).filter((c) => c === "echo mine")).toHaveLength(1);
    expect(commands(home).filter((c) => pinnedApprover(c) !== null)).toHaveLength(HOOK_EVENTS.length);
  });
  it("keeps a backup of the file it changed", () => {
    const home = tempHome();
    spawnCli(["install", "--no-approver"], { home });
    const before = readFileSync(settings(home), "utf8");
    const l = layout(fw(home));
    initApprover(l, PASS);
    repinApprover(l);
    const backups = readdirSync(l.backups).filter((f) => f.endsWith("-repin-settings.json"));
    expect(backups).toHaveLength(1);
    expect((JSON.parse(readFileSync(join(l.backups, backups[0] as string), "utf8")) as { content: string }).content).toBe(before);
  });
  it("reports a file that is gone or unreadable instead of failing", () => {
    const home = tempHome();
    spawnCli(["install", "--no-approver"], { home });
    const l = layout(fw(home));
    initApprover(l, PASS);
    rmSync(settings(home));
    const r = repinApprover(l);
    expect(r.updated).toEqual([]);
    expect(r.skipped).toHaveLength(1);
    expect(existsSync(settings(home))).toBe(false);
    writeFileSync(settings(home), "{ not json");
    expect(repinApprover(l).skipped).toHaveLength(1);
  });
  it("does nothing when no install is recorded", () => {
    const home = tempHome();
    const l = layout(fw(home));
    initApprover(l, PASS);
    expect(readRecords(l)).toEqual([]);
    expect(repinApprover(l)).toEqual({ updated: [], skipped: [] });
  });
});

describe("hookCommand and the install result", () => {
  it("install reports whether the command it wrote is pinned", () => {
    const home = tempHome();
    const l = layout(fw(home));
    expect(install(l, "user", home, "t", { home }).pinned).toBe(false);
    initApprover(l, PASS);
    expect(pinnedApprover(hookCommand(l))).not.toBeNull();
    expect(install(l, "user", home, "t", { home }).pinned).toBe(true);
  });
});
