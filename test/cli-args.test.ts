/**
 * F-a: every subcommand parses against a declared spec; --help never has side effects; usage errors
 * exit 64 and change nothing; the hook fails closed on a bad invocation. Acceptance rows A1-A12, FP1-FP3.
 */
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { COMMANDS, helpText, isReadOnlyInvocation, parseCommandLine } from "../src/cliargs.js";
import { HANDLERS, handlerKey } from "../src/climain.js";
import { enqueue } from "../src/runtime/store.js";
import { layout } from "../src/runtime/layout.js";
import { spawnCli, tempHome } from "./helpers.js";

const settingsOf = (home: string): string => join(home, ".claude", "settings.json");
const fwHome = (home: string): string => join(home, ".launchsafe-firewall");
const nothingWritten = (home: string): void => {
  expect(existsSync(settingsOf(home)), "settings file created").toBe(false);
  expect(existsSync(join(fwHome(home), "install.json")), "install record created").toBe(false);
  expect(existsSync(join(fwHome(home), "backups")), "backup created").toBe(false);
};
const preToolUse = JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s", cwd: "/tmp", tool_name: "Bash", tool_input: { command: "ls" } });

describe("parser (pure)", () => {
  it("every declared command has exactly one handler, and every handler a spec", () => {
    const keys = COMMANDS.map(handlerKey);
    expect(new Set(keys).size).toBe(keys.length);
    expect(Object.keys(HANDLERS).sort()).toEqual([...keys].sort());
  });
  it("longest path wins; --flag=value equals --flag value (FP2)", () => {
    const a = parseCommandLine(["install", "--scope=project", "--project=./x"]);
    const b = parseCommandLine(["install", "--scope", "project", "--project", "./x"]);
    expect(a.kind).toBe("ok");
    expect(a).toEqual(b);
    const q = parseCommandLine(["queue", "approve", "abc", "def"]);
    expect(q.kind === "ok" && q.spec.path.join(" ")).toBe("queue approve");
    expect(q.kind === "ok" && q.positionals).toEqual(["abc", "def"]);
  });
  it("--help wins over errors, anywhere before --", () => {
    expect(parseCommandLine(["install", "--bogus", "--help"]).kind).toBe("help");
    expect(parseCommandLine(["queue", "approve", "q1", "-h"]).kind).toBe("help");
    const after = parseCommandLine(["queue", "approve", "--", "-h"]);
    expect(after.kind === "ok" && after.positionals).toEqual(["-h"]);
  });
  it("bool flags take no value, flags are not repeated, values are required", () => {
    expect(parseCommandLine(["status", "--json=yes"])).toMatchObject({ kind: "error", message: "--json does not take a value" });
    expect(parseCommandLine(["status", "--json", "--json"])).toMatchObject({ kind: "error", message: "--json given more than once" });
    expect(parseCommandLine(["install", "--scope"])).toMatchObject({ kind: "error", message: "--scope needs a value" });
    expect(parseCommandLine(["log", "tail", "x"])).toMatchObject({ kind: "error" });
    expect(parseCommandLine(["log", "tail", "5"]).kind).toBe("ok");
  });
  it("read-only invocations are derived from the specs", () => {
    expect(isReadOnlyInvocation(["status"])).toBe(true);
    expect(isReadOnlyInvocation(["install", "--help"])).toBe(true);
    expect(isReadOnlyInvocation(["install"])).toBe(false);
    expect(isReadOnlyInvocation(["doctor"])).toBe(true);
    expect(isReadOnlyInvocation(["doctor", "--fix"])).toBe(false);
    expect(isReadOnlyInvocation(["explain", "FW-SEND"])).toBe(true);
    expect(isReadOnlyInvocation(["queue", "approve", "q1"])).toBe(false);
    expect(isReadOnlyInvocation(["queue", "show", "q1"])).toBe(true);
    expect(isReadOnlyInvocation(["policy", "init"])).toBe(false);
    expect(isReadOnlyInvocation(["frobnicate"])).toBe(false);
    expect(isReadOnlyInvocation(["copy"])).toBe(false);
  });
  it("help text is generated from the specs", () => {
    const top = helpText(null);
    for (const s of COMMANDS) if (s.hidden !== true) expect(top).toContain(`launchsafe-firewall ${s.usage.split("\n")[0]}`);
    expect(helpText(COMMANDS.find((s) => s.path[0] === "install") ?? null)).toContain("--scope user|project|local");
  });
});

describe("CLI (subprocess, temporary home)", () => {
  it("A1: install --help prints usage and writes nothing", () => {
    const r = spawnCli(["install", "--help"]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("launchsafe-firewall install");
    nothingWritten(r.home);
  });
  it("A2: install -h --scope project prints help and writes nothing", () => {
    const r = spawnCli(["install", "-h", "--scope", "project"]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("Usage:");
    nothingWritten(r.home);
    expect(existsSync(join(r.home, ".claude"))).toBe(false);
  });
  it("A3: install --hlep is a usage error", () => {
    const r = spawnCli(["install", "--hlep"]);
    expect(r.status).toBe(64);
    expect(r.stderr).toContain("unknown flag --hlep");
    nothingWritten(r.home);
  });
  it("A4: install --scope usr names the allowed values", () => {
    const r = spawnCli(["install", "--scope", "usr"]);
    expect(r.status).toBe(64);
    expect(r.stderr).toContain("--scope must be one of user, project, local");
    nothingWritten(r.home);
  });
  it("INST-002: install --scpoe user is a usage error", () => {
    const r = spawnCli(["install", "--scpoe", "user"]);
    expect(r.status).toBe(64);
    nothingWritten(r.home);
  });
  it("A5: uninstall --purge --dryrun keeps the state directory", () => {
    const home = tempHome();
    expect(spawnCli(["install", "--no-approver"], { home }).status).toBe(0);
    expect(existsSync(fwHome(home))).toBe(true);
    const r = spawnCli(["uninstall", "--purge", "--dryrun"], { home });
    expect(r.status).toBe(64);
    expect(existsSync(fwHome(home))).toBe(true);
    expect(existsSync(settingsOf(home))).toBe(true);
  });
  it("A6: uninstall --help keeps the hooks and never asks for the passphrase", () => {
    const home = tempHome();
    spawnCli(["install", "--no-approver"], { home });
    const r = spawnCli(["uninstall", "--help"], { home });
    expect(r.status).toBe(0);
    expect(r.stderr).not.toMatch(/terminal|passphrase/i);
    expect(r.stdout).not.toMatch(/Approval passphrase:/);
    const { readFileSync } = require("node:fs") as typeof import("node:fs");
    expect(readFileSync(settingsOf(home), "utf8")).toContain("LAUNCHSAFE_FIREWALL_HOOK");
  });
  it("A7: queue approve without an id", () => {
    const r = spawnCli(["queue", "approve"]);
    expect(r.status).toBe(64);
    expect(r.stderr).toContain("needs at least one id");
  });
  it("A8: queue approve abc --json", () => {
    const r = spawnCli(["queue", "approve", "abc", "--json"]);
    expect(r.status).toBe(64);
    expect(r.stderr).toContain("unknown flag --json");
  });
  it("A9: hook --bogus fails closed (exit 2)", () => {
    const r = spawnCli(["hook", "--bogus"], { input: preToolUse });
    expect(r.status).toBe(2);
  });
  it("A10: hook --agent codex is parsed and routed to the Codex adapter", () => {
    const r = spawnCli(["hook", "--agent", "codex"], { input: JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s", cwd: "/tmp", tool_name: "shell", tool_input: { command: ["ls"] } }) });
    expect(r.status).toBe(0);
    expect(r.stderr).not.toContain("malformed");
    const bad = spawnCli(["hook", "--agent", "codex"], { input: JSON.stringify({ tool_name: "Bash" }) });
    expect(bad.status).toBe(2);
    expect(bad.stderr).toContain("Codex hook event");
  });
  it("A11: an unknown command prints the top-level help on stderr, exit 64", () => {
    const r = spawnCli(["frobnicate"]);
    expect(r.status).toBe(64);
    expect(r.stderr).toContain("Usage:");
    expect(r.stdout).toBe("");
  });
  it("A12: doctor --json is read-only and exits 0 or 1", () => {
    const r = spawnCli(["doctor", "--json"]);
    expect([0, 1]).toContain(r.status);
    expect(Array.isArray(JSON.parse(r.stdout))).toBe(true);
    nothingWritten(r.home);
  });
  it("FP1: read-only commands behave as before (exit 0)", () => {
    const home = tempHome();
    const l = layout(fwHome(home));
    const item = enqueue(l, { sessionId: "s", cwd: home, tool: "Bash", input: { command: "git push" }, actionHash: "h", rules: ["FW-SEND"], reasons: ["r"], kind: "approval" });
    for (const args of [["status", "--json"], ["queue"], ["queue", "list", "--json"], ["queue", "show", item.id], ["log", "verify"], ["policy", "show"], ["approver", "status"], ["demo"], ["version"], ["--version"]]) {
      const r = spawnCli(args, { home });
      expect(r.status, `${args.join(" ")}: ${r.stderr}`).toBe(0);
    }
    expect(readdirSync(fwHome(home)).includes("install.json")).toBe(false);
    // Ten CLI processes in a row: the default 30 s timeout made this flaky under full-suite load.
  }, 120_000);
  it("FP3: check and explain read a JSON action on stdin (old form)", () => {
    const input = JSON.stringify({ tool: "Bash", input: { command: "git status" } });
    const a = spawnCli(["check"], { input });
    const b = spawnCli(["explain"], { input });
    expect(a.status).toBe(0);
    expect(JSON.parse(a.stdout).verdict).toBe("allow");
    expect(JSON.parse(b.stdout)).toEqual(JSON.parse(a.stdout));
  });
});
