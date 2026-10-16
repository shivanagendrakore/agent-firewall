/**
 * Catalogue section 12 (INST): commands a person runs, through the built CLI in a temporary home.
 * Rows that need a real terminal, or a later item, say so.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, type TestContext } from "vitest";
import { INST } from "../src/catalogue-scenarios.js";
import { BUILT_ITEMS } from "../src/catalogue.js";
import { initApprover } from "../src/runtime/approver.js";
import { layout } from "../src/runtime/layout.js";
import { skipWithoutExec, spawnCli, tempHome } from "./helpers.js";

const fw = (home: string): string => join(home, ".launchsafe-firewall");
const settings = (home: string): string => join(home, ".claude", "settings.json");
type Check = { name: string; status: string; detail: string };
const doctorJson = (home: string, project = home): Check[] => JSON.parse(spawnCli(["doctor", "--json", "--project", project], { home }).stdout) as Check[];

const automated: Record<string, (ctx: TestContext) => void> = {
  "INST-001": () => {
    const r = spawnCli(["install", "--help"]);
    expect(r.status).toBe(0);
    expect(existsSync(settings(r.home))).toBe(false);
    expect(existsSync(fw(r.home))).toBe(false);
  },
  "INST-002": () => {
    const r = spawnCli(["install", "--scpoe", "user"]);
    expect(r.status).toBe(64);
    expect(existsSync(settings(r.home))).toBe(false);
  },
  "INST-004": () => {
    const home = tempHome();
    const r = spawnCli(["install"], { home, input: "" });
    expect(r.status).toBe(0);
    expect(readFileSync(settings(home), "utf8")).toContain("LAUNCHSAFE_FIREWALL_HOOK");
    expect(existsSync(join(fw(home), "keys", "approver.json"))).toBe(false);
    expect(doctorJson(home).find((c) => c.name === "approval passphrase")?.status).toBe("warn");
  },
  "INST-005": () => {
    const home = tempHome();
    expect(spawnCli(["install", "--no-approver"], { home }).status).toBe(0);
    initApprover(layout(fw(home)), "correct horse battery");
    const c = doctorJson(home).find((x) => x.name === "approval passphrase");
    expect(c?.status).toBe("warn");
    expect(c?.detail).toMatch(/set, but not pinned/);
  },
  "INST-006": () => {
    const home = tempHome();
    spawnCli(["install", "--no-approver"], { home });
    const proj = join(home, "proj");
    mkdirSync(join(proj, ".claude"), { recursive: true });
    writeFileSync(join(proj, ".claude", "settings.json"), JSON.stringify({ disableAllHooks: true }));
    const r = spawnCli(["doctor", "--json", "--project", proj], { home });
    expect(r.status).toBe(1);
    expect((JSON.parse(r.stdout) as Check[]).find((x) => x.name === "disableAllHooks")?.status).toBe("fail");
  },
  "INST-007": (ctx) => {
    // A stand-in claude that only answers --version, where doctor looks for the desktop app's copy (doctor runs it).
    skipWithoutExec(ctx);
    const home = tempHome();
    const bin = join(home, "Library", "Application Support", "Claude", "claude-code", "2.1.289", "x", "claude.app", "Contents", "MacOS");
    mkdirSync(bin, { recursive: true });
    writeFileSync(join(bin, "claude"), '#!/bin/sh\necho "2.1.289 (Claude Code)"\n', { mode: 0o755 });
    spawnCli(["install", "--no-approver"], { home });
    const r = spawnCli(["doctor", "--json"], { home, env: { PATH: "/usr/bin:/bin" } });
    const cs = JSON.parse(r.stdout) as (Check & { weight?: number; points?: number; score?: number })[];
    expect(cs.find((c) => c.name === "Claude Code")?.detail).toMatch(/^2\.1\.289/);
    for (const n of ["sandbox", "sandbox network", "sandbox escape"]) expect(cs.find((c) => c.name === n)?.points, n).toBe(0);
    expect(typeof cs.find((c) => c.name === "protection score")?.score).toBe("number");
    expect(spawnCli(["doctor"], { home, env: { PATH: "/usr/bin:/bin" } }).stdout).toMatch(/Setup score: \d+\/100/);
  },
  "INST-011": () => {
    const r = spawnCli(["install", "--managed", "--print"]);
    expect(r.status).toBe(0);
    expect(JSON.stringify(JSON.parse(r.stdout))).toContain("LAUNCHSAFE_FIREWALL_HOOK");
    expect(existsSync(settings(r.home))).toBe(false);
    expect(existsSync(join(fw(r.home), "install.json"))).toBe(false);
  },
  "INST-014": () => {
    const home = tempHome();
    const proj = join(home, "proj");
    mkdirSync(proj, { recursive: true });
    writeFileSync(join(proj, ".launchsafe-firewall.json"), JSON.stringify({ version: 2, sendAllowHosts: ["anywhere.example.com"] }));
    const r = spawnCli(["policy", "validate"], { home, cwd: proj });
    expect(r.stdout).toMatch(/Ignored: .*sendAllowHosts \(a project cannot allow destinations/);
  },
};

describe("catalogue INST (commands a person runs)", () => {
  for (const row of INST) {
    const name = `${row.id} ${row.task}`;
    const fn = automated[row.id];
    if (fn !== undefined && (row.item === undefined || BUILT_ITEMS.has(row.item))) it(name, fn);
    else if (row.coveredBy !== undefined) it.skip(`${name} (covered by ${row.coveredBy})`, () => undefined);
    else if (row.skip !== undefined) it.skip(`${name} (${row.skip})`, () => undefined);
    else it.todo(`${name} (item ${row.item ?? ""})`);
  }
});
