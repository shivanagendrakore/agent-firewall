/**
 * Gemini CLI's own sandbox (gemini -s, macOS seatbelt): the profile install writes, its record,
 * doctor's lines, and the hook's one message when the sandbox refuses it its state.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { layout, type Layout } from "../src/runtime/layout.js";
import { blockOf, expectedProfile, findGeminiBundle, HOOK_STATE_DIRS, installSeatbelt, readSeatbeltRecord, removeSeatbelt, sbString, seatbeltBlock, seatbeltChecks, seatbeltProfilePath, seatbeltRefusal, SEATBELT_PROFILE_NAME } from "../src/runtime/gemini-seatbelt.js";
import { runHook } from "../src/hook/claude.js";
import { testRoot } from "./helpers.js";

// A stand-in for Gemini CLI's bundle: a deny-by-default profile that lets node run and read, and writes nowhere.
const BASE = `(version 1)
;; stand-in for Gemini CLI's profile
(deny default)
(allow file-read*)
(allow process-exec)
(allow process-fork)
(allow sysctl-read)
(allow mach-lookup)
(allow signal (target self))
(allow file-ioctl)
(allow file-write* (literal "/dev/null"))
(deny file-write* (subpath (string-append (param "HOME_DIR") "/.gemini")))
`;

let root: string;
let home: string;
let bundle: string;
let project: string;
let l: Layout;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(testRoot(), "lsfw-seatbelt-")));
  home = join(root, "home");
  bundle = join(root, "gemini", "bundle");
  project = join(root, "proj");
  mkdirSync(join(home, ".gemini"), { recursive: true });
  mkdirSync(bundle, { recursive: true });
  mkdirSync(project, { recursive: true });
  writeFileSync(join(bundle, "sandbox-macos-permissive-open.sb"), BASE);
  writeFileSync(join(bundle, "sandbox-macos-strict-open.sb"), BASE.replace("stand-in", "strict stand-in"));
  l = layout(join(home, ".launchsafe-firewall"));
});
afterEach(() => {
  try {
    chmodSync(l.home, 0o700);
  } catch {
    // Not created.
  }
  rmSync(root, { recursive: true, force: true });
});

const env = (): NodeJS.ProcessEnv => ({ HOME: home });
const opts = (base: "permissive-open" | "strict-open" = "permissive-open") => ({ base, bundle, home, env: env(), node: process.execPath, packageDir: join(root, "pkg") });

describe("the firewall's block", () => {
  it("opens only the hook's state directories for writing", () => {
    const block = seatbeltBlock({ fwHome: "/Users/u/.launchsafe-firewall" });
    const writes = [...block.matchAll(/\(subpath "([^"]+)"\)/g)].map((m) => m[1]);
    expect(writes).toEqual(HOOK_STATE_DIRS.map((d) => `/Users/u/.launchsafe-firewall/${d}`));
    for (const never of ["policy.json", "keys", "install.json", "backups", "vault", "identity.json", "canaries.json", "relay", "gemini-seatbelt.json"]) expect(block).not.toContain(`/.launchsafe-firewall/${never}`);
    expect(block).not.toMatch(/\(subpath "\/Users\/u\/\.launchsafe-firewall"\)/);
    expect(block).not.toContain("file-read*");
  });
  it("denies hard links, after the writes it allows, so a link cannot give a protected file a writable name", () => {
    const block = seatbeltBlock({ fwHome: "/Users/u/.launchsafe-firewall" });
    expect(block).toContain("\n(deny file-link)\n");
    expect(block.indexOf("(deny file-link)")).toBeGreaterThan(block.indexOf("(allow file-write*"));
    expect(seatbeltBlock({ fwHome: "/h/.lsfw", readRoots: ["/opt/fw"] })).toContain("(deny file-link)");
  });
  it("adds reads of the data directory, the package and node for the strict profiles only", () => {
    const block = seatbeltBlock({ fwHome: "/h/.launchsafe-firewall", readRoots: ["/opt/fw", "/usr/local"] });
    expect(block).toContain('(allow file-read*\n    (subpath "/h/.launchsafe-firewall")\n    (subpath "/opt/fw")\n    (subpath "/usr/local")\n)');
  });
  it("refuses a path it cannot quote", () => {
    for (const bad of ['/a"b', "/a\\b", "/a\nb", "relative/path", "/a\u0007"]) expect(() => sbString(bad)).toThrow();
    expect(sbString("/Users/a b/ü")).toBe('"/Users/a b/ü"');
  });
});

describe("install --seatbelt", () => {
  it("writes Gemini CLI's profile unchanged plus the block, a record and the state directories", () => {
    const r = installSeatbelt(l, opts());
    expect(r).toMatchObject({ path: seatbeltProfilePath(env(), home), changed: true });
    expect(r.path).toBe(join(home, ".gemini", `sandbox-macos-${SEATBELT_PROFILE_NAME}.sb`));
    const text = readFileSync(r.path, "utf8");
    expect(text).toContain(BASE);
    expect(text.indexOf(BASE)).toBeLessThan(text.indexOf(blockOf(text) ?? "?"));
    expect(blockOf(text)).toBe(seatbeltBlock({ fwHome: realpathSync(l.home) }));
    for (const d of HOOK_STATE_DIRS) expect(statSync(join(l.home, d)).isDirectory()).toBe(true);
    expect(readSeatbeltRecord(l)).toMatchObject({ path: r.path, base: "permissive-open", baseFile: join(bundle, "sandbox-macos-permissive-open.sb") });
    expect(installSeatbelt(l, opts()).changed).toBe(false);
  });
  it("honours GEMINI_CLI_HOME, as Gemini CLI does", () => {
    const other = join(root, "gch");
    mkdirSync(join(other, ".gemini"), { recursive: true });
    const r = installSeatbelt(l, { ...opts(), env: { HOME: home, GEMINI_CLI_HOME: other } });
    expect(r.path).toBe(join(other, ".gemini", "sandbox-macos-launchsafe.sb"));
  });
  it("keeps a copy of a file it did not write before replacing it", () => {
    writeFileSync(seatbeltProfilePath(env(), home), "(version 1)(allow default)");
    const r = installSeatbelt(l, opts());
    expect(r.backup).toBeDefined();
    expect(readFileSync(r.backup as string, "utf8")).toBe("(version 1)(allow default)");
  });
  it("the copy is the file as it was, a leading byte order mark included", () => {
    writeFileSync(seatbeltProfilePath(env(), home), "﻿(version 1)(allow default)");
    const r = installSeatbelt(l, opts());
    expect(r.backup).toBeDefined();
    expect(readFileSync(r.backup as string, "utf8")).toBe("﻿(version 1)(allow default)");
  });
  it("builds the strict profiles with reads of the package and node", () => {
    const { text } = expectedProfile(l, opts("strict-open"));
    expect(blockOf(text)).toContain("(allow file-read*");
    expect(blockOf(text)).toContain(join(root, "pkg"));
  });
  it("refuses a data directory inside ~/.gemini, a base that is not deny-by-default, and an unknown base", () => {
    expect(() => installSeatbelt(layout(join(home, ".gemini", "fw")), opts())).toThrow(/overlaps Gemini CLI/);
    writeFileSync(join(bundle, "sandbox-macos-permissive-open.sb"), "(version 1)\n(allow default)\n");
    expect(() => installSeatbelt(l, opts())).toThrow(/deny-by-default/);
    expect(() => installSeatbelt(l, { ...opts(), base: "nonsense" as "strict-open" })).toThrow(/unknown seatbelt profile/);
    expect(existsSync(seatbeltProfilePath(env(), home))).toBe(false);
  });
  it("finds Gemini CLI's bundle from its package, its bundle directory or the gemini command", () => {
    expect(findGeminiBundle({ dir: join(root, "gemini") })).toBe(bundle);
    expect(findGeminiBundle({ dir: bundle })).toBe(bundle);
    expect(findGeminiBundle({ dir: root })).toBeNull();
    writeFileSync(join(bundle, "gemini.js"), "");
    expect(findGeminiBundle({ find: () => join(bundle, "gemini.js") })).toBe(bundle);
    expect(findGeminiBundle({ find: () => null })).toBeNull();
  });
});

describe("uninstall", () => {
  it("removes the profile it wrote and leaves an edited one", () => {
    const r = installSeatbelt(l, opts());
    expect(removeSeatbelt(l)).toEqual({ path: r.path, action: "removed" });
    expect(existsSync(r.path)).toBe(false);
    expect(removeSeatbelt(l)).toBeNull();
    installSeatbelt(l, opts());
    writeFileSync(r.path, `${readFileSync(r.path, "utf8")}\n(allow default)\n`);
    expect(removeSeatbelt(l)).toEqual({ path: r.path, action: "left-edited" });
    expect(existsSync(r.path)).toBe(true);
  });
});

describe("doctor", () => {
  const checks = (e: NodeJS.ProcessEnv = { SEATBELT_PROFILE: "launchsafe" }, b: string | null = bundle) => seatbeltChecks(l, { home, env: { HOME: home, ...e }, platform: "darwin", projectDir: project, bundle: b, node: process.execPath, packageDir: join(root, "pkg") });
  it("says how to set it up, and fails when Gemini CLI starts sandboxed by default", () => {
    expect(checks({})).toEqual([expect.objectContaining({ status: "warn", detail: expect.stringContaining("install --agent gemini --seatbelt permissive-open") })]);
    expect(checks({ GEMINI_SANDBOX: "true" })[0]?.status).toBe("fail");
    writeFileSync(join(home, ".gemini", "settings.json"), JSON.stringify({ tools: { sandbox: true } }));
    expect(checks({})[0]).toMatchObject({ status: "fail", detail: expect.stringContaining("tools.sandbox") });
    expect(seatbeltChecks(l, { home, env: {}, platform: "linux", projectDir: project })).toEqual([]);
  });
  it("is ok on a fresh install with the profile selected", () => {
    installSeatbelt(l, opts());
    expect(checks().map((c) => c.status)).toEqual(["ok"]);
  });
  it("warns when this shell does not select the profile, when Gemini CLI's base changed, and when a project ships one", () => {
    installSeatbelt(l, opts());
    expect(checks({})).toContainEqual(expect.objectContaining({ status: "warn", detail: expect.stringContaining("export SEATBELT_PROFILE=launchsafe") }));
    writeFileSync(join(bundle, "sandbox-macos-permissive-open.sb"), `${BASE};; updated\n`);
    expect(checks()).toContainEqual(expect.objectContaining({ name: "Gemini CLI sandbox (-s) base profile", status: "warn" }));
    mkdirSync(join(project, ".gemini"), { recursive: true });
    writeFileSync(join(project, ".gemini", "sandbox-macos-launchsafe.sb"), "(version 1)(allow default)");
    expect(checks()).toContainEqual(expect.objectContaining({ name: "Gemini CLI sandbox (-s) project profile", status: "warn" }));
  });
  it("fails when the profile is gone, edited, or names another data directory", () => {
    const r = installSeatbelt(l, opts());
    writeFileSync(r.path, "(version 1)(allow default)");
    expect(checks()[0]).toMatchObject({ status: "fail", detail: expect.stringContaining("changed since") });
    rmSync(r.path);
    expect(checks()[0]).toMatchObject({ status: "fail", detail: expect.stringContaining("is gone") });
    installSeatbelt(l, opts());
    const moved = layout(join(root, "elsewhere"));
    mkdirSync(moved.home, { recursive: true });
    writeFileSync(join(moved.home, "gemini-seatbelt.json"), readFileSync(join(l.home, "gemini-seatbelt.json")));
    expect(seatbeltChecks(moved, { home, env: { SEATBELT_PROFILE: "launchsafe" }, platform: "darwin", projectDir: project })[0]).toMatchObject({ status: "fail", detail: expect.stringContaining("does not match this install") });
  });
});

describe("the hook inside Gemini CLI's sandbox", () => {
  const eperm = Object.assign(new Error("EPERM: operation not permitted, mkdir '/h/.launchsafe-firewall/sessions'"), { code: "EPERM" });
  it("gives one message that says what to do, only for a refusal inside the sandbox", () => {
    expect(seatbeltRefusal(eperm, { SANDBOX: "sandbox-exec" })).toMatch(/Gemini CLI's sandbox \(-s, seatbelt profile "permissive-open"\).*install --agent gemini --seatbelt permissive-open.*SEATBELT_PROFILE=launchsafe; or run it without -s/);
    expect(seatbeltRefusal(eperm, { SANDBOX: "sandbox-exec", SEATBELT_PROFILE: "launchsafe" })).toMatch(/does not match this install/);
    expect(seatbeltRefusal(eperm, {})).toBeNull();
    expect(seatbeltRefusal(Object.assign(new Error("x"), { code: "ENOENT" }), { SANDBOX: "sandbox-exec" })).toBeNull();
    expect(seatbeltRefusal(null, { SANDBOX: "sandbox-exec" })).toBeNull();
  });
  it.skipIf(process.getuid?.() === 0)("blocks a shell command and lets a read through, with that message", () => {
    mkdirSync(l.home, { recursive: true });
    chmodSync(l.home, 0o500);
    const send = (event: Record<string, unknown>) => runHook(JSON.stringify({ session_id: "s1", cwd: project, ...event }), { env: { SANDBOX: "sandbox-exec", SEATBELT_PROFILE: "permissive-open" }, layout: l, agent: "gemini", home, detectNonInteractive: () => false, notifyDeps: { spawn: () => undefined } });
    const shell = send({ hook_event_name: "BeforeTool", tool_name: "run_shell_command", tool_input: { command: "echo hi" } });
    const out = JSON.parse(shell.stdout) as { decision: string; reason: string };
    expect(out.decision).toBe("deny");
    expect(out.reason).toMatch(/^LaunchSafe Firewall cannot save its state inside Gemini CLI's sandbox/);
    const read = send({ hook_event_name: "BeforeTool", tool_name: "read_file", tool_input: { file_path: join(project, "a.txt") } });
    expect(read.stdout).toBe("");
    expect(read.stderr).toMatch(/read-only tool read_file allowed/);
    const start = send({ hook_event_name: "SessionStart", source: "startup" });
    expect(start.stderr).toMatch(/^LaunchSafe Firewall cannot save its state inside Gemini CLI's sandbox/);
  });
});

describe.skipIf(process.platform !== "darwin")("the profile under sandbox-exec", () => {
  it("lets a process write the state directories and nothing else of the firewall's", () => {
    const r = installSeatbelt(l, opts());
    const fw = realpathSync(l.home);
    const tryWrite = (p: string): boolean => spawnSync("sandbox-exec", ["-D", `HOME_DIR=${realpathSync(home)}`, "-f", r.path, "/usr/bin/touch", p]).status === 0;
    for (const d of HOOK_STATE_DIRS) expect(tryWrite(join(fw, d, "x")), d).toBe(true);
    for (const p of ["policy.json", "install.json", "identity.json", "gemini-seatbelt.json", "x"]) expect(tryWrite(join(fw, p)), p).toBe(false);
    mkdirSync(join(fw, "keys"), { recursive: true });
    expect(tryWrite(join(fw, "keys", "x"))).toBe(false);
    expect(tryWrite(r.path)).toBe(false);
    expect(tryWrite(join(root, "elsewhere"))).toBe(false);
  });
});
