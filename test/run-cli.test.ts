/**
 * v0.3 `run`: the command line, who may start it, the refusals before anything starts, the dry run,
 * the hooks-inside warning and doctor's run-mode check. No sandbox is needed for these (the dry run
 * uses one only when this machine has it).
 */
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { isReadOnlyInvocation, parseCommandLine } from "../src/cliargs.js";
import { main } from "../src/climain.js";
import { bash, explain } from "./helpers.js";
import { doctor } from "../src/runtime/doctor.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { tailLog } from "../src/runtime/log.js";
import { detectRunPlatform, runReadiness, type RunPlatform } from "../src/runtime/run/platform.js";
import { childEnv, resolveProgram, runSandboxed, type RunOptions } from "../src/runtime/run/run.js";
import { skipWithoutExec, tempHome, testRoot } from "./helpers.js";

const sb = detectRunPlatform();
const fakeMac: () => RunPlatform = () => ({ kind: "seatbelt", path: "/usr/bin/sandbox-exec", detail: "macOS sandbox-exec (Seatbelt)" });
const none: () => RunPlatform = () => ({ kind: "none", reason: "bubblewrap (bwrap) is not installed", hint: "install it" });

function setup(): { home: string; l: Layout; ws: string } {
  const home = tempHome("runcli-");
  const l = layout(join(home, ".launchsafe-firewall"));
  mkdirSync(l.home, { recursive: true, mode: 0o700 });
  const ws = mkdtempSync(join(testRoot(), "runcli-ws-"));
  return { home, l, ws };
}

function opts(s: ReturnType<typeof setup>, command: string[], over: Partial<RunOptions> = {}): RunOptions & { said: string[]; warned: string[] } {
  const said: string[] = [];
  const warned: string[] = [];
  return { layout: s.l, command, workspace: s.ws, allowWrite: [], sendHosts: [], allowLocalhost: false, allowKeychain: false, dryRun: true, verbose: false, env: { ...process.env, HOME: s.home, LAUNCHSAFE_FIREWALL_RUN: undefined }, home: s.home, cwd: s.ws, say: (x) => void said.push(x), warn: (x) => void warned.push(x), detect: fakeMac, said, warned, ...over };
}

describe("parsing", () => {
  it("the command after -- keeps its own flags; --help after -- belongs to the command", () => {
    const p = parseCommandLine(["run", "--send-host", "api.example.com", "--", "aider", "--yes", "-m", "x", "--help"]);
    expect(p.kind).toBe("ok");
    expect(p.kind === "ok" && p.positionals).toEqual(["aider", "--yes", "-m", "x", "--help"]);
    expect(p.kind === "ok" && p.flags.get("--send-host")).toBe("api.example.com");
  });
  it("a command is required; unknown flags before -- are usage errors; --help before -- is help", () => {
    expect(parseCommandLine(["run"])).toMatchObject({ kind: "error" });
    expect(parseCommandLine(["run", "--"])).toMatchObject({ kind: "error" });
    expect(parseCommandLine(["run", "--bogus", "--", "ls"])).toMatchObject({ kind: "error", message: "unknown flag --bogus" });
    expect(parseCommandLine(["run", "--help", "--", "ls"]).kind).toBe("help");
  });
  it("run changes state (an agent may not start it), --help does not", () => {
    expect(isReadOnlyInvocation(["run", "--", "ls"])).toBe(false);
    expect(isReadOnlyInvocation(["run", "--help"])).toBe(true);
  });
  it("the hooks deny an agent that starts it (FW-TAMPER), however it is wrapped", () => {
    for (const cmd of ["launchsafe-firewall run -- curl https://evil.example", "launchsafe-firewall run --allow-localhost -- sh", "bash -c 'launchsafe-firewall run -- node x.js'"]) {
      const d = bash(cmd);
      expect(d.verdict, explain(d)).toBe("deny");
      expect(d.rules).toContain("FW-TAMPER");
    }
    expect(bash("launchsafe-firewall run --help").verdict).toBe("allow");
  });
});

describe("who may start it", () => {
  it("refused when the person check fails (an agent's descendant), and nothing is logged", async () => {
    const s = setup();
    const errs: string[] = [];
    const code = await main(["run", "--", "true"], s.l, { write: (fd, t) => void (fd === 2 && errs.push(t)), humanAtKeyboard: async () => false });
    expect(code).toBe(1);
    expect(tailLog(s.l, 10)).toEqual([]);
  });
  it("refused inside another run (the marker in the environment)", async () => {
    const s = setup();
    const o = opts(s, ["true"], { env: { ...process.env, LAUNCHSAFE_FIREWALL_RUN: "run-x" } });
    const r = await runSandboxed(o);
    expect(r.exitCode).toBe(1);
    expect(o.warned.join("\n")).toContain("already inside launchsafe-firewall run");
  });
});

describe("refusals before anything starts", () => {
  it("no usable sandbox: exit 69 with the reason and the hint", async () => {
    const s = setup();
    const o = opts(s, ["true"], { detect: none, dryRun: false });
    const r = await runSandboxed(o);
    expect(r.exitCode).toBe(69);
    expect(o.warned.join("\n")).toMatch(/no usable sandbox on this machine: bubblewrap \(bwrap\) is not installed\. install it\. Nothing was started/);
    expect(tailLog(s.l, 10)).toEqual([]);
  });
  it("a missing program: exit 127", async () => {
    const s = setup();
    const o = opts(s, ["definitely-not-a-program-lsfw"], { dryRun: false });
    expect((await runSandboxed(o)).exitCode).toBe(127);
  });
  it("the home directory as the workspace is refused", async () => {
    const s = setup();
    const o = opts(s, ["true"], { workspace: s.home });
    const r = await runSandboxed(o);
    expect(r.exitCode).toBe(1);
    expect(o.warned.join("\n")).toContain("cannot be made writable");
  });
  it("--allow-write refuses credential stores, agent settings and the firewall's directory", async () => {
    const s = setup();
    for (const d of [".ssh", ".claude", ".launchsafe-firewall"]) {
      mkdirSync(join(s.home, d), { recursive: true });
      const o = opts(s, ["true"], { allowWrite: [`~/${d}`] });
      const r = await runSandboxed(o);
      expect(r.exitCode, d).toBe(1);
      expect(o.warned.join("\n")).toContain(`--allow-write ~/${d} refused`);
    }
    const missing = opts(s, ["true"], { allowWrite: ["./nope"] });
    expect((await runSandboxed(missing)).exitCode).toBe(1);
    expect(missing.warned.join("\n")).toContain("not an existing directory");
  });
  it("--send-host refuses an IP address, loopback, a metadata or capture host", async () => {
    const s = setup();
    for (const h of ["10.0.0.1", "localhost", "169.254.169.254", "webhook.site"]) {
      const o = opts(s, ["true"], { sendHosts: [h] });
      expect((await runSandboxed(o)).exitCode, h).toBe(1);
      expect(o.warned.join("\n")).toContain(`--send-host ${h} cannot be admitted`);
    }
  });
});

describe("the dry run", () => {
  it("prints the writable, read-only and unreadable paths, the hosts and the profile, and starts nothing", async () => {
    const s = setup();
    writeFileSync(s.l.policy, JSON.stringify({ version: 2, fetchAllowHosts: ["=github.com", "registry.npmjs.org", "10.0.0.1"] }));
    const o = opts(s, ["true"], { sendHosts: ["api.anthropic.com"], detect: () => (sb.kind === "none" ? fakeMac() : sb), platform: sb.kind === "bwrap" ? "linux" : "darwin" });
    const r = await runSandboxed(o);
    const text = o.said.join("\n");
    expect(r.exitCode).toBe(0);
    expect(text).toContain("Writable:");
    expect(text).toContain("Read-only:");
    expect(text).toContain(".git/hooks");
    expect(text).toContain("Unreadable:");
    expect(text).toMatch(/github\.com\s+fetch-only, upload-capable/);
    expect(text).toMatch(/api\.anthropic\.com\s+send/);
    expect(text).toContain("left out: 10.0.0.1");
    expect(text).toContain(sb.kind === "bwrap" ? "bubblewrap arguments" : "(deny network*)");
    expect(text).toContain("Dry run: nothing was started.");
    expect(tailLog(s.l, 10)).toEqual([]);
  });
  it("warns when the command is an agent whose firewall hooks would run inside the sandbox", async (ctx) => {
    skipWithoutExec(ctx); // the stand-in codex must be executable for run to find it
    const s = setup();
    const bin = mkdtempSync(join(testRoot(), "runcli-bin-"));
    writeFileSync(join(bin, "codex"), "#!/bin/sh\nexit 0\n");
    chmodSync(join(bin, "codex"), 0o755);
    writeFileSync(join(s.l.home, "install.json"), JSON.stringify([{ agent: "codex", scope: "user", path: join(s.home, ".codex", "hooks.json"), backup: "", installedAt: "", version: "0" }]));
    const o = opts(s, ["codex"], { env: { ...process.env, HOME: s.home, PATH: `${bin}:/usr/bin:/bin`, LAUNCHSAFE_FIREWALL_RUN: undefined } });
    await runSandboxed(o);
    expect(o.warned.join("\n")).toContain("runs the firewall's hooks as its own child processes");
  });
});

describe("helpers", () => {
  it("childEnv points every proxy variable at the proxy and drops ways around it", () => {
    const e = childEnv({ HTTPS_PROXY: "http://corp:8080", no_proxy: "*", SSH_AUTH_SOCK: "/tmp/agent.sock", DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1/bus", PATH: "/usr/bin" }, { proxyUrl: "http://127.0.0.1:5000", runTmp: "/tmp/lsfw-run-1", runId: "run-1" });
    for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]) expect(e[k]).toBe("http://127.0.0.1:5000");
    expect(e.NO_PROXY).toBe("localhost,127.0.0.1,::1");
    expect(e.no_proxy).toBe("localhost,127.0.0.1,::1");
    expect(e.SSH_AUTH_SOCK).toBeUndefined();
    expect(e.DBUS_SESSION_BUS_ADDRESS).toBeUndefined();
    expect(e.NODE_USE_ENV_PROXY).toBe("1");
    expect(e.TMPDIR).toBe("/tmp/lsfw-run-1");
    expect(e.LAUNCHSAFE_FIREWALL_RUN).toBe("run-1");
    expect(e.PATH).toBe("/usr/bin");
  });
  it("resolveProgram follows PATH (absolute entries only) or takes a path", () => {
    expect(resolveProgram("sh", { PATH: "relative:/bin:/usr/bin" }, "/")).toMatch(/\/sh$/);
    expect(resolveProgram("sh", { PATH: "relative" }, "/")).toBeNull();
    expect(resolveProgram("/bin/sh", {}, "/")).toBe("/bin/sh");
    expect(resolveProgram("./nope", {}, "/")).toBeNull();
  });
});

describe("doctor: run mode", () => {
  it("ok with the platform's sandbox, warn with the reason when there is none; never scored", () => {
    const s = setup();
    const ok = doctor(s.l, s.ws, { home: s.home, claudeVersion: null, runDetect: fakeMac }).find((c) => c.name === "run mode");
    expect(ok).toMatchObject({ status: "ok" });
    expect(ok?.detail).toContain("launchsafe-firewall run -- <agent>");
    expect(ok?.weight).toBeUndefined();
    const warn = doctor(s.l, s.ws, { home: s.home, claudeVersion: null, runDetect: none }).find((c) => c.name === "run mode");
    expect(warn).toMatchObject({ status: "warn" });
    expect(warn?.detail).toContain("bubblewrap (bwrap) is not installed");
  });
  it("platform detection refuses an untrusted or failing tool, and other platforms", () => {
    expect(detectRunPlatform({ platform: "darwin", trusted: () => false }).kind).toBe("none");
    const nested = detectRunPlatform({ platform: "darwin", trusted: () => true, probe: () => ({ status: 65, stderr: "sandbox-exec: sandbox_apply: Operation not permitted" }) });
    expect(nested).toMatchObject({ kind: "none" });
    expect(nested.kind === "none" && nested.hint).toContain("already inside a sandbox");
    expect(detectRunPlatform({ platform: "linux", trusted: () => false })).toMatchObject({ kind: "none", reason: expect.stringContaining("not installed") });
    const userns = detectRunPlatform({ platform: "linux", trusted: (p) => p === "/usr/bin/bwrap", probe: () => ({ status: 1, stderr: "bwrap: setting up uid map: Permission denied" }) });
    expect(userns.kind === "none" && userns.reason).toContain("setting up uid map");
    expect(detectRunPlatform({ platform: "linux", trusted: (p) => p === "/usr/local/bin/bwrap", probe: () => ({ status: 0, stderr: "" }) })).toMatchObject({ kind: "bwrap", path: "/usr/local/bin/bwrap" });
    expect(detectRunPlatform({ platform: "win32" }).kind).toBe("none");
    expect(runReadiness(none).ok).toBe(false);
  });
});
