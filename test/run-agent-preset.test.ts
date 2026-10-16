/**
 * `run --agent claude|codex|gemini` (docs/run.md, "Agent presets") and doctor's "agent sandbox" note. The
 * presets add the agent's model API and its documented switches, nothing else: run's file rules and its
 * refusals are the same with and without one.
 */
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseCommandLine } from "../src/cliargs.js";
import { AGENT_PRESETS, PRESET_AGENTS } from "../src/engine/agent-presets.js";
import { runNetPolicy } from "../src/engine/netgate.js";
import { defaultConfig } from "../src/policy.js";
import { agentSandboxChecks, codexSandboxMode } from "../src/runtime/agent-sandbox-doctor.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import type { RunPlatform } from "../src/runtime/run/platform.js";
import { applyAgentPreset, runSandboxed, type RunOptions } from "../src/runtime/run/run.js";
import { tempHome, testRoot } from "./helpers.js";

const fakeMac: () => RunPlatform = () => ({ kind: "seatbelt", path: "/usr/bin/sandbox-exec", detail: "macOS sandbox-exec (Seatbelt)" });

function setup(): { home: string; l: Layout; ws: string; bin: string } {
  const home = tempHome("runagent-");
  const l = layout(join(home, ".launchsafe-firewall"));
  mkdirSync(l.home, { recursive: true, mode: 0o700 });
  const ws = mkdtempSync(join(testRoot(), "runagent-ws-"));
  const bin = mkdtempSync(join(testRoot(), "runagent-bin-"));
  for (const name of ["claude", "codex", "gemini"]) {
    writeFileSync(join(bin, name), "#!/bin/sh\nexit 0\n");
    chmodSync(join(bin, name), 0o755);
  }
  return { home, l, ws, bin };
}

function opts(s: ReturnType<typeof setup>, command: string[], over: Partial<RunOptions> = {}): RunOptions & { said: string[]; warned: string[] } {
  const said: string[] = [];
  const warned: string[] = [];
  return { layout: s.l, command, workspace: s.ws, allowWrite: [], sendHosts: [], allowLocalhost: false, allowKeychain: false, dryRun: true, verbose: false, env: { ...process.env, HOME: s.home, PATH: `${s.bin}:/usr/bin:/bin`, LAUNCHSAFE_FIREWALL_RUN: undefined }, home: s.home, cwd: s.ws, say: (x) => void said.push(x), warn: (x) => void warned.push(x), detect: fakeMac, platform: "darwin", said, warned, ...over };
}

describe("the presets", () => {
  it("each lists only exact host names that run admits as send hosts", () => {
    for (const a of PRESET_AGENTS) {
      const p = AGENT_PRESETS[a];
      expect(p.sendHosts.every((h) => /^=[a-z0-9.-]+$/.test(h)), a).toBe(true);
      const net = runNetPolicy(defaultConfig(), { sendHosts: [...p.sendHosts] });
      expect(net.problems, a).toEqual([]);
      for (const h of p.sendHosts) expect(net.policy.allowed.some((x) => x.domain === h.slice(1) && x.kind === "send"), `${a} ${h}`).toBe(true);
    }
  });

  it("applyAgentPreset adds the hosts and the variables; the person's --send-host and --env come too, and --env wins", () => {
    const r = applyAgentPreset({ agent: "claude", command: ["claude", "-p", "hi"], sendHosts: ["api.example.com"], extraEnv: { DISABLE_AUTOUPDATER: "0", TOKEN: "x" } });
    expect(r.command).toEqual(["claude", "-p", "hi"]);
    expect(r.sendHosts).toEqual(["=api.anthropic.com", "api.example.com"]);
    expect(r.extraEnv).toEqual({ CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1", DISABLE_AUTOUPDATER: "0", TOKEN: "x" });
    expect(r.note).toBeUndefined();
    expect(applyAgentPreset({ agent: "codex", command: ["aider"], sendHosts: [] }).note).toContain("--agent codex prepares the run for Codex CLI");
    expect(applyAgentPreset({ agent: "gemini", command: ["npx", "@google/gemini-cli"], sendHosts: [] }).note).toBeUndefined();
    expect(applyAgentPreset({ command: ["aider"], sendHosts: ["x.example"] })).toEqual({ command: ["aider"], sendHosts: ["x.example"] });
  });

  it("the command line: --agent takes claude, codex or gemini, and still needs the command after --", () => {
    const p = parseCommandLine(["run", "--agent", "codex", "--", "codex", "--full-auto"]);
    expect(p.kind === "ok" && p.flags.get("--agent")).toBe("codex");
    expect(p.kind === "ok" && p.positionals).toEqual(["codex", "--full-auto"]);
    expect(parseCommandLine(["run", "--agent", "cursor", "--", "x"])).toMatchObject({ kind: "error" });
    expect(parseCommandLine(["run", "--agent", "claude"])).toMatchObject({ kind: "error" });
  });

  it("the dry run names the preset and its hosts; the file rules are the same as without it", async () => {
    const s = setup();
    const withPreset = opts(s, [join(s.bin, "claude")], { agent: "claude" });
    expect((await runSandboxed(withPreset)).exitCode).toBe(0);
    const text = withPreset.said.join("\n");
    expect(text).toContain("Agent preset: Claude Code: send hosts =api.anthropic.com; environment CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_AUTOUPDATER=1; ~/.claude is read-only but readable: the agent's credentials there can be read by every program in the run, and =api.anthropic.com receives whatever is sent there, unbudgeted");
    expect(text).toMatch(/api\.anthropic\.com\s+send/);
    const without = opts(s, [join(s.bin, "claude")]);
    await runSandboxed(without);
    // The run's private temporary directory has a new name each run.
    const lines = (o: { said: string[] }, prefix: string): string | undefined => o.said.find((x) => x.startsWith(prefix))?.replace(/lsfw-run-[A-Za-z0-9]+/g, "lsfw-run-X");
    for (const prefix of ["Writable:", "Read-only:", "Unreadable:"]) expect(lines(withPreset, prefix), prefix).toBe(lines(without, prefix));
    expect(without.said.join("\n")).not.toContain("api.anthropic.com");
  });

  it("with the agent's hooks installed, the warning also points at OpenShell", async () => {
    const s = setup();
    writeFileSync(join(s.l.home, "install.json"), JSON.stringify([{ agent: "codex", scope: "user", path: join(s.home, ".codex", "hooks.json"), backup: "", installedAt: new Date().toISOString(), version: "0.3.0" }]));
    const o = opts(s, [join(s.bin, "codex")], { agent: "codex" });
    await runSandboxed(o);
    const w = o.warned.join("\n");
    expect(w).toContain("runs the firewall's hooks as its own child processes");
    expect(w).toContain("docs/sandboxes.md");
  });
});

describe("doctor: agent sandbox", () => {
  const base = (home: string, over: Partial<Parameters<typeof agentSandboxChecks>[0]> = {}): Parameters<typeof agentSandboxChecks>[0] => ({ home, env: {}, projectDir: home, hooked: new Set(), claudeSandboxOn: true, findBinary: () => null, ...over });

  it("an agent on PATH without the firewall's hooks: recommends run --agent", () => {
    const home = tempHome("agsb-");
    const c = agentSandboxChecks(base(home, { findBinary: (n) => (n === "codex" ? "/usr/local/bin/codex" : null) }));
    expect(c).toHaveLength(1);
    expect(c[0]?.status).toBe("warn");
    expect(c[0]?.detail).toContain('"launchsafe-firewall run --agent codex"');
  });

  it("hooked agents with no sandbox: their own sandbox or OpenShell, never run (their hooks would fail closed there)", () => {
    const home = tempHome("agsb-");
    mkdirSync(join(home, ".codex"), { recursive: true });
    writeFileSync(join(home, ".codex", "config.toml"), 'model = "x"\nsandbox_mode = "danger-full-access"\n[profiles.a]\nsandbox_mode = "read-only"\n');
    expect(codexSandboxMode({}, home)).toBe("danger-full-access");
    const c = agentSandboxChecks(base(home, { hooked: new Set(["codex", "gemini", "claude"]), claudeSandboxOn: false, findBinary: () => "/bin/x" }));
    const d = c[0]?.detail ?? "";
    expect(c[0]?.status).toBe("warn");
    expect(d).toContain("doctor --fix");
    expect(d).toContain('sandbox_mode = "danger-full-access"');
    expect(d).toContain("--seatbelt permissive-open");
    expect(d).toContain("docs/sandboxes.md");
    expect(d).not.toContain("run --agent");
  });

  it("ok when every agent has a sandbox, and inside run", () => {
    const home = tempHome("agsb-");
    mkdirSync(join(home, ".gemini"), { recursive: true });
    writeFileSync(join(home, ".gemini", "settings.json"), JSON.stringify({ tools: { sandbox: true } }));
    expect(agentSandboxChecks(base(home, { hooked: new Set(["claude", "gemini", "codex"]) }))[0]?.status).toBe("ok");
    // Inside run: the whole environment run gives its child, not LAUNCHSAFE_FIREWALL_RUN alone (which any shell can set).
    const proxy = "http://127.0.0.1:50123";
    const inside = { LAUNCHSAFE_FIREWALL_RUN: "run-20261014120000-0a1b2c3d", TMPDIR: "/tmp/lsfw-run-AbCd", HTTPS_PROXY: proxy, HTTP_PROXY: proxy, ALL_PROXY: proxy, https_proxy: proxy, http_proxy: proxy, NODE_USE_ENV_PROXY: "1" };
    expect(agentSandboxChecks(base(home, { env: inside, findBinary: () => "/bin/x" }))[0]).toMatchObject({ status: "ok", detail: expect.stringContaining("inside launchsafe-firewall run") });
    expect(agentSandboxChecks(base(home, { env: { LAUNCHSAFE_FIREWALL_RUN: "run-1" }, findBinary: () => "/bin/x" }))[0]?.status).toBe("warn");
  });
});
