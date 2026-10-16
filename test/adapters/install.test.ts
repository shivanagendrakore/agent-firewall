/**
 * Install, uninstall and doctor for Codex and Gemini CLI (temporary homes only), and the
 * self-protection of their settings files.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { codexAdapter, codexManagedSnippet } from "../../src/adapters/codex.js";
import { cursorAdapter } from "../../src/adapters/cursor.js";
import { geminiAdapter } from "../../src/adapters/gemini.js";
import { doctor } from "../../src/runtime/doctor.js";
import { checkHookRegistration, hookCommand, install, readRecords, repinApprover, uninstall } from "../../src/runtime/install.js";
import { codexTrustHash, trustStatus } from "../../src/runtime/codex-trust.js";
import { initApprover } from "../../src/runtime/approver.js";
import { parseHookCommand } from "../../src/runtime/identity.js";
import { settingsViolations } from "../../src/engine/settings.js";
import { adapterFor } from "../../src/adapters/index.js";
import { spawnCli } from "../helpers.js";
import { box, send, verdict, rules, type Box } from "./harness.js";

let b: Box;
beforeEach(() => {
  b = box();
});
afterEach(() => b.cleanup());

const find = (cs: ReturnType<typeof doctor>, name: string) => cs.filter((c) => c.name.startsWith(name));

describe("install --agent codex", () => {
  it("writes ~/.codex/hooks.json in Codex's shape: first, matcher *, the loud fail-closed wrapper; idempotent; uninstall restores", () => {
    const path = join(b.home, ".codex", "hooks.json");
    mkdirSync(join(b.home, ".codex"), { recursive: true });
    const original = JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "mine" }] }] } });
    writeFileSync(path, original);
    const r = install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings });
    expect(r.path).toBe(path);
    const s = JSON.parse(readFileSync(path, "utf8")) as { hooks: Record<string, { matcher?: string; hooks: { command: string; timeout: number }[] }[]> };
    for (const ev of ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"]) expect(s.hooks[ev]?.[0]?.hooks[0]?.command).toMatch(/hook --agent codex \|\| \{ echo '[^']+' >&2; exit 2; \}$/);
    expect(s.hooks.PreToolUse?.[0]?.matcher).toBe("*");
    expect(s.hooks.PreToolUse?.[0]?.hooks[0]?.timeout).toBe(600);
    expect(s.hooks.PreToolUse?.[1]?.hooks[0]?.command).toBe("mine");
    expect(install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings }).changed).toBe(false);
    expect(readRecords(b.l)).toEqual([expect.objectContaining({ agent: "codex", path })]);
    uninstall(b.l, { restoreBackup: true, agent: "codex", settings: codexAdapter.settings });
    expect(readFileSync(path, "utf8")).toBe(original);
    expect(readRecords(b.l)).toEqual([]);
  });
  it("Codex has no local scope", () => {
    expect(() => install(b.l, "local", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings })).toThrow(/no local settings file/);
  });
  it("installing for one agent and uninstalling another leaves the first alone", () => {
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings });
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "gemini", settings: geminiAdapter.settings });
    uninstall(b.l, { agent: "gemini", settings: geminiAdapter.settings });
    expect(readRecords(b.l).map((r) => r.agent)).toEqual(["codex"]);
    expect(readFileSync(join(b.home, ".gemini", "settings.json"), "utf8")).not.toContain("LAUNCHSAFE_FIREWALL_HOOK");
  });
  it("the identity is read from a Codex or Gemini hook command (F-c)", () => {
    const cmd = hookCommand(b.l, "/usr/local/bin/node", "/opt/fw/dist/cli.js", "codex");
    expect(parseHookCommand(cmd)).toEqual(expect.objectContaining({ node: "/usr/local/bin/node", cli: "/opt/fw/dist/cli.js" }));
  });
  it("managed: requirements.toml with the hooks and allow_managed_hooks_only", () => {
    const t = codexManagedSnippet("CMD", true);
    expect(t).toContain("allow_managed_hooks_only = true");
    expect(t).toContain("[[hooks.PreToolUse]]");
    expect(t).toContain("command = '''CMD'''");
  });
  it("install --managed --agent codex --print prints TOML and writes nothing (CLI)", () => {
    const r = spawnCli(["install", "--managed", "--agent", "codex", "--print"]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("[[hooks.PreToolUse]]");
    expect(r.stdout).toContain("hook --agent codex");
    expect(existsSync(join(r.home, ".codex"))).toBe(false);
  });
  it("install --agent codex --scope local is a usage error (CLI)", () => {
    expect(spawnCli(["install", "--agent", "codex", "--scope", "local", "--no-approver"]).status).toBe(64);
  });
});

describe("self-protection of Codex and Gemini settings", () => {
  it("removing the firewall from hooks.json through apply_patch is FW-TAMPER", () => {
    install(b.l, "project", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings });
    const path = join(b.ws, ".codex", "hooks.json");
    const r = send(b, "codex", { hook_event_name: "PreToolUse", tool_name: "apply_patch", tool_input: { command: `*** Begin Patch\n*** Delete File: ${path}\n*** End Patch\n` } });
    expect(verdict("codex", r)).toBe("deny");
    expect(rules("codex", r)).toContain("FW-TAMPER");
    const r2 = send(b, "codex", { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: `echo '{}' > ${path}` } });
    expect(rules("codex", r2)).toContain("FW-TAMPER");
  });
  it("TOML: removing the firewall's command line or flipping allow_managed_hooks_only is tampering", () => {
    const before = "allow_managed_hooks_only = true\n[[hooks.PreToolUse]]\ncommand = '''LAUNCHSAFE_FIREWALL_HOOK=1 x hook --agent codex || exit 2'''\n";
    expect(settingsViolations(before, before.replace(/command.*\n/, ""), true, "/etc/codex/requirements.toml")).toEqual(["it removes the firewall's hooks"]);
    expect(settingsViolations(before, before.replace("true", "false"), true, "/etc/codex/requirements.toml")).toEqual(["it changes allow_managed_hooks_only, which decides which hooks may run"]);
    expect(settingsViolations(before, `${before}model = "x"\n`, true, "/etc/codex/requirements.toml")).toEqual([]);
  });
  it("a Claude Code ConfigChange also notices a removed Codex hook", () => {
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings });
    writeFileSync(join(b.home, ".codex", "hooks.json"), "{}");
    expect(checkHookRegistration(b.l, b.ws, b.home, (id) => adapterFor(id).settings).join(" ")).toMatch(/PreToolUse.*hooks\.json/);
  });
});

describe("doctor: Codex and Gemini CLI sections", () => {
  const opts = (bin: Partial<Record<string, string>> = {}) => ({ home: b.home, platform: "darwin" as const, claudeVersion: "2.1.289", findBinary: (n: string) => bin[n] ?? null, agentVersion: () => "0.162.1" });
  it("K15: Codex present and its hooks missing -> fail with the install command", () => {
    mkdirSync(join(b.home, ".codex"), { recursive: true });
    const c = find(doctor(b.l, b.ws, opts()), "Codex hooks");
    expect(c[0]?.status).toBe("fail");
    expect(c[0]?.detail).toContain("launchsafe-firewall install --agent codex");
  });
  it("Codex installed: ok, plus managed, sandbox, version and coverage lines", () => {
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings });
    const cs = doctor(b.l, b.ws, opts({ codex: "/usr/local/bin/codex" }));
    expect(find(cs, "Codex hooks (user)")[0]?.status).toBe("ok");
    expect(find(cs, "Codex managed hooks")[0]?.status).toBe("warn");
    expect(find(cs, "Codex sandbox")[0]?.status).toBe("ok");
    expect(find(cs, "Codex coverage")[0]?.detail).toMatch(/hosted web search/);
    expect(cs.find((c) => c.name === "Codex")?.detail).toMatch(/tested with 0\.162\.1/);
  });
  it("Codex: the wrapper missing, and a sandbox switched off, are reported", () => {
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings, command: "LAUNCHSAFE_FIREWALL_HOOK=1 '/n' '/c/dist/cli.js' hook --agent codex" });
    writeFileSync(join(b.home, ".codex", "config.toml"), 'sandbox_mode = "danger-full-access"\napproval_policy = "never"\n');
    const cs = doctor(b.l, b.ws, opts());
    expect(find(cs, "Codex hooks (user)")[0]?.status).toBe("fail");
    expect(find(cs, "Codex sandbox")[0]?.status).toBe("warn");
    expect(find(cs, "Codex approvals")[0]?.status).toBe("warn");
  });
  it("Gemini: hooks switched off in settings are a failure", () => {
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "gemini", settings: geminiAdapter.settings });
    const p = join(b.home, ".gemini", "settings.json");
    writeFileSync(p, JSON.stringify({ ...JSON.parse(readFileSync(p, "utf8")), hooksConfig: { enabled: false } }));
    const c = find(doctor(b.l, b.ws, opts()), "Gemini CLI hooks (user)");
    expect(c[0]?.status).toBe("fail");
    expect(c[0]?.detail).toMatch(/hooksConfig\.enabled is false/);
  });
  it("neither agent on the machine: no lines for them", () => {
    const cs = doctor(b.l, b.ws, opts());
    expect(cs.filter((c) => /^(Codex|Gemini)/.test(c.name))).toEqual([]);
  });
  // The coverage line names the hook timeout; it must be the one install writes (Gemini CLI's is in milliseconds).
  for (const [label, a, seconds] of [
    ["Codex", codexAdapter, codexAdapter.settings.timeout],
    ["Gemini CLI", geminiAdapter, geminiAdapter.settings.timeout / 1000],
    ["Cursor", cursorAdapter, cursorAdapter.settings.timeout],
  ] as const) {
    it(`${label}: the timeout the coverage line names is the one install writes`, () => {
      const detail = a.coverage.find((c) => c.capability === "Fails closed by default")?.detail ?? "";
      expect(/\btime(?:s )?out \((\d+) s\b/.exec(detail)?.[1]).toBe(String(seconds));
    });
  }
});

describe("Codex hook trust (reproduced trusted_hash)", () => {
  it("the hash matches the value Codex 0.162.1 computed for a captured hook", () => {
    // From codex app-server hooks/list: matcher "zzz", command "true", no timeout (600).
    expect(codexTrustHash("PreToolUse", "zzz", { type: "command", command: "true" })).toBe("sha256:292d622b051152798e15697628a2a06d83894f161ab77beb636d729a1c200ed4");
  });
  it("install records the firewall hooks' trust, moves the person's own trust with their hook, and uninstall undoes both", () => {
    const hooksPath = join(b.home, ".codex", "hooks.json");
    const configPath = join(b.home, ".codex", "config.toml");
    mkdirSync(join(b.home, ".codex"), { recursive: true });
    writeFileSync(hooksPath, JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "mine" }] }] } }));
    const mine = codexTrustHash("PreToolUse", "Bash", { type: "command", command: "mine" });
    writeFileSync(configPath, `model = "x"\n\n[hooks.state."${hooksPath}:pre_tool_use:0:0"]\ntrusted_hash = "${mine}"\n`);
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings });
    const config = readFileSync(configPath, "utf8");
    expect(config).toContain('model = "x"');
    expect(config).toContain(`[hooks.state."${hooksPath}:pre_tool_use:1:0"]\ntrusted_hash = "${mine}"`);
    const settings = JSON.parse(readFileSync(hooksPath, "utf8")) as Record<string, unknown>;
    expect(trustStatus(config, hooksPath, settings)).toEqual({ trusted: ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"], untrusted: [], modified: [] });
    expect(find(doctor(b.l, b.ws, { home: b.home, platform: "darwin", findBinary: () => null }), "Codex hook trust")[0]?.status).toBe("ok");
    uninstall(b.l, { agent: "codex", settings: codexAdapter.settings, home: b.home });
    const after = readFileSync(configPath, "utf8");
    expect(after).toContain(`[hooks.state."${hooksPath}:pre_tool_use:0:0"]\ntrusted_hash = "${mine}"`);
    expect(after).not.toContain("pre_tool_use:1:0");
    expect(after).not.toContain("post_tool_use");
  });
  it("a hook changed by hand is reported as no longer trusted (Codex would skip it)", () => {
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings });
    const p = join(b.home, ".codex", "hooks.json");
    writeFileSync(p, readFileSync(p, "utf8").replaceAll('"timeout": 600', '"timeout": 601'));
    const c = find(doctor(b.l, b.ws, { home: b.home, platform: "darwin", findBinary: () => null }), "Codex hook trust")[0];
    expect(c?.status).toBe("fail");
    expect(c?.detail).toMatch(/changed since it was trusted/);
  });
  it("an approver re-pin updates the recorded trust with the new command", () => {
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings });
    initApprover(b.l, "a long approval passphrase");
    repinApprover(b.l, (id) => adapterFor(id).settings, b.home);
    const p = join(b.home, ".codex", "hooks.json");
    expect(readFileSync(p, "utf8")).toContain("LAUNCHSAFE_FIREWALL_APPROVER=");
    expect(trustStatus(readFileSync(join(b.home, ".codex", "config.toml"), "utf8"), p, JSON.parse(readFileSync(p, "utf8")) as Record<string, unknown>).modified).toEqual([]);
  });
  it("a hooks.json that starts with a byte order mark keeps the person's own trust through install, a re-pin and uninstall", () => {
    const hooksPath = join(b.home, ".codex", "hooks.json");
    const configPath = join(b.home, ".codex", "config.toml");
    mkdirSync(join(b.home, ".codex"), { recursive: true });
    const withMark = (): void => writeFileSync(hooksPath, `\uFEFF${readFileSync(hooksPath, "utf8")}`);
    writeFileSync(hooksPath, JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "mine" }] }] } }));
    withMark();
    const mine = codexTrustHash("PreToolUse", "Bash", { type: "command", command: "mine" });
    writeFileSync(configPath, `model = "x"\n\n[hooks.state."${hooksPath}:pre_tool_use:0:0"]\ntrusted_hash = "${mine}"\n`);
    // The person's hook moves behind the firewall's, and its trust moves with it (the hooks file before the write is read after the mark).
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings });
    expect(readFileSync(configPath, "utf8")).toContain(`[hooks.state."${hooksPath}:pre_tool_use:1:0"]\ntrusted_hash = "${mine}"`);
    withMark();
    initApprover(b.l, "a long approval passphrase");
    expect(repinApprover(b.l, (id) => adapterFor(id).settings, b.home).updated).toEqual([hooksPath]);
    expect(readFileSync(configPath, "utf8")).toContain(`[hooks.state."${hooksPath}:pre_tool_use:1:0"]\ntrusted_hash = "${mine}"`);
    withMark();
    uninstall(b.l, { agent: "codex", settings: codexAdapter.settings, home: b.home });
    const after = readFileSync(configPath, "utf8");
    expect(after).toContain(`[hooks.state."${hooksPath}:pre_tool_use:0:0"]\ntrusted_hash = "${mine}"`);
    expect(after).not.toContain("pre_tool_use:1:0");
  });
  it("the config.toml backup is the file as it was, a leading byte order mark included", () => {
    const configPath = join(b.home, ".codex", "config.toml");
    mkdirSync(join(b.home, ".codex"), { recursive: true });
    const original = '\uFEFFmodel = "x"\n';
    writeFileSync(configPath, original);
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings });
    expect(readFileSync(configPath, "utf8")).toContain('model = "x"');
    const backups = readdirSync(b.l.backups)
      .filter((n) => n.endsWith("-codex-config.toml.json"))
      .map((n) => JSON.parse(readFileSync(join(b.l.backups, n), "utf8")) as { path: string; existed: boolean; content: string | null });
    expect(backups).toEqual([{ path: configPath, existed: true, content: original }]);
  });
  it("the agent may not grant or revoke Codex hook trust (FW-TAMPER)", () => {
    const cfg = join(b.ws, ".codex", "config.toml");
    mkdirSync(join(b.ws, ".codex"), { recursive: true });
    writeFileSync(cfg, 'model = "x"\n');
    const r = send(b, "codex", { hook_event_name: "PreToolUse", tool_name: "apply_patch", tool_input: { command: `*** Begin Patch\n*** Update File: .codex/config.toml\n@@\n model = "x"\n+[hooks.state."/x/hooks.json:pre_tool_use:0:0"]\n+trusted_hash = "sha256:00"\n*** End Patch\n` } });
    expect(verdict("codex", r)).toBe("deny");
    expect(rules("codex", r)).toContain("FW-TAMPER");
  });
  it("doctor fails a project that switches Codex hooks off, and one that switches Gemini CLI hooks off", () => {
    mkdirSync(join(b.ws, ".codex"), { recursive: true });
    writeFileSync(join(b.ws, ".codex", "config.toml"), "[features]\nhooks = false\n");
    mkdirSync(join(b.ws, ".gemini"), { recursive: true });
    writeFileSync(join(b.ws, ".gemini", "settings.json"), JSON.stringify({ hooksConfig: { disabled: ["launchsafe-firewall"] } }));
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings });
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "gemini", settings: geminiAdapter.settings });
    const cs = doctor(b.l, b.ws, { home: b.home, platform: "darwin", findBinary: () => null });
    expect(find(cs, "Codex project hooks")[0]?.status).toBe("fail");
    expect(find(cs, "Gemini CLI project settings")[0]?.status).toBe("fail");
  });
});

describe("install: registration checks, the agent's own step, JSONC settings", () => {
  const claudePath = (): string => join(b.home, ".claude", "settings.json");
  const rewriteCommands = (path: string, f: (c: string) => string): void => {
    const doc = JSON.parse(readFileSync(path, "utf8")) as { hooks: Record<string, { hooks: { command: string }[] }[]> };
    for (const groups of Object.values(doc.hooks)) for (const g of groups) for (const h of g.hooks) if (h.command.includes("LAUNCHSAFE_FIREWALL_HOOK")) h.command = f(h.command);
    writeFileSync(path, JSON.stringify(doc));
  };
  const problems = (): string => checkHookRegistration(b.l, b.ws, b.home, (id) => adapterFor(id).settings).join(" | ");

  it("a hook that keeps the marker but no longer runs the firewall, or no longer fails closed, is a problem", () => {
    install(b.l, "user", b.ws, "t", { home: b.home });
    expect(problems()).not.toMatch(/no longer/);
    rewriteCommands(claudePath(), (c) => c.replace(/ \|\| exit 2$/, ""));
    expect(problems()).toMatch(/no longer fails closed/);
    rewriteCommands(claudePath(), () => "LAUNCHSAFE_FIREWALL_HOOK=1 true");
    expect(problems()).toMatch(/PreToolUse.*no longer runs the firewall/);
  });

  it("when the agent's own step fails, the settings file and the install record are put back", () => {
    const path = join(b.home, ".codex", "hooks.json");
    mkdirSync(join(b.home, ".codex"), { recursive: true });
    const original = JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "mine" }] }] } });
    writeFileSync(path, original);
    const failing = { ...codexAdapter.settings, afterWrite: () => { throw new Error("hook trust could not be recorded"); } };
    expect(() => install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: failing })).toThrow(/hook trust could not be recorded/);
    expect(readFileSync(path, "utf8")).toBe(original);
    expect(readRecords(b.l)).toEqual([]);
  });

  it("Gemini settings with comments are read for checks but never rewritten (the comments would be lost)", () => {
    const path = join(b.home, ".gemini", "settings.json");
    mkdirSync(join(b.home, ".gemini"), { recursive: true });
    const commented = '// my settings\n{ "ui": { "theme": "dark" } }\n';
    writeFileSync(path, commented);
    expect(() => install(b.l, "user", b.ws, "t", { home: b.home, agent: "gemini", settings: geminiAdapter.settings })).toThrow(/comments or trailing commas/);
    expect(readFileSync(path, "utf8")).toBe(commented);
    expect(readRecords(b.l)).toEqual([]);
    // A file installed into, then commented by the person, still reads: ConfigChange does not report it unreadable.
    writeFileSync(path, "{}");
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "gemini", settings: geminiAdapter.settings });
    writeFileSync(path, `// mine\n${readFileSync(path, "utf8")}`);
    expect(problems()).not.toMatch(/cannot be read/);
  });
});
