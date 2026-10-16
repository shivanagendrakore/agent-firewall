/**
 * Lifecycle 1: install. The real built CLI, in a fresh temporary home per test (see lab.ts), for every agent.
 * Fresh install writes exactly the documented entries and keeps the person's own settings; install twice changes nothing;
 * doctor and status say the truth before and after.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { AGENTS, CLI, assertTempHome, json, lab, ourEntryCount, readOrNull, run, tree, write, type Agent, type Lab } from "./lab.js";
import { CODEX_TOML, SPECS, ourEntries, seed, userText, withoutOurs } from "./agents.js";

let l: Lab;
beforeEach(() => {
  l = lab();
});
afterEach(() => l.cleanup());

/** Doctor's check for the agent's user-scope hooks. */
function hooksCheck(a: Agent): { status: string; detail: string } | undefined {
  const name = a === "claude" ? "hooks (user)" : `${SPECS[a].label} hooks (user)`;
  const checks = JSON.parse(run(l, ["doctor", "--json"]).stdout) as { name: string; status: string; detail: string }[];
  return checks.find((c) => c.name === name);
}

function install(a: Agent, extra: string[] = []) {
  return run(l, ["install", "--agent", a, "--no-approver", ...extra]);
}

describe("the lab itself", () => {
  it("runs under the OS temp dir with every agent directory inside the temporary home", () => {
    assertTempHome(l.home);
    for (const k of ["HOME", "CLAUDE_CONFIG_DIR", "CODEX_HOME", "GEMINI_CLI_HOME", "LAUNCHSAFE_FIREWALL_HOME", "XDG_CONFIG_HOME"]) expect((l.env[k] as string).startsWith(l.home)).toBe(true);
    expect(l.env.LAUNCHSAFE_FIREWALL_TEST).toBe("1");
    expect(l.env.CLAUDECODE).toBeUndefined();
  });
});

describe.each(AGENTS)("install: %s", (a) => {
  const spec = SPECS[a];

  it("writes exactly the documented entries and keeps the person's own settings", () => {
    seed(l, a, write);
    const before = tree(l.home);
    const r = install(a);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain(`Installed (${spec.label})`);

    const doc = json(l.file(a));
    const ours = ourEntries(doc);
    // One entry per documented event, no more, no fewer, none on an event the adapter does not register.
    expect(ours.map(([ev]) => ev).sort()).toEqual([...spec.events].sort());
    const hooks = doc.hooks as Record<string, Record<string, unknown>[]>;
    for (const ev of spec.events) {
      const first = (hooks[ev] as Record<string, unknown>[])[0] as Record<string, unknown>;
      const entry = (spec.flat ? first : (first.hooks as Record<string, unknown>[])[0]) as Record<string, unknown>;
      expect(String(entry.command).startsWith("LAUNCHSAFE_FIREWALL_HOOK=1 "), `${ev} is first in order`).toBe(true);
      expect(entry.command).toContain(`'${process.execPath}' '${CLI}' hook`);
      expect(entry.command).toMatch(spec.tail);
      expect(entry.type).toBe("command");
      expect(entry.timeout).toBe(spec.timeout);
      if (spec.matched.includes(ev)) expect(first.matcher).toBe("*");
      else expect(first.matcher).toBeUndefined();
      if (a === "gemini") expect(entry.name).toBe("launchsafe-firewall");
      if (a === "cursor") expect(entry.failClosed).toBe(true);
      if (a === "claude") expect(entry.onFailure).toBe("block");
      // I1: every installed command pins the data directory and clears the loader variables; all but managed pin HOME.
      expect(entry.command).toContain(`LAUNCHSAFE_FIREWALL_HOME='${l.env.LAUNCHSAFE_FIREWALL_HOME as string}'`);
      expect(entry.command).toContain(` HOME='${l.env.HOME as string}'`);
      expect(entry.command).toContain(" NODE_OPTIONS= NODE_PATH= LD_PRELOAD= DYLD_INSERT_LIBRARIES= ");
    }

    // Everything the person had is still there, in the same order, byte for byte once the firewall's entries and its documented
    // enable flag are taken out.
    expect(JSON.stringify(spec.stripEnable(withoutOurs(doc)), null, 2)).toBe(JSON.stringify(spec.user(), null, 2));
    // The person's hook on an event the firewall also uses stays, after the firewall's (the firewall decides first).
    const userHooks = (spec.user().hooks as Record<string, unknown[]>)[spec.id === "gemini" ? "BeforeTool" : spec.id === "cursor" ? "preToolUse" : "PreToolUse"] as unknown[];
    const evName = spec.id === "gemini" ? "BeforeTool" : spec.id === "cursor" ? "preToolUse" : "PreToolUse";
    expect((hooks[evName] as unknown[]).slice(1)).toEqual(userHooks);

    // The documented extra: Gemini CLI needs hooksConfig.enabled, Cursor needs a version; nothing else changes in the file.
    if (a === "gemini") expect(doc.hooksConfig).toEqual({ enabled: true });
    if (a === "cursor") expect(doc.version).toBe(1);

    // Nothing outside the agent's file, the firewall's own directory and (Codex) the hook trust record was touched.
    const after = tree(l.home);
    const changed = Object.keys({ ...before, ...after }).filter((k) => before[k] !== after[k]);
    const expected = [join(".", relativeAgentFile(a)).replace(/^\.\//, ""), ...(a === "codex" ? [".codex/config.toml"] : [])];
    expect(changed.sort()).toEqual(expected.sort());

    // The backup holds the person's file exactly as it was.
    const rec = JSON.parse(readFileSync(join(l.fwHome, "install.json"), "utf8")) as { path: string; backup: string; scope: string }[];
    expect(rec).toHaveLength(1);
    expect(rec[0]?.path).toBe(l.file(a));
    expect(rec[0]?.scope).toBe("user");
    const backup = JSON.parse(readFileSync(rec[0]?.backup as string, "utf8")) as { path: string; existed: boolean; content: string };
    expect(backup).toEqual({ path: l.file(a), existed: true, content: userText(a) });
  });

  it("creates the file when the person has none, and doctor then reports it protected", () => {
    expect(existsSync(l.file(a))).toBe(false);
    // Before install: Claude Code (the default) is reported as unprotected; an agent the person never installed for is not checked.
    if (a === "claude") expect((JSON.parse(run(l, ["doctor", "--json"]).stdout) as { name: string; status: string }[]).find((c) => c.name === "hooks")?.status).toBe("fail");
    else expect(hooksCheck(a)).toBeUndefined();
    const r = install(a);
    expect(r.code, r.stderr).toBe(0);
    expect(ourEntries(json(l.file(a))).map(([ev]) => ev).sort()).toEqual([...spec.events].sort());
    const c = hooksCheck(a);
    expect(c?.status, c?.detail).toBe("ok");
    expect(c?.detail).toContain(`all ${spec.events.length} events, first in order, exit-2 wrapper present (an agent that runs the tool when a hook times out is not covered: docs/limitations.md)`);
    const rec = JSON.parse(readFileSync(join(l.fwHome, "install.json"), "utf8")) as { backup: string }[];
    expect(JSON.parse(readFileSync(rec[0]?.backup as string, "utf8"))).toEqual({ path: l.file(a), existed: false, content: null });
  });

  it("is idempotent: a second install changes no byte, adds no entry and keeps the first backup", () => {
    seed(l, a, write);
    install(a);
    const afterFirst = tree(l.home);
    const recordsFirst = readFileSync(join(l.fwHome, "install.json"), "utf8");
    const backupsFirst = readdirSync(join(l.fwHome, "backups")).sort();
    const second = install(a);
    expect(second.code, second.stderr).toBe(0);
    expect(second.stdout).toContain("Already installed");
    expect(tree(l.home)).toEqual(afterFirst);
    expect(ourEntryCount(readOrNull(l.file(a)))).toBe(spec.events.length);
    const recordsSecond = JSON.parse(readFileSync(join(l.fwHome, "install.json"), "utf8")) as { backup: string }[];
    expect(recordsSecond).toHaveLength(1);
    expect(readdirSync(join(l.fwHome, "backups")).sort()).toEqual(backupsFirst);
    expect(JSON.parse(recordsFirst)[0].backup).toBe(recordsSecond[0]?.backup);
    expect(JSON.parse(readFileSync(recordsSecond[0]?.backup as string, "utf8")).content).toBe(userText(a));
    if (a === "codex") expect(readOrNull(join(l.home, ".codex", "config.toml"))).toBe(afterFirst[".codex/config.toml"]);
  });

  it("repairs a file where the person deleted one of the firewall's hooks, without duplicating the others, and doctor sees both states", () => {
    install(a);
    const doc = json(l.file(a));
    const hooks = doc.hooks as Record<string, unknown[]>;
    const victim = spec.events[1] as string;
    delete hooks[victim];
    write(l.file(a), `${JSON.stringify(doc, null, 2)}\n`);
    const broken = hooksCheck(a);
    expect(broken?.status).not.toBe("ok");
    expect(broken?.detail).toContain(victim);
    install(a);
    expect(ourEntries(json(l.file(a))).map(([ev]) => ev).sort()).toEqual([...spec.events].sort());
    expect(hooksCheck(a)?.status).toBe("ok");
  });

  it("collapses duplicate firewall entries left by hand into one per event", () => {
    install(a);
    const doc = json(l.file(a));
    const hooks = doc.hooks as Record<string, unknown[]>;
    for (const ev of spec.events) hooks[ev] = [...(hooks[ev] as unknown[]), ...(hooks[ev] as unknown[])];
    write(l.file(a), `${JSON.stringify(doc, null, 2)}\n`);
    expect(ourEntryCount(readOrNull(l.file(a)))).toBe(spec.events.length * 2);
    install(a);
    expect(ourEntryCount(readOrNull(l.file(a)))).toBe(spec.events.length);
  });

  it("status names the settings file once installed, and says 'nowhere' before", () => {
    const s0 = JSON.parse(run(l, ["status", "--json"]).stdout) as { installedIn: string[] };
    expect(s0.installedIn).toEqual([]);
    install(a);
    const s1 = JSON.parse(run(l, ["status", "--json"]).stdout) as { installedIn: string[] };
    expect(s1.installedIn).toEqual([`user (${l.file(a)})`]);
    expect(run(l, ["status"]).stdout).toMatch(/Installed in:/);
  });

  it("uses the project scope file when asked, and leaves the user file alone", () => {
    if (a === "claude" || a === "codex" || a === "gemini" || a === "cursor") {
      const r = install(a, ["--scope", "project", "--project", l.proj]);
      expect(r.code, r.stderr).toBe(0);
      expect(existsSync(l.file(a))).toBe(false);
      const projFile = { claude: ".claude/settings.json", codex: ".codex/hooks.json", gemini: ".gemini/settings.json", cursor: ".cursor/hooks.json" }[a];
      expect(ourEntryCount(readOrNull(join(l.proj, projFile)))).toBe(spec.events.length);
      const c = (JSON.parse(run(l, ["doctor", "--json", "--project", l.proj]).stdout) as { name: string; status: string }[]).find((x) => /hooks \(project\)/.test(x.name));
      expect(c?.status).toBe("ok");
    }
  });
});

describe("install: all agents in one home", () => {
  it("each agent's file gets only its own hooks, each with its own command, and one record each", () => {
    for (const a of AGENTS) seed(l, a, write);
    for (const a of AGENTS) expect(install(a).code).toBe(0);
    for (const a of AGENTS) {
      const doc = json(l.file(a));
      expect(ourEntries(doc).map(([ev]) => ev).sort()).toEqual([...SPECS[a].events].sort());
      for (const [, e] of ourEntries(doc)) expect(String(e.command)).toMatch(SPECS[a].tail);
    }
    const rec = JSON.parse(readFileSync(join(l.fwHome, "install.json"), "utf8")) as { agent?: string; path: string }[];
    expect(rec.map((r) => r.agent ?? "claude").sort()).toEqual([...AGENTS].sort());
    expect(readFileSync(join(l.home, ".codex", "config.toml"), "utf8").startsWith(CODEX_TOML.trimEnd())).toBe(true);
    const checks = JSON.parse(run(l, ["doctor", "--json"]).stdout) as { name: string; status: string }[];
    for (const n of ["hooks (user)", "Codex hooks (user)", "Gemini CLI hooks (user)", "Cursor hooks (user)"]) expect(checks.find((c) => c.name === n)?.status, n).toBe("ok");
  });
});

function relativeAgentFile(a: Agent): string {
  return { claude: ".claude/settings.json", codex: ".codex/hooks.json", gemini: ".gemini/settings.json", cursor: ".cursor/hooks.json" }[a];
}
