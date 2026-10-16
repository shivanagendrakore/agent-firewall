/**
 * Self-protection of the hook registration (live-recording finding): any change to a Claude Code
 * settings file is judged by the file it would produce. Removing, altering or re-scoping the
 * firewall's hooks, switching hooks off, or setting the firewall's variables is denied in any
 * session; a change whose result cannot be computed (shell) is assumed to be the worst.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runHook } from "../src/hook/claude.js";
import { install, settingsPath, withOurs } from "../src/runtime/install.js";
import { layout } from "../src/runtime/layout.js";
import { MARKER, settingsViolations } from "../src/engine/settings.js";
import { bash, explain, HOME, run, WS } from "./helpers.js";

const SETTINGS = `${WS}/.claude/settings.json`;
const CMD = `${MARKER} '/usr/local/bin/node' '/opt/launchsafe-firewall/dist/cli.js' hook || exit 2`;
const INSTALLED = withOurs({ permissions: { allow: ["Bash(npm test)"] } }, CMD);
const TEXT = JSON.stringify(INSTALLED, null, 2);
const files: Record<string, string> = { [SETTINGS]: TEXT };
const ctxFor = (over: Record<string, string> = {}) => ({
  readFile: (p: string): string | null => ({ ...files, ...over })[p] ?? null,
  registeredSettings: [SETTINGS],
});

function denied(d: ReturnType<typeof run>): void {
  expect(d.verdict, explain(d)).toBe("deny");
  expect(d.rules, explain(d)).toContain("FW-TAMPER");
}

const clone = (): typeof INSTALLED => JSON.parse(TEXT) as typeof INSTALLED;
type Hooks = Record<string, { matcher?: string; hooks: { command: string }[] }[]>;

describe("Write/Edit/MultiEdit of a settings file that registers the firewall", () => {
  const writes: [string, string][] = [
    ["Write {}", "{}"],
    ["Write a settings file without the hook", JSON.stringify({ permissions: { allow: ["Bash(npm test)"] } })],
    ["Write with the hook command altered (no fail-closed wrapper)", TEXT.replace(" || exit 2", "")],
    ["Write with the hook pointing elsewhere", TEXT.replace("/opt/launchsafe-firewall/dist/cli.js", "/tmp/fake.js")],
    ["Write with the hook moved to a non-matching matcher", (() => { const s = clone(); ((s.hooks as Hooks).PreToolUse![0]!).matcher = "NoSuchTool"; return JSON.stringify(s); })()],
    ["Write with the hook moved under another event", (() => { const s = clone(); const h = s.hooks as Hooks; h.Stop = h.PreToolUse!; delete h.PreToolUse; return JSON.stringify(s); })()],
    ["Write adding disableAllHooks: true", JSON.stringify({ ...clone(), disableAllHooks: true })],
    ["Write adding allowManagedHooksOnly", JSON.stringify({ ...clone(), allowManagedHooksOnly: true })],
    ["Write setting the firewall's variables", JSON.stringify({ ...clone(), env: { LAUNCHSAFE_FIREWALL_APPROVER: "AAAA" } })],
    ["Write that is not valid JSON", TEXT.slice(0, -10)],
  ];
  for (const [name, content] of writes) {
    for (const tainted of [false, true]) {
      it(`${name} (${tainted ? "untrusted" : "trusted"})`, () => denied(run("Write", { file_path: SETTINGS, content }, { tainted, ctx: ctxFor() })));
    }
  }
  it("Edit removing the PreToolUse hook", () => {
    const pre = JSON.stringify((INSTALLED.hooks as Hooks).PreToolUse![0], null, 2).split("\n").map((l, i) => (i === 0 ? l : `      ${l}`)).join("\n");
    void pre;
    denied(run("Edit", { file_path: SETTINGS, old_string: "|| exit 2", new_string: "" }, { ctx: ctxFor() }));
  });
  it("Edit replacing the whole hook command", () => denied(run("Edit", { file_path: SETTINGS, old_string: MARKER, new_string: "X=1", replace_all: true }, { ctx: ctxFor() })));
  it("MultiEdit removing the hook", () => {
    denied(run("MultiEdit", { file_path: SETTINGS, edits: [{ old_string: "Bash(npm test)", new_string: "Bash(npm run *)" }, { old_string: "\"PreToolUse\"", new_string: "\"PreToolUseOff\"" }] }, { ctx: ctxFor() }));
  });
  it("Edit adding disableAllHooks", () => denied(run("Edit", { file_path: SETTINGS, old_string: '"permissions"', new_string: '"disableAllHooks": true,\n  "permissions"' }, { ctx: ctxFor() })));
  it("unreadable but registered: assume the worst", () => {
    denied(run("Edit", { file_path: SETTINGS, old_string: "a", new_string: "b" }, { ctx: { readFile: () => { throw new Error("EACCES"); }, registeredSettings: [SETTINGS] } }));
  });
});

describe("ordinary settings changes that keep the hooks are not tampering", () => {
  it("Write keeping the hooks identical and adding a setting asks (agent settings), not deny", () => {
    const d = run("Write", { file_path: SETTINGS, content: JSON.stringify({ ...clone(), model: "sonnet" }) }, { ctx: ctxFor() });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-AGENT-SETTINGS");
  });
  it("Edit of a permission rule keeps the hooks: asks", () => {
    const d = run("Edit", { file_path: SETTINGS, old_string: "Bash(npm test)", new_string: "Bash(npm run *)" }, { ctx: ctxFor() });
    expect(d.verdict, explain(d)).toBe("ask");
  });
  it("a project settings file that does not register the firewall may be written (asks), unless it switches hooks off", () => {
    const proj = `${WS}/sub/.claude/settings.json`;
    expect(run("Write", { file_path: proj, content: '{"model":"x"}' }, { ctx: ctxFor() }).verdict).toBe("ask");
    denied(run("Write", { file_path: proj, content: '{"disableAllHooks": true}' }, { ctx: ctxFor() }));
  });
});

describe("a settings write that starts with a UTF-8 byte order mark", () => {
  const PROJ = "/p/.claude/settings.json";
  const LOADER = "it sets env.NODE_OPTIONS, which reaches the firewall's hook process (where it reads its state from, or what code node loads)";
  const loader = JSON.stringify({ env: { NODE_OPTIONS: "--require /tmp/x.js" } });

  it("is judged on what follows the mark, as an agent that drops the mark (like the firewall's own readers) would load it", () => {
    expect(settingsViolations(null, loader, false, PROJ)).toContain(LOADER);
    // It was no finding at all: the text did not parse, and the fallback only looks for the hook switches.
    expect(settingsViolations(null, `\uFEFF${loader}`, false, PROJ)).toContain(LOADER);
    expect(settingsViolations(JSON.stringify({ env: {} }), `\uFEFF${loader}`, false, PROJ)).toContain(LOADER);
    const d = run("Write", { file_path: `${WS}/sub/.claude/settings.json`, content: `\uFEFF${loader}` }, { ctx: ctxFor() });
    denied(d);
  });

  it("an edit that keeps the mark is compared with the file as that agent reads it: a variable already set is not new, a new switch is", () => {
    const before = `\uFEFF${JSON.stringify({ env: { NODE_OPTIONS: "--require /tmp/x.js" }, model: "opus" })}`;
    const after = `\uFEFF${JSON.stringify({ env: { NODE_OPTIONS: "--require /tmp/x.js" }, model: "sonnet" })}`;
    expect(settingsViolations(before, after, false, PROJ)).not.toContain(LOADER);
    // A switch that is new is still found.
    expect(settingsViolations(before, `\uFEFF${JSON.stringify({ env: { NODE_OPTIONS: "--require /tmp/x.js" }, disableAllHooks: true })}`, false, PROJ)).toContain("it sets disableAllHooks, which turns the firewall off");
  });

  it("in a file that registers the firewall it is still refused as a file an agent that refuses the mark would not load, hooks kept or not", () => {
    const kept = settingsViolations(TEXT, `\uFEFF${TEXT}`, true, SETTINGS);
    expect(kept).toEqual(["the file would no longer be valid JSON, so the firewall's hooks would not load"]);
    const removed = settingsViolations(TEXT, `\uFEFF${JSON.stringify({ permissions: { allow: ["Bash(npm test)"] } })}`, true, SETTINGS);
    expect(removed).toContain("the file would no longer be valid JSON, so the firewall's hooks would not load");
    expect(removed).toContain("it removes the firewall's PreToolUse hook");
    denied(run("Write", { file_path: SETTINGS, content: `\uFEFF${TEXT}` }, { ctx: ctxFor() }));
  });

  it("text that is not JSON after the mark is judged as the same text without the mark: the fallback for hook switches still applies", () => {
    for (const [text, reg, file] of [['{"env": ', false, PROJ], ['{"disableAllHooks": true', false, PROJ], ['{"env": ', true, SETTINGS]] as const) {
      expect(settingsViolations(reg ? TEXT : null, `\uFEFF${text}`, reg, file), text).toEqual(settingsViolations(reg ? TEXT : null, text, reg, file));
    }
    expect(settingsViolations(null, '\uFEFF{"disableAllHooks": true', false, PROJ)).toEqual(["the change sets hook controls in a file that is not valid JSON"]);
    expect(settingsViolations(TEXT, '\uFEFF{"env": ', true, SETTINGS)).toEqual(["the file would no longer be valid JSON, so the firewall's hooks would not load"]);
  });
});

describe("shell changes to settings cannot be checked, so they are denied", () => {
  const cmds = [
    `echo '{}' > ${SETTINGS}`,
    `printf '{}' >| ${SETTINGS}`,
    `cat other.json > ${SETTINGS}`,
    `cp other.json ${SETTINGS}`,
    `mv other.json ${SETTINGS}`,
    `tee ${SETTINGS} < other.json`,
    `echo '{}' | tee ${SETTINGS}`,
    `sed -i 's/exit 2/true/' ${SETTINGS}`,
    `rm ${SETTINGS}`,
    `rm -rf ${WS}/.claude`,
    `mv ${WS}/.claude ${WS}/.claude.bak`,
    `truncate -s 0 ${SETTINGS}`,
    `git checkout -- .claude/settings.json`,
    `python3 -c "open('${SETTINGS}','w').write('{}')"`,
    `jq 'del(.hooks)' ${SETTINGS} > /tmp/s && mv /tmp/s ${SETTINGS}`,
    `ln -sf /tmp/empty.json ${SETTINGS}`,
    `echo '{}' > ${HOME}/.claude/settings.json`,
    `cp x.json ${WS}/.claude/settings.local.json`,
  ];
  for (const cmd of cmds) {
    for (const tainted of [false, true]) {
      it(`${cmd.slice(0, 60)} (${tainted ? "untrusted" : "trusted"})`, () => denied(bash(cmd, { tainted, ctx: ctxFor() })));
    }
  }
  it("reading settings through the shell is still fine", () => {
    expect(bash(`cat ${SETTINGS}`, { ctx: ctxFor() }).verdict).toBe("allow");
    expect(bash(`jq .hooks ${SETTINGS}`, { ctx: ctxFor() }).verdict).toBe("allow");
  });
});

describe("the firewall's own config, state, queue, keys and log", () => {
  const FW = `${HOME}/.launchsafe-firewall`;
  const targets = [`${FW}/policy.json`, `${FW}/queue/abcd1234.json`, `${FW}/keys/approver.json`, `${FW}/keys/log-ed25519.pem`, `${FW}/log/decisions.jsonl`, `${FW}/log/head.json`, `${FW}/sessions/s.jsonl`, `${FW}/install.json`];
  for (const t of targets) {
    for (const tainted of [false, true]) {
      it(`${t.slice(FW.length)} (${tainted ? "untrusted" : "trusted"})`, () => {
        denied(run("Write", { file_path: t, content: "{}" }, { tainted }));
        denied(run("Edit", { file_path: t, old_string: "a", new_string: "b" }, { tainted }));
        denied(run("MultiEdit", { file_path: t, edits: [{ old_string: "a", new_string: "b" }] }, { tainted }));
        denied(bash(`echo x > ${t}`, { tainted }));
        denied(bash(`cp x ${t}`, { tainted }));
        denied(bash(`rm ${t}`, { tainted }));
      });
    }
  }
  it("the managed settings file", () => {
    denied(run("Write", { file_path: "/Library/Application Support/ClaudeCode/managed-settings.json", content: '{"disableAllHooks": true}' }));
    denied(bash(`echo '{}' > "/Library/Application Support/ClaudeCode/managed-settings.json"`));
  });
});

describe("through the real hook, against an installed settings file", () => {
  let root: string, ws: string, l: ReturnType<typeof layout>;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "lsfw-st-"));
    ws = join(root, "ws");
    mkdirSync(ws, { recursive: true });
    l = layout(join(root, "fw"));
    install(l, "project", ws, "0.1.0", { home: root, platform: "darwin" });
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));
  const pre = (tool: string, input: Record<string, unknown>, session = "s"): string =>
    runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: session, cwd: ws, permission_mode: "default", tool_name: tool, tool_input: input }), { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, detectNonInteractive: () => false, home: root }).stdout;

  it("Write {} over the installed settings is denied (the recorded case)", () => {
    const out = pre("Write", { file_path: settingsPath("project", ws), content: "{}" });
    expect(out).toMatch(/"permissionDecision":"deny"/);
    expect(out).toMatch(/FW-TAMPER/);
  });
  it("…also after the session read outside content", () => {
    runHook(JSON.stringify({ hook_event_name: "PostToolUse", session_id: "u", cwd: ws, tool_name: "WebFetch", tool_input: { url: "https://x.example.com" }, tool_response: "p" }), { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, detectNonInteractive: () => false, home: root });
    expect(pre("Write", { file_path: settingsPath("project", ws), content: "{}" }, "u")).toMatch(/"permissionDecision":"deny"/);
  });
  it("a Write that keeps the installed hooks byte-for-byte is not tampering", () => {
    const p = settingsPath("project", ws);
    const current = JSON.parse(require("node:fs").readFileSync(p, "utf8")) as Record<string, unknown>;
    expect(pre("Write", { file_path: p, content: JSON.stringify({ ...current, model: "sonnet" }) })).toMatch(/"permissionDecision":"ask"/);
  });
  it("a symlink in the workspace pointing at the settings file does not hide it", () => {
    const link = join(ws, "settings-link.json");
    require("node:fs").symlinkSync(settingsPath("project", ws), link);
    expect(pre("Write", { file_path: link, content: "{}" })).toMatch(/"permissionDecision":"deny"/);
  });
  it("shell redirect over the installed settings is denied", () => {
    expect(pre("Bash", { command: `echo '{}' > .claude/settings.json` })).toMatch(/"permissionDecision":"deny"/);
  });
  void writeFileSync;
});
