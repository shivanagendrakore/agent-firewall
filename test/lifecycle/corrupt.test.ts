/**
 * Lifecycle 3: files that are not what the firewall expects. Install on a corrupted or odd settings file must lose nothing
 * (refuse and leave the file alone, or change it with the original kept in a backup), and doctor, status and uninstall must
 * stay usable and honest afterwards.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, readlinkSync, rmSync, statSync, symlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import { AGENTS, json, lab, ourEntryCount, person, readOrNull, run, tree, write, type Agent, type Lab } from "./lab.js";
import { CODEX_TOML, SPECS, seed, userText } from "./agents.js";

let l: Lab;
beforeEach(() => {
  l = lab();
});
afterEach(() => l.cleanup());

const install = (a: Agent) => run(l, ["install", "--agent", a, "--no-approver"]);

function hooksCheck(a: Agent): { status: string; detail: string } | undefined {
  const name = a === "claude" ? "hooks (user)" : `${SPECS[a].label} hooks (user)`;
  const checks = JSON.parse(run(l, ["doctor", "--json"]).stdout) as { name: string; status: string; detail: string }[];
  return checks.find((c) => c.name === name || (a === "claude" && c.name === "hooks"));
}

/** Whether `text` can still be found: in the file now, or in a backup the firewall made. */
function recoverable(a: Agent, text: string): boolean {
  if (readOrNull(l.file(a)) === text) return true;
  const dir = join(l.fwHome, "backups");
  if (!existsSync(dir)) return false;
  return readdirSync(dir).some((n) => {
    try {
      return (JSON.parse(readFileSync(join(dir, n), "utf8")) as { content?: string | null }).content === text;
    } catch {
      return false;
    }
  });
}

/** Files that cannot be a settings object: install refuses, the file is untouched, and no stack trace reaches the person. */
const REFUSED: [string, string][] = [
  ["truncated JSON", '{\n  "model": "opus",\n  "hooks": {\n    "PreToolUse": [\n'],
  ["not JSON at all", "model = opus\n"],
  ["an array", "[]\n"],
  ["null", "null\n"],
  ["a string", '"hello"\n'],
  ["a byte-order mark before something that is not an object", "\uFEFF[]\n"],
  ["a byte-order mark and then truncated JSON", '\uFEFF{"model": '],
  ["comments in the JSON", '{\n  // my model\n  "model": "opus"\n}\n'],
];

describe.each(AGENTS)("corrupted settings: %s", (a) => {
  const spec = SPECS[a];

  it.each(REFUSED)("refuses %s, exits non-zero, and leaves the file byte for byte (no state recorded)", (_n, text) => {
    write(l.file(a), text);
    const r = install(a);
    expect(r.code).not.toBe(0);
    expect(r.stderr).not.toMatch(/^\s+at /m);
    expect(readFileSync(l.file(a), "utf8")).toBe(text);
    expect(readOrNull(join(l.fwHome, "install.json")) ?? "[]").toBe("[]");
    expect(ourEntryCount(readOrNull(l.file(a)))).toBe(0);
  });

  // A person told only "Unexpected token" does not know which of their files it is about.
  it("names the file in the refusal (LC4: a JSON syntax error is reported without the path)", () => {
    write(l.file(a), '{"model": ');
    const r = install(a);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain(l.file(a));
  });

  // A Windows editor's byte-order mark is not damage: it was refused before, for three invisible bytes. The file is read, the hooks go in, and
  // the original (mark included) is what a restore puts back.
  it("reads a settings file that starts with a UTF-8 byte-order mark: the hooks are added, the settings kept, and --restore-backup returns the original byte for byte", () => {
    const original = `\uFEFF${JSON.stringify(spec.user(), null, 2)}\n`;
    write(l.file(a), original);
    const r = install(a);
    expect(r.code, r.stderr).toBe(0);
    expect(ourEntryCount(readOrNull(l.file(a)))).toBe(spec.events.length);
    const doc = json(l.file(a));
    for (const [k, v] of Object.entries(spec.user())) if (k !== "hooks") expect(doc[k], k).toEqual(v);
    // The person's own hooks are still there beside ours.
    for (const m of JSON.stringify(spec.user()).matchAll(/"command":"([^"]+)"/g)) expect(readFileSync(l.file(a), "utf8")).toContain(m[1] as string);
    expect(recoverable(a, original)).toBe(true);
    const restored = person(l, ["uninstall", "--agent", a, "--restore-backup"]);
    expect(restored.code, restored.output).toBe(0);
    expect(readFileSync(l.file(a), "utf8")).toBe(original);
  });

  it("a settings file that gained a byte-order mark after install still holds the hooks for doctor, and installing again leaves it alone", () => {
    seed(l, a, write);
    expect(install(a).code).toBe(0);
    const before = hooksCheck(a)?.status;
    expect(before).not.toBe("fail");
    const marked = `\uFEFF${readFileSync(l.file(a), "utf8")}`;
    write(l.file(a), marked);
    expect(hooksCheck(a)?.status).toBe(before);
    expect(install(a).code).toBe(0);
    expect(readFileSync(l.file(a), "utf8")).toBe(marked);
  });

  it("treats an empty file as no settings, and the empty original stays recoverable", () => {
    write(l.file(a), "");
    expect(install(a).code).toBe(0);
    expect(ourEntryCount(readOrNull(l.file(a)))).toBe(spec.events.length);
    expect(recoverable(a, "")).toBe(true);
  });

  const odd: [string, (hooksKey: string) => Record<string, unknown>][] = [
    ["hooks is an array", () => ({ keep: 1, hooks: [] })],
    ["an event's list is a string", (ev) => ({ keep: 1, hooks: { [ev]: "x", other: [{ command: "y" }] } })],
    ["an event's list is an object", (ev) => ({ keep: 1, hooks: { [ev]: { a: 1 }, other: [{ command: "y" }] } })],
  ];
  it.each(odd)("installs when %s, keeps every other key, and the malformed original is kept in a backup", (_n, build) => {
    const original = `${JSON.stringify(build(spec.events[0] as string), null, 2)}\n`;
    write(l.file(a), original);
    const r = install(a);
    expect(r.code, r.stderr).toBe(0);
    const doc = json(l.file(a));
    expect(doc.keep).toBe(1);
    expect(ourEntryCount(readOrNull(l.file(a)))).toBe(spec.events.length);
    expect(recoverable(a, original)).toBe(true);
  });

  it("a settings file truncated after install: doctor fails and names it, status still works, plain uninstall leaves the file alone and keeps the record, --restore-backup recovers", () => {
    seed(l, a, write);
    install(a);
    const damaged = readFileSync(l.file(a), "utf8").slice(0, 40);
    write(l.file(a), damaged);
    const d = run(l, ["doctor", "--json"]);
    expect(d.code).toBe(1);
    const c = hooksCheck(a);
    expect(c?.status).toBe("fail");
    expect(run(l, ["status"]).code).toBe(0);
    const plain = person(l, ["uninstall", "--agent", a]);
    expect(plain.code).not.toBe(0);
    expect(readFileSync(l.file(a), "utf8")).toBe(damaged);
    expect(JSON.parse(readFileSync(join(l.fwHome, "install.json"), "utf8"))).toHaveLength(1);
    const restored = person(l, ["uninstall", "--agent", a, "--restore-backup"]);
    expect(restored.code, restored.output).toBe(0);
    expect(readFileSync(l.file(a), "utf8")).toBe(userText(a));
  });

  it("a settings file deleted after install: doctor reports it, uninstall says nothing to do and drops the record", () => {
    seed(l, a, write);
    install(a);
    rmSync(l.file(a));
    expect(hooksCheck(a)?.status).not.toBe("ok");
    const r = person(l, ["uninstall", "--agent", a]);
    expect(r.code, r.output).toBe(0);
    expect(r.output).toContain("Nothing to do");
    expect(JSON.parse(readFileSync(join(l.fwHome, "install.json"), "utf8"))).toEqual([]);
  });
});

describe("corrupted firewall state", () => {
  // install.json is what uninstall, status and the hooks' self-protection read. When it is damaged every one of them stops with
  // the parser's own words and no file name, and the documented commands offer no repair.
  it("a damaged install.json is named by install, status and uninstall, and settings are not touched (LC5)", () => {
    write(l.file("claude"), '{"keep": 1}\n');
    write(join(l.fwHome, "install.json"), "garbage");
    for (const args of [["install", "--no-approver"], ["status"]]) {
      const r = run(l, args);
      expect(r.code).not.toBe(0);
      expect(r.stderr, args.join(" ")).toContain("install.json");
    }
    expect(readFileSync(l.file("claude"), "utf8")).toBe('{"keep": 1}\n');
  });

  it("doctor --repair-state moves a damaged install.json aside and rebuilds it from the settings files, and uninstall and status work again (LC5)", () => {
    seed(l, "claude", write);
    seed(l, "gemini", write);
    run(l, ["install", "--no-approver"]);
    run(l, ["install", "--agent", "gemini", "--no-approver"]);
    write(join(l.fwHome, "install.json"), "garbage");
    expect(run(l, ["status"]).code).not.toBe(0);
    const r = person(l, ["doctor", "--repair-state"]);
    expect(r.code, r.output).toBe(0);
    expect(r.output).toContain("install.json.damaged-");
    expect(readdirSync(l.fwHome).some((n) => n.startsWith("install.json.damaged-"))).toBe(true);
    const records = JSON.parse(readFileSync(join(l.fwHome, "install.json"), "utf8")) as { path: string; backup: string; agent?: string }[];
    expect(records.map((x) => x.path).sort()).toEqual([l.file("claude"), l.file("gemini")].sort());
    expect(records.every((x) => x.backup !== "")).toBe(true);
    expect(run(l, ["status"]).code).toBe(0);
    expect(person(l, ["uninstall", "--agent", "gemini", "--restore-backup"]).code).toBe(0);
    expect(readFileSync(l.file("gemini"), "utf8")).toBe(userText("gemini"));
    expect(person(l, ["uninstall"]).code).toBe(0);
    expect(ourEntryCount(readOrNull(l.file("claude")))).toBe(0);
  });

  it("doctor --repair-state on a readable install.json changes nothing", () => {
    run(l, ["install", "--no-approver"]);
    const before = readFileSync(join(l.fwHome, "install.json"), "utf8");
    const r = person(l, ["doctor", "--repair-state"]);
    expect(r.output).toContain("nothing to repair");
    expect(readFileSync(join(l.fwHome, "install.json"), "utf8")).toBe(before);
  });

  it("a damaged install.json leaves the person's settings untouched and doctor reports it as FAIL", () => {
    write(l.file("claude"), '{"keep": 1}\n');
    write(join(l.fwHome, "install.json"), "garbage");
    expect(run(l, ["install", "--no-approver"]).code).not.toBe(0);
    expect(readFileSync(l.file("claude"), "utf8")).toBe('{"keep": 1}\n');
    const checks = JSON.parse(run(l, ["doctor", "--json"]).stdout) as { name: string; status: string }[];
    expect(checks.find((c) => c.name === "install record")?.status).toBe("fail");
  });

  it("a non-array install.json is refused the same way", () => {
    run(l, ["install", "--no-approver"]);
    write(join(l.fwHome, "install.json"), '{"not":"a list"}');
    expect(run(l, ["install", "--no-approver"]).code).not.toBe(0);
    expect(run(l, ["doctor"]).stdout).toMatch(/FAIL\s+install record/);
  });

  it("a truncated decision log fails `log verify` and doctor, and the hooks keep deciding", () => {
    run(l, ["install", "--no-approver"]);
    for (let i = 0; i < 3; i++) run(l, ["hook"], { input: JSON.stringify({ hook_event_name: "PreToolUse", session_id: `s${i}`, cwd: l.proj, tool_name: "Bash", tool_input: { command: "ls" } }) });
    const ok = run(l, ["log", "verify"]);
    expect(ok.stdout, ok.stderr).toMatch(/^OK:/);
    const logFile = join(l.fwHome, "log", readdirSync(join(l.fwHome, "log")).find((n) => n.endsWith(".jsonl")) as string);
    const lines = readFileSync(logFile, "utf8").split("\n").filter((x) => x !== "");
    expect(lines.length).toBeGreaterThan(0);
    write(logFile, `${lines.slice(0, -1).join("\n")}\n${(lines.at(-1) as string).slice(0, 30)}\n`);
    const bad = run(l, ["log", "verify"]);
    expect(bad.code).not.toBe(0);
    expect(run(l, ["doctor"]).stdout).toMatch(/FAIL\s+decision log/);
    const h = run(l, ["hook"], { input: JSON.stringify({ hook_event_name: "PreToolUse", session_id: "after", cwd: l.proj, tool_name: "Bash", tool_input: { command: "ls" } }) });
    expect(h.code).not.toBe(1);
  });
});

describe("file system edge cases", () => {
  // LC6: install writes by rename, which replaces a symlink with a regular file: the person's dotfiles copy is left without the hooks and
  // the two drift apart (Cursor's own adapter refuses a symlinked hooks.json; the others do not say anything).
  it.each(["claude", "codex", "gemini"] as const)("%s: a settings file that is a symlink into the person's dotfiles stays a symlink and the target gets the hooks (LC6)", (a) => {
    const target = join(l.home, "dotfiles", "agent-settings.json");
    write(target, userText(a));
    mkdirSync(dirname(l.file(a)), { recursive: true });
    symlinkSync(target, l.file(a));
    expect(install(a).code).toBe(0);
    expect(lstatSync(l.file(a)).isSymbolicLink(), "the symlink was replaced by a regular file").toBe(true);
    expect(readlinkSync(l.file(a))).toBe(target);
    expect(ourEntryCount(readFileSync(target, "utf8"))).toBe(SPECS[a].events.length);
  });

  // LC7: install writes 0644 whatever the file had; Claude Code's settings.json commonly holds an `env` block with API keys.
  it.each(AGENTS)("%s: a private (0600) settings file is not made world-readable by install (LC7)", (a) => {
    seed(l, a, write);
    chmodSync(l.file(a), 0o600);
    install(a);
    expect(statSync(l.file(a)).mode & 0o077, `mode is now ${(statSync(l.file(a)).mode & 0o777).toString(8)}`).toBe(0);
  });

  it("a read-only settings file is refused without a half-written result", () => {
    seed(l, "claude", write);
    chmodSync(l.file("claude"), 0o444);
    chmodSync(dirname(l.file("claude")), 0o555);
    try {
      const r = install("claude");
      // Either way the original must survive, whole.
      if (r.code !== 0) expect(readFileSync(l.file("claude"), "utf8")).toBe(userText("claude"));
      else expect(ourEntryCount(readOrNull(l.file("claude")))).toBe(SPECS.claude.events.length);
    } finally {
      chmodSync(dirname(l.file("claude")), 0o755);
    }
  });

  it("Codex: a config.toml with CRLF line endings and the person's own hook trust records survives install and a restoring uninstall exactly", () => {
    const toml = `model = "gpt-5.1"\r\n\r\n[hooks.state."/Users/dev/.codex/hooks.json:pre_tool_use:0:0"]\r\ntrusted_hash = "sha256:${"ab".repeat(32)}"\r\n\r\n[projects."/x"]\r\ntrust_level = "trusted"\r\n`;
    write(join(l.home, ".codex", "config.toml"), toml);
    write(l.file("codex"), userText("codex"));
    expect(install("codex").code).toBe(0);
    const during = readFileSync(join(l.home, ".codex", "config.toml"), "utf8");
    expect(during).toContain(`[hooks.state."/Users/dev/.codex/hooks.json:pre_tool_use:0:0"]`);
    expect(during).toContain('trust_level = "trusted"');
    expect(person(l, ["uninstall", "--agent", "codex"]).code).toBe(0);
    const after = readFileSync(join(l.home, ".codex", "config.toml"), "utf8");
    expect(after).toContain(`[hooks.state."/Users/dev/.codex/hooks.json:pre_tool_use:0:0"]`);
    expect(after).not.toContain(l.file("codex"));
    expect(person(l, ["uninstall", "--agent", "codex", "--restore-backup"]).code).toBe(0);
    expect(readFileSync(l.file("codex"), "utf8")).toBe(userText("codex"));
  });

  it("the lab never wrote outside its temporary root", () => {
    install("claude");
    expect(Object.keys(tree(l.root, [])).every((k) => k.startsWith("home/") || k.startsWith("person-") || k.startsWith("proj/"))).toBe(true);
  });
});

void CODEX_TOML;
