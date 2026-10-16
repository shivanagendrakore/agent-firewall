/**
 * Lifecycle 5: the MCP gateway's config rewrite (`mcp wrap-config` / `mcp unwrap-config`) for every client it supports.
 * Person-run only (terminal, not under an agent, approval passphrase): it writes the documented wrapper, keeps everything else,
 * is idempotent, and unwrap puts the file back; a later edit by the person survives; a damaged file is refused untouched.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CLI, PASSPHRASE, json, lab, person, readOrNull, run, setPassphrase, tree, write, type Lab } from "./lab.js";
import { SPECS, seed } from "./agents.js";

let l: Lab;
beforeEach(() => {
  l = lab();
});
afterEach(() => l.cleanup());

type Client = "claude-desktop" | "claude-code" | "cursor" | "gemini" | "vscode" | "codex";

const linux = process.platform !== "darwin";
const JSON_CLIENTS: { client: Exclude<Client, "codex">; file: () => string; key: string; hookAgent: "claude" | "gemini" | "cursor" | null }[] = [
  { client: "claude-desktop", file: () => join(l.home, linux ? ".config/Claude" : "Library/Application Support/Claude", "claude_desktop_config.json"), key: "mcpServers", hookAgent: null },
  { client: "claude-code", file: () => join(l.home, ".claude", ".claude.json"), key: "mcpServers", hookAgent: "claude" },
  { client: "cursor", file: () => join(l.home, ".cursor", "mcp.json"), key: "mcpServers", hookAgent: "cursor" },
  { client: "gemini", file: () => join(l.home, ".gemini", "settings.json"), key: "mcpServers", hookAgent: "gemini" },
  { client: "vscode", file: () => join(l.home, linux ? ".config/Code/User" : "Library/Application Support/Code/User", "mcp.json"), key: "servers", hookAgent: null },
];

/** The person's MCP configuration for a client, as an editor leaves it. */
function config(key: string, extra: Record<string, unknown> = {}): string {
  return `${JSON.stringify(
    {
      globalShortcut: "Ctrl+Space",
      [key]: {
        files: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/Users/dev/work"], env: { LOG: "debug", API_KEY: "sk-test-not-real" } },
        remote: { url: "https://mcp.example.com/mcp", headers: { "X-Team": "red" } },
        parked: { command: "node", args: ["old.js"], disabled: true },
      },
      theme: { mode: "dark", accent: ["#fff", "#000"] },
      ...extra,
    },
    null,
    2,
  )}\n`;
}

const TOML = [
  'model = "gpt-5.1"',
  "",
  "[mcp_servers.files]",
  'command = "npx"',
  'args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/dev/work"]',
  "",
  "[mcp_servers.remote]",
  'url = "https://mcp.example.com/mcp"',
  "",
  '[projects."/Users/dev/work"]',
  'trust_level = "trusted"',
  "",
].join("\n");

const codexFile = (): string => join(l.home, ".codex", "config.toml");
const mcp = (verb: "wrap-config" | "unwrap-config", client: string, extra: string[] = []): string[] => ["mcp", verb, "--client", client, ...extra];
const gwRecord = (): { entries: { server: string; client: string; mode: string; file: string; original: Record<string, unknown> }[] } => JSON.parse(readOrNull(join(l.fwHome, "gateway", "install.json")) ?? '{"entries":[]}');

describe.each(JSON_CLIENTS)("wrap-config: $client", ({ client, file, key, hookAgent }) => {
  const wrap = (extra: string[] = []) => person(l, mcp("wrap-config", client, extra), [["Approval passphrase", PASSPHRASE]]);
  const unwrap = (extra: string[] = []) => person(l, mcp("unwrap-config", client, extra), [["Approval passphrase", PASSPHRASE]]);
  const servers = (): Record<string, Record<string, unknown>> => json(file())[key] as Record<string, Record<string, unknown>>;

  beforeEach(() => {
    expect(setPassphrase(l).code).toBe(0);
    write(file(), config(key));
  });

  it("is refused for a script or an agent (no terminal); a dry run works and writes nothing", () => {
    const before = tree(l.home);
    const refused = run(l, mcp("wrap-config", client));
    expect(refused.code).not.toBe(0);
    expect(refused.stderr).toMatch(/interactive terminal/);
    expect(tree(l.home)).toEqual(before);
    const dry = run(l, mcp("wrap-config", client, ["--dry-run"]));
    expect(dry.code, dry.stderr).toBe(0);
    expect(dry.stdout).toContain("wraps");
    expect(tree(l.home)).toEqual(before);
  });

  it("with the wrong passphrase writes nothing", () => {
    const before = tree(l.home);
    const r = person(l, mcp("wrap-config", client), [["Approval passphrase", "definitely not it"]]);
    expect(r.code).not.toBe(0);
    expect(tree(l.home)).toEqual(before);
  });

  it("writes the documented wrapper, keeps every other key and server, backs the original up, and records it", () => {
    const original = readFileSync(file(), "utf8");
    const r = wrap();
    expect(r.code, r.output).toBe(0);
    const doc = json(file());
    const s = servers();
    // stdio: the node binary runs this CLI's `mcp wrap` around the original command; env and the rest are kept.
    expect(s.files?.command).toBe(process.execPath);
    expect(s.files?.args).toEqual([CLI, "mcp", "wrap", "--client", client, "--server", "files", "--mode", "full", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/dev/work"]);
    expect(s.files?.env).toEqual({ LOG: "debug", API_KEY: "sk-test-not-real", NODE_COMPILE_CACHE: "" }); // LG4
    // http: the entry points at the local gateway with a bearer; the real URL moves to the record.
    expect(String(s.remote?.url)).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/c\/[^/]+\/u\/remote$/);
    expect(String((s.remote?.headers as Record<string, string>).Authorization)).toMatch(/^Bearer /);
    // A disabled entry is left exactly as it is.
    expect(s.parked).toEqual({ command: "node", args: ["old.js"], disabled: true });
    // Everything outside the servers is as it was, in the same order.
    const orig = JSON.parse(original) as Record<string, unknown>;
    expect(Object.keys(doc)).toEqual(Object.keys(orig));
    for (const k of Object.keys(orig).filter((k) => k !== key)) expect(doc[k]).toEqual(orig[k]);
    expect(Object.keys(s)).toEqual(["files", "remote", "parked"]);
    // Backup and record.
    const backups = readdirSync(join(l.fwHome, "backups")).filter((n) => n.startsWith("gateway-"));
    expect(backups).toHaveLength(1);
    expect(readFileSync(join(l.fwHome, "backups", backups[0] as string), "utf8")).toBe(original);
    const rec = gwRecord().entries;
    expect(rec.map((e) => e.server).sort()).toEqual(["files", "remote"]);
    expect(rec.find((e) => e.server === "files")?.original).toEqual(JSON.parse(original)[key].files);
    // The status command agrees.
    const st = run(l, ["gateway", "status", "--json"]);
    expect((JSON.parse(st.stdout) as { wrapped: { server: string }[] }).wrapped.map((w) => w.server).sort()).toEqual(["files", "remote"]);
  });

  it("--server wraps only the named servers", () => {
    expect(wrap(["--server", "files"]).code).toBe(0);
    expect(servers().files?.command).toBe(process.execPath);
    expect(servers().remote).toEqual(JSON.parse(config(key))[key].remote);
    expect(gwRecord().entries.map((e) => e.server)).toEqual(["files"]);
  });

  it("is idempotent: wrapping again changes no byte, adds no record and no second backup", () => {
    wrap();
    const once = readFileSync(file(), "utf8");
    const rec = readFileSync(join(l.fwHome, "gateway", "install.json"), "utf8").replace(/"wrappedAt": "[^"]*"/g, "");
    const second = wrap();
    expect(second.code, second.output).toBe(0);
    expect(readFileSync(file(), "utf8")).toBe(once);
    expect(gwRecord().entries).toHaveLength(2);
    expect(readFileSync(join(l.fwHome, "gateway", "install.json"), "utf8").replace(/"wrappedAt": "[^"]*"/g, "")).toBe(rec);
    expect(readdirSync(join(l.fwHome, "backups")).filter((n) => n.startsWith("gateway-"))).toHaveLength(1);
  });

  it("unwrap puts the file back byte for byte, drops the records, and is a no-op the second time", () => {
    const original = readFileSync(file(), "utf8");
    wrap();
    const r = unwrap();
    expect(r.code, r.output).toBe(0);
    expect(readFileSync(file(), "utf8")).toBe(original);
    expect(gwRecord().entries).toEqual([]);
    const again = unwrap();
    expect(again.code).toBe(0);
    expect(again.output).toContain("is wrapped");
    expect(readFileSync(file(), "utf8")).toBe(original);
  });

  it("unwrap by a script or an agent is refused and the wrapper stays", () => {
    wrap();
    const wrapped = readFileSync(file(), "utf8");
    const r = run(l, mcp("unwrap-config", client));
    expect(r.code).not.toBe(0);
    expect(readFileSync(file(), "utf8")).toBe(wrapped);
    expect(gwRecord().entries).toHaveLength(2);
  });

  it("keeps the person's edits made after wrapping: a new server, a changed setting, a removed server", () => {
    wrap();
    const doc = json(file());
    (doc[key] as Record<string, unknown>).addedLater = { command: "uvx", args: ["mcp-thing"] };
    doc.globalShortcut = "Alt+Space";
    delete (doc[key] as Record<string, unknown>).parked;
    write(file(), `${JSON.stringify(doc, null, 2)}\n`);
    const r = unwrap();
    expect(r.code, r.output).toBe(0);
    const s = servers();
    expect(s.addedLater).toEqual({ command: "uvx", args: ["mcp-thing"] });
    expect(json(file()).globalShortcut).toBe("Alt+Space");
    expect(s.parked).toBeUndefined();
    expect(s.files).toEqual(JSON.parse(config(key))[key].files);
    expect(s.remote).toEqual(JSON.parse(config(key))[key].remote);
  });

  // LC8: an edit made after wrapping is never overwritten with the old original.
  it("a wrapped entry the person edited keeps the edit with only the wrapper removed, and the command says so (LC8)", () => {
    wrap();
    const doc = json(file());
    ((doc[key] as Record<string, Record<string, unknown>>).files as Record<string, unknown>).env = { LOG: "trace" };
    write(file(), `${JSON.stringify(doc, null, 2)}\n`);
    const r = unwrap();
    expect(r.code, r.output).toBe(0);
    expect(r.output).toMatch(/"files" was edited after it was wrapped: your edit is kept and only the gateway wrapper is removed/);
    const original = JSON.parse(config(key))[key].files as Record<string, unknown>;
    expect(servers().files).toEqual({ ...original, env: { LOG: "trace" } });
    expect(gwRecord().entries).toEqual([]);
  });

  it("a wrapped entry the person replaced is left as they wrote it, and the original is saved and named (LC8)", () => {
    wrap();
    const doc = json(file());
    (doc[key] as Record<string, unknown>).files = { command: "bun", args: ["run", "mine.ts"] };
    write(file(), `${JSON.stringify(doc, null, 2)}\n`);
    const r = unwrap();
    expect(r.code, r.output).toBe(0);
    expect(r.output).toMatch(/"files" was edited after it was wrapped, and the wrapper cannot be separated/);
    expect(servers().files).toEqual({ command: "bun", args: ["run", "mine.ts"] });
    const saved = readdirSync(join(l.fwHome, "backups")).filter((n) => n.startsWith("gateway-unwrap-original-"));
    expect(saved).toHaveLength(1);
    expect(r.output).toContain(saved[0] as string);
    expect(readFileSync(join(l.fwHome, "backups", saved[0] as string), "utf8")).toContain("server-filesystem");
  });

  it("a server added after wrap is wrapped by the next wrap, the earlier ones are not wrapped twice", () => {
    wrap();
    const doc = json(file());
    (doc[key] as Record<string, unknown>).second = { command: "python3", args: ["-m", "srv"] };
    write(file(), `${JSON.stringify(doc, null, 2)}\n`);
    expect(wrap().code).toBe(0);
    const s = servers();
    expect((s.second?.args as string[]).slice(0, 2)).toEqual([CLI, "mcp"]);
    expect((s.files?.args as string[]).filter((x) => x === "wrap")).toHaveLength(1);
    expect(gwRecord().entries.map((e) => e.server).sort()).toEqual(["files", "remote", "second"]);
  });

  it("refuses a file that is not valid JSON, untouched, with no record; unwrap of a damaged file refuses and keeps the records", () => {
    write(file(), '{"mcpServers": {"files": {"command": "npx"');
    const damaged = readFileSync(file(), "utf8");
    const r = person(l, mcp("wrap-config", client), [["Approval passphrase", PASSPHRASE]]);
    expect(r.code).not.toBe(0);
    expect(readFileSync(file(), "utf8")).toBe(damaged);
    expect(gwRecord().entries).toEqual([]);
    // Wrap a good file, damage it, unwrap.
    write(file(), config(key));
    wrap();
    const wrapped = readFileSync(file(), "utf8");
    write(file(), wrapped.slice(0, wrapped.length - 40));
    const cut = readFileSync(file(), "utf8");
    const u = unwrap();
    expect(u.code).not.toBe(0);
    expect(readFileSync(file(), "utf8")).toBe(cut);
    expect(gwRecord().entries).toHaveLength(2);
    // The refusal prints what to paste back by hand.
    expect(u.output).toContain("npx");
  });

  it("a missing file is 'not found, nothing to wrap'", () => {
    const missing = lab();
    try {
      expect(setPassphrase(missing).code).toBe(0);
      const r = run(missing, mcp("wrap-config", client, ["--dry-run"]));
      expect(r.code).toBe(0);
      expect(r.stdout).toContain("not found, nothing to wrap");
    } finally {
      missing.cleanup();
    }
  });

  if (hookAgent !== null) {
    it(`runs in full mode by default with the ${hookAgent} hook installed (I4), and in hook mode only when the person's policy names it`, () => {
      const agent = hookAgent;
      expect(run(l, ["install", "--agent", agent]).code).toBe(0);
      // I4: an install record does not prove the hook runs, so "auto" is full mode.
      expect(run(l, mcp("wrap-config", client, ["--dry-run"])).stdout).not.toMatch(/--mode", "hook|mode hook/);
      writeFileSync(join(l.fwHome, "policy.json"), JSON.stringify({ version: 3, gateway: { mode: "hook" } }));
      expect(wrap().code).toBe(0);
      const s = servers();
      expect(s.files?.args).toContain("hook");
      expect(gwRecord().entries.every((e) => e.mode === "hook")).toBe(true);
      expect(person(l, ["uninstall", "--agent", agent], [["Approval passphrase", PASSPHRASE]]).code).toBe(0);
      // The wrapped entries survive an uninstall of the hooks (including Gemini's, which lives in the same file) ...
      expect(servers().files?.command).toBe(process.execPath);
      // ... and the gateway says plainly that they now run in full mode.
      expect(run(l, ["gateway", "status"]).stdout).toMatch(/hook for .* is not installed: it runs in full mode/);
      expect(unwrap().code).toBe(0);
      expect(servers().files).toEqual(JSON.parse(config(key))[key].files);
    });
  }
});

describe("wrap-config: claude-code's project entries", () => {
  it("wraps and unwraps the servers under projects.<dir>.mcpServers and leaves the rest of ~/.claude.json alone", () => {
    expect(setPassphrase(l).code).toBe(0);
    const file = join(l.home, ".claude", ".claude.json");
    const text = `${JSON.stringify({ userID: "u-123", numStartups: 41, mcpServers: { a: { command: "a-bin" } }, projects: { "/work/x": { allowedTools: ["Read"], mcpServers: { b: { command: "b-bin", args: ["--x"] } }, history: [1, 2, 3] } } }, null, 2)}\n`;
    write(file, text);
    expect(person(l, mcp("wrap-config", "claude-code"), [["Approval passphrase", PASSPHRASE]]).code).toBe(0);
    const doc = json(file) as { userID: string; numStartups: number; mcpServers: Record<string, { command: string }>; projects: Record<string, { allowedTools: string[]; history: number[]; mcpServers: Record<string, { command: string }> }> };
    expect(doc.mcpServers.a?.command).toBe(process.execPath);
    expect(doc.projects["/work/x"]?.mcpServers.b?.command).toBe(process.execPath);
    expect(doc.projects["/work/x"]?.allowedTools).toEqual(["Read"]);
    expect(doc.projects["/work/x"]?.history).toEqual([1, 2, 3]);
    expect(doc.userID).toBe("u-123");
    expect(person(l, mcp("unwrap-config", "claude-code"), [["Approval passphrase", PASSPHRASE]]).code).toBe(0);
    expect(readFileSync(file, "utf8")).toBe(text);
  });
});

describe("wrap-config: codex (config.toml)", () => {
  const wrap = (extra: string[] = []) => person(l, mcp("wrap-config", "codex", extra), [["Approval passphrase", PASSPHRASE]]);
  const unwrap = () => person(l, mcp("unwrap-config", "codex"), [["Approval passphrase", PASSPHRASE]]);

  beforeEach(() => {
    expect(setPassphrase(l).code).toBe(0);
    write(codexFile(), TOML);
  });

  it("changes only the two server tables, keeps every other line, and unwrap restores the file byte for byte", () => {
    const r = wrap();
    expect(r.code, r.output).toBe(0);
    const wrapped = readFileSync(codexFile(), "utf8");
    expect(wrapped).toContain(`command = "${process.execPath}"`);
    expect(wrapped).toContain('model = "gpt-5.1"');
    expect(wrapped).toContain('[projects."/Users/dev/work"]\ntrust_level = "trusted"');
    expect(wrapped).toMatch(/url = "http:\/\/127\.0\.0\.1:\d+\/c\/codex\/u\/remote"/);
    expect(wrapped).not.toContain("https://mcp.example.com/mcp");
    expect(gwRecord().entries.map((e) => e.server).sort()).toEqual(["files", "remote"]);
    const u = unwrap();
    expect(u.code, u.output).toBe(0);
    expect(readFileSync(codexFile(), "utf8")).toBe(TOML);
  });

  it("is idempotent", () => {
    wrap();
    const once = readFileSync(codexFile(), "utf8");
    expect(wrap().code).toBe(0);
    expect(readFileSync(codexFile(), "utf8")).toBe(once);
    expect(gwRecord().entries).toHaveLength(2);
  });

  it("refuses, with the snippet to paste and no change, a table the editor does not fully understand (a comment inside it)", () => {
    const odd = `${TOML.replace('command = "npx"\n', 'command = "npx" # my launcher\n')}`;
    write(codexFile(), odd);
    const r = wrap();
    expect(r.code).not.toBe(0);
    expect(readFileSync(codexFile(), "utf8")).toBe(odd);
    expect(r.output).toMatch(/comment/i);
    expect(gwRecord().entries).toEqual([]);
  });

  it("installing the hooks (which records trust in the same config.toml) before and after a wrap loses neither", () => {
    write(join(l.home, ".codex", "hooks.json"), `${JSON.stringify(SPECS.codex.user(), null, 2)}\n`);
    expect(run(l, ["install", "--agent", "codex"]).code).toBe(0);
    expect(wrap().code).toBe(0);
    expect(readFileSync(codexFile(), "utf8")).toContain("[hooks.state.");
    expect(readFileSync(codexFile(), "utf8")).toContain(`command = "${process.execPath}"`);
    // Reinstall (re-trusts) and a plain uninstall of the hooks: the wrapped servers and the person's tables stay.
    expect(run(l, ["install", "--agent", "codex"]).code).toBe(0);
    expect(person(l, ["uninstall", "--agent", "codex"], [["Approval passphrase", PASSPHRASE]]).code).toBe(0);
    const left = readFileSync(codexFile(), "utf8");
    expect(left).not.toContain("[hooks.state.");
    expect(left).toContain(`command = "${process.execPath}"`);
    expect(left).toContain('trust_level = "trusted"');
    expect(unwrap().code).toBe(0);
    expect(readFileSync(codexFile(), "utf8")).toBe(TOML);
  });
});

describe("wrap-config and the hooks share a file (Gemini CLI's settings.json)", () => {
  it("hooks, then wrap, then a restoring uninstall of the hooks: nothing is lost and the gateway still unwraps without error", () => {
    expect(setPassphrase(l).code).toBe(0);
    seed(l, "gemini", write);
    const original = readFileSync(l.file("gemini"), "utf8");
    expect(run(l, ["install", "--agent", "gemini"]).code).toBe(0);
    expect(person(l, mcp("wrap-config", "gemini"), [["Approval passphrase", PASSPHRASE]]).code).toBe(0);
    const both = json(l.file("gemini"));
    expect(Object.keys(both)).toContain("hooks");
    expect((both.mcpServers as Record<string, { command: string }>).files?.command).toBe(process.execPath);
    // --restore-backup writes the pre-install file over the wrapped one: the wrapper is gone, the person's servers are as they were.
    const r = person(l, ["uninstall", "--agent", "gemini", "--restore-backup"], [["Approval passphrase", PASSPHRASE]]);
    expect(r.code, r.output).toBe(0);
    expect(readFileSync(l.file("gemini"), "utf8")).toBe(original);
    const u = person(l, mcp("unwrap-config", "gemini"), [["Approval passphrase", PASSPHRASE]]);
    expect(u.code, u.output).toBe(0);
    expect(readFileSync(l.file("gemini"), "utf8")).toBe(original);
    expect(existsSync(l.fwHome)).toBe(true);
  });
});

describe("wrap-config: files that are symlinks", () => {
  // Same cause as LC6 for install: the write is a rename over the path, so a dotfiles symlink is replaced by a regular file.
  it("a symlinked ~/.cursor/mcp.json stays a symlink and the target is the file that gets wrapped (LC9)", () => {
    expect(setPassphrase(l).code).toBe(0);
    const target = join(l.home, "dotfiles", "cursor-mcp.json");
    write(target, config("mcpServers"));
    mkdirSync(join(l.home, ".cursor"), { recursive: true });
    symlinkSync(target, join(l.home, ".cursor", "mcp.json"));
    expect(person(l, mcp("wrap-config", "cursor"), [["Approval passphrase", PASSPHRASE]]).code).toBe(0);
    expect(lstatSync(join(l.home, ".cursor", "mcp.json")).isSymbolicLink()).toBe(true);
    expect(readFileSync(target, "utf8")).toContain("127.0.0.1");
  });
});
