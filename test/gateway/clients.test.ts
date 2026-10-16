/**
 * Item G acceptance: config rewrite helpers and the protection of wrapped
 * configuration (GW21-GW24, GW27), always in temporary homes (the real Claude
 * Desktop, Cursor, Codex and Gemini CLI files are never touched: the test-home
 * guard refuses it).
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { applyPlan, applyUnwrap, clientFiles, planUnwrap, planWrap, unwrappedServers, wrappedWithoutCompileCache } from "../../src/gateway/clients.js";
import { gatewayConfigs, readGatewayInstall, updateGatewayInstall, upstreamEnv, UPSTREAM_COMPILE_CACHE } from "../../src/gateway/install.js";
import { runHook } from "../../src/hook/claude.js";
import { installDir, type Layout } from "../../src/runtime/layout.js";
import { loadPins } from "../../src/runtime/pins.js";
import { loadState } from "../../src/runtime/store.js";
import { bash, explain, run } from "../helpers.js";
import { newHome } from "./harness.js";
import { entryHashOf as hashOf } from "../../src/engine/gateway-config.js";

const CLI = join(installDir(), "dist", "cli.js");
const NODE = process.execPath;
const fe = (home: string) => ({ home, platform: "darwin" as NodeJS.Platform, env: {} });

function write(p: string, text: string): void {
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, text);
}

function wrap(l: Layout, home: string, client: Parameters<typeof clientFiles>[0], servers?: string[]) {
  const plans = planWrap({ l, client, node: NODE, cli: CLI, port: 8473, ...(servers !== undefined ? { servers } : {}) }, fe(home));
  for (const p of plans) applyPlan(l, p);
  return plans;
}

const DESKTOP = (home: string) => join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");

describe("wrap-config / unwrap-config", () => {
  it("Claude Desktop: stdio entries are wrapped (env kept), HTTP entries point at the local gateway, unwrap restores the file", () => {
    const { l, home } = newHome();
    const original = { mcpServers: { files: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/tmp"], env: { LOG: "1" } }, remote: { url: "https://mcp.example.com/mcp", headers: { Authorization: "Bearer abc" } } }, other: true };
    write(DESKTOP(home), JSON.stringify(original, null, 2));
    const [plan] = wrap(l, home, "claude-desktop");
    expect(plan?.wrapped.map((w) => w.server)).toEqual(["files", "remote"]);
    const after = JSON.parse(readFileSync(DESKTOP(home), "utf8"));
    expect(after.mcpServers.files).toEqual({ command: NODE, args: [CLI, "mcp", "wrap", "--client", "claude-desktop", "--server", "files", "--mode", "full", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/tmp"], env: { LOG: "1", NODE_COMPILE_CACHE: "" } });
    expect(after.mcpServers.remote.url).toBe("http://127.0.0.1:8473/c/claude-desktop/u/remote");
    expect(after.mcpServers.remote.headers.Authorization).toMatch(/^Bearer lsgw_/);
    expect(after.other).toBe(true);
    expect(readGatewayInstall(l).entries).toHaveLength(2);
    expect(unwrappedServers({ l, client: "claude-desktop", cli: CLI, node: NODE }, fe(home))).toEqual([]);
    // Wrapping again changes nothing.
    expect(planWrap({ l, client: "claude-desktop", node: NODE, cli: CLI, port: 8473 }, fe(home))[0]?.after).toBeNull();
    for (const p of planUnwrap(l, "claude-desktop")) applyUnwrap(l, p);
    expect(JSON.parse(readFileSync(DESKTOP(home), "utf8"))).toEqual(original);
    expect(readGatewayInstall(l).entries).toHaveLength(0);
  });

  it("GW27: a Codex config.toml with a comment inside [mcp_servers.x]: wrap-config refuses and prints the snippet", () => {
    const { l, home } = newHome();
    const toml = '[mcp_servers.docs]\n# pinned on purpose\ncommand = "npx"\nargs = ["-y", "docs-mcp@1.2.3"]\n';
    write(join(home, ".codex", "config.toml"), toml);
    const [plan] = planWrap({ l, client: "codex", node: NODE, cli: CLI, port: 8473 }, fe(home));
    expect(plan?.refused?.why).toMatch(/comment inside the server's table/);
    expect(plan?.refused?.snippet).toContain('args = ["');
    expect(plan?.refused?.snippet).toContain('"mcp", "wrap", "--client", "codex", "--server", "docs"');
    expect(readFileSync(join(home, ".codex", "config.toml"), "utf8")).toBe(toml);
  });

  it("Codex: a plain table is wrapped by the narrow editor (env subtable and other keys untouched) and unwrapped back", () => {
    const { l, home } = newHome();
    const toml = 'model = "o5"\n\n[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "docs-mcp@1.2.3"]\n\n[mcp_servers.docs.env]\nTOKEN_NAME = "x"\n';
    const file = join(home, ".codex", "config.toml");
    write(file, toml);
    const [plan] = wrap(l, home, "codex");
    expect(plan?.refused).toBeUndefined();
    const after = readFileSync(file, "utf8");
    expect(after).toContain(`command = ${JSON.stringify(NODE)}`);
    expect(after).toContain('[mcp_servers.docs.env]\nNODE_COMPILE_CACHE = ""\nTOKEN_NAME = "x"'); // LG4
    expect(after.startsWith('model = "o5"')).toBe(true);
    for (const p of planUnwrap(l, "codex")) applyUnwrap(l, p);
    expect(readFileSync(file, "utf8")).toBe(toml);
  });

  it("Gemini CLI: trust: true is removed from a wrapped entry; repository files are not in the list", () => {
    const { l, home } = newHome();
    write(join(home, ".gemini", "settings.json"), JSON.stringify({ mcpServers: { db: { command: "uvx", args: ["db-mcp==2.0"], trust: true } } }));
    wrap(l, home, "gemini");
    const after = JSON.parse(readFileSync(join(home, ".gemini", "settings.json"), "utf8"));
    expect(after.mcpServers.db.trust).toBeUndefined();
    expect(clientFiles("cursor", fe(home)).map((f) => f.path)).toEqual([join(home, ".cursor", "mcp.json")]);
  });
});

describe("GW21: the wrapper is not a change", () => {
  it("wrap-config of Claude Code and Claude Desktop, then the next Claude Code session: no FW-MCP-CHANGED, no drift taint", () => {
    const { l, home } = newHome();
    const ws = join(home, "ws");
    mkdirSync(ws, { recursive: true });
    write(join(home, ".claude.json"), JSON.stringify({ mcpServers: { docs: { command: "npx", args: ["-y", "docs-mcp@1.2.3"] } } }, null, 2));
    write(DESKTOP(home), JSON.stringify({ mcpServers: { files: { command: "npx", args: ["-y", "fs-mcp@1.0.0"] } } }));
    const start = (id: string) => {
      runHook(JSON.stringify({ session_id: id, cwd: ws, hook_event_name: "SessionStart", source: "startup" }), { env: { CLAUDE_CONFIG_DIR: join(home, ".claude") }, layout: l, home, detectNonInteractive: () => false, notifyDeps: { spawn: () => undefined } });
      return loadState(l, id);
    };
    expect(start("s1").tainted).toBe(false);
    const pinned = loadPins(l).pins.servers["user:docs"]?.configHash;
    wrap(l, home, "claude-code");
    wrap(l, home, "claude-desktop");
    expect(JSON.parse(readFileSync(join(home, ".claude.json"), "utf8")).mcpServers.docs.command).toBe(NODE);
    const s2 = start("s2");
    expect(s2.taintSources).toEqual([]);
    expect(s2.tainted).toBe(false);
    expect(loadPins(l).pins.servers["user:docs"]?.configHash).toBe(pinned);
    expect(loadPins(l).pins.pending).toEqual([]);
  });
});

describe("GW22-GW24: wrapped configuration is protected", () => {
  function setup() {
    const { l, home } = newHome();
    write(DESKTOP(home), JSON.stringify({ mcpServers: { files: { command: "npx", args: ["-y", "fs-mcp@1.0.0"] } } }, null, 2));
    wrap(l, home, "claude-desktop");
    const path = DESKTOP(home);
    const text = readFileSync(path, "utf8");
    const c = { home, workspaceRoots: [join(home, "ws")], cwd: join(home, "ws"), gatewayConfigs: gatewayConfigs(l), readFile: (p: string) => (p === path ? text : null), caseInsensitive: false };
    return { l, home, path, text, c };
  }

  it("GW22: an agent edit that removes the wrapper is FW-TAMPER (deny)", () => {
    const { path, text, c } = setup();
    const doc = JSON.parse(text);
    doc.mcpServers.files = { command: "npx", args: ["-y", "fs-mcp@1.0.0"] };
    const d = run("Write", { file_path: path, content: JSON.stringify(doc, null, 2) }, { ctx: c });
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toContain("FW-TAMPER");
    const removed = run("Write", { file_path: path, content: JSON.stringify({ mcpServers: {} }) }, { ctx: c });
    expect(removed.rules, explain(removed)).toContain("FW-TAMPER");
  });

  it("GW23: an agent adding an unwrapped server is FW-AGENT-SETTINGS (asked when trusted, held when untrusted)", () => {
    const { path, text, c } = setup();
    const doc = JSON.parse(text);
    doc.mcpServers.extra = { command: "npx", args: ["-y", "extra-mcp@1.0.0"] };
    const content = JSON.stringify(doc, null, 2);
    const trusted = run("Write", { file_path: path, content }, { ctx: c });
    expect(trusted.verdict, explain(trusted)).toBe("ask");
    expect(trusted.rules).toContain("FW-AGENT-SETTINGS");
    expect(trusted.rules).not.toContain("FW-TAMPER");
    const untrusted = run("Write", { file_path: path, content }, { ctx: c, tainted: true });
    expect(["queue", "ask"]).toContain(untrusted.verdict);
    expect(untrusted.verdict).not.toBe("allow");
  });

  it("a shell write to a wrapped file is FW-TAMPER", () => {
    const { path, c } = setup();
    const d = bash(`echo '{}' > '${path}'`, { ctx: c });
    expect(d.rules, explain(d)).toContain("FW-TAMPER");
  });

  it("GW24: an agent running pkill -f \"launchsafe-firewall mcp wrap\" is FW-TAMPER", () => {
    const d = bash('pkill -f "launchsafe-firewall mcp wrap"');
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toContain("FW-TAMPER");
  });

  it("an agent running mcp wrap-config or gateway quarantine show is FW-TAMPER; gateway status is allowed", () => {
    expect(bash("launchsafe-firewall mcp wrap-config --client cursor").rules).toContain("FW-TAMPER");
    expect(bash("launchsafe-firewall gateway quarantine show q-abcd1234").rules).toContain("FW-TAMPER");
    expect(bash("launchsafe-firewall gateway status").rules).not.toContain("FW-TAMPER");
  });
});

describe("LG4: the wrapper's node never loads a compile cache from the environment", () => {
  it("the entry's own NODE_COMPILE_CACHE is moved aside for the server, given back to it, and restored on unwrap", () => {
    const { l, home } = newHome();
    const original = { mcpServers: { files: { command: "npx", args: ["files-mcp"], env: { NODE_COMPILE_CACHE: "/tmp/mine", K: "v" } } } };
    write(DESKTOP(home), JSON.stringify(original, null, 2));
    wrap(l, home, "claude-desktop");
    const env = JSON.parse(readFileSync(DESKTOP(home), "utf8")).mcpServers.files.env;
    expect(env).toEqual({ K: "v", NODE_COMPILE_CACHE: "", [UPSTREAM_COMPILE_CACHE]: "/tmp/mine" });
    const child = upstreamEnv({ ...env, PATH: "/bin" });
    expect(child.NODE_COMPILE_CACHE).toBe("/tmp/mine");
    expect(child[UPSTREAM_COMPILE_CACHE]).toBeUndefined();
    expect(upstreamEnv({ NODE_COMPILE_CACHE: "" }).NODE_COMPILE_CACHE).toBeUndefined();
    expect(wrappedWithoutCompileCache(l)).toEqual([]);
    for (const p of planUnwrap(l, "claude-desktop")) applyUnwrap(l, p);
    expect(JSON.parse(readFileSync(DESKTOP(home), "utf8"))).toEqual(original);
  });

  it("an entry wrapped before the fix is flagged (doctor) and fixed in place by wrap-config; unwrap still restores the original", () => {
    const { l, home } = newHome();
    const original = { mcpServers: { files: { command: "npx", args: ["files-mcp"] } } };
    write(DESKTOP(home), JSON.stringify(original, null, 2));
    wrap(l, home, "claude-desktop");
    // Simulate a 0.2-era wrapper: no env, and the record's hash matching that.
    const doc = JSON.parse(readFileSync(DESKTOP(home), "utf8"));
    delete doc.mcpServers.files.env;
    write(DESKTOP(home), JSON.stringify(doc, null, 2));
    updateGatewayInstall(l, (g) => {
      for (const e of g.entries) e.wrappedHash = hashOf(doc.mcpServers.files);
    });
    expect(wrappedWithoutCompileCache(l).map((x) => x.server)).toEqual(["files"]);
    const [plan] = wrap(l, home, "claude-desktop");
    expect(plan?.fixed.map((f) => f.server)).toEqual(["files"]);
    expect(JSON.parse(readFileSync(DESKTOP(home), "utf8")).mcpServers.files.env).toEqual({ NODE_COMPILE_CACHE: "" });
    expect(wrappedWithoutCompileCache(l)).toEqual([]);
    for (const p of planUnwrap(l, "claude-desktop")) applyUnwrap(l, p);
    expect(JSON.parse(readFileSync(DESKTOP(home), "utf8"))).toEqual(original);
  });

  it("Codex: no env gets an inline env line, an inline env gets the key, and an entry setting NODE_COMPILE_CACHE is refused", () => {
    const { l, home } = newHome();
    const file = join(home, ".codex", "config.toml");
    const toml = '[mcp_servers.a]\ncommand = "npx"\nargs = ["a-mcp"]\n\n[mcp_servers.b]\ncommand = "npx"\nargs = ["b-mcp"]\nenv = { K = "v" }\n';
    write(file, toml);
    const [plan] = wrap(l, home, "codex");
    expect(plan?.refused).toBeUndefined();
    const after = readFileSync(file, "utf8");
    expect(after).toContain('env = { NODE_COMPILE_CACHE = "" }');
    expect(after).toContain('env = { NODE_COMPILE_CACHE = "", K = "v" }');
    expect(wrappedWithoutCompileCache(l)).toEqual([]);
    for (const p of planUnwrap(l, "codex")) applyUnwrap(l, p);
    expect(readFileSync(file, "utf8")).toBe(toml);
    const { l: l2, home: h2 } = newHome();
    write(join(h2, ".codex", "config.toml"), '[mcp_servers.c]\ncommand = "npx"\nargs = ["c-mcp"]\nenv = { NODE_COMPILE_CACHE = "/tmp/x" }\n');
    const [p2] = planWrap({ l: l2, client: "codex", node: NODE, cli: CLI, port: 8473 }, fe(h2));
    expect(p2?.refused?.why).toMatch(/sets NODE_COMPILE_CACHE in its env/);
  });
});
