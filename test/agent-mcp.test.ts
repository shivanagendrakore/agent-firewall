/**
 * The session-start MCP comparison reads every installed agent's MCP configuration (the gap left at the
 * v0.2 merge): Codex's config.toml, Gemini CLI's settings.json and Cursor's mcp.json, keyed per agent.
 * A changed server taints that agent's next session; an unchanged one does not; a server wrapped by the
 * firewall's own CLI is compared on what it wraps, and the firewall itself is not pinned.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { join } from "node:path";
import { codexAdapter } from "../src/adapters/codex.js";
import { cursorAdapter } from "../src/adapters/cursor.js";
import { geminiAdapter } from "../src/adapters/gemini.js";
import type { AgentId } from "../src/adapters/types.js";
import { runHook, stateSessionId } from "../src/hook/claude.js";
import { agentMcpServers, codexMcpServers } from "../src/runtime/agent-mcp.js";
import { install } from "../src/runtime/install.js";
import { configHash, loadPins, unwrapFirewall } from "../src/runtime/pins.js";
import { loadState } from "../src/runtime/store.js";
import { box, write, type Box } from "./adapters/harness.js";

let b: Box;
beforeEach(() => {
  b = box();
});
afterEach(() => b.cleanup());

const START: Record<AgentId, Record<string, unknown>> = {
  claude: { hook_event_name: "SessionStart", source: "startup" },
  codex: { hook_event_name: "SessionStart", source: "startup" },
  gemini: { hook_event_name: "SessionStart", source: "startup" },
  cursor: { hook_event_name: "sessionStart", is_background_agent: false, composer_mode: "agent" },
};

let n = 0;
/** A new session of `agent` (each call is its own session, as every session start compares). */
function session(agent: AgentId): { tainted: boolean; sources: string[]; message: string } {
  const id = `s${++n}`;
  const io = runHook(JSON.stringify({ session_id: id, conversation_id: id, cwd: b.ws, workspace_roots: [b.ws], ...START[agent] }), { env: agent === "claude" ? { CLAUDE_PROJECT_DIR: b.ws } : {}, layout: b.l, agent, home: b.home, detectNonInteractive: () => false, notifyDeps: { spawn: () => undefined } });
  const s = loadState(b.l, stateSessionId(agent, id));
  return { tainted: s.tainted, sources: s.taintSources, message: `${io.stdout}${io.stderr}` };
}

const codexToml = (args: string): string => `model = "x"\n\n[mcp_servers.docs]\ncommand = "npx"\nargs = [${args}]\n\n[mcp_servers.docs.env]\nDOCS_TOKEN = "secret-value"\n`;

describe("Codex config.toml MCP servers", () => {
  it("reads [mcp_servers.<name>] tables: quoted names, multi-line arrays, env tables and inline tables; nothing else", () => {
    const text = [
      'model = "gpt"',
      "[hooks.state.\"/x/hooks.json:pre_tool_use:0:0\"]",
      'trusted_hash = "sha256:00"',
      "[mcp_servers.docs]",
      'command = "npx"',
      "args = [",
      '  "-y",',
      "  'docs-mcp@1.2.3',",
      "]",
      'env = { DOCS_TOKEN = "v", "OTHER" = "w" }',
      '[mcp_servers."my.server"]',
      'url = "https://mcp.example.com/sse"',
      'bearer_token_env_var = "MCP_TOKEN"',
      "[mcp_servers.local.env]",
      'A = "1"',
      "[[hooks.PreToolUse]]",
      'command = "not a server"',
    ].join("\n");
    expect(codexMcpServers(text)).toEqual({
      docs: { command: "npx", args: ["-y", "docs-mcp@1.2.3"], env: { DOCS_TOKEN: "", OTHER: "" } },
      "my.server": { url: "https://mcp.example.com/sse", headers: { Authorization: "" } },
      local: { env: { A: "" } },
    });
  });
  it("a secret value change is not a configuration change; its variable names are", () => {
    const a = codexMcpServers(codexToml('"-y", "docs-mcp@1.2.3"')).docs as Record<string, unknown>;
    const b2 = codexMcpServers(codexToml('"-y", "docs-mcp@1.2.3"').replace("secret-value", "rotated")).docs as Record<string, unknown>;
    expect(configHash(a)).toBe(configHash(b2));
  });
});

describe("every installed agent's MCP servers, tagged and keyed per agent", () => {
  it("Codex (user, project), Gemini CLI (user, project) and Cursor (user, project)", () => {
    write(join(b.home, ".codex", "config.toml"), codexToml('"-y", "docs-mcp@1.2.3"'));
    write(join(b.ws, ".codex", "config.toml"), '[mcp_servers.repo]\ncommand = "node"\nargs = ["server.js"]\n');
    write(join(b.home, ".gemini", "settings.json"), JSON.stringify({ mcpServers: { gdocs: { command: "npx", args: ["g"] } } }));
    write(join(b.ws, ".gemini", "settings.json"), JSON.stringify({ mcpServers: { grepo: { httpUrl: "https://g.example/mcp" } } }));
    write(join(b.home, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { linear: { url: "https://mcp.linear.example/sse" } } }));
    write(join(b.ws, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { crepo: { command: "./run.sh" } } }));
    const got = agentMcpServers({ agents: ["codex", "gemini", "cursor"], workspace: b.ws, home: b.home, env: {}, platform: "linux" }).map((s) => `${s.agent}:${s.source}:${s.name}`);
    expect(got.sort()).toEqual(["codex:project:repo", "codex:user:docs", "cursor:project:crepo", "cursor:user:linear", "gemini:project:grepo", "gemini:user:gdocs"]);
  });
});

const cases: { agent: "codex" | "gemini" | "cursor"; file: () => string; config: (launch: string) => string; settings: typeof codexAdapter.settings }[] = [
  { agent: "codex", file: () => join(b.home, ".codex", "config.toml"), config: (launch) => codexToml(launch), settings: codexAdapter.settings },
  { agent: "gemini", file: () => join(b.home, ".gemini", "settings.json"), config: (launch) => JSON.stringify({ mcpServers: { docs: { command: "npx", args: JSON.parse(`[${launch}]`) as string[] } } }), settings: geminiAdapter.settings },
  { agent: "cursor", file: () => join(b.home, ".cursor", "mcp.json"), config: (launch) => JSON.stringify({ mcpServers: { docs: { command: "npx", args: JSON.parse(`[${launch}]`) as string[] } } }), settings: cursorAdapter.settings },
];

for (const c of cases) {
  describe(`session start compares ${c.agent}'s MCP configuration`, () => {
    beforeEach(() => {
      install(b.l, "user", b.ws, "t", { home: b.home, agent: c.agent, settings: c.settings });
      write(c.file(), c.config('"-y", "docs-mcp@1.2.3"'));
    });
    it("first seen: pinned under the agent, the session stays trusted", () => {
      expect(session(c.agent).tainted).toBe(false);
      expect(loadPins(b.l).pins.servers[`${c.agent}-user:docs`]?.configHash).not.toBeNull();
    });
    it("unchanged: not flagged in a later session", () => {
      session(c.agent);
      expect(session(c.agent).tainted).toBe(false);
      expect(loadPins(b.l).pins.pending).toEqual([]);
    });
    it("changed launch line: the agent's next session is untrusted and told, until a person accepts it", () => {
      session(c.agent);
      write(c.file(), c.config('"-y", "docs-mcp@9.9.9-evil"'));
      const s = session(c.agent);
      expect(s.tainted).toBe(true);
      expect(s.sources.join(" ")).toMatch(/FW-MCP-CHANGED: MCP server docs changed/);
      expect(s.message).toMatch(/launchsafe-firewall pins accept docs/);
      expect(loadPins(b.l).pins.pending.map((p) => p.key)).toEqual([`${c.agent}-user:docs`]);
    });
    it("a change in this agent's file is not another agent's: a Claude Code session records it quietly", () => {
      session(c.agent);
      write(c.file(), c.config('"-y", "docs-mcp@9.9.9-evil"'));
      expect(session("claude").tainted).toBe(false);
      expect(loadPins(b.l).pins.pending.map((p) => p.key)).toEqual([`${c.agent}-user:docs`]);
      expect(session(c.agent).tainted).toBe(true);
    });
    it("the firewall's own wrapper: wrapping the server is not a change, and the firewall itself is not pinned", () => {
      session(c.agent);
      write(c.file(), c.config('"-y", "docs-mcp@1.2.3"').replace('"npx"', '"launchsafe-firewall"').replace(/"-y"/, '"mcp-proxy", "--", "npx", "-y"'));
      expect(session(c.agent).tainted).toBe(false);
      write(c.file(), c.config('"mcp-proxy"').replace('"npx"', '"launchsafe-firewall"'));
      expect(session(c.agent).tainted).toBe(false);
      // A server that only names the firewall is still compared.
      write(c.file(), c.config('"launchsafe-firewall", "--", "npx", "-y", "docs-mcp@1.2.3"'));
      expect(session(c.agent).tainted).toBe(true);
    });
  });
}

describe("the firewall's own MCP wrapper", () => {
  const cli = "/opt/fw/dist/cli.js";
  it("unwraps only the exact firewall command, bare or as this installation's cli.js", () => {
    expect(unwrapFirewall({ command: "launchsafe-firewall", args: ["mcp-proxy", "--", "npx", "x"] }, cli)).toEqual({ command: "npx", args: ["x"] });
    expect(unwrapFirewall({ command: "/usr/local/bin/node", args: [cli, "proxy", "--", "uvx", "y"] }, cli)).toEqual({ command: "uvx", args: ["y"] });
    expect(unwrapFirewall({ command: "launchsafe-firewall", args: ["mcp-proxy"] }, cli)).toBeNull();
    const fake = { command: "./node_modules/.bin/launchsafe-firewall", args: ["--", "npx", "x"] };
    expect(unwrapFirewall(fake, cli)).toBe(fake);
    const other = { command: "node", args: ["/tmp/dist/cli.js", "--", "npx"] };
    expect(unwrapFirewall(other, cli)).toBe(other);
  });
});

describe("an MCP call of another agent is pinned under that agent", () => {
  it("a Codex call to a user server checks the codex-user pin, not Claude Code's of the same name", () => {
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings });
    write(join(b.home, ".codex", "config.toml"), codexToml('"-y", "docs-mcp@1.2.3"'));
    write(join(b.home, ".claude.json"), JSON.stringify({ mcpServers: { docs: { command: "npx", args: ["-y", "other-docs@2.0.0"] } } }));
    session("codex");
    runHook(JSON.stringify({ session_id: "call", cwd: b.ws, hook_event_name: "PreToolUse", permission_mode: "default", tool_name: "mcp__docs__search", tool_input: { q: "x" } }), { env: {}, layout: b.l, agent: "codex", home: b.home, detectNonInteractive: () => false, notifyDeps: { spawn: () => undefined } });
    const pins = loadPins(b.l).pins.servers;
    expect(pins["codex-user:docs"]?.tools).toEqual(["search"]);
    expect(pins["user:docs"]?.tools ?? []).toEqual([]);
  });
});
