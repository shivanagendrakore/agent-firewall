/**
 * F10: MCP server provenance. Claude Code 2.1.289 sends mcp_server.source on PreToolUse (verified
 * live; fixture recorded). When a version does not, the firewall derives it from the configuration
 * files itself, so a repository-defined server is never trusted because of its name.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runHook } from "../src/hook/claude.js";
import { mcpProvenance } from "../src/runtime/context.js";
import { layout } from "../src/runtime/layout.js";
import { loadState } from "../src/runtime/store.js";

let root: string, ws: string, home: string, l: ReturnType<typeof layout>;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-mcp-"));
  ws = join(root, "ws");
  home = join(root, "home");
  mkdirSync(ws, { recursive: true });
  mkdirSync(home, { recursive: true });
  l = layout(join(root, "fw"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("mcpProvenance", () => {
  it("local > project > user > managed; plugin by name; unknown otherwise", () => {
    writeFileSync(join(ws, ".mcp.json"), JSON.stringify({ mcpServers: { proj: {}, both: {} } }));
    writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: { usr: {}, both: {} }, projects: { [ws]: { mcpServers: { loc: {} } } } }));
    expect(mcpProvenance("loc", ws, home)).toBe("local");
    expect(mcpProvenance("proj", ws, home)).toBe("project");
    expect(mcpProvenance("both", ws, home)).toBe("project");
    expect(mcpProvenance("usr", ws, home)).toBe("user");
    expect(mcpProvenance("plugin_acme_db", ws, home)).toBe("plugin");
    expect(mcpProvenance("nowhere", ws, home)).toBe("unknown");
  });
  it("survives missing or broken config files", () => {
    writeFileSync(join(home, ".claude.json"), "{ not json");
    expect(mcpProvenance("x", ws, home)).toBe("unknown");
  });
});

/** A read on the "time" server: a trusted preset by name, so only provenance decides. */
function readTime(extra: Record<string, unknown>, session: string): boolean {
  const ev = { hook_event_name: "PreToolUse", session_id: session, cwd: ws, permission_mode: "default", tool_name: "mcp__time__get_current_time", tool_input: { timezone: "UTC" }, ...extra };
  runHook(JSON.stringify(ev), { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, detectNonInteractive: () => false, home });
  return loadState(l, session).tainted;
}

describe("the hook uses provenance to decide trust", () => {
  it("the recorded 2.1.289 event carries mcp_server.source and is read", () => {
    const fx = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures", "claude-2.1.289-pretooluse-mcp.json"), "utf8")) as Record<string, unknown>;
    expect(fx.mcp_server).toEqual({ name: "echo", source: "project" });
    const ev = { ...fx, cwd: ws, session_id: "fx" };
    delete (ev as Record<string, unknown>)._note;
    runHook(JSON.stringify(ev), { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, detectNonInteractive: () => false, home });
    expect(loadState(l, "fx").tainted).toBe(true);
  });
  it("source: project makes a trusted-by-name server untrusted", () => {
    expect(readTime({ mcp_server: { name: "time", source: "project" } }, "a")).toBe(true);
  });
  it("source: user keeps a trusted preset trusted", () => {
    expect(readTime({ mcp_server: { name: "time", source: "user" } }, "b")).toBe(false);
  });
  it("without the field, a server the repository's .mcp.json defines is untrusted", () => {
    writeFileSync(join(ws, ".mcp.json"), JSON.stringify({ mcpServers: { time: { command: "x" } } }));
    expect(readTime({}, "c")).toBe(true);
  });
  it("without the field, a user-scope server keeps its preset", () => {
    writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: { time: { command: "x" } } }));
    expect(readTime({}, "d")).toBe(false);
  });
  it("without the field and with no config naming it, it is treated as unknown (untrusted)", () => {
    expect(readTime({}, "e")).toBe(true);
  });
});
