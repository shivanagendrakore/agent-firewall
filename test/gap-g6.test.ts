/**
 * G6: a filesystem MCP server started with directories inside the workspace does not taint what it
 * reads; one whose roots are unknown, outside the workspace, or defined by the repository does.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runHook } from "../src/hook/claude.js";
import { layout } from "../src/runtime/layout.js";
import { loadState } from "../src/runtime/store.js";
import { explain, HOME, run, WS } from "./helpers.js";

const read = (roots: string[] | undefined, server = "filesystem", extra: Record<string, unknown> = {}) =>
  run(`mcp__${server}__read_file`, { path: `${WS}/src/a.ts` }, { ctx: { ...(roots !== undefined ? { mcpRoots: roots } : {}), ...extra } });
const taints = (d: ReturnType<typeof read>): boolean => d.events.some((e) => e.type === "taint");

describe("G6 in the engine", () => {
  it("roots inside the workspace: allowed, nothing tainted", () => {
    for (const roots of [[WS], [`${WS}/src`], [WS, `${WS}/docs`]]) {
      const d = read(roots);
      expect(d.verdict, explain(d)).toBe("allow");
      expect(taints(d), `${roots}`).toBe(false);
    }
  });
  it("unknown, empty, or outside roots keep the default: tainted", () => {
    for (const roots of [undefined, [], [HOME], [WS, HOME], ["/"], [`${WS}-other`], [`${WS}/../other`]]) {
      const d = read(roots as string[] | undefined);
      expect(d.verdict, explain(d)).toBe("allow");
      expect(taints(d), `${JSON.stringify(roots)}`).toBe(true);
    }
  });
  it("a repository-defined server is never confined by its own arguments", () => {
    const d = read([WS], "filesystem", { mcpSource: "project" });
    expect(taints(d)).toBe(true);
  });
  it("other servers are unaffected by roots", () => {
    expect(taints(run("mcp__github__get_issue", { owner: "a", repo: "b", issue_number: 1 }, { ctx: { mcpRoots: [WS] } }))).toBe(true);
    expect(taints(run("mcp__notes__read_file", { path: `${WS}/a` }, { ctx: { mcpRoots: [WS] } }))).toBe(true);
  });
  it("the user's own policy entry still wins", () => {
    const d = run("mcp__filesystem__read_file", { path: `${WS}/a` }, { ctx: { mcpRoots: [WS] }, config: { mcpServers: { filesystem: { results: "untrusted", privateData: true } } } as never });
    expect(taints(d)).toBe(true);
  });
  it("the path rules still judge what the server is asked for", () => {
    const d = run("mcp__filesystem__read_file", { path: `${HOME}/.ssh/id_ed25519` }, { ctx: { mcpRoots: [WS] } });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-CREDENTIAL-READ");
    expect(run("mcp__filesystem__write_file", { path: `${WS}/CLAUDE.md`, content: "x" }, { ctx: { mcpRoots: [WS] }, tainted: true }).rules).toContain("FW-INSTRUCTIONS-HELD");
  });
});

describe("G6 from the server's launch arguments", () => {
  let root: string, ws: string, home: string, l: ReturnType<typeof layout>;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "lsfw-g6-"));
    ws = join(root, "ws");
    home = join(root, "home");
    mkdirSync(join(ws, "src"), { recursive: true });
    mkdirSync(home, { recursive: true });
    l = layout(join(root, "fw"));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));
  let n = 0;
  const tainted = (def: Record<string, unknown>, where: "user" | "project" = "user", notice?: RegExp): boolean => {
    if (where === "user") writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: { filesystem: def } }));
    else writeFileSync(join(ws, ".mcp.json"), JSON.stringify({ mcpServers: { filesystem: def } }));
    const session = `s${n++}`;
    // Each case is a separate installation: with one state dir, the MCP pins would (rightly) see
    // the rewritten launch arguments as a changed server and taint the session for that reason.
    l = layout(join(root, `fw-${session}`));
    const ev = { hook_event_name: "PreToolUse", session_id: session, cwd: ws, permission_mode: "default", tool_name: "mcp__filesystem__read_file", tool_input: { path: join(ws, "src", "a.ts") } };
    const out = runHook(JSON.stringify(ev), { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, detectNonInteractive: () => false, home });
    // The session-start scan speaks only about configurations it flags on its own (a root of "/").
    if (notice === undefined) expect(out.stdout, out.stdout).toBe("");
    else expect(out.stdout).toMatch(notice);
    return loadState(l, session).tainted;
  };
  const pkg = ["-y", "@modelcontextprotocol/server-filesystem"];
  it("a root inside the workspace", () => {
    expect(tainted({ command: "npx", args: [...pkg, ws] })).toBe(false);
    expect(tainted({ command: "npx", args: [...pkg, join(ws, "src"), join(ws, "docs")] })).toBe(false);
    expect(tainted({ command: "npx", args: [...pkg, "."] })).toBe(false);
    expect(tainted({ command: "npx", args: [...pkg, "${workspaceFolder}/src"] })).toBe(false);
  });
  it("a root outside the workspace, or any root outside among several", () => {
    expect(tainted({ command: "npx", args: [...pkg, home] })).toBe(true);
    expect(tainted({ command: "npx", args: [...pkg, ws, home] })).toBe(true);
    expect(tainted({ command: "npx", args: [...pkg, ".."] })).toBe(true);
    expect(tainted({ command: "npx", args: [...pkg, "/"] }, "user", /ls-agent-mcp-filesystem-root/)).toBe(true);
  });
  it("roots that cannot be resolved, or none", () => {
    expect(tainted({ command: "npx", args: [...pkg, "$HOME/code"] })).toBe(true);
    expect(tainted({ command: "npx", args: [...pkg] })).toBe(true);
    expect(tainted({ command: "npx" })).toBe(true);
  });
  it("a server the repository defines is untrusted whatever it says", () => {
    // (The repository's server is also new to this installation, which the session start says: agent-safety audit I11.)
    expect(tainted({ command: "npx", args: [...pkg, ws] }, "project", /you have not used before/)).toBe(true);
  });
});

describe("R21: writes through a workspace-confined filesystem server are local writes, not sends", () => {
  const confined = { mcpSource: "user", mcpRoots: [WS] };
  it("write_file of an ordinary file in an untrusted session is allowed and recorded as a tainted write", () => {
    const d = run("mcp__filesystem__write_file", { path: `${WS}/src/a.ts`, content: "x" }, { tainted: true, ctx: confined });
    expect(d.verdict, explain(d)).toBe("allow");
    expect(d.events).toContainEqual({ type: "tainted_write", path: `${WS}/src/a.ts` });
  });
  it("the path rules still apply: CLAUDE.md is held, a path outside the workspace asks", () => {
    expect(run("mcp__filesystem__write_file", { path: `${WS}/CLAUDE.md`, content: "x" }, { tainted: true, ctx: confined }).rules).toContain("FW-INSTRUCTIONS-HELD");
    expect(run("mcp__filesystem__write_file", { path: "/Users/dev/other/x.txt", content: "x" }, { tainted: true, ctx: confined }).rules).toContain("FW-OUTSIDE-WRITE");
  });
  it("a filesystem server with roots outside the workspace (or unknown roots) is still judged as sending", () => {
    expect(run("mcp__filesystem__write_file", { path: `${WS}/a.ts`, content: "x" }, { tainted: true, ctx: { mcpSource: "user", mcpRoots: ["/Users/dev"] } }).rules).toContain("FW-SEND");
    expect(run("mcp__filesystem__write_file", { path: `${WS}/a.ts`, content: "x" }, { tainted: true, ctx: { mcpSource: "user" } }).rules).toContain("FW-SEND");
  });
});
