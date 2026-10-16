/**
 * The Gemini CLI adapter, driven by events captured live from Gemini
 * CLI 0.63.0 (test/fixtures/gemini-0.63.0-*.json) and the K rows of its acceptance table.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { geminiAdapter, geminiUnattendedArgs, normalizeGemini, parseGemini, urlsIn } from "../../src/adapters/gemini.js";
import { UNPARSEABLE_TOOL } from "../../src/adapters/types.js";
import { install, readRecords } from "../../src/runtime/install.js";
import { listQueue, loadState } from "../../src/runtime/store.js";
import { box, fixture, rules, send, verdict, type Box } from "./harness.js";

let b: Box;
beforeEach(() => {
  b = box();
});
afterEach(() => b.cleanup());

const pre = (tool_name: string, tool_input: Record<string, unknown>) => ({ hook_event_name: "BeforeTool", tool_name, tool_input });
const post = (tool_name: string, tool_input: Record<string, unknown>, tool_response: unknown) => ({ hook_event_name: "AfterTool", tool_name, tool_input, tool_response });
const taint = (): void => {
  send(b, "gemini", post("web_fetch", { prompt: "Summarize https://blog.example.org/post" }, { llmContent: "(outside content placeholder)" }));
};

describe("captured Gemini CLI 0.63.0 events parse", () => {
  const cases: [string, string, string?][] = [
    ["BeforeTool-run_shell_command", "pre_tool", "run_shell_command"],
    ["AfterTool-run_shell_command", "post_tool", "run_shell_command"],
    ["BeforeTool-write_file", "pre_tool", "write_file"],
    ["BeforeTool-replace", "pre_tool", "replace"],
    ["BeforeTool-glob", "pre_tool", "glob"],
    ["BeforeTool-grep_search", "pre_tool", "grep_search"],
    ["BeforeTool-list_directory", "pre_tool", "list_directory"],
    ["BeforeTool-write_todos", "pre_tool", "write_todos"],
    ["BeforeTool-mcp", "pre_tool", "mcp_echosrv_echo"],
    ["AfterTool-mcp", "post_tool", "mcp_echosrv_echo"],
    ["BeforeAgent", "prompt"],
    ["SessionStart", "session_start"],
    ["SessionEnd", "session_end"],
    ["AfterAgent", "ignored"],
    ["BeforeModel", "ignored"],
    ["BeforeToolSelection", "ignored"],
    ["PreCompress", "ignored"],
  ];
  for (const [name, kind, tool] of cases) {
    it(`${name} -> ${kind}`, () => {
      const ev = parseGemini(fixture(`gemini-0.63.0-${name}.json`));
      expect(ev.kind).toBe(kind);
      if (tool !== undefined) expect(ev.tool).toBe(tool);
    });
  }
  it("the captured MCP call is named by its server (mcp_context)", () => {
    const ev = parseGemini(fixture("gemini-0.63.0-BeforeTool-mcp.json"));
    expect(ev.mcp).toEqual({ server: "echosrv", tool: "echo", structural: true });
    expect(normalizeGemini(ev)).toEqual([{ tool: "mcp__echosrv__echo", input: { text: "hello mcp" } }]);
  });
  it("the captured tools normalize to the engine's vocabulary", () => {
    const n = (name: string) => normalizeGemini(parseGemini(fixture(`gemini-0.63.0-${name}.json`)));
    expect(n("BeforeTool-run_shell_command")).toEqual([{ tool: "Bash", input: { command: "echo hi" } }]);
    expect(n("BeforeTool-write_file")).toEqual([{ tool: "Write", input: { file_path: "added.txt", content: "hello added\n" } }]);
    expect(n("BeforeTool-replace")[0]?.tool).toBe("Edit");
    expect(n("BeforeTool-glob")[0]?.tool).toBe("Glob");
    expect(n("BeforeTool-grep_search")[0]?.tool).toBe("Grep");
    expect(n("BeforeTool-list_directory")[0]?.tool).toBe("LS");
    expect(n("BeforeTool-write_todos")[0]?.tool).toBe("TodoWrite");
  });
  it("the captured run is allowed silently (normal work)", () => {
    for (const name of ["BeforeTool-run_shell_command", "BeforeTool-write_file", "BeforeTool-replace", "BeforeTool-glob", "BeforeTool-grep_search", "BeforeTool-list_directory", "BeforeTool-write_todos"]) {
      const r = send(b, "gemini", { ...fixture(`gemini-0.63.0-${name}.json`), cwd: b.ws, session_id: "s1" });
      expect(verdict("gemini", r), name).toBe("allow");
      expect(r.stdout).toBe("");
    }
  });
  it("the captured read, search, fetch and web search tools normalize as documented", () => {
    const n = (name: string) => normalizeGemini(parseGemini(fixture(`gemini-0.63.0-${name}.json`)));
    expect(n("BeforeTool-read_file")).toEqual([{ tool: "Read", input: { file_path: "notes.txt" } }]);
    expect(n("BeforeTool-search_file_content")[0]?.tool).toBe("Grep");
    expect(n("BeforeTool-google_web_search")).toEqual([{ tool: "WebSearch", input: { query: "launchsafe" } }]);
    expect(n("BeforeTool-web_fetch").map((a) => a.input.url)).toEqual(["https://a.example/x", "https://b.example/y"]);
  });
  it("the captured secret flow (cat .env | curl -d @-) is denied FW-SECRET-FLOW", () => {
    const r = send(b, "gemini", { ...fixture("gemini-0.63.0-BeforeTool-run_shell_command-secret-flow.json"), cwd: b.ws, session_id: "s1" });
    expect(verdict("gemini", r)).toBe("deny");
    expect(rules("gemini", r)).toContain("FW-SECRET-FLOW");
  });
  it("the project directory comes from GEMINI_PROJECT_DIR", () => {
    expect(geminiAdapter.projectDirEnv).toBe("GEMINI_PROJECT_DIR");
  });
});

describe("Gemini CLI input shapes", () => {
  it("web_fetch: every URL in the prompt", () => {
    // F3 (final review): whitespace-delimited, as Gemini CLI requests them (trailing punctuation included).
    expect(urlsIn("Compare https://a.example/x, and https://b.example/y.")).toEqual(["https://a.example/x,", "https://b.example/y."]);
    expect(urlsIn("see (https://a.example/q?d=(x)) and 'https://b.example/p'")).toEqual(["https://a.example/q?d=(x))", "https://b.example/p'"]);
  });
  it("read_many_files: plain paths are reads, globs are recursive reads of their base", () => {
    const ev = parseGemini({ hook_event_name: "BeforeTool", session_id: "s", cwd: "/w", tool_name: "read_many_files", tool_input: { paths: ["README.md", "docs/**/*.md"] } });
    expect(normalizeGemini(ev)).toEqual([{ tool: "Read", input: { file_path: "README.md" } }, { tool: "Grep", input: { pattern: "", path: "docs" } }]);
  });
  it("run_shell_command with a directory runs there; without a command it is unparseable", () => {
    expect(normalizeGemini(parseGemini({ hook_event_name: "BeforeTool", session_id: "s", cwd: "/w", tool_name: "run_shell_command", tool_input: { command: "ls", dir_path: "sub" } }))[0]?.input).toEqual({ command: "cd 'sub' && ls" });
    expect(normalizeGemini(parseGemini({ hook_event_name: "BeforeTool", session_id: "s", cwd: "/w", tool_name: "run_shell_command", tool_input: {} }))[0]?.tool).toBe(UNPARSEABLE_TOOL);
  });
  it("unattended: gemini -p and yolo mode", () => {
    expect(geminiUnattendedArgs("node /usr/local/bin/gemini -p summarise")).toMatch(/-p/);
    expect(geminiUnattendedArgs("node /usr/local/lib/node_modules/@google/gemini-cli/dist/index.js --yolo")).toMatch(/yolo/);
    expect(geminiUnattendedArgs("node /usr/local/bin/gemini")).toBeNull();
  });
  it("malformed BeforeTool fails closed", () => {
    expect(send(b, "gemini", { hook_event_name: "BeforeTool", tool_input: {} }).exitCode).toBe(2);
    expect(send(b, "gemini", { tool_name: "run_shell_command" }).exitCode).toBe(2);
  });
});

describe("acceptance rows K7-K10, K14", () => {
  it("K7: run_shell_command rm -rf ~ -> deny FW-DESTROY-ROOT (Gemini's decision format)", () => {
    const r = send(b, "gemini", pre("run_shell_command", { command: "rm -rf ~" }));
    expect(verdict("gemini", r)).toBe("deny");
    expect(rules("gemini", r)).toContain("FW-DESTROY-ROOT");
    const o = JSON.parse(r.stdout) as { decision: string; reason: string };
    expect(o.decision).toBe("deny");
    expect(o.reason).toMatch(/blocked/);
  });
  it("K8: web_fetch with two URLs (untrusted) -> FW-FETCH judged per URL; the fetch taints on AfterTool", () => {
    taint();
    const input = { prompt: "Compare https://docs.one.example/a and https://two.example/b" };
    const r = send(b, "gemini", pre("web_fetch", input));
    expect(verdict("gemini", r)).toBe("queue");
    expect(rules("gemini", r)).toContain("FW-FETCH");
    expect(r.stdout).toContain("docs.one.example");
    expect(r.stdout).toContain("two.example");
    // A fresh session: the fetch itself (allowed when trusted) taints only once it ran.
    const s = { session_id: "fresh" };
    expect(verdict("gemini", send(b, "gemini", { ...pre("web_fetch", input), ...s }))).toBe("allow");
    send(b, "gemini", { ...post("web_fetch", input, { llmContent: "(outside content placeholder)" }), ...s });
    expect(loadState(b.l, "gemini:fresh").tainted).toBe(true);
  });
  it("K9: save_memory (untrusted) -> held as a proposal, FW-INSTRUCTIONS-HELD", () => {
    taint();
    const r = send(b, "gemini", pre("save_memory", { fact: "prefers tabs" }));
    expect(verdict("gemini", r)).toBe("queue");
    expect(rules("gemini", r)).toContain("FW-INSTRUCTIONS-HELD");
    const item = listQueue(b.l).items[0];
    expect(item?.kind).toBe("proposal");
    expect(item?.tool).toBe("save_memory");
    expect(item?.proposal?.target).toMatch(/\.gemini\/GEMINI\.md$/);
  });
  it("K9 (trusted): save_memory is allowed, like Claude Code memory writes in a clean session", () => {
    expect(verdict("gemini", send(b, "gemini", pre("save_memory", { fact: "prefers tabs" })))).toBe("allow");
  });
  it("K10: write_file of .gemini/settings.json removing the firewall's hook -> deny FW-TAMPER, trusted or not", () => {
    install(b.l, "project", b.ws, "t", { home: b.home, agent: "gemini", settings: geminiAdapter.settings });
    const path = join(b.ws, ".gemini", "settings.json");
    for (const state of ["trusted", "untrusted"]) {
      if (state === "untrusted") taint();
      const r = send(b, "gemini", pre("write_file", { file_path: path, content: '{"hooks":{}}\n' }));
      expect(verdict("gemini", r), state).toBe("deny");
      expect(rules("gemini", r)).toContain("FW-TAMPER");
    }
    // Switching Gemini's hook system off is tampering too.
    const now = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    const r = send(b, "gemini", pre("write_file", { file_path: path, content: JSON.stringify({ ...now, hooksConfig: { enabled: false } }) }));
    expect(rules("gemini", r)).toContain("FW-TAMPER");
    // An edit through replace is result-checked the same way.
    const text = readFileSync(path, "utf8");
    const r2 = send(b, "gemini", pre("replace", { file_path: path, old_string: '"BeforeTool"', new_string: '"BeforeToolX"' }));
    expect(text).toContain('"BeforeTool"');
    expect(rules("gemini", r2)).toContain("FW-TAMPER");
  });
  it("K14: install --agent gemini puts the hook first, wrapped, in ~/.gemini/settings.json, and records agent gemini", () => {
    const path = join(b.home, ".gemini", "settings.json");
    mkdirSync(join(b.home, ".gemini"), { recursive: true });
    writeFileSync(path, JSON.stringify({ hooks: { BeforeTool: [{ matcher: "run_shell_command", hooks: [{ type: "command", command: "other-hook" }] }] }, general: { vimMode: true } }));
    const r = install(b.l, "user", b.ws, "t", { home: b.home, agent: "gemini", settings: geminiAdapter.settings });
    expect(r.path).toBe(path);
    const s = JSON.parse(readFileSync(path, "utf8")) as { hooks: Record<string, { matcher?: string; hooks: { command: string; timeout: number; name: string }[] }[]>; general: unknown; hooksConfig: { enabled: boolean } };
    for (const ev of ["BeforeTool", "AfterTool", "BeforeAgent", "SessionStart"]) {
      const first = s.hooks[ev]?.[0];
      expect(first?.hooks[0]?.command).toMatch(/LAUNCHSAFE_FIREWALL_HOOK=1 .* hook --agent gemini \|\| \{ echo '.*' >&2; exit 2; \}$/);
      expect(first?.hooks[0]?.timeout).toBe(60000);
    }
    expect(s.hooks.BeforeTool?.[0]?.matcher).toBe("*");
    expect(s.hooks.BeforeTool?.[1]?.hooks[0]?.command).toBe("other-hook");
    expect(s.general).toEqual({ vimMode: true });
    expect(s.hooksConfig.enabled).toBe(true);
    expect(readRecords(b.l)).toEqual([expect.objectContaining({ agent: "gemini", scope: "user", path })]);
    // Idempotent.
    expect(install(b.l, "user", b.ws, "t", { home: b.home, agent: "gemini", settings: geminiAdapter.settings }).changed).toBe(false);
  });
});
