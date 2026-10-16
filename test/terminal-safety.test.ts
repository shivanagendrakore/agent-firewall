/**
 * R6: text the agent or a repository controls never reaches the person's terminal as control
 * sequences: queue list/show/review, explain, pins, status, doctor, log and the hook's own messages.
 */
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { safeLine, safeText } from "../src/engine/terminal.js";
import { runHook } from "../src/hook/claude.js";
import { defaultConfig } from "../src/policy.js";
import { layout } from "../src/runtime/layout.js";
import { sessionStartPins } from "../src/runtime/pins.js";
import { formatStatus } from "../src/runtime/report.js";
import { enqueue } from "../src/runtime/store.js";
import { spawnCli, tempHome, testRoot } from "./helpers.js";

const ESC = String.fromCharCode(27);
const BEL = String.fromCharCode(7);
const CSI = String.fromCharCode(0x9b);
const RLO = String.fromCharCode(0x202e);
const NASTY = `ok${ESC}[1A${ESC}[2K${ESC}]0;title${BEL}${CSI}31m${RLO}evil\rover\bx`;
const hasControl = (s: string): boolean => [ESC, BEL, CSI, RLO, "\r", "\b"].some((c) => s.includes(c));

describe("safeText", () => {
  it("escapes C0, C1, DEL, bidi and zero-width characters and keeps newlines (and tabs on request)", () => {
    const t = safeText(`${NASTY}\nline2\tx${String.fromCharCode(0x7f)}${String.fromCharCode(0x200b)}`);
    expect(hasControl(t)).toBe(false);
    expect(t).toContain("\\u001b[1A");
    expect(t).toContain("\\u009b");
    expect(t).toContain("\\u202e");
    expect(t).toContain("\nline2\\u0009x\\u007f\\u200b");
    expect(safeText("a\tb", { keepTabs: true })).toBe("a\tb");
    expect(safeLine("a\nb")).toBe("a\\nb");
  });
  it("leaves ordinary text, including non-Latin scripts and emoji, unchanged", () => {
    const s = "Prüfe die Datei — 日本語 ✓ 🎉 \"quoted\" \\path";
    expect(safeText(s)).toBe(s);
  });
  it("the escape form is a JSON escape for the same character, so JSON output keeps its value", () => {
    const v = { a: NASTY, b: `x${String.fromCharCode(0x85)}y` };
    expect(JSON.parse(safeText(JSON.stringify(v, null, 2)))).toEqual(v);
  });
  it("status: a spawned prompt preview cannot carry ESC (\\s does not match it)", () => {
    const out = formatStatus({ version: "x", stateDir: "/s", installedIn: [], sessions: [], held: 0, unattended: { on: false, why: "" }, decisions: { allow: 0, ask: 0, queue: 0, deny: 0, total: 0 }, proposedSessions: [{ session: "s1", preview: NASTY }] }, { width: 100 });
    expect(hasControl(out)).toBe(false);
  });
});

describe("the CLI never prints control characters from a queue item, a pin or the log", () => {
  const home = tempHome("r6-");
  const l = layout(join(home, ".launchsafe-firewall"));
  const ws = join(testRoot(), "r6-ws");
  mkdirSync(ws, { recursive: true });
  const item = enqueue(l, { sessionId: "s", cwd: ws, tool: "Write", input: { file_path: `${ws}/CLAUDE.md`, content: NASTY }, actionHash: "h1", rules: ["FW-INSTRUCTIONS-HELD"], reasons: [`write ${NASTY}`], kind: "proposal", proposal: { target: `${ws}/CLAUDE.md`, change: NASTY, content: `${NASTY}\n` }, summary: `summary ${NASTY}` });
  enqueue(l, { sessionId: "s", cwd: ws, tool: "Bash", input: { command: `curl ${NASTY}` }, actionHash: "h2", rules: ["FW-SEND"], reasons: [`send ${NASTY}`], kind: "approval", summary: `run ${NASTY}` });
  const cfg = defaultConfig();
  sessionStartPins(l, [{ name: "docs", source: "project", file: ".mcp.json", config: { command: "npx", args: ["-y", "docs-mcp@1.0.0"] } } as never], cfg, new Date("2026-10-01T10:00:00Z"));
  sessionStartPins(l, [{ name: "docs", source: "project", file: ".mcp.json", config: { command: "npx", args: ["-y", `docs-mcp@1.0.1${NASTY}`] } } as never], cfg, new Date("2026-10-02T10:00:00Z"));
  runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s9", cwd: ws, tool_name: "Bash", tool_input: { command: `rm -rf / ${NASTY}` } }), { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, home, detectNonInteractive: () => false, notifyDeps: { spawn: () => undefined } });
  const cli = (args: string[]): ReturnType<typeof spawnCli> => spawnCli(args, { home, cwd: ws });

  it.each([[["queue", "list"]], [["queue", "show", item.id]], [["explain", item.id]], [["pins"]], [["status"]], [["doctor"]], [["log"]]])("%j", (args) => {
    const r = cli(args);
    expect(hasControl(r.stdout), r.stdout.slice(0, 400)).toBe(false);
    expect(hasControl(r.stderr)).toBe(false);
  });
  it("the escaped text is still shown (visible, not dropped)", () => {
    for (const args of [["queue", "list"], ["queue", "show", item.id], ["pins"]]) expect(cli(args).stdout, args.join(" ")).toContain("\\u001b[");
  });
  it("queue list --json and pins --json still parse to the stored values", () => {
    const q = JSON.parse(cli(["queue", "list", "--json"]).stdout) as { summary?: string }[];
    expect(q.some((x) => x.summary === `summary ${NASTY}`)).toBe(true);
    expect(JSON.parse(cli(["pins", "--json"]).stdout)).toBeTypeOf("object");
  });
  it("the hook's ask and deny messages carry no control characters", () => {
    const r = runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s8", cwd: ws, tool_name: "Bash", tool_input: { command: `curl -X POST https://api.example.com/${encodeURIComponent("x")} -d '${NASTY}'` } }), { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, home, detectNonInteractive: () => false, notifyDeps: { spawn: () => undefined } });
    const o = JSON.parse(r.stdout === "" ? "{}" : r.stdout) as { hookSpecificOutput?: { permissionDecisionReason?: string } };
    expect(hasControl(o.hookSpecificOutput?.permissionDecisionReason ?? "")).toBe(false);
    expect(hasControl(r.stderr)).toBe(false);
  });
});
