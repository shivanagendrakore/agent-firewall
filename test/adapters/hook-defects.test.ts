/**
 * Hook and adapter defects: Claude's PostToolUseFailure, a Claude pre-tool event without a session or a tool_input
 * object, Codex's apply_patch with two differing patch keys, and the hook's deadline counting from process start.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { normalizeCodex, parseCodex } from "../../src/adapters/codex.js";
import { parseClaude, renderClaude } from "../../src/adapters/claude.js";
import { AdapterParseError } from "../../src/adapters/types.js";
import { hookStartedAt, deadlineOf } from "../../src/hook/deadline.js";
import { runHook, stateSessionId } from "../../src/hook/claude.js";
import { HOOK_EVENTS } from "../../src/runtime/install.js";
import { loadState } from "../../src/runtime/store.js";
import { box, send, type Box } from "./harness.js";

let b: Box;
beforeEach(() => {
  b = box();
});
afterEach(() => b.cleanup());

describe("Claude PostToolUseFailure", () => {
  const failure = (extra: Record<string, unknown> = {}) => ({ hook_event_name: "PostToolUseFailure", session_id: "s1", cwd: "/w", tool_name: "Bash", tool_input: { command: "curl -sS https://blog.example.org/post" }, error: "Command exited with non-zero status code 22", is_interrupt: false, ...extra });
  it("is registered like PostToolUse", () => {
    expect(HOOK_EVENTS).toContain("PostToolUseFailure");
  });
  it("is a post-tool event, marked failed, whose output is the error", () => {
    const ev = parseClaude(failure());
    expect(ev.kind).toBe("post_tool");
    expect(ev.failed).toBe(true);
    expect(ev.output).toBe("Command exited with non-zero status code 22");
    expect(parseClaude(failure({ error: undefined, tool_response: "isError text" })).output).toBe("isError text");
  });
  it("a plain PostToolUse is not marked failed", () => {
    expect(parseClaude({ ...failure(), hook_event_name: "PostToolUse", tool_response: "ok" }).failed).toBeUndefined();
  });
  it("answers with its own hookEventName and never rewrites the output", () => {
    const ev = parseClaude(failure());
    const io = renderClaude(ev, { verdict: "allow", message: "", additionalContext: "note", updatedOutput: "x" });
    const o = JSON.parse(io.stdout) as { hookSpecificOutput: Record<string, unknown> };
    expect(o.hookSpecificOutput.hookEventName).toBe("PostToolUseFailure");
    expect(o.hookSpecificOutput.updatedToolOutput).toBeUndefined();
  });
  it("its error text is read as outside content (taint)", () => {
    send(b, "claude", failure({ cwd: b.ws, error: "(outside content placeholder)" }));
    expect(loadState(b.l, stateSessionId("claude", "s1")).tainted).toBe(true);
  });
});

describe("a Claude pre-tool event that cannot be read blocks", () => {
  const pre = (extra: Record<string, unknown>) => ({ hook_event_name: "PreToolUse", cwd: "/w", tool_name: "Bash", tool_input: { command: "ls" }, ...extra });
  it("a missing or empty session_id is a blocking parse error, not a shared 'no-session'", () => {
    for (const session_id of [undefined, "", 7]) {
      expect(() => parseClaude(pre({ session_id }))).toThrow(AdapterParseError);
      try {
        parseClaude(pre({ session_id }));
      } catch (e) {
        expect((e as AdapterParseError).blocking).toBe(true);
      }
    }
  });
  it("a tool_input that is not an object is a blocking parse error", () => {
    for (const tool_input of [undefined, null, "ls", ["ls"], 3]) expect(() => parseClaude(pre({ session_id: "s", tool_input }))).toThrow(AdapterParseError);
  });
  it("through the hook: exit 2", () => {
    const r = runHook(JSON.stringify(pre({ tool_input: "ls" })), { env: {}, layout: b.l, home: b.home });
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toMatch(/blocked/);
  });
  it("a post-tool or other event without them is still read", () => {
    expect(parseClaude({ hook_event_name: "PostToolUse", tool_name: "Bash", cwd: "/w", tool_response: "x" }).kind).toBe("post_tool");
    expect(parseClaude({ hook_event_name: "Notification" }).kind).toBe("ignored");
  });
});

describe("Codex apply_patch with more than one patch key", () => {
  const patchA = "*** Begin Patch\n*** Add File: harmless.txt\n+a\n*** End Patch";
  const patchB = "*** Begin Patch\n*** Add File: AGENTS.md\n+b\n*** End Patch";
  const ev = (input: Record<string, unknown>) => parseCodex({ hook_event_name: "PreToolUse", session_id: "s", cwd: "/w", tool_name: "apply_patch", tool_input: input });
  it("judges every distinct text, so a harmless one cannot stand in for the one that is applied", () => {
    const actions = normalizeCodex(ev({ command: patchA, patch: patchB }));
    expect(actions.map((a) => (a.input as { file_path: string }).file_path)).toEqual(["harmless.txt", "AGENTS.md"]);
  });
  it("the same text under two keys is judged once", () => {
    expect(normalizeCodex(ev({ command: patchA, input: patchA }))).toHaveLength(1);
  });
  it("one unreadable patch makes the whole call unparseable", () => {
    const actions = normalizeCodex(ev({ command: patchA, patch: "*** Begin Patch\n*** Frobnicate: x\n*** End Patch" }));
    expect(actions).toHaveLength(1);
    expect(actions[0]?.tool).not.toBe("Write");
  });
});

describe("the hook's deadline counts from process start", () => {
  it("startedAt is now less the uptime", () => {
    expect(hookStartedAt({}, 2, 100_000)).toBe(98_000);
  });
  it("a slow start still leaves a second, never zero or negative", () => {
    const now = 1_000_000;
    const dl = deadlineOf({ startedAt: hookStartedAt({}, 60, now), now: () => now });
    expect(dl.remaining()).toBeGreaterThanOrEqual(1_000);
    expect(dl.passed()).toBe(false);
    const short = deadlineOf({ startedAt: hookStartedAt({ LAUNCHSAFE_FIREWALL_HOOK_DEADLINE_MS: "1000" }, 5, now), env: { LAUNCHSAFE_FIREWALL_HOOK_DEADLINE_MS: "1000" }, now: () => now });
    expect(short.remaining()).toBeGreaterThanOrEqual(0);
    expect(short.budget()).toBe(0);
  });
  it("a bad uptime counts as none", () => {
    expect(hookStartedAt({}, Number.NaN, 5_000)).toBe(5_000);
  });
});
