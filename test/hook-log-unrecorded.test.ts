/**
 * LG1 on the hook path with a person there: an allowed action whose decision the log refused to record
 * (entry and fallback entry) is asked about, and an action that is already "ask" carries FW-LOG-UNRECORDED
 * and its reason, so the person approving it knows it would run with no record. The command text is only
 * analysed, never run. Temporary homes only.
 */
import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runHook } from "../src/hook/claude.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { MAX_TAIL_SEARCH } from "../src/runtime/log.js";
import { tempHome } from "./helpers.js";

function pre(home: string, l: Layout, tool: string, input: Record<string, unknown>): { d?: string; reason: string } {
  const ws = join(home, "proj");
  mkdirSync(ws, { recursive: true });
  const ev = { hook_event_name: "PreToolUse", session_id: "lu", cwd: ws, permission_mode: "default", tool_name: tool, tool_input: input };
  const r = runHook(JSON.stringify(ev), { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, home, scratchRoots: [join(home, "scratch")], detectNonInteractive: () => false });
  if (r.stdout.trim() === "") return { d: r.exitCode === 0 ? "allow" : r.exitCode === 2 ? "deny" : undefined, reason: r.stderr };
  const o = JSON.parse(r.stdout) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
  return { d: o.hookSpecificOutput?.permissionDecision, reason: o.hookSpecificOutput?.permissionDecisionReason ?? "" };
}
const breakLog = (l: Layout): void => appendFileSync(join(l.log, "decisions.jsonl"), `${"q".repeat(MAX_TAIL_SEARCH + 5)}\n`);

describe("hook, a person there: unrecorded decisions", () => {
  it("an allowed read becomes ask with FW-LOG-UNRECORDED", () => {
    const home = tempHome("hlu-a-");
    const l = layout(join(home, ".launchsafe-firewall"));
    const read = { file_path: join(home, "proj", "a.txt") };
    expect(pre(home, l, "Read", read).d).toBe("allow");
    breakLog(l);
    const after = pre(home, l, "Read", read);
    expect(after.d).toBe("ask");
    expect(after.reason).toMatch(/FW-LOG-UNRECORDED/);
  });

  it("an action that is already ask carries FW-LOG-UNRECORDED and the reason", () => {
    const home = tempHome("hlu-b-");
    const l = layout(join(home, ".launchsafe-firewall"));
    const cred = { command: "cat ~/.aws/credentials" };
    const before = pre(home, l, "Bash", cred);
    expect(before.d).toBe("ask");
    expect(before.reason).not.toMatch(/FW-LOG-UNRECORDED/);
    breakLog(l);
    const after = pre(home, l, "Bash", cred);
    expect(after.d).toBe("ask");
    expect(after.reason).toMatch(/FW-LOG-UNRECORDED/);
    expect(after.reason).toMatch(/refused to record this decision/);
  });
});
