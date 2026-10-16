/** The dashboard finds a session's decisions when its id is not a plain file name (an API `agent/session` id). */

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { runHook, type HookEnv } from "../src/hook/claude.js";
import { layout, safeId } from "../src/runtime/layout.js";
import { sessionView } from "../src/ui/data.js";

const root = mkdtempSync(join(tmpdir(), "lsfw-uisid-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("session pages for ids that are hashed on disk", () => {
  it("lists the decisions logged under the raw id when the page asks by the file's id", () => {
    const l = layout(join(root, "home"));
    const ws = join(root, "ws");
    mkdirSync(ws, { recursive: true });
    const env: HookEnv = { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, detectNonInteractive: () => true };
    const raw = "agent/session one";
    runHook(JSON.stringify({ session_id: raw, cwd: ws, permission_mode: "default", hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "git push origin main" } }), env);
    const id = safeId(raw);
    expect(id).toMatch(/^h-[0-9a-f]{32}$/);
    const v = sessionView(l, id, new Date());
    expect(v.ok).toBe(true);
    if (!v.ok || v.value === null) throw new Error("the session was not found");
    expect(v.value.decisions.length).toBeGreaterThan(0);
  });
});
