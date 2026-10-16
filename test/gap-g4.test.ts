/**
 * Gap G4: editor settings that switch on agent auto-approval.
 */
import { describe, expect, it } from "vitest";
import { explain, run, WS, type RunOpts } from "./helpers.js";

const UNTRUSTED: RunOpts = { tainted: true };
describe("G4: editor settings that switch on agent auto-approval", () => {
  const settings = `${WS}/.vscode/settings.json`;
  it("is detected in a written file", () => {
    for (const content of [
      '{"chat.tools.autoApprove": true}',
      '{\n  // yolo\n  "chat.tools.global.autoApprove": true,\n}',
      '{"chat.tools.terminal.autoApprove": {"/.*/": true}}',
      '{"claudeCode.initialPermissionMode": "bypassPermissions"}',
      '{"claudeCode.allowDangerouslySkipPermissions": true}',
    ]) {
      const d = run("Write", { file_path: settings, content });
      expect(d.verdict, `${content}: ${explain(d)}`).toBe("ask");
      expect(d.rules, explain(d)).toContain("FW-AGENT-SETTINGS");
      const u = run("Write", { file_path: settings, content }, UNTRUSTED);
      expect(u.rules, explain(u)).toContain("FW-INSTRUCTIONS-HELD");
    }
  });
  it("is detected in an edit's new text", () => {
    const d = run("Edit", { file_path: settings, old_string: '"editor.tabSize": 2', new_string: '"editor.tabSize": 2,\n  "chat.tools.autoApprove": true' });
    expect(d.rules, explain(d)).toContain("FW-AGENT-SETTINGS");
  });
  it("also covers workspace files and other editors' settings", () => {
    for (const f of [`${WS}/app.code-workspace`, `${WS}/.cursor/settings.json`, `${WS}/.zed/settings.json`]) {
      const d = run("Write", { file_path: f, content: '{"settings": {"chat.tools.autoApprove": true}}' });
      expect(d.rules, `${f}: ${explain(d)}`).toContain("FW-AGENT-SETTINGS");
    }
  });
  it("ordinary editor settings are allowed (false positives)", () => {
    for (const content of [
      '{"editor.formatOnSave": true, "eslint.validate": ["javascript"]}',
      '{"chat.tools.autoApprove": false}',
      '{"chat.tools.terminal.autoApprove": {"rm": false, "curl": false}}',
      '{"files.autoSave": "afterDelay", "git.autofetch": true}',
      '{"claudeCode.initialPermissionMode": "default"}',
    ]) {
      const d = run("Write", { file_path: settings, content });
      expect(d.rules, `${content}: ${explain(d)}`).not.toContain("FW-AGENT-SETTINGS");
      expect(d.rules).not.toContain("FW-INSTRUCTIONS-HELD");
    }
  });
  it("turning it off, or leaving it as it was, does not ask", () => {
    const d = run("Edit", { file_path: settings, old_string: '"chat.tools.autoApprove": true', new_string: '"chat.tools.autoApprove": false' });
    expect(d.rules).not.toContain("FW-AGENT-SETTINGS");
  });
});
