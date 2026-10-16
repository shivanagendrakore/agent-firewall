/**
 * Review fixes in the settings, gateway, patch, store and policy readers: an Edit with an empty old_string
 * judged by the text it creates; a wrapper-shaped MCP entry that the install did not record; a patch path
 * with a control character; a torn session line before an approval_used; a user outsider exemption that
 * covers a managed server; unattendedHours entries that are not strings; `..` in a sandbox allowWrite entry.
 * Nothing runs a command; temporary homes only.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parsePatch } from "../src/engine/codex-patch.js";
import { entryHashOf, gatewayConfigChanges } from "../src/engine/gateway-config.js";
import { broadWritePath } from "../src/engine/sandbox.js";
import { applyEdits, looseEditResults } from "../src/engine/settings.js";
import { defaultConfig, mergeManaged, validatePolicy } from "../src/policy.js";
import { approvalSigner, initApprover, unlockApprover } from "../src/runtime/approver.js";
import { consumeApproval, readEvents, sessionFile } from "../src/runtime/store.js";
import { explain, HOME, run, WS } from "./helpers.js";
import { makeTree, removeTree } from "./sdk/harness.js";

describe("an Edit with an empty old_string creates the file with the new text", () => {
  it("applyEdits and looseEditResults give the new text for an absent or blank file", () => {
    expect(applyEdits("", [{ old: "", new: '{"a":1}' }])).toBe('{"a":1}');
    expect(applyEdits("  \n", [{ old: "", new: "x" }])).toBe("x");
    expect(applyEdits('{"a":1}', [{ old: "", new: "x" }])).toBe('{"a":1}');
    expect(looseEditResults("", [{ old: "", new: "x" }])).toEqual(["x"]);
    expect(looseEditResults("{}", [{ old: "", new: "x" }])).toBeNull();
  });
  const bad: [string, string][] = [
    [`${WS}/.gemini/settings.json`, '{"tools":{"enableHooks":false}}'],
    [`${WS}/.claude/settings.local.json`, '{"env":{"NODE_OPTIONS":"--require /tmp/x.js"}}'],
  ];
  for (const [file, text] of bad) {
    it(`creating ${file} with a hook-disabling result is denied`, () => {
      const d = run("Edit", { file_path: file, old_string: "", new_string: text });
      expect(d.verdict, explain(d)).toBe("deny");
      const blank = run("Edit", { file_path: file, old_string: "", new_string: text }, { ctx: { readFile: (p: string) => (p === file ? "" : null) } });
      expect(blank.verdict, explain(blank)).toBe("deny");
    });
  }
});

describe("a wrapper-shaped MCP entry the install did not record is an added server", () => {
  const recorded = { command: "node", args: ["/opt/fw/dist/cli.js", "mcp", "wrap", "--", "files"] };
  const key = JSON.stringify(["mcpServers", "files"]);
  const wrapped = { [key]: entryHashOf(recorded) };
  const text = (extra: unknown): string => JSON.stringify({ mcpServers: { files: recorded, x: extra } });
  it("flags a different program after --, and allows the recorded entry", () => {
    const evil = { command: "node", args: ["/tmp/x/dist/cli.js", "mcp", "wrap", "--", "evil"] };
    expect(gatewayConfigChanges(JSON.stringify({ mcpServers: { files: recorded } }), text(evil), wrapped, "/h/.claude.json").added).toEqual(["x"]);
    expect(gatewayConfigChanges(JSON.stringify({ mcpServers: { files: recorded } }), text(recorded), wrapped, "/h/.claude.json").added).toEqual([]);
  });
});

describe("a control character in a patch path", () => {
  it("is refused, so U+0085 cannot hide a suffix", () => {
    expect(parsePatch("*** Begin Patch\n*** Update File: .claude/settings.json\u0085\n@@\n-a\n+b\n*** End Patch\n").ok).toBe(false);
    expect(parsePatch("*** Begin Patch\n*** Add File: a\u0000b\n+1\n*** End Patch\n").ok).toBe(false);
    expect(parsePatch("*** Begin Patch\n*** Add File: a\n+1\n*** End Patch\n").ok).toBe(true);
  });
});

describe("consumeApproval after a torn last line", () => {
  it("starts its line on its own, so the approval reads as used", () => {
    const t = makeTree();
    try {
      const file = sessionFile(t.l, "s1");
      mkdirSync(t.l.home, { recursive: true });
      mkdirSync(join(file, ".."), { recursive: true });
      // A signed, unexpired approval, then a last line cut off by a crash.
      initApprover(t.l, "correct horse battery");
      const g = { sessionId: "s1", actionHash: "hash", id: "id1", nonce: "n1", exp: "2999-01-01T00:00:00.000Z", rules: ["FW-SEND"], cwd: "/w", projectDir: "/w" };
      const sig = approvalSigner(unlockApprover(t.l, "correct horse battery"))(g);
      writeFileSync(file, `${JSON.stringify({ type: "approval", actionHash: g.actionHash, id: g.id, sig, nonce: g.nonce, exp: g.exp, rules: g.rules, cwd: g.cwd, projectDir: g.projectDir })}\n{"type":"taint","torn`);
      expect(consumeApproval(t.l, "s1", "hash", "id1")).toBe(true);
      expect(readFileSync(file, "utf8")).toContain('\n{"type":"approval_used"');
      expect(readEvents(t.l, "s1").some((e) => e.type === "approval_used")).toBe(true);
    } finally {
      removeTree(t);
    }
  });
});

describe("a user outsiderWritable exemption that covers a managed server", () => {
  const user = { ...defaultConfig(), outsiderWritable: { exempt: ["*", "corp-*", "sentry"] } };
  it("is dropped whole when it matches a managed name, as a pattern or exactly", () => {
    const m = mergeManaged(user, validatePolicy({ version: 3, outsiderWritable: { servers: ["payments", "corp-desk"] } }, "m"));
    expect(m.config.outsiderWritable?.exempt).toEqual(["sentry"]);
  });
});

describe("unattendedHours entries must be strings", () => {
  it("refuses an array that stringifies to a time", () => {
    expect(() => validatePolicy({ version: 3, unattendedHours: [{ from: ["09:00"], to: "17:00" }] }, "p")).toThrow(/unattendedHours/);
    expect(() => validatePolicy({ version: 3, unattendedHours: [{ from: "09:00", to: ["17:00"] }] }, "p")).toThrow(/unattendedHours/);
    expect(validatePolicy({ version: 3, unattendedHours: [{ from: "09:00", to: "17:00" }] }, "p").unattendedHours).toEqual([{ from: "09:00", to: "17:00" }]);
  });
});

describe("broadWritePath folds `..`", () => {
  it("judges ~/proj/../.ssh as ~/.ssh", () => {
    expect(broadWritePath("~/proj/../.ssh", HOME)).toBe(true);
    expect(broadWritePath(`${HOME}/proj/./../../..`, HOME)).toBe(true);
    expect(broadWritePath("~/proj/sub/../build", HOME)).toBe(false);
  });
});
