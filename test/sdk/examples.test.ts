/**
 * The examples in examples/sdk/ type-check against the built package (they import it by name, as a
 * user would) and run to completion offline, printing what they claim.
 */

import { spawnSync } from "node:child_process";
import { join } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { REPO } from "../helpers.js";

const DIR = join(REPO, "examples", "sdk");

function runExample(name: string): string {
  const r = spawnSync(process.execPath, [join(DIR, name)], { cwd: REPO, encoding: "utf8", timeout: 60_000, env: { ...process.env, RUN_CLAUDE: "" }, stdio: ["ignore", "pipe", "pipe"] });
  expect(r.status, `${name}: ${r.stderr}`).toBe(0);
  return r.stdout;
}

describe("examples/sdk", () => {
  it("type-check against the built package", () => {
    const cfg = ts.getParsedCommandLineOfConfigFile(join(DIR, "tsconfig.json"), {}, { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => undefined });
    if (cfg === undefined) throw new Error("no examples tsconfig");
    const program = ts.createProgram(cfg.fileNames, cfg.options);
    const problems = ts.getPreEmitDiagnostics(program).map((d) => `${d.file?.fileName.slice(REPO.length + 1) ?? ""}: ${ts.flattenDiagnosticMessageText(d.messageText, "\n")}`);
    expect(cfg.fileNames.length).toBe(5);
    expect(problems).toEqual([]);
  }, 120_000);

  it("plain-loop: the send asks (and nobody says yes), the credential flow is denied, the log verifies", () => {
    const out = runExample("plain-loop.ts");
    expect(out).toMatch(/send_email\s+ask\s+not run\s+FW-MESSAGE/);
    expect(out).toMatch(/run_shell\s+deny\s+not run\s+FW-SECRET-FLOW/);
    expect(out).toMatch(/chain intact, signed: true/);
  }, 60_000);

  it("vercel-ai: approval requested, then sent after the person's yes", () => {
    const out = runExample("vercel-ai.ts");
    expect(out).toMatch(/first call: approval requested/);
    expect(out).toMatch(/after the person's yes: Sent\./);
  }, 60_000);

  it("openai-agents: an interruption, then the run finishes after approve()", () => {
    const out = runExample("openai-agents.ts");
    expect(out).toMatch(/approval needed for send_email/);
    expect(out).toMatch(/final: Sent\./);
  }, 60_000);

  it("claude-agent-sdk: a read passes, a credential read asks", () => {
    const out = runExample("claude-agent-sdk.ts");
    expect(out).toMatch(/Read: allow/);
    expect(out).toMatch(/Bash: ask/);
  }, 60_000);

  it("langgraph: interrupted, then the tool ran after the resume", () => {
    const out = runExample("langgraph.ts");
    expect(out).toMatch(/interrupted: LaunchSafe Agent Firewall/);
    expect(out).toMatch(/tool result: sent to bob@example.com/);
  }, 60_000);
});
