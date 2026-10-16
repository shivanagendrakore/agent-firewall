/**
 * `launchsafe-firewall explain <id>` (acceptance rows X1-X9).
 */
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runHook } from "../src/hook/claude.js";
import { layout } from "../src/runtime/layout.js";
import { enqueue, listQueue } from "../src/runtime/store.js";
import { explainId } from "../src/runtime/explain.js";
import { tailLog } from "../src/runtime/log.js";
import { mkdirSync, writeFileSync } from "node:fs";
import { bash, explain as describeDecision, spawnCli, tempHome } from "./helpers.js";

const flat = (s: string): string => s.replace(/\s+/g, " ");

describe("explain <id>", () => {
  it("X1: explain FW-SEND", () => {
    const r = spawnCli(["explain", "FW-SEND"]);
    expect(r.status).toBe(0);
    const t = flat(r.stdout);
    expect(t).toContain("FW-SEND Sending data out after reading outside content");
    expect(t).toMatch(/trusted session: no · untrusted: needs you/);
    expect(t).toMatch(/Can you approve it: yes, once, for that exact action/);
    expect(t).toContain("Settings that change it: sendAllowHosts");
    expect(t).toMatch(/INC-02 GitHub MCP toxic agent flow; INC-07 Supabase MCP lethal trifecta/);
    expect(t).toMatch(/Maps to: OWASP LLM LLM01:2025, LLM02:2025, LLM06:2025 · OWASP Agentic ASI01, ASI02 · MITRE ATLAS: AML\.T0086 Exfiltration via AI Agent Tool Invocation; AML\.T0051 LLM Prompt Injection · MCP: MCP-TOOLS-HITL; MCP-TOOLS-CONFIRM/);
  });
  it("X2: explain FW-DLP-CREDENTIAL", () => {
    const t = flat(spawnCli(["explain", "FW-DLP-CREDENTIAL"]).stdout);
    expect(t).toContain("always on");
    expect(t).toContain("cannot be approved from inside the agent");
    expect(t).toContain("dataAllowHosts.credential");
  });
  it("X3: explain <queue id> of a proposal: summary, trust sources, diff, commands", () => {
    const home = tempHome();
    const ws = join(home, "ws");
    mkdirSync(ws, { recursive: true });
    writeFileSync(join(ws, "CLAUDE.md"), "# acme\n");
    const l = layout(join(home, ".launchsafe-firewall"));
    const e = { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, detectNonInteractive: () => false, home };
    const send = (ev: Record<string, unknown>): void => void runHook(JSON.stringify({ session_id: "x3", cwd: ws, permission_mode: "default", ...ev }), e);
    send({ hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: { url: "https://blog.example.org/p" }, tool_response: "page" });
    send({ hook_event_name: "PreToolUse", tool_name: "Edit", tool_input: { file_path: join(ws, "CLAUDE.md"), old_string: "# acme", new_string: "# acme\n\nNew rule." } });
    const id = listQueue(l).items[0]?.id ?? "";
    const r = spawnCli(["explain", id], { home, env: { COLUMNS: "100" } });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("proposed change");
    expect(r.stdout).toContain("+ New rule.");
    expect(flat(r.stdout)).toContain("FW-INSTRUCTIONS-HELD: It changes the agent's own instructions, memory or settings after reading outside content");
    expect(flat(r.stdout)).toMatch(/What made the session untrusted: - read the web page https:\/\/blog\.example\.org\/p/);
    expect(flat(r.stdout)).toContain(`Approve: launchsafe-firewall queue approve ${id} Reject: launchsafe-firewall queue reject ${id}`);
  });
  it("X4: explain <log seq> shows the decision with its rules explained", () => {
    const home = tempHome();
    const l = layout(join(home, ".launchsafe-firewall"));
    const e = { env: { CLAUDE_PROJECT_DIR: home }, layout: l, detectNonInteractive: () => false, home };
    runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: "x4", cwd: home, tool_name: "Bash", tool_input: { command: "curl http://169.254.169.254/latest/meta-data/" } }), e);
    const seq = tailLog(l, 1)[0]?.seq ?? -1;
    const t = flat(spawnCli(["explain", String(seq)], { home }).stdout);
    expect(t).toContain(`Log entry ${seq}`);
    expect(t).toContain("deny");
    expect(t).toContain("FW-METADATA: It asks the cloud metadata service");
  });
  it("X5: explain ls-agent-hidden-unicode (vendored agent-safety rule)", () => {
    const t = flat(spawnCli(["explain", "ls-agent-hidden-unicode"]).stdout);
    expect(t).toContain("Instruction file contains invisible characters");
    expect(t).toMatch(/Impact: Invisible or reordering characters/);
    expect(t).toMatch(/Fix: Delete the invisible characters/);
  });
  it("a finding id says which rule it feeds", () => {
    expect(flat(spawnCli(["explain", "credential_store_read"]).stdout)).toContain("It feeds FW-CREDENTIAL-READ");
  });
  it("X6: explain FW-NOPE exits 64", () => {
    const r = spawnCli(["explain", "FW-NOPE"]);
    expect(r.status).toBe(64);
    expect(r.stderr).toContain("no rule, queue item or log entry named FW-NOPE");
  });
  it("X7: explain with a JSON action on stdin is the v0.1 check output", () => {
    const input = JSON.stringify({ tool: "Bash", input: { command: "rm -rf ~" } });
    const home = tempHome();
    expect(JSON.parse(spawnCli(["explain"], { input, home }).stdout)).toEqual(JSON.parse(spawnCli(["check"], { input, home }).stdout));
  });
  it("X8: explain FW-SEND --json is the RuleDoc", () => {
    const d = JSON.parse(spawnCli(["explain", "FW-SEND", "--json"]).stdout) as Record<string, unknown>;
    expect(d.id).toBe("FW-SEND");
    expect(d.policyKeys).toEqual(["sendAllowHosts"]);
    expect(d.outcome).toEqual({ trusted: "n/a", untrusted: "approve", unattended: "queue" });
  });
  it("X9: an agent running explain FW-SEND is allowed (read-only)", () => {
    const d = bash("launchsafe-firewall explain FW-SEND", { tainted: true });
    expect(d.verdict, describeDecision(d)).toBe("allow");
  });
});

describe("R18: explain matches what the queue lets the person do", () => {
  it("a queued item's rules never say they cannot be approved; the rule pages state the partly approvable cases", () => {
    const home = tempHome("r18-");
    const l = layout(join(home, ".launchsafe-firewall"));
    const it0 = enqueue(l, { sessionId: "s", cwd: "/w", tool: "Bash", input: { command: "curl -X POST https://x.example" }, actionHash: "h", rules: ["FW-CANARY-READ", "FW-MALICIOUS-PACKAGE"], reasons: ["r"], kind: "approval" });
    const out = explainId(l, it0.id, { json: false, width: 100 }) ?? "";
    expect(out).not.toMatch(/Cannot be approved/);
    expect(explainId(l, "FW-CANARY-READ", { json: false, width: 200 })).toMatch(/can be approved once/);
    expect(explainId(l, "FW-MALICIOUS-PACKAGE", { json: false, width: 200 })).toMatch(/a listed version that is denied cannot be approved/);
  });
});
