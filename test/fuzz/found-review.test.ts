/**
 * Reproducers for the review of the API fuzzing pass (FZ14 to FZ20): what a review of those fixes found. Each
 * test failed on the code before its fix. Every command and path is data the engine judges; nothing is run.
 */
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { ApiCore } from "../../src/api/core.js";
import { verdictOf } from "../../src/demo.js";
import { MAX_EGRESS_EFFECTS } from "../../src/engine/effects.js";
import { InputTooDeep, isInputShapeError } from "../../src/engine/input-depth.js";
import { resolveMcpTool } from "../../src/engine/mcp.js";
import { afterTool } from "../../src/engine/post.js";
import { classifySql } from "../../src/engine/sql.js";
import { runHook } from "../../src/hook/claude.js";
import { inputShapeCheck } from "../../src/runtime/doctor.js";
import { layout, type Layout } from "../../src/runtime/layout.js";
import { appendLog, verifyLog } from "../../src/runtime/log.js";
import { createGuard } from "../../src/sdk/guard.js";
import { verifyEntries } from "../../src/sdk/log.js";
import { memoryStore } from "../../src/sdk/store.js";
import type { StateStore } from "../../src/sdk/types.js";
import { agent, apiTree, removeApiTree } from "../api/harness.js";
import { testRoot } from "../helpers.js";
import { deep } from "./gen.js";

const roots: string[] = [];
function home(): { l: Layout; ws: string } {
  const root = realpathSync(mkdtempSync(join(testRoot(), "lsfw-review-")));
  roots.push(root);
  const ws = join(root, "home", "proj");
  mkdirSync(ws, { recursive: true });
  return { l: layout(join(root, "home", ".launchsafe-firewall")), ws };
}
afterAll(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true });
});

const KEY = "AKIAZ3MXQ7P2LKJ4WN8R";

describe("review of the API fuzzing pass", () => {
  // 1. Every URL in a call's arguments was an egress effect carrying the whole payload, and the data rules scanned
  // the payload once per effect (and the duplicate check was linear): 2,000 URLs took 10 s, 8,000 took 167 s.
  it("R1: a call with 20,000 URLs in its arguments decides in seconds, and past 200 destinations a person decides", () => {
    const urls = Array.from({ length: 20_000 }, (_, i) => `https://h${i}.example/x`);
    for (const tool of ["mcp__notes__read_note", "mcp__gmail__send_email", "frobnicate"]) {
      const g = createGuard({ workspace: "/srv/app", home: "/home/agent", session: `r1-${tool}` });
      g.reportInput({ source: "a ticket", content: KEY });
      const t0 = performance.now();
      const d = g.decide({ tool, input: { urls }, mcpSource: "user" });
      expect(performance.now() - t0, tool).toBeLessThan(5000);
      expect(d.verdict).not.toBe("allow");
      // Integration with the kill switch (fw/t1-kill): a call that contacts more than the behaviour monitor's
      // new-host limit (budgets.loop.stopNewHosts10m, 40) in one go stops the session (FW-STOPPED, a denial),
      // which is stricter than the person's decision FW-UNCLASSIFIABLE asks for; one or the other, never allow.
      if (d.rules.includes("FW-STOPPED")) {
        expect(d.verdict, tool).toBe("deny");
        expect(d.engine.stop?.signal, tool).toBe("newhosts");
      } else expect(d.rules, tool).toContain("FW-UNCLASSIFIABLE");
    }
    // Under the cap nothing changes: a few URLs are each judged.
    const g = createGuard({ workspace: "/srv/app", home: "/home/agent", session: "r1-small" });
    const few = g.decide({ tool: "mcp__notes__read_note", input: { urls: urls.slice(0, MAX_EGRESS_EFFECTS - 10) }, mcpSource: "user" });
    expect(few.rules).not.toContain("FW-UNCLASSIFIABLE");
  });

  // 2. Every RangeError counted as the input's doing; only a stack overflow or an over-long string is.
  it("R2: only stack overflows, over-long strings and InputTooDeep are input-shape errors; the deny carries FW-INPUT-SHAPE and doctor counts it", () => {
    expect(isInputShapeError(new InputTooDeep())).toBe(true);
    expect(isInputShapeError(new RangeError("Maximum call stack size exceeded"))).toBe(true);
    expect(isInputShapeError(new RangeError("Invalid string length"))).toBe(true);
    expect(isInputShapeError(new RangeError("Invalid time value"))).toBe(false);
    expect(isInputShapeError(new RangeError("Invalid array length"))).toBe(false);
    const { l } = home();
    const g = createGuard({ workspace: "/w", home: "/home/u", session: "r2" });
    const d = g.decide({ tool: "Read", input: { file_path: "/w/a.ts", x: deep(5_000) } });
    expect(d.verdict).toBe("deny");
    expect(d.rules).toEqual(["FW-INPUT-SHAPE"]);
    expect(inputShapeCheck(l).status).toBe("ok");
    appendLog(l, { type: "decision", tool: "Read", verdict: "deny", rules: ["FW-INPUT-SHAPE"] });
    expect(inputShapeCheck(l)).toMatchObject({ status: "warn" });
  });

  // 3. A failure after the engine decided (recording the session, queueing) went to the failure policy, which let a
  // read-only tool through: an asked or denied Read became an allow.
  it("R3 (guard): a Read the engine asked about stays stopped when recording it fails", () => {
    const base = memoryStore();
    const store: StateStore = {
      ...base,
      append: () => {
        throw new Error("EIO: the session file cannot be written");
      },
    };
    const g = createGuard({ workspace: "/w", home: "/home/u", session: "r3", store, onLogError: () => undefined });
    const d = g.decide({ tool: "Read", input: { file_path: "/home/u/.ssh/id_rsa" } });
    expect(d.verdict).toBe("deny");
    expect(d.rules).toContain("FW-CREDENTIAL-READ");
    // An allowed read whose recording fails keeps the documented failure policy (it only reads).
    expect(g.decide({ tool: "Read", input: { file_path: "/w/a.ts" } }).verdict).toBe("allow");
  });

  it("R3 (guard): when the session cannot even be loaded, a read the engine would stop is denied, a plain read goes ahead", () => {
    const base = memoryStore();
    const store: StateStore = {
      ...base,
      load: () => {
        throw new Error("EIO: the session cannot be read");
      },
    };
    const g = createGuard({ workspace: "/w", home: "/home/u", session: "r3b", store, onLogError: () => undefined });
    expect(g.decide({ tool: "Read", input: { file_path: "/home/u/.ssh/id_rsa" } }).verdict).toBe("deny");
    expect(g.check({ tool: "Read", input: { file_path: "/home/u/.ssh/id_rsa" } }).verdict).toBe("deny");
    expect(g.decide({ tool: "Read", input: { file_path: "/w/a.ts" } }).verdict).toBe("allow");
  });

  it("R3 (hook): a Read of a private key the engine asked about is not allowed when the session cannot be written", () => {
    const { l, ws } = home();
    // The sessions directory is a file: the decision is made, then appending its events fails.
    mkdirSync(l.home, { recursive: true });
    writeFileSync(l.sessions, "not a directory");
    const ev = { hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: join(ws, "..", ".ssh", "id_rsa") }, session_id: "r3", cwd: ws };
    const res = runHook(JSON.stringify(ev), { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, agent: "claude", home: join(ws, ".."), detectNonInteractive: () => false, notifyDeps: { spawn: () => undefined } });
    expect(verdictOf(res.stdout, res.exitCode).verdict).not.toBe("allow");
  });

  // 5. A result too large or too deep to scan was scanned in part, silently.
  it("R5: a tool result past the scan's bounds marks the session as holding private data", () => {
    const many = Array.from({ length: 25_000 }, (_, i) => `s${i}`);
    expect(afterTool(many, { redact: false, source: "t" }).events).toContainEqual(expect.objectContaining({ type: "sensitive" }));
    expect(afterTool({ a: deep(300, "array", KEY) }, { redact: false, source: "t" }).events).toContainEqual(expect.objectContaining({ type: "sensitive" }));
    expect(afterTool({ a: "ok" }, { redact: false, source: "t" }).events).toEqual([]);
  });

  // 6. COPY\b[\s\S]*\bTO\s+PROGRAM scanned to the end of the text from every COPY.
  it("R6: SQL with 100,000 COPYs is classified in well under a second, and COPY ... TO PROGRAM is still external", () => {
    const t0 = performance.now();
    classifySql("COPY ".repeat(100_000));
    expect(performance.now() - t0).toBeLessThan(1000);
    expect(classifySql("COPY t TO PROGRAM 'curl x'").external).toBe(true);
    expect(classifySql("copy t from program 'sh'").external).toBe(true);
    expect(classifySql("COPY t TO '/tmp/x'").external).toBe(false);
  });

  // 7. mcp__notes___x was always read as server "notes", tool "_x": a server named "notes_" got notes' policy.
  it("R7: an ambiguous MCP name resolves only to a listed longest server, otherwise a person decides", () => {
    expect(resolveMcpTool("mcp__notes__read", {})).toEqual({ server: "notes", tool: "read", ambiguous: false });
    expect(resolveMcpTool("mcp__notes___read", { notes_: {} })).toEqual({ server: "notes_", tool: "read", ambiguous: false });
    expect(resolveMcpTool("mcp__notes___read", { notes: {} })).toMatchObject({ ambiguous: true });
    const g = createGuard({ workspace: "/w", home: "/home/u", session: "r7", policy: { mcpServers: { notes: { results: "trusted", privateData: false, readTools: ["*"] } } } });
    const plain = g.decide({ tool: "mcp__notes__read_note", input: { id: "1" }, mcpSource: "user" });
    expect(plain.verdict).toBe("allow");
    const spoof = g.decide({ tool: "mcp__notes___read_note", input: { id: "1" }, mcpSource: "user" });
    expect(spoof.verdict).not.toBe("allow");
    expect(spoof.rules).toContain("FW-UNCLASSIFIABLE");
  });

  // 8. One agent's traffic evicted every agent's decisions (one shared memory).
  it("R8: one agent filling the sidecar's memory does not make it forget another agent's decisions", () => {
    const t = apiTree();
    try {
      agent(t, "a");
      agent(t, "b");
      const core = new ApiCore({ l: t.l, env: {}, home: t.home, scratch: [t.scratch], fileAccess: false });
      const keep = String(core.decide("b", { session: "s", action: { format: "native", tool: "lookup_status", input: { id: "1" } } }, "", undefined).body.decisionId);
      for (let i = 0; i < 80; i++) core.decide("a", { session: "s", action: { format: "native", tool: "lookup_status", input: { id: "1", pad: `${i}`.padEnd(1_000_000, "A") } } }, "", undefined);
      const r = core.result("b", "s", { decisionId: keep, output: "fine" });
      expect(r.status).toBe(200);
      expect(r.body.rule).toBeUndefined();
    } finally {
      removeApiTree(t);
    }
  });

  // 9. Only the runtime log rejected extra fields; the library's verifier and the dashboard's index did not.
  it("R9: the library's log verifier refuses an entry with an extra field, and the runtime log names it", () => {
    const store = memoryStore();
    store.appendLog({ type: "decision", n: 1 });
    store.appendLog({ type: "decision", n: 2 });
    const entries = store.entries();
    expect(verifyEntries(entries).ok).toBe(true);
    const edited = entries.map((e, i) => (i === 1 ? { ...e, verdict: "allow" } : e));
    const v = verifyEntries(edited);
    expect(v.ok).toBe(false);
    expect(v.problems.join(" ")).toMatch(/outside its hashed content \("verdict"\)/);
    const { l } = home();
    for (let i = 0; i < 3; i++) appendLog(l, { type: "decision", i });
    const f = join(l.log, "decisions.jsonl");
    const lines = readFileSync(f, "utf8").split("\n");
    lines[1] = (lines[1] as string).replace(/^\{/, '{"verdict":"allow",');
    writeFileSync(f, lines.join("\n"));
    expect(verifyLog(l).problems.join(" ")).toMatch(/outside its hashed content \("verdict"\)/);
  });
});
