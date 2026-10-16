/**
 * The kill switch (FW-STOPPED): `session stop`, `agent stop`, `session resume`, `agent resume` through
 * main() in-process with scripted input, and the real hook in a temporary home. Every guarantee has its
 * refusal case: the agent cannot resume (its own tool call, a forged or replayed record, a project policy
 * file), a stop survives a restart, unreadable records keep the session stopped, and every stop and resume
 * is a signed log entry.
 */
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { main } from "../src/climain.js";
import { runHook, type HookEnv } from "../src/hook/claude.js";
import { initApprover, signStateChange, unlockApprover } from "../src/runtime/approver.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { tailLog, verifyLog } from "../src/runtime/log.js";
import { agentOfSession, listStops, readStops, resumeFields, resumeTarget, stopFile, stopTarget, stopView } from "../src/runtime/stops.js";
import { tempHome, testRoot } from "./helpers.js";

const PASS = "kill switch test passphrase";

let home: string, ws: string, l: Layout, clock: number, spawns: string[], seq = 0;

beforeEach(() => {
  home = tempHome("kill-home-");
  ws = mkdtempSync(join(testRoot(), "kill-ws-"));
  mkdirSync(join(ws, "src"), { recursive: true });
  writeFileSync(join(ws, "src", "a.ts"), "export const a = 1;\n");
  l = layout(join(home, ".launchsafe-firewall"));
  clock = Date.UTC(2026, 9, 13, 9, 0, 0);
  spawns = [];
});

const session = (): string => `k${++seq}`;

function env(): HookEnv {
  return { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, home, scratchRoots: [join(home, "tmp")], now: new Date(clock), detectNonInteractive: () => false, notifyDeps: { spawn: (_c, args) => void spawns.push(args[args.length - 1] ?? ""), platform: "darwin", executable: () => true, now: () => clock } };
}

function pre(s: string, tool: string, input: Record<string, unknown>, layoutOverride?: Layout): { verdict: string; reason: string } {
  const h = env();
  if (layoutOverride !== undefined) h.layout = layoutOverride;
  const r = runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: s, cwd: ws, permission_mode: "default", tool_name: tool, tool_input: input }), h);
  if (r.stdout.trim() === "") return { verdict: "allow", reason: "" };
  const o = JSON.parse(r.stdout) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
  return { verdict: o.hookSpecificOutput?.permissionDecision ?? "allow", reason: o.hookSpecificOutput?.permissionDecisionReason ?? "" };
}

const read = (s: string, layoutOverride?: Layout): { verdict: string; reason: string } => pre(s, "Read", { file_path: join(ws, "src", "a.ts") }, layoutOverride);

async function cli(args: string[], o: { human?: boolean; notAgent?: boolean; secret?: string } = {}): Promise<{ status: number; stdout: string; stderr: string }> {
  let stdout = "";
  let stderr = "";
  // notAgent and humanAtKeyboard share the in-process stand-in: `human` (default true) answers both.
  const status = await main(args, l, { write: (fd, s) => (fd === 1 ? (stdout += s) : (stderr += s)), humanAtKeyboard: () => Promise.resolve(o.human ?? o.notAgent ?? true), session: { readSecret: () => Promise.resolve(o.secret ?? PASS), env: {} } });
  return { status, stdout, stderr };
}

function logTypes(): string[] {
  return tailLog(l, 1000).map((e) => String((e as { event: { type?: string } }).event.type));
}

describe("kill switch: a person stops a session", () => {
  it("every later action is denied with FW-STOPPED and a clear message, reads included", async () => {
    const s = session();
    expect(read(s).verdict).toBe("allow");
    const r = await cli(["session", "stop", s, "--reason", "it is deleting the wrong branch"]);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(new RegExp(`Session ${s} is stopped`));
    for (const [tool, input] of [["Read", { file_path: join(ws, "src", "a.ts") }], ["Bash", { command: "npm test" }], ["Edit", { file_path: join(ws, "src", "a.ts"), old_string: "1", new_string: "2" }]] as const) {
      const d = pre(s, tool, input);
      expect(d.verdict, tool).toBe("deny");
      expect(d.reason).toMatch(/FW-STOPPED/);
      expect(d.reason).toMatch(/this session was stopped by a person/);
      expect(d.reason).toMatch(/it is deleting the wrong branch/);
      expect(d.reason).toMatch(new RegExp(`launchsafe-firewall session resume ${s}`));
    }
    // Other sessions are not affected.
    expect(read(session()).verdict).toBe("allow");
  });

  it("is logged as a signed entry, and stopping again records nothing new", async () => {
    const s = session();
    await cli(["session", "stop", s]);
    const again = await cli(["session", "stop", s]);
    expect(again.stdout).toMatch(/Already stopped/);
    const stops = tailLog(l, 1000).filter((e) => (e as { event: { type?: string } }).event.type === "stop");
    expect(stops).toHaveLength(1);
    expect(stops[0]).toMatchObject({ event: { type: "stop", scope: "session", target: s, by: "person" } });
    expect(typeof (stops[0] as { sig?: unknown }).sig).toBe("string");
    expect(verifyLog(l).ok).toBe(true);
  });

  it("stays stopped after a restart: the record is on disk, a fresh process reads it", async () => {
    const s = session();
    await cli(["session", "stop", s]);
    expect(existsSync(stopFile(l, "session", s))).toBe(true);
    // A new hook process: nothing in memory, a layout built again from the same home.
    const fresh = layout(join(home, ".launchsafe-firewall"));
    clock += 3 * 86400000;
    expect(read(s, fresh).verdict).toBe("deny");
    expect(stopView(fresh, s, "claude", null).active?.by).toBe("person");
  });

  it("session list shows what is stopped, by whom and why", async () => {
    const s = session();
    expect((await cli(["session", "list"])).stdout).toMatch(/No session or agent is stopped/);
    await cli(["session", "stop", s, "--reason", "looping"]);
    const out = (await cli(["session", "list"])).stdout;
    expect(out).toMatch(new RegExp(`session ${s}\\s+stopped by a person at .*: looping`));
    const j = JSON.parse((await cli(["session", "list", "--json"])).stdout) as { stopped: { scope: string; target: string; by: string }[] };
    expect(j.stopped).toEqual([expect.objectContaining({ scope: "session", target: s, by: "person" })]);
  });

  it("a process started by an agent may not stop a session (the command is refused, nothing is written)", async () => {
    const s = session();
    const r = await cli(["session", "stop", s], { notAgent: false });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/started from inside an agent session/);
    expect(existsSync(stopFile(l, "session", s))).toBe(false);
  });
});

describe("kill switch: agent stop", () => {
  it("stops every session of that agent, and only that agent", async () => {
    const [a, b] = [session(), session()];
    await cli(["agent", "stop", "claude", "--reason", "all hands"]);
    for (const s of [a, b]) {
      const d = read(s);
      expect(d.verdict).toBe("deny");
      expect(d.reason).toMatch(/every session of agent claude was stopped by a person/);
      expect(d.reason).toMatch(/launchsafe-firewall agent resume claude/);
    }
    // A Codex session, a gateway session and a local API agent are other agents.
    expect(stopView(l, "codex:x1", "codex", null).active).toBeNull();
    expect(stopView(l, "bot/x1", agentOfSession("bot/x1"), null).active).toBeNull();
  });

  it("a local API agent's sessions are <agentId>/<session>: agent stop covers them", async () => {
    await cli(["agent", "stop", "nightly-bot"]);
    expect(agentOfSession("nightly-bot/run-7")).toBe("nightly-bot");
    expect(agentOfSession("codex:abc")).toBe("codex");
    expect(agentOfSession("gateway:claude-desktop")).toBe("gateway");
    expect(agentOfSession("0b6c1e2a-claude-session")).toBeNull();
    expect(stopView(l, "nightly-bot/run-7", agentOfSession("nightly-bot/run-7"), null).active?.scope).toBe("agent");
  });

  it("refuses an agent id that is not one", async () => {
    const r = await cli(["agent", "stop", "../../etc"]);
    expect(r.status).toBe(64);
    expect(existsSync(l.stops)).toBe(false);
  });
});

describe("kill switch: only a person resumes, with the passphrase", () => {
  it("resume needs the passphrase; afterwards actions are checked as usual, and it is a signed log entry", async () => {
    initApprover(l, PASS);
    const s = session();
    await cli(["session", "stop", s]);
    expect(read(s).verdict).toBe("deny");
    const r = await cli(["session", "resume", s]);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/is resumed/);
    expect(read(s).verdict).toBe("allow");
    expect(logTypes().filter((t) => t === "stop" || t === "resume")).toEqual(["stop", "resume"]);
    expect(verifyLog(l).ok).toBe(true);
  });

  it("refused without a person at the keyboard: the session stays stopped", async () => {
    initApprover(l, PASS);
    const s = session();
    await cli(["session", "stop", s]);
    const r = await cli(["session", "resume", s], { human: false });
    expect(r.status).toBe(1);
    expect(read(s).verdict).toBe("deny");
  });

  it("refused with a wrong passphrase: the session stays stopped and nothing is written", async () => {
    initApprover(l, PASS);
    const s = session();
    await cli(["session", "stop", s]);
    const before = readFileSync(stopFile(l, "session", s), "utf8");
    await expect(cli(["session", "resume", s], { secret: "not the passphrase" })).rejects.toThrow(/wrong approval passphrase/);
    expect(readFileSync(stopFile(l, "session", s), "utf8")).toBe(before);
    expect(read(s).verdict).toBe("deny");
  });

  it("refused when no passphrase is set up (nothing could sign the resume)", async () => {
    const s = session();
    await cli(["session", "stop", s]);
    const r = await cli(["session", "resume", s]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/approver init/);
    expect(read(s).verdict).toBe("deny");
  });

  it("session resume does not end an agent stop", async () => {
    initApprover(l, PASS);
    const s = session();
    await cli(["agent", "stop", "claude"]);
    expect((await cli(["session", "resume", s])).stdout).toMatch(/is not stopped/);
    expect(read(s).verdict).toBe("deny");
    await cli(["agent", "resume", "claude"]);
    expect(read(s).verdict).toBe("allow");
  });
});

describe("kill switch: the agent cannot resume or clear a stop", () => {
  it("its own tool call: in a stopped session everything is FW-STOPPED, the resume command included", async () => {
    const s = session();
    await cli(["session", "stop", s]);
    for (const command of [`launchsafe-firewall session resume ${s}`, `rm -rf ${l.stops}`, "launchsafe-firewall agent resume claude"]) {
      const d = pre(s, "Bash", { command });
      expect(d.verdict, command).toBe("deny");
      expect(d.reason).toMatch(/FW-STOPPED/);
    }
  });

  it("from another session of the agent: the resume command, writing or deleting the records are FW-TAMPER", async () => {
    const s = session();
    const other = session();
    await cli(["session", "stop", s]);
    const file = stopFile(l, "session", s);
    for (const [tool, input] of [
      ["Bash", { command: `launchsafe-firewall session resume ${s}` }],
      ["Bash", { command: "launchsafe-firewall agent resume claude" }],
      ["Bash", { command: `launchsafe-firewall session stop ${s}` }],
      ["Bash", { command: `rm -f ${file}` }],
      ["Bash", { command: `echo '{}' > ${file}` }],
      ["Write", { file_path: file, content: "" }],
    ] as const) {
      const d = pre(other, tool, input);
      expect(d.verdict, JSON.stringify(input)).toBe("deny");
      expect(d.reason, JSON.stringify(input)).toMatch(/FW-TAMPER/);
    }
    // Reading the list is fine.
    expect(pre(other, "Bash", { command: "launchsafe-firewall session list" }).verdict).toBe("allow");
    expect(read(s).verdict).toBe("deny");
  });

  it("a resume written into the record without the approval key's signature is ignored", () => {
    initApprover(l, PASS);
    const s = session();
    const { stop } = stopTarget(l, "session", s, { by: "person", reason: "", approverKey: null });
    const file = stopFile(l, "session", s);
    appendFileSync(file, `${JSON.stringify({ type: "resume", id: "r1", at: new Date(clock).toISOString(), stopId: stop.id, sig: "" })}\n`);
    appendFileSync(file, `${JSON.stringify({ type: "resume", id: "r2", at: new Date(clock).toISOString(), stopId: stop.id, sig: Buffer.alloc(64).toString("base64") })}\n`);
    // Signed by another key (another firewall home's passphrase).
    const otherHome = layout(join(tempHome("kill-other-"), ".launchsafe-firewall"));
    initApprover(otherHome, PASS);
    const otherKey = unlockApprover(otherHome, PASS);
    appendFileSync(file, `${JSON.stringify({ type: "resume", id: "r3", at: new Date(clock).toISOString(), stopId: stop.id, sig: signStateChange(otherKey, "resume", s, resumeFields("session", stop.id, "r3", new Date(clock).toISOString())) })}\n`);
    expect(readStops(l, "session", s, JSON.parse(readFileSync(join(l.keys, "approver.json"), "utf8")).publicKey as string).ignored).toBe(3);
    expect(read(s).verdict).toBe("deny");
  });

  it("an old resume never ends a newer stop (a resume names the stop it ends)", () => {
    initApprover(l, PASS);
    const priv = unlockApprover(l, PASS);
    const pub = JSON.parse(readFileSync(join(l.keys, "approver.json"), "utf8")).publicKey as string;
    const s = session();
    stopTarget(l, "session", s, { by: "person", reason: "first", approverKey: pub });
    resumeTarget(l, "session", s, { sign: (f) => signStateChange(priv, "resume", s, f), approverKey: pub });
    expect(read(s).verdict).toBe("allow");
    const file = stopFile(l, "session", s);
    const oldResume = readFileSync(file, "utf8").trim().split("\n").at(-1) as string;
    stopTarget(l, "session", s, { by: "person", reason: "second", approverKey: pub });
    appendFileSync(file, `${oldResume}\n`);
    expect(read(s).verdict).toBe("deny");
    // A resume signed for another session does not transfer either.
    const t = session();
    const { stop } = stopTarget(l, "session", t, { by: "person", reason: "", approverKey: pub });
    appendFileSync(stopFile(l, "session", t), `${JSON.stringify({ type: "resume", id: "x", at: new Date(clock).toISOString(), stopId: stop.id, sig: signStateChange(priv, "resume", s, resumeFields("session", stop.id, "x", new Date(clock).toISOString())) })}\n`);
    expect(read(t).verdict).toBe("deny");
  });

  it("a repository policy file cannot resume it or switch the monitor off", () => {
    const s = session();
    stopTarget(l, "session", s, { by: "person", reason: "", approverKey: null });
    writeFileSync(join(ws, ".launchsafe-firewall.json"), JSON.stringify({ version: 3, budgets: { enabled: false, loop: { stopNonAllow10m: 100000, stopConfigTouches10m: 100000 } } }));
    expect(read(s).verdict).toBe("deny");
    writeFileSync(join(ws, ".launchsafe-firewall.json"), JSON.stringify({ version: 3, stops: { resume: [s] }, resume: true }));
    expect(read(s).verdict).toBe("deny");
  });
});

describe("kill switch: unreadable records fail closed", () => {
  it("a damaged record keeps the session stopped; a person's resume moves it aside", async () => {
    initApprover(l, PASS);
    const s = session();
    mkdirSync(l.stops, { recursive: true });
    writeFileSync(stopFile(l, "session", s), "{not json\n");
    const d = read(s);
    expect(d.verdict).toBe("deny");
    expect(d.reason).toMatch(/stop record cannot be read|not a valid entry/);
    expect(listStops(l, null).stops).toEqual([expect.objectContaining({ by: "unreadable" })]);
    const r = await cli(["session", "resume", s]);
    expect(r.stdout).toMatch(/moved aside/);
    expect(read(s).verdict).toBe("allow");
  });

  it("a directory where the record should be keeps the session stopped", () => {
    const s = session();
    mkdirSync(stopFile(l, "session", s), { recursive: true });
    expect(read(s).verdict).toBe("deny");
  });

  it("a stop line filed under another session's name is damage, not someone else's stop", () => {
    const s = session();
    mkdirSync(l.stops, { recursive: true });
    writeFileSync(stopFile(l, "session", s), `${JSON.stringify({ type: "stop", id: "a", at: "2026-10-13T09:00:00.000Z", scope: "session", target: "someone-else", by: "person", reason: "" })}\n`);
    expect(readStops(l, "session", s, null).damaged).toBe(true);
    expect(read(s).verdict).toBe("deny");
  });
});
