/**
 * F4: the human channel. Approvals need the approval passphrase (which the agent never sees); the
 * hook honours only approvals signed by the pinned approver key; anything else is tampering.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCipheriv, generateKeyPairSync, randomBytes, scryptSync, sign } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { agentLaunch, approverKdfWeak, approverPath, approverPublicKey, initApprover, launchedByAgent, passphraseProblem, rotateApprover, signApproval, signStateChange, stateChangeMessage, unlockApprover, verifyApproval, verifyStateChange, type ApprovalGrant } from "../src/runtime/approver.js";
import { hookCommand, pinnedApprover } from "../src/runtime/install.js";
import { layout } from "../src/runtime/layout.js";
import { appendEvents, enqueue, listQueue, loadState } from "../src/runtime/store.js";
import { runHook } from "../src/hook/claude.js";
import { processLine } from "../src/runtime/ancestry.js";
import { agentAncestor } from "../src/runtime/run/guards.js";
import { processStart } from "../src/gateway/session.js";

let root: string;
let l: ReturnType<typeof layout>;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-ap-"));
  l = layout(join(root, "home"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));
const PASS = "correct horse battery";
const grant = (sessionId: string, actionHash: string, id: string): ApprovalGrant => ({ sessionId, actionHash, id, nonce: "n1", exp: new Date(Date.now() + 3600_000).toISOString(), rules: ["FW-SEND"], cwd: "/w", projectDir: "/w" });

describe("approver key", () => {
  it("is created once, unlocks with the passphrase only", () => {
    const pub = initApprover(l, PASS);
    expect(approverPublicKey(l)).toBe(pub);
    expect(() => initApprover(l, "another passphrase")).toThrow(/already set/);
    expect(() => unlockApprover(l, "wrong passphrase!")).toThrow(/wrong/);
    expect(() => unlockApprover(l, PASS)).not.toThrow();
  });
  it("rejects a short passphrase", () => expect(() => initApprover(l, "short")).toThrow(/at least/));
  it("I4: rejects a passphrase under 14 characters or one that repeats a few characters", () => {
    expect(passphraseProblem("thirteen char")).toMatch(/at least 14/);
    expect(passphraseProblem("abababababababab")).toMatch(/too few different/);
    expect(passphraseProblem("correct horse battery")).toBeNull();
    expect(() => initApprover(l, "aaaaaaaaaaaaaaaaaaaa")).toThrow(/not strong enough/);
  });
  it("I4: a new key file uses scrypt N = 2^17", () => {
    initApprover(l, PASS);
    expect(JSON.parse(readFileSync(approverPath(l), "utf8")).kdf).toEqual({ alg: "scrypt", N: 1 << 17, r: 8, p: 1 });
  });
  it("I4: an older key file (N = 2^15, no kdf field) still unlocks, and is re-encrypted with the same key", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", scryptSync(PASS, salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }), iv);
    const ct = Buffer.concat([c.update(privateKey.export({ type: "pkcs8", format: "der" })), c.final()]);
    const pub = (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
    mkdirSync(l.keys, { recursive: true });
    writeFileSync(approverPath(l), JSON.stringify({ version: 1, publicKey: pub, salt: salt.toString("base64"), iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), ciphertext: ct.toString("base64"), createdAt: new Date().toISOString() }));
    expect(approverKdfWeak(l)).toBe(true);
    expect(() => unlockApprover(l, "wrong passphrase!")).toThrow(/wrong/);
    expect(approverKdfWeak(l)).toBe(true);
    unlockApprover(l, PASS);
    expect(approverKdfWeak(l)).toBe(false);
    expect(approverPublicKey(l)).toBe(pub);
    expect(() => unlockApprover(l, PASS)).not.toThrow();
  });
  it("M4: state changes are signed as a JSON array; v1 still verifies only when no value holds a newline", () => {
    const pub = initApprover(l, PASS);
    const priv = unlockApprover(l, PASS);
    const sig = signStateChange(priv, "scope-widen", "s", ["path", "/a\nb"]);
    expect(verifyStateChange(pub, "scope-widen", "s", ["path", "/a\nb"], sig)).toBe(true);
    expect(verifyStateChange(pub, "scope-widen", "s", ["path\n/a", "b"], sig)).toBe(false);
    expect(stateChangeMessage("resume", "s", ["x"]).toString()).toBe('["launchsafe-firewall/resume/v2","s","x"]');
    const v1 = (fields: string[]): string => sign(null, Buffer.from(["launchsafe-firewall/scope-widen/v1", "s", ...fields].join("\n")), priv).toString("base64");
    expect(verifyStateChange(pub, "scope-widen", "s", ["path", "/a"], v1(["path", "/a"]))).toBe(true);
    // A v1 signature over "path\n/a\nb" could be read as either split: not accepted.
    expect(verifyStateChange(pub, "scope-widen", "s", ["path", "/a\nb"], v1(["path", "/a\nb"]))).toBe(false);
  });
  it("I4: a key file naming a weaker KDF than any this version wrote is refused", () => {
    initApprover(l, PASS);
    const f = JSON.parse(readFileSync(approverPath(l), "utf8")) as { kdf: { N: number } };
    f.kdf.N = 1 << 10;
    writeFileSync(approverPath(l), JSON.stringify(f));
    expect(() => unlockApprover(l, PASS)).toThrow(/corrupt/);
  });
  it("rotation needs the old passphrase and changes the key", () => {
    const a = initApprover(l, PASS);
    expect(() => rotateApprover(l, "wrong passphrase!", "a brand new one")).toThrow(/wrong/);
    const b = rotateApprover(l, PASS, "a brand new one");
    expect(b).not.toBe(a);
    expect(() => unlockApprover(l, "a brand new one")).not.toThrow();
  });
  it("signs and verifies approvals bound to session, action and item", () => {
    const pub = initApprover(l, PASS);
    const g = grant("s1", "h1", "id1");
    const sig = signApproval(unlockApprover(l, PASS), g);
    expect(verifyApproval(pub, g, sig)).toBe(true);
    expect(verifyApproval(pub, { ...g, sessionId: "s2" }, sig)).toBe(false);
    expect(verifyApproval(pub, { ...g, actionHash: "h2" }, sig)).toBe(false);
    // B1/I2: the nonce, the expiry, the rules shown and where it was given are signed too.
    expect(verifyApproval(pub, { ...g, nonce: "other" }, sig)).toBe(false);
    expect(verifyApproval(pub, { ...g, exp: "2999-01-01T00:00:00.000Z" }, sig)).toBe(false);
    expect(verifyApproval(pub, { ...g, rules: ["FW-SEND", "FW-EXFIL"] }, sig)).toBe(false);
    expect(verifyApproval(pub, { ...g, cwd: "/elsewhere" }, sig)).toBe(false);
    expect(verifyApproval(pub, { ...g, projectDir: "/elsewhere" }, sig)).toBe(false);
  });
});

describe("the hook honours only signed approvals", () => {
  it("an approval written directly into the session file (no signature) is ignored and taints the session", () => {
    initApprover(l, PASS);
    appendEvents(l, "s", [{ type: "approval", actionHash: "h", id: "x" }]);
    const st = loadState(l, "s", approverPublicKey(l));
    expect(st.approvals.size).toBe(0);
    expect(st.tainted).toBe(true);
  });
  it("an approval signed by some other key is ignored", () => {
    const pub = initApprover(l, PASS);
    const other = generateKeyPairSync("ed25519").privateKey;
    const g = grant("s", "h", "x");
    appendEvents(l, "s", [{ type: "approval", actionHash: "h", id: "x", sig: signApproval(other, g), nonce: g.nonce, exp: g.exp, rules: [...g.rules], cwd: g.cwd, projectDir: g.projectDir }]);
    expect(loadState(l, "s", pub).approvals.size).toBe(0);
  });
  it("with no approver key at all, no approval counts", () => {
    appendEvents(l, "s", [{ type: "approval", actionHash: "h", id: "x", sig: "AAAA" }]);
    expect(loadState(l, "s", null).approvals.size).toBe(0);
  });
  it("the pinned key wins over the key file: replacing the file does not help a forger", () => {
    const pinned = initApprover(l, PASS);
    const ws = join(root, "ws");
    const env = { CLAUDE_PROJECT_DIR: ws, LAUNCHSAFE_FIREWALL_APPROVER: pinned };
    const e = { env, layout: l, detectNonInteractive: () => true };
    runHook(JSON.stringify({ hook_event_name: "PostToolUse", session_id: "u", cwd: ws, tool_name: "WebFetch", tool_input: { url: "https://x.example.com" }, tool_response: "p" }), e);
    const push = JSON.stringify({ hook_event_name: "PreToolUse", session_id: "u", cwd: ws, permission_mode: "default", tool_name: "Bash", tool_input: { command: "git push origin main" } });
    runHook(push, e);
    const item = listQueue(l).items[0];
    expect(item).toBeDefined();
    // A forger with its own key (as if it had replaced approver.json) signs the approval.
    const forged = generateKeyPairSync("ed25519").privateKey;
    const g = { ...grant("u", item!.actionHash, item!.id), rules: item!.rules, cwd: item!.cwd, projectDir: item!.projectDir ?? "" };
    appendEvents(l, "u", [{ type: "approval", actionHash: item!.actionHash, id: item!.id, sig: signApproval(forged, g), nonce: g.nonce, exp: g.exp, rules: [...g.rules], cwd: g.cwd, projectDir: g.projectDir }]);
    expect(runHook(push, e).stdout).toMatch(/held this for review/);
  });
  it("install pins the approver key in the hook command", () => {
    const pub = initApprover(l, PASS);
    const cmd = hookCommand(l);
    expect(pinnedApprover(cmd)).toBe(pub);
  });
  it("enqueue still works without an approver (approval is what needs it)", () => {
    enqueue(l, { sessionId: "s", cwd: "/w", tool: "Bash", input: {}, actionHash: "h", rules: [], reasons: [], kind: "approval" });
    expect(listQueue(l).items.length).toBe(1);
  });
});

describe("who is at the keyboard", () => {
  it("a Claude Code environment marks the caller as the agent", () => {
    expect(launchedByAgent({ CLAUDECODE: "1" }, 1)).toBe(true);
    expect(launchedByAgent({ CLAUDE_CODE_SESSION_ID: "abc" }, 1)).toBe(true);
  });
  it("without those markers and no ancestors to inspect, it is not the agent", () => {
    expect(launchedByAgent({}, 1)).toBe(false);
  });

  // A fake /proc: "<pid>/stat" with the parent in field 4 and the start time in field 22, and "<pid>/cmdline".
  const makeProc = (procs: Record<number, { ppid: number; comm?: string; args: string[]; starttime?: number }>): string => {
    const procRoot = join(root, "proc");
    for (const [pid, p] of Object.entries(procs)) {
      mkdirSync(join(procRoot, pid), { recursive: true });
      writeFileSync(join(procRoot, pid, "stat"), `${pid} (${p.comm ?? "node"}) S ${p.ppid} ${pid} ${pid} 0 -1 4194560 1200 0 0 0 10 5 0 0 20 0 11 0 ${p.starttime ?? 90210} 1234567 8000\n`);
      writeFileSync(join(procRoot, pid, "cmdline"), p.args.map((a) => `${a}\0`).join(""));
    }
    return procRoot;
  };
  const noExec = (): never => {
    throw new Error("no ps");
  };

  it("no ps and no /proc: the process table cannot be read, so the caller counts as an agent", () => {
    const missing = join(root, "missing-proc");
    expect(launchedByAgent({}, 500, (p) => processLine(p, { platform: "linux", procRoot: missing, exec: noExec }))).toBe(true);
    expect(launchedByAgent({}, 500, (p) => processLine(p, { platform: "darwin", exec: noExec }))).toBe(true);
    expect(launchedByAgent({}, 500, () => null)).toBe(true);
  });
  it("a process on the way that cannot be read counts as an agent; an unreadable PID 1 does not", () => {
    const procRoot = makeProc({
      400: { ppid: 300, args: ["node", "/usr/local/bin/launchsafe-firewall", "queue", "approve"] },
      300: { ppid: 1, comm: "zsh", args: ["-zsh"] },
    });
    // 300's parent, PID 1, is missing from the fake /proc (as with hidepid): the walk reached the top.
    expect(launchedByAgent({}, 400, (p) => processLine(p, { platform: "linux", procRoot }))).toBe(false);
    // A gap in the middle: 300 cannot be read.
    expect(launchedByAgent({}, 400, (p) => (p === 300 ? null : processLine(p, { platform: "linux", procRoot })))).toBe(true);
    // A loop in what was read.
    expect(launchedByAgent({}, 400, (p) => (p === 400 ? "300 node launchsafe-firewall" : "400 -zsh"))).toBe(true);
  });
  it("an agent ancestor read from /proc, PID 1 in a container included, is found by launchedByAgent and agentAncestor", () => {
    const procRoot = makeProc({
      300: { ppid: 200, args: ["node", "/usr/local/bin/launchsafe-firewall", "queue", "approve"] },
      200: { ppid: 100, comm: "sh", args: ["/bin/sh", "-c", "launchsafe-firewall queue approve"] },
      100: { ppid: 1, args: ["node", "/opt/node_modules/@openai/codex/bin/codex.js"] },
      1: { ppid: 0, comm: "init", args: ["/sbin/init"] },
    });
    const reader = (p: number) => processLine(p, { platform: "linux", procRoot });
    expect(launchedByAgent({}, 300, reader)).toBe(true);
    expect(agentAncestor(300, reader)).toContain("@openai/codex");

    rmSync(procRoot, { recursive: true, force: true });
    const inContainer = makeProc({
      50: { ppid: 1, comm: "sh", args: ["/bin/sh", "-c", "launchsafe-firewall status"] },
      1: { ppid: 0, comm: "claude", args: ["/usr/local/bin/claude"] },
    });
    const reader1 = (p: number) => processLine(p, { platform: "linux", procRoot: inContainer });
    expect(launchedByAgent({}, 50, reader1)).toBe(true);
    expect(agentAncestor(50, reader1)).toBe("/usr/local/bin/claude");
  });
  it("a plain shell chain with no agent is the person", () => {
    const procRoot = makeProc({
      400: { ppid: 300, args: ["node", "/usr/local/bin/launchsafe-firewall", "approver", "init"] },
      300: { ppid: 200, comm: "zsh", args: ["-zsh"] },
      200: { ppid: 1, comm: "sshd", args: ["sshd: user@pts/0"] },
      1: { ppid: 0, comm: "init", args: ["/sbin/init"] },
    });
    const reader = (p: number) => processLine(p, { platform: "linux", procRoot });
    expect(launchedByAgent({}, 400, reader)).toBe(false);
    expect(agentAncestor(400, reader)).toBeNull();
  });
  it("processStart reads field 22 of /proc/<pid>/stat on Linux, past a command name holding ')', and says unknown otherwise", () => {
    const procRoot = makeProc({ 400: { ppid: 1, comm: "a) S 1 (b", args: ["node"], starttime: 987654321 } });
    expect(processStart(400, { platform: "linux", procRoot })).toBe("987654321");
    expect(processStart(999, { platform: "linux", procRoot })).toBe("unknown");
    expect(processStart(400, { platform: "darwin", exec: noExec })).toBe("unknown");
  });
  it("processStart says unknown for a bad pid or a malformed stat line", () => {
    // Valid entries named "0" and "1.5": only the pid check keeps them from being read.
    const procRoot = makeProc({ 0: { ppid: 0, args: ["x"] }, 1.5: { ppid: 1, args: ["x"] } });
    expect(processStart(0, { platform: "linux", procRoot })).toBe("unknown");
    expect(processStart(1.5, { platform: "linux", procRoot })).toBe("unknown");
    const lstart = (): string => "Thu Oct 15 14:04:39 2026\n";
    expect(processStart(7, { platform: "darwin", exec: lstart })).toBe("ThuOct151404392026");
    expect(processStart(-3, { platform: "darwin", exec: lstart })).toBe("unknown");
    const stat = (pid: number, line: string): void => {
      mkdirSync(join(procRoot, String(pid)), { recursive: true });
      writeFileSync(join(procRoot, String(pid), "stat"), line);
    };
    // No "(comm)": without it the fields cannot be counted (read from the start, field 22 would be "11").
    stat(7, "7 node S 1 7 7 0 -1 4194560 1200 0 0 0 10 5 0 0 20 0 11 0 90210 1234567 8000\n");
    expect(processStart(7, { platform: "linux", procRoot })).toBe("unknown");
    stat(8, "8 (node) S 1 8 8\n");
    expect(processStart(8, { platform: "linux", procRoot })).toBe("unknown");
    stat(9, "9 (node) S 1 9 9 0 -1 4194560 1200 0 0 0 10 5 0 0 20 0 11 0 abc 1234567 8000\n");
    expect(processStart(9, { platform: "linux", procRoot })).toBe("unknown");
  });
  it("a parent chain longer than the 40-step walk counts as an agent, an agent past the walk included", () => {
    // Nested shells that do not reach the top within 40 reads: the walk cannot say the person started it.
    expect(launchedByAgent({}, 5000, (p) => `${p - 1} /bin/sh`)).toBe(true);
    expect(agentLaunch({}, 5000, (p) => `${p - 1} /bin/sh`)).toBe("unknown");
    // An agent 45 levels up, past the 40 processes read.
    expect(launchedByAgent({}, 5000, (p) => (p === 4955 ? "1 node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js" : `${p - 1} /bin/sh`))).toBe(true);
    // A chain of 30 shells up to init is still read to the top: the person.
    expect(launchedByAgent({}, 30, (p) => (p === 1 ? "0 /sbin/init" : `${p - 1} /bin/sh`))).toBe(false);
  });
  it("agentLaunch says why: the agent's variables, an agent's process, or a walk it could not finish", () => {
    expect(agentLaunch({ CLAUDECODE: "1" }, 1)).toBe("environment");
    expect(agentLaunch({}, 400, (p) => (p === 400 ? "300 node launchsafe-firewall" : "1 node /opt/node_modules/@anthropic-ai/claude-code/cli.js"))).toBe("process");
    expect(agentLaunch({}, 400, (p) => (p === 400 ? "300 node launchsafe-firewall" : null))).toBe("unknown");
    expect(agentLaunch({}, 400, (p) => (p === 400 ? "300 node launchsafe-firewall" : "400 -zsh"))).toBe("unknown");
    // PID 1 hidden (hidepid) ends the walk; PID 1 read with ppid 0 ends it too.
    expect(agentLaunch({}, 400, (p) => (p === 400 ? "1 -zsh" : null))).toBeNull();
    expect(agentLaunch({}, 400, (p) => (p === 400 ? "1 -zsh" : "0 /sbin/init"))).toBeNull();
  });
  it("on macOS the walk reads the parent and the full command line from ps", () => {
    const calls: string[][] = [];
    const table: Record<string, string> = { "60": "   50 /bin/zsh\n", "50": "   40 node /opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js\n" };
    const exec = (cmd: string, args: string[]): string => {
      calls.push([cmd, ...args]);
      return table[args[3] ?? ""] ?? "";
    };
    expect(processLine(50, { platform: "darwin", exec })).toBe("40 node /opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js");
    expect(calls[0]).toEqual(["ps", "-o", "ppid=,command=", "-p", "50"]);
    // Claude Code started by node is seen through its script path, which only the full command line holds.
    expect(launchedByAgent({}, 60, (p) => processLine(p, { platform: "darwin", exec }))).toBe(true);
    // ps printing nothing (the process is gone): nothing is known about it.
    expect(processLine(70, { platform: "darwin", exec })).toBeNull();
  });
});
