/**
 * Runtime: session state and queue on disk, the signed hash-chained log with
 * rotation and tamper detection, policy loading (defaults, tightening,
 * invalid files), install/uninstall round-trips, and crash/corruption safety.
 */

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { layout } from "../src/runtime/layout.js";
import { appendEvents, decideQueueItem, enqueue, getQueueItem, listQueue, loadState, pruneSessions, readEvents } from "../src/runtime/store.js";
import { appendLog, loadKey, rotateNow, tailLog, verifyLog } from "../src/runtime/log.js";
import { loadPolicy } from "../src/runtime/config.js";
import { inspectSettings, install, MARKER, settingsPath, uninstall, withOurs, withoutOurs, HOOK_EVENTS } from "../src/runtime/install.js";
import { atomicWrite, withLock } from "../src/runtime/fsutil.js";
import { approvalSigner, initApprover, unlockApprover, approverPublicKey } from "../src/runtime/approver.js";

let root: string;
let l: ReturnType<typeof layout>;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-rt-"));
  l = layout(join(root, "home"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("session state", () => {
  it("appends and folds events; taint is sticky", () => {
    appendEvents(l, "s1", [{ type: "taint", source: "web" }]);
    appendEvents(l, "s1", [{ type: "sensitive", source: "env" }]);
    const st = loadState(l, "s1");
    expect(st.tainted).toBe(true);
    expect(st.sensitive).toBe(true);
  });
  it("a corrupt line makes the session untrusted, never looser", () => {
    appendEvents(l, "s2", [{ type: "fingerprint", hash: "x" }]);
    appendFileSync(join(l.sessions, "s2.jsonl"), "this is not json\n");
    const st = loadState(l, "s2");
    expect(st.tainted).toBe(true);
    expect(readEvents(l, "s2").some((e) => e.type === "corrupt")).toBe(true);
  });
  it("FZ21: a line that cannot be an event is damage, whatever JSON.parse would make of it, and each kind leaves the session untrusted", () => {
    mkdirSync(l.sessions, { recursive: true });
    const damage = ["not json at all", "5", "[]", '"text"', "null", "{}", "{x}", "{nope", "{xxxxxxxxxx}", "{ \t  }", '{"type":"taint","source":"cut off', '{"type":"taint"}', '{"type":"fingerprint","hash":"a"}{"type":"taint","source":"b"}', '{"type":"taint","source":}', '{ "type" "taint" }'];
    for (const [i, line] of damage.entries()) {
      writeFileSync(join(l.sessions, `dmg${i}.jsonl`), `${JSON.stringify({ type: "fingerprint", hash: "ok" })}\n${line}\n`);
      const evs = readEvents(l, `dmg${i}`);
      expect(evs.map((e) => e.type), line).toEqual(["fingerprint", "corrupt"]);
      expect(loadState(l, `dmg${i}`).tainted, line).toBe(true);
      expect(loadState(l, `dmg${i}`).fingerprints.has("ok"), line).toBe(true);
    }
  });
  it("FZ21: a line that is valid is never mistaken for damage: an escaped key, padding, space or a carriage return inside the brace, and a carriage return at the end still parse", () => {
    mkdirSync(l.sessions, { recursive: true });
    writeFileSync(join(l.sessions, "ok.jsonl"), ['{"\\u0074ype":"downloaded","path":"/a"}', '  {"type":"downloaded","path":"/b"}  ', '{"type":"downloaded","path":"/c"}\r', '\t{"type":"fingerprint","hash":"h"}\t', '{ \t "type":"downloaded","path":"/d"}', '{\r"type":"downloaded","path":"/e"}'].join("\n") + "\n");
    expect(readEvents(l, "ok").map((e) => e.type)).toEqual(["downloaded", "downloaded", "downloaded", "fingerprint", "downloaded", "downloaded"]);
    const st = loadState(l, "ok");
    expect(st.tainted).toBe(false);
    expect([...st.downloaded]).toEqual(["/a", "/b", "/c", "/d", "/e"]);
  });
  it("FZ21: many damaged lines are listed a few at a time and counted, every line is still read, and the session is untrusted", () => {
    mkdirSync(l.sessions, { recursive: true });
    const junk = Array.from({ length: 5000 }, (_, i) => (i % 3 === 0 ? "<<EOF" : i % 3 === 1 ? `{"type":"taint"${i}` : "{}")).join("\n");
    writeFileSync(join(l.sessions, "many.jsonl"), `${junk}\n${JSON.stringify({ type: "downloaded", path: "/after" })}\n${JSON.stringify({ type: "fingerprint", hash: "late" })}\n`);
    const evs = readEvents(l, "many");
    const corrupt = evs.filter((e) => e.type === "corrupt");
    expect(corrupt.length).toBe(11);
    expect(corrupt.at(-1)).toEqual({ type: "corrupt", detail: "4990 more damaged lines (5000 in all)" });
    expect(corrupt[0]).toEqual({ type: "corrupt", detail: "line 1 of the session file is not a JSON object" });
    expect(evs.filter((e) => e.type !== "corrupt").map((e) => e.type)).toEqual(["downloaded", "fingerprint"]);
    const st = loadState(l, "many");
    expect(st.tainted && st.sensitive).toBe(true);
    // What tightens the session after the damage still counts.
    expect(st.downloaded.has("/after")).toBe(true);
    expect(st.fingerprints.has("late")).toBe(true);
  });
  it("FZ21: lines that parse as JSON but are not events are listed with parseEvent's reason and counted with the rest of the damage", () => {
    mkdirSync(l.sessions, { recursive: true });
    const taintNoSource = '{"type":"taint"}';
    const unknown = '{"type":"nope","x":1}';
    const lines = [...Array<string>(5).fill(taintNoSource), ...Array<string>(30).fill(unknown), ...Array<string>(25).fill(taintNoSource), "<<EOF", '{"type":"taint","source":}', JSON.stringify({ type: "fingerprint", hash: "late" })];
    writeFileSync(join(l.sessions, "sem.jsonl"), `${lines.join("\n")}\n`);
    const evs = readEvents(l, "sem");
    const corrupt = evs.filter((e) => e.type === "corrupt");
    // The first ten keep the reason parseEvent gave; the 60 such lines and the two that are not JSON share one count.
    expect(corrupt.slice(0, 10)).toEqual([...Array(5).fill({ type: "corrupt", detail: "taint without source" }), ...Array(5).fill({ type: "corrupt", detail: "unknown event type nope" })]);
    expect(corrupt.slice(10)).toEqual([{ type: "corrupt", detail: "52 more damaged lines (62 in all)" }]);
    expect(evs.filter((e) => e.type !== "corrupt").map((e) => e.type)).toEqual(["fingerprint"]);
    const st = loadState(l, "sem");
    expect(st.tainted && st.sensitive).toBe(true);
    expect(st.fingerprints.has("late")).toBe(true);
  });
  it("FZ21: a line that cannot be an event is recorded as damage without being handed to JSON.parse", () => {
    mkdirSync(l.sessions, { recursive: true });
    // Each would make JSON.parse throw, or give something that is not an event: a thrown error apiece cost seconds for a large file.
    const junk = ["<<EOF", "{}", "{xxxxxxxxxx}", "5", "[]", '{"type":"taint"7'];
    const valid = JSON.stringify({ type: "fingerprint", hash: "h" });
    writeFileSync(join(l.sessions, "pre.jsonl"), `${Array.from({ length: 1000 }, (_, i) => junk[i % junk.length]).join("\n")}\n${valid}\n`);
    const parse = vi.spyOn(JSON, "parse");
    let evs: ReturnType<typeof readEvents>;
    let parsed: unknown[];
    try {
      evs = readEvents(l, "pre");
      parsed = parse.mock.calls.map((c) => c[0]);
    } finally {
      parse.mockRestore();
    }
    expect(parsed).toEqual([valid]);
    const corrupt = evs.filter((e) => e.type === "corrupt");
    expect(corrupt.length).toBe(11);
    expect(corrupt.at(-1)).toEqual({ type: "corrupt", detail: "990 more damaged lines (1000 in all)" });
    expect(evs.filter((e) => e.type !== "corrupt")).toEqual([{ type: "fingerprint", hash: "h" }]);
  });
  it("prunes old session files", () => {
    appendEvents(l, "old", [{ type: "sensitive", source: "x" }]);
    expect(pruneSessions(l, 30, Date.now() + 40 * 86400000)).toBeGreaterThan(0);
    // I9: one that records taint is kept, whatever its age.
    appendEvents(l, "old-tainted", [{ type: "taint", source: "x" }]);
    expect(pruneSessions(l, 30, Date.now() + 40 * 86400000)).toBe(0);
  });
});

describe("queue", () => {
  const base = { sessionId: "s", cwd: "/w", tool: "Bash", input: { command: "x" }, actionHash: "h1", rules: ["R"], reasons: ["why"], kind: "approval" as const };
  it("enqueues, approves, and records an approval event for the session", () => {
    const item = enqueue(l, base);
    expect(getQueueItem(l, item.id)?.status).toBe("pending");
    initApprover(l, "correct horse battery");
    const priv = unlockApprover(l, "correct horse battery");
    decideQueueItem(l, item.id, "approved", approvalSigner(priv));
    expect(getQueueItem(l, item.id)?.status).toBe("approved");
    expect(loadState(l, "s", approverPublicKey(l)).approvals.has("h1")).toBe(true);
  });
  it("deduplicates the same pending action in a session", () => {
    const a = enqueue(l, base);
    const b = enqueue(l, base);
    expect(a.id).toBe(b.id);
    expect(listQueue(l).items.length).toBe(1);
  });
  it("masks secrets stored in a queue item", () => {
    const item = enqueue(l, { ...base, input: { command: "echo AKIA1A2B3C4D5E6F7G8H" } });
    expect(JSON.stringify(getQueueItem(l, item.id)?.input)).not.toContain("AKIA1A2B3C4D5E6F7G8H");
  });
  it("will not approve an item twice", () => {
    const item = enqueue(l, base);
    decideQueueItem(l, item.id, "rejected");
    expect(() => decideQueueItem(l, item.id, "rejected")).toThrow();
  });
  it("refuses to approve without a signer (the passphrase)", () => {
    const item = enqueue(l, { ...base, actionHash: "h2" });
    expect(() => decideQueueItem(l, item.id, "approved")).toThrow(/passphrase/);
  });
});

describe("signed hash-chained log", () => {
  it("appends and verifies", () => {
    loadKey(l);
    for (let i = 0; i < 5; i++) appendLog(l, { type: "decision", n: i });
    const v = verifyLog(l);
    expect(v.ok).toBe(true);
    expect(v.entries).toBe(5);
  });
  it("detects an edited entry", () => {
    loadKey(l);
    appendLog(l, { type: "decision", n: 1 });
    appendLog(l, { type: "decision", n: 2 });
    const f = join(l.log, "decisions.jsonl");
    writeFileSync(f, readFileSync(f, "utf8").replace('"n":2', '"n":9'));
    expect(verifyLog(l).ok).toBe(false);
  });
  it("detects a removed last entry", () => {
    loadKey(l);
    appendLog(l, { type: "decision", n: 1 });
    appendLog(l, { type: "decision", n: 2 });
    const f = join(l.log, "decisions.jsonl");
    const lines = readFileSync(f, "utf8").trim().split("\n");
    writeFileSync(f, lines.slice(0, -1).join("\n") + "\n");
    expect(verifyLog(l).ok).toBe(false);
  });
  it("carries the chain across a rotation", () => {
    loadKey(l);
    for (let i = 0; i < 3; i++) appendLog(l, { type: "decision", n: i });
    rotateNow(l);
    for (let i = 3; i < 6; i++) appendLog(l, { type: "decision", n: i });
    const v = verifyLog(l);
    expect(v.ok).toBe(true);
    expect(v.files).toBeGreaterThan(1);
    expect(tailLog(l, 100).length).toBe(6);
  });
});

describe("policy loading", () => {
  it("returns defaults when no file exists", () => {
    const p = loadPolicy(l, ["/w"]);
    expect(p.error).toBeUndefined();
    expect(p.config.fetchAllowHosts.length).toBeGreaterThan(0);
  });
  it("reports an invalid user policy and keeps strict defaults", () => {
    atomicWrite(l.policy, JSON.stringify({ version: 1, sendAllowHosts: "not-a-list" }));
    const p = loadPolicy(l, ["/w"]);
    expect(p.error).toBeDefined();
    expect(p.config.sendAllowHosts).toEqual([]);
  });
  it("rejects an unknown key", () => {
    atomicWrite(l.policy, JSON.stringify({ version: 1, bogusKey: true }));
    expect(loadPolicy(l, ["/w"]).error).toMatch(/bogusKey/);
  });
  it("rejects a future version", () => {
    atomicWrite(l.policy, JSON.stringify({ version: 99 }));
    expect(loadPolicy(l, ["/w"]).error).toMatch(/newer/);
  });
  it("a project policy can tighten but not loosen", () => {
    const ws = join(root, "ws");
    atomicWrite(join(ws, ".launchsafe-firewall.json"), JSON.stringify({ version: 1, denyHosts: ["evil.com"], sendAllowHosts: ["anywhere.com"] }));
    const p = loadPolicy(l, [ws]);
    expect(p.config.denyHosts).toContain("evil.com");
    expect(p.config.sendAllowHosts).not.toContain("anywhere.com");
    expect(p.ignored.join(" ")).toMatch(/sendAllowHosts/);
  });
});

describe("install / uninstall", () => {
  it("withOurs puts the firewall first and withoutOurs removes it", () => {
    const withExisting = { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "other" }] }] } };
    const cmd = `${MARKER} node cli.js hook || exit 2`;
    const installed = withOurs(withExisting, cmd);
    const groups = (installed.hooks as Record<string, unknown[]>).PreToolUse!;
    expect(JSON.stringify(groups[0])).toContain(MARKER);
    expect(JSON.stringify(groups[1])).toContain("other");
    const removed = withoutOurs(installed);
    expect(JSON.stringify(removed)).not.toContain(MARKER);
    expect(JSON.stringify(removed)).toContain("other");
  });
  it("installs into a settings file, is idempotent, and inspects clean", () => {
    const r1 = install(l, "user", root, "0.1.0", { home: root, platform: "darwin" });
    const r2 = install(l, "user", root, "0.1.0", { home: root, platform: "darwin" });
    expect(r1.changed).toBe(true);
    expect(r2.changed).toBe(false);
    const st = inspectSettings(settingsPath("user", root, root));
    for (const ev of HOOK_EVENTS) {
      expect(st.events[ev]?.ours).toBe(true);
      expect(st.events[ev]?.first).toBe(true);
      expect(st.events[ev]?.failClosed).toBe(true);
    }
  });
  it("uninstall removes only the firewall's hooks and keeps the rest", () => {
    const path = settingsPath("user", root, root);
    atomicWrite(path, JSON.stringify({ hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "keep-me" }] }] }, otherSetting: 1 }));
    install(l, "user", root, "0.1.0", { home: root, platform: "darwin" });
    uninstall(l, { scope: "user", projectDir: root, home: root });
    const after = JSON.parse(readFileSync(path, "utf8"));
    expect(JSON.stringify(after)).toContain("keep-me");
    expect(JSON.stringify(after)).not.toContain("LAUNCHSAFE_FIREWALL_HOOK");
    expect(after.otherSetting).toBe(1);
  });
  it("restore-backup puts the original file back", () => {
    const path = settingsPath("user", root, root);
    atomicWrite(path, JSON.stringify({ original: true }));
    install(l, "user", root, "0.1.0", { home: root, platform: "darwin" });
    uninstall(l, { restoreBackup: true, scope: "user", projectDir: root, home: root });
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({ original: true });
  });
  it("refuses an unsupported platform", () => {
    expect(() => install(l, "user", root, "0.1.0", { home: root, platform: "win32" })).toThrow(/macOS and Linux/);
  });
});

describe("locking is reentrant-safe and survives a stale lock", () => {
  it("serializes concurrent-ish writes", () => {
    let counter = 0;
    for (let i = 0; i < 50; i++) withLock(join(l.locks, "t.lock"), () => (counter += 1));
    expect(counter).toBe(50);
  });
});
