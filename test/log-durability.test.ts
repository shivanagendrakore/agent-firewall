/**
 * The decision log's crash guarantees after the hot-path change (docs/design.md, "Runtime: durability and
 * concurrency"): one fsync per entry, before appendLog returns; head.json replaced atomically without an
 * fsync (the lock file is renamed over it). So a power cut can leave head.json behind the log, missing or
 * empty. These check that the chain then continues from the log's last entry (never forked), that the
 * recovery is itself logged, that a cut-off line never swallows the next entry, that a removed tail is
 * still reported, and that session appends stay durable without a lock.
 */
import fs, { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, appendFileSync } from "node:fs";
import module from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { layout } from "../src/runtime/layout.js";
import { appendLog, keyPairConsistent, loadKey, rotateNow, tailLog, verifyLog, type LogEntry } from "../src/runtime/log.js";
import { appendEvents, readEvents } from "../src/runtime/store.js";
import { withLockReplacing } from "../src/runtime/fsutil.js";

let root: string;
let l: ReturnType<typeof layout>;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-dur-"));
  l = layout(join(root, "home"));
  loadKey(l);
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const head = (): string => join(l.log, "head.json");
const current = (): string => join(l.log, "decisions.jsonl");
const entries = (f = current()): LogEntry[] => readFileSync(f, "utf8").split("\n").filter((x) => x.trim() !== "").map((x) => JSON.parse(x) as LogEntry);

/** Counts fsyncSync calls (and the paths opened just before them) while fn runs. */
function countFsyncs(fn: () => void): { fsyncs: number; opened: string[] } {
  const origFsync = fs.fsyncSync;
  const origOpen = fs.openSync;
  let fsyncs = 0;
  const opened: string[] = [];
  const fdPath = new Map<number, string>();
  fs.openSync = ((p: fs.PathLike, ...rest: unknown[]) => {
    const fd = (origOpen as (...a: unknown[]) => number)(p, ...rest);
    fdPath.set(fd, String(p));
    return fd;
  }) as typeof fs.openSync;
  fs.fsyncSync = ((fd: number) => {
    fsyncs++;
    opened.push(fdPath.get(fd) ?? "?");
    origFsync(fd);
  }) as typeof fs.fsyncSync;
  module.syncBuiltinESMExports();
  try {
    fn();
  } finally {
    fs.fsyncSync = origFsync;
    fs.openSync = origOpen;
    module.syncBuiltinESMExports();
  }
  return { fsyncs, opened };
}

describe("decision log after a crash", () => {
  it("one fsync per entry, on the log file itself; head.json follows the entry and no lock file is left", () => {
    appendLog(l, { type: "decision", n: 0 });
    const { fsyncs, opened } = countFsyncs(() => appendLog(l, { type: "decision", n: 1 }));
    expect(fsyncs).toBe(1);
    expect(opened).toEqual([current()]);
    const last = entries().at(-1) as LogEntry;
    expect(JSON.parse(readFileSync(head(), "utf8"))).toEqual({ seq: last.seq, hash: last.hash, sig: expect.any(String) });
    // I5: and the reserve kept free for a full disk.
    expect(readdirSync(l.log).sort()).toEqual(["decisions.jsonl", "head.json", "reserve.bin"]);
    expect(verifyLog(l).ok).toBe(true);
  });

  it("a head left behind by a power cut: verify accepts it, and the next entry chains from the log, not the old head", () => {
    for (let i = 0; i < 3; i++) appendLog(l, { type: "decision", n: i });
    const old = readFileSync(head(), "utf8");
    appendLog(l, { type: "decision", n: 3 });
    appendLog(l, { type: "decision", n: 4 });
    writeFileSync(head(), old); // the last two head updates never reached the disk
    const before = verifyLog(l);
    expect(before.ok, before.problems.join("; ")).toBe(true);
    appendLog(l, { type: "decision", n: 5 });
    const es = entries();
    expect(es.map((e) => e.seq)).toEqual([1, 2, 3, 4, 5, 6, 7]);
    // The recovery is on the signed record, between the last entry and the new one.
    expect(es[5]?.event).toMatchObject({ type: "log_head_recovered", why: "behind the log", head: { seq: 3 }, last: { seq: 5 } });
    expect(es[6]?.event).toEqual({ type: "decision", n: 5 });
    const after = verifyLog(l);
    expect(after.ok, after.problems.join("; ")).toBe(true);
    expect(JSON.parse(readFileSync(head(), "utf8")).seq).toBe(7);
  });

  it("merged with FZ6: the head the lock file becomes is signed; a behind head must still carry a good signature", () => {
    for (let i = 0; i < 3; i++) appendLog(l, { type: "decision", n: i });
    const old = JSON.parse(readFileSync(head(), "utf8")) as { seq: number; hash: string; sig: string };
    expect(old.sig).toMatch(/^[A-Za-z0-9+/]+=*$/);
    appendLog(l, { type: "decision", n: 3 });
    // Behind and signed: a power cut. Behind with its signature damaged (junk inside the base64): not accepted.
    writeFileSync(head(), JSON.stringify(old));
    expect(verifyLog(l).ok).toBe(true);
    writeFileSync(head(), JSON.stringify({ ...old, sig: `${old.sig.slice(0, 10)}!${old.sig.slice(10)}` }));
    expect(verifyLog(l).problems).toContain("the log's recorded head has a bad signature");
    // A signed head moved to another entry fails on its signature, even though it names an entry of the chain.
    const second = entries()[1] as LogEntry;
    writeFileSync(head(), JSON.stringify({ seq: second.seq, hash: second.hash, sig: old.sig }));
    expect(verifyLog(l).problems).toContain("the log's recorded head has a bad signature");
  });

  it("merged with FZ6: an emptied log fails even when the head is behind it would have been", () => {
    for (let i = 0; i < 3; i++) appendLog(l, { type: "decision", n: i });
    writeFileSync(current(), "");
    expect(verifyLog(l).problems.join(" ")).toMatch(/deleted or emptied/);
  });

  it("an empty or missing head (a rename that reached the disk before its data, or never did) is rebuilt from the log", () => {
    appendLog(l, { type: "decision", n: 0 });
    appendLog(l, { type: "decision", n: 1 });
    writeFileSync(head(), "");
    expect(verifyLog(l).ok).toBe(false); // reported until the next append rebuilds it
    appendLog(l, { type: "decision", n: 2 });
    expect(entries().map((e) => [e.seq, e.event.type])).toEqual([[1, "decision"], [2, "decision"], [3, "log_head_recovered"], [4, "decision"]]);
    expect(verifyLog(l).ok).toBe(true);
    rmSync(head());
    expect(verifyLog(l).problems).toContain("the log has entries but no recorded head (head.json is missing)");
    appendLog(l, { type: "decision", n: 3 });
    expect(entries().at(-2)?.event).toMatchObject({ type: "log_head_recovered", why: "missing" });
    expect(verifyLog(l).ok).toBe(true);
  });

  it("a line cut off by a crash stays on its own line: the next entry is intact and chains from the last whole entry", () => {
    appendLog(l, { type: "decision", n: 0 });
    appendLog(l, { type: "decision", n: 1 });
    appendFileSync(current(), '{"seq":3,"ts":"2026-10-11T00:00:00.000Z","prev":"ab'); // an unfinished append
    appendLog(l, { type: "decision", n: 2 });
    const lines = readFileSync(current(), "utf8").split("\n");
    expect(lines[2]).toBe('{"seq":3,"ts":"2026-10-11T00:00:00.000Z","prev":"ab');
    const last = JSON.parse(lines[3] as string) as LogEntry;
    expect(last.seq).toBe(3);
    expect(last.event).toEqual({ type: "decision", n: 2 });
    const v = verifyLog(l);
    // Only the fragment itself is reported; the chain around it holds.
    expect(v.problems).toEqual(["decisions.jsonl line 3: not valid JSON"]);
    expect(v.entries).toBe(3);
  });

  it("a removed tail is still reported, and so is a head that names another entry", () => {
    for (let i = 0; i < 3; i++) appendLog(l, { type: "decision", n: i });
    const full = readFileSync(current(), "utf8");
    writeFileSync(current(), full.split("\n").slice(0, 2).join("\n") + "\n");
    expect(verifyLog(l).problems).toContain("the log ends before its recorded head (entries were removed from the end)");
    writeFileSync(current(), full);
    writeFileSync(head(), JSON.stringify({ seq: 2, hash: "f".repeat(64) }));
    expect(verifyLog(l).problems).toContain("the recorded head (sequence 2) is not an entry of this log");
    writeFileSync(head(), JSON.stringify({ seq: 3, hash: "f".repeat(64) }));
    expect(verifyLog(l).ok).toBe(false);
  });

  it("a head ahead of the log keeps the chain from the head, as before (the gap stays visible)", () => {
    for (let i = 0; i < 3; i++) appendLog(l, { type: "decision", n: i });
    const full = readFileSync(current(), "utf8");
    writeFileSync(current(), full.split("\n").slice(0, 2).join("\n") + "\n");
    appendLog(l, { type: "decision", n: 3 });
    expect(entries().map((e) => e.seq)).toEqual([1, 2, 4]);
    expect(verifyLog(l).ok).toBe(false);
  });

  it("just after a rotation, a head left behind is rebuilt from the archived file's last entry", () => {
    for (let i = 0; i < 3; i++) appendLog(l, { type: "decision", n: i });
    const old = readFileSync(head(), "utf8");
    appendLog(l, { type: "decision", n: 3 });
    rotateNow(l);
    writeFileSync(head(), old);
    expect(existsSync(current())).toBe(false);
    appendLog(l, { type: "decision", n: 4 });
    expect(entries().map((e) => [e.seq, e.event.type])).toEqual([[5, "log_head_recovered"], [6, "decision"]]);
    const v = verifyLog(l);
    expect(v.ok, v.problems.join("; ")).toBe(true);
    expect(tailLog(l, 10).map((e) => e.seq)).toEqual([1, 2, 3, 4, 5, 6]);
  });
});

describe("withLockReplacing", () => {
  it("renames the lock over the target on release, and removes it when there is nothing to write or fn throws", () => {
    const dir = join(root, "x");
    const lock = join(dir, "a.lock"), target = join(dir, "a.json");
    expect(withLockReplacing(lock, target, () => ({ result: 1, content: "new" }))).toBe(1);
    expect(readFileSync(target, "utf8")).toBe("new");
    expect(fs.statSync(target).mode & 0o777).toBe(0o600);
    expect(existsSync(lock)).toBe(false);
    withLockReplacing(lock, target, () => ({ result: 2, content: null }));
    expect(readFileSync(target, "utf8")).toBe("new");
    expect(existsSync(lock)).toBe(false);
    expect(() => withLockReplacing(lock, target, () => { throw new Error("boom"); })).toThrow("boom");
    expect(existsSync(lock)).toBe(false);
    expect(readFileSync(target, "utf8")).toBe("new");
  });

  it("a lock broken as stale meanwhile (another process holds it now) is neither renamed nor removed", () => {
    const dir = join(root, "y");
    const lock = join(dir, "a.lock"), target = join(dir, "a.json");
    withLockReplacing(lock, target, () => ({ result: 0, content: "first" }));
    withLockReplacing(lock, target, () => {
      // Another process broke this lock as stale and took it.
      fs.renameSync(lock, `${lock}.stale`);
      writeFileSync(lock, "99999 0");
      return { result: 0, content: "second" };
    });
    expect(readFileSync(target, "utf8")).toBe("first");
    expect(readFileSync(lock, "utf8")).toBe("99999 0");
  });
});

describe("session appends", () => {
  it("are durable (one fsync, on the session file) and take no lock", () => {
    appendEvents(l, "s", [{ type: "taint", source: "web" }]);
    const { fsyncs, opened } = countFsyncs(() => appendEvents(l, "s", [{ type: "downloaded", path: "/w/a" }, { type: "sensitive", source: "env" }]));
    expect(fsyncs).toBe(1);
    expect(opened).toEqual([join(l.sessions, "s.jsonl")]);
    expect(readdirSync(l.sessions)).toEqual(["s.jsonl"]);
    expect(readEvents(l, "s").map((e) => e.type)).toEqual(["taint", "downloaded", "sensitive"]);
  });

});

describe("the log key pair", () => {
  it("a public key lost between the two key writes is derived again from the private key", () => {
    const pub = join(l.keys, "log-ed25519.pub.pem");
    const before = readFileSync(pub, "utf8");
    rmSync(pub);
    expect(loadKey(l)).not.toBeNull();
    expect(readFileSync(pub, "utf8")).toBe(before);
    expect(keyPairConsistent(l)).toBe(true);
  });
});

describe("a failing rotation after a durable append", () => {
  it("does not report the append as failed: the entry is returned, written once, and no gap is recorded", () => {
    // A current file past the size limit, made of copies of a real entry line (only its last line has to read as an entry).
    appendLog(l, { type: "decision", n: "seed" });
    const line = `${readFileSync(current(), "utf8").trim().split("\n").at(-1) as string}\n`;
    writeFileSync(current(), line.repeat(Math.ceil((5 * 1024 * 1024 + 1024) / line.length)));
    const origRename = fs.renameSync;
    fs.renameSync = ((from: fs.PathLike, to: fs.PathLike) => {
      if (/decisions-\d{8}\.jsonl$/.test(String(to))) throw Object.assign(new Error("no space left on device"), { code: "ENOSPC" });
      return origRename(from, to);
    }) as typeof fs.renameSync;
    module.syncBuiltinESMExports();
    try {
      const e = appendLog(l, { type: "decision", n: "rotation-fails" });
      expect(e.event.n).toBe("rotation-fails");
    } finally {
      fs.renameSync = origRename;
      module.syncBuiltinESMExports();
    }
    expect(readFileSync(current(), "utf8").split("rotation-fails").length - 1).toBe(1);
    expect(existsSync(join(l.log, "unlogged.json"))).toBe(false);
  });
});
