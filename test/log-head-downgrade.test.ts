/**
 * Stripping the head's signature is a downgrade to the v0.2 format, and must fail `log verify` once a
 * signed head has been written. The signed record of that is each v0.3 entry's `heads: "signed"` (its
 * signature covers the flag) and, after pruning, the anchor's. A pure v0.2 log (unflagged entries, unsigned
 * head) still verifies until its first v0.3 append.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { sign } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { layout } from "../src/runtime/layout.js";
import { appendLog, entryHash, GENESIS, loadKey, rotateNow, verifyLog, type LogEntry } from "../src/runtime/log.js";

let root: string;
let l: ReturnType<typeof layout>;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-hd-"));
  l = layout(join(root, "home"));
  loadKey(l);
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const head = (): string => join(l.log, "head.json");
const current = (): string => join(l.log, "decisions.jsonl");
const entries = (): LogEntry[] => readFileSync(current(), "utf8").split("\n").filter((x) => x.trim() !== "").map((x) => JSON.parse(x) as LogEntry);
const unsign = (): void => {
  const h = JSON.parse(readFileSync(head(), "utf8")) as { seq: number; hash: string };
  writeFileSync(head(), JSON.stringify({ seq: h.seq, hash: h.hash }));
};

/** A log as v0.2 wrote it: entries signed over the hash bytes, no `heads` field, an unsigned head. */
function writeV02(n: number): void {
  const key = loadKey(l);
  if (key === null) throw new Error("no key");
  let prev = GENESIS;
  const lines: string[] = [];
  for (let seq = 1; seq <= n; seq++) {
    const ts = new Date(Date.UTC(2026, 8, 1, 0, 0, seq)).toISOString();
    const event = { type: "decision", n: seq };
    const hash = entryHash(prev, seq, ts, event);
    lines.push(JSON.stringify({ seq, ts, prev, event, hash, sig: sign(null, Buffer.from(hash, "hex"), key.priv).toString("base64") }));
    prev = hash;
  }
  mkdirSync(l.log, { recursive: true });
  writeFileSync(current(), `${lines.join("\n")}\n`);
  writeFileSync(head(), JSON.stringify({ seq: n, hash: prev }));
}

describe("signed heads cannot be downgraded", () => {
  it("a pure v0.2 log verifies with its unsigned head; after the first v0.3 append an unsigned head fails", () => {
    writeV02(3);
    expect(verifyLog(l)).toMatchObject({ ok: true, entries: 3 });
    appendLog(l, { type: "decision", n: 4 });
    const es = entries();
    expect(es.slice(0, 3).every((e) => e.heads === undefined)).toBe(true);
    expect(es[3]?.heads).toBe("signed");
    expect(verifyLog(l).ok).toBe(true);
    unsign();
    expect(verifyLog(l).problems).toEqual(["the log's recorded head has no signature, but heads are signed since sequence 4 (the signature was removed)"]);
  });

  it("an unsigned head that names an older, pre-upgrade entry does not pass either (no truncation back past the upgrade's head)", () => {
    writeV02(3);
    for (let i = 0; i < 3; i++) appendLog(l, { type: "decision", n: 4 + i });
    const es = entries();
    writeFileSync(current(), `${es.slice(0, 5).map((e) => JSON.stringify(e)).join("\n")}\n`);
    writeFileSync(head(), JSON.stringify({ seq: 2, hash: (es[1] as LogEntry).hash }));
    expect(verifyLog(l).problems.join("\n")).toMatch(/no signature, but heads are signed since sequence 4/);
  });

  it("a fresh v0.3 log: every entry carries the flag, so stripping the head's signature fails from the first entry", () => {
    appendLog(l, { type: "decision", n: 0 });
    unsign();
    expect(verifyLog(l).ok).toBe(false);
  });

  it("removing the flag from an entry breaks that entry's signature; a flag with another value is not an entry", () => {
    for (let i = 0; i < 2; i++) appendLog(l, { type: "decision", n: i });
    const es = entries();
    const stripped = { ...(es[0] as LogEntry) };
    delete stripped.heads;
    writeFileSync(current(), `${[JSON.stringify(stripped), JSON.stringify(es[1])].join("\n")}\n`);
    expect(verifyLog(l).problems).toContain("decisions.jsonl line 1: bad signature");
    writeFileSync(current(), `${[JSON.stringify({ ...es[0], heads: "unsigned" }), JSON.stringify(es[1])].join("\n")}\n`);
    expect(verifyLog(l).problems).toContain("decisions.jsonl line 1: not a log entry");
  });

  it("after pruning, the anchor carries the record: the flagged files gone, an unsigned head still fails; stripping the anchor's flag breaks its signature", () => {
    for (let i = 0; i < 3; i++) appendLog(l, { type: "decision", n: i });
    rotateNow(l, 0); // prunes every archive: the anchor alone records the chain
    const anchor = JSON.parse(readFileSync(join(l.log, "anchor.json"), "utf8")) as Record<string, unknown>;
    expect(anchor.heads).toBe("signed");
    expect(verifyLog(l).ok).toBe(true);
    unsign();
    expect(verifyLog(l).problems.join("\n")).toMatch(/no signature, but heads are signed since sequence 3/);
    const { heads: _drop, ...bare } = anchor;
    writeFileSync(join(l.log, "anchor.json"), JSON.stringify(bare));
    expect(verifyLog(l).problems).toContain("the anchor of pruned log files has a bad signature");
  });

  it("a v0.2 log rotated and pruned by v0.3 without an append keeps an unflagged anchor and still verifies", () => {
    writeV02(3);
    rotateNow(l, 0);
    const anchor = JSON.parse(readFileSync(join(l.log, "anchor.json"), "utf8")) as Record<string, unknown>;
    expect(anchor.heads).toBeUndefined();
    const v = verifyLog(l);
    expect(v.ok, v.problems.join("; ")).toBe(true);
  });
});
