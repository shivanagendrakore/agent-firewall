import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalJson } from "../../src/engine/decide.js";
import { entryHash, GENESIS } from "../../src/runtime/log.js";
import { mountRegistry } from "../../src/runtime/run/mountpoints.js";
import { newQueueId, queueIdFrom } from "../../src/runtime/store.js";

const ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";

describe("queue ids (CodeQL #41: no modulo bias)", () => {
  it("keeps the format: 8 symbols from the typing alphabet, matching readQueueItem's id check", () => {
    for (let i = 0; i < 2000; i++) {
      const id = newQueueId();
      expect(id).toHaveLength(8);
      for (const ch of id) expect(ALPHABET).toContain(ch);
      expect(id).toMatch(/^[a-z0-9]{4,32}$/);
    }
  });

  it("draws again for bytes at or above the largest multiple of 31 (248)", () => {
    const draws: Uint8Array[] = [Uint8Array.from([248, 255, 0, 30, 31, 247, 249, 62]), Uint8Array.from([1, 2, 3])];
    const id = queueIdFrom(() => draws.shift() ?? Uint8Array.from([0]));
    // 248, 255 and 249 are dropped; 0, 30, 31, 247 and 62 map by modulo (a, 9, a, 9, a); the second draw fills the rest.
    expect(id).toBe("a9a9abcd");
  });

  it("gives every symbol exactly the same weight over all byte values", () => {
    let next = 0;
    const counts = new Map<string, number>();
    // A source that walks every byte value 0..255 in turn, over and over.
    const source = (n: number): Uint8Array => Uint8Array.from({ length: n }, () => next++ % 256);
    for (let i = 0; i < 32 * 32; i++) {
      for (const ch of queueIdFrom(source)) counts.set(ch, (counts.get(ch) ?? 0) + 1);
    }
    expect(counts.size).toBe(31);
    const values = [...counts.values()];
    // Each pass over 0..247 gives every symbol 8 times and 248..255 are dropped, so counts differ by at most one.
    expect(Math.max(...values) - Math.min(...values)).toBeLessThanOrEqual(1);
  });
});

describe("decision log entry hash (CodeQL #35: a chain hash, kept as is)", () => {
  it("is the SHA-256 of prev, seq, ts and the canonical event, as existing logs carry", () => {
    const event = { kind: "oauth", vault: "github-token-entry", decision: "allow" };
    const ts = "2026-10-20T00:00:00.000Z";
    const want = createHash("sha256").update(`${GENESIS}\n1\n${ts}\n${canonicalJson(event)}`).digest("hex");
    expect(entryHash(GENESIS, 1, ts, event)).toBe(want);
    expect(entryHash(GENESIS, 1, ts, event)).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("mount registry key (CodeQL #36: a path name, kept as is)", () => {
  it("files a path's claims under the first 32 hex digits of its SHA-256", () => {
    const root = mkdtempSync(join(tmpdir(), "fw-codeql-e-"));
    try {
      const registry = join(root, "run-mounts");
      const p = join(root, "ws", "etc", "passwd");
      const reg = mountRegistry(registry, process.pid, null);
      reg.claim([p]);
      const key = createHash("sha256").update(p).digest("hex").slice(0, 32);
      expect(existsSync(join(registry, key, String(process.pid)))).toBe(true);
      expect(reg.release()).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
