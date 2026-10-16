/**
 * The decision log's chain (design 9): verifies after appends, catches
 * tampering (an edited, removed, reordered or forged entry, a cut tail or
 * head), prunes at 30 days without breaking the chain, exports and deletes.
 * The IndexedDB backend is exercised end to end in test/e2e/leak.spec.ts.
 */
import { describe, expect, it } from "vitest";
import type { LogEntry } from "../shared/messages.js";
import { canonical, createLog, createMemoryBackend, entryHash, escapeEvidence, EVIDENCE_MAX, GENESIS_HASH, RETENTION_MS } from "./log.js";

const DAY = 24 * 60 * 60 * 1000;
const T0 = Date.UTC(2026, 9, 1);

function entry(over: Partial<LogEntry> = {}): LogEntry {
  return { at: T0, site: "attacker.test", actionClass: null, verdict: "approve", rules: ["leak.seen_elsewhere"], event: "leak", detail: ["type", "seen_elsewhere"], ...over };
}

function setup(start = T0) {
  let now = start;
  const backend = createMemoryBackend();
  const log = createLog({ backend, now: () => now, purgeEveryMs: Number.POSITIVE_INFINITY });
  return { backend, log, setNow: (t: number) => (now = t), advance: (ms: number) => (now += ms) };
}

async function filled(n = 5) {
  const s = setup();
  for (let i = 0; i < n; i++) {
    await s.log.append(entry());
    s.advance(1000);
  }
  return s;
}

describe("chain", () => {
  it("links each entry to the previous one from the genesis, and verifies", async () => {
    const { log } = await filled(3);
    const all = await log.list();
    expect(all.map((e) => e.seq)).toEqual([0, 1, 2]);
    expect(all[0]?.prevHash).toBe(GENESIS_HASH);
    expect(all[1]?.prevHash).toBe(all[0]?.hash);
    expect(all[2]?.prevHash).toBe(all[1]?.hash);
    expect(await log.verify()).toEqual({ brokenAt: null, count: 3 });
  });

  it("an empty log verifies", async () => {
    expect(await setup().log.verify()).toEqual({ brokenAt: null, count: 0 });
  });

  it("each hash is SHA-256 over the canonical form", async () => {
    const { log } = await filled(1);
    const [e] = await log.list();
    if (e === undefined) throw new Error("no entry");
    const { hash, ...rest } = e;
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(await entryHash(rest)).toBe(hash);
    expect(canonical(rest)).toContain('"leak.seen_elsewhere"');
  });

  it("concurrent appends take distinct sequence numbers and still verify", async () => {
    const { log } = setup();
    await Promise.all(Array.from({ length: 20 }, (_, i) => log.append(entry({ site: `s${i}.test` }))));
    const all = await log.list();
    expect(all.map((e) => e.seq)).toEqual(Array.from({ length: 20 }, (_, i) => i));
    expect((await log.verify()).brokenAt).toBeNull();
  });

  it("stores only the fields a log entry may hold (no values sneak in)", async () => {
    const { log } = setup();
    const e = await log.append({ ...entry(), value: "482915", text: "secret page text" } as LogEntry);
    expect(JSON.stringify(e)).not.toContain("482915");
    expect(JSON.stringify(e)).not.toContain("secret page text");
  });
});

describe("tampering", () => {
  it("detects an edited field", async () => {
    const { log, backend } = await filled();
    (backend.entries[2] as { verdict: string }).verdict = "allow";
    expect((await log.verify()).brokenAt).toBe(2);
  });

  it("detects an entry removed from the middle", async () => {
    const { log, backend } = await filled();
    backend.entries.splice(2, 1);
    expect((await log.verify()).brokenAt).toBe(2);
  });

  it("detects reordered entries", async () => {
    const { log, backend } = await filled();
    const [a, b] = [backend.entries[1], backend.entries[2]];
    if (a === undefined || b === undefined) throw new Error("setup");
    backend.entries[1] = b;
    backend.entries[2] = a;
    expect((await log.verify()).brokenAt).toBe(1);
  });

  it("detects a forged entry whose hash was recomputed but whose successor still links to the original", async () => {
    const { log, backend } = await filled();
    const e = backend.entries[1];
    if (e === undefined) throw new Error("setup");
    const forged = { ...e, verdict: "allow" as const };
    const { hash: _old, ...rest } = forged;
    backend.entries[1] = { ...forged, hash: await entryHash(rest) };
    expect((await log.verify()).brokenAt).toBe(2);
  });

  it("detects the newest entries removed (the head no longer matches)", async () => {
    const { log, backend } = await filled();
    backend.entries.pop();
    expect((await log.verify()).brokenAt).toBe(4);
  });

  it("detects the oldest entries removed without moving the anchor", async () => {
    const { log, backend } = await filled();
    backend.entries.shift();
    expect((await log.verify()).brokenAt).toBe(0);
  });

  it("detects a malformed row", async () => {
    const { log, backend } = await filled();
    (backend.entries[3] as { rules: unknown }).rules = ["not-a-rule"];
    expect((await log.verify()).brokenAt).toBe(3);
  });

  it("appends after a verified chain keep verifying", async () => {
    const s = await filled();
    await s.log.append(entry({ verdict: "deny", rules: ["leak.seen_elsewhere_quarantine"] }));
    expect(await s.log.verify()).toEqual({ brokenAt: null, count: 6 });
  });
});

describe("retention", () => {
  it("defaults to 30 days", () => {
    expect(RETENTION_MS).toBe(30 * DAY);
  });

  it("prunes entries older than 30 days and the rest still verifies", async () => {
    const s = setup();
    await s.log.append(entry({ site: "old1.test", at: T0 }));
    await s.log.append(entry({ site: "old2.test", at: T0 + DAY }));
    await s.log.append(entry({ site: "recent.test", at: T0 + 11 * DAY }));
    expect((await s.log.verify()).brokenAt).toBeNull();

    expect(await s.log.purge(T0 + 30 * DAY + DAY / 2)).toBe(1);
    expect((await s.log.list()).map((e) => e.site)).toEqual(["old2.test", "recent.test"]);
    expect(await s.log.verify()).toEqual({ brokenAt: null, count: 2 });

    expect(await s.log.purge(T0 + 41 * DAY + 1)).toBe(2);
    expect(await s.log.list()).toEqual([]);
    expect(await s.log.verify()).toEqual({ brokenAt: null, count: 0 });

    // The chain continues from the last pruned entry.
    const next = await s.log.append(entry({ site: "after.test" }));
    expect(next.seq).toBe(3);
    expect((await s.log.verify()).brokenAt).toBeNull();
  });

  it("keeps entries inside the period", async () => {
    const { log } = await filled(3);
    expect(await log.purge(T0 + 29 * DAY)).toBe(0);
    expect((await log.list()).length).toBe(3);
  });

  it("follows a changed retention period", async () => {
    let days = 30;
    let now = T0;
    const backend = createMemoryBackend();
    const log = createLog({ backend, now: () => now, retentionMs: () => days * DAY, purgeEveryMs: Number.POSITIVE_INFINITY });
    await log.append(entry());
    now = T0 + 8 * DAY;
    expect(await log.purge()).toBe(0);
    days = 7;
    expect(await log.purge()).toBe(1);
  });

  it("an append purges when the purge interval has passed", async () => {
    let now = T0;
    const backend = createMemoryBackend();
    const log = createLog({ backend, now: () => now, purgeEveryMs: 60 * 60 * 1000 });
    await log.append(entry({ at: T0 }));
    now = T0 + 31 * DAY;
    await log.append(entry({ at: now }));
    expect((await log.list()).length).toBe(1);
    expect((await log.verify()).brokenAt).toBeNull();
  });
});

describe("export and delete", () => {
  it("exports every entry with the chain's ends and its verification", async () => {
    const { log } = await filled(3);
    const doc = JSON.parse(await log.exportJson()) as { format: string; entries: unknown[]; verify: { brokenAt: number | null }; anchor: { seq: number }; head: { seq: number } };
    expect(doc.format).toBe("launchsafe-browser-firewall-log");
    expect(doc.entries.length).toBe(3);
    expect(doc.verify.brokenAt).toBeNull();
    expect(doc.anchor.seq).toBe(-1);
    expect(doc.head.seq).toBe(2);
  });

  it("an export of a tampered log says where it breaks", async () => {
    const { log, backend } = await filled(3);
    (backend.entries[1] as { site: string }).site = "other.test";
    expect((JSON.parse(await log.exportJson()) as { verify: { brokenAt: number } }).verify.brokenAt).toBe(1);
  });

  it("delete removes every entry and restarts the chain from the genesis with a record of the deletion (RR14)", async () => {
    const { log } = await filled(3);
    await log.clear();
    const left = await log.list();
    expect(left).toHaveLength(1);
    expect(left[0]).toMatchObject({ seq: 0, prevHash: GENESIS_HASH, event: "log_cleared", site: "", verdict: "log", rules: [] });
    expect(await log.verify()).toEqual({ brokenAt: null, count: 1 });
    const e = await log.append(entry());
    expect(e.seq).toBe(1);
    expect(e.prevHash).toBe(left[0]?.hash);
  });

  it("purges with a retention period read asynchronously, before it is applied (RR8)", async () => {
    const backend = createMemoryBackend();
    const NOW = 1_800_000_000_000;
    const seed = createLog({ backend, now: () => NOW - 40 * DAY, retentionMs: () => 365 * DAY });
    await seed.append(entry({ at: NOW - 40 * DAY }));
    const log = createLog({ backend, now: () => NOW, retentionMs: () => new Promise((ok) => setTimeout(() => ok(90 * DAY), 0)) });
    expect(await log.purge()).toBe(0);
    expect(backend.entries).toHaveLength(1);
    const short = createLog({ backend, now: () => NOW, retentionMs: async () => 30 * DAY });
    expect(await short.purge()).toBe(1);
  });

  it("list returns the newest entries since a time", async () => {
    const { log } = await filled(5);
    expect((await log.list({ limit: 2 })).map((e) => e.seq)).toEqual([3, 4]);
  });
});

describe("evidence", () => {
  it("escapes invisible and bidi characters and cuts to 200", () => {
    expect(escapeEvidence("a‮b​c\nd")).toBe("a\\u{202e}b\\u{200b}c\\u{a}d");
    expect(escapeEvidence("x".repeat(500)).length).toBe(EVIDENCE_MAX);
  });
  it("is escaped on append", async () => {
    const { log } = setup();
    const e = await log.append(entry({ evidence: "hidden‮text" }));
    expect(e.evidence).toBe("hidden\\u{202e}text");
  });
});
