import { describe, expect, it } from "vitest";
import type { LogEntry } from "../shared/messages.js";
import { senderKey, TokenBuckets } from "./rate-limit.js";
import { createSenderLog } from "./sender-log.js";

describe("per-sender token buckets (I4, I11)", () => {
  it("allows a burst up to capacity, then refuses until time refills it", () => {
    let t = 0;
    const b = new TokenBuckets({ capacity: 3, refillPerSecond: 1, now: () => t });
    const k = senderKey(1, 0);
    expect([b.take(k), b.take(k), b.take(k), b.take(k)]).toEqual([true, true, true, false]);
    t = 999;
    expect(b.take(k)).toBe(false);
    t = 1000;
    expect(b.take(k)).toBe(true);
  });
  it("keeps senders apart: one flooding frame does not use another's budget", () => {
    const b = new TokenBuckets({ capacity: 1, refillPerSecond: 0, now: () => 0 });
    expect(b.take(senderKey(1, 0))).toBe(true);
    expect(b.take(senderKey(1, 0))).toBe(false);
    expect(b.take(senderKey(1, 1))).toBe(true);
  });
  it("charges by cost (characters scanned) and never goes negative", () => {
    const b = new TokenBuckets({ capacity: 100, refillPerSecond: 0, now: () => 0 });
    expect(b.take("k", 150)).toBe(false);
    expect(b.take("k", 60)).toBe(true);
    expect(b.take("k", 60)).toBe(false);
    expect(b.take("k", 40)).toBe(true);
  });
  it("bounds the number of senders it remembers", () => {
    const b = new TokenBuckets({ capacity: 1, refillPerSecond: 0, maxKeys: 10, now: () => 0 });
    for (let i = 0; i < 1000; i++) b.take(senderKey(i, 0));
    expect(b.size()).toBe(10);
  });
});

describe("per-sender log throttle (I11)", () => {
  const entry = (n: number): LogEntry => ({ at: n, site: "attacker.test", actionClass: null, verdict: "deny", rules: ["nav.script_url"] });

  it("drops a flooding sender's rows past its budget and records how many with its next row", async () => {
    let t = 0;
    const rows: LogEntry[] = [];
    const log = createSenderLog({ append: async (e) => void rows.push(e) }, new TokenBuckets({ capacity: 5, refillPerSecond: 1, now: () => t }));
    for (let i = 0; i < 1000; i++) await log.append("1:0", entry(i));
    expect(rows).toHaveLength(5);
    t = 1000;
    await log.append("1:0", entry(2000));
    expect(rows).toHaveLength(7);
    expect(rows[5]).toMatchObject({ event: "log_throttled", detail: ["995"] });
    expect(rows[6]?.at).toBe(2000);
    // Another frame was never throttled.
    await log.append("2:0", entry(3000));
    expect(rows.at(-1)?.at).toBe(3000);
  });
});
