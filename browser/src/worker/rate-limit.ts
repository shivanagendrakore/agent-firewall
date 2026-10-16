/**
 * Token buckets keyed by sender (tab and frame), so one page cannot make the
 * worker scan, decide or log without bound. A message over its sender's budget
 * gets no answer, which every caller treats as "worker unreachable": the leak
 * guard keeps the value held, the gate drops the action. Fail closed.
 *
 * The number of keys is bounded too: past `maxKeys` the least recently used
 * key is forgotten (it starts again with a full bucket, which only matters to
 * a page that spreads itself over more frames than that).
 */

export interface BucketOptions {
  /** Most tokens a sender can hold (the burst). */
  capacity: number;
  /** Tokens added per second. */
  refillPerSecond: number;
  maxKeys?: number;
  now?: () => number;
}

export class TokenBuckets {
  private readonly buckets = new Map<string, { tokens: number; at: number }>();
  private readonly now: () => number;
  private readonly maxKeys: number;

  constructor(private readonly opts: BucketOptions) {
    this.now = opts.now ?? Date.now;
    this.maxKeys = opts.maxKeys ?? 1_000;
  }

  /** Takes `cost` tokens from the sender's bucket; false (and nothing taken) when it does not have them. */
  take(key: string, cost = 1): boolean {
    const t = this.now();
    const b = this.buckets.get(key) ?? { tokens: this.opts.capacity, at: t };
    const tokens = Math.min(this.opts.capacity, b.tokens + (Math.max(0, t - b.at) / 1000) * this.opts.refillPerSecond);
    this.buckets.delete(key);
    if (tokens < cost) {
      this.buckets.set(key, { tokens, at: t });
      this.evict();
      return false;
    }
    this.buckets.set(key, { tokens: tokens - cost, at: t });
    this.evict();
    return true;
  }

  size(): number {
    return this.buckets.size;
  }

  private evict(): void {
    while (this.buckets.size > this.maxKeys) {
      const oldest = this.buckets.keys().next().value;
      if (oldest === undefined) break;
      this.buckets.delete(oldest);
    }
  }
}

/** The key a content sender is budgeted under. */
export function senderKey(tabId: number, frameId: number): string {
  return `${tabId}:${frameId}`;
}
