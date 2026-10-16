/**
 * Log appends caused by a content sender, under a per-sender token bucket, so
 * a page that makes thousands of decisions cannot flood the decision log (and
 * push older entries out of it) or keep the worker busy hashing. Decisions are
 * still made and enforced; only their log rows are throttled. The rows a sender
 * lost are counted, and its next row that fits the budget is preceded by one
 * `log_throttled` row saying how many were dropped.
 */
import type { LogEntry } from "../shared/messages.js";
import type { TokenBuckets } from "./rate-limit.js";

export interface SenderLog {
  append(senderKey: string, entry: LogEntry): Promise<void>;
}

const MAX_TRACKED = 1_000;

export function createSenderLog(log: { append(entry: LogEntry): Promise<unknown> }, buckets: TokenBuckets): SenderLog {
  const dropped = new Map<string, number>();
  return {
    async append(key, entry) {
      if (!buckets.take(key)) {
        dropped.set(key, (dropped.get(key) ?? 0) + 1);
        if (dropped.size > MAX_TRACKED) {
          const oldest = dropped.keys().next().value;
          if (oldest !== undefined) dropped.delete(oldest);
        }
        return;
      }
      const n = dropped.get(key);
      if (n !== undefined) {
        dropped.delete(key);
        await log.append({ at: entry.at, site: entry.site, actionClass: null, verdict: "log", rules: [], event: "log_throttled", detail: [String(n)] });
      }
      await log.append(entry);
    },
  };
}
