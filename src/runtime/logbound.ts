/**
 * LG1: a decision is never carried out without a log entry. The bounding, the fallback entry and
 * LogUnrecorded live in the browser-safe src/engine/log-bound.ts (the library uses them with any store);
 * this module binds them to the runtime's log file. An I/O failure (a full disk) is not a refusal: it is
 * thrown as it was, and the callers keep their documented behaviour for it (docs/limitations.md).
 */

import { appendBoundedWith } from "../engine/log-bound.js";
import { appendLog, type LogEntry } from "./log.js";
import type { Layout } from "./layout.js";

export { boundEvent, fallbackEvent, isLogUnrecorded, LogUnrecorded, MAX_FIELD_CHARS, MAX_ITEMS, type BoundNote } from "../engine/log-bound.js";

/**
 * Appends a firewall event bounded, or its fallback entry when the bounded event is refused. Throws
 * LogUnrecorded when both are refused; any other error (I/O) is thrown unchanged.
 */
export function appendBounded(l: Layout, event: Record<string, unknown>, append: (l: Layout, e: Record<string, unknown>) => LogEntry = appendLog): LogEntry {
  return appendBoundedWith((e) => append(l, e), event);
}
