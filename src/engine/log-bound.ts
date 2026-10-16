/**
 * LG1: a decision is never carried out without a log entry. The firewall's own events carry values an agent
 * or an MCP server chooses (a tool name, a server name, paths, a description of the action), and a log
 * refuses an event over its cap. So every such event is bounded first: a long string keeps its first
 * MAX_FIELD_CHARS characters and the SHA-256 and length of the whole value are recorded beside it (in
 * `bounded`), long arrays and objects are cut the same way, and deep nesting is replaced by its hash. If the
 * log still refuses (the event is still too large, or the log's last entry cannot be found), a minimal
 * fallback entry is written instead: the event type, verdict, rule ids, action hash and why the full entry
 * was refused. Only if that is refused too does the caller learn that nothing was recorded (LogUnrecorded),
 * and the hook, the gateway, `run` and the library then fail closed. Any other error (I/O: a full disk) is
 * not a refusal: it is thrown as it was, and the callers keep their documented behaviour for it
 * (docs/limitations.md).
 *
 * Browser-safe (the library, src/sdk/, uses it with any StateStore); src/runtime/logbound.ts binds it to the
 * runtime's log file.
 */

import { sha256Hex } from "./bytes.js";
import { canonicalJson } from "./decide.js";
import { own, setOwn } from "../own.js";

/** The longest string kept whole in a logged event (characters). */
export const MAX_FIELD_CHARS = 1024;
/** The most items of an array, or keys of an object, kept in a logged event. */
export const MAX_ITEMS = 64;
const MAX_KEY_CHARS = 128;
const MAX_DEPTH = 6;
/** How many cut fields are described in `bounded` (the rest are counted). */
const MAX_NOTES = 16;

/** The log would not take this event (too large, not JSON, or its chain's end cannot be found). Nothing was written. */
export class LogRefused extends Error {
  readonly reason: "size" | "unsearchable" | "unserializable";
  constructor(reason: "size" | "unsearchable" | "unserializable", message: string) {
    super(message);
    this.name = "LogRefused";
    this.reason = reason;
  }
}

/** The event and its fallback entry were both refused: nothing about this event is in the log. */
export class LogUnrecorded extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LogUnrecorded";
  }
}

/** A refusal from any store (a custom StateStore may throw its own error named LogRefused). */
export function isLogRefused(e: unknown): e is Error & { reason?: string } {
  return e instanceof LogRefused || (e instanceof Error && e.name === "LogRefused");
}

export function isLogUnrecorded(e: unknown): e is Error {
  return e instanceof LogUnrecorded || (e instanceof Error && e.name === "LogUnrecorded");
}

export interface BoundNote {
  /** Where the value was, as a dotted path (itself bounded). */
  field: string;
  /** SHA-256 of the whole value: the string's UTF-8 bytes, or the canonical JSON of an array or object. */
  sha256: string;
  /** The whole value's length: characters of a string, items of an array, keys of an object (-1: not measurable). */
  length: number;
}

function canonicalOrNull(v: unknown): string | null {
  try {
    return canonicalJson(v);
  } catch {
    return null;
  }
}

/** The event with every string, array and object bounded; what was cut is described in `bounded`. */
export function boundEvent(event: Record<string, unknown>): Record<string, unknown> {
  const notes: BoundNote[] = [];
  let more = 0;
  const note = (field: string, whole: string | null, length: number): void => {
    if (notes.length < MAX_NOTES) notes.push({ field: field.slice(0, 200), sha256: whole === null ? "" : sha256Hex(whole), length });
    else more++;
  };
  const walk = (v: unknown, path: string, depth: number): unknown => {
    if (typeof v === "string") {
      if (v.length <= MAX_FIELD_CHARS) return v;
      note(path, v, v.length);
      return v.slice(0, MAX_FIELD_CHARS);
    }
    if (v === null || typeof v !== "object") return v;
    if (depth >= MAX_DEPTH) {
      note(path, canonicalOrNull(v), -1);
      return "[nested too deeply to log; see bounded]";
    }
    if (Array.isArray(v)) {
      if (v.length > MAX_ITEMS) note(path, canonicalOrNull(v), v.length);
      return v.slice(0, MAX_ITEMS).map((x, i) => walk(x, `${path}.${i}`, depth + 1));
    }
    const o = v as Record<string, unknown>;
    let keys = Object.keys(o).filter((k) => own(o, k) !== undefined);
    if (keys.length > MAX_ITEMS) {
      note(path, canonicalOrNull(v), keys.length);
      keys = keys.sort().slice(0, MAX_ITEMS);
    }
    const out: Record<string, unknown> = {};
    for (const k of keys) {
      let key = k;
      if (k.length > MAX_KEY_CHARS) {
        key = `${k.slice(0, MAX_KEY_CHARS)}#${sha256Hex(k).slice(0, 16)}`;
        note(`${path}.${key}`, k, k.length);
      }
      setOwn<unknown>(out, key, walk(own(o, k), path === "" ? key : `${path}.${key}`, depth + 1));
    }
    return out;
  };
  const out = walk(event, "", 0) as Record<string, unknown>;
  if (notes.length > 0) out.bounded = more > 0 ? { fields: notes, more } : { fields: notes };
  return out;
}

const str = (v: unknown, max: number): string | undefined => (typeof v === "string" ? v.slice(0, max) : undefined);

/** The minimal entry written when the full one is refused: what was decided, never the agent's text. */
export function fallbackEvent(event: Record<string, unknown>, refused: Error & { reason?: string }): Record<string, unknown> {
  const type = str(event.type, 64) ?? "unknown";
  const session = str(event.session, 128);
  const verdict = str(event.verdict, 16);
  const rules = Array.isArray(event.rules) ? event.rules.filter((r): r is string => typeof r === "string").slice(0, 32).map((r) => r.slice(0, 64)) : undefined;
  const action = typeof event.action === "string" && /^[0-9a-f]{64}$/.test(event.action) ? event.action : undefined;
  return {
    type,
    fallback: true,
    ...(session !== undefined ? { session } : {}),
    ...(verdict !== undefined ? { verdict } : {}),
    ...(rules !== undefined ? { rules } : {}),
    ...(action !== undefined ? { action } : {}),
    refused: typeof refused.reason === "string" ? refused.reason.slice(0, 32) : "refused",
    why: refused.message.slice(0, 300),
  };
}

/**
 * Appends a firewall event bounded (above) through `append`, or its fallback entry when the bounded event is
 * refused. Throws LogUnrecorded when both are refused (or `append` itself reports LogUnrecorded); any other
 * error (I/O) is thrown unchanged.
 */
export function appendBoundedWith<T>(append: (e: Record<string, unknown>) => T, event: Record<string, unknown>): T {
  try {
    return append(boundEvent(event));
  } catch (e) {
    if (!isLogRefused(e)) throw e;
    try {
      return append(fallbackEvent(event, e));
    } catch (e2) {
      if (!isLogRefused(e2)) throw e2;
      throw new LogUnrecorded(`the decision log refused this entry (${e.message}) and its fallback entry (${e2.message})`);
    }
  }
}
