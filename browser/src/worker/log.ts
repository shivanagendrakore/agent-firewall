/**
 * The decision log (design 9): every decision appended to IndexedDB,
 * hash-chained with SHA-256 (WebCrypto), kept 30 days by default, with export,
 * delete and verify.
 *
 * - Each entry's hash covers its sequence number, the previous entry's hash
 *   and every field, so editing, reordering or removing an entry in the middle
 *   breaks the chain at that entry.
 * - The chain's two ends are kept in a meta record: the anchor (the last entry
 *   retention removed, or the genesis) and the head (the newest entry). Removing
 *   the oldest rows without moving the anchor, or the newest without moving the
 *   head, is caught too.
 * - Anyone who controls the browser profile can rewrite the whole chain and its
 *   meta record; the extension cannot keep a key secret from them, so this is
 *   tamper-evident against partial edits, not a signed log (design 9). Signed
 *   entries come with the native link.
 * - Never page text or field values: entries carry the registrable domain,
 *   fixed rule ids and codes. Hidden-text evidence only with "keep evidence"
 *   on, escaped and cut to 200 characters (`escapeEvidence`).
 *
 * Storage is behind `LogBackend` so the chain logic is unit-tested in Node
 * (`createMemoryBackend`); the extension uses `createIdbBackend`.
 */
import type { ChainedEntry, LogEntry, LogVerifyReply } from "../shared/messages.js";
import { isRuleId } from "../shared/messages.js";

export type { ChainedEntry, LogEntry } from "../shared/messages.js";

export const RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
export const GENESIS_HASH = "0".repeat(64);
export const EVIDENCE_MAX = 200;

/** One end of the chain: a sequence number and the hash of that entry. */
export interface ChainPoint {
  seq: number;
  hash: string;
}

/** The chain's ends. `anchor` is what the oldest kept entry links to; `head` is the newest entry. */
export interface ChainMeta {
  anchor: ChainPoint;
  head: ChainPoint;
}

export const GENESIS: ChainMeta = Object.freeze({ anchor: Object.freeze({ seq: -1, hash: GENESIS_HASH }), head: Object.freeze({ seq: -1, hash: GENESIS_HASH }) });

/**
 * The most entries the log keeps, whatever the retention period: past it, the oldest go first and the anchor
 * moves with them (as for retention), so a page that makes thousands of decisions cannot grow the log without
 * bound. Every read is bounded too (cursors with a limit, never getAll over the whole store).
 */
export const MAX_LOG_ENTRIES = 20_000;

export interface LogBackend {
  /** Every entry, oldest first (at most MAX_LOG_ENTRIES and a margin). */
  all(): Promise<ChainedEntry[]>;
  /** The newest `limit` entries, oldest first. */
  recent(limit: number): Promise<ChainedEntry[]>;
  /** Removes the oldest entries beyond `max`, moving the anchor to the last one removed. Returns how many. */
  trim(max: number): Promise<number>;
  meta(): Promise<ChainMeta>;
  /** Writes the entry and the new head together. */
  append(entry: ChainedEntry, meta: ChainMeta): Promise<void>;
  /** Removes the oldest entries while their time is before `cutoff`, moving the anchor to the last one removed. Returns how many. */
  dropOlderThan(cutoff: number): Promise<number>;
  /** Removes every entry and resets the chain to the genesis. */
  clear(): Promise<void>;
}

export interface DecisionLog {
  append(entry: LogEntry): Promise<ChainedEntry>;
  /** Entries since `since` (ms), oldest first, at most the newest `limit`. */
  list(opts?: { since?: number; limit?: number }): Promise<ChainedEntry[]>;
  /** Recomputes the chain; `brokenAt` is the first sequence number that does not match, or null when intact. */
  verify(): Promise<LogVerifyReply>;
  exportJson(): Promise<string>;
  /** Deletes every entry; the new chain starts with a `log_cleared` entry saying when (RR14). */
  clear(): Promise<void>;
  /** Drops entries older than the retention period. Returns how many. */
  purge(now?: number): Promise<number>;
}

export interface LogOptions {
  backend: LogBackend;
  now?: () => number;
  /** The retention period in ms, read on every purge (the person may change it; async so it can be read from storage first, RR8). */
  retentionMs?: () => number | Promise<number>;
  /** How often an append also purges (default hourly; the worker has no alarms permission). */
  purgeEveryMs?: number;
  /** The entry cap (default MAX_LOG_ENTRIES). */
  maxEntries?: number;
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** The exact bytes an entry's hash covers: a fixed field order, absent fields as null. */
export function canonical(e: Omit<ChainedEntry, "hash">): string {
  return JSON.stringify([e.seq, e.prevHash, e.at, e.site, e.actionClass, e.verdict, e.rules, e.approval ?? null, e.binding ?? null, e.evidence ?? null, e.event ?? null, e.detail ?? null]);
}

export function entryHash(e: Omit<ChainedEntry, "hash">): Promise<string> {
  return sha256Hex(canonical(e));
}

/** Only the fields a log entry may hold; anything else a caller passes is dropped, never stored. */
function clean(entry: LogEntry): LogEntry {
  const out: LogEntry = { at: entry.at, site: entry.site, actionClass: entry.actionClass, verdict: entry.verdict, rules: [...entry.rules] };
  if (entry.approval !== undefined) out.approval = entry.approval;
  if (entry.binding !== undefined) out.binding = entry.binding;
  if (entry.evidence !== undefined) out.evidence = escapeEvidence(entry.evidence);
  if (entry.event !== undefined) out.event = entry.event;
  if (entry.detail !== undefined) out.detail = entry.detail.slice(0, 16).map((d) => d.slice(0, 64));
  return out;
}

/**
 * Hidden text as evidence: control, format (bidi, zero-width, tag) and
 * non-ASCII-space characters shown as \u{...} so they cannot steer a reader
 * or reorder the display, then cut to 200 characters (threat model 4, #22).
 */
export function escapeEvidence(text: string): string {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0) as number;
    const invisible = cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) || /\p{Cf}|\p{Zl}|\p{Zp}/u.test(ch) || (cp > 0x7f && /\s/u.test(ch));
    out += invisible ? `\\u{${cp.toString(16)}}` : ch;
    if (out.length >= EVIDENCE_MAX) break;
  }
  return out.slice(0, EVIDENCE_MAX);
}

function wellFormed(e: unknown): e is ChainedEntry {
  if (typeof e !== "object" || e === null) return false;
  const x = e as Record<string, unknown>;
  return (
    typeof x.seq === "number" &&
    typeof x.prevHash === "string" &&
    typeof x.hash === "string" &&
    typeof x.at === "number" &&
    typeof x.site === "string" &&
    (x.actionClass === null || typeof x.actionClass === "string") &&
    typeof x.verdict === "string" &&
    Array.isArray(x.rules) &&
    x.rules.every(isRuleId)
  );
}

export function createLog(opts: LogOptions): DecisionLog {
  const { backend } = opts;
  const now = opts.now ?? Date.now;
  const retentionMs = opts.retentionMs ?? (() => RETENTION_MS);
  const purgeEvery = opts.purgeEveryMs ?? 60 * 60 * 1000;
  const maxEntries = opts.maxEntries ?? MAX_LOG_ENTRIES;
  let lastPurge = Number.NEGATIVE_INFINITY;
  // Appends, purges and clears run one at a time, so two appends never take the same sequence number.
  let chain: Promise<unknown> = Promise.resolve();
  const serial = <T>(fn: () => Promise<T>): Promise<T> => {
    const next = chain.then(fn);
    chain = next.catch(() => undefined);
    return next;
  };

  const purgeNow = async (at: number): Promise<number> => {
    lastPurge = at;
    return backend.dropOlderThan(at - (await retentionMs()));
  };

  const appendNow = async (entry: LogEntry): Promise<ChainedEntry> => {
    const at = now();
    if (at - lastPurge >= purgeEvery) await purgeNow(at);
    const meta = await backend.meta();
    const body = { ...clean(entry), seq: meta.head.seq + 1, prevHash: meta.head.hash };
    const hash = await entryHash(body);
    const chained: ChainedEntry = { ...body, hash };
    await backend.append(chained, { anchor: meta.anchor, head: { seq: chained.seq, hash } });
    // Keep at most maxEntries (checked every append; trimming happens only past the cap).
    if (chained.seq - meta.anchor.seq > maxEntries) await backend.trim(maxEntries);
    return chained;
  };

  const verify = async (): Promise<LogVerifyReply> => {
    const [entries, meta] = await Promise.all([backend.all(), backend.meta()]);
    let prev = meta.anchor;
    for (const e of entries) {
      const expectedSeq = prev.seq + 1;
      if (!wellFormed(e)) return { brokenAt: expectedSeq, count: entries.length };
      if (e.seq !== expectedSeq || e.prevHash !== prev.hash) return { brokenAt: Math.min(e.seq, expectedSeq), count: entries.length };
      const { hash, ...rest } = e;
      if ((await entryHash(rest)) !== hash) return { brokenAt: e.seq, count: entries.length };
      prev = { seq: e.seq, hash };
    }
    // The newest entry must be the recorded head: a removed tail shows here.
    if (prev.seq !== meta.head.seq || prev.hash !== meta.head.hash) return { brokenAt: prev.seq + 1, count: entries.length };
    return { brokenAt: null, count: entries.length };
  };

  return {
    append(entry) {
      return serial(() => appendNow(entry));
    },
    async list(o) {
      const since = o?.since ?? 0;
      const rows = o?.limit === undefined ? await backend.all() : await backend.recent(o.limit);
      return rows.filter((e) => e.at >= since);
    },
    verify,
    async exportJson() {
      const [entries, meta, check] = await Promise.all([backend.all(), backend.meta(), verify()]);
      return JSON.stringify(
        {
          format: "launchsafe-browser-firewall-log",
          version: 1,
          exportedAt: new Date(now()).toISOString(),
          hash: "sha256 over canonical([seq, prevHash, at, site, actionClass, verdict, rules, approval, binding, evidence, event, detail])",
          anchor: meta.anchor,
          head: meta.head,
          verify: check,
          entries,
        },
        null,
        2,
      );
    },
    clear() {
      return serial(async () => {
        await backend.clear();
        // The deletion itself is recorded, so an empty log is never mistaken for one that had nothing in it.
        await appendNow({ at: now(), site: "", actionClass: null, verdict: "log", rules: [], event: "log_cleared" });
      });
    },
    purge(at) {
      return serial(() => purgeNow(at ?? now()));
    },
  };
}

// ---- backends ---------------------------------------------------------------

/** An in-memory backend (tests). `entries` is exposed so tests can tamper with it. */
export function createMemoryBackend(): LogBackend & { entries: ChainedEntry[]; state: { meta: ChainMeta } } {
  const entries: ChainedEntry[] = [];
  const state = { meta: structuredClone(GENESIS) as ChainMeta };
  return {
    entries,
    state,
    all: async () => entries.slice(0, MAX_LOG_ENTRIES + ALL_MARGIN).map((e) => structuredClone(e)),
    recent: async (limit) => entries.slice(-limit).map((e) => structuredClone(e)),
    async trim(max) {
      let n = 0;
      while (entries.length > max) {
        const e = entries.shift() as ChainedEntry;
        state.meta = { ...state.meta, anchor: { seq: e.seq, hash: e.hash } };
        n++;
      }
      return n;
    },
    meta: async () => structuredClone(state.meta),
    async append(e, meta) {
      entries.push(structuredClone(e));
      state.meta = structuredClone(meta);
    },
    async dropOlderThan(cutoff) {
      let n = 0;
      while (entries.length > 0 && (entries[0] as ChainedEntry).at < cutoff) {
        const e = entries.shift() as ChainedEntry;
        state.meta = { ...state.meta, anchor: { seq: e.seq, hash: e.hash } };
        n++;
      }
      return n;
    },
    async clear() {
      entries.length = 0;
      state.meta = structuredClone(GENESIS) as ChainMeta;
    },
  };
}

/** all() reads at most this many entries past the cap (a log written before the cap existed is trimmed on its next append). */
const ALL_MARGIN = 1_000;

export const IDB_NAME = "launchsafe-log";
const ENTRIES = "entries";
const META = "meta";
const META_KEY = "chain";

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((ok, fail) => {
    r.onsuccess = () => ok(r.result);
    r.onerror = () => fail(r.error);
  });
}

function done(tx: IDBTransaction): Promise<void> {
  return new Promise((ok, fail) => {
    tx.oncomplete = () => ok();
    tx.onerror = () => fail(tx.error);
    tx.onabort = () => fail(tx.error ?? new Error("log transaction aborted"));
  });
}

function isMeta(x: unknown): x is ChainMeta {
  const p = (v: unknown): boolean => typeof v === "object" && v !== null && typeof (v as ChainPoint).seq === "number" && typeof (v as ChainPoint).hash === "string";
  return typeof x === "object" && x !== null && p((x as ChainMeta).anchor) && p((x as ChainMeta).head);
}

/** The IndexedDB backend: entries keyed by sequence number, the chain's ends in one meta record, each change in one transaction. */
export function createIdbBackend(factory: IDBFactory = indexedDB, name: string = IDB_NAME): LogBackend {
  let dbp: Promise<IDBDatabase> | null = null;
  const db = (): Promise<IDBDatabase> => {
    dbp ??= new Promise((ok, fail) => {
      const open = factory.open(name, 1);
      open.onupgradeneeded = () => {
        const d = open.result;
        if (!d.objectStoreNames.contains(ENTRIES)) d.createObjectStore(ENTRIES, { keyPath: "seq" });
        if (!d.objectStoreNames.contains(META)) d.createObjectStore(META);
      };
      open.onsuccess = () => ok(open.result);
      open.onerror = () => fail(open.error);
    });
    return dbp;
  };
  const readMeta = async (store: IDBObjectStore): Promise<ChainMeta> => {
    const m: unknown = await req(store.get(META_KEY));
    return isMeta(m) ? m : (structuredClone(GENESIS) as ChainMeta);
  };
  /** Up to `limit` entries by cursor, oldest first (`newest`: the newest ones, still returned oldest first). */
  const readCursor = async (limit: number, newest: boolean): Promise<ChainedEntry[]> => {
    const tx = (await db()).transaction(ENTRIES, "readonly");
    const out: ChainedEntry[] = [];
    if (limit <= 0) return out;
    await new Promise<void>((ok, fail) => {
      const cur = tx.objectStore(ENTRIES).openCursor(null, newest ? "prev" : "next");
      cur.onerror = () => fail(cur.error);
      cur.onsuccess = () => {
        const c = cur.result;
        if (c == null) return ok();
        out.push(c.value as ChainedEntry);
        if (out.length >= limit) return ok();
        c.continue();
      };
    });
    return newest ? out.reverse() : out;
  };
  return {
    all: () => readCursor(MAX_LOG_ENTRIES + ALL_MARGIN, false),
    recent: (limit) => readCursor(limit, true),
    async trim(max) {
      const tx = (await db()).transaction([ENTRIES, META], "readwrite");
      const entries = tx.objectStore(ENTRIES);
      const metaStore = tx.objectStore(META);
      const meta = await readMeta(metaStore);
      const total = await req(entries.count());
      let excess = total - max;
      let n = 0;
      let anchor = meta.anchor;
      if (excess > 0) {
        await new Promise<void>((ok, fail) => {
          const cur = entries.openCursor();
          cur.onerror = () => fail(cur.error);
          cur.onsuccess = () => {
            const c = cur.result;
            const e = c?.value as ChainedEntry | undefined;
            if (c == null || e === undefined || excess <= 0) return ok();
            anchor = { seq: e.seq, hash: e.hash };
            n++;
            excess--;
            c.delete();
            c.continue();
          };
        });
      }
      if (n > 0) metaStore.put({ anchor, head: meta.head }, META_KEY);
      await done(tx);
      return n;
    },
    async meta() {
      const tx = (await db()).transaction(META, "readonly");
      return readMeta(tx.objectStore(META));
    },
    async append(e, meta) {
      const tx = (await db()).transaction([ENTRIES, META], "readwrite");
      tx.objectStore(ENTRIES).put(e);
      tx.objectStore(META).put(meta, META_KEY);
      await done(tx);
    },
    async dropOlderThan(cutoff) {
      const tx = (await db()).transaction([ENTRIES, META], "readwrite");
      const entries = tx.objectStore(ENTRIES);
      const metaStore = tx.objectStore(META);
      const meta = await readMeta(metaStore);
      let n = 0;
      let anchor = meta.anchor;
      await new Promise<void>((ok, fail) => {
        const cur = entries.openCursor();
        cur.onerror = () => fail(cur.error);
        cur.onsuccess = () => {
          const c = cur.result;
          const e = c?.value as ChainedEntry | undefined;
          // Oldest first; stop at the first entry inside the retention period, so only a prefix goes.
          if (c == null || e === undefined || !(e.at < cutoff)) return ok();
          anchor = { seq: e.seq, hash: e.hash };
          n++;
          c.delete();
          c.continue();
        };
      });
      if (n > 0) metaStore.put({ anchor, head: meta.head }, META_KEY);
      await done(tx);
      return n;
    },
    async clear() {
      const tx = (await db()).transaction([ENTRIES, META], "readwrite");
      tx.objectStore(ENTRIES).clear();
      tx.objectStore(META).put(structuredClone(GENESIS), META_KEY);
      await done(tx);
    },
  };
}
