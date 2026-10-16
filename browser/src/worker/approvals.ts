/**
 * The approvals queue (design 5.3, 5.4, 9) over engine/bindings.ts, kept in
 * chrome.storage.session so a service-worker restart neither loses a pending
 * approval nor revives a spent token. The session area is cleared when the
 * browser closes and is readable only by trusted contexts (the worker sets
 * TRUSTED_CONTEXTS), never by content scripts or pages.
 *
 * - Every operation runs on one promise chain, after the ledger is loaded, and
 *   persists before it resolves: two messages arriving together cannot lose
 *   each other's change, and a token is never handed out before the record
 *   that can redeem it is stored.
 * - Next to each record the service keeps its display metadata (label,
 *   destination, masked fields, reasons). Never a raw field value: the
 *   snapshot holds only a digest, and the metadata only masked values.
 * - A corrupt stored value is ignored (the queue starts empty), never trusted.
 * - The stored ledger is bounded in bytes too (MAX_STORED_CHARS): a record keeps a few capped field names and
 *   capped metadata, spent records are dropped first and then the oldest live ones when the total is too large,
 *   and a write that fails (quota) sheds half and is tried once more. An agent-mode-off approval is never
 *   shed. A request whose record cannot be stored fails, and the gate then fails closed.
 * - The queue is bounded (RR10): a request identical to one already pending
 *   (same tab, frame, element and fingerprint) is coalesced into it; a tab
 *   holds at most MAX_PENDING_PER_TAB and the queue MAX_PENDING_TOTAL. Over a
 *   bound, the oldest pending approval of the tab with the most is retired, so
 *   a flooding tab only pushes out its own requests and the newest request
 *   always stays visible. Retired approvals are reported (`onEvicted`) so the
 *   frame that holds them can let go.
 */
import { ApprovalLedger, type ApprovalPurpose, type ApprovalRecord, type LedgerJson, type RedeemResult } from "../engine/bindings.js";
import { actionFingerprint, type ActionSnapshot } from "../engine/fingerprint.js";
import type { RuleId } from "../engine/types.js";
import type { ApprovalSubject } from "../shared/messages.js";
import type { KeyValueArea } from "./state.js";

export const APPROVALS_KEY = "ls.approvals";

/** What the approval surfaces show for one approval. Masked and bounded; page text is escaped by the UI. */
export interface ApprovalMeta {
  subject: ApprovalSubject;
  label: string;
  /** The form destination or download URL ("" when none). */
  target: string;
  pageUrl: string;
  fields: { name: string; masked: string }[];
  reasons: string[];
  untrustedBecause: string[];
  /** The engine said deny with a side-panel override (quarantine in agent mode). */
  overridesDeny: boolean;
  /** For downloads: what the worker needs to fetch the file again once approved. */
  download?: { url: string; filename: string; mime: string };
  /**
   * For a blocked navigation: the tab, the destination host, how many characters of data the address carries
   * and a salted digest of the address (guard-nav.ts). Never the address itself (RR9): the worker holds that
   * in memory-only session storage until the pass is used or dropped, and finds it by the digest.
   */
  navigation?: { tabId: number; host: string; chars: number; digest: string; rule: RuleId };
}

export interface ApprovalService {
  /** Resolves once the stored queue is loaded. Every method waits for it. */
  ready: Promise<void>;
  request(snapshot: ActionSnapshot, purpose: ApprovalPurpose, meta: ApprovalMeta): Promise<ApprovalRecord>;
  /** A person approved in extension UI; the one-shot token for the replay, or null when no longer pending. */
  approve(approvalId: string): Promise<string | null>;
  deny(approvalId: string): Promise<boolean>;
  redeem(token: string, presented: ActionSnapshot, purpose?: ApprovalPurpose): Promise<RedeemResult>;
  pending(): Promise<ApprovalRecord[]>;
  get(approvalId: string): Promise<ApprovalRecord | undefined>;
  meta(approvalId: string): Promise<ApprovalMeta | undefined>;
  /** A tab's top-level document changed or the tab closed: its approvals expire. */
  onTabNavigated(tabId: number): Promise<number>;
  /** A subframe navigated: its approvals expire. */
  onFrameNavigated(tabId: number, frameId: number): Promise<number>;
  /** A blocked navigation's tab closed or moved on: its pending navigation approvals expire (they are not bound to a frame). */
  expireNavigations(tabId: number): Promise<number>;
  /** An approved navigation could not be carried out: back to pending, token forgotten (not spent). */
  unapprove(approvalId: string): Promise<boolean>;
}

/** Pending approvals one tab may hold, and the whole queue (RR10). */
export const MAX_PENDING_PER_TAB = 50;
export const MAX_PENDING_TOTAL = 200;
/** The stored ledger and metadata, in characters of JSON: well inside the session area's 10 MB quota. */
export const MAX_STORED_CHARS = 2 * 1024 * 1024;
/** The bucket downloads count in: they belong to no tab, and must not share the "no tab" bucket (-1) with others. */
const DOWNLOAD_BUCKET = -2;

/** The metadata as stored: every page-controlled string cut to what the surfaces show. */
export function clampMeta(m: ApprovalMeta): ApprovalMeta {
  return {
    ...m,
    label: m.label.slice(0, 512),
    target: m.target.slice(0, 2048),
    pageUrl: m.pageUrl.slice(0, 2048),
    fields: m.fields.slice(0, 40).map((f) => ({ name: f.name.slice(0, 128), masked: f.masked.slice(0, 160) })),
    reasons: m.reasons.slice(0, 32),
    untrustedBecause: m.untrustedBecause.slice(0, 32),
  };
}

/** 128 bits from the platform CSPRNG, hex. */
export function randomId(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

interface Stored {
  ledger: LedgerJson;
  meta: Record<string, ApprovalMeta>;
}

const STATES = new Set(["pending", "approved", "denied", "consumed", "expired", "burned"]);

function isRecord(r: unknown): r is ApprovalRecord {
  if (typeof r !== "object" || r === null) return false;
  const x = r as Record<string, unknown>;
  const s = x.snapshot as Record<string, unknown> | undefined;
  return (
    typeof x.id === "string" &&
    (x.purpose === "action" || x.purpose === "agent_mode_off") &&
    typeof x.state === "string" &&
    STATES.has(x.state) &&
    typeof x.fingerprint === "string" &&
    typeof x.createdAt === "number" &&
    typeof x.expiresAt === "number" &&
    (x.token === undefined || typeof x.token === "string") &&
    typeof s === "object" &&
    s !== null &&
    typeof s.tabId === "number" &&
    typeof s.frameId === "number" &&
    typeof s.elementPath === "string" &&
    Array.isArray(s.fieldNames)
  );
}

function parseStored(v: unknown): Stored | null {
  if (typeof v !== "object" || v === null) return null;
  const x = v as Partial<Stored>;
  if (typeof x.ledger !== "object" || x.ledger === null || !Array.isArray(x.ledger.records) || !x.ledger.records.every(isRecord)) return null;
  if (typeof x.meta !== "object" || x.meta === null) return null;
  return { ledger: x.ledger, meta: x.meta };
}

export interface ApprovalServiceOptions {
  now?: () => number;
  randomId?: () => string;
  /** Pending approvals retired to keep the queue within its bounds (index.ts tells their frames). */
  onEvicted?: (records: ApprovalRecord[]) => void;
  /** The stored size above which the oldest records are shed. */
  maxStoredChars?: number;
}

export function createApprovalService(area: KeyValueArea, opts: ApprovalServiceOptions = {}): ApprovalService {
  const now = opts.now ?? Date.now;
  const rid = opts.randomId ?? randomId;
  let ledger = new ApprovalLedger({ now, randomId: rid });
  let meta: Record<string, ApprovalMeta> = {};

  const ready = (async () => {
    try {
      const got = await area.get(APPROVALS_KEY);
      const stored = parseStored(got[APPROVALS_KEY]);
      if (stored !== null) {
        ledger = new ApprovalLedger({ now, randomId: rid }, stored.ledger);
        meta = stored.meta;
      }
    } catch {
      // Unreadable storage: start empty. Nothing pending is better than trusting a value we cannot read.
    }
  })();

  const maxChars = opts.maxStoredChars ?? MAX_STORED_CHARS;
  const syncMeta = (): void => {
    const live = new Set(ledger.toJSON().records.map((r) => r.id));
    for (const id of Object.keys(meta)) if (!live.has(id)) delete meta[id];
  };
  const storedChars = (): number => {
    syncMeta();
    return JSON.stringify({ ledger: ledger.toJSON(), meta }).length;
  };

  async function store(): Promise<void> {
    ledger.prune();
    const shed: ApprovalRecord[] = [];
    const shedWhile = (tooBig: () => boolean): void => {
      while (tooBig()) {
        const v = ledger.shedOldest();
        if (v === undefined) return;
        if (v !== null) shed.push(v);
      }
    };
    shedWhile(() => storedChars() > maxChars);
    const write = (): Promise<void> => area.set({ [APPROVALS_KEY]: { ledger: ledger.toJSON(), meta } satisfies Stored });
    try {
      syncMeta();
      await write();
    } catch (e) {
      // Quota or a transient failure: shed the older half and try once more; a second failure is the caller's.
      const half = storedChars() / 2;
      shedWhile(() => storedChars() > half);
      try {
        await write();
      } catch {
        throw e;
      }
    } finally {
      if (shed.length > 0) opts.onEvicted?.(shed);
    }
  }

  let chain: Promise<unknown> = ready;
  function run<T>(fn: () => T, persist: boolean): Promise<T> {
    const next = chain.then(async () => {
      const out = fn();
      if (persist) await store();
      return out;
    });
    chain = next.catch(() => undefined);
    return next;
  }

  /** The bucket an approval counts in for the queue bounds: a navigation's tab, downloads' own bucket, else the snapshot's tab. */
  const bucket = (s: ActionSnapshot, m: ApprovalMeta | undefined): number => m?.navigation?.tabId ?? (m?.subject === "download" ? DOWNLOAD_BUCKET : s.tabId);
  const tabOf = (r: ApprovalRecord): number => bucket(r.snapshot, meta[r.id]);

  const request = (s: ActionSnapshot, purpose: ApprovalPurpose, m: ApprovalMeta): ApprovalRecord => {
    const pending = ledger.pending();
    const fp = actionFingerprint(s);
    const same = pending.find((r) => r.purpose === purpose && r.fingerprint === fp && r.snapshot.tabId === s.tabId && r.snapshot.frameId === s.frameId && r.snapshot.elementPath === s.elementPath && tabOf(r) === bucket(s, m));
    if (same !== undefined) {
      meta[same.id] = clampMeta(m);
      return same;
    }
    const tab = bucket(s, m);
    const evicted: ApprovalRecord[] = [];
    const retire = (r: ApprovalRecord) => {
      if (ledger.expire(r.id)) evicted.push(r);
    };
    let live = pending;
    // The agent-mode-off approval has no tab and is never retired to make room.
    const mine = live.filter((r) => tabOf(r) === tab && r.purpose !== "agent_mode_off");
    for (const r of mine.slice(0, Math.max(0, mine.length - (MAX_PENDING_PER_TAB - 1)))) retire(r);
    live = live.filter((r) => !evicted.includes(r));
    while (live.length >= MAX_PENDING_TOTAL) {
      const counts = new Map<number, number>();
      for (const r of live) counts.set(tabOf(r), (counts.get(tabOf(r)) ?? 0) + 1);
      const busiest = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
      const victim = live.find((r) => tabOf(r) === busiest && r.purpose !== "agent_mode_off") ?? live.find((r) => r.purpose !== "agent_mode_off");
      if (victim === undefined) break;
      retire(victim);
      live = live.filter((r) => r !== victim);
    }
    const rec = ledger.request(s, purpose);
    meta[rec.id] = clampMeta(m);
    if (evicted.length > 0) opts.onEvicted?.(evicted);
    return rec;
  };

  return {
    ready,
    request: (s, purpose, m) => run(() => request(s, purpose, m), true),
    approve: (id) => run(() => ledger.approve(id), true),
    deny: (id) => run(() => ledger.deny(id), true),
    redeem: (token, s, purpose) => run(() => ledger.redeem(token, s, purpose), true),
    // Reads persist too: a lazily expired record must not come back after a restart as pending.
    pending: () => run(() => ledger.pending(), true),
    get: (id) => run(() => ledger.get(id), false),
    meta: (id) => run(() => meta[id], false),
    onTabNavigated: (tabId) => run(() => ledger.expireTab(tabId), true),
    onFrameNavigated: (tabId, frameId) => run(() => ledger.expireFrame(tabId, frameId), true),
    expireNavigations: (tabId) =>
      run(() => {
        let n = 0;
        // Pending only: an approved one is being carried out right now (its tab is the one moving on).
        for (const r of ledger.toJSON().records) if (r.state === "pending" && meta[r.id]?.navigation?.tabId === tabId && ledger.expire(r.id)) n++;
        return n;
      }, true),
    unapprove: (id) => run(() => ledger.unapprove(id), true),
  };
}
