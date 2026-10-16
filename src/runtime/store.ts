/**
 * Session state on disk (an append-only event log per session) and the
 * approval queue. Every write happens under a lock; queue items are replaced
 * atomically. Anything unreadable makes the session stricter, never looser.
 */

import { randomBytes } from "node:crypto";
import { readdirSync, statSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { approvalUnused, foldEvents, parseEvent } from "../engine/state.js";
import { redactSecrets } from "../engine/secrets.js";
import type { SessionState, StateEvent } from "../types.js";
import { APPROVAL_TTL_MS, approvalNonce, verifyApproval, verifyLegacyApproval, verifyStateChange, type ApprovalGrant } from "./approver.js";
import { appendDurable, atomicWrite, endsWithNewline, readText, tryReadText, withLock } from "./fsutil.js";
import { layout, safeId, type Layout } from "./layout.js";
import { checkPhoneApproval, type PhoneTrust } from "./relay/trust.js";

export function sessionFile(l: Layout, sessionId: string): string {
  return join(l.sessions, `${safeId(sessionId)}.jsonl`);
}

/**
 * FZ21: damaged lines past this many are counted in one last "corrupt" event, not listed one by one. One corrupt
 * event is all the fold needs to make the session untrusted, and it keeps only the last few reasons anyway; a file
 * of hundreds of thousands of damaged lines (a mutated or truncated one) used to cost an event, a thrown error and
 * several passes each, seconds in all. Every line is still read: a valid event after the damage still counts.
 */
const MAX_DAMAGE_NOTES = 10;

/**
 * Whether a trimmed line can be an event at all: a JSON object whose first member is named by a string (an event has a
 * "type" member, so `{"type":""}`, 11 characters, is the least there is). Anything else is damage whatever
 * JSON.parse would make of it (a number, a list, `{}`, text, a brace around junk), so it is recorded without being
 * parsed: parsing a line that fails throws an error each time, about 2 microseconds, and a file can hold a line per
 * three bytes. What JSON.parse could still read as an event is never turned away here.
 */
function mayBeEvent(t: string): boolean {
  if (t.length < 11 || t.charCodeAt(0) !== 0x7b || t.charCodeAt(t.length - 1) !== 0x7d) return false;
  let i = 1;
  // JSON allows white space (space, tab, carriage return; a newline cannot be inside a line) before the first member's name.
  while (t.charCodeAt(i) === 0x20 || t.charCodeAt(i) === 0x09 || t.charCodeAt(i) === 0x0d) i++;
  return t.charCodeAt(i) === 0x22;
}

export function readEvents(l: Layout, sessionId: string): StateEvent[] {
  const text = tryReadText(sessionFile(l, sessionId));
  if (text === null) return [];
  // FZ7: a session file that exists but cannot be read leaves the session untrusted, like a corrupt line.
  if (typeof text !== "string") return [{ type: "corrupt", detail: `the session file cannot be read (${text.unreadable})` }];
  const out: StateEvent[] = [];
  let damaged = 0;
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    const t = line.trim();
    if (t === "") continue;
    let e: StateEvent | undefined;
    let notJson = false;
    if (mayBeEvent(t)) {
      try {
        e = parseEvent(JSON.parse(line));
      } catch {
        notJson = true;
      }
    }
    if (e !== undefined && e.type !== "corrupt") {
      out.push(e);
      continue;
    }
    if (++damaged <= MAX_DAMAGE_NOTES) out.push(e ?? { type: "corrupt", detail: `line ${i + 1} of the session file is not ${notJson ? "valid JSON" : "a JSON object"}` });
  }
  if (damaged > MAX_DAMAGE_NOTES) out.push({ type: "corrupt", detail: `${damaged - MAX_DAMAGE_NOTES} more damaged lines (${damaged} in all)` });
  return out;
}

/**
 * The session's state. Approvals count only if signed by the approver key (F4); an approval without a
 * valid signature was not made through the human channel, so it is treated as tampering: the session
 * becomes untrusted and the approval is ignored. Pass approverKey null when no key is pinned or set up.
 */
/** The keys a decision trusts: the approver key, and the phone pin with the policy's windows. */
export interface TrustKeys {
  approver: string | null;
  /** Absent: phone approvals are ignored (neither counted nor treated as tampering); the hook always passes it. */
  phones?: PhoneTrust;
  /** Item P: told of each stored phone approval that has lapsed (ignored as before: it changes no decision). The hook logs it once. */
  onPhoneExpired?: (e: { id: string; actionHash: string; credentialId: string; exp: string }) => void;
  /** The clock approvals' expiry is judged by (ms; tests). Default: now. */
  now?: number;
}

export function loadState(l: Layout, sessionId: string, keys: string | null | TrustKeys = null): SessionState {
  const k: TrustKeys = typeof keys === "object" && keys !== null ? keys : { approver: keys };
  const approverKey = k.approver;
  const now = k.now ?? Date.now();
  const counters = new Map<string, number>();
  // B1: one phone assertion (credential and the nonce of its signed message) approves once, whatever its counter.
  const phoneSeen = new Set<string>();
  const events = readEvents(l, sessionId).flatMap((e): StateEvent[] => {
    // Item P: a phone approval counts only if it re-verifies against the pinned phones and has not lapsed.
    if (e.type === "phone_approval") {
      if (k.phones === undefined) return [];
      const r = checkPhoneApproval(l, sessionId, e, k.phones, counters, phoneSeen);
      if (r.result === "ok") return [{ ...e, verified: true }];
      if (r.result === "corrupt") return [{ type: "corrupt", detail: r.detail }];
      if (r.result === "expired") {
        try {
          k.onPhoneExpired?.({ id: e.id, actionHash: e.actionHash, credentialId: e.credentialId, exp: e.exp });
        } catch {
          // Reporting must never change what the state says.
        }
      }
      return [];
    }
    return verifySigned(e);
  });
  return foldEvents(events);

  function queueKindOf(id: string): QueueItem["kind"] | null {
    try {
      return getQueueItem(l, id)?.kind ?? null;
    } catch {
      // Unreadable: not known to be a proposal, so the approval covers only an "approve" outcome.
      return null;
    }
  }

  function verifySigned(e: StateEvent): StateEvent[] {
    // Person-made changes count only with a valid approver signature; anything else is tampering.
    if (e.type === "scope_widen") return [approverKey !== null && verifyStateChange(approverKey, "scope-widen", sessionId, [e.kind, e.value, e.id], e.sig) ? e : { type: "corrupt", detail: `scope widening ${e.id} is not signed by the approval key` }];
    if (e.type === "budget_raise") return [approverKey !== null && verifyStateChange(approverKey, "budget-raise", sessionId, [e.key, String(e.amount), e.id], e.sig) ? e : { type: "corrupt", detail: `budget raise ${e.id} is not signed by the approval key` }];
    if (e.type !== "approval") return [e];
    const forged: StateEvent = { type: "corrupt", detail: `approval ${e.id} is not signed by the approval key` };
    if (approverKey === null || e.sig === undefined) return [forged];
    if (e.nonce === undefined || e.exp === undefined || e.rules === undefined || e.cwd === undefined || e.projectDir === undefined) {
      // B1: a v1 approval (no nonce, no expiry) could be replayed for the session's life: never honoured now.
      // One the key signed is stale, not tampering.
      return verifyLegacyApproval(approverKey, sessionId, e.actionHash, e.id, e.sig) ? [] : [forged];
    }
    if (!verifyApproval(approverKey, { sessionId, actionHash: e.actionHash, id: e.id, nonce: e.nonce, exp: e.exp, rules: e.rules, cwd: e.cwd, projectDir: e.projectDir }, e.sig)) return [forged];
    // B1: past its expiry an approval no longer counts (ignored: lapsing is normal, not tampering).
    const exp = Date.parse(e.exp);
    if (!Number.isFinite(exp) || now > exp) return [];
    // V37: whether the approved item was a proposal (shown with its diff) comes from the queue, never from the event.
    const { proposal: _ignored, ...base } = e;
    return [queueKindOf(e.id) === "proposal" ? { ...base, proposal: true } : base];
  }
}

/**
 * Appends events to the session, durably (fsynced before this returns). No lock: a session file is only
 * ever appended to, and appendDurable's single O_APPEND write cannot interleave with or overwrite another
 * process's append. The session lock serializes read-then-write sequences (consumeApproval, the budget
 * counters), and a plain append changes neither what they read nor what they decide: approval_used, the
 * one event consumeApproval checks, is only ever written under the lock (here too, if one is passed).
 */
export function appendEvents(l: Layout, sessionId: string, events: readonly StateEvent[]): void {
  if (events.length === 0) return;
  const file = sessionFile(l, sessionId);
  const ts = new Date().toISOString();
  // E: after a torn last line the new events start on a line of their own (the torn one reads as corrupt, never merged).
  const write = (): void => appendDurable(file, (endsWithNewline(file) ? "" : "\n") + events.map((e) => JSON.stringify({ ...e, ts })).join("\n") + "\n");
  // Anything carrying approval_used still goes through the lock, as consumeApproval's own write does.
  if (events.some((e) => e.type === "approval_used")) withLock(`${file}.lock`, write);
  else write();
}

/**
 * Uses a held approval once, atomically across processes: under the session lock the file is read again,
 * and the "approval_used" event is appended only if no other process used the approval since this one
 * read it. Returns false (nothing written) when it was used already; the caller then decides again
 * without it.
 */
export function consumeApproval(l: Layout, sessionId: string, actionHash: string, approvalId: string): boolean {
  const file = sessionFile(l, sessionId);
  return withLock(`${file}.lock`, () => {
    if (!approvalUnused(readEvents(l, sessionId), actionHash, approvalId)) return false;
    // B1: the id is recorded, so no line carrying this approval counts again anywhere in the session.
    appendDurable(file, `${endsWithNewline(file) ? "" : "\n"}${JSON.stringify({ type: "approval_used", actionHash, id: approvalId, ts: new Date().toISOString() })}\n`);
    return true;
  });
}

/**
 * I9: a session file that records taint or damage is kept whatever its age: removing it would let the session (a
 * resumed or compacted one keeps its id) start again trusted. Unreadable counts as holding them.
 */
function holdsTaint(p: string): boolean {
  try {
    const t = readText(p);
    return t !== null && /"type"\s*:\s*"(?:taint|corrupt)"/.test(t);
  } catch {
    return true;
  }
}

/** Removes session files not touched for `days` days. Bounded disk use. */
export function pruneSessions(l: Layout, days = 30, now = Date.now()): number {
  let n = 0;
  let names: string[];
  try {
    names = readdirSync(l.sessions);
  } catch {
    return 0;
  }
  for (const name of names) {
    if (!name.endsWith(".jsonl") && !name.endsWith(".meta.json") && !name.endsWith(".mode.json") && !name.endsWith(".counters.json")) continue;
    const p = join(l.sessions, name);
    try {
      if (now - statSync(p).mtimeMs > days * 86400000) {
        if (name.endsWith(".jsonl") && holdsTaint(p)) continue;
        unlinkSync(p);
        n++;
      }
    } catch {
      // Raced with another prune.
    }
  }
  return n;
}

// --- queue ------------------------------------------------------------------------------------------

export type QueueStatus = "pending" | "approved" | "rejected";

export interface Proposal {
  target: string;
  /** The change as text (always present). */
  change: string;
  /** Structured form for diffs: an edit's replacements, or a whole new file's content. */
  /** `all`: replace every occurrence (Edit's replace_all), as the approved action will (R19). */
  edits?: { old: string; new: string; all?: boolean }[];
  content?: string;
}

export interface QueueItem {
  version: 1;
  id: string;
  createdAt: string;
  sessionId: string;
  /** Where the agent was (for display). */
  cwd: string;
  /** The project directory the policy was judged under: every phone policy lookup uses this, never cwd. Older items lack it (a phone may not decide them). */
  projectDir?: string;
  tool: string;
  /** The tool input with credentials masked and long strings cut. */
  input: unknown;
  actionHash: string;
  rules: string[];
  reasons: string[];
  /** "proposal": a change to the agent's instructions or memory, held for review. */
  kind: "approval" | "proposal";
  proposal?: Proposal;
  /** What the agent wanted to do, in one line (added in 0.1; older items fall back to the tool). */
  summary?: string;
  /** What made the session untrusted, most recent last. */
  trustSources?: string[];
  /** Held because nobody could answer at the time (unattended), rather than a hold that always applies. */
  unattended?: boolean;
  /** What approving may also add to the session's task scope (offered by queue approve/review). */
  scopeWiden?: { kind: "path" | "repo" | "host" | "intent"; value: string }[];
  /**
   * F12: every part of a native call that became several actions (a multi-file patch), each with its change,
   * so the person sees everything an approval lets run (it runs as a whole).
   */
  parts?: { tool: string; target: string; change: string; held?: boolean }[];
  /** Fewer prompts: the code of this exact action in its project (`allow add <code>`, `allow never <code>`). */
  learn?: string;
  /** I3: what storing the item cut (each also marked "… [N more ...]" where it happened); absent: nothing. */
  truncated?: string[];
  status: QueueStatus;
  decidedAt?: string;
  /** Item P: who decided, when it was not the terminal ("phone: <label>"). */
  decidedBy?: string;
}

const MAX_STRING = 20000;
const MAX_ENTRIES = 200;
const MAX_NOTES = 20;

/**
 * I3: credentials masked and long values cut, each cut marked where it happened ("… [N more ...]") and
 * noted in `cut`, so the person is told that what they approve is more than what they see.
 */
function maskValue(v: unknown, depth = 0, cut: string[] = []): unknown {
  const note = (s: string): void => {
    if (cut.length < MAX_NOTES && !cut.includes(s)) cut.push(s);
  };
  if (depth > 10) {
    note("values nested deeper than 10 levels");
    return "… [nested deeper than 10 levels, not shown]";
  }
  if (typeof v === "string") {
    const r = redactSecrets(v).text;
    if (r.length <= MAX_STRING) return r;
    note(`a text of ${r.length} characters (${r.length - MAX_STRING} more not shown)`);
    return `${r.slice(0, MAX_STRING)}… [${r.length - MAX_STRING} more characters]`;
  }
  if (Array.isArray(v)) {
    const out = v.slice(0, MAX_ENTRIES).map((x) => maskValue(x, depth + 1, cut));
    if (v.length > MAX_ENTRIES) {
      note(`a list of ${v.length} items (${v.length - MAX_ENTRIES} more not shown)`);
      out.push(`… [${v.length - MAX_ENTRIES} more items]`);
    }
    return out;
  }
  if (typeof v === "object" && v !== null) {
    const entries = Object.entries(v);
    const out = Object.fromEntries(entries.slice(0, MAX_ENTRIES).map(([k, x]) => [k, maskValue(x, depth + 1, cut)]));
    if (entries.length > MAX_ENTRIES) {
      note(`an object with ${entries.length} keys (${entries.length - MAX_ENTRIES} more not shown)`);
      out["…"] = `[${entries.length - MAX_ENTRIES} more keys]`;
    }
    return out;
  }
  return v;
}

export function maskForStorage(v: unknown): unknown {
  return maskValue(v);
}

/**
 * I3: what of a held action is not shown in full (empty: nothing was cut). Items written before the
 * `truncated` field are checked for the cut markers storage wrote.
 */
export function itemTruncation(it: QueueItem): string[] {
  if (Array.isArray(it.truncated)) return it.truncated.filter((x): x is string => typeof x === "string");
  const text = JSON.stringify([it.input, it.proposal ?? null, it.parts ?? null]);
  return /… \[\d+ more characters\]/.test(text) || text.includes('"…"') ?["parts of the stored action (cut when it was held)"] : [];
}

function itemPath(l: Layout, id: string): string {
  return join(l.queue, `${id}.json`);
}

export function newQueueId(): string {
  // Short enough to type; 40 bits of randomness.
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  const bytes = randomBytes(8);
  let s = "";
  for (const b of bytes) s += alphabet[b % alphabet.length];
  return s;
}

export function listQueue(l: Layout): { items: QueueItem[]; corrupt: string[] } {
  const items: QueueItem[] = [];
  const corrupt: string[] = [];
  let names: string[] = [];
  try {
    names = readdirSync(l.queue).filter((n) => n.endsWith(".json"));
  } catch {
    return { items, corrupt };
  }
  for (const n of names) {
    try {
      const it: unknown = JSON.parse(readText(join(l.queue, n)) ?? "");
      // An item filed under another id is damaged too: it could not be decided by the id it shows.
      if (!validItem(it) || n !== `${it.id}.json`) throw new Error("bad item");
      items.push(it);
    } catch {
      corrupt.push(n);
    }
  }
  items.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  return { items, corrupt };
}

function validItem(v: unknown): v is QueueItem {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const it = v as Record<string, unknown>;
  return it.version === 1 && typeof it.id === "string" && typeof it.actionHash === "string" && typeof it.status === "string" && typeof it.createdAt === "string" && typeof it.sessionId === "string";
}

/** One item, or "absent", or "corrupt" (unreadable, not JSON, not an item, or another item's id): never throws. */
export function readQueueItem(l: Layout, id: string): QueueItem | "absent" | "corrupt" {
  if (!/^[a-z0-9]{4,32}$/.test(id)) return "absent";
  try {
    const t = readText(itemPath(l, id));
    if (t === null) return "absent";
    const it: unknown = JSON.parse(t);
    return validItem(it) && it.id === id ? it : "corrupt";
  } catch {
    return "corrupt";
  }
}

/**
 * FZ5: the item, or null when it is absent or damaged (as listQueue reports it). A damaged item is never
 * an approval of anything: every caller treats null as "no such item".
 */
export function getQueueItem(l: Layout, id: string): QueueItem | null {
  const r = readQueueItem(l, id);
  return typeof r === "string" ? null : r;
}

function itemForDecision(l: Layout, id: string): QueueItem {
  const it = readQueueItem(l, id);
  if (it === "corrupt") throw new Error(`queue item ${id} is damaged and cannot be decided`);
  if (it === "absent") throw new Error(`no queue item ${id}`);
  return it;
}

function sameRules(a: readonly string[], b: readonly string[]): boolean {
  const x = [...new Set(a)].sort();
  const y = [...new Set(b)].sort();
  return x.length === y.length && x.every((r, i) => r === y[i]);
}

/**
 * Records an action that needs a person. The same pending action in the same session reuses its item only while it
 * shows the rules asking now, for the same directory and project: approving an item signs what it shows (I2/I9), so
 * a stale one would give an approval the engine then refuses.
 */
export function enqueue(l: Layout, item: Omit<QueueItem, "id" | "createdAt" | "status" | "version">): QueueItem {
  return withLock(join(l.locks, "queue.lock"), () => {
    const existing = listQueue(l).items.find(
      (i) =>
        i.status === "pending" &&
        i.sessionId === item.sessionId &&
        i.actionHash === item.actionHash &&
        i.cwd === item.cwd &&
        (i.projectDir ?? "") === (item.projectDir ?? "") &&
        sameRules(shownRules(i), item.rules),
    );
    if (existing !== undefined) return existing;
    const cut: string[] = [];
    const { truncated: _ignored, ...given } = item;
    const full: QueueItem = { version: 1, id: newQueueId(), createdAt: new Date().toISOString(), status: "pending", ...given, input: maskValue(item.input, 0, cut) };
    if (full.proposal !== undefined) {
      const pr = full.proposal;
      full.proposal = { target: pr.target, change: maskValue(pr.change, 0, cut) as string };
      if (pr.edits !== undefined) {
        full.proposal.edits = pr.edits.slice(0, MAX_ENTRIES).map((e) => ({ old: maskValue(e.old, 0, cut) as string, new: maskValue(e.new, 0, cut) as string, ...(e.all === true ? { all: true } : {}) }));
        if (pr.edits.length > MAX_ENTRIES) cut.push(`${pr.edits.length - MAX_ENTRIES} more edits not shown`);
      }
      if (pr.content !== undefined) full.proposal.content = maskValue(pr.content, 0, cut) as string;
    }
    if (full.parts !== undefined) {
      const n = full.parts.length;
      full.parts = full.parts.slice(0, MAX_ENTRIES).map((x) => ({ ...x, target: maskValue(x.target, 0, cut) as string, change: maskValue(x.change, 0, cut) as string }));
      if (n > MAX_ENTRIES) cut.push(`${n - MAX_ENTRIES} more parts not shown (${n} in all)`);
    }
    if (cut.length > 0) full.truncated = cut;
    atomicWrite(itemPath(l, full.id), JSON.stringify(full, null, 2));
    return full;
  });
}

/** The rule ids an item shows (an item read from disk may lack the list: then none, so any rule asking later refuses the approval). */
function shownRules(it: QueueItem): string[] {
  const r: unknown = it.rules;
  return Array.isArray(r) ? r.filter((x): x is string => typeof x === "string").slice(0, 64) : [];
}

/** What an approval signs about an item: the action, the rules shown, and where the agent was. */
export interface ShownBinding {
  actionHash: string;
  rules: string[];
  cwd: string;
  projectDir: string;
}

/** The binding an item has right now (what a screen shows is captured with this, then checked when signing). */
export function shownBinding(it: QueueItem): ShownBinding {
  return { actionHash: it.actionHash, rules: shownRules(it), cwd: typeof it.cwd === "string" ? it.cwd : "", projectDir: typeof it.projectDir === "string" ? it.projectDir : "" };
}

/**
 * A person's decision on a queued item. Approval lets that exact action run once in its session, and
 * needs a signer: a function holding the unlocked approver key (see approver.ts). `shown` is what the
 * person was shown: if the item on disk changed since (between the screen and the passphrase), the
 * approval is refused rather than signing something else.
 */
export function decideQueueItem(l: Layout, id: string, status: "approved" | "rejected", signer?: (g: ApprovalGrant) => string, o: { now?: number; ttlMs?: number; shown?: ShownBinding } = {}): QueueItem {
  return withLock(join(l.locks, "queue.lock"), () => {
    const it = itemForDecision(l, id);
    if (it.status !== "pending") throw new Error(`queue item ${id} is already ${it.status}`);
    if (status === "approved" && signer === undefined) throw new Error("approving needs the approval passphrase");
    if (status === "approved" && o.shown !== undefined && JSON.stringify(shownBinding(it)) !== JSON.stringify(o.shown)) throw new Error(`queue item ${id} changed after it was shown; look at it again before approving`);
    const done: QueueItem = { ...it, status, decidedAt: new Date().toISOString() };
    if (status === "approved" && signer !== undefined) {
      // B1/I2: single-use (nonce), lapsing (exp), and bound to the rules shown and where the agent was.
      const g: ApprovalGrant = { sessionId: it.sessionId, actionHash: it.actionHash, id: it.id, nonce: approvalNonce(), exp: new Date((o.now ?? Date.now()) + (o.ttlMs ?? APPROVAL_TTL_MS)).toISOString(), rules: shownRules(it), cwd: typeof it.cwd === "string" ? it.cwd : "", projectDir: typeof it.projectDir === "string" ? it.projectDir : "" };
      appendEvents(l, it.sessionId, [{ type: "approval", actionHash: g.actionHash, id: g.id, sig: signer(g), nonce: g.nonce, exp: g.exp, rules: [...g.rules], cwd: g.cwd, projectDir: g.projectDir }]);
    }
    atomicWrite(itemPath(l, id), JSON.stringify(done, null, 2));
    return done;
  });
}

/**
 * Item P: a decision made on a paired phone. The passkey assertion is the signature, so no passphrase
 * signer is needed. `check` runs under the queue lock with the current item and throws to refuse (the
 * item no longer pending, the nonce used, the item expired): the first decision under the lock wins.
 * `event` (a phone_approval) is appended to the session before the item is marked approved.
 */
export function decideQueueItemByPhone(l: Layout, id: string, status: "approved" | "rejected", o: { decidedBy: string; check: (it: QueueItem) => void; event?: StateEvent; after?: () => void }): QueueItem {
  return withLock(join(l.locks, "queue.lock"), () => {
    const it = itemForDecision(l, id);
    if (it.status !== "pending") throw new Error(`queue item ${id} is already ${it.status}`);
    o.check(it);
    if (status === "approved" && o.event === undefined) throw new Error("a phone approval needs its signed event");
    const done: QueueItem = { ...it, status, decidedAt: new Date().toISOString(), decidedBy: o.decidedBy };
    if (status === "approved" && o.event !== undefined) appendEvents(l, it.sessionId, [o.event]);
    atomicWrite(itemPath(l, id), JSON.stringify(done, null, 2));
    o.after?.();
    return done;
  });
}

/** Removes decided items older than `days`. */
export function pruneQueue(l: Layout, days = 30, now = Date.now()): number {
  let n = 0;
  for (const it of listQueue(l).items) {
    if (it.status !== "pending" && now - Date.parse(it.decidedAt ?? it.createdAt) > days * 86400000) {
      try {
        unlinkSync(itemPath(l, it.id));
        n++;
      } catch {
        // Already gone.
      }
    }
  }
  return n;
}

export { layout };

// --- session overview (for `status`) ----------------------------------------------------------------

export interface SessionSummary {
  id: string;
  lastActivity: Date;
  trusted: boolean;
  /** When the session first read outside content (null for older files without timestamps). */
  untrustedSince: Date | null;
  /** What made it untrusted, first one. */
  firstSource: string | null;
  sensitive: boolean;
  /** Why nobody could answer prompts in this session (claude -p, dontAsk, hours...), if so. */
  unattended: string | null;
  /** The session touched a decoy file or saw its value. */
  canary?: boolean;
}

/** Records that a session ran without a person to answer prompts (shown by `status`). */
export function noteUnattended(l: Layout, sessionId: string, reason: string): void {
  const p = join(l.sessions, `${safeId(sessionId)}.mode.json`);
  // An unreadable path (FZ7) is left alone: it cannot be written either, and this is a display note only.
  if (tryReadText(p) === null) atomicWrite(p, JSON.stringify({ unattended: reason }));
}

function unattendedOf(l: Layout, id: string): string | null {
  try {
    const t = readText(join(l.sessions, `${id}.mode.json`));
    return t === null ? null : ((JSON.parse(t) as { unattended?: string }).unattended ?? null);
  } catch {
    return null;
  }
}

/** The most recently active sessions, newest first. */
export function recentSessions(l: Layout, limit = 5, now = Date.now(), maxAgeDays = 7): SessionSummary[] {
  let names: string[] = [];
  try {
    names = readdirSync(l.sessions).filter((n) => n.endsWith(".jsonl"));
  } catch {
    return [];
  }
  const withTime = names
    .map((n) => {
      try {
        return { n, m: statSync(join(l.sessions, n)).mtimeMs };
      } catch {
        return null;
      }
    })
    .filter((x): x is { n: string; m: number } => x !== null && now - x.m <= maxAgeDays * 86400000)
    .sort((a, b) => b.m - a.m)
    .slice(0, limit);
  return withTime.map(({ n, m }) => {
    const id = n.replace(/\.jsonl$/, "");
    let untrustedSince: Date | null = null;
    let firstSource: string | null = null;
    const text = tryReadText(join(l.sessions, n));
    if (text !== null && typeof text !== "string") firstSource = `unreadable state (the session file cannot be read: ${text.unreadable})`;
    for (const line of (typeof text === "string" ? text : "").split("\n")) {
      if (line.trim() === "") continue;
      try {
        const o = JSON.parse(line) as { type?: string; source?: string; ts?: string; detail?: string };
        if (o.type === "taint" || o.type === "corrupt") {
          firstSource = o.type === "taint" ? (o.source ?? null) : `unreadable state (${o.detail ?? ""})`;
          untrustedSince = typeof o.ts === "string" ? new Date(o.ts) : null;
          break;
        }
      } catch {
        firstSource = "unreadable state";
        break;
      }
    }
    const st = loadState(l, id);
    return { id, lastActivity: new Date(m), trusted: !st.tainted, untrustedSince, firstSource: st.tainted ? (firstSource ?? st.taintSources[0] ?? null) : null, sensitive: st.sensitive, unattended: unattendedOf(l, id), canary: st.canaryTripped.size + st.canarySeen.size > 0 };
  });
}
