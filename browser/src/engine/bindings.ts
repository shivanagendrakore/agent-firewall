/**
 * Approval bindings (design 5.3, 9; threat model 5 "Approval replay").
 *
 * A gated action becomes a pending approval bound to its tab, frame, element
 * and action fingerprint. When a person approves it in extension UI, the
 * ledger issues a random one-shot token. The content script replays the
 * action itself and presents the token with a fresh snapshot of the action;
 * the ledger redeems the token only if:
 *
 * - the token is known, approved, not yet used and not expired;
 * - the tab, the frame and the element are the ones approved;
 * - the fingerprint (field names, value digest, target, method, class) is unchanged.
 *
 * Any failed redeem of a known token burns it: an approval is a single attempt,
 * so an agent cannot probe for a variant that passes. Pending approvals expire
 * after 5 minutes or when their tab or frame navigates.
 *
 * Pure: the clock and the token source are injected. The ledger serializes to
 * plain JSON for chrome.storage.session (the worker may be restarted).
 */
import { actionFingerprint, storedFieldNames, type ActionSnapshot } from "./fingerprint.js";
import type { AgentModeOffProof } from "./session.js";

export const APPROVAL_TTL_MS = 5 * 60 * 1000;

/** What an approval is for: an in-page action, or turning agent mode off (design 8). */
export type ApprovalPurpose = "action" | "agent_mode_off";

export type ApprovalState = "pending" | "approved" | "denied" | "consumed" | "expired" | "burned";

export interface ApprovalRecord {
  id: string;
  purpose: ApprovalPurpose;
  state: ApprovalState;
  snapshot: ActionSnapshot;
  fingerprint: string;
  createdAt: number;
  expiresAt: number;
  /** Set on approve; the content script receives it once. */
  token?: string;
}

export type RedeemRefusal = "unknown_token" | "not_approved" | "used" | "expired" | "wrong_purpose" | "tab_mismatch" | "frame_mismatch" | "element_mismatch" | "changed";

export type RedeemResult = { ok: true; record: ApprovalRecord } | { ok: false; reason: RedeemRefusal };

export interface LedgerOptions {
  now: () => number;
  /** A fresh random string per call (crypto.getRandomValues in the extension). At least 128 bits. */
  randomId: () => string;
  ttlMs?: number;
}

export interface LedgerJson {
  records: ApprovalRecord[];
}

const TERMINAL: readonly ApprovalState[] = ["denied", "consumed", "expired", "burned"];

export class ApprovalLedger {
  private readonly records = new Map<string, ApprovalRecord>();
  private readonly byToken = new Map<string, string>();
  private readonly now: () => number;
  private readonly randomId: () => string;
  private readonly ttlMs: number;

  constructor(opts: LedgerOptions, json?: LedgerJson) {
    this.now = opts.now;
    this.randomId = opts.randomId;
    this.ttlMs = opts.ttlMs ?? APPROVAL_TTL_MS;
    for (const r of json?.records ?? []) {
      this.records.set(r.id, { ...r, snapshot: { ...r.snapshot, fieldNames: storedFieldNames(r.snapshot.fieldNames) } });
      if (r.token !== undefined && r.state === "approved") this.byToken.set(r.token, r.id);
    }
  }

  toJSON(): LedgerJson {
    return { records: [...this.records.values()].map((r) => ({ ...r })) };
  }

  /** A new pending approval for this snapshot. */
  request(snapshot: ActionSnapshot, purpose: ApprovalPurpose = "action"): ApprovalRecord {
    const t = this.now();
    const rec: ApprovalRecord = { id: this.randomId(), purpose, state: "pending", snapshot: { ...snapshot, fieldNames: storedFieldNames(snapshot.fieldNames) }, fingerprint: actionFingerprint(snapshot), createdAt: t, expiresAt: t + this.ttlMs };
    this.records.set(rec.id, rec);
    return { ...rec };
  }

  get(id: string): ApprovalRecord | undefined {
    const r = this.records.get(id);
    if (r === undefined) return undefined;
    this.expireIfDue(r);
    return { ...r };
  }

  /** Pending approvals, oldest first (for the side panel). */
  pending(): ApprovalRecord[] {
    const out: ApprovalRecord[] = [];
    for (const r of this.records.values()) {
      this.expireIfDue(r);
      if (r.state === "pending") out.push({ ...r });
    }
    return out.sort((a, b) => a.createdAt - b.createdAt);
  }

  /** A person approved: returns the one-shot token, or null if the approval is no longer pending. */
  approve(id: string): string | null {
    const r = this.records.get(id);
    if (r === undefined) return null;
    this.expireIfDue(r);
    if (r.state !== "pending") return null;
    const token = this.randomId();
    r.state = "approved";
    r.token = token;
    this.byToken.set(token, id);
    return token;
  }

  /** Retires a pending or approved-but-unused approval as expired (a queue bound, its tab gone). */
  expire(id: string): boolean {
    const r = this.records.get(id);
    if (r === undefined || (r.state !== "pending" && r.state !== "approved")) return false;
    this.retire(r, "expired");
    return true;
  }

  /**
   * Puts an approved approval whose token was never redeemed back to pending, and forgets the token: the
   * approval could not be carried out (a navigation whose tab no longer shows the explanation page), so it is
   * not spent and the person can decide again (RR7).
   */
  unapprove(id: string): boolean {
    const r = this.records.get(id);
    if (r === undefined) return false;
    this.expireIfDue(r);
    if (r.state !== "approved") return false;
    if (r.token !== undefined) this.byToken.delete(r.token);
    delete r.token;
    r.state = "pending";
    return true;
  }

  deny(id: string): boolean {
    const r = this.records.get(id);
    if (r === undefined || TERMINAL.includes(r.state)) return false;
    this.retire(r, "denied");
    return true;
  }

  /** The content script's replay: redeem the token for the action as it is now. */
  redeem(token: string, presented: ActionSnapshot, purpose: ApprovalPurpose = "action"): RedeemResult {
    const id = this.byToken.get(token);
    const r = id === undefined ? undefined : this.records.get(id);
    if (r === undefined) {
      // A token that was used, burned or denied is no longer indexed; say "used" when we can tell.
      const spent = [...this.records.values()].some((x) => x.token === token);
      return { ok: false, reason: spent ? "used" : "unknown_token" };
    }
    this.expireIfDue(r);
    if (r.state === "expired") return { ok: false, reason: "expired" };
    if (r.state !== "approved") return { ok: false, reason: r.state === "pending" ? "not_approved" : "used" };
    const refuse = (reason: RedeemRefusal): RedeemResult => {
      this.retire(r, "burned");
      return { ok: false, reason };
    };
    if (r.purpose !== purpose) return refuse("wrong_purpose");
    if (presented.tabId !== r.snapshot.tabId) return refuse("tab_mismatch");
    if (presented.frameId !== r.snapshot.frameId || presented.frameOrigin !== r.snapshot.frameOrigin) return refuse("frame_mismatch");
    if (presented.elementPath !== r.snapshot.elementPath) return refuse("element_mismatch");
    if (actionFingerprint(presented) !== r.fingerprint) return refuse("changed");
    this.retire(r, "consumed");
    const ok: RedeemResult = { ok: true, record: { ...r } };
    redeemedResults.add(ok);
    return ok;
  }

  /** The tab navigated or closed: its pending and approved-but-unused approvals expire. */
  expireTab(tabId: number): number {
    return this.expireWhere((r) => r.snapshot.tabId === tabId);
  }

  /** A frame navigated: its approvals expire. */
  expireFrame(tabId: number, frameId: number): number {
    return this.expireWhere((r) => r.snapshot.tabId === tabId && r.snapshot.frameId === frameId);
  }

  /**
   * Frees space for the stored ledger: drops the oldest record that is not an agent-mode-off approval (spent ones
   * first, then the oldest live one). Returns the live approval it dropped, or null when it dropped a spent one;
   * undefined when nothing may be dropped.
   */
  shedOldest(): ApprovalRecord | null | undefined {
    const pool = [...this.records.values()].filter((r) => r.purpose !== "agent_mode_off").sort((a, b) => a.createdAt - b.createdAt);
    const victim = pool.find((r) => TERMINAL.includes(r.state)) ?? pool[0];
    if (victim === undefined) return undefined;
    const live = victim.state === "pending" || victim.state === "approved";
    if (victim.token !== undefined) this.byToken.delete(victim.token);
    this.records.delete(victim.id);
    return live ? { ...victim } : null;
  }

  /** Drops terminal records older than `olderThanMs` (the log keeps the history, not the ledger). */
  prune(olderThanMs: number = this.ttlMs): void {
    const cutoff = this.now() - olderThanMs;
    for (const [id, r] of this.records) {
      this.expireIfDue(r);
      if (TERMINAL.includes(r.state) && r.expiresAt < cutoff) this.records.delete(id);
    }
  }

  private expireWhere(pred: (r: ApprovalRecord) => boolean): number {
    let n = 0;
    for (const r of this.records.values()) {
      if ((r.state === "pending" || r.state === "approved") && pred(r)) {
        this.retire(r, "expired");
        n++;
      }
    }
    return n;
  }

  private expireIfDue(r: ApprovalRecord): void {
    if ((r.state === "pending" || r.state === "approved") && this.now() >= r.expiresAt) this.retire(r, "expired");
  }

  private retire(r: ApprovalRecord, state: ApprovalState): void {
    r.state = state;
    if (r.token !== undefined) this.byToken.delete(r.token);
  }
}

/** The snapshot an agent-mode-off approval binds to: no tab, no frame, one fixed control in extension UI. */
export function agentModeOffSnapshot(): ActionSnapshot {
  return { tabId: -1, frameId: -1, frameOrigin: "extension", kind: "activate", actionClass: null, elementPath: "agent-mode-off", fieldNames: [], valuesDigest: "", targetOrigin: "", method: "" };
}

/**
 * Successful redeems this module produced, and the agent-mode-off proofs it minted from them. Module-private:
 * nothing outside this file can add to either, so a proof is checked by identity, not by shape (a message
 * body, stored JSON or any other structural copy is never a proof). Each is spent once.
 */
const redeemedResults = new WeakSet<object>();
const mintedProofs = new WeakSet<object>();

/** The proof session.endAgentSession needs, from a successful redeem of an agent-mode-off approval; null otherwise. */
export function agentModeOffProof(result: RedeemResult): AgentModeOffProof | null {
  if (!result.ok || result.record.purpose !== "agent_mode_off" || !redeemedResults.delete(result)) return null;
  const proof: AgentModeOffProof = Object.freeze({ ok: true, purpose: "agent_mode_off" });
  mintedProofs.add(proof);
  return proof;
}

/** Whether `proof` is one this module minted and nobody has spent yet; spends it. */
export function isAgentModeOffProof(proof: unknown): proof is AgentModeOffProof {
  return typeof proof === "object" && proof !== null && mintedProofs.delete(proof);
}
