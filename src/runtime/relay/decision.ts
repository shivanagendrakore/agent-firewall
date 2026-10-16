/**
 * The daemon's handling of one signed decision from the relay (docs/phone.md,
 * "Decision and verification"). All seven checks must pass, in order:
 * 1-4 in verify.ts (pin, client data, authenticator data, signature), then
 *
 * 5. the signature counter grows (0 and 0: a synced passkey, no counter);
 * 6. M names this device, a pending queue item with that action hash and
 *    session, its displayHash and its unused nonce, and the relay's item
 *    reference belongs to that same item;
 * 7. the firewall's clock is before the item's expiresAt, and M.issuedAt is
 *    within the clock skew of the firewall's clock.
 *
 * Before 6, the item must still be phone-decidable under the policy in effect
 * now (V21): phone.enabled, phone.approvable and phone.excludeRules of its
 * project, and its expiry under the current phone.itemTtlMinutes (never later
 * than the expiresAt it was sealed with).
 *
 * Checks 6 and 7 run again under the queue lock, where the decision is
 * applied: an approval appends a phone_approval event (which the hook
 * re-verifies), marks the nonce used and the item approved by the phone. A
 * rejection marks the item rejected. Anything that fails is dropped, logged
 * with the failing check, and the phone is told why through a withdraw.
 */

import { phonePolicy, type PhonePolicy } from "../../policy-phone.js";
import type { FirewallConfig, StateEvent } from "../../types.js";
import { loadPolicy } from "../config.js";
import { appendLog } from "../log.js";
import type { Layout } from "../layout.js";
import { decideQueueItemByPhone, getQueueItem, type QueueItem } from "../store.js";
import { markNonceUsed, nonceUsed, outboxByRef, readOutbox, storeCounter, storedCounter, type OutboxRecord } from "./files.js";
import { deviceIdOf } from "./keys.js";
import type { RelayDecision, WithdrawReason } from "./protocol.js";
import { minutes, sessionTag } from "./util.js";
import { counterOk, refuse, verifySignedDecision, type Refusal } from "./verify.js";

export interface DecisionOutcome {
  applied: "approved" | "rejected" | null;
  /** The failed check, when refused. */
  refusal?: Refusal;
  itemId?: string;
  /** What the relay should be told for this item reference (null: nothing). */
  withdraw: WithdrawReason | null;
}

class Refused extends Error {
  constructor(readonly r: Refusal) {
    super(r.reason);
  }
}

/**
 * V21: whether a queue item may be decided on a phone under the policy in effect now (its project's). The
 * daemon seals only such items, withdraws any that stop being so, and a decision for one is refused: a
 * policy tightened after the item was sent (phone.approvable, phone.excludeRules) reaches it.
 */
export function phoneSendable(pol: PhonePolicy, it: Pick<QueueItem, "kind" | "rules">): boolean {
  return pol.enabled && it.kind === "approval" && pol.approvable.includes("approval") && !it.rules.some((r) => pol.excludeRules.includes(r));
}

/** V21: when the item expires on the phone under the policy in effect now: never later than when it was sealed. */
export function phoneExpiry(pol: PhonePolicy, it: Pick<QueueItem, "createdAt">, rec: Pick<OutboxRecord, "expiresAt">): number {
  const sealed = Date.parse(rec.expiresAt);
  const now = Date.parse(it.createdAt) + minutes(pol.itemTtlMinutes);
  // An unreadable time is already expired.
  if (!Number.isFinite(sealed) || !Number.isFinite(now)) return -Infinity;
  return Math.min(sealed, now);
}

/** The policy check, 6 (item binding) and 7 (freshness) against the item and its outbox record. Throws Refused. */
function checkItem(l: Layout, it: QueueItem, rec: OutboxRecord, m: ReturnType<typeof verifySignedDecision> & { ok: true }, now: Date, pol: PhonePolicy): void {
  const msg = m.message;
  if (!phoneSendable(pol, it)) throw new Refused(refuse(0, "policy", `queue item ${it.id} may no longer be decided on a phone under the current policy (phone.approvable or phone.excludeRules); decide it in the terminal`));
  if (nonceUsed(l, msg.nonce)) throw new Refused(refuse(6, "replay", "nonce already used"));
  if (it.status !== "pending") throw new Refused(refuse(6, "decided", `queue item ${it.id} is already ${it.status}`));
  if (msg.actionHash !== it.actionHash || msg.sessionTag !== sessionTag(it.sessionId)) throw new Refused(refuse(6, "binding", "the decision names another action or session than the queue item"));
  if (msg.displayHash !== rec.displayHash) throw new Refused(refuse(6, "display", "the decision was made on a different screen than the one sent for this item"));
  if (msg.nonce !== rec.nonce) throw new Refused(refuse(6, "nonce", "the decision's nonce is not this item's"));
  const exp = phoneExpiry(pol, it, rec);
  if (!(now.getTime() <= exp)) throw new Refused(refuse(7, "expired", `the item expired at ${Number.isFinite(exp) ? new Date(exp).toISOString() : rec.expiresAt}`));
  const skewMin = pol.clockSkewMinutes;
  const issued = Date.parse(msg.issuedAt);
  if (!Number.isFinite(issued) || Math.abs(now.getTime() - issued) > minutes(skewMin)) throw new Refused(refuse(7, "clock", `the phone's time (${msg.issuedAt}) is more than ${skewMin} minutes from this machine's`));
}

function withdrawFor(r: Refusal): WithdrawReason | null {
  if (r.step === "decided" || r.step === "replay") return "already_decided";
  if (r.step === "expired") return "expired";
  // No longer phone-decidable under the current policy: the phones stop showing it; the terminal decides.
  if (r.step === "policy") return "refused";
  // A forged or mismatched decision says nothing about the item: leave it on the phone.
  return null;
}

/** Verifies and applies one decision. Never throws for a bad decision: it is refused and logged. */
/**
 * The policy a phone decision on `it` is judged under: the project's (where the hook judged the call), or null,
 * which means no phone decision: an item without its project directory (older items), a policy file that does not
 * parse (loadPolicy returns defaults plus an error, which must not loosen anything), or an unreadable one.
 */
export function phoneConfigFor(l: Layout, it: QueueItem): Pick<FirewallConfig, "phone"> | null {
  if (it.projectDir === undefined || it.projectDir === "") return null;
  try {
    const p = loadPolicy(l, [it.projectDir]);
    return p.error === undefined ? p.config : null;
  } catch {
    return null;
  }
}

export function handleDecision(l: Layout, d: RelayDecision, o: { pin: string | null; cfg: Pick<FirewallConfig, "phone">; cfgFor?: (it: QueueItem) => Pick<FirewallConfig, "phone"> | null; now?: Date }): DecisionOutcome {
  const now = o.now ?? new Date();
  let pol = phonePolicy(o.cfg);
  const fail = (r: Refusal, itemId?: string): DecisionOutcome => {
    const out: DecisionOutcome = { applied: null, refusal: r, withdraw: withdrawFor(r), ...(itemId !== undefined ? { itemId } : {}) };
    try {
      appendLog(l, { type: "phone_decision_refused", check: r.check, step: r.step, reason: r.reason, ...(itemId !== undefined ? { queue: itemId } : {}), credential: d.credentialId.slice(0, 16) });
    } catch {
      // The log is best effort here; the decision is refused either way.
    }
    return out;
  };
  if (!pol.enabled) return fail(refuse(0, "disabled", "phone approvals are switched off in the policy"));
  const v = verifySignedDecision(l, o.pin, d);
  if (!v.ok) return fail(v);
  const msg = v.message;
  // Check 5: counters (stored per credential; synced passkeys report 0 every time).
  const stored = storedCounter(l, d.credentialId);
  if (!counterOk(stored, v.signCount)) return fail(refuse(5, "counter", `the signature counter did not grow (${v.signCount} after ${stored}): a cloned authenticator?`), msg.itemId);
  // Check 6, the parts that need no lock.
  const device = deviceIdOf(l);
  if (device === null || msg.deviceId !== device) return fail(refuse(6, "device", "the decision was made for another machine"), msg.itemId);
  const byRef = outboxByRef(l, d.itemRef);
  const rec = readOutbox(l, msg.itemId);
  if (rec === null) return fail(refuse(6, "item", `no item ${msg.itemId} was sent from this machine`), msg.itemId);
  if (byRef === null || byRef.record.itemId !== msg.itemId || byRef.credentialId !== d.credentialId) return fail(refuse(6, "reference", "the relay delivered the decision under another item's reference"), msg.itemId);
  const it = getQueueItem(l, msg.itemId);
  if (it === null) return fail(refuse(6, "item", `queue item ${msg.itemId} no longer exists`), msg.itemId);
  // The item's project may only have tightened the windows (or switched phone approvals off).
  if (o.cfgFor !== undefined) {
    // PH1/PH2: the project's policy (under the directory the hook judged the call), or no phone decision when it
    // cannot be read or the item does not say where it was judged: the item stays pending for the terminal.
    const cfg = o.cfgFor(it);
    if (cfg === null) return fail(refuse(0, "policy", "the policy for this item's project cannot be read (or the item does not record its project), so a phone may not decide it"), msg.itemId);
    pol = phonePolicy(cfg);
  }
  if (!pol.enabled) return fail(refuse(0, "disabled", "phone approvals are switched off for this project"), msg.itemId);
  try {
    checkItem(l, it, rec, v, now, pol);
  } catch (e) {
    if (e instanceof Refused) return fail(e.r, msg.itemId);
    throw e;
  }
  const label = `phone: ${v.phone.label}`;
  const status = msg.decision === "approve" ? "approved" : "rejected";
  const event: StateEvent | undefined =
    status === "approved"
      ? { type: "phone_approval", actionHash: it.actionHash, id: it.id, credentialId: d.credentialId, m: d.m, authData: d.authenticatorData, clientData: d.clientDataJSON, sig: d.signature, exp: new Date(now.getTime() + minutes(pol.useWithinMinutes)).toISOString() }
      : undefined;
  let counterNow = stored;
  try {
    decideQueueItemByPhone(l, it.id, status, {
      decidedBy: label,
      ...(event !== undefined ? { event } : {}),
      // Under the queue lock: the first decision wins, and the nonce is checked and spent atomically.
      check: (cur) => {
        checkItem(l, cur, rec, v, now, pol);
        // M8: check 5 again under the lock, so two decisions from one credential racing through the daemon
        // cannot both pass against the same stored counter.
        counterNow = storedCounter(l, d.credentialId);
        if (!counterOk(counterNow, v.signCount)) throw new Refused(refuse(5, "counter", `the signature counter did not grow (${v.signCount} after ${counterNow}): a cloned authenticator?`));
        // M8: logged before it is applied: a decision the log cannot record is not applied (appendLog throws).
        appendLog(l, { type: status === "approved" ? "approval" : "rejection", queue: cur.id, session: cur.sessionId, action: cur.actionHash, via: "phone", phone: v.phone.label, credential: d.credentialId.slice(0, 16) });
      },
      after: () => {
        markNonceUsed(l, msg.nonce, now);
        storeCounter(l, d.credentialId, Math.max(counterNow, v.signCount));
      },
    });
  } catch (e) {
    if (e instanceof Refused) return fail(e.r, msg.itemId);
    return fail(refuse(6, "decided", (e as Error).message), msg.itemId);
  }
  return { applied: status, itemId: it.id, withdraw: status === "approved" ? "approved" : "rejected" };
}
