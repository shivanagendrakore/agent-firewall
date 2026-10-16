/**
 * The hook's side of phone approvals: what loadState() needs to decide
 * whether a stored phone_approval counts. The hook re-verifies every event
 * from the assertion it carries (checks 1 to 4 in verify.ts), checks that the
 * signed message names exactly this approval (approve, the event's action
 * hash and item id, this session's tag, a device id this machine holds or
 * held before a registration reset), that the
 * signature counters of one credential grow across the session's events,
 * and that the approval has not lapsed. No network, no queue: only the pin
 * from the hook command and two small files.
 *
 * Outcomes: "ok" (folds into the session's approvals), "expired" or
 * "disabled" (ignored: expiry is normal), or corrupt (the session becomes
 * untrusted, exactly as for a forged passphrase approval).
 */

import { phonePolicy } from "../../policy-phone.js";
import type { FirewallConfig, StateEvent } from "../../types.js";
import type { Layout } from "../layout.js";
import { deviceIdHistoryOf } from "./keys.js";
import { sessionTag, minutes } from "./util.js";
import { counterOk, verifySignedDecision } from "./verify.js";

export interface PhoneTrust {
  /** LAUNCHSAFE_FIREWALL_PHONES from the hook command, or null. */
  pin: string | null;
  enabled: boolean;
  useWithinMinutes: number;
  clockSkewMinutes: number;
  now: Date;
}

/** The phone trust a hook decision uses: the pin from its own command and the policy's windows. */
export function phoneTrust(env: NodeJS.ProcessEnv, cfg?: Pick<FirewallConfig, "phone">, now: Date = new Date()): PhoneTrust {
  const p = phonePolicy(cfg ?? {});
  const pin = env.LAUNCHSAFE_FIREWALL_PHONES;
  return { pin: pin !== undefined && pin !== "" ? pin : null, enabled: p.enabled, useWithinMinutes: p.useWithinMinutes, clockSkewMinutes: p.clockSkewMinutes, now };
}

type PhoneApproval = Extract<StateEvent, { type: "phone_approval" }>;

export type PhoneCheck = { result: "ok" } | { result: "expired" } | { result: "disabled" } | { result: "corrupt"; detail: string };

/**
 * Checks one stored phone_approval. `counters` carries the last counter per credential seen earlier in the
 * same session file (updated here), so a replayed older assertion after a newer one is refused.
 */
export function checkPhoneApproval(l: Layout, sessionId: string, e: PhoneApproval, t: PhoneTrust, counters: Map<string, number>, seen: Set<string> = new Set()): PhoneCheck {
  const corrupt = (why: string): PhoneCheck => ({ result: "corrupt", detail: `phone approval ${e.id} ${why}` });
  const v = verifySignedDecision(l, t.pin, { credentialId: e.credentialId, m: e.m, authenticatorData: e.authData, clientDataJSON: e.clientData, signature: e.sig });
  if (!v.ok) return corrupt(`does not verify (check ${v.check}: ${v.reason})`);
  const m = v.message;
  if (m.decision !== "approve") return corrupt("is a signed rejection, not an approval");
  if (m.actionHash !== e.actionHash || m.itemId !== e.id) return corrupt("was signed for another action or queue item");
  if (m.sessionTag !== sessionTag(sessionId)) return corrupt("was signed for another session");
  // V38: an approval already stored here was verified by the daemon under the device id of the time; a later
  // registration reset (a relay 401) keeps that id in the device record's history, so it stays this machine's.
  // New decisions are still checked against the current id only (decision.ts).
  if (!deviceIdHistoryOf(l).includes(m.deviceId)) return corrupt("was signed for another machine");
  // B1: a synced passkey signs with counter 0 every time, so the counter cannot catch a copied assertion; the
  // signed message's nonce can. One (credential, nonce) approves once per session file, whatever its counter.
  const once = JSON.stringify([e.credentialId, m.nonce]);
  if (seen.has(once)) return corrupt("repeats an assertion already in this session (a copied phone approval)");
  seen.add(once);
  const prior = counters.get(e.credentialId) ?? 0;
  if (!counterOk(prior, v.signCount) && !(prior === 0 && v.signCount === 0)) return corrupt("repeats an older signature counter");
  counters.set(e.credentialId, Math.max(prior, v.signCount));
  if (!t.enabled) return { result: "disabled" };
  const issued = Date.parse(m.issuedAt);
  const exp = Date.parse(e.exp);
  if (!Number.isFinite(issued) || !Number.isFinite(exp)) return corrupt("has an unreadable time");
  // The event's exp is not signed: it can never extend past what the signed issuedAt and the policy allow.
  const lapses = Math.min(exp, issued + minutes(t.useWithinMinutes + t.clockSkewMinutes));
  return t.now.getTime() > lapses ? { result: "expired" } : { result: "ok" };
}
