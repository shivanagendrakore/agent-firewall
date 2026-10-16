/**
 * Checks 1 to 4 of a phone decision (docs/phone.md, "Decision and
 * verification"), shared by the daemon (a pre-check before anything is
 * written) and the hook's loadState() (the authoritative re-check of every
 * stored phone_approval):
 *
 * 1. keys/phones.json hashes to the pin in the hook command, and the
 *    credential is in it;
 * 2. clientDataJSON: type webauthn.get, challenge = SHA-256(M), the pinned
 *    origin, not cross-origin;
 * 3. authenticator data: the pinned RP ID's hash, UP and UV set;
 * 4. the signature with the pinned COSE key.
 *
 * Pure apart from reading keys/phones.json. No queue access (store.ts calls
 * this, so this must not call store.ts).
 */

import type { Layout } from "../layout.js";
import { pinnedPhones, type PairedPhone } from "./phones.js";
import { decisionChallenge, parseDecisionMessage, RelayProtocolError, type DecisionMessage } from "./protocol.js";
import { unb64u } from "./util.js";
import { verifyAssertion, WebAuthnError } from "./webauthn.js";

export interface SignedDecision {
  credentialId: string;
  m: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
}

export type Refusal = { ok: false; check: number; step: string; reason: string };
export type Verified = { ok: true; phone: PairedPhone; message: DecisionMessage; signCount: number };

export function refuse(check: number, step: string, reason: string): Refusal {
  return { ok: false, check, step, reason };
}

/** Checks 1 to 4. `pin` is the hook command's LAUNCHSAFE_FIREWALL_PHONES. */
export function verifySignedDecision(l: Layout, pin: string | null, d: SignedDecision): Verified | Refusal {
  const pinned = pinnedPhones(l, pin);
  if (!pinned.ok) return refuse(1, "pin", pinned.reason);
  const phone = pinned.file.phones.find((p) => p.credentialId === d.credentialId);
  if (phone === undefined) return refuse(1, "credential", "the decision is signed by a credential that is not paired");
  let message: DecisionMessage;
  try {
    message = parseDecisionMessage(d.m);
  } catch (e) {
    return refuse(2, "message", (e as RelayProtocolError).message);
  }
  try {
    const r = verifyAssertion({
      publicKey: unb64u(phone.publicKey),
      authenticatorData: unb64u(d.authenticatorData, "authenticatorData"),
      clientDataJSON: unb64u(d.clientDataJSON, "clientDataJSON"),
      signature: unb64u(d.signature, "signature"),
      challenge: decisionChallenge(d.m),
      origin: phone.origin,
      rpId: phone.rpId,
      // phone.requireUserVerification cannot be turned off in this version.
      requireUV: true,
    });
    return { ok: true, phone, message, signCount: r.signCount };
  } catch (e) {
    if (e instanceof WebAuthnError) {
      const check = e.check === "clientData" || e.check === "challenge" || e.check === "origin" ? 2 : e.check === "rpIdHash" || e.check === "flags" || e.check === "authData" ? 3 : 4;
      return refuse(check, e.check, e.message);
    }
    return refuse(2, "encoding", (e as Error).message);
  }
}

/** Check 5: a counter above 0 must grow. 0 then 0 is a synced passkey (no counter). */
export function counterOk(stored: number, received: number): boolean {
  if (stored === 0 && received === 0) return true;
  return received > stored;
}
