/**
 * Pairing a phone (docs/phone.md, "Pairing"). Person-run only: the CLI has
 * already checked for a person at the keyboard and the approval passphrase.
 *
 * 1. The device key signs a pairing start; the relay returns a pairing id.
 * 2. The terminal shows a QR code with the pairing link, whose fragment
 *    carries the 32-byte secret S (never sent to any server), and the
 *    comparison code.
 * 3. The phone creates a NEW passkey just for approvals, an ECDH key, and
 *    MACs its answer with a key derived from S; the relay passes it back.
 * 4. The firewall checks the MAC (a relay that swapped in its own passkey
 *    cannot make it), the registration (origin, RP ID, UP and UV, a
 *    supported algorithm, the pairing's challenge), shows the label and the
 *    code, and the person types "yes".
 * 5. The relay confirms (device id and token), the phone is added to
 *    keys/phones.json, and the hook command is re-pinned.
 *
 * Nothing is written before step 5. Any failure leaves no trace but the
 * device's signing key.
 */

import { randomBytes } from "node:crypto";
import { safeLine } from "../../engine/terminal.js";
import { rpIdOf } from "../../policy-phone.js";
import type { Layout } from "../layout.js";
import type { RelayClient } from "./client.js";
import { readRelayState } from "./files.js";
import { deviceFingerprint, devicePublicDer, ensureDevice, resetRegistration, updateDevice } from "./keys.js";
import { loadPhones, writePhones, type PairedPhone } from "./phones.js";
import { comparisonCode, pairingLink, pairingMac, registrationChallenge, type PairingAnswer } from "./protocol.js";
import { encodeQr, renderQr } from "./qr.js";
import { p256FromRaw } from "./seal.js";
import { b64u, equalBytes, sha256, unb64u } from "./util.js";
import { verifyRegistration, WebAuthnError } from "./webauthn.js";

export interface PairDeps {
  l: Layout;
  client: RelayClient;
  /** The policy's phone.relayOrigin: the WebAuthn origin the passkey must be created on. */
  origin: string;
  machineLabel: string;
  out: (line: string) => void;
  /** Writes the QR code's lines as they are (they hold terminal colour codes the normal output escapes). */
  raw: (line: string) => void;
  ansi: boolean;
  /** Asks and returns whether the person typed "yes". */
  confirm: (question: string) => Promise<boolean>;
  sleep: (ms: number) => Promise<void>;
  now?: () => Date;
  pollMs?: number;
  /** How long to wait for the phone (the relay keeps a pairing 10 minutes). */
  timeoutMs?: number;
  random?: (n: number) => Buffer;
}

export type PairResult = { ok: true; phone: PairedPhone; deviceId: string; firstPairing: boolean } | { ok: false; reason: string };

/** A label from the phone (relay-carried, untrusted): one line, no control characters, at most 64 characters. */
export function cleanLabel(s: string): string {
  const one = safeLine(s).replace(/\\u[0-9a-f]{4}/g, "").trim();
  return (one === "" ? "phone" : one).slice(0, 64);
}

/** Checks the phone's answer against what only this terminal and the phone know. Throws with the reason. */
export function verifyAnswer(o: { answer: PairingAnswer; mac: string; secret: Uint8Array; pairingId: string; deviceSpki: Uint8Array; origin: string; existing: readonly PairedPhone[] }): Omit<PairedPhone, "label" | "pairedAt"> & { label: string } {
  const expect = pairingMac(o.secret, o.answer, o.pairingId, o.deviceSpki);
  if (!equalBytes(Buffer.from(expect), Buffer.from(o.mac))) throw new Error("the phone's answer does not carry a valid pairing code (MAC): it was not made by the phone that scanned this QR code, or the relay changed it");
  const rpId = rpIdOf(o.origin);
  let reg;
  try {
    reg = verifyRegistration({ attestationObject: unb64u(o.answer.attestationObject), clientDataJSON: unb64u(o.answer.clientDataJSON), challenge: registrationChallenge(o.pairingId, deviceFingerprint(o.deviceSpki)), origin: o.origin, rpId });
  } catch (e) {
    throw new Error(`the passkey registration does not verify (${e instanceof WebAuthnError ? `${e.check}: ` : ""}${(e as Error).message})`, { cause: e });
  }
  if (b64u(reg.credentialId) !== o.answer.credentialId) throw new Error("the answer's credential id is not the registered one");
  if (!equalBytes(reg.publicKey, unb64u(o.answer.publicKey))) throw new Error("the answer's public key is not the registered one");
  try {
    p256FromRaw(unb64u(o.answer.phoneEcdhPub));
  } catch {
    throw new Error("the phone's encryption key is not a P-256 public key");
  }
  if (o.existing.some((p) => p.credentialId === o.answer.credentialId)) throw new Error("this passkey is already paired");
  return { credentialId: o.answer.credentialId, publicKey: o.answer.publicKey, alg: reg.alg, rpId, origin: o.origin, ecdhPub: o.answer.phoneEcdhPub, label: cleanLabel(o.answer.label) };
}

export async function pairPhone(d: PairDeps): Promise<PairResult> {
  const now = d.now ?? (() => new Date());
  const random = d.random ?? randomBytes;
  const existing = loadPhones(d.l);
  if (existing.state === "corrupt") return { ok: false, reason: `${existing.error}; fix or remove it first ("launchsafe-firewall doctor")` };
  const phones = existing.state === "ok" ? existing.file.phones : [];
  const before = ensureDevice(d.l);
  // A different relay than the one this identity was registered with starts a fresh registration.
  if (before.relayOrigin !== undefined && before.relayOrigin !== d.origin) resetRegistration(d.l);
  // Unpaired in the app (the daemon saw a 401 for this device): the old registration is gone; the relay will
  // issue a new device id, accepted only because it starts from no id at all.
  else if (readRelayState(d.l).revoked !== undefined) resetRegistration(d.l);
  const device = updateDevice(d.l, { label: d.machineLabel, relayOrigin: d.origin });
  const spki = devicePublicDer(device);
  const secret = random(32);
  const start = await d.client.startPairing({ deviceSignPub: b64u(spki), secretHash: b64u(sha256(secret)), label: d.machineLabel });
  const fp = deviceFingerprint(spki);
  const link = pairingLink(d.origin, start.pairingId, secret, fp);
  const code = comparisonCode(secret, spki);
  d.out("Scan this with your phone's camera (it opens the LaunchSafe approval app):\n");
  for (const line of renderQr(encodeQr(link), { ansi: d.ansi })) d.raw(line);
  d.out(`\nOr open this link on your phone (keep it private: it pairs a phone with this machine):\n  ${link}\n\nComparison code: ${code}  (your phone shows the same code)\nWaiting for your phone (up to 10 minutes; Ctrl-C to stop)...`);
  const deadline = now().getTime() + (d.timeoutMs ?? 10 * 60_000);
  for (;;) {
    if (now().getTime() > deadline) return { ok: false, reason: "no phone answered within 10 minutes. Nothing was written." };
    const st = await d.client.pairingStatus(start.pairingId);
    if (st.status === "expired") return { ok: false, reason: "the pairing expired on the relay. Nothing was written." };
    if (st.status === "claimed") {
      let checked;
      try {
        checked = verifyAnswer({ answer: st.answer, mac: st.mac, secret, pairingId: start.pairingId, deviceSpki: spki, origin: d.origin, existing: phones });
      } catch (e) {
        return { ok: false, reason: `pairing refused: ${(e as Error).message}. Nothing was written.` };
      }
      if (!(await d.confirm(`\nPair the phone "${checked.label}"? Its screen must show the code ${code}. Type "yes": `))) return { ok: false, reason: "not confirmed. Nothing was written." };
      const conf = await d.client.confirmPairing(start.pairingId);
      if (device.deviceId !== undefined && conf.deviceId !== device.deviceId) return { ok: false, reason: "the relay answered with another device id than this machine's. Nothing was written." };
      if (device.token === undefined && conf.deviceToken === undefined) return { ok: false, reason: "the relay did not issue a device token. Nothing was written." };
      const firstPairing = device.deviceId === undefined;
      updateDevice(d.l, { deviceId: conf.deviceId, ...(conf.deviceToken !== undefined ? { token: conf.deviceToken } : {}) });
      const phone: PairedPhone = { ...checked, pairedAt: now().toISOString() };
      writePhones(d.l, [...phones, phone]);
      return { ok: true, phone, deviceId: conf.deviceId, firstPairing };
    }
    await d.sleep(d.pollMs ?? 2000);
  }
}
