/**
 * The relay contract, in one module (docs/phone.md, "Relay API"). Everything
 * the firewall and the LaunchSafe app's relay (and its phone web app) must
 * agree on lives here: endpoint paths, request and response shapes, how a
 * device signs a request, the pairing link, the pairing MAC and comparison
 * code, the registration challenge, the decision message the passkey signs,
 * and the sealed-item envelope. If the app's relay changes a path or a field,
 * this is the file to adjust.
 *
 * Every response is untrusted: the parsers below accept only the documented
 * shape (strings of bounded length, base64url where bytes are carried) and
 * throw RelayProtocolError otherwise. The relay is assumed hostile: nothing
 * it says can approve anything, it can only carry what the phone signed.
 */

import { createHmac, hkdfSync } from "node:crypto";
import { b64u, canonicalJson, sha256 } from "./util.js";
import { own } from "../../own.js";

export const API = {
  pairings: "/v1/firewall/pairings",
  pairing: (id: string): string => `/v1/firewall/pairings/${encodeURIComponent(id)}`,
  confirm: (id: string): string => `/v1/firewall/pairings/${encodeURIComponent(id)}/confirm`,
  items: "/v1/firewall/relay/items",
  withdraw: (ref: string): string => `/v1/firewall/relay/items/${encodeURIComponent(ref)}/withdraw`,
  decisions: (after: string | null, wait: number): string => `/v1/firewall/relay/decisions?wait=${wait}${after !== null ? `&after=${encodeURIComponent(after)}` : ""}`,
  summary: "/v1/firewall/relay/summary",
} as const;

export const HEADER_TS = "x-launchsafe-timestamp";
export const HEADER_SIG = "x-launchsafe-signature";

export class RelayProtocolError extends Error {}

/** An HTTP error from the relay, with its documented error code when it sent one. */
export class RelayHttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
  /** The device token was revoked (unpaired in the app) or never issued. */
  get revoked(): boolean {
    return this.status === 401 || this.code === "device_revoked";
  }
  /** A fair-use limit (500 items a day per device, 6 KB per sealed payload, 10 phones per person). */
  get fairUse(): boolean {
    return this.status === 429 || this.code === "fair_use";
  }
}

/**
 * What a device signs on every request: method, path with query, timestamp (ms) and the body's digest.
 * ECDSA P-256 / SHA-256, IEEE P1363, base64url, in the x-launchsafe-signature header, with the timestamp
 * in x-launchsafe-timestamp. The relay checks it against the key registered at pairing start.
 */
export function requestSigningString(method: string, pathWithQuery: string, ts: number, body: string): Buffer {
  return Buffer.from(`launchsafe-firewall/relay-request/v1\n${method.toUpperCase()}\n${pathWithQuery}\n${ts}\n${b64u(sha256(body))}`, "utf8");
}

// --- pairing ----------------------------------------------------------------------------------------

export interface PairingStartRequest {
  /** SPKI DER of the device's P-256 signing key, base64url. */
  deviceSignPub: string;
  /** SHA-256 of the pairing secret S, base64url: lets the relay match nothing, prove nothing. */
  secretHash: string;
  /** The machine's label. */
  label: string;
}

export interface PairingStartResponse {
  pairingId: string;
  expiresAt: string;
}

/** The phone's answer R (posted by the phone with its MAC, returned to the device by the relay). */
export interface PairingAnswer {
  credentialId: string;
  /** COSE_Key bytes, base64url (must equal the attested credential's key). */
  publicKey: string;
  attestationObject: string;
  clientDataJSON: string;
  /** The phone's ECDH P-256 public key, uncompressed point (65 bytes), base64url. */
  phoneEcdhPub: string;
  /** The label the person gave the phone. */
  label: string;
}

export type PairingStatus = { status: "waiting" | "expired" } | { status: "claimed"; answer: PairingAnswer; mac: string };

export interface ConfirmResponse {
  deviceId: string;
  /** Issued on the device's first confirmed pairing; a device that already has one keeps it. */
  deviceToken?: string;
}

/** The pairing link the QR carries. The fragment never reaches a server. */
export function pairingLink(origin: string, pairingId: string, secret: Uint8Array, fingerprint: string): string {
  return `${origin}/firewall/pair#v=1&p=${encodeURIComponent(pairingId)}&s=${b64u(secret)}&f=${fingerprint}`;
}

/** The challenge the phone must use when it creates the approval passkey: binds the credential to this pairing. */
export function registrationChallenge(pairingId: string, fingerprint: string): Buffer {
  return sha256(`launchsafe-firewall/pair/v1\n${pairingId}\n${fingerprint}`);
}

function macKey(secret: Uint8Array): Buffer {
  return Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), "launchsafe-firewall/pair-mac/v1", 32));
}

/**
 * The phone's MAC over its answer: HMAC-SHA256 with HKDF(S, "launchsafe-firewall/pair-mac/v1") over
 * canonicalJson(R) "\n" pairingId "\n" base64url(device SPKI). The relay never sees S, so it cannot
 * swap in its own passkey.
 */
export function pairingMac(secret: Uint8Array, answer: PairingAnswer, pairingId: string, deviceSpki: Uint8Array): string {
  return b64u(createHmac("sha256", macKey(secret)).update(`${canonicalJson(answer)}\n${pairingId}\n${b64u(deviceSpki)}`).digest());
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** The comparison code both screens show: base32(HMAC(S, "compare" || device SPKI)), 8 characters, shown as XXXX-XXXX. */
export function comparisonCode(secret: Uint8Array, deviceSpki: Uint8Array): string {
  const mac = createHmac("sha256", Buffer.from(secret)).update(Buffer.concat([Buffer.from("compare", "utf8"), Buffer.from(deviceSpki)])).digest();
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of mac) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5 && out.length < 8) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    if (out.length >= 8) break;
  }
  return `${out.slice(0, 4)}-${out.slice(4, 8)}`;
}

// --- items ------------------------------------------------------------------------------------------

/** What the phone sees, built by the firewall from fields it controls (never raw tool input). */
export interface PhoneItem {
  v: 1;
  deviceId: string;
  itemId: string;
  sessionTag: string;
  actionHash: string;
  kind: "approval";
  createdAt: string;
  expiresAt: string;
  nonce: string;
  /** The firewall's fixed sentence for the first rule. */
  title: string;
  /** What the agent asked for, after the sanitizer (agent-written text: shown in a labelled box). */
  what: string;
  destination?: string;
  rules: string[];
  why: string[];
  trust: string[];
  vault?: { ref: string; kind: string; destination: string }[];
  agent: "claude" | "codex" | "gemini" | "cursor" | "gateway";
  machine: string;
  /** The first 6 characters of actionHash, also shown by `queue list`. */
  code: string;
}

/**
 * The sealed envelope one phone receives: ECDH P-256 (ephemeral key `epk`, uncompressed point) with the
 * phone's key, HKDF-SHA256 (salt epk || phone key, info "launchsafe-firewall/phone-item/v1") to an
 * AES-256-GCM key, the canonical PhoneItem encrypted with AAD = deviceId "\n" itemRef. `sig` is the
 * device's ECDSA P-256 signature (P1363) over epk || iv || ct || AAD; the phone checks it first.
 */
export interface SealedItem {
  v: 1;
  epk: string;
  iv: string;
  /** Ciphertext with the 16-byte GCM tag appended. */
  ct: string;
  sig: string;
}

export interface UploadItem {
  /** Random 128-bit reference, base64url; the relay knows the item only by this. */
  itemRef: string;
  /** Which paired phone it is sealed to. */
  credentialId: string;
  /** JSON of SealedItem, base64url. */
  sealed: string;
  expiresAt: string;
  /** Only "approval" items are phone-approvable; the relay refuses any other kind per item (not_phone_approvable). */
  kind?: "approval";
}

/** The relay's per-request upload limits (docs/firewall-relay.md in the app). */
export const UPLOAD_MAX_ITEMS = 50;
export const UPLOAD_MAX_BYTES = 768 * 1024;

/**
 * Splits uploads into requests within the relay's limits: at most 50 items and 768 KB of JSON body each.
 * An item too large to fit any request on its own is returned apart (the relay would refuse the request).
 */
export function uploadBatches(items: readonly UploadItem[]): { batches: UploadItem[][]; oversize: UploadItem[] } {
  const batches: UploadItem[][] = [];
  const oversize: UploadItem[] = [];
  const envelope = Buffer.byteLength(JSON.stringify({ items: [] }), "utf8");
  let cur: UploadItem[] = [];
  let size = envelope;
  for (const it of items) {
    const n = Buffer.byteLength(JSON.stringify(it), "utf8") + 1;
    if (envelope + n > UPLOAD_MAX_BYTES) {
      oversize.push(it);
      continue;
    }
    if (cur.length >= UPLOAD_MAX_ITEMS || size + n > UPLOAD_MAX_BYTES) {
      batches.push(cur);
      cur = [];
      size = envelope;
    }
    cur.push(it);
    size += n;
  }
  if (cur.length > 0) batches.push(cur);
  return { batches, oversize };
}

export interface UploadResponse {
  accepted: string[];
  refused: { itemRef: string; code: string; message: string }[];
}

/** Why an item stops being shown: the phone shows each as a fixed sentence. */
export type WithdrawReason = "approved" | "rejected" | "decided_in_terminal" | "already_decided" | "expired" | "refused";

// --- decisions --------------------------------------------------------------------------------------

/** The message the phone's passkey signs: challenge = SHA-256(canonicalJson(M)). */
export interface DecisionMessage {
  v: 1;
  type: "launchsafe-firewall/phone-decision";
  deviceId: string;
  itemId: string;
  sessionTag: string;
  actionHash: string;
  decision: "approve" | "reject";
  displayHash: string;
  nonce: string;
  issuedAt: string;
}

export const DECISION_TYPE = "launchsafe-firewall/phone-decision";

export interface RelayDecision {
  /** The relay's cursor for this decision: the next poll passes the last one processed as `after`. */
  id: string;
  itemRef: string;
  credentialId: string;
  /** The exact canonical JSON string of M the phone signed. */
  m: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
}

export interface DecisionsResponse {
  decisions: RelayDecision[];
  /** The cursor to resume from (the last decision's id, or the one passed in). */
  cursor: string | null;
}

export function decisionChallenge(m: string): Buffer {
  return sha256(m);
}

/** Parses M: it must be the canonical JSON of a decision message (anything else was not built by the web app's rule). */
export function parseDecisionMessage(m: string): DecisionMessage {
  let v: unknown;
  try {
    v = JSON.parse(m);
  } catch {
    throw new RelayProtocolError("the decision message is not JSON");
  }
  if (canonicalJson(v) !== m) throw new RelayProtocolError("the decision message is not in canonical form");
  const o = v as Record<string, unknown>;
  const s = (k: string): string => {
    const x = own(o, k);
    if (typeof x !== "string" || x === "" || x.length > 200) throw new RelayProtocolError(`the decision message's ${k} is missing or too long`);
    return x;
  };
  if (o.v !== 1 || o.type !== DECISION_TYPE) throw new RelayProtocolError("not a phone decision message (v1)");
  const decision = s("decision");
  if (decision !== "approve" && decision !== "reject") throw new RelayProtocolError("the decision is neither approve nor reject");
  const keys = Object.keys(o).sort().join(",");
  if (keys !== "actionHash,decision,deviceId,displayHash,issuedAt,itemId,nonce,sessionTag,type,v") throw new RelayProtocolError("the decision message has unexpected fields");
  return { v: 1, type: DECISION_TYPE, deviceId: s("deviceId"), itemId: s("itemId"), sessionTag: s("sessionTag"), actionHash: s("actionHash"), decision, displayHash: s("displayHash"), nonce: s("nonce"), issuedAt: s("issuedAt") };
}

// --- response parsers -------------------------------------------------------------------------------

const B64U = /^[A-Za-z0-9_-]+$/;

function obj(v: unknown, what: string): Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new RelayProtocolError(`${what} is not an object`);
  return v as Record<string, unknown>;
}

function str(o: Record<string, unknown>, k: string, what: string, max = 512): string {
  const v = own(o, k);
  if (typeof v !== "string" || v === "" || v.length > max) throw new RelayProtocolError(`${what}.${k} is missing or too long`);
  return v;
}

function b64(o: Record<string, unknown>, k: string, what: string, max = 16384): string {
  const v = str(o, k, what, max);
  if (!B64U.test(v)) throw new RelayProtocolError(`${what}.${k} is not base64url`);
  return v;
}

export function parsePairingStart(v: unknown): PairingStartResponse {
  const o = obj(v, "pairing");
  return { pairingId: str(o, "pairingId", "pairing", 128), expiresAt: str(o, "expiresAt", "pairing", 64) };
}

export function parsePairingStatus(v: unknown): PairingStatus {
  const o = obj(v, "pairing status");
  const status = o.status;
  if (status === "waiting" || status === "expired") return { status };
  if (status !== "claimed") throw new RelayProtocolError("pairing status is not waiting, claimed or expired");
  const a = obj(o.answer, "pairing answer");
  const answer: PairingAnswer = {
    credentialId: b64(a, "credentialId", "answer", 2048),
    publicKey: b64(a, "publicKey", "answer", 2048),
    attestationObject: b64(a, "attestationObject", "answer", 16384),
    clientDataJSON: b64(a, "clientDataJSON", "answer", 4096),
    phoneEcdhPub: b64(a, "phoneEcdhPub", "answer", 256),
    label: str(a, "label", "answer", 64),
  };
  return { status, answer, mac: b64(o, "mac", "pairing status", 128) };
}

export function parseConfirm(v: unknown): ConfirmResponse {
  const o = obj(v, "confirm");
  const out: ConfirmResponse = { deviceId: str(o, "deviceId", "confirm", 128) };
  if (o.deviceToken !== undefined) out.deviceToken = str(o, "deviceToken", "confirm", 512);
  return out;
}

export function parseUpload(v: unknown): UploadResponse {
  const o = obj(v, "upload");
  if (!Array.isArray(o.accepted) || !o.accepted.every((x) => typeof x === "string")) throw new RelayProtocolError("upload.accepted is not a list of references");
  const refused = o.refused === undefined ? [] : o.refused;
  if (!Array.isArray(refused)) throw new RelayProtocolError("upload.refused is not a list");
  return { accepted: o.accepted as string[], refused: refused.map((r) => { const x = obj(r, "refusal"); return { itemRef: str(x, "itemRef", "refusal", 64), code: str(x, "code", "refusal", 64), message: str(x, "message", "refusal", 300) }; }) };
}

export function parseDecisions(v: unknown): DecisionsResponse {
  const o = obj(v, "decisions");
  if (!Array.isArray(o.decisions) || o.decisions.length > 100) throw new RelayProtocolError("decisions is not a list of at most 100");
  const decisions = o.decisions.map((d): RelayDecision => {
    const x = obj(d, "decision");
    return { id: str(x, "id", "decision", 128), itemRef: b64(x, "itemRef", "decision", 64), credentialId: b64(x, "credentialId", "decision", 2048), m: str(x, "m", "decision", 2048), authenticatorData: b64(x, "authenticatorData", "decision", 4096), clientDataJSON: b64(x, "clientDataJSON", "decision", 4096), signature: b64(x, "signature", "decision", 1024) };
  });
  const cursor = o.cursor === null || o.cursor === undefined ? null : str(o, "cursor", "decisions", 128);
  return { decisions, cursor };
}
