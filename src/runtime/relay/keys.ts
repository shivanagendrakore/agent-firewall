/**
 * This machine's relay identity (`keys/relay-device.json`, mode 600): an
 * ECDSA P-256 signing key and, once a pairing is confirmed, the device id and
 * device token the relay issued. P-256 rather than Ed25519 because WebCrypto
 * supports it on every phone browser: the phone pins this public key at
 * pairing and checks every sealed item's signature with it. Signatures use
 * the IEEE P1363 form (r || s), which is what WebCrypto produces and checks.
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { join } from "node:path";
import { atomicWrite, ensureDir, readText, withLock } from "../fsutil.js";
import { assertNotRealHome } from "../guard.js";
import type { Layout } from "../layout.js";
import { b64u, sha256Hex, unb64u } from "./util.js";

export interface DeviceFile {
  version: 1;
  /** PKCS8 DER, base64url. */
  signPriv: string;
  /** SPKI DER, base64url. */
  signPub: string;
  createdAt: string;
  /** The machine's label, shown on the phone. */
  label?: string;
  /** Set when a pairing is confirmed. */
  deviceId?: string;
  token?: string;
  /** The relay this identity is registered with. */
  relayOrigin?: string;
  /**
   * V38: device ids this machine held before a registration reset (a relay 401, another relay origin).
   * Past phone approvals signed for one of them stay this machine's; new decisions need the current id.
   */
  formerDeviceIds?: string[];
}

/** At most this many former device ids are kept (oldest dropped). */
const MAX_FORMER_IDS = 32;

export function devicePath(l: Layout): string {
  return join(l.keys, "relay-device.json");
}

/**
 * The device file, or null when there is none. A damaged one throws one clear Error whatever the damage
 * (not JSON, the wrong type, a directory): ensureDevice must not replace it silently, and the hook's
 * readers (deviceIdOf, deviceIdHistoryOf) catch it.
 */
export function readDevice(l: Layout): DeviceFile | null {
  let d: Partial<DeviceFile> | null;
  try {
    const t = readText(devicePath(l));
    if (t === null) return null;
    d = JSON.parse(t) as Partial<DeviceFile> | null;
  } catch (e) {
    throw new Error(`keys/relay-device.json is corrupt (${(e as Error).message})`, { cause: e });
  }
  if (typeof d !== "object" || d === null || Array.isArray(d) || d.version !== 1 || typeof d.signPriv !== "string" || typeof d.signPub !== "string") throw new Error("keys/relay-device.json is corrupt");
  return d as DeviceFile;
}

/** The device id, or null when there is no confirmed relay identity (never throws: the hook calls it). */
export function deviceIdOf(l: Layout): string | null {
  try {
    return readDevice(l)?.deviceId ?? null;
  } catch {
    return null;
  }
}

/**
 * V38: every device id this machine has held: the current one (if any) and the former ones. Used only to
 * re-verify phone approvals already spent in a session, never to accept a new decision. Never throws.
 */
export function deviceIdHistoryOf(l: Layout): string[] {
  try {
    const d = readDevice(l);
    if (d === null) return [];
    const former = Array.isArray(d.formerDeviceIds) ? d.formerDeviceIds.filter((x): x is string => typeof x === "string" && x !== "") : [];
    return [...new Set([...(d.deviceId !== undefined ? [d.deviceId] : []), ...former])];
  } catch {
    return [];
  }
}

/** The signing key pair, created on first use. */
export function ensureDevice(l: Layout): DeviceFile {
  assertNotRealHome(devicePath(l));
  ensureDir(l.keys);
  return withLock(join(l.keys, "relay-device.lock"), () => {
    const existing = readDevice(l);
    if (existing !== null) return existing;
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const d: DeviceFile = {
      version: 1,
      signPriv: b64u(privateKey.export({ type: "pkcs8", format: "der" })),
      signPub: b64u(publicKey.export({ type: "spki", format: "der" })),
      createdAt: new Date().toISOString(),
    };
    atomicWrite(devicePath(l), JSON.stringify(d, null, 2), 0o600);
    return d;
  });
}

export function updateDevice(l: Layout, patch: Partial<Pick<DeviceFile, "label" | "deviceId" | "token" | "relayOrigin">>): DeviceFile {
  assertNotRealHome(devicePath(l));
  return withLock(join(l.keys, "relay-device.lock"), () => {
    const d = readDevice(l);
    if (d === null) throw new Error("no relay identity on this machine");
    const next: DeviceFile = { ...d, ...patch };
    atomicWrite(devicePath(l), JSON.stringify(next, null, 2), 0o600);
    return next;
  });
}

/**
 * Forgets the relay's device id and token (another relay origin, or the app revoked them); the signing key
 * stays. The id moves to `formerDeviceIds` (V38): a 401, which anything answering at the relay address can
 * send, must not turn phone approvals this machine already verified and spent into tampering.
 */
export function resetRegistration(l: Layout): void {
  assertNotRealHome(devicePath(l));
  withLock(join(l.keys, "relay-device.lock"), () => {
    const d = readDevice(l);
    if (d === null) return;
    const { deviceId, token: _token, formerDeviceIds, ...rest } = d;
    const former = [...new Set([...(Array.isArray(formerDeviceIds) ? formerDeviceIds : []), ...(deviceId !== undefined ? [deviceId] : [])])].slice(-MAX_FORMER_IDS);
    atomicWrite(devicePath(l), JSON.stringify({ ...rest, ...(former.length > 0 ? { formerDeviceIds: former } : {}) }, null, 2), 0o600);
  });
}

export function devicePrivateKey(d: DeviceFile): KeyObject {
  return createPrivateKey({ key: unb64u(d.signPriv), format: "der", type: "pkcs8" });
}

export function devicePublicDer(d: DeviceFile): Buffer {
  return unb64u(d.signPub);
}

/** ECDSA P-256 / SHA-256, IEEE P1363 (r || s), base64url. */
export function deviceSign(d: DeviceFile, data: Uint8Array): string {
  return b64u(sign("sha256", data, { key: devicePrivateKey(d), dsaEncoding: "ieee-p1363" }));
}

/** The fingerprint the pairing link carries (`f`): the first 16 hex characters of SHA-256 over the SPKI DER. */
export function deviceFingerprint(spkiDer: Uint8Array): string {
  return sha256Hex(spkiDer).slice(0, 16);
}

/** Checks that an SPKI is a P-256 public key (used by tests and the stub relay). */
export function isP256Spki(der: Uint8Array): boolean {
  try {
    const k = createPublicKey({ key: Buffer.from(der), format: "der", type: "spki" });
    return k.asymmetricKeyType === "ec" && k.asymmetricKeyDetails?.namedCurve === "prime256v1";
  } catch {
    return false;
  }
}
