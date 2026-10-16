/**
 * The paired phones (`keys/phones.json`) and their pin. Each entry is one
 * dedicated approval passkey: its credential id and COSE public key, the
 * algorithm, the RP ID and origin it was created on, the phone's ECDH key
 * (what items are sealed to) and the label the phone gave.
 *
 * The hook command pins `LAUNCHSAFE_FIREWALL_PHONES=sha256:<hex>`, the hash
 * of the file's canonical JSON, next to the approver key. A key appended to
 * the file by anything but `phone pair` changes the hash, so every phone
 * approval is refused until a person re-pins (which needs the passphrase).
 */

import { join } from "node:path";
import { atomicWrite, ensureDir, readText } from "../fsutil.js";
import { assertNotRealHome } from "../guard.js";
import type { Layout } from "../layout.js";
import { canonicalJson, sha256Hex } from "./util.js";

export interface PairedPhone {
  /** base64url. */
  credentialId: string;
  /** The COSE_Key bytes, base64url. */
  publicKey: string;
  alg: number;
  rpId: string;
  origin: string;
  /** The phone's ECDH P-256 public key, uncompressed point, base64url: items are sealed to it. */
  ecdhPub: string;
  label: string;
  pairedAt: string;
}

export interface PhonesFile {
  version: 1;
  phones: PairedPhone[];
}

export function phonesPath(l: Layout): string {
  return join(l.keys, "phones.json");
}

const B64U = /^[A-Za-z0-9_-]+$/;

function validPhone(p: unknown): p is PairedPhone {
  if (typeof p !== "object" || p === null) return false;
  const o = p as Record<string, unknown>;
  return (
    typeof o.credentialId === "string" && B64U.test(o.credentialId) &&
    typeof o.publicKey === "string" && B64U.test(o.publicKey) &&
    typeof o.alg === "number" && [-7, -257, -8].includes(o.alg) &&
    typeof o.rpId === "string" && o.rpId !== "" &&
    typeof o.origin === "string" && o.origin !== "" &&
    typeof o.ecdhPub === "string" && B64U.test(o.ecdhPub) &&
    typeof o.label === "string" && typeof o.pairedAt === "string"
  );
}

export type PhonesState = { state: "absent" } | { state: "ok"; file: PhonesFile; hash: string } | { state: "corrupt"; error: string };

/** Parses the file text. The hash is over the canonical form, so reformatting it does not break the pin; any change of content does. */
export function parsePhones(text: string): PhonesState {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return { state: "corrupt", error: `${"keys/phones.json"} is not valid JSON` };
  }
  const o = v as Partial<PhonesFile> | null;
  if (typeof o !== "object" || o === null || o.version !== 1 || !Array.isArray(o.phones) || !o.phones.every(validPhone)) return { state: "corrupt", error: "keys/phones.json is not a valid list of paired phones" };
  const ids = new Set(o.phones.map((p) => p.credentialId));
  if (ids.size !== o.phones.length) return { state: "corrupt", error: "keys/phones.json lists a credential twice" };
  return { state: "ok", file: o as PhonesFile, hash: phonesHash(o as PhonesFile) };
}

export function phonesHash(f: PhonesFile): string {
  return `sha256:${sha256Hex(canonicalJson(f))}`;
}

export function loadPhones(l: Layout): PhonesState {
  let text: string | null;
  try {
    text = readText(phonesPath(l));
  } catch (e) {
    return { state: "corrupt", error: `keys/phones.json cannot be read (${(e as Error).message})` };
  }
  return text === null ? { state: "absent" } : parsePhones(text);
}

/** The pin `phone pair` writes into the hook command: null when no phone is paired (or the file is unusable). */
export function phonesPinOf(l: Layout): string | null {
  const s = loadPhones(l);
  return s.state === "ok" && s.file.phones.length > 0 ? s.hash : null;
}

/** Writes the list (mode 600). Person-run callers only: pair and remove, which then re-pin. */
export function writePhones(l: Layout, phones: PairedPhone[]): PhonesFile {
  assertNotRealHome(phonesPath(l));
  ensureDir(l.keys);
  const f: PhonesFile = { version: 1, phones };
  atomicWrite(phonesPath(l), `${JSON.stringify(f, null, 2)}\n`, 0o600);
  return f;
}

export const PIN_RE = /^sha256:[0-9a-f]{64}$/;

/** Whether the pin given (the hook command's) matches the file: the first check on every phone decision. */
export function pinnedPhones(l: Layout, pin: string | null | undefined): { ok: true; file: PhonesFile } | { ok: false; reason: string } {
  if (pin === null || pin === undefined || pin === "") return { ok: false, reason: "no paired phone is pinned in the hook command" };
  if (!PIN_RE.test(pin)) return { ok: false, reason: "the hook command's phone pin is malformed" };
  const s = loadPhones(l);
  if (s.state === "absent") return { ok: false, reason: "keys/phones.json is missing" };
  if (s.state === "corrupt") return { ok: false, reason: s.error };
  if (s.hash !== pin) return { ok: false, reason: "keys/phones.json does not match the pin in the hook command (changed without phone pair?)" };
  return { ok: true, file: s.file };
}
