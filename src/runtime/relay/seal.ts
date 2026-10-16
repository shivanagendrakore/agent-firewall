/**
 * What the phone sees, and how it is sealed (docs/phone.md, "What the phone
 * sees"). The PhoneItem is built from fields the firewall controls: the rule
 * catalogue's fixed sentence, the one-line summary, the reasons, the trust
 * sources. Never file contents, diffs, prompts, tool output or vault values.
 * Every free-text field goes through the sanitizer: secrets redacted,
 * personal data masked, workspace and home paths shortened, URLs cut to
 * scheme, host and first path segment, control/bidi/zero-width characters
 * escaped, each field at most 300 characters, the whole item at most 6 KB.
 * Whatever is left out (rules past 10, reasons past 3, shortened text, the
 * parts of a multi-part action, values cut when it was held) is counted in a
 * last "Not shown here" line of `why` (I3), so the phone never looks complete
 * when it is not.
 *
 * Sealing: an ephemeral ECDH P-256 key with the phone's key, HKDF-SHA256 to
 * an AES-256-GCM key, then the device's ECDSA signature over the envelope,
 * so the relay can neither read nor alter an item (protocol.ts SealedItem).
 */

import { createCipheriv, createDecipheriv, createECDH, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, verify, type KeyObject } from "node:crypto";
import { homedir } from "node:os";
import { findPersonalData } from "../../engine/pii.js";
import { redactSecrets } from "../../engine/secrets.js";
import { parseMcpTool } from "../../engine/mcp.js";
import { safeLine } from "../../engine/terminal.js";
import { findRefs } from "../../engine/vault-ref.js";
import { RULES } from "../../rules.js";
import type { QueueItem } from "../store.js";
import { deviceSign, type DeviceFile } from "./keys.js";
import type { PhoneItem, SealedItem } from "./protocol.js";
import { b64u, canonicalJson, sessionTag, sha256Hex, unb64u } from "./util.js";
import { own } from "../../own.js";

export const MAX_FIELD = 300;
export const MAX_ITEM_BYTES = 6 * 1024;

function maskPersonal(text: string): string {
  let out = text;
  // Every card-shaped number, also inside a longer token: hiding too much on the phone is harmless, showing a card is not.
  for (const h of findPersonalData(text, { insideTokens: true })) {
    const digits = h.value.replace(/[^0-9A-Za-z]/g, "");
    const label = h.kind === "card" ? `[card ••••${digits.slice(-4)}]` : h.kind === "iban" ? `[iban ••••${digits.slice(-4)}]` : "[national id]";
    out = out.split(h.value).join(label);
  }
  return out;
}

function shortenPaths(text: string, cwd: string, home: string): string {
  let out = text;
  const ws = cwd.replace(/\/+$/, "");
  if (ws.length > 1) out = out.split(`${ws}/`).join("").split(ws).join(".");
  const h = home.replace(/\/+$/, "");
  if (h.length > 1) out = out.split(`${h}/`).join("~/").split(h).join("~");
  return out;
}

/** URLs keep their scheme, host and first path segment (query, fragment and the rest of the path go). */
function cutUrls(text: string): string {
  return text.replace(/\b([a-z][a-z0-9+.-]*):\/\/([^\s/?#'"`<>]+)(\/[^\s/?#'"`<>]*)?([^\s'"`<>]*)/gi, (_m, scheme: string, host: string, seg: string | undefined, rest: string) => {
    const at = host.lastIndexOf("@");
    const bare = at === -1 ? host : host.slice(at + 1);
    return `${scheme}://${bare}${seg ?? ""}${rest !== "" && rest !== undefined ? "/…" : ""}`;
  });
}

function cap(text: string, max = MAX_FIELD): string {
  if (text.length <= max) return text;
  let cut = text.slice(0, max - 1);
  // Never end inside a \uXXXX escape the line escaping produced.
  const esc = cut.lastIndexOf("\\u");
  if (esc !== -1 && esc > cut.length - 6) cut = cut.slice(0, esc);
  return `${cut}…`;
}

/** The sanitizer every free-text field passes through, in the order docs/phone.md gives. */
export function sanitize(text: string, o: { cwd: string; home?: string; max?: number }): string {
  const redacted = redactSecrets(text).text;
  const masked = maskPersonal(redacted);
  const escaped = safeLine(masked);
  const pathed = shortenPaths(escaped, o.cwd, o.home ?? homedir());
  return cap(cutUrls(pathed), o.max ?? MAX_FIELD);
}

function firstUrlHost(v: unknown, depth = 0): string | null {
  if (depth > 6) return null;
  if (typeof v === "string") {
    const m = /\bhttps?:\/\/(?:[^\s/@'"]*@)?([A-Za-z0-9.-]+(?::\d+)?)/.exec(v);
    if (m !== null) return (m[1] as string).toLowerCase();
    const scp = /\bgit@([A-Za-z0-9.-]+):/.exec(v);
    return scp !== null ? (scp[1] as string).toLowerCase() : null;
  }
  if (Array.isArray(v)) {
    for (const x of v) {
      const h = firstUrlHost(x, depth + 1);
      if (h !== null) return h;
    }
    return null;
  }
  if (typeof v === "object" && v !== null) {
    for (const x of Object.values(v)) {
      const h = firstUrlHost(x, depth + 1);
      if (h !== null) return h;
    }
  }
  return null;
}

/** Where the action would send something: a host, "mcp:<server>", or github:owner/repo. */
export function destinationOf(it: Pick<QueueItem, "tool" | "input">): string | undefined {
  const mcp = parseMcpTool(it.tool);
  const input = typeof it.input === "object" && it.input !== null ? (it.input as Record<string, unknown>) : {};
  if (mcp !== null) {
    if (/github/i.test(mcp.server) && typeof input.owner === "string" && typeof input.repo === "string") return `github:${input.owner}/${input.repo}`;
    return `mcp:${mcp.server}`;
  }
  return firstUrlHost(input) ?? undefined;
}

function agentOf(sessionId: string): PhoneItem["agent"] {
  const p = /^(codex|gemini|cursor|gateway):/.exec(sessionId)?.[1];
  return (p as PhoneItem["agent"] | undefined) ?? "claude";
}

export interface BuildOptions {
  deviceId: string;
  machine: string;
  nonce: string;
  expiresAt: string;
  home?: string;
  /** Vault entries' kinds by name, when the index is readable (references only, never values). */
  vaultKinds?: (name: string) => string | undefined;
}

/** Builds the sanitized PhoneItem for a queued approval item. */
export function buildPhoneItem(it: QueueItem, o: BuildOptions): PhoneItem {
  const s = (t: string, max?: number): string => sanitize(t, { cwd: it.cwd, ...(o.home !== undefined ? { home: o.home } : {}), ...(max !== undefined ? { max } : {}) });
  const destination = destinationOf(it);
  const title = it.rules.map((r) => own(RULES, r)?.sentence).find((x): x is string => x !== undefined) ?? "It needs your approval before it runs.";
  const allRefs = findRefs(JSON.stringify(it.input ?? null));
  const refs = allRefs.slice(0, 5);
  const rules = it.rules.filter((r) => /^FW-[A-Z0-9-]{1,40}$/.test(r));
  const trustAll = it.trustSources ?? [];
  // I3: what the phone is not shown, counted, so the last line of "why" can say so.
  const omitted = { rules: Math.max(0, rules.length - 10), reasons: Math.max(0, it.reasons.length - 3), trust: Math.max(0, trustAll.length - 2), vault: Math.max(0, allRefs.length - 5), parts: Array.isArray(it.parts) ? it.parts.length : 0, cut: itemCut(it) };
  const item: PhoneItem = {
    v: 1,
    deviceId: o.deviceId,
    itemId: it.id,
    sessionTag: sessionTag(it.sessionId),
    actionHash: it.actionHash,
    kind: "approval",
    createdAt: it.createdAt,
    expiresAt: o.expiresAt,
    nonce: o.nonce,
    title,
    what: s(it.summary ?? `Use ${it.tool}`),
    ...(destination !== undefined ? { destination: s(destination, 120) } : {}),
    rules: rules.slice(0, 10),
    why: it.reasons.slice(0, 3).map((r) => s(r)),
    trust: trustAll.slice(-2).map((t) => s(t)),
    ...(refs.length > 0 ? { vault: refs.map((r) => ({ ref: s(r.text, 100), kind: o.vaultKinds?.(r.name) ?? "secret", destination: s(destination ?? "unknown", 120) })) } : {}),
    agent: agentOf(it.sessionId),
    machine: s(o.machine, 64),
    code: it.actionHash.slice(0, 6),
  };
  const fitted = fitItem(item, MAX_ITEM_BYTES - MARKER_RESERVE);
  const notShown: string[] = [];
  const more = (n: number, one: string, many: string): void => {
    if (n > 0) notShown.push(`${n} more ${n === 1 ? one : many}`);
  };
  more(omitted.rules, "rule", "rules");
  more(omitted.reasons + (item.why.length - fitted.why.length), "reason", "reasons");
  more(omitted.trust + (item.trust.length - fitted.trust.length), "outside source", "outside sources");
  more(omitted.vault + (item.vault !== undefined && fitted.vault === undefined ? item.vault.length : 0), "vault reference", "vault references");
  if (fitted.what !== item.what || fitted.why.some((w, i) => w !== item.why[i])) notShown.push("text shortened");
  if (omitted.parts > 1) notShown.push(`the action runs as ${omitted.parts} parts (shown in the terminal)`);
  if (omitted.cut) notShown.push("parts of the action were cut when it was held");
  if (notShown.length > 0) fitted.why = [...fitted.why, cap(`Not shown here: ${notShown.join("; ")}.`)];
  return fitted;
}

/** Room kept for the "Not shown here" line (at most MAX_FIELD characters, escaped). */
const MARKER_RESERVE = 3 * MAX_FIELD + 16;

/** Whether storing the item cut anything (store.ts records it; older items carry the markers). */
function itemCut(it: QueueItem): boolean {
  if (Array.isArray(it.truncated)) return it.truncated.length > 0;
  const text = JSON.stringify([it.input ?? null, it.parts ?? null]);
  return /… \[\d+ more characters\]/.test(text) || text.includes('"…"');
}

function bytes(item: PhoneItem): number {
  return Buffer.byteLength(canonicalJson(item), "utf8");
}

/** Shrinks the free text until the whole item is at most `max` bytes (the reasons and sources go first). */
function fitItem(item: PhoneItem, max = MAX_ITEM_BYTES): PhoneItem {
  const out = { ...item };
  const steps: (() => void)[] = [
    () => (out.trust = out.trust.slice(0, 1)),
    () => (out.why = out.why.slice(0, 1)),
    () => (out.trust = []),
    () => delete out.vault,
    () => (out.why = out.why.map((w) => cap(w, 120))),
    () => (out.what = cap(out.what, 150)),
    () => (out.why = []),
  ];
  for (const step of steps) {
    if (bytes(out) <= max) break;
    step();
  }
  return out;
}

export function displayHash(item: PhoneItem): string {
  return sha256Hex(canonicalJson(item));
}

// --- sealing ----------------------------------------------------------------------------------------

const INFO = "launchsafe-firewall/phone-item/v1";

function rawP256(pub: KeyObject): Buffer {
  const jwk = pub.export({ format: "jwk" });
  return Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x as string, "base64url"), Buffer.from(jwk.y as string, "base64url")]);
}

/** A P-256 public key from an uncompressed point (what WebCrypto exports as "raw"). */
export function p256FromRaw(raw: Uint8Array): KeyObject {
  if (raw.length !== 65 || raw[0] !== 4) throw new Error("not an uncompressed P-256 point");
  // createECDH validates that the point is on the curve.
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(randomBytes(32));
  ecdh.computeSecret(Buffer.from(raw));
  return createPublicKey({ key: { kty: "EC", crv: "P-256", x: b64u(raw.subarray(1, 33)), y: b64u(raw.subarray(33, 65)) }, format: "jwk" });
}

/**
 * AAD = deviceId "\n" itemRef. The reference is used rather than the item id because the phone
 * knows it before decrypting (the relay lists items by reference), and it binds the blob to its reference,
 * so the relay cannot move a sealed item under another one. The item id is inside the plaintext.
 */
function aad(deviceId: string, itemRef: string): Buffer {
  return Buffer.from(`${deviceId}\n${itemRef}`, "utf8");
}

function aesKey(shared: Buffer, epk: Buffer, recipient: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", shared, Buffer.concat([epk, recipient]), INFO, 32));
}

/** Seals one PhoneItem to one phone's ECDH key, signed with the device key. */
export function sealItem(item: PhoneItem, phoneEcdhPubB64u: string, device: DeviceFile, itemRef: string): SealedItem {
  const recipientRaw = unb64u(phoneEcdhPubB64u, "the phone's ECDH key");
  const recipient = p256FromRaw(recipientRaw);
  const eph = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const epk = rawP256(eph.publicKey);
  const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: recipient });
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", aesKey(shared, epk, recipientRaw), iv);
  c.setAAD(aad(item.deviceId, itemRef));
  const ct = Buffer.concat([c.update(canonicalJson(item), "utf8"), c.final(), c.getAuthTag()]);
  const sig = deviceSign(device, Buffer.concat([epk, iv, ct, aad(item.deviceId, itemRef)]));
  return { v: 1, epk: b64u(epk), iv: b64u(iv), ct: b64u(ct), sig };
}

/**
 * The phone's side, in Node (the reference for the web app's WebCrypto code, and what the tests' phone
 * uses): check the device signature with the pinned device key, then decrypt.
 */
export function openSealed(s: SealedItem, o: { phoneEcdhPriv: KeyObject; phoneEcdhPubRaw: Uint8Array; deviceSpki: Uint8Array; deviceId: string; itemRef: string }): PhoneItem {
  const epk = unb64u(s.epk);
  const iv = unb64u(s.iv);
  const ct = unb64u(s.ct);
  const a = aad(o.deviceId, o.itemRef);
  const dev = createPublicKey({ key: Buffer.from(o.deviceSpki), format: "der", type: "spki" });
  if (!verify("sha256", Buffer.concat([epk, iv, ct, a]), { key: dev, dsaEncoding: "ieee-p1363" }, unb64u(s.sig))) throw new Error("the sealed item is not signed by the paired machine");
  const shared = diffieHellman({ privateKey: o.phoneEcdhPriv, publicKey: p256FromRaw(epk) });
  const d = createDecipheriv("aes-256-gcm", aesKey(shared, epk, Buffer.from(o.phoneEcdhPubRaw)), iv);
  d.setAAD(a);
  d.setAuthTag(ct.subarray(ct.length - 16));
  const plain = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString("utf8");
  const item = JSON.parse(plain) as PhoneItem;
  if (item.deviceId !== o.deviceId) throw new Error("the sealed item names another machine");
  return item;
}

export { rawP256 };
