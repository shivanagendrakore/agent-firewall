/**
 * The native link's messages (design 10), on the extension's side. The local firewall's host
 * (`launchsafe-firewall native-host`) checks everything it receives against a strict schema and drops the
 * link on anything that does not fit, so what is sent here is built field by field and cleaned to that
 * schema first: never page text, field values, evidence snippets or full URLs.
 *
 * What the host sends is parsed here just as strictly. Anything unexpected is a reason to drop the link
 * (link.ts), never to act.
 *
 * Pure: no extension APIs, so it is unit-tested in Node.
 */
import type { ChainedEntry } from "../shared/messages.js";

export const HOST_NAME = "com.launchsafe.agent_firewall";
export const PROTOCOL_VERSION = 1;
/** The host refuses a message larger than this; ours stay far below it. */
export const MAX_MESSAGE_BYTES = 64 * 1024;
/** What the extension enforces, sent in its hello (the firewall logs it). */
export const EXTENSION_CAPABILITIES = ["gate", "leak_guard", "content_guard", "nav_policy", "log"] as const;

const CODE = /^[a-z][a-z0-9_]{0,39}$/;
const RULE = /^[a-z][a-z0-9_.]{0,63}$/;
const DETAIL = /^[A-Za-z0-9_.:-]{1,64}$/;
const BINDING = /^[0-9a-f]{16,128}$/;
const SITE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const NONCE = /^[A-Za-z0-9_-]{8,64}$/;
const VERSION_STRING = /^\d{1,5}(?:\.\d{1,5}){0,3}$/;
const APPROVAL_OUTCOMES = new Set(["approved", "denied", "expired", "redeemed", "refused"]);

export type ExtensionMessage =
  | { type: "hello"; nonce: string; version: number; capabilities: string[]; extension: string }
  | { type: "log.append"; nonce: string; entry: WireLogEntry }
  | { type: "state.taint"; nonce: string; session: string; reason: string }
  | { type: "approval.request"; nonce: string; binding: string; action: { kind: string; actionClass: string | null; site: string; label: string }; surface: "firewall" }
  | { type: "approval.cancel"; nonce: string; binding: string };

export interface WireLogEntry {
  seq: number;
  hash: string;
  prevHash: string;
  at: number;
  site: string;
  actionClass: string | null;
  verdict: string;
  rules: string[];
  approval?: string;
  binding?: string;
  event?: string;
  detail?: string[];
}

export type HostCapability = "log" | "taint" | "approval";

export type HostMessage =
  | { type: "hello"; re: string; version: number; capabilities: HostCapability[]; firewall: string }
  | { type: "log.ack"; re: string; seq: number }
  | { type: "ack"; re: string }
  | { type: "approval.queued"; re: string; id: string }
  /**
   * `sig` (m3): the firewall may attach its approval key's signature. The extension does NOT verify it (it holds
   * no copy of the key, and no verification code ships): it is accepted only so a host that sends it is not
   * refused, and nothing reads it. What the extension relies on instead: the message arrived on the native port
   * Chrome opened to the host named in our manifest (only our extension id may connect), and it names a pending
   * approval's salted binding. A process that can replace the host binary is outside the threat model.
   */
  | { type: "approval.result"; nonce: string; binding: string; verdict: "approve" | "deny"; sig?: string }
  | { type: "state.taint"; nonce: string; session: string; reason: string }
  | { type: "error"; re?: string; code: string; message: string };

/** A fresh nonce: 96 bits from the platform CSPRNG, base64url. */
export function newNonce(random: (n: number) => Uint8Array = (n) => crypto.getRandomValues(new Uint8Array(n))): string {
  const b = random(12);
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * A log entry as the host accepts it. The evidence snippet (page text, opt-in) never leaves the browser;
 * a site, rule or code the schema would refuse is dropped rather than sent (the host would drop the link).
 */
export function wireEntry(e: ChainedEntry): WireLogEntry {
  const out: WireLogEntry = {
    seq: e.seq,
    hash: e.hash,
    prevHash: e.prevHash,
    at: Math.max(0, Math.floor(e.at)),
    site: SITE.test(e.site) && e.site.length <= 253 ? e.site : "",
    actionClass: e.actionClass !== null && CODE.test(e.actionClass) ? e.actionClass : null,
    verdict: CODE.test(e.verdict) ? e.verdict : "log",
    rules: e.rules.filter((r) => RULE.test(r)).slice(0, 16),
  };
  if (e.approval !== undefined && APPROVAL_OUTCOMES.has(e.approval)) out.approval = e.approval;
  if (e.binding !== undefined && BINDING.test(e.binding)) out.binding = e.binding;
  if (e.event !== undefined && CODE.test(e.event)) out.event = e.event;
  const detail = (e.detail ?? []).filter((d) => DETAIL.test(d)).slice(0, 16);
  if (detail.length > 0) out.detail = detail;
  return out;
}

/** A label for the firewall's queue: the approval's own label without control or invisible characters, at most 200 characters. */
export function wireLabel(label: string): string {
  // eslint-disable-next-line no-control-regex -- removing control characters is the point
  const clean = label.replace(/[\u0000-\u001f\u007f-\u009f]|\p{Cf}|\p{Zl}|\p{Zp}/gu, " ").replace(/\s+/g, " ").trim();
  const cut = [...clean].slice(0, 200).join("");
  return cut === "" ? "a held action" : cut;
}

export function wireSite(site: string): string {
  return SITE.test(site) && site.length <= 253 ? site : "";
}

export function wireCode(x: string | null): string | null {
  return x !== null && CODE.test(x) ? x : null;
}

export function isBinding(x: string): boolean {
  return BINDING.test(x);
}

export function isSessionId(x: string): boolean {
  return /^[A-Za-z0-9_-]{1,64}$/.test(x);
}

export function isReason(x: string): boolean {
  return CODE.test(x);
}

export function isExtensionVersion(x: string): boolean {
  return VERSION_STRING.test(x);
}

type Obj = Record<string, unknown>;

function isObj(x: unknown): x is Obj {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function exactly(o: Obj, required: readonly string[], optional: readonly string[] = []): boolean {
  return required.every((k) => Object.prototype.hasOwnProperty.call(o, k)) && Object.keys(o).every((k) => required.includes(k) || optional.includes(k));
}

const s = (x: unknown, re: RegExp): x is string => typeof x === "string" && re.test(x);

/** A message from the host, or null for anything that does not fit (the caller drops the link). */
export function parseHostMessage(x: unknown): HostMessage | null {
  if (!isObj(x)) return null;
  switch (x.type) {
    case "hello": {
      if (!exactly(x, ["type", "re", "version", "capabilities", "firewall"]) || !s(x.re, NONCE) || typeof x.version !== "number" || !Number.isInteger(x.version) || !s(x.firewall, VERSION_STRING)) return null;
      const caps = x.capabilities;
      if (!Array.isArray(caps) || caps.length > 8 || !caps.every((c) => c === "log" || c === "taint" || c === "approval")) return null;
      return { type: "hello", re: x.re, version: x.version, capabilities: caps as HostCapability[], firewall: x.firewall };
    }
    case "log.ack":
      return exactly(x, ["type", "re", "seq"]) && s(x.re, NONCE) && typeof x.seq === "number" && Number.isInteger(x.seq) && x.seq > 0 ? { type: "log.ack", re: x.re, seq: x.seq } : null;
    case "ack":
      return exactly(x, ["type", "re"]) && s(x.re, NONCE) ? { type: "ack", re: x.re } : null;
    case "approval.queued":
      return exactly(x, ["type", "re", "id"]) && s(x.re, NONCE) && s(x.id, /^[a-z0-9]{4,32}$/) ? { type: "approval.queued", re: x.re, id: x.id } : null;
    case "approval.result": {
      if (!exactly(x, ["type", "nonce", "binding", "verdict"], ["sig"]) || !s(x.nonce, NONCE) || !s(x.binding, BINDING) || (x.verdict !== "approve" && x.verdict !== "deny")) return null;
      if (x.sig !== undefined && !s(x.sig, /^[A-Za-z0-9+/=]{1,200}$/)) return null;
      return { type: "approval.result", nonce: x.nonce, binding: x.binding, verdict: x.verdict, ...(x.sig !== undefined ? { sig: x.sig as string } : {}) };
    }
    case "state.taint":
      return exactly(x, ["type", "nonce", "session", "reason"]) && s(x.nonce, NONCE) && s(x.session, /^[A-Za-z0-9_-]{1,64}$/) && s(x.reason, CODE) ? { type: "state.taint", nonce: x.nonce, session: x.session, reason: x.reason } : null;
    case "error":
      if (!exactly(x, ["type", "code", "message"], ["re"]) || !s(x.code, CODE) || typeof x.message !== "string" || (x.re !== undefined && !s(x.re, NONCE))) return null;
      return { type: "error", ...(x.re !== undefined ? { re: x.re as string } : {}), code: x.code, message: x.message.slice(0, 300) };
    default:
      return null;
  }
}

/** The JSON size of a message, as the host counts it. */
export function messageBytes(m: ExtensionMessage): number {
  return new TextEncoder().encode(JSON.stringify(m)).length;
}
