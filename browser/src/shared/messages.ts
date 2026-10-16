/**
 * The message protocol between the three adapters: content scripts, the
 * service worker and the extension UI. This file is the contract the three
 * lanes build against; change it only with all three in mind.
 *
 * Trust rules (threat model 5, "Messages from pages"):
 * - The worker accepts content messages only from its own content scripts
 *   (`isFromOwnContentScript`): sender.id is ours and sender.tab/frameId exist.
 *   Tab and frame ids always come from `sender`, never from the message.
 * - The worker accepts UI messages only from its own extension pages
 *   (`isFromOwnExtensionPage`): sender.id is ours and the sender URL is under
 *   our own chrome-extension:// origin (content scripts never run there).
 * - Every field is validated (`parseContentMessage`, `parseUiMessage`) with
 *   size bounds; an invalid message is dropped.
 * - Nothing here carries a raw field value to the UI: approval views are masked.
 */
import type { ActionSnapshot } from "../engine/fingerprint.js";
import type { LeakContext, LeakFinding } from "../engine/leak.js";
import type { PrivatePrint } from "../engine/private-data.js";
import { MAX_SESSION_PRINTS } from "../engine/session.js";
import { ACTION_CLASSES, ALWAYS_ON_CLASSES, RULE_IDS, type ActionClass, type AlwaysOnClass, type Decision, type FieldInfo, type NormalizedAction, type RuleId, type Verdict } from "../engine/types.js";

/** In-page actions the content script asks about; the worker fills `frame.tabId/frameId` from the sender. */
export type InPageAction = Exclude<NormalizedAction, { kind: "navigate" | "download" }>;

export type ContentVerdict = "deliver" | "neutralize" | "flag" | "quarantine";

// ---- content script -> worker ------------------------------------------------

export type ContentMessage =
  /** A frame's content script started (document_start). */
  | { type: "frame.hello"; url: string; top: boolean }
  /** The content guard scanned the page or a late subtree. `preview` only when the person keeps evidence. */
  | { type: "page.scanned"; url: string; verdict: ContentVerdict; reasons: string[]; scanIncomplete: boolean; preview?: string }
  /** The gate cancelled an action and asks for a decision. Reply: GateReply. */
  | { type: "action.check"; action: InPageAction }
  /** Fingerprints of private strings the page shows (only one-way hashes). */
  | { type: "private.prints"; prints: PrivatePrint[] }
  /** The gate replays an approved action and redeems its token. Reply: RedeemReply. */
  | { type: "approval.redeem"; token: string; snapshot: ActionSnapshot }
  /** Leak guard, agent mode and log messages: see the "leak/agent/log" section below. */
  | LeakAgentLogContentMessage
  /** Content guard and navigation messages: see the "guard/nav" section below. */
  | GuardNavMessage;

export interface GateReply {
  decision: Decision;
  /** Set when the verdict is approve (or an overridable deny): the pending approval the side panel shows. */
  approvalId?: string;
}

export interface LeakReply {
  decision: Decision;
  findings: LeakFinding[];
  approvalId?: string;
}

export type RedeemReply = { ok: true } | { ok: false; reason: string };

// ---- worker -> content script (chrome.tabs.sendMessage with a frameId) -------

export type WorkerToContentMessage =
  | { type: "approval.granted"; approvalId: string; token: string }
  | { type: "approval.denied"; approvalId: string }
  | { type: "agent.mode"; on: boolean }
  | LeakAgentLogWorkerMessage;

// ---- extension UI -> worker ---------------------------------------------------

export type UiMessage =
  | { type: "ui.state" }
  | { type: "ui.approve"; approvalId: string }
  | { type: "ui.deny"; approvalId: string }
  /** Turning on is immediate; turning off creates an approval the person confirms in the same UI. */
  | { type: "ui.agentMode"; on: boolean }
  | LeakAgentLogUiMessage;

/** What the side panel and popup show. Masked; no page text except escaped evidence. */
export interface ApprovalView {
  approvalId: string;
  actionClass: ActionClass | null;
  kind: InPageAction["kind"];
  /** The frame's origin and its registrable domain. */
  origin: string;
  domain: string;
  label: string;
  /** Form destination, if any. */
  target: string;
  /** Field names with masked values. */
  fields: { name: string; masked: string }[];
  reasons: string[];
  /** Why the tab is untrusted, with escaped hidden-text evidence when kept. */
  untrustedBecause: string[];
  createdAt: number;
  expiresAt: number;
}

export interface UiState {
  agentMode: boolean;
  pending: ApprovalView[];
  /** Agent classes and what holds against each (threat model 3); the UI never says "protected" beyond this. */
  coverageNote: string;
}

// ---- sender checks ------------------------------------------------------------

/** The subset of chrome.runtime.MessageSender the checks read (so they are testable without Chrome). */
export interface SenderLike {
  id?: string;
  url?: string;
  origin?: string;
  tab?: { id?: number; url?: string };
  frameId?: number;
}

export function isFromOwnContentScript(sender: SenderLike, extensionId: string): sender is SenderLike & { tab: { id: number }; frameId: number } {
  // Our own extension page in a tab also has a tab and frame; it is UI, not a content script.
  if ((sender.url ?? "").startsWith(`chrome-extension://${extensionId}/`)) return false;
  return sender.id === extensionId && sender.tab !== undefined && typeof sender.tab.id === "number" && sender.tab.id >= 0 && typeof sender.frameId === "number" && sender.frameId >= 0;
}

export function isFromOwnExtensionPage(sender: SenderLike, extensionId: string): boolean {
  // An extension page may sit in a tab (the approval window); content scripts never run in our pages, so a
  // sender URL under our own origin is ours. A content script's sender URL is the web page's.
  if (sender.id !== extensionId) return false;
  const prefix = `chrome-extension://${extensionId}/`;
  return typeof sender.url === "string" && sender.url.startsWith(prefix);
}

// ---- validation ---------------------------------------------------------------

export const LIMITS = {
  url: 8 * 1024,
  label: 512,
  path: 2 * 1024,
  name: 256,
  text: 1024 * 1024,
  fields: 500,
  files: 100,
  reasons: 32,
  /** Prints per message and per leak context: the session keeps no more than this (session.ts capPrints), so a context always fits. */
  prints: MAX_SESSION_PRINTS,
  preview: 400,
  token: 128,
  /** Total characters across every string (and key) in one message: each field's own bound is not enough. */
  message: 2 * 1024 * 1024 + 64 * 1024,
  /** Nesting depth of one message. */
  depth: 8,
} as const;

type Obj = Record<string, unknown>;
const isObj = (x: unknown): x is Obj => typeof x === "object" && x !== null && !Array.isArray(x);
const str = (x: unknown, max: number): x is string => typeof x === "string" && x.length <= max;
const optStr = (x: unknown, max: number): boolean => x === undefined || str(x, max);
/** A finite, non-negative number (a file size: Infinity and NaN are refused). */
const size = (x: unknown): x is number => typeof x === "number" && Number.isFinite(x) && x >= 0 && x <= Number.MAX_SAFE_INTEGER;
const int = (x: unknown): x is number => typeof x === "number" && Number.isInteger(x) && x >= -1 && x <= Number.MAX_SAFE_INTEGER;
const bool = (x: unknown): x is boolean => typeof x === "boolean";
const strArray = (x: unknown, maxItems: number, maxLen: number): x is string[] => Array.isArray(x) && x.length <= maxItems && x.every((s) => str(s, maxLen));

function validField(f: unknown): f is FieldInfo {
  return isObj(f) && str(f.name, LIMITS.name) && str(f.type, 64) && optStr(f.autocomplete, LIMITS.name) && optStr(f.label, LIMITS.label) && optStr(f.value, LIMITS.text);
}

function validFields(x: unknown): x is FieldInfo[] {
  return Array.isArray(x) && x.length <= LIMITS.fields && x.every(validField);
}

function validContext(c: unknown): boolean {
  if (!isObj(c) || !str(c.pageUrl, LIMITS.url)) return false;
  if (c.formFields !== undefined && !validFields(c.formFields)) return false;
  if (c.formTarget !== undefined && !(isObj(c.formTarget) && str(c.formTarget.url, LIMITS.url) && str(c.formTarget.method, 16))) return false;
  if (c.compose !== undefined && !(isObj(c.compose) && bool(c.compose.hasRecipient) && bool(c.compose.hasBody))) return false;
  return true;
}

function validFrame(f: unknown): boolean {
  return isObj(f) && int(f.tabId) && int(f.frameId) && str(f.origin, LIMITS.url);
}

function validAction(a: unknown): a is InPageAction {
  if (!isObj(a) || !validFrame(a.frame) || !str(a.elementPath, LIMITS.path) || !validContext(a.context)) return false;
  switch (a.kind) {
    case "submit":
      return optStr(a.label, LIMITS.label) && isObj(a.form) && validFields(a.form.fields) && str(a.form.targetUrl, LIMITS.url) && str(a.form.method, 16);
    case "activate":
      return str(a.label, LIMITS.label) && str(a.role, 64) && str(a.tag, 64) && optStr(a.inputType, 64) && optStr(a.href, LIMITS.url);
    case "upload":
      return (
        Array.isArray(a.files) &&
        a.files.length <= LIMITS.files &&
        a.files.every((f) => isObj(f) && str(f.name, LIMITS.name) && size(f.size) && str(f.type, LIMITS.name)) &&
        optStr(a.targetUrl, LIMITS.url)
      );
    case "paste":
      return str(a.text, LIMITS.text);
    case "type":
      return validField(a.field) && str(a.value, LIMITS.text);
    default:
      return false;
  }
}

function validSnapshot(s: unknown): s is ActionSnapshot {
  return (
    isObj(s) &&
    int(s.tabId) &&
    int(s.frameId) &&
    str(s.frameOrigin, LIMITS.url) &&
    str(s.kind, 16) &&
    (s.actionClass === null || (typeof s.actionClass === "string" && (ACTION_CLASSES as readonly string[]).includes(s.actionClass))) &&
    str(s.elementPath, LIMITS.path) &&
    strArray(s.fieldNames, LIMITS.fields, LIMITS.name) &&
    str(s.valuesDigest, 64) &&
    str(s.targetOrigin, LIMITS.url) &&
    str(s.method, 16)
  );
}

function validPrint(p: unknown): p is PrivatePrint {
  return isObj(p) && str(p.fp, 128) && (p.kind === "long" || p.kind === "short") && str(p.domain, 253);
}

const VERDICTS: readonly string[] = ["deliver", "neutralize", "flag", "quarantine"];

/**
 * Whether a message stays within the total bounds: characters across all strings and keys, nesting depth,
 * and only finite numbers. Walks at most the budget, so an oversized message costs no more than a small one.
 */
export function withinMessageBounds(x: unknown, budget: number = LIMITS.message, maxDepth: number = LIMITS.depth): boolean {
  let left = budget;
  const walk = (v: unknown, depth: number): boolean => {
    if (typeof v === "string") return (left -= v.length + 1) >= 0;
    if (typeof v === "number") return Number.isFinite(v) && (left -= 8) >= 0;
    if (typeof v === "boolean" || v === null || v === undefined) return (left -= 1) >= 0;
    if (typeof v !== "object" || depth >= maxDepth) return false;
    if (Array.isArray(v)) {
      if ((left -= v.length + 1) < 0) return false;
      for (const item of v) if (!walk(item, depth + 1)) return false;
      return true;
    }
    for (const [k, item] of Object.entries(v)) {
      if ((left -= k.length + 1) < 0 || !walk(item, depth + 1)) return false;
    }
    return true;
  };
  return walk(x, 0);
}

/** A content message, or null if any field is missing, mistyped or over its bound, or the whole is over the total bound. */
export function parseContentMessage(x: unknown): ContentMessage | null {
  if (!isObj(x) || !withinMessageBounds(x)) return null;
  switch (x.type) {
    case "frame.hello":
      return str(x.url, LIMITS.url) && bool(x.top) ? { type: "frame.hello", url: x.url, top: x.top } : null;
    case "page.scanned":
      if (!str(x.url, LIMITS.url) || typeof x.verdict !== "string" || !VERDICTS.includes(x.verdict) || !strArray(x.reasons, LIMITS.reasons, 64) || !bool(x.scanIncomplete) || !optStr(x.preview, LIMITS.preview)) return null;
      return { type: "page.scanned", url: x.url, verdict: x.verdict as ContentVerdict, reasons: x.reasons, scanIncomplete: x.scanIncomplete, ...(x.preview !== undefined ? { preview: x.preview as string } : {}) };
    case "action.check":
      return validAction(x.action) ? { type: "action.check", action: x.action } : null;
    case "private.prints":
      return Array.isArray(x.prints) && x.prints.length <= LIMITS.prints && x.prints.every(validPrint) ? { type: "private.prints", prints: x.prints } : null;
    case "approval.redeem":
      return str(x.token, LIMITS.token) && x.token.length > 0 && validSnapshot(x.snapshot) ? { type: "approval.redeem", token: x.token, snapshot: x.snapshot } : null;
    default:
      return parseLeakAgentLogContent(x) ?? parseGuardNavMessage(x);
  }
}

// ---- guard/nav: content guard and navigation policy (owned by the guard/nav lane) ----------------

/**
 * - `tab.mode`: a frame asks, at document_start, whether agent mode is on, so a page loaded during an agent
 *   session is neutralised without waiting for the next `agent.mode` broadcast. Reply: TabModeReply.
 * - `nav.hosts`: raw-IP and DNS-exfil-shaped hosts the frame's links point to (engine isRawIp /
 *   isDnsExfilShape, checked again by the worker), so the agent-mode session rules can block exactly
 *   those hosts on top of the coarse regex. Host names only, never paths or queries.
 * - `nav.blocked`: the frame cancelled a navigation itself (a javascript: link in agent mode), for the log.
 */
export type GuardNavMessage =
  | { type: "tab.mode" }
  | { type: "nav.hosts"; hosts: string[] }
  | { type: "nav.blocked"; rule: "nav.script_url"; scheme: "javascript" | "data" };

export interface TabModeReply {
  agentMode: boolean;
}

export const GUARD_NAV_LIMITS = { hosts: 200, host: 253 } as const;

const HOST_RE = /^[a-z0-9.:[\]-]+$/;

function parseGuardNavMessage(x: Obj): GuardNavMessage | null {
  switch (x.type) {
    case "tab.mode":
      return { type: "tab.mode" };
    case "nav.hosts":
      return Array.isArray(x.hosts) && x.hosts.length <= GUARD_NAV_LIMITS.hosts && x.hosts.every((h) => str(h, GUARD_NAV_LIMITS.host) && h.length > 0 && HOST_RE.test(h)) ? { type: "nav.hosts", hosts: x.hosts as string[] } : null;
    case "nav.blocked":
      return x.rule === "nav.script_url" && (x.scheme === "javascript" || x.scheme === "data") ? { type: "nav.blocked", rule: x.rule, scheme: x.scheme } : null;
    default:
      return null;
  }
}

/** A UI message, or null. */
export function parseUiMessage(x: unknown): UiMessage | null {
  if (!isObj(x) || !withinMessageBounds(x)) return null;
  switch (x.type) {
    case "ui.state":
      return { type: "ui.state" };
    case "ui.approve":
    case "ui.deny":
      return str(x.approvalId, LIMITS.token) && x.approvalId.length > 0 ? { type: x.type, approvalId: x.approvalId } : null;
    case "ui.agentMode":
      return bool(x.on) ? { type: "ui.agentMode", on: x.on } : null;
    default:
      return parseLeakAgentLogUi(x);
  }
}

/** A worker message as a content script receives it, or null (content scripts accept only messages from the worker). */
export function parseWorkerMessage(x: unknown): WorkerToContentMessage | null {
  if (!isObj(x)) return null;
  switch (x.type) {
    case "approval.granted":
      return str(x.approvalId, LIMITS.token) && str(x.token, LIMITS.token) ? { type: "approval.granted", approvalId: x.approvalId, token: x.token } : null;
    case "approval.denied":
      return str(x.approvalId, LIMITS.token) ? { type: "approval.denied", approvalId: x.approvalId } : null;
    case "agent.mode":
      return bool(x.on) ? { type: "agent.mode", on: x.on } : null;
    default:
      return parseLeakAgentLogWorker(x);
  }
}

// =============================================================================
// ---- leak/agent/log (leak lane) ---------------------------------------------
// The leak guard's field checks and context, agent detection signals, and the
// decision log and settings the side panel's log/settings view reads. Owned
// by the leak lane; the other lanes do not depend on these types.
// =============================================================================

/** Content script -> worker. */
export type LeakAgentLogContentMessage =
  /** A field value, paste or form about to carry data. The worker re-decides, logs, and creates the approval. Reply: LeakReply. */
  | { type: "leak.guard"; via: "type" | "paste" | "submit"; text: string; destinationHost: string; checkoutMerchantHost?: string; elementPath: string; fieldName: string }
  /** The frame asks for its leak context (agent mode, trust flags, print hashes). Reply: LeakContext. */
  | { type: "leak.context" }
  /** An agent signal seen in the page (design 8): navigator.webdriver is true. Reply: { agentMode: boolean }. */
  | { type: "agent.signal"; signal: "webdriver" };

/** Worker -> content script: the leak context changed (pushed to every tab). */
export type LeakAgentLogWorkerMessage = { type: "leak.context"; context: LeakContext };

/** Extension UI -> worker. */
export type LeakAgentLogUiMessage =
  | { type: "ui.log.list"; limit?: number }
  | { type: "ui.log.verify" }
  | { type: "ui.log.export" }
  | { type: "ui.log.clear" }
  | { type: "ui.settings.get" }
  | { type: "ui.settings.set"; patch: SettingsPatch };

/** One decision as the log keeps it (design 9): never page text or field values. */
export interface LogEntry {
  /** ms since epoch. */
  at: number;
  /** Registrable domain of the tab (the full origin only if the person opts in). */
  site: string;
  actionClass: ActionClass | null;
  verdict: Verdict;
  rules: RuleId[];
  approval?: "approved" | "denied" | "expired" | "redeemed" | "refused";
  /** The action fingerprint the approval was bound to. */
  binding?: string;
  /** Escaped, truncated hidden-text evidence; only with "keep evidence" on. */
  evidence?: string;
  /** What kind of record this is when it is not an action decision. */
  event?: "agent_mode_on" | "agent_mode_off" | "leak" | "settings_changed" | "link_taint" | "log_cleared" | "quarantine" | "log_throttled";
  /** Short fixed codes (finding kinds, signals); never values. */
  detail?: string[];
}

export interface ChainedEntry extends LogEntry {
  seq: number;
  prevHash: string;
  hash: string;
}

export interface LogVerifyReply {
  /** The first sequence number whose hash or link does not match, or null when the chain is intact. */
  brokenAt: number | null;
  count: number;
}

/** The person's settings (chrome.storage.local). */
export interface Settings {
  /** Days the log keeps entries (design 9: 30 by default). */
  retentionDays: number;
  /** Keep up to 200 escaped characters of hidden text that triggered a quarantine. */
  keepEvidence: boolean;
  /** navigator.webdriver === true turns agent mode on (a strong signal, design 8). */
  detectWebdriver: boolean;
  /** Agent-mode-off gating of the always-on classes (agent mode gates them regardless). */
  alwaysOn: Record<AlwaysOnClass, boolean>;
  /** Host patterns the person trusts: pages from them do not make a tab untrusted (engine Policy.trustedHosts). */
  trustedHosts: string[];
  /** Host patterns the person marks sensitive, on top of the bundled list (engine Policy.privateHosts). */
  privateHosts: string[];
}

export type SettingsPatch = Partial<Omit<Settings, "alwaysOn">> & { alwaysOn?: Partial<Record<AlwaysOnClass, boolean>> };

/** Entries per site list, and the shape of one entry ("example.com", "*.example.com", "=host.example.com"). */
export const SITE_LIST_MAX = 200;
export const SITE_PATTERN_RE = /^(?:=|\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** A site list entry as typed, normalised (lower case, no spaces or trailing dots), or null when it is not one. */
export function normalizeSitePattern(raw: string): string | null {
  const p = raw.trim().toLowerCase().replace(/\.+$/, "");
  return p.length > 0 && p.length <= 253 && SITE_PATTERN_RE.test(p) ? p : null;
}

export interface SettingsReply {
  ok: boolean;
  settings: Settings;
  /** Changes refused (weakening a setting while agent mode is on). */
  refused?: string[];
}

export const RETENTION_DAYS_MIN = 1;
export const RETENTION_DAYS_MAX = 365;

function validLeakContext(c: unknown): c is LeakContext {
  return (
    isObj(c) &&
    bool(c.agentMode) &&
    bool(c.untrusted) &&
    bool(c.quarantined) &&
    bool(c.private) &&
    Array.isArray(c.prints) &&
    c.prints.length <= LIMITS.prints &&
    c.prints.every(validPrint) &&
    optStr(c.printSalt, 64) &&
    Array.isArray(c.secretAllow) &&
    c.secretAllow.length <= 500 &&
    c.secretAllow.every((a) => isObj(a) && str(a.fingerprint, 256) && strArray(a.hosts, 100, 253)) &&
    strArray(c.paymentHosts, 500, 253)
  );
}

function parseLeakAgentLogContent(x: Obj): LeakAgentLogContentMessage | null {
  switch (x.type) {
    case "leak.guard":
      if ((x.via !== "type" && x.via !== "paste" && x.via !== "submit") || !str(x.text, LIMITS.text) || !str(x.destinationHost, 253) || !optStr(x.checkoutMerchantHost, 253) || !str(x.elementPath, LIMITS.path) || !str(x.fieldName, LIMITS.name)) return null;
      return {
        type: "leak.guard",
        via: x.via,
        text: x.text,
        destinationHost: x.destinationHost,
        ...(x.checkoutMerchantHost !== undefined ? { checkoutMerchantHost: x.checkoutMerchantHost as string } : {}),
        elementPath: x.elementPath,
        fieldName: x.fieldName,
      };
    case "leak.context":
      return { type: "leak.context" };
    case "agent.signal":
      return x.signal === "webdriver" ? { type: "agent.signal", signal: "webdriver" } : null;
    default:
      return null;
  }
}

function parseLeakAgentLogWorker(x: Obj): LeakAgentLogWorkerMessage | null {
  return x.type === "leak.context" && validLeakContext(x.context) ? { type: "leak.context", context: x.context } : null;
}

function parseSettingsPatch(p: unknown): SettingsPatch | null {
  if (!isObj(p)) return null;
  const out: SettingsPatch = {};
  for (const k of Object.keys(p)) if (!["retentionDays", "keepEvidence", "detectWebdriver", "alwaysOn", "trustedHosts", "privateHosts"].includes(k)) return null;
  for (const key of ["trustedHosts", "privateHosts"] as const) {
    const list = p[key];
    if (list === undefined) continue;
    if (!strArray(list, SITE_LIST_MAX, 253)) return null;
    const norm = list.map(normalizeSitePattern);
    if (norm.some((x) => x === null)) return null;
    out[key] = [...new Set(norm as string[])];
  }
  if (p.retentionDays !== undefined) {
    if (typeof p.retentionDays !== "number" || !Number.isInteger(p.retentionDays) || p.retentionDays < RETENTION_DAYS_MIN || p.retentionDays > RETENTION_DAYS_MAX) return null;
    out.retentionDays = p.retentionDays;
  }
  if (p.keepEvidence !== undefined) {
    if (!bool(p.keepEvidence)) return null;
    out.keepEvidence = p.keepEvidence;
  }
  if (p.detectWebdriver !== undefined) {
    if (!bool(p.detectWebdriver)) return null;
    out.detectWebdriver = p.detectWebdriver;
  }
  if (p.alwaysOn !== undefined) {
    if (!isObj(p.alwaysOn)) return null;
    const a: Partial<Record<AlwaysOnClass, boolean>> = {};
    for (const [k, v] of Object.entries(p.alwaysOn)) {
      if (!(ALWAYS_ON_CLASSES as readonly string[]).includes(k) || !bool(v)) return null;
      a[k as AlwaysOnClass] = v;
    }
    out.alwaysOn = a;
  }
  return out;
}

function parseLeakAgentLogUi(x: Obj): LeakAgentLogUiMessage | null {
  switch (x.type) {
    case "ui.log.list":
      if (x.limit !== undefined && !(typeof x.limit === "number" && Number.isInteger(x.limit) && x.limit > 0 && x.limit <= 10_000)) return null;
      return x.limit === undefined ? { type: "ui.log.list" } : { type: "ui.log.list", limit: x.limit as number };
    case "ui.log.verify":
    case "ui.log.export":
    case "ui.log.clear":
    case "ui.settings.get":
      return { type: x.type };
    case "ui.settings.set": {
      const patch = parseSettingsPatch(x.patch);
      return patch === null ? null : { type: "ui.settings.set", patch };
    }
    default:
      return null;
  }
}

// =============================================================================
// ---- gate/approvals ------------------------------------------------------------
// Messages added by the gate and approvals lane. Kept in their own section with their own parsers so the
// messages above stay untouched; the worker and content script try these
// parsers after the ones above.
// =============================================================================

/** What the gate needs to decide, synchronously, whether to hold a classified action and ask the worker. */
export interface GatePosture {
  agentMode: boolean;
  /** The tab carries a quarantine verdict (every class is gated). */
  quarantined: boolean;
}

/** Content script -> worker: the gate asks for its tab's posture at document_start. Reply: GatePosture. */
export type GateContentMessage = { type: "gate.posture" };

/** Worker -> content script: the tab's posture changed (agent mode, quarantine). */
export type GateWorkerMessage = { type: "gate.posture"; posture: GatePosture };

/** Extension UI -> worker. */
export type GateUiMessage =
  /** Everything the approval surfaces show. Reply: ApprovalsState. */
  | { type: "ui.approvals" }
  /** "Approve, and allow this class on this site for this agent session" (design 9); refused for consent and account security. */
  | { type: "ui.approveForSite"; approvalId: string };

/** Worker -> extension pages (chrome.runtime.sendMessage; content scripts never receive it): re-fetch state. */
export type GateUiBroadcast = { type: "ui.changed" };

/** What an approval is for, as the surfaces show it. */
export type ApprovalSubject = "action" | "download" | "agent_mode_off" | "leak" | "navigation";

/** An approval as the side panel and approval window show it: masked, page text escaped by the UI. */
export interface GateApprovalView extends Omit<ApprovalView, "kind"> {
  subject: ApprovalSubject;
  kind: InPageAction["kind"] | "download" | "agent_mode_off" | "navigate";
  /** The full page URL the action came from ("" when none). Page-controlled: shown escaped. */
  pageUrl: string;
  /** For downloads: the file name the site offered. Page-controlled: shown escaped. */
  filename?: string;
  /** Whether "approve for this site for this agent session" is offered (design 9). */
  siteGrantable: boolean;
  /** The engine verdict was deny with a side-panel override (quarantine in agent mode): the reason must be shown. */
  overridesDeny: boolean;
}

export interface ApprovalsState {
  agentMode: boolean;
  approvals: GateApprovalView[];
  coverageNote: string;
}

export function parseGateContentMessage(x: unknown): GateContentMessage | null {
  if (!isObj(x)) return null;
  return x.type === "gate.posture" && Object.keys(x).length === 1 ? { type: "gate.posture" } : null;
}

export function parseGateWorkerMessage(x: unknown): GateWorkerMessage | null {
  if (!isObj(x) || x.type !== "gate.posture" || !isObj(x.posture)) return null;
  const p = x.posture;
  return bool(p.agentMode) && bool(p.quarantined) ? { type: "gate.posture", posture: { agentMode: p.agentMode, quarantined: p.quarantined } } : null;
}

export function parseGateUiMessage(x: unknown): GateUiMessage | null {
  if (!isObj(x)) return null;
  switch (x.type) {
    case "ui.approvals":
      return { type: "ui.approvals" };
    case "ui.approveForSite":
      return str(x.approvalId, LIMITS.token) && x.approvalId.length > 0 ? { type: "ui.approveForSite", approvalId: x.approvalId } : null;
    default:
      return null;
  }
}

/** Whether a value names a rule-table row (the log checks stored rows with it). */
export function isRuleId(x: unknown): x is RuleId {
  return typeof x === "string" && (RULE_IDS as readonly string[]).includes(x);
}

export function isGateUiBroadcast(x: unknown): x is GateUiBroadcast {
  return isObj(x) && x.type === "ui.changed";
}

// =============================================================================
// ---- native link ------------------------------------------------------
// The side panel's status line and switch for the link to the local firewall
// (design 10). The worker owns the link (src/worker/link.ts).
// =============================================================================

export type LinkState = "off" | "connecting" | "connected" | "unavailable" | "error";

export interface LinkStatus {
  enabled: boolean;
  state: LinkState;
  /** Why it is not connected, or what the firewall offers. */
  detail: string;
  capabilities: ("log" | "taint" | "approval")[];
  firewall?: string;
  /** Entries the firewall acknowledged in this browser session. */
  mirrored: number;
}

/** Extension UI -> worker. `ui.link.set` on needs the optional nativeMessaging permission granted first (the side panel asks). */
export type LinkUiMessage = { type: "ui.link.state" } | { type: "ui.link.set"; on: boolean };

export interface LinkSetReply {
  ok: boolean;
  /** "permission": not granted; "agent_mode": turning it off is refused while agent mode is on. */
  reason?: "permission" | "agent_mode";
}

export function parseLinkUiMessage(x: unknown): LinkUiMessage | null {
  if (typeof x !== "object" || x === null || Array.isArray(x)) return null;
  const o = x as Record<string, unknown>;
  if (o.type === "ui.link.state" && Object.keys(o).length === 1) return { type: "ui.link.state" };
  if (o.type === "ui.link.set" && typeof o.on === "boolean" && Object.keys(o).length === 2) return { type: "ui.link.set", on: o.on };
  return null;
}
