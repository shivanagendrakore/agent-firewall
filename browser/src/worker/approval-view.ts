/**
 * What the approval surfaces show (design 5.4): the action class, the origin
 * and its registrable domain, the control's label, the destination, a summary
 * of the fields with every value masked, and why the tab is untrusted. Built
 * once, when the approval is requested, and stored next to it; raw values never
 * reach storage or the UI (RR9): a field shows at most its first three
 * characters and its length, and a blocked navigation its host, how much data
 * the address carries and a salted digest of it.
 *
 * Page-controlled strings (labels, field names, URLs, file names) are kept
 * as text here and escaped by the UI (ui/view.ts escapeForDisplay).
 */
import type { ApprovalRecord } from "../engine/bindings.js";
import { valuesDigest, type ActionSnapshot } from "../engine/fingerprint.js";
import { hostOf, originOf, registrableDomain } from "../engine/domain.js";
import type { LeakFinding } from "../engine/leak.js";
import type { BrowserState } from "../engine/session.js";
import { SESSION_GRANTABLE_CLASSES, type Decision, type FieldInfo, type RuleId } from "../engine/types.js";
import { findPersonalData } from "../vendor/firewall/engine/pii.js";
import { findSecrets } from "../vendor/firewall/engine/secrets.js";
import type { GateApprovalView, InPageAction } from "../shared/messages.js";
import type { ApprovalMeta } from "./approvals.js";

const MAX_SHOWN = 120;
const MAX_FIELDS = 40;
/** Characters of an ordinary value the card shows: enough to recognise the field's content, not to read it. */
const PREVIEW_CHARS = 3;

function lastDigits(v: string, n: number): string {
  const d = v.replace(/\D/g, "");
  return d.length >= n + 4 ? d.slice(-n) : "";
}

/** An ordinary value as a masked preview: its first characters and its length, never the rest (RR9). */
export function maskedPreview(v: string): string {
  const chars = [...v];
  const n = chars.length;
  if (n <= PREVIEW_CHARS + 2) return `${"•".repeat(Math.max(4, n))} (${n} character${n === 1 ? "" : "s"})`;
  return `${chars.slice(0, PREVIEW_CHARS).join("")}… (${n} characters)`;
}

/**
 * A field value as the approval shows it: passwords, card fields, secrets and
 * personal ids fully masked; any other value as a masked preview (first three
 * characters and the length), so the card says which field carries what kind
 * of content without the value ever being stored.
 */
export function maskField(f: FieldInfo): string {
  const v = f.value ?? "";
  if (v === "") return "(empty)";
  const ac = (f.autocomplete ?? "").toLowerCase();
  if (f.type === "password" || /\b(?:current|new)-password\b|one-time-code/.test(ac)) return "•".repeat(8);
  if (/\bcc-(?:csc)\b/.test(ac)) return "•••";
  if (/\bcc-number\b/.test(ac)) {
    const last = lastDigits(v, 4);
    return last === "" ? "•".repeat(8) : `•••• ${last}`;
  }
  // File names are what the person picks to send, not typed content: shown (escaped by the UI), truncated.
  if (f.type === "file") return v.split("\u0001").map((x) => x.split("\u0000")[0] ?? "").join(", ").slice(0, MAX_SHOWN);
  if (findSecrets(v).length > 0) return "(secret, hidden)";
  const pd = findPersonalData(v).filter((d) => d.kind !== "credential");
  if (pd.length > 0) {
    const last = lastDigits(v, 4);
    return last === "" ? "(personal data, hidden)" : `•••• ${last}`;
  }
  return maskedPreview(v);
}

function labelOf(a: InPageAction): string {
  switch (a.kind) {
    case "activate":
      return a.label;
    case "submit":
      return a.label ?? "";
    case "upload":
      return `${a.files.length} file${a.files.length === 1 ? "" : "s"}: ${a.files.map((f) => f.name).join(", ")}`;
    case "paste":
      return "Paste";
    case "type":
      return a.field.label ?? a.field.name;
  }
}

function targetOf(a: InPageAction): string {
  if (a.kind === "submit") return a.form.targetUrl;
  if (a.kind === "upload") return a.targetUrl ?? "";
  if (a.kind === "activate") return a.href ?? a.context.formTarget?.url ?? "";
  return "";
}

function fieldsOf(a: InPageAction): readonly FieldInfo[] {
  if (a.kind === "submit") return a.form.fields;
  if (a.kind === "upload") return a.files.map((f) => ({ name: f.name, type: "file", value: `${f.name}\u0000${f.size}` }));
  return a.context.formFields ?? [];
}

/** The metadata for an in-page action's approval. */
export function actionMeta(action: InPageAction, decision: Decision, untrustedBecause: readonly string[]): ApprovalMeta {
  return {
    subject: "action",
    label: labelOf(action).slice(0, 512),
    target: targetOf(action),
    pageUrl: action.context.pageUrl,
    fields: fieldsOf(action)
      .slice(0, MAX_FIELDS)
      .filter((f) => f.type !== "hidden")
      .map((f) => ({ name: f.label ?? f.name, masked: maskField(f) })),
    reasons: [...decision.reasons],
    untrustedBecause: [...untrustedBecause],
    overridesDeny: decision.verdict === "deny",
  };
}

export function downloadMeta(d: { url: string; filename: string; mime: string }, decision: Decision, untrustedBecause: readonly string[]): ApprovalMeta {
  return {
    subject: "download",
    label: d.filename.split(/[\\/]/).pop() ?? d.filename,
    target: d.url,
    pageUrl: "",
    fields: [],
    reasons: [...decision.reasons],
    untrustedBecause: [...untrustedBecause],
    overridesDeny: decision.verdict === "deny",
    download: d,
  };
}

/** Why a tab (and its agent session) is untrusted, as reason codes the approval surfaces explain. */
export function untrustedBecause(s: BrowserState, tabId: number): string[] {
  const tab = s.tabs.find((t) => t.tabId === tabId);
  const out = new Set<string>(tab?.reasons ?? []);
  if (s.session !== null) {
    if (s.session.untrusted) out.add("agent_session_untrusted");
    if (s.session.private) out.add("agent_session_private");
    if (s.session.quarantined) out.add("agent_session_quarantine");
  }
  return [...out];
}

const LEAK_VIA_LABEL = { type: "Typed into a field", paste: "Pasted into a field", submit: "Sent with a form" } as const;

/**
 * The metadata for a leak guard hold: how the data was going out, the field,
 * the destination host, and what was found (masked by the engine: first and
 * last characters only, never the value), with the rule's reasons.
 */
export function leakMeta(
  hold: { via: "type" | "paste" | "submit"; fieldName: string; destinationHost: string },
  decision: Decision,
  findings: readonly LeakFinding[],
  untrusted: readonly string[],
): ApprovalMeta {
  return {
    subject: "leak",
    label: `${LEAK_VIA_LABEL[hold.via]}${hold.fieldName === "" ? "" : `: ${hold.fieldName}`}`.slice(0, 512),
    target: hold.destinationHost,
    pageUrl: "",
    fields: findings.slice(0, MAX_FIELDS).map((f) => ({ name: f.name, masked: f.kind === "seen_elsewhere" ? `shown on ${f.seenOn ?? "another site"}` : f.masked })),
    reasons: [...decision.reasons],
    untrustedBecause: [...untrusted],
    overridesDeny: false,
  };
}

/**
 * The snapshot a blocked navigation's approval binds to. Not bound to a frame (tab and frame -1, like a
 * download): the tab has already moved to the explanation page, and the worker, not a content script,
 * replays the navigation. The digest covers the tab and the address's salted digest (guard-nav.ts), never
 * the address itself.
 */
export function navigationSnapshot(tabId: number, origin: string, addressDigest: string): ActionSnapshot {
  return {
    tabId: -1,
    frameId: -1,
    frameOrigin: origin,
    kind: "navigate",
    actionClass: null,
    elementPath: `navigate:tab:${tabId}`,
    fieldNames: ["tab", "url"],
    valuesDigest: valuesDigest([
      { name: "tab", type: "text", value: String(tabId) },
      { name: "url", type: "url-digest", value: addressDigest },
    ]),
    targetOrigin: origin,
    method: "GET",
  };
}

/**
 * The metadata for a blocked navigation: the destination origin, how much data the address carries and its
 * salted digest; never the path or query (they may be the person's data). The address itself is held by
 * guard-nav.ts in memory-only session storage until the tab moves on, and is never part of this record (RR9).
 */
export function navigationMeta(req: { tabId: number; url: string; rule: RuleId; reasons: readonly string[]; digest?: string }, untrusted: readonly string[]): ApprovalMeta {
  let chars = 0;
  try {
    const u = new URL(req.url);
    chars = u.search.length + Math.max(0, u.pathname.length - 1);
  } catch {
    // Unparsable: shown without a count.
  }
  return {
    subject: "navigation",
    label: chars === 0 ? "No data in the address" : `${chars} characters of data in the address (not shown)`,
    target: originOf(req.url) ?? "",
    pageUrl: "",
    fields: [],
    reasons: [...req.reasons],
    untrustedBecause: [...untrusted],
    overridesDeny: false,
    navigation: { tabId: req.tabId, host: hostOf(req.url) ?? "", chars, digest: req.digest ?? "", rule: req.rule },
  };
}

export function agentModeOffMeta(): ApprovalMeta {
  return { subject: "agent_mode_off", label: "Turn agent mode off", target: "", pageUrl: "", fields: [], reasons: ["turn_off_needs_person"], untrustedBecause: [], overridesDeny: false };
}

/** The view of one approval for the side panel and the approval window. */
export function viewOf(r: ApprovalRecord, m: ApprovalMeta | undefined): GateApprovalView {
  const s = r.snapshot;
  const subject = m?.subject ?? (r.purpose === "agent_mode_off" ? "agent_mode_off" : "action");
  const origin = subject === "download" || subject === "navigation" ? s.targetOrigin : s.frameOrigin;
  const kind: GateApprovalView["kind"] = subject === "agent_mode_off" ? "agent_mode_off" : s.kind;
  const view: GateApprovalView = {
    approvalId: r.id,
    subject,
    actionClass: s.actionClass,
    kind,
    origin: subject === "agent_mode_off" ? "" : origin,
    domain: subject === "agent_mode_off" ? "" : registrableDomain(hostOf(origin) ?? ""),
    label: m?.label ?? "",
    target: m?.target ?? s.targetOrigin,
    pageUrl: m?.pageUrl ?? "",
    fields: m?.fields ?? s.fieldNames.map((name) => ({ name, masked: "" })),
    reasons: m?.reasons ?? [],
    untrustedBecause: m?.untrustedBecause ?? [],
    createdAt: r.createdAt,
    expiresAt: r.expiresAt,
    siteGrantable: subject !== "agent_mode_off" && s.actionClass !== null && SESSION_GRANTABLE_CLASSES.includes(s.actionClass) && !(m?.overridesDeny ?? false),
    overridesDeny: m?.overridesDeny ?? false,
  };
  if (m?.download !== undefined) view.filename = m.download.filename;
  return view;
}
