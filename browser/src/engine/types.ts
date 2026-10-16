/**
 * The engine's vocabulary: normalized browser actions (design 5.1), action
 * classes (5.2), policy, and decisions. Plain, serializable data: the content
 * script builds actions from DOM activity, the worker keeps state in
 * chrome.storage.session, and the same shapes could later be judged inside
 * the coding firewall for `mcp__claude-in-chrome__*` calls (design 10).
 */

export const ACTION_CLASSES = ["payment", "send", "account_security", "oauth_consent", "upload", "download_exec", "delete"] as const;
export type ActionClass = (typeof ACTION_CLASSES)[number];

/** Classes gated even with agent mode off (design 5.3, first row). Each can be turned off in policy for agent-mode-off only. */
export const ALWAYS_ON_CLASSES = ["oauth_consent", "account_security", "download_exec"] as const;
export type AlwaysOnClass = (typeof ALWAYS_ON_CLASSES)[number];

/** Classes a person may approve "for this site for this agent session" (design 9): never consent or account security. */
export const SESSION_GRANTABLE_CLASSES: readonly ActionClass[] = ["payment", "send", "delete", "upload", "download_exec"];

/** Where an action happened: a frame of a tab. `origin` is the frame document's origin. */
export interface FrameRef {
  tabId: number;
  frameId: number;
  origin: string;
}

/**
 * One form field as the content script sees it. `value` is held in memory for
 * the leak guard and the binding digest; it is never logged or sent to the UI
 * unmasked.
 */
export interface FieldInfo {
  name: string;
  /** input type ("text", "password", "email", ...), "textarea", "select" or "contenteditable". */
  type: string;
  autocomplete?: string;
  label?: string;
  value?: string;
}

/** What the content script knows about the surroundings of a control, for classification. */
export interface ControlContext {
  /** The top-level page URL (the frame's own URL is in `FrameRef.origin`). */
  pageUrl: string;
  /** Fields of the form the control belongs to, if any. */
  formFields?: readonly FieldInfo[];
  /** A compose surface around the control: a recipient field and/or a message body. */
  compose?: { hasRecipient: boolean; hasBody: boolean };
  /**
   * Where the form a clicked control belongs to would post (its action URL, the control's own formaction when it
   * has one) and with which method. The approval binds to it, so a page cannot approve a click for one form
   * target and then replay it against another.
   */
  formTarget?: { url: string; method: string };
}

export interface FileInfo {
  name: string;
  size: number;
  type: string;
}

export type NormalizedAction =
  | { kind: "submit"; frame: FrameRef; elementPath: string; label?: string; form: { fields: readonly FieldInfo[]; targetUrl: string; method: string }; context: ControlContext }
  | { kind: "activate"; frame: FrameRef; elementPath: string; label: string; role: string; tag: string; inputType?: string; href?: string; context: ControlContext }
  | { kind: "upload"; frame: FrameRef; elementPath: string; files: readonly FileInfo[]; targetUrl?: string; context: ControlContext }
  | { kind: "paste"; frame: FrameRef; elementPath: string; text: string; context: ControlContext }
  | { kind: "type"; frame: FrameRef; elementPath: string; field: FieldInfo; value: string; context: ControlContext }
  | { kind: "navigate"; tabId: number; frameId: number; url: string; initiator?: string; resourceType: "main_frame" | "sub_frame" | "other"; viaLinkClick?: boolean }
  | { kind: "download"; tabId?: number; url: string; filename: string; mime: string };

export type ActionKind = NormalizedAction["kind"];

export interface Classification {
  actionClass: ActionClass | null;
  /** "adapter" is precise (a site adapter matched); "heuristic" is a generic match; null when unclassified. */
  source: "adapter" | "heuristic" | null;
  /** Short, fixed signal names for the log and the approval UI (never page text). */
  signals: string[];
}

/** The person's settings. Lives in chrome.storage.local; DEFAULT_POLICY is the install state. */
export interface Policy {
  /** Agent-mode-off gating of the always-on classes; agent mode on gates them regardless. */
  alwaysOn: Record<AlwaysOnClass, boolean>;
  /** Host patterns (network.hostMatches syntax) the person trusts. Default: none, so every origin is outside. */
  trustedHosts: readonly string[];
  /** Host patterns the person marks private, added to the bundled list. */
  privateHosts: readonly string[];
  /** Per-secret allow list: a fingerprint of the secret (secrets.fingerprint) and the hosts it may go to. */
  secretAllow: readonly { fingerprint: string; hosts: readonly string[] }[];
  /** Extra hosts the person treats as payment frames for cards (added to the bundled provider list). */
  paymentHosts: readonly string[];
  /** Agent origin set (design 7): host patterns an agent session may navigate to; null when off (the default). */
  originSet: readonly string[] | null;
}

export const DEFAULT_POLICY: Policy = Object.freeze({
  alwaysOn: Object.freeze({ oauth_consent: true, account_security: true, download_exec: true }),
  trustedHosts: Object.freeze([]),
  privateHosts: Object.freeze([]),
  secretAllow: Object.freeze([]),
  paymentHosts: Object.freeze([]),
  originSet: null,
});

/**
 * - allow: let it happen.
 * - log: let it happen, record it.
 * - warn: let it happen, tell the person in the page (agent mode off).
 * - approve: cancel it; it happens only after a person approves in extension UI.
 * - deny: cancel it; `override` says whether a person can still approve it, and where.
 */
export type Verdict = "allow" | "log" | "warn" | "approve" | "deny";

export interface Decision {
  verdict: Verdict;
  /** The rule-table row that produced the verdict (RULE_TABLE). */
  rule: RuleId;
  actionClass: ActionClass | null;
  /** Fixed reason codes for the log and the UI. */
  reasons: string[];
  /** For deny: the person can still approve from the side panel, with the reason shown. */
  override?: "side_panel_with_reason";
}

/** Every rule-table row (design 5.3, 6.2, 7). Tests cover each row with an allow case and a refusal case. */
export const RULE_TABLE = [
  { id: "gate.unclassified", table: "gate", summary: "Unclassified actions are allowed (the leak guard covers data in them)." },
  { id: "gate.quarantine", table: "gate", summary: "Any class on a tab with a quarantine verdict: approve with agent mode off; deny (side-panel override with reason) with agent mode on." },
  { id: "gate.always_on", table: "gate", summary: "oauth_consent, account_security, download_exec: approve in both modes (agent-mode-off gating can be turned off per class)." },
  { id: "gate.agent_mode", table: "gate", summary: "payment, send, delete: allow with agent mode off; approve with agent mode on." },
  { id: "gate.upload", table: "gate", summary: "upload: allow with agent mode off; approve with agent mode on when the session is private or the target is new to the session." },
  { id: "gate.session_grant", table: "gate", summary: "A person's 'approve for this site for this agent session' grant allows a grantable class; never consent or account security." },
  { id: "control.agent_mode_off", table: "control", summary: "Turning agent mode off needs an approval in extension UI; turning it on never does." },
  { id: "leak.none", table: "leak", summary: "No finding in the data: allow." },
  { id: "leak.secret", table: "leak", summary: "A secret shape to a host not on its allow list or its issuer: warn with agent mode off; approve with agent mode on." },
  { id: "leak.card_or_id", table: "leak", summary: "A card, IBAN or national id to a host that is not a payment frame or this checkout's merchant: warn off; approve on." },
  { id: "leak.seen_elsewhere", table: "leak", summary: "A private string seen on another registrable domain: log off; approve on." },
  { id: "leak.seen_elsewhere_quarantine", table: "leak", summary: "As leak.seen_elsewhere, on an untrusted tab with a quarantine verdict in agent mode: deny." },
  { id: "nav.none", table: "nav", summary: "No navigation rule matched: allow." },
  { id: "nav.capture_host", table: "nav", summary: "Capture and paste hosts: always blocked for subresources; blocked for main frames in agent mode." },
  { id: "nav.script_url", table: "nav", summary: "javascript: and data: top-level navigations: blocked in agent mode." },
  { id: "nav.high_entropy_new_origin", table: "nav", summary: "Data-carrying URL to a domain new to a private agent session: approve (redirect to the explanation page)." },
  { id: "nav.suspicious_host", table: "nav", summary: "Raw IPs, DNS-exfil-shaped hosts and cloud metadata addresses: approve in agent mode (metadata: block)." },
  { id: "nav.origin_set", table: "nav", summary: "With an agent origin set, a main-frame navigation outside it: approve in agent mode." },
] as const;

export type RuleId = (typeof RULE_TABLE)[number]["id"];
export const RULE_IDS: readonly RuleId[] = RULE_TABLE.map((r) => r.id);
