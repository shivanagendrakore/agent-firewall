/**
 * Shared view logic for the side panel, the approval window and the popup.
 * Pure (no chrome.*, no DOM), so copy, escaping and the approve gesture are
 * unit-tested.
 *
 * Copy rule (design 1, threat model 3): never say "protected" for an agent
 * class the threat model marks as not holding. The status line says what is
 * on, not that the person is safe.
 */
import type { ActionClass } from "../engine/types.js";
import type { GateApprovalView, LinkStatus, UiState } from "../shared/messages.js";
import { displayHost } from "./host-display.js";

export function modeLine(s: Pick<UiState, "agentMode">): string {
  return s.agentMode ? "Agent mode is on: sensitive actions wait for your approval here." : "Agent mode is off. Account security, OAuth consent and executable downloads still wait for your approval.";
}

export function pendingLine(s: { pending: readonly unknown[] }): string {
  const n = s.pending.length;
  return n === 0 ? "Nothing is waiting for your approval." : `${n} action${n === 1 ? "" : "s"} waiting for your approval in the side panel.`;
}

/** The side panel's status line for the link to the local firewall (design 10): what it does now, never "protected". */
export function linkLine(s: Pick<LinkStatus, "enabled" | "state" | "detail">): string {
  if (!s.enabled) return "Link to the local firewall: off.";
  const head = s.state === "connected" ? "Link to the local firewall: connected." : s.state === "connecting" ? "Link to the local firewall: connecting." : "Link to the local firewall: not connected. This extension keeps deciding on its own.";
  return `${head} ${s.detail}`;
}

export function linkButtonLabel(s: Pick<LinkStatus, "enabled">): string {
  return s.enabled ? "Turn the link off" : "Link to the local firewall…";
}

// ---- gate/approvals ------------------------------------------------------------

/**
 * Page text as the approval UI shows it (threat model 22): control, format
 * (bidi, zero-width, tag characters) and private-use characters made visible
 * as their code points, whitespace collapsed, truncated. The result is set
 * with textContent, never parsed as HTML.
 */
export function escapeForDisplay(text: string, max = 300): string {
  // Format characters first (\s would swallow U+FEFF), keeping ordinary whitespace for the collapse.
  const shown = text.replace(/[\p{Cf}\p{Co}]|(?![\t\n\r\f\v])\p{Cc}/gu, (ch) => `[U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}]`).replace(/\s+/g, " ");
  const chars = Array.from(shown.trim());
  return chars.length > max ? `${chars.slice(0, max).join("")}…` : chars.join("");
}

const CLASS_TITLE: Record<ActionClass, string> = {
  payment: "Payment",
  send: "Send a message",
  account_security: "Account security change",
  oauth_consent: "Grant an app access to your account",
  upload: "Upload files",
  download_exec: "Download a program or installer",
  delete: "Delete",
};

export function approvalTitle(view: Pick<GateApprovalView, "subject" | "actionClass" | "domain">): string {
  // An internationalised domain in Unicode and in its xn-- form (m12).
  const v = { ...view, domain: displayHost(view.domain) };
  if (v.subject === "agent_mode_off") return "Turn agent mode off";
  if (v.subject === "navigation") return v.domain === "" ? "Open a blocked address" : `Open ${v.domain} (blocked navigation)`;
  if (v.subject === "leak") return v.domain === "" ? "Private data held back" : `Private data held back on ${v.domain}`;
  const what = v.actionClass === null ? "Action" : CLASS_TITLE[v.actionClass];
  return v.domain === "" ? what : `${what} on ${v.domain}`;
}

const REASON_WORDS: Record<string, string> = {
  agent_mode: "Agent mode is on.",
  always_on: "This kind of action always needs your approval.",
  quarantine_verdict: "The page showed hidden instructions aimed at AI agents.",
  private_session: "The agent has seen private data in this session.",
  new_target: "It goes to a site new to this agent session.",
  turn_off_needs_person: "Turning agent mode off needs your approval, so an agent cannot do it.",
  card_fields: "The form has card fields.",
  payment_frame: "It is inside a payment provider's frame.",
  payment_label: "The control is labelled as a purchase.",
  compose_with_recipient: "It sends a message you are composing.",
  compose_body: "It posts text you are composing.",
  new_password_field: "The form sets a new password.",
  security_label: "The control changes account security.",
  security_settings_path: "It is on a security settings page.",
  oauth_endpoint: "It is an app access (OAuth) consent page.",
  consent_path_and_label: "It looks like an app access (OAuth) consent page.",
  destructive_label: "The control deletes something.",
  file_input: "Files are being given to the page.",
  executable_download: "The file is a program, installer or macro document.",
  outside_origin: "The tab showed a site outside your trusted list.",
  flag_verdict: "The page had text addressed to AI agents.",
  scan_incomplete: "The page was too large to scan completely.",
  inherited: "The tab was opened by an untrusted tab.",
  private_origin: "The tab showed a private site (mail, bank, account).",
  private_data: "The tab showed private data.",
  agent_session_untrusted: "The agent session has seen outside content.",
  agent_session_private: "The agent session has seen private data.",
  agent_session_quarantine: "The agent session saw hidden instructions aimed at AI agents.",
  secret_shape: "It contains what looks like a secret (an API key, token or password).",
  personal_data: "It contains a card number, bank account or national id.",
  seen_elsewhere: "It contains private text the agent saw on another site.",
  raw_ip: "The address is a raw IP address.",
  dns_exfil_shape: "The host name is shaped to carry data out through DNS.",
  data_in_url: "The address carries a long, random-looking value.",
  new_origin: "The site is new to this agent session.",
  outside_origin_set: "The site is outside the sites you allowed for this agent task.",
};

export function reasonText(code: string): string {
  const known = REASON_WORDS[code];
  if (known !== undefined) return known;
  const adapter = /^adapter:([a-z_]+):/.exec(code);
  if (adapter !== null) return `Recognised by LaunchSafe's ${adapter[1]?.replace(/_/g, " ")} rules.`;
  return escapeForDisplay(code, 80);
}

export function expiresText(expiresAt: number, now: number): string {
  const s = Math.max(0, Math.round((expiresAt - now) / 1000));
  if (s <= 0) return "Expired.";
  return s >= 60 ? `Expires in ${Math.ceil(s / 60)} min.` : `Expires in ${s} s.`;
}

/** The fields of a pointer event the gesture reads. */
export interface PointerLike {
  isTrusted: boolean;
  button: number;
}

/** A card's Approve button arms this long after it appears, so a click aimed at something that just moved cannot land on it. */
export const ARM_MS = 400;
/** A press held longer than this is not taken as an approval. */
export const MAX_PRESS_MS = 10_000;

/** The fields of a keyboard event the gesture reads. */
export interface KeyLike {
  isTrusted: boolean;
  key: string;
  repeat: boolean;
}

const APPROVE_KEYS = new Set(["Enter", " "]);

/**
 * The approve gesture (design 5.4), by pointer or keyboard, after the button has armed:
 *
 * - pointer: a fresh, trusted primary-button press and release on the button;
 * - keyboard: the button focused after it armed (Tab, a trusted focus), then a trusted, non-repeating Enter or
 *   Space pressed and released on it. The card's own code never moves focus to the button, and a held-down key
 *   (auto-repeat) never counts, so a person typing in another window when the approval window opens cannot
 *   approve by accident.
 *
 * Why keyboard is as safe as the pointer: our pages are extension pages that page script, and agents whose
 * input goes to a tab (classes A, B, C), cannot reach or send events to; an event marked trusted there came from
 * the person's own input devices or from the browser's remote debugging or the OS, which can produce trusted
 * pointer events just as well (threat model 3, rows D and E). A script-dispatched click or key is never trusted
 * and never approves.
 */
export class ApproveGesture {
  private downAt: number | null = null;
  private focusedAt: number | null = null;
  private keyDownAt: number | null = null;
  private key: string | null = null;
  constructor(
    private readonly now: () => number,
    private readonly armedAt: number,
  ) {}

  /** The button received focus (from a trusted focus event). */
  focus(e: { isTrusted: boolean }): void {
    this.focusedAt = e.isTrusted ? this.now() : null;
  }

  blur(): void {
    this.focusedAt = null;
    this.keyDownAt = null;
    this.key = null;
  }

  /** A key pressed on the button; true when it is an approve key (the caller cancels its default click). */
  keyDown(e: KeyLike): boolean {
    if (!APPROVE_KEYS.has(e.key)) return false;
    const ok = e.isTrusted && !e.repeat && this.armed() && this.focusedAt !== null && this.focusedAt >= this.armedAt;
    this.keyDownAt = ok ? this.now() : null;
    this.key = ok ? e.key : null;
    return true;
  }

  /** True exactly when this key release completes an approval gesture. */
  keyUp(e: KeyLike): boolean {
    const ok = this.keyDownAt !== null && e.isTrusted && e.key === this.key && this.now() - this.keyDownAt <= MAX_PRESS_MS;
    this.keyDownAt = null;
    this.key = null;
    return ok;
  }

  armed(): boolean {
    return this.now() >= this.armedAt;
  }

  down(e: PointerLike): void {
    this.downAt = e.isTrusted && e.button === 0 && this.armed() ? this.now() : null;
  }

  /** True exactly when this release completes an approval gesture. */
  up(e: PointerLike): boolean {
    const ok = this.downAt !== null && e.isTrusted && e.button === 0 && this.now() - this.downAt <= MAX_PRESS_MS;
    this.downAt = null;
    return ok;
  }

  cancel(): void {
    this.downAt = null;
  }
}
