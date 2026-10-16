/**
 * The sensitive-action gate's rule table (design 5.3).
 *
 *   class                                          agent mode off   agent mode on
 *   oauth_consent, account_security, download_exec approve*         approve
 *   payment, send, delete                          allow            approve
 *   upload                                         allow            approve if the session is private or the target is new to it
 *   any class on a tab with a quarantine verdict   approve          deny (side-panel override, reason shown)
 *
 *   * on by default; the person can turn agent-mode-off gating off per class.
 *
 * A session grant ("approve for this site for this agent session") turns an
 * agent-mode approve into allow for a grantable class; it never applies to
 * consent or account security, and never lifts a quarantine deny.
 *
 * Grants and the upload "new target" test judge the frame's real origin (the
 * browser's, not the page's). A form action or upload target, which the page
 * controls, is judged as well and can only make the verdict stricter (BR3,
 * BR4): a grant must cover every judged host, and any judged host new to the
 * session makes an upload a new target.
 */
import { classify, type SiteAdapter } from "./classify.js";
import { hostOf, registrableDomain } from "./domain.js";
import { grantKey, type EffectiveTrust } from "./session.js";
import type { ActionClass, AlwaysOnClass, Decision, NormalizedAction, Policy } from "./types.js";
import { ALWAYS_ON_CLASSES } from "./types.js";

export interface GateInput {
  actionClass: ActionClass | null;
  /** The frame's host (a navigation's or download's URL host), or null when it has none. */
  targetHost: string | null;
  /** Page-controlled hosts the action also goes to (a form action, an upload target). They can only make the verdict stricter. */
  extraHosts?: readonly (string | null)[];
}

function judgedHosts(input: GateInput): (string | null)[] {
  return [input.targetHost, ...(input.extraHosts ?? [])];
}

function isAlwaysOn(c: ActionClass): c is AlwaysOnClass {
  return (ALWAYS_ON_CLASSES as readonly string[]).includes(c);
}

function hasGrant(trust: EffectiveTrust, hosts: readonly (string | null)[], c: ActionClass): boolean {
  if (c === "oauth_consent" || c === "account_security") return false;
  return hosts.length > 0 && hosts.every((h) => h !== null && trust.grants.has(grantKey(h, c)));
}

/** The gate's verdict for a classified action. */
export function decideGate(input: GateInput, trust: EffectiveTrust, policy: Policy): Decision {
  const c = input.actionClass;
  if (c === null) return { verdict: "allow", rule: "gate.unclassified", actionClass: null, reasons: [] };

  if (trust.quarantined) {
    return trust.agentMode
      ? { verdict: "deny", rule: "gate.quarantine", actionClass: c, reasons: ["quarantine_verdict", "agent_mode"], override: "side_panel_with_reason" }
      : { verdict: "approve", rule: "gate.quarantine", actionClass: c, reasons: ["quarantine_verdict"] };
  }

  if (isAlwaysOn(c)) {
    if (trust.agentMode) {
      if (c === "download_exec" && hasGrant(trust, judgedHosts(input), c)) return { verdict: "allow", rule: "gate.session_grant", actionClass: c, reasons: ["session_grant"] };
      return { verdict: "approve", rule: "gate.always_on", actionClass: c, reasons: ["always_on", "agent_mode"] };
    }
    return policy.alwaysOn[c]
      ? { verdict: "approve", rule: "gate.always_on", actionClass: c, reasons: ["always_on"] }
      : { verdict: "allow", rule: "gate.always_on", actionClass: c, reasons: ["always_on_disabled_by_person"] };
  }

  if (c === "upload") {
    if (!trust.agentMode) return { verdict: "allow", rule: "gate.upload", actionClass: c, reasons: [] };
    const newTarget = judgedHosts(input).some((h) => {
      const domain = h === null ? "" : registrableDomain(h);
      return domain === "" || !trust.sessionDomains.has(domain);
    });
    if (!trust.private && !newTarget) return { verdict: "allow", rule: "gate.upload", actionClass: c, reasons: ["known_target_public_session"] };
    if (hasGrant(trust, judgedHosts(input), c)) return { verdict: "allow", rule: "gate.session_grant", actionClass: c, reasons: ["session_grant"] };
    return { verdict: "approve", rule: "gate.upload", actionClass: c, reasons: [trust.private ? "private_session" : "new_target"] };
  }

  // payment, send, delete
  if (!trust.agentMode) return { verdict: "allow", rule: "gate.agent_mode", actionClass: c, reasons: [] };
  if (hasGrant(trust, judgedHosts(input), c)) return { verdict: "allow", rule: "gate.session_grant", actionClass: c, reasons: ["session_grant"] };
  return { verdict: "approve", rule: "gate.agent_mode", actionClass: c, reasons: ["agent_mode"] };
}

/** The host an action acts on, for grants and the upload "new target" test: the frame's real origin (a navigation's or download's URL). */
export function targetHostOf(action: NormalizedAction): string | null {
  switch (action.kind) {
    case "navigate":
    case "download":
      return hostOf(action.url);
    default:
      return hostOf(action.frame.origin);
  }
}

/** Page-controlled destinations of an action, judged on top of the frame: a form action, an upload's form target. */
export function extraHostsOf(action: NormalizedAction): (string | null)[] {
  const frameHost = targetHostOf(action);
  const extra = action.kind === "submit" ? action.form.targetUrl : action.kind === "upload" ? action.targetUrl : undefined;
  if (extra === undefined) return [];
  const h = hostOf(extra);
  // A target with no host (javascript:, an empty action resolved oddly) adds nothing the frame does not already cover.
  return h === null || h === frameHost ? [] : [h];
}

/** design 3: `decide(action, tabState, policy) -> Decision` for the gate. Classifies, then applies the rule table. */
export function decide(action: NormalizedAction, trust: EffectiveTrust, policy: Policy, adapters: readonly SiteAdapter[] = []): Decision {
  const cls = classify(action, adapters);
  const d = decideGate({ actionClass: cls.actionClass, targetHost: targetHostOf(action), extraHosts: extraHostsOf(action) }, trust, policy);
  return cls.signals.length > 0 ? { ...d, reasons: [...d.reasons, ...cls.signals] } : d;
}

/** Turning agent mode on is never gated; turning it off always is (design 8). */
export function decideAgentModeChange(turnOn: boolean): Decision {
  return turnOn
    ? { verdict: "allow", rule: "control.agent_mode_off", actionClass: null, reasons: ["turn_on"] }
    : { verdict: "approve", rule: "control.agent_mode_off", actionClass: null, reasons: ["turn_off_needs_person"] };
}
