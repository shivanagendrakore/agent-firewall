/**
 * The data-leak guard's checks and decisions (design 6).
 *
 *   finding                   destination                                   off    on
 *   secret shape              any host not on its allow list or its issuer warn   approve
 *   card / IBAN / national id a host that is not a payment frame or this   warn   approve
 *                             checkout's merchant
 *   seen-elsewhere print      a different registrable domain               log    approve
 *                             ... on an untrusted, quarantined tab          log    deny
 *
 * Published test card numbers, test IBANs, specimen ids and test keys are not
 * findings. Findings carry masked values only.
 *
 * Two hosts are judged when both are known: the frame the data is in (its
 * origin comes from the browser, never the page) and the destination (a
 * submit's form action, which the page controls). An exemption ("goes to its
 * issuer", "a payment frame", "this checkout's merchant") holds only when it
 * holds for the frame; the destination can only make the decision stricter
 * (BR19b). A checkout merchant is a known checkout host (the checkout
 * adapters' sites, or a host the person added to paymentHosts), never one a
 * page names itself (BR9).
 */
import { findPersonalData, isKnownTestValue } from "../vendor/firewall/engine/pii.js";
import { hostMatches } from "../vendor/firewall/engine/network.js";
import { allGoingToIssuer, decodedVariants, findSecrets, fingerprint, isTestSecret, type SecretHit } from "../vendor/firewall/engine/secrets.js";
import { CHECKOUT_MERCHANT_HOSTS } from "./adapters.js";
import { isPaymentFrameHost } from "./classify.js";
import { sameSite } from "./domain.js";
import { seenElsewhere, type PrivatePrint } from "./private-data.js";
import { capPrints, type EffectiveTrust } from "./session.js";
import { valuesDigest, type ActionSnapshot } from "./fingerprint.js";
import type { Decision, Policy } from "./types.js";

export type LeakKind = "secret" | "card" | "iban" | "national_id" | "seen_elsewhere";

export interface LeakFinding {
  kind: LeakKind;
  /** The detector's name ("GitHub token", "card"), or "private string" for a print. */
  name: string;
  /** First and last characters only, for the approval UI. */
  masked: string;
  /** For seen_elsewhere: the registrable domain the string was shown on. */
  seenOn?: string;
}

export interface LeakInput {
  /** The typed value, pasted text, or a submitted form's field values joined by newlines. */
  text: string;
  /** Where the data is going: the form target host for a submit, the field's frame host for type and paste. Page-controlled for a submit. */
  destinationHost: string;
  /**
   * The host of the frame the data is in, from the browser (the sender's
   * origin in the worker, the frame's own location in the content script).
   * When given, every exemption must also hold for it.
   */
  frameHost?: string;
  /** The checkout's merchant host, when the page has card fields. Counts only for a known checkout host. */
  checkoutMerchantHost?: string;
}

export function mask(value: string): string {
  const v = value.replace(/\s+/g, "");
  if (v.length <= 8) return "•".repeat(Math.max(4, v.length));
  return `${v.slice(0, 4)}…${v.slice(-2)}`;
}

function secretAllowed(hit: SecretHit, host: string, policy: Policy): boolean {
  if (allGoingToIssuer([hit], host)) return true;
  const fp = fingerprint(hit.value);
  return fp !== null && policy.secretAllow.some((a) => a.fingerprint === fp && a.hosts.some((h) => hostMatches(host, h)));
}

/**
 * Keys published as examples by their issuers (AWS documents its example key
 * ids as AKIA... ending in EXAMPLE), on top of the vendored test-key prefixes
 * (sk_test_, rk_test_, sk-test-, ...). Sending one leaks nothing.
 */
export function isPublishedTestKey(value: string): boolean {
  return isTestSecret(value) || /^(?:AKIA|ASIA)[0-9A-Z]{9}EXAMPLE$/.test(value);
}

/** Secrets in the text and its decoded variants (CometJacking base64-encoded its payload), minus test values. */
function secretsIn(text: string): SecretHit[] {
  const seen = new Set<string>();
  const out: SecretHit[] = [];
  for (const v of decodedVariants(text)) {
    for (const h of findSecrets(v)) {
      if (seen.has(h.value) || isPublishedTestKey(h.value)) continue;
      seen.add(h.value);
      out.push(h);
    }
  }
  return out;
}

/** A known checkout host (never one the page names itself) that a card may go to when the page has card fields. */
export function isKnownCheckoutMerchant(host: string, extra: readonly string[] = []): boolean {
  return host !== "" && (CHECKOUT_MERCHANT_HOSTS.some((p) => hostMatches(host, p)) || extra.some((p) => hostMatches(host, p)));
}

/** The hosts an exemption must hold for: the frame's (when known) and the destination. */
function judgedHosts(input: LeakInput): string[] {
  const hosts = [input.destinationHost];
  if (input.frameHost !== undefined && input.frameHost !== "" && input.frameHost !== input.destinationHost) hosts.push(input.frameHost);
  return hosts;
}

function cardMayGoTo(host: string, input: LeakInput, policy: Policy): boolean {
  if (isPaymentFrameHost(host, policy.paymentHosts)) return true;
  const m = input.checkoutMerchantHost;
  return m !== undefined && isKnownCheckoutMerchant(m, policy.paymentHosts) && sameSite(m, host);
}

/** Cards: the frame must be a payment frame or a known merchant; the destination must be one too, or the same site as that frame. */
function paymentOk(input: LeakInput, policy: Policy): boolean {
  const dest = input.destinationHost;
  const frameHost = input.frameHost;
  if (frameHost === undefined || frameHost === "") return cardMayGoTo(dest, input, policy);
  return cardMayGoTo(frameHost, input, policy) && (cardMayGoTo(dest, input, policy) || sameSite(dest, frameHost));
}

/** Every finding in the text for this destination, before any decision. */
export function leakFindings(input: LeakInput, prints: readonly PrivatePrint[], policy: Policy, printSalt = ""): LeakFinding[] {
  const out: LeakFinding[] = [];
  const hosts = judgedHosts(input);
  for (const h of secretsIn(input.text)) {
    if (!hosts.every((host) => secretAllowed(h, host, policy))) out.push({ kind: "secret", name: h.name, masked: mask(h.value) });
  }
  if (!paymentOk(input, policy)) {
    // Cards and ids in the clear and in decoded variants: a card number sent base64- or hex-encoded is still a card.
    const seen = new Set<string>();
    for (const v of decodedVariants(input.text)) {
      for (const d of findPersonalData(v)) {
        const key = `${d.kind}|${d.value.replace(/[ -]/g, "")}`;
        if (seen.has(key) || isKnownTestValue(d) || d.kind === "credential") continue;
        seen.add(key);
        out.push({ kind: d.kind, name: d.name, masked: mask(d.value) });
      }
    }
  }
  let print: PrivatePrint | null = null;
  for (const host of hosts) print ??= seenElsewhere(input.text, host, prints, printSalt);
  if (print !== null) out.push({ kind: "seen_elsewhere", name: "private string", masked: "", seenOn: print.domain });
  return out;
}

/** The leak guard's decision: the strictest row any finding triggers. */
export function decideLeak(input: LeakInput, trust: EffectiveTrust, policy: Policy): { decision: Decision; findings: LeakFinding[] } {
  const findings = leakFindings(input, trust.prints, policy, trust.printSalt);
  const kinds = new Set(findings.map((f) => f.kind));
  const on = trust.agentMode;
  if (kinds.has("seen_elsewhere") && on && trust.untrusted && trust.quarantined) {
    return { decision: { verdict: "deny", rule: "leak.seen_elsewhere_quarantine", actionClass: null, reasons: ["seen_elsewhere", "quarantine_verdict"] }, findings };
  }
  if (kinds.has("secret")) return { decision: { verdict: on ? "approve" : "warn", rule: "leak.secret", actionClass: null, reasons: ["secret_shape"] }, findings };
  if (kinds.has("card") || kinds.has("iban") || kinds.has("national_id")) {
    return { decision: { verdict: on ? "approve" : "warn", rule: "leak.card_or_id", actionClass: null, reasons: ["personal_data"] }, findings };
  }
  if (kinds.has("seen_elsewhere")) return { decision: { verdict: on ? "approve" : "log", rule: "leak.seen_elsewhere", actionClass: null, reasons: ["seen_elsewhere"] }, findings };
  return { decision: { verdict: "allow", rule: "leak.none", actionClass: null, reasons: [] }, findings };
}

// ---- the leak guard's local context and approval binding ---------------------

/**
 * What a content script needs to decide a leak synchronously, inside the event
 * that would carry the data (a keystroke, a paste, a submit): the worker's
 * trust flags for the tab, the session's print hashes and the policy's allow
 * lists. The worker pushes it to every frame and re-decides authoritatively on
 * every non-allow verdict, so a stale context can only delay a block, never
 * grant anything. Prints are one-way hashes; no value is in it.
 */
export interface LeakContext {
  agentMode: boolean;
  untrusted: boolean;
  quarantined: boolean;
  private: boolean;
  prints: PrivatePrint[];
  /** The agent session's salt for short-code prints ("" or absent: none). */
  printSalt?: string;
  secretAllow: Policy["secretAllow"];
  paymentHosts: readonly string[];
}

export function leakContextOf(trust: EffectiveTrust, policy: Policy): LeakContext {
  return {
    agentMode: trust.agentMode,
    untrusted: trust.untrusted,
    quarantined: trust.quarantined,
    private: trust.private,
    // The session already keeps at most MAX_SESSION_PRINTS; capped again so a context always passes the content script's bound.
    prints: capPrints(trust.prints),
    ...(trust.printSalt !== undefined ? { printSalt: trust.printSalt } : {}),
    secretAllow: policy.secretAllow,
    paymentHosts: policy.paymentHosts,
  };
}

/** The empty context a frame starts from before the worker answers: agent mode off, nothing seen. */
export const EMPTY_LEAK_CONTEXT: LeakContext = Object.freeze({ agentMode: false, untrusted: false, quarantined: false, private: false, prints: [], secretAllow: [], paymentHosts: [] });

/** decideLeak over a pushed context (the content script's synchronous decision). */
export function decideLeakLocally(input: LeakInput, ctx: LeakContext, base: Policy): { decision: Decision; findings: LeakFinding[] } {
  const trust: EffectiveTrust = {
    agentMode: ctx.agentMode,
    declaredClass: null,
    untrusted: ctx.untrusted,
    private: ctx.private,
    quarantined: ctx.quarantined,
    sessionDomains: new Set(),
    grants: new Set(),
    prints: ctx.prints,
    ...(ctx.printSalt !== undefined ? { printSalt: ctx.printSalt } : {}),
  };
  return decideLeak(input, trust, { ...base, secretAllow: ctx.secretAllow, paymentHosts: ctx.paymentHosts });
}

export type LeakVia = "type" | "paste" | "submit";

export interface LeakBindingInput {
  tabId: number;
  frameId: number;
  frameOrigin: string;
  via: LeakVia;
  elementPath: string;
  fieldName: string;
  text: string;
  destinationHost: string;
}

/**
 * The snapshot a leak approval binds to: the frame, the field (or form), how
 * the data was going out, a digest of the exact text and the destination. The
 * worker builds it from the check; the content script builds the same one when
 * it redeems the token, so an approval for one value cannot release another.
 */
export function leakSnapshot(b: LeakBindingInput): ActionSnapshot {
  return {
    tabId: b.tabId,
    frameId: b.frameId,
    frameOrigin: b.frameOrigin,
    kind: b.via,
    actionClass: null,
    elementPath: b.elementPath,
    fieldNames: [b.fieldName],
    valuesDigest: valuesDigest([{ name: b.fieldName, type: `leak.${b.via}`, value: b.text }]),
    targetOrigin: b.destinationHost,
    method: "",
  };
}
