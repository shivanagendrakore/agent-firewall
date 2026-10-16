/**
 * The navigation policy's predicates and decisions (design 7). The worker
 * turns these into declarativeNetRequest rules and the content script uses
 * them for link clicks DNR cannot see (javascript: URLs); both call this one
 * function so the rule table lives in one place.
 *
 *   rule                                                   off                     on
 *   capture and paste hosts                                subresources blocked    blocked
 *   javascript: / data: top-level navigations              allow                   blocked
 *   data-carrying URL to a domain new to a private session allow                   approve
 *   raw IP, DNS-exfil-shaped host                          allow                   approve
 *   cloud metadata address                                 allow (subresource: block) blocked
 *   agent origin set (engine only, never on), main frame   allow                   approve
 *
 * Every DNR rule blocks; none redirects. For "approve", the worker shows an
 * explanation page in the tab (which offers nothing to click) and files an
 * approval in the side panel and approval window, so the approval stays out of
 * the page; an approved navigation is reopened once.
 */
import { registrableDomain } from "./domain.js";
import { hostMatches, isCaptureUrl, isDnsExfilShape, isMetadataEndpoint, isRawIp, parseUrlLike, urlCarriesData } from "./network.js";
import type { EffectiveTrust } from "./session.js";
import type { Decision, Policy } from "./types.js";

export interface NavigationInput {
  url: string;
  resourceType: "main_frame" | "sub_frame" | "other";
}

const allow = (reasons: string[] = []): Decision => ({ verdict: "allow", rule: "nav.none", actionClass: null, reasons });

/** Whether a URL is a capture host or a chat-webhook-style capture URL (Discord, Telegram bot). */
export function isCaptureDestination(url: string): boolean {
  const p = parseUrlLike(url);
  return p !== null && isCaptureUrl(p);
}

/**
 * The URL as the browser reads it before it looks at the scheme: leading C0 controls and spaces are
 * stripped and tabs and newlines are removed everywhere, so "\u0001javascript:" and "java\tscript:" are javascript:.
 */
export function normalizeUrlText(raw: string): string {
  // eslint-disable-next-line no-control-regex -- the WHATWG URL parser strips exactly these characters
  return raw.replace(/^[\u0000-\u0020]+/, "").replace(/[\t\n\r]/g, "");
}

export function decideNavigation(nav: NavigationInput, trust: EffectiveTrust, policy: Policy): Decision {
  const url = normalizeUrlText(nav.url).trimEnd();
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(url)?.[1]?.toLowerCase() ?? "";
  const top = nav.resourceType === "main_frame";

  if (scheme === "javascript" || scheme === "data") {
    if (top && trust.agentMode) return { verdict: "deny", rule: "nav.script_url", actionClass: null, reasons: [`${scheme}_url`] };
    return { verdict: "allow", rule: "nav.script_url", actionClass: null, reasons: [] };
  }
  if (scheme !== "http" && scheme !== "https" && scheme !== "ws" && scheme !== "wss") return allow(["not_web_url"]);

  const p = parseUrlLike(url);
  if (p === null) {
    // A web URL we cannot read may still be one the browser reads (and contacts): fail closed where nothing is
    // approved by a person, as the capture-host rule does.
    if (!top || trust.agentMode) return { verdict: "deny", rule: "nav.suspicious_host", actionClass: null, reasons: ["unparsable_url"] };
    return allow(["unparsed"]);
  }

  if (isCaptureUrl(p)) {
    if (!top || trust.agentMode) return { verdict: "deny", rule: "nav.capture_host", actionClass: null, reasons: ["capture_host"] };
    return { verdict: "allow", rule: "nav.capture_host", actionClass: null, reasons: ["capture_host_main_frame_agent_mode_off"] };
  }

  if (isMetadataEndpoint(p.host)) {
    if (!top || trust.agentMode) return { verdict: "deny", rule: "nav.suspicious_host", actionClass: null, reasons: ["metadata_address"] };
    return { verdict: "allow", rule: "nav.suspicious_host", actionClass: null, reasons: [] };
  }

  if (!trust.agentMode) return allow();

  if (isRawIp(p.host) || isDnsExfilShape(p.host)) {
    return { verdict: "approve", rule: "nav.suspicious_host", actionClass: null, reasons: [isRawIp(p.host) ? "raw_ip" : "dns_exfil_shape"] };
  }

  const domain = registrableDomain(p.host);
  // The site that injected outside content into a quarantined session is never a known destination (RR6).
  const newToSession = !trust.sessionDomains.has(domain) || (trust.injectorDomains?.has(domain) ?? false);
  if (trust.private && newToSession && urlCarriesData(p)) {
    return { verdict: "approve", rule: "nav.high_entropy_new_origin", actionClass: null, reasons: ["data_in_url", "new_origin", "private_session"] };
  }

  if (top && policy.originSet !== null && !policy.originSet.some((pat) => hostMatches(p.host, pat))) {
    return { verdict: "approve", rule: "nav.origin_set", actionClass: null, reasons: ["outside_origin_set"] };
  }
  return allow();
}
