/**
 * What the explanation page says for each navigation rule. Pure, so it is
 * tested without a browser; the page itself only writes these strings with
 * textContent.
 */
import { RULE_IDS, type RuleId } from "../engine/types.js";
import { displayHost } from "./host-display.js";

export interface BlockedView {
  title: string;
  why: string;
  host: string;
  chars: string;
  rule: string;
  next: string;
}

const WHY: Partial<Record<RuleId, string>> = {
  "nav.capture_host": "The address belongs to a service built to catch data sent to it (a request bin, webhook catcher, paste site or tunnel). Pages that hijack AI agents send what the agent read to services like this.",
  "nav.high_entropy_new_origin": "While agent mode is on and the agent has seen private data, it tried to open a site it had not visited in this session with a long, random-looking value in the address. That is how a hijacked agent carries data out.",
  "nav.suspicious_host": "The address is a raw IP address, a cloud metadata address, or a host name shaped to carry data out through DNS. Agents rarely need these; hijacked agents use them to send data somewhere unlisted.",
  "nav.origin_set": "The agent tried to leave the sites you allowed when you started this agent task.",
  "nav.script_url": "The agent clicked a javascript: link, which runs code in the page instead of opening one.",
};

const NEXT =
  "If an agent was browsing, nothing was sent: the browser stopped the request before it left. If you opened this address yourself and meant to, turn agent mode off in the LaunchSafe side panel (it asks you to confirm there) and open it again. LaunchSafe never asks you to approve anything from inside a web page.";

const NEXT_APPROVABLE =
  "If an agent was browsing, nothing was sent: the browser stopped the request before it left. If you opened this address yourself and meant to, open the LaunchSafe side panel or approval window: this navigation is waiting there, and approving it opens this address once in this tab. LaunchSafe never asks you to approve anything from inside a web page.";

const isRuleId = (s: string): s is RuleId => (RULE_IDS as readonly string[]).includes(s);

/** The page's text for a rule, a host and a character count; unknown or malformed input gets a plain fallback. */
export function explanationFor(q: { rule: string; host: string; chars: string; approval?: string }): BlockedView {
  const rule = isRuleId(q.rule) ? q.rule : null;
  // A host name only: anything else in the parameter is shown as nothing rather than as text a page chose.
  // An internationalised host is shown in Unicode and as its ASCII (xn--) form, with a warning when it mixes alphabets (m12).
  const host = /^[a-z0-9.:[\]-]{1,253}$/i.test(q.host) ? displayHost(q.host.toLowerCase()) : "(not shown)";
  const n = /^\d{1,7}$/.test(q.chars) ? Number(q.chars) : 0;
  return {
    title: "LaunchSafe stopped this navigation",
    why: (rule !== null ? WHY[rule] : undefined) ?? "A LaunchSafe navigation rule stopped this request.",
    host,
    chars: n === 0 ? "None" : `${n} characters (not shown here, so they stay on this device)`,
    rule: rule ?? "unknown",
    next: q.approval === "1" ? NEXT_APPROVABLE : NEXT,
  };
}
