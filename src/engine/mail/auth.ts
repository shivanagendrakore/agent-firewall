/**
 * Sender authentication as the mailbox provider reported it (email guard).
 * Nothing here checks a signature or does a DNS
 * lookup: it reads the `Authentication-Results` header the receiving server
 * wrote.
 *
 * Only the top-most header whose authserv-id belongs to the provider counts
 * (`mx.google.com`, `*.prod.outlook.com`, `*.protection.outlook.com`,
 * `mx.microsoft.com`, plus ids the person configures). A sender can write any
 * `Authentication-Results` header it likes into its own message, but those sit
 * below the provider's, so they cannot replace its verdict. Microsoft 365's
 * Exchange Online writes its header without an authserv-id; with Microsoft's
 * own `ARC-Authentication-Results` present, that top-most id-less header and
 * Microsoft's ARC result are read. With no provider `Authentication-Results`,
 * the provider's `ARC-Authentication-Results` (top-most, lowest instance) are.
 * A sender-written header can add a failure, never remove one (`readAuth`).
 *
 * `fail` is `dmarc=fail`, or `spf=fail` with no passing DKIM signature. A
 * passing ARC chain sealed by a listed forwarder (mailing lists, forwarding
 * services, which break DMARC by design) cancels it. Unknown (no provider
 * header) is `null`: the auth rule cannot fire, the other rules still apply.
 *
 * Also reported, never a reason to withhold alone: a display name that names
 * another domain, a Reply-To on a different registrable domain, punycode and
 * mixed-script domains.
 *
 * Pure: no I/O.
 */
import { headerValue, headerValues, parseAddresses, type MailHeader } from "./mime.js";

/** Authentication-Results authserv-ids of the providers the firewall knows (exact, or `*.` suffix). */
export const PROVIDER_AUTHSERV_IDS: readonly string[] = ["mx.google.com", "*.prod.outlook.com", "*.protection.outlook.com", "mx.microsoft.com", "*.mx.microsoft"];

/**
 * Forwarders whose passing ARC seal cancels a DMARC failure: mailing-list hosts and forwarding services
 * that rewrite messages by design. A seal is cryptographic, so only mail that really passed through one of
 * these benefits; a sender's own seal (its own domain) does not. Mailbox providers that also seal the mail
 * their own customers send (google.com, microsoft.com, outlook.com, icloud.com, fastmail.com) are not
 * listed: a spoofer sending through one of them would otherwise cancel its own DMARC failure.
 */
export const ARC_FORWARDERS: readonly string[] = [
  "googlegroups.com", "groups.io", "freelists.org", "lists.sourceforge.net", "simplelogin.co", "simplelogin.com", "duck.com", "lists.debian.org", "vger.kernel.org", "kernel.org",
  "python.org", "apache.org", "ietf.org", "w3.org", "lists.ubuntu.com", "lists.fedoraproject.org", "freebsd.org", "mozilla.org", "gnu.org", "lists.openwall.com", "mailman3.com",
  "discourse.org", "topicbox.com",
];

export interface AuthReport {
  /** true: the sender failed authentication; false: it did not; null: unknown (no provider header). */
  fail: boolean | null;
  /** The header the verdict came from, summarized ("mx.google.com: spf=pass dkim=pass dmarc=fail arc=pass"). */
  detail: string;
  arcPass: boolean;
  /** The authserv-id of the header that was read, when one was. */
  authservId?: string;
  /** Where it came from. */
  via?: "authentication-results" | "arc-authentication-results";
}

export type SenderNote =
  | { id: "display_name_domain"; detail: string }
  | { id: "reply_to_domain"; detail: string }
  | { id: "punycode_domain"; detail: string }
  | { id: "mixed_script_domain"; detail: string };

const lc = (s: string) => s.trim().toLowerCase().replace(/\.$/, "");

function idMatches(id: string, pattern: string): boolean {
  const p = lc(pattern);
  const i = lc(id);
  if (p === "") return false;
  if (p.startsWith("*.")) return i.endsWith(p.slice(1)) && i.length > p.length - 1;
  return i === p;
}

export function isProviderId(id: string, extra: readonly string[] = []): boolean {
  return [...PROVIDER_AUTHSERV_IDS, ...extra].some((p) => idMatches(id, p));
}

/** Removes RFC 5322 comments (nested parentheses), keeping quoted strings. */
function stripComments(s: string): string {
  let out = "";
  let depth = 0;
  let quoted = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i] as string;
    if (c === "\\") {
      if (depth === 0) out += c + (s[i + 1] ?? "");
      i++;
      continue;
    }
    if (c === '"' && depth === 0) quoted = !quoted;
    if (!quoted && c === "(") {
      depth++;
      continue;
    }
    if (!quoted && c === ")" && depth > 0) {
      depth--;
      continue;
    }
    if (depth === 0) out += c;
  }
  return out;
}

/** Splits an Authentication-Results value on `;` outside quoted strings. */
function splitSemicolons(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i] as string;
    if (c === "\\") {
      cur += c + (s[i + 1] ?? "");
      i++;
      continue;
    }
    if (c === '"') {
      quoted = !quoted;
      cur += c;
      continue;
    }
    if (c === ";" && !quoted) {
      out.push(cur.trim());
      cur = "";
      continue;
    }
    cur += c;
  }
  out.push(cur.trim());
  return out;
}

export interface ParsedAuthResults {
  /** "" when the header carries none (Exchange Online's own header has no authserv-id). */
  authservId: string;
  /** ARC-Authentication-Results instance (i=), when it is one. */
  instance?: number;
  results: { method: string; result: string; props: string }[];
}

/** Parses one Authentication-Results (or ARC-Authentication-Results) value (RFC 8601). */
export function parseAuthResults(value: string, arc = false): ParsedAuthResults {
  const parts = splitSemicolons(stripComments(value));
  let instance: number | undefined;
  if (arc) {
    const m = /^i\s*=\s*(\d{1,3})$/i.exec(parts[0] ?? "");
    if (m !== null) {
      instance = Number(m[1]);
      parts.shift();
    }
  }
  const head = parts[0] ?? "";
  let authservId = "";
  if (!/^[a-z][a-z0-9_.-]*\s*=/i.test(head)) {
    authservId = head.split(/\s+/)[0] ?? "";
    parts.shift();
  }
  const results: ParsedAuthResults["results"] = [];
  for (const p of parts) {
    const m = /^([a-z][a-z0-9_.-]*)\s*=\s*([a-z]+)\b\s*(.*)$/i.exec(p);
    if (m !== null) results.push({ method: lc(m[1] as string), result: lc(m[2] as string), props: m[3] as string });
  }
  return { authservId, ...(instance !== undefined ? { instance } : {}), results };
}

/** The sealing domains of an ARC chain (d= of each ARC-Seal). */
function arcSealers(headers: readonly MailHeader[]): string[] {
  return headerValues(headers, "arc-seal")
    .map((v) => /(?:^|;)\s*d\s*=\s*([^;\s]+)/i.exec(stripComments(v))?.[1])
    .filter((d): d is string => d !== undefined)
    .map(lc);
}

const isForwarder = (d: string) => ARC_FORWARDERS.some((f) => d === f || d.endsWith(`.${f}`));

function authPassed(p: ParsedAuthResults): boolean {
  const is = (method: string, result: string) => p.results.some((r) => r.method === method && r.result === result);
  const rawFail = is("dmarc", "fail") || (is("spf", "fail") && !is("dkim", "pass"));
  const anyPass = is("dmarc", "pass") || is("dkim", "pass") || is("spf", "pass");
  return anyPass && !rawFail;
}

/** Microsoft 365's authserv-ids (Exchange Online writes its Authentication-Results without one). */
const MICROSOFT_IDS: readonly string[] = ["mx.microsoft.com", "*.mx.microsoft", "*.prod.outlook.com", "*.protection.outlook.com"];

interface Verdict {
  p: ParsedAuthResults;
  via: NonNullable<AuthReport["via"]>;
  rawFail: boolean;
  arcPass: boolean;
  fail: boolean;
}

/**
 * The provider's authentication verdict for a message (`extraIds`: authserv-ids the person configured or
 * the mailbox learned, `emailGuard.authservIds`).
 *
 * Headers are in order, top first: the receiving provider prepends its own, so anything a sender wrote
 * sits below them. The verdict is read from the provider's top-most header:
 *
 * - the first `Authentication-Results` whose authserv-id is the provider's;
 * - for Microsoft 365, whose Exchange Online header has no authserv-id: the first `Authentication-Results`
 *   without an id (above any provider-id one) is Exchange's, and when the message carries Microsoft's own
 *   `ARC-Authentication-Results` or the id-less header reports a failure, it and Microsoft's top-most ARC
 *   result are the verdict, so a provider-looking header lower down (a sender's forged
 *   `mx.google.com; dmarc=pass`) cannot replace it;
 * - with no provider `Authentication-Results`, the provider's `ARC-Authentication-Results`: the top-most
 *   one and the lowest instance (a sender can write any `i=` it likes, so a forged high instance does not
 *   win).
 *
 * A sender-written header can only add a failure, never remove one: every candidate that could be the
 * provider's is read, and the message fails when any of them reports a failure (each with its own ARC
 * cancellation). A pass written by a sender therefore never overrides the provider's failure.
 */
export function readAuth(headers: readonly MailHeader[], extraIds: readonly string[] = []): AuthReport {
  const rawAr = headerValues(headers, "authentication-results");
  const ar = rawAr.map((v) => parseAuthResults(v));
  const allArcs = headerValues(headers, "arc-authentication-results").map((v) => parseAuthResults(v, true));
  const arcs = allArcs.filter((a) => a.authservId !== "" && isProviderId(a.authservId, extraIds));
  const microsoft = arcs.some((a) => MICROSOFT_IDS.some((m) => idMatches(a.authservId, m)));
  const sealers = arcSealers(headers);
  const arc1 = allArcs.filter((a) => a.instance === 1);
  const arc1Pass =
    arc1.length > 0
      ? arc1.every(authPassed)
      : allArcs.length === 0 && rawAr.some((v) => /\barc\s*=\s*pass\s*\(\s*i\s*=\s*1\b[^)]{0,200}\bdmarc\s*=\s*pass\b(?![^)]{0,200}\bfail\b)/i.test(v.slice(0, 4096)));
  // Only the top-most ARC result decides, and only one written by Microsoft: a lower, sender-written one cannot.
  const microsoftTop = arcs.find((a) => a.instance !== undefined);
  const microsoftArcPass = microsoftTop !== undefined && MICROSOFT_IDS.some((m) => idMatches(microsoftTop.authservId, m)) && microsoftTop.results.some((r) => r.method === "arc" && r.result === "pass");
  const judge = (p: ParsedAuthResults, via: Verdict["via"]): Verdict => {
    const is = (method: string, result: string) => p.results.some((r) => r.method === method && r.result === result);
    const rawFail = is("dmarc", "fail") || (is("spf", "fail") && !is("dkim", "pass"));
    // Exchange's id-less header has no arc= of its own: Microsoft's top-most ARC result (a forwarder sealed
    // the chain and Microsoft saw it pass) cancels its DMARC failure, as it cancels any provider's.
    const arcPass = (is("arc", "pass") || (p.authservId === "" && microsoftArcPass)) && sealers.some(isForwarder) && arc1Pass;
    return { p, via, rawFail, arcPass, fail: rawFail && !arcPass };
  };
  // The first provider header, or the first id-less header (Exchange Online's sits above any sender's
  // header; headers above it were added after delivery).
  let top: ParsedAuthResults | null = null;
  for (const p of ar) {
    if (p.authservId !== "" && isProviderId(p.authservId, extraIds)) {
      top = p;
      break;
    }
    if (p.authservId === "") {
      top = p;
      break;
    }
  }
  const firstProvider = ar.find((p) => p.authservId !== "" && isProviderId(p.authservId, extraIds)) ?? null;
  const arcTop = arcs.find((a) => a.instance !== undefined) ?? null;
  const arcLowest = arcs.reduce<ParsedAuthResults | null>((best, a) => (a.instance !== undefined && (best === null || (best.instance ?? 0) > a.instance) ? a : best), null);
  const arcHighest = arcs.reduce<ParsedAuthResults | null>((best, a) => (a.instance !== undefined && (best === null || (best.instance ?? 0) < a.instance) ? a : best), null);
  const candidates: Verdict[] = [];
  const push = (p: ParsedAuthResults | null, via: Verdict["via"]) => {
    if (p !== null && !candidates.some((c) => c.p === p)) candidates.push(judge(p, via));
  };
  if (top !== null && top.authservId !== "") {
    // A provider's own header on top (Gmail, Outlook with an id, a configured id): it alone decides.
    push(top, "authentication-results");
  } else {
    // Microsoft 365 (Exchange's id-less header on top) or no provider Authentication-Results at all.
    push(arcTop, "arc-authentication-results");
    if (top !== null && (microsoft || judge(top, "authentication-results").fail)) push(top, "authentication-results");
    push(arcLowest, "arc-authentication-results");
    // What the reader used before (the first provider-id header anywhere, the highest ARC instance) can
    // still add a failure, never a pass.
    if (firstProvider !== null && (top === null || judge(firstProvider, "authentication-results").fail)) push(firstProvider, "authentication-results");
    push(arcHighest, "arc-authentication-results");
  }
  if (candidates.length === 0) return { fail: null, detail: "no Authentication-Results header from the mailbox provider", arcPass: false };
  const chosen = candidates.find((c) => c.fail) ?? (candidates[0] as Verdict);
  const results = chosen.p.results;
  const summary = ["spf", "dkim", "dmarc", "arc"]
    .map((m) => {
      const r = results.find((x) => x.method === m);
      return r === undefined ? null : `${m}=${r.result}`;
    })
    .filter((x): x is string => x !== null)
    .join(" ");
  const id = chosen.p.authservId === "" ? "Exchange Online" : chosen.p.authservId;
  const detail = `${id}: ${summary || "no results"}${chosen.rawFail && chosen.arcPass ? ` (ARC sealed by ${sealers.filter(isForwarder).join(", ")} cancels the failure)` : ""}`;
  return { fail: chosen.fail, detail: detail.slice(0, 300), arcPass: chosen.arcPass, authservId: chosen.p.authservId, via: chosen.via };
}

// --- sender notes -------------------------------------------------------------------------------

/** Second-level labels under which registrations sit one level deeper (co.uk, com.au). Not the full public suffix list. */
const TWO_LEVEL = /^(?:co|com|net|org|gov|ac|edu|or|ne|go|mil|nic|ltd|plc|sch|me|gen|biz|info|nom)\.[a-z]{2}$/;

/** The registrable domain (example.co.uk for a.b.example.co.uk), by a small public-suffix approximation. */
export function registrableDomain(host: string): string {
  const labels = lc(host).split(".").filter((x) => x !== "");
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  return TWO_LEVEL.test(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

const domainOf = (address: string) => {
  const at = address.lastIndexOf("@");
  return at === -1 ? "" : lc(address.slice(at + 1).replace(/[>\s]+$/, ""));
};

const SCRIPTS = ["Latin", "Cyrillic", "Greek", "Armenian", "Hebrew", "Arabic", "Devanagari", "Han", "Hiragana", "Katakana", "Hangul", "Thai", "Georgian"] as const;
const SCRIPT_RE = SCRIPTS.map((s) => [s, new RegExp(`\\p{Script=${s}}`, "u")] as const);

function mixedScript(label: string): boolean {
  const found = new Set<string>();
  for (const ch of label) {
    for (const [s, re] of SCRIPT_RE) if (re.test(ch)) found.add(s);
  }
  // Japanese mixes Han, Hiragana and Katakana by design.
  const cjk = ["Han", "Hiragana", "Katakana"];
  const nonCjk = [...found].filter((s) => !cjk.includes(s));
  return nonCjk.length > 1 || (nonCjk.length === 1 && nonCjk[0] !== "Latin" && [...found].some((s) => cjk.includes(s)));
}

/**
 * The domain of the first address written in a display name, as /[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/ finds it, read from
 * each "@": that pattern tried from every position of a long name backtracked over the rest of it (quadratic: a
 * 100,000-character Graph display name took 5 s, mail:scanMail seeds 30964, 39045, 56025). The text after one
 * "@" ends at the next, so the work is linear.
 */
function addressDomainIn(name: string): string | undefined {
  const domain = /[\w-]+(?:\.[\w-]+)+/y;
  for (let at = name.indexOf("@"); at !== -1; at = name.indexOf("@", at + 1)) {
    if (at === 0 || !/[\w.+-]/.test(name[at - 1] as string)) continue;
    domain.lastIndex = at + 1;
    const m = domain.exec(name);
    if (m !== null) return m[0];
  }
  return undefined;
}

/**
 * A domain written in a display name. A label is at most 63 characters (as in DNS) and at most eight labels come
 * before the suffix, so a match tried from every word boundary of a long name looks at a bounded stretch of it,
 * not the rest. A longer chain still matches from a later label, which has the same registrable domain.
 */
const NAMED_DOMAIN = /\b((?:[a-z0-9-]{1,63}\.){1,8}(?:com|net|org|io|co|gov|edu|app|dev|ai|uk|de|fr|in|us))\b/i;

/** Reported facts about the sender's addresses; never a reason to withhold alone. */
export function senderNotes(headers: readonly MailHeader[]): SenderNote[] {
  const out: SenderNote[] = [];
  const from = parseAddresses(headerValue(headers, "from") ?? "")[0];
  const fromDomain = from === undefined ? "" : domainOf(from.address);
  if (from !== undefined && fromDomain !== "") {
    // A display name that carries an address or a domain of its own ("PayPal <x@evil.example>" is common
    // and fine; "service@paypal.com <x@evil.example>" is the trick).
    const named = addressDomainIn(from.name) ?? NAMED_DOMAIN.exec(from.name)?.[1];
    if (named !== undefined && registrableDomain(named) !== registrableDomain(fromDomain)) out.push({ id: "display_name_domain", detail: `the display name names ${lc(named)} but the address is at ${fromDomain}` });
  }
  const replyTo = parseAddresses(headerValue(headers, "reply-to") ?? "");
  for (const r of replyTo) {
    const d = domainOf(r.address);
    if (d !== "" && fromDomain !== "" && registrableDomain(d) !== registrableDomain(fromDomain)) {
      out.push({ id: "reply_to_domain", detail: `replies go to ${registrableDomain(d)}, not the sender's ${registrableDomain(fromDomain)}` });
      break;
    }
  }
  const domains = new Set([fromDomain, ...replyTo.map((r) => domainOf(r.address))].filter((d) => d !== ""));
  for (const d of domains) {
    if (d.split(".").some((l) => l.startsWith("xn--"))) out.push({ id: "punycode_domain", detail: `${d} is an internationalized (punycode) domain` });
    else if (d.split(".").some(mixedScript)) out.push({ id: "mixed_script_domain", detail: `${d} mixes writing systems` });
  }
  return out;
}
