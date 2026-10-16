/**
 * Origins, hosts and registrable domains.
 *
 * The leak guard and the session compare *registrable* domains ("mail.test"
 * for "inbox.mail.test"), so moving data between two subdomains of one site is
 * not a leak and moving it to another site is. There is no runtime dependency
 * and no fetched list: the rule is the Public Suffix List (ICANN and private
 * sections), generated into psl-data.ts by scripts/gen-psl.mjs from a pinned
 * commit, plus two small additions of our own:
 *
 * - EXTRA_SUFFIXES: hosting platforms where every label is a different owner
 *   but that the list does not carry (yet);
 * - TENANT_HOSTS: one host of a big first-party domain that serves pages and
 *   forms written by anyone (docs.google.com Forms, script.google.com Apps
 *   Script, gist.github.com), so it is a different site from the rest of the
 *   domain: a code shown on mail.google.com typed into a Form is a leak.
 *
 * IP addresses and single-label hosts are their own registrable domain. Erring
 * towards *more* distinct domains is the safe direction: it can only make a
 * cross-site move look like one, never hide it.
 */
import { isIpv4, isIpv6, normalizeHost } from "./network.js";
import { PSL_EXCEPTION, PSL_PLAIN, PSL_WILDCARD } from "./psl-data.js";

const split = (s: string): string[] => (s === "" ? [] : s.split("\n"));

/** Platforms where every label below the suffix is a different owner, not in the list. */
const EXTRA_SUFFIXES: readonly string[] = ["railway.app", "wordpress.com", "substack.com", "glitch.me", "bolt.new", "sharepoint.com", "storage.googleapis.com", "softr.app"];

/**
 * A host (and its subdomains) that is its own site although its domain is shared with a first party: it serves
 * pages, forms, notebooks, reports or posts that anyone writes, so data sent there reaches whoever wrote the page.
 * nav-rules.ts reads this list too, so the browser's navigation rules draw the same line (RR1).
 */
export const TENANT_HOSTS: readonly string[] = [
  "docs.google.com",
  "script.google.com",
  "sites.google.com",
  "groups.google.com",
  "colab.research.google.com",
  "lookerstudio.google.com",
  "datastudio.google.com",
  "usercontent.google.com",
  "forms.office.com",
  "forms.microsoft.com",
  "forms.cloud.microsoft",
  "sway.office.com",
  "sway.cloud.microsoft",
  "answers.microsoft.com",
  "discussions.apple.com",
  "gist.github.com",
  "forms.zohopublic.com",
];

const PLAIN = new Set([...split(PSL_PLAIN), ...EXTRA_SUFFIXES]);
const WILDCARD = new Set(split(PSL_WILDCARD));
const EXCEPTION = new Set(split(PSL_EXCEPTION));

/** Number of labels of the public suffix of `labels` (the Public Suffix List algorithm; the default rule is "*"). */
function suffixLength(labels: readonly string[]): number {
  let best = 1;
  for (let i = labels.length - 1; i >= 0; i--) {
    const candidate = labels.slice(i).join(".");
    const len = labels.length - i;
    if (EXCEPTION.has(candidate)) return len - 1;
    if (PLAIN.has(candidate) && len > best) best = len;
    // "*.x" matches a host with one more label than x.
    if (i > 0 && WILDCARD.has(candidate) && len + 1 > best) best = len + 1;
  }
  return best;
}

/** The registrable domain of a host, lower-case. Never throws; an empty host gives "". */
export function registrableDomain(host: string): string {
  const h = normalizeHost(host);
  if (h === "" || isIpv4(h) || isIpv6(h) || !h.includes(".")) return h;
  for (const t of TENANT_HOSTS) if (h === t || h.endsWith(`.${t}`)) return t;
  const labels = h.split(".");
  const n = suffixLength(labels);
  // The host is itself a public suffix: it is its own domain.
  if (n >= labels.length) return h;
  return labels.slice(-(n + 1)).join(".");
}

/** Whether a host is itself a public suffix (no registrable owner of its own: "github.io", "co.uk"). */
export function isPublicSuffix(host: string): boolean {
  const h = normalizeHost(host);
  if (h === "" || isIpv4(h) || isIpv6(h) || !h.includes(".")) return false;
  const labels = h.split(".");
  return suffixLength(labels) >= labels.length;
}

/**
 * Stand-in host for a document with an opaque origin and no creator we can read from its URL (a data: or
 * about:srcdoc frame). It is never a trusted host and never a real site, so such a frame counts as outside content.
 */
export const OPAQUE_HOST = "opaque-origin.invalid";

/**
 * The host of a URL (lower-case, no brackets), or null for a URL with no host (about:, javascript:).
 * A blob: URL has the origin of the page that minted it, so that is its host; a data: or about:srcdoc
 * document gets OPAQUE_HOST, so it cannot pass as the page around it.
 */
export function hostOf(url: string): string | null {
  try {
    const u = new URL(url);
    if (u.protocol === "blob:") {
      // "blob:https://evil.test/uuid": the creator's origin is the part after "blob:". An opaque creator is untrusted.
      const inner = hostOf(u.pathname);
      return inner ?? OPAQUE_HOST;
    }
    if (u.protocol === "data:" || (u.protocol === "about:" && u.pathname === "srcdoc")) return OPAQUE_HOST;
    const h = normalizeHost(u.hostname);
    return h === "" ? null : h;
  } catch {
    return null;
  }
}

/** The origin of a URL ("https://shop.test:8443"), or null when it has none (opaque origins). */
export function originOf(url: string): string | null {
  try {
    const o = new URL(url).origin;
    return o === "null" ? null : o;
  } catch {
    return null;
  }
}

/** Whether two hosts belong to the same registrable domain. Two empty hosts are not the same site. */
export function sameSite(a: string, b: string): boolean {
  const ra = registrableDomain(a);
  return ra !== "" && ra === registrableDomain(b);
}
