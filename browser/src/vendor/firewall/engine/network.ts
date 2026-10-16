// Vendored from the LaunchSafe Agent Firewall (src/engine/network.ts), Apache-2.0, at commit 5145f69e102584ff11ae342cd2349c4ee76974f3.
// Licence: Apache-2.0 (see NOTICE).
// Do not edit here: it is copied from the firewall repository by
// `node scripts/sync-firewall.mjs` (`--check` verifies the copy).

/**
 * Network destinations: parse what an agent is about to contact, and say
 * whether the address itself is a problem (a data-capture service, a raw
 * IP, a cloud metadata endpoint, a host name built to carry data).
 *
 * Capture-host list adapted from LaunchSafe's agent-safety signals
 * (Apache-2.0, same owner), extended.
 */

export interface ParsedUrl {
  url: string;
  scheme: string;
  /** Lower-case, no trailing dot, IPv4 numbers normalized to dotted form, IPv6 without brackets. */
  host: string;
  path: string;
  query: string;
}

/**
 * Parses a URL, or a bare host[/path] the way curl and wget accept it.
 * The WHATWG parser normalizes the IPv4 spellings attackers use to dodge
 * lists (0x7f000001, 2130706433, 0177.0.0.1) to dotted form.
 */
export function parseUrlLike(raw: string, assumeScheme = "http"): ParsedUrl | null {
  let s = raw.trim();
  if (s === "" || /\s/.test(s)) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    // Bare host: must look like a host name, an IP, or localhost, optionally with port and path.
    if (!/^(?:[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.?|\[[0-9a-f:.]+\])(?::\d+)?(?:[/?#].*)?$/i.test(s)) return null;
    const hostPart = s.split(/[/?#:]/)[0] ?? "";
    if (!hostPart.includes(".") && hostPart.toLowerCase() !== "localhost" && !/^\d+$/.test(hostPart) && !s.startsWith("[")) return null;
    s = `${assumeScheme}://${s}`;
  }
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
  if (host === "") return null;
  return { url: u.href, scheme: u.protocol.replace(/:$/, "").toLowerCase(), host, path: u.pathname, query: u.search + u.hash };
}

/** Every http(s)/ws(s)/ftp URL in free text. */
export function urlsIn(text: string): ParsedUrl[] {
  const out: ParsedUrl[] = [];
  for (const m of text.matchAll(/\b(?:https?|wss?|ftp):\/\/[^\s'"`<>\\]+/gi)) {
    // A closing bracket is trailing punctuation unless the URL has an IPv6 literal ("http://[::1]:8080/").
    const p = parseUrlLike(m[0].replace(m[0].includes("[") ? /[),.;}]+$/ : /[),.;\]}]+$/, ""));
    if (p !== null) out.push(p);
  }
  return out;
}

export function normalizeHost(h: string): string {
  return h.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
}

/** A host pattern as written by a person: a scheme, a path, a port or a leading dot is not part of the host. */
function cleanPattern(raw: string): string {
  let p = raw.trim().toLowerCase();
  const lead = /^[=*.]*/.exec(p)?.[0] ?? "";
  p = p.slice(lead.length);
  p = p.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/[/?#].*$/, "");
  // A port ("example.com:8443", "[::1]:8080"); a bare IPv6 literal has several colons and no port.
  p = /^\[[^\]]*\]:\d+$/.test(p) || /^[^:]+:\d+$/.test(p) ? p.replace(/:\d+$/, "") : p;
  const prefix = lead.startsWith("=") ? "=" : lead.startsWith("*") ? "*." : "";
  return `${prefix}${p}`;
}

/**
 * Pattern "example.com" matches it and its subdomains; "=example.com" matches only itself; "*.example.com" only
 * subdomains. A scheme, port or leading dot in the pattern ("https://example.com", "example.com:8443",
 * ".example.com") is ignored, so a denyHosts entry written that way still does something.
 */
export function hostMatches(host: string, pattern: string): boolean {
  const h = normalizeHost(host);
  const p = cleanPattern(pattern);
  if (p.startsWith("=")) return h === normalizeHost(p.slice(1));
  if (p.startsWith("*.")) return h.endsWith(`.${normalizeHost(p.slice(2))}`);
  const base = normalizeHost(p);
  return h === base || h.endsWith(`.${base}`);
}

export function hostInList(host: string, list: readonly string[]): boolean {
  return list.some((p) => hostMatches(host, p));
}

/** IPv6 text to its eight 16-bit groups (null when it is not IPv6). */
export function v6Groups(ip: string): number[] | null {
  let s = ip.toLowerCase();
  const zone = s.indexOf("%");
  if (zone !== -1) s = s.slice(0, zone);
  const tail4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (tail4 !== null) {
    const parts = (tail4[1] as string).split(".").map(Number);
    s = `${s.slice(0, -(tail4[1] as string).length)}${(((parts[0] as number) << 8) | (parts[1] as number)).toString(16)}:${(((parts[2] as number) << 8) | (parts[3] as number)).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] === "" ? [] : (halves[0] as string).split(":");
  const tail = halves.length === 2 ? (halves[1] === "" ? [] : (halves[1] as string).split(":")) : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  const all = [...head, ...new Array<string>(Math.max(fill, 0)).fill("0"), ...tail];
  if (all.length !== 8 || !all.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
  return all.map((g) => parseInt(g, 16));
}

export function isIpv4(host: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
}

export function isIpv6(host: string): boolean {
  return host.includes(":") && /^[0-9a-f:.]+$/i.test(host);
}

/**
 * The dotted-quad form of an IPv4 literal in any spelling inet_aton accepts (1 to 4 parts, each
 * decimal, octal with a leading 0, or hex with 0x), or null when the text is not one. Host names that
 * merely start with digits ("127.attacker.example") are not IPv4 literals.
 */
export function canonicalIpv4(host: string): string | null {
  const h = normalizeHost(host);
  const parts = h.split(".");
  if (parts.length < 1 || parts.length > 4) return null;
  const nums: number[] = [];
  for (const part of parts) {
    let n: number;
    if (/^0x[0-9a-f]*$/i.test(part)) n = part.length === 2 ? 0 : parseInt(part.slice(2), 16);
    else if (/^0[0-7]*$/.test(part)) n = part.length === 1 ? 0 : parseInt(part.slice(1), 8);
    else if (/^[1-9][0-9]*$/.test(part)) n = parseInt(part, 10);
    else return null;
    if (!Number.isFinite(n)) return null;
    nums.push(n);
  }
  const last = nums.length - 1;
  for (let i = 0; i < last; i++) if ((nums[i] as number) > 255) return null;
  if ((nums[last] as number) >= 256 ** (4 - last)) return null;
  let v = nums[last] as number;
  for (let i = 0; i < last; i++) v += (nums[i] as number) * 256 ** (3 - i);
  return [v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join(".");
}

/**
 * F1: loopback only when the host is a loopback IP literal (127.0.0.0/8 after IPv4 normalization, ::1,
 * 0.0.0.0, ::) or localhost / *.localhost. A DNS name such as 127.0.0.1.attacker.example resolves wherever
 * its owner points it, so it is an ordinary remote host.
 */
export function isLoopback(host: string): boolean {
  const h = normalizeHost(host);
  if (h === "localhost" || h.endsWith(".localhost") || h === "::1" || h === "::" || h === "0:0:0:0:0:0:0:1") return true;
  // ::ffff:127.0.0.1 and its hex spelling ::ffff:7f00:1 are the IPv4 address.
  const g = h.includes(":") ? v6Groups(h) : null;
  if (g !== null && g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return isLoopback(`${(g[6] as number) >> 8}.${(g[6] as number) & 255}.${(g[7] as number) >> 8}.${(g[7] as number) & 255}`);
  if (g !== null && g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return true;
  const v4 = canonicalIpv4(h);
  return v4 !== null && (v4.startsWith("127.") || v4 === "0.0.0.0");
}

export function isRawIp(host: string): boolean {
  const h = normalizeHost(host);
  return (isIpv4(h) || isIpv6(h)) && !isLoopback(h);
}

/** Cloud instance metadata: hands out the machine's cloud credentials to anything that asks. */
export function isMetadataEndpoint(host: string): boolean {
  const h = normalizeHost(host);
  // Any spelling of the IPv6 metadata addresses (fd00:ec2::254 for the instance service, fd00:ec2::23 for EKS Pod Identity).
  const g = h.includes(":") ? v6Groups(h) : null;
  if (g !== null && g[0] === 0xfd00 && g[1] === 0x0ec2 && g.slice(2, 7).every((x) => x === 0) && (g[7] === 0x254 || g[7] === 0x23)) return true;
  // M8: an IPv4-mapped IPv6 address (::ffff:169.254.169.254, ::ffff:a9fe:a9fe) is the IPv4 address.
  const mapped = /^(?:0{0,4}:){0,4}:?:ffff:(.+)$/i.exec(h)?.[1];
  if (mapped !== undefined) {
    const hex = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(mapped);
    const v4 = hex !== null ? [parseInt(hex[1] as string, 16) >> 8, parseInt(hex[1] as string, 16) & 255, parseInt(hex[2] as string, 16) >> 8, parseInt(hex[2] as string, 16) & 255].join(".") : mapped;
    if (v4 !== h && isMetadataEndpoint(v4)) return true;
  }
  // Any spelling of an IPv4 address (decimal, octal, hex, short forms) is judged in its canonical form.
  const v4 = canonicalIpv4(h);
  if (v4 !== null && v4 !== h) return isMetadataEndpoint(v4);
  return (
    // M8: Azure's WireServer and Oracle Cloud's metadata service.
    h === "168.63.129.16" ||
    h === "192.0.0.192" ||
    h === "169.254.169.254" ||
    h === "169.254.170.2" ||
    // EKS Pod Identity Agent.
    h === "169.254.170.23" ||
    h === "fd00:ec2::254" ||
    h === "metadata.google.internal" ||
    h === "metadata" ||
    h === "100.100.100.200" ||
    h === "instance-data" ||
    h === "instance-data.ec2.internal"
  );
}

/** Hosts whose common use, from an agent, is catching data or tunnelling out. */
const CAPTURE_HOSTS: readonly string[] = [
  "webhook.site",
  "requestbin.com",
  "requestbin.net",
  "pipedream.net",
  "pipedream.com",
  "ngrok.io",
  "ngrok.app",
  "ngrok.dev",
  "ngrok-free.app",
  "ngrok-free.dev",
  "trycloudflare.com",
  "interact.sh",
  "interactsh.com",
  "oast.pro",
  "oast.live",
  "oast.site",
  "oast.online",
  "oast.fun",
  "oast.me",
  "burpcollaborator.net",
  "oastify.com",
  "dnslog.cn",
  "ceye.io",
  "requestcatcher.com",
  "postb.in",
  "ptsv2.com",
  "ptsv3.com",
  "beeceptor.com",
  "hookbin.com",
  "canarytokens.com",
  "transfer.sh",
  "0x0.st",
  "file.io",
  "temp.sh",
  "termbin.com",
  "ix.io",
  "sprunge.us",
  "pastebin.com",
  "paste.ee",
  "hastebin.com",
  "dpaste.com",
  "dpaste.org",
  "ghostbin.co",
  "serveo.net",
  "localtunnel.me",
  "loca.lt",
  "localhost.run",
  "lhr.life",
  "bore.pub",
  "playit.gg",
  "tunnelmole.net",
];

export function isCaptureHost(host: string): boolean {
  return hostInList(host, CAPTURE_HOSTS);
}

/** A URL that anyone holding it can post to: chat webhooks with the secret in the path. */
export function isCaptureUrl(p: ParsedUrl): boolean {
  if (isCaptureHost(p.host)) return true;
  if (hostMatches(p.host, "discord.com") || hostMatches(p.host, "discordapp.com")) return /\/api(?:\/v\d+)?\/webhooks\//i.test(p.path);
  if (p.host === "api.telegram.org") return /^\/bot[0-9]+:/i.test(p.path);
  return false;
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let e = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

/**
 * A host name built to carry data out through DNS: a long or random-looking
 * label in front of a domain (the CVE-2025-55284 pattern: `<secret>.attacker.com`).
 */
export function isDnsExfilShape(host: string): boolean {
  const h = normalizeHost(host);
  if (isIpv4(h) || isIpv6(h)) return false;
  if (h.length > 100) return true;
  const labels = h.split(".");
  if (labels.length < 3) return false;
  // Only the labels below the registrable part can carry data; take everything but the last two.
  for (const label of labels.slice(0, -2)) {
    // Hyphenated words (preview deployments, bucket names) are addresses, not payloads.
    if (/^[a-z]+(?:-[a-z]+)*$/.test(label)) {
      if (label.length >= 60) return true;
      continue;
    }
    if (/^[0-9a-f]{16,}$/.test(label)) return true;
    if (label.length >= 24 && entropy(label) >= 3.5) return true;
    if (label.length >= 16 && /\d/.test(label) && /[a-z]/.test(label) && entropy(label) >= 3.6) return true;
  }
  return false;
}

/**
 * How much data a URL could be carrying, beyond a normal address: a long
 * random-looking path segment, query value, fragment or subdomain label.
 */
export function urlCarriesData(p: ParsedUrl): boolean {
  if (isDnsExfilShape(p.host)) return true;
  const pieces: string[] = [];
  for (const seg of p.path.split("/")) pieces.push(safeDecode(seg));
  const q = p.query.replace(/^[?#]/, "");
  for (const kv of q.split(/[&#;]/)) {
    const eq = kv.indexOf("=");
    pieces.push(safeDecode(eq === -1 ? kv : kv.slice(eq + 1)));
  }
  for (const piece of pieces) {
    if (piece.length >= 64) return true;
    if (piece.length >= 20 && entropy(piece) >= 4.0 && !/^[a-z-]+$/i.test(piece)) return true;
  }
  return q.length > 512;
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}
