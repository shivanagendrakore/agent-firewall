/**
 * The vendored network predicates, with the ones the extension needs stricter
 * than upstream. The vendored file is never edited; everything under
 * src/engine imports network predicates from here.
 */
import { canonicalIpv4, normalizeHost } from "../vendor/firewall/engine/network.js";

export * from "../vendor/firewall/engine/network.js";

const METADATA_V4 = new Set(["169.254.169.254", "169.254.170.2", "100.100.100.200", "168.63.129.16", "192.0.0.192"]);
const METADATA_V6 = new Set(["fd00:ec2:0:0:0:0:0:254"]);
const METADATA_NAMES = new Set(["metadata.google.internal", "metadata.goog", "metadata", "instance-data", "instance-data.ec2.internal"]);

/** The eight 16-bit groups of an IPv6 literal (no brackets; an embedded dotted quad allowed), or null. */
function ipv6Groups(h: string): number[] | null {
  if (!/^[0-9a-f:.]+$/i.test(h) || !h.includes(":")) return null;
  let s = h;
  const dotted = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (dotted !== null) {
    const q = dotted.slice(1).map(Number);
    if (q.some((n) => n > 255)) return null;
    s = `${s.slice(0, dotted.index)}${(((q[0] as number) << 8) | (q[1] as number)).toString(16)}:${(((q[2] as number) << 8) | (q[3] as number)).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parse = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    for (const g of part.split(":")) {
      if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = parse(halves[0] as string);
  const tail = halves.length === 2 ? parse(halves[1] as string) : [];
  if (head === null || tail === null) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  const fill = 8 - head.length - tail.length;
  if (fill < 1) return null;
  return [...head, ...new Array<number>(fill).fill(0), ...tail];
}

const quad = (hi: number, lo: number): string => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;

/** Every IPv4 address an IPv6 literal embeds: mapped, compatible, NAT64, SIIT and 6to4 forms. */
function embeddedIpv4(g: readonly number[]): string[] {
  const out: string[] = [];
  const zero = (from: number, to: number): boolean => g.slice(from, to).every((x) => x === 0);
  if (zero(0, 5) && (g[5] === 0xffff || g[5] === 0)) out.push(quad(g[6] as number, g[7] as number)); // ::ffff:a.b.c.d and ::a.b.c.d
  if (g[0] === 0x64 && g[1] === 0xff9b && zero(2, 6)) out.push(quad(g[6] as number, g[7] as number)); // 64:ff9b::/96
  if (zero(0, 4) && g[4] === 0xffff && g[5] === 0) out.push(quad(g[6] as number, g[7] as number)); // ::ffff:0:a.b.c.d
  if (g[0] === 0x2002) out.push(quad(g[1] as number, g[2] as number)); // 2002:aabb:ccdd::/48
  return out;
}

/** Cloud instance metadata: hands out the machine's cloud credentials to anything that asks. Every spelling of the address counts. */
export function isMetadataEndpoint(host: string): boolean {
  const h = normalizeHost(host);
  if (METADATA_NAMES.has(h)) return true;
  const v4 = canonicalIpv4(h);
  if (v4 !== null && METADATA_V4.has(v4)) return true;
  const g = ipv6Groups(h);
  if (g === null) return false;
  if (METADATA_V6.has(g.map((x) => x.toString(16)).join(":"))) return true;
  return embeddedIpv4(g).some((a) => METADATA_V4.has(a));
}
