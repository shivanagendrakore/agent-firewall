/**
 * v0.3 `run`: the network side, pure (no I/O). Which hosts the run's proxy
 * admits, and the run's budgets. The host list is not a second policy: it is
 * `profileFromPolicy()`, the derivation doctor --fix uses for Claude Code's
 * sandbox, so both sandboxes admit exactly the same hosts (docs/run.md).
 *
 * Run mode has no one to ask in the middle of a connection and no view of
 * what the agent read, so it is treated as an untrusted session from the
 * start and a reached budget refuses (fail closed) instead of asking.
 */

import type { FirewallConfig } from "../types.js";
import { budgetPolicy, INSTALL_HOSTS, type BudgetPolicy } from "./budgets.js";
import { knownHostsPolicy } from "../policy-knownhosts.js";
import { canonicalIpv4, hostInList, isCaptureHost, isIpv4, isIpv6, isLoopback, isMetadataEndpoint, isRawIp, normalizeHost, v6Groups } from "./network.js";
import { domainAdmits, profileFromPolicy, sandboxDomains, UPLOAD_CAPABLE, type HostLabel } from "./sandbox.js";

/** The only ports the proxy connects to: HTTPS and plain HTTP. */
export const RUN_PORTS: readonly number[] = [443, 80];

/** Why the proxy refused (also the `why` of a `run_net` log entry). */
export type RunWhy = "bad-host" | "port" | "raw-ip" | "loopback" | "metadata" | "capture" | "denied-host" | "not-listed" | "resolves-internal" | "sni-mismatch" | "not-tls" | "budget" | "upstream";

export interface RunNetPolicy {
  /** The derived host list: the policy's fetch and send hosts plus --send-host, in the sandbox's syntax. */
  allowed: HostLabel[];
  /** Policy entries left out of the list, with why (same as doctor --fix reports). */
  dropped: { pattern: string; reason: string }[];
  /** The policy's denyHosts (firewall syntax). */
  denyHosts: string[];
  /** --send-host entries for this run (firewall syntax, as given). */
  sendHosts: string[];
  /** Hosts whose traffic is not counted: sendAllowHosts, --send-host, budgets.exemptHosts. */
  exempt: string[];
  budgets: BudgetPolicy;
  /**
   * knownHosts.mode is not "off": the hosts a person approved for the workspace (the same per-project list
   * the hooks use, src/runtime/knownhosts.ts) are admitted too, as fetch-only hosts under the counted
   * budgets. They are passed to judgeHost() as they are when each connection opens, so a host approved in
   * the agent's own prompt during the run is admitted from then on. The built-in known hosts are not added
   * (they include model APIs that receive your code by design; pass --send-host for the one your agent uses).
   */
  knownHosts: boolean;
}

/**
 * The run's network policy, from the firewall policy plus the person's --send-host list. A --send-host
 * entry the sandbox derivation would leave out (an IP address, loopback, a metadata or capture host,
 * one in denyHosts, not a host name) is a problem: run refuses to start rather than drop it silently.
 */
export function runNetPolicy(cfg: FirewallConfig, opts: { sendHosts?: readonly string[]; knownHostsFrom?: Pick<FirewallConfig, "knownHosts"> } = {}): { policy: RunNetPolicy; problems: string[] } {
  const sendHosts = [...new Set((opts.sendHosts ?? []).map((h) => h.trim()).filter((h) => h !== ""))];
  const derived = profileFromPolicy({ ...cfg, sendAllowHosts: [...cfg.sendAllowHosts, ...sendHosts] });
  const problems: string[] = [];
  for (const h of sendHosts) {
    const d = derived.dropped.find((x) => x.pattern === h);
    if (d !== undefined) problems.push(`--send-host ${h} cannot be admitted: ${d.reason}`);
    else if (sandboxDomains(h) === null) problems.push(`--send-host ${h} is not a host name`);
  }
  const bud = budgetPolicy(cfg);
  return {
    policy: {
      allowed: derived.hosts,
      dropped: derived.dropped.filter((x) => !sendHosts.includes(x.pattern)),
      denyHosts: [...cfg.denyHosts],
      sendHosts,
      exempt: [...cfg.sendAllowHosts, ...sendHosts, ...bud.exemptHosts],
      budgets: bud,
      // run passes the user and managed policy only: a repository's policy may switch the hooks' question on,
      // never what the proxy admits.
      knownHosts: knownHostsPolicy(opts.knownHostsFrom ?? cfg).mode !== "off",
    },
    problems,
  };
}

export interface RunJudgement {
  verdict: "allow" | "deny";
  why?: RunWhy;
  /** The catalogue rule when one says the same thing (FW-RAW-IP, FW-METADATA, FW-CAPTURE-HOST). */
  rule?: string;
  /** For an allowed host: fetch-only (fetchAllowHosts only) or send. */
  kind?: HostLabel["kind"];
  /** Admitted because a person approved the host for this workspace (knownHosts), not by the policy's lists. */
  known?: boolean;
  /** For an approved host: it accepts uploads too (a registry, a code host: UPLOAD_CAPABLE). */
  uploadCapable?: boolean;
  /** One plain sentence: what was refused and which policy key would change it. */
  reason: string;
}

const HOST_CHARS = /^[a-z0-9.\-_:[\]]+$/;

/**
 * Whether the run's proxy may open a connection to host:port (before DNS and TLS checks). `known` is the
 * workspace's approved hosts (knownHosts; read only when `p.knownHosts`): exact names, admitted after every
 * refusal above the list (port, address form, metadata, capture hosts, denyHosts) has had its say.
 */
export function judgeHost(p: RunNetPolicy, rawHost: string, port: number, known: readonly string[] = []): RunJudgement {
  const host = normalizeHost(rawHost.trim());
  if (host === "" || !HOST_CHARS.test(host) || host.length > 253) return { verdict: "deny", why: "bad-host", reason: `"${rawHost.slice(0, 80)}" is not a host name` };
  if (!Number.isInteger(port) || !RUN_PORTS.includes(port)) return { verdict: "deny", why: "port", reason: `port ${port} on ${host}: run's proxy connects only to ports 443 and 80` };
  const v4 = canonicalIpv4(host);
  if (isMetadataEndpoint(host) || (v4 !== null && isMetadataEndpoint(v4))) return { verdict: "deny", why: "metadata", rule: "FW-METADATA", reason: `${host} is a cloud metadata endpoint, which can hand out this machine's cloud credentials; it is never admitted` };
  if (isLoopback(host)) return { verdict: "deny", why: "loopback", reason: `${host} is this machine (loopback); the sandbox never reaches the host's local services through the proxy` };
  if (isRawIp(host) || v4 !== null) return { verdict: "deny", why: "raw-ip", rule: "FW-RAW-IP", reason: `${host} is a bare IP address; run admits named hosts from fetchAllowHosts and sendAllowHosts only` };
  if (isCaptureHost(host)) return { verdict: "deny", why: "capture", rule: "FW-CAPTURE-HOST", reason: `${host} is a request catcher or tunnel service; it is never admitted` };
  if (hostInList(host, p.denyHosts)) return { verdict: "deny", why: "denied-host", reason: `${host} is in denyHosts` };
  const match = p.allowed.find((h) => domainAdmits(h.domain, host));
  if (match === undefined) {
    if (p.knownHosts && known.some((k) => normalizeHost(k) === host)) {
      const up = hostInList(host, UPLOAD_CAPABLE);
      return { verdict: "allow", kind: "fetch-only", known: true, ...(up ? { uploadCapable: true } : {}), reason: `${host} is admitted (you approved it for this project: knownHosts${up ? "; it accepts uploads too" : ""})` };
    }
    const approve = p.knownHosts ? `, approve it for this project in your own terminal (launchsafe-firewall hosts allow ${host})` : "";
    return { verdict: "deny", why: "not-listed", reason: `${host} is not in fetchAllowHosts or sendAllowHosts${p.knownHosts ? " and you have not approved it for this project" : ""}; add it to your policy${approve} (or pass --send-host ${host} for this run) if the agent needs it` };
  }
  return { verdict: "allow", kind: match.kind, reason: `${host} is admitted (${match.domain}, ${match.kind})` };
}

/** What a DNS answer is, for the proxy's rebinding check. */
export type AnswerClass =
  /** Never connected to: metadata, link-local, unspecified, multicast, reserved, garbage. */
  | { kind: "never"; why: string }
  /** This machine (127/8, ::1). */
  | { kind: "loopback"; why: string }
  /** A private network: 10/8, 172.16/12, 192.168/16, 100.64/10 (CGNAT), fc00::/7 (ULA), fec0::/10 (site-local). */
  | { kind: "private"; why: string }
  | { kind: "public" };

function classifyV4(ip: string): AnswerClass {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return { kind: "never", why: "not an address" };
  const [a, b] = parts as [number, number];
  if (isMetadataEndpoint(ip)) return { kind: "never", why: "a cloud metadata address" };
  if (a === 127) return { kind: "loopback", why: "loopback" };
  if (a === 0) return { kind: "never", why: "an unspecified address" };
  if (a === 169 && b === 254) return { kind: "never", why: "a link-local address" };
  if (a >= 224) return { kind: "never", why: "a multicast or reserved address" };
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return { kind: "private", why: "a private address" };
  if (a === 100 && b >= 64 && b <= 127) return { kind: "private", why: "a carrier-grade NAT (shared) address" };
  const c = parts[2] as number;
  // Special-purpose blocks (RFC 6890) that are not the public internet: a name answering with one of them is
  // pointing somewhere local or nowhere.
  if (a === 192 && b === 0 && c === 0) return { kind: "never", why: "an IETF protocol-assignment address (192.0.0.0/24)" };
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return { kind: "never", why: "a documentation (TEST-NET) address" };
  if (a === 198 && (b === 18 || b === 19)) return { kind: "never", why: "a benchmarking address (198.18.0.0/15)" };
  return { kind: "public" };
}

/** The class of an address a DNS lookup returned (IPv4, IPv6, and IPv4 inside IPv6 in its mapped forms). */
export function classifyAnswer(ip: string): AnswerClass {
  if (isIpv4(ip)) return classifyV4(ip);
  if (isIpv6(ip) || ip.includes(":")) {
    const g = v6Groups(ip);
    if (g === null) return { kind: "never", why: "not an address" };
    if (isMetadataEndpoint(ip)) return { kind: "never", why: "a cloud metadata address" };
    const v4 = (): string => `${(g[6] as number) >> 8}.${(g[6] as number) & 255}.${(g[7] as number) >> 8}.${(g[7] as number) & 255}`;
    // ::ffff:a.b.c.d (mapped) and ::ffff:0:a.b.c.d (translated) reach the IPv4 address.
    if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return classifyV4(v4());
    if (g.slice(0, 4).every((x) => x === 0) && g[4] === 0xffff && g[5] === 0) return classifyV4(v4());
    if (g.slice(0, 7).every((x) => x === 0) && (g[7] === 0 || g[7] === 1)) return g[7] === 1 ? { kind: "loopback", why: "loopback" } : { kind: "never", why: "an unspecified address" };
    // ::a.b.c.d (the deprecated IPv4-compatible form): judged as the IPv4 address it carries.
    if (g.slice(0, 6).every((x) => x === 0)) return classifyV4(v4());
    if (((g[0] as number) & 0xffc0) === 0xfe80) return { kind: "never", why: "a link-local address" };
    if (((g[0] as number) & 0xff00) === 0xff00) return { kind: "never", why: "a multicast address" };
    if (((g[0] as number) & 0xfe00) === 0xfc00) return { kind: "private", why: "a private (unique local) address" };
    // fec0::/10: the deprecated site-local block, still routed inside some networks.
    if (((g[0] as number) & 0xffc0) === 0xfec0) return { kind: "private", why: "a site-local address (fec0::/10)" };
    // 64:ff9b::/96 (NAT64): the IPv4 address in the low 32 bits is what is reached.
    if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return classifyV4(v4());
    // 64:ff9b:1::/48 (local-use NAT64, RFC 8215): a translator inside someone's network, not the public internet.
    if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return { kind: "private", why: "a local-use NAT64 address (64:ff9b:1::/48)" };
    // 6to4 (2002::/16) carries the IPv4 address in groups 1 and 2; Teredo (2001::/32) carries the client's, bit-inverted, in the last two.
    if (g[0] === 0x2002) return classifyV4(`${(g[1] as number) >> 8}.${(g[1] as number) & 255}.${(g[2] as number) >> 8}.${(g[2] as number) & 255}`);
    if (g[0] === 0x2001 && g[1] === 0) {
      const x = (n: number): number => ~n & 0xffff;
      return classifyV4(`${x(g[6] as number) >> 8}.${x(g[6] as number) & 255}.${x(g[7] as number) >> 8}.${x(g[7] as number) & 255}`);
    }
    if (g[0] === 0x2001 && g[1] === 0x0db8) return { kind: "never", why: "a documentation address (2001:db8::/32)" };
    return { kind: "public" };
  }
  return { kind: "never", why: "not an address" };
}

/**
 * Names whose DNS answers may be local: `loopback` (the person passed --allow-localhost on macOS, where
 * the sandbox reaches 127.0.0.1 directly anyway) and `privateHosts` (run.privateHosts in user or managed
 * policy: company hosts that resolve to 10/8 and the like).
 */
export interface LocalAnswers {
  loopback: boolean;
  privateHosts: readonly string[];
}

export const NO_LOCAL_ANSWERS: LocalAnswers = { loopback: false, privateHosts: [] };

/**
 * Why the proxy must not connect to an address an admitted name resolved to (DNS rebinding: a public
 * name that answers with this machine or a private network), or null when it may. Metadata,
 * link-local, unspecified and multicast answers are never connected to, whatever the policy says.
 */
export function internalAddress(ip: string, host = "", local: LocalAnswers = NO_LOCAL_ANSWERS): string | null {
  const c = classifyAnswer(ip);
  if (c.kind === "public") return null;
  if (c.kind === "loopback") return local.loopback ? null : `${c.why} (allowed only with --allow-localhost on macOS)`;
  if (c.kind === "private") return host !== "" && hostInList(normalizeHost(host), local.privateHosts) ? null : `${c.why} (list the host in run.privateHosts in your user policy if it is a company host)`;
  return c.why;
}

// --- budgets ----------------------------------------------------------------------------------------

export interface RunBudgetHit {
  rule: "FW-BUDGET-BYTES" | "FW-BUDGET-REQUESTS";
  /** bytes:<host>, bytes:*, bytes:registries, req:<host>. */
  key: string;
  limit: number;
  used: number;
  reason: string;
}

/** Which budget row a host is counted under (docs/run.md, "Budgets in run mode"). */
export type RunTier = "exempt" | "registry" | "other";

const TEN_MINUTES = 10 * 60 * 1000;

function kb(n: number): string {
  return n < 1024 ? `${n} bytes` : n < 1024 * 1024 ? `${Math.round(n / 102.4) / 10} KB` : `${Math.round(n / 104857.6) / 10} MB`;
}

/**
 * The run's budget counters. Mutable, but pure: the clock is passed in. Once a budget is reached its
 * key stays exhausted for the rest of the run (nobody is there to raise it).
 */
export class RunBudgets {
  private readonly bytes = new Map<string, number>();
  private readonly requests = new Map<string, number[]>();
  private readonly exhausted = new Map<string, RunBudgetHit>();

  constructor(private readonly p: RunNetPolicy) {}

  tier(host: string): RunTier {
    const h = normalizeHost(host);
    if (!this.p.budgets.enabled || hostInList(h, this.p.exempt)) return "exempt";
    return hostInList(h, INSTALL_HOSTS) ? "registry" : "other";
  }

  /** The budget that already stops this host, if any. */
  blocked(host: string): RunBudgetHit | null {
    const h = normalizeHost(host);
    const t = this.tier(h);
    if (t === "exempt") return null;
    return this.exhausted.get(`bytes:${h}`) ?? this.exhausted.get(`req:${h}`) ?? this.exhausted.get(t === "registry" ? "bytes:registries" : "bytes:*") ?? null;
  }

  /** Counts one connection or request; a hit when the host is blocked or this one is over the 10-minute limit. */
  admitRequest(host: string, now: number): RunBudgetHit | null {
    const h = normalizeHost(host);
    const t = this.tier(h);
    if (t === "exempt") return null;
    const b = this.blocked(h);
    if (b !== null) return b;
    const limit = t === "registry" ? this.p.budgets.trusted.requestsPerHost10m : this.p.budgets.untrusted.requestsPerHost10m;
    const recent = (this.requests.get(h) ?? []).filter((x) => now - x < TEN_MINUTES);
    if (recent.length + 1 > limit) {
      const hit: RunBudgetHit = { rule: "FW-BUDGET-REQUESTS", key: `req:${h}`, limit, used: recent.length, reason: `${recent.length} connections to ${h} in 10 minutes reached run's limit of ${limit} (budgets.${t === "registry" ? "trusted" : "untrusted"}.requestsPerHost10m)` };
      this.exhausted.set(hit.key, hit);
      return hit;
    }
    recent.push(now);
    this.requests.set(h, recent);
    return null;
  }

  /** Adds bytes sent to a host; a hit (and the key stays exhausted) when that crosses a limit. */
  addBytes(host: string, n: number): RunBudgetHit | null {
    const h = normalizeHost(host);
    const t = this.tier(h);
    if (t === "exempt" || n <= 0) return null;
    const b = this.blocked(h);
    if (b !== null) return b;
    const checks: { key: string; limit: number; what: string }[] =
      t === "registry"
        ? [{ key: "bytes:registries", limit: this.p.budgets.trusted.bytesTotal, what: "to package registries and code hosts together (budgets.trusted.bytesTotal)" }]
        : [
            { key: `bytes:${h}`, limit: this.p.budgets.untrusted.bytesPerHost, what: `to ${h} (budgets.untrusted.bytesPerHost)` },
            { key: "bytes:*", limit: this.p.budgets.untrusted.bytesTotal, what: "to counted hosts together (budgets.untrusted.bytesTotal)" },
          ];
    let first: RunBudgetHit | null = null;
    for (const c of checks) {
      const used = (this.bytes.get(c.key) ?? 0) + n;
      this.bytes.set(c.key, used);
      if (used > c.limit && !this.exhausted.has(c.key)) {
        const hit: RunBudgetHit = { rule: "FW-BUDGET-BYTES", key: c.key, limit: c.limit, used, reason: `${kb(used)} sent ${c.what} passed run's limit of ${kb(c.limit)}` };
        this.exhausted.set(c.key, hit);
        first ??= hit;
      }
    }
    return first;
  }

  /** Bytes counted under a key so far (for tests and the summary). */
  used(key: string): number {
    return this.bytes.get(key) ?? 0;
  }
}
