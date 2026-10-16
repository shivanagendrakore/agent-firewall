/**
 * Claude Code's OS sandbox, as far as the engine needs it. Pure: no
 * I/O. Two jobs:
 *
 * 1. `profileFromPolicy`: the `sandbox` settings `doctor --fix` writes, with
 *    the network allowlist derived from the firewall's own host lists, and
 *    each host labelled fetch-only or send (the sandbox sees hosts, never
 *    methods, so a fetch host is reachable for uploads too).
 * 2. `sandboxViolations`: whether a settings change weakens a profile the
 *    firewall installed (policy key
 *    `sandbox.protectInstalledProfile`, on by default): judged like removing the hooks.
 *
 * Setting names were confirmed from the settings schema inside the Claude Code
 * 2.1.289 binary (test/fixtures/claude-2.1.289-sandbox-schema.json); nothing
 * here is guessed. Keys the schema does not have are reported, never written.
 */

import type { FirewallConfig } from "../types.js";
import { canonicalIpv4, hostInList, isCaptureHost, isLoopback, isMetadataEndpoint, isRawIp, normalizeHost } from "./network.js";
import { own, setOwn } from "../own.js";

export type Json = Record<string, unknown>;

/** The Claude Code version whose settings schema the key lists below were read from. */
export const SANDBOX_SCHEMA_VERSION = "2.1.289";

/** `sandbox.*` keys in the 2.1.289 schema. */
export const SANDBOX_KEYS: readonly string[] = ["enabled", "failIfUnavailable", "autoAllowBashIfSandboxed", "allowUnsandboxedCommands", "network", "filesystem", "credentials", "ignoreViolations", "enableWeakerNestedSandbox", "enableWeakerNetworkIsolation", "allowAppleEvents", "excludedCommands", "ripgrep", "bwrapPath", "socatPath"];
/** `sandbox.network.*` keys in the 2.1.289 schema. */
export const SANDBOX_NETWORK_KEYS: readonly string[] = ["allowedDomains", "deniedDomains", "strictAllowlist", "allowManagedDomainsOnly", "allowUnixSockets", "allowAllUnixSockets", "allowLocalBinding", "allowMachLookup", "httpProxyPort", "socksProxyPort", "tlsTerminate"];
/** `sandbox.filesystem.*` keys in the 2.1.289 schema. */
export const SANDBOX_FILESYSTEM_KEYS: readonly string[] = ["allowWrite", "denyWrite", "denyRead", "allowRead", "allowManagedReadPathsOnly", "disabled"];

/** The policy key `sandbox` (src/policy-sandbox.ts validates it). */
export interface SandboxPolicy {
  /**
   * On by default: once `doctor --fix` has installed a profile, an agent change that weakens it is FW-TAMPER
   * (deny), like removing the hooks. false: such a change is an ordinary settings change
   * (FW-AGENT-SETTINGS). Loosening (false): user or managed policy only.
   */
  protectInstalledProfile: boolean;
  /** The profile sets network.strictAllowlist (hosts outside the list are refused, not prompted). User scope only in Claude Code. */
  strictAllowlist: boolean;
  /** `excludedCommands` entries that do not count as an unsandboxed escape (exact patterns). User or managed policy only. */
  safeExcludedCommands: string[];
}

export const DEFAULT_SANDBOX_POLICY: Readonly<SandboxPolicy> = { protectInstalledProfile: true, strictAllowlist: true, safeExcludedCommands: [] };

export function sandboxPolicy(cfg: FirewallConfig): SandboxPolicy {
  const s = cfg.sandbox ?? {};
  return { ...DEFAULT_SANDBOX_POLICY, ...s, safeExcludedCommands: [...(s.safeExcludedCommands ?? DEFAULT_SANDBOX_POLICY.safeExcludedCommands)] };
}

/** What `doctor --fix` merges under the `sandbox` key. */
export interface SandboxProfile {
  enabled: boolean;
  autoAllowBashIfSandboxed: boolean;
  allowUnsandboxedCommands: boolean;
  excludedCommands: string[];
  network: {
    allowedDomains: string[];
    deniedDomains: string[];
    allowLocalBinding: boolean;
    allowUnixSockets: string[];
    strictAllowlist?: boolean;
  };
}

export interface HostLabel {
  /** As written into allowedDomains (exact host or *.suffix). */
  domain: string;
  /** fetch-only: from fetchAllowHosts only; send: in sendAllowHosts. */
  kind: "fetch-only" | "send";
  /** Accepts user content over HTTPS even when used for fetching (a registry, a code host). */
  uploadCapable: boolean;
}

/**
 * Hosts that accept uploads over HTTPS. A sandbox that admits them for fetching admits uploads too;
 * the firewall's rules for git push, npm publish, gh and docker push are what control those.
 */
export const UPLOAD_CAPABLE: readonly string[] = ["github.com", "api.github.com", "uploads.github.com", "gist.github.com", "gitlab.com", "bitbucket.org", "registry.npmjs.org", "npm.pkg.github.com", "pypi.org", "upload.pypi.org", "ghcr.io", "registry-1.docker.io", "crates.io", "rubygems.org", "api.nuget.org", "jsr.io"];

/** Firewall host syntax to the sandbox's: "=x" exact, "*.x" subdomains, "x" the host and its subdomains. Null when it is not a host name. */
export function sandboxDomains(pattern: string): string[] | null {
  const p = pattern.trim().toLowerCase();
  let exact: string | null = null;
  let sub: string | null = null;
  if (p.startsWith("=")) exact = p.slice(1);
  else if (p.startsWith("*.")) sub = p.slice(2);
  else {
    exact = p;
    sub = p;
  }
  const base = normalizeHost(exact ?? sub ?? "");
  if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(base)) return null;
  return [...(exact !== null ? [base] : []), ...(sub !== null ? [`*.${base}`] : [])];
}

/** The host a sandbox domain names (without the wildcard). */
function baseOf(domain: string): string {
  return domain.startsWith("*.") ? domain.slice(2) : domain;
}

/** Whether a sandbox domain (exact or *.suffix) admits a host. */
export function domainAdmits(domain: string, host: string): boolean {
  const h = normalizeHost(host);
  const d = domain.toLowerCase();
  return d.startsWith("*.") ? h.endsWith(`.${d.slice(2)}`) : h === normalizeHost(d);
}

/** Host names of cloud metadata services, for F30's wildcard check. */
const METADATA_NAMES = ["metadata.google.internal", "metadata", "instance-data", "instance-data.ec2.internal"];

function excludedReason(domain: string, deny: readonly string[]): string | null {
  const base = baseOf(domain);
  // F30: any IPv4 spelling (octal, hex, fewer than four parts) is an IP address too.
  if (isRawIp(base) || isLoopback(base) || canonicalIpv4(base) !== null) return "an IP address or loopback";
  if (isMetadataEndpoint(base) || (canonicalIpv4(base) !== null && isMetadataEndpoint(canonicalIpv4(base) as string))) return "a cloud metadata endpoint";
  if (domain.startsWith("*.")) {
    // F30: a wildcard admits every name below its base: one over a metadata name, or over numeric labels
    // (which can complete an IP address), admits what the profile refuses by name.
    if (METADATA_NAMES.some((m) => m.endsWith(`.${base}`))) return "a wildcard that covers a cloud metadata endpoint";
    if (/(?:^|\.)\d+$/.test(base)) return "a wildcard that covers IP addresses";
  }
  if (isCaptureHost(base)) return "a capture or tunnel host";
  if (hostInList(base, deny)) return "in denyHosts";
  return null;
}

export interface DerivedProfile {
  profile: SandboxProfile;
  hosts: HostLabel[];
  /** Policy entries left out of the profile, with why. */
  dropped: { pattern: string; reason: string }[];
}

/**
 * The profile for this policy. Hosts named in prompts (user destinations) are per session and never
 * added; denyHosts become deniedDomains too (Claude Code blocks those even when an allowed wildcard
 * matches them).
 */
export function profileFromPolicy(cfg: FirewallConfig, opts: { strict?: boolean } = {}): DerivedProfile {
  const pol = sandboxPolicy(cfg);
  const hosts = new Map<string, HostLabel>();
  const dropped: DerivedProfile["dropped"] = [];
  const add = (pattern: string, kind: HostLabel["kind"]): void => {
    const domains = sandboxDomains(pattern);
    if (domains === null) {
      dropped.push({ pattern, reason: "not a host name the sandbox can match" });
      return;
    }
    for (const d of domains) {
      const why = excludedReason(d, cfg.denyHosts);
      if (why !== null) {
        if (!dropped.some((x) => x.pattern === pattern)) dropped.push({ pattern, reason: why });
        continue;
      }
      const prev = hosts.get(d);
      const k = prev?.kind === "send" || kind === "send" ? "send" : "fetch-only";
      hosts.set(d, { domain: d, kind: k, uploadCapable: UPLOAD_CAPABLE.some((u) => domainAdmits(d, u)) });
    }
  };
  for (const p of cfg.fetchAllowHosts) add(p, "fetch-only");
  for (const p of cfg.sendAllowHosts) add(p, "send");
  const denied = [...new Set(cfg.denyHosts.flatMap((p) => sandboxDomains(p) ?? []))].sort();
  const allowed = [...hosts.keys()].sort();
  const network: SandboxProfile["network"] = { allowedDomains: allowed, deniedDomains: denied, allowLocalBinding: true, allowUnixSockets: [] };
  if (opts.strict ?? pol.strictAllowlist) network.strictAllowlist = true;
  return {
    profile: { enabled: true, autoAllowBashIfSandboxed: false, allowUnsandboxedCommands: false, excludedCommands: [], network },
    hosts: allowed.map((d) => hosts.get(d) as HostLabel),
    dropped,
  };
}

/** Whether a domain someone put in allowedDomains (or a WebFetch(domain:...) rule) is covered by the policy's hosts. */
export function domainWithinPolicy(domain: string, policyDomains: readonly string[]): boolean {
  const d = domain.trim().toLowerCase();
  if (policyDomains.includes(d)) return true;
  // An exact host inside an allowed wildcard ("api.github.com" under "*.github.com") is narrower, so covered.
  return !d.startsWith("*") && policyDomains.some((p) => p.startsWith("*.") && domainAdmits(p, d));
}

// --- weakening a recorded profile ----------------------------------------------------------------

const obj = (v: unknown): Json | null => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : null);
const list = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

/** The `WebFetch(domain:...)` allow rules of a settings document (Claude Code merges them into the sandbox allowlist). */
export function webFetchDomains(settings: Json | null): string[] {
  const allow = list(obj(settings?.permissions)?.allow);
  return allow.flatMap((r) => {
    const m = /^WebFetch\(domain:([^)]+)\)$/.exec(r.trim());
    return m === null ? [] : [(m[1] as string).trim().toLowerCase()];
  });
}

export interface SandboxGuard {
  /** The `sandbox` object the firewall recorded when it installed the profile. */
  installed: Json;
  /** Domains the current policy allows (an addition inside these is not a weakening). */
  policyDomains: readonly string[];
  /** excludedCommands entries the policy calls safe. */
  safeExcluded: readonly string[];
}

/** Scalar settings whose weak value (after defaults) the firewall's profile avoids. */
const WEAK_SCALARS: readonly { path: string[]; weak: (v: unknown, installed: unknown) => boolean; what: string }[] = [
  { path: ["enabled"], weak: (v) => v !== true, what: "switches the sandbox off (sandbox.enabled)" },
  { path: ["allowUnsandboxedCommands"], weak: (v) => v !== false, what: "lets commands run outside the sandbox (sandbox.allowUnsandboxedCommands)" },
  { path: ["autoAllowBashIfSandboxed"], weak: (v, i) => i === false && v !== false, what: "auto-approves sandboxed commands (sandbox.autoAllowBashIfSandboxed)" },
  { path: ["network", "strictAllowlist"], weak: (v, i) => i === true && v !== true, what: "turns off the strict network allowlist (sandbox.network.strictAllowlist)" },
  { path: ["network", "allowAllUnixSockets"], weak: (v) => v === true, what: "allows every Unix socket (sandbox.network.allowAllUnixSockets)" },
  { path: ["network", "httpProxyPort"], weak: (v) => v !== undefined, what: "routes sandboxed traffic through another proxy (sandbox.network.httpProxyPort)" },
  { path: ["network", "socksProxyPort"], weak: (v) => v !== undefined, what: "routes sandboxed traffic through another proxy (sandbox.network.socksProxyPort)" },
  { path: ["filesystem", "disabled"], weak: (v) => v === true, what: "switches filesystem isolation off (sandbox.filesystem.disabled)" },
  { path: ["enableWeakerNestedSandbox"], weak: (v) => v === true, what: "weakens the sandbox (sandbox.enableWeakerNestedSandbox)" },
  { path: ["enableWeakerNetworkIsolation"], weak: (v) => v === true, what: "weakens network isolation (sandbox.enableWeakerNetworkIsolation)" },
  { path: ["allowAppleEvents"], weak: (v) => v === true, what: "lets sandboxed commands launch other applications (sandbox.allowAppleEvents)" },
  // F29: the programs the sandbox itself runs: a different one is not the sandbox the firewall installed.
  { path: ["bwrapPath"], weak: (v, i) => v !== undefined && JSON.stringify(v) !== JSON.stringify(i), what: "points the sandbox at another bubblewrap program (sandbox.bwrapPath)" },
  { path: ["socatPath"], weak: (v, i) => v !== undefined && JSON.stringify(v) !== JSON.stringify(i), what: "points the sandbox at another socat program (sandbox.socatPath)" },
  { path: ["ripgrep"], weak: (v, i) => v !== undefined && JSON.stringify(v) !== JSON.stringify(i), what: "points the sandbox at another ripgrep program (sandbox.ripgrep)" },
  { path: ["ignoreViolations"], weak: (v, i) => v !== undefined && JSON.stringify(v) !== JSON.stringify(i), what: "ignores sandbox violations (sandbox.ignoreViolations)" },
];

const LISTS: readonly { path: string[]; what: string; allowed?: (x: string, g: SandboxGuard) => boolean }[] = [
  { path: ["excludedCommands"], what: "runs commands outside the sandbox (sandbox.excludedCommands)", allowed: (x, g) => g.safeExcluded.includes(x) },
  { path: ["network", "allowedDomains"], what: "adds hosts the firewall's policy does not list (sandbox.network.allowedDomains)", allowed: (x, g) => domainWithinPolicy(x, g.policyDomains) },
  { path: ["network", "allowUnixSockets"], what: "allows Unix sockets (sandbox.network.allowUnixSockets)" },
  { path: ["network", "allowMachLookup"], what: "allows more system services (sandbox.network.allowMachLookup)" },
  { path: ["filesystem", "allowWrite"], what: "makes more paths writable (sandbox.filesystem.allowWrite)" },
  // F29: allowRead re-opens what denyRead closes.
  { path: ["filesystem", "allowRead"], what: "makes more paths readable (sandbox.filesystem.allowRead)" },
];

const REMOVALS: readonly { path: string[]; what: string }[] = [
  { path: ["network", "deniedDomains"], what: "removes hosts from sandbox.network.deniedDomains" },
  { path: ["filesystem", "denyWrite"], what: "removes paths from sandbox.filesystem.denyWrite" },
  { path: ["filesystem", "denyRead"], what: "removes paths from sandbox.filesystem.denyRead" },
];

function at(o: Json | null, path: readonly string[]): unknown {
  let v: unknown = o;
  for (const k of path) v = own(obj(v), k);
  return v;
}

/**
 * Why changing a settings document from `before` to `after` weakens the sandbox profile the firewall
 * installed (empty when it does not). Only what the change itself introduces counts: a weakness
 * already in `before` (the person's own edit outside the agent) is not the agent's, and narrowing
 * (removing an allowed host, adding a denied one) is always fine. Additions the recorded profile or
 * the current policy already cover are not weakenings either. For a ConfigChange, pass the recorded
 * profile as `before`.
 */
export function sandboxViolations(before: Json | null, after: Json | null, g: SandboxGuard): string[] {
  const b = obj(before?.sandbox);
  const a = obj(after?.sandbox);
  if (a === null) return b !== null ? ["it removes the sandbox settings the firewall installed"] : [];
  const out: string[] = [];
  for (const s of WEAK_SCALARS) {
    const iv = at(g.installed, s.path);
    if (s.weak(at(a, s.path), iv) && (b === null || !s.weak(at(b, s.path), iv))) out.push(`it ${s.what}`);
  }
  for (const l of LISTS) {
    const was = new Set([...list(at(b, l.path)), ...list(at(g.installed, l.path))]);
    const added = list(at(a, l.path)).filter((x) => !was.has(x) && !(l.allowed?.(x, g) ?? false));
    if (added.length > 0) out.push(`it ${l.what}: ${added.slice(0, 5).join(", ")}`);
  }
  for (const r of REMOVALS) {
    const now = new Set(list(at(a, r.path)));
    const gone = list(at(b, r.path)).filter((x) => list(at(g.installed, r.path)).includes(x) && !now.has(x));
    if (gone.length > 0) out.push(`it ${r.what}: ${gone.slice(0, 5).join(", ")}`);
  }
  // Claude Code merges WebFetch(domain:...) allow rules into the sandbox's allowlist.
  const hadRules = new Set(webFetchDomains(before));
  const newRules = webFetchDomains(after).filter((d) => !hadRules.has(d) && !domainWithinPolicy(d, g.policyDomains) && !list(at(g.installed, ["network", "allowedDomains"])).includes(d));
  if (newRules.length > 0) out.push(`it adds WebFetch(domain:...) allow rules, which widen the sandbox's network allowlist: ${newRules.slice(0, 5).join(", ")}`);
  // A sandbox setting this version does not know could weaken it in a newer Claude Code.
  const unknown = Object.keys(a).filter((k) => !SANDBOX_KEYS.includes(k) && (b === null || !(k in b)));
  for (const [sub, keys] of [["network", SANDBOX_NETWORK_KEYS], ["filesystem", SANDBOX_FILESYSTEM_KEYS]] as const) {
    const ao = obj(a[sub]);
    const bo = obj(b?.[sub]);
    if (ao !== null) unknown.push(...Object.keys(ao).filter((k) => !keys.includes(k) && (bo === null || !(k in bo))).map((k) => `${sub}.${k}`));
  }
  if (unknown.length > 0) out.push(`it adds sandbox settings this firewall does not know (${unknown.slice(0, 5).map((k) => `sandbox.${k}`).join(", ")})`);
  return out;
}

// --- F9: settings layers ---------------------------------------------------------------------------

/** A Claude Code settings layer's precedence for the `sandbox` key (local > project > user). */
export function settingsRank(path: string, home: string): number {
  if (/\/\.claude\/settings\.local\.json$/i.test(path)) return 3;
  if (/\/\.claude\/settings\.json$/i.test(path) && path.toLowerCase() !== `${home.replace(/\/+$/, "")}/.claude/settings.json`.toLowerCase()) return 2;
  return 1;
}

/** The .claude directory a project or local settings file sits in (null for user settings). */
function projectDirOf(path: string, home: string): string | null {
  return settingsRank(path, home) >= 2 ? path.replace(/\/settings(?:\.local)?\.json$/i, "").toLowerCase() : null;
}

/** Whether writing settings file `other` can change the effective sandbox of the profile recorded in `recorded`. */
export function layersInteract(recorded: string, other: string, home: string): boolean {
  if (recorded.toLowerCase() === other.toLowerCase()) return false;
  const r = projectDirOf(recorded, home);
  const o = projectDirOf(other, home);
  // A user-level profile is overridden by every project's settings; a project-level one only by its own project's.
  if (r === null) return o !== null;
  return o === r || o === null;
}

function mergeValues(values: unknown[], path: string[], dropRepoDomains: boolean[]): unknown {
  const defined = values.map((v, i) => ({ v, i })).filter((x) => x.v !== undefined);
  if (defined.length === 0) return undefined;
  if (defined.every((x) => Array.isArray(x.v))) {
    const isDomains = path.join(".") === "network.allowedDomains";
    return [...new Set(defined.filter((x) => !(isDomains && dropRepoDomains[x.i] === true)).flatMap((x) => list(x.v)))];
  }
  if (defined.every((x) => obj(x.v) !== null)) {
    const keys = new Set(defined.flatMap((x) => Object.keys(x.v as Json)));
    const out: Json = {};
    for (const k of keys) {
      const m = mergeValues(values.map((v) => own(obj(v), k)), [...path, k], dropRepoDomains);
      if (m !== undefined) setOwn<unknown>(out, k, m);
    }
    return out;
  }
  return (defined[0] as { v: unknown }).v;
}

/**
 * F9: the settings Claude Code would use for the sandbox, from layers given highest precedence first:
 * scalars from the highest layer that sets them, lists merged, WebFetch(domain:...) allow rules merged.
 * With a strict allowlist (honoured from user settings), project and local layers add no hosts.
 */
export function mergeSettingsLayers(layers: readonly { doc: Json | null; repo: boolean }[], strict: boolean): Json {
  const drop = layers.map((l) => strict && l.repo);
  const sandbox = mergeValues(layers.map((l) => l.doc?.sandbox), [], drop);
  const allow = layers.flatMap((l, i) => list(obj(l.doc?.permissions)?.allow).filter((r) => !(drop[i] === true && /^WebFetch\(domain:/.test(r.trim()))));
  const out: Json = { permissions: { allow: [...new Set(allow)] } };
  if (sandbox !== undefined) out.sandbox = sandbox;
  return out;
}

/**
 * F27: settings that weaken the sandbox, which `doctor --fix` removes from what it writes (its profile says
 * "no Unix sockets", "filesystem isolated", no weaker modes); listed so the plan can say what it removed.
 */
export const WEAKENING_KEYS: readonly string[][] = [["network", "allowAllUnixSockets"], ["network", "httpProxyPort"], ["network", "socksProxyPort"], ["filesystem", "disabled"], ["enableWeakerNestedSandbox"], ["enableWeakerNetworkIsolation"], ["allowAppleEvents"], ["ignoreViolations"]];

/** Folds `.`, `..` and repeated slashes in an absolute path (no node:path: this module is in the browser-safe SDK graph). */
function foldAbsolute(p: string): string {
  const out: string[] = [];
  for (const part of p.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") out.pop();
    else out.push(part);
  }
  return `/${out.join("/")}`;
}

/** F28: a filesystem.allowWrite entry that opens the disk, the home directory or a credential store. */
export function broadWritePath(entry: string, home: string): boolean {
  const h = home.replace(/\/+$/, "");
  const raw = entry.trim().replace(/^~(?=\/|$)/, h);
  // `~/proj/../.ssh` is `~/.ssh`: fold `..` and `.` before judging (a relative entry is judged as written).
  const e = (raw.startsWith("/") ? foldAbsolute(raw) : raw).replace(/\/+$/, "") || "/";
  if (e === "/" || e === "" || e === "/Users" || e === "/home" || e === "/root" || e === "/etc" || e === "/usr" || e === "/private" || e === "/var") return true;
  if (h === e || h.startsWith(`${e}/`)) return true;
  return /^(?:\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config|Library|\.claude|\.codex|\.gemini|\.launchsafe-firewall|\.zshrc|\.bashrc|\.profile|\.gitconfig)(?:\/|$)/.test(e.startsWith(`${h}/`) ? e.slice(h.length + 1) : "\u0000");
}
