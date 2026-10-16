/**
 * `openshell policy`: an OpenShell sandbox policy (YAML) that mirrors the firewall's host lists, and the
 * gateway registration for the firewall's middleware (docs/sandboxes.md). Pure: the firewall policy in, text
 * out.
 *
 * The host list is `profileFromPolicy()`, the derivation `run` and `doctor --fix` use, so OpenShell admits the
 * same hosts the firewall's own sandboxes do (IP addresses, loopback, metadata and capture hosts, denyHosts
 * and their wildcards are never listed). What OpenShell's policy cannot say, and the firewall's middleware
 * says instead:
 * - a denied host below an admitted wildcard (denyHosts "gist.github.com" under "github.com"): OpenShell's
 *   network rules have no host exclusions; the middleware denies it (the engine's deny list);
 * - anything about session taint, secrets or private data in a body: the middleware.
 */

import type { FirewallConfig } from "../types.js";
import { profileFromPolicy, type HostLabel } from "../engine/sandbox.js";
import { AGENT_PRESETS, presetHostNames, type PresetAgent } from "../engine/agent-presets.js";

export interface OpenShellPolicyOptions {
  agent?: PresetAgent;
  /** Extra send hosts (firewall syntax), as run's --send-host. */
  sendHosts?: readonly string[];
  /** The middleware registration name in the gateway's TOML (default "launchsafe-firewall"); null: no middleware. */
  middleware?: string | null;
  /** The endpoint OpenShell reaches the service at, for the TOML comment. */
  endpoint?: string;
}

export interface OpenShellPolicy {
  yaml: string;
  /** Hosts in OpenShell's syntax, by rule. */
  hosts: { host: string; access: "full" | "read-only"; from: string }[];
  /** Patterns left out, and why. */
  dropped: { pattern: string; reason: string }[];
  /** Denied hosts inside an admitted wildcard: enforced only by the middleware. */
  middlewareOnlyDenies: string[];
  problems: string[];
  /** Said on standard error, the policy still printed: a deny list entry nothing will enforce (--no-middleware). */
  warnings: string[];
}

/** Firewall sandbox domain ("x" exact, "*.x" any subdomain) to OpenShell's endpoint host, or why not. */
export function openShellHost(domain: string): { host: string } | { reason: string } {
  if (!domain.startsWith("*.")) return { host: domain };
  const base = domain.slice(2);
  // OpenShell: a wildcard host needs at least three DNS labels; "**" as the first label spans any depth.
  if (base.split(".").length < 2) return { reason: "OpenShell needs at least three labels in a wildcard host" };
  return { host: `**.${base}` };
}

/** JSON-quoted: every value a person or a policy chose is printed this way, in comments too (no newline can end a comment early). */
const q = (s: string): string => JSON.stringify(s);

// eslint-disable-next-line no-control-regex -- control characters (and the Unicode line separators) are what is refused
const CONTROL = /[\u0000-\u001f\u007f\u0085\u2028\u2029]/;

/** A middleware name as the gateway's TOML registers it. */
const MW_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

const MAX_PATTERNS = 32;
const MAX_ENTRIES = 10;

export function openShellPolicy(cfg: FirewallConfig, o: OpenShellPolicyOptions = {}): OpenShellPolicy {
  const preset = o.agent !== undefined ? AGENT_PRESETS[o.agent] : undefined;
  const modelHosts = preset !== undefined ? presetHostNames(preset) : [];
  const problems: string[] = [];
  const warnings: string[] = [];
  const refuse = (problem: string): OpenShellPolicy => ({ yaml: "", hosts: [], dropped: [], middlewareOnlyDenies: [], problems: [problem], warnings: [] });
  // Values from the command line and the policy are checked before anything is printed: a control character
  // (a newline above all) in a host could end a comment and start a YAML key of its own.
  const extra = [...(o.sendHosts ?? [])];
  for (const h of extra) if (CONTROL.test(h)) return refuse(`--send-host ${q(h.slice(0, 120))} has a control character`);
  for (const k of ["fetchAllowHosts", "sendAllowHosts", "denyHosts"] as const) for (const h of cfg[k]) if (CONTROL.test(h)) return refuse(`${k} entry ${q(h.slice(0, 120))} has a control character`);
  if (o.endpoint !== undefined && CONTROL.test(o.endpoint)) return refuse("--endpoint has a control character");
  if (typeof o.middleware === "string" && !MW_NAME.test(o.middleware)) return refuse(`--middleware ${q(o.middleware.slice(0, 80))} is not a name (letters, digits, '.', '_' and '-', at most 64)`);
  const derived = profileFromPolicy({ ...cfg, sendAllowHosts: [...cfg.sendAllowHosts, ...extra] });
  for (const h of extra) {
    const d = derived.dropped.find((x) => x.pattern === h);
    if (d !== undefined) problems.push(`--send-host ${q(h)} cannot be admitted: ${d.reason}`);
  }
  const dropped = [...derived.dropped];
  const hosts: OpenShellPolicy["hosts"] = [];
  const add = (h: HostLabel): void => {
    const os = openShellHost(h.domain);
    if ("reason" in os) {
      dropped.push({ pattern: h.domain, reason: os.reason });
      return;
    }
    if (hosts.some((x) => x.host === os.host)) return;
    // A host the policy lists for fetching only is read-only, unless it is a code host or registry, where
    // fetching itself uses POST (git's smart HTTP); uploads there are judged by the middleware.
    hosts.push({ host: os.host, access: h.kind === "send" || h.uploadCapable ? "full" : "read-only", from: h.kind === "send" ? "sendAllowHosts" : "fetchAllowHosts" });
  };
  for (const h of derived.hosts) add(h);
  const middlewareOnlyDenies = cfg.denyHosts.filter((d) => {
    const base = d.replace(/^[=*.]+/, "");
    return derived.hosts.some((h) => h.domain.startsWith("*.") && base.endsWith(`.${h.domain.slice(2)}`));
  });
  const mw = o.middleware === undefined ? "launchsafe-firewall" : o.middleware;
  const includes = hosts.map((h) => h.host);
  if (mw !== null && includes.length > MAX_PATTERNS * MAX_ENTRIES) problems.push(`the policy lists ${includes.length} hosts; one OpenShell policy can attach a middleware to at most ${MAX_PATTERNS * MAX_ENTRIES}`);
  if (mw === null && middlewareOnlyDenies.length > 0) {
    warnings.push(`without the middleware nothing refuses ${middlewareOnlyDenies.map(q).join(", ")}: each is on your denyHosts but inside a wildcard this policy admits, and OpenShell's network rules cannot subtract a host. Keep the middleware, or remove the wildcard`);
  }

  const lines: string[] = [];
  lines.push("# OpenShell sandbox policy written by launchsafe-firewall openshell policy (docs/sandboxes.md).");
  lines.push("# It mirrors the firewall's host lists (fetchAllowHosts, sendAllowHosts, denyHosts); regenerate it when they change.");
  if (mw !== null) {
    lines.push("#");
    lines.push("# The firewall's middleware must be registered in the gateway's TOML, and running, before the gateway starts:");
    lines.push("#");
    lines.push("#   [[openshell.supervisor.middleware]]");
    lines.push(`#   name = ${q(mw)}`);
    lines.push(`#   grpc_endpoint = ${q(o.endpoint ?? "https://<this machine, as the gateway and sandboxes reach it>:50051")}`);
    lines.push('#   tls_ca_cert_path = "/path/to/ca.pem"        # or, for local development only: allow_insecure_transport = true');
    lines.push(`#   max_payload_bytes = ${512 * 1024}`);
    lines.push('#   timeout = "500ms"');
  }
  if (preset !== undefined) {
    lines.push("#");
    lines.push(`# ${preset.label}'s model API (${modelHosts.map(q).join(", ")}) is admitted below and left out of the middleware: the`);
    lines.push("# whole conversation goes there on every turn. Nothing judges or counts what is sent there: anything the agent");
    lines.push("# reads can leave through it. Attach its key as an OpenShell provider so the agent never holds it.");
  }
  if (middlewareOnlyDenies.length > 0) {
    lines.push("#");
    if (mw !== null) lines.push(`# denyHosts inside an admitted wildcard, refused only by the middleware: ${middlewareOnlyDenies.map(q).join(", ")}`);
    else lines.push(`# WARNING: denyHosts inside an admitted wildcard, and NOT refused (no middleware): ${middlewareOnlyDenies.map(q).join(", ")}`);
  }
  for (const d of dropped) lines.push(`# left out: ${q(d.pattern)} (${q(d.reason)})`);
  lines.push("");
  lines.push("version: 1");
  lines.push("");
  lines.push("filesystem_policy:");
  lines.push("  include_workdir: true");
  lines.push("  # Landlock cannot make a path inside the workdir read-only: .git/hooks, .claude/settings.json and the");
  lines.push("  # other files run's sandbox protects stay writable here (the firewall's hooks still judge the agent's writes).");
  lines.push("  read_only: [/usr, /lib, /etc]");
  lines.push("  read_write: [/tmp]");
  lines.push("");
  const netAt = lines.length;
  lines.push("network_policies:");
  const rule = (key: string, name: string, eps: { host: string; access: string }[]): void => {
    if (eps.length === 0) return;
    lines.push(`  ${key}:`);
    lines.push(`    name: ${q(name)}`);
    lines.push("    endpoints:");
    for (const e of eps) {
      lines.push(`      - host: ${q(e.host)}`);
      lines.push("        ports: [443, 80]");
      lines.push("        protocol: rest");
      lines.push("        enforcement: enforce");
      lines.push(`        access: ${e.access}`);
    }
    lines.push("    binaries:");
    lines.push('      # Any program in the sandbox; list the agent and the tools it needs to narrow this.');
    lines.push('      - path: "/**"');
  };
  if (modelHosts.length > 0) rule("agent_model_api", `${preset?.label ?? "agent"} model API`, modelHosts.filter((h) => !includes.includes(h)).map((h) => ({ host: h, access: "full" })));
  rule("launchsafe_send", "LaunchSafe sendAllowHosts", hosts.filter((h) => h.from === "sendAllowHosts"));
  rule("launchsafe_fetch", "LaunchSafe fetchAllowHosts", hosts.filter((h) => h.from === "fetchAllowHosts"));
  if (lines.length === netAt + 1) lines[netAt] = "network_policies: {}";
  if (mw !== null && includes.length > 0) {
    lines.push("");
    lines.push("network_middlewares:");
    const exclude = modelHosts.filter((m) => hosts.some((h) => (h.host.startsWith("**.") ? m.endsWith(`.${h.host.slice(3)}`) : h.host === m)));
    for (let i = 0; i * MAX_PATTERNS < includes.length && i < MAX_ENTRIES; i++) {
      lines.push(`  launchsafe-firewall-${i + 1}:`);
      lines.push(`    name: ${q("LaunchSafe Agent Firewall")}`);
      lines.push(`    middleware: ${q(mw)}`);
      lines.push(`    order: ${(i + 1) * 10}`);
      lines.push("    # fail_closed: a middleware failure (the firewall down, an error) blocks the traffic. Keep it.");
      lines.push("    on_error: fail_closed");
      lines.push("    config:");
      lines.push("      # One firewall session per sandbox; nobody watches the network, so an ask is a hold in the queue.");
      lines.push("      attended: false");
      lines.push("    endpoints:");
      lines.push(`      include: [${includes.slice(i * MAX_PATTERNS, (i + 1) * MAX_PATTERNS).map(q).join(", ")}]`);
      if (exclude.length > 0) lines.push(`      exclude: [${exclude.map(q).join(", ")}]`);
    }
  }
  // The last check: one element per line, and nothing in any line that could start another.
  const bad = lines.findIndex((l) => CONTROL.test(l));
  if (bad !== -1) return refuse(`internal error: generated line ${bad + 1} has a control character; nothing was printed`);
  return { yaml: `${lines.join("\n")}\n`, hosts, dropped, middlewareOnlyDenies, problems, warnings };
}
