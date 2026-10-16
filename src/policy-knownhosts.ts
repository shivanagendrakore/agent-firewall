/**
 * The known-hosts policy key, kept apart from policy.ts so it stays one module: `knownHosts`.
 *
 * "Ask before the agent contacts a website it has never contacted in this project." Each project has a
 * list of hosts a person approved, kept in the firewall's own directory (src/runtime/knownhosts.ts), never
 * in the repository. With `mode: "ask"`, contacting a host that is not on that list, not in
 * fetchAllowHosts or sendAllowHosts, and not in the small built-in set asks once (FW-NEW-HOST); the
 * person's yes adds the host to the project's list. `"watch"` asks nothing and records the hosts contacted
 * for `watchDays` days so `hosts review` can propose a list. `"off"` (the default) changes nothing.
 * `builtins: false` turns off the built-in set only: the hosts fetchAllowHosts names (its defaults list the
 * package registries and GitHub's code hosts) stay known, so a strict start sets that list too.
 *
 * A project file (which the agent may have written) may only tighten: move the mode toward "ask" and
 * switch the built-in set off. It can never add a host: there is no key for that, and the list itself is
 * outside the repository.
 */

import type { FirewallConfig } from "./types.js";

export const KNOWN_HOSTS_POLICY_KEYS = ["knownHosts"] as const;

export const KNOWN_HOSTS_MODES = ["off", "watch", "ask"] as const;
export type KnownHostsMode = (typeof KNOWN_HOSTS_MODES)[number];

export interface KnownHostsPolicy {
  /** "off": nothing changes; "watch": record contacted hosts for review; "ask": a new host asks once. */
  mode: KnownHostsMode;
  /** Whether the built-in common development hosts (src/engine/knownhosts.ts) count as known. Hosts fetchAllowHosts or sendAllowHosts names count either way. */
  builtins: boolean;
  /** How long "watch" records hosts in a project, from the first one it records there. */
  watchDays: number;
}

export interface KnownHostsDoc {
  knownHosts?: Partial<KnownHostsPolicy>;
}

export const DEFAULT_KNOWN_HOSTS: Readonly<KnownHostsPolicy> = Object.freeze({ mode: "off", builtins: true, watchDays: 7 });
export const MAX_WATCH_DAYS = 90;

const RANK: Record<KnownHostsMode, number> = { off: 0, watch: 1, ask: 2 };

type Raw = Record<string, unknown>;

/** The settings in effect (defaults for anything not set). */
export function knownHostsPolicy(cfg: Pick<FirewallConfig, "knownHosts">): KnownHostsPolicy {
  return { ...DEFAULT_KNOWN_HOSTS, ...(cfg.knownHosts ?? {}) };
}

/** Validates `knownHosts` of a (migrated) policy document into `out`. Unknown sub-keys and bad values are errors. */
export function validateKnownHostsKeys(raw: Raw, problems: string[], out: KnownHostsDoc): void {
  if (raw.knownHosts === undefined) return;
  const v = raw.knownHosts;
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    problems.push('"knownHosts" must be an object');
    return;
  }
  const res: Partial<KnownHostsPolicy> = {};
  for (const [k, x] of Object.entries(v as Raw)) {
    if (k === "mode") {
      if (typeof x !== "string" || !(KNOWN_HOSTS_MODES as readonly string[]).includes(x)) problems.push(`"knownHosts.mode" must be one of ${KNOWN_HOSTS_MODES.map((m) => `"${m}"`).join(", ")}`);
      else res.mode = x as KnownHostsMode;
    } else if (k === "builtins") {
      if (typeof x !== "boolean") problems.push('"knownHosts.builtins" must be true or false');
      else res.builtins = x;
    } else if (k === "watchDays") {
      if (typeof x !== "number" || !Number.isInteger(x) || x < 1 || x > MAX_WATCH_DAYS) problems.push(`"knownHosts.watchDays" must be a whole number from 1 to ${MAX_WATCH_DAYS}`);
      else res.watchDays = x;
    } else problems.push(`"knownHosts.${k}" is not a known setting (expected one of mode, builtins, watchDays; the approved hosts themselves are kept in the firewall's own directory, never in a policy file)`);
  }
  out.knownHosts = res;
}

/** The user's (or an administrator's) `knownHosts` over the base: any direction. */
export function mergeKnownHosts(base: FirewallConfig["knownHosts"], over: KnownHostsDoc["knownHosts"]): KnownHostsPolicy {
  return { ...knownHostsPolicy({ knownHosts: base }), ...(over ?? {}) };
}

/** Applies a project file's `knownHosts`: the mode toward "ask" and the built-in set off only; the rest is listed in `ignored`. */
export function tightenKnownHostsKeys(base: FirewallConfig, over: KnownHostsDoc, cfg: FirewallConfig, ignored: string[]): void {
  const o = over.knownHosts;
  if (o === undefined) return;
  const cur = knownHostsPolicy(base);
  if (o.mode !== undefined) {
    if (RANK[o.mode] >= RANK[cur.mode]) cur.mode = o.mode;
    else ignored.push(`knownHosts.mode "${o.mode}" (a project may only move it toward "ask")`);
  }
  if (o.builtins === false) cur.builtins = false;
  if (o.builtins === true && !cur.builtins) ignored.push("knownHosts.builtins (a project may only turn the built-in hosts off)");
  if (o.watchDays !== undefined) ignored.push("knownHosts.watchDays (user or managed policy only)");
  cfg.knownHosts = cur;
}
