/**
 * The gateway's policy key, kept apart from policy.ts so it stays one module:
 * `gateway` (docs/gateway.md). Defaults: changed tools are hidden, approvals are
 * queued, local only.
 *
 * A project file may only tighten: set `mode` to "full", `askVia` to "queue",
 * `toolChanges` to "hide", the response switches on, `withhold` to "strong",
 * raise `maxScanBytes` (up to 64 MiB), set `oversize` to "withhold", move
 * `sampling` towards "deny", raise `httpSessionIdleMinutes`. `unknownMethods`
 * and per-client workspace roots are user or managed policy only.
 */

import type { FirewallConfig } from "./types.js";
import { own, setOwn } from "./own.js";

export const GATEWAY_POLICY_KEYS = ["gateway"] as const;

export type GatewayMode = "auto" | "full" | "hook";
export type SamplingPolicy = "deny" | "deny_untrusted" | "allow";

export interface GatewayResponses {
  stripHidden: boolean;
  withhold: "strong" | "never";
  annotate: boolean;
  maxScanBytes: number;
  oversize: "deliver" | "withhold";
}

export interface GatewayPolicy {
  enabled: boolean;
  mode: GatewayMode;
  askVia: "queue" | "elicitation";
  toolChanges: "hide" | "taint";
  responses: GatewayResponses;
  sampling: SamplingPolicy;
  unknownMethods: "deny" | "allow";
  httpSessionIdleMinutes: number;
  clients: Record<string, { workspaceRoots: string[] }>;
}

export interface GatewayDoc {
  gateway?: Partial<Omit<GatewayPolicy, "responses" | "clients">> & { responses?: Partial<GatewayResponses>; clients?: Record<string, { workspaceRoots?: string[] }> };
}

export const MIB = 1024 * 1024;
const MAX_SCAN_LIMIT = 64 * MIB;

export function defaultGateway(): GatewayPolicy {
  return {
    enabled: true,
    mode: "auto",
    askVia: "queue",
    toolChanges: "hide",
    responses: { stripHidden: true, withhold: "strong", annotate: true, maxScanBytes: 4 * MIB, oversize: "deliver" },
    sampling: "deny_untrusted",
    unknownMethods: "deny",
    httpSessionIdleMinutes: 60,
    clients: {},
  };
}

/** The gateway policy in effect (defaults for anything a policy file did not set). */
export function gatewayPolicy(cfg: Pick<FirewallConfig, "gateway">): GatewayPolicy {
  const d = defaultGateway();
  const g = cfg.gateway ?? {};
  const clients: GatewayPolicy["clients"] = {};
  for (const [k, v] of Object.entries(g.clients ?? {})) setOwn(clients, k, { workspaceRoots: [...(v.workspaceRoots ?? [])] });
  return { ...d, ...g, responses: { ...d.responses, ...(g.responses ?? {}) }, clients } as GatewayPolicy;
}

const KEYS = ["enabled", "mode", "askVia", "toolChanges", "responses", "sampling", "unknownMethods", "httpSessionIdleMinutes", "clients"] as const;
const RESPONSE_KEYS = ["stripHidden", "withhold", "annotate", "maxScanBytes", "oversize"] as const;
const ENUMS: Record<string, readonly string[]> = { mode: ["auto", "full", "hook"], askVia: ["queue", "elicitation"], toolChanges: ["hide", "taint"], sampling: ["deny", "deny_untrusted", "allow"], unknownMethods: ["deny", "allow"] };

type Raw = Record<string, unknown>;
const isObj = (v: unknown): v is Raw => typeof v === "object" && v !== null && !Array.isArray(v);

/** Validates the key of a (migrated) policy document into `out`. */
export function validateGatewayKeys(raw: Raw, problems: string[], out: GatewayDoc): void {
  if (raw.gateway === undefined) return;
  const v = raw.gateway;
  if (!isObj(v)) {
    problems.push('"gateway" must be an object');
    return;
  }
  const res: NonNullable<GatewayDoc["gateway"]> = {};
  for (const k of Object.keys(v)) if (!(KEYS as readonly string[]).includes(k)) problems.push(`"gateway.${k}" is not a known setting (expected one of ${KEYS.join(", ")})`);
  if (v.enabled !== undefined) {
    if (typeof v.enabled === "boolean") res.enabled = v.enabled;
    else problems.push('"gateway.enabled" must be true or false');
  }
  for (const [k, values] of Object.entries(ENUMS)) {
    const x = own(v, k);
    if (x === undefined) continue;
    if (typeof x === "string" && values.includes(x)) setOwn(res as Raw, k, x);
    else problems.push(`"gateway.${k}" must be one of ${values.map((x) => `"${x}"`).join(", ")}`);
  }
  if (v.httpSessionIdleMinutes !== undefined) {
    const n = v.httpSessionIdleMinutes;
    if (typeof n === "number" && Number.isInteger(n) && n >= 5 && n <= 1440) res.httpSessionIdleMinutes = n;
    else problems.push('"gateway.httpSessionIdleMinutes" must be a whole number from 5 to 1440');
  }
  if (v.responses !== undefined) {
    if (!isObj(v.responses)) problems.push('"gateway.responses" must be an object');
    else {
      const r = v.responses;
      const rr: Partial<GatewayResponses> = {};
      for (const k of Object.keys(r)) if (!(RESPONSE_KEYS as readonly string[]).includes(k)) problems.push(`"gateway.responses.${k}" is not a known setting (expected one of ${RESPONSE_KEYS.join(", ")})`);
      for (const k of ["stripHidden", "annotate"] as const) {
        if (r[k] === undefined) continue;
        if (typeof r[k] === "boolean") rr[k] = r[k];
        else problems.push(`"gateway.responses.${k}" must be true or false`);
      }
      if (r.withhold !== undefined) {
        if (r.withhold === "strong" || r.withhold === "never") rr.withhold = r.withhold;
        else problems.push('"gateway.responses.withhold" must be "strong" or "never"');
      }
      if (r.oversize !== undefined) {
        if (r.oversize === "deliver" || r.oversize === "withhold") rr.oversize = r.oversize;
        else problems.push('"gateway.responses.oversize" must be "deliver" or "withhold"');
      }
      if (r.maxScanBytes !== undefined) {
        const n = r.maxScanBytes;
        if (typeof n === "number" && Number.isInteger(n) && n >= 1024 && n <= MAX_SCAN_LIMIT) rr.maxScanBytes = n;
        else problems.push(`"gateway.responses.maxScanBytes" must be a whole number from 1024 to ${MAX_SCAN_LIMIT}`);
      }
      res.responses = rr;
    }
  }
  if (v.clients !== undefined) {
    if (!isObj(v.clients)) problems.push('"gateway.clients" must be an object of client name to { "workspaceRoots": [...] }');
    else {
      const cl: NonNullable<NonNullable<GatewayDoc["gateway"]>["clients"]> = {};
      for (const [name, c] of Object.entries(v.clients)) {
        if (!isObj(c) || Object.keys(c).some((k) => k !== "workspaceRoots") || (c.workspaceRoots !== undefined && !(Array.isArray(c.workspaceRoots) && c.workspaceRoots.every((x) => typeof x === "string" && x.startsWith("/"))))) {
          problems.push(`"gateway.clients.${name}" must be { "workspaceRoots": [absolute paths] }`);
          continue;
        }
        setOwn(cl, name, c.workspaceRoots !== undefined ? { workspaceRoots: c.workspaceRoots as string[] } : {});
      }
      res.clients = cl;
    }
  }
  out.gateway = res;
}

/** The user's (or an administrator's) `gateway` over the layer below: anything goes. */
export function mergeGateway(base: FirewallConfig["gateway"], over: GatewayDoc["gateway"]): FirewallConfig["gateway"] {
  if (base === undefined && over === undefined) return undefined;
  return { ...(base ?? {}), ...(over ?? {}), responses: { ...(base?.responses ?? {}), ...(over?.responses ?? {}) }, clients: { ...(base?.clients ?? {}), ...(over?.clients ?? {}) } };
}

const SAMPLING_ORDER: Record<SamplingPolicy, number> = { allow: 0, deny_untrusted: 1, deny: 2 };

/** Applies a project file's `gateway`: tightening only; anything looser is listed in `ignored`. */
export function tightenGatewayKeys(base: FirewallConfig, over: GatewayDoc, cfg: FirewallConfig, ignored: string[]): void {
  const g = over.gateway;
  if (g === undefined) return;
  const cur = gatewayPolicy(base);
  const next: NonNullable<FirewallConfig["gateway"]> = { ...(base.gateway ?? {}), responses: { ...(base.gateway?.responses ?? {}) } };
  const loose = (what: string): void => void ignored.push(`gateway.${what}`);
  if (g.enabled === false) loose("enabled (a repository must not switch the gateway off)");
  if (g.mode !== undefined) {
    if (g.mode === "full") next.mode = "full";
    else if (g.mode !== cur.mode) loose("mode (a project may only set \"full\")");
  }
  if (g.askVia === "queue") next.askVia = "queue";
  else if (g.askVia !== undefined && g.askVia !== cur.askVia) loose("askVia (a project may only set \"queue\")");
  if (g.toolChanges === "hide") next.toolChanges = "hide";
  else if (g.toolChanges !== undefined && g.toolChanges !== cur.toolChanges) loose("toolChanges (a project may only set \"hide\")");
  if (g.sampling !== undefined) {
    if (SAMPLING_ORDER[g.sampling] >= SAMPLING_ORDER[cur.sampling]) next.sampling = g.sampling;
    else loose("sampling (a project may only move it towards \"deny\")");
  }
  if (g.unknownMethods === "allow") loose("unknownMethods (user or managed policy only)");
  if (g.httpSessionIdleMinutes !== undefined) {
    if (g.httpSessionIdleMinutes >= cur.httpSessionIdleMinutes) next.httpSessionIdleMinutes = g.httpSessionIdleMinutes;
    else loose("httpSessionIdleMinutes (a project may only raise it)");
  }
  const r = g.responses ?? {};
  const nr = next.responses ?? {};
  for (const k of ["stripHidden", "annotate"] as const) {
    if (r[k] === true) nr[k] = true;
    else if (r[k] === false && cur.responses[k]) loose(`responses.${k} (a project may only turn it on)`);
  }
  if (r.withhold === "strong") nr.withhold = "strong";
  else if (r.withhold === "never" && cur.responses.withhold !== "never") loose("responses.withhold (a project may only set \"strong\")");
  if (r.oversize === "withhold") nr.oversize = "withhold";
  else if (r.oversize === "deliver" && cur.responses.oversize !== "deliver") loose("responses.oversize (a project may only set \"withhold\")");
  if (r.maxScanBytes !== undefined) {
    if (r.maxScanBytes >= cur.responses.maxScanBytes) nr.maxScanBytes = r.maxScanBytes;
    else loose("responses.maxScanBytes (a project may only raise it)");
  }
  next.responses = nr;
  if (g.clients !== undefined && Object.keys(g.clients).length > 0) loose("clients (workspace roots are user or managed policy only)");
  cfg.gateway = next;
}
