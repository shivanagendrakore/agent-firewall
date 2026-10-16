/**
 * `gateway/install.json` (mode 600, inside the protected data directory): what
 * `mcp wrap-config` wrapped, so `mcp unwrap-config` can put it back, `doctor`
 * and `gateway status` can report drift, and the hooks can protect the wrapped
 * files (Context.gatewayConfigs, judged in src/engine/settings.ts). Also the
 * mode a wrapped entry runs in (`auto` resolves to `hook` only while the
 * firewall's hook for that client is installed) and the session resets.
 */

import { join } from "node:path";
import { entryHashOf } from "../engine/gateway-config.js";
import type { AgentId } from "../adapters/types.js";
import { readRecords } from "../runtime/install.js";
import { atomicWrite, parseJsonFile, readText, withLock } from "../runtime/fsutil.js";
import type { Layout } from "../runtime/layout.js";
import { realpathLoose } from "../runtime/realpath.js";
import { unwrapFirewall } from "../runtime/pins.js";
import { own, setOwn } from "../own.js";

export const CLIENTS = ["claude-desktop", "claude-code", "cursor", "codex", "gemini", "vscode"] as const;
export type ClientId = (typeof CLIENTS)[number];

export function isClient(v: string): v is ClientId {
  return (CLIENTS as readonly string[]).includes(v);
}

export type Upstream = { kind: "stdio"; command: string; args: string[]; envKeys: string[] } | { kind: "http"; url: string; headerKeys: string[] };

export interface GatewayEntry {
  client: ClientId;
  server: string;
  file: string;
  scope: "user" | "local" | "managed";
  mode: "full" | "hook";
  upstream: Upstream;
  /** sha256 of the original entry (canonical JSON), for unwrap and drift. */
  originalHash: string;
  /** sha256 of the wrapped entry as written (canonical JSON): what settings.ts protects. */
  wrappedHash: string;
  /** The original entry, to put back on unwrap (secret values in env/headers are kept as written). */
  original: Record<string, unknown>;
  /** Where the entry sits in the file: ["mcpServers", name], ["projects", dir, "mcpServers", name], ["servers", name], ["mcp_servers", name]. */
  location: string[];
  vaultRefs?: string[];
  wrappedAt: string;
}

/** The argument list a wrapped stdio entry carries: the client's own server command behind the wrapper's fixed head. */
export function wrapperArgs(cli: string, client: string, server: string, mode: string, command: string, args: readonly string[], phones: string | null): string[] {
  return withPhonesArg([cli, "mcp", "wrap", "--client", client, "--server", server, "--mode", mode, "--", command, ...args], phones);
}

/**
 * the paired-phones pin (`--phones sha256:<hex>`) in a wrapper's own arguments, the counterpart of the
 * hook command's LAUNCHSAFE_FIREWALL_PHONES. It is read only from the wrapper's head, before the first `--`, never
 * from the server's own arguments.
 */
export function pinnedPhonesInArgs(args: readonly string[]): string | null {
  const sep = args.indexOf("--");
  const head = sep === -1 ? args : args.slice(0, sep);
  if (head[1] !== "mcp" || head[2] !== "wrap") return null;
  const at = head.indexOf("--phones");
  return at === -1 ? null : (head[at + 1] ?? null);
}

/** `args` of a wrapper with the phones pin set, or (null) removed; everything else, the server's arguments included, exactly as it was. */
export function withPhonesArg(args: readonly string[], pin: string | null): string[] {
  const sep = args.indexOf("--");
  if (sep === -1 || args[1] !== "mcp" || args[2] !== "wrap") return [...args];
  const head = args.slice(0, sep);
  const at = head.indexOf("--phones");
  const bare = at === -1 ? head : [...head.slice(0, at), ...head.slice(at + 2)];
  return [...bare, ...(pin === null ? [] : ["--phones", pin]), ...args.slice(sep)];
}

/**
 * LG4: a wrapped stdio entry runs the firewall's own code under node with the client's environment plus the
 * entry's `env`. Node enables a compile cache named by NODE_COMPILE_CACHE before any firewall code runs, so the
 * wrapped entry sets it empty (which node ignores); a value the entry itself set moves here and the wrapper
 * gives it back to the server it starts, so only the server's own node uses it.
 */
export const UPSTREAM_COMPILE_CACHE = "LAUNCHSAFE_FIREWALL_UPSTREAM_NODE_COMPILE_CACHE";

type EnvMap = Record<string, unknown>;
const isEnvMap = (v: unknown): v is EnvMap => typeof v === "object" && v !== null && !Array.isArray(v);

/** A wrapped stdio entry's `env` (LG4), or null when the entry's env is not an object. */
export function wrapperEnv(env: unknown): EnvMap | null {
  if (env !== undefined && !isEnvMap(env)) return null;
  const out: EnvMap = {};
  for (const [k, v] of Object.entries(env ?? {})) if (k !== "NODE_COMPILE_CACHE" && k !== UPSTREAM_COMPILE_CACHE) setOwn<unknown>(out, k, v);
  const user = env !== undefined ? own(env, "NODE_COMPILE_CACHE") : undefined;
  const kept = typeof user === "string" && user !== "" ? user : env !== undefined ? own(env, UPSTREAM_COMPILE_CACHE) : undefined;
  setOwn<unknown>(out, "NODE_COMPILE_CACHE", "");
  if (kept !== undefined) setOwn<unknown>(out, UPSTREAM_COMPILE_CACHE, kept);
  return out;
}

/** The wrapper's `env` as the entry had it before wrapping (LG4), for an unwrap that keeps a person's edit. */
export function unwrappedEnv(env: EnvMap): EnvMap {
  const out: EnvMap = {};
  for (const [k, v] of Object.entries(env)) if (k !== UPSTREAM_COMPILE_CACHE && !(k === "NODE_COMPILE_CACHE" && v === "")) setOwn<unknown>(out, k, v);
  const kept = own(env, UPSTREAM_COMPILE_CACHE);
  if (kept !== undefined) setOwn<unknown>(out, "NODE_COMPILE_CACHE", kept);
  return out;
}

/** Whether a wrapped JSON stdio entry clears NODE_COMPILE_CACHE for the firewall's node (LG4). */
export function clearsCompileCache(entry: EnvMap): boolean {
  return isEnvMap(entry.env) && own(entry.env, "NODE_COMPILE_CACHE") === "";
}

/** The environment the wrapper starts the real server with (LG4): the entry's own compile cache, never the firewall's empty one. */
export function upstreamEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = { ...env };
  const kept = out[UPSTREAM_COMPILE_CACHE];
  delete out[UPSTREAM_COMPILE_CACHE];
  if (kept !== undefined) out.NODE_COMPILE_CACHE = kept;
  else if (out.NODE_COMPILE_CACHE === "") delete out.NODE_COMPILE_CACHE;
  return out;
}

export interface GatewayInstall {
  version: 1;
  entries: GatewayEntry[];
}

export function gatewayDir(l: Layout): string {
  return join(l.home, "gateway");
}

export function installPath(l: Layout): string {
  return join(gatewayDir(l), "install.json");
}

export const entryHash = entryHashOf;

/** The records; empty when there are none. Throws on an unreadable file (doctor reports it; callers fail safe). */
export function readGatewayInstall(l: Layout): GatewayInstall {
  const t = readText(installPath(l));
  if (t === null) return { version: 1, entries: [] };
  const v = parseJsonFile(installPath(l), t) as GatewayInstall;
  if (v.version !== 1 || !Array.isArray(v.entries)) throw new Error(`${installPath(l)} is not a gateway install record`);
  return v;
}

export function updateGatewayInstall<T>(l: Layout, fn: (g: GatewayInstall) => T): T {
  const p = installPath(l);
  return withLock(`${p}.lock`, () => {
    const g = readGatewayInstall(l);
    const r = fn(g);
    atomicWrite(p, `${JSON.stringify(g, null, 2)}\n`);
    return r;
  });
}

/** Context.gatewayConfigs: each wrapped file (and its realpath) with its wrapped entries' hashes by key path (JSON). */
export function gatewayConfigs(l: Layout): { path: string; wrapped: Record<string, string> }[] {
  let g: GatewayInstall;
  try {
    g = readGatewayInstall(l);
  } catch {
    return [];
  }
  const byFile = new Map<string, Record<string, string>>();
  for (const e of g.entries) byFile.set(e.file, { ...(byFile.get(e.file) ?? {}), [JSON.stringify(e.location)]: e.wrappedHash });
  return [...byFile].flatMap(([path, wrapped]) => {
    const real = realpathLoose(path);
    return real === path ? [{ path, wrapped }] : [{ path, wrapped }, { path: real, wrapped }];
  });
}

/** The agent whose hook covers a client's MCP calls, if it has one. */
export function hookAgentOf(client: ClientId): AgentId | null {
  if (client === "claude-code") return "claude";
  if (client === "codex" || client === "gemini" || client === "cursor") return client;
  return null;
}

/** Whether the firewall's hook is installed for the client (install records). Unreadable records: no. */
export function hookInstalledFor(l: Layout, client: ClientId): boolean {
  const agent = hookAgentOf(client);
  if (agent === null) return false;
  try {
    return readRecords(l).some((r) => (r.agent ?? "claude") === agent);
  } catch {
    return false;
  }
}

/**
 * The mode a wrapped server runs in. I4: `auto` is full mode: the gateway decides every call itself. An install
 * record says a hook was installed, not that it runs for this session (a client started with its hooks off, a
 * settings file that dropped them), and in hook mode a call the hook never saw would pass undecided. Hook mode is
 * only what a person asked for by name (`--mode hook`, or `gateway.mode: "hook"` in their own policy), and
 * even then it falls back to full mode when the hook's install record is gone (the failure table: no call may
 * pass undecided).
 */
export function resolveMode(l: Layout, client: ClientId, requested: "auto" | "full" | "hook"): { mode: "full" | "hook"; warning: string | null } {
  if (requested !== "hook") return { mode: "full", warning: null };
  if (hookInstalledFor(l, client)) return { mode: "hook", warning: null };
  return { mode: "full", warning: `the firewall's hook for ${client} is not installed, so this server runs in full mode` };
}

/** Session resets (`gateway reset <client>`): a new generation starts a new session at once. */
export function resetsPath(l: Layout): string {
  return join(gatewayDir(l), "resets.json");
}

export function resetGeneration(l: Layout, client: string): string {
  const t = readText(resetsPath(l));
  if (t === null) return "0";
  try {
    const v = own(JSON.parse(t) as Record<string, unknown>, client);
    return typeof v === "string" ? v : "0";
  } catch {
    return "corrupt";
  }
}

export function resetSession(l: Layout, client: string, now = new Date()): string {
  const p = resetsPath(l);
  return withLock(`${p}.lock`, () => {
    let v: Record<string, unknown> = {};
    try {
      v = JSON.parse(readText(p) ?? "{}") as Record<string, unknown>;
    } catch {
      v = {};
    }
    const gen = now.toISOString().replace(/[^0-9]/g, "");
    setOwn(v, client, gen);
    atomicWrite(p, `${JSON.stringify(v, null, 2)}\n`);
    return gen;
  });
}

const WRAPPED_URL = /^https?:\/\/127\.0\.0\.1:\d+\/c\/([^/]+)\/u\/([^/?#]+)$/;

/**
 * The wrapper is not a change (tools/list pinning and hiding): what an entry was
 * before the gateway wrapped it, for pins, the agent-safety analysis and drift. A stdio wrapper is
 * unwrapped by pins.ts unwrapFirewall() (the exact installed CLI only); a local gateway URL is mapped
 * back to the original entry recorded in gateway/install.json. Anything else as it is.
 */
export function unwrapGatewayEntry(l: Layout, entry: Record<string, unknown>, records?: GatewayEntry[]): Record<string, unknown> {
  const unwrapped = unwrapFirewall(entry);
  if (unwrapped !== null && unwrapped !== entry) return unwrapped;
  const url = typeof entry.url === "string" ? entry.url : typeof entry.httpUrl === "string" ? entry.httpUrl : typeof entry.serverUrl === "string" ? entry.serverUrl : null;
  const m = url === null ? null : WRAPPED_URL.exec(url);
  if (m === null) return entry;
  let list = records;
  if (list === undefined) {
    try {
      list = readGatewayInstall(l).entries;
    } catch {
      return entry;
    }
  }
  const client = decodeURIComponent(m[1] as string);
  const server = decodeURIComponent(m[2] as string);
  const rec = list.find((e) => e.client === client && e.server === server && e.upstream.kind === "http");
  return rec !== undefined && entryHash(entry) === rec.wrappedHash ? rec.original : entry;
}

/** A client configuration file's text with every gateway-wrapped server entry put back as it was (JSON files; others unchanged). */
export function unwrapGatewayText(l: Layout, text: string): string {
  if (!text.includes("mcp") || !(text.includes(" wrap") || text.includes("\"wrap\"") || text.includes("127.0.0.1"))) return text;
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return text;
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return text;
  let records: GatewayEntry[] = [];
  try {
    records = readGatewayInstall(l).entries;
  } catch {
    records = [];
  }
  let changed = false;
  const fix = (servers: unknown): void => {
    if (typeof servers !== "object" || servers === null || Array.isArray(servers)) return;
    const s = servers as Record<string, unknown>;
    for (const [name, e] of Object.entries(s)) {
      if (typeof e !== "object" || e === null || Array.isArray(e)) continue;
      const u = unwrapGatewayEntry(l, e as Record<string, unknown>, records);
      if (u !== e) {
        setOwn(s, name, u);
        changed = true;
      }
    }
  };
  const d = doc as Record<string, unknown>;
  fix(d.mcpServers);
  fix(d.servers);
  if (typeof d.projects === "object" && d.projects !== null) for (const p of Object.values(d.projects as Record<string, unknown>)) if (typeof p === "object" && p !== null) fix((p as Record<string, unknown>).mcpServers);
  return changed ? JSON.stringify(doc, null, 2) : text;
}
