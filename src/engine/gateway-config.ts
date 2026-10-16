/**
 * Protecting the MCP client configuration files the gateway
 * wrapped (see docs/gateway.md). A
 * Write or Edit of such a file is judged by its result:
 *
 * - removing or changing a wrapped entry (back to the unwrapped command, or to
 *   another wrapper) is tampering with the firewall (FW-TAMPER);
 * - adding a server the gateway does not wrap is a settings change
 *   (FW-AGENT-SETTINGS, held when the session is untrusted), as for .mcp.json;
 * - a shell write, whose result cannot be seen, is tampering (effects.ts).
 *
 * Which files and entries are wrapped comes from gateway/install.json
 * (Context.gatewayConfigs). Entries are identified by their key path in the
 * file (["mcpServers", name], ["projects", dir, "mcpServers", name],
 * ["servers", name] for VS Code, ["mcp_servers", name] for Codex's TOML).
 * Pure; the hashes match src/gateway/install.ts entryHash().
 */

import type { Context } from "../types.js";
import { sha256Hex } from "./bytes.js";
import { canonicalJson } from "./decide.js";
import { tomlFlatten } from "./settings.js";
import { own, setOwn } from "../own.js";

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

export function entryHashOf(entry: unknown): string {
  return sha256Hex(canonicalJson(entry));
}

/** A Codex TOML server table as a canonical object of its flattened keys (comments and layout ignored). */
export function tomlTable(text: string, name: string): Json | null {
  const flat = tomlFlatten(text);
  if (flat === null) return null;
  const out: Json = {};
  let any = false;
  for (const [k, v] of flat) {
    const path = JSON.parse(k) as string[];
    if (path[0] !== "mcp_servers" || path[1] !== name) continue;
    setOwn<unknown>(out, JSON.stringify(path.slice(2)), v);
    any = true;
  }
  return any ? out : null;
}

/** Every MCP server entry in a client configuration file, by key path (JSON-encoded) to its entry. */
export function serverEntries(text: string, toml: boolean): Map<string, unknown> | null {
  const out = new Map<string, unknown>();
  if (toml) {
    const flat = tomlFlatten(text);
    if (flat === null) return null;
    const names = new Set<string>();
    for (const k of flat.keys()) {
      const p = JSON.parse(k) as string[];
      if (p[0] === "mcp_servers" && p[1] !== undefined) names.add(p[1]);
    }
    for (const n of names) out.set(JSON.stringify(["mcp_servers", n]), tomlTable(text, n));
    return out;
  }
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isObj(v)) return null;
  for (const container of ["mcpServers", "servers"]) {
    const s = own(v, container);
    if (isObj(s)) for (const [n, e] of Object.entries(s)) out.set(JSON.stringify([container, n]), e);
  }
  if (isObj(v.projects)) {
    for (const [dir, p] of Object.entries(v.projects)) {
      if (isObj(p) && isObj(p.mcpServers)) for (const [n, e] of Object.entries(p.mcpServers)) out.set(JSON.stringify(["projects", dir, "mcpServers", n]), e);
    }
  }
  return out;
}

/** The wrapped configuration file `abs` is, if it is one. */
export function gatewayConfigFor(ctx: Pick<Context, "gatewayConfigs">, abs: string): { path: string; wrapped: Record<string, string> } | null {
  // I1: a wrapped file is protected whatever the case of the name that reaches it (PROTECTION_FOLDS_CASE, canonical.ts).
  const lc = (s: string): string => s.toLowerCase();
  return (ctx.gatewayConfigs ?? []).find((g) => lc(g.path) === lc(abs)) ?? null;
}

/** The files each agent's own `<agent> mcp` command edits, among those the gateway can wrap. */
const AGENT_MCP_FILES: Record<string, RegExp> = { claude: /(?:^|[\\/])\.claude\.json$/i, gemini: /[\\/]\.gemini[\\/]settings\.json$/i, codex: /\.toml$/i };

/** V35: the names of the servers the gateway wrapped in the files `agent mcp …` edits. */
export function wrappedServerNames(ctx: Pick<Context, "gatewayConfigs">, agent: string): Set<string> {
  const re = own(AGENT_MCP_FILES, agent);
  const out = new Set<string>();
  if (re === undefined) return out;
  for (const g of ctx.gatewayConfigs ?? []) if (re.test(g.path)) for (const key of Object.keys(g.wrapped)) out.add(label(key));
  return out;
}

/** Whether an entry launches the firewall's own wrapper (`launchsafe-firewall mcp wrap … --`, or its cli.js through node). */
function isWrapper(entry: unknown): boolean {
  if (!isObj(entry)) return false;
  const cmd = typeof entry.command === "string" ? entry.command : "";
  const args = Array.isArray(entry.args) ? entry.args.map(String) : [];
  const words = [cmd, ...args];
  const at = words.findIndex((w) => w === "launchsafe-firewall" || /\/dist\/cli\.js$/.test(w));
  return at !== -1 && words[at + 1] === "mcp" && words[at + 2] === "wrap" && words.includes("--");
}

function label(key: string): string {
  const p = JSON.parse(key) as string[];
  return p[p.length - 1] ?? key;
}

/**
 * What a change from `before` to `after` does to a wrapped file: wrapped entries removed or changed
 * (tampering) and unwrapped servers added. An unreadable result counts as removing every wrapper.
 */
export function gatewayConfigChanges(before: string | null, after: string | null, wrapped: Record<string, string>, file: string): { tamper: string[]; added: string[] } {
  const toml = /\.toml$/i.test(file);
  const now = after === null ? null : serverEntries(after, toml);
  if (now === null) return { tamper: Object.keys(wrapped).length > 0 ? ["the result cannot be read, so the gateway wrappers in it cannot be checked"] : [], added: [] };
  const was = before === null ? new Map<string, unknown>() : (serverEntries(before, toml) ?? new Map<string, unknown>());
  const tamper: string[] = [];
  for (const [key, hash] of Object.entries(wrapped)) {
    const e = now.get(key);
    if (e === undefined) tamper.push(`it removes MCP server "${label(key)}", which the firewall's gateway wraps`);
    else if (entryHashOf(e) !== hash) tamper.push(isWrapper(e) ? `it changes the gateway wrapper of MCP server "${label(key)}"` : `it removes the gateway wrapper from MCP server "${label(key)}", so its calls would no longer be checked`);
  }
  const added: string[] = [];
  // A wrapper-shaped entry only passes when it is one the install recorded: any `.../dist/cli.js mcp wrap --`
  // command would otherwise launch an arbitrary program after `--`.
  const recorded = new Set(Object.values(wrapped));
  for (const [key, e] of now) {
    if (key in wrapped || was.has(key)) continue;
    if (!isWrapper(e) || !recorded.has(entryHashOf(e))) added.push(label(key));
  }
  return { tamper, added };
}
