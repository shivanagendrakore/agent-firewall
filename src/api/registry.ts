/**
 * An agent's tool registry for the local API (docs/api.md, "Tool registry"): the library's tool specs
 * (src/sdk/tools.ts) as data, set only by a person with `api tools set <agentId> <file.json>`. A remote
 * caller cannot pass a JavaScript mapper, so an `as` spec carries `map`: engine field -> `$.a.b` (dot
 * paths only). The file is validated strictly (an unknown or misspelt key is an error) and with the same
 * rules the library applies to its specs (toolServers), so a registry the server loads always works.
 */

import { readText, atomicWrite } from "../runtime/fsutil.js";
import type { Layout } from "../runtime/layout.js";
import { hasOwn, own, ownMap, setOwn } from "../own.js";
import { toolServers } from "../sdk/tools.js";
import type { ToolSpec } from "../sdk/types.js";
import { toolsPath } from "./files.js";
import { serverNameProblem } from "../gateway/names.js";

export interface RegistryAsSpec {
  as: string;
  map?: Record<string, string>;
}

export interface RegistryKindSpec {
  kind: "read" | "send" | "destroy" | "blocked";
  results?: "trusted" | "untrusted";
  privateData?: boolean;
  server?: string;
}

export type RegistrySpec = RegistryAsSpec | RegistryKindSpec;

export interface Registry {
  tools: Record<string, RegistrySpec>;
  /**
   * I2: where each MCP server the agent uses was configured, as the person knows it ("user", "project", "sdk"...).
   * A decide request's `action.mcp.source` is the agent's own say; the registry's is the person's. A server not
   * listed here is never judged as configured by a trusted source (user, sdk...) on the agent's word alone.
   */
  mcpServers?: Record<string, { source: string }>;
  /** I2: the only workspace roots (and cwd) a request of this agent may name: each must be one of these or inside one. */
  workspaceRoots?: string[];
}

/** Sources the engine never trusts on a server's name alone (src/engine/mcp.ts serverPolicy). */
export const UNTRUSTED_SOURCE = /^(?:project|dynamic|unknown)$/i;

/** Whether the engine treats a server of this source as a person's own configuration. */
export function trustedSource(source: string | undefined): boolean {
  return source !== undefined && !UNTRUSTED_SOURCE.test(source);
}

export { serverNameProblem };

const SOURCE = /^[A-Za-z][A-Za-z0-9_-]{0,31}$/;

const PATH = /^\$(?:\.[A-Za-z0-9_-]+)+$/;
const FIELD = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MAX_TOOLS = 1000;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function onlyKeys(o: Record<string, unknown>, allowed: readonly string[], where: string): void {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) throw new Error(`${where}: unknown field "${k.slice(0, 80)}" (allowed: ${allowed.join(", ")})`);
}

function spec(name: string, v: unknown): RegistrySpec {
  const where = `tool ${name}`;
  if (!isObject(v)) throw new Error(`${where}: must be an object`);
  if (hasOwn(v, "as") && hasOwn(v, "kind")) throw new Error(`${where}: give either "as" or "kind", not both`);
  if (hasOwn(v, "as")) {
    onlyKeys(v, ["as", "map"], where);
    if (typeof v.as !== "string" || v.as === "" || v.as.length > 200) throw new Error(`${where}: "as" must be an engine tool name (Bash, Read, WebFetch, ...)`);
    const out: RegistryAsSpec = { as: v.as };
    if (hasOwn(v, "map")) {
      if (!isObject(v.map)) throw new Error(`${where}: "map" must be an object of engine field to "$.path"`);
      const map = ownMap<string>();
      for (const [field, path] of Object.entries(v.map)) {
        if (!FIELD.test(field) || field === "__proto__") throw new Error(`${where}: map field "${field.slice(0, 80)}" is not a field name`);
        if (typeof path !== "string" || !PATH.test(path)) throw new Error(`${where}: map.${field} must be a dot path like "$.cmd" or "$.args.url" (v0 takes dot paths only)`);
        setOwn(map, field, path);
      }
      out.map = { ...map };
    }
    return out;
  }
  if (!hasOwn(v, "kind")) throw new Error(`${where}: needs "as" (an engine tool) or "kind" (read, send, destroy or blocked)`);
  onlyKeys(v, ["kind", "results", "privateData", "server"], where);
  if (v.kind !== "read" && v.kind !== "send" && v.kind !== "destroy" && v.kind !== "blocked") throw new Error(`${where}: kind must be read, send, destroy or blocked`);
  const out: RegistryKindSpec = { kind: v.kind };
  if (hasOwn(v, "results")) {
    if (v.results !== "trusted" && v.results !== "untrusted") throw new Error(`${where}: results must be "trusted" or "untrusted"`);
    out.results = v.results;
  }
  if (hasOwn(v, "privateData")) {
    if (typeof v.privateData !== "boolean") throw new Error(`${where}: privateData must be true or false`);
    out.privateData = v.privateData;
  }
  if (hasOwn(v, "server")) {
    if (typeof v.server !== "string" || v.server === "" || v.server.length > 200) throw new Error(`${where}: server must be a name`);
    out.server = v.server;
  }
  return out;
}

/** Validates a registry document. Throws an Error naming the first problem. */
export function parseRegistry(raw: unknown): Registry {
  if (!isObject(raw)) throw new Error('the registry must be an object: { "tools": { ... } }');
  onlyKeys(raw, ["tools", "mcpServers", "workspaceRoots"], "the registry");
  if (!isObject(raw.tools)) throw new Error('the registry needs "tools": an object of tool name to spec');
  const names = Object.keys(raw.tools);
  if (names.length > MAX_TOOLS) throw new Error(`the registry has ${names.length} tools; at most ${MAX_TOOLS}`);
  const tools = ownMap<RegistrySpec>();
  for (const name of names) {
    // eslint-disable-next-line no-control-regex -- refusing control characters is the point
    if (name === "" || name.length > 200 || /[\u0000-\u001f\u007f]/.test(name)) throw new Error(`tool name "${name.slice(0, 80)}" is not valid`);
    setOwn(tools, name, spec(name, own(raw.tools as Record<string, unknown>, name)));
  }
  // The library's own rules (kind values, glob characters in names, servers whose tools disagree).
  toolServers(toolSpecs({ tools }));
  const out: Registry = { tools: { ...tools } };
  if (hasOwn(raw, "mcpServers")) {
    if (!isObject(raw.mcpServers)) throw new Error('"mcpServers" must be an object of server name to { "source": "user" | "project" | ... }');
    const servers = ownMap<{ source: string }>();
    const names = Object.keys(raw.mcpServers);
    if (names.length > MAX_TOOLS) throw new Error(`the registry has ${names.length} MCP servers; at most ${MAX_TOOLS}`);
    for (const name of names) {
      const why = serverNameProblem(name);
      if (why !== null) throw new Error(`MCP server "${name.slice(0, 80)}": the name ${why}`);
      const v = own(raw.mcpServers as Record<string, unknown>, name);
      if (!isObject(v)) throw new Error(`MCP server ${name}: must be an object`);
      onlyKeys(v, ["source"], `MCP server ${name}`);
      if (typeof v.source !== "string" || !SOURCE.test(v.source)) throw new Error(`MCP server ${name}: "source" must be a short name ("user", "project", "local", "sdk", ...)`);
      setOwn(servers, name, { source: v.source });
    }
    out.mcpServers = { ...servers };
  }
  if (hasOwn(raw, "workspaceRoots")) {
    const w = raw.workspaceRoots;
    if (!Array.isArray(w) || w.length > 32 || !w.every((x) => typeof x === "string" && x.startsWith("/") && x.length <= 4096 && !x.split("/").some((seg) => seg === "." || seg === ".."))) throw new Error('"workspaceRoots" must be at most 32 absolute paths (without "." or ".." segments)');
    out.workspaceRoots = [...(w as string[])];
  }
  return out;
}

/** The value at a dot path, own properties only; undefined when any step is missing. */
export function valueAt(input: unknown, path: string): unknown {
  let at: unknown = input;
  for (const key of path.slice(2).split(".")) {
    if (!isObject(at) || !Object.hasOwn(at, key)) return undefined;
    at = own(at, key);
  }
  return at;
}

/** The registry as the library's tool specs: a `map` becomes the spec's input mapper. */
export function toolSpecs(r: Registry): Record<string, ToolSpec> {
  const out = ownMap<ToolSpec>();
  for (const [name, s] of Object.entries(r.tools)) {
    if ("kind" in s) {
      setOwn(out, name, { ...s });
      continue;
    }
    const map = s.map;
    if (map === undefined) {
      setOwn(out, name, { as: s.as });
      continue;
    }
    setOwn(out, name, {
      as: s.as,
      input: (args) => {
        const mapped = ownMap<unknown>();
        for (const [field, path] of Object.entries(map)) {
          const v = valueAt(args, path);
          if (v !== undefined) setOwn(mapped, field, v);
        }
        return { ...mapped };
      },
    });
  }
  return out;
}

/** The agent's stored registry, or null when none was set. Throws when the stored file is damaged. */
export function readRegistry(l: Layout, agentId: string): Registry | null {
  const text = readText(toolsPath(l, agentId));
  if (text === null) return null;
  return parseRegistry(JSON.parse(text));
}

/** Validates and stores the agent's registry (replacing any earlier one). */
export function writeRegistry(l: Layout, agentId: string, raw: unknown): Registry {
  const r = parseRegistry(raw);
  atomicWrite(toolsPath(l, agentId), `${JSON.stringify(r, null, 2)}\n`);
  return r;
}
