/**
 * The MCP servers configured for the other agents the firewall is installed for, so the session-start
 * MCP comparison (src/runtime/pins.ts) sees them too: Codex's config.toml ([mcp_servers.<name>], the
 * user's $CODEX_HOME and a project's .codex/), Gemini CLI's settings.json (mcpServers: system, project,
 * user) and Cursor's mcp.json (a project's .cursor/ and the user's ~/.cursor/). Each server carries its
 * agent, so pins are keyed per agent (`codex-user:<name>`): the same name configured for two agents is
 * two pins, and a change in one agent's file is that agent's change.
 *
 * Pure reads with size caps; a file that cannot be read or parsed contributes nothing (the agent itself
 * reports a broken configuration file).
 */

import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { codexHome } from "../adapters/codex.js";
import { cursorHome } from "../adapters/cursor.js";
import { geminiHome, geminiSystemSettings } from "../adapters/gemini.js";
import type { ConfiguredServer } from "./agentfiles.js";
import { tomlFlatten } from "../engine/settings.js";
import { own, setOwn } from "../own.js";

export type McpAgent = "codex" | "gemini" | "cursor";

const MAX_BYTES = 1024 * 1024;

type Json = Record<string, unknown>;

function readSmall(abs: string): string | null {
  try {
    const st = statSync(abs);
    if (!st.isFile() || st.size > MAX_BYTES) return null;
    return readFileSync(abs, "utf8");
  } catch {
    return null;
  }
}

function jsonServers(text: string | null): Record<string, Json> {
  if (text === null) return {};
  try {
    const v = (JSON.parse(text) as Json).mcpServers;
    if (typeof v !== "object" || v === null || Array.isArray(v)) return {};
    const out: Record<string, Json> = {};
    for (const [k, x] of Object.entries(v as Json)) if (typeof x === "object" && x !== null && !Array.isArray(x)) setOwn(out, k, x as Json);
    return out;
  } catch {
    return {};
  }
}

// --- Codex config.toml ------------------------------------------------------------------------------

/** One TOML value: a basic or literal string, an array of them, an inline table (its keys), a bare value. */
function tomlValue(text: string): unknown {
  const t = text.trim();
  if (t.startsWith('"')) {
    const m = /^"((?:[^"\\]|\\.)*)"/.exec(t);
    if (m === null) return undefined;
    try {
      return JSON.parse(`"${m[1] as string}"`) as string;
    } catch {
      return m[1];
    }
  }
  if (t.startsWith("'")) return /^'([^']*)'/.exec(t)?.[1];
  if (t.startsWith("[")) {
    const items: unknown[] = [];
    const re = /"((?:[^"\\]|\\.)*)"|'([^']*)'/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(t)) !== null) items.push(m[1] !== undefined ? tomlValue(`"${m[1]}"`) : m[2]);
    return items;
  }
  if (t.startsWith("{")) {
    const keys: Json = {};
    const re = /(?:^|[{,])\s*("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+)\s*=/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(t)) !== null) setOwn(keys, (m[1] as string).replace(/^["']|["']$/g, ""), "");
    return keys;
  }
  return t.replace(/\s+#.*$/, "");
}

/** A table header's key path ([mcp_servers."a.b".env] -> ["mcp_servers", "a.b", "env"]). */
function tablePath(header: string): string[] {
  const parts: string[] = [];
  const re = /\s*("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+)\s*(\.|$)/y;
  let m: RegExpExecArray | null;
  while (re.lastIndex < header.length && (m = re.exec(header)) !== null) {
    parts.push((m[1] as string).replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1"));
    if (m[2] === "") break;
  }
  return parts;
}

/**
 * The [mcp_servers.<name>] tables of a Codex config.toml, as the configuration shape pins compare
 * (command, args, url, and the names of environment variables and headers). F11: read from the parsed
 * TOML (tomlFlatten), so dotted keys (`mcp_servers.docs.command = ...`) and inline tables
 * (`mcp_servers.docs = { ... }`) are seen like a [mcp_servers.docs] table; TOML the parser does not
 * understand falls back to the line-based reading.
 */
export function codexMcpServers(text: string | null): Record<string, Json> {
  if (text === null) return {};
  const flat = tomlFlatten(text);
  return flat === null ? codexMcpServersByLine(text) : codexMcpServersFlat(flat);
}

function parsed(v: string): unknown {
  try {
    return JSON.parse(v) as unknown;
  } catch {
    return v;
  }
}

/** The servers from a flattened config.toml, in the same shape as the line-based reading. */
function codexMcpServersFlat(flat: Map<string, string>): Record<string, Json> {
  const out: Record<string, Json> = {};
  for (const [k, v] of flat) {
    const path = parsed(k) as string[];
    if (!Array.isArray(path) || path[0] !== "mcp_servers" || typeof path[1] !== "string") continue;
    const server = (own(out, path[1]) ?? (setOwn(out, path[1], {}), own(out, path[1]) as Json));
    const key = path[2];
    if (key === undefined) continue;
    const rest = path.slice(3);
    const value = parsed(v);
    const container = v === "{}" || v === "[]";
    if (key === "env" || key === "http_headers" || key === "env_http_headers") {
      const into = key === "env" ? "env" : "headers";
      setOwn(server, into, { ...((own(server, into) as Json | undefined) ?? {}) });
      if (rest[0] !== undefined) setOwn(own(server, into) as Json, rest[0], "");
    } else if (key === "env_vars") {
      server.env = { ...((server.env as Json | undefined) ?? {}) };
      if (rest.length === 1 && typeof value === "string") setOwn(server.env as Json, value, "");
    } else if (key === "bearer_token_env_var") server.headers = { ...((server.headers as Json | undefined) ?? {}), Authorization: "" };
    else if (rest.length === 0) {
      const cur = own(server, key);
      if (v === "[]") setOwn(server, key, Array.isArray(cur) ? cur : []);
      else if (v === "{}") setOwn(server, key, typeof cur === "object" && cur !== null ? cur : {});
      else setOwn(server, key, typeof value === "string" ? value : v);
    } else if (/^\d+$/.test(rest[0] as string) && Array.isArray(own(server, key))) {
      if (rest.length === 1 && !container) (own(server, key) as unknown[])[Number(rest[0])] = typeof value === "string" ? value : v;
    } else if (typeof own(server, key) === "object" && own(server, key) !== null && !Array.isArray(own(server, key))) setOwn(own(server, key) as Json, rest[0] as string, "");
  }
  return out;
}

/** The line-based reading (multi-line arrays joined; other tables not read), for TOML tomlFlatten refuses. */
function codexMcpServersByLine(text: string): Record<string, Json> {
  const out: Record<string, Json> = {};
  const lines = text.split("\n");
  let path: string[] | null = null;
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] ?? "").trim();
    if (line === "" || line.startsWith("#")) continue;
    const header = /^\[\s*([^[\]]+?)\s*\]\s*(?:#.*)?$/.exec(line);
    if (header !== null) {
      path = tablePath(header[1] as string);
      if (path[0] === "mcp_servers" && path[1] !== undefined && own(out, path[1]) === undefined) setOwn(out, path[1], {});
      continue;
    }
    if (line.startsWith("[[")) {
      path = null;
      continue;
    }
    const kv = /^("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_.-]+)\s*=\s*([\s\S]*)$/.exec(line);
    if (kv === null || path === null || path[0] !== "mcp_servers" || path[1] === undefined) continue;
    let value = kv[2] as string;
    // A multi-line array: join until its brackets balance.
    if (value.trimStart().startsWith("[")) {
      while ((value.match(/\[/g) ?? []).length > (value.match(/\]/g) ?? []).length && i + 1 < lines.length) value += ` ${(lines[++i] ?? "").trim()}`;
    }
    const key = (kv[1] as string).replace(/^["']|["']$/g, "");
    const server = own(out, path[1]) as Json;
    const sub = path[2];
    if (sub === undefined) {
      if (key === "env" || key === "http_headers" || key === "env_http_headers") server[key === "env" ? "env" : "headers"] = { ...((server[key === "env" ? "env" : "headers"] as Json | undefined) ?? {}), ...((tomlValue(value) as Json | undefined) ?? {}) };
      else if (key === "env_vars") server.env = { ...((server.env as Json | undefined) ?? {}), ...Object.fromEntries(((tomlValue(value) as unknown[] | undefined) ?? []).filter((x): x is string => typeof x === "string").map((x) => [x, ""])) };
      else if (key === "bearer_token_env_var") server.headers = { ...((server.headers as Json | undefined) ?? {}), Authorization: "" };
      else setOwn(server, key, tomlValue(value));
    } else if (sub === "env" || sub === "http_headers" || sub === "env_http_headers") {
      const k = sub === "env" ? "env" : "headers";
      server[k] = { ...((server[k] as Json | undefined) ?? {}), [key]: "" };
    }
  }
  return out;
}

// --- every agent ------------------------------------------------------------------------------------

export interface AgentMcpOptions {
  agents: readonly McpAgent[];
  /** The workspace root, or null when the project directory is too broad (as for the agent scan). */
  workspace: string | null;
  home: string;
  env: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
}

/** The MCP servers each listed agent is configured with, tagged with the agent and where they are configured. */
export function agentMcpServers(o: AgentMcpOptions): ConfiguredServer[] {
  const out: ConfiguredServer[] = [];
  const add = (agent: McpAgent, source: ConfiguredServer["source"], file: string, servers: Record<string, Json>): void => {
    for (const [name, config] of Object.entries(servers)) out.push({ name, source, file, config, agent });
  };
  for (const agent of new Set(o.agents)) {
    if (agent === "codex") {
      if (o.workspace !== null) add("codex", "project", ".codex/config.toml", codexMcpServers(readSmall(join(o.workspace, ".codex", "config.toml"))));
      add("codex", "user", "~/.codex/config.toml", codexMcpServers(readSmall(join(codexHome(o.env, o.home), "config.toml"))));
    } else if (agent === "gemini") {
      const sys = geminiSystemSettings(o.env, o.platform ?? process.platform);
      if (sys !== undefined) add("gemini", "managed", sys, jsonServers(readSmall(sys)));
      if (o.workspace !== null) add("gemini", "project", ".gemini/settings.json", jsonServers(readSmall(join(o.workspace, ".gemini", "settings.json"))));
      add("gemini", "user", "~/.gemini/settings.json", jsonServers(readSmall(join(geminiHome(o.env, o.home), "settings.json"))));
    } else {
      if (o.workspace !== null) add("cursor", "project", ".cursor/mcp.json", jsonServers(readSmall(join(o.workspace, ".cursor", "mcp.json"))));
      add("cursor", "user", "~/.cursor/mcp.json", jsonServers(readSmall(join(cursorHome(o.home), "mcp.json"))));
    }
  }
  return out;
}
