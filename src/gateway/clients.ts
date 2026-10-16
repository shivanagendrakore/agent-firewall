/**
 * Config rewrite helpers:
 * `mcp wrap-config --client <c>` puts the gateway in front of a client's MCP
 * servers, `mcp unwrap-config --client <c>` puts them back. Both are
 * person-run (terminal, not under an agent, approval passphrase): they show
 * the diff, back the file up into `backups/`, write atomically and record the
 * originals in gateway/install.json.
 *
 * - stdio entries become `command: <node>`, `args: [<cli.js>, "mcp", "wrap",
 *   "--client", c, "--server", name, "--mode", m, "--", <command>, …<args>]`;
 *   `env` and everything else are kept.
 * - HTTP entries become `http://127.0.0.1:<port>/c/<c>/u/<name>` with the
 *   per-client bearer header; the original URL and headers move into the
 *   install record (inside the protected data directory, mode 600).
 *
 * Repository files (.mcp.json, .cursor/mcp.json, .vscode/mcp.json, project
 * .gemini/settings.json) are never rewritten. Codex's TOML is edited by a
 * narrow editor (codex-toml.ts) that refuses, printing the snippet instead,
 * on anything it does not fully understand.
 */

import { copyFileSync, existsSync } from "node:fs";
import { basename, join } from "node:path";
import { atomicWrite, ensureDir, parseJsonFile, readText, writeTarget, writeUserFile } from "../runtime/fsutil.js";
import { tomlFlatten } from "../engine/settings.js";
import { tomlTable as tomlTableOf } from "../engine/gateway-config.js";
import { assertNotRealHome } from "../runtime/guard.js";
import type { Layout } from "../runtime/layout.js";
import { recordOwnWrite } from "../runtime/install.js";
import { unwrapFirewall } from "../runtime/pins.js";
import { phonesPinOf } from "../runtime/relay/phones.js";
import { codexClearsCompileCache, codexCompileCache, codexRepin, codexUnwrap, codexWrap } from "./codex-toml.js";
import { clearsCompileCache, entryHash, pinnedPhonesInArgs, readGatewayInstall, resolveMode, unwrappedEnv, updateGatewayInstall, withPhonesArg, wrapperArgs, wrapperEnv, type ClientId, type GatewayEntry, type Upstream } from "./install.js";
import { clientToken, gatewayUrl } from "./tokens.js";
import { own, setOwn } from "../own.js";
import { loadPolicy } from "../runtime/config.js";
import { gatewayPolicy } from "../policy-gateway.js";
import { serverNameProblem } from "./names.js";

export { gatewayUrl };

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

export const DEFAULT_PORT = 8473;

export interface ClientFile {
  path: string;
  format: "json" | "toml";
  /** The container key paths that hold servers in this file (JSON). */
  containers: string[][];
  scope: "user" | "local" | "managed";
  /** Honest notes for the person (an unconfirmed path, what cannot be wrapped). */
  notes: string[];
}

export interface FileEnv {
  home: string;
  platform: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
}

/** The user-level files of a client (verified 10 Oct 2026; Linux Claude Desktop path not confirmed). */
export function clientFiles(client: ClientId, e: FileEnv): ClientFile[] {
  const { home, platform, env } = e;
  const appData = env.APPDATA !== undefined && env.APPDATA !== "" ? env.APPDATA : join(home, "AppData", "Roaming");
  switch (client) {
    case "claude-desktop": {
      const path = platform === "darwin" ? join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json") : platform === "win32" ? join(appData, "Claude", "claude_desktop_config.json") : join(home, ".config", "Claude", "claude_desktop_config.json");
      return [{ path, format: "json", containers: [["mcpServers"]], scope: "user", notes: [".mcpb desktop extensions and remote custom connectors are not in this file and cannot be wrapped locally.", ...(platform === "linux" ? ["The Linux path of Claude Desktop's configuration is not confirmed."] : [])] }];
    }
    case "claude-code": {
      const dir = env.CLAUDE_CONFIG_DIR !== undefined && env.CLAUDE_CONFIG_DIR !== "" ? env.CLAUDE_CONFIG_DIR : null;
      return [{ path: dir !== null ? join(dir, ".claude.json") : join(home, ".claude.json"), format: "json", containers: [["mcpServers"], ["projects", "*", "mcpServers"]], scope: "user", notes: ["Project .mcp.json files are repository content and are never rewritten; claude.ai connectors registered in the desktop app are out of reach."] }];
    }
    case "cursor":
      return [{ path: join(home, ".cursor", "mcp.json"), format: "json", containers: [["mcpServers"]], scope: "user", notes: ["The project .cursor/mcp.json is repository content and is never rewritten."] }];
    case "gemini": {
      const gh = env.GEMINI_CLI_HOME !== undefined && env.GEMINI_CLI_HOME !== "" ? env.GEMINI_CLI_HOME : home;
      return [{ path: join(gh, ".gemini", "settings.json"), format: "json", containers: [["mcpServers"]], scope: "user", notes: ["A project .gemini/settings.json wins over this file and is never rewritten.", "\"trust\": true skips every confirmation; wrapping removes it from the wrapped entries."] }];
    }
    case "vscode": {
      const user = platform === "darwin" ? join(home, "Library", "Application Support", "Code", "User", "mcp.json") : platform === "win32" ? join(appData, "Code", "User", "mcp.json") : join(home, ".config", "Code", "User", "mcp.json");
      return [
        { path: user, format: "json", containers: [["servers"]], scope: "user", notes: ["Workspace .vscode/mcp.json files are repository content and are never rewritten."] },
        { path: join(home, ".copilot", "mcp-config.json"), format: "json", containers: [["mcpServers"]], scope: "user", notes: [] },
      ];
    }
    case "codex": {
      const ch = env.CODEX_HOME !== undefined && env.CODEX_HOME !== "" ? env.CODEX_HOME : join(home, ".codex");
      return [{ path: join(ch, "config.toml"), format: "toml", containers: [["mcp_servers"]], scope: "user", notes: ["The ChatGPT desktop app edits the same file; doctor rereads it."] }];
    }
  }
}

export interface WrapContext {
  l: Layout;
  client: ClientId;
  node: string;
  cli: string;
  port: number;
  /** Only these servers (default: all). */
  servers?: readonly string[];
  /** The paired phones' pin carried in each wrapper's arguments; default: the pin of the phones paired now (null: none). */
  phones?: string | null;
  now?: Date;
}

/** The pin of the phones paired now, or null (none paired, or an unreadable list: no pin, so phone approvals are refused). */
function currentPhonesPin(l: Layout): string | null {
  try {
    return phonesPinOf(l);
  } catch {
    return null;
  }
}

export interface FilePlan {
  file: ClientFile;
  before: string | null;
  after: string | null;
  wrapped: GatewayEntry[];
  skipped: { server: string; why: string }[];
  /** LG4: entries wrapped before the compile-cache fix, given `NODE_COMPILE_CACHE` empty in place (their records keep the original). */
  fixed: { server: string; location: string[]; wrappedHash: string }[];
  /** Codex: the editor refused; the snippet to paste by hand. */
  refused?: { why: string; snippet: string };
}

/** LG4: why an already-wrapped entry cannot be fixed in place (it changed since it was wrapped), or null. */
function unfixable(records: readonly GatewayEntry[], file: string, location: readonly string[], hash: string): string | null {
  const rec = records.find((r) => r.file === file && r.upstream.kind === "stdio" && JSON.stringify(r.location) === JSON.stringify(location));
  if (rec === undefined) return "already wrapped, but not by a recorded wrap-config, and it does not clear NODE_COMPILE_CACHE; unwrap it by hand and wrap it again";
  if (rec.wrappedHash !== hash) return "already wrapped, but it does not clear NODE_COMPILE_CACHE and changed since it was wrapped; run mcp unwrap-config, then wrap-config";
  return null;
}

function wrapArgs(c: WrapContext, name: string, mode: string, command: string, args: readonly string[]): string[] {
  return wrapperArgs(c.cli, c.client, name, mode, command, args, c.phones ?? null);
}


const URL_KEYS = ["url", "httpUrl", "serverUrl"] as const;

/** One JSON server entry wrapped, or why it is left as it is. */
export function wrapJsonEntry(c: WrapContext, name: string, entry: unknown, mode: "full" | "hook", token: string): { entry: Json; upstream: Upstream } | { skip: string } {
  if (!isObj(entry)) return { skip: "not an object" };
  // A name with "__" or a trailing "_" runs into mcp__<server>__<tool>: its calls would be judged as another server's.
  const bad = serverNameProblem(name);
  if (bad !== null) return { skip: `its name ${bad}; rename it in the client's configuration, then wrap it` };
  if (entry.disabled === true) return { skip: "disabled" };
  if (unwrapFirewall(entry, c.cli) !== entry || (typeof entry.command === "string" && entry.command === c.node && Array.isArray(entry.args) && entry.args[1] === "mcp")) return { skip: "already wrapped" };
  const urlKeys = URL_KEYS.filter((k) => entry[k] !== undefined);
  // V8: an entry the client could read two ways is not guessed at: a command next to a URL, or URL keys that
  // name different servers, would leave one way reaching the server directly (with the gateway's bearer).
  if (typeof entry.command === "string" && urlKeys.length > 0) return { skip: `it has both a command and ${urlKeys.join(" and ")}; keep one of them, then wrap it` };
  if (typeof entry.command === "string") {
    const args = Array.isArray(entry.args) ? entry.args : [];
    if (!args.every((a) => typeof a === "string")) return { skip: "its arguments are not all strings" };
    if (/\s/.test(entry.command) && args.length === 0) return { skip: "its command has spaces and no separate arguments; split it into command and args first" };
    // LG4: NODE_COMPILE_CACHE empty for the firewall's own node; the entry's value is passed on to the server only.
    const env = wrapperEnv(entry.env);
    if (env === null) return { skip: "its env is not an object" };
    const out: Json = { ...entry, command: c.node, args: wrapArgs(c, name, mode, entry.command, args as string[]), env };
    if (out.trust === true) delete out.trust;
    return { entry: out, upstream: { kind: "stdio", command: entry.command, args: args as string[], envKeys: isObj(entry.env) ? Object.keys(entry.env).sort() : [] } };
  }
  if (urlKeys.length > 0) {
    if (urlKeys.some((k) => typeof entry[k] !== "string")) return { skip: `its ${urlKeys.join(" and ")} must all be strings` };
    const urls = urlKeys.map((k) => entry[k] as string);
    const local = urls.filter((u) => /^https?:\/\/127\.0\.0\.1:\d+\/c\//.test(u));
    if (local.length === urls.length) return { skip: "already wrapped" };
    if (local.length > 0) return { skip: `some of its ${urlKeys.join(" and ")} point at the gateway and some do not; fix the entry, then wrap it` };
    const origins = new Set(urls.map((u) => {
      try {
        return new URL(u).origin;
      } catch {
        return u;
      }
    }));
    if (origins.size > 1) return { skip: `its ${urlKeys.join(" and ")} name different servers (${[...origins].join(", ")}); keep one, then wrap it` };
    // Gemini CLI prefers httpUrl (Streamable HTTP) over url (SSE); the gateway speaks Streamable HTTP upstream.
    const key = (["httpUrl", "url", "serverUrl"] as const).find((k) => urlKeys.includes(k)) as (typeof URL_KEYS)[number];
    const url = entry[key] as string;
    const out: Json = { ...entry, headers: { Authorization: `Bearer ${token}` } };
    for (const k of urlKeys) out[k] = gatewayUrl(c.port, c.client, name);
    if (out.trust === true) delete out.trust;
    return { entry: out, upstream: { kind: "http", url, headerKeys: isObj(entry.headers) ? Object.keys(entry.headers).sort() : [] } };
  }
  return { skip: "neither a command nor a URL" };
}

function containersOf(doc: Json, spec: string[][]): { path: string[]; servers: Json }[] {
  const out: { path: string[]; servers: Json }[] = [];
  for (const p of spec) {
    if (p[1] === "*") {
      const projects = own(doc, p[0] as string);
      if (!isObj(projects)) continue;
      for (const [dir, proj] of Object.entries(projects)) if (isObj(proj) && isObj(own(proj, p[2] as string))) out.push({ path: [p[0] as string, dir, p[2] as string], servers: own(proj, p[2] as string) as Json });
    } else if (isObj(own(doc, p[0] as string))) out.push({ path: [p[0] as string], servers: own(doc, p[0] as string) as Json });
  }
  return out;
}

/** What wrapping a client's files would do (nothing is written). */
export function planWrap(c0: WrapContext, e: FileEnv): FilePlan[] {
  const c: WrapContext = { ...c0, phones: c0.phones !== undefined ? c0.phones : currentPhonesPin(c0.l) };
  // I4: full mode unless the person's own policy names hook mode (and the hook is installed).
  const mode = resolveMode(c.l, c.client, gatewayPolicy(loadPolicy(c.l, []).config).mode).mode;
  const token = clientToken(c.l, c.client);
  const ts = (c.now ?? new Date()).toISOString();
  const records = ((): GatewayEntry[] => {
    try {
      return readGatewayInstall(c.l).entries;
    } catch {
      return [];
    }
  })();
  return clientFiles(c.client, e).map((file) => {
    const before = readText(file.path);
    const plan: FilePlan = { file, before, after: null, wrapped: [], skipped: [], fixed: [] };
    if (before === null) return plan;
    const want = (n: string): boolean => c.servers === undefined || c.servers.includes(n);
    if (file.format === "toml") {
      const r = codexWrap(before, { ...c, phones: c.phones ?? null, mode, token, want });
      if ("refused" in r) {
        plan.refused = r.refused;
        return plan;
      }
      plan.after = r.text;
      plan.skipped = r.skipped;
      // LG4: tables wrapped before the compile-cache fix get NODE_COMPILE_CACHE empty in place.
      const stale = r.skipped.filter((k) => k.why === "already wrapped" && strArgs(tomlTableOf(before, k.server))[1] === "mcp" && !codexClearsCompileCache(before, k.server));
      const fixable = stale.filter((k) => {
        const why = unfixable(records, file.path, ["mcp_servers", k.server], entryHash(tomlTableOf(before, k.server)));
        if (why !== null) k.why = why;
        return why === null;
      });
      if (fixable.length > 0) {
        const cc = codexCompileCache(r.text, fixable.map((k) => k.server));
        if ("why" in cc) for (const k of fixable) k.why = `already wrapped, but it does not clear NODE_COMPILE_CACHE and ${cc.why}`;
        else {
          plan.after = cc.text;
          plan.skipped = r.skipped.filter((k) => !fixable.includes(k));
          for (const k of fixable) plan.fixed.push({ server: k.server, location: ["mcp_servers", k.server], wrappedHash: entryHash(tomlTableOf(cc.text, k.server)) });
          for (const w of r.entries) w.wrappedHash = entryHash(tomlTableOf(cc.text, w.name));
        }
      }
      plan.wrapped = r.entries.map((x) => ({ client: c.client, server: x.name, file: file.path, scope: file.scope, mode, upstream: x.upstream, originalHash: entryHash(x.original), wrappedHash: x.wrappedHash, original: x.original, location: ["mcp_servers", x.name], wrappedAt: ts }));
      return plan;
    }
    let doc: unknown;
    try {
      doc = parseJsonFile(file.path, before);
    } catch (e) {
      plan.refused = { why: (e as Error).message, snippet: "" };
      return plan;
    }
    if (!isObj(doc)) return plan;
    for (const { path, servers } of containersOf(doc, file.containers)) {
      for (const [name, entry] of Object.entries(servers)) {
        if (!want(name)) continue;
        const w = wrapJsonEntry(c, name, entry, mode, token);
        if ("skip" in w) {
          // LG4: a stdio wrapper from before the compile-cache fix gets NODE_COMPILE_CACHE empty in place.
          if (w.skip === "already wrapped" && isObj(entry) && isStdioWrapper(entry, c.cli) && !clearsCompileCache(entry)) {
            const location = [...path, name];
            const why = unfixable(records, file.path, location, entryHash(entry));
            const env = wrapperEnv(entry.env);
            if (why !== null || env === null) plan.skipped.push({ server: name, why: why ?? "already wrapped, but its env is not an object" });
            else {
              const next: Json = { ...entry, env };
              setOwn<unknown>(servers, name, next);
              plan.fixed.push({ server: name, location, wrappedHash: entryHash(next) });
            }
            continue;
          }
          plan.skipped.push({ server: name, why: w.skip });
          continue;
        }
        setOwn<unknown>(servers, name, w.entry);
        const scope = path[0] === "projects" ? "local" : file.scope;
        plan.wrapped.push({ client: c.client, server: name, file: file.path, scope, mode, upstream: w.upstream, originalHash: entryHash(entry), wrappedHash: entryHash(w.entry), original: entry as Json, location: [...path, name], wrappedAt: ts });
      }
    }
    if (plan.wrapped.length > 0 || plan.fixed.length > 0) plan.after = `${JSON.stringify(doc, null, 2)}\n`;
    return plan;
  });
}

/** The `args` of a Codex table as tomlTable returns it (its flattened keys), in order. */
function strArgs(table: Json | null): string[] {
  const out: string[] = [];
  for (let i = 0; table !== null; i++) {
    const v = own(table, JSON.stringify(["args", String(i)]));
    if (typeof v !== "string") break;
    try {
      out.push(String(JSON.parse(v)));
    } catch {
      break;
    }
  }
  return out;
}

/** Whether a JSON entry is the gateway's stdio wrapper (`<node> <cli.js> mcp wrap …`). */
function isStdioWrapper(entry: Json, cli: string): boolean {
  const args = entry.args;
  return typeof entry.command === "string" && Array.isArray(args) && args[0] === cli && args[1] === "mcp" && args[2] === "wrap";
}

/** A short line diff: the changed middle of the file, with a little context. */
export function lineDiff(before: string, after: string, context = 2): string {
  const a = before.split("\n");
  const b = after.split("\n");
  let s = 0;
  while (s < a.length && s < b.length && a[s] === b[s]) s++;
  let ea = a.length - 1;
  let eb = b.length - 1;
  while (ea >= s && eb >= s && a[ea] === b[eb]) {
    ea--;
    eb--;
  }
  const out: string[] = [];
  for (let i = Math.max(0, s - context); i < s; i++) out.push(`  ${a[i] ?? ""}`);
  for (let i = s; i <= ea; i++) out.push(`- ${a[i] ?? ""}`);
  for (let i = s; i <= eb; i++) out.push(`+ ${b[i] ?? ""}`);
  for (let i = ea + 1; i <= Math.min(a.length - 1, ea + context); i++) out.push(`  ${a[i] ?? ""}`);
  return out.join("\n");
}

/** Writes a plan: backup, atomic write, install record. Returns the backup path. */
export function applyPlan(l: Layout, plan: FilePlan, now = new Date()): string | null {
  if (plan.after === null || plan.before === null) return null;
  assertNotRealHome(plan.file.path);
  // FA4: a symlinked client file is checked before it is copied or recorded, not only at the write.
  writeTarget(plan.file.path);
  ensureDir(l.backups);
  const backup = join(l.backups, `gateway-${now.toISOString().replace(/[:.]/g, "-")}-${basename(plan.file.path)}`);
  if (existsSync(plan.file.path)) copyFileSync(plan.file.path, backup);
  updateGatewayInstall(l, (g) => {
    g.entries = g.entries.filter((x) => !plan.wrapped.some((w) => w.file === x.file && JSON.stringify(w.location) === JSON.stringify(x.location)));
    g.entries.push(...plan.wrapped);
    // LG4: a fixed entry keeps its record (and original); only the hash of what is now written changes.
    for (const x of g.entries) {
      const f = plan.fixed.find((y) => x.file === plan.file.path && JSON.stringify(y.location) === JSON.stringify(x.location));
      if (f !== undefined) x.wrappedHash = f.wrappedHash;
    }
  });
  // Written through a symlink (a dotfiles link), never replacing it; the mode is kept, a new file is 0600.
  writeUserFile(plan.file.path, plan.after);
  recordOwnWrite(l, plan.file.path, plan.before, plan.after);
  return backup;
}

export interface UnwrapPlan {
  file: string;
  before: string | null;
  after: string | null;
  restored: GatewayEntry[];
  /** What happened to entries the person edited after wrapping, and entries gone from the file. */
  notes: string[];
  /** Edited entries whose wrapper could not be separated from the edit: kept as edited, the original saved to the backups folder when the plan is applied. */
  saved: { server: string; original: Json }[];
  /** Filled in by applyUnwrap: where each original was saved. */
  savedPaths?: string[];
  refused?: { why: string; snippet: string };
}

/** What unwrapping a client would do: each recorded entry back to its original. */
export function planUnwrap(l: Layout, client: ClientId): UnwrapPlan[] {
  const entries = readGatewayInstall(l).entries.filter((e) => e.client === client);
  const byFile = new Map<string, GatewayEntry[]>();
  for (const e of entries) byFile.set(e.file, [...(byFile.get(e.file) ?? []), e]);
  return [...byFile].map(([file, list]) => {
    const before = readText(file);
    const plan: UnwrapPlan = { file, before, after: null, restored: [], notes: [], saved: [] };
    if (before === null) {
      plan.notes.push(`${file} no longer exists; its records are removed`);
      plan.restored = list;
      return plan;
    }
    if (/\.toml$/i.test(file)) {
      const r = codexUnwrap(before, list);
      if ("refused" in r) plan.refused = r.refused;
      else {
        plan.after = r.text;
        plan.restored = list;
        plan.notes.push(...r.notes);
        plan.saved.push(...r.saved);
      }
      return plan;
    }
    let doc: unknown;
    try {
      doc = parseJsonFile(file, before);
    } catch (err) {
      plan.refused = { why: (err as Error).message, snippet: JSON.stringify(Object.fromEntries(list.map((e) => [e.server, e.original])), null, 2) };
      return plan;
    }
    if (!isObj(doc)) return plan;
    for (const e of list) {
      let holder: unknown = doc;
      for (const k of e.location.slice(0, -1)) holder = isObj(holder) ? own(holder, k) : undefined;
      if (!isObj(holder)) {
        plan.notes.push(`MCP server "${e.server}" is no longer in ${file}; nothing to restore`);
        plan.restored.push(e);
        continue;
      }
      const cur = own(holder, e.server);
      if (cur === undefined) plan.notes.push(`MCP server "${e.server}" is no longer in ${file}; nothing to restore`);
      else {
        if (entryHash(cur) === e.wrappedHash) setOwn<unknown>(holder, e.server, e.original);
        else {
          // The person edited the entry after it was wrapped: their edit is never overwritten with the old original.
          const mine = unwrapEdited(cur, e);
          if (mine !== null) {
            setOwn<unknown>(holder, e.server, mine);
            plan.notes.push(`MCP server "${e.server}" was edited after it was wrapped: your edit is kept and only the gateway wrapper is removed from it (the original from before wrapping is not used).`);
          } else {
            plan.saved.push({ server: e.server, original: e.original });
            plan.notes.push(`MCP server "${e.server}" was edited after it was wrapped, and the wrapper cannot be separated from your edit without guessing: the entry is left exactly as you edited it (it may still go through the gateway), and the original from before wrapping is saved to the backups folder.`);
          }
        }
      }
      plan.restored.push(e);
    }
    plan.after = `${JSON.stringify(doc, null, 2)}\n`;
    return plan;
  });
}

/** An entry the person edited after it was wrapped, with the gateway wrapper taken out, when that is unambiguous; else null. */
function unwrapEdited(cur: unknown, e: GatewayEntry): Json | null {
  if (!isObj(cur)) return null;
  if (e.upstream.kind === "stdio") {
    const args = cur.args;
    if (typeof cur.command !== "string" || !Array.isArray(args) || !args.every((a) => typeof a === "string") || args[1] !== "mcp" || args[2] !== "wrap") return null;
    const sep = args.indexOf("--");
    if (sep < 3 || typeof args[sep + 1] !== "string") return null;
    const out: Json = { ...cur, command: args[sep + 1], args: args.slice(sep + 2) };
    if (isObj(cur.env)) {
      const env = unwrappedEnv(cur.env);
      if (Object.keys(env).length === 0 && e.original.env === undefined) delete out.env;
      else out.env = env;
    }
    return out;
  }
  const urlKeys = URL_KEYS.filter((k) => cur[k] !== undefined);
  if (urlKeys.length === 0 || !urlKeys.every((k) => typeof cur[k] === "string" && /^https?:\/\/127\.0\.0\.1:\d+\/c\//.test(cur[k] as string))) return null;
  // Only the bearer header the wrapper added: any other header is the person's, and which of the two is meant is a guess.
  if (cur.headers !== undefined && !(isObj(cur.headers) && Object.keys(cur.headers).length === 1 && typeof cur.headers.Authorization === "string" && cur.headers.Authorization.startsWith("Bearer "))) return null;
  const out: Json = { ...cur };
  for (const k of urlKeys) out[k] = typeof e.original[k] === "string" ? e.original[k] : e.upstream.url;
  if (e.original.headers !== undefined) out.headers = e.original.headers;
  else delete out.headers;
  return out;
}

export function applyUnwrap(l: Layout, plan: UnwrapPlan, now = new Date()): string | null {
  let backup: string | null = null;
  if (plan.after !== null && plan.before !== null) writeTarget(plan.file);
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  if (plan.saved.length > 0) {
    ensureDir(l.backups);
    plan.savedPaths = plan.saved.map((x) => {
      const path = join(l.backups, `gateway-unwrap-original-${stamp}-${x.server.replace(/[^A-Za-z0-9._-]/g, "_")}.json`);
      atomicWrite(path, `${JSON.stringify({ file: plan.file, server: x.server, original: x.original }, null, 2)}\n`, 0o600);
      return path;
    });
  }
  if (plan.after !== null && plan.before !== null) {
    assertNotRealHome(plan.file);
    ensureDir(l.backups);
    backup = join(l.backups, `gateway-unwrap-${stamp}-${basename(plan.file)}`);
    copyFileSync(plan.file, backup);
    writeUserFile(plan.file, plan.after);
    recordOwnWrite(l, plan.file, plan.before, plan.after);
  }
  updateGatewayInstall(l, (g) => {
    g.entries = g.entries.filter((x) => !plan.restored.some((r) => r.file === x.file && JSON.stringify(r.location) === JSON.stringify(x.location)));
  });
  return backup;
}

/** Servers in a client's files that are not wrapped (doctor and gateway status). */
export function unwrappedServers(c: { l: Layout; client: ClientId; cli: string; node: string }, e: FileEnv): { file: string; server: string }[] {
  const out: { file: string; server: string }[] = [];
  for (const file of clientFiles(c.client, e)) {
    const text = readText(file.path);
    if (text === null) continue;
    if (file.format === "toml") continue; // Codex: reported by the agent-mcp drift check
    let doc: unknown;
    try {
      doc = JSON.parse(text);
    } catch {
      continue;
    }
    if (!isObj(doc)) continue;
    for (const { servers } of containersOf(doc, file.containers)) {
      for (const [name, entry] of Object.entries(servers)) {
        if (!isObj(entry) || entry.disabled === true) continue;
        const wrapped = unwrapFirewall(entry, c.cli) !== entry || (Array.isArray(entry.args) && entry.args[0] === c.cli && entry.args[1] === "mcp") || URL_KEYS.some((k) => typeof entry[k] === "string" && /^https?:\/\/127\.0\.0\.1:\d+\/c\//.test(entry[k] as string));
        if (!wrapped) out.push({ file: file.path, server: name });
      }
    }
  }
  return out;
}

export interface GatewayRepinResult {
  updated: string[];
  skipped: { path: string; server: string; reason: string }[];
}

/**
 * sets the paired phones' pin (or removes it) in every recorded stdio wrapper, the gateway's counterpart
 * of repinApprover for hook commands. Person-run only (`phone pair` and `phone remove`). An entry changed since it
 * was wrapped, or a file that cannot be read or written, is reported and left as it is: phone approvals then stay
 * refused for that server (they fall back to the terminal) and doctor says so.
 */
export function repinGatewayEntries(l: Layout, pin: string | null, now = new Date()): GatewayRepinResult {
  const out: GatewayRepinResult = { updated: [], skipped: [] };
  const records = readGatewayInstall(l).entries.filter((e) => e.upstream.kind === "stdio");
  const byFile = new Map<string, GatewayEntry[]>();
  for (const e of records) byFile.set(e.file, [...(byFile.get(e.file) ?? []), e]);
  for (const [file, list] of byFile) {
    const skip = (e: GatewayEntry, reason: string): void => void out.skipped.push({ path: file, server: e.server, reason });
    try {
      assertNotRealHome(file);
      const before = readText(file);
      if (before === null) {
        for (const e of list) skip(e, "the file no longer exists");
        continue;
      }
      let after: string;
      const newHashes = new Map<GatewayEntry, string>();
      const done: GatewayEntry[] = [];
      if (/\.toml$/i.test(file)) {
        const current = list.filter((e) => {
          const hash = entryHash(tomlTableOf(before, e.server));
          if (hash === e.wrappedHash) return true;
          skip(e, "it changed since it was wrapped");
          return false;
        });
        const r = codexRepin(before, current.map((e) => e.server), pin);
        if ("refused" in r) {
          for (const e of current) skip(e, r.refused.why);
          continue;
        }
        for (const k of r.skipped) {
          const e = current.find((x) => x.server === k.server);
          if (e !== undefined) skip(e, k.why);
        }
        after = r.text;
        for (const e of current.filter((x) => r.updated.includes(x.server))) {
          done.push(e);
          newHashes.set(e, entryHash(tomlTableOf(after, e.server)));
        }
      } else {
        const doc = parseJsonFile(file, before);
        for (const e of list) {
          let holder: unknown = doc;
          for (const k of e.location.slice(0, -1)) holder = isObj(holder) ? own(holder, k) : undefined;
          const cur = isObj(holder) ? own(holder, e.server) : undefined;
          if (!isObj(cur)) {
            skip(e, "it is no longer in the file");
            continue;
          }
          if (entryHash(cur) !== e.wrappedHash) {
            skip(e, "it changed since it was wrapped");
            continue;
          }
          if (!Array.isArray(cur.args) || !cur.args.every((a) => typeof a === "string")) {
            skip(e, "its arguments are not the wrapper's");
            continue;
          }
          const args = cur.args as string[];
          const next = withPhonesArg(args, pin);
          if (next.length === args.length && next.every((a, i) => a === args[i])) continue;
          cur.args = next;
          done.push(e);
          newHashes.set(e, entryHash(cur));
        }
        after = `${JSON.stringify(doc, null, 2)}\n`;
      }
      if (done.length === 0) continue;
      writeTarget(file);
      ensureDir(l.backups);
      const backup = join(l.backups, `gateway-repin-${now.toISOString().replace(/[:.]/g, "-")}-${basename(file)}`);
      copyFileSync(file, backup);
      writeUserFile(file, after);
      recordOwnWrite(l, file, before, after);
      updateGatewayInstall(l, (g) => {
        for (const x of g.entries) {
          const hit = done.find((d) => d.file === x.file && JSON.stringify(d.location) === JSON.stringify(x.location));
          if (hit !== undefined) x.wrappedHash = newHashes.get(hit) as string;
        }
      });
      out.updated.push(file);
    } catch (e) {
      if (e instanceof Error && e.name === "RealHomeRefused") throw e;
      for (const x of list) skip(x, (e as Error).message);
    }
  }
  return out;
}

/**
 * the phones pin of every recorded stdio wrapper (null where one carries none), read from the client
 * files as they are now; and whether any gateway entry is HTTP (`mcp serve` pins the list when it starts).
 */
export function wrappedPhonePins(l: Layout): { pins: (string | null)[]; http: boolean; problems: string[] } {
  const out = { pins: [] as (string | null)[], http: false, problems: [] as string[] };
  let records: GatewayEntry[];
  try {
    records = readGatewayInstall(l).entries;
  } catch (e) {
    return { ...out, problems: [(e as Error).message] };
  }
  out.http = records.some((e) => e.upstream.kind === "http");
  for (const e of records.filter((x) => x.upstream.kind === "stdio")) {
    try {
      const text = readText(e.file);
      if (text === null) continue;
      if (/\.toml$/i.test(e.file)) {
        const flat = tomlFlatten(text);
        const args: string[] = [];
        for (let i = 0; flat !== null; i++) {
          const v = flat.get(JSON.stringify(["mcp_servers", e.server, "args", String(i)]));
          if (v === undefined) break;
          args.push(String(JSON.parse(v)));
        }
        out.pins.push(pinnedPhonesInArgs(args));
        continue;
      }
      let holder: unknown = JSON.parse(text);
      for (const k of e.location) holder = isObj(holder) ? own(holder, k) : undefined;
      out.pins.push(isObj(holder) && Array.isArray(holder.args) ? pinnedPhonesInArgs(holder.args.map(String)) : null);
    } catch (err) {
      out.problems.push(`${e.file}: ${(err as Error).message}`);
    }
  }
  return out;
}

/** The symlink a wrap or unwrap of `path` writes through, for the message (the link is kept). */
export function linkTarget(path: string): string | null {
  return writeTarget(path).linkedTo;
}

/**
 * LG4: recorded stdio wrappers that do not set NODE_COMPILE_CACHE empty for the firewall's own node (wrapped
 * before 0.3.0's fix, or edited since), read from the client files as they are now (doctor).
 */
export function wrappedWithoutCompileCache(l: Layout): { client: ClientId; file: string; server: string }[] {
  const out: { client: ClientId; file: string; server: string }[] = [];
  let records: GatewayEntry[];
  try {
    records = readGatewayInstall(l).entries.filter((e) => e.upstream.kind === "stdio");
  } catch {
    return out;
  }
  for (const e of records) {
    try {
      const text = readText(e.file);
      if (text === null) continue;
      if (/\.toml$/i.test(e.file)) {
        if (strArgs(tomlTableOf(text, e.server))[2] === "wrap" && !codexClearsCompileCache(text, e.server)) out.push({ client: e.client, file: e.file, server: e.server });
        continue;
      }
      let holder: unknown = JSON.parse(text);
      for (const k of e.location) holder = isObj(holder) ? own(holder, k) : undefined;
      if (isObj(holder) && Array.isArray(holder.args) && holder.args[1] === "mcp" && holder.args[2] === "wrap" && !clearsCompileCache(holder)) out.push({ client: e.client, file: e.file, server: e.server });
    } catch {
      // An unreadable file is reported by the other gateway checks.
    }
  }
  return out;
}
