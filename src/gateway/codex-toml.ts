/**
 * A narrow editor for Codex's ~/.codex/config.toml (see docs/gateway.md): it changes only the `command`/`args` (or `url` and auth) lines of
 * `[mcp_servers.<name>]` tables and refuses, printing the snippet to paste
 * instead, on any construct it does not fully parse: a comment inside a server
 * table, a value spanning lines (multi-line array, inline table or string),
 * arrays of tables, or servers written as dotted keys or inline tables. Every
 * edit is checked by parsing the result and comparing every other key with
 * the original.
 */

import { entryHashOf, tomlTable } from "../engine/gateway-config.js";
import { tomlFlatten } from "../engine/settings.js";
import { UPSTREAM_COMPILE_CACHE, withPhonesArg, wrapperArgs, type GatewayEntry, type Upstream } from "./install.js";
import { gatewayUrl } from "./tokens.js";
import { serverNameProblem } from "./names.js";

const HEADER = /^\s*\[\s*mcp_servers\s*\.\s*(?:"([^"\\]+)"|([A-Za-z0-9_-]+))\s*\]\s*$/;
const ANY_HEADER = /^\s*\[/;
const tq = (s: string): string => JSON.stringify(s);

interface Section {
  name: string;
  start: number;
  end: number;
}

function sections(lines: readonly string[]): Section[] {
  const out: Section[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = HEADER.exec(lines[i] as string);
    if (m === null) continue;
    let end = i + 1;
    while (end < lines.length && !ANY_HEADER.test(lines[end] as string)) end++;
    out.push({ name: (m[1] ?? m[2]) as string, start: i, end });
  }
  return out;
}

/** Why a server table's body is outside what the editor handles, or null. */
function unsupported(body: readonly string[]): string | null {
  for (const raw of body) {
    const line = raw.trim();
    if (line === "") continue;
    if (line.startsWith("#")) return "a comment inside the server's table";
    if (line.includes('"""') || line.includes("'''")) return "a multi-line string";
    let inStr: string | null = null;
    let depth = 0;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i] as string;
      if (inStr !== null) {
        if (ch === "\\" && inStr === '"') i++;
        else if (ch === inStr) inStr = null;
        continue;
      }
      if (ch === '"' || ch === "'") inStr = ch;
      else if (ch === "#") return "a comment inside the server's table";
      else if (ch === "[" || ch === "{") depth++;
      else if (ch === "]" || ch === "}") depth--;
    }
    if (depth !== 0 || inStr !== null) return "a value spanning lines";
  }
  return null;
}

const keyOf = (line: string): string | null => /^\s*([A-Za-z0-9_-]+)\s*=/.exec(line)?.[1] ?? null;

function str(flat: Map<string, string>, path: string[]): string | undefined {
  const v = flat.get(JSON.stringify(path));
  if (v === undefined) return undefined;
  try {
    const s = JSON.parse(v) as unknown;
    return typeof s === "string" ? s : undefined;
  } catch {
    return undefined;
  }
}

function strList(flat: Map<string, string>, path: string[]): string[] | null {
  const out: string[] = [];
  for (let i = 0; ; i++) {
    const v = str(flat, [...path, String(i)]);
    if (v === undefined) {
      if (flat.has(JSON.stringify([...path, String(i)]))) return null;
      break;
    }
    out.push(v);
  }
  return out;
}

export interface CodexWrapOptions {
  client: string;
  node: string;
  cli: string;
  port: number;
  mode: "full" | "hook";
  token: string;
  /** The paired phones' pin carried in each wrapper's arguments (null: none). */
  phones?: string | null;
  want: (name: string) => boolean;
}

type Refused = { refused: { why: string; snippet: string } };

/** Wraps the wanted servers of a config.toml, or refuses with a snippet. */
export function codexWrap(text: string, o: CodexWrapOptions): { text: string; entries: { name: string; upstream: Upstream; original: Record<string, unknown>; wrappedHash: string }[]; skipped: { server: string; why: string }[] } | Refused {
  const flat = tomlFlatten(text);
  if (flat === null) return { refused: { why: "config.toml could not be parsed", snippet: "" } };
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  if (lines.some((l) => /^\s*\[\[\s*mcp_servers/.test(l))) return { refused: { why: "an array of tables under mcp_servers", snippet: "" } };
  const secs = sections(lines);
  const names = new Set<string>();
  for (const k of flat.keys()) {
    const p = JSON.parse(k) as string[];
    if (p[0] === "mcp_servers" && p[1] !== undefined) names.add(p[1]);
  }
  const out = [...lines];
  const entries: { name: string; upstream: Upstream; original: Record<string, unknown>; wrappedHash: string }[] = [];
  const skipped: { server: string; why: string }[] = [];
  const snippets: string[] = [];
  let refusal: string | null = null;
  // Edits are made from the bottom up so line numbers above stay valid.
  const edits: { sec: Section; body: string[] }[] = [];
  for (const name of names) {
    if (!o.want(name)) continue;
    const badName = serverNameProblem(name);
    if (badName !== null) {
      skipped.push({ server: name, why: `its name ${badName}; rename it in the client's configuration, then wrap it` });
      continue;
    }
    const sec = secs.find((s) => s.name === name);
    const command = str(flat, ["mcp_servers", name, "command"]);
    const args = strList(flat, ["mcp_servers", name, "args"]) ?? null;
    const url = str(flat, ["mcp_servers", name, "url"]);
    const snippet = command !== undefined && args !== null ? `[mcp_servers.${tq(name)}]\ncommand = ${tq(o.node)}\nargs = [${wrapperArgs(o.cli, o.client, name, o.mode, command, args, o.phones ?? null).map(tq).join(", ")}]` : url !== undefined ? `[mcp_servers.${tq(name)}]\nurl = ${tq(gatewayUrl(o.port, o.client, name))}\nhttp_headers = { "Authorization" = ${tq(`Bearer ${o.token}`)} }` : "";
    if (sec === undefined) {
      refusal ??= `server "${name}" is written as dotted keys or an inline table`;
      snippets.push(snippet);
      continue;
    }
    const body = lines.slice(sec.start + 1, sec.end);
    const why = unsupported(body);
    if (why !== null) {
      refusal ??= `${why} (server "${name}")`;
      snippets.push(snippet);
      continue;
    }
    if (flat.get(JSON.stringify(["mcp_servers", name, "enabled"])) === "false") {
      skipped.push({ server: name, why: "disabled" });
      continue;
    }
    if (command === o.node && args?.[1] === "mcp") {
      skipped.push({ server: name, why: "already wrapped" });
      continue;
    }
    const original = { toml: body.join("\n") };
    let next: string[];
    let upstream: Upstream;
    if (command !== undefined && args !== null) {
      const wrapped = wrapperArgs(o.cli, o.client, name, o.mode, command, args, o.phones ?? null);
      next = [];
      let placed = false;
      for (const l of body) {
        const k = keyOf(l);
        if (k === "command") {
          next.push(`command = ${tq(o.node)}`, `args = [${wrapped.map(tq).join(", ")}]`);
          placed = true;
        } else if (k !== "args") next.push(l);
      }
      if (!placed) {
        refusal ??= `server "${name}" has no command line the editor can replace`;
        snippets.push(snippet);
        continue;
      }
      const envKeys = [...flat.keys()].map((k) => JSON.parse(k) as string[]).filter((p) => p[0] === "mcp_servers" && p[1] === name && p[2] === "env" && p[3] !== undefined).map((p) => p[3] as string);
      upstream = { kind: "stdio", command, args, envKeys: [...new Set(envKeys)].sort() };
    } else if (url !== undefined) {
      if (/^https?:\/\/127\.0\.0\.1:\d+\/c\//.test(url)) {
        skipped.push({ server: name, why: "already wrapped" });
        continue;
      }
      next = [];
      for (const l of body) {
        const k = keyOf(l);
        if (k === "url") next.push(`url = ${tq(gatewayUrl(o.port, o.client, name))}`, `http_headers = { "Authorization" = ${tq(`Bearer ${o.token}`)} }`);
        else if (k !== "http_headers" && k !== "bearer_token_env_var" && k !== "env_http_headers") next.push(l);
      }
      upstream = { kind: "http", url, headerKeys: [] };
    } else {
      skipped.push({ server: name, why: "neither a command nor a URL" });
      continue;
    }
    edits.push({ sec, body: next });
    entries.push({ name, upstream, original, wrappedHash: "" });
  }
  if (refusal !== null) return { refused: { why: `config.toml has ${refusal}; the narrow editor does not change what it cannot fully parse. Paste this yourself instead`, snippet: snippets.filter((s) => s !== "").join("\n\n") } };
  for (const e of [...edits].sort((a, b) => b.sec.start - a.sec.start)) out.splice(e.sec.start + 1, e.sec.end - e.sec.start - 1, ...e.body);
  const result = out.join("\n");
  const after = tomlFlatten(result);
  if (after === null) return { refused: { why: "the edited config.toml would not parse", snippet: "" } };
  // Every key outside the wrapped servers' command/args/url/auth must be unchanged.
  const touched = new Set(entries.map((e) => e.name));
  const changedOk = (p: string[]): boolean => p[0] === "mcp_servers" && touched.has(p[1] ?? "") && ["command", "args", "url", "http_headers", "bearer_token_env_var", "env_http_headers"].includes(p[2] ?? "");
  for (const [k, v] of flat) if (!changedOk(JSON.parse(k) as string[]) && after.get(k) !== v) return { refused: { why: "the edit would change other settings", snippet: "" } };
  for (const [k] of after) if (!changedOk(JSON.parse(k) as string[]) && !flat.has(k)) return { refused: { why: "the edit would add other settings", snippet: "" } };
  // LG4: each wrapped stdio table gets NODE_COMPILE_CACHE empty in its env (only that key changes).
  const cc = codexCompileCache(result, entries.filter((e) => e.upstream.kind === "stdio").map((e) => e.name));
  if ("why" in cc) return { refused: { why: `${cc.why}. Paste this yourself instead`, snippet: snippets.filter((x) => x !== "").join("\n\n") } };
  for (const e of entries) e.wrappedHash = entryHashOf(tomlTable(cc.text, e.name));
  return { text: cc.text, entries, skipped };
}

const CC = "NODE_COMPILE_CACHE";
const CC_LINE = `${CC} = ""`;
const escRe = (x: string): string => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const envHeader = (name: string): RegExp => new RegExp(`^\\s*\\[\\s*mcp_servers\\s*\\.\\s*(?:"${escRe(name)}"|${escRe(name)})\\s*\\.\\s*env\\s*\\]\\s*$`);

/** Whether a Codex server table sets NODE_COMPILE_CACHE empty in its env (LG4). */
export function codexClearsCompileCache(text: string, name: string): boolean {
  return tomlFlatten(text)?.get(JSON.stringify(["mcp_servers", name, "env", CC])) === '""';
}

/**
 * LG4: `NODE_COMPILE_CACHE = ""` in the env of each named server table, so the firewall's own node never loads a
 * compile cache named there. Added to a one-line inline `env = { … }`, under an `[mcp_servers.<name>.env]` table,
 * or as a new `env = { … }` line. A table that sets NODE_COMPILE_CACHE itself, passes it with env_vars, or writes
 * env any other way is refused (with what to do), never guessed at. Only that one key may change.
 */
export function codexCompileCache(text: string, names: readonly string[]): { text: string } | { why: string } {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const flat = tomlFlatten(text);
  if (flat === null) return { why: "config.toml could not be parsed" };
  const todo = names.filter((n) => flat.get(JSON.stringify(["mcp_servers", n, "env", CC])) !== '""');
  // From the bottom up, so line numbers above stay valid.
  const plans: { at: number; replace: boolean; line: string }[] = [];
  for (const name of todo) {
    if (flat.has(JSON.stringify(["mcp_servers", name, "env", CC]))) return { why: `server "${name}" sets ${CC} in its env, which would load a compile cache into the gateway; remove it, or rename it ${UPSTREAM_COMPILE_CACHE} (the gateway passes that to the server as ${CC}), then wrap again` };
    if ((strList(flat, ["mcp_servers", name, "env_vars"]) ?? []).includes(CC)) return { why: `server "${name}" passes ${CC} through env_vars, which would load a compile cache into the gateway; remove it from env_vars, then wrap again` };
    const sec = sections(lines).find((x) => x.name === name);
    if (sec === undefined) return { why: `server "${name}" is written as dotted keys or an inline table` };
    const inline = lines.findIndex((l, i) => i > sec.start && i < sec.end && keyOf(l) === "env");
    const sub = lines.findIndex((l) => envHeader(name).test(l));
    if (inline !== -1) {
      const l = lines[inline] as string;
      const empty = /^(\s*env\s*=\s*\{)\s*\}\s*$/.exec(l);
      const some = /^(\s*env\s*=\s*\{)(.*\}\s*)$/.exec(l);
      if (empty !== null) plans.push({ at: inline, replace: true, line: `${empty[1] as string} ${CC_LINE} }` });
      else if (some !== null) plans.push({ at: inline, replace: true, line: `${some[1] as string} ${CC_LINE},${some[2] as string}` });
      else return { why: `server "${name}" writes its env in a way the narrow editor does not change` };
    } else if (sub !== -1) plans.push({ at: sub + 1, replace: false, line: CC_LINE });
    else if ([...flat.keys()].some((k) => { const p = JSON.parse(k) as string[]; return p[0] === "mcp_servers" && p[1] === name && p[2] === "env"; })) return { why: `server "${name}" writes its env as dotted keys` };
    else {
      let last = sec.end - 1;
      while (last > sec.start && (lines[last] as string).trim() === "") last--;
      plans.push({ at: last + 1, replace: false, line: `env = { ${CC_LINE} }` });
    }
  }
  for (const p of plans.sort((a, b) => b.at - a.at)) lines.splice(p.at, p.replace ? 1 : 0, p.line);
  const result = lines.join("\n");
  const after = tomlFlatten(result);
  if (after === null) return { why: "the edited config.toml would not parse" };
  const ours = (k: string): boolean => {
    const p = JSON.parse(k) as string[];
    return p[0] === "mcp_servers" && todo.includes(p[1] ?? "") && p[2] === "env" && p[3] === CC && p.length === 4;
  };
  for (const [k, v] of flat) if (after.get(k) !== v) return { why: "the edit would change other settings" };
  const newEnv = (k: string): boolean => {
    const p = JSON.parse(k) as string[];
    return p[0] === "mcp_servers" && todo.includes(p[1] ?? "") && p[2] === "env" && p.length === 3;
  };
  for (const [k, v] of after) if (!flat.has(k) && !(ours(k) && v === '""') && !(newEnv(k) && v === "{}")) return { why: "the edit would add other settings" };
  return { text: result };
}

/** Puts recorded Codex entries back (their original table bodies). */
export function codexUnwrap(text: string, list: readonly GatewayEntry[]): { text: string; notes: string[]; saved: { server: string; original: Record<string, unknown> }[] } | Refused {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const secs = sections(lines);
  const notes: string[] = [];
  const saved: { server: string; original: Record<string, unknown> }[] = [];
  const edits: { sec: Section; body: string[] }[] = [];
  for (const e of list) {
    const sec = secs.find((s) => s.name === e.server);
    const body = typeof e.original.toml === "string" ? e.original.toml.split("\n") : null;
    if (sec === undefined) {
      notes.push(`MCP server "${e.server}" is no longer in ${e.file}; nothing to restore`);
      continue;
    }
    if (body === null) return { refused: { why: `the record for "${e.server}" has no original table`, snippet: "" } };
    if (entryHashOf(tomlTable(text, e.server)) !== e.wrappedHash) {
      // Edited after wrapping: the table stays as the person left it, and the original is saved beside the backups.
      saved.push({ server: e.server, original: e.original });
      notes.push(`MCP server "${e.server}" was edited after it was wrapped, and the wrapper cannot be separated from your edit without guessing: the table is left exactly as you edited it (it may still go through the gateway), and the original from before wrapping is saved to the backups folder.`);
      continue;
    }
    edits.push({ sec, body });
  }
  for (const ed of [...edits].sort((a, b) => b.sec.start - a.sec.start)) lines.splice(ed.sec.start + 1, ed.sec.end - ed.sec.start - 1, ...ed.body);
  // LG4: the line the wrap added under an `[mcp_servers.<name>.env]` table goes too (an inline one is in the body).
  for (const ed of edits) {
    const h = lines.findIndex((l) => envHeader(ed.sec.name).test(l));
    if (h !== -1 && (lines[h + 1] ?? "").trim() === CC_LINE) lines.splice(h + 1, 1);
  }
  const result = lines.join("\n");
  if (tomlFlatten(result) === null) return { refused: { why: "the restored config.toml would not parse", snippet: list.map((e) => `[mcp_servers.${tq(e.server)}]\n${String(e.original.toml ?? "")}`).join("\n\n") } };
  return { text: result, notes, saved };
}

/**
 * the phones pin set (or, with null, removed) in each listed server's wrapper arguments. Only the
 * `args` line of a table the narrow editor fully parses is touched; a table whose wrapper no longer looks like
 * ours is left alone and named in `skipped`.
 */
export function codexRepin(text: string, servers: readonly string[], pin: string | null): { text: string; updated: string[]; skipped: { server: string; why: string }[] } | Refused {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const secs = sections(lines);
  const flat = tomlFlatten(text);
  if (flat === null) return { refused: { why: "config.toml could not be parsed", snippet: "" } };
  const updated: string[] = [];
  const skipped: { server: string; why: string }[] = [];
  const edits: { sec: Section; body: string[] }[] = [];
  for (const name of servers) {
    const sec = secs.find((s) => s.name === name);
    const args = strList(flat, ["mcp_servers", name, "args"]);
    if (sec === undefined || args === null) {
      skipped.push({ server: name, why: "its table is not where the gateway wrote it" });
      continue;
    }
    const body = lines.slice(sec.start + 1, sec.end);
    const why = unsupported(body);
    if (why !== null) {
      skipped.push({ server: name, why });
      continue;
    }
    const next = withPhonesArg(args, pin);
    if (next.length === args.length && next.every((a, i) => a === args[i])) continue;
    edits.push({ sec, body: body.map((l) => (keyOf(l) === "args" ? `args = [${next.map(tq).join(", ")}]` : l)) });
    updated.push(name);
  }
  for (const e of [...edits].sort((a, b) => b.sec.start - a.sec.start)) lines.splice(e.sec.start + 1, e.sec.end - e.sec.start - 1, ...e.body);
  const result = lines.join("\n");
  if (tomlFlatten(result) === null) return { refused: { why: "the edited config.toml would not parse", snippet: "" } };
  return { text: result, updated, skipped };
}
