/**
 * MCP pins (firewallHome/pins/mcp.json): what each MCP server was when it was
 * first seen or last reviewed by a person. Three things are pinned:
 *
 * - its configuration (type, command, arguments, URL, working directory, the
 *   names of its environment variables and headers, the values of the
 *   environment variables that are not credentials, and the content of a
 *   local entry script it runs), from the files Claude Code reads;
 * - the set of tool names it has been seen to expose (tool calls, and tool
 *   definitions the firewall sees in ToolSearch results);
 * - each tool's description and input schema, when the firewall sees them.
 *
 * A change is never accepted automatically: it is recorded as pending, the
 * session is tainted (FW-MCP-CHANGED) and the person is told; only
 * `launchsafe-firewall pins accept <server>` (a person, with the approval
 * passphrase) re-pins. A server the repository's own .mcp.json names, seen
 * for the first time, is pinned and taints that session once. When the pins
 * file is unreadable it is moved aside and every configured server waits for
 * review (pending, tainting) instead of being pinned again as a first use.
 * Tool names a server exposes within the grace window
 * after its first-use pin are added silently, because servers expose tools
 * lazily. After it, a name not called before is a change only when the server's
 * tools could have changed (R9): its launch is not pinned to an exact version,
 * or its configuration changed. A tool whose definition was seen, or one on an
 * exact-version server with an unchanged configuration, is a first use (logged). `mcp pin --connect` (asking a server for tools/list directly) is
 * not built: descriptions are pinned only
 * from what the firewall observes.
 */

import { createHash, randomBytes } from "node:crypto";
import { readFileSync, realpathSync, renameSync, statSync } from "node:fs";
import { basename, isAbsolute, join, resolve, sep } from "node:path";
import type { FirewallConfig, StateEvent } from "../types.js";
import { canonicalJson, pinStability, type JsonValue } from "../vendor/agent-safety/index.js";
import { hiddenTextIn, injectionIn, isCredentialName, outboundInstructionIn, revealInvisible } from "../vendor/agent-safety/signals.js";
import type { ConfiguredServer } from "./agentfiles.js";
import { atomicWrite, tryReadText, withLock } from "./fsutil.js";
import { installDir, type Layout } from "./layout.js";
import { own, setOwn } from "../own.js";

export const MCP_CHANGED = "FW-MCP-CHANGED";

export type LaunchPin = "stable" | "floating" | "not_a_package" | "remote" | "unknown";

export interface McpPin {
  /** `${source}:${name}`. */
  key: string;
  name: string;
  source: string;
  /** sha256 of the canonical configuration; null while the server has only been seen in tool calls. */
  configHash: string | null;
  /** Where it was configured, for messages. */
  file?: string;
  launch: { pin: LaunchPin };
  tools: string[];
  /** Tool name -> sha256 of its canonical { description, inputSchema }, as last observed and accepted. */
  descriptions: Record<string, string>;
  pinnedAt: string;
  pinnedBy: "first-use" | "person";
  /** Tool name -> sha256 of its canonical full definition (name, title, description, schemas, annotations), from tools/list. */
  gatewayDefs?: Record<string, string>;
  /** The server's self-reported version (server/discover or initialize), as last accepted. */
  serverVersion?: string;
  /** Who has seen this server: a hook (tool calls, ToolSearch) and/or the gateway (tools/list). */
  seenBy?: ("hook" | "gateway")[];
  /**
   * 2: configHash covers non-secret environment values, the working directory and the local entry
   * script (I11). A pin without it was made with the older hash and is upgraded silently when that
   * older hash still matches.
   */
  hashVersion?: 2;
}

/** configHash of a server whose pin could not be confirmed (the pins file was unreadable): it never matches. */
export const UNVERIFIED_HASH = "unverified";

export type PendingKind = "config" | "new_tool" | "description" | "annotations" | "server_version";
const PENDING_KINDS: readonly string[] = ["config", "new_tool", "description", "annotations", "server_version"];

export interface PendingChange {
  id: string;
  key: string;
  name: string;
  kind: PendingKind;
  /** The tool, for new_tool and description changes. */
  tool?: string;
  /** The value accepting it pins: the new configuration hash, or the new description hash. */
  to?: string;
  /** The new full-definition hash (gatewayDefs) accepting it pins. */
  toV2?: string;
  /** (V22) The gateway saw this tool in the server's tools/list (a hook-style new tool it lets the hook decide). */
  listed?: boolean;
  /** The definition behind this change carries a finding (hidden text, an instruction): hides under every policy. */
  finding?: boolean;
  launch?: LaunchPin;
  detail: string;
  firstSeen: string;
  lastSeen: string;
}

export interface PinFile {
  version: 1;
  servers: Record<string, McpPin>;
  pending: PendingChange[];
  /**
   * When an unreadable pins file was moved aside and this one started empty. Until a person accepts
   * the servers, a server with no confirmed pin is a change waiting for review, never a first use.
   */
  recovered?: string;
}

export function pinsPath(l: Layout): string {
  return join(l.home, "pins", "mcp.json");
}

function emptyPins(): PinFile {
  return { version: 1, servers: {}, pending: [] };
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStrList = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");

/** Validates a pins file; null when anything is malformed. */
export function parsePins(text: string): PinFile | null {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isObj(v) || v.version !== 1 || !isObj(v.servers) || !Array.isArray(v.pending)) return null;
  if (v.recovered !== undefined && typeof v.recovered !== "string") return null;
  for (const [k, p] of Object.entries(v.servers)) {
    if (!isObj(p) || p.key !== k || typeof p.name !== "string" || typeof p.source !== "string") return null;
    if (!(p.configHash === null || typeof p.configHash === "string") || !isStrList(p.tools) || !isObj(p.descriptions) || !isObj(p.launch)) return null;
    if (typeof p.pinnedAt !== "string" || (p.pinnedBy !== "first-use" && p.pinnedBy !== "person")) return null;
    if (!Object.values(p.descriptions).every((x) => typeof x === "string")) return null;
    if (p.gatewayDefs !== undefined && !(isObj(p.gatewayDefs) && Object.values(p.gatewayDefs).every((x) => typeof x === "string"))) return null;
    if (p.serverVersion !== undefined && typeof p.serverVersion !== "string") return null;
    if (p.seenBy !== undefined && !(isStrList(p.seenBy) && p.seenBy.every((x) => x === "hook" || x === "gateway"))) return null;
    if (p.hashVersion !== undefined && p.hashVersion !== 2) return null;
  }
  for (const c of v.pending) {
    if (!isObj(c) || typeof c.id !== "string" || typeof c.key !== "string" || typeof c.name !== "string" || typeof c.detail !== "string") return null;
    if (typeof c.kind !== "string" || !PENDING_KINDS.includes(c.kind)) return null;
    if (c.toV2 !== undefined && typeof c.toV2 !== "string") return null;
    if (c.listed !== undefined && typeof c.listed !== "boolean") return null;
    if (c.finding !== undefined && typeof c.finding !== "boolean") return null;
    // A record written before the flag existed: its wording was the only mark of a finding, so keep it hiding.
    if (c.finding === undefined && typeof c.detail === "string" && / carries /.test(c.detail)) c.finding = true;
    if (typeof c.firstSeen !== "string" || typeof c.lastSeen !== "string") return null;
  }
  return v as unknown as PinFile;
}

export interface LoadedPins {
  pins: PinFile;
  /** Set when the file existed but was unreadable; it has been moved aside to this path. */
  corrupt: string | null;
}

/** Reads the pins file. A corrupt one is moved aside (doctor shows it) and replaced by an empty one. */
export function loadPins(l: Layout, now = new Date()): LoadedPins {
  const p = pinsPath(l);
  const text = tryReadText(p);
  if (text === null) return { pins: emptyPins(), corrupt: null };
  // FZ7: a directory or a symlink loop in its place is a corrupt pins file: moved aside, every server unpinned.
  const parsed = typeof text === "string" ? parsePins(text) : null;
  if (parsed !== null) return { pins: parsed, corrupt: null };
  const aside = `${p}.corrupt-${now.toISOString().replace(/[:.]/g, "-")}`;
  try {
    renameSync(p, aside);
  } catch {
    // Another hook moved it first.
  }
  return { pins: emptyPins(), corrupt: aside };
}

/** Read-modify-write under the pins lock. `fn` returns whether it changed anything. */
export function updatePins<T>(l: Layout, now: Date, fn: (pins: PinFile, corrupt: string | null) => { changed: boolean; result: T }): T {
  const p = pinsPath(l);
  return withLock(`${p}.lock`, () => {
    const { pins, corrupt } = loadPins(l, now);
    // I6: whoever finds the file unreadable marks the new one as recovered, so no server's pin is confirmed by default.
    if (corrupt !== null) pins.recovered ??= now.toISOString();
    const { changed, result } = fn(pins, corrupt);
    if (changed || corrupt !== null) atomicWrite(p, `${JSON.stringify(pins, null, 2)}\n`);
    return result;
  });
}

// --- configuration ----------------------------------------------------------------------------------

const strOf = (v: unknown): string | null => (typeof v === "string" ? v : null);
const keysOf = (v: unknown): string[] => (isObj(v) ? Object.keys(v).sort() : []);

/** The firewall's own CLI as an MCP launch command: `launchsafe-firewall` on PATH, or the installed cli.js (directly or through node). */
function firewallLaunch(command: string | null, args: readonly string[], cli: string): number {
  if (command === null) return -1;
  if (command === "launchsafe-firewall" || command === cli) return 0;
  if (/^node(?:js)?$/.test(basename(command)) && args[0] === cli) return 1;
  return -1;
}

/**
 * A server launched through the firewall's own CLI as a wrapper (`launchsafe-firewall <sub> -- <server>`):
 * what it wraps, which is what pins compare, so wrapping a server is not a change of it. A firewall
 * launch with nothing after `--` is the firewall itself (ignored by pins: null). Anything else as it is.
 * Only the exact firewall command counts (bare on PATH, or this installation's cli.js), never a name
 * that merely contains it.
 */
export function unwrapFirewall(config: Record<string, unknown>, cli = join(installDir(), "dist", "cli.js")): Record<string, unknown> | null {
  const command = strOf(config.command);
  const args = isStrList(config.args) ? config.args : [];
  const at = firewallLaunch(command, args, cli);
  if (at === -1) return config;
  const sep = args.indexOf("--", at);
  if (sep === -1 || args[sep + 1] === undefined) return null;
  const out: Record<string, unknown> = { ...config, command: args[sep + 1], args: args.slice(sep + 2) };
  // LG4: the wrapper's empty NODE_COMPILE_CACHE is the gateway's, and a value the entry set is kept under
  // LAUNCHSAFE_FIREWALL_UPSTREAM_NODE_COMPILE_CACHE for the server: put back, so wrapping is still not a change.
  const env = config.env;
  if (typeof env === "object" && env !== null && !Array.isArray(env)) {
    const e = env as Record<string, unknown>;
    const back: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(e)) if (k !== "LAUNCHSAFE_FIREWALL_UPSTREAM_NODE_COMPILE_CACHE" && !(k === "NODE_COMPILE_CACHE" && v === "")) Object.defineProperty(back, k, { value: v, enumerable: true, writable: true, configurable: true });
    if (Object.hasOwn(e, "LAUNCHSAFE_FIREWALL_UPSTREAM_NODE_COMPILE_CACHE")) back.NODE_COMPILE_CACHE = e.LAUNCHSAFE_FIREWALL_UPSTREAM_NODE_COMPILE_CACHE;
    if (Object.keys(back).length === 0) delete out.env;
    else out.env = back;
  }
  return out;
}

/** The part of a server's configuration that decides what runs or what is reached (secret values left out). */
export function canonicalConfig(raw: Record<string, unknown>): JsonValue {
  const config = unwrapFirewall(raw) ?? raw;
  const args = isStrList(config.args) ? config.args : Array.isArray(config.args) ? config.args.map((a) => String(a)) : [];
  return {
    type: strOf(config.type) ?? strOf(config.transport),
    command: strOf(config.command),
    args,
    url: strOf(config.url) ?? strOf(config.serverUrl) ?? strOf(config.httpUrl),
    envKeys: keysOf(config.env),
    headerKeys: keysOf(config.headers),
  };
}

/** The configuration hash pins made before hashVersion 2 recorded (command, arguments, URL, variable names). */
export function legacyConfigHash(config: Record<string, unknown>): string {
  return createHash("sha256").update(canonicalJson(canonicalConfig(config))).digest("hex");
}

const shortHash = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, 32);

/**
 * I11: what decides what runs, beyond the command line: the working directory, each non-secret
 * environment value (hashed; a credential's value is left out so rotating it is not a change), and
 * the local entry script's content (`entry`, from entryScriptHash).
 */
export function canonicalConfigV2(raw: Record<string, unknown>, entry: string | null = null): JsonValue {
  const config = unwrapFirewall(raw) ?? raw;
  const env = isObj(config.env) ? config.env : {};
  const values: Record<string, JsonValue> = {};
  for (const k of Object.keys(env).sort()) {
    const v = own(env, k);
    if (isCredentialName(k)) continue;
    Object.defineProperty(values, k, { value: typeof v === "string" ? shortHash(v) : shortHash(JSON.stringify(v) ?? ""), enumerable: true, writable: true, configurable: true });
  }
  return { v: 2, base: canonicalConfig(raw), cwd: strOf(config.cwd), envValues: values, entry };
}

/** The pin's configuration hash (hashVersion 2). `entry` is the local entry script's hash, when there is one. */
export function configHash(config: Record<string, unknown>, entry: string | null = null): string {
  return createHash("sha256").update(canonicalJson(canonicalConfigV2(config, entry))).digest("hex");
}

const ENTRY_SCRIPT = /\.(?:m?[jt]s|c[jt]s|py|sh|bash|zsh|rb|pl|php|lua|ps1)$/i;
const MAX_ENTRY_BYTES = 4 * 1024 * 1024;

/**
 * I11: the SHA-256 of the local scripts a server runs (`node ./server.js`, `python tools/mcp.py`, a
 * command that is itself a file in the project), so editing the server's code is a change to its pin
 * like editing its command. Null when it runs no local file (a package runner, a binary on PATH) or
 * the server has no base folder.
 */
export function entryScriptHash(s: Pick<ConfiguredServer, "config" | "base">): string | null {
  if (s.base === undefined) return null;
  const config = unwrapFirewall(s.config) ?? s.config;
  const cwdRaw = strOf(config.cwd);
  const cwd = cwdRaw === null ? s.base : resolve(s.base, cwdRaw);
  const words = [strOf(config.command) ?? "", ...(isStrList(config.args) ? config.args : [])].filter((w) => w !== "" && !w.startsWith("-"));
  const h = createHash("sha256");
  let found = 0;
  for (const w of words.slice(0, 20)) {
    if (!ENTRY_SCRIPT.test(w) && !w.includes("/") && !w.includes(sep)) continue;
    if (/^[a-z][a-z0-9+.-]*:/i.test(w) || w.startsWith("@")) continue;
    const abs = isAbsolute(w) ? w : resolve(cwd, w);
    try {
      const real = realpathSync(abs);
      const st = statSync(real);
      if (!st.isFile() || st.size > MAX_ENTRY_BYTES) continue;
      h.update(`${w}\u0000`).update(readFileSync(real)).update("\n");
      found++;
    } catch {
      // Not a local file.
    }
    if (found >= 5) break;
  }
  return found === 0 ? null : h.digest("hex");
}

/** A configured server's current hash (hashVersion 2, with its entry script). */
export function serverHash(s: ConfiguredServer): string {
  return configHash(s.config, entryScriptHash(s));
}

export function launchPin(config: Record<string, unknown>): LaunchPin {
  const c = canonicalConfig(config) as { command: string | null; args: string[]; url: string | null };
  if (c.url !== null && c.command === null) return "remote";
  if (c.command === null) return "unknown";
  return pinStability([c.command, ...c.args].join(" ")).stability;
}

function describeConfig(config: Record<string, unknown>): string {
  const c = canonicalConfig(config) as { command: string | null; args: string[]; url: string | null };
  const s = c.url ?? [c.command ?? "", ...c.args].join(" ").trim();
  return s.length > 120 ? `${s.slice(0, 119)}…` : s;
}

// --- pending changes --------------------------------------------------------------------------------

function newId(): string {
  return `p-${randomBytes(4).toString("hex")}`;
}

/** Whether a pending change records a finding (hidden text, an instruction): the stricter of two wins. */
const carriesFinding = (c: { finding?: boolean }): boolean => c.finding === true;

/**
 * Records a pending change, or merges it into the one already pending for the same server, kind and tool.
 * The stricter state wins (V22): a record without a definition (a hook's, from a tool call or ToolSearch)
 * never replaces what the gateway saw in a tool list (its definition hashes and detail), a detail naming a
 * finding is never replaced by one that names none, and "listed" once set stays set.
 */
export function upsertPending(pins: PinFile, c: Omit<PendingChange, "id" | "firstSeen" | "lastSeen">, now: string): PendingChange {
  const existing = pins.pending.find((p) => p.key === c.key && p.kind === c.kind && p.tool === c.tool);
  if (existing !== undefined) {
    const weaker = existing.toV2 !== undefined && c.toV2 === undefined;
    const newDefinition = (c.toV2 !== undefined && c.toV2 !== existing.toV2) || (c.to !== undefined && c.to !== existing.to);
    const keepDetail = weaker || (carriesFinding(existing) && !carriesFinding(c) && !newDefinition);
    if (!keepDetail || (carriesFinding(c) && !carriesFinding(existing))) {
      existing.detail = c.detail;
      if (carriesFinding(c)) existing.finding = true;
      else delete existing.finding;
    }
    if (!weaker && c.to !== undefined) existing.to = c.to;
    if (c.toV2 !== undefined) existing.toV2 = c.toV2;
    if (c.listed === true) existing.listed = true;
    if (c.launch !== undefined) existing.launch = c.launch;
    existing.lastSeen = now;
    return existing;
  }
  const p: PendingChange = { id: newId(), ...c, firstSeen: now, lastSeen: now };
  pins.pending.push(p);
  return p;
}

export function dropPending(pins: PinFile, key: string, kind: PendingKind, tool?: string): boolean {
  const before = pins.pending.length;
  pins.pending = pins.pending.filter((p) => !(p.key === key && p.kind === kind && p.tool === tool));
  return pins.pending.length !== before;
}

export const day = (iso: string): string => iso.slice(0, 10);

export interface PinOutcome {
  events: StateEvent[];
  /** Sentences for the person and the agent. */
  alerts: string[];
  /** Log entries (type mcp_pin). */
  log: Record<string, unknown>[];
}

function emptyOutcome(): PinOutcome {
  return { events: [], alerts: [], log: [] };
}

// --- session start ----------------------------------------------------------------------------------

/** A configured server's pin source: Claude Code's as it is; another agent's under that agent (`codex-user`). */
export function pinSourceOf(s: ConfiguredServer): string {
  return s.agent === undefined ? s.source : `${s.agent}-${s.source}`;
}

export function pinKeyOf(s: ConfiguredServer): string {
  return `${pinSourceOf(s)}:${s.name}`;
}

export interface StartPinOptions {
  /**
   * Servers this session does not load (another agent's): a change is still recorded as pending and
   * logged, so that agent's next session reports it, but this session is neither told nor tainted.
   */
  quiet?: (s: ConfiguredServer) => boolean;
}

/**
 * Compares every configured server with its pin. Unknown servers are pinned at first use (no alert);
 * a server whose configuration differs from its pin taints the session until a person accepts it;
 * unreviewed description changes of a configured server taint too (the agent loads descriptions into
 * every session).
 */
export function sessionStartPins(l: Layout, all: readonly ConfiguredServer[], cfg: FirewallConfig, now: Date, o: StartPinOptions = {}): PinOutcome {
  const out = emptyOutcome();
  if (!cfg.mcpPinning.enabled) return out;
  const ts = now.toISOString();
  // The firewall's own launch (an MCP server that is the firewall itself) is not pinned.
  const servers = all.filter((s) => unwrapFirewall(s.config) !== null);
  const hashes = new Map(servers.map((s) => [s, serverHash(s)] as const));
  // Fast path (no lock, no write): every server pinned, unchanged, nothing pending for it.
  const { pins: snap, corrupt: bad } = loadPins(l, now);
  if (bad === null && servers.every((s) => own(snap.servers, pinKeyOf(s))?.configHash === hashes.get(s)) && !snap.pending.some((p) => servers.some((s) => p.key === pinKeyOf(s)))) return out;
  const corruptAlert = (moved: string): void => {
    out.alerts.push(`The MCP pins file was unreadable; it was moved to ${moved}. No server could be compared with what you approved, so every configured server waits for your review: run "launchsafe-firewall pins" and, for each one you recognise, "launchsafe-firewall pins accept <server>" in your own terminal. Run "launchsafe-firewall doctor".`);
    out.events.push({ type: "taint", source: `${MCP_CHANGED}: the MCP pins file was unreadable, so no server could be compared with its pin` });
    out.log.push({ type: "mcp_pin", change: "corrupt", moved });
  };
  // loadPins moved the corrupt file aside; the locked pass below records every server as waiting for review.
  if (bad !== null) corruptAlert(bad);
  return updatePins(l, now, (pins, corrupt) => {
    let changed = false;
    if (corrupt !== null) corruptAlert(corrupt);
    if (bad !== null || corrupt !== null) {
      pins.recovered ??= ts;
      changed = true;
    }
    const recovering = pins.recovered !== undefined;
    for (const s of servers) {
      const key = pinKeyOf(s);
      const hash = hashes.get(s) ?? serverHash(s);
      let pin = own(pins.servers, key);
      const quiet = o.quiet?.(s) === true;
      // After an unreadable pins file, no server has a pin a person confirmed: each one is a change to review (I6).
      if (recovering && (pin === undefined || pin.configHash === null)) {
        if (pin === undefined) {
          pin = { key, name: s.name, source: pinSourceOf(s), configHash: UNVERIFIED_HASH, file: s.file, launch: { pin: launchPin(s.config) }, tools: [], descriptions: {}, pinnedAt: ts, pinnedBy: "first-use", hashVersion: 2 };
          setOwn(pins.servers, key, pin);
        } else pin.configHash = UNVERIFIED_HASH;
        changed = true;
      }
      if (pin === undefined) {
        setOwn(pins.servers, key, { key, name: s.name, source: pinSourceOf(s), configHash: hash, file: s.file, launch: { pin: launchPin(s.config) }, tools: [], descriptions: {}, pinnedAt: ts, pinnedBy: "first-use", hashVersion: 2 });
        out.log.push({ type: "mcp_pin", change: "pinned", server: key, by: "first-use" });
        changed = true;
        // I11: a server the repository itself configures, seen for the first time, is a decision for a person.
        if (s.source === "project" && !quiet) {
          out.alerts.push(`The repository configures an MCP server you have not used before: "${s.name}" (${s.file}) runs ${describeConfig(s.config)}. This session is untrusted until you have looked at it; it is pinned now, so the next session is not.`);
          if (cfg.mcpPinning.taintOnChange) out.events.push({ type: "taint", source: `${MCP_CHANGED}: the repository's MCP server ${s.name} is new (first seen this session)` });
          out.log.push({ type: "mcp_pin", change: "first_seen_project", server: key });
        }
        continue;
      }
      if (pin.configHash === null) {
        pin.configHash = hash;
        pin.hashVersion = 2;
        pin.file = s.file;
        pin.launch = { pin: launchPin(s.config) };
        changed = true;
        continue;
      }
      // A pin made with the older hash: upgraded silently when the older hash still matches (nothing changed).
      if (pin.hashVersion !== 2 && pin.configHash !== hash && pin.configHash === legacyConfigHash(s.config)) {
        pin.configHash = hash;
        pin.hashVersion = 2;
        changed = true;
      }
      if (pin.configHash !== hash) {
        const detail =
          pin.configHash === UNVERIFIED_HASH
            ? `MCP server "${s.name}" (${s.file}) could not be compared with what you approved, because the pins file was unreadable on ${day(pins.recovered ?? pin.pinnedAt)}: it now runs ${describeConfig(s.config)}`
            : `MCP server "${s.name}" (${s.file}) changed its command, arguments, URL, settings or local script since it was pinned on ${day(pin.pinnedAt)}: it now runs ${describeConfig(s.config)}`;
        upsertPending(pins, { key, name: s.name, kind: "config", to: hash, launch: launchPin(s.config), detail }, ts);
        changed = true;
        out.log.push({ type: "mcp_pin", change: "config", server: key });
        if (quiet) continue;
        out.alerts.push(`${detail}. Until you review it, the session is untrusted and this server's results count as outside content. If you made this change, run in your own terminal: launchsafe-firewall pins accept ${s.name}`);
        if (cfg.mcpPinning.taintOnChange) out.events.push({ type: "taint", source: `${MCP_CHANGED}: MCP server ${s.name} changed its command/URL since ${day(pin.pinnedAt)}` });
      } else if (dropPending(pins, key, "config")) changed = true;
      if (quiet) continue;
      for (const p of pins.pending.filter((x) => x.key === key && x.kind === "description")) {
        out.alerts.push(`${p.detail}. Review it, then run in your own terminal: launchsafe-firewall pins accept ${s.name}`);
        if (cfg.mcpPinning.taintOnChange) out.events.push({ type: "taint", source: `${MCP_CHANGED}: the description of ${p.tool ?? "a tool"} on MCP server ${s.name} changed and is not reviewed` });
      }
    }
    return { changed, result: out };
  });
}

// --- tool calls -------------------------------------------------------------------------------------

export interface ToolCallPin extends PinOutcome {
  /** Treat this call's results as outside content whatever the policy says (changed server, unreviewed tool). */
  forceUntrusted: boolean;
  /** FW-MCP-CHANGED when this call involved a change. */
  rule: string | null;
  reason: string | null;
}

function findPin(pins: PinFile, server: string, source: string | undefined): McpPin | undefined {
  if (source !== undefined && source !== "unknown") {
    const exact = pins.servers[`${source}:${server}`];
    if (exact !== undefined) return exact;
  }
  const all = Object.values(pins.servers).filter((p) => p.name === server);
  // Another agent's call (source `codex-user`, `cursor-unknown`): that agent's pins first.
  const agent = /^(codex|gemini|cursor)-/.exec(source ?? "")?.[1];
  const mine = agent !== undefined ? all.filter((p) => p.source.startsWith(`${agent}-`)) : all.filter((p) => !/^(?:codex|gemini|cursor)-/.test(p.source));
  const byName = mine.length > 0 ? mine : all;
  // Several configurations of the same name: prefer one with a pending change (the stricter answer).
  return byName.find((p) => pins.pending.some((c) => c.key === p.key)) ?? byName[0];
}

/**
 * "Fewer prompts": what an MCP tool currently is, as a hash of its server's pin (key, configuration, launch,
 * the tool's observed description and full definition, the server's version), or null when there is no
 * current pin to bind to: no pin, a change waiting for review, the tool not pinned, or an unreadable file.
 * Reads only (an unreadable file is left for the hook's own pin check to move aside).
 */
export function mcpToolIdentity(l: Layout, server: string, tool: string, source: string | undefined): string | null {
  const text = tryReadText(pinsPath(l));
  if (typeof text !== "string") return null;
  const pins = parsePins(text);
  if (pins === null) return null;
  const pin = findPin(pins, server, source);
  if (pin === undefined || !pin.tools.includes(tool) || pins.pending.some((c) => c.key === pin.key)) return null;
  const defs = pin.gatewayDefs;
  return createHash("sha256").update(JSON.stringify(["mcp-pin/v1", pin.key, pin.configHash, pin.launch.pin, own(pin.descriptions, tool) ?? null, defs !== undefined ? (own(defs, tool) ?? null) : null, pin.serverVersion ?? null])).digest("hex");
}

/**
 * Whether toolCallPins() forces this call's results to count as outside content, read without writing anything
 * (PostToolUse derives the override again): the server's configuration changed and is not reviewed, or the tool
 * waits for review as new, or the pins file cannot be read. Never throws (an error forces it).
 */
export function pinForcesUntrusted(l: Layout, server: string, tool: string, source: string | undefined, cfg: FirewallConfig): boolean {
  if (!cfg.mcpPinning.enabled || !cfg.mcpPinning.taintOnChange) return false;
  try {
    const text = tryReadText(pinsPath(l));
    if (text === null) return false;
    const pins = typeof text === "string" ? parsePins(text) : null;
    if (pins === null) return true;
    const pin = findPin(pins, server, source);
    if (pin === undefined) return false;
    return pins.pending.some((c) => c.key === pin.key && (c.kind === "config" || (c.kind === "new_tool" && c.tool === tool)));
  } catch {
    return true;
  }
}

export function inGrace(pin: McpPin, cfg: FirewallConfig, now: Date): boolean {
  return pin.pinnedBy === "first-use" && now.getTime() - Date.parse(pin.pinnedAt) < cfg.mcpPinning.newToolGraceHours * 3600_000;
}

/**
 * A call to mcp__<server>__<tool>. A server seen for the first time is pinned with this tool. A tool
 * the pinned server was never seen to expose, after the grace window, is unknown until a person
 * reviews it: the session is tainted and the call's results count as outside content. The call itself
 * is judged by the normal rules.
 */
export function toolCallPins(l: Layout, server: string, tool: string, source: string | undefined, cfg: FirewallConfig, now: Date): ToolCallPin {
  const out: ToolCallPin = { ...emptyOutcome(), forceUntrusted: false, rule: null, reason: null };
  if (!cfg.mcpPinning.enabled) return out;
  const ts = now.toISOString();
  // Fast path: no write needed when the server is pinned, unchanged and knows the tool.
  const { pins: snapshot, corrupt } = loadPins(l, now);
  const known = corrupt === null ? findPin(snapshot, server, source) : undefined;
  if (known !== undefined && known.tools.includes(tool) && !snapshot.pending.some((c) => c.key === known.key && c.kind === "config")) return out;
  return updatePins(l, now, (pins, corruptNow) => {
    // The snapshot read above may be the one that found the file unreadable (and moved it aside).
    const moved = corruptNow ?? corrupt;
    if (moved !== null) {
      pins.recovered ??= ts;
      out.events.push({ type: "taint", source: `${MCP_CHANGED}: the MCP pins file was unreadable` });
      out.log.push({ type: "mcp_pin", change: "corrupt", moved });
    }
    const pin = findPin(pins, server, source);
    if (pin === undefined) {
      const key = `${source ?? "unknown"}:${server}`;
      // After an unreadable pins file, a server seen in a call is not confirmed: its next session start asks (I6).
      setOwn(pins.servers, key, { key, name: server, source: source ?? "unknown", configHash: null, launch: { pin: "unknown" }, tools: [tool], descriptions: {}, pinnedAt: ts, pinnedBy: "first-use" });
      out.log.push({ type: "mcp_pin", change: "pinned", server: key, by: "first-use", tool });
      return { changed: true, result: out };
    }
    let changed = false;
    const pendingConfig = pins.pending.find((c) => c.key === pin.key && c.kind === "config");
    if (pendingConfig !== undefined && cfg.mcpPinning.taintOnChange) {
      out.forceUntrusted = true;
      out.rule = MCP_CHANGED;
      out.reason = `MCP server ${server} changed its command/URL since it was pinned on ${day(pin.pinnedAt)} and is not reviewed, so its results count as outside content`;
      out.events.push({ type: "taint", source: `${MCP_CHANGED}: MCP server ${server} changed its command/URL since ${day(pin.pinnedAt)}` });
    }
    if (!pin.tools.includes(tool)) {
      // R9: a hook never sees tools/list, so a name not called before is only "new" when something could
      // have changed the server's tools. It existed already when its definition was seen (ToolSearch), or
      // when the server's launch is pinned to an exact version whose configuration has not changed since
      // the pin (the same code exposes the same tools). Those are a first use: pinned silently, logged.
      const existed = Object.prototype.hasOwnProperty.call(pin.descriptions, tool) || (pin.launch.pin === "stable" && pin.configHash !== null && pendingConfig === undefined);
      if (inGrace(pin, cfg, now)) {
        pin.tools.push(tool);
        changed = true;
      } else if (existed) {
        pin.tools.push(tool);
        changed = true;
        out.log.push({ type: "mcp_pin", change: "first_use", server: pin.key, tool });
      } else {
        const why = pendingConfig !== undefined ? "its configuration changed and is not reviewed" : pin.launch.pin === "stable" ? "it was never seen to expose it" : "its launch is not pinned to a version, so its tools can change without a configuration change";
        const detail = `MCP server "${server}" exposes a new tool, ${tool}, not seen since it was pinned on ${day(pin.pinnedAt)} (${why})`;
        upsertPending(pins, { key: pin.key, name: server, kind: "new_tool", tool, detail }, ts);
        changed = true;
        out.log.push({ type: "mcp_pin", change: "new_tool", server: pin.key, tool });
        out.alerts.push(`${detail}. A new tool counts as unknown until you review it. If you expected it, run in your own terminal: launchsafe-firewall pins accept ${server}`);
        if (cfg.mcpPinning.taintOnChange) {
          out.forceUntrusted = true;
          out.rule = MCP_CHANGED;
          out.reason = `${tool} is a new tool on MCP server ${server} (not seen when it was pinned on ${day(pin.pinnedAt)}); it counts as unknown until a person reviews it`;
          out.events.push({ type: "taint", source: `${MCP_CHANGED}: new tool ${tool} on MCP server ${server}` });
        }
      }
    }
    return { changed: changed || moved !== null, result: out };
  });
}

// --- observed tool definitions (descriptions) -------------------------------------------------------

export interface ToolDefinition {
  server: string;
  tool: string;
  description: string;
  schema: unknown;
}

const FUNCTION_TAG = /<function>\s*(\{[\s\S]*?\})\s*<\/function>/g;
const MAX_DEFS = 500;

function defFrom(o: Record<string, unknown>): ToolDefinition | null {
  const name = strOf(o.name);
  const description = strOf(o.description);
  if (name === null || description === null || !name.startsWith("mcp__")) return null;
  const rest = name.slice(5);
  const i = rest.indexOf("__");
  if (i <= 0) return null;
  return { server: rest.slice(0, i), tool: rest.slice(i + 2), description, schema: o.input_schema ?? o.inputSchema ?? o.parameters ?? null };
}

/**
 * Tool definitions in a ToolSearch result: `<function>{"name": "mcp__s__t", "description": ...}</function>`
 * lines (the form Claude Code returns), or objects with the same fields anywhere in a JSON result. A result
 * that only references tools (no descriptions) yields nothing. [verify] against a captured fixture.
 */
export function extractToolDefinitions(response: unknown): ToolDefinition[] {
  const out: ToolDefinition[] = [];
  const seen = new Set<string>();
  const push = (d: ToolDefinition | null): void => {
    if (d === null || out.length >= MAX_DEFS) return;
    const k = `${d.server}\u0000${d.tool}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push(d);
  };
  let budget = 5000;
  const visit = (v: unknown, depth: number): void => {
    if (budget-- <= 0 || depth > 8) return;
    if (typeof v === "string") {
      if (!v.includes("mcp__")) return;
      for (const m of v.matchAll(FUNCTION_TAG)) {
        try {
          const o: unknown = JSON.parse(m[1] ?? "");
          if (isObj(o)) push(defFrom(o));
        } catch {
          // Not a definition.
        }
      }
      const t = v.trim();
      if ((t.startsWith("{") || t.startsWith("[")) && depth < 3) {
        try {
          visit(JSON.parse(t), depth + 1);
        } catch {
          // Not JSON.
        }
      }
      return;
    }
    if (Array.isArray(v)) {
      for (const x of v) visit(x, depth + 1);
      return;
    }
    if (isObj(v)) {
      push(defFrom(v));
      for (const x of Object.values(v)) visit(x, depth + 1);
    }
  };
  visit(response, 0);
  return out;
}

export function descriptionHash(d: ToolDefinition): string {
  let schema: string;
  try {
    schema = canonicalJson((d.schema ?? null) as JsonValue);
  } catch {
    schema = JSON.stringify(d.schema ?? null);
  }
  return createHash("sha256").update(`${d.description}\u0000${schema}`).digest("hex");
}

/** What agent-safety's hidden-text and instruction detectors find in a description, as short phrases. */
export function descriptionFindings(description: string): string[] {
  const found = new Set<string>();
  for (const line of description.split(/\r?\n/)) {
    const hidden = hiddenTextIn(line);
    if (hidden !== null) found.add(`hidden text (${hidden.replace(/_/g, " ")})`);
    const inj = injectionIn(line);
    if (inj !== null) found.add(`an instruction to the agent ("${revealInvisible(inj).slice(0, 60)}")`);
    const outbound = outboundInstructionIn(line);
    if (outbound !== null) found.add(`an instruction to send data out ("${revealInvisible(outbound).slice(0, 60)}")`);
  }
  return [...found];
}

/**
 * Tool definitions the firewall saw (a ToolSearch result). A description seen for the first time is
 * pinned (and checked for hidden text and instructions); one that differs from its pin taints the
 * session and is held for review; a tool the pinned server did not expose, after the grace window, is
 * unknown until reviewed.
 */
export function observeDefinitions(l: Layout, defs: readonly ToolDefinition[], cfg: FirewallConfig, now: Date): PinOutcome {
  const out = emptyOutcome();
  if (!cfg.mcpPinning.enabled || defs.length === 0) return out;
  const ts = now.toISOString();
  return updatePins(l, now, (pins, corrupt) => {
    let changed = false;
    if (corrupt !== null) {
      out.events.push({ type: "taint", source: `${MCP_CHANGED}: the MCP pins file was unreadable` });
      out.log.push({ type: "mcp_pin", change: "corrupt", moved: corrupt });
    }
    for (const d of defs) {
      let pin = findPin(pins, d.server, undefined);
      if (pin === undefined) {
        const key = `unknown:${d.server}`;
        pin = { key, name: d.server, source: "unknown", configHash: null, launch: { pin: "unknown" }, tools: [], descriptions: {}, pinnedAt: ts, pinnedBy: "first-use" };
        setOwn(pins.servers, key, pin);
        changed = true;
      }
      const hash = descriptionHash(d);
      const pinned = own(pin.descriptions, d.tool);
      if (!pin.tools.includes(d.tool)) {
        if (inGrace(pin, cfg, now)) pin.tools.push(d.tool);
        else {
          const detail = `MCP server "${d.server}" lists a new tool, ${d.tool}, that it did not have when it was pinned on ${day(pin.pinnedAt)}`;
          upsertPending(pins, { key: pin.key, name: d.server, kind: "new_tool", tool: d.tool, detail }, ts);
          out.alerts.push(`${detail}. If you expected it, run in your own terminal: launchsafe-firewall pins accept ${d.server}`);
          out.log.push({ type: "mcp_pin", change: "new_tool", server: pin.key, tool: d.tool });
        }
        changed = true;
      }
      if (pinned === undefined) {
        setOwn(pin.descriptions, d.tool, hash);
        changed = true;
        const bad = descriptionFindings(d.description);
        if (bad.length > 0) {
          out.alerts.push(`The description of ${d.tool} on MCP server "${d.server}" carries ${bad.join(" and ")}. Treat that server as hostile until you have read it.`);
          out.events.push({ type: "taint", source: `${MCP_CHANGED}: the description of ${d.tool} on MCP server ${d.server} carries ${bad[0] ?? "hidden text"}` });
          out.log.push({ type: "mcp_pin", change: "description_finding", server: pin.key, tool: d.tool, findings: bad });
        }
      } else if (pinned !== hash) {
        const bad = descriptionFindings(d.description);
        const detail = `The description of ${d.tool} on MCP server "${d.server}" changed since it was pinned on ${day(pin.pinnedAt)}${bad.length > 0 ? `, and the new text carries ${bad.join(" and ")}` : ""}`;
        upsertPending(pins, { key: pin.key, name: d.server, kind: "description", tool: d.tool, to: hash, detail, ...(bad.length > 0 ? { finding: true } : {}) }, ts);
        changed = true;
        out.log.push({ type: "mcp_pin", change: "description", server: pin.key, tool: d.tool });
        out.alerts.push(`${detail}. A changed description can carry new instructions for the agent (a "rug pull"). Review it, then run in your own terminal: launchsafe-firewall pins accept ${d.server}`);
        if (cfg.mcpPinning.taintOnChange) out.events.push({ type: "taint", source: `${MCP_CHANGED}: the description of ${d.tool} on MCP server ${d.server} changed since ${day(pin.pinnedAt)}` });
      } else if (dropPending(pins, pin.key, "description", d.tool)) changed = true;
    }
    return { changed, result: out };
  });
}

// --- the person's commands --------------------------------------------------------------------------

export interface Accepted {
  server: string;
  changes: PendingChange[];
}

/**
 * The pending changes an argument of `pins accept` names: a pin key (`user:docs`) exactly, or a server name. A name that
 * several pins share (the same server in two files, or under two agents) is refused: accepting one must not accept the others.
 */
export function pendingFor(pending: readonly PendingChange[], arg: string): PendingChange[] {
  const byKey = pending.filter((p) => p.key === arg);
  if (byKey.length > 0) return byKey;
  const byName = pending.filter((p) => p.name === arg);
  const keys = [...new Set(byName.map((p) => p.key))];
  if (keys.length > 1) throw new Error(`${keys.length} pinned MCP servers are named "${arg}" and each has changes waiting; name the one you reviewed: ${keys.map((k) => `launchsafe-firewall pins accept ${k}`).join("  or  ")}`);
  return byName;
}

/** Applies every pending change for the named servers (a person ran `pins accept`). A name or a pin key; see pendingFor. */
export function acceptPins(l: Layout, names: readonly string[], now = new Date()): Accepted[] {
  const ts = now.toISOString();
  return updatePins(l, now, (pins) => {
    const out: Accepted[] = [];
    // Resolved before anything is applied, so an ambiguous name leaves every pin as it was.
    const chosen = names.map((name) => ({ name, mine: pendingFor(pins.pending, name) }));
    for (const { name, mine } of chosen) {
      for (const p of mine) {
        const pin = own(pins.servers, p.key);
        if (pin === undefined) continue;
        if (p.kind === "config" && p.to !== undefined) {
          pin.configHash = p.to;
          pin.hashVersion = 2;
          if (p.launch !== undefined) pin.launch = { pin: p.launch };
        }
        if (p.kind === "new_tool" && p.tool !== undefined && !pin.tools.includes(p.tool)) pin.tools.push(p.tool);
        if ((p.kind === "description" || p.kind === "new_tool") && p.tool !== undefined && p.to !== undefined) setOwn(pin.descriptions, p.tool, p.to);
        // The gateway's full-definition hash and the server's version.
        if ((p.kind === "description" || p.kind === "new_tool" || p.kind === "annotations") && p.tool !== undefined && p.toV2 !== undefined) pin.gatewayDefs = { ...(pin.gatewayDefs ?? {}), [p.tool]: p.toV2 };
        if (p.kind === "server_version" && p.to !== undefined) pin.serverVersion = p.to;
        pin.pinnedAt = ts;
        pin.pinnedBy = "person";
      }
      pins.pending = pins.pending.filter((p) => !mine.includes(p));
      out.push({ server: name, changes: mine });
    }
    // Recovery ends once a person has reviewed every server that was waiting.
    const cleared = pins.recovered !== undefined && pins.pending.length === 0 && !Object.values(pins.servers).some((p) => p.configHash === UNVERIFIED_HASH);
    if (cleared) delete pins.recovered;
    return { changed: cleared || out.some((a) => a.changes.length > 0), result: out };
  });
}
