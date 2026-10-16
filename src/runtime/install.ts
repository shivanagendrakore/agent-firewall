/**
 * Registers the firewall's hooks in Claude Code settings: idempotent, first
 * in order, wrapped to fail closed, with a backup of every file it changes
 * and a record so uninstall removes exactly what install added.
 */

import { createHash } from "node:crypto";
import { existsSync, lstatSync, readdirSync, renameSync, rmSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { stripBom } from "../bom.js";
import { jsonValueOf, parseJsoncResult } from "../vendor/agent-safety/index.js";
import { assertRestorableTarget, atomicWrite, parseJsonFile, readText, readTextExact, withLock, writeTarget, writeUserFile } from "./fsutil.js";
import { installDir, type Layout } from "./layout.js";
import { assertSupportedPlatform } from "./platform.js";
import { approverPublicKey } from "./approver.js";
import { phonesPinOf } from "./relay/phones.js";
import { assertNotRealHome, testMarker } from "./guard.js";
import { sandboxRegistrationProblems } from "./sandbox.js";
import { trustedHome } from "./home-trust.js";
import type { AdapterSettings, AgentId } from "../adapters/types.js";

export type Scope = "user" | "project" | "local";

import { HOOK_EVENTS, isFailClosed, LOUD_FAIL_CLOSED, MARKER } from "../engine/settings.js";
import { own, setOwn } from "../own.js";
export { HOOK_EVENTS, MARKER };

export const MANAGED_SETTINGS_PATHS: Record<string, string> = {
  darwin: "/Library/Application Support/ClaudeCode/managed-settings.json",
  linux: "/etc/claude-code/managed-settings.json",
};

export function settingsPath(scope: Scope, projectDir: string, home = homedir()): string {
  if (scope === "user") return join(home, ".claude", "settings.json");
  if (scope === "project") return join(resolve(projectDir), ".claude", "settings.json");
  return join(resolve(projectDir), ".claude", "settings.local.json");
}

function shq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** The assignment in the hook command that turns off a compile cache chosen by the environment (SR3). */
export const CLEAR_COMPILE_CACHE = "NODE_COMPILE_CACHE= ";

/**
 * I1: the other variables that make node (or the loader under it) run code before the firewall's own, set empty for
 * the hook's node like NODE_COMPILE_CACHE: an agent's settings `env` reaches every command it starts.
 */
export const CLEAR_LOADER_ENV = "NODE_OPTIONS= NODE_PATH= LD_PRELOAD= DYLD_INSERT_LIBRARIES= ";

/** What a hook command pins besides the keys: the user's home (installs into a settings file), or nothing per user (managed). */
export interface HookCommandPins {
  /** The home pinned as HOME (default: the user database's, src/runtime/home-trust.ts). */
  home?: string;
  /**
   * A managed deployment serves every user of the machine, so no one user's home is pinned: HOME is checked against
   * the user database at run time, and the default data directory is pinned empty (the hook then derives it from that
   * home, never from the environment).
   */
  managed?: boolean;
  /** Tests: the environment install runs in (default process.env), for the test markers it pins. */
  env?: NodeJS.ProcessEnv;
}

/** The shell command the agent runs. `|| exit 2` makes a crash of node itself block the action (every supported agent blocks on exit 2). */
export function hookCommand(l: Layout, nodePath = process.execPath, cli = join(installDir(), "dist", "cli.js"), agent: AgentId = "claude", pins: HookCommandPins = {}): string {
  // I1: the data directory and the home are pinned in the command itself (prefix assignments win over any
  // environment the agent passes), so a settings file's `env` cannot point the hook at other state or settings.
  const defaultHome = l.home === join(homedir(), ".launchsafe-firewall");
  const home = pins.managed === true && defaultHome ? "LAUNCHSAFE_FIREWALL_HOME='' " : `LAUNCHSAFE_FIREWALL_HOME=${shq(l.home)} `;
  const userHome = pins.managed === true ? "" : `HOME=${shq(pins.home ?? trustedHome().home)} `;
  // M7: the test markers change what the firewall allows (src/runtime/guard.ts, home-trust.ts); a repository's
  // settings env must not set them for the hook, so the command pins them as install found them (cleared outside tests).
  const markers = testMarker(pins.env ?? process.env) ? "LAUNCHSAFE_FIREWALL_TEST='1' VITEST= " : "LAUNCHSAFE_FIREWALL_TEST= VITEST= ";
  // Pin the approver public key in the command itself: approvals must be signed with it, and the agent
  // cannot change this settings file (nor, under managed settings, write it at all).
  let approver = "";
  try {
    const pub = approverPublicKey(l);
    if (pub !== null) approver = `LAUNCHSAFE_FIREWALL_APPROVER=${shq(pub)} `;
  } catch {
    // A corrupt approver file: install without a pin; doctor reports it.
  }
  // Cursor: no shell wrapper. Its hook entries say failClosed: true (a crash, a non-zero exit, a timeout
  // or no output blocks), and its legacy payload transport appends a heredoc to the command, which must
  // reach node itself, not an `|| { ...; }` group after it (read from cursor-agent 2026.10.01).
  // Item P: the paired phones' list is pinned the same way (phone approvals verify against it).
  let phones = "";
  try {
    const pin = phonesPinOf(l);
    if (pin !== null) phones = `LAUNCHSAFE_FIREWALL_PHONES=${shq(pin)} `;
  } catch {
    // Unreadable: no pin, so phone approvals are refused; doctor reports it.
  }
  const tail = agent === "claude" ? " || exit 2" : agent === "cursor" ? " --agent cursor" : ` --agent ${agent} ${LOUD_FAIL_CLOSED}`;
  // SR3: NODE_COMPILE_CACHE set in the agent's environment (a settings file's `env`, say) would make node load
  // and write compiled code in a directory the agent can write, before cli.ts chooses the firewall's own
  // cache; set empty, node ignores it.
  return `${MARKER} ${home}${approver}${phones}${userHome}${markers}${CLEAR_COMPILE_CACHE}${CLEAR_LOADER_ENV}${shq(nodePath)} ${shq(cli)} hook${tail}`;
}

/** Item P: the phones pin in an installed hook command, if any. */
export function pinnedPhonesOf(command: string): string | null {
  return /LAUNCHSAFE_FIREWALL_PHONES='(sha256:[0-9a-f]{64})'/.exec(command)?.[1] ?? null;
}

/**
 * Item P: `command` with the phones pin set (or, with null, removed), placed after the approver pin.
 * Everything else in the command is kept exactly.
 */
export function withPhonesPin(command: string, pin: string | null): string {
  const bare = command.replace(/LAUNCHSAFE_FIREWALL_PHONES='[^']*' /, "");
  if (pin === null) return bare;
  const head = /^LAUNCHSAFE_FIREWALL_HOOK=1 (?:LAUNCHSAFE_FIREWALL_HOME='(?:[^']|'\\'')*' )?(?:LAUNCHSAFE_FIREWALL_APPROVER='[A-Za-z0-9+/=]*' )?/.exec(bare);
  if (head === null) return command;
  return `${head[0]}LAUNCHSAFE_FIREWALL_PHONES=${shq(pin)} ${bare.slice(head[0].length)}`;
}

/** The approver key pinned in an installed hook command, if any. */
export function pinnedApprover(command: string): string | null {
  return /LAUNCHSAFE_FIREWALL_APPROVER='([A-Za-z0-9+/=]+)'/.exec(command)?.[1] ?? null;
}

/**
 * G5: `command` with the approver key pinned (or, with null, unpinned). Everything else in the command
 * (the data directory, the node path, the CLI path, the fail-closed wrapper) is kept exactly.
 */
export function withApproverPin(command: string, pub: string | null): string {
  const bare = command.replace(/LAUNCHSAFE_FIREWALL_APPROVER='[A-Za-z0-9+/=]*' /, "");
  if (pub === null) return bare;
  const head = /^LAUNCHSAFE_FIREWALL_HOOK=1 (?:LAUNCHSAFE_FIREWALL_HOME='(?:[^']|'\\'')*' )?/.exec(bare);
  if (head === null) return command;
  return `${head[0]}LAUNCHSAFE_FIREWALL_APPROVER=${shq(pub)} ${bare.slice(head[0].length)}`;
}

type Json = Record<string, unknown>;

interface HookGroup {
  matcher?: string;
  hooks: { type: string; command?: string; timeout?: number }[];
}

/** Claude Code's settings: where the hooks go and how they are written (the Claude adapter uses this). */
export const CLAUDE_SETTINGS: AdapterSettings = {
  label: "Claude Code",
  scopes: ["user", "project", "local"],
  path: (scope, projectDir, home) => settingsPath(scope, projectDir, home),
  events: HOOK_EVENTS,
  matched: new Set(["PreToolUse", "PostToolUse", "PostToolUseFailure"]),
  matchAll: "*",
  // B: Claude Code's own default (600 s). The firewall denies first at its internal deadline (src/hook/deadline.ts),
  // so a slow decision is a deny the hook writes, never a timeout the agent treats as a failure.
  timeout: 600,
  // A: Claude Code lets an action proceed when a hook fails or times out (the process is killed, so `|| exit 2` never
  // runs). `onFailure: "block"` (Claude Code 2.1.295 and later) makes that a block; doctor warns on older versions.
  entryExtras: { onFailure: "block" },
  disabledBy: (s) => (s.disableAllHooks === true ? ["disableAllHooks is true"] : []),
  managedPaths: MANAGED_SETTINGS_PATHS,
  managedSnippet: (command, lock) => ({ path: MANAGED_SETTINGS_PATHS[process.platform] ?? "", format: "json", text: JSON.stringify(managedSettingsSnippet(command, lock), null, 2) }),
};

/** A group (Claude Code's shape) holding the firewall's entry, or the firewall's own flat entry (Cursor's shape). */
function isOurs(g: unknown): boolean {
  if (typeof g !== "object" || g === null) return false;
  const hooks = (g as HookGroup).hooks;
  if (Array.isArray(hooks)) return hooks.some((h) => typeof h?.command === "string" && h.command.includes(MARKER));
  const c = (g as { command?: unknown }).command;
  return typeof c === "string" && c.includes(MARKER);
}

/** The firewall's entries in a group, or the flat entry itself. */
function ourEntries(g: unknown): { command?: string; [k: string]: unknown }[] {
  if (!isOurs(g)) return [];
  const hooks = (g as HookGroup).hooks;
  const list: unknown[] = Array.isArray(hooks) ? hooks : [g];
  return list.filter((h): h is { command: string } => typeof (h as { command?: unknown } | null)?.command === "string" && (h as { command: string }).command.includes(MARKER));
}

/** Gemini CLI reads its settings as JSONC (comments, trailing commas); Claude Code, Codex and Cursor read plain JSON. */
const readsJsonc = (agent: AgentId | undefined): boolean => agent === "gemini";

/**
 * `jsonc` reads comments and trailing commas the way the agent does. A file that needs it is refused when `forWrite`:
 * rewriting would drop the person's comments, so the hooks are left for them to add.
 */
function parseSettings(path: string, o: { jsonc?: boolean; forWrite?: boolean } = {}): Json {
  const text = readText(path);
  if (text === null || text.trim() === "") return {};
  let v: unknown;
  try {
    v = parseJsonFile(path, text);
  } catch (e) {
    if (o.jsonc !== true) throw e;
    const r = parseJsoncResult(text);
    if (!r.ok) throw e;
    if (o.forWrite === true) throw new Error(`${path} has comments or trailing commas, which rewriting it would drop, so the firewall left it alone. Remove them (or add or remove the firewall's hooks by hand), then run this again`, { cause: e });
    v = jsonValueOf(r.root);
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error(`${path} is not a JSON object`);
  // A `hooks` that is not an object but holds something (a non-empty list, a string, a number) would be replaced by
  // install, losing what the person wrote there: refuse. An empty list or null holds nothing to lose.
  const hooks = (v as Json).hooks;
  const holdsSomething = Array.isArray(hooks) ? hooks.length > 0 : hooks !== undefined && hooks !== null && typeof hooks !== "object";
  if (holdsSomething) throw new Error(`${path}: "hooks" is not an object, so the firewall's hooks were not added. Fix the file, then run install again`);
  return v as Json;
}

/** Settings with the firewall's groups removed. */
export function withoutOurs(settings: Json): Json {
  const out: Json = { ...settings };
  const hooks = settings.hooks;
  if (typeof hooks !== "object" || hooks === null) return out;
  const nh: Json = {};
  for (const [ev, groups] of Object.entries(hooks as Json)) {
    if (!Array.isArray(groups)) {
      setOwn(nh, ev, groups);
      continue;
    }
    // A group that holds the firewall's entry and a person's own hook keeps the person's hook (only ours goes).
    const kept = groups.flatMap((g): unknown[] => {
      if (!isOurs(g)) return [g];
      const hooks = (g as HookGroup).hooks;
      if (!Array.isArray(hooks)) return [];
      const rest = hooks.filter((h) => !(typeof h?.command === "string" && h.command.includes(MARKER)));
      return rest.length > 0 ? [{ ...(g as object), hooks: rest }] : [];
    });
    if (kept.length > 0) setOwn(nh, ev, kept);
  }
  if (Object.keys(nh).length > 0) out.hooks = nh;
  else delete out.hooks;
  return out;
}

/** Settings with the firewall's groups first in every event it handles (in the agent's names and shape). */
export function withOurs(settings: Json, command: string, spec: AdapterSettings = CLAUDE_SETTINGS): Json {
  const base = withoutOurs(spec.enable !== undefined ? spec.enable(settings) : settings);
  const hooks: Json = { ...((base.hooks as Json | undefined) ?? {}) };
  for (const ev of spec.events) {
    const entry = { ...(spec.entryExtras ?? {}), type: "command", command, timeout: spec.timeout };
    const group: unknown = spec.flat === true ? { ...entry, ...(spec.matched.has(ev) ? { matcher: spec.matchAll } : {}) } : ({ ...(spec.matched.has(ev) ? { matcher: spec.matchAll } : {}), hooks: [entry] } satisfies HookGroup);
    const existing = Array.isArray(own(hooks, ev)) ? (own(hooks, ev) as unknown[]) : [];
    setOwn(hooks, ev, [group, ...existing]);
  }
  return { ...base, hooks };
}

/** A setting install added so the agent runs hooks at all (Gemini CLI's hooksConfig.enabled), so plain uninstall can take it out again. */
export interface EnableAdded {
  path: string[];
  /** What install set. */
  value: unknown;
  /** What the key held before (absent: it did not exist). */
  was?: unknown;
}

export interface InstallRecord {
  /** The agent whose settings file this is (absent in records written before 0.2: Claude Code). */
  agent?: AgentId;
  scope: Scope | "managed";
  path: string;
  backup: string;
  installedAt: string;
  version: string;
  /** What install added besides its own hook entries (absent in records written before 0.3.1). */
  enableAdded?: EnableAdded[];
  /** sha256 of the settings file as the firewall last wrote it: a different one means the person edited it since. */
  sha?: string;
}

const sha256 = (t: string): string => createHash("sha256").update(t).digest("hex");

function recordsPath(l: Layout): string {
  return join(l.home, "install.json");
}

export function readRecords(l: Layout): InstallRecord[] {
  const t = readText(recordsPath(l));
  if (t === null) return [];
  const hint = `Run "launchsafe-firewall doctor --repair-state" to rebuild it from the agent settings files, or restore it from a backup.`;
  let v: unknown;
  try {
    v = parseJsonFile(recordsPath(l), t);
  } catch (e) {
    throw new Error(`${(e as Error).message}. ${hint}`, { cause: e });
  }
  if (!Array.isArray(v)) throw new Error(`${recordsPath(l)} is not a list of installs. ${hint}`);
  return v as InstallRecord[];
}

function writeRecords(l: Layout, r: InstallRecord[]): void {
  atomicWrite(recordsPath(l), JSON.stringify(r, null, 2));
}

// The one platform check lives in platform.ts (the CLI and the Node library use it too); install keeps its old name for it.
export { assertSupportedPlatform };

function jsonOrNull(text: string | null): Json | null {
  if (text === null || text.trim() === "") return null;
  try {
    const v: unknown = JSON.parse(text);
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : null;
  } catch {
    return null;
  }
}

/** Lets the agent's settings react to a written hooks file (Codex hook trust). */
function afterWrite(spec: AdapterSettings, l: Layout, path: string, before: string | null, after: string | null, home: string | undefined): void {
  spec.afterWrite?.({ path, before: jsonOrNull(before), after: jsonOrNull(after), home: home ?? homedir(), backupDir: l.backups });
}

type SpecFor = (agent: AgentId) => AdapterSettings;

const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

/** The keys `after` has that `before` lacks or holds differently, as paths: what an enable step added. */
function addedPaths(before: Json, after: Json, prefix: string[] = []): EnableAdded[] {
  const out: EnableAdded[] = [];
  for (const [k, v] of Object.entries(after)) {
    if (!(k in before)) out.push({ path: [...prefix, k], value: v });
    else if (isObj(v) && isObj(own(before, k))) out.push(...addedPaths(own(before, k) as Json, v, [...prefix, k]));
    else if (JSON.stringify(v) !== JSON.stringify(own(before, k))) out.push({ path: [...prefix, k], value: v, was: own(before, k) });
  }
  return out;
}

/** Settings with what install added besides its entries put back as it was, when the person has not changed it since. */
function revertEnable(settings: Json, added: readonly EnableAdded[] | undefined): Json {
  const out = JSON.parse(JSON.stringify(settings)) as Json;
  for (const a of added ?? []) {
    const chain: Json[] = [out];
    let at: unknown = out;
    for (const k of a.path.slice(0, -1)) {
      at = isObj(at) ? own(at, k) : undefined;
      if (isObj(at)) chain.push(at);
    }
    const last = a.path[a.path.length - 1] as string;
    const holder = chain[chain.length - 1];
    if (chain.length !== a.path.length || holder === undefined || JSON.stringify(own(holder, last)) !== JSON.stringify(a.value)) continue;
    if ("was" in a) setOwn(holder, last, a.was);
    else delete holder[last];
    // A parent object that only held what install added goes with it.
    for (let i = chain.length - 1; i > 0; i--) {
      if (Object.keys(chain[i] as Json).length > 0) break;
      delete (chain[i - 1] as Json)[a.path[i - 1] as string];
    }
  }
  return out;
}

/** How many settings differ between two documents (a list counts the entries only one side has). */
export function countDifferences(a: unknown, b: unknown): number {
  if (Array.isArray(a) && Array.isArray(b)) {
    const rest = b.map((x) => JSON.stringify(x));
    let n = 0;
    for (const x of a) {
      const i = rest.indexOf(JSON.stringify(x));
      if (i === -1) n++;
      else rest.splice(i, 1);
    }
    return n + rest.length;
  }
  if (isObj(a) && isObj(b)) {
    let n = 0;
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) n += k in a && k in b ? countDifferences(own(a, k), own(b, k)) : 1;
    return n;
  }
  return JSON.stringify(a) === JSON.stringify(b) ? 0 : 1;
}

export interface InstallResult {
  /** Set when the settings file is a symlink: the file the hooks were written to (the link was kept). */
  linkedTo?: string;
  path: string;
  backup: string;
  changed: boolean;
  /** The installed hook command pins the approver key (false when no approval passphrase is set). */
  pinned: boolean;
}

export function install(l: Layout, scope: Scope, projectDir: string, version: string, opts: { home?: string; command?: string; platform?: NodeJS.Platform; agent?: AgentId; settings?: AdapterSettings } = {}): InstallResult {
  assertSupportedPlatform(opts.platform);
  const agent = opts.agent ?? "claude";
  const spec = opts.settings ?? CLAUDE_SETTINGS;
  if (!spec.scopes.includes(scope)) throw new Error(`${spec.label} has no ${scope} settings file (scopes: ${spec.scopes.join(", ")})`);
  const path = spec.path(scope, projectDir, opts.home ?? homedir());
  // Tests: never the developer's real settings or state (F-a). A no-op without the test marker.
  assertNotRealHome(path);
  assertNotRealHome(l.home);
  if (spec.refuseSymlink === true) refuseSymlinked(path, spec.label);
  // A symlinked settings file is checked before anything is read through it or backed up (FA4).
  writeTarget(path, opts.home !== undefined ? { home: opts.home } : {});
  return withLock(join(l.locks, "install.lock"), () => {
    // The backup keeps the file's own text, a byte order mark included, so a restore puts back exactly what the person had;
    // everything else (the record's fingerprint, the agent's hook-trust step) sees the text without the mark.
    const exact = readTextExact(path);
    const original = exact === null ? null : stripBom(exact);
    const settings = parseSettings(path, { jsonc: readsJsonc(agent), forWrite: true });
    const command = opts.command ?? hookCommand(l, undefined, undefined, agent, opts.home !== undefined ? { home: opts.home } : {});
    const next = withOurs(settings, command, spec);
    const prior = readRecords(l).find((r) => r.path === path);
    // What the enable step added, and what an earlier install already recorded (a second install finds the flag set and adds nothing).
    const enableAdded = [...(prior?.enableAdded ?? [])];
    if (spec.enable !== undefined) for (const a of addedPaths(settings, spec.enable(settings))) if (!enableAdded.some((x) => x.path.join("\0") === a.path.join("\0"))) enableAdded.push(a);
    const changed = JSON.stringify(next) !== JSON.stringify(settings);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backup = join(l.backups, `${stamp}-${agent === "claude" ? "" : `${agent}-`}${scope}-settings.json`);
    const records = readRecords(l).filter((r) => r.path !== path);
    // Keep the very first backup: it is the user's file from before the firewall ever touched it.
    const keepBackup = prior !== undefined && existsSync(prior.backup) ? prior.backup : backup;
    if (keepBackup === backup) atomicWrite(backup, JSON.stringify({ path, existed: exact !== null, content: exact }, null, 2));
    const text = `${JSON.stringify(next, null, 2)}\n`;
    const linkedTo = changed ? writeUserFile(path, text) : writeTarget(path).linkedTo;
    // The record goes down before the agent's own step (Codex's hook trust may throw), so hooks that are installed are always
    // recorded and uninstall can remove them; when that step fails, the file and the record go back to what they were.
    const before = readRecords(l);
    records.push({ ...(agent !== "claude" ? { agent } : {}), scope, path, backup: keepBackup, installedAt: new Date().toISOString(), version, ...(enableAdded.length > 0 ? { enableAdded } : {}), sha: sha256(changed ? text : (original ?? "")) });
    writeRecords(l, records);
    try {
      afterWrite(spec, l, path, original, `${JSON.stringify(next)}`, opts.home);
    } catch (e) {
      try {
        if (changed) {
          if (exact === null) rmSync(path, { force: true });
          else writeUserFile(path, exact);
        }
      } finally {
        writeRecords(l, before);
      }
      throw e;
    }
    return { path, backup: keepBackup, changed, pinned: pinnedApprover(command) !== null, ...(linkedTo !== null ? { linkedTo } : {}) };
  });
}

export interface RepinResult {
  updated: string[];
  skipped: { path: string; reason: string }[];
}

/**
 * G5: pins the current approver key in the firewall's hook command in every settings file install
 * recorded, so setting or rotating the passphrase after install does not leave the hook falling back
 * to the key on disk. Person-run only (called by `approver init` and `approver rotate`, which need a
 * terminal); a file that cannot be read or written (a managed file owned by an administrator) is
 * reported, not guessed at.
 */
export function repinApprover(l: Layout, specFor: SpecFor = () => CLAUDE_SETTINGS, home?: string): RepinResult {
  assertNotRealHome(l.home);
  const pub = approverPublicKey(l);
  // Item P: the same pass pins the paired phones' list (phone pair and phone remove call this too).
  const phones = phonesPinOf(l);
  const out: RepinResult = { updated: [], skipped: [] };
  return withLock(join(l.locks, "install.lock"), () => {
    const all = readRecords(l);
    for (const r of all) {
      assertNotRealHome(r.path);
      try {
        // FA4: never read, back up or write through a link to a protected place.
        writeTarget(r.path, home !== undefined ? { home } : {});
        const exact = readTextExact(r.path);
        if (exact === null) {
          out.skipped.push({ path: r.path, reason: "the file no longer exists" });
          continue;
        }
        const original = stripBom(exact);
        const settings = parseJsonFile(r.path, original) as Json;
        let touched = false;
        const hooks = typeof settings.hooks === "object" && settings.hooks !== null ? (settings.hooks as Json) : {};
        for (const groups of Object.values(hooks)) {
          if (!Array.isArray(groups)) continue;
          for (const g of groups) {
            for (const h of ourEntries(g)) {
              if (typeof h.command !== "string") continue;
              const next = withPhonesPin(withApproverPin(h.command, pub), phones);
              if (next !== h.command) {
                h.command = next;
                touched = true;
              }
            }
          }
        }
        if (!touched) continue;
        const stamp = new Date().toISOString().replace(/[:.]/g, "-");
        atomicWrite(join(l.backups, `${stamp}-repin-settings.json`), JSON.stringify({ path: r.path, existed: true, content: exact }, null, 2));
        const repinned = `${JSON.stringify(settings, null, 2)}\n`;
        writeUserFile(r.path, repinned);
        if (r.sha !== undefined && r.sha === sha256(original)) {
          r.sha = sha256(repinned);
          writeRecords(l, all);
        }
        afterWrite(specFor(r.agent ?? "claude"), l, r.path, original, JSON.stringify(settings), home);
        out.updated.push(r.path);
      } catch (e) {
        out.skipped.push({ path: r.path, reason: (e as Error).message });
      }
    }
    return out;
  });
}

/**
 * The approval key the hooks trust, when one is pinned: LAUNCHSAFE_FIREWALL_APPROVER in `env` (the hook's own
 * environment), else the key every installed hook command pins (null when none pins one, or they differ).
 */
export function pinnedApproverKey(l: Layout, env: NodeJS.ProcessEnv): string | null {
  const e = env.LAUNCHSAFE_FIREWALL_APPROVER;
  if (e !== undefined && e !== "") return e;
  const pins = [...new Set(installedHookCommands(l).commands.map((c) => pinnedApprover(c.command)).filter((p): p is string => p !== null))];
  return pins.length === 1 ? (pins[0] as string) : null;
}

/** Every distinct approval key the hook commands pin (and the environment's), for the CLI's check before a resume. */
export function pinnedApproverKeys(l: Layout, env: NodeJS.ProcessEnv): string[] {
  const e = env.LAUNCHSAFE_FIREWALL_APPROVER;
  const pins = installedHookCommands(l).commands.map((c) => pinnedApprover(c.command)).filter((p): p is string => p !== null);
  return [...new Set([...(e !== undefined && e !== "" ? [e] : []), ...pins])];
}

/** Item P: the firewall's hook commands in every settings file install recorded (unreadable files are listed). */
export function installedHookCommands(l: Layout): { commands: { path: string; command: string }[]; problems: string[] } {
  const commands: { path: string; command: string }[] = [];
  const problems: string[] = [];
  let records: InstallRecord[] = [];
  try {
    records = readRecords(l);
  } catch (e) {
    problems.push((e as Error).message);
  }
  for (const r of records) {
    if (r.scope === "managed") continue;
    try {
      const s = parseSettings(r.path, { jsonc: readsJsonc(r.agent) });
      const hooks = typeof s.hooks === "object" && s.hooks !== null ? (s.hooks as Json) : {};
      for (const groups of Object.values(hooks)) {
        if (!Array.isArray(groups)) continue;
        for (const g of groups) for (const h of ourEntries(g)) if (typeof h.command === "string") commands.push({ path: r.path, command: h.command });
      }
    } catch (e) {
      problems.push(`${r.path}: ${(e as Error).message}`);
    }
  }
  return { commands, problems };
}

export interface UninstallResult {
  path: string;
  restored: "removed-hooks" | "restored-backup" | "nothing-to-do" | "kept-edits";
  /** --restore-backup: where the file as it was just before the restore was saved. */
  savedCopy?: string;
  /** --restore-backup: the settings changed since install that the restore would discard (0: none). */
  differences?: number;
  /** The file was a symlink: the file that was written. */
  linkedTo?: string;
  /** --restore-backup removed a file install had created. */
  removedFile?: boolean;
}

/** After the firewall itself rewrites a settings file (re-pin, sandbox profile, MCP wrapper), the recorded fingerprint follows, unless the person had edited the file. */
export function recordOwnWrite(l: Layout, path: string, before: string | null, after: string): void {
  try {
    const records = readRecords(l);
    const r = records.find((x) => x.path === path);
    if (r === undefined || r.sha === undefined || before === null || r.sha !== sha256(before)) return;
    r.sha = sha256(after);
    writeRecords(l, records);
  } catch {
    // An unreadable record is reported elsewhere; the fingerprint then stays and a restore asks first.
  }
}

interface Backup {
  existed: boolean;
  content: string | null;
}

function readBackup(path: string): Backup {
  const b = parseJsonFile(path, readText(path) ?? "{}") as Partial<Backup>;
  return { existed: b.existed === true, content: typeof b.content === "string" ? b.content : null };
}

/** The settings changes a restore of this record would discard: edits the person made after install. */
function editsSinceInstall(r: InstallRecord, b: Backup): number {
  const cur = readText(r.path);
  if (cur === null) return 0;
  if (r.sha !== undefined && r.sha === sha256(cur)) return 0;
  // Through a symlink the target may not be a settings file at all: anything unreadable as settings counts as changed, so the person is asked (FA4).
  const linked = lstatSync(r.path, { throwIfNoEntry: false })?.isSymbolicLink() === true;
  let doc: unknown;
  try {
    doc = JSON.parse(cur);
  } catch {
    // Damaged, not edited: there are no settings in it to lose (the file is still saved beside the restored one).
    return linked ? 1 : 0;
  }
  let original: unknown = {};
  try {
    // The backup holds the file's exact text, a byte order mark included: the edits are counted against the settings after it, not against nothing.
    original = b.existed && b.content !== null && b.content.trim() !== "" ? JSON.parse(stripBom(b.content)) : {};
  } catch {
    original = {};
  }
  if (!isObj(doc)) return linked ? 1 : 0;
  return countDifferences(withoutOurs(revertEnable(doc, r.enableAdded)), original);
}

/**
 * What `--restore-backup` would discard, per recorded file (only files with a difference). The command shows
 * these and asks the person (or takes --force) before anything is written.
 */
export function restoreEdits(l: Layout, opts: { scope?: Scope; projectDir?: string; home?: string; agent?: AgentId; settings?: AdapterSettings } = {}): { path: string; differences: number }[] {
  const spec = opts.settings ?? CLAUDE_SETTINGS;
  const records = readRecords(l);
  const forAgent = opts.agent !== undefined ? records.filter((r) => (r.agent ?? "claude") === opts.agent) : records;
  const targets = opts.scope !== undefined ? forAgent.filter((r) => r.path === spec.path(opts.scope as Scope, opts.projectDir ?? process.cwd(), opts.home ?? homedir())) : forAgent;
  const out: { path: string; differences: number }[] = [];
  for (const r of targets) {
    if (!existsSync(r.backup)) continue;
    // Refused before the person is asked anything (FA4).
    assertRestorableTarget(r.path, opts.home !== undefined ? { home: opts.home } : {});
    const n = editsSinceInstall(r, readBackup(r.backup));
    if (n > 0) out.push({ path: r.path, differences: n });
  }
  return out;
}

/**
 * Removes the firewall's hooks. By default only the firewall's own entries (and what install added so the
 * hooks run, when the person has not changed it) are removed; later edits stay. With restoreBackup the file is
 * put back exactly as it was before the first install (deleted if it did not exist), after the current file is
 * saved beside it as <file>.before-restore.<timestamp>; a file changed since install is restored only with
 * `force` (the command asks the person first).
 */
export function uninstall(l: Layout, opts: { restoreBackup?: boolean; force?: boolean; scope?: Scope; projectDir?: string; home?: string; agent?: AgentId; settings?: AdapterSettings; specFor?: SpecFor } = {}): UninstallResult[] {
  assertNotRealHome(l.home);
  for (const r of readRecords(l)) assertNotRealHome(r.path);
  return withLock(join(l.locks, "install.lock"), () => {
    const records = readRecords(l);
    const spec = opts.settings ?? CLAUDE_SETTINGS;
    const forAgent = opts.agent !== undefined ? records.filter((r) => (r.agent ?? "claude") === opts.agent) : records;
    const targets = opts.scope !== undefined ? forAgent.filter((r) => r.path === spec.path(opts.scope as Scope, opts.projectDir ?? process.cwd(), opts.home ?? homedir())) : forAgent;
    const out: UninstallResult[] = [];
    const kept = new Set<InstallRecord>();
    const specOf = (r: InstallRecord): AdapterSettings => (opts.settings !== undefined && opts.agent === (r.agent ?? "claude") ? opts.settings : (opts.specFor ?? (() => CLAUDE_SETTINGS))(r.agent ?? "claude"));
    for (const r of targets) {
      const beforeExact = readTextExact(r.path);
      const beforeText = beforeExact === null ? null : stripBom(beforeExact);
      const done = (): void => afterWrite(specOf(r), l, r.path, beforeText, readText(r.path), opts.home);
      if (opts.restoreBackup === true && existsSync(r.backup)) {
        // FA4: no write through a link to a protected place, and no copy of a file kept elsewhere saved beside the settings.
        assertRestorableTarget(r.path, opts.home !== undefined ? { home: opts.home } : {});
        const b = readBackup(r.backup);
        const differences = editsSinceInstall(r, b);
        if (differences > 0 && opts.force !== true) {
          kept.add(r);
          out.push({ path: r.path, restored: "kept-edits", differences });
          continue;
        }
        const res: UninstallResult = { path: r.path, restored: "restored-backup", ...(differences > 0 ? { differences } : {}) };
        if (beforeExact !== null) {
          const copy = `${r.path}.before-restore.${new Date().toISOString().replace(/[:.]/g, "-")}`;
          atomicWrite(copy, beforeExact, existsSync(r.path) ? statSync(r.path).mode & 0o777 : 0o600);
          res.savedCopy = copy;
        }
        if (b.existed && b.content !== null) {
          const linked = writeUserFile(r.path, b.content);
          if (linked !== null) res.linkedTo = linked;
        } else if (existsSync(r.path) || lstatSync(r.path, { throwIfNoEntry: false }) !== undefined) {
          // The file did not exist before install: restoring is having none.
          rmSync(r.path, { force: true });
          res.removedFile = true;
        }
        done();
        out.push(res);
        continue;
      }
      if (!existsSync(r.path)) {
        out.push({ path: r.path, restored: "nothing-to-do" });
        continue;
      }
      const s = parseSettings(r.path, { jsonc: readsJsonc(r.agent), forWrite: true });
      const next = revertEnable(withoutOurs(s), r.enableAdded);
      const linked = writeUserFile(r.path, `${JSON.stringify(next, null, 2)}\n`);
      done();
      out.push({ path: r.path, restored: "removed-hooks", ...(linked !== null ? { linkedTo: linked } : {}) });
    }
    writeRecords(l, records.filter((r) => !targets.includes(r) || kept.has(r)));
    return out;
  });
}

function refuseSymlinked(path: string, label: string): void {
  for (const p of [path, dirname(path)]) {
    if (lstatSync(p, { throwIfNoEntry: false })?.isSymbolicLink() === true) throw new Error(`${p} is a symbolic link, and ${label} does not load hooks reached through one, so the firewall's hooks would never run. Install nothing through the link: make ${path} a regular file (copy it out of your dotfiles), then install again.`);
  }
}

export interface RepairResult {
  /** install.json was readable: nothing was changed. */
  ok: boolean;
  /** The damaged file, moved aside. */
  movedTo?: string;
  rebuilt: { agent: AgentId; scope: Scope; path: string; backup: string }[];
}

/**
 * `doctor --repair-state`: rebuilds a damaged install.json from the agent settings files the firewall can see
 * (each agent's user file, and the project's files for `projectDir`): every file holding the firewall's hooks gets
 * a record again. The damaged file is moved aside, never deleted. The first backup of each file is found by the
 * path it names in the backups folder; with none, a restoring uninstall can only remove the hooks.
 */
export function repairState(l: Layout, projectDir: string, version: string, adapters: readonly { id: AgentId; settings: AdapterSettings }[], home: string = homedir()): RepairResult {
  assertNotRealHome(l.home);
  return withLock(join(l.locks, "install.lock"), () => {
    try {
      readRecords(l);
      return { ok: true, rebuilt: [] };
    } catch {
      // Damaged: rebuilt below.
    }
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const movedTo = `${recordsPath(l)}.damaged-${stamp}`;
    renameSync(recordsPath(l), movedTo);
    const backups: { path: string; file: string }[] = [];
    try {
      for (const n of readdirSync(l.backups).sort()) {
        if (!n.endsWith("-settings.json")) continue;
        try {
          const b = JSON.parse(readText(join(l.backups, n)) ?? "") as { path?: unknown };
          if (typeof b.path === "string") backups.push({ path: b.path, file: join(l.backups, n) });
        } catch {
          // Not a backup record.
        }
      }
    } catch {
      // No backups folder.
    }
    const rebuilt: RepairResult["rebuilt"] = [];
    const records: InstallRecord[] = [];
    for (const { id, settings } of adapters) {
      for (const scope of settings.scopes) {
        const path = settings.path(scope, projectDir, home);
        assertNotRealHome(path);
        if (!existsSync(path) || records.some((r) => r.path === path)) continue;
        let present = false;
        try {
          present = inspectSettings(path, settings).present;
        } catch {
          continue;
        }
        if (!present) continue;
        const backup = backups.find((b) => b.path === path)?.file ?? "";
        const text = readText(path) ?? "";
        records.push({ ...(id !== "claude" ? { agent: id } : {}), scope, path, backup, installedAt: new Date().toISOString(), version, sha: sha256(text) });
        rebuilt.push({ agent: id, scope, path, backup });
      }
    }
    writeRecords(l, records);
    return { ok: false, movedTo, rebuilt };
  });
}

export interface RegistrationStatus {
  path: string;
  present: boolean;
  events: Record<string, { ours: boolean; first: boolean; failClosed: boolean; invokesHook: boolean }>;
  disableAllHooks: boolean;
}

/** The part of every installed command that runs the hook: `... hook || exit 2`, `... hook --agent codex || {...}`, `... hook --agent cursor`. A marker with `true` after it is not this. */
const HOOK_INVOCATION = /\shook(?:\s+--agent\s+(?:claude|codex|gemini|cursor))?\s*(?:\|\||$)/;

export function inspectSettings(path: string, spec: AdapterSettings = CLAUDE_SETTINGS): RegistrationStatus & { disabledBy: string[] } {
  const s = existsSync(path) ? parseSettings(path, { jsonc: spec.label === "Gemini CLI" }) : {};
  const hooks = (s.hooks as Json | undefined) ?? {};
  const events: RegistrationStatus["events"] = {};
  for (const ev of spec.events) {
    const groups = Array.isArray(own(hooks, ev)) ? (own(hooks, ev) as unknown[]) : [];
    const idx = groups.findIndex(isOurs);
    const entry = idx === -1 ? undefined : ourEntries(groups[idx])[0];
    const cmd = entry?.command ?? "";
    setOwn(events, ev, { ours: idx !== -1, first: idx === 0, failClosed: entry !== undefined && spec.failClosedEntry !== undefined ? spec.failClosedEntry(entry) : isFailClosed(cmd), invokesHook: HOOK_INVOCATION.test(cmd) });
  }
  return { path, present: Object.values(events).some((e) => e.ours), events, disableAllHooks: s.disableAllHooks === true, disabledBy: spec.disabledBy(s) };
}

/** For ConfigChange: the problems a settings change created for the firewall (in every agent's file it is installed in). */
export function checkHookRegistration(l: Layout, projectDir: string, home = homedir(), specFor: (agent: AgentId) => AdapterSettings = () => CLAUDE_SETTINGS): string[] {
  const problems: string[] = [];
  let records: InstallRecord[] = [];
  try {
    records = readRecords(l);
  } catch {
    problems.push("the firewall's install record is unreadable");
  }
  for (const r of records) {
    if (r.scope === "managed") continue;
    try {
      const spec = specFor(r.agent ?? "claude");
      const st = inspectSettings(r.path, spec);
      const missing = spec.events.filter((ev) => !own(st.events, ev)?.ours);
      if ((r.agent ?? "claude") !== "claude") for (const d of st.disabledBy) problems.push(`${r.path}: ${d}, which would turn the firewall off`);
      if (missing.length > 0) problems.push(`the firewall's ${missing.join(", ")} hook${missing.length > 1 ? "s were" : " was"} removed from ${r.path}`);
      // An entry that still carries the marker but no longer runs the hook, or no longer fails closed, protects nothing.
      const present = spec.events.filter((ev) => own(st.events, ev)?.ours === true);
      const neutered = present.filter((ev) => own(st.events, ev)?.invokesHook !== true);
      const open = present.filter((ev) => own(st.events, ev)?.invokesHook === true && own(st.events, ev)?.failClosed !== true);
      if (neutered.length > 0) problems.push(`the firewall's ${neutered.join(", ")} hook${neutered.length > 1 ? "s" : ""} in ${r.path} no longer runs the firewall`);
      if (open.length > 0) problems.push(`the firewall's ${open.join(", ")} hook${open.length > 1 ? "s" : ""} in ${r.path} no longer fails closed`);
    } catch (e) {
      problems.push(`${r.path} cannot be read (${(e as Error).message})`);
    }
  }
  for (const scope of ["user", "project", "local"] as const) {
    const p = settingsPath(scope, projectDir, home);
    try {
      if (existsSync(p) && inspectSettings(p).disableAllHooks) problems.push(`${p} sets disableAllHooks, which would turn the firewall off`);
    } catch {
      // Unreadable settings are Claude Code's problem to report; the hooks check above covers ours.
    }
  }
  // The sandbox profile doctor --fix installed, compared with what it recorded.
  problems.push(...sandboxRegistrationProblems(l, projectDir, process.platform, home));
  return problems;
}

/** The managed-settings document an administrator deploys so no user or project setting can remove the hooks. */
export function managedSettingsSnippet(command: string, lockOtherHooks: boolean): Json {
  const s = withOurs({}, command);
  if (lockOtherHooks) s.allowManagedHooksOnly = true;
  return s;
}
