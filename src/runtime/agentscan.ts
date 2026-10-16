/**
 * The SessionStart scan: reads what the agent is armed with (its
 * instructions, settings, hooks, skills, MCP servers and memory: the
 * workspace's, the user's and the administrator's), runs LaunchSafe's
 * agent-safety rules on it (vendored in src/vendor/agent-safety), compares it
 * with what it was armed with last session, and turns what it finds into
 * session state:
 *
 * - a critical finding, or a high-severity one the rule is highly confident
 *   in (policy agentScan.taintOn), makes the session untrusted from the start,
 *   with the finding as the taint source; everything else is logged;
 * - a hook, helper, folder-open task or MCP server added or changed since the
 *   last session taints ("changed since your last session"), and so does a
 *   memory change whose files carry a finding;
 * - an analyzer failure taints (fail closed); running out of time or file
 *   budget does not, but is logged and shown by doctor.
 *
 * - a file under .claude/hooks or a skills folder added, changed or removed,
 *   and a new finding of medium severity or more in a file that changed, taint
 *   too; other changed files are logged;
 * - a collection problem (a workspace path that resolves outside the
 *   workspace, a file too large to check, an MCP list that does not parse)
 *   taints for the workspace and memory, and is logged for the user's files.
 *
 * An unchanged setup costs one read and hash per file: the analysis and
 * receipts are cached by the files' content (never by size and modification
 * time alone, which a file can keep while its content changes).
 */

import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import type { FirewallConfig, StateEvent } from "../types.js";
import {
  analyzeAgentFiles,
  canonicalJson,
  compareReceipts,
  inventoryParts,
  jsonValueOf,
  memoryDriftSentence,
  parseJsoncResult,
  receiptContent,
  RECEIPT_FORMAT,
  RULES_VERSION,
  summarizeAgentSafety,
  agentFileKind,
  parseReceipt,
  type AgentAnalysis,
  type AgentCheckReceipt,
  type AgentFile,
  type AgentFinding,
  type JsonValue,
} from "../vendor/agent-safety/index.js";
import { AGENT_SAFETY_COMMIT } from "../vendor/agent-safety-commit.js";
import { collectAgentFiles, collectionKey, readEntry, type AgentFileEntry, type Collection, type ConfiguredServer, type Scope } from "./agentfiles.js";
import { readText, withLock } from "./fsutil.js";
import type { Layout } from "./layout.js";
import { registeredSettingsFiles } from "./context.js";
import { loadIdentity, parseHookCommand } from "./identity.js";
import { realpathLoose } from "./realpath.js";
import { hookEntries } from "../engine/settings.js";
import { unwrapGatewayText } from "../gateway/install.js";
import { own as ownEntry, setOwn } from "../own.js";

/** SessionStart's wall-clock cap (spec: cold scan under 100 ms typical, capped at 300 ms). */
export const SESSION_START_BUDGET_MS = 300;
/** The inline scan when a session's first tool call arrives without a SessionStart scan. */
export const FALLBACK_BUDGET_MS = 150;

/** 3: keyed by the files' content (not size and modification time), rule set 1.2.0-fw. */
const CACHE_FORMAT = 3;
/** Cached scope analyses kept (content-addressed: the user's own files are shared by every workspace). */
const MAX_CACHED = 100;
/** The scopes a receipt is kept for (drift); the administrator's files are reported only. */
type DriftScope = "workspace" | "user" | "memory";
const DRIFT_SCOPES: readonly DriftScope[] = ["workspace", "user", "memory"];

export interface ScopedFinding {
  scope: Scope;
  ruleId: string;
  family: string;
  title: string;
  severity: AgentFinding["severity"];
  confidence: AgentFinding["confidence"];
  /** Display path (workspace-relative, ~/..., or the managed file). */
  file: string;
  line: number;
}

/** What one scan saw. */
export interface ScanSnapshot {
  findings: ScopedFinding[];
  receipts: Partial<Record<DriftScope, AgentCheckReceipt>>;
  /** Repository-style path -> display path, per scope (receipts use the former). */
  displays: Partial<Record<Scope, Record<string, string>>>;
  filesChecked: number;
  error?: string;
}

export interface ScanOptions {
  l: Layout;
  /** The workspace root, or null when too broad to scan. */
  workspace: string | null;
  home: string;
  configDir: string;
  claudeJson?: string | undefined;
  cfg: FirewallConfig;
  budgetMs: number;
  now: Date;
  managedSettings?: string | undefined;
  managedMcp?: string | undefined;
  /** Tests: a clock for the budget, and a replacement analyzer. */
  clock?: () => number;
  analyze?: (files: readonly AgentFile[]) => AgentAnalysis;
  /** R5: which hook entries are the firewall's own (default: ownHookMatcher from the install record and identity). */
  ownHook?: OwnHook;
  /** I12: model gateways the person runs themselves; a model endpoint on one of them (HTTPS) is not a finding. */
  allowedModelHosts?: readonly string[];
}

/** Whether a hook command in a settings file is the firewall's own installed entry. */
export type OwnHook = ((file: string, command: string) => boolean) & { key: string };

export interface SessionScan {
  events: StateEvent[];
  /** Sentences explaining why the session starts untrusted (empty: it does not). */
  untrustedBecause: string[];
  /** Findings and changes that were logged without changing the session. */
  logged: string[];
  /** Rule ids found (all of them), for the agent_scan event. */
  rules: string[];
  incomplete: string[];
  servers: ConfiguredServer[];
  cached: boolean;
  ms: number;
}

/** The workspace to scan: the project directory, unless it is / or contains the home directory. */
export function scanWorkspace(projectDir: string, home: string): string | null {
  const p = resolve(projectDir);
  const h = resolve(home);
  return p === "/" || p === h || h.startsWith(`${p}/`) ? null : p;
}

// --- receipts (synchronous: the hook is synchronous) ------------------------------------------------

const byText = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const sha256Hex = (s: string | Uint8Array): string => createHash("sha256").update(s).digest("hex");
const textBytes = (text: string): Uint8Array => new TextEncoder().encode(text.startsWith("﻿") ? text.slice(1) : text);

/**
 * agent-safety's buildReceipt(), computed synchronously with Node's hash (its own takes an async
 * WebCrypto hasher). test/agent-scan.test.ts checks the two give the same receipt.
 */
export function receiptSync(files: readonly AgentFile[], analysis: AgentAnalysis, toolVersion: string, checkedAt: string, repository: string): AgentCheckReceipt {
  const read = new Set(analysis.filesRead);
  const memory = new Map(analysis.memory.map((m) => [m.path, m]));
  const out: AgentCheckReceipt["files"] = [];
  for (const file of files) {
    if (!read.has(file.path) || agentFileKind(file.path) === "env_file") continue;
    const bytes = textBytes(file.content);
    const mem = memory.get(file.path);
    out.push({ path: file.path, sha256: sha256Hex(bytes), bytes: bytes.length, ...(mem === undefined ? {} : { memory: true as const, lines: mem.lines }) });
  }
  out.sort((a, b) => byText(a.path, b.path));
  // The same servers and hooks (with their whole-command hashes) as buildReceipt().
  const { servers, hooks } = inventoryParts(analysis);
  const summary = summarizeAgentSafety(analysis);
  const receipt: Omit<AgentCheckReceipt, "digest"> = {
    format: RECEIPT_FORMAT,
    tool_version: toolVersion,
    rules_version: RULES_VERSION,
    source: { host: "github", repository, default_branch: "", commit: "" },
    files: out,
    servers,
    hooks,
    summary: { files_checked: summary.filesChecked, findings: { ...summary.counts }, runs_on_its_own: servers.length + hooks.length },
    findings: analysis.findings.map((f) => ({ rule: f.ruleId, severity: f.severity, path: f.file, line: f.line })).sort((a, b) => byText(a.path, b.path) || a.line - b.line || byText(a.rule, b.rule)),
    checked_at: checkedAt,
  };
  return { ...receipt, digest: sha256Hex(new TextEncoder().encode(canonicalJson(receiptContent(receipt)))) };
}

// --- the firewall's own hooks -----------------------------------------------------------------------

/** The exact hook command `install` writes (src/runtime/install.ts hookCommand). */
const OWN_HOOK = /^LAUNCHSAFE_FIREWALL_HOOK=1 (?:LAUNCHSAFE_FIREWALL_HOME='(?:[^']|'\\'')*' )?(?:LAUNCHSAFE_FIREWALL_APPROVER='[A-Za-z0-9+/=]+' )?(?:LAUNCHSAFE_FIREWALL_PHONES='sha256:[0-9a-f]{64}' )?(?:HOME='(?:[^']|'\\'')*' )?(?:LAUNCHSAFE_FIREWALL_TEST=(?:'1')? VITEST= )?(?:NODE_COMPILE_CACHE= )?(?:NODE_OPTIONS= NODE_PATH= LD_PRELOAD= DYLD_INSERT_LIBRARIES= )?'[^']+' '[^']+\/dist\/cli\.js' hook(?:(?: --agent (?:claude|codex|gemini))? (?:\|\| exit 2|\|\| \{ echo '[^']*' >&2; exit 2; \})| --agent cursor)$/;

/** How agent-safety shows a command in its inventory (whitespace collapsed, at most 200 characters). */
function shown(command: string): string {
  const t = command.replace(/\s+/g, " ").trim();
  return t.length > 200 ? `${t.slice(0, 199)}…` : t;
}

/**
 * R5: the firewall's own entry is identified by what is installed, never by its shape alone. A command
 * counts only when it has the shape install writes, sits in a settings file the install record (or
 * managed settings) registers, names an absolute node binary and an absolute CLI file that the
 * installed identity lists, and, when it names a data directory, names this one. A repository hook
 * that imitates the shape (a relative './dist/cli.js', another interpreter, an unregistered file) is
 * drift like any other.
 */
export function ownHookMatcher(l: Layout, home: string): OwnHook {
  let registered: string[] = [];
  try {
    registered = registeredSettingsFiles(l);
  } catch {
    registered = [];
  }
  const id = registered.length === 0 ? null : loadIdentity(l, registered, { home });
  const files = new Set(registered);
  const clis = new Set(id?.source === "hook-command" ? id.cliFiles : []);
  const nodes = new Set(id?.source === "hook-command" ? id.nodeBinaries : []);
  const homes = new Set([l.home, realpathLoose(l.home)]);
  const fn = (file: string, command: string): boolean => {
    if (!OWN_HOOK.test(command)) return false;
    if (!files.has(file) && !files.has(realpathLoose(file))) return false;
    const parts = parseHookCommand(command);
    if (parts === null || !parts.cli.startsWith("/") || !parts.node.startsWith("/")) return false;
    if (!clis.has(parts.cli) && !clis.has(realpathLoose(parts.cli))) return false;
    if (!nodes.has(parts.node) && !nodes.has(realpathLoose(parts.node))) return false;
    return parts.firewallHome === undefined || homes.has(parts.firewallHome) || homes.has(realpathLoose(parts.firewallHome));
  };
  return Object.assign(fn, { key: JSON.stringify([[...files].sort(), [...clis].sort(), [...nodes].sort(), [...homes].sort()]) });
}

/** The firewall's own hook commands in a settings file, as agent-safety would show them. */
function ownHookCommands(file: string, content: string, own: OwnHook): Set<string> {
  const out = new Set<string>();
  // Read as the agent reads it (JSONC), so a comment cannot hide one of the firewall's hooks from this match.
  const parsed = parseJsoncResult(content);
  if (!parsed.ok) return out;
  const v = jsonValueOf(parsed.root);
  // Both shapes: groups (Claude Code, Codex, Gemini CLI) and Cursor's flat entries.
  for (const { command } of hookEntries(v)) if (command !== "" && own(file, command)) out.add(shown(command));
  return out;
}

/** The receipt without the firewall's own hook entries: installing or re-pinning the firewall is not drift. */
function withoutOwnHooks(r: AgentCheckReceipt, own: Map<string, Set<string>>): AgentCheckReceipt {
  return { ...r, hooks: r.hooks.filter((h) => !(own.get(h.file)?.has(h.command) ?? false)) };
}

// --- cache and stored receipts ----------------------------------------------------------------------

function wsId(workspace: string | null): string {
  return sha256Hex(workspace === null ? "(no workspace)" : resolve(workspace)).slice(0, 32);
}

function scanDir(l: Layout): string {
  return join(l.home, "scan");
}

/** One scope's analysis, keyed by what its files are (paths, sizes, modification times). */
interface ScopeEntry {
  at: string;
  findings: ScopedFinding[];
  receipt?: AgentCheckReceipt;
  displays: Record<string, string>;
  filesChecked: number;
}

interface CacheFile {
  format: number;
  entries: Record<string, ScopeEntry>;
}

function readCache(l: Layout): CacheFile {
  const t = readText(join(scanDir(l), "cache.json"));
  if (t !== null) {
    try {
      const v = JSON.parse(t) as CacheFile;
      if (v.format === CACHE_FORMAT && typeof v.entries === "object" && v.entries !== null) return v;
    } catch {
      // A broken cache is only a slower scan.
    }
  }
  return { format: CACHE_FORMAT, entries: {} };
}

function writeCache(l: Layout, fresh: Record<string, ScopeEntry>): void {
  const p = join(scanDir(l), "cache.json");
  withLock(`${p}.lock`, () => {
    const c = readCache(l);
    Object.assign(c.entries, fresh);
    const keys = Object.keys(c.entries).sort((a, b) => byText(ownEntry(c.entries, b)?.at ?? "", ownEntry(c.entries, a)?.at ?? ""));
    for (const old of keys.slice(MAX_CACHED)) delete c.entries[old];
    quickWrite(p, JSON.stringify(c));
  });
}

/**
 * Atomic replace without fsync, for files that only save time or inform doctor (the cache, the last
 * scan): losing one to a power cut costs a re-scan, nothing more. Each fsync is felt at session start.
 */
function quickWrite(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  writeFileSync(tmp, text, { mode: 0o600 });
  renameSync(tmp, path);
}

export function receiptsPath(l: Layout, workspace: string | null): string {
  return join(scanDir(l), "receipts", `${wsId(workspace)}.json`);
}

type StoredReceipts = Partial<Record<DriftScope, AgentCheckReceipt>>;

/** The receipts of the last session in this workspace; "corrupt" when the file exists but is not valid. */
function readReceipts(l: Layout, workspace: string | null): StoredReceipts | "missing" | "corrupt" {
  const t = readText(receiptsPath(l, workspace));
  if (t === null) return "missing";
  try {
    const v = JSON.parse(t) as Record<string, unknown>;
    const out: StoredReceipts = {};
    for (const k of DRIFT_SCOPES) {
      if (v[k] === undefined) continue;
      const p = parseReceipt(JSON.stringify(v[k]));
      if (!p.ok) return "corrupt";
      out[k] = p.receipt;
    }
    return out;
  } catch {
    return "corrupt";
  }
}

/** The result of the last scan of a workspace, for doctor. */
export interface LastScan {
  at: string;
  tainted: string[];
  logged: string[];
  incomplete: string[];
  error?: string;
}

export function lastScanPath(l: Layout, workspace: string | null): string {
  return join(scanDir(l), "last", `${wsId(workspace)}.json`);
}

export function readLastScan(l: Layout, workspace: string | null): LastScan | null {
  const t = readText(lastScanPath(l, workspace));
  if (t === null) return null;
  try {
    return JSON.parse(t) as LastScan;
  } catch {
    return null;
  }
}

/**
 * Writes the receipts only when they changed, without fsync: a receipt lost to a power cut reads as
 * missing (the next session records a new one) or unreadable (that session is tainted once), never as
 * "unchanged". Each fsync is felt at session start.
 */
function writeIfChanged(path: string, text: string): void {
  if (readText(path) === text) return;
  quickWrite(path, text);
}

// --- the scan ---------------------------------------------------------------------------------------

/** Runs the analysis for every scope, reusing the cached result of a scope whose files are unchanged. */
export function scanSnapshot(o: ScanOptions, collection: Collection): { snapshot: ScanSnapshot; cached: boolean } {
  const snapshot: ScanSnapshot = { findings: [], receipts: {}, displays: {}, filesChecked: 0 };
  const allowed = [...(o.allowedModelHosts ?? [])].sort();
  const analyze = o.analyze ?? ((files: readonly AgentFile[]) => analyzeAgentFiles(files, { allowedModelHosts: allowed }));
  const own = o.ownHook ?? ownHookMatcher(o.l, o.home);
  const cache = o.analyze === undefined ? readCache(o.l).entries : {};
  const fresh: Record<string, ScopeEntry> = {};
  const at = o.now.toISOString();
  let allCached = true;
  try {
    for (const scope of ["workspace", "user", "memory", "managed"] as const) {
      const entries = collection.files.filter((e) => e.scope === scope);
      if (entries.length === 0) continue;
      const key = sha256Hex(`${CACHE_FORMAT}\u0000${RULES_VERSION}\u0000${AGENT_SAFETY_COMMIT}\u0000${scope}\u0000${own.key}\u0000${JSON.stringify(allowed)}\u0000${collectionKey(entries)}`);
      let entry = ownEntry(cache, key);
      if (entry === undefined) {
        allCached = false;
        entry = analyzeOne(scope, entries, analyze, at, own, (t) => unwrapGatewayText(o.l, t));
        setOwn(fresh, key, entry);
      }
      snapshot.displays[scope] = entry.displays;
      snapshot.filesChecked += entry.filesChecked;
      snapshot.findings.push(...entry.findings);
      if (entry.receipt !== undefined && scope !== "managed") snapshot.receipts[scope] = entry.receipt;
    }
  } catch (e) {
    snapshot.error = (e as Error).message;
    return { snapshot, cached: false };
  }
  if (Object.keys(fresh).length > 0) {
    try {
      writeCache(o.l, fresh);
    } catch {
      // The cache only saves time.
    }
  }
  return { snapshot, cached: allCached };
}

function analyzeOne(scope: Scope, entries: readonly AgentFileEntry[], analyze: (f: readonly AgentFile[]) => AgentAnalysis, at: string, ownHook: OwnHook, unwrap: (text: string) => string = (t) => t): ScopeEntry {
  const displays: Record<string, string> = {};
  for (const e of entries) setOwn(displays, e.path, e.display);
  // The analysis, receipts and drift see each MCP server as it was before the gateway wrapped it.
  const files = entries.map((e) => ({ path: e.path, content: unwrap(readEntry(e)) }));
  const analysis = analyze(files);
  const findings: ScopedFinding[] = [];
  for (const f of analysis.findings) {
    const sf: ScopedFinding = { scope, ruleId: f.ruleId, family: f.family, title: f.title, severity: f.severity, confidence: f.confidence, file: ownEntry(displays, f.file) ?? f.file, line: f.line };
    findings.push(sf);
  }
  const entry: ScopeEntry = { at, findings, displays, filesChecked: analysis.filesChecked };
  if (scope !== "managed") {
    const own = new Map<string, Set<string>>();
    for (const f of files) if (agentFileKind(f.path) === "claude_settings") own.set(f.path, ownHookCommands(entries.find((e) => e.path === f.path)?.abs ?? f.path, f.content, ownHook));
    entry.receipt = withoutOwnHooks(receiptSync(files, analysis, `launchsafe-firewall agent-safety@${AGENT_SAFETY_COMMIT.slice(0, 12)}`, at, `local:${scope}`), own);
  }
  return entry;
}

/** Whether a finding makes the session start untrusted under the policy. */
export function taints(f: Pick<ScopedFinding, "scope" | "severity" | "confidence">, cfg: FirewallConfig): boolean {
  if (f.scope === "managed") return false; // The administrator's files: reported, never a reason to distrust the person's session.
  if (cfg.agentScan.taintOn === "never") return false;
  if (f.severity === "critical") return true;
  return cfg.agentScan.taintOn === "high" && f.severity === "high" && f.confidence === "high";
}

const where = (f: ScopedFinding): string => `${f.file}:${f.line}`;

function displayOf(snapshot: ScanSnapshot, scope: DriftScope, path: string): string {
  return ownEntry(ownEntry(snapshot.displays, scope), path) ?? path;
}

/** Drift since the last session, as taint sources and logged lines. */
function judgeDrift(snapshot: ScanSnapshot, stored: StoredReceipts, scope: DriftScope, taint: string[], logged: string[]): void {
  const now = snapshot.receipts[scope];
  if (now === undefined) return;
  // A scope with no agent files last session has no receipt: what appeared since is compared with nothing, so a hook or skill added there is drift.
  const before = stored[scope] ?? receiptSync([], analyzeAgentFiles([]), "launchsafe-firewall agent-safety", now.checked_at, `local:${scope}`);
  const d = compareReceipts(before, now);
  const show = (p: string): string => displayOf(snapshot, scope, p);
  for (const h of d.hooks.added) taint.push(`changed since your last session: a new ${h.label} in ${show(h.file)} (${h.command.slice(0, 80)})`);
  for (const h of d.hooks.changed) taint.push(`changed since your last session: the ${h.label} in ${show(h.file)} now runs ${h.to.slice(0, 80)}`);
  for (const h of d.hooks.removed) logged.push(`since your last session: the ${h.label} in ${show(h.file)} was removed`);
  for (const s of d.servers.added) taint.push(`changed since your last session: a new MCP server "${s.name}" in ${show(s.file)} (${s.launch.slice(0, 80)})`);
  for (const s of d.servers.pin_changed) taint.push(`changed since your last session: MCP server "${s.name}" in ${show(s.file)} now launches ${s.to.launch.slice(0, 80)}`);
  for (const s of d.servers.removed) logged.push(`since your last session: MCP server "${s.name}" in ${show(s.file)} was removed`);
  // I10: hook scripts and skills are code the agent runs: any change to them is a change to what runs.
  const code = (p: string): boolean => /(?:^|\/)\.claude\/hooks\/|(?:^|\/)(?:\.claude|\.agents)\/skills\//.test(p);
  for (const p of d.files.added.filter(code)) taint.push(`changed since your last session: ${show(p)} was added`);
  for (const p of d.files.changed.filter(code)) taint.push(`changed since your last session: ${show(p)} changed`);
  for (const p of d.files.removed.filter(code)) taint.push(`changed since your last session: ${show(p)} was removed`);
  const memoryPaths = new Set([...d.memory.added, ...d.memory.changed, ...d.memory.removed]);
  for (const p of d.files.changed) if (!code(p) && !memoryPaths.has(p)) logged.push(`since your last session: ${show(p)} changed`);
  // A finding that is new in a file that changed (with the same rules): what changed brought it. Memory has its own sentence below.
  if (d.rules_changed === null) {
    const touched = new Set([...d.files.added, ...d.files.changed]);
    for (const f of d.findings.new) {
      if (!touched.has(f.path) || memoryPaths.has(f.path) || f.severity === "low") continue;
      taint.push(`changed since your last session: ${show(f.path)} gained ${f.rule} (${f.severity}, line ${f.line})`);
    }
  }
  const sentence = memoryDriftSentence(d.memory);
  if (sentence !== null) {
    const drifted = new Set([...d.memory.added, ...d.memory.changed].map(show));
    const flagged = snapshot.findings.filter((f) => f.scope === scope && drifted.has(f.file));
    const text = sentence.replace("since the last receipt", "since your last session");
    // The agent writes its own memory every day; a change is a reason to distrust the session when the changed
    // files carry something a rule flags (an instruction to send data out, a standing override, hidden text).
    if (flagged.length > 0) taint.push(`changed since your last session: ${text} The changed memory carries ${[...new Set(flagged.map((f) => `${f.ruleId} (${where(f)})`))].join(", ")}`);
    else logged.push(text);
  }
}

/**
 * The whole SessionStart check for one session: collect, analyze (or reuse the cache), judge findings
 * and drift, store the receipts, and return the state events. Never throws: a failure is a taint.
 */
export function runSessionScan(o: ScanOptions): SessionScan {
  const t0 = performance.now();
  const out: SessionScan = { events: [], untrustedBecause: [], logged: [], rules: [], incomplete: [], servers: [], cached: false, ms: 0 };
  const taintSources: string[] = [];
  try {
    const collection = collectAgentFiles({ workspace: o.workspace, home: o.home, configDir: o.configDir, ...(o.claudeJson !== undefined ? { claudeJson: o.claudeJson } : {}), userScope: o.cfg.agentScan.userScope, serversOnly: !o.cfg.agentScan.enabled, managedSettings: o.managedSettings, managedMcp: o.managedMcp, budgetMs: o.budgetMs, ...(o.clock !== undefined ? { clock: o.clock } : {}) });
    out.servers = collection.servers;
    out.incomplete = collection.incomplete;
    if (collection.skipped.length > 0) out.logged.push(`not checked (larger than 512 KB): ${collection.skipped.slice(0, 5).join(", ")}`);
    // I8/I9/B2: what the collection could not check. A repository (and the memory the agent writes) controls it: taint.
    // The user's own files (a dotfiles symlink, a large ~/.claude.json) are logged; the administrator's never count.
    for (const p of collection.problems) {
      const text = `agent configuration could not be fully checked: ${p.display} (${p.why})`;
      if (o.cfg.agentScan.enabled && o.cfg.agentScan.taintOn !== "never" && (p.scope === "workspace" || p.scope === "memory")) taintSources.push(text);
      else out.logged.push(text);
    }
    if (!o.cfg.agentScan.enabled) {
      out.ms = performance.now() - t0;
      return out;
    }
    // I7: an agent file the check could not read is one whose instructions are unknown: the session starts untrusted,
    // naming it (a repository can make a file too large, or a symlink to anywhere, on purpose).
    if (collection.skipped.length > 0) taintSources.push(`agent files too large to check (over 512 KB): ${collection.skipped.slice(0, 5).join(", ")}`);
    if ((collection.dropped ?? []).length > 0) taintSources.push(`agent files that are symbolic links out of their folder, so not checked: ${(collection.dropped ?? []).slice(0, 5).join(", ")}`);
    // R7: a repository decides how many agent files it holds. Past the file or byte cap, a file could be
    // hidden behind filler, so the session starts untrusted. Running out of time inside the agent trees
    // counts too; the directory cap and a time-out in the generic walk for nested instruction files
    // reflect ordinary repository size and the machine, and stay logged only.
    if (collection.workspaceCapped === true) taintSources.push(`the workspace holds more agent files than the check reads (${collection.incomplete.filter((x) => /agent files|time budget/.test(x)).join("; ")}), so a file past the limit could not be checked`);
    const { snapshot, cached } = scanSnapshot(o, collection);
    out.cached = cached;
    if (snapshot.error !== undefined) {
      taintSources.push(`agent configuration could not be checked (${snapshot.error.slice(0, 120)})`);
    } else {
      out.rules = [...new Set(snapshot.findings.map((f) => f.ruleId))];
      for (const f of snapshot.findings) {
        if (taints(f, o.cfg)) {
          taintSources.push(`agent configuration: ${f.ruleId} in ${where(f)}`);
          if (f.family === "secret_in_config") out.events.push({ type: "sensitive", source: `agent configuration: ${f.ruleId} in ${where(f)}` });
        } else out.logged.push(`${f.severity} ${f.ruleId} in ${where(f)}: ${f.title}`);
      }
      const stored = readReceipts(o.l, o.workspace);
      if (stored === "corrupt") taintSources.push("the record of the agent's setup from your last session was unreadable, so changes since then could not be checked");
      else if (stored !== "missing") for (const scope of DRIFT_SCOPES) judgeDrift(snapshot, stored, scope, taintSources, out.logged);
      const next: StoredReceipts = {};
      for (const scope of DRIFT_SCOPES) {
        const r = snapshot.receipts[scope];
        if (r !== undefined) next[scope] = r;
      }
      writeIfChanged(receiptsPath(o.l, o.workspace), `${JSON.stringify(next as unknown as JsonValue)}\n`);
    }
  } catch (e) {
    taintSources.push(`agent configuration could not be checked (${(e as Error).message.slice(0, 120)})`);
  }
  for (const s of taintSources) out.events.push({ type: "taint", source: s.slice(0, 300) });
  out.untrustedBecause = taintSources;
  out.ms = performance.now() - t0;
  try {
    const last: LastScan = { at: o.now.toISOString(), tainted: taintSources, logged: out.logged.slice(0, 50), incomplete: out.incomplete };
    const path = lastScanPath(o.l, o.workspace);
    const text = `${JSON.stringify(last)}\n`;
    const norm = (t: string): string => t.replace(/"at":"[^"]*",/, "");
    const old = readText(path);
    if (old === null || norm(old) !== norm(text)) quickWrite(path, text);
  } catch {
    // Only doctor reads it.
  }
  return out;
}
