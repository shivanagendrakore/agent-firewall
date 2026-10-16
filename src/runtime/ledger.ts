/**
 * F-e: the provenance ledger. A record of files (and directories) the agent wrote itself, with the
 * hash of the content it left behind and whether the writing session was untrusted at the time.
 *
 * - A file whose current content is exactly what a trusted session wrote is self-authored: reading it
 *   does not bring outside content in, wherever it lives.
 * - A file whose current content an untrusted session wrote stays untrusted in later sessions (running
 *   it, or a manifest that is it).
 * - Any doubt (no entry, a hash that no longer matches, a file too large to hash, an unreadable ledger)
 *   returns null, and the engine falls back to the v0.1 classification. Never looser.
 *
 * Files under <firewallHome>/ledger/ (all covered by FW-TAMPER, like the rest of the data directory):
 *   files.jsonl  append-only, one LedgerEntry per write; the latest by writtenAt wins
 *   dirs.jsonl   append-only, one DirEntry per directory a session created
 *   index.json   the compacted map at the last compaction, with the byte offsets it covers
 *   prior.jsonl  notes taken in PreToolUse about what a partial write is about to change (see notePrior)
 *
 * Writes and reads happen under one lock, so a reader never sees a half-written line: a line without
 * its newline is a truncated (corrupt) ledger, not a write in progress.
 */

import { createHash } from "node:crypto";
import { closeSync, lstatSync, openSync, readFileSync, readSync, statSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { downloadsOf } from "../engine/effects.js";
import { normalizeAbs } from "../engine/paths.js";
import type { Context, Effect, Finding, FirewallConfig } from "../types.js";
import { appendDurable, atomicWrite, withLock } from "./fsutil.js";
import { safeId, type Layout } from "./layout.js";
import { realpathLoose } from "./realpath.js";

export interface LedgerEntry {
  /** Real path, normalized (not case-folded; the lookup key is). */
  path: string;
  /** Of the full content after the write. */
  sha256: string;
  size: number;
  writtenAt: string;
  session: string;
  taintedAtWrite: boolean;
  /** "Write" | "Edit" | "MultiEdit" | "NotebookEdit" | "shell:<program>" | "download" */
  via: string;
}

export interface DirEntry {
  path: string;
  createdAt: string;
  session: string;
  taintedAtWrite: boolean;
}

/** What a partial write (an edit, an append, a shell write) was about to change, noted before it ran. */
export interface PriorNote {
  path: string;
  session: string;
  at: string;
  existed: boolean;
  dir: boolean;
  /** absent: nothing there; self: content a trusted session wrote; self-tainted: an untrusted one; foreign: anything else. */
  prior: "absent" | "self" | "self-tainted" | "foreign";
}

export interface LedgerView {
  files: Map<string, LedgerEntry>;
  dirs: Map<string, DirEntry>;
}

export interface LedgerLimits {
  /** Compact at SessionStart when files.jsonl + dirs.jsonl are larger than this. */
  compactBytes: number;
  /** Compact on a write when they are larger than this (a long session without a SessionStart). */
  hardBytes: number;
  maxAgeDays: number;
  maxPaths: number;
  /** prior.jsonl is compacted beyond this. Only its tail is ever read. */
  priorBytes: number;
}

export const DEFAULT_LIMITS: LedgerLimits = { compactBytes: 5 * 1024 * 1024, hardBytes: 10 * 1024 * 1024, maxAgeDays: 90, maxPaths: 100_000, priorBytes: 256 * 1024 };

/** Prior notes older than this are not used (the PostToolUse of an action follows its PreToolUse). */
const NOTE_MAX_AGE_MS = 6 * 60 * 60 * 1000;
const NOTE_TAIL_BYTES = 64 * 1024;
const READ_LOCK_TIMEOUT_MS = 3000;
/**
 * The size up to which content an untrusted session wrote is always hashed, whatever maxHashBytes says:
 * a lower limit (which a project policy may set) only narrows the trust given to self-authored files,
 * it cannot switch off the cross-session carry.
 */
export const CARRY_HASH_BYTES = 4 * 1024 * 1024;

export class LedgerCorrupt extends Error {}

export function ledgerDir(l: Layout): string {
  return join(l.home, "ledger");
}

const files = (l: Layout): string => join(ledgerDir(l), "files.jsonl");
const dirsFile = (l: Layout): string => join(ledgerDir(l), "dirs.jsonl");
const indexFile = (l: Layout): string => join(ledgerDir(l), "index.json");
const priorFile = (l: Layout): string => join(ledgerDir(l), "prior.jsonl");
const lockFile = (l: Layout): string => join(ledgerDir(l), "ledger.lock");

function caseInsensitiveFs(): boolean {
  return process.platform === "darwin" || process.platform === "win32";
}

/** The real, normalized path of an absolute path (which may not exist yet). */
export function realOf(abs: string): string {
  return normalizeAbs(realpathLoose(normalizeAbs(abs)));
}

export function pathKey(abs: string, ci = caseInsensitiveFs()): string {
  const r = realOf(abs);
  return ci ? r.toLowerCase() : r;
}

// --- validation -------------------------------------------------------------------------------------

const SHA = /^[0-9a-f]{64}$/;

function isIso(v: unknown): v is string {
  return typeof v === "string" && v.length <= 40 && !Number.isNaN(Date.parse(v));
}

function isAbsPath(v: unknown): v is string {
  return typeof v === "string" && v.startsWith("/") && v.length <= 4096 && !v.includes("\0");
}

function parseEntry(o: unknown): LedgerEntry {
  const e = o as Record<string, unknown>;
  if (typeof o !== "object" || o === null || !isAbsPath(e.path) || typeof e.sha256 !== "string" || !SHA.test(e.sha256) || typeof e.size !== "number" || !Number.isInteger(e.size) || e.size < 0 || !isIso(e.writtenAt) || typeof e.session !== "string" || e.session.length > 200 || typeof e.taintedAtWrite !== "boolean" || typeof e.via !== "string" || e.via.length > 200) {
    throw new LedgerCorrupt("a ledger entry is malformed");
  }
  return { path: e.path, sha256: e.sha256, size: e.size, writtenAt: e.writtenAt, session: e.session, taintedAtWrite: e.taintedAtWrite, via: e.via };
}

function parseDir(o: unknown): DirEntry {
  const e = o as Record<string, unknown>;
  if (typeof o !== "object" || o === null || !isAbsPath(e.path) || !isIso(e.createdAt) || typeof e.session !== "string" || e.session.length > 200 || typeof e.taintedAtWrite !== "boolean") {
    throw new LedgerCorrupt("a directory entry is malformed");
  }
  return { path: e.path, createdAt: e.createdAt, session: e.session, taintedAtWrite: e.taintedAtWrite };
}

function parseNote(o: unknown): PriorNote | null {
  const e = o as Record<string, unknown>;
  if (typeof o !== "object" || o === null || !isAbsPath(e.path) || typeof e.session !== "string" || !isIso(e.at) || typeof e.existed !== "boolean" || typeof e.dir !== "boolean") return null;
  if (e.prior !== "absent" && e.prior !== "self" && e.prior !== "self-tainted" && e.prior !== "foreign") return null;
  return { path: e.path, session: e.session, at: e.at, existed: e.existed, dir: e.dir, prior: e.prior };
}

// --- reading ----------------------------------------------------------------------------------------

function readBuf(p: string): Buffer | null {
  try {
    return readFileSync(p);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw e;
  }
}

/** Parses JSONL. Strict: any bad or unterminated line is corruption. Lenient: bad lines are skipped. */
function lines<T>(text: string, parse: (o: unknown) => T, strict: boolean): T[] {
  const out: T[] = [];
  if (text === "") return out;
  if (strict && !text.endsWith("\n")) throw new LedgerCorrupt("the ledger ends in the middle of a line");
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    try {
      out.push(parse(JSON.parse(line)));
    } catch (e) {
      if (strict) throw e instanceof LedgerCorrupt ? e : new LedgerCorrupt("a ledger line is not valid JSON");
    }
  }
  return out;
}

function putFile(m: Map<string, LedgerEntry>, e: LedgerEntry, ci: boolean): void {
  const k = ci ? e.path.toLowerCase() : e.path;
  const cur = m.get(k);
  if (cur === undefined) {
    m.set(k, e);
    return;
  }
  // Untrusted is sticky per content: a trusted entry for the same bytes never clears an untrusted one (a clean
  // session reporting a write of what an untrusted one left would otherwise launder it). Only new content is trusted.
  const sticky = cur.sha256 === e.sha256 && cur.size === e.size && (cur.taintedAtWrite || e.taintedAtWrite);
  if (e.writtenAt >= cur.writtenAt) m.set(k, sticky && !e.taintedAtWrite ? { ...e, taintedAtWrite: true } : e);
  else if (sticky && !cur.taintedAtWrite) m.set(k, { ...cur, taintedAtWrite: true });
}

function putDir(m: Map<string, DirEntry>, e: DirEntry, ci: boolean): void {
  const k = ci ? e.path.toLowerCase() : e.path;
  const cur = m.get(k);
  if (cur === undefined || e.createdAt >= cur.createdAt) m.set(k, e);
}

interface IndexDoc {
  version: 1;
  filesOffset: number;
  dirsOffset: number;
  files: unknown[];
  dirs: unknown[];
}

/** Reads the whole ledger (index plus the tail after it). Caller holds the lock. Throws LedgerCorrupt. */
function readView(l: Layout, ci: boolean, strict = true): LedgerView {
  const view: LedgerView = { files: new Map(), dirs: new Map() };
  let filesOffset = 0;
  let dirsOffset = 0;
  const idx = readBuf(indexFile(l));
  if (idx !== null) {
    let doc: IndexDoc;
    try {
      doc = JSON.parse(idx.toString("utf8")) as IndexDoc;
    } catch {
      throw new LedgerCorrupt("the ledger index is not valid JSON");
    }
    if (doc.version !== 1 || !Number.isInteger(doc.filesOffset) || !Number.isInteger(doc.dirsOffset) || doc.filesOffset < 0 || doc.dirsOffset < 0 || !Array.isArray(doc.files) || !Array.isArray(doc.dirs)) throw new LedgerCorrupt("the ledger index is malformed");
    for (const o of doc.files) putFile(view.files, parseEntry(o), ci);
    for (const o of doc.dirs) putDir(view.dirs, parseDir(o), ci);
    filesOffset = doc.filesOffset;
    dirsOffset = doc.dirsOffset;
  }
  const f = readBuf(files(l)) ?? Buffer.alloc(0);
  const d = readBuf(dirsFile(l)) ?? Buffer.alloc(0);
  if (f.length < filesOffset || d.length < dirsOffset) throw new LedgerCorrupt("the ledger is shorter than its index says");
  if (filesOffset > 0 && f[filesOffset - 1] !== 0x0a) throw new LedgerCorrupt("the ledger index does not end on a line boundary");
  if (dirsOffset > 0 && d[dirsOffset - 1] !== 0x0a) throw new LedgerCorrupt("the directory ledger index does not end on a line boundary");
  for (const e of lines(f.subarray(filesOffset).toString("utf8"), parseEntry, strict)) putFile(view.files, e, ci);
  for (const e of lines(d.subarray(dirsOffset).toString("utf8"), parseDir, strict)) putDir(view.dirs, e, ci);
  return view;
}

function statKey(p: string): string {
  try {
    const s = statSync(p);
    return `${s.size}:${s.mtimeMs}:${s.ino}`;
  } catch {
    return "-";
  }
}

const cache = new Map<string, { key: string; view: LedgerView }>();

/**
 * The ledger as a map, or null when it cannot be trusted (unreadable, malformed, truncated, the lock
 * not obtainable). Cached per process by the files' size and modification time.
 */
export function loadLedger(l: Layout, ci = caseInsensitiveFs()): LedgerView | null {
  try {
    return loadLedgerOrThrow(l, ci);
  } catch {
    return null;
  }
}

function loadLedgerOrThrow(l: Layout, ci: boolean): LedgerView {
  const key = `${ci ? "i" : "s"}|${statKey(indexFile(l))}|${statKey(files(l))}|${statKey(dirsFile(l))}`;
  const hit = cache.get(l.home);
  if (hit !== undefined && hit.key === key) return hit.view;
  if (key.endsWith("|-|-|-")) return { files: new Map(), dirs: new Map() };
  const view = withLock(lockFile(l), () => readView(l, ci), { timeoutMs: READ_LOCK_TIMEOUT_MS });
  cache.set(l.home, { key, view });
  return view;
}

/** For doctor: whether the ledger can be read, and how big it is. */
export function ledgerHealth(l: Layout): { ok: boolean; detail: string } {
  try {
    const v = loadLedgerOrThrow(l, caseInsensitiveFs());
    return { ok: true, detail: `${v.files.size} file(s) and ${v.dirs.size} director${v.dirs.size === 1 ? "y" : "ies"} the agent wrote` };
  } catch (e) {
    return { ok: false, detail: `provenance ledger unreadable (${(e as Error).message}); files the agent wrote are treated as outside content until the next session start repairs it` };
  }
}

// --- hashing ----------------------------------------------------------------------------------------

/** The hash of a regular file's full content, or null (missing, a directory, larger than max, unreadable). */
export function hashFile(abs: string, maxBytes: number): { sha256: string; size: number } | null {
  let fd: number | null = null;
  try {
    const st = statSync(abs);
    if (!st.isFile() || st.size > maxBytes) return null;
    fd = openSync(abs, "r");
    const h = createHash("sha256");
    const buf = Buffer.allocUnsafe(64 * 1024);
    let total = 0;
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n <= 0) break;
      total += n;
      if (total > maxBytes) return null;
      h.update(buf.subarray(0, n));
    }
    return { sha256: h.digest("hex"), size: total };
  } catch {
    return null;
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

// --- lookups for the engine (Context.provenance / Context.dirProvenance) ----------------------------

export interface Provenance {
  selfAuthored: boolean;
  taintedAtWrite: boolean;
}

/** The provenance of a file's current content: null when unknown (no entry, too large, unreadable ledger). */
export function provenanceOf(l: Layout, abs: string, maxHashBytes: number, ci = caseInsensitiveFs()): Provenance | null {
  const view = loadLedger(l, ci);
  if (view === null || view.files.size === 0) return null;
  // Fast path for the many candidate files a check names that do not exist (R8's config list): no realpath, no exception.
  if (lstatSync(abs, { throwIfNoEntry: false }) === undefined) return null;
  const real = realOf(abs);
  const e = view.files.get(ci ? real.toLowerCase() : real);
  if (e === undefined) return null;
  const h = hashFile(real, e.taintedAtWrite ? Math.max(maxHashBytes, CARRY_HASH_BYTES) : maxHashBytes);
  if (h === null) return null;
  return { selfAuthored: h.sha256 === e.sha256 && h.size === e.size, taintedAtWrite: e.taintedAtWrite };
}

export function dirProvenanceOf(l: Layout, abs: string, ci = caseInsensitiveFs()): { createdBySession: boolean; taintedAtWrite: boolean } | null {
  const view = loadLedger(l, ci);
  if (view === null) return null;
  const real = realOf(abs);
  const d = view.dirs.get(ci ? real.toLowerCase() : real);
  if (d === undefined) return null;
  try {
    if (!statSync(real).isDirectory()) return null;
  } catch {
    return null;
  }
  return { createdBySession: true, taintedAtWrite: d.taintedAtWrite };
}

/** The runtime's hook point: gives the engine its provenance lookups (the engine stays pure). */
export function attachProvenance(ctx: Context, l: Layout, cfg: FirewallConfig): void {
  const max = cfg.provenance.maxHashBytes;
  ctx.provenance = (abs: string) => provenanceOf(l, abs, max, ctx.caseInsensitive);
  ctx.dirProvenance = (abs: string) => dirProvenanceOf(l, abs, ctx.caseInsensitive);
}

// --- recording --------------------------------------------------------------------------------------

/** The tools whose writes are recorded. Others (MCP tools, unknown tools) write content the firewall cannot see. */
export const RECORDED_TOOLS: ReadonlySet<string> = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"]);
const WRITE_CLASSES: ReadonlySet<Effect["cls"]> = new Set(["write_workspace", "write_outside_workspace", "write_persistence", "write_protected"]);

/** The write effects that name a concrete file the action leaves content in (not a deletion, not a glob). */
function writeTargets(effects: readonly Effect[]): Effect[] {
  // writePath() describes deletions (rm, the source of mv) as "delete ...": those leave no content.
  return effects.filter((e) => WRITE_CLASSES.has(e.cls) && e.download === undefined && e.target.startsWith("/") && !/[*?[\]{}]/.test(e.target) && !e.detail.startsWith("delete "));
}

function viaOf(tool: string, e: Effect): string {
  if (tool !== "Bash") return tool;
  const m = /\(([A-Za-z0-9_.+-]{1,40})\)$/.exec(e.detail);
  return m !== null ? `shell:${m[1] as string}` : "shell";
}

function appendLines(path: string, rows: readonly unknown[]): void {
  if (rows.length === 0) return;
  appendDurable(path, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
}

function sizeOf(p: string): number {
  try {
    return statSync(p).size;
  } catch {
    return 0;
  }
}

/** The latest prior note this session took for a path, from the tail of prior.jsonl. */
function latestNote(l: Layout, session: string, key: string, ci: boolean, now: number): PriorNote | null {
  let text = "";
  let fd: number | null = null;
  try {
    const size = statSync(priorFile(l)).size;
    const start = Math.max(0, size - NOTE_TAIL_BYTES);
    fd = openSync(priorFile(l), "r");
    const buf = Buffer.alloc(size - start);
    readSync(fd, buf, 0, buf.length, start);
    text = buf.toString("utf8");
    if (start > 0) text = text.slice(text.indexOf("\n") + 1);
  } catch {
    return null;
  } finally {
    if (fd !== null) closeSync(fd);
  }
  let found: PriorNote | null = null;
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    let n: PriorNote | null = null;
    try {
      n = parseNote(JSON.parse(line));
    } catch {
      n = null;
    }
    if (n === null || n.session !== session || (ci ? n.path.toLowerCase() : n.path) !== key) continue;
    if (now - Date.parse(n.at) > NOTE_MAX_AGE_MS) continue;
    found = n;
  }
  return found;
}

export interface NoteInput {
  l: Layout;
  sessionId: string;
  tool: string;
  effects: readonly Effect[];
  maxHashBytes: number;
  ci?: boolean;
  now?: Date;
}

/**
 * PreToolUse, for an action that will run: a partial write (an edit, an append, any shell write) keeps
 * part of what was there, so before it runs, note what that was. Only for targets outside the workspace
 * (where reading taints); inside it, PostToolUse inherits the previous writer's taint instead.
 */
export function notePrior(i: NoteInput): void {
  if (!RECORDED_TOOLS.has(i.tool) || i.tool === "Write") return;
  const targets = writeTargets(i.effects).filter((e) => e.cls !== "write_workspace");
  if (targets.length === 0) return;
  const ci = i.ci ?? caseInsensitiveFs();
  const sid = safeId(i.sessionId);
  const at = (i.now ?? new Date()).toISOString();
  const notes: PriorNote[] = [];
  for (const e of targets) {
    const real = realOf(e.target);
    let existed = false;
    let dir = false;
    try {
      const st = lstatSync(real);
      existed = true;
      dir = st.isDirectory();
    } catch {
      existed = false;
    }
    let prior: PriorNote["prior"] = "absent";
    if (existed) {
      const p = dir ? null : provenanceOf(i.l, real, i.maxHashBytes, ci);
      prior = p === null || !p.selfAuthored ? "foreign" : p.taintedAtWrite ? "self-tainted" : "self";
    }
    notes.push({ path: real, session: sid, at, existed, dir, prior });
  }
  withLock(lockFile(i.l), () => appendLines(priorFile(i.l), notes));
}

export interface RecordInput {
  l: Layout;
  sessionId: string;
  tool: string;
  /** The action's effects, re-derived in PostToolUse with the provenance lookups attached. */
  effects: readonly Effect[];
  findings: readonly Finding[];
  /** The session was untrusted before this action. */
  taintedBefore: boolean;
  maxHashBytes: number;
  ci?: boolean;
  now?: Date;
  limits?: LedgerLimits;
}

/**
 * PostToolUse: record what the action left on disk. Content counts as written by an untrusted session
 * when the session was untrusted before, when the same action brought outside content in (cp from a
 * download, curl > f), when a write target was only known at run time, or when a partial write kept
 * content that was not the agent's own (or was an untrusted session's).
 */
export function recordWrites(i: RecordInput): { files: number; dirs: number } {
  if (!RECORDED_TOOLS.has(i.tool)) return { files: 0, dirs: 0 };
  const ci = i.ci ?? caseInsensitiveFs();
  const now = i.now ?? new Date();
  const at = now.toISOString();
  const sid = safeId(i.sessionId);
  const base = i.taintedBefore || i.effects.some((e) => e.taints === true) || i.findings.some((f) => f.id === "unresolvable_write_target");
  const fileRows: LedgerEntry[] = [];
  const dirRows: DirEntry[] = [];
  const seen = new Set<string>();
  // Downloads: outside content wherever they land, in this session and later ones.
  for (const d of i.effects.flatMap(downloadsOf)) {
    if (!d.startsWith("/")) continue;
    const real = realOf(d);
    const key = ci ? real.toLowerCase() : real;
    if (seen.has(key)) continue;
    seen.add(key);
    const h = hashFile(real, Math.max(i.maxHashBytes, CARRY_HASH_BYTES));
    if (h !== null) fileRows.push({ path: real, sha256: h.sha256, size: h.size, writtenAt: at, session: sid, taintedAtWrite: true, via: "download" });
  }
  const targets = writeTargets(i.effects);
  const view = targets.length > 0 ? loadLedger(i.l, ci) : null;
  for (const e of targets) {
    const real = realOf(e.target);
    const key = ci ? real.toLowerCase() : real;
    if (seen.has(key)) continue;
    seen.add(key);
    let isDir = false;
    try {
      isDir = statSync(real).isDirectory();
    } catch {
      continue; // The tool failed or removed it: nothing to record.
    }
    const note = e.cls === "write_workspace" || i.tool === "Write" ? null : latestNote(i.l, sid, key, ci, now.getTime());
    if (isDir) {
      // Only a directory this action created (it was not there before), and only outside the workspace.
      if (note !== null && !note.existed) dirRows.push({ path: real, createdAt: at, session: sid, taintedAtWrite: base });
      continue;
    }
    const prior = view?.files.get(key);
    let tainted = base;
    if (i.tool !== "Write") {
      if (e.cls === "write_workspace") {
        // Inside the workspace: an untrusted session's earlier content carries on into the new version
        // (an unreadable ledger counts as such: no entry is then written trusted over it).
        if (view === null || prior?.taintedAtWrite === true) tainted = true;
      } else if (note === null || note.prior === "foreign" || note.prior === "self-tainted") {
        tainted = true;
      }
    }
    const h = hashFile(real, tainted || prior?.taintedAtWrite === true ? Math.max(i.maxHashBytes, CARRY_HASH_BYTES) : i.maxHashBytes);
    if (h === null) continue;
    // Untrusted is sticky per content: the exact bytes an untrusted session left stay untrusted, whoever reports a
    // write of them later; and with an unreadable ledger nothing is written trusted.
    if (!tainted && (view === null || (prior?.taintedAtWrite === true && prior.sha256 === h.sha256 && prior.size === h.size))) tainted = true;
    fileRows.push({ path: real, sha256: h.sha256, size: h.size, writtenAt: at, session: sid, taintedAtWrite: tainted, via: viaOf(i.tool, e) });
  }
  if (fileRows.length === 0 && dirRows.length === 0) return { files: 0, dirs: 0 };
  const limits = i.limits ?? DEFAULT_LIMITS;
  withLock(lockFile(i.l), () => {
    appendLines(files(i.l), fileRows);
    appendLines(dirsFile(i.l), dirRows);
    if (sizeOf(files(i.l)) + sizeOf(dirsFile(i.l)) > limits.hardBytes) compactLocked(i.l, ci, limits, now.getTime());
  });
  return { files: fileRows.length, dirs: dirRows.length };
}

// --- compaction -------------------------------------------------------------------------------------

function existsAs(p: string, dir: boolean): boolean {
  try {
    const st = statSync(p);
    return dir ? st.isDirectory() : st.isFile();
  } catch {
    return false;
  }
}

/**
 * Rewrites the ledger: the latest entry per path, younger than maxAgeDays, for files that still exist,
 * at most maxPaths (oldest dropped). A corrupt ledger is repaired by keeping its readable entries that
 * an untrusted session wrote and dropping the rest: stricter than before, never looser.
 */
function compactLocked(l: Layout, ci: boolean, limits: LedgerLimits, now: number): { kept: number; repaired: boolean } {
  let view: LedgerView;
  let repaired = false;
  try {
    view = readView(l, ci, true);
  } catch {
    repaired = true;
    view = { files: new Map(), dirs: new Map() };
    try {
      const lenient = readView(l, ci, false);
      for (const [k, e] of lenient.files) if (e.taintedAtWrite) view.files.set(k, e);
      for (const [k, d] of lenient.dirs) if (d.taintedAtWrite) view.dirs.set(k, d);
    } catch {
      // The index itself is unreadable: start again from nothing.
      for (const e of lines((readBuf(files(l)) ?? Buffer.alloc(0)).toString("utf8"), parseEntry, false)) if (e.taintedAtWrite) putFile(view.files, e, ci);
    }
  }
  const cutoff = now - limits.maxAgeDays * 86400000;
  const fileList = [...view.files.values()].filter((e) => Date.parse(e.writtenAt) >= cutoff && existsAs(e.path, false)).sort((a, b) => b.writtenAt.localeCompare(a.writtenAt)).slice(0, limits.maxPaths);
  const dirList = [...view.dirs.values()].filter((d) => Date.parse(d.createdAt) >= cutoff && existsAs(d.path, true)).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, limits.maxPaths);
  const fText = fileList.map((e) => JSON.stringify(e)).join("\n") + (fileList.length > 0 ? "\n" : "");
  const dText = dirList.map((e) => JSON.stringify(e)).join("\n") + (dirList.length > 0 ? "\n" : "");
  // Index first out of the way: a crash between the steps leaves a ledger that replays from the start.
  try {
    unlinkSync(indexFile(l));
  } catch {
    // No index yet.
  }
  atomicWrite(files(l), fText);
  atomicWrite(dirsFile(l), dText);
  const idx: IndexDoc = { version: 1, filesOffset: Buffer.byteLength(fText), dirsOffset: Buffer.byteLength(dText), files: fileList, dirs: dirList };
  atomicWrite(indexFile(l), JSON.stringify(idx));
  // Prior notes are only needed between a PreToolUse and its PostToolUse.
  const notes = lines((readBuf(priorFile(l)) ?? Buffer.alloc(0)).toString("utf8"), parseNote, false).filter((n): n is PriorNote => n !== null && now - Date.parse(n.at) <= NOTE_MAX_AGE_MS);
  atomicWrite(priorFile(l), notes.map((n) => JSON.stringify(n)).join("\n") + (notes.length > 0 ? "\n" : ""));
  cache.delete(l.home);
  return { kept: fileList.length, repaired };
}

/** SessionStart (startup): compact when the ledger is large, its notes have grown, or it is unreadable. */
export function maintainLedger(l: Layout, opts: { limits?: LedgerLimits; ci?: boolean; now?: number; force?: boolean } = {}): { compacted: boolean; repaired: boolean } {
  const limits = opts.limits ?? DEFAULT_LIMITS;
  const ci = opts.ci ?? caseInsensitiveFs();
  const big = sizeOf(files(l)) + sizeOf(dirsFile(l)) > limits.compactBytes || sizeOf(priorFile(l)) > limits.priorBytes;
  const broken = loadLedger(l, ci) === null;
  if (!big && !broken && opts.force !== true) return { compacted: false, repaired: false };
  const r = withLock(lockFile(l), () => compactLocked(l, ci, limits, opts.now ?? Date.now()));
  return { compacted: true, repaired: r.repaired };
}
