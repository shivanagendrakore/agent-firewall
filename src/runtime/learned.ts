/**
 * Learned project choices ("Fewer prompts", docs/usage.md): what the person chose for one exact action in
 * one project ("always" or "never"), and the counts the firewall offers "always" from.
 *
 * Everything lives in the firewall's own home (`<home>/learned/`), which the agent may never write and a
 * repository never reaches: a project policy file has no key for allows (validation refuses one), and
 * nothing in a checkout is read here. An "always" entry counts only when its Ed25519 signature verifies
 * against the approver key the hook trusts (pinned in the hook command), so a forged or edited entry is
 * ignored; a "never" entry only tightens and counts as written. decide() re-checks every guarantee of an
 * "always" entry on each use (src/engine/learn.ts).
 *
 * "never" entries are kept twice, in allows.json and in nevers.json, so damage to one file never lifts a
 * "never"; a damaged allows.json applies no "always" at all (those actions are asked again), and nothing is
 * written while either file is damaged (a write would drop what cannot be read).
 *
 * M1: an entry's signature covers its rules (learned message v3; v2 entries from before still verify), and
 * a person-run command holding the key seals the whole set (a signed generation and digest of every entry,
 * in both files). A set changed outside the CLI (an entry added, or a "never" deleted from both files)
 * breaks the seal: no "always" applies, doctor warns, and the CLI refuses to write until it is looked at.
 * Not covered: putting back an older sealed copy of both files (an earlier generation) is not detected.
 *
 * candidates.json counts, per project and action, how often the firewall asked and how often a person
 * said yes: an answered Claude Code prompt (the tool then ran: PostToolUse) or a queue approval (the
 * approved retry). The counts only decide when the offer is shown; accepting it needs the person.
 */

import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { atomicWrite, ensureDir, readText, withLock } from "./fsutil.js";
import type { Layout } from "./layout.js";
import { approverPublicKey, learnedSignature, verifyLearned, verifyLearnedSeal } from "./approver.js";
import { allowKey, rulesEligibility, type LearnedView } from "../engine/learn.js";

const MAX_CANDIDATES = 500;
const MAX_PENDING = 10;
const MAX_DATES = 10;
/** An answered prompt is counted when its tool finishes within this time of the ask. */
const PENDING_TTL_MS = 2 * 3600 * 1000;
const MAX_SUMMARY = 300;
/** 32 symbols, 5 bits each: a code is 21 of them (105 bits), so one cannot be guessed or collide. */
const ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789";
const CODE_LENGTH = 21;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

export interface LearnedEntry {
  version: 1;
  /** The same code as the candidate it came from (one entry per project and action). */
  id: string;
  kind: "allow" | "never";
  project: string;
  key: string;
  /** The tool's identity the choice was made under (an MCP server's pin, or the agent); "" for "never". */
  identity: string;
  tool: string;
  summary: string;
  /** The rules that asked when it was chosen (an "allow" entry is honoured only while they are all learnable). */
  rules: string[];
  /** How many times the person had approved it when they chose. */
  approvals: number;
  createdAt: string;
  /** Ed25519 by the approver key over learnedMessage(); required for "allow", added to "never" when a passphrase is set. */
  sig?: string;
}

export interface Candidate {
  code: string;
  project: string;
  key: string;
  /** The tool's identity at the last ask (null: an MCP server with no current pin, never learnable). */
  identity: string | null;
  tool: string;
  summary: string;
  rules: string[];
  /** Whether the action itself could be learned (the session is checked on each use). */
  eligible: boolean;
  why?: string;
  asked: number;
  approved: number;
  /** When the person said yes, most recent last (shown with the offer). */
  approvedAt: string[];
  firstAt: string;
  lastAt: string;
  /** Prompts shown and not yet answered: counted as approved when the tool runs (session, action hash). */
  pending: { session: string; hash: string; at: number }[];
}

export function learnedDir(l: Layout): string {
  return join(l.home, "learned");
}

export function allowsPath(l: Layout): string {
  return join(learnedDir(l), "allows.json");
}

export function neversPath(l: Layout): string {
  return join(learnedDir(l), "nevers.json");
}

function candidatesPath(l: Layout): string {
  return join(learnedDir(l), "candidates.json");
}

function lockPath(l: Layout): string {
  return join(l.locks, "learned.lock");
}

/** The project an entry belongs to: the absolute, resolved project directory (symlinks followed when it exists). */
export function projectId(dir: string): string {
  const abs = resolve(dir);
  let real = abs;
  try {
    real = realpathSync.native(abs);
  } catch {
    real = abs;
  }
  if (real.length <= 1) return real;
  // A backward scan, not /\/+$/ (which retries the run from each "/" in it: CodeQL js/polynomial-redos).
  let end = real.length;
  while (end > 0 && real.charCodeAt(end - 1) === 47) end--;
  return real.slice(0, end);
}

/** The code a person types for an action in a project (stable: the same action always has the same code). */
export function codeOf(project: string, key: string): string {
  const h = createHash("sha256").update(JSON.stringify(["launchsafe-firewall/learn-code/v2", project, key])).digest();
  let s = "";
  for (let i = 0; i < CODE_LENGTH; i++) {
    const bit = i * 5;
    const v = ((((h[bit >> 3] as number) << 8) | (h[(bit >> 3) + 1] as number)) >> (11 - (bit & 7))) & 31;
    s += ALPHABET[v];
  }
  return s;
}

const str = (v: unknown, max = 4096): v is string => typeof v === "string" && v.length <= max;
const iso = (v: unknown): boolean => str(v, 64) && ISO.test(v) && Number.isFinite(Date.parse(v));

function validEntry(v: unknown): v is LearnedEntry {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const e = v as Record<string, unknown>;
  return e.version === 1 && str(e.id, 32) && /^[a-z0-9]{4,32}$/.test(e.id) && (e.kind === "allow" || e.kind === "never") && str(e.project) && e.project.startsWith("/") && str(e.key, 64) && /^[0-9a-f]{64}$/.test(e.key) && str(e.identity, 128) && str(e.tool, 1024) && str(e.summary, 2048) && Array.isArray(e.rules) && e.rules.every((r) => str(r, 64)) && typeof e.approvals === "number" && iso(e.createdAt) && (e.sig === undefined || str(e.sig, 512));
}

/** M1: the signed seal over every choice (written by person-run commands holding the key). */
export interface LearnedSeal {
  generation: number;
  /** SHA-256 over every choice in both files (learnedDigest). */
  digest: string;
  sig: string;
}

function validSeal(v: unknown): v is LearnedSeal {
  if (typeof v !== "object" || v === null) return false;
  const s = v as Record<string, unknown>;
  return typeof s.generation === "number" && Number.isSafeInteger(s.generation) && s.generation > 0 && typeof s.digest === "string" && /^[0-9a-f]{64}$/.test(s.digest) && str(s.sig, 512);
}

function readFile(path: string, neversOnly: boolean): { entries: LearnedEntry[]; damaged: boolean; seal: LearnedSeal | null } {
  let t: string | null;
  try {
    t = readText(path);
  } catch {
    return { entries: [], damaged: true, seal: null };
  }
  if (t === null) return { entries: [], damaged: false, seal: null };
  try {
    const o = JSON.parse(t) as { version?: unknown; entries?: unknown; seal?: unknown };
    if (o.version !== 1 || !Array.isArray(o.entries)) return { entries: [], damaged: true, seal: null };
    const entries = o.entries.filter(validEntry).filter((e) => !neversOnly || e.kind === "never");
    const sealBad = o.seal !== undefined && !validSeal(o.seal);
    return { entries, damaged: entries.length !== o.entries.length || sealBad, seal: validSeal(o.seal) ? o.seal : null };
  } catch {
    return { entries: [], damaged: true, seal: null };
  }
}

/** The digest a seal signs: every choice by what identifies it, its kind and its signature, in a fixed order. */
export function learnedDigest(entries: readonly LearnedEntry[]): string {
  const rows = entries.map((e) => [e.id, e.kind, e.project, e.key, e.identity, e.createdAt, e.sig ?? ""]).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return createHash("sha256").update(JSON.stringify(["launchsafe-firewall/learned-set/v1", rows])).digest("hex");
}

/**
 * M1: whether the choices are as the last person-run command sealed them. "none": never sealed (older files,
 * or no passphrase); "ok"; "broken": the seal does not verify, the files' seals differ, or an entry was added
 * or removed since (a "never" deleted from both files shows here), or entries signed with rules (v3, only
 * written by versions that seal) are there without a seal.
 */
export function sealState(l: Layout, approverKey: string | null): { state: "none" | "ok" | "broken"; why?: string } {
  const a = readFile(allowsPath(l), false);
  const n = readFile(neversPath(l), true);
  // A damaged file is reported as damaged (no "always" applies, writes are refused); the seal is not judged then.
  if (a.damaged || n.damaged) return { state: "none" };
  if (a.seal === null && n.seal === null) {
    const v3 = approverKey !== null && a.entries.some((e) => e.sig !== undefined && learnedSignature(approverKey, fieldsOf(e), e.sig) === "v3");
    return v3 ? { state: "broken", why: "its seal was removed" } : { state: "none" };
  }
  if (a.seal === null || n.seal === null || a.seal.generation !== n.seal.generation || a.seal.digest !== n.seal.digest) return { state: "broken", why: "the two files carry different seals" };
  if (approverKey === null || !verifyLearnedSeal(approverKey, a.seal.generation, a.seal.digest, a.seal.sig)) return { state: "broken", why: "its seal does not verify against your approval key" };
  const all = [...a.entries, ...n.entries.filter((x) => !a.entries.some((y) => y.id === x.id))];
  if (learnedDigest(all) !== a.seal.digest) return { state: "broken", why: "a choice was added or removed outside launchsafe-firewall" };
  return { state: "ok" };
}

/** Every stored choice; `damaged` when allows.json exists but cannot be read whole (no "always" then applies). */
export function readEntries(l: Layout): { entries: LearnedEntry[]; damaged: boolean } {
  const { entries, damaged } = readFile(allowsPath(l), false);
  return { entries, damaged };
}

/** Every "never", from both files: damage to one of them never lifts a "never" the other still holds. */
export function readNevers(l: Layout): { entries: LearnedEntry[]; damaged: boolean } {
  const a = readEntries(l);
  const b = readFile(neversPath(l), true);
  const seen = new Set<string>();
  const entries: LearnedEntry[] = [];
  for (const e of [...a.entries.filter((x) => x.kind === "never"), ...b.entries]) {
    const k = `${e.project}\n${e.key}`;
    if (!seen.has(k)) {
      seen.add(k);
      entries.push(e);
    }
  }
  return { entries, damaged: a.damaged || b.damaged };
}

function fieldsOf(e: LearnedEntry): Parameters<typeof verifyLearned>[1] {
  return { kind: e.kind, id: e.id, project: e.project, key: e.key, identity: e.identity, tool: e.tool, createdAt: e.createdAt, rules: e.rules };
}

/** Whether an entry carries a valid signature from this approver key. */
export function entrySigned(e: LearnedEntry, approverKey: string | null): boolean {
  if (approverKey === null || e.sig === undefined) return false;
  return verifyLearned(approverKey, fieldsOf(e), e.sig);
}

/**
 * The choices that apply in a project, for decide(). "always" needs `allowsEnabled`, an undamaged
 * allows.json, a signature from the trusted approver key and rules that are all learnable today; it is
 * keyed with the identity it was signed under, so it holds only while the tool is still that tool.
 * "never" applies from either file (it only tightens). `ignored` lists this project's "always" entries
 * that do not count, and why; `damaged` names a damaged file.
 */
export function loadLearnedView(l: Layout, project: string, approverKey: string | null, allowsEnabled: boolean, identity: string | null): { view: LearnedView; ignored: { entry: LearnedEntry; why: string }[]; damaged: string | null } {
  const allows = new Map<string, string>();
  const nevers = new Map<string, string>();
  const ignored: { entry: LearnedEntry; why: string }[] = [];
  const all = readEntries(l);
  const nv = readNevers(l);
  // M1: choices changed outside the CLI (the seal breaks): no "always" applies; every "never" still does.
  // Without a trusted key nothing "always" applies anyway, and a seal cannot be checked: no warning then.
  const seal: { state: "none" | "ok" | "broken"; why?: string } = approverKey !== null ? sealState(l, approverKey) : { state: "none" };
  for (const e of nv.entries) if (e.project === project) nevers.set(e.key, e.id);
  for (const e of all.entries) {
    if (e.project !== project || e.kind !== "allow") continue;
    if (all.damaged) ignored.push({ entry: e, why: "the learned choices file is damaged" });
    else if (seal.state === "broken") ignored.push({ entry: e, why: `the learned choices were changed outside launchsafe-firewall (${seal.why ?? "seal broken"})` });
    else if (!allowsEnabled) ignored.push({ entry: e, why: "learned allows are switched off by policy (learnedAllows.enabled)" });
    else if (!entrySigned(e, approverKey)) ignored.push({ entry: e, why: "its signature does not verify against your approval key" });
    else if (!rulesEligibility(e.rules).eligible) ignored.push({ entry: e, why: "its rules are no longer learnable" });
    else allows.set(allowKey(e.key, e.identity), e.id);
  }
  const damaged = all.damaged || seal.state === "broken" ? allowsPath(l) : nv.damaged ? neversPath(l) : null;
  return { view: { allows, nevers, identity }, ignored, damaged };
}

/** Just the "never" choices of a project (for routes that never apply "always": the gateway, the local API, check). */
export function loadNevers(l: Layout, project: string): ReadonlyMap<string, string> {
  return new Map(readNevers(l).entries.filter((e) => e.project === project).map((e) => [e.key, e.id]));
}

/** Signs a seal (generation, digest): from a person-run command holding the unlocked approver key (approver.ts learnedSealer). */
export type LearnedSealer = (generation: number, digest: string) => string;

/**
 * Writes both files from one full set of choices (every "never" of both files is in `entries`, so a write
 * never drops one: CLI-I5), sealed when a sealer is given.
 */
function writeChoices(l: Layout, entries: LearnedEntry[], seal: LearnedSeal | null): void {
  const s = seal !== null ? { seal } : {};
  atomicWrite(allowsPath(l), JSON.stringify({ version: 1, entries, ...s }, null, 2));
  atomicWrite(neversPath(l), JSON.stringify({ version: 1, entries: entries.filter((e) => e.kind === "never"), ...s }, null, 2));
}

/**
 * Every current choice for a write: allows.json's entries and every "never" held only in nevers.json. CLI-I5:
 * refuses while either file is damaged (a write would rebuild both from what is readable and drop the rest)
 * or the seal is broken (re-sealing would make an outside change look like the person's).
 */
function choicesForWrite(l: Layout, approverKey: string | null): { entries: LearnedEntry[]; generation: number; sealed: boolean } {
  const a = readFile(allowsPath(l), false);
  const n = readFile(neversPath(l), true);
  if (a.damaged || n.damaged) throw new Error(`${a.damaged ? allowsPath(l) : neversPath(l)} is damaged; nothing was changed. Check it with "launchsafe-firewall allow list --all" and move the damaged file aside first`);
  const seal = sealState(l, approverKey);
  if (seal.state === "broken") throw new Error(`the learned choices were changed outside launchsafe-firewall (${seal.why ?? "seal broken"}); nothing was changed. Check them with "launchsafe-firewall allow list --all" and move ${learnedDir(l)} aside to start again`);
  const entries = [...a.entries, ...n.entries.filter((x) => !a.entries.some((y) => y.id === x.id || (y.project === x.project && y.key === x.key)))];
  return { entries, generation: a.seal?.generation ?? 0, sealed: seal.state === "ok" };
}

function sealFor(entries: readonly LearnedEntry[], generation: number, sealer: LearnedSealer | undefined, sealed: boolean, approverKey: string | null): LearnedSeal | null {
  if (sealer === undefined) {
    // A sealed set changes only with the key: otherwise the change would be indistinguishable from tampering.
    // Nor is a set holding rules-signed (v3) entries left unsealed: that is what a removed seal looks like.
    const v3 = approverKey !== null && entries.some((e) => e.sig !== undefined && learnedSignature(approverKey, fieldsOf(e), e.sig) === "v3");
    if (sealed || v3) throw new Error("the learned choices are sealed with your approval key; this change needs the approval passphrase");
    return null;
  }
  const digest = learnedDigest(entries);
  return { generation: generation + 1, digest, sig: sealer(generation + 1, digest) };
}

/**
 * Stores a choice for (project, key), replacing an earlier one for the same project and action, and
 * returns the replaced one. Refuses when another action already has this id. A "never" still held only
 * in nevers.json counts as an earlier choice. Person-run commands only; `seal` (with the approver key) seals
 * the new set (M1), and a sealed set needs it.
 */
export function saveEntry(l: Layout, entry: LearnedEntry, o: { seal?: LearnedSealer; approverKey?: string | null } = {}): LearnedEntry | null {
  ensureDir(learnedDir(l));
  return withLock(lockPath(l), () => {
    const key = o.approverKey !== undefined ? o.approverKey : safeApproverKey(l);
    const cur = choicesForWrite(l, key);
    const same = (e: LearnedEntry): boolean => e.project === entry.project && e.key === entry.key;
    if (cur.entries.some((e) => e.id === entry.id && !same(e))) throw new Error(`another learned choice already has the id ${entry.id}; nothing was changed`);
    const replaced = cur.entries.find(same) ?? null;
    const next = [...cur.entries.filter((e) => !same(e)), entry];
    writeChoices(l, next, sealFor(next, cur.generation, o.seal, cur.sealed, key));
    return replaced;
  });
}

/** Removes a choice by id from both files; returns it, or null when there is none. Person-run commands only (sealing as saveEntry). */
export function removeEntry(l: Layout, id: string, o: { seal?: LearnedSealer; approverKey?: string | null } = {}): LearnedEntry | null {
  ensureDir(learnedDir(l));
  return withLock(lockPath(l), () => {
    const key = o.approverKey !== undefined ? o.approverKey : safeApproverKey(l);
    const cur = choicesForWrite(l, key);
    const gone = cur.entries.find((e) => e.id === id) ?? null;
    if (gone === null) return null;
    const next = cur.entries.filter((e) => e.id !== id);
    writeChoices(l, next, sealFor(next, cur.generation, o.seal, cur.sealed, key));
    return gone;
  });
}

/** Doctor: a damaged learned-choices file, or choices changed outside the CLI (M1). */
export function learnedChecks(l: Layout, approverKey: string | null = safeApproverKey(l)): { name: string; status: "ok" | "warn" | "fail"; detail: string }[] {
  const a = readEntries(l).damaged;
  const n = readFile(neversPath(l), true).damaged;
  const out: { name: string; status: "ok" | "warn" | "fail"; detail: string }[] = [];
  if (a || n) out.push({ name: "learned choices", status: "warn", detail: `${a ? allowsPath(l) : neversPath(l)} is damaged: no "always in this project" choice applies until it is repaired ("never" choices still do from the other copy). Check it with "launchsafe-firewall allow list --all", then remove bad entries or move the file aside` });
  const s = sealState(l, approverKey);
  if (s.state === "broken") out.push({ name: "learned choices", status: "warn", detail: `the learned choices were changed outside launchsafe-firewall (${s.why ?? "seal broken"}): no "always in this project" choice applies, and a "never" may have been removed. Check them with "launchsafe-firewall allow list --all"` });
  return out;
}

function safeApproverKey(l: Layout): string | null {
  try {
    return approverPublicKey(l);
  } catch {
    return null;
  }
}

function validCandidate(v: unknown): v is Candidate {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const c = v as Record<string, unknown>;
  return str(c.code, 32) && str(c.project) && str(c.key, 64) && (c.identity === null || str(c.identity, 128)) && str(c.tool, 1024) && str(c.summary, 2048) && Array.isArray(c.rules) && typeof c.eligible === "boolean" && typeof c.asked === "number" && typeof c.approved === "number" && Array.isArray(c.approvedAt) && str(c.firstAt, 64) && str(c.lastAt, 64) && Array.isArray(c.pending);
}

export function readCandidates(l: Layout): Candidate[] {
  try {
    const t = readText(candidatesPath(l));
    if (t === null) return [];
    const o = JSON.parse(t) as { version?: unknown; items?: unknown };
    return o.version === 1 && Array.isArray(o.items) ? o.items.filter(validCandidate) : [];
  } catch {
    return [];
  }
}

/** Keeps the newest MAX_CANDIDATES; actions nobody ever approved go first, so a flood of asks cannot push out real approvals. */
function writeCandidates(l: Layout, items: Candidate[]): void {
  const order = (c: Candidate): string => `${c.approved > 0 ? 1 : 0}${c.lastAt}`;
  const keep = [...items].sort((a, b) => order(a).localeCompare(order(b))).slice(-MAX_CANDIDATES).sort((a, b) => a.lastAt.localeCompare(b.lastAt));
  atomicWrite(candidatesPath(l), JSON.stringify({ version: 1, items: keep }));
}

function update(l: Layout, fn: (items: Candidate[]) => Candidate | null): Candidate | null {
  ensureDir(learnedDir(l));
  return withLock(lockPath(l), () => {
    const items = readCandidates(l);
    const out = fn(items);
    if (out !== null) writeCandidates(l, items);
    return out;
  });
}

const sameAs = (c: Candidate, project: string, key: string): boolean => c.project === project && c.key === key;

/** The candidate a code names: it must be the code of that candidate's own project and action. */
export function getCandidate(l: Layout, code: string): Candidate | null {
  return readCandidates(l).find((c) => c.code === code && codeOf(c.project, c.key) === code) ?? null;
}

function approvedNow(c: Candidate, now: Date): void {
  c.approved += 1;
  c.approvedAt = [...c.approvedAt, now.toISOString()].slice(-MAX_DATES);
  c.lastAt = now.toISOString();
}

/**
 * The firewall asked about (or held) an action: counts it, and for a prompt a person can answer now,
 * remembers it so the tool finishing counts as the person's yes. Returns the candidate.
 */
export function noteAsked(l: Layout, x: { project: string; key: string; identity: string | null; tool: string; summary: string; rules: readonly string[]; eligible: boolean; why?: string | undefined; session: string; hash: string; answerable: boolean }, now = new Date()): Candidate {
  const code = codeOf(x.project, x.key);
  return update(l, (items) => {
    let c = items.find((i) => sameAs(i, x.project, x.key));
    if (c === undefined) {
      c = { code, project: x.project, key: x.key, identity: x.identity, tool: x.tool.slice(0, 1024), summary: x.summary.slice(0, MAX_SUMMARY), rules: [...x.rules].slice(0, 16), eligible: x.eligible, asked: 0, approved: 0, approvedAt: [], firstAt: now.toISOString(), lastAt: now.toISOString(), pending: [] };
      items.push(c);
    }
    c.asked += 1;
    c.lastAt = now.toISOString();
    c.rules = [...x.rules].slice(0, 16);
    c.eligible = x.eligible;
    c.identity = x.identity;
    if (x.why !== undefined) c.why = x.why.slice(0, 200);
    else delete c.why;
    c.summary = x.summary.slice(0, MAX_SUMMARY);
    c.pending = c.pending.filter((p) => now.getTime() - p.at < PENDING_TTL_MS && !(p.session === x.session && p.hash === x.hash));
    if (x.answerable) c.pending = [...c.pending, { session: x.session, hash: x.hash, at: now.getTime() }].slice(-MAX_PENDING);
    return c;
  }) as Candidate;
}

/** A person approved the action through the queue (signed) and the approved retry ran: counts the yes. */
export function noteApproved(l: Layout, project: string, key: string, now = new Date()): Candidate | null {
  return update(l, (items) => {
    const c = items.find((i) => sameAs(i, project, key));
    if (c === undefined) return null;
    approvedNow(c, now);
    return c;
  });
}

const hasPending = (items: readonly Candidate[], session: string, hash: string): boolean => items.some((c) => c.pending.some((p) => p.session === session && p.hash === hash));

/**
 * A later decision for the same action in the same session that was not an ask (allowed by something
 * else, held, denied): the earlier prompt is no longer the one the tool's run would answer.
 */
export function clearPending(l: Layout, session: string, hash: string): void {
  if (!hasPending(readCandidates(l), session, hash)) return;
  update(l, (items) => {
    let hit: Candidate | null = null;
    for (const c of items) {
      const before = c.pending.length;
      c.pending = c.pending.filter((p) => !(p.session === session && p.hash === hash));
      if (c.pending.length !== before) hit = c;
    }
    return hit;
  });
}

/**
 * PostToolUse: the tool of an asked action ran, so the person answered yes in the prompt. Counts it once
 * (the prompt is forgotten). Returns the candidate, or null when this was not an asked action. Reads
 * nothing more when there is no pending prompt.
 */
export function confirmAsked(l: Layout, session: string, hash: string, now = new Date()): Candidate | null {
  if (!hasPending(readCandidates(l), session, hash)) return null;
  return update(l, (all) => {
    const c = all.find((i) => i.pending.some((p) => p.session === session && p.hash === hash && now.getTime() - p.at < PENDING_TTL_MS));
    if (c === undefined) return null;
    c.pending = c.pending.filter((p) => !(p.session === session && p.hash === hash));
    approvedNow(c, now);
    return c;
  });
}
