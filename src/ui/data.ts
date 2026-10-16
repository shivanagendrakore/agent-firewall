/**
 * What the dashboard shows, read from the same functions the CLI's read-only commands use (status,
 * queue, queue show, log, log verify, explain, pins, canary list, doctor). Nothing here writes the
 * queue, session state, pins, decoys, policy, settings or the log; a pins file that does not parse is
 * reported, not moved aside (that is the hook's job). Every reader is wrapped so a damaged file shows
 * as an honest error on its screen instead of a broken page.
 */

import { closeSync, constants as fsConstants, existsSync, fstatSync, lstatSync, openSync, readlinkSync, readSync, realpathSync, statSync, type Stats } from "node:fs";
import { posix } from "node:path";
import { globMatch } from "../engine/glob.js";
import { CREDENTIAL_STORE_EXCEPTIONS, CREDENTIAL_STORE_PATTERNS, PROTECTION_FOLDS_CASE, SECRET_EXCEPTIONS, SECRET_PATTERNS } from "../engine/paths.js";
import type { Check } from "../runtime/doctor.js";
import { loadPolicy } from "../runtime/config.js";
import { readText } from "../runtime/fsutil.js";
import { readRecords, type InstallRecord } from "../runtime/install.js";
import { safeId, type Layout } from "../runtime/layout.js";
import { tailLog, type LogEntry, type VerifyResult } from "../runtime/log.js";
import { cachedVerify, logIndex, readRows, type IndexRow } from "./logindex.js";
import { parsePins, pinsPath, type PinFile } from "../runtime/pins.js";
import { loadRegistry } from "../runtime/canaries.js";
import { getQueueItem, listQueue, loadState, recentSessions, type QueueItem, type SessionSummary } from "../runtime/store.js";
import { inUnattendedHours } from "../policy.js";
import { approverPublicKey } from "../runtime/approver.js";
import { loadIndex, vaultView as engineVaultView, type BackendId } from "../runtime/vault/index.js";
import { bindingSummary, formatRef, type VaultView } from "../engine/vault-ref.js";
import { readGatewayInstall } from "../gateway/install.js";
import { listRecords } from "../runtime/quarantine.js";
import { loadPhones } from "../runtime/relay/phones.js";
import { readDevice } from "../runtime/relay/keys.js";
import { relayStatusLine } from "../runtime/relay/files.js";

export type Result<T> = { ok: true; value: T } | { ok: false; error: string };

function attempt<T>(fn: () => T): Result<T> {
  try {
    return { ok: true, value: fn() };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

export interface Overview {
  home: string;
  homeExists: boolean;
  installs: Result<InstallRecord[]>;
  sessions: Result<SessionSummary[]>;
  held: Result<number>;
  /** Queue files that could not be read: an item the person may need to decide that no screen can show. */
  unreadable: Result<string[]>;
  decisions: Result<{ allow: number; ask: number; queue: number; deny: number; total: number }>;
  /** `log verify`'s answer (cached; logindex.ts). */
  log: Result<VerifyResult>;
  unattended: Result<{ on: boolean; why: string }>;
  checks: Result<Check[]>;
  checkedAt: Date | null;
}

export function unattendedMode(l: Layout, project: string, env: NodeJS.ProcessEnv, now: Date): { on: boolean; why: string } {
  const cfg = loadPolicy(l, [project]).config;
  const hours = cfg.unattendedHours.map((h) => `${h.from}-${h.to}`).join(", ");
  if (cfg.unattended) return { on: true, why: "the policy sets it" };
  if (env.LAUNCHSAFE_FIREWALL_UNATTENDED === "1") return { on: true, why: "LAUNCHSAFE_FIREWALL_UNATTENDED=1" };
  if (inUnattendedHours(cfg.unattendedHours, now)) return { on: true, why: `inside unattended hours ${hours}` };
  return { on: false, why: `${hours !== "" ? `unattended hours ${hours}; ` : ""}sessions run with claude -p or in dontAsk mode are always unattended` };
}

export function overview(l: Layout, project: string, env: NodeJS.ProcessEnv, now: Date, checks: { value: Result<Check[]>; at: Date | null }): Overview {
  const queue = attempt(() => listQueue(l));
  return {
    home: l.home,
    homeExists: existsSync(l.home),
    installs: attempt(() => readRecords(l)),
    sessions: attempt(() => recentSessions(l, 20, now.getTime())),
    held: queue.ok ? { ok: true, value: queue.value.items.filter((i) => i.status === "pending").length } : queue,
    unreadable: queue.ok ? { ok: true, value: queue.value.corrupt } : queue,
    log: attempt(() => cachedVerify(l)),
    decisions: attempt(() => {
      const recent = tailLog(l, 200).filter((e) => e.event.type === "decision");
      const by = (v: string): number => recent.filter((e) => e.event.verdict === v).length;
      return { allow: by("allow"), ask: by("ask"), queue: by("queue"), deny: by("deny"), total: recent.length };
    }),
    unattended: attempt(() => unattendedMode(l, project, env, now)),
    checks: checks.value,
    checkedAt: checks.at,
  };
}

/** Held items per page of the queue list (the log's page size too). */
export const QUEUE_PAGE = 100;

export interface QueueView {
  /** This page's items, oldest first. */
  pending: QueueItem[];
  /** Every held item, not just this page. */
  total: number;
  page: number;
  pages: number;
  corrupt: string[];
}

export function queueView(l: Layout, page = 1): Result<QueueView> {
  return attempt(() => {
    const q = listQueue(l);
    const all = q.items.filter((i) => i.status === "pending");
    const pages = Math.max(1, Math.ceil(all.length / QUEUE_PAGE));
    const at = Math.min(Math.max(1, page), pages);
    return { pending: all.slice((at - 1) * QUEUE_PAGE, at * QUEUE_PAGE), total: all.length, page: at, pages, corrupt: q.corrupt };
  });
}

/** Largest current file the diff reads (the CLI reads the whole file; a browser page should stay small). */
export const MAX_CURRENT_BYTES = 1024 * 1024;

export interface ItemView {
  item: QueueItem;
  /** The proposal's target as it is now, when it is an absolute path that can be read. */
  current: string | null;
  currentNote: string | null;
}

/** Where the dashboard may read a proposal's target from: the project and the home directory (both forms). */
export interface ReadRoots {
  roots: readonly string[];
  /** Home directories, for the credential-store patterns written with `~`. */
  homes: readonly string[];
}

function underAny(p: string, roots: readonly string[]): boolean {
  return roots.some((r) => {
    const x = r.replace(/\/+$/, "");
    return x !== "" && (p === x || p.startsWith(`${x}/`));
  });
}

function realRoot(r: string): string {
  try {
    return realpathSync(r);
  } catch {
    return r;
  }
}

/** Whether a path names a secret file or a credential store (the engine's own lists), as written. */
export function sensitivePath(abs: string, homes: readonly string[]): boolean {
  // I1: matched ignoring case on every platform, like the engine's own classification of these lists.
  const ci = PROTECTION_FOLDS_CASE;
  const forms = (p: string): string[] => (p.startsWith("~/") ? homes.map((h) => `${h.replace(/\/+$/, "")}${p.slice(1)}`) : [p]);
  const any = (patterns: readonly string[]): boolean => patterns.some((p) => forms(p).some((f) => globMatch(f, abs, ci)));
  return (any(CREDENTIAL_STORE_PATTERNS) && !any(CREDENTIAL_STORE_EXCEPTIONS)) || (any(SECRET_PATTERNS) && !any(SECRET_EXCEPTIONS));
}

const NOT_SHOWN_SENSITIVE = "Not shown: sensitive path. The change is shown on its own.";

/** The real path of an open file: the kernel's answer on Linux, else the path's resolution, which must be the very file that is open. */
function openedPath(fd: number, abs: string, open: Stats): string {
  if (process.platform === "linux") {
    try {
      return readlinkSync(`/proc/self/fd/${fd}`);
    } catch {
      // Fall through to the resolution below.
    }
  }
  const real = realpathSync(abs);
  const now = statSync(real);
  if (now.dev !== open.dev || now.ino !== open.ino) throw new Error("the path no longer leads to the open file");
  return real;
}

/**
 * The proposal's target as it is now, for the diff, or why it is not shown. The target is agent-written,
 * so it is read only when it is a regular file (lstat: never a symbolic link, a device, a FIFO or a socket)
 * inside the project or the home directory, as written and as resolved, and not a secret file or a
 * credential store. The read itself is opened without following links and without blocking, and stops
 * at MAX_CURRENT_BYTES.
 */
export function readTarget(target: string, where: ReadRoots): { current: string | null; note: string | null } {
  const not = (note: string): { current: null; note: string } => ({ current: null, note });
  if (!target.startsWith("/")) return not("The target is not an absolute path, so the change is shown on its own.");
  const abs = posix.normalize(target);
  if (sensitivePath(abs, where.homes)) return not(NOT_SHOWN_SENSITIVE);
  if (!underAny(abs, where.roots)) return not("Not shown: the target is outside the project and your home directory. The change is shown on its own.");
  let st: Stats;
  try {
    st = lstatSync(abs);
  } catch {
    return not("The file does not exist yet.");
  }
  if (st.isSymbolicLink()) return not("Not shown: the target is a symbolic link. The change is shown on its own.");
  if (!st.isFile()) return not("Not shown: the target is not a regular file. The change is shown on its own.");
  const big = `The file is larger than ${MAX_CURRENT_BYTES / 1024} KB, so the change is shown on its own.`;
  if (st.size > MAX_CURRENT_BYTES) return not(big);
  // Open first, then judge the file that was opened: a folder swapped for a link after a path check cannot
  // lead the read to another file, and O_NOFOLLOW covers only the last name.
  let fd: number;
  try {
    fd = openSync(abs, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  } catch {
    return not("Not shown: the file could not be opened. The change is shown on its own.");
  }
  try {
    const open = fstatSync(fd);
    if (!open.isFile()) return not("Not shown: the target is not a regular file. The change is shown on its own.");
    // A second name for the same file could be a secret that passed the name checks.
    if (open.nlink > 1) return not("Not shown: the target has more than one name (a hard link). The change is shown on its own.");
    let real: string;
    try {
      real = openedPath(fd, abs, open);
    } catch {
      return not("Not shown: the target could not be resolved. The change is shown on its own.");
    }
    if (sensitivePath(real, where.homes)) return not(NOT_SHOWN_SENSITIVE);
    // The roots as resolved too: a project under /tmp or /var (links on a Mac) resolves to /private/..., which is still inside it.
    if (!underAny(real, [...where.roots, ...where.roots.map(realRoot)])) return not("Not shown: a folder on the way to the target leads outside the project and your home directory. The change is shown on its own.");
    const buf = Buffer.alloc(MAX_CURRENT_BYTES + 1);
    let n = 0;
    for (;;) {
      const got = readSync(fd, buf, n, buf.length - n, null);
      if (got === 0) break;
      n += got;
      if (n > MAX_CURRENT_BYTES) return not(big);
    }
    return { current: buf.toString("utf8", 0, n), note: null };
  } catch {
    return not("Not shown: the file could not be read. The change is shown on its own.");
  } finally {
    closeSync(fd);
  }
}

export function itemView(l: Layout, id: string, where: ReadRoots = { roots: [], homes: [] }): Result<ItemView | null> {
  return attempt(() => {
    const item = getQueueItem(l, id);
    if (item === null) return null;
    const target = item.proposal?.target;
    const { current, note } = target !== undefined ? readTarget(target, where) : { current: null, note: null };
    return { item, current, currentNote: note };
  });
}

export const LOG_PAGE = 100;

export interface LogView {
  entries: LogEntry[];
  /** The sequence number to pass as ?before= for the next (older) page, if any. */
  older: number | null;
  types: string[];
}

export function logView(l: Layout, o: { before?: number; type?: string; verdict?: string }): Result<LogView> {
  return attempt(() => {
    // From the cached index: only the lines of this page are read (logindex.ts).
    const ix = logIndex(l);
    const match = ix.rows.filter((r) => (o.before === undefined || r.seq < o.before) && (o.type === undefined || r.type === o.type) && (o.verdict === undefined || r.verdict === o.verdict));
    const rows = match.slice(-LOG_PAGE).reverse();
    const older = match.length > LOG_PAGE && rows.length > 0 ? (rows[rows.length - 1] as IndexRow).seq : null;
    return { entries: readRows(l, rows), older, types: ix.types };
  });
}

export function logEntry(l: Layout, seq: number): Result<LogEntry | null> {
  return attempt(() => {
    const row = logIndex(l).bySeq.get(seq);
    return row === undefined ? null : (readRows(l, [row])[0] ?? null);
  });
}

export function logVerify(l: Layout): Result<VerifyResult> {
  return attempt(() => cachedVerify(l));
}

export interface IntegrityView {
  pins: Result<PinFile | null>;
  pinsUnreadable: boolean;
  canaries: Result<{ id: string; kind: string; path: string; present: boolean; plantedAt: string }[]>;
  canarySessions: Result<SessionSummary[]>;
  alerts: Result<LogEntry[]>;
}

export function integrityView(l: Layout, now: Date): IntegrityView {
  let pinsUnreadable = false;
  const pins = attempt((): PinFile | null => {
    const text = readText(pinsPath(l));
    if (text === null) return null;
    const p = parsePins(text);
    if (p === null) pinsUnreadable = true;
    return p;
  });
  const canaries = attempt(() => {
    const reg = loadRegistry(l);
    if (!reg.ok) throw new Error(`the decoy registry is damaged: ${reg.error}`);
    // The decoy's value is never shown: it is not a secret, but nothing needs to display it.
    return reg.canaries.map((c) => ({ id: c.id, kind: c.kind, path: c.path, present: existsSync(c.path), plantedAt: c.plantedAt }));
  });
  return {
    pins,
    pinsUnreadable,
    canaries,
    canarySessions: attempt(() => recentSessions(l, 50, now.getTime(), 30).filter((s) => s.canary === true)),
    alerts: attempt(() => tailLog(l, 2000).filter((e) => e.event.type === "canary").slice(-20).reverse()),
  };
}

export interface SessionView {
  summary: SessionSummary | null;
  taintSources: string[];
  decisions: LogEntry[];
}

/** One session: its summary, everything that made it untrusted, and its recent logged decisions. */
export function sessionView(l: Layout, id: string, now: Date): Result<SessionView | null> {
  return attempt(() => {
    const summary = recentSessions(l, 500, now.getTime(), 30).find((s) => s.id === id) ?? null;
    const decisions = tailLog(l, 5000).filter((e) => typeof e.event.session === "string" && (e.event.session === id || safeId(e.event.session) === id)).slice(-50).reverse();
    if (summary === null && decisions.length === 0) return null;
    const st = loadState(l, id);
    return { summary, taintSources: [...st.taintSources], decisions };
  });
}

// --- the vault ------------------------------------------------------------------------------------

/** One stored secret as the dashboard shows it: names, kinds, fields, stores and rules. Never a value or a fingerprint. */
export interface VaultRow {
  ref: string;
  kind: string;
  fields: string[];
  backend: BackendId;
  confirm: string;
  /** Where its value may go, one line per binding (as `vault list` prints them). */
  rules: string[];
  createdAt: string;
  rotatedAt?: string;
}

export interface VaultSummary {
  /** absent: no vault yet; ok: signed by the approval key; unsigned: the signature does not verify (nothing is bound). */
  state: "absent" | "ok" | "unsigned";
  problem?: string;
  rows: VaultRow[];
}

/** The approval key the hook trusts: the one its command pins, else the one on disk. */
function trustedApprover(l: Layout, env: NodeJS.ProcessEnv): string | null {
  const pinned = env.LAUNCHSAFE_FIREWALL_APPROVER;
  if (pinned !== undefined && pinned !== "") return pinned;
  try {
    return approverPublicKey(l);
  } catch {
    return null;
  }
}

/** The vault as `vault list` reads it, without values or fingerprints. */
export function vaultSummary(l: Layout, env: NodeJS.ProcessEnv): Result<VaultSummary> {
  return attempt(() => {
    const st = loadIndex(l, trustedApprover(l, env));
    if (st.state === "corrupt") throw new Error(st.error);
    if (st.state === "absent") return { state: "absent", rows: [] };
    const rows = st.index.entries.map((e): VaultRow => ({ ref: formatRef(e.name), kind: e.kind, fields: [...e.fields], backend: e.backend, confirm: e.confirm, rules: e.bindings.map(bindingSummary), createdAt: e.createdAt, ...(e.rotatedAt !== undefined ? { rotatedAt: e.rotatedAt } : {}) }));
    return st.state === "ok" ? { state: "ok", rows } : { state: "unsigned", problem: st.reason, rows };
  });
}

/**
 * The vault's names and fingerprints, used only on the server to hide a stored value wherever a page would
 * show one (src/ui/html.ts withVault). Never rendered. `view` is undefined when there is no vault.
 * `unavailable` says why stored values cannot be recognised (an index that exists but cannot be read or
 * parsed), so every page can say masking is off instead of looking as safe as usual. An index that does
 * not verify still carries its fingerprints, so masking keeps working for it.
 */
export function vaultMask(l: Layout, env: NodeJS.ProcessEnv): { view: VaultView | undefined; unavailable: string | null } {
  try {
    const st = loadIndex(l, trustedApprover(l, env));
    return { view: engineVaultView(st), unavailable: st.state === "corrupt" ? st.error : null };
  } catch (e) {
    return { view: undefined, unavailable: (e as Error).message };
  }
}

// --- v0.3: the gateway, the quarantine, phones and run --------------------------------------------

export interface WrappedRow {
  client: string;
  server: string;
  mode: string;
  upstream: "stdio" | "http";
}

/** One withheld item: names, subjects and signals only. The withheld text and its preview are never read here. */
export interface QuarantineRow {
  id: string;
  kind: "mcp_result" | "email";
  createdAt: string;
  status: string;
  client?: string;
  server?: string;
  tool?: string;
  from?: string;
  subject?: string;
  signals: string[];
}

export interface GuardsView {
  wrapped: Result<WrappedRow[]>;
  quarantine: Result<{ rows: QuarantineRow[]; corrupt: number }>;
  /** Paired phones' labels (and when), never keys or credential ids. */
  phones: Result<{ labels: { label: string; pairedAt: string }[]; registered: boolean; relay: string | null }>;
}

export function guardsView(l: Layout): GuardsView {
  return {
    wrapped: attempt(() => readGatewayInstall(l).entries.map((e): WrappedRow => ({ client: e.client, server: e.server, mode: e.mode, upstream: e.upstream.kind }))),
    quarantine: attempt(() => {
      const { records, corrupt } = listRecords(l);
      const rows = records
        .slice(-200)
        .reverse()
        .map((r): QuarantineRow => ({
          id: r.id,
          kind: r.kind,
          createdAt: r.createdAt,
          status: r.status,
          signals: [...r.signals],
          ...(r.client !== undefined ? { client: r.client } : {}),
          ...(r.server !== undefined ? { server: r.server } : {}),
          ...(r.tool !== undefined ? { tool: r.tool } : {}),
          ...(r.mail !== undefined ? { from: r.mail.from, subject: r.mail.subject } : {}),
        }));
      return { rows, corrupt: corrupt.length };
    }),
    phones: attempt(() => {
      const p = loadPhones(l);
      if (p.state === "corrupt") throw new Error(p.error);
      const device = readDevice(l);
      return { labels: p.state === "ok" ? p.file.phones.map((x) => ({ label: x.label, pairedAt: x.pairedAt })) : [], registered: device?.token !== undefined && device.deviceId !== undefined, relay: relayStatusLine(l, device?.token !== undefined) };
    }),
  };
}
