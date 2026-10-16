// Vendored from LaunchSafe's agent-safety package (src/drift.ts), Apache-2.0, at commit fc329d4314dc07a65da266a1256b1da0d17ec97c.
// Licence: Apache-2.0 (see NOTICE).
// Transform: add ".js" to relative import specifiers.
// Do not edit here: it is copied from the upstream package by
// `node scripts/sync-agent-safety.mjs` (`--check` verifies the copy).

/**
 * Drift: what changed in a repository's agent setup between two receipts.
 * Pure. Files are matched by path, tool servers by file and name, hooks by
 * file, label and their order under that label, and findings by rule and
 * file (lines move when a file is edited, so a finding that only moved is
 * neither new nor resolved).
 */
// DIVERGES FROM UPSTREAM (firewall audit I10): a hook or server whose whole command (its SHA-256)
// changed is a change even when the 200 characters shown are the same. Upstream should take this.
import { agentFileKind } from "./paths.js";
import type { AgentCheckReceipt, ReceiptFile, ReceiptFinding, ReceiptHook, ReceiptServer } from "./receipt.js";

export interface ServerChange {
  name: string;
  file: string;
  from: ReceiptServer;
  to: ReceiptServer;
}

export interface HookChange {
  file: string;
  label: string;
  from: string;
  to: string;
}

export interface ReceiptDrift {
  /** Nothing the check saw or found differs (the times and tool builds may). */
  identical: boolean;
  same_source: { repository: boolean; commit: boolean };
  same_rules: boolean;
  /** The rule set changed between the two: a finding may be new because a rule is. */
  rules_changed: { from: string; to: string } | null;
  files: { added: string[]; removed: string[]; changed: string[] };
  servers: {
    added: ReceiptServer[];
    removed: ReceiptServer[];
    /** The launch line or address changed. */
    pin_changed: ServerChange[];
    /** Pinned before, floating now. */
    unpinned_now: ServerChange[];
    /** Floating before, pinned now. */
    pinned_now: ServerChange[];
    /** Every server in the newer receipt that is pinned to a moving target. */
    floating: ReceiptServer[];
  };
  hooks: { added: ReceiptHook[]; removed: ReceiptHook[]; changed: HookChange[] };
  findings: { new: ReceiptFinding[]; resolved: ReceiptFinding[] };
  /** Agent memory files (also listed under files), called out on their own: the agent writes them itself. */
  memory: MemoryDrift;
}

export interface MemoryDrift {
  added: string[];
  removed: string[];
  changed: string[];
  /**
   * The memory files' total line count now minus then, over the files added,
   * removed or changed. Net, so an edit that replaced lines one for one
   * counts 0. Null when a receipt has no line counts (made before rule set
   * 1.1.0).
   */
  line_delta: number | null;
  /** The earlier receipt read no memory files under an older rule set, so "added" may only mean "read for the first time". */
  first_read: boolean;
}

/** A memory file: flagged in the receipt, or a memory path in a receipt made before files were flagged. */
const isMemory = (f: ReceiptFile) => f.memory === true || agentFileKind(f.path) === "memory";

function memoryDrift(before: AgentCheckReceipt, after: AgentCheckReceipt, rulesChanged: boolean): MemoryDrift {
  const oldMem = new Map(before.files.filter(isMemory).map((f) => [f.path, f]));
  const newMem = new Map(after.files.filter(isMemory).map((f) => [f.path, f]));
  const added = [...newMem.keys()].filter((p) => !oldMem.has(p));
  const removed = [...oldMem.keys()].filter((p) => !newMem.has(p));
  const changed = [...newMem].filter(([p, f]) => {
    const old = oldMem.get(p);
    return old !== undefined && (old.sha256 !== f.sha256 || old.bytes !== f.bytes);
  }).map(([p]) => p);
  const now = [...added, ...changed].map((p) => newMem.get(p)?.lines);
  const then = [...removed, ...changed].map((p) => oldMem.get(p)?.lines);
  const sum = (xs: (number | undefined)[]) => (xs.some((x) => x === undefined) ? null : xs.reduce<number>((a, x) => a + (x ?? 0), 0));
  const nowLines = sum(now);
  const thenLines = sum(then);
  return { added, removed, changed, line_delta: nowLines === null || thenLines === null ? null : nowLines - thenLines, first_read: rulesChanged && oldMem.size === 0 && newMem.size > 0 };
}

/**
 * The memory drift as one sentence, for any page or output that shows drift:
 * "Memory changed since the last receipt: 2 files, 14 more lines." Null when
 * no memory file was added, removed or changed.
 */
export function memoryDriftSentence(memory: MemoryDrift): string | null {
  const n = memory.added.length + memory.removed.length + memory.changed.length;
  if (n === 0) return null;
  const parts = [memory.added.length ? `${memory.added.length} added` : "", memory.changed.length ? `${memory.changed.length} changed` : "", memory.removed.length ? `${memory.removed.length} removed` : ""].filter(Boolean);
  const files = `${n} file${n === 1 ? "" : "s"}${parts.length > 1 || memory.changed.length === 0 ? ` (${parts.join(", ")})` : ""}`;
  const d = memory.line_delta;
  const lines = d === null ? "" : d === 0 ? ", the same number of lines" : `, ${Math.abs(d)} ${d > 0 ? "more" : "fewer"} line${Math.abs(d) === 1 ? "" : "s"}`;
  const first = memory.first_read ? " The earlier receipt's rule set did not read memory files, so they may only be new to the check." : "";
  return `Memory changed since the last receipt: ${files}${lines}.${first}`;
}

const serverKey = (s: ReceiptServer) => `${s.file}\u0000${s.name}\u0000${s.transport}`;

/** Hooks keyed by file, label and their place among hooks with that label in that file. */
function hookMap(hooks: readonly ReceiptHook[]): Map<string, ReceiptHook> {
  const seen = new Map<string, number>();
  const out = new Map<string, ReceiptHook>();
  for (const hook of hooks) {
    const base = `${hook.file}\u0000${hook.label}`;
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    out.set(`${base}\u0000${n}`, hook);
  }
  return out;
}

/** Two shown commands differ, or their whole-command hashes do (when both receipts have them). */
const differs = (a: string, b: string, ha: string | undefined, hb: string | undefined) => a !== b || (ha !== undefined && hb !== undefined && ha !== hb);

/** Findings present in `a` beyond their count in `b`, by rule and file. */
function beyond(a: readonly ReceiptFinding[], b: readonly ReceiptFinding[]): ReceiptFinding[] {
  const budget = new Map<string, number>();
  for (const f of b) budget.set(`${f.rule}\u0000${f.path}`, (budget.get(`${f.rule}\u0000${f.path}`) ?? 0) + 1);
  const out: ReceiptFinding[] = [];
  for (const f of a) {
    const key = `${f.rule}\u0000${f.path}`;
    const left = budget.get(key) ?? 0;
    if (left > 0) budget.set(key, left - 1);
    else out.push(f);
  }
  return out;
}

/** What changed from `before` to `after`. */
export function compareReceipts(before: AgentCheckReceipt, after: AgentCheckReceipt): ReceiptDrift {
  const oldFiles = new Map(before.files.map((f) => [f.path, f]));
  const newFiles = new Map(after.files.map((f) => [f.path, f]));
  const files = {
    added: after.files.filter((f) => !oldFiles.has(f.path)).map((f) => f.path),
    removed: before.files.filter((f) => !newFiles.has(f.path)).map((f) => f.path),
    changed: after.files.filter((f) => {
      const old = oldFiles.get(f.path);
      return old !== undefined && (old.sha256 !== f.sha256 || old.bytes !== f.bytes);
    }).map((f) => f.path),
  };

  const oldServers = new Map(before.servers.map((s) => [serverKey(s), s]));
  const newServers = new Map(after.servers.map((s) => [serverKey(s), s]));
  const pinChanged: ServerChange[] = [];
  const unpinnedNow: ServerChange[] = [];
  const pinnedNow: ServerChange[] = [];
  for (const [key, to] of newServers) {
    const from = oldServers.get(key);
    if (from === undefined || !differs(from.launch, to.launch, from.sha256, to.sha256)) continue;
    const change = { name: to.name, file: to.file, from, to };
    pinChanged.push(change);
    if (from.pin === "stable" && to.pin === "floating") unpinnedNow.push(change);
    if (from.pin === "floating" && to.pin === "stable") pinnedNow.push(change);
  }
  const servers = {
    added: after.servers.filter((s) => !oldServers.has(serverKey(s))),
    removed: before.servers.filter((s) => !newServers.has(serverKey(s))),
    pin_changed: pinChanged,
    unpinned_now: unpinnedNow,
    pinned_now: pinnedNow,
    floating: after.servers.filter((s) => s.pin === "floating"),
  };

  const oldHooks = hookMap(before.hooks);
  const newHooks = hookMap(after.hooks);
  const hooks = {
    added: [...newHooks].filter(([k]) => !oldHooks.has(k)).map(([, h]) => h),
    removed: [...oldHooks].filter(([k]) => !newHooks.has(k)).map(([, h]) => h),
    changed: [...newHooks].flatMap(([k, h]) => {
      const old = oldHooks.get(k);
      return old !== undefined && differs(old.command, h.command, old.sha256, h.sha256) ? [{ file: h.file, label: h.label, from: old.command, to: h.command }] : [];
    }),
  };

  const findings = { new: beyond(after.findings, before.findings), resolved: beyond(before.findings, after.findings) };
  const sameRules = before.rules_version === after.rules_version;
  const sameSource = { repository: before.source.repository.toLowerCase() === after.source.repository.toLowerCase(), commit: before.source.commit === after.source.commit };
  const identical =
    sameRules &&
    sameSource.repository &&
    sameSource.commit &&
    files.added.length + files.removed.length + files.changed.length === 0 &&
    servers.added.length + servers.removed.length + servers.pin_changed.length === 0 &&
    hooks.added.length + hooks.removed.length + hooks.changed.length === 0 &&
    findings.new.length + findings.resolved.length === 0;
  return {
    identical,
    same_source: sameSource,
    same_rules: sameRules,
    rules_changed: sameRules ? null : { from: before.rules_version, to: after.rules_version },
    files,
    servers,
    hooks,
    findings,
    memory: memoryDrift(before, after, !sameRules),
  };
}
