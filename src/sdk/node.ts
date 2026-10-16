/**
 * @launchsafe/agent-firewall/sdk/node: the Node-only parts of the library
 * (docs/library.md). fileStore() keeps a guard's state in the runtime's own
 * files, through the functions the hook uses, so held actions show up in
 * `launchsafe-firewall queue list` and approvals made there count;
 * ed25519Signer() signs the memory store's log; nodeEnvironment() gives the
 * engine the file system the hook gives it (symlinks, file contents, the OS
 * temp directories, package intel, lockfiles).
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import { homedir, tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileSize, protectedSettingsFiles, readSmallFile } from "../runtime/context.js";
import { approvalSigner, approverPublicKey, unlockApprover } from "../runtime/approver.js";
import { loadCanaryIndex } from "../runtime/canaries.js";
import { assertSupportedPlatform } from "../runtime/platform.js";
import { confirmBudget, loadBudgetView, recordBudget } from "../runtime/counters.js";
import { capStopped, loadCapView, recordDaily, recordFailure } from "../runtime/caps.js";
import { assertNotRealHome } from "../runtime/guard.js";
import { openIntel } from "../runtime/intel.js";
import { installDir, layout, type Layout } from "../runtime/layout.js";
import { readLockfiles } from "../runtime/lockfiles.js";
import { tailLog, verifyLog } from "../runtime/log.js";
import { appendBounded } from "../runtime/logbound.js";
import { dirProvenanceOf, notePrior, provenanceOf, recordWrites } from "../runtime/ledger.js";
import { realpathLoose, realpathStrict } from "../runtime/realpath.js";
import { statKind } from "../runtime/scope.js";
import { loadIndex, vaultView } from "../runtime/vault/index.js";
import { withRotatingPrints } from "../gateway/oauth-vault.js";
import { agentOfSession, stopTarget, stopView } from "../runtime/stops.js";
import { loadNevers, projectId } from "../runtime/learned.js";
import { readKnownHosts } from "../runtime/knownhosts.js";
import { pinnedApproverKey } from "../runtime/install.js";
import { appendEvents, consumeApproval, decideQueueItem, enqueue, getQueueItem, listQueue, loadState, type QueueItem } from "../runtime/store.js";
import { createGuard, resolvePolicy, type Guard } from "./guard.js";
import { memoryStore } from "./store.js";
import type { GuardOptions, HeldAction, LogEntry, LogSigner, ProvenanceLedger, StateStore } from "./types.js";

export * from "./index.js";
export { createRemoteGuard, readOnlyBySpec, type RemoteGuard } from "./remote.js";
export { RemoteHttpError, MAX_REQUEST_BYTES } from "./remote-http.js";
export type * from "./remote-types.js";

export interface FileStoreOptions {
  /** The firewall home to keep state in (its sessions/, queue/ and log/). Default: LAUNCHSAFE_FIREWALL_HOME or ~/.launchsafe-firewall. */
  home?: string;
  /**
   * Signs approvals made with guard.approve(): the unlocked approver key, or the passphrase to unlock it.
   * Without it, held actions are approved with `launchsafe-firewall queue approve <id>` (the person's passphrase).
   */
  approver?: KeyObject | { passphrase: string };
  /** The approver public key approvals must verify against (default: the pinned one, else the one in the firewall home). */
  approverPublicKey?: string | null;
  /** The environment the pinned key is read from (default process.env). */
  env?: NodeJS.ProcessEnv;
  /** The platform to check, for tests (default process.platform). Only macOS and Linux are supported: any other throws. */
  platform?: NodeJS.Platform;
}

function heldOf(it: QueueItem, by?: string): HeldAction {
  return {
    id: it.id,
    session: it.sessionId,
    createdAt: it.createdAt,
    tool: it.tool,
    input: it.input,
    actionHash: it.actionHash,
    rules: it.rules,
    reasons: it.reasons,
    kind: it.kind,
    ...(it.proposal !== undefined ? { proposal: { target: it.proposal.target, change: it.proposal.change } } : {}),
    status: it.status,
    ...(it.decidedAt !== undefined ? { decidedAt: it.decidedAt } : {}),
    ...(by !== undefined ? { by } : {}),
  };
}

export interface FileLedgerOptions {
  /** The firewall home whose ledger/ is read and written. Default: LAUNCHSAFE_FIREWALL_HOME or ~/.launchsafe-firewall. */
  home?: string;
  /** The platform to check, for tests (default process.platform). Only macOS and Linux are supported: any other throws. */
  platform?: NodeJS.Platform;
}

function ledgerOf(l: Layout): ProvenanceLedger {
  return {
    file: (abs, max, ci) => provenanceOf(l, abs, max, ci),
    dir: (abs, ci) => dirProvenanceOf(l, abs, ci),
    note: (n) => notePrior({ l, sessionId: n.session, tool: n.tool, effects: n.effects, maxHashBytes: n.maxHashBytes, ci: n.caseInsensitive }),
    record: (r) => void recordWrites({ l, sessionId: r.session, tool: r.tool, effects: r.effects, findings: r.findings, taintedBefore: r.taintedBefore, maxHashBytes: r.maxHashBytes, ci: r.caseInsensitive }),
  };
}

/**
 * The runtime's provenance ledger (`<home>/ledger/`) as a guard's ledger, through the functions the hook uses, so a file
 * written under the hook and one written under a guard on the same home know each other. fileStore() has it already; this
 * is for a custom store (`{ ...myStore, ledger: fileLedger({ home }) }`). Entries are ordered by the wall clock, as the
 * hook orders them, not by the guard's `now`. Refuses the real home while a test marker is set, and any platform but
 * macOS and Linux (it reads and writes the firewall home, like fileStore).
 */
export function fileLedger(o: FileLedgerOptions = {}): ProvenanceLedger {
  assertSupportedPlatform(o.platform);
  const l: Layout = o.home !== undefined ? layout(resolve(o.home)) : layout();
  assertNotRealHome(l.home);
  return ledgerOf(l);
}

/** The runtime's files as a guard's store. Refuses the real home while a test marker is set (the runtime's guard), and any platform but macOS and Linux. */
export function fileStore(o: FileStoreOptions = {}): StateStore {
  assertSupportedPlatform(o.platform);
  const l: Layout = o.home !== undefined ? layout(resolve(o.home)) : layout();
  assertNotRealHome(l.home);
  // The key the hook trusts: the one pinned in its command (LAUNCHSAFE_FIREWALL_APPROVER, else the installed hooks'
  // pin), else the one on disk; an explicit approverPublicKey wins.
  const key = (): string | null => (o.approverPublicKey !== undefined ? o.approverPublicKey : (pinnedApproverKey(l, o.env ?? process.env) ?? approverPublicKey(l)));
  // An unreadable approver file makes no resume count (the session stays stopped), never an error.
  const safeKey = (): string | null => {
    try {
      return key();
    } catch {
      return null;
    }
  };
  let priv: KeyObject | null = null;
  const signer = (): ReturnType<typeof approvalSigner> | undefined => {
    if (o.approver === undefined) return undefined;
    priv ??= "passphrase" in o.approver ? unlockApprover(l, o.approver.passphrase) : o.approver;
    return approvalSigner(priv);
  };
  return {
    kind: "file",
    firewallHome: l.home,
    load: (session) => loadState(l, session, key()),
    append: (session, events) => appendEvents(l, session, events),
    consumeApproval: (session, actionHash, approvalId) => consumeApproval(l, session, actionHash, approvalId),
    budgetView: (session, state, now) => loadBudgetView(l, session, state, now).view,
    recordBudget: (session, d, now) => recordBudget(l, session, d, now),
    confirmBudget: (session, hash, at) => confirmBudget(l, session, hash, at),
    // The kill switch's records, as the hook reads them: a stop of the session, or of its agent when the session
    // id names one (a local API session is <agentId>/<session>).
    stops: (session, agent) => stopView(l, session, agent ?? agentOfSession(session), safeKey()),
    stop: (target, s, now) => {
      const r = stopTarget(l, s.scope, target, { by: "monitor", reason: s.reason, signal: s.signal, now, approverKey: safeKey(), id: s.id });
      return { created: r.created, id: r.stop.id };
    },
    capView: (session, state, now) => loadCapView(l, session, state, now, key()),
    // The person's "never" choices and approved hosts for a project, from the firewall's home (as the hook reads them).
    nevers: (root) => loadNevers(l, projectId(root)),
    knownHosts: (root) => {
      const { file, damaged } = readKnownHosts(l, root);
      return damaged ? [] : file.approved.map((x) => x.host);
    },
    recordCaps: (_session, d, now) => recordDaily(l, d, now),
    recordFailure: (session, hash, fingerprints, now) => recordFailure(l, session, hash, fingerprints, now),
    capStopped: (session, d) => capStopped(l, session, d),
    hold: (item) =>
      heldOf(
        enqueue(l, {
          sessionId: item.session,
          cwd: item.cwd,
          tool: item.tool,
          input: item.input,
          actionHash: item.actionHash,
          rules: item.rules,
          reasons: item.reasons,
          kind: item.kind,
          ...(item.proposal !== undefined ? { proposal: item.proposal } : {}),
          ...(item.summary !== undefined ? { summary: item.summary } : {}),
          ...(item.trustSources !== undefined ? { trustSources: item.trustSources } : {}),
          unattended: item.unattended,
        }),
      ),
    held: (id) => {
      const it = getQueueItem(l, id);
      return it === null ? null : heldOf(it);
    },
    listHeld: (session) => listQueue(l).items.filter((it) => session === undefined || it.sessionId === session).map((it) => heldOf(it)),
    settle: (id, status, by) => {
      const it = getQueueItem(l, id);
      if (it === null) throw new Error(`no held action ${id}`);
      if (it.status !== "pending") throw new Error(`held action ${id} is already ${it.status}`);
      const sign = signer();
      if (status === "approved" && sign === undefined) throw new Error(`approving held action ${id} needs the approver key: run "launchsafe-firewall queue approve ${id}" with LAUNCHSAFE_FIREWALL_HOME=${l.home}, or give fileStore an approver`);
      return heldOf(decideQueueItem(l, id, status, sign), by);
    },
    // LG1/LR11: bounded, with the fallback entry, as the hook writes; LogUnrecorded when both are refused.
    appendLog: (event) => appendBounded(l, event) as LogEntry,
    entries: (limit) => tailLog(l, limit ?? Number.MAX_SAFE_INTEGER) as LogEntry[],
    verifyLog: () => {
      const r = verifyLog(l);
      return { ok: r.ok, entries: r.entries, signed: r.ok && r.entries > 0, problems: r.problems };
    },
    canaries: (ci, realpath) => loadCanaryIndex(l, ci, realpath),
    // F-e: the hook's provenance ledger, in the same home: what an untrusted session wrote stays untrusted in later sessions.
    ledger: ledgerOf(l),
    // The signed index verified against the approver key, read for each call as the hook reads it.
    vault: () => {
      let k: string | null;
      try {
        k = key();
      } catch {
        k = null;
      }
      return withRotatingPrints(l, vaultView(loadIndex(l, k)));
    },
  };
}

/** An Ed25519 signer for the memory store's log (a new key unless one is given). */
export function ed25519Signer(privateKey?: KeyObject | string): LogSigner & { publicKeyPem: string } {
  const priv = privateKey === undefined ? generateKeyPairSync("ed25519").privateKey : typeof privateKey === "string" ? createPrivateKey(privateKey) : privateKey;
  const pub = createPublicKey(priv);
  return {
    publicKeyPem: pub.export({ type: "spki", format: "pem" }) as string,
    sign: (hash) => sign(null, hash, priv).toString("base64"),
    verify: (hash, sig) => {
      try {
        return verify(null, hash, pub, Buffer.from(sig, "base64"));
      } catch {
        return false;
      }
    },
  };
}

function withReal(paths: readonly string[]): string[] {
  const out = new Set<string>();
  for (const p of paths) {
    if (p === "") continue;
    out.add(resolve(p));
    out.add(realpathLoose(resolve(p)));
  }
  return [...out];
}

export interface NodeEnvironmentOptions {
  workspace?: string | string[];
  /** Default os.homedir(). */
  home?: string;
  /** Default the OS temp directories. */
  scratch?: string[];
  /** The firewall home whose package-intel snapshot and install record are read (default: the file store's, else ~/.launchsafe-firewall). */
  firewallHome?: string;
  /** The guard's policy (for whether an installed sandbox profile is protected). Default the defaults. */
  policy?: GuardOptions["policy"];
  /** The platform to check, for tests (default process.platform). Only macOS and Linux are supported: any other throws. */
  platform?: NodeJS.Platform;
}

/**
 * What the hook's context builder gives the engine (src/runtime/context.ts): workspace roots with their
 * realpaths (a root of / or the home directory is refused: it would make every file a workspace file),
 * the OS temp directories as scratch, symlink resolution, file contents, the platform's case rule,
 * the installed package, the package-intel snapshot and the lockfile reader.
 */
export function nodeEnvironment(o: NodeEnvironmentOptions = {}): Pick<GuardOptions, "workspace" | "cwd" | "home" | "scratch" | "caseInsensitive" | "fs" | "settingsFiles" | "installDir" | "packageIntel" | "lockfiles"> {
  assertSupportedPlatform(o.platform);
  const home = o.home ?? homedir();
  const roots = o.workspace === undefined ? [] : Array.isArray(o.workspace) ? o.workspace : [o.workspace];
  const broad = (p: string): boolean => {
    const abs = resolve(p);
    return abs === "/" || abs === resolve(home) || resolve(home).startsWith(`${abs}/`);
  };
  const workspace = withReal(roots.filter((r) => !broad(r)));
  return {
    workspace,
    ...(roots[0] !== undefined ? { cwd: resolve(roots[0]) } : {}),
    home,
    scratch: withReal(o.scratch ?? [tmpdir(), "/tmp", "/private/tmp", "/var/tmp"]),
    // I1: the platform's rule, for what grants trust; protection folds case on every platform (engine/canonical.ts).
    caseInsensitive: process.platform === "darwin" || process.platform === "win32",
    fs: { realpath: realpathStrict, readFile: readSmallFile, stat: statKind, size: fileSize },
    // F13: the same protected settings files the hook judges by their result.
    settingsFiles: protectedSettingsFiles(layout(o.firewallHome ?? layout().home), resolvePolicy(o.policy), process.env, home),
    installDir: installDir(),
    packageIntel: openIntel(o.firewallHome ?? layout().home),
    lockfiles: readLockfiles,
  };
}

export interface NodeGuardOptions extends GuardOptions {
  /** "memory" (default) or "file": keep state in the runtime's files under `firewallHome`. A store given in `store` wins. */
  persist?: "memory" | "file";
  /** The firewall home for the file store and the package-intel snapshot. */
  firewallHome?: string;
  /** For persist: "file": signs approvals made with guard.approve(). */
  approver?: FileStoreOptions["approver"];
  /** The platform to check, for tests (default process.platform). Only macOS and Linux are supported: any other throws, before anything is created. */
  platform?: NodeJS.Platform;
}

/**
 * createGuard() with nodeEnvironment() filled in, and the file store when asked for. Explicit options win.
 * The memory store's log is signed with `signer`, else a new Ed25519 key for this process.
 */
export function createNodeGuard(o: NodeGuardOptions = {}): Guard {
  const { persist, firewallHome, approver, platform, ...rest } = o;
  // First, so no guard is made on an unsupported platform whatever store it was given.
  assertSupportedPlatform(platform);
  const store = rest.store ?? (persist === "file" ? fileStore({ ...(firewallHome !== undefined ? { home: firewallHome } : {}), ...(approver !== undefined ? { approver } : {}) }) : memoryStore({ signer: rest.signer ?? ed25519Signer() }));
  const env = nodeEnvironment({
    ...(rest.workspace !== undefined ? { workspace: rest.workspace } : {}),
    ...(rest.home !== undefined ? { home: rest.home } : {}),
    ...(rest.scratch !== undefined ? { scratch: rest.scratch } : {}),
    firewallHome: store.kind === "file" ? store.firewallHome : (firewallHome ?? layout().home),
    ...(rest.policy !== undefined ? { policy: rest.policy } : {}),
  });
  const defined = Object.fromEntries(Object.entries(rest).filter(([, v]) => v !== undefined)) as GuardOptions;
  // The scratch directories the person named are already in env.scratch with their resolved forms (a Mac's
  // /var/folders is /private/var/folders to the engine); passing them again would drop the resolved form.
  return createGuard({ ...env, ...defined, workspace: env.workspace ?? [], ...(env.scratch !== undefined ? { scratch: env.scratch } : {}), ...(rest.cwd !== undefined ? { cwd: rest.cwd } : env.cwd !== undefined ? { cwd: env.cwd } : {}), store });
}
