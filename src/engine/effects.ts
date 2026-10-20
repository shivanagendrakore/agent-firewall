/**
 * Builders that turn "this command reads X / writes Y / contacts Z" into
 * classified effects and findings. Shared by the shell analyzer and the
 * built-in and MCP tool classifiers, so every path and every destination is
 * judged by the same code.
 */

import { gatewayConfigFor } from "./gateway-config.js";
import type { Context, Effect, Finding, FindingId, FirewallConfig, SessionState } from "../types.js";
import { hostInList, isCaptureHost, isCaptureUrl, isDnsExfilShape, isLoopback, isMetadataEndpoint, isRawIp, parseUrlLike } from "./network.js";
import { canariesUnder, canaryAtPath } from "./canary.js";
import { isImportedInstruction } from "./imports.js";
import { classifyAsSpelled, classifyPath, containsCredentialStores, isUnder, normalizeAbs, pathForms, PROTECTION_FOLDS_CASE, resolvePath, UNKNOWN_ROOT, underUnknownCwd, type PathInfo, type ResolvedPath } from "./paths.js";
import type { Script } from "./shell/parse.js";
import { agentOfSettings, isAgentHookSettingsFile, registersFirewall, settingsFilesUnder } from "./settings.js";

export interface Collector {
  ctx: Context;
  cfg: FirewallConfig;
  state: SessionState;
  effects: Effect[];
  findings: Finding[];
  /** Shell variables bound to literal values in the same command (for f in *.ts; X=dist). */
  bindings?: Map<string, string[]>;
  /** Aliases defined in the same command (alias g='...'). */
  aliases?: Map<string, string>;
  /** FZ8/FZ10: shell functions defined anywhere in the command line, by name: every body given that name. */
  functions?: Map<string, Script[]>;
  /** How many function calls were followed into their bodies (bounded), and the ones being followed now. */
  functionCalls?: number;
  functionsActive?: Set<string>;
  /** Proxies set by a proxy variable earlier in the command line (https_proxy=...). */
  proxies?: string[];
  /** The current command's standard input: a file (< f), a pipe, or neither (a here-document is passed separately). */
  stdinFile?: string;
  stdinPiped?: boolean;
  /**
   * What the piped-in standard input holds when the command before it prints static text (echo or printf
   * of literals, cat of a here-document): every reading of it (an echo with backslashes may or may not
   * interpret them). null when the pipe carries output only known at run time; undefined when not piped.
   */
  stdinText?: readonly string[] | null;
  /** Files this command line wrote with a here-document (cat > f <<EOF), by absolute path; null when appended to. */
  heredocFiles?: Map<string, string | null>;
  /**
   * SELF-016: symbolic links this command line creates (ln -s), link -> target, absolute. A later part of
   * the same command reaches the target through the link before it exists on disk.
   */
  links?: Map<string, string>;
  /**
   * What this action's paths were judged to be under the context and policy now in force (see judgedFor). Shared
   * by the probe collectors the analyzer makes, so a path named again anywhere in the command line is not
   * judged again.
   */
  judged?: Judged;
}

const NAME_START = /[A-Za-z_]/;
const NAME_CHAR = /[A-Za-z0-9_]/;

/**
 * The variables a word refers to, in order: ${NAME...} up to the first "}" after the name, or $NAME. One pass:
 * the regular expression this replaces rescanned the rest of the word for each "${" that had no "}" after it
 * (CodeQL js/polynomial-redos). The first "}" is looked up once and kept while names stay before it.
 */
function varNames(raw: string): string[] {
  const names: string[] = [];
  let close = -1;
  let noClose = false;
  let i = 0;
  while (i < raw.length) {
    if (raw[i] !== "$") {
      i++;
      continue;
    }
    const braced = raw[i + 1] === "{";
    const start = braced ? i + 2 : i + 1;
    if (!NAME_START.test(raw[start] ?? "")) {
      i++;
      continue;
    }
    let end = start + 1;
    while (end < raw.length && NAME_CHAR.test(raw[end] as string)) end++;
    if (!braced) {
      names.push(raw.slice(start, end));
      i = end;
      continue;
    }
    if (!noClose && close < end) {
      close = raw.indexOf("}", end);
      noClose = close === -1;
    }
    if (noClose) {
      // An unclosed ${NAME is no reference, and "{" after the "$" is no $NAME either.
      i++;
      continue;
    }
    names.push(raw.slice(start, end));
    i = close + 1;
  }
  return names;
}

/**
 * Substitutes variables the same command bound to literal values. Returns the
 * text unchanged when any variable is unbound, so it stays "unresolvable".
 */
export function bindingVariants(c: Collector, raw: string): string[] {
  if (c.bindings === undefined || !raw.includes("$")) return [raw];
  const names = varNames(raw);
  if (names.length === 0 || names.some((n) => n === "HOME" || n === "PWD")) return [raw];
  if (!names.every((n) => c.bindings?.has(n) === true)) return [raw];
  if (/\$\(|`/.test(raw)) return [raw];
  let out = [raw];
  for (const n of new Set(names)) {
    const vals = c.bindings.get(n) as string[];
    const next: string[] = [];
    for (const t of out) for (const v of vals.slice(0, 16)) next.push(t.replace(new RegExp(String.raw`\$\{${n}(?:[^}]*)\}|\$${n}(?![A-Za-z0-9_])`, "g"), v));
    out = next.slice(0, 64);
  }
  return out;
}

export function newCollector(ctx: Context, cfg: FirewallConfig, state: SessionState): Collector {
  return { ctx, cfg, state, effects: [], findings: [], judged: newJudged(ctx, cfg) };
}

/**
 * Judgements of a path that depend only on the path, the context and the policy, remembered for the rest of the
 * action: a command of 17,000 words that name the same two paths (shell:robust seed 536906832, 612 ms) classified
 * each one against the whole pattern table again. A repeat gets exactly the answer it would have computed, because
 * everything an answer reads is kept here and compared: when any of it differs (the next pipeline's context carries
 * another resolver, or `ln` has just made a link), the memory starts over. The effects a judgement leads to are
 * still added every time, so what the rules see is unchanged.
 */
export interface Judged {
  cfg: FirewallConfig;
  realpath: Context["realpath"];
  workspaceRoots: Context["workspaceRoots"];
  scratchRoots: Context["scratchRoots"];
  home: string;
  caseInsensitive: boolean;
  firewallHome: string;
  firewallInstallDir: string;
  identity: Context["identity"];
  gatewayConfigs: Context["gatewayConfigs"];
  registeredSettings: Context["registeredSettings"];
  agentSettings: Context["agentSettings"];
  readFile: Context["readFile"];
  info: Map<string, PathInfo>;
  settings: Map<string, boolean>;
  imported: Map<string, boolean>;
}

/** Most answers of each kind kept (a command naming more distinct paths starts the memory over). */
const MAX_JUDGED = 4096;
/** Paths this long are judged afresh each time: their keys would hold the memory. */
const MAX_JUDGED_KEY = 1024;

function newJudged(x: Context, cfg: FirewallConfig): Judged {
  return {
    cfg,
    realpath: x.realpath,
    workspaceRoots: x.workspaceRoots,
    scratchRoots: x.scratchRoots,
    home: x.home,
    caseInsensitive: x.caseInsensitive,
    firewallHome: x.firewallHome,
    firewallInstallDir: x.firewallInstallDir,
    identity: x.identity,
    gatewayConfigs: x.gatewayConfigs,
    registeredSettings: x.registeredSettings,
    agentSettings: x.agentSettings,
    readFile: x.readFile,
    info: new Map(),
    settings: new Map(),
    imported: new Map(),
  };
}

function judgedFor(c: Collector): Judged {
  const x = c.ctx;
  const j = c.judged;
  if (
    j !== undefined &&
    j.cfg === c.cfg &&
    j.realpath === x.realpath &&
    j.workspaceRoots === x.workspaceRoots &&
    j.scratchRoots === x.scratchRoots &&
    j.home === x.home &&
    j.caseInsensitive === x.caseInsensitive &&
    j.firewallHome === x.firewallHome &&
    j.firewallInstallDir === x.firewallInstallDir &&
    j.identity === x.identity &&
    j.gatewayConfigs === x.gatewayConfigs &&
    j.registeredSettings === x.registeredSettings &&
    j.agentSettings === x.agentSettings &&
    j.readFile === x.readFile
  ) {
    return j;
  }
  const fresh = newJudged(x, c.cfg);
  c.judged = fresh;
  return fresh;
}

/** Forgets every remembered judgement: something a later one reads has changed (a link `ln` made). */
export function forgetJudgements(c: Collector): void {
  c.judged = newJudged(c.ctx, c.cfg);
}

/** The key of a resolved path: one string per distinct (abs, physical, glob), whatever characters the path holds. */
function judgedKey(r: ResolvedPath): string | null {
  const p = r.physical;
  if (r.abs.length + (p?.length ?? 0) > MAX_JUDGED_KEY) return null;
  return `${r.glob ? "g" : "p"}${p === undefined ? "-" : p.length}:${p ?? ""}${r.abs}`;
}

function remember<V>(m: Map<string, V>, key: string, v: V): V {
  if (m.size >= MAX_JUDGED) m.clear();
  m.set(key, v);
  return v;
}

/** classifyPath, remembered. */
function classified(c: Collector, r: ResolvedPath): PathInfo {
  const key = judgedKey(r);
  if (key === null) return classifyPath(r, c.ctx, c.cfg);
  const j = judgedFor(c);
  return j.info.get(key) ?? remember(j.info, key, classifyPath(r, c.ctx, c.cfg));
}

/** classifyAsSpelled, remembered (its keys start with "s"; classified's never do). */
function classifiedAsSpelled(c: Collector, r: ResolvedPath): PathInfo {
  const key = judgedKey(r);
  if (key === null) return classifyAsSpelled(r, c.ctx, c.cfg);
  const j = judgedFor(c);
  const k = `s${key}`;
  return j.info.get(k) ?? remember(j.info, k, classifyAsSpelled(r, c.ctx, c.cfg));
}

/** Whether a shell write of the path reaches a settings file the firewall cannot check, in any form of the path. */
function reachesSettings(c: Collector, r: ResolvedPath, remove: boolean): boolean {
  const compute = (): boolean => pathForms(r.abs, c.ctx, r.physical).paths.some((p) => touchesSettings(c, p, remove));
  const key = judgedKey(r);
  if (key === null) return compute();
  const j = judgedFor(c);
  const k = `${remove ? "d" : "w"}${key}`;
  return j.settings.get(k) ?? remember(j.settings, k, compute());
}

/** Whether an instruction file imports the path, remembered. */
function importedInstruction(c: Collector, abs: string): boolean {
  if (abs.length > MAX_JUDGED_KEY) return isImportedInstruction(c.ctx, abs);
  const j = judgedFor(c);
  return j.imported.get(abs) ?? remember(j.imported, abs, isImportedInstruction(c.ctx, abs));
}

/**
 * The keys of a collector's effects and findings, for duplicate checks in constant time (review of FZ17: a call
 * with tens of thousands of URLs made the linear check quadratic). Rebuilt whenever the list changed behind
 * addEffect's back, so it never hides an effect (a caller that removes effects pays a rebuild for each removal:
 * the shell analyzer judges a write it may drop on a copy of the collector instead, and adds what it keeps).
 */
const effectIndex = new WeakMap<Effect[], { byKey: Map<string, Effect>; size: number }>();
/** The payloads already folded into an effect (mergeEffect), so each is added once. */
const mergedPayloads = new WeakMap<Effect, Set<string>>();

const effectKey = (x: Effect): string => `${x.cls}\u0000${x.target}\u0000${x.detail}`;
const findingKey = (f: Finding): string => `${f.id}\u0000${f.detail}`;

/** A findings list's keys. */
interface FindingIndex {
  keys: Set<string>;
  size: number;
}
const findingIndexes = new WeakMap<Finding[], FindingIndex>();

function findingIndex(list: Finding[]): FindingIndex {
  let k = findingIndexes.get(list);
  if (k === undefined || k.size !== list.length) {
    k = { keys: new Set(list.map(findingKey)), size: list.length };
    findingIndexes.set(list, k);
  }
  return k;
}

export function addFinding(c: Collector, id: FindingId, detail: string): void {
  const idx = findingIndex(c.findings);
  const k = findingKey({ id, detail });
  if (idx.keys.has(k)) return;
  c.findings.push({ id, detail });
  idx.keys.add(k);
  idx.size = c.findings.length;
}

/** Records an effect once; whether it was new. An equal effect (same class, target and detail) already recorded
 * is not added again, but what the new one adds is merged into it: taints, private, tags, a download, a
 * proposal, upload bytes, and a payload it does not already carry, so dropping the duplicate never weakens what
 * the rules see. */
export function addEffect(c: Collector, e: Effect): boolean {
  let idx = effectIndex.get(c.effects);
  if (idx === undefined || idx.size !== c.effects.length) {
    const byKey = new Map<string, Effect>();
    for (const x of c.effects) if (!byKey.has(effectKey(x))) byKey.set(effectKey(x), x);
    idx = { byKey, size: c.effects.length };
    effectIndex.set(c.effects, idx);
  }
  const k = effectKey(e);
  const prior = idx.byKey.get(k);
  if (prior !== undefined) {
    mergeEffect(prior, e);
    return false;
  }
  c.effects.push(e);
  idx.byKey.set(k, e);
  idx.size = c.effects.length;
  return true;
}

/** Every file an effect downloads (download, then moreDownloads). */
export function downloadsOf(e: Effect): string[] {
  return e.download === undefined ? [] : [e.download, ...(e.moreDownloads ?? [])];
}

/** Folds what `e` adds into `into`, an equal effect recorded earlier (addEffect). Only ever stricter. */
function mergeEffect(into: Effect, e: Effect): void {
  if (e.taints === true) into.taints = true;
  if (e.private === true) into.private = true;
  if (e.tags !== undefined && e.tags.length > 0) {
    const tags = new Set([...(into.tags ?? []), ...e.tags]);
    if (tags.size !== (into.tags ?? []).length) into.tags = [...tags];
  }
  // Every distinct download is kept: each one is outside content later, so dropping one would trust a downloaded file.
  for (const d of downloadsOf(e)) {
    if (into.download === undefined) into.download = d;
    else if (!downloadsOf(into).includes(d)) into.moreDownloads = [...(into.moreDownloads ?? []), d];
  }
  if (into.proposal === undefined && e.proposal !== undefined) into.proposal = e.proposal;
  if (into.host === undefined && e.host !== undefined) into.host = e.host;
  if (into.destination === undefined && e.destination !== undefined) into.destination = e.destination;
  if (e.uploadBytes !== undefined) into.uploadBytes = Math.max(into.uploadBytes ?? 0, e.uploadBytes);
  if (e.payload !== undefined) {
    let seen = mergedPayloads.get(into);
    if (seen === undefined) {
      seen = new Set(into.payload !== undefined ? [into.payload] : []);
      mergedPayloads.set(into, seen);
    }
    if (!seen.has(e.payload)) {
      seen.add(e.payload);
      into.payload = into.payload === undefined ? e.payload : `${into.payload}\n${e.payload}`;
    }
  }
}

/** The most network destinations one action is judged by, one by one; past it the action is FW-UNCLASSIFIABLE. */
export const MAX_EGRESS_EFFECTS = 200;

const DEVICE_OK = /^\/dev\/(?:null|zero|stdout|stderr|stdin|tty|fd\/\d+|random|urandom)$/;

/** Variables that point at the temporary directory: writes there are scratch. */
const TEMP_PREFIX = /^(?:"?\$\{?(?:TMPDIR|TMP|TEMP|RUNNER_TEMP)\}?|\$\(\s*mktemp\b[^)]*\))(?=\/|$)/;

function isDownloadedLike(set: Set<string>, abs: string, ci: boolean): boolean {
  for (const d of set) if (isUnder(abs, d, ci)) return true;
  return false;
}

function isDownloaded(state: SessionState, abs: string, ci: boolean): boolean {
  for (const d of state.downloaded) if (isUnder(abs, d, ci)) return true;
  return false;
}

export interface ReadOptions {
  /** The read descends into directories (grep -r, tar, cp -r, rg). */
  recursive?: boolean;
  /** What reads it, for the reason a person sees. */
  via?: string;
  /** Only names and metadata are read (ls, stat, find without -exec): a glob that could name a credential store is not a read of it. */
  namesOnly?: boolean;
}

/** Records a read of a path. Returns the classification, or null when the path was empty. */
export function readPath(c: Collector, raw: string, opts: ReadOptions = {}): PathInfo | null {
  let last: PathInfo | null = null;
  for (const v of bindingVariants(c, raw)) last = readOne(c, v, opts) ?? last;
  return last;
}

/**
 * A decoy was touched: a finding (FW-CANARY-READ allows, because blocking would tell an attacker which file
 * is the decoy), and an effect that makes the session untrusted and sensitive and records the id.
 */
function tripCanary(c: Collector, abs: string, id: string, verb: "read" | "write" | "delete", via: string): void {
  addFinding(c, "canary_read", `${verb === "read" ? "reads" : verb === "write" ? "writes" : "deletes"} the decoy ${abs} that you planted${via}`);
  addEffect(c, { cls: verb === "read" ? "read_secret" : "write_workspace", target: abs, detail: `${verb} a decoy file planted by the person: ${abs}${via}`, private: true, taints: true, tags: ["canary", `canary:${id}`] });
}

/** What a read of a classified path is, by the first of readOne's checks that applies. */
type ReadKind = "firewall-key" | "firewall-data" | "credential-store" | "sweep" | "secret" | "outside" | "local";

/** `ci` is the case rule for the sweep check: PROTECTION_FOLDS_CASE with classifyPath's info, the platform's with classifyAsSpelled's. */
function readKind(c: Collector, r: ResolvedPath, info: PathInfo, opts: ReadOptions, ci: boolean): ReadKind {
  if (info.firewallData === "key") return "firewall-key";
  // I7: a glob that could name a store (/etc/ssh/ssh_host_*) reads it; a listing of one shows only names.
  const store = info.credentialStore || (info.globNamesStore === true && opts.namesOnly !== true);
  if (info.firewallData === "data" && !store) return "firewall-data";
  if (store) return "credential-store";
  // SELF-016: in any form of the path, so a symlinked alias of /etc/ssh or ~/.aws is swept as the directory itself.
  if (opts.recursive === true && pathForms(r.abs, c.ctx, r.physical).paths.some((p) => containsCredentialStores(p, c.ctx, ci))) return "sweep";
  if (info.secret || isDownloadedLike(c.state.secretPaths, info.abs, c.ctx.caseInsensitive)) return "secret";
  if (isDownloaded(c.state, info.abs, c.ctx.caseInsensitive) || info.untrusted || (info.zone === "outside" && !info.trustedRead && !info.firewall && !info.protected)) return "outside";
  return "local";
}

function readOne(c: Collector, raw: string, opts: ReadOptions): PathInfo | null {
  const r = resolvePath(raw, c.ctx);
  if (r === null || DEVICE_OK.test(r.abs)) return null;
  const via = opts.via === undefined ? "" : ` (${opts.via})`;
  if (underUnknownCwd(r.abs)) return readUnknownDir(c, r.abs, via);
  const info = classified(c, r);
  // Only a direct read trips by itself: ordinary searches sweep directories (policy canaries.tripOnRecursive changes that).
  const decoy = canaryAtPath(c.ctx, info.abs);
  if (decoy !== null) tripCanary(c, info.abs, decoy, "read", via);
  else if (opts.recursive === true && c.cfg.canaries.tripOnRecursive) for (const u of canariesUnder(c.ctx, info.abs)) tripCanary(c, u.path, u.id, "read", via);
  const kind = readKind(c, r, info, opts, PROTECTION_FOLDS_CASE);
  // I1: the lists fold case so that another spelling asks or is refused; that must not also turn outside content into
  // a local read. Whether a read is outside content follows the platform's rule (classifyAsSpelled): on a
  // case-sensitive disk, agents.md in someone else's directory only folds to an instruction file's name, and stays
  // outside content. That taint is recorded first, so a caller that judges a read by its first effect (ls) sees it.
  const mayDiffer = c.ctx.caseInsensitive !== PROTECTION_FOLDS_CASE && kind !== "outside" && ((info.zone === "outside" && !info.trustedRead) || info.untrusted || isDownloaded(c.state, info.abs, c.ctx.caseInsensitive));
  const outside = kind === "outside" || (mayDiffer && readKind(c, r, classifiedAsSpelled(c, r), opts, c.ctx.caseInsensitive) === "outside");
  if (outside) readOutside(c, info, via);
  switch (kind) {
    case "firewall-key":
      // I2: the firewall's own data. Its keys, vault and signing material are never read by an agent (denied as
      // tampering: a read key signs approvals or forges the log); anything else there is a credential store (asked).
      addFinding(c, "credential_store_read", `reads the firewall's own keys at ${info.abs}${via}`);
      addEffect(c, { cls: "firewall_tamper", target: info.abs, detail: `read the firewall's own keys or vault at ${info.abs}${via} (they sign approvals and the log)`, private: true });
      break;
    case "firewall-data":
      addFinding(c, "credential_store_read", `reads the firewall's own data at ${info.abs}${via}`);
      addEffect(c, { cls: "read_secret", target: info.abs, detail: `read the firewall's own data ${info.abs}${via} (a credential store)`, private: true });
      break;
    case "credential-store":
      addFinding(c, "credential_store_read", `reads ${info.abs}${via}`);
      addEffect(c, { cls: "read_secret", target: info.abs, detail: `read the credential store ${info.abs}${via}`, private: true });
      break;
    case "sweep":
      addFinding(c, "recursive_home_sweep", `searches everything under ${info.abs}${via}, including credential stores`);
      addEffect(c, { cls: "read_secret", target: info.abs, detail: `search everything under ${info.abs}${via}`, private: true });
      break;
    case "secret":
      addEffect(c, { cls: "read_secret", target: info.abs, detail: `read the secret file ${info.abs}${via}`, private: true });
      break;
    case "local":
      if (!outside) addEffect(c, { cls: "read_local_workspace", target: info.abs, detail: `read ${info.abs}${via}` });
      break;
    case "outside":
      break;
  }
  return info;
}

/** A read of content from outside the workspace (taints), unless the agent wrote it itself from a trusted session. */
function readOutside(c: Collector, info: PathInfo, via: string): void {
  const downloaded = isDownloaded(c.state, info.abs, c.ctx.caseInsensitive);
  // F-e: outside the workspace, content the agent itself wrote from a trusted session is not outside content.
  const prov = !downloaded && !info.untrusted ? selfProvenance(c, info.abs) : null;
  if (prov !== null && prov.selfAuthored && !prov.taintedAtWrite) {
    addEffect(c, { cls: "read_local_workspace", target: info.abs, detail: `read ${info.abs}${via}, a file the agent wrote itself`, tags: ["self-authored"] });
    return;
  }
  const why = downloaded
    ? "a downloaded file"
    : info.untrusted
      ? "third-party content"
      : prov === null
        ? "a file outside the workspace"
        : prov.selfAuthored
          ? "a file an untrusted session wrote"
          : "a file the agent wrote earlier but something else changed since";
  addEffect(c, { cls: "read_external", target: info.abs, detail: `read ${why}: ${info.abs}${via}`, taints: true });
}

/**
 * F-f: a relative read after a cd the firewall cannot follow. The file's name still tells a secret
 * (.env) from ordinary content; where it is does not, so it taints only a session that is already
 * untrusted (stricter is pointless there and noisy in a trusted one).
 */
function readUnknownDir(c: Collector, abs: string, via: string): PathInfo {
  const tail = abs.slice(UNKNOWN_ROOT.length).replace(/^(?:\/_)+/, "");
  const as = `${withoutTrailingSlashes(c.ctx.workspaceRoots[0] ?? "/__workspace__")}${tail === "" ? "" : tail}`;
  const info = classified(c, { abs: as, exact: false, glob: false });
  const shown = `<unknown directory>${tail}`;
  if (info.secret || info.credentialStore) addEffect(c, { cls: "read_secret", target: shown, detail: `read the secret file ${shown} in a directory the firewall cannot follow${via}`, private: true });
  else if (c.state.tainted) addEffect(c, { cls: "read_external", target: shown, detail: `read ${shown} in a directory the firewall cannot follow${via}`, taints: true });
  else addEffect(c, { cls: "read_local_workspace", target: shown, detail: `read ${shown}${via}`, tags: ["cwd-unknown"] });
  return { ...info, abs };
}

/** The text without its trailing "/"s, by a backward scan (/\/+$/ retries the run from each "/" in it: CodeQL js/polynomial-redos). */
export function withoutTrailingSlashes(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 47) end--;
  return end === s.length ? s : s.slice(0, end);
}

/** F-e: the ledger's view of a file, when the policy trusts self-authored files (null on any doubt). */
export function selfProvenance(c: Collector, abs: string): { selfAuthored: boolean; taintedAtWrite: boolean } | null {
  if (!c.cfg.provenance.trustSelfAuthored || c.ctx.provenance === undefined) return null;
  try {
    return c.ctx.provenance(abs);
  } catch {
    return null;
  }
}

/** F-e: a file whose current content an untrusted session wrote, in this or an earlier session. */
export function writtenByUntrustedSession(c: Collector, abs: string): boolean {
  if (!c.cfg.provenance.carryUntrustedWrites || c.ctx.provenance === undefined) return false;
  try {
    const p = c.ctx.provenance(abs);
    return p !== null && p.selfAuthored && p.taintedAtWrite;
  } catch {
    return false;
  }
}

/** F-e: a directory outside the workspace that a trusted agent session created (listing it shows names, not content). */
export function createdByTrustedSession(c: Collector, abs: string): boolean {
  if (!c.cfg.provenance.trustSelfAuthored || c.ctx.dirProvenance === undefined) return false;
  try {
    const d = c.ctx.dirProvenance(abs);
    return d !== null && d.createdBySession && !d.taintedAtWrite;
  } catch {
    return false;
  }
}

export interface WriteOptions {
  via?: string;
  /** The writer's resulting content is checked separately (the Write/Edit tools); skip the unverifiable-settings rule. */
  contentChecked?: boolean;
  /** The content or change, kept as a proposal if the write is held. */
  proposal?: string;
  /** A deletion rather than a write. */
  remove?: boolean;
}

/** Records a write (or delete) of a path. */
export function writePath(c: Collector, raw: string, opts: WriteOptions = {}): PathInfo | null {
  let last: PathInfo | null = null;
  for (const v of bindingVariants(c, raw)) last = writeOne(c, v, opts) ?? last;
  return last;
}

function writeOne(c: Collector, raw: string, opts: WriteOptions): PathInfo | null {
  let text = raw.trim();
  if (text === "") return null;
  let scratch = false;
  const tmp = TEMP_PREFIX.exec(text);
  if (tmp !== null) {
    text = `/tmp${text.slice(tmp[0].length)}`;
    scratch = true;
  }
  const r = resolvePath(text, c.ctx);
  if (r === null || DEVICE_OK.test(r.abs)) return null;
  const info = classified(c, r);
  const verb = opts.remove === true ? "delete" : "write";
  const via = opts.via === undefined ? "" : ` (${opts.via})`;
  const decoy = canaryAtPath(c.ctx, info.abs);
  if (decoy !== null) tripCanary(c, info.abs, decoy, verb, via);
  if (!r.exact && !scratch) addFinding(c, "unresolvable_write_target", `${verb}s ${raw}, whose final path is only known at run time`);
  const base: Pick<Effect, "target"> & { proposal?: string } = { target: info.abs };
  if (opts.proposal !== undefined) base.proposal = opts.proposal;
  // SELF-016: a settings file reached through a symlinked alias is that settings file.
  if (opts.contentChecked !== true && reachesSettings(c, r, opts.remove === true)) {
    addEffect(c, { ...base, cls: "firewall_tamper", detail: `${verb} ${agentOfSettings(info.abs)} settings at ${info.abs}${via} in a way the firewall cannot check; this could remove its hooks or switch hooks off (use the Write or Edit tool, whose result is checked)` });
    return info;
  }
  if (info.firewall) addEffect(c, { ...base, cls: "firewall_tamper", detail: `${verb} the firewall's own file ${info.abs}${via}` });
  else if (info.unresolved === true) addEffect(c, { ...base, cls: "write_protected", detail: `${verb} ${info.abs}${via}, which the firewall cannot resolve (a symlink loop or a directory it may not search), so it may be a protected file`, tags: ["unresolved"] });
  else if (info.protected) addEffect(c, { ...base, cls: "write_protected", detail: `${verb} ${info.memory ? "the agent's memory" : "the agent's instructions or settings"}: ${info.abs}${via}`, ...(info.memory ? { tags: ["memory"] } : settingsTag(info.abs)) });
  else if (importedInstruction(c, info.abs)) addEffect(c, { ...base, cls: "write_protected", detail: `${verb} ${info.abs}, which the agent's instructions import (an @ reference in CLAUDE.md or a file it imports), so it loads as instructions in every session${via}` });
  else if (info.persistence) addEffect(c, { ...base, cls: "write_persistence", detail: `${verb} ${info.abs}, which ${persistWhat(info)}${via}`, ...persistTags(info, opts.remove === true) });
  else if (info.zone === "outside" && !scratch) addEffect(c, { ...base, cls: "write_outside_workspace", detail: `${verb} ${info.abs}, outside the workspace${via}` });
  else if (opts.contentChecked !== true && !scratch && CONTENT_PERSISTENCE.test(info.abs)) {
    // F18: .gitattributes and shell.nix are persistence points by content (a driver, a shellHook). A shell
    // write's content cannot be checked, so it is one of those writes (asks when the session is untrusted).
    const git = /\.gitattributes$/i.test(info.abs);
    addEffect(c, { ...base, cls: "write_persistence", detail: `${verb} ${info.abs}, which can ${git ? "name a git driver that runs a program" : "hold a nix shellHook that runs when the shell starts"}, and the firewall cannot see the content a shell write leaves${via}`, tags: [`persist:${git ? "git-hook" : "devcontainer"}`, ...(opts.remove === true ? ["removed"] : [])] });
  } else addEffect(c, { ...base, cls: "write_workspace", detail: `${verb} ${info.abs}${via}` });
  return info;
}

/** F18: files that run code only by what they contain (judged by content for the Write/Edit tools). */
const CONTENT_PERSISTENCE = /(?:^|\/)(?:\.gitattributes|shell\.nix|flake\.nix)$/i;

/** What a persistence point is, for the reason a person reads. */
function persistWhat(info: PathInfo): string {
  switch (info.persistTag) {
    case "ci":
      return "a CI system runs (a CI file)";
    case "git-hook":
      return "git runs on its own (a git hook or hook manager)";
    case "editor-task":
      return "an editor runs (an editor task or settings file)";
    case "devcontainer":
      return "a dev container runs when it starts (a dev-container file)";
    case "env-hook":
      return "runs when you enter the folder or install packages (an environment hook)";
    default:
      return "runs code later on its own";
  }
}

/** The persistence tag (persist:<tag>), and whether the write removes the file. */
function persistTags(info: PathInfo, remove: boolean): { tags?: string[] } {
  const tags = [...(info.persistTag !== undefined ? [`persist:${info.persistTag}`] : []), ...(remove ? ["removed"] : [])];
  return tags.length > 0 ? { tags } : {};
}

/**
 * Whether a write the firewall cannot see the result of reaches a Claude Code settings file: the file
 * itself (any content could switch hooks off), or a directory holding one that registers the firewall.
 */
function touchesSettings(c: Collector, abs: string, remove: boolean): boolean {
  // I1: settings files are protected ignoring case on every platform (PROTECTION_FOLDS_CASE, paths.ts).
  const ci = PROTECTION_FOLDS_CASE;
  // An MCP client configuration the gateway wrapped; a shell write's result cannot be checked.
  if (gatewayConfigFor(c.ctx, abs) !== null) return true;
  // V9: a directory holding one (moved away, copied or extracted over, removed): the wrapped file goes with it.
  if ((c.ctx.gatewayConfigs ?? []).some((g) => isUnder(g.path, abs, ci))) return true;
  if (isAgentHookSettingsFile(abs) || (c.ctx.agentSettings ?? []).some((p) => p.toLowerCase() === abs.toLowerCase())) {
    if (!remove) return true;
    return registeredHere(c, abs);
  }
  const inside = [...settingsFilesUnder(abs), ...[...(c.ctx.registeredSettings ?? []), ...(c.ctx.agentSettings ?? [])].filter((p) => isUnder(p, abs, ci))];
  return inside.some((p) => registeredHere(c, p));
}

function registeredHere(c: Collector, abs: string): boolean {
  const lc = (s: string): string => s.toLowerCase();
  if ((c.ctx.registeredSettings ?? []).some((p) => lc(p) === lc(abs))) return true;
  let text: string | null = null;
  try {
    text = c.ctx.readFile?.(abs) ?? null;
  } catch {
    text = null;
  }
  return registersFirewall(text);
}

/** Settings files that can register hooks or MCP servers (code that runs), not just text instructions. */
function settingsTag(abs: string): { tags?: string[] } {
  return /(?:\/\.claude\/settings(?:\.local)?\.json|\/\.claude\.json|\/\.mcp\.json|\/managed-settings\.json|\/managed-settings\.d\/|\/\.claude\/hooks\/|\/\.cursor\/mcp\.json|\/\.vscode\/mcp\.json|\/\.claude\/agents\/|\/\.claude\/commands\/|\/\.claude\/skills\/|\/claude_desktop_config\.json|\/\.codex\/(?:hooks\.json|config\.toml)|\/\.gemini\/settings\.json|\/codex\/requirements\.toml|\/(?:GeminiCli|gemini-cli)\/(?:settings|system-defaults)\.json|\/\.cursor\/(?:hooks|cli|cli-config)\.json|\/Application Support\/Cursor\/hooks\.json|\/etc\/cursor\/hooks\.json)/i.test(abs)
    ? { tags: ["settings"] }
    : {};
}

export interface EgressOptions {
  /** The text that leaves the machine with this request. */
  payload?: string;
  /** The URL scheme to assume for a bare host. */
  scheme?: string;
  via?: string;
  /** Override the destination identity (github:owner/repo). */
  destination?: string;
}

/** Records network traffic to a URL or host. Returns false when the text is not an address. */
export function egress(c: Collector, raw: string, mode: "fetch" | "send", opts: EgressOptions = {}): boolean {
  const p = parseUrlLike(raw, opts.scheme ?? "http");
  if (p === null) return false;
  // Review of FZ17: past MAX_EGRESS_EFFECTS destinations the action is not judged destination by destination
  // (each one carries the whole payload to the data rules); a person decides instead.
  if (c.effects.filter((x) => x.cls === "egress_send" || x.cls === "egress_fetch").length >= MAX_EGRESS_EFFECTS) {
    addFinding(c, "too_large", `it contacts more than ${MAX_EGRESS_EFFECTS} network destinations, more than the firewall judges one by one`);
    return true;
  }
  const via = opts.via === undefined ? "" : ` (${opts.via})`;
  if (isLoopback(p.host)) {
    // M7: services on this machine (a dev server, a database console, a local agent API) are reachable from a
    // trusted session without a question; after outside content, a request to one is a send a person approves.
    if (c.state.tainted) addEffect(c, { cls: "egress_send", target: p.url, host: p.host, destination: p.host, detail: `contact a service on this machine (${p.host}) after reading outside content${via}`, payload: opts.payload ?? p.url, tags: ["loopback"] });
    return true;
  }
  if (isMetadataEndpoint(p.host)) {
    addFinding(c, "metadata_endpoint", `${p.host} is a cloud metadata service, which can hand out this machine's credentials`);
    addEffect(c, { cls: "read_secret", target: p.url, host: p.host, detail: `ask the cloud metadata service ${p.host} for credentials${via}`, private: true });
    return true;
  }
  if (hostInList(p.host, c.cfg.denyHosts)) addFinding(c, "capture_host", `${p.host} is on the deny list`);
  if (isCaptureUrl(p) || isCaptureHost(p.host)) addFinding(c, "capture_host", `${p.host} is a data-capture or tunnelling service`);
  if (isRawIp(p.host)) addFinding(c, "raw_ip", `${p.host} is a bare IP address`);
  if (isDnsExfilShape(p.host)) addFinding(c, "dns_exfil_shape", `${p.host} has a host name built to carry data`);
  const e: Effect = {
    cls: mode === "send" ? "egress_send" : "egress_fetch",
    target: p.url,
    host: p.host,
    destination: opts.destination ?? p.host,
    detail: `${mode === "send" ? "send data to" : "contact"} ${p.host}${via}`,
  };
  e.payload = opts.payload ?? p.url;
  // F19: an incoming chat webhook posts a message (Slack, Microsoft Teams, Google Chat, Mattermost-style hooks).
  if (mode === "send" && isMessageWebhook(p)) e.tags = [...(e.tags ?? []), "message"];
  addEffect(c, e);
  return true;
}

/** F19: URLs that post a chat message to whoever holds them. */
export function isMessageWebhook(p: { host: string; path: string }): boolean {
  if (p.host === "hooks.slack.com" || p.host === "hooks.slack-gov.com") return true;
  if (/(?:^|\.)webhook\.office\.com$/.test(p.host) || (p.host === "outlook.office.com" && /^\/webhook/i.test(p.path))) return true;
  if (p.host === "chat.googleapis.com" && /\/messages/.test(p.path)) return true;
  if (/(?:^|\.)logic\.azure\.com$/.test(p.host) && /\/workflows\//.test(p.path)) return true;
  return /\/hooks\/[A-Za-z0-9]{20,}$/.test(p.path) && /mattermost|rocket/i.test(p.host);
}

/** An external system reached through a tool (an MCP server, a CLI) rather than a URL. */
/**
 * A send to a destination outside the machine. `extra` sets the effect's class, tags or taint when it is
 * recorded: a caller never relabels "the last effect" afterwards, because when an equal effect is already
 * recorded (a function body walked again at its call) nothing is added and the last effect is another
 * command's (a write to ~/.ssh/authorized_keys relabelled as a fetch was allowed: shell:grammar 68636).
 */
export function externalSend(c: Collector, destination: string, detail: string, payload: string, extra: Partial<Pick<Effect, "cls" | "taints" | "private" | "tags">> = {}): void {
  addEffect(c, { cls: "egress_send", target: destination, destination, detail, payload, ...extra });
}

export function abs(c: Collector, raw: string): string {
  const r = resolvePath(raw, c.ctx);
  return r === null ? normalizeAbs(c.ctx.cwd) : r.abs;
}

/** Marks the content a network command brings back as outside content (taints the session). */
export function taintFetched(c: Collector, urls: readonly string[], via: string): void {
  if (urls.length === 0) return;
  for (const u of urls) {
    const p = parseUrlLike(u);
    if (p !== null && (isLoopback(p.host) || isMetadataEndpoint(p.host))) continue;
    addEffect(c, { cls: "read_external", target: p?.url ?? u, detail: `read what ${via} brings back from ${p?.host ?? u}`, taints: true });
  }
}

