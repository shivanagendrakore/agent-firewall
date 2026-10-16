/**
 * The sandbox profile, runtime side: reads the effective Claude Code sandbox settings (the
 * same scopes Claude Code merges, for the `sandbox` key only; it never runs
 * Claude Code), scores them in `doctor`, plans and applies `doctor --fix`
 * (behind the approval passphrase, with a backup and a record), and checks a
 * recorded profile on ConfigChange.
 *
 * The record lives in `sandbox-install.json` beside `install.json` (both in
 * the firewall's protected data directory): it holds the exact `sandbox`
 * object written, so a later change can be compared with it.
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { broadWritePath, domainWithinPolicy, mergeSettingsLayers, WEAKENING_KEYS, profileFromPolicy, SANDBOX_FILESYSTEM_KEYS, SANDBOX_KEYS, SANDBOX_NETWORK_KEYS, SANDBOX_SCHEMA_VERSION, sandboxPolicy, sandboxViolations, settingsRank, webFetchDomains, type HostLabel, type Json } from "../engine/sandbox.js";
import type { FirewallConfig } from "../types.js";
import { approverPublicKey, unlockApprover } from "./approver.js";
import { loadPolicy } from "./config.js";
import type { Check } from "./doctor.js";
import { stripBom } from "../bom.js";
import { atomicWrite, parseJsonFile, readText, readTextExact, withLock, writeUserFile } from "./fsutil.js";
import { recordOwnWrite } from "./install.js";
import { assertNotRealHome } from "./guard.js";
import { MANAGED_SETTINGS_PATHS, settingsPath, type Scope } from "./install.js";
import type { Layout } from "./layout.js";
import { own, setOwn } from "../own.js";

// --- reading the effective settings --------------------------------------------------------------

export interface SandboxView {
  /** Settings files that set something under `sandbox` (managed, local, project, user). */
  source: string[];
  enabled: boolean;
  autoAllowBash: boolean;
  allowUnsandboxed: boolean;
  excludedCommands: string[];
  /** null: no file sets it (the network is not restricted to a list). */
  allowedDomains: string[] | null;
  deniedDomains: string[];
  /** Hosts outside the list are refused instead of prompted (honoured from user and managed settings only). */
  strictAllowlist: boolean;
  /** WebFetch(domain:...) allow rules Claude Code merges into the allowlist. */
  webFetchDomains: string[];
  /** allowedDomains and WebFetch rules contributed by the repository (project and local settings). */
  repoDomains: string[];
  allowUnixSockets: string[];
  allowAllUnixSockets: boolean;
  allowLocalBinding: boolean;
  /** sandbox.filesystem.allowWrite. */
  writableExtra: string[];
  /** Settings that weaken isolation (filesystem.disabled, enableWeaker*, allowAppleEvents, own proxies). */
  weakeners: string[];
  /** Managed settings set sandbox.enabled. */
  managedLocked: boolean;
  /** Files that could not be read, or values of the wrong type. */
  problems: string[];
  /** sandbox keys the 2.1.289 schema does not have. */
  unknownKeys: string[];
}

interface Layer {
  scope: "managed" | "local" | "project" | "user";
  path: string;
  doc: Json;
}

const obj = (v: unknown): Json | null => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : null);

function managedFiles(platform: NodeJS.Platform, managedPath?: string): string[] {
  const main = managedPath ?? MANAGED_SETTINGS_PATHS[platform];
  if (main === undefined) return [];
  const out = [main];
  try {
    const d = join(dirname(main), "managed-settings.d");
    for (const f of readdirSync(d).filter((n) => n.endsWith(".json")).sort()) out.push(join(d, f));
  } catch {
    // No drop-in directory.
  }
  return out;
}

function readLayers(projectDir: string, home: string, platform: NodeJS.Platform, managedPath: string | undefined, problems: string[]): Layer[] {
  const files: { scope: Layer["scope"]; path: string }[] = [
    ...managedFiles(platform, managedPath).map((path) => ({ scope: "managed" as const, path })),
    { scope: "local", path: settingsPath("local", projectDir, home) },
    { scope: "project", path: settingsPath("project", projectDir, home) },
    { scope: "user", path: settingsPath("user", projectDir, home) },
  ];
  const out: Layer[] = [];
  for (const f of files) {
    let text: string | null;
    try {
      text = readText(f.path);
    } catch (e) {
      problems.push(`${f.path} cannot be read (${(e as Error).message})`);
      continue;
    }
    if (text === null || text.trim() === "") continue;
    try {
      const doc = obj(JSON.parse(text));
      if (doc === null) problems.push(`${f.path} is not a JSON object`);
      else out.push({ scope: f.scope, path: f.path, doc });
    } catch (e) {
      problems.push(`${f.path} is not valid JSON (${(e as Error).message})`);
    }
  }
  return out;
}

/**
 * The effective sandbox settings: scalars from the highest scope that sets them (managed > local >
 * project > user), lists merged across scopes, as Claude Code documents for these keys.
 */
export function readSandbox(projectDir: string, home: string = homedir(), platform: NodeJS.Platform = process.platform, opts: { managedPath?: string } = {}): SandboxView {
  const problems: string[] = [];
  const layers = readLayers(projectDir, home, platform, opts.managedPath, problems);
  const unknown = new Set<string>();
  const sb: { layer: Layer; s: Json }[] = [];
  for (const layer of layers) {
    const raw = layer.doc.sandbox;
    if (raw === undefined) continue;
    const s = obj(raw);
    if (s === null) {
      problems.push(`${layer.path}: "sandbox" must be an object (Claude Code ${SANDBOX_SCHEMA_VERSION} has no boolean form)`);
      continue;
    }
    sb.push({ layer, s });
    for (const k of Object.keys(s)) if (!SANDBOX_KEYS.includes(k)) unknown.add(k);
    for (const [sub, keys] of [["network", SANDBOX_NETWORK_KEYS], ["filesystem", SANDBOX_FILESYSTEM_KEYS]] as const) {
      const o = obj(s[sub]);
      if (s[sub] !== undefined && o === null) problems.push(`${layer.path}: "sandbox.${sub}" must be an object`);
      for (const k of Object.keys(o ?? {})) if (!keys.includes(k)) unknown.add(`${sub}.${k}`);
    }
  }
  const pick = (path: readonly string[], type: "boolean" | "number"): unknown => {
    for (const { layer, s } of sb) {
      let v: unknown = s;
      for (const k of path) v = own(obj(v), k);
      if (v === undefined) continue;
      if (typeof v !== type) {
        problems.push(`${layer.path}: "sandbox.${path.join(".")}" must be a ${type}`);
        continue;
      }
      return v;
    }
    return undefined;
  };
  const merged = (path: readonly string[], scopes?: readonly Layer["scope"][]): string[] | null => {
    let seen = false;
    const outList: string[] = [];
    for (const { layer, s } of sb) {
      if (scopes !== undefined && !scopes.includes(layer.scope)) continue;
      let v: unknown = s;
      for (const k of path) v = own(obj(v), k);
      if (v === undefined) continue;
      if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) {
        problems.push(`${layer.path}: "sandbox.${path.join(".")}" must be a list of strings`);
        continue;
      }
      seen = true;
      outList.push(...(v as string[]));
    }
    return seen ? [...new Set(outList)] : null;
  };
  // Claude Code honours strictAllowlist from user and managed settings only; when on, the repository's
  // allowedDomains and WebFetch rules are left out of the allowlist.
  let strict = false;
  for (const { layer, s } of sb) {
    if (layer.scope !== "user" && layer.scope !== "managed") continue;
    const v = obj(s.network)?.strictAllowlist;
    if (typeof v === "boolean") {
      strict = v;
      break;
    }
  }
  const allScopes = strict ? (["managed", "user"] as const) : undefined;
  const allowedDomains = merged(["network", "allowedDomains"], allScopes);
  const repo = strict ? [] : [...(merged(["network", "allowedDomains"], ["project", "local"]) ?? []), ...layers.filter((x) => x.scope === "project" || x.scope === "local").flatMap((x) => webFetchDomains(x.doc))];
  const wf = layers.filter((x) => !strict || x.scope === "user" || x.scope === "managed").flatMap((x) => webFetchDomains(x.doc));
  const weakeners: string[] = [];
  if (pick(["filesystem", "disabled"], "boolean") === true) weakeners.push("sandbox.filesystem.disabled");
  for (const k of ["enableWeakerNestedSandbox", "enableWeakerNetworkIsolation", "allowAppleEvents"]) if (pick([k], "boolean") === true) weakeners.push(`sandbox.${k}`);
  for (const k of ["httpProxyPort", "socksProxyPort"]) if (pick(["network", k], "number") !== undefined) weakeners.push(`sandbox.network.${k}`);
  return {
    source: [...new Set(sb.map((x) => x.layer.path))],
    enabled: pick(["enabled"], "boolean") === true,
    autoAllowBash: pick(["autoAllowBashIfSandboxed"], "boolean") !== false,
    allowUnsandboxed: pick(["allowUnsandboxedCommands"], "boolean") !== false,
    excludedCommands: merged(["excludedCommands"]) ?? [],
    allowedDomains,
    deniedDomains: merged(["network", "deniedDomains"]) ?? [],
    strictAllowlist: strict,
    webFetchDomains: [...new Set(wf)],
    repoDomains: [...new Set(repo)],
    allowUnixSockets: merged(["network", "allowUnixSockets"]) ?? [],
    allowAllUnixSockets: pick(["network", "allowAllUnixSockets"], "boolean") === true,
    allowLocalBinding: pick(["network", "allowLocalBinding"], "boolean") === true,
    writableExtra: merged(["filesystem", "allowWrite"]) ?? [],
    weakeners,
    managedLocked: sb.some((x) => x.layer.scope === "managed" && x.s.enabled !== undefined),
    problems,
    unknownKeys: [...unknown].sort(),
  };
}

// --- the record ----------------------------------------------------------------------------------

export interface SandboxRecord {
  kind: "sandbox";
  scope: Scope;
  path: string;
  /** sha256 of the canonical JSON of `profile`. */
  profileHash: string;
  /** The exact `sandbox` object written. */
  profile: Json;
  /** The settings file as it was before the firewall first wrote a sandbox profile into it. */
  backup: string;
  installedAt: string;
  /**
   * F10: the WebFetch(domain:...) allow rules the file held when the profile was recorded (the person's own;
   * Claude Code merges them into the allowlist). Older records: read from the backup.
   */
  webFetch?: string[];
}

export function sandboxRecordsPath(l: Layout): string {
  return join(l.home, "sandbox-install.json");
}

export function readSandboxRecords(l: Layout): SandboxRecord[] {
  const t = readText(sandboxRecordsPath(l));
  if (t === null) return [];
  const v = parseJsonFile(sandboxRecordsPath(l), t);
  if (!Array.isArray(v) || !v.every((r) => obj(r)?.kind === "sandbox" && typeof obj(r)?.path === "string" && obj(obj(r)?.profile) !== null)) throw new Error(`${sandboxRecordsPath(l)} is corrupt`);
  return v as SandboxRecord[];
}

function writeSandboxRecords(l: Layout, r: SandboxRecord[]): void {
  atomicWrite(sandboxRecordsPath(l), JSON.stringify(r, null, 2));
}

function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  const o = v as Json;
  return `{${Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(own(o, k))}`)
    .join(",")}}`;
}

export function profileHash(sandbox: unknown): string {
  return createHash("sha256").update(canonical(sandbox)).digest("hex");
}

/**
 * The recorded profiles, for the hook's context. An unreadable record protects nothing here, but
 * every settings file stays covered by the hook rules, and doctor reports the record.
 */
export function loadSandboxProfiles(l: Layout): { path: string; installed: Json }[] {
  try {
    return readSandboxRecords(l).map((r) => ({ path: r.path, installed: r.profile }));
  } catch {
    return [];
  }
}

function currentSandbox(path: string): { text: string | null; doc: Json | null; error?: string } {
  let text: string | null;
  try {
    text = readText(path);
  } catch (e) {
    return { text: null, doc: null, error: (e as Error).message };
  }
  if (text === null || text.trim() === "") return { text, doc: {} };
  try {
    const doc = obj(JSON.parse(text));
    return doc === null ? { text, doc: null, error: "not a JSON object" } : { text, doc };
  } catch (e) {
    return { text, doc: null, error: (e as Error).message };
  }
}

// --- ConfigChange --------------------------------------------------------------------------------

/** For ConfigChange: how the settings on disk weaken a profile the firewall recorded. */
export function sandboxRegistrationProblems(l: Layout, projectDir: string, platform: NodeJS.Platform = process.platform, home: string = homedir()): string[] {
  let records: SandboxRecord[];
  try {
    records = readSandboxRecords(l);
  } catch {
    if (!sandboxPolicy(loadPolicy(l, [projectDir], platform).config).protectInstalledProfile) return [];
    return ["the firewall's sandbox record is unreadable"];
  }
  if (records.length === 0) return [];
  const cfg = loadPolicy(l, [projectDir], platform).config;
  const pol = sandboxPolicy(cfg);
  if (!pol.protectInstalledProfile) return [];
  const policyDomains = profileFromPolicy(cfg).profile.network.allowedDomains;
  const problems: string[] = [];
  for (const r of records) {
    const cur = currentSandbox(r.path);
    if (cur.doc === null) {
      problems.push(`${r.path} cannot be read (${cur.error ?? "unknown error"}), and it holds the sandbox profile the firewall installed`);
      continue;
    }
    const guard = { installed: r.profile, policyDomains, safeExcluded: pol.safeExcludedCommands };
    // F10: the person's own WebFetch rules from when the profile was recorded are not the change's.
    const baseline: Json = { sandbox: r.profile, permissions: { allow: recordedWebFetch(r).map((d) => `WebFetch(domain:${d})`) } };
    for (const p of sandboxViolations(baseline, cur.doc, guard)) problems.push(`${r.path}: ${p.replace(/^it /, "")}`);
    // F9: a higher-precedence layer (local over project over user) can override the recorded profile.
    // The record's scope says which layer it is (user < project < local); only this project's layers above it count.
    const RANK = { user: 1, project: 2, local: 3 } as const;
    const recRank = RANK[r.scope as keyof typeof RANK] ?? settingsRank(r.path, home);
    const ownProject = recRank === 1 || r.path === settingsPath("project", projectDir, home) || r.path === settingsPath("local", projectDir, home);
    const higher = !ownProject ? [] : (["local", "project"] as const).filter((sc) => RANK[sc] > recRank).map((sc) => settingsPath(sc, projectDir, home)).filter((p) => p !== r.path);
    const layers: { doc: Json | null; repo: boolean; path: string }[] = [];
    for (const p of higher) {
      const c = currentSandbox(p);
      if (c.doc === null) problems.push(`${p} cannot be read (${c.error ?? "unknown error"}), and it can override the sandbox profile the firewall installed in ${r.path}`);
      else if (c.text !== null && c.text.trim() !== "") layers.push({ doc: c.doc, repo: true, path: p });
    }
    if (layers.length === 0) continue;
    const strict = recRank === 1 && obj(r.profile.network)?.strictAllowlist === true;
    const mine = { doc: cur.doc, repo: recRank >= 2 };
    // `higher` is already highest first (local, then project).
    const effective = mergeSettingsLayers([...layers, mine], strict);
    const base = mergeSettingsLayers([{ doc: baseline, repo: mine.repo }], strict);
    for (const p of sandboxViolations(base, effective, guard)) if (!problems.some((x) => x.endsWith(p.replace(/^it /, "")))) problems.push(`${layers.map((x) => x.path).join(", ")} (over ${r.path}): ${p.replace(/^it /, "")}`);
  }
  return problems;
}

/** F10: the WebFetch domains the recorded file held when doctor --fix recorded it (older records: its backup's). */
function recordedWebFetch(r: SandboxRecord): string[] {
  const out = new Set(r.webFetch ?? []);
  try {
    const b = JSON.parse(readText(r.backup) ?? "{}") as { content?: string | null };
    // The backup's content keeps the file's byte order mark.
    if (typeof b.content === "string" && b.content.trim() !== "") for (const d of webFetchDomains(obj(JSON.parse(stripBom(b.content))))) out.add(d);
  } catch {
    // No readable backup: only the recorded list.
  }
  return [...out];
}

// --- doctor --------------------------------------------------------------------------------------

export interface SandboxCheckOptions {
  home: string;
  platform: NodeJS.Platform;
  /** null: Claude Code is not installed (the sandbox checks are left out of the score). */
  claudeVersion: string | null;
  /** Writes and removes a probe file in a directory; false when that fails (tests inject a failure). */
  probe?: (dir: string) => boolean;
  managedPath?: string;
}

function defaultProbe(dir: string): boolean {
  const f = join(dir, `.probe-${process.pid}`);
  try {
    writeFileSync(f, "probe", { mode: 0o600 });
    rmSync(f, { force: true });
    return true;
  } catch {
    return false;
  }
}

function hostSummary(hosts: readonly HostLabel[]): string {
  const fetch = hosts.filter((h) => h.kind === "fetch-only").length;
  const send = hosts.filter((h) => h.kind === "send").map((h) => h.domain);
  const upload = hosts.filter((h) => h.uploadCapable).map((h) => h.domain);
  return `${fetch} fetch-only, ${send.length} send${send.length > 0 ? ` (${send.slice(0, 5).join(", ")})` : ""}; upload-capable and reachable from inside the sandbox: ${upload.slice(0, 8).join(", ") || "none"}${upload.length > 8 ? ", ..." : ""}. Uploading to these is controlled by the firewall's rules for the commands it can see (git push, npm publish, gh, docker push), not by the sandbox`;
}

/** The sandbox part of doctor: four scored checks, plus the record's state. */
export function sandboxChecks(l: Layout, projectDir: string, cfg: FirewallConfig, o: SandboxCheckOptions): Check[] {
  const out: Check[] = [];
  const probe = o.probe ?? defaultProbe;
  const view = readSandbox(projectDir, o.home, o.platform, o.managedPath !== undefined ? { managedPath: o.managedPath } : {});
  const derived = profileFromPolicy(cfg);
  const pol = sandboxPolicy(cfg);
  const fixHint = 'run "launchsafe-firewall doctor --fix" in your own terminal';
  if (o.claudeVersion === null) {
    out.push({ name: "sandbox", status: "ok", detail: "Claude Code not found on this machine, so its sandbox checks are left out of the score" });
  } else if (view.problems.length > 0 || view.unknownKeys.length > 0) {
    const why = [...view.problems, ...(view.unknownKeys.length > 0 ? [`settings this firewall does not know: ${view.unknownKeys.map((k) => `sandbox.${k}`).join(", ")}`] : [])];
    const detail = `could not read the sandbox settings for Claude Code ${o.claudeVersion} (schema checked against ${SANDBOX_SCHEMA_VERSION}): ${why.slice(0, 4).join("; ")}`;
    out.push({ name: "sandbox", status: "warn", detail, weight: 15, points: 0 });
    out.push({ name: "sandbox network", status: "warn", detail: "not scored: the sandbox settings could not be read", weight: 10, points: 0 });
    out.push({ name: "sandbox escape", status: "warn", detail: "not scored: the sandbox settings could not be read", weight: 5, points: 0 });
  } else {
    // 1. On or off.
    if (view.enabled) out.push({ name: "sandbox", status: "ok", detail: `on (${view.source.join(", ")}): switched on in Claude Code's settings (the firewall reads the settings and does not test the confinement)${view.managedLocked ? ", set by managed settings" : ""}`, weight: 15, points: 15 });
    else out.push({ name: "sandbox", status: "warn", detail: `off: a command the firewall allows (or cannot see into, like a compiled binary) can reach any file and host. ${fixHint} to write a profile derived from your policy`, weight: 15, points: 0 });
    // 2. Network.
    if (!view.enabled) out.push({ name: "sandbox network", status: "warn", detail: "not restricted: the sandbox is off", weight: 10, points: 0 });
    else if (view.allowedDomains === null && view.webFetchDomains.length === 0) out.push({ name: "sandbox network", status: "warn", detail: `not restricted to a list (sandbox.network.allowedDomains is not set). ${fixHint}`, weight: 10, points: 0 });
    else {
      const all = [...new Set([...(view.allowedDomains ?? []), ...view.webFetchDomains, ...view.repoDomains])];
      const extra = all.filter((d) => !domainWithinPolicy(d, derived.profile.network.allowedDomains));
      const lax = view.strictAllowlist ? "" : "; hosts outside the list are prompted rather than refused, and a repository's .claude/settings.json can add hosts (network.strictAllowlist is off)";
      if (extra.length > 0) out.push({ name: "sandbox network", status: "warn", detail: `restricted, but to hosts the firewall's policy does not list: ${extra.slice(0, 6).join(", ")}${extra.length > 6 ? ", ..." : ""}${view.repoDomains.length > 0 ? ` (from the repository: ${view.repoDomains.slice(0, 3).join(", ")})` : ""}. Add the ones you need to fetchAllowHosts, then ${fixHint}${lax}`, weight: 10, points: 5 });
      else out.push({ name: "sandbox network", status: "ok", detail: `restricted to ${all.length} host pattern(s) within your policy: ${hostSummary(derived.hosts.filter((h) => all.includes(h.domain)))}${lax}`, weight: 10, points: 10 });
    }
    // 3. Ways out of the sandbox.
    const escapes: string[] = [];
    if (view.allowUnsandboxed) escapes.push("commands may ask to run outside the sandbox (sandbox.allowUnsandboxedCommands is not false; Claude Code's default is true)");
    const unsafe = view.excludedCommands.filter((c) => !pol.safeExcludedCommands.includes(c));
    if (unsafe.length > 0) escapes.push(`sandbox.excludedCommands always run outside it: ${unsafe.slice(0, 5).join(", ")} (list deliberate ones in the policy's sandbox.safeExcludedCommands)`);
    if (view.allowAllUnixSockets) escapes.push("every Unix socket is allowed (sandbox.network.allowAllUnixSockets)");
    const docker = view.allowUnixSockets.filter((s) => /docker\.sock|podman\.sock|containerd\.sock/.test(s));
    if (docker.length > 0) escapes.push(`a container engine socket is allowed (${docker.join(", ")}): a container can mount the whole disk`);
    if (view.weakeners.length > 0) escapes.push(`isolation is weakened: ${view.weakeners.join(", ")}`);
    // F28: a writable path that opens the disk, the home directory or a credential store is a way out.
    const broadWrites = view.writableExtra.filter((w) => broadWritePath(w, o.home));
    if (broadWrites.length > 0) escapes.push(`sandbox.filesystem.allowWrite opens ${broadWrites.slice(0, 4).join(", ")} to sandboxed commands`);
    if (!view.enabled) out.push({ name: "sandbox escape", status: "warn", detail: "not scored: the sandbox is off", weight: 5, points: 0 });
    else if (escapes.length > 0) out.push({ name: "sandbox escape", status: "warn", detail: `${escapes.join("; ")}. ${fixHint}`, weight: 5, points: 0 });
    else out.push({ name: "sandbox escape", status: "ok", detail: "none of the sandbox settings the firewall reads lets a command run outside it; the Docker socket is deliberately not allowed (a container can mount the whole disk)", weight: 5, points: 5 });
  }
  // 4. The hook must be able to write its state: if hooks ran inside the sandbox, every call would fail closed.
  const dir = existsSync(l.home) ? l.home : dirname(l.home);
  if (probe(dir)) out.push({ name: "sandbox hooks", status: "ok", detail: `the firewall can write its state (${dir}); Claude Code runs hooks outside the sandbox (the sandbox confines Bash commands)`, weight: 5, points: 5 });
  else if (view.enabled) out.push({ name: "sandbox hooks", status: "fail", detail: `the firewall cannot write its state (${dir}): hooks would run inside the sandbox, and every risky action will be blocked. Run hooks outside the sandbox, or add ${l.home} to sandbox.filesystem.allowWrite`, weight: 5, points: 0 });
  else out.push({ name: "sandbox hooks", status: "fail", detail: `the firewall cannot write its state directory (${dir}); every risky action will be blocked`, weight: 5, points: 0 });
  // The record: what doctor --fix wrote, and whether it is still what is on disk.
  try {
    for (const r of readSandboxRecords(l)) {
      const cur = currentSandbox(r.path);
      const s = obj(cur.doc?.sandbox);
      if (cur.doc === null) out.push({ name: "sandbox profile", status: "warn", detail: `${r.path} cannot be read (${cur.error ?? ""}); it holds the profile doctor --fix installed` });
      else if (s === null) out.push({ name: "sandbox profile", status: "warn", detail: `the profile doctor --fix installed in ${r.path} is gone; ${fixHint} to write it again` });
      else if (profileHash(s) !== r.profileHash) out.push({ name: "sandbox profile", status: "warn", detail: `the profile in ${r.path} differs from the one doctor --fix recorded (edited outside the firewall?). A change the agent makes is compared with the recorded one; ${fixHint} to record the current one` });
      else out.push({ name: "sandbox profile", status: "ok", detail: `installed by doctor --fix in ${r.path} (${r.installedAt.slice(0, 10)}); ${pol.protectInstalledProfile ? "an agent change that weakens it is blocked" : "policy sandbox.protectInstalledProfile is false: an agent change to it is an ordinary settings change"}` });
    }
  } catch (e) {
    out.push({ name: "sandbox profile", status: "fail", detail: `${(e as Error).message}: the sandbox profile doctor --fix installed is not protected` });
  }
  return out;
}

// --- doctor --fix --------------------------------------------------------------------------------

export interface SandboxFixPlan {
  scope: Scope;
  path: string;
  /** Why nothing may be written (unknown schema, unreadable settings). */
  refused?: string;
  beforeText: string | null;
  afterText: string;
  /** The `sandbox` object that will be on disk afterwards (and recorded). */
  sandbox: Json;
  diff: string[];
  /** The file changes. */
  changed: boolean;
  /** The record changes (a new profile, or the person edited the recorded one). */
  rerecord: boolean;
  hosts: HostLabel[];
  dropped: { pattern: string; reason: string }[];
  notes: string[];
}

/** A small line diff (longest common subsequence) for showing a settings change. */
export function lineDiff(a: string, b: string): string[] {
  const x = a === "" ? [] : a.replace(/\n$/, "").split("\n");
  const y = b.replace(/\n$/, "").split("\n");
  const n = x.length;
  const m = y.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) (dp[i] as number[])[j] = x[i] === y[j] ? ((dp[i + 1] as number[])[j + 1] as number) + 1 : Math.max((dp[i + 1] as number[])[j] as number, (dp[i] as number[])[j + 1] as number);
  const out: string[] = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && x[i] === y[j]) {
      out.push(`  ${x[i] as string}`);
      i++;
      j++;
    } else if (j < m && (i >= n || ((dp[i] as number[])[j + 1] as number) >= ((dp[i + 1] as number[])[j] as number))) out.push(`+ ${y[j++] as string}`);
    else out.push(`- ${x[i++] as string}`);
  }
  // Keep the changed lines with two lines of context.
  const keep = new Set<number>();
  out.forEach((line, k) => {
    if (!line.startsWith("  ")) for (let c = k - 2; c <= k + 2; c++) keep.add(c);
  });
  const shown: string[] = [];
  let last = -2;
  out.forEach((line, k) => {
    if (!keep.has(k)) return;
    if (k !== last + 1 && shown.length > 0) shown.push("  ...");
    shown.push(line);
    last = k;
  });
  return shown;
}

/** What `doctor --fix` would write. Pure apart from reading the settings files. */
export function planSandboxFix(l: Layout, projectDir: string, cfg: FirewallConfig, o: { scope: Scope; home: string; platform: NodeJS.Platform; claudeVersion: string | null; managedPath?: string }): SandboxFixPlan {
  const path = settingsPath(o.scope, projectDir, o.home);
  const pol = sandboxPolicy(cfg);
  const strict = o.scope === "user" && pol.strictAllowlist;
  const derived = profileFromPolicy(cfg, { strict });
  const notes: string[] = [];
  if (o.scope !== "user" && pol.strictAllowlist) notes.push(`network.strictAllowlist is only honoured from user and managed settings, so it is not written at ${o.scope} scope: hosts outside the list will be prompted, not refused`);
  const empty: SandboxFixPlan = { scope: o.scope, path, beforeText: null, afterText: "", sandbox: {}, diff: [], changed: false, rerecord: false, hosts: derived.hosts, dropped: derived.dropped, notes };
  const view = readSandbox(projectDir, o.home, o.platform, o.managedPath !== undefined ? { managedPath: o.managedPath } : {});
  if (o.claudeVersion === null) notes.push("Claude Code was not found on this machine; the profile is written for the settings schema of Claude Code " + SANDBOX_SCHEMA_VERSION);
  if (view.problems.length > 0 || view.unknownKeys.length > 0) {
    const why = [...view.problems, ...(view.unknownKeys.length > 0 ? [`sandbox settings this firewall does not know: ${view.unknownKeys.map((k) => `sandbox.${k}`).join(", ")}`] : [])];
    return { ...empty, refused: `could not read the sandbox settings for Claude Code ${o.claudeVersion ?? "(not found)"} (this firewall knows the ${SANDBOX_SCHEMA_VERSION} schema): ${why.join("; ")}. Nothing was written; update the firewall, or fix the settings by hand` };
  }
  const cur = currentSandbox(path);
  if (cur.doc === null) return { ...empty, refused: `${path} cannot be read as JSON (${cur.error ?? ""}); nothing was written` };
  if (view.managedLocked) notes.push("managed settings also set the sandbox; where they disagree they win over this file");
  const curSandbox = obj(cur.doc.sandbox) ?? {};
  const merged: Json = { ...curSandbox, ...derived.profile, network: { ...(obj(curSandbox.network) ?? {}), ...derived.profile.network } };
  if (!strict) delete (merged.network as Json).strictAllowlist;
  // F27: the profile's promises ("no Unix sockets", filesystem isolated, no weaker modes) hold for what is
  // written: weakening keys already in the file are removed, and so are allowWrite entries that open the disk.
  const removed: string[] = [];
  for (const path of WEAKENING_KEYS) {
    const key = path[path.length - 1] as string;
    if (path.length === 1) {
      if (own(merged, key) !== undefined) {
        delete merged[key];
        removed.push(`sandbox.${key}`);
      }
      continue;
    }
    const parent = obj(own(merged, path[0] as string));
    if (parent !== null && own(parent, key) !== undefined) {
      const copy = { ...parent };
      delete copy[key];
      setOwn(merged, path[0] as string, copy);
      removed.push(`sandbox.${path.join(".")}`);
    }
  }
  const fsObj = obj(merged.filesystem);
  const writes = Array.isArray(fsObj?.allowWrite) ? (fsObj?.allowWrite as unknown[]).filter((x): x is string => typeof x === "string") : [];
  const broad = writes.filter((w) => broadWritePath(w, o.home));
  if (fsObj !== null && broad.length > 0) {
    merged.filesystem = { ...fsObj, allowWrite: writes.filter((w) => !broad.includes(w)) };
    removed.push(`sandbox.filesystem.allowWrite entries ${broad.join(", ")}`);
  }
  if (removed.length > 0) notes.push(`removes settings that weaken the sandbox: ${removed.join("; ")}`);
  const next = { ...cur.doc, sandbox: merged };
  const afterText = `${JSON.stringify(next, null, 2)}\n`;
  const beforeNorm = cur.text === null || cur.text.trim() === "" ? "" : `${JSON.stringify(cur.doc, null, 2)}\n`;
  const changed = canonical(next) !== canonical(cur.doc) || cur.text === null;
  let records: SandboxRecord[] = [];
  try {
    records = readSandboxRecords(l);
  } catch {
    records = [];
  }
  const rec = records.find((r) => r.path === path);
  const rerecord = rec === undefined || rec.profileHash !== profileHash(merged);
  return { ...empty, beforeText: cur.text, afterText, sandbox: merged, diff: lineDiff(beforeNorm, afterText), changed, rerecord };
}

export interface SandboxFixResult {
  path: string;
  backup: string;
  record: SandboxRecord;
}

/** Writes the plan: backup, atomic write of the settings file, record entry. Only after the human gate (runSandboxFix). */
export function applySandboxFix(l: Layout, plan: SandboxFixPlan, now: Date = new Date()): SandboxFixResult {
  if (plan.refused !== undefined) throw new Error(plan.refused);
  assertNotRealHome(plan.path);
  assertNotRealHome(l.home);
  return withLock(join(l.locks, "install.lock"), () => {
    // The backup is the file as it was, a byte order mark included; the comparison and the fingerprint use the text without it.
    const exact = readTextExact(plan.path);
    const original = exact === null ? null : stripBom(exact);
    if (original !== plan.beforeText) throw new Error(`${plan.path} changed while the fix was being confirmed; run doctor --fix again`);
    const records = readSandboxRecords(l);
    const prior = records.find((r) => r.path === plan.path);
    const stamp = now.toISOString().replace(/[:.]/g, "-");
    const fresh = join(l.backups, `${stamp}-sandbox-${plan.scope}-settings.json`);
    // Keep the first backup: the file from before the firewall ever wrote a sandbox profile into it.
    const backup = prior !== undefined && existsSync(prior.backup) ? prior.backup : fresh;
    if (backup === fresh) atomicWrite(fresh, JSON.stringify({ path: plan.path, existed: exact !== null, content: exact }, null, 2));
    if (plan.changed) {
      writeUserFile(plan.path, plan.afterText);
      recordOwnWrite(l, plan.path, original, plan.afterText);
    }
    let after: Json | null = null;
    try {
      after = obj(JSON.parse(plan.afterText));
    } catch {
      after = null;
    }
    const record: SandboxRecord = { kind: "sandbox", scope: plan.scope, path: plan.path, profileHash: profileHash(plan.sandbox), profile: plan.sandbox, backup, installedAt: now.toISOString(), webFetch: webFetchDomains(after) };
    writeSandboxRecords(l, [...records.filter((r) => r.path !== plan.path), record]);
    return { path: plan.path, backup, record };
  });
}

export interface FixIO {
  /** Reads the approval passphrase from the terminal (never echoed). */
  passphrase: () => Promise<string>;
  /** Asks a yes/no question; true only for "yes". */
  confirm: (question: string) => Promise<boolean>;
  say: (line: string) => void;
}

export type FixOutcome = "written" | "recorded" | "unchanged" | "refused" | "no-approver" | "bad-passphrase" | "declined";

/** Prints the plan: the hosts (fetch-only or send, upload-capable), what was left out, and the diff. */
export function describePlan(plan: SandboxFixPlan, say: (s: string) => void): void {
  say(`\nClaude Code sandbox profile for ${plan.path} (from your firewall policy):`);
  for (const h of plan.hosts) say(`  ${h.domain.padEnd(32)} ${h.kind}${h.uploadCapable ? ", upload-capable" : ""}`);
  if (plan.hosts.some((h) => h.uploadCapable)) say("  Upload-capable hosts are reachable from inside the sandbox; uploading to them is controlled by the firewall's rules for the commands it can see (git push, npm publish, gh, docker push), not by the sandbox.");
  for (const d of plan.dropped) say(`  left out: ${d.pattern} (${d.reason})`);
  say("  Hosts you name in a prompt are not added (they are per session). To reach another host from inside the sandbox, add it to fetchAllowHosts in your policy and run doctor --fix again.");
  for (const n of plan.notes) say(`  Note: ${n}`);
  if (plan.refused !== undefined) return;
  if (plan.changed) say(`  Change:\n${plan.diff.map((x) => `    ${x}`).join("\n")}`);
  else if (plan.rerecord) say("  The file already has this profile; it will be recorded so that weakening it is blocked.");
  else say("  Already installed and recorded.");
}

/**
 * The human gate for the sandbox fix: the approval passphrase, then the diff, then "yes". Called only
 * after the CLI has checked for a terminal and that no agent started it (humanAtKeyboard).
 */
export async function runSandboxFix(l: Layout, plan: SandboxFixPlan, io: FixIO, now: Date = new Date()): Promise<FixOutcome> {
  if (plan.refused !== undefined) {
    describePlan(plan, io.say);
    io.say(`  Refused: ${plan.refused}`);
    return "refused";
  }
  if (!plan.changed && !plan.rerecord) {
    describePlan(plan, io.say);
    return "unchanged";
  }
  if (approverPublicKey(l) === null) {
    io.say('\nThe sandbox profile is a change to your Claude Code settings, so it needs the approval passphrase, and none is set. In your own terminal run "launchsafe-firewall approver init", then "launchsafe-firewall doctor --fix" again.');
    return "no-approver";
  }
  try {
    unlockApprover(l, await io.passphrase());
  } catch (e) {
    io.say(`  ${(e as Error).message}. Nothing was written.`);
    return "bad-passphrase";
  }
  describePlan(plan, io.say);
  if (!(await io.confirm('  Apply? Type "yes": '))) {
    io.say("  Skipped. Nothing was written.");
    return "declined";
  }
  const r = applySandboxFix(l, plan, now);
  io.say(`  ${plan.changed ? "Written" : "Recorded"}: ${r.path} (backup of the earlier file: ${r.backup}). Restart Claude Code sessions for it to apply.`);
  return plan.changed ? "written" : "recorded";
}

// --- uninstall -----------------------------------------------------------------------------------

/**
 * Removes the sandbox profiles doctor --fix installed (uninstall --remove-sandbox or
 * --restore-backup). A file whose hooks were just restored from their own backup is left as that
 * restore put it. Otherwise the person's own earlier `sandbox` value is put back, or the key is
 * removed when there was none.
 */
export function removeSandboxProfiles(l: Layout, opts: { skipPaths?: readonly string[] } = {}): { path: string; action: "restored" | "removed" | "left" }[] {
  assertNotRealHome(l.home);
  return withLock(join(l.locks, "install.lock"), () => {
    const records = readSandboxRecords(l);
    const out: { path: string; action: "restored" | "removed" | "left" }[] = [];
    for (const r of records) {
      assertNotRealHome(r.path);
      const cur = currentSandbox(r.path);
      // F31: a file whose hooks were restored from their own backup keeps what that backup held, unless the
      // backup holds the very profile doctor --fix recorded (doctor --fix ran before install): then it is removed.
      const restoredWithProfile = opts.skipPaths?.includes(r.path) === true && obj(cur.doc?.sandbox) !== null && profileHash(obj(cur.doc?.sandbox)) === r.profileHash;
      if (opts.skipPaths?.includes(r.path) === true && !restoredWithProfile) {
        out.push({ path: r.path, action: "left" });
        continue;
      }
      if (cur.doc === null || !existsSync(r.path)) {
        out.push({ path: r.path, action: "left" });
        continue;
      }
      let prior: unknown;
      try {
        const b = JSON.parse(readText(r.backup) ?? "{}") as { content?: string | null };
        // The backup's content keeps the file's byte order mark: the person's own sandbox value is read after it.
        prior = b.content ? obj(JSON.parse(stripBom(b.content)))?.sandbox : undefined;
      } catch {
        prior = undefined;
      }
      const next: Json = { ...cur.doc };
      if (prior !== undefined) next.sandbox = prior;
      else delete next.sandbox;
      const written = `${JSON.stringify(next, null, 2)}\n`;
      const prev = readText(r.path);
      writeUserFile(r.path, written);
      recordOwnWrite(l, r.path, prev, written);
      out.push({ path: r.path, action: prior !== undefined ? "restored" : "removed" });
    }
    writeSandboxRecords(l, []);
    return out;
  });
}

