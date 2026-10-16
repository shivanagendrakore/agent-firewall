/**
 * `launchsafe-firewall doctor`: every check of the install and of the files it can read, with what to do
 * when one is wrong. It cannot see flags a CI job passes or a folder an agent does not trust (limitations.md).
 */

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { loadPolicy } from "./config.js";
import { HOOK_EVENTS, inspectSettings, MANAGED_SETTINGS_PATHS, readRecords } from "./install.js";
import { hookEntries } from "../engine/settings.js";
import type { Layout } from "./layout.js";
import { keyPairConsistent, loadKey, logHealthChecks, tailLog, verifyLog } from "./log.js";
import { RULE_INPUT_SHAPE } from "../engine/input-depth.js";
import { approverPublicKey } from "./approver.js";
import { installedHookCommands, pinnedApprover, pinnedApproverKey } from "./install.js";
import { phoneChecks } from "./relay/doctor.js";
import { listQueue, readEvents } from "./store.js";
import { registeredSettingsFiles } from "./context.js";
import { buildIdentity, parseHookCommand } from "./identity.js";
import { HOST_TOOLS_VERIFIED_VERSION } from "../engine/hosttools.js";
import { ledgerHealth } from "./ledger.js";
import { agentChecks } from "./agent-doctor.js";
import { canaryChecks } from "./canaries.js";
import { counterChecks } from "./counters.js";
import { knownHostsChecks } from "./knownhosts.js";
import { stopChecks } from "./stops.js";
import { capChecks } from "./caps.js";
import { learnedChecks } from "./learned.js";
import { probeAndCache } from "./notify.js";
import { packageChecks } from "./package-doctor.js";
import { readSandbox, sandboxChecks } from "./sandbox.js";
import { withScore } from "./score.js";
import { hookChecks, otherAgentChecks } from "./agent-hooks-doctor.js";
import { hookBypassChecks } from "./hook-bypass.js";
import { pinnedWatchKey, watchState } from "./rollout.js";
import { adapterFor } from "../adapters/index.js";
import { vaultChecks } from "./vault/doctor.js";
import { browserLinkChecks } from "./native/browsers.js";
import { linkStateProblems } from "./native/link.js";
import { quarantineCheck } from "./quarantine.js";
import { wrappedWithoutCompileCache } from "../gateway/clients.js";
import { detectRunPlatform, runReadiness, type RunPlatform } from "./run/platform.js";
import { agentSandboxChecks } from "./agent-sandbox-doctor.js";
import { resolveProgram } from "./run/run.js";

export interface Check {
  name: string;
  status: "ok" | "warn" | "fail";
  detail: string;
  /** What the check is worth in the protection score; absent = not scored (does not apply here). */
  weight?: number;
  /** Points earned, 0..weight. */
  points?: number;
  /** On the "protection score" entry only, the score out of 100. */
  score?: number;
}

export const MIN_CLAUDE_VERSION = "2.1.0";
export const TESTED_CLAUDE_VERSION = "2.1.289";

function cmpVersion(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export function findClaudeBinary(home = homedir()): string | null {
  try {
    const p = execFileSync("sh", ["-c", "command -v claude"], { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"] }).trim();
    if (p !== "") return p;
  } catch {
    // Not on PATH.
  }
  const base = join(home, "Library", "Application Support", "Claude", "claude-code");
  try {
    const versions = readdirSync(base).filter((v) => /^\d+\.\d+\.\d+$/.test(v)).sort(cmpVersion);
    for (let i = versions.length - 1; i >= 0; i--) {
      const dir = join(base, versions[i] as string);
      const found = findFile(dir, "claude", 4);
      if (found !== null) return found;
    }
  } catch {
    // Not installed through the desktop app.
  }
  return null;
}

function findFile(dir: string, name: string, depth: number): string | null {
  if (depth < 0) return null;
  let entries: string[] = [];
  try {
    entries = readdirSync(dir);
  } catch {
    return null;
  }
  for (const e of entries) {
    const p = join(dir, e);
    try {
      const st = statSync(p);
      if (st.isFile() && e === name && (st.mode & 0o111) !== 0) return p;
      if (st.isDirectory()) {
        const f = findFile(p, name, depth - 1);
        if (f !== null) return f;
      }
    } catch {
      // Skip unreadable entries.
    }
  }
  return null;
}

export interface DoctorOptions {
  home?: string;
  platform?: NodeJS.Platform;
  claudeVersion?: string | null;
  findBinary?: (name: string) => string | null;
  agentVersion?: (bin: string) => string | null;
  probe?: (dir: string) => boolean;
  runDetect?: () => RunPlatform;
  /** Tests: Claude Code's managed settings file (default: the platform's). */
  claudeManagedPath?: string;
  /** Tests: Gemini CLI's system settings file. */
  geminiSystemPath?: string;
  env?: NodeJS.ProcessEnv;
}

/** Whether Claude Code's hooks are in each settings file install recorded (present, fail-closed, first), and the managed install. */
function claudeHookChecks(records: ReturnType<typeof readRecords>, managedPath: string | undefined, managedHasUs: boolean, ci: boolean): Check[] {
  const checks: Check[] = [];
  if (records.length === 0 && !managedHasUs) checks.push({ name: "hooks", status: "fail", detail: `not installed${ci ? " on this machine" : ""}: run launchsafe-firewall install (or, so no repository or user setting can switch it off, launchsafe-firewall install --managed)` });
  if (managedHasUs) {
    const open = managedOpen(managedPath);
    checks.push(open.length === 0 ? { name: "hooks (managed)", status: "ok", detail: `${managedPath ?? ""}: all ${HOOK_EVENTS.length} events, exit-2 wrapper present` } : { name: "hooks (managed)", status: "fail", detail: `the fail-closed wrapper (|| exit 2) is missing for ${open.join(", ")} in ${managedPath ?? ""}: deploy the snippet from launchsafe-firewall install --managed --print again (administrator)` });
  }
  for (const r of records.filter((x) => x.scope !== "managed" && (x.agent ?? "claude") === "claude")) {
    const st = safeInspect(r.path);
    if (st === null) {
      checks.push({ name: `hooks (${r.scope})`, status: "fail", detail: `${r.path} cannot be read` });
      continue;
    }
    const missing = HOOK_EVENTS.filter((ev) => !st.events[ev]?.ours);
    const notFirst = HOOK_EVENTS.filter((ev) => st.events[ev]?.ours && !st.events[ev]?.first);
    const open = HOOK_EVENTS.filter((ev) => st.events[ev]?.ours && !st.events[ev]?.failClosed);
    if (missing.length > 0) checks.push({ name: `hooks (${r.scope})`, status: "fail", detail: `missing for ${missing.join(", ")} in ${r.path}: run launchsafe-firewall install --scope ${r.scope}` });
    else if (open.length > 0) checks.push({ name: `hooks (${r.scope})`, status: "fail", detail: `the fail-closed wrapper (|| exit 2) is missing for ${open.join(", ")}: run launchsafe-firewall install --scope ${r.scope}` });
    else if (notFirst.length > 0) checks.push({ name: `hooks (${r.scope})`, status: "warn", detail: `not first for ${notFirst.join(", ")} in ${r.path}; another hook runs before the firewall` });
    else checks.push({ name: `hooks (${r.scope})`, status: "ok", detail: `${r.path}: all ${HOOK_EVENTS.length} events, first in order, exit-2 wrapper present (an agent that runs the tool when a hook times out is not covered: docs/limitations.md)` });
    if (!ci && !existsSync(process.execPath)) checks.push({ name: "hook command", status: "fail", detail: `${process.execPath} no longer exists: reinstall` });
  }
  return checks;
}

/** Whether an installed hook command starts node by a bare name rather than its path. */
function bareNode(l: Layout): boolean {
  return installedHookCommands(l).commands.some((c) => /^LAUNCHSAFE_FIREWALL_HOOK=1 (?:[A-Z_]+='[^']*' |[A-Z_]+= )*(?:node|'node') /.test(c.command));
}

/** The events whose managed hook entry lacks the fail-closed wrapper. */
function managedOpen(managedPath: string | undefined): string[] {
  const st = managedPath !== undefined && existsSync(managedPath) ? safeInspect(managedPath) : null;
  return st === null ? [] : HOOK_EVENTS.filter((ev) => st.events[ev]?.ours === true && st.events[ev]?.failClosed !== true);
}

/** Installed hook commands that do not pin the approval key (approvals and watch mode then cannot be trusted to the hook). */
function unpinnedChecks(l: Layout): Check[] {
  const loose = installedHookCommands(l).commands.filter((c) => pinnedApprover(c.command) === null);
  if (loose.length === 0) return [];
  return [{ name: "hook approval pin", status: "warn", detail: `${[...new Set(loose.map((c) => c.path))].join(", ")}: the hook command does not pin the approval key, so the hook falls back to the key on disk and watch mode cannot be turned on. Set a passphrase (launchsafe-firewall approver init) and run launchsafe-firewall install again` }];
}

function managedCheck(managedPath: string | undefined, managedHasUs: boolean): Check {
  return managedHasUs
    ? { name: "managed settings", status: "ok", detail: `${managedPath ?? ""} registers the firewall; no user or project settings file can remove it (command-line flags are not covered)` }
    : { name: "managed settings", status: "warn", detail: `recommended: a repository's .claude/settings.json can set disableAllHooks and turn user-level hooks off (in a claude -p run without the trust dialog), and a run started with --setting-sources that leaves out "user" does not load them. Only managed settings resist both. Deploy them with "launchsafe-firewall install --managed --lock-other-hooks" (needs admin rights; --lock-other-hooks also sets allowManagedHooksOnly so no other hook can run ahead of the firewall).` };
}

/**
 * `doctor --ci`: only what decides whether an agent's hooks can be switched off or bypassed here (the hook
 * registrations install recorded, the managed install, and every agent settings file that can switch hooks
 * off or reach into the hook process, the repository's first). No probes, no agent binaries run, no score.
 * A machine without the firewall is a fail (the "hooks" check says it is not installed), whatever the repository's files hold.
 */
export function doctorCi(l: Layout, projectDir: string, opts: DoctorOptions = {}): Check[] {
  const home = opts.home ?? homedir();
  const platform = opts.platform ?? process.platform;
  let records: ReturnType<typeof readRecords> = [];
  const checks: Check[] = [];
  try {
    records = readRecords(l);
  } catch (e) {
    checks.push({ name: "install record", status: "fail", detail: (e as Error).message });
  }
  const managedPath = opts.claudeManagedPath ?? MANAGED_SETTINGS_PATHS[platform];
  const managed = managedPath !== undefined && existsSync(managedPath) ? safeInspect(managedPath) : null;
  const managedHasUs = managed !== null && HOOK_EVENTS.every((ev) => managed.events[ev]?.ours === true);
  checks.push(...claudeHookChecks(records, managedPath, managedHasUs, true));
  for (const id of ["codex", "gemini", "cursor"] as const) {
    const a = adapterFor(id);
    checks.push(...hookChecks(l, a, a.settings.label));
  }
  checks.push(...hookBypassChecks({ projectDir, home, platform, ...(opts.env !== undefined ? { env: opts.env } : {}), ...(managedPath !== undefined ? { claudeManagedPath: managedPath } : {}), ...(opts.geminiSystemPath !== undefined ? { geminiSystemPath: opts.geminiSystemPath } : {}), installed: records.map((r) => ({ agent: r.agent ?? "claude", scope: r.scope })), bareNode: bareNode(l) }));
  checks.push(managedCheck(managedPath, managedHasUs));
  checks.push(...unpinnedChecks(l));
  // Strict: watch mode on means risky actions run, which a CI gate counts as a failure.
  checks.push(...rolloutChecks(l, projectDir, platform, home).map((c) => (c.status === "warn" && /^watch/.test(c.detail) ? { ...c, status: "fail" as const } : c)));
  // A policy file that does not load sends every risky action to a person; a CI gate counts it as a failure.
  const pol = loadPolicy(l, [projectDir], platform);
  if (pol.error !== undefined) checks.push({ name: "policy", status: "fail", detail: `${pol.error}; that file's settings are not applied. Run "launchsafe-firewall policy validate"` });
  checks.push(...hookNodeChecks(l));
  return checks;
}

/** The node binary each installed hook command names must exist, or every hook fails (closed, but every tool call is blocked). */
function hookNodeChecks(l: Layout): Check[] {
  const missing = installedHookCommands(l).commands.filter((c) => {
    const parts = parseHookCommand(c.command);
    return parts !== null && parts.node.startsWith("/") && !existsSync(parts.node);
  });
  return missing.length === 0 ? [] : [{ name: "hook node", status: "fail", detail: `${[...new Set(missing.map((c) => c.path))].join(", ")}: the hook command names a node binary that does not exist (${[...new Set(missing.map((c) => parseHookCommand(c.command)?.node ?? ""))].join(", ")}), so every tool call is blocked. Run "launchsafe-firewall install" again with the node you use now` }];
}

/** Watch mode: on is a warning (risky actions run), requested but not in effect is a warning with the reason. */
function rolloutChecks(l: Layout, projectDir: string, platform: NodeJS.Platform, home: string): Check[] {
  const st = watchState(l, loadPolicy(l, [projectDir], platform), pinnedWatchKey(l, home, platform));
  if (st.active) return [{ name: "rollout mode", status: "warn", detail: `watch (${st.layer === "managed" ? `the managed policy ${st.path ?? ""}` : `turned on by a person${st.grant !== undefined ? ` at ${st.grant.at}, until ${st.grant.until}` : ""}`}): risky actions are logged and allowed, except the always-enforced core. See "launchsafe-firewall rollout report"; switch back with "launchsafe-firewall rollout enforce"` }];
  if (st.requested === "watch") return [{ name: "rollout mode", status: "warn", detail: `enforce: ${st.problem ?? "watch mode is requested but not in effect"}` }];
  return [{ name: "rollout mode", status: "ok", detail: `enforce${st.layer !== "default" ? ` (${st.layer} policy)` : ""}` }];
}

export function doctor(l: Layout, projectDir: string, opts: DoctorOptions = {}): Check[] {
  const checks: Check[] = [];
  const home = opts.home ?? homedir();
  const platform = opts.platform ?? process.platform;
  checks.push(platform === "darwin" || platform === "linux" ? { name: "platform", status: "ok", detail: platform } : { name: "platform", status: "fail", detail: `${platform} is not supported (macOS and Linux only)` });
  const major = Number(process.versions.node.split(".")[0]);
  checks.push(major >= 22 ? { name: "node", status: "ok", detail: process.versions.node } : { name: "node", status: "fail", detail: `Node ${process.versions.node}; 22 or newer is required` });

  // Firewall home permissions.
  try {
    const st = statSync(l.home);
    checks.push((st.mode & 0o077) === 0 ? { name: "state directory", status: "ok", detail: `${l.home} (private)` } : { name: "state directory", status: "warn", detail: `${l.home} is readable by other users; run chmod 700 ${l.home}` });
  } catch {
    checks.push({ name: "state directory", status: "warn", detail: `${l.home} does not exist yet (created on first use)` });
  }

  // Hooks.
  let records: ReturnType<typeof readRecords> = [];
  try {
    records = readRecords(l);
  } catch (e) {
    checks.push({ name: "install record", status: "fail", detail: (e as Error).message });
  }
  const managedPath = opts.claudeManagedPath ?? MANAGED_SETTINGS_PATHS[platform];
  const managed = managedPath !== undefined && existsSync(managedPath) ? safeInspect(managedPath) : null;
  const managedHasUs = managed !== null && HOOK_EVENTS.every((ev) => managed.events[ev]?.ours === true);
  checks.push(...claudeHookChecks(records, managedPath, managedHasUs, false));

  // SR3: every installed hook command clears NODE_COMPILE_CACHE (installs before 0.3.0 do not).
  const uncleared = installedHookCommands(l).commands.filter((c) => parseHookCommand(c.command)?.clearsCompileCache === false);
  if (uncleared.length > 0) checks.push({ name: "hook command", status: "fail", detail: `${[...new Set(uncleared.map((c) => c.path))].join(", ")}: the hook command does not clear NODE_COMPILE_CACHE, so a compile cache directory set in the agent's environment would be loaded into the hook. Run "launchsafe-firewall install" again` });

  checks.push(...hookNodeChecks(l));
  // I1: installs before this release neither pin the home and data directory nor clear the loader variables.
  const unpinned = installedHookCommands(l).commands.filter((c) => {
    const parts = parseHookCommand(c.command);
    return parts !== null && (parts.clearsLoaderEnv !== true || parts.pinsHome !== true);
  });
  if (unpinned.length > 0) checks.push({ name: "hook environment", status: "warn", detail: `${[...new Set(unpinned.map((c) => c.path))].join(", ")}: the hook command does not pin HOME and the firewall's data directory, or does not clear NODE_OPTIONS, NODE_PATH, LD_PRELOAD and DYLD_INSERT_LIBRARIES, so an agent's settings env reaches the hook process (a HOME that differs from your user's is still refused at run time). Run "launchsafe-firewall install" again` });

  // LG4: the same for every stdio MCP server the gateway wraps (its wrapper runs firewall code under node).
  const ccStale = wrappedWithoutCompileCache(l);
  if (ccStale.length > 0) checks.push({ name: "gateway wrapper", status: "fail", detail: `${ccStale.map((x) => `${x.file} "${x.server}"`).join(", ")}: the wrapped MCP server does not set NODE_COMPILE_CACHE empty for the gateway, so a compile cache directory in the client's environment or the entry's env would be loaded into the firewall's code. Run "launchsafe-firewall mcp wrap-config --client ${[...new Set(ccStale.map((x) => x.client))].join("|")}" again` });

  // Codex and Gemini CLI (present on this machine or installed into).
  checks.push(...otherAgentChecks(l, { home, platform, projectDir, findBinary: opts.findBinary ?? (opts.home !== undefined ? () => null : undefined), ...(opts.agentVersion !== undefined ? { version: opts.agentVersion } : {}) }));
  checks.push(...identityChecks(l, home, platform));

  // Anything that switches an agent's hooks off or reaches into the hook process, the repository's files first.
  checks.push(...hookBypassChecks({ projectDir, home, platform, ...(opts.env !== undefined ? { env: opts.env } : {}), ...(managedPath !== undefined ? { claudeManagedPath: managedPath } : {}), ...(opts.geminiSystemPath !== undefined ? { geminiSystemPath: opts.geminiSystemPath } : {}), installed: records.map((r) => ({ agent: r.agent ?? "claude", scope: r.scope })), bareNode: bareNode(l) }));
  checks.push(managedCheck(managedPath, managedHasUs));

  // Policy.
  const pol = loadPolicy(l, [projectDir], platform);
  const version = opts.claudeVersion !== undefined ? opts.claudeVersion : claudeVersion(home);
  // A: before 2.1.295 Claude Code ignores onFailure: "block", so a hook that times out or is killed lets the action run.
  if (records.some((r) => (r.agent ?? "claude") === "claude") || managedHasUs) {
    const c = onFailureCheck(version);
    if (c !== null) checks.push(c);
  }

  // Claude Code's OS sandbox. Hooks are not a full boundary on their own: the firewall decides
  // what an action may do, the sandbox limits what a command that runs anyway can reach.
  checks.push(...sandboxChecks(l, projectDir, pol.config, { home, platform, claudeVersion: version, ...(opts.probe !== undefined ? { probe: opts.probe } : {}) }));
  // v0.3: whether `run` can sandbox an agent here (not scored: it is for agents without their own sandbox).
  const ready = runReadiness(opts.runDetect ?? (() => detectRunPlatform({ platform })));
  checks.push({ name: "run mode", status: ready.ok ? "ok" : "warn", detail: ready.detail });
  // Which coding agents would run with no sandbox at all, and what to use (not scored).
  {
    let claudeOn = false;
    try {
      claudeOn = readSandbox(projectDir, home, platform).enabled;
    } catch {
      claudeOn = false;
    }
    const finder = opts.findBinary ?? (opts.home !== undefined ? () => null : (name: string) => resolveProgram(name, process.env, projectDir));
    checks.push(...agentSandboxChecks({ home, env: process.env, projectDir, hooked: new Set(records.map((r) => r.agent ?? "claude")), claudeSandboxOn: claudeOn, findBinary: finder }));
  }

  checks.push(pol.error === undefined ? { name: "policy", status: "ok", detail: `valid (${pol.sources.join(", ")})` } : { name: "policy", status: "fail", detail: `${pol.error}; that file's settings are not applied (the other policy layers still are), and every risky action is sent to you (FW-POLICY-ERROR) until it is fixed` });
  checks.push(...rolloutChecks(l, projectDir, platform, home));
  if (pol.ignored.length > 0) checks.push({ name: "project policy", status: "warn", detail: `ignored (projects may only tighten): ${pol.ignored.join("; ")}` });
  checks.push(...packageChecks(l.home, projectDir, pol.config, { home, platform }));

  // Log and key.
  const key = (() => {
    try {
      return loadKey(l, false);
    } catch {
      return null;
    }
  })();
  checks.push(key !== null ? { name: "log key", status: "ok", detail: join(l.keys, "log-ed25519.pem") } : { name: "log key", status: "warn", detail: "no signing key yet (created with the first decision)" });
  try {
    if (!keyPairConsistent(l)) checks.push({ name: "log key pair", status: "fail", detail: "the stored public key is not the public half of the signing key; log entries cannot be verified" });
  } catch (e) {
    checks.push({ name: "log key pair", status: "fail", detail: (e as Error).message });
  }

  // F4: the human channel for approvals and uninstall.
  let approver: string | null = null;
  try {
    approver = approverPublicKey(l);
  } catch (e) {
    checks.push({ name: "approval passphrase", status: "fail", detail: (e as Error).message });
  }
  if (approver === null) checks.push({ name: "approval passphrase", status: "warn", detail: 'not set: held actions cannot be approved. In your own terminal run "launchsafe-firewall approver init", then "launchsafe-firewall install" again' });
  else {
    const commands = records.filter((r) => r.scope !== "managed").flatMap((r) => {
      try {
        return hookEntries(JSON.parse(readFileSync(r.path, "utf8"))).filter((e) => e.event === "PreToolUse" || e.event === "BeforeTool" || e.event === "preToolUse").map((e) => e.command).filter((c) => c.includes("LAUNCHSAFE_FIREWALL_HOOK"));
      } catch {
        return [];
      }
    });
    const pins = commands.map(pinnedApprover);
    if (pins.length > 0 && pins.every((p) => p === approver)) checks.push({ name: "approval passphrase", status: "ok", detail: "set, and its key is pinned in the hook command" });
    else if (pins.some((p) => p !== null && p !== approver)) checks.push({ name: "approval passphrase", status: "fail", detail: 'the hook pins a different approval key than the one on disk (rotated without reinstalling?): run "launchsafe-firewall install" again' });
    else checks.push({ name: "approval passphrase", status: "warn", detail: 'set, but not pinned in the hook command: run "launchsafe-firewall install" again' });
  }
  // The vault index is signed with the approval key (doctor's check above compares it with the hook's pin).
  checks.push(...vaultChecks(l, pol.config, { platform, trustedKey: approver }));
  // Paired phones (nothing until a phone is paired).
  checks.push(...phoneChecks(l, pol.config));
  checks.push(...browserLinkChecks(l));
  for (const problem of linkStateProblems(l)) checks.push({ name: "browser link state", status: "warn", detail: problem });
  try {
    const v = verifyLog(l);
    checks.push(v.ok || v.entries === 0 ? { name: "decision log", status: "ok", detail: `${v.entries} entries in ${v.files} file(s), chain and signatures valid` } : { name: "decision log", status: "fail", detail: v.problems.slice(0, 5).join("; ") });
  } catch (e) {
    checks.push({ name: "decision log", status: "fail", detail: (e as Error).message });
  }
  // I5/I6: decisions that could not be logged, and pruned files nobody exported.
  checks.push(...logHealthChecks(l));

  checks.push(inputShapeCheck(l));

  // State files.
  let corruptSessions = 0;
  try {
    for (const f of readdirSync(l.sessions).filter((n) => n.endsWith(".jsonl"))) {
      if (readEvents(l, f.replace(/\.jsonl$/, "")).some((e) => e.type === "corrupt")) corruptSessions++;
    }
  } catch {
    // No sessions yet.
  }
  checks.push(corruptSessions === 0 ? { name: "session state", status: "ok", detail: "readable" } : { name: "session state", status: "warn", detail: `${corruptSessions} session file(s) had unreadable entries; those sessions are treated as untrusted` });
  // F-e: the provenance ledger (files the agent wrote). Unreadable = those files count as outside content.
  const ledger = ledgerHealth(l);
  checks.push(ledger.ok ? { name: "provenance ledger", status: "ok", detail: ledger.detail } : { name: "provenance ledger", status: "warn", detail: ledger.detail });
  const q = listQueue(l);
  checks.push(q.corrupt.length === 0 ? { name: "queue", status: "ok", detail: `${q.items.filter((i) => i.status === "pending").length} pending` } : { name: "queue", status: "warn", detail: `unreadable items: ${q.corrupt.join(", ")}` });
  // The quarantine store for messages withheld from the agent.
  checks.push({ name: "quarantine store", ...quarantineCheck(l) });

  // The agent-configuration scan and MCP pins.
  checks.push(...agentChecks(l, projectDir, home));
  // Decoy files.
  checks.push(...canaryChecks(l));
  checks.push(...counterChecks(l));
  checks.push(...knownHostsChecks(l));
  // The kill switch: damaged records, resumes not signed by the key, and logged stops whose record is gone.
  checks.push(...stopChecks(l, approverKeyForStops(l)));
  checks.push(...capChecks(l));
  checks.push(...learnedChecks(l));
  // Desktop notifications.
  const note = loadPolicy(l, [projectDir]).config.notifications;
  if (!note.enabled) checks.push({ name: "notifications", status: "ok", detail: "off (policy notifications.enabled is false)" });
  else {
    const a = probeAndCache(l, process.env, { platform });
    checks.push(a.ok ? { name: "notifications", status: "ok", detail: `on (${a.tool})` } : { name: "notifications", status: "warn", detail: `unavailable: ${a.reason}` });
  }

  // Claude Code version.
  if (version === null) checks.push({ name: "Claude Code", status: "warn", detail: `not found; not tested below ${TESTED_CLAUDE_VERSION}` });
  else if (cmpVersion(version, MIN_CLAUDE_VERSION) < 0) checks.push({ name: "Claude Code", status: "fail", detail: `${version} is older than ${MIN_CLAUDE_VERSION}; not tested below ${TESTED_CLAUDE_VERSION}; update Claude Code` });
  // F-d: the host tools (sending a file to you, chapter markers...) were catalogued from this version's events.
  else if (cmpVersion(version, HOST_TOOLS_VERIFIED_VERSION) > 0) checks.push({ name: "Claude Code", status: "warn", detail: `${version} (tested with ${TESTED_CLAUDE_VERSION}); new host tools not catalogued: tools added after ${HOST_TOOLS_VERIFIED_VERSION} are judged as unknown tools until the catalogue is updated` });
  else checks.push({ name: "Claude Code", status: "ok", detail: `${version} (tested with ${TESTED_CLAUDE_VERSION})` });
  return withScore(checks, { canariesEnabled: pol.config.canaries.enabled });
}

/** How many decisions the log reads back for the input-shape count. */
const INPUT_SHAPE_WINDOW = 5000;

/**
 * FW-INPUT-SHAPE denials among the recent decisions (review of FZ14): a call whose arguments are nested past
 * what the engine judges is refused; one now and then is an agent's mistake, a run of them is worth a look.
 */
export function inputShapeCheck(l: Layout): Check {
  let n = 0;
  try {
    for (const e of tailLog(l, INPUT_SHAPE_WINDOW)) {
      const rules = (e.event as { rules?: unknown }).rules;
      if (Array.isArray(rules) && rules.includes(RULE_INPUT_SHAPE)) n++;
    }
  } catch {
    // An unreadable log is reported by the decision log check.
  }
  return n === 0 ? { name: "input shape", status: "ok", detail: `no call refused for its input's shape in the last ${INPUT_SHAPE_WINDOW} decisions` } : { name: "input shape", status: "warn", detail: `${n} call(s) in the last ${INPUT_SHAPE_WINDOW} decisions were refused because their input was nested too deep or too large to judge (${RULE_INPUT_SHAPE}); an agent or a tool sending such input should be looked at` };
}

/**
 * F-c: what self-protection protects, by identity. Warns when the identity could not be built from a
 * hook command (fallback), or when the runtime is a source checkout (building it from inside an agent
 * is blocked); fails when a hook command points at a CLI file that no longer exists.
 */
function identityChecks(l: Layout, home: string, platform: NodeJS.Platform): Check[] {
  let id: ReturnType<typeof buildIdentity>;
  try {
    id = buildIdentity(l, registeredSettingsFiles(l, platform), { home });
  } catch (e) {
    return [{ name: "firewall identity", status: "warn", detail: `could not be built (${(e as Error).message}); protecting the data directory and the install directory's dist/, node_modules/ and package.json` }];
  }
  const out: Check[] = [];
  const listed = `CLI ${id.cliFiles.join(", ") || "none"}; runtime ${id.runtimeRoots.join(", ") || "none"}`;
  if (id.source === "fallback-install-dir") {
    out.push({ name: "firewall identity", status: "warn", detail: `no registered hook command found, so self-protection falls back to the install directory (${listed}) and the data directory` });
    return out;
  }
  const missing = id.cliFiles.filter((f) => !existsSync(f));
  if (missing.length === id.cliFiles.length) out.push({ name: "firewall identity", status: "fail", detail: `the hook command points at a missing file (${missing.join(", ")}): every tool call will be blocked; reinstall` });
  const checkout = id.packageRoots.find((r) => existsSync(join(r, "src")) || existsSync(join(r, ".git")));
  if (checkout !== undefined) out.push({ name: "firewall identity", status: "warn", detail: `installed from a working copy (${checkout}): building it from inside an agent is blocked because that rewrites the running firewall; install from a packed tarball (npm pack, then npm install -g --prefix <dir> <tarball>) for a clean separation. ${listed}` });
  else if (out.length === 0) out.push({ name: "firewall identity", status: "ok", detail: `${listed} (from the registered hook command)` });
  return out;
}

function safeInspect(p: string): ReturnType<typeof inspectSettings> | null {
  try {
    return inspectSettings(p);
  } catch {
    return null;
  }
}

export function claudeVersion(home = homedir()): string | null {
  const bin = findClaudeBinary(home);
  if (bin === null) return null;
  try {
    const out = execFileSync(bin, ["--version"], { encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "ignore"] });
    return /(\d+\.\d+\.\d+)/.exec(out)?.[1] ?? null;
  } catch {
    return null;
  }
}

/** A: the first Claude Code version that honours a hook entry's `onFailure: "block"`. */
export const CLAUDE_ON_FAILURE_VERSION = "2.1.295";

function olderThan(v: string, min: string): boolean {
  const a = v.split(".").map(Number);
  const b = min.split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) < (b[i] ?? 0);
  return false;
}

/** The check for Claude Code's onFailure support, or null when the version is new enough or unknown (no binary found). */
export function onFailureCheck(version: string | null): Check | null {
  if (version === null || !olderThan(version, CLAUDE_ON_FAILURE_VERSION)) return null;
  const which = `Claude Code ${version} is older than ${CLAUDE_ON_FAILURE_VERSION}`;
  return { name: "hook failure mode", status: "warn", detail: `${which}: before ${CLAUDE_ON_FAILURE_VERSION} Claude Code is documented to ignore onFailure: "block", so a firewall hook that times out or is killed lets the action run (the firewall denies at its own deadline first, but a hung process is not covered). Update Claude Code` };
}

/** The key a resume must verify against for doctor: the hooks' pin, else the one on disk. */
function approverKeyForStops(l: Layout): string | null {
  try {
    return pinnedApproverKey(l, process.env) ?? approverPublicKey(l);
  } catch {
    return null;
  }
}
