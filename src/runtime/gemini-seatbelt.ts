/**
 * Gemini CLI's own sandbox (`gemini -s`, macOS seatbelt). Gemini CLI re-runs itself under
 * `sandbox-exec` with one profile, and everything it starts inherits it: the firewall's hook and the
 * agent's own tools run in the same sandbox (captured: `ps` fails there, SANDBOX=sandbox-exec is in
 * the hook's environment). Its built-in profiles let a process write only the project, temporary
 * and cache directories, so the hook cannot save its state and fails closed on every action.
 *
 * Gemini CLI loads a custom profile by name: SEATBELT_PROFILE=<name> reads
 * ~/.gemini/sandbox-macos-<name>.sb (GEMINI_CLI_HOME honoured), or the project's
 * .gemini/sandbox-macos-<name>.sb only when the user's file does not exist (read from Gemini CLI
 * 0.63.0's sandbox launcher). `install --agent gemini --seatbelt BASE` writes
 * ~/.gemini/sandbox-macos-launchsafe.sb: Gemini CLI's own BASE profile, copied unchanged from the
 * installed Gemini CLI, plus one block that lets a process write the hook's per-session state
 * directories and nothing else.
 *
 * Why only those: the agent's tools share the sandbox, so whatever the profile lets the hook write,
 * a command the agent runs can write too. The firewall still judges every command (writing its
 * directory is FW-TAMPER), exactly as without `-s`; but a command the analyser cannot see through
 * (inline code with a path built at run time is allowed in a clean session) would reach any file the
 * profile opens. So the policy, the keys, the install records, the backups, the vault, the decoy
 * registry, the identity cache and the scan cache stay read-only inside the sandbox, where without
 * `-s` they are protected by the analyser alone. ~/.gemini stays unwritable (Gemini CLI's own rule),
 * so the agent cannot rewrite this profile from inside.
 *
 * I9, what remains: the state directories themselves (session trust and counters, the queue, the log)
 * are writable by the agent's commands too. Seatbelt has no append-only rule, and the hook has no helper
 * process outside the sandbox to write through, so doctor and docs/sandboxes.md say so plainly.
 */

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, realpathSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { geminiHome } from "../adapters/gemini.js";
import { isUnder } from "../engine/paths.js";
import type { Check } from "./doctor.js";
import { stripBom } from "../bom.js";
import { atomicWrite, readText, readTextExact } from "./fsutil.js";
import { assertNotRealHome } from "./guard.js";
import { installDir, type Layout } from "./layout.js";

/** The profile's name: SEATBELT_PROFILE=launchsafe. */
export const SEATBELT_PROFILE_NAME = "launchsafe";

/** Gemini CLI's built-in profiles that ship as files (permissive-closed and restrictive-closed are aliases with no file). */
export const SEATBELT_BASES = ["permissive-open", "permissive-proxied", "restrictive-open", "restrictive-proxied", "strict-open", "strict-proxied"] as const;
export type SeatbeltBase = (typeof SEATBELT_BASES)[number];

/**
 * The directories the hook writes while deciding (captured: a live `gemini -s` run with the whole data
 * directory writable wrote only these, plus identity.json and policy.json; see the module comment for
 * why those two are left out). sessions: state, counters, mode; queue: held actions; log: the signed
 * decision log; locks: queue and notification locks; ledger: provenance of what the agent wrote;
 * pins: MCP descriptions; quarantine: the email guard; scan/receipts and scan/last: the session-start
 * agent-configuration check (without receipts every session would start untrusted).
 */
export const HOOK_STATE_DIRS = ["sessions", "queue", "log", "locks", "ledger", "pins", "quarantine", "scan/receipts", "scan/last"] as const;

const MARK_BEGIN = ";; ---- LaunchSafe Agent Firewall: begin ----";
const MARK_END = ";; ---- LaunchSafe Agent Firewall: end ----";

export function seatbeltProfilePath(env: NodeJS.ProcessEnv = process.env, home = homedir()): string {
  return join(geminiHome(env, home), `sandbox-macos-${SEATBELT_PROFILE_NAME}.sb`);
}

export function seatbeltRecordPath(l: Layout): string {
  return join(l.home, "gemini-seatbelt.json");
}

export interface SeatbeltRecord {
  path: string;
  base: SeatbeltBase;
  /** Gemini CLI's profile file it was built from, and its sha256 then. */
  baseFile: string;
  baseSha: string;
  /** sha256 of the profile as written. */
  sha: string;
  installedAt: string;
}

const sha256 = (t: string): string => createHash("sha256").update(t).digest("hex");

/** A path as a seatbelt string literal. Refuses what it cannot quote without doubt. */
export function sbString(p: string): string {
  if (!isAbsolute(p) || /["\\]/.test(p) || [...p].some((c) => c.charCodeAt(0) < 0x20 || c.charCodeAt(0) === 0x7f)) throw new Error(`cannot put ${JSON.stringify(p)} in a seatbelt profile (it must be an absolute path without quotes, backslashes or control characters)`);
  return `"${p}"`;
}

function real(p: string): string {
  try {
    return realpathSync.native(p);
  } catch {
    return resolve(p);
  }
}

export interface BlockInput {
  /** The firewall's data directory (resolved: seatbelt compares real paths). */
  fwHome: string;
  /** For the strict profiles, which confine reads too: the firewall's package and node's install prefix. */
  readRoots?: readonly string[];
}

/** The firewall's block, appended after Gemini CLI's profile (later rules win in a seatbelt profile). */
export function seatbeltBlock(o: BlockInput): string {
  const lines = [
    MARK_BEGIN,
    ";; The firewall's hook runs inside this sandbox, and so do the agent's own commands. It may write only",
    ";; its per-session state; its policy, keys, install records, backups and vault stay read-only here.",
  ];
  if (o.readRoots !== undefined && o.readRoots.length > 0) {
    lines.push(";; This base profile confines reads: the hook reads its data directory, its package and node.");
    lines.push("(allow file-read*", `    (subpath ${sbString(o.fwHome)})`, ...o.readRoots.map((r) => `    (subpath ${sbString(r)})`), ")");
  }
  lines.push("(allow file-write*", ...HOOK_STATE_DIRS.map((d) => `    (subpath ${sbString(join(o.fwHome, d))})`), ")");
  // Seatbelt judges a write by the name it uses: a hard link in a writable directory to the policy, a key or an
  // install record would give it a writable name. No hard links at all (as in `run`; tools fall back to copying).
  lines.push(";; No hard links: a link to the firewall's read-only files would be writable under its new name.", "(deny file-link)", MARK_END);
  return `${lines.join("\n")}\n`;
}

/** The whole profile: a header, Gemini CLI's profile unchanged, the firewall's block. */
export function buildSeatbeltProfile(base: SeatbeltBase, baseFile: string, baseText: string, block: string): string {
  const head = [
    `;; Gemini CLI seatbelt profile "${SEATBELT_PROFILE_NAME}", written by launchsafe-firewall install --agent gemini --seatbelt ${base}.`,
    `;; Use it with: SEATBELT_PROFILE=${SEATBELT_PROFILE_NAME} gemini -s`,
    `;; Gemini CLI's ${base} profile follows unchanged (${baseFile}, sha256 ${sha256(baseText)}), then the firewall's block.`,
    ";; Do not edit: run the install command again instead (doctor compares this file with what it wrote).",
    "",
  ].join("\n");
  return `${head}\n${baseText.endsWith("\n") ? baseText : `${baseText}\n`}\n${block}`;
}

/** The firewall's block in a profile file, or null. */
export function blockOf(text: string): string | null {
  const a = text.indexOf(MARK_BEGIN);
  const b = text.indexOf(MARK_END);
  if (a < 0 || b < a) return null;
  return text.slice(a, b + MARK_END.length) + "\n";
}

function onPath(name: string, env: NodeJS.ProcessEnv): string | null {
  try {
    const p = execFileSync("sh", ["-c", `command -v ${name}`], { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"], env }).trim();
    return p === "" ? null : p;
  } catch {
    return null;
  }
}

/**
 * The directory holding Gemini CLI's profile files (its package's bundle/): from `dir` when given (the
 * package or its bundle), else from the `gemini` command on PATH (bin/gemini links to bundle/gemini.js).
 */
export function findGeminiBundle(o: { dir?: string; env?: NodeJS.ProcessEnv; find?: (name: string) => string | null } = {}): string | null {
  const has = (d: string): boolean => existsSync(join(d, "sandbox-macos-permissive-open.sb"));
  if (o.dir !== undefined) {
    const d = real(o.dir);
    for (const c of [d, join(d, "bundle")]) if (has(c)) return c;
    return null;
  }
  const bin = (o.find ?? ((n) => onPath(n, o.env ?? process.env)))("gemini");
  if (bin === null) return null;
  let d = dirname(real(bin));
  for (let i = 0; i < 4; i++) {
    for (const c of [d, join(d, "bundle")]) if (has(c)) return c;
    d = dirname(d);
  }
  return null;
}

/** node's install prefix (…/bin/node → …), which the strict profiles must let the hook read. */
function nodePrefix(node: string): string {
  return dirname(dirname(real(node)));
}

export interface InstallSeatbeltOptions {
  base: SeatbeltBase;
  /** Gemini CLI's bundle directory (findGeminiBundle). */
  bundle: string;
  home?: string;
  env?: NodeJS.ProcessEnv;
  node?: string;
  packageDir?: string;
  now?: Date;
}

export interface InstallSeatbeltResult {
  path: string;
  changed: boolean;
  /** A different file that was there before, saved in the firewall's backups. */
  backup?: string;
}

/** What the profile for this install must say: Gemini CLI's base file and the block. */
export function expectedProfile(l: Layout, o: InstallSeatbeltOptions): { text: string; baseFile: string; baseText: string } {
  if (!(SEATBELT_BASES as readonly string[]).includes(o.base)) throw new Error(`unknown seatbelt profile ${o.base} (one of ${SEATBELT_BASES.join(", ")})`);
  const baseFile = join(o.bundle, `sandbox-macos-${o.base}.sb`);
  const baseText = readText(baseFile);
  if (baseText === null) throw new Error(`Gemini CLI's ${o.base} profile is not at ${baseFile}`);
  if (!/^\s*\(version 1\)/m.test(baseText) || !/\(deny default\)/.test(baseText)) throw new Error(`${baseFile} does not look like a deny-by-default seatbelt profile; refusing to build on it`);
  const fwHome = real(l.home);
  const gem = real(geminiHome(o.env ?? process.env, o.home ?? homedir()));
  // Gemini CLI's own rule keeps ~/.gemini unwritable; a data directory inside it (or around it) would undo that.
  if (isUnder(fwHome, gem, true) || isUnder(gem, fwHome, true)) throw new Error(`the firewall's data directory ${fwHome} overlaps Gemini CLI's ${gem}; a profile that opens it would let the agent rewrite Gemini CLI's settings`);
  const strict = o.base.startsWith("strict-");
  const readRoots = strict ? [...new Set([real(o.packageDir ?? installDir()), nodePrefix(o.node ?? process.execPath)])] : undefined;
  const block = seatbeltBlock({ fwHome, ...(readRoots !== undefined ? { readRoots } : {}) });
  return { text: buildSeatbeltProfile(o.base, baseFile, baseText, block), baseFile, baseText };
}

export function readSeatbeltRecord(l: Layout): SeatbeltRecord | null {
  const t = readText(seatbeltRecordPath(l));
  if (t === null) return null;
  try {
    const r = JSON.parse(t) as SeatbeltRecord;
    return typeof r.path === "string" && typeof r.sha === "string" && typeof r.base === "string" ? r : null;
  } catch {
    return null;
  }
}

/**
 * Writes the profile and its record, and creates the hook's state directories (inside the sandbox the
 * data directory itself is read-only, so they must exist beforehand). Idempotent.
 */
export function installSeatbelt(l: Layout, o: InstallSeatbeltOptions): InstallSeatbeltResult {
  const path = seatbeltProfilePath(o.env ?? process.env, o.home ?? homedir());
  assertNotRealHome(path);
  assertNotRealHome(l.home);
  mkdirSync(l.home, { recursive: true, mode: 0o700 });
  for (const d of HOOK_STATE_DIRS) mkdirSync(join(l.home, d), { recursive: true, mode: 0o700 });
  const { text, baseFile, baseText } = expectedProfile(l, o);
  // The copy is the file as it was, a byte order mark included; the comparisons see the text without it.
  const exact = readTextExact(path);
  const before = exact === null ? null : stripBom(exact);
  let backup: string | undefined;
  const rec = readSeatbeltRecord(l);
  if (exact !== null && before !== null && before !== text && !(rec !== null && rec.path === path && sha256(before) === rec.sha)) {
    // A file the firewall did not write (or one edited since): keep a copy before replacing it.
    backup = join(l.backups, `${(o.now ?? new Date()).toISOString().replace(/[:.]/g, "-")}-gemini-${SEATBELT_PROFILE_NAME}.sb`);
    atomicWrite(backup, exact);
  }
  if (before !== text) atomicWrite(path, text, 0o644);
  const record: SeatbeltRecord = { path, base: o.base, baseFile, baseSha: sha256(baseText), sha: sha256(text), installedAt: (o.now ?? new Date()).toISOString() };
  atomicWrite(seatbeltRecordPath(l), `${JSON.stringify(record, null, 2)}\n`);
  return { path, changed: before !== text, ...(backup !== undefined ? { backup } : {}) };
}

/** Removes the profile when it is still exactly what install wrote; an edited one is left in place. */
export function removeSeatbelt(l: Layout): { path: string; action: "removed" | "left-edited" | "gone" } | null {
  const rec = readSeatbeltRecord(l);
  if (rec === null) return null;
  assertNotRealHome(rec.path);
  const now = readText(rec.path);
  let action: "removed" | "left-edited" | "gone" = "gone";
  if (now !== null && sha256(now) === rec.sha) {
    rmSync(rec.path, { force: true });
    action = "removed";
  } else if (now !== null) action = "left-edited";
  rmSync(seatbeltRecordPath(l), { force: true });
  return { path: rec.path, action };
}

/** Gemini CLI is set to start in its sandbox (settings tools.sandbox, or GEMINI_SANDBOX). */
export function sandboxByDefault(env: NodeJS.ProcessEnv, settingsFiles: readonly string[]): string | null {
  const v = (env.GEMINI_SANDBOX ?? "").trim().toLowerCase();
  if (v !== "" && v !== "0" && v !== "false") return `GEMINI_SANDBOX=${env.GEMINI_SANDBOX ?? ""}`;
  for (const f of settingsFiles) {
    try {
      const s = JSON.parse(readText(f) ?? "{}") as { tools?: { sandbox?: unknown } };
      const sb = s.tools?.sandbox;
      if (sb === true || sb === "sandbox-exec" || (typeof sb === "object" && sb !== null && (sb as { enabled?: unknown }).enabled === true)) return `tools.sandbox in ${f}`;
    } catch {
      // Gemini CLI reports its own unreadable settings.
    }
  }
  return null;
}

export interface SeatbeltCheckOptions {
  home: string;
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
  projectDir: string;
  /** Gemini CLI's bundle directory, when known (doctor finds it from PATH). */
  bundle?: string | null;
  node?: string;
  packageDir?: string;
}

/** Doctor's lines for Gemini CLI's `-s` on macOS. */
export function seatbeltChecks(l: Layout, o: SeatbeltCheckOptions): Check[] {
  if (o.platform !== "darwin") return [];
  const name = "Gemini CLI sandbox (-s)";
  const out: Check[] = [];
  const rec = readSeatbeltRecord(l);
  const projectFile = join(o.projectDir, ".gemini", `sandbox-macos-${SEATBELT_PROFILE_NAME}.sb`);
  const settings = [join(geminiHome(o.env, o.home), "settings.json"), join(o.projectDir, ".gemini", "settings.json")];
  const fix = `run launchsafe-firewall install --agent gemini --seatbelt permissive-open, then start Gemini CLI with SEATBELT_PROFILE=${SEATBELT_PROFILE_NAME}`;
  if (rec === null) {
    const byDefault = sandboxByDefault(o.env, settings);
    if (byDefault !== null) out.push({ name, status: "fail", detail: `Gemini CLI starts in its seatbelt sandbox here (${byDefault}), where the firewall cannot save its state, so it blocks every action: ${fix}` });
    else out.push({ name, status: "warn", detail: `not set up: under gemini -s the firewall cannot save its state and blocks every action. To use -s, ${fix}` });
    return out;
  }
  const text = readText(rec.path);
  if (text === null) {
    out.push({ name, status: "fail", detail: `${rec.path} is gone: SEATBELT_PROFILE=${SEATBELT_PROFILE_NAME} now loads a project's .gemini/sandbox-macos-${SEATBELT_PROFILE_NAME}.sb if one exists, or fails. Run launchsafe-firewall install --agent gemini --seatbelt ${rec.base} again` });
    return out;
  }
  if (sha256(text) !== rec.sha) out.push({ name, status: "fail", detail: `${rec.path} changed since the firewall wrote it; run launchsafe-firewall install --agent gemini --seatbelt ${rec.base} again (the current file is kept in the backups)` });
  else {
    let stale: string | null = null;
    try {
      const block = blockOf(text);
      const want = seatbeltBlock({ fwHome: real(l.home), ...(rec.base.startsWith("strict-") ? { readRoots: [...new Set([real(o.packageDir ?? installDir()), nodePrefix(o.node ?? process.execPath)])] } : {}) });
      if (block !== want) stale = "it names another data directory, package or node than this install's";
    } catch (e) {
      stale = (e as Error).message;
    }
    if (stale !== null) out.push({ name, status: "fail", detail: `${rec.path} does not match this install (${stale}): run launchsafe-firewall install --agent gemini --seatbelt ${rec.base} again` });
    else out.push({ name, status: "ok", detail: `${rec.path}: Gemini CLI's ${rec.base} profile plus write access to the hook's state directories only (policy, keys, install records, vault stay read-only). The agent's own commands can write that state too (session trust and counters, queue, log, ledger): there it is protected by the firewall's judgement of each command, not by the sandbox` });
  }
  if (o.bundle !== undefined && o.bundle !== null) {
    const now = readText(join(o.bundle, `sandbox-macos-${rec.base}.sb`));
    if (now !== null && sha256(now) !== rec.baseSha) out.push({ name: `${name} base profile`, status: "warn", detail: `Gemini CLI's ${rec.base} profile changed since the firewall copied it (Gemini CLI was updated): run launchsafe-firewall install --agent gemini --seatbelt ${rec.base} again to pick up its changes` });
  }
  const sel = o.env.SEATBELT_PROFILE;
  if (sel !== SEATBELT_PROFILE_NAME) out.push({ name: `${name} profile selected`, status: "warn", detail: `this shell ${sel === undefined || sel === "" ? "does not set SEATBELT_PROFILE" : `sets SEATBELT_PROFILE=${sel}`}, so gemini -s uses ${sel === undefined || sel === "" ? "permissive-open" : sel} and the firewall blocks every action there: export SEATBELT_PROFILE=${SEATBELT_PROFILE_NAME} in your shell profile (a project's .env cannot override an exported value)` });
  if (existsSync(projectFile)) out.push({ name: `${name} project profile`, status: "warn", detail: `${projectFile} exists: Gemini CLI loads it only if ${rec.path} is missing, but a repository should not ship a profile under the firewall's name` });
  return out;
}

/**
 * The one message the hook gives when Gemini CLI's seatbelt refused it its own state (EPERM inside
 * `-s`), or null for any other failure.
 */
export function seatbeltRefusal(e: unknown, env: NodeJS.ProcessEnv): string | null {
  const code = (e as NodeJS.ErrnoException | null)?.code;
  if (env.SANDBOX !== "sandbox-exec" || (code !== "EPERM" && code !== "EACCES")) return null;
  const profile = env.SEATBELT_PROFILE !== undefined && env.SEATBELT_PROFILE !== "" ? env.SEATBELT_PROFILE : "permissive-open";
  if (profile === SEATBELT_PROFILE_NAME) return `LaunchSafe Firewall cannot save its state inside Gemini CLI's sandbox: the "${SEATBELT_PROFILE_NAME}" seatbelt profile does not match this install (${(e as Error).message}). Outside the agent run "launchsafe-firewall install --agent gemini --seatbelt permissive-open" again, then "launchsafe-firewall doctor".`;
  return `LaunchSafe Firewall cannot save its state inside Gemini CLI's sandbox (-s, seatbelt profile "${profile}"), so it blocks every action there. Outside the agent run "launchsafe-firewall install --agent gemini --seatbelt permissive-open", then start Gemini CLI with SEATBELT_PROFILE=${SEATBELT_PROFILE_NAME}; or run it without -s.`;
}
