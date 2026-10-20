/**
 * Package-manager release-age cooldowns (doctor). Most malicious
 * versions are found and pulled within days; a manager that refuses versions
 * younger than a few days never installs them. This module detects the
 * managers a project uses, reports whether a cooldown is configured, and plans
 * the user-level setting `doctor --fix` may write after showing the diff.
 *
 * Setting names, units and user-level file locations [verify each against the
 * tool's current docs before release]:
 *   pnpm   minimumReleaseAge (minutes) in pnpm-workspace.yaml; minimum-release-age in .npmrc / pnpm's global rc
 *   Yarn   npmMinimalAgeGate (minutes) in .yarnrc.yml (Berry only)
 *   Bun    [install] minimumReleaseAge (seconds) in bunfig.toml
 *   uv     exclude-newer (a relative duration such as "3 days", in recent versions) in uv.toml / [tool.uv]
 *   npm    only `before` (a fixed date): no rolling cooldown
 *   pip    none
 * Only user-level files are ever written: a project file would be a commit the person did not ask for.
 */

import { copyFileSync, existsSync, lstatSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { join } from "node:path";
import { atomicWrite, ensureDir } from "./fsutil.js";
import { assertNotRealHome } from "./guard.js";

export type Manager = "pnpm" | "yarn" | "bun" | "npm" | "uv" | "pip" | "poetry";

/** Three days: long enough for most malicious versions to be found and pulled. */
export const DEFAULT_COOLDOWN_MINUTES = 3 * 24 * 60;

export interface CooldownStatus {
  manager: Manager;
  state: "configured" | "missing" | "unavailable";
  /** Where it is set (configured) or what the gap is (unavailable). */
  detail: string;
}

export interface CooldownFix {
  manager: Manager;
  path: string;
  before: string | null;
  after: string;
  /** Lines for the person to read before saying yes. */
  diff: string[];
}

export interface CooldownEnv {
  home: string;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
}

function read(p: string): string | null {
  try {
    if (statSync(p).size > 1024 * 1024) return null;
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

function xdgConfig(e: CooldownEnv): string {
  const x = e.env?.XDG_CONFIG_HOME;
  return x !== undefined && x !== "" ? x : join(e.home, ".config");
}

/** pnpm's global rc (pnpm config set --global) [verify]. */
export function pnpmGlobalRc(e: CooldownEnv): string {
  return (e.platform ?? process.platform) === "darwin" ? join(e.home, "Library", "Preferences", "pnpm", "rc") : join(xdgConfig(e), "pnpm", "rc");
}

const positive = (v: string | undefined): boolean => v !== undefined && v !== "" && !/^["']?0+["']?$/.test(v) && !/^["']?(?:false|null|~)["']?$/i.test(v);

/** A key as a literal inside a RegExp: every metacharacter escaped, the backslash included, so no key can change the pattern. */
const reKey = (key: string): string => key.replace(/[\\^$.*+?()[\]{}|/-]/g, "\\$&");

function iniValue(text: string | null, key: string): string | undefined {
  if (text === null) return undefined;
  const m = new RegExp(`^\\s*${reKey(key)}\\s*=\\s*(.+?)\\s*$`, "m").exec(text);
  return m?.[1];
}

function yamlTopValue(text: string | null, key: string): string | undefined {
  if (text === null) return undefined;
  const m = new RegExp(`^${reKey(key)}:\\s*(.+?)\\s*$`, "m").exec(text);
  return m?.[1]?.replace(/\s+#.*$/, "");
}

/** A key's value inside a TOML table (`section` "" = before the first table). */
function tomlValue(text: string | null, section: string, key: string): string | undefined {
  if (text === null) return undefined;
  let cur = "";
  for (const line of text.split(/\r?\n/)) {
    const h = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (h !== null) {
      cur = (h[1] as string).trim();
      continue;
    }
    if (cur !== section) continue;
    const m = new RegExp(`^\\s*${reKey(key)}\\s*=\\s*(.+?)\\s*$`).exec(line);
    if (m !== null) return (m[1] as string).replace(/\s+#.*$/, "");
  }
  return undefined;
}

/** The managers a project (and the user's own config) uses. */
export function detectManagers(projectDir: string, e: CooldownEnv): Manager[] {
  const has = (f: string): boolean => existsSync(join(projectDir, f));
  const out = new Set<Manager>();
  if (has("pnpm-lock.yaml") || has("pnpm-workspace.yaml") || existsSync(pnpmGlobalRc(e))) out.add("pnpm");
  if (has("yarn.lock") || has(".yarnrc.yml") || existsSync(join(e.home, ".yarnrc.yml"))) out.add("yarn");
  if (has("bun.lock") || has("bun.lockb") || has("bunfig.toml") || existsSync(join(e.home, ".bunfig.toml"))) out.add("bun");
  if (has("package-lock.json") || has("npm-shrinkwrap.json")) out.add("npm");
  if (has("uv.lock") || has("uv.toml") || existsSync(join(xdgConfig(e), "uv", "uv.toml"))) out.add("uv");
  if (has("poetry.lock")) out.add("poetry");
  let reqs = false;
  try {
    reqs = readdirSync(projectDir).some((f) => /^requirements.*\.txt$/.test(f));
  } catch {
    reqs = false;
  }
  if (reqs || has("Pipfile") || has("Pipfile.lock")) out.add("pip");
  return [...out];
}

function yarnIsBerry(projectDir: string, e: CooldownEnv): boolean {
  if (existsSync(join(projectDir, ".yarnrc.yml")) || existsSync(join(e.home, ".yarnrc.yml"))) return true;
  const lock = read(join(projectDir, "yarn.lock"));
  return lock !== null && /^__metadata:/m.test(lock);
}

/** Whether each detected manager refuses brand-new versions. */
export function cooldownStatus(projectDir: string, e: CooldownEnv): CooldownStatus[] {
  const out: CooldownStatus[] = [];
  for (const m of detectManagers(projectDir, e)) {
    switch (m) {
      case "pnpm": {
        const places: [string, string | undefined][] = [
          [join(projectDir, "pnpm-workspace.yaml"), yamlTopValue(read(join(projectDir, "pnpm-workspace.yaml")), "minimumReleaseAge")],
          [join(projectDir, ".npmrc"), iniValue(read(join(projectDir, ".npmrc")), "minimum-release-age")],
          [pnpmGlobalRc(e), iniValue(read(pnpmGlobalRc(e)), "minimum-release-age")],
          [join(e.home, ".npmrc"), iniValue(read(join(e.home, ".npmrc")), "minimum-release-age")],
        ];
        const hit = places.find(([, v]) => positive(v));
        out.push(hit !== undefined ? { manager: m, state: "configured", detail: `minimumReleaseAge ${hit[1] ?? ""} minutes (${hit[0]})` } : { manager: m, state: "missing", detail: "no minimumReleaseAge" });
        break;
      }
      case "yarn": {
        if (!yarnIsBerry(projectDir, e)) {
          out.push({ manager: m, state: "unavailable", detail: "Yarn 1 has no release-age setting (Yarn 4 has npmMinimalAgeGate)" });
          break;
        }
        const places: [string, string | undefined][] = [
          [join(projectDir, ".yarnrc.yml"), yamlTopValue(read(join(projectDir, ".yarnrc.yml")), "npmMinimalAgeGate")],
          [join(e.home, ".yarnrc.yml"), yamlTopValue(read(join(e.home, ".yarnrc.yml")), "npmMinimalAgeGate")],
        ];
        const hit = places.find(([, v]) => positive(v));
        out.push(hit !== undefined ? { manager: m, state: "configured", detail: `npmMinimalAgeGate ${hit[1] ?? ""} (${hit[0]})` } : { manager: m, state: "missing", detail: "no npmMinimalAgeGate" });
        break;
      }
      case "bun": {
        const places: [string, string | undefined][] = [
          [join(projectDir, "bunfig.toml"), tomlValue(read(join(projectDir, "bunfig.toml")), "install", "minimumReleaseAge")],
          [join(e.home, ".bunfig.toml"), tomlValue(read(join(e.home, ".bunfig.toml")), "install", "minimumReleaseAge")],
          [join(xdgConfig(e), ".bunfig.toml"), tomlValue(read(join(xdgConfig(e), ".bunfig.toml")), "install", "minimumReleaseAge")],
        ];
        const hit = places.find(([, v]) => positive(v));
        out.push(hit !== undefined ? { manager: m, state: "configured", detail: `install.minimumReleaseAge ${hit[1] ?? ""} seconds (${hit[0]})` } : { manager: m, state: "missing", detail: "no install.minimumReleaseAge" });
        break;
      }
      case "npm": {
        const before = iniValue(read(join(projectDir, ".npmrc")), "before") ?? iniValue(read(join(e.home, ".npmrc")), "before");
        out.push({ manager: m, state: "unavailable", detail: before !== undefined ? `npm only has a fixed date (before=${before}), not a rolling cooldown` : "npm has no rolling release-age setting (only a fixed date, `before`)" });
        break;
      }
      case "uv": {
        const places: [string, string | undefined][] = [
          [join(projectDir, "uv.toml"), tomlValue(read(join(projectDir, "uv.toml")), "", "exclude-newer")],
          [join(projectDir, "pyproject.toml"), tomlValue(read(join(projectDir, "pyproject.toml")), "tool.uv", "exclude-newer")],
          [join(xdgConfig(e), "uv", "uv.toml"), tomlValue(read(join(xdgConfig(e), "uv", "uv.toml")), "", "exclude-newer")],
        ];
        const hit = places.find(([, v]) => positive(v));
        out.push(hit !== undefined ? { manager: m, state: "configured", detail: `exclude-newer ${hit[1] ?? ""} (${hit[0]})` } : { manager: m, state: "missing", detail: "no exclude-newer" });
        break;
      }
      case "pip":
        out.push({ manager: m, state: "unavailable", detail: "pip has no release-age setting (uv has exclude-newer)" });
        break;
      case "poetry":
        out.push({ manager: m, state: "unavailable", detail: "Poetry has no release-age setting" });
        break;
    }
  }
  return out;
}

// --- editing user-level config ----------------------------------------------------------------------------

function setIni(text: string, key: string, value: string): string {
  const re = new RegExp(`^\\s*${reKey(key)}\\s*=.*$`, "m");
  if (re.test(text)) return text.replace(re, `${key}=${value}`);
  return `${text}${text === "" || text.endsWith("\n") ? "" : "\n"}${key}=${value}\n`;
}

function setYamlTop(text: string, key: string, value: string): string {
  const re = new RegExp(`^${reKey(key)}:.*$`, "m");
  if (re.test(text)) return text.replace(re, `${key}: ${value}`);
  return `${text}${text === "" || text.endsWith("\n") ? "" : "\n"}${key}: ${value}\n`;
}

function setToml(text: string, section: string, key: string, value: string): string {
  const lines = text === "" ? [] : text.replace(/\n$/, "").split("\n");
  const header = (l: string): string | null => /^\s*\[([^\]]+)\]\s*$/.exec(l)?.[1]?.trim() ?? null;
  const keyRe = new RegExp(`^\\s*${reKey(key)}\\s*=`);
  let start: number;
  if (section === "") start = 0;
  else {
    const h = lines.findIndex((l) => header(l) === section);
    if (h === -1) return `${text}${text === "" || text.endsWith("\n") ? "" : "\n"}${text === "" ? "" : "\n"}[${section}]\n${key} = ${value}\n`;
    start = h + 1;
  }
  const next = lines.findIndex((l, i) => i >= start && header(l) !== null);
  const end = next === -1 ? lines.length : next;
  for (let i = start; i < end; i++) {
    if (keyRe.test(lines[i] as string)) {
      lines[i] = `${key} = ${value}`;
      return `${lines.join("\n")}\n`;
    }
  }
  let at = start;
  for (let i = start; i < end; i++) if ((lines[i] as string).trim() !== "") at = i + 1;
  lines.splice(at, 0, `${key} = ${value}`);
  return `${lines.join("\n")}\n`;
}

function diffLines(path: string, before: string | null, after: string): string[] {
  const a = before === null ? [] : before.replace(/\n$/, "").split("\n");
  const b = after.replace(/\n$/, "").split("\n");
  const out = [`--- ${before === null ? "/dev/null" : path}`, `+++ ${path}`];
  for (const l of a) if (!b.includes(l)) out.push(`- ${l}`);
  for (const l of b) if (!a.includes(l)) out.push(`+ ${l}`);
  return out;
}

/** The user-level settings `doctor --fix` would write for the managers missing a cooldown. Writes nothing. */
export function planCooldownFixes(projectDir: string, e: CooldownEnv, minutes = DEFAULT_COOLDOWN_MINUTES): CooldownFix[] {
  const fixes: CooldownFix[] = [];
  for (const s of cooldownStatus(projectDir, e)) {
    if (s.state !== "missing") continue;
    let path: string;
    let after: (t: string) => string;
    switch (s.manager) {
      case "pnpm":
        path = pnpmGlobalRc(e);
        after = (t) => setIni(t, "minimum-release-age", String(minutes));
        break;
      case "yarn":
        path = join(e.home, ".yarnrc.yml");
        after = (t) => setYamlTop(t, "npmMinimalAgeGate", String(minutes));
        break;
      case "bun":
        path = join(e.home, ".bunfig.toml");
        after = (t) => setToml(t, "install", "minimumReleaseAge", String(minutes * 60));
        break;
      case "uv":
        path = join(xdgConfig(e), "uv", "uv.toml");
        after = (t) => setToml(t, "", "exclude-newer", `"${Math.max(1, Math.round(minutes / 1440))} days"`);
        break;
      default:
        continue;
    }
    const before = read(path);
    // A file that exists but could not be read (over 1 MB, unreadable) is not planned over: writing would replace what the person has.
    if (before === null && lstatSync(path, { throwIfNoEntry: false }) !== undefined) continue;
    const next = after(before ?? "");
    fixes.push({ manager: s.manager, path, before, after: next, diff: diffLines(path, before, next) });
  }
  return fixes;
}

/** Writes one planned fix, keeping a backup of the file it replaces. Returns the backup path (null for a new file). */
export function applyCooldownFix(fix: CooldownFix, backupsDir: string, now: Date = new Date()): string | null {
  assertNotRealHome(fix.path);
  let backup: string | null = null;
  if (fix.before === null && existsSync(fix.path)) throw new Error(`${fix.path} exists but could not be read, so it was left alone`);
  if (existsSync(fix.path)) {
    ensureDir(backupsDir);
    backup = join(backupsDir, `cooldown-${fix.manager}-${now.toISOString().replace(/[^0-9]/g, "").slice(0, 14)}.bak`);
    copyFileSync(fix.path, backup);
  }
  // The person's own file: written through a symlink (a dotfiles repository) rather than replacing it, and with its own mode.
  let target = fix.path;
  let mode = 0o644;
  if (lstatSync(fix.path, { throwIfNoEntry: false })?.isSymbolicLink() === true) target = realpathSync(fix.path);
  try {
    mode = statSync(target).mode & 0o777;
  } catch {
    // A new file.
  }
  atomicWrite(target, fix.after, mode);
  return backup;
}
