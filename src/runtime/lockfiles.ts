/**
 * Lockfile reading for the lockfile check: which name@version pairs an
 * install from a lockfile will fetch. Bounded (20 MB per file) and parsed with
 * JSON or line-oriented regular expressions only: no YAML or TOML library, and
 * nothing in a lockfile is ever executed. A file that is too large or cannot
 * be parsed is reported as skipped, never as clean-by-default silently.
 */

import { readFileSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { stripBom } from "../bom.js";
import type { Ecosystem, LockfileEntry, LockfileRead } from "../engine/packages.js";
import { own } from "../own.js";

export const MAX_LOCKFILE_BYTES = 20 * 1024 * 1024;

const FILES: Partial<Record<Ecosystem, readonly string[]>> = {
  npm: ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "deno.lock"],
  PyPI: ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock"],
  RubyGems: ["Gemfile.lock"],
  "crates.io": ["Cargo.lock"],
  Packagist: ["composer.lock"],
};

/** Lockfiles the firewall finds but has no reader for: reported as skipped, never as clean. */
const UNREAD_LOCKFILES: ReadonlySet<string> = new Set(["bun.lock", "bun.lockb", "deno.lock"]);

/** `npm:name@range` (an alias): the real package behind it, or null when the spec is a plain range. */
function npmAlias(spec: string): { name: string; range: string } | null {
  const m = /^npm:((?:@[^/@\s]+\/)?[^@/\s]+)@(.+)$/.exec(spec);
  return m === null ? null : { name: m[1] as string, range: m[2] as string };
}

function statExists(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

function readBounded(p: string): string | { error: string } | null {
  try {
    const st = statSync(p);
    if (!st.isFile()) return null;
    if (st.size > MAX_LOCKFILE_BYTES) return { error: `larger than ${MAX_LOCKFILE_BYTES / (1024 * 1024)} MB` };
    // A lockfile saved with a byte order mark is read as the lockfile it is, not reported as unparseable.
    return stripBom(readFileSync(p, "utf8"));
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return null;
    return { error: (e as Error).message };
  }
}

/** package-lock.json / npm-shrinkwrap.json (lockfile v1, v2 and v3). */
export function parsePackageLock(text: string): LockfileEntry[] {
  const doc = JSON.parse(text) as { packages?: Record<string, { version?: unknown; name?: unknown; link?: unknown }>; dependencies?: Record<string, unknown> };
  const out: LockfileEntry[] = [];
  if (doc.packages !== undefined && typeof doc.packages === "object") {
    for (const [key, v] of Object.entries(doc.packages)) {
      if (key === "" || typeof v !== "object" || v === null || v.link === true || typeof v.version !== "string") continue;
      const i = key.lastIndexOf("node_modules/");
      if (i === -1) continue; // a workspace package, not a download
      const name = typeof v.name === "string" ? v.name : key.slice(i + "node_modules/".length);
      out.push({ name, version: v.version });
    }
    return out;
  }
  const walk = (deps: unknown, depth: number): void => {
    if (typeof deps !== "object" || deps === null || depth > 64) return;
    for (const [name, v] of Object.entries(deps as Record<string, { version?: unknown; dependencies?: unknown }>)) {
      if (typeof v !== "object" || v === null) continue;
      if (typeof v.version === "string" && !/^(?:file|link|git\+|https?):/.test(v.version)) {
        // An alias ("foo": { "version": "npm:evil@1.0.0" }) installs the package behind it, under the name foo.
        const alias = npmAlias(v.version);
        out.push(alias !== null ? { name: alias.name, version: alias.range } : { name, version: v.version });
      }
      walk(v.dependencies, depth + 1);
    }
  };
  walk(doc.dependencies, 0);
  return out;
}

/** pnpm-lock.yaml, v5 to v9: package keys `/name/1.0.0:`, `/name@1.0.0:` or `name@1.0.0:` (peer suffixes dropped). */
export function parsePnpmLock(text: string): LockfileEntry[] {
  const out: LockfileEntry[] = [];
  let section = "";
  for (const line of text.split(/\r?\n/)) {
    const top = /^([A-Za-z]+):\s*$/.exec(line);
    if (top !== null) {
      section = top[1] as string;
      continue;
    }
    if (section !== "packages" && section !== "snapshots") continue;
    const m = /^ {2}['"]?([^\s'"][^'":]*?)(?:\([^)]*\))*['"]?:\s*$/.exec(line);
    if (m === null) continue;
    let key = (m[1] as string).replace(/\(.*$/, "");
    if (key.startsWith("/")) key = key.slice(1);
    // v5: name/1.0.0[_peer@x]; v6 and v9: name@1.0.0 (scoped names keep their leading @scope/).
    const v5 = /^((?:@[^/]+\/)?[^/@]+)\/(\d[^/]*)$/.exec(key);
    const v6 = v5 === null ? /^((?:@[^/]+\/)?[^/@]+)@(\d.*)$/.exec(key) : null;
    const hit = v5 ?? v6;
    if (hit === null) continue;
    const name = hit[1] as string;
    const version = (hit[2] as string).replace(/_.*$/, "");
    out.push({ name, version });
  }
  return out;
}

/** yarn.lock, classic (v1) and Berry: an entry header, then its `version`. */
export function parseYarnLock(text: string): LockfileEntry[] {
  const out: LockfileEntry[] = [];
  let pending: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (line === "" || line.startsWith("#")) continue;
    if (!line.startsWith(" ")) {
      pending = null;
      if (!line.endsWith(":") || line.startsWith("__metadata")) continue;
      const first = (line.slice(0, -1).split(/,\s*/)[0] ?? "").replace(/^"|"$/g, "");
      const at = first.indexOf("@", first.startsWith("@") ? 1 : 0);
      if (at <= 0) continue;
      const spec = first.slice(at + 1);
      // Workspace, link, file, patch and git entries are not registry downloads.
      if (/^(?:workspace|link|file|portal|patch|git|github|https?):/.test(spec)) continue;
      // `foo@npm:evil@1.0.0` installs evil, whatever the project calls it.
      pending = npmAlias(spec)?.name ?? first.slice(0, at);
      continue;
    }
    if (pending !== null) {
      const v = /^ {2}version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
      if (v !== null) {
        out.push({ name: pending, version: v[1] as string });
        pending = null;
      }
    }
  }
  return out;
}

/** TOML lockfiles with [[package]] tables: Cargo.lock, poetry.lock, uv.lock, pdm.lock. */
export function parseTomlPackages(text: string, opts: { registryOnly?: boolean; requireSource?: boolean } = {}): LockfileEntry[] {
  const out: LockfileEntry[] = [];
  let cur: { name?: string; version?: string; source?: string } | null = null;
  const flush = (): void => {
    if (cur?.name !== undefined && cur.version !== undefined) {
      const local = cur.source !== undefined && /^\{\s*(?:editable|virtual|directory|path|workspace)\s*=/.test(cur.source);
      const git = cur.source !== undefined && /git\+|\bgit\s*=/.test(cur.source);
      const unsourced = opts.requireSource === true && cur.source === undefined; // a workspace crate, not a download
      if (!(opts.registryOnly === true && (local || git)) && !unsourced) out.push({ name: cur.name, version: cur.version });
    }
  };
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*\[\[package\]\]\s*$/.test(line)) {
      flush();
      cur = {};
      continue;
    }
    if (/^\s*\[/.test(line)) {
      flush();
      cur = null;
      continue;
    }
    if (cur === null) continue;
    const kv = /^\s*(name|version|source)\s*=\s*(.+?)\s*$/.exec(line);
    if (kv === null) continue;
    const val = kv[2] as string;
    const str = /^"((?:[^"\\]|\\.)*)"$/.exec(val);
    if (kv[1] === "source") cur.source = val;
    else if (str !== null) cur[kv[1] as "name" | "version"] = str[1] as string;
  }
  flush();
  return out;
}

/** Pipfile.lock (JSON): default and develop sections, `==` pins. */
export function parsePipfileLock(text: string): LockfileEntry[] {
  const doc = JSON.parse(text) as Record<string, Record<string, { version?: unknown }>>;
  const out: LockfileEntry[] = [];
  for (const sec of ["default", "develop"]) {
    for (const [name, v] of Object.entries(own(doc, sec) ?? {})) {
      if (typeof v?.version === "string" && v.version.startsWith("==")) out.push({ name, version: v.version.slice(2) });
    }
  }
  return out;
}

/** Gemfile.lock: the `specs:` lists under GEM. */
export function parseGemfileLock(text: string): LockfileEntry[] {
  const out: LockfileEntry[] = [];
  let inGem = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^[A-Z]/.test(line)) {
      inGem = line.trim() === "GEM";
      continue;
    }
    if (!inGem) continue;
    const m = /^ {4}([A-Za-z0-9._-]+) \(([^)\s]+)\)\s*$/.exec(line);
    if (m !== null) out.push({ name: m[1] as string, version: (m[2] as string).replace(/-(?:x86|x64|arm|aarch|universal|java|mingw|mswin|darwin|linux)[\w-]*$/, "") });
  }
  return out;
}

/** composer.lock (JSON). */
export function parseComposerLock(text: string): LockfileEntry[] {
  const doc = JSON.parse(text) as Record<string, { name?: unknown; version?: unknown }[]>;
  const out: LockfileEntry[] = [];
  for (const sec of ["packages", "packages-dev"]) {
    for (const p of own(doc, sec) ?? []) if (typeof p?.name === "string" && typeof p.version === "string") out.push({ name: p.name, version: p.version.replace(/^v/, "") });
  }
  return out;
}

/** requirements*.txt: `name==version` pins, following `-r other.txt` includes a few levels deep. */
export function parseRequirements(path: string, depth = 0, seen: Set<string> = new Set()): { entries: LockfileEntry[]; error?: string; /** Includes that could not be followed: reported on their own, so the pins that were read still count. */ problems?: { file: string; error: string }[] } {
  if (depth > 4) return { entries: [], error: "includes are nested more than 4 levels deep, so this one was not read" };
  if (seen.has(path)) return { entries: [] };
  seen.add(path);
  const text = readBounded(path);
  if (text === null) return { entries: [], error: "not found" };
  if (typeof text !== "string") return { entries: [], error: text.error };
  const out: LockfileEntry[] = [];
  const problems: { file: string; error: string }[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/(?:^|\s)#.*$/, "").trim();
    if (line === "") continue;
    const inc = /^(?:-r|--requirement)\s*=?\s*(\S+)$/.exec(line);
    if (inc !== null) {
      const p = inc[1] as string;
      const file = isAbsolute(p) ? p : join(dirname(path), p);
      const sub = parseRequirements(file, depth + 1, seen);
      out.push(...sub.entries);
      if (sub.error !== undefined) problems.push({ file, error: sub.error });
      problems.push(...(sub.problems ?? []));
      continue;
    }
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9.+!_-]+)(?:\s*;.*)?(?:\s+--hash=\S+)*\s*\\?$/.exec(line);
    if (m !== null) out.push({ name: m[1] as string, version: m[2] as string });
  }
  return { entries: out, ...(problems.length > 0 ? { problems } : {}) };
}

function parseFor(file: string, text: string): LockfileEntry[] {
  if (file.endsWith("package-lock.json") || file.endsWith("npm-shrinkwrap.json")) return parsePackageLock(text);
  if (file.endsWith("pnpm-lock.yaml")) return parsePnpmLock(text);
  if (file.endsWith("yarn.lock")) return parseYarnLock(text);
  if (file.endsWith("Pipfile.lock")) return parsePipfileLock(text);
  if (file.endsWith("Gemfile.lock")) return parseGemfileLock(text);
  if (file.endsWith("composer.lock")) return parseComposerLock(text);
  return parseTomlPackages(text, { registryOnly: true, requireSource: file.endsWith("Cargo.lock") });
}

/** The LockfileReader the hook injects (ctx.lockfiles). */
export function readLockfiles(dir: string, eco: Ecosystem, files?: readonly string[]): LockfileRead[] {
  const out: LockfileRead[] = [];
  if (files !== undefined && files.length > 0) {
    for (const f of files) {
      const abs = resolve(dir, f);
      const r = parseRequirements(abs);
      out.push({ file: abs, eco, entries: r.entries, ...(r.error !== undefined ? { error: r.error } : {}) });
      for (const p of r.problems ?? []) out.push({ file: p.file, eco, entries: [], error: p.error });
    }
    return out;
  }
  for (const name of FILES[eco] ?? []) {
    const file = join(dir, name);
    if (UNREAD_LOCKFILES.has(name)) {
      if (statExists(file)) out.push({ file, eco, entries: [], error: "is a lockfile the firewall cannot read yet, so its packages were not checked" });
      continue;
    }
    const text = readBounded(file);
    if (text === null) continue;
    if (typeof text !== "string") {
      out.push({ file, eco, entries: [], error: text.error });
      continue;
    }
    try {
      out.push({ file, eco, entries: parseFor(file, text) });
    } catch (e) {
      out.push({ file, eco, entries: [], error: `could not be parsed (${(e as Error).message})` });
    }
  }
  return out;
}
