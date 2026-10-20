/**
 * Package vetting. Which packages an install or a package runner asks
 * for (per package manager), whether the local malicious-package snapshot
 * lists them, whether a name looks like a typosquat of a popular package, and
 * whether an install from a lockfile would pull a listed version.
 *
 * Pure: the snapshot and the lockfile reader are injected through the
 * Context (ctx.packageIntel, ctx.lockfiles), so the decision path does no
 * network I/O and only reads files when an install verb needs them.
 *
 * The shell analyzer calls notePackageCommand() from packageManager() and the
 * runner branch; evaluate() calls packageRules() once per decision.
 */

import type { Context, FindingId, FirewallConfig, Outcome } from "../types.js";
import type { Collector } from "./effects.js";
import type { Word } from "./shell/parse.js";
import { typosquatOf } from "./typosquat.js";

export type Ecosystem = "npm" | "PyPI" | "crates.io" | "RubyGems" | "Go" | "Maven" | "NuGet" | "Packagist";

export const ECOSYSTEMS: readonly Ecosystem[] = ["npm", "PyPI", "crates.io", "RubyGems", "Go", "Maven", "NuGet", "Packagist"];

/** File-system-safe directory name for an ecosystem inside the snapshot. */
export function ecoDir(eco: Ecosystem): string {
  return eco.toLowerCase();
}

export function parseEcosystem(s: string): Ecosystem | null {
  const l = s.trim().toLowerCase();
  return ECOSYSTEMS.find((e) => e.toLowerCase() === l) ?? null;
}

/** Names as the registry compares them, so `Evil_Fixture` finds `evil-fixture` (PEP 503 for PyPI). */
export function normalizeName(eco: Ecosystem, name: string): string {
  const n = name.trim();
  switch (eco) {
    case "PyPI":
      return n.toLowerCase().replace(/[-_.]+/g, "-");
    case "crates.io":
      return n.toLowerCase().replace(/_/g, "-");
    case "Go":
    case "Maven":
      return n;
    default:
      return n.toLowerCase();
  }
}

// --- the snapshot's shape (written by `update`, read through ctx.packageIntel) -----------------------

export interface IntelRange {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

export interface IntelEntry {
  /** Every version of the package is malicious (a range introduced at 0 with no end). */
  all: boolean;
  versions: string[];
  ranges: IntelRange[];
  /** The advisory ids (MAL-...). */
  ids: string[];
}

export type IntelAnswer =
  | { kind: "listed"; entry: IntelEntry }
  /** The snapshot covers this ecosystem and does not list the name. */
  | { kind: "clean" }
  /** No snapshot, or it does not cover this ecosystem. */
  | { kind: "none" }
  /** The snapshot could not be read for this name: no verdict, logged, doctor fails. */
  | { kind: "damaged"; detail: string };

export interface PackageIntel {
  /** Whether a snapshot covering this ecosystem exists (lockfiles are read only then). */
  covers(eco: Ecosystem): boolean;
  lookup(eco: Ecosystem, name: string): IntelAnswer;
  /** Many names at once (a lockfile); only listed or damaged names need be returned. */
  lookupMany(eco: Ecosystem, names: readonly string[]): Map<string, IntelAnswer>;
  /** When the snapshot was fetched (ISO), for reasons; undefined without one. */
  fetchedAt(): string | undefined;
}

export interface LockfileEntry {
  name: string;
  version: string;
}

export interface LockfileRead {
  file: string;
  eco: Ecosystem;
  entries: LockfileEntry[];
  /** Set when the file was skipped (too large, unparseable); entries is then empty. */
  error?: string;
}

/** Reads the lockfiles for an ecosystem in a directory, or exactly `files` when given (pip -r). */
export type LockfileReader = (dir: string, eco: Ecosystem, files?: readonly string[]) => LockfileRead[];

// --- what a command asks for --------------------------------------------------------------------------

export interface PackageRequest {
  eco: Ecosystem;
  name: string;
  /** An exact version (npm i x@1.2.3, pip install x==1.2.3). */
  version: string | null;
  /** A range or tag the resolver will pick from (x@^1, x>=2, x@next). */
  range: string | null;
  /** The command, for reasons ("npm install"). */
  via: string;
}

export interface LockfileInstall {
  eco: Ecosystem;
  /** Directory the manager runs in (absolute). */
  dir: string;
  /** Explicit requirement files (pip install -r f); otherwise the ecosystem's lockfiles in dir. */
  files: string[];
  via: string;
}

interface Note {
  requests: PackageRequest[];
  lockfiles: LockfileInstall[];
}

/** Per-classification notes, keyed by the collector so the shared Collector type needs no new field. */
const NOTES = new WeakMap<Collector, Note>();

function note(c: Collector): Note {
  let n = NOTES.get(c);
  if (n === undefined) {
    n = { requests: [], lockfiles: [] };
    NOTES.set(c, n);
  }
  return n;
}

export function notedPackages(c: Collector): Readonly<Note> {
  return NOTES.get(c) ?? { requests: [], lockfiles: [] };
}

interface Split {
  /** Positional words, in order, with whether each is literal. */
  pos: { text: string; literal: boolean }[];
  /** Values of value-taking flags, by flag name. */
  opts: Map<string, string[]>;
  bools: Set<string>;
}

/** Splits arguments, consuming the values of the flags that take one (so `-w web add x` finds `add`). */
function split(args: readonly Word[], valueFlags: ReadonlySet<string>): Split {
  const out: Split = { pos: [], opts: new Map(), bools: new Set() };
  let rest = false;
  for (let i = 0; i < args.length; i++) {
    const w = args[i] as Word;
    const t = w.text;
    if (!rest && t === "--") {
      rest = true;
      continue;
    }
    if (!rest && t.startsWith("-") && t !== "-") {
      const eq = t.indexOf("=");
      const name = eq === -1 ? t : t.slice(0, eq);
      if (valueFlags.has(name)) {
        const v = eq === -1 ? args[++i]?.text : t.slice(eq + 1);
        if (v !== undefined) out.opts.set(name, [...(out.opts.get(name) ?? []), v]);
      } else out.bools.add(name);
      continue;
    }
    out.pos.push({ text: t, literal: !w.dynamic && !w.glob });
  }
  return out;
}

function opt(s: Split, ...names: string[]): string | undefined {
  for (const n of names) {
    const v = s.opts.get(n);
    if (v !== undefined && v.length > 0) return v[v.length - 1];
  }
  return undefined;
}

function resolveDir(ctx: Context, d: string | undefined): string {
  if (d === undefined || d === "") return ctx.cwd;
  const expanded = d.startsWith("~/") ? `${ctx.home}${d.slice(1)}` : d;
  if (expanded.startsWith("/")) return expanded.replace(/\/+$/, "") || "/";
  const parts = `${ctx.cwd}/${expanded}`.split("/");
  const outParts: string[] = [];
  for (const p of parts) {
    if (p === "" || p === ".") continue;
    if (p === "..") outParts.pop();
    else outParts.push(p);
  }
  return `/${outParts.join("/")}`;
}

const EXACT_SEMVER = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/** A registry name, not a path, URL, git spec or tarball. */
function registryName(s: string): boolean {
  if (s === "" || /^[./~]/.test(s) || /^[a-z][a-z0-9+.-]*:/i.test(s) || /\.(?:tgz|tar\.gz|tar|zip|whl|gem|crate)$/i.test(s)) return false;
  return true;
}

/** npm-style `name@spec` (scoped names keep their leading @). */
export function parseNpmSpec(raw: string): { name: string; version: string | null; range: string | null } | null {
  const s = raw.trim();
  if (!registryName(s)) return null;
  const at = s.indexOf("@", s.startsWith("@") ? 1 : 0);
  let name = at === -1 ? s : s.slice(0, at);
  const spec = at === -1 ? "" : s.slice(at + 1);
  // Aliases: alias@npm:real@1.2.3 installs `real`.
  if (spec.startsWith("npm:")) return parseNpmSpec(spec.slice(4));
  if (/^[a-z][a-z0-9+.-]*:/i.test(spec)) return null; // git+https:, file:, github: ...
  // `user/repo` is a GitHub shorthand, not a registry name.
  if (!name.startsWith("@") && name.includes("/")) return null;
  if (name.startsWith("@") && !/^@[^/]+\/[^/]+$/.test(name)) return null;
  if (!/^(?:@[a-z0-9][\w.~-]*\/)?[a-z0-9][\w.~-]*$/i.test(name)) return null;
  name = name.toLowerCase();
  if (spec === "" || spec === "latest" || spec === "*") return { name, version: null, range: null };
  if (EXACT_SEMVER.test(spec) || /^=v?\d+\.\d+\.\d+/.test(spec)) return { name, version: spec.replace(/^=/, ""), range: null };
  return { name, version: null, range: spec };
}

/** A PEP 508 requirement (`name[extra]==1.0; marker`). */
export function parsePep508(raw: string): { name: string; version: string | null; range: string | null } | null {
  const s = raw.split(";")[0]?.trim() ?? "";
  if (!registryName(s) || / @ /.test(s) || s.includes("/")) return null;
  const m = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(s);
  if (m === null) return null;
  const name = m[1] as string;
  const rest = (m[2] ?? "").trim();
  if (rest === "") return { name, version: null, range: null };
  const exact = /^===?\s*([A-Za-z0-9.+!_-]+)$/.exec(rest);
  if (exact !== null && !(exact[1] as string).includes("*")) return { name, version: exact[1] as string, range: null };
  // uvx / uv tool accept name@version.
  const at = /^@\s*([0-9][A-Za-z0-9.+!_-]*)$/.exec(rest);
  if (at !== null) return { name, version: at[1] as string, range: null };
  if (/^[<>=!~^@*,\s0-9A-Za-z.+_-]+$/.test(rest)) return { name, version: null, range: rest };
  return null;
}

const NPM_VALUE_FLAGS = new Set(["--prefix", "-w", "--workspace", "--registry", "--tag", "--cache", "--userconfig", "--globalconfig", "-C", "--dir", "--cwd", "--save-prefix", "--omit", "--include", "--install-strategy", "--loglevel", "--before", "--filter", "-F", "--reporter", "--store-dir", "--virtual-store-dir", "--network-concurrency", "--child-concurrency", "--config", "-c", "--call", "--package", "-p", "--network-timeout", "--mode", "--modules-folder", "--cache-folder", "--cache-dir", "--backend", "--workspace-root"]);
const PIP_VALUE_FLAGS = new Set(["-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix", "--root", "--trusted-host", "--platform", "--python-version", "--implementation", "--abi", "--src", "--upgrade-strategy", "--progress-bar", "--log", "--cache-dir", "--report", "--python", "-p", "--index", "--default-index", "--group", "--extra", "--package", "--directory", "--project", "--with", "--from", "-o", "--output-file", "--python-platform", "--resolution", "--prerelease", "--config-file", "--exclude-newer", "--index-strategy", "--keyring-provider", "--link-mode", "--refresh-package", "--reinstall-package", "--upgrade-package", "-P", "--overrides", "--torch-backend", "--with-requirements", "--with-editable", "--spec", "--pip-args", "--suffix", "-G", "-E", "--extras", "--source", "-C", "-L", "--lockfile", "--only-binary", "--no-binary"]);
const CARGO_VALUE_FLAGS = new Set(["--vers", "--version", "--git", "--branch", "--tag", "--rev", "--path", "--registry", "--index", "-p", "--package", "-F", "--features", "--target", "--root", "--manifest-path", "--rename", "-j", "--jobs", "--profile", "--target-dir", "--color", "-Z", "--config", "--bin", "--example"]);
const GEM_VALUE_FLAGS = new Set(["-v", "--version", "-s", "--source", "-i", "--install-dir", "-n", "--bindir", "--platform", "-g", "--file", "--group", "--git", "--branch", "--path", "--gemfile", "--jobs", "-j", "--retry", "--without", "--with"]);
const GO_VALUE_FLAGS = new Set(["-modfile", "-C", "-o", "-tags", "-ldflags", "-gcflags", "-p", "-mod"]);
const COMPOSER_VALUE_FLAGS = new Set(["-d", "--working-dir"]);

/** `npm init foo` / `yarn create foo` run the package create-foo (scoped: @s/create-foo). */
function createPackage(arg: string): string | null {
  const m = /^(@[^/@]+)(?:\/([^@]+))?(@.*)?$/.exec(arg);
  if (m !== null) return `${m[1]}/create${m[2] !== undefined ? `-${m[2]}` : ""}${m[3] ?? ""}`;
  if (!registryName(arg) || arg.includes("/")) return null;
  const at = arg.indexOf("@");
  return at === -1 ? `create-${arg}` : `create-${arg.slice(0, at)}${arg.slice(at)}`;
}

function addRequest(n: Note, eco: Ecosystem, parsed: { name: string; version: string | null; range: string | null } | null, via: string): void {
  if (parsed === null || parsed.name === "") return;
  if (n.requests.some((r) => r.eco === eco && r.name === parsed.name && r.version === parsed.version && r.range === parsed.range)) return;
  n.requests.push({ eco, name: parsed.name, version: parsed.version, range: parsed.range, via });
}

function addLockfile(n: Note, l: LockfileInstall): void {
  if (!n.lockfiles.some((x) => x.eco === l.eco && x.dir === l.dir && x.files.join("\0") === l.files.join("\0"))) n.lockfiles.push(l);
}

function literalNames(s: Split, from: number): string[] {
  return s.pos.slice(from).filter((p) => p.literal && !/^[A-Z_][A-Z0-9_]*=/.test(p.text)).map((p) => p.text);
}

/**
 * Records the packages a package-manager or runner invocation asks for. Called by the shell analyzer
 * with the program's base name and its argument words; anything it does not recognise is ignored
 * (the install is still judged by FW-INSTALL as before).
 */
export function notePackageCommand(c: Collector, program: string, args: readonly Word[]): void {
  try {
    noteInner(c, program, args);
  } catch {
    // A parsing surprise must never break the decision; the install rules still apply.
  }
}

function noteInner(c: Collector, program: string, args: readonly Word[]): void {
  const n = note(c);
  const name = program === "pip3" ? "pip" : program === "bundler" ? "bundle" : program;
  switch (name) {
    case "npx":
    case "pnpx":
    case "bunx":
    case "dlx": {
      const s = split(args, NPM_VALUE_FLAGS);
      const pkgs = s.opts.get("--package") ?? s.opts.get("-p") ?? [];
      if (pkgs.length > 0) for (const p of pkgs) addRequest(n, "npm", parseNpmSpec(p), name);
      else if (s.pos[0]?.literal === true) addRequest(n, "npm", parseNpmSpec(s.pos[0].text), name);
      return;
    }
    case "uvx": {
      const s = split(args, PIP_VALUE_FLAGS);
      const from = opt(s, "--from");
      if (from !== undefined) addRequest(n, "PyPI", parsePep508(from), "uvx");
      else if (s.pos[0]?.literal === true) addRequest(n, "PyPI", parsePep508(s.pos[0].text), "uvx");
      for (const w of s.opts.get("--with") ?? []) addRequest(n, "PyPI", parsePep508(w), "uvx --with");
      return;
    }
    case "npm":
    case "pnpm":
    case "yarn":
    case "bun":
      return noteNode(c, n, name, args);
    case "pip":
    case "uv":
    case "poetry":
    case "pdm":
    case "pipx":
    case "pipenv":
      return notePython(c, n, name, args);
    case "cargo": {
      const s = split(args, CARGO_VALUE_FLAGS);
      const verb = s.pos[0]?.text ?? "";
      if (verb === "add") for (const p of literalNames(s, 1)) {
        const at = p.indexOf("@");
        const nm = at === -1 ? p : p.slice(0, at);
        const ver = at === -1 ? "" : p.slice(at + 1);
        if (!/^[A-Za-z0-9_-]+$/.test(nm) || s.opts.has("--git") || s.opts.has("--path")) continue;
        // `cargo add x@1.2.3` is a caret requirement: the resolver may pick a newer version.
        addRequest(n, "crates.io", { name: nm, version: ver.startsWith("=") ? ver.slice(1) : null, range: ver !== "" && !ver.startsWith("=") ? ver : null }, "cargo add");
      } else if (verb === "install") {
        if (s.opts.has("--git") || s.opts.has("--path")) return;
        const v = opt(s, "--version", "--vers");
        for (const p of literalNames(s, 1)) {
          const at = p.indexOf("@");
          const nm = at === -1 ? p : p.slice(0, at);
          const ver = at === -1 ? v : p.slice(at + 1);
          if (!/^[A-Za-z0-9_-]+$/.test(nm)) continue;
          // `cargo install --version 1.2.3` installs exactly that version; with an operator it is a range.
          const exact = ver !== undefined && EXACT_SEMVER.test(ver.replace(/^=/, "")) ? ver.replace(/^=/, "") : null;
          addRequest(n, "crates.io", { name: nm, version: exact, range: exact === null ? (ver ?? null) : null }, "cargo install");
        }
      } else if (verb === "build" || verb === "fetch") {
        addLockfile(n, { eco: "crates.io", dir: manifestDir(c.ctx, opt(s, "--manifest-path")), files: [], via: `cargo ${verb}` });
      }
      return;
    }
    case "gem": {
      const s = split(args, GEM_VALUE_FLAGS);
      if (s.pos[0]?.text !== "install" || s.opts.has("--file") || s.opts.has("-g")) return;
      const v = opt(s, "-v", "--version");
      const names = literalNames(s, 1).filter((x) => /^[A-Za-z0-9._-]+$/.test(x));
      for (const nm of names) {
        const exact = v !== undefined && names.length === 1 && /^\d+(?:\.[0-9A-Za-z]+)*$/.test(v.replace(/^=\s*/, "")) ? v.replace(/^=\s*/, "") : null;
        addRequest(n, "RubyGems", { name: nm, version: exact, range: exact === null && v !== undefined && names.length === 1 ? v : null }, "gem install");
      }
      return;
    }
    case "bundle": {
      const s = split(args, GEM_VALUE_FLAGS);
      const verb = s.pos[0]?.text ?? "install";
      if (verb === "add") {
        if (s.opts.has("--git") || s.opts.has("--path")) return;
        const v = opt(s, "--version", "-v");
        for (const nm of literalNames(s, 1).filter((x) => /^[A-Za-z0-9._-]+$/.test(x))) {
          const exact = v !== undefined && /^\d+(?:\.[0-9A-Za-z]+)*$/.test(v) ? v : null;
          addRequest(n, "RubyGems", { name: nm, version: exact, range: exact === null ? (v ?? null) : null }, "bundle add");
        }
      } else if (verb === "install") {
        const gemfile = opt(s, "--gemfile");
        addLockfile(n, { eco: "RubyGems", dir: gemfile !== undefined ? parentDir(resolveDir(c.ctx, gemfile)) : c.ctx.cwd, files: [], via: "bundle install" });
      }
      return;
    }
    case "go": {
      const s = split(args, GO_VALUE_FLAGS);
      const verb = s.pos[0]?.text ?? "";
      if (verb !== "get" && verb !== "install" && verb !== "run") return;
      for (const p of literalNames(s, 1)) {
        // One optional path part: `(?:\/[^\s@]+)*` accepts the same strings, but [^\s@] also matches "/", so it
        // could split a path many ways and backtracked exponentially on one that fails to match.
        const m = /^([a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s@]+)?)(?:@(.+))?$/i.exec(p);
        if (m === null) continue;
        if (verb === "run" && m[2] === undefined) continue; // a local package path, not a download
        const ver = m[2];
        const exact = ver !== undefined && /^v?\d+\.\d+\.\d+/.test(ver) ? ver : null;
        addRequest(n, "Go", { name: m[1] as string, version: exact, range: exact === null && ver !== undefined && ver !== "latest" && ver !== "upgrade" && ver !== "patch" ? ver : null }, `go ${verb}`);
      }
      return;
    }
    case "composer": {
      const s = split(args, COMPOSER_VALUE_FLAGS);
      const verb = s.pos[0]?.text ?? "";
      const dir = resolveDir(c.ctx, opt(s, "-d", "--working-dir"));
      if (verb === "require" || verb === "req") {
        const names = literalNames(s, 1);
        for (let i = 0; i < names.length; i++) {
          const p = names[i] as string;
          const m = /^([a-z0-9][a-z0-9_.-]*\/[a-z0-9][a-z0-9_.-]*)(?:[:=](.+))?$/i.exec(p);
          if (m === null) continue;
          let ver = m[2];
          // `composer require vendor/pkg 1.2.3`: a bare constraint after the name.
          if (ver === undefined && names[i + 1] !== undefined && !(names[i + 1] as string).includes("/")) ver = names[++i];
          const exact = ver !== undefined && /^v?\d+\.\d+\.\d+$/.test(ver) ? ver : null;
          addRequest(n, "Packagist", { name: (m[1] as string).toLowerCase(), version: exact, range: exact === null ? (ver ?? null) : null }, "composer require");
        }
      } else if (verb === "install" || verb === "i") addLockfile(n, { eco: "Packagist", dir, files: [], via: "composer install" });
      return;
    }
    default:
      return;
  }
}

function parentDir(p: string): string {
  const i = p.lastIndexOf("/");
  return i <= 0 ? "/" : p.slice(0, i);
}

function manifestDir(ctx: Context, manifest: string | undefined): string {
  return manifest === undefined ? ctx.cwd : parentDir(resolveDir(ctx, manifest));
}

const NODE_INSTALL = new Set(["install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isntall", "add", "a", "ci", "clean-install", "ic", "install-clean", "isntall-clean", "update", "up", "upgrade", "udpate"]);
const NODE_LOCKFILE_VERBS = new Set(["install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isntall", "ci", "clean-install", "ic", "install-clean", "isntall-clean"]);

function noteNode(c: Collector, n: Note, name: "npm" | "pnpm" | "yarn" | "bun", args: readonly Word[]): void {
  const s = split(args, NPM_VALUE_FLAGS);
  let i = 0;
  let verb = s.pos[0]?.text ?? "";
  if (name === "yarn" && verb === "global") {
    i = 1;
    verb = s.pos[1]?.text ?? "";
  }
  const dir = resolveDir(c.ctx, opt(s, "--prefix", "-C", "--dir", "--cwd"));
  const via = `${name} ${verb}`.trim();
  if ((name === "npm" && (verb === "exec" || verb === "x")) || ((name === "pnpm" || name === "yarn") && verb === "dlx") || (name === "bun" && verb === "x")) {
    const pkgs = s.opts.get("--package") ?? s.opts.get("-p") ?? [];
    if (pkgs.length > 0) for (const p of pkgs) addRequest(n, "npm", parseNpmSpec(p), via);
    else if (s.pos[i + 1]?.literal === true) addRequest(n, "npm", parseNpmSpec((s.pos[i + 1] as { text: string }).text), via);
    return;
  }
  if (verb === "create" || (name === "npm" && (verb === "init" || verb === "innit"))) {
    const target = s.pos[i + 1];
    if (target?.literal === true) {
      const pkg = createPackage(target.text);
      if (pkg !== null) addRequest(n, "npm", parseNpmSpec(pkg), via);
    }
    return;
  }
  const bare = verb === "" && (name === "yarn" || name === "bun");
  if (!NODE_INSTALL.has(verb) && !bare) return;
  const names = literalNames(s, i + 1);
  for (const p of names) addRequest(n, "npm", parseNpmSpec(p), via);
  const lockVerb = bare || NODE_LOCKFILE_VERBS.has(verb);
  if (lockVerb && names.length === 0 && s.pos.slice(i + 1).length === 0) addLockfile(n, { eco: "npm", dir, files: [], via: via === "" ? name : via });
}

function notePython(c: Collector, n: Note, name: "pip" | "uv" | "poetry" | "pdm" | "pipx" | "pipenv", args: readonly Word[]): void {
  const s = split(args, PIP_VALUE_FLAGS);
  let verbs = s.pos.map((p) => p.text);
  let via = name as string;
  if (name === "uv" && verbs[0] === "pip") {
    verbs = verbs.slice(1);
    via = "uv pip";
  }
  if (name === "uv" && verbs[0] === "tool") {
    verbs = verbs.slice(1);
    via = "uv tool";
  }
  const verb = verbs[0] ?? (name === "pipenv" ? "install" : "");
  via = `${via} ${verb}`.trim();
  const firstName = s.pos.length - verbs.length + 1;
  const dir = resolveDir(c.ctx, name === "uv" || name === "poetry" || name === "pdm" ? opt(s, "--directory", "--project", "-C") : undefined);
  const reqFiles = [...(s.opts.get("-r") ?? []), ...(s.opts.get("--requirement") ?? [])].map((f) => resolveDir(c.ctx, f));
  const named = (from: number): void => {
    for (const p of literalNames(s, from)) addRequest(n, "PyPI", parsePep508(p), via);
  };
  if (name === "pipx") {
    if (verb === "install" || verb === "run") {
      const spec = opt(s, "--spec");
      if (spec !== undefined) addRequest(n, "PyPI", parsePep508(spec), via);
      else if (verb === "run") {
        const p = s.pos[firstName];
        if (p?.literal === true) addRequest(n, "PyPI", parsePep508(p.text), via);
      } else named(firstName);
    }
    return;
  }
  if (via.startsWith("uv tool") && (verb === "install" || verb === "run")) {
    const from = opt(s, "--from");
    if (from !== undefined) addRequest(n, "PyPI", parsePep508(from), via);
    else {
      const p = s.pos[firstName];
      if (p?.literal === true) addRequest(n, "PyPI", parsePep508(p.text), via);
    }
    for (const w of s.opts.get("--with") ?? []) addRequest(n, "PyPI", parsePep508(w), via);
    return;
  }
  if (name === "uv" && verb === "run") {
    for (const w of s.opts.get("--with") ?? []) addRequest(n, "PyPI", parsePep508(w), "uv run --with");
    return;
  }
  if (verb === "install" || verb === "add" || verb === "download") {
    if (name === "poetry" && verb === "add") {
      for (const p of literalNames(s, firstName)) {
        // poetry add name@1.2.3 pins exactly; name@^1.2 is a range.
        const at = p.indexOf("@");
        if (at > 0) {
          const ver = p.slice(at + 1);
          addRequest(n, "PyPI", { name: p.slice(0, at), version: /^\d+(?:\.\d+)*$/.test(ver) ? ver : null, range: /^\d+(?:\.\d+)*$/.test(ver) ? null : ver }, via);
        } else addRequest(n, "PyPI", parsePep508(p), via);
      }
    } else named(firstName);
    const editable = s.opts.has("-e") || s.opts.has("--editable");
    if (reqFiles.length > 0) addLockfile(n, { eco: "PyPI", dir: c.ctx.cwd, files: reqFiles, via });
    else if ((name === "poetry" || name === "pdm" || name === "pipenv") && verb === "install" && literalNames(s, firstName).length === 0 && !editable) addLockfile(n, { eco: "PyPI", dir, files: [], via });
    return;
  }
  if (verb === "sync") {
    if (name === "uv" && via.startsWith("uv pip")) {
      const files = literalNames(s, firstName).map((f) => resolveDir(c.ctx, f));
      if (files.length > 0) addLockfile(n, { eco: "PyPI", dir: c.ctx.cwd, files, via });
    } else if (name === "uv" || name === "pdm" || name === "pipenv") addLockfile(n, { eco: "PyPI", dir, files: [], via });
  }
}

// --- judging a version against an entry ------------------------------------------------------------------

/** Compares two dotted versions (an optional leading v, numeric segments, a pre-release tail). Throws when not comparable. */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string): { nums: number[]; pre: string } => {
    const m = /^v?(\d+(?:\.\d+)*)(?:[-.]?((?:a|b|rc|alpha|beta|pre|preview|dev|c)\.?\d*|[-+][0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/i.exec(v.trim());
    if (m === null) throw new Error(`cannot compare version ${v}`);
    return { nums: (m[1] as string).split(".").map(Number), pre: (m[2] ?? "").replace(/^[-+]/, "") };
  };
  const pa = parse(a);
  const pb = parse(b);
  const len = Math.max(pa.nums.length, pb.nums.length);
  for (let i = 0; i < len; i++) {
    const d = (pa.nums[i] ?? 0) - (pb.nums[i] ?? 0);
    if (d !== 0) return d;
  }
  if (pa.pre === pb.pre) return 0;
  if (pa.pre === "") return 1;
  if (pb.pre === "") return -1;
  return pa.pre < pb.pre ? -1 : 1;
}

function sameVersion(eco: Ecosystem, a: string, b: string): boolean {
  if (a === b) return true;
  const strip = (v: string): string => v.trim().replace(/^v/, "");
  if (strip(a) === strip(b)) return true;
  if (eco === "PyPI" || eco === "RubyGems") {
    try {
      return compareVersions(a, b) === 0;
    } catch {
      return false;
    }
  }
  return false;
}

export type Judgement = "malicious" | "maybe" | "clean";

/** Whether an exact version, or "whatever the resolver picks" (null), is malicious according to an entry. */
export function judge(eco: Ecosystem, entry: IntelEntry, version: string | null): Judgement {
  if (entry.all) return "malicious";
  if (version === null) return entry.versions.length > 0 || entry.ranges.length > 0 ? "maybe" : "clean";
  if (entry.versions.some((v) => sameVersion(eco, v, version))) return "malicious";
  let unsure = false;
  for (const r of entry.ranges) {
    try {
      const lo = r.introduced === undefined || r.introduced === "0" ? true : compareVersions(version, r.introduced) >= 0;
      const hi = r.fixed !== undefined ? compareVersions(version, r.fixed) < 0 : r.last_affected !== undefined ? compareVersions(version, r.last_affected) <= 0 : true;
      if (lo && hi) return "malicious";
    } catch {
      unsure = true;
    }
  }
  // A range the comparator cannot read is "maybe" (a person looks), never "no".
  return unsure ? "maybe" : "clean";
}

// --- the policy ---------------------------------------------------------------------------------------------

export interface PackageIntelPolicy {
  malicious: "deny" | "approve" | "off";
  typosquat: "approve" | "off";
  lockfiles: boolean;
  maxSnapshotAgeDays: number;
}

export const DEFAULT_PACKAGE_INTEL: Readonly<PackageIntelPolicy> = { malicious: "deny", typosquat: "approve", lockfiles: true, maxSnapshotAgeDays: 30 };

export function packageIntelPolicy(cfg: FirewallConfig): PackageIntelPolicy {
  return { ...DEFAULT_PACKAGE_INTEL, ...(cfg.packageIntel ?? {}) };
}

// --- the rules ------------------------------------------------------------------------------------------------

export interface PackageHit {
  rule: string;
  outcome: Outcome;
  reason: string;
}

function label(r: { name: string; version: string | null; range: string | null }): string {
  return r.version !== null ? `${r.name}@${r.version}` : r.range !== null ? `${r.name}@${r.range}` : r.name;
}

function ids(e: IntelEntry): string {
  return e.ids.slice(0, 3).join(", ") || "OSV malicious-package data";
}

/** Bounded so a lockfile with many hits stays a readable reason. */
const MAX_LISTED = 5;
/** Lockfile entries looked up per decision (a monorepo lockfile can hold tens of thousands). */
const MAX_LOCK_ENTRIES = 100_000;

/**
 * The package rules for one classified action: FW-MALICIOUS-PACKAGE (deny, any session, for a listed
 * version or a lockfile that pins one; approve when the resolver might pick a listed version) and
 * FW-TYPOSQUAT (approve, any session). Findings are added to the collector so they are logged.
 */
export function packageRules(c: Collector): PackageHit[] {
  const n = NOTES.get(c);
  if (n === undefined || (n.requests.length === 0 && n.lockfiles.length === 0)) return [];
  const pol = packageIntelPolicy(c.cfg);
  const intel = c.ctx.packageIntel;
  const hits: PackageHit[] = [];
  const add = (id: FindingId, detail: string): void => {
    if (!c.findings.some((f) => f.id === id && f.detail === detail)) c.findings.push({ id, detail });
  };
  const malOutcome: Outcome = pol.malicious === "deny" ? "deny" : "approve";
  for (const r of n.requests) {
    if (pol.malicious !== "off" && intel !== undefined) {
      const ans = safeLookup(intel, r.eco, r.name);
      if (ans.kind === "listed") {
        const j = judge(r.eco, ans.entry, r.version);
        if (j === "malicious") {
          const detail = `${label(r)} (${r.eco}) is listed as malicious (${ids(ans.entry)})${ans.entry.all ? ", every version" : ""}`;
          add("malicious_package", detail);
          hits.push({ rule: "FW-MALICIOUS-PACKAGE", outcome: malOutcome, reason: `${r.via} ${label(r)}: ${detail} in the local OSV malicious-package snapshot${fetched(intel)}` });
        } else if (j === "maybe") {
          const detail = `some versions of ${r.name} (${r.eco}) are listed as malicious (${ids(ans.entry)}) and no exact version is given, so the resolver may pick one`;
          add("malicious_package_maybe", detail);
          hits.push({ rule: "FW-MALICIOUS-PACKAGE", outcome: "approve", reason: `${r.via} ${label(r)}: ${detail}. Pin a version that is not listed, or check it before it installs` });
        }
      } else if (ans.kind === "damaged") add("intel_unreadable", `malicious-package data for ${r.eco} could not be read (${ans.detail}); ${r.name} was not checked`);
    }
    if (pol.typosquat !== "off") {
      const t = typosquatOf(r.eco, r.name);
      if (t !== null) {
        const detail = `${r.name} looks like the popular ${r.eco} package ${t.lookalike} (${t.how})`;
        add("typosquat_name", detail);
        hits.push({ rule: "FW-TYPOSQUAT", outcome: "approve", reason: `${r.via} ${label(r)}: ${detail}. Check the name before it installs; a misspelt name is a common way to ship malware` });
      }
    }
  }
  if (pol.lockfiles && pol.malicious !== "off" && intel !== undefined && c.ctx.lockfiles !== undefined) {
    for (const l of n.lockfiles) {
      if (!safeCovers(intel, l.eco)) continue;
      let reads: LockfileRead[] = [];
      try {
        reads = c.ctx.lockfiles(l.dir, l.eco, l.files.length > 0 ? l.files : undefined);
      } catch (e) {
        add("lockfile_unreadable", `the lockfiles in ${l.dir} could not be read (${(e as Error).message}); skipped`);
        continue;
      }
      for (const rd of reads) {
        if (rd.error !== undefined) {
          add("lockfile_unreadable", `${rd.file}: ${rd.error}; skipped`);
          continue;
        }
        const entries = rd.entries.slice(0, MAX_LOCK_ENTRIES);
        const names = [...new Set(entries.map((e) => normalizeName(l.eco, e.name)))];
        let answers: Map<string, IntelAnswer>;
        try {
          answers = intel.lookupMany(l.eco, names);
        } catch (e) {
          add("intel_unreadable", `malicious-package data for ${l.eco} could not be read (${(e as Error).message})`);
          continue;
        }
        const bad: string[] = [];
        for (const e of entries) {
          const ans = answers.get(normalizeName(l.eco, e.name));
          if (ans === undefined) continue;
          if (ans.kind === "damaged") {
            add("intel_unreadable", `malicious-package data for ${l.eco} could not be read (${ans.detail})`);
            continue;
          }
          if (ans.kind !== "listed") continue;
          if (judge(l.eco, ans.entry, e.version) === "malicious") {
            const s = `${e.name}@${e.version} (${ids(ans.entry)})`;
            if (!bad.includes(s)) bad.push(s);
          }
        }
        if (bad.length > 0) {
          const detail = `${rd.file} pins ${bad.length === 1 ? "a version" : `${bad.length} versions`} listed as malicious: ${bad.slice(0, MAX_LISTED).join(", ")}${bad.length > MAX_LISTED ? ", ..." : ""}`;
          add("lockfile_malicious", detail);
          hits.push({ rule: "FW-MALICIOUS-PACKAGE", outcome: malOutcome, reason: `${l.via}: ${detail}, in the local OSV malicious-package snapshot${fetched(intel)}` });
        }
      }
    }
  }
  return hits;
}

function fetched(intel: PackageIntel): string {
  try {
    const f = intel.fetchedAt();
    return f === undefined ? "" : ` (fetched ${f.slice(0, 10)})`;
  } catch {
    return "";
  }
}

function safeLookup(intel: PackageIntel, eco: Ecosystem, name: string): IntelAnswer {
  try {
    return intel.lookup(eco, normalizeName(eco, name));
  } catch (e) {
    return { kind: "damaged", detail: (e as Error).message };
  }
}

function safeCovers(intel: PackageIntel, eco: Ecosystem): boolean {
  try {
    return intel.covers(eco);
  } catch {
    return false;
  }
}
