/**
 * Decoy files, the runtime's side: the registry, `canary plant|list|remove`, the doctor checks
 * and the alert. A decoy is credential-shaped, unmistakably fake (the infix LSCANARY), valid with no
 * provider, planted only by the person, and never written to the provenance ledger. Local only: no
 * network, no remote tokens.
 */

import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, rmdirSync, rmSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { buildCanaryIndex } from "../engine/canary.js";
import { findSecrets, fingerprint, isPlaceholder } from "../engine/secrets.js";
import type { CanaryIndex } from "../types.js";
import type { Check } from "./doctor.js";
import { atomicWrite, readText, readTextExact, withLock } from "./fsutil.js";
import { assertNotRealHome } from "./guard.js";
import type { Layout } from "./layout.js";
import { appendBounded as appendLog } from "./logbound.js";
import { realpathLoose } from "./realpath.js";

export const CANARY_KINDS = ["env", "aws", "ssh", "gh", "notes", "npmrc", "kube"] as const;
export type CanaryKind = (typeof CANARY_KINDS)[number];

/** The fixed infix that tells a person who finds a decoy what it is. */
export const CANARY_INFIX = "LSCANARY";

export interface Canary {
  id: string;
  /** Realpath of the decoy file. */
  path: string;
  kind: CanaryKind;
  /** The decoy's unique value. Stored here in the clear on purpose: it is a decoy, not a secret. */
  token: string;
  fingerprint: string;
  plantedAt: string;
  /** Realpath of the workspace it belongs to, if any. */
  workspace?: string;
  /** The file and line `plant` added to a git exclude file, so `remove` takes exactly that back out. */
  exclude?: { file: string; line: string };
  /** Directories `plant` created for it (outermost first); `remove` deletes them if they are empty. */
  createdDirs?: string[];
}

export function registryPath(l: Layout): string {
  return join(l.home, "canaries.json");
}

export type Registry = { ok: true; canaries: Canary[]; exists: boolean } | { ok: false; error: string };

function validCanary(v: unknown): v is Canary {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  if (typeof o.id !== "string" || !/^[a-z0-9]{1,32}$/.test(o.id)) return false;
  if (typeof o.path !== "string" || !isAbsolute(o.path)) return false;
  if (typeof o.kind !== "string" || !(CANARY_KINDS as readonly string[]).includes(o.kind)) return false;
  if (typeof o.token !== "string" || !o.token.includes(CANARY_INFIX)) return false;
  // The fingerprint must be the token's: a registry edited to disarm a decoy is damaged, not trusted.
  if (typeof o.fingerprint !== "string" || fingerprint(o.token) !== o.fingerprint) return false;
  if (typeof o.plantedAt !== "string") return false;
  if (o.workspace !== undefined && (typeof o.workspace !== "string" || !isAbsolute(o.workspace))) return false;
  if (o.exclude !== undefined) {
    const e = o.exclude as Record<string, unknown>;
    if (typeof e !== "object" || e === null || typeof e.file !== "string" || typeof e.line !== "string") return false;
  }
  if (o.createdDirs !== undefined && !(Array.isArray(o.createdDirs) && o.createdDirs.every((d) => typeof d === "string"))) return false;
  return true;
}

/** Reads the registry. Missing is fine (nothing planted); unreadable or corrupt is reported, never guessed at. */
export function loadRegistry(l: Layout): Registry {
  let text: string | null;
  try {
    text = readText(registryPath(l));
  } catch (e) {
    return { ok: false, error: `cannot be read (${(e as Error).message})` };
  }
  if (text === null) return { ok: true, canaries: [], exists: false };
  try {
    const raw = JSON.parse(text) as { version?: unknown; canaries?: unknown };
    if (raw.version !== 1 || !Array.isArray(raw.canaries)) return { ok: false, error: "not a version 1 registry" };
    const bad = raw.canaries.findIndex((c) => !validCanary(c));
    if (bad !== -1) return { ok: false, error: `entry ${bad + 1} is malformed or its fingerprint does not match its value` };
    return { ok: true, canaries: raw.canaries as Canary[], exists: true };
  } catch (e) {
    return { ok: false, error: `not valid JSON (${(e as Error).message})` };
  }
}

function saveRegistry(l: Layout, canaries: readonly Canary[]): void {
  assertNotRealHome(registryPath(l));
  atomicWrite(registryPath(l), `${JSON.stringify({ version: 1, canaries }, null, 2)}\n`);
}

/** The index the engine reads, or undefined when there are no decoys or the registry is damaged (doctor says so). */
export function loadCanaryIndex(l: Layout, caseInsensitive: boolean, realpath?: (p: string) => string): CanaryIndex | undefined {
  const r = loadRegistry(l);
  if (!r.ok || r.canaries.length === 0) return undefined;
  return buildCanaryIndex(r.canaries, caseInsensitive, realpath);
}

// --- values ------------------------------------------------------------------------------------------

// Spelled in two parts so the compiled file holds no complete PEM header for a secret scanner to flag.
const KEY_KIND = ["OPENSSH", "PRIVATE KEY"].join(" ");

const HEX = "0123456789abcdef";
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

function randomFrom(alphabet: string, n: number): string {
  let out = "";
  while (out.length < n) {
    for (const b of randomBytes(n * 2)) {
      if (b < 256 - (256 % alphabet.length)) out += alphabet[b % alphabet.length];
      if (out.length === n) break;
    }
  }
  return out;
}

interface Made {
  content: string;
  token: string;
}

/** Makes a decoy's content until its value is not mistaken for a placeholder (which no detector would act on). */
function make(gen: () => Made): Made {
  for (let i = 0; i < 20; i++) {
    const m = gen();
    if (!isPlaceholder(m.token)) return m;
  }
  throw new Error("could not generate a decoy value");
}

const hex = (n: number): string => randomFrom(HEX, n);
const alnum = (n: number): string => randomFrom(ALNUM, n);

interface KindSpec {
  /** Path under the workspace, or null when the kind is home-only. */
  ws: string | null;
  /** Path under the home directory, or null when the kind is workspace-only. */
  home: string | null;
  /** Make the file for a workspace (`json` true for the workspace form of aws) or home location. */
  make: (where: "ws" | "home") => Made;
}

const SPECS: Record<CanaryKind, KindSpec> = {
  env: {
    ws: ".env.backup",
    home: null,
    make: () => {
      const token = `sk-proj-${CANARY_INFIX}${hex(32)}`;
      return { token, content: `# restored from backup\nOPENAI_API_KEY=${token}\nNODE_ENV=production\n` };
    },
  },
  aws: {
    ws: "config/credentials.old.json",
    home: ".aws/credentials.bak",
    make: (where) => {
      const token = `${CANARY_INFIX}${hex(32)}`;
      const id = `AKIA${CANARY_INFIX}${randomFrom("0123456789ABCDEF", 8)}`;
      const content = where === "ws" ? `${JSON.stringify({ type: "aws", aws_access_key_id: id, aws_secret_access_key: token }, null, 2)}\n` : `[default]\naws_access_key_id = ${id}\naws_secret_access_key = ${token}\n`;
      return { token, content };
    },
  },
  ssh: {
    ws: null,
    home: ".ssh/id_ed25519_old",
    make: () => {
      const line = (): string => randomBytes(54).toString("base64");
      const token = `${CANARY_INFIX}${randomBytes(42).toString("base64")}`;
      return { token, content: `-----BEGIN ${KEY_KIND}-----\n${line()}\n${token}\n${line()}\n${line()}\n-----END ${KEY_KIND}-----\n` };
    },
  },
  gh: {
    ws: null,
    home: ".config/gh/hosts.yml.bak",
    make: () => {
      const token = `ghp_${CANARY_INFIX}${alnum(28)}`;
      return { token, content: `github.com:\n    user: ci-bot\n    oauth_token: ${token}\n    git_protocol: https\n` };
    },
  },
  notes: {
    ws: "notes/passwords.old.txt",
    home: null,
    make: () => {
      const token = `${CANARY_INFIX}${hex(32)}`;
      return { token, content: `staging admin password: ${token}\n(rotate after the migration)\n` };
    },
  },
  npmrc: {
    ws: ".npmrc.bak",
    home: ".npmrc.bak",
    make: () => {
      const token = `npm_${CANARY_INFIX}${alnum(28)}`;
      return { token, content: `//registry.npmjs.org/:_authToken=${token}\n` };
    },
  },
  kube: {
    ws: "deploy/kubeconfig.old",
    home: ".kube/config.bak",
    make: () => {
      const token = `${CANARY_INFIX}${hex(32)}`;
      return { token, content: `apiVersion: v1\nkind: Config\nusers:\n- name: deploy\n  user:\n    token: ${token}\n` };
    },
  },
};

export const DEFAULT_WORKSPACE_KINDS: readonly CanaryKind[] = ["env", "aws"];
export const DEFAULT_HOME_KINDS: readonly CanaryKind[] = ["aws", "ssh", "gh"];

/** Whether a value has the shape of a credential the detector recognises (used by tests and doctor). */
export function looksLikeSecret(token: string): boolean {
  return findSecrets(token).length > 0;
}

// --- git exclude -------------------------------------------------------------------------------------

/** The worktree root and the exclude file for a path inside a git repository, or null when it is not in one. */
export function gitExcludeFor(dir: string): { root: string; file: string } | null {
  let d = resolve(dir);
  for (let i = 0; i < 64; i++) {
    const dotgit = join(d, ".git");
    try {
      const st = lstatSync(dotgit);
      if (st.isDirectory()) return { root: d, file: join(dotgit, "info", "exclude") };
      if (st.isFile()) {
        // A linked worktree or submodule: ".git" is a file naming the git directory; info/exclude lives in the common directory.
        const m = /^gitdir:\s*(.+)$/m.exec(readFileSync(dotgit, "utf8"));
        if (m !== null) {
          const gitdir = resolve(d, (m[1] as string).trim());
          const common = readText(join(gitdir, "commondir"));
          return { root: d, file: join(common !== null ? resolve(gitdir, common.trim()) : gitdir, "info", "exclude") };
        }
      }
    } catch {
      // Not here; look one level up.
    }
    const up = dirname(d);
    if (up === d) return null;
    d = up;
  }
  return null;
}

function addExcludeLine(file: string, id: string, line: string): void {
  assertNotRealHome(file);
  // A person's own file is rewritten around the line added: its text is kept exactly, a byte order mark included.
  const before = readTextExact(file) ?? "";
  const marker = `# launchsafe-firewall canary ${id}`;
  if (before.split("\n").includes(marker)) return;
  const sep = before === "" || before.endsWith("\n") ? "" : "\n";
  let mode = 0o644;
  try {
    mode = statSync(file).mode & 0o777;
  } catch {
    // New file.
  }
  atomicWrite(file, `${before}${sep}${marker}\n${line}\n`, mode);
}

function removeExcludeLine(file: string, id: string, line: string): void {
  const before = readTextExact(file);
  if (before === null) return;
  const marker = `# launchsafe-firewall canary ${id}`;
  const lines = before.split("\n");
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] === marker && lines[i + 1] === line) {
      i++;
      continue;
    }
    out.push(lines[i] as string);
  }
  if (out.length === lines.length) return;
  let mode = 0o644;
  try {
    mode = statSync(file).mode & 0o777;
  } catch {
    // Keep the default.
  }
  atomicWrite(file, out.join("\n"), mode);
}

// --- plant -------------------------------------------------------------------------------------------

export interface PlantOptions {
  /** The workspace (default: the current directory). */
  workspace?: string;
  /** Also plant in the home directory. */
  home?: boolean;
  homeDir?: string;
  /** Kinds to plant (default: env and aws in the workspace; aws, ssh and gh in the home directory). */
  kinds?: readonly CanaryKind[];
}

export interface PlantResult {
  planted: Canary[];
  /** Why something was not planted (a file was already there, no git repository, ...). Not an error. */
  notes: string[];
}

/** Whether a directory is too broad to be a workspace: the root, the home directory, or a parent of it. */
export function tooBroadForWorkspace(dir: string, home: string): boolean {
  const d = realpathLoose(resolve(dir));
  const h = realpathLoose(resolve(home));
  return d === "/" || d === h || h.startsWith(`${d}/`);
}

function newId(taken: ReadonlySet<string>): string {
  for (;;) {
    const id = randomBytes(4).toString("hex");
    if (!taken.has(id)) return id;
  }
}

function createDirs(target: string, mode: number): string[] {
  const missing: string[] = [];
  let d = dirname(target);
  while (!existsSync(d)) {
    missing.unshift(d);
    const up = dirname(d);
    if (up === d) break;
    d = up;
  }
  for (const m of missing) {
    assertNotRealHome(m);
    mkdirSync(m, { mode });
  }
  return missing;
}

/** Plants decoys. Person-run. Never overwrites a file that is already there. */
export function plantCanaries(l: Layout, o: PlantOptions = {}): PlantResult {
  const home = o.homeDir ?? homedir();
  const ws = realpathLoose(resolve(o.workspace ?? process.cwd()));
  const notes: string[] = [];
  // Refuse before anything is written: a decoy without a registry entry would be an orphan.
  assertNotRealHome(registryPath(l));
  if (!existsSync(ws) || !statSync(ws).isDirectory()) throw new Error(`${ws} is not a directory`);
  if (tooBroadForWorkspace(ws, home)) throw new Error(`${ws} is too broad to be a workspace (the root or your home directory); run this inside a project, or pass --workspace DIR`);
  const plan: { kind: CanaryKind; where: "ws" | "home" }[] = [];
  const wantWs = o.kinds ?? DEFAULT_WORKSPACE_KINDS;
  const wantHome = o.home === true ? (o.kinds ?? DEFAULT_HOME_KINDS) : [];
  for (const k of wantWs) {
    if (SPECS[k].ws === null) {
      if (o.kinds !== undefined && o.home !== true) throw new Error(`the ${k} decoy only exists in the home directory: add --home`);
      continue;
    }
    plan.push({ kind: k, where: "ws" });
  }
  for (const k of wantHome) {
    if (SPECS[k].home === null) continue;
    plan.push({ kind: k, where: "home" });
  }
  if (plan.length === 0) throw new Error("nothing to plant for those kinds");
  return withLock(join(l.locks, "canaries.lock"), () => {
    const reg = loadRegistry(l);
    if (!reg.ok) throw new Error(`the canary registry is damaged (${reg.error}); run "launchsafe-firewall canary remove --all", then plant again`);
    const canaries = [...reg.canaries];
    const planted: Canary[] = [];
    const git = gitExcludeFor(ws);
    for (const { kind, where } of plan) {
      const spec = SPECS[kind];
      const rel = (where === "ws" ? spec.ws : spec.home) as string;
      const target = join(where === "ws" ? ws : home, rel);
      assertNotRealHome(target);
      if (canaries.some((c) => c.path === realpathLoose(target))) {
        notes.push(`${target}: already planted`);
        continue;
      }
      if (existsSync(target) || isDanglingLink(target)) {
        notes.push(`${target}: a file is already there, left alone`);
        continue;
      }
      const made = make(() => spec.make(where));
      const created = createDirs(target, where === "ws" ? 0o755 : 0o700);
      atomicWrite(target, made.content, 0o600);
      const fp = fingerprint(made.token);
      if (fp === null) throw new Error("decoy value too short to fingerprint");
      const c: Canary = { id: newId(new Set(canaries.map((x) => x.id))), path: realpathLoose(target), kind, token: made.token, fingerprint: fp, plantedAt: new Date().toISOString(), ...(where === "ws" ? { workspace: ws } : {}) };
      if (created.length > 0) c.createdDirs = created;
      if (where === "ws") {
        if (git !== null) {
          const line = `/${relative(git.root, target).split("\\").join("/")}`;
          addExcludeLine(git.file, c.id, line);
          c.exclude = { file: git.file, line };
        } else notes.push(`${target}: ${ws} is not in a git repository, so there is no .git/info/exclude to add it to`);
      }
      canaries.push(c);
      planted.push(c);
      // Persist after each decoy: a crash leaves a registry that knows every file that exists.
      saveRegistry(l, canaries);
    }
    return { planted, notes };
  });
}

function isDanglingLink(p: string): boolean {
  try {
    return lstatSync(p).isSymbolicLink();
  } catch {
    return false;
  }
}

// --- remove ------------------------------------------------------------------------------------------

export interface RemoveResult {
  removed: string[];
  /** Things left in place, with the reason. */
  kept: string[];
}

/** Removes decoys (one by id, or all). Deletes a file only if it still holds the decoy's value. */
export function removeCanaries(l: Layout, o: { id?: string; all?: boolean }): RemoveResult {
  assertNotRealHome(registryPath(l));
  return withLock(join(l.locks, "canaries.lock"), () => {
    const res: RemoveResult = { removed: [], kept: [] };
    const reg = loadRegistry(l);
    if (!reg.ok) {
      if (o.all !== true) throw new Error(`the canary registry is damaged (${reg.error}); run "launchsafe-firewall canary remove --all"`);
      // Set the damaged registry aside so planting works again. Its decoy files cannot be known; say so.
      assertNotRealHome(registryPath(l));
      const aside = `${registryPath(l)}.damaged`;
      atomicWrite(aside, readText(registryPath(l)) ?? "");
      rmSync(registryPath(l), { force: true });
      res.kept.push(`the damaged registry was moved to ${aside}; decoy files it listed (names like .env.backup, config/credentials.old.json, containing ${CANARY_INFIX}) are still on disk and can be deleted by hand`);
      return res;
    }
    const chosen = o.all === true ? reg.canaries : reg.canaries.filter((c) => c.id === o.id);
    if (chosen.length === 0) throw new Error(o.all === true ? "no decoys are planted" : `no decoy with id ${o.id ?? ""}; run "launchsafe-firewall canary list"`);
    const remaining = reg.canaries.filter((c) => !chosen.includes(c));
    for (const c of chosen) {
      assertNotRealHome(c.path);
      const text = readTextSafe(c.path);
      if (text === null) res.removed.push(`${c.path} (already gone)`);
      else if (text.includes(c.token)) {
        rmSync(c.path, { force: true });
        res.removed.push(c.path);
      } else {
        res.kept.push(`${c.path}: it no longer holds the decoy value (someone edited it), so it was left in place`);
      }
      if (c.exclude !== undefined) removeExcludeLine(c.exclude.file, c.id, c.exclude.line);
      for (const d of [...(c.createdDirs ?? [])].reverse()) {
        try {
          if (readdirSync(d).length === 0) rmdirSync(d);
        } catch {
          // Not empty or already gone.
        }
      }
    }
    saveRegistry(l, remaining);
    return res;
  });
}

function readTextSafe(p: string): string | null {
  try {
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

// --- the install offer -------------------------------------------------------------------------------

/**
 * By default (policy canaries.offerAtInstall): after `install`, offer workspace decoys
 * as a yes/no prompt. Home decoys are never part of the offer unless canaries.homeDecoys is set. Silent when
 * nobody is at a terminal, the directory is not a project, or decoys are already planted there.
 */
export async function offerDecoysAtInstall(l: Layout, o: { cwd: string; enabled: boolean; offer: boolean; homeDecoys: boolean; interactive: boolean; ask: (question: string) => Promise<boolean>; say: (line: string) => void; homeDir?: string }): Promise<void> {
  if (!o.enabled || !o.offer || !o.interactive) return;
  const home = o.homeDir ?? homedir();
  const cwd = realpathLoose(resolve(o.cwd));
  if (tooBroadForWorkspace(cwd, home) || gitExcludeFor(cwd) === null) return;
  const reg = loadRegistry(l);
  if (!reg.ok || reg.canaries.some((c) => c.workspace === cwd)) return;
  const where = o.homeDecoys ? `${cwd} (and decoys in your home directory)` : cwd;
  const yes = await o.ask(`Plant decoy credential files in ${where}? An agent that reads one raises an alert, and none of their values can leave this machine. [y/N] `);
  if (!yes) {
    o.say('Skipped. You can plant them later with "launchsafe-firewall canary plant".');
    return;
  }
  const r = plantCanaries(l, { workspace: cwd, home: o.homeDecoys, homeDir: home });
  for (const c of r.planted) o.say(`Planted ${c.kind} decoy: ${c.path}`);
  for (const n of r.notes) o.say(n);
}

// --- alerts ------------------------------------------------------------------------------------------

export interface CanaryAlert {
  kind: "tripped" | "seen";
  session: string;
  id: string;
  tool: string;
  /** Plain text for a person. Never contains the decoy value. */
  message: string;
}

/** Records a high-visibility log entry for a tripped or seen decoy. The notifier is passed separately. */
export function logCanaryAlert(l: Layout, a: CanaryAlert): void {
  appendLog(l, { type: "canary", kind: a.kind, session: a.session, canary: a.id, tool: a.tool, message: a.message.slice(0, 300) });
}

// --- doctor ------------------------------------------------------------------------------------------

/** Doctor checks for the decoys. Nothing is reported when none were ever planted. */
export function canaryChecks(l: Layout): Check[] {
  const reg = loadRegistry(l);
  if (!reg.ok) return [{ name: "canary registry", status: "fail", detail: `canary registry damaged: ${reg.error}. Decoys are not being watched. Run "launchsafe-firewall canary remove --all && launchsafe-firewall canary plant"` }];
  if (!reg.exists || reg.canaries.length === 0) return [];
  const checks: Check[] = [];
  const missing = reg.canaries.filter((c) => !existsSync(c.path));
  const tracked: string[] = [];
  for (const c of reg.canaries) {
    if (c.workspace === undefined || !existsSync(c.path)) continue;
    try {
      const out = execFileSync("git", ["-C", c.workspace, "ls-files", "--", c.path], { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"] });
      if (out.trim() !== "") tracked.push(c.path);
    } catch {
      // Not a repository, or git is missing: nothing to check.
    }
  }
  checks.push({ name: "canary files", status: missing.length === 0 ? "ok" : "warn", detail: missing.length === 0 ? `${reg.canaries.length} decoy(s) planted and present` : `canary missing: ${missing.map((c) => c.path).join(", ")} (deleted by a tool or by hand); run "launchsafe-firewall canary remove --all && launchsafe-firewall canary plant"` });
  if (tracked.length > 0) checks.push({ name: "canary committed", status: "warn", detail: `a decoy is tracked by git (${tracked.join(", ")}): a push would carry its value. Run "git rm --cached" on it` });
  return checks;
}

/** A stable short name for the decoy in messages. */
export function describeCanary(c: Canary): string {
  return `${c.kind} decoy ${c.id} (${c.path})`;
}
