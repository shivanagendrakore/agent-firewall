/**
 * A vector's `setup` (conformance/README.md, "The prepared environment"): files, decoys and policy put in a
 * fresh temporary tree before the steps run. The library runner (run.ts) and the sidecar runner
 * (test/api/conformance-sidecar.test.ts) both prepare it here, so they start from the same tree.
 *
 * The tree, under one new temporary directory (its realpath):
 *   workspace/   the agent's project (`{{workspace}}` in the vector)
 *   home/        the agent's home directory (`{{home}}`)
 *   firewall/    the firewall home: policy.json (setup.policy and setup.budgets), canaries.json (setup.decoys),
 *                intel/ (setup.packages: the malicious-package snapshot `launchsafe-firewall update` writes)
 *
 * `{{workspace}}` and `{{home}}` in file contents, the policy and every request string are replaced by those paths.
 * Everything in a vector is data: file contents are written, never run, and every path is checked to stay
 * inside workspace/ or home/ before anything is written.
 */

import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { ECOSYSTEMS, ecoDir, normalizeName, type Ecosystem, type IntelEntry } from "../src/engine/packages.js";
import { INTEL_FORMAT, intelDir, writeEcosystem } from "../src/runtime/intel.js";
import { layout, type Layout } from "../src/runtime/layout.js";

/** One decoy, as `canary plant` registers it, with the value fixed by the vector so the steps can name it. */
export interface SetupDecoy {
  /** [a-z0-9]{1,32}. */
  id: string;
  /** `workspace/...` or `home/...`. */
  path: string;
  kind: "env" | "aws" | "ssh" | "gh" | "notes" | "npmrc" | "kube";
  /** The decoy's value: contains LSCANARY. */
  token: string;
  /** The engine's fingerprint of `token` (src/engine/secrets.ts fingerprint()), recorded by the author kit. */
  fingerprint: string;
}

export interface Setup {
  /** `workspace/<path>` or `home/<path>` to the file's text. */
  files?: Record<string, string>;
  decoys?: SetupDecoy[];
  /** The user's policy file (docs/policy.md), written as is to the firewall home's policy.json. */
  policy?: Record<string, unknown>;
  /** The policy's `budgets` key (docs/policy.md), merged into policy.json. */
  budgets?: Record<string, unknown>;
  /** The malicious-package snapshot: ecosystem (npm, PyPI, ...) to package name to its entry. Only the ecosystems named are covered. */
  packages?: Record<string, Record<string, SetupPackage>>;
}

/** A package listed as malicious (the snapshot's entry; missing lists are empty, `all` defaults to false). */
export interface SetupPackage {
  all?: boolean;
  versions?: string[];
  ranges?: { introduced?: string; fixed?: string; last_affected?: string }[];
  ids?: string[];
}

export interface Prepared {
  root: string;
  workspace: string;
  home: string;
  firewallHome: string;
  l: Layout;
}

/** Fixed: the time a decoy was planted (no clock in the tree). */
const PLANTED_AT = "2026-10-12T11:00:00.000Z";
const AREAS = ["workspace", "home"] as const;
const SETUP_KEYS = ["files", "decoys", "policy", "budgets", "packages"];
/** The snapshot generation directory the runner writes (any g-* name is valid). */
const INTEL_GENERATION = "g-conformance";
const DECOY_KEYS = ["id", "path", "kind", "token", "fingerprint"];

/** The absolute path of a `workspace/...` or `home/...` path in the tree; throws on anything that would leave it. */
export function treePath(p: Prepared, rel: string): string {
  const [area, ...rest] = rel.split("/");
  if (!(AREAS as readonly string[]).includes(area ?? "") || rest.length === 0 || rest.some((s) => s === "" || s === "." || s === "..") || rel.includes("\\") || rel.includes("\u0000")) {
    throw new Error(`setup path ${JSON.stringify(rel)} must be workspace/<path> or home/<path> with no empty, "." or ".." segments`);
  }
  const base = area === "workspace" ? p.workspace : p.home;
  const abs = resolve(base, ...rest);
  const r = relative(base, abs);
  if (r === "" || r.startsWith("..") || r.startsWith(sep)) throw new Error(`setup path ${JSON.stringify(rel)} leaves the tree`);
  return abs;
}

function writeInside(p: Prepared, rel: string, text: string): string {
  const abs = treePath(p, rel);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, text, { mode: 0o600 });
  return abs;
}

/** Throws unless `s` is a well-formed setup object (unknown keys included). */
export function checkSetup(s: unknown): asserts s is Setup {
  if (typeof s !== "object" || s === null || Array.isArray(s)) throw new Error("setup must be an object");
  const o = s as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!SETUP_KEYS.includes(k)) throw new Error(`setup.${k} is not a setup key`);
  if (o.files !== undefined) {
    if (typeof o.files !== "object" || o.files === null || Array.isArray(o.files)) throw new Error("setup.files must be an object");
    for (const v of Object.values(o.files)) if (typeof v !== "string") throw new Error("setup.files values are text");
  }
  if (o.decoys !== undefined) {
    if (!Array.isArray(o.decoys)) throw new Error("setup.decoys must be a list");
    for (const d of o.decoys as unknown[]) {
      if (typeof d !== "object" || d === null) throw new Error("a decoy must be an object");
      const e = d as Record<string, unknown>;
      for (const k of Object.keys(e)) if (!DECOY_KEYS.includes(k)) throw new Error(`decoy.${k} is not a decoy key`);
      if (typeof e.id !== "string" || !/^[a-z0-9]{1,32}$/.test(e.id)) throw new Error("decoy.id must be [a-z0-9]{1,32}");
      if (typeof e.path !== "string" || typeof e.kind !== "string" || typeof e.token !== "string" || !e.token.includes("LSCANARY") || typeof e.fingerprint !== "string") throw new Error(`decoy ${String(e.id)} is malformed`);
    }
  }
  if (o.packages !== undefined) {
    if (typeof o.packages !== "object" || o.packages === null || Array.isArray(o.packages)) throw new Error("setup.packages must be an object");
    for (const eco of Object.keys(o.packages)) if (!(ECOSYSTEMS as readonly string[]).includes(eco)) throw new Error(`setup.packages.${eco} is not an ecosystem (${ECOSYSTEMS.join(", ")})`);
  }
  for (const k of ["policy", "budgets"] as const) {
    const v = o[k];
    if (v !== undefined && (typeof v !== "object" || v === null || Array.isArray(v))) throw new Error(`setup.${k} must be an object`);
  }
  if (o.budgets !== undefined && o.policy !== undefined && "budgets" in (o.policy as object)) throw new Error("give budgets in setup.budgets or in setup.policy, not both");
}

/** Makes the tree and applies the setup. Call `dispose` when done. */
export function prepare(setup: Setup): Prepared {
  checkSetup(setup);
  const root = realpathSync(mkdtempSync(join(tmpdir(), "lsfw-conf-")));
  const p: Prepared = { root, workspace: join(root, "workspace"), home: join(root, "home"), firewallHome: join(root, "firewall"), l: layout(join(root, "firewall")) };
  try {
    for (const d of [p.workspace, p.home, p.firewallHome]) mkdirSync(d, { recursive: true, mode: 0o700 });
    for (const [rel, text] of Object.entries(setup.files ?? {})) writeInside(p, rel, substitute(text, p));
    const decoys = (setup.decoys ?? []).map((d) => {
      const abs = treePath(p, d.path);
      // A decoy file not named in `files` holds just its value.
      if (setup.files?.[d.path] === undefined) writeInside(p, d.path, `${d.token}\n`);
      return { id: d.id, path: abs, kind: d.kind, token: d.token, fingerprint: d.fingerprint, plantedAt: PLANTED_AT, ...(d.path.startsWith("workspace/") ? { workspace: p.workspace } : {}) };
    });
    if (decoys.length > 0) writeFileSync(join(p.firewallHome, "canaries.json"), `${JSON.stringify({ version: 1, canaries: decoys }, null, 2)}\n`, { mode: 0o600 });
    if (setup.policy !== undefined || setup.budgets !== undefined) {
      const doc = substitute({ ...(setup.policy ?? { version: 3 }), ...(setup.budgets !== undefined ? { budgets: setup.budgets } : {}) }, p);
      writeFileSync(p.l.policy, `${JSON.stringify(doc, null, 2)}\n`, { mode: 0o600 });
    }
    if (setup.packages !== undefined) writeSnapshot(p, setup.packages);
  } catch (e) {
    dispose(p);
    throw e;
  }
  return p;
}

/** The snapshot as `update` writes it, fetched at the reference clock so it is never stale. */
function writeSnapshot(p: Prepared, packages: NonNullable<Setup["packages"]>): void {
  const sources = Object.entries(packages).map(([e, names]) => {
    const eco = e as Ecosystem;
    const map = new Map<string, IntelEntry>();
    for (const [name, x] of Object.entries(names)) map.set(normalizeName(eco, name), { all: x.all ?? false, versions: x.versions ?? [], ranges: x.ranges ?? [], ids: x.ids ?? [] });
    const buckets = writeEcosystem(join(intelDir(p.firewallHome), INTEL_GENERATION, ecoDir(eco)), map);
    return { eco, url: "conformance:setup", sha256: "", entries: map.size, buckets };
  });
  writeFileSync(join(intelDir(p.firewallHome), "manifest.json"), `${JSON.stringify({ format: INTEL_FORMAT, fetchedAt: "2026-10-12T12:00:00.000Z", dir: INTEL_GENERATION, sources }, null, 2)}\n`, { mode: 0o600 });
}

/** Removes the tree (only the directory prepare() created). */
export function dispose(p: Prepared): void {
  if (!p.root.includes("lsfw-conf-")) throw new Error(`refusing to remove ${p.root}`);
  rmSync(p.root, { recursive: true, force: true });
}

const TOKENS = /\{\{(workspace|home)\}\}/g;

/** The value with `{{workspace}}` and `{{home}}` replaced by the tree's paths, in every string at any depth. */
export function substitute<T>(v: T, p: Prepared): T {
  if (typeof v === "string") return v.replace(TOKENS, (_, k: string) => (k === "workspace" ? p.workspace : p.home)) as T;
  if (Array.isArray(v)) return v.map((x: unknown) => substitute(x, p)) as T;
  if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, substitute(x, p)])) as T;
  return v;
}
