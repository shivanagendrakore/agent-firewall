/**
 * The malicious-package snapshot: built by the person-run `update`
 * command from OSV's per-ecosystem bulk exports (only MAL- entries, the
 * OpenSSF malicious-packages feed), read by the hook one small bucket file at
 * a time. `update` is the only command that downloads data (decisions make no
 * network calls unless a phone is paired, which is experimental; `run` is a
 * network proxy); the package check only ever reads these local files.
 *
 * Layout under the firewall's state directory (covered by FW-TAMPER):
 *   intel/manifest.json            { format, fetchedAt, dir, sources: [{eco, url, sha256, entries, buckets}] }
 *   intel/<dir>/<eco>/<xx>.json    { name: {all, versions, ranges, ids} } for names whose sha256 starts with xx
 *                                  (only non-empty buckets are written; the manifest lists them, so a listed
 *                                  bucket that is missing is damage, not "clean")
 *   intel/<dir>/<eco>/names.idx    sorted 8-byte sha256 prefixes of every listed name (lockfile scans)
 * A new snapshot is built in a fresh generation directory and switched to by
 * replacing the manifest atomically, so an interrupted update leaves the
 * previous snapshot in force.
 */

import { createHash, randomBytes } from "node:crypto";
import { closeSync, cpSync, createWriteStream, existsSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { pathToFileURL } from "node:url";
import { ECOSYSTEMS, ecoDir, normalizeName, type Ecosystem, type IntelAnswer, type IntelEntry, type IntelRange, type PackageIntel } from "../engine/packages.js";
import { atomicWrite, ensureDir } from "./fsutil.js";
import { assertNotRealHome } from "./guard.js";
import { forEachEntry } from "./zip.js";
import { own, setOwn } from "../own.js";

export const INTEL_FORMAT = 1;
/** OSV's public bulk exports: <base>/<ecosystem>/all.zip [verify size per ecosystem before each release]. */
export const OSV_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com";
const BUCKETS = 256;
const MAX_VERSIONS = 5000;
const MAX_RANGES = 200;
const MAX_IDS = 50;
/** Largest download accepted per ecosystem. */
export const MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024 * 1024;

export interface ManifestSource {
  eco: Ecosystem;
  url: string;
  sha256: string;
  entries: number;
  /** The bucket files written (two hex digits each); a name in any other bucket is not listed. */
  buckets: string[];
}

export interface Manifest {
  format: number;
  fetchedAt: string;
  dir: string;
  sources: ManifestSource[];
}

export function intelDir(firewallHome: string): string {
  return join(firewallHome, "intel");
}

export class IntelDamaged extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IntelDamaged";
  }
}

/** The manifest, null when there is no snapshot; throws IntelDamaged when it cannot be trusted. */
export function readManifest(firewallHome: string): Manifest | null {
  const p = join(intelDir(firewallHome), "manifest.json");
  let text: string;
  try {
    text = readFileSync(p, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new IntelDamaged(`${p}: ${(e as Error).message}`);
  }
  let m: unknown;
  try {
    m = JSON.parse(text);
  } catch {
    throw new IntelDamaged(`${p} is not valid JSON`);
  }
  const o = m as Partial<Manifest>;
  if (typeof o !== "object" || o === null || o.format !== INTEL_FORMAT || typeof o.fetchedAt !== "string" || Number.isNaN(Date.parse(o.fetchedAt)) || typeof o.dir !== "string" || !/^g-[A-Za-z0-9-]+$/.test(o.dir) || !Array.isArray(o.sources)) {
    throw new IntelDamaged(`${p} is not a snapshot manifest this version understands`);
  }
  for (const s of o.sources) {
    if (typeof s !== "object" || s === null || !ECOSYSTEMS.includes(s.eco) || typeof s.url !== "string" || typeof s.sha256 !== "string" || typeof s.entries !== "number" || !Array.isArray(s.buckets) || !s.buckets.every((b) => typeof b === "string" && /^[0-9a-f]{2}$/.test(b))) throw new IntelDamaged(`${p} lists a malformed source`);
  }
  return o as Manifest;
}

/** The hash both the bucket (first byte, as two hex digits) and the name index (first 8 bytes) use. */
function nameHash(normalized: string): Buffer {
  return createHash("sha256").update(normalized, "utf8").digest();
}

function bucketOf(h: Buffer): string {
  return h.subarray(0, 1).toString("hex");
}

function validEntry(v: unknown): v is IntelEntry {
  if (typeof v !== "object" || v === null) return false;
  const e = v as Record<string, unknown>;
  const strings = (x: unknown): boolean => Array.isArray(x) && x.every((s) => typeof s === "string");
  return typeof e.all === "boolean" && strings(e.versions) && strings(e.ids) && Array.isArray(e.ranges) && e.ranges.every((r) => typeof r === "object" && r !== null && Object.entries(r as Record<string, unknown>).every(([k, x]) => (k === "introduced" || k === "fixed" || k === "last_affected") && typeof x === "string"));
}

function parseBucket(text: string, file: string): Record<string, IntelEntry> {
  let o: unknown;
  try {
    o = JSON.parse(text);
  } catch {
    throw new IntelDamaged(`${file} is not valid JSON`);
  }
  if (typeof o !== "object" || o === null || Array.isArray(o)) throw new IntelDamaged(`${file} is not a bucket`);
  return o as Record<string, IntelEntry>;
}

/**
 * The hook's view of the snapshot. Nothing is read until an install asks: the manifest on the first
 * lookup, then one bucket per looked-up name (and the name index for a lockfile scan).
 */
export function openIntel(firewallHome: string): PackageIntel {
  let loaded = false;
  let manifest: Manifest | null = null;
  let damaged: string | null = null;
  const buckets = new Map<string, Record<string, IntelEntry> | IntelDamaged>();
  const indexes = new Map<Ecosystem, Buffer | IntelDamaged>();
  const bucketSets = new Map<Ecosystem, Set<string>>();
  const load = (): void => {
    if (loaded) return;
    loaded = true;
    try {
      manifest = readManifest(firewallHome);
      for (const s of manifest?.sources ?? []) bucketSets.set(s.eco, new Set(s.buckets));
    } catch (e) {
      damaged = (e as Error).message;
    }
  };
  const covers = (eco: Ecosystem): boolean => {
    load();
    return manifest !== null && (manifest as Manifest).sources.some((s) => s.eco === eco);
  };
  const ecoPath = (eco: Ecosystem): string => join(intelDir(firewallHome), (manifest as Manifest).dir, ecoDir(eco));
  const lookup = (eco: Ecosystem, name: string): IntelAnswer => {
    load();
    if (damaged !== null) return { kind: "damaged", detail: damaged };
    if (!covers(eco)) return { kind: "none" };
    const n = normalizeName(eco, name);
    const bucket = bucketOf(nameHash(n));
    if (!bucketSets.get(eco)?.has(bucket)) return { kind: "clean" };
    const file = join(ecoPath(eco), `${bucket}.json`);
    let b = buckets.get(file);
    if (b === undefined) {
      try {
        b = parseBucket(readFileSync(file, "utf8"), file);
      } catch (e) {
        b = e instanceof IntelDamaged ? e : new IntelDamaged(`${file}: ${(e as Error).message}`);
      }
      buckets.set(file, b);
    }
    if (b instanceof IntelDamaged) return { kind: "damaged", detail: b.message };
    const entry = own(b, n);
    if (entry === undefined) return { kind: "clean" };
    if (!validEntry(entry)) return { kind: "damaged", detail: `the entry for ${n} in ${file} is malformed` };
    return { kind: "listed", entry };
  };
  const index = (eco: Ecosystem): Buffer | IntelDamaged => {
    let ix = indexes.get(eco);
    if (ix === undefined) {
      const file = join(ecoPath(eco), "names.idx");
      try {
        const b = readFileSync(file);
        ix = b.length % 8 === 0 ? b : new IntelDamaged(`${file} has a partial record`);
      } catch (e) {
        ix = new IntelDamaged(`${file}: ${(e as Error).message}`);
      }
      indexes.set(eco, ix);
    }
    return ix;
  };
  return {
    covers,
    lookup,
    lookupMany(eco, names) {
      const out = new Map<string, IntelAnswer>();
      load();
      if (damaged !== null) {
        for (const n of names) out.set(n, { kind: "damaged", detail: damaged });
        return out;
      }
      if (!covers(eco)) return out;
      const ix = index(eco);
      if (ix instanceof IntelDamaged) {
        for (const n of names) out.set(n, { kind: "damaged", detail: ix.message });
        return out;
      }
      const count = ix.length / 8;
      for (const n of names) {
        const key = nameHash(normalizeName(eco, n)).subarray(0, 8);
        let lo = 0;
        let hi = count - 1;
        let hit = false;
        while (lo <= hi) {
          const mid = (lo + hi) >>> 1;
          const c = key.compare(ix, mid * 8, mid * 8 + 8);
          if (c === 0) {
            hit = true;
            break;
          }
          if (c < 0) hi = mid - 1;
          else lo = mid + 1;
        }
        if (hit) out.set(n, lookup(eco, n));
      }
      return out;
    },
    fetchedAt() {
      load();
      return manifest === null ? undefined : (manifest as Manifest).fetchedAt;
    },
  };
}

// --- building a snapshot ------------------------------------------------------------------------------------

interface OsvAffected {
  package?: { ecosystem?: unknown; name?: unknown };
  versions?: unknown;
  ranges?: unknown;
}

/** The MAL- entries of one OSV record for one ecosystem: (normalized name, entry) pairs. */
export function entriesFromOsv(record: unknown, eco: Ecosystem): { name: string; entry: IntelEntry }[] {
  if (typeof record !== "object" || record === null) return [];
  const r = record as { id?: unknown; withdrawn?: unknown; affected?: unknown };
  if (typeof r.id !== "string" || !r.id.startsWith("MAL-") || r.withdrawn !== undefined || !Array.isArray(r.affected)) return [];
  const out: { name: string; entry: IntelEntry }[] = [];
  for (const a of r.affected as OsvAffected[]) {
    if (typeof a !== "object" || a === null || typeof a.package?.name !== "string" || typeof a.package.ecosystem !== "string") continue;
    if (a.package.ecosystem.toLowerCase() !== eco.toLowerCase()) continue;
    const allVersions = Array.isArray(a.versions) ? (a.versions as unknown[]).filter((v): v is string => typeof v === "string") : [];
    const versions = allVersions.slice(0, MAX_VERSIONS);
    const ranges: IntelRange[] = [];
    // A list cut at the cap would leave the versions past it unflagged: such a package is condemned whole instead.
    let all = allVersions.length > MAX_VERSIONS;
    if (Array.isArray(a.ranges)) {
      for (const rg of a.ranges as { type?: unknown; events?: unknown }[]) {
        if (typeof rg !== "object" || rg === null || rg.type === "GIT" || !Array.isArray(rg.events)) continue;
        let intro: string | undefined;
        let open = false;
        for (const ev of rg.events as Record<string, unknown>[]) {
          if (typeof ev !== "object" || ev === null) continue;
          if (typeof ev.introduced === "string") {
            if (open) ranges.push(intro === undefined ? {} : { introduced: intro });
            intro = ev.introduced;
            open = true;
          } else if (typeof ev.fixed === "string") {
            ranges.push({ ...(intro !== undefined ? { introduced: intro } : {}), fixed: ev.fixed });
            open = false;
            intro = undefined;
          } else if (typeof ev.last_affected === "string") {
            ranges.push({ ...(intro !== undefined ? { introduced: intro } : {}), last_affected: ev.last_affected });
            open = false;
            intro = undefined;
          }
        }
        if (open) {
          if (intro === undefined || intro === "0") all = true;
          else ranges.push({ introduced: intro });
        }
      }
    }
    // An entry that names a package but no versions or ranges condemns the whole package.
    if (versions.length === 0 && ranges.length === 0) all = true;
    if (ranges.length > MAX_RANGES) all = true;
    out.push({ name: normalizeName(eco, a.package.name), entry: { all, versions, ranges: ranges.slice(0, MAX_RANGES), ids: [r.id] } });
  }
  return out;
}

function merge(into: Map<string, IntelEntry>, name: string, e: IntelEntry): void {
  const cur = into.get(name);
  if (cur === undefined) {
    into.set(name, { all: e.all, versions: [...e.versions], ranges: [...e.ranges], ids: [...e.ids] });
    return;
  }
  cur.all = cur.all || e.all;
  for (const v of e.versions) {
    if (cur.versions.includes(v)) continue;
    if (cur.versions.length < MAX_VERSIONS) cur.versions.push(v);
    else cur.all = true;
  }
  for (const r of e.ranges) {
    if (cur.ranges.length < MAX_RANGES) cur.ranges.push(r);
    else cur.all = true;
  }
  for (const i of e.ids) if (cur.ids.length < MAX_IDS && !cur.ids.includes(i)) cur.ids.push(i);
}

/** Reads the MAL- records of one ecosystem's export into a name map. */
export function indexOsvZip(zipPath: string, eco: Ecosystem): Map<string, IntelEntry> {
  const map = new Map<string, IntelEntry>();
  forEachEntry(
    zipPath,
    (name) => /(?:^|\/)MAL-[^/]*\.json$/.test(name),
    (_name, data) => {
      let rec: unknown;
      try {
        rec = JSON.parse(data.toString("utf8"));
      } catch {
        return; // One unreadable record is skipped; the archive itself was intact (sizes and CRC checked).
      }
      for (const { name, entry } of entriesFromOsv(rec, eco)) merge(map, name, entry);
    },
  );
  return map;
}

/** Writes one ecosystem's non-empty buckets and its name index; returns the buckets written. */
export function writeEcosystem(dir: string, map: Map<string, IntelEntry>): string[] {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const buckets: Record<string, IntelEntry>[] = Array.from({ length: BUCKETS }, () => ({}));
  const keys: Buffer[] = [];
  for (const [name, entry] of map) {
    const h = nameHash(name);
    setOwn(buckets[h[0] as number] as Record<string, IntelEntry>, name, entry);
    keys.push(h.subarray(0, 8));
  }
  const written: string[] = [];
  for (let i = 0; i < BUCKETS; i++) {
    const b = buckets[i] as Record<string, IntelEntry>;
    if (Object.keys(b).length === 0) continue;
    const hex = i.toString(16).padStart(2, "0");
    writeFileSync(join(dir, `${hex}.json`), JSON.stringify(b), { mode: 0o600 });
    written.push(hex);
  }
  keys.sort(Buffer.compare);
  writeFileSync(join(dir, "names.idx"), Buffer.concat(keys), { mode: 0o600 });
  return written;
}

function sha256File(path: string): string {
  const h = createHash("sha256");
  const fd = openSync(path, "r");
  try {
    const buf = Buffer.alloc(1024 * 1024);
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n <= 0) break;
      h.update(buf.subarray(0, n));
    }
  } finally {
    closeSync(fd);
  }
  return h.digest("hex");
}

export interface UpdateOptions {
  /** A base URL (https://..., http://127.0.0.1:... in tests) or a local directory holding <Ecosystem>/all.zip. Default: OSV. */
  source?: string;
  ecosystems?: readonly Ecosystem[];
  fetchImpl?: typeof fetch;
  now?: () => Date;
  /** Progress lines for the person running it. */
  log?: (line: string) => void;
  maxBytes?: number;
  /** Per-download timeout in milliseconds. */
  timeoutMs?: number;
}

export interface UpdateResult {
  manifest: Manifest;
  path: string;
}

async function download(url: string, dest: string, o: UpdateOptions): Promise<void> {
  const res = await (o.fetchImpl ?? fetch)(url, { signal: AbortSignal.timeout(o.timeoutMs ?? 30 * 60_000), redirect: "follow" });
  if (!res.ok || res.body === null) throw new Error(`${url}: HTTP ${res.status}`);
  const max = o.maxBytes ?? MAX_DOWNLOAD_BYTES;
  const declared = Number(res.headers.get("content-length") ?? Number.NaN);
  if (Number.isFinite(declared) && declared > max) throw new Error(`${url} is ${declared} bytes, more than the ${max} accepted`);
  let seen = 0;
  const cap = new Transform({
    transform(chunk: Buffer, _enc, cb) {
      seen += chunk.length;
      if (seen > max) cb(new Error(`${url} is larger than the ${max} bytes accepted`));
      else cb(null, chunk);
    },
  });
  await pipeline(Readable.fromWeb(res.body as import("node:stream/web").ReadableStream<Uint8Array>), cap, createWriteStream(dest, { mode: 0o600 }));
  if (Number.isFinite(declared) && seen !== declared) throw new Error(`${url}: the download stopped after ${seen} of ${declared} bytes`);
}

/**
 * `launchsafe-firewall update`: fetch each ecosystem's export, keep the MAL- entries, build a new
 * generation and switch the manifest to it. All or nothing: any failure leaves the previous snapshot.
 */
export async function runUpdate(firewallHome: string, o: UpdateOptions = {}): Promise<UpdateResult> {
  const base = intelDir(firewallHome);
  assertNotRealHome(base);
  ensureDir(base);
  const log = o.log ?? ((): void => undefined);
  const ecos = o.ecosystems ?? ECOSYSTEMS;
  const source = o.source ?? OSV_BASE_URL;
  const remote = /^https?:\/\//i.test(source);
  const stamp = (o.now ?? (() => new Date()))();
  const gen = `g-${stamp.toISOString().replace(/[^0-9]/g, "").slice(0, 14)}-${randomBytes(4).toString("hex")}`;
  const work = join(base, `tmp-${process.pid}-${randomBytes(4).toString("hex")}`);
  mkdirSync(join(work, gen), { recursive: true, mode: 0o700 });
  try {
    const sources: ManifestSource[] = [];
    for (const eco of ecos) {
      let zip: string;
      let url: string;
      if (remote) {
        url = `${source.replace(/\/+$/, "")}/${encodeURIComponent(eco)}/all.zip`;
        zip = join(work, `${ecoDir(eco)}.zip`);
        log(`Downloading ${url} ...`);
        await download(url, zip, o);
      } else {
        zip = join(source, eco, "all.zip");
        if (!existsSync(zip)) throw new Error(`${zip} does not exist`);
        url = pathToFileURL(zip).href;
      }
      const sha256 = sha256File(zip);
      const map = indexOsvZip(zip, eco);
      const buckets = writeEcosystem(join(work, gen, ecoDir(eco)), map);
      if (remote) rmSync(zip, { force: true });
      sources.push({ eco, url, sha256, entries: map.size, buckets });
      log(`${eco}: ${map.size} package name(s) listed as malicious`);
    }
    // A partial update (--ecosystem) keeps the other ecosystems of the snapshot in force: their data and sources are carried into the new generation.
    if (o.ecosystems !== undefined) {
      let previous: Manifest | null = null;
      try {
        previous = readManifest(firewallHome);
      } catch {
        // A damaged manifest cannot be carried over; the update below replaces it with the ecosystems asked for.
      }
      for (const prev of previous?.sources ?? []) {
        if (ecos.includes(prev.eco)) continue;
        const from = join(base, previous?.dir ?? "", ecoDir(prev.eco));
        if (!existsSync(from)) throw new Error(`the current snapshot's ${prev.eco} data is missing (${from}), so a partial update would drop it. Run: launchsafe-firewall update`);
        cpSync(from, join(work, gen, ecoDir(prev.eco)), { recursive: true });
        sources.push(prev);
      }
    }
    renameSync(join(work, gen), join(base, gen));
    const manifest: Manifest = { format: INTEL_FORMAT, fetchedAt: stamp.toISOString(), dir: gen, sources };
    atomicWrite(join(base, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
    pruneGenerations(base);
    return { manifest, path: join(base, "manifest.json") };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

/** Keeps the generation the manifest names and the one before it (a hook may still be reading it). */
function pruneGenerations(base: string): void {
  let current: string | null = null;
  try {
    current = readManifest(join(base, ".."))?.dir ?? null;
  } catch {
    return;
  }
  const gens = readdirSync(base)
    .filter((d) => /^g-/.test(d))
    .map((d) => ({ d, t: statSync(join(base, d)).mtimeMs }))
    .sort((a, b) => b.t - a.t);
  let keptPrevious = false;
  for (const { d } of gens) {
    if (d === current) continue;
    if (!keptPrevious) {
      keptPrevious = true;
      continue;
    }
    rmSync(join(base, d), { recursive: true, force: true });
  }
}

// --- checking a snapshot (doctor, status) ----------------------------------------------------------------------

export interface IntelInspection {
  state: "none" | "ok" | "damaged";
  manifest?: Manifest;
  ageDays?: number;
  problems: string[];
}

/** Reads every file of the snapshot: what `doctor` reports. */
export function inspectIntel(firewallHome: string, now: Date = new Date()): IntelInspection {
  let m: Manifest | null;
  try {
    m = readManifest(firewallHome);
  } catch (e) {
    return { state: "damaged", problems: [(e as Error).message] };
  }
  if (m === null) return { state: "none", problems: [] };
  const ageDays = Math.max(0, Math.floor((now.getTime() - Date.parse(m.fetchedAt)) / 86_400_000));
  const problems: string[] = [];
  for (const s of m.sources) {
    const dir = join(intelDir(firewallHome), m.dir, ecoDir(s.eco));
    let names = 0;
    for (const hex of s.buckets) {
      const f = join(dir, `${hex}.json`);
      try {
        const b = parseBucket(readFileSync(f, "utf8"), f);
        for (const [k, v] of Object.entries(b)) {
          if (!validEntry(v)) throw new IntelDamaged(`${f}: the entry for ${k} is malformed`);
          names++;
        }
      } catch (e) {
        problems.push((e as Error).message.replace(/^ENOENT: [^,]*, open /, "missing "));
        if (problems.length > 5) break;
      }
    }
    try {
      const ix = readFileSync(join(dir, "names.idx"));
      if (ix.length % 8 !== 0 || ix.length / 8 !== names) problems.push(`${join(dir, "names.idx")} does not match the buckets`);
    } catch (e) {
      problems.push(`${join(dir, "names.idx")}: ${(e as Error).message}`);
    }
    if (problems.length === 0 && names !== s.entries) problems.push(`${s.eco}: ${names} names on disk, the manifest says ${s.entries}`);
  }
  return { state: problems.length > 0 ? "damaged" : "ok", manifest: m, ageDays, problems };
}

/** Age of the snapshot in whole days, null without one (cheap: the manifest only). */
export function snapshotAgeDays(firewallHome: string, now: Date = new Date()): number | null {
  try {
    const m = readManifest(firewallHome);
    return m === null ? null : Math.max(0, Math.floor((now.getTime() - Date.parse(m.fetchedAt)) / 86_400_000));
  } catch {
    return null;
  }
}
