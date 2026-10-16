/**
 * Fixtures for the package-vetting tests: a tiny zip writer (stored, deflated, and a
 * forced-ZIP64 variant), OSV records with invented package names, and a local
 * "OSV export" directory that `runUpdate({ source })` reads instead of the
 * network. Every package name here is a placeholder, not a real package.
 */

import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import * as zlib from "node:zlib";
import type { Ecosystem } from "../src/engine/packages.js";
import { runUpdate } from "../src/runtime/intel.js";
import { testRoot } from "./helpers.js";

export interface ZipInput {
  name: string;
  data: Buffer | string;
  method?: 0 | 8;
}

function crc32(b: Buffer): number {
  const f = (zlib as unknown as { crc32?: (x: Buffer) => number }).crc32;
  if (typeof f === "function") return f(b) >>> 0;
  let c = ~0;
  for (const byte of b) {
    c ^= byte;
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}

/** A valid zip archive; `zip64` forces the ZIP64 end records and extra fields even for small archives. */
export function makeZip(entries: readonly ZipInput[], o: { zip64?: boolean } = {}): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data, "utf8");
    const method = e.method ?? 8;
    const comp = method === 8 ? zlib.deflateRawSync(data) : data;
    const name = Buffer.from(e.name, "utf8");
    const crc = crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(comp.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(name.length, 26);
    locals.push(lh, name, comp);
    const extra = o.zip64 === true ? Buffer.alloc(28) : Buffer.alloc(0);
    if (o.zip64 === true) {
      extra.writeUInt16LE(0x0001, 0);
      extra.writeUInt16LE(24, 2);
      extra.writeBigUInt64LE(BigInt(data.length), 4);
      extra.writeBigUInt64LE(BigInt(comp.length), 12);
      extra.writeBigUInt64LE(BigInt(offset), 20);
    }
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(45, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(o.zip64 === true ? 0xffffffff : comp.length, 20);
    ch.writeUInt32LE(o.zip64 === true ? 0xffffffff : data.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt16LE(extra.length, 30);
    ch.writeUInt32LE(o.zip64 === true ? 0xffffffff : offset, 42);
    centrals.push(ch, name, extra);
    offset += 30 + name.length + comp.length;
  }
  const cd = Buffer.concat(centrals);
  const tail: Buffer[] = [];
  if (o.zip64 === true) {
    const rec = Buffer.alloc(56);
    rec.writeUInt32LE(0x06064b50, 0);
    rec.writeBigUInt64LE(44n, 4);
    rec.writeUInt16LE(45, 12);
    rec.writeUInt16LE(45, 14);
    rec.writeBigUInt64LE(BigInt(entries.length), 24);
    rec.writeBigUInt64LE(BigInt(entries.length), 32);
    rec.writeBigUInt64LE(BigInt(cd.length), 40);
    rec.writeBigUInt64LE(BigInt(offset), 48);
    const loc = Buffer.alloc(20);
    loc.writeUInt32LE(0x07064b50, 0);
    loc.writeBigUInt64LE(BigInt(offset + cd.length), 8);
    loc.writeUInt32LE(1, 16);
    tail.push(rec, loc);
  }
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(o.zip64 === true ? 0xffff : entries.length, 8);
  eocd.writeUInt16LE(o.zip64 === true ? 0xffff : entries.length, 10);
  eocd.writeUInt32LE(o.zip64 === true ? 0xffffffff : cd.length, 12);
  eocd.writeUInt32LE(o.zip64 === true ? 0xffffffff : offset, 16);
  return Buffer.concat([...locals, cd, ...tail, eocd]);
}

export function osv(id: string, eco: Ecosystem, name: string, o: { versions?: string[]; all?: boolean; ranges?: { introduced: string; fixed?: string }[]; withdrawn?: boolean } = {}): string {
  const ranges = o.all === true ? [{ type: "SEMVER", events: [{ introduced: "0" }] }] : (o.ranges ?? []).map((r) => ({ type: "SEMVER", events: [{ introduced: r.introduced }, ...(r.fixed !== undefined ? [{ fixed: r.fixed }] : [])] }));
  return JSON.stringify({ id, modified: "2026-10-01T00:00:00Z", ...(o.withdrawn === true ? { withdrawn: "2026-10-02T00:00:00Z" } : {}), affected: [{ package: { ecosystem: eco, name }, ...(o.versions !== undefined ? { versions: o.versions } : {}), ...(ranges.length > 0 ? { ranges } : {}) }] });
}

/** The invented entries every item-4 test uses. */
export const FIXTURE: Partial<Record<Ecosystem, ZipInput[]>> = {
  npm: [
    { name: "MAL-2099-0001.json", data: osv("MAL-2099-0001", "npm", "evil-fixture", { all: true }) },
    { name: "MAL-2099-0002.json", data: osv("MAL-2099-0002", "npm", "partly-bad", { versions: ["1.0.0", "1.0.1"] }) },
    { name: "MAL-2099-0004.json", data: osv("MAL-2099-0004", "npm", "mcp-mail-fixture", { versions: ["1.0.16"] }), method: 0 },
    { name: "MAL-2099-0005.json", data: osv("MAL-2099-0005", "npm", "build-tool-fixture", { ranges: [{ introduced: "21.5.0", fixed: "21.5.2" }] }) },
    { name: "MAL-2099-0006.json", data: osv("MAL-2099-0006", "npm", "withdrawn-fixture", { all: true, withdrawn: true }) },
    // Not malicious-package advisories: ignored by the snapshot.
    { name: "GHSA-0000-0000-0000.json", data: osv("GHSA-0000-0000-0000", "npm", "ordinary-vuln-fixture", { all: true }) },
    { name: "MAL-2099-0007.json", data: "{ not json" },
  ],
  PyPI: [
    { name: "MAL-2099-0003.json", data: osv("MAL-2099-0003", "PyPI", "Evil-Fixture", { versions: ["1.0"] }) },
    { name: "MAL-2099-0008.json", data: osv("MAL-2099-0008", "PyPI", "fixture-llm-proxy", { versions: ["1.82.7", "1.82.8"] }) },
  ],
  "crates.io": [{ name: "MAL-2099-0009.json", data: osv("MAL-2099-0009", "crates.io", "evil_crate_fixture", { all: true }) }],
  RubyGems: [{ name: "MAL-2099-0010.json", data: osv("MAL-2099-0010", "RubyGems", "evil-gem-fixture", { versions: ["0.1.0"] }) }],
};

/** A local directory laid out like OSV's bucket: <dir>/<Ecosystem>/all.zip. */
export function fixtureSource(entries: Partial<Record<Ecosystem, ZipInput[]>> = FIXTURE, o: { zip64?: boolean } = {}): string {
  const dir = mkdtempSync(join(testRoot(), "osv-"));
  for (const [eco, list] of Object.entries(entries)) {
    mkdirSync(join(dir, eco), { recursive: true });
    writeFileSync(join(dir, eco, "all.zip"), makeZip(list ?? [], o));
  }
  return dir;
}

export const FIXTURE_ECOS = Object.keys(FIXTURE) as Ecosystem[];

/** A firewall home with the fixture snapshot built by the real `update` code path (from a local source). */
export async function fixtureHome(o: { now?: Date } = {}): Promise<string> {
  const home = mkdtempSync(join(testRoot(), "fwhome-"));
  await runUpdate(home, { source: fixtureSource(), ecosystems: FIXTURE_ECOS, ...(o.now !== undefined ? { now: () => o.now as Date } : {}) });
  return home;
}
