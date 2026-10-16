/**
 * The zip reader `update` uses on OSV's exports (round trips, ZIP64,
 * corruption, and a deterministic fuzz: any mutated or truncated archive ends
 * in a ZipError, never a crash of another kind or a hang), the OSV record
 * reader, and the lockfile parsers.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { entriesFromOsv } from "../src/runtime/intel.js";
import { parseComposerLock, parseGemfileLock, parsePackageLock, parsePipfileLock, parsePnpmLock, parseTomlPackages, parseYarnLock, readLockfiles, MAX_LOCKFILE_BYTES } from "../src/runtime/lockfiles.js";
import { forEachEntry, ZipError } from "../src/runtime/zip.js";
import { testRoot } from "./helpers.js";
import { makeZip, osv } from "./intel-fixture.js";

function tmpZip(buf: Buffer): string {
  const p = join(mkdtempSync(join(testRoot(), "zip-")), "a.zip");
  writeFileSync(p, buf);
  return p;
}

function readAll(p: string): Record<string, string> {
  const out: Record<string, string> = {};
  forEachEntry(p, () => true, (n, d) => (out[n] = d.toString("utf8")));
  return out;
}

/** A small deterministic PRNG so the fuzz run is reproducible. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

describe("zip reader", () => {
  const entries = [
    { name: "MAL-1.json", data: '{"id":"MAL-1"}' },
    { name: "dir/GHSA-2.json", data: "x".repeat(5000), method: 0 as const },
    { name: "MAL-3.json", data: Buffer.from(Array.from({ length: 3000 }, (_, i) => i % 251)) },
  ];
  it("round-trips stored and deflated entries", () => {
    const got = readAll(tmpZip(makeZip(entries)));
    expect(Object.keys(got)).toEqual(["MAL-1.json", "dir/GHSA-2.json", "MAL-3.json"]);
    expect(got["MAL-1.json"]).toBe('{"id":"MAL-1"}');
    expect(got["dir/GHSA-2.json"]).toBe("x".repeat(5000));
  });
  it("reads ZIP64 end records and extra fields", () => {
    expect(Object.keys(readAll(tmpZip(makeZip(entries, { zip64: true }))))).toHaveLength(3);
  });
  it("filters by name before inflating", () => {
    let n = 0;
    forEachEntry(tmpZip(makeZip(entries)), (name) => name.startsWith("MAL-"), () => n++);
    expect(n).toBe(2);
  });
  it("rejects a truncated archive, a bad checksum, and oversize entries", () => {
    const z = makeZip(entries);
    expect(() => readAll(tmpZip(z.subarray(0, z.length - 30)))).toThrow(ZipError);
    expect(() => readAll(tmpZip(Buffer.from("not a zip at all, just text")))).toThrow(ZipError);
    const bad = Buffer.from(z);
    const at = 30 + "MAL-1.json".length + 2; // a byte of the first entry's compressed data
    bad[at] = (bad[at] as number) ^ 0xff;
    expect(() => readAll(tmpZip(bad))).toThrow(ZipError);
    expect(() => forEachEntry(tmpZip(z), () => true, () => undefined, { maxDirectory: 1 << 20, maxEntry: 100, maxEntries: 10 })).toThrow(/larger than/);
    expect(() => forEachEntry(join(testRoot(), "missing.zip"), () => true, () => undefined)).toThrow(ZipError);
  });
  it("fuzz: mutated and truncated archives only ever throw ZipError", () => {
    const seeds = [makeZip(entries), makeZip(entries, { zip64: true })];
    const r = rng(20261009);
    const dir = mkdtempSync(join(testRoot(), "fuzz-"));
    for (let i = 0; i < 600; i++) {
      const base = seeds[i % 2] as Buffer;
      const b = Buffer.from(base);
      const mode = i % 3;
      if (mode === 0) for (let k = 0; k < 1 + Math.floor(r() * 8); k++) b[Math.floor(r() * b.length)] = Math.floor(r() * 256);
      const buf = mode === 1 ? b.subarray(0, Math.floor(r() * b.length)) : mode === 2 ? Buffer.concat([b.subarray(0, Math.floor(r() * b.length)), Buffer.from(Array.from({ length: 40 }, () => Math.floor(r() * 256)))]) : b;
      const p = join(dir, `${i}.zip`);
      writeFileSync(p, buf);
      try {
        forEachEntry(p, () => true, () => undefined);
      } catch (e) {
        expect(e, `case ${i}: ${(e as Error).message}`).toBeInstanceOf(ZipError);
      }
    }
  });
});

describe("OSV records", () => {
  it("keeps MAL- entries for the ecosystem, folding ranges into all/ranges", () => {
    expect(entriesFromOsv(JSON.parse(osv("MAL-1", "npm", "X-Pkg", { all: true })), "npm")).toEqual([{ name: "x-pkg", entry: { all: true, versions: [], ranges: [], ids: ["MAL-1"] } }]);
    expect(entriesFromOsv(JSON.parse(osv("MAL-2", "npm", "y", { ranges: [{ introduced: "1.0.0", fixed: "1.0.3" }] })), "npm")[0]?.entry).toEqual({ all: false, versions: [], ranges: [{ introduced: "1.0.0", fixed: "1.0.3" }], ids: ["MAL-2"] });
    expect(entriesFromOsv(JSON.parse(osv("MAL-3", "PyPI", "Some_Pkg", { versions: ["1.0"] })), "PyPI")[0]?.name).toBe("some-pkg");
  });
  it("a package with more versions or ranges than the snapshot keeps is condemned whole, not left partly unflagged", () => {
    const many = Array.from({ length: 5001 }, (_, i) => `1.0.${i}`);
    expect(entriesFromOsv(JSON.parse(osv("MAL-8", "npm", "big", { versions: many })), "npm")[0]?.entry.all).toBe(true);
    expect(entriesFromOsv(JSON.parse(osv("MAL-9", "npm", "few", { versions: ["1.0.0", "1.0.1"] })), "npm")[0]?.entry.all).toBe(false);
    const ranges = Array.from({ length: 201 }, (_, i) => ({ introduced: `${i + 1}.0.0`, fixed: `${i + 1}.0.1` }));
    expect(entriesFromOsv(JSON.parse(osv("MAL-10", "npm", "wide", { ranges })), "npm")[0]?.entry.all).toBe(true);
  });
  it("ignores other ids, other ecosystems, withdrawn entries and junk", () => {
    expect(entriesFromOsv(JSON.parse(osv("GHSA-x", "npm", "y", { all: true })), "npm")).toEqual([]);
    expect(entriesFromOsv(JSON.parse(osv("MAL-4", "PyPI", "y", { all: true })), "npm")).toEqual([]);
    expect(entriesFromOsv(JSON.parse(osv("MAL-5", "npm", "y", { all: true, withdrawn: true })), "npm")).toEqual([]);
    for (const junk of [null, 1, "x", [], { id: "MAL-6" }, { id: "MAL-7", affected: [null, { package: {} }] }]) expect(entriesFromOsv(junk, "npm")).toEqual([]);
  });
  it("an entry naming a package with no versions or ranges condemns every version", () => {
    expect(entriesFromOsv({ id: "MAL-8", affected: [{ package: { ecosystem: "npm", name: "z" } }] }, "npm")[0]?.entry.all).toBe(true);
  });
});

describe("lockfile parsers", () => {
  it("package-lock v1 and v3 (nested, aliased, linked)", () => {
    expect(parsePackageLock(JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/a": { version: "1.0.0" }, "node_modules/a/node_modules/@s/b": { version: "2.0.0" }, "node_modules/al": { name: "real", version: "3.0.0" }, "packages/web": { version: "0.0.1" }, "node_modules/web": { link: true } } }))).toEqual([
      { name: "a", version: "1.0.0" },
      { name: "@s/b", version: "2.0.0" },
      { name: "real", version: "3.0.0" },
    ]);
    expect(parsePackageLock(JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "2.0.0" } } }, c: { version: "file:../c" } } }))).toEqual([
      { name: "a", version: "1.0.0" },
      { name: "b", version: "2.0.0" },
    ]);
  });
  it("pnpm v5, v6 and v9 keys", () => {
    expect(parsePnpmLock("lockfileVersion: 5.4\npackages:\n  /a/1.0.0:\n    dev: false\n  /@s/b/2.0.0_react@18.0.0:\n    dev: true\n")).toEqual([{ name: "a", version: "1.0.0" }, { name: "@s/b", version: "2.0.0" }]);
    expect(parsePnpmLock("lockfileVersion: '6.0'\npackages:\n  /a@1.0.0:\n    x: 1\n  /@s/b@2.0.0(react@18.0.0):\n    x: 1\n")).toEqual([{ name: "a", version: "1.0.0" }, { name: "@s/b", version: "2.0.0" }]);
    expect(parsePnpmLock("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies: {}\npackages:\n  '@s/b@2.0.0':\n    resolution: {}\nsnapshots:\n  a@1.0.0(b@2.0.0):\n    x: 1\n")).toEqual([{ name: "@s/b", version: "2.0.0" }, { name: "a", version: "1.0.0" }]);
  });
  it("yarn classic and Berry, skipping workspace entries", () => {
    expect(parseYarnLock('"@s/a@^1.0.0", "@s/a@^1.1.0":\n  version "1.2.0"\nb@^2:\n  version "2.0.1"\n')).toEqual([{ name: "@s/a", version: "1.2.0" }, { name: "b", version: "2.0.1" }]);
    expect(parseYarnLock('__metadata:\n  version: 8\n\n"a@npm:^1.0.0":\n  version: 1.0.4\n\n"web@workspace:packages/web":\n  version: 0.0.0-use.local\n')).toEqual([{ name: "a", version: "1.0.4" }]);
  });
  it("yarn aliases and npm: aliases in package-lock v1 name the package they install, not the alias", () => {
    expect(parseYarnLock('"foo@npm:evil-pkg@1.0.0":\n  version "1.0.0"\n\n"bar@npm:@s/evil@^2.0.0":\n  version: 2.1.0\n')).toEqual([{ name: "evil-pkg", version: "1.0.0" }, { name: "@s/evil", version: "2.1.0" }]);
    expect(parsePackageLock(JSON.stringify({ lockfileVersion: 1, dependencies: { foo: { version: "npm:evil-pkg@1.0.0" }, ok: { version: "2.0.0" } } }))).toEqual([{ name: "evil-pkg", version: "1.0.0" }, { name: "ok", version: "2.0.0" }]);
  });
  it("bun and deno lockfiles are reported as unread, not silently clean", () => {
    const d = mkdtempSync(join(testRoot(), "bun-"));
    writeFileSync(join(d, "bun.lock"), "{}");
    writeFileSync(join(d, "deno.lock"), "{}");
    const r = readLockfiles(d, "npm");
    expect(r.map((x) => [x.file, x.entries.length])).toEqual([[join(d, "bun.lock"), 0], [join(d, "deno.lock"), 0]]);
    expect(r.every((x) => x.error?.includes("cannot read") === true)).toBe(true);
  });
  it("a requirements include that is missing is reported, and the pins around it are still read", () => {
    const d = mkdtempSync(join(testRoot(), "req-"));
    writeFileSync(join(d, "requirements.txt"), "-r missing.txt\nrequests==2.0.0\n");
    const r = readLockfiles(d, "PyPI", ["requirements.txt"]);
    expect(r[0]).toEqual({ file: join(d, "requirements.txt"), eco: "PyPI", entries: [{ name: "requests", version: "2.0.0" }] });
    expect(r[1]).toEqual({ file: join(d, "missing.txt"), eco: "PyPI", entries: [], error: "not found" });
  });
  it("TOML [[package]] tables, Pipfile.lock, Gemfile.lock, composer.lock", () => {
    expect(parseTomlPackages('[[package]]\nname = "a"\nversion = "1.0"\n[package.dependencies]\nb = "*"\n\n[[package]]\nname = "c"\nversion = "2.0"\nsource = { git = "https://x" }\n', { registryOnly: true })).toEqual([{ name: "a", version: "1.0" }]);
    expect(parsePipfileLock(JSON.stringify({ default: { a: { version: "==1.0" } }, develop: { b: { version: "==2.0" }, c: { git: "x" } } }))).toEqual([{ name: "a", version: "1.0" }, { name: "b", version: "2.0" }]);
    expect(parseGemfileLock("GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.16.0-x86_64-linux)\n      racc (~> 1.4)\n    racc (1.7.3)\n\nPLATFORMS\n  ruby\n")).toEqual([{ name: "nokogiri", version: "1.16.0" }, { name: "racc", version: "1.7.3" }]);
    expect(parseComposerLock(JSON.stringify({ packages: [{ name: "a/b", version: "v1.2.3" }], "packages-dev": [{ name: "c/d", version: "2.0.0" }] }))).toEqual([{ name: "a/b", version: "1.2.3" }, { name: "c/d", version: "2.0.0" }]);
  });
  it("a lockfile over the size limit is skipped with a reason", () => {
    const d = mkdtempSync(join(testRoot(), "big-"));
    writeFileSync(join(d, "package-lock.json"), Buffer.alloc(MAX_LOCKFILE_BYTES + 1, 0x20));
    const r = readLockfiles(d, "npm");
    expect(r[0]?.error).toContain("larger than");
    expect(r[0]?.entries).toEqual([]);
  });
  it("a lockfile or a requirements file saved with a UTF-8 byte order mark is read, not skipped or half read; damage after the mark is still reported", () => {
    const d = mkdtempSync(join(testRoot(), "bom-"));
    const BOM = "\uFEFF";
    const lock = join(d, "package-lock.json");
    writeFileSync(lock, `${BOM}${JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/a": { version: "1.0.0" } } })}`);
    expect(readLockfiles(d, "npm")).toEqual([{ file: lock, eco: "npm", entries: [{ name: "a", version: "1.0.0" }] }]);
    // The first line is a pin too: with the mark in front of it, it matched nothing and its package was never checked.
    writeFileSync(join(d, "requirements.txt"), `${BOM}requests==2.0.0\nflask==1.0.0\n`);
    expect(readLockfiles(d, "PyPI", ["requirements.txt"])[0]?.entries).toEqual([{ name: "requests", version: "2.0.0" }, { name: "flask", version: "1.0.0" }]);
    writeFileSync(lock, `${BOM}{"packages": `);
    expect(readLockfiles(d, "npm")[0]?.error).toContain("could not be parsed");
  });
});
