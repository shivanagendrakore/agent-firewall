/**
 * A minimal, bounded zip reader for the OSV bulk exports (`update`).
 * Zero dependencies: the central directory is parsed by hand (ZIP64 included,
 * since an ecosystem's export can hold more than 65,535 entries) and each
 * entry is inflated with zlib.inflateRawSync on its own, read from the file
 * descriptor, so memory stays bounded by the largest entry rather than the
 * archive. Every malformed input ends in a ZipError, never a hang or an
 * out-of-bounds read.
 */

import { closeSync, fstatSync, openSync, readSync } from "node:fs";
import * as zlib from "node:zlib";

export class ZipError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ZipError";
  }
}

export interface ZipEntry {
  name: string;
  method: number;
  flags: number;
  crc: number;
  compressedSize: number;
  size: number;
  localOffset: number;
}

export interface ZipLimits {
  /** Largest central directory read (bytes). */
  maxDirectory: number;
  /** Largest single entry, compressed or not (bytes). */
  maxEntry: number;
  /** Most entries listed. */
  maxEntries: number;
}

export const DEFAULT_ZIP_LIMITS: ZipLimits = { maxDirectory: 256 * 1024 * 1024, maxEntry: 16 * 1024 * 1024, maxEntries: 2_000_000 };

const SIG_EOCD = 0x06054b50;
const SIG_EOCD64_LOCATOR = 0x07064b50;
const SIG_EOCD64 = 0x06064b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;

function readAt(fd: number, pos: number, len: number, fileSize: number): Buffer {
  if (!Number.isSafeInteger(pos) || !Number.isSafeInteger(len) || pos < 0 || len < 0 || pos + len > fileSize) throw new ZipError(`read outside the archive (${pos}+${len} of ${fileSize})`);
  const buf = Buffer.alloc(len);
  let off = 0;
  while (off < len) {
    const n = readSync(fd, buf, off, len - off, pos + off);
    if (n <= 0) throw new ZipError("unexpected end of the archive");
    off += n;
  }
  return buf;
}

function u64(b: Buffer, at: number): number {
  const v = b.readBigUInt64LE(at);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new ZipError("a 64-bit size is too large");
  return Number(v);
}

function need(b: Buffer, at: number, len: number): void {
  if (at < 0 || at + len > b.length) throw new ZipError("truncated record");
}

/** The central directory: where it is and how many entries it says it has. */
function findDirectory(fd: number, fileSize: number, limits: ZipLimits): { offset: number; size: number; count: number } {
  if (fileSize < 22) throw new ZipError("not a zip archive (too small)");
  const tailLen = Math.min(fileSize, 22 + 65535 + 20);
  const tailPos = fileSize - tailLen;
  const tail = readAt(fd, tailPos, tailLen, fileSize);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail.readUInt32LE(i) === SIG_EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) throw new ZipError("not a zip archive (no end-of-directory record; truncated download?)");
  let count = tail.readUInt16LE(eocd + 10);
  let size = tail.readUInt32LE(eocd + 12);
  let offset = tail.readUInt32LE(eocd + 16);
  if (count === 0xffff || size === 0xffffffff || offset === 0xffffffff) {
    const loc = eocd - 20;
    if (loc < 0 || tail.readUInt32LE(loc) !== SIG_EOCD64_LOCATOR) throw new ZipError("ZIP64 locator missing");
    const recPos = u64(tail, loc + 8);
    const rec = readAt(fd, recPos, 56, fileSize);
    if (rec.readUInt32LE(0) !== SIG_EOCD64) throw new ZipError("ZIP64 end-of-directory record missing");
    count = u64(rec, 32);
    size = u64(rec, 40);
    offset = u64(rec, 48);
  }
  if (size > limits.maxDirectory) throw new ZipError(`central directory too large (${size} bytes)`);
  if (count > limits.maxEntries) throw new ZipError(`too many entries (${count})`);
  if (offset + size > fileSize) throw new ZipError("central directory outside the archive");
  return { offset, size, count };
}

/** Lists the entries of an open archive. */
export function listEntries(fd: number, fileSize: number, limits: ZipLimits = DEFAULT_ZIP_LIMITS): ZipEntry[] {
  const dir = findDirectory(fd, fileSize, limits);
  const cd = readAt(fd, dir.offset, dir.size, fileSize);
  const out: ZipEntry[] = [];
  let p = 0;
  for (let i = 0; i < dir.count; i++) {
    need(cd, p, 46);
    if (cd.readUInt32LE(p) !== SIG_CENTRAL) throw new ZipError(`bad central directory entry ${i}`);
    const flags = cd.readUInt16LE(p + 8);
    const method = cd.readUInt16LE(p + 10);
    const crc = cd.readUInt32LE(p + 16);
    let compressedSize = cd.readUInt32LE(p + 20);
    let size = cd.readUInt32LE(p + 24);
    const nameLen = cd.readUInt16LE(p + 28);
    const extraLen = cd.readUInt16LE(p + 30);
    const commentLen = cd.readUInt16LE(p + 32);
    let localOffset = cd.readUInt32LE(p + 42);
    need(cd, p + 46, nameLen + extraLen + commentLen);
    const name = cd.toString("utf8", p + 46, p + 46 + nameLen);
    // ZIP64 extended information: the fields that overflowed, in this order.
    let e = p + 46 + nameLen;
    const extraEnd = e + extraLen;
    while (e + 4 <= extraEnd) {
      const id = cd.readUInt16LE(e);
      const len = cd.readUInt16LE(e + 2);
      if (e + 4 + len > extraEnd) throw new ZipError(`bad extra field in ${name}`);
      if (id === 0x0001) {
        let q = e + 4;
        const end = q + len;
        const take = (): number => {
          if (q + 8 > end) throw new ZipError(`short ZIP64 field in ${name}`);
          const v = u64(cd, q);
          q += 8;
          return v;
        };
        if (size === 0xffffffff) size = take();
        if (compressedSize === 0xffffffff) compressedSize = take();
        if (localOffset === 0xffffffff) localOffset = take();
      }
      e += 4 + len;
    }
    out.push({ name, method, flags, crc, compressedSize, size, localOffset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

/** Reads and decompresses one entry, checking its sizes and (where Node offers it) its CRC. */
export function readEntry(fd: number, fileSize: number, e: ZipEntry, limits: ZipLimits = DEFAULT_ZIP_LIMITS): Buffer {
  if ((e.flags & 0x1) !== 0) throw new ZipError(`${e.name} is encrypted`);
  if (e.compressedSize > limits.maxEntry || e.size > limits.maxEntry) throw new ZipError(`${e.name} is larger than ${limits.maxEntry} bytes`);
  const lh = readAt(fd, e.localOffset, 30, fileSize);
  if (lh.readUInt32LE(0) !== SIG_LOCAL) throw new ZipError(`bad local header for ${e.name}`);
  const start = e.localOffset + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
  const raw = readAt(fd, start, e.compressedSize, fileSize);
  let data: Buffer;
  if (e.method === 0) data = raw;
  else if (e.method === 8) {
    try {
      data = zlib.inflateRawSync(raw, { maxOutputLength: Math.max(1, limits.maxEntry) });
    } catch (err) {
      throw new ZipError(`${e.name}: ${(err as Error).message}`);
    }
  } else throw new ZipError(`${e.name}: unsupported compression method ${e.method}`);
  if (data.length !== e.size) throw new ZipError(`${e.name}: size ${data.length}, expected ${e.size}`);
  const crc32 = (zlib as unknown as { crc32?: (b: Buffer) => number }).crc32;
  if (typeof crc32 === "function" && crc32(data) >>> 0 !== e.crc >>> 0) throw new ZipError(`${e.name}: checksum mismatch`);
  return data;
}

/**
 * Calls `fn` for each entry whose name passes `filter`, one at a time. Any malformed input throws a
 * ZipError (other errors from reading the file are wrapped too).
 */
export function forEachEntry(path: string, filter: (name: string) => boolean, fn: (name: string, data: Buffer) => void, limits: ZipLimits = DEFAULT_ZIP_LIMITS): number {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch (err) {
    throw new ZipError(`cannot open ${path}: ${(err as Error).message}`);
  }
  try {
    const size = fstatSync(fd).size;
    let n = 0;
    for (const e of listEntries(fd, size, limits)) {
      if (e.name.endsWith("/") || !filter(e.name)) continue;
      fn(e.name, readEntry(fd, size, e, limits));
      n++;
    }
    return n;
  } catch (err) {
    if (err instanceof ZipError) throw err;
    throw new ZipError((err as Error).message);
  } finally {
    closeSync(fd);
  }
}
