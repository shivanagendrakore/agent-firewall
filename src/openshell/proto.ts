/**
 * The smallest protobuf (proto3 wire format) codec the OpenShell middleware needs: varints, 64-bit fixed
 * (doubles in google.protobuf.Value), length-delimited fields (strings, bytes, nested messages) and the
 * google.protobuf.Struct the gateway passes as a middleware's `config`. No dependency: the firewall has none
 * at run time, and the messages it reads are a handful (docs/sandboxes.md). Unknown fields are skipped, as
 * protobuf requires; a truncated or malformed buffer throws ProtoError.
 */

import { setOwn } from "../own.js";

export class ProtoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProtoError";
  }
}

export interface Field {
  wire: 0 | 1 | 2 | 5;
  /** Wire type 0 (varint), 1 (fixed64) and 5 (fixed32): the number; 2: the bytes. */
  int?: bigint;
  bytes?: Buffer;
}

/** A decoded message: every occurrence of each field number, in order. */
export type Fields = Map<number, Field[]>;

function readVarint(buf: Buffer, pos: number): [bigint, number] {
  let result = 0n;
  let shift = 0n;
  for (let i = 0; i < 10; i++) {
    if (pos >= buf.length) throw new ProtoError("truncated varint");
    const b = buf[pos++] as number;
    result |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) return [BigInt.asUintN(64, result), pos];
    shift += 7n;
  }
  throw new ProtoError("varint longer than 10 bytes");
}

/** Decodes one message's fields (not nested ones: call decode again on a field's bytes). */
export function decode(buf: Buffer): Fields {
  const out: Fields = new Map();
  let pos = 0;
  while (pos < buf.length) {
    const [key, p1] = readVarint(buf, pos);
    pos = p1;
    const no = Number(key >> 3n);
    const wire = Number(key & 7n);
    if (no < 1 || no > 536870911) throw new ProtoError(`bad field number ${no}`);
    let f: Field;
    if (wire === 0) {
      const [v, p2] = readVarint(buf, pos);
      pos = p2;
      f = { wire: 0, int: v };
    } else if (wire === 1) {
      if (pos + 8 > buf.length) throw new ProtoError("truncated fixed64");
      f = { wire: 1, int: buf.readBigUInt64LE(pos), bytes: buf.subarray(pos, pos + 8) };
      pos += 8;
    } else if (wire === 2) {
      const [len, p2] = readVarint(buf, pos);
      pos = p2;
      if (len > BigInt(buf.length - pos)) throw new ProtoError("truncated length-delimited field");
      f = { wire: 2, bytes: buf.subarray(pos, pos + Number(len)) };
      pos += Number(len);
    } else if (wire === 5) {
      if (pos + 4 > buf.length) throw new ProtoError("truncated fixed32");
      f = { wire: 5, int: BigInt(buf.readUInt32LE(pos)), bytes: buf.subarray(pos, pos + 4) };
      pos += 4;
    } else throw new ProtoError(`unsupported wire type ${wire}`);
    const list = out.get(no);
    if (list === undefined) out.set(no, [f]);
    else list.push(f);
  }
  return out;
}

/** The last occurrence of a field (proto3: the last one wins for singular fields). */
function last(m: Fields, no: number): Field | undefined {
  const l = m.get(no);
  return l === undefined ? undefined : l[l.length - 1];
}

/** A known field sent with the wrong wire type is an error, never read as its default (a mismatch is a malformed message). */
function typed(m: Fields, no: number, wire: 0 | 2): Field | undefined {
  const l = m.get(no);
  if (l === undefined) return undefined;
  for (const f of l) if (f.wire !== wire) throw new ProtoError(`field ${no} has wire type ${f.wire}, expected ${wire}`);
  return l[l.length - 1];
}

export function str(m: Fields, no: number): string {
  const f = typed(m, no, 2);
  return f?.bytes !== undefined ? f.bytes.toString("utf8") : "";
}

export function bytes(m: Fields, no: number): Buffer {
  const f = typed(m, no, 2);
  return f?.bytes !== undefined ? f.bytes : Buffer.alloc(0);
}

export function uint(m: Fields, no: number): number {
  const f = typed(m, no, 0);
  return f?.int !== undefined ? Number(BigInt.asUintN(32, f.int)) : 0;
}

export function bool(m: Fields, no: number): boolean {
  return uint(m, no) !== 0;
}

/** A nested message field, decoded (null when absent). */
export function msg(m: Fields, no: number): Fields | null {
  const f = typed(m, no, 2);
  return f?.bytes !== undefined ? decode(f.bytes) : null;
}

/** Every occurrence of a repeated message field, decoded. */
export function msgs(m: Fields, no: number): Fields[] {
  typed(m, no, 2);
  return (m.get(no) ?? []).map((f) => decode(f.bytes as Buffer));
}

/** A repeated enum, packed (wire type 2, as prost writes it) or not (wire type 0). */
export function enums(m: Fields, no: number): number[] {
  const out: number[] = [];
  for (const f of m.get(no) ?? []) {
    if (f.wire === 0 && f.int !== undefined) out.push(Number(BigInt.asUintN(32, f.int)));
    else if (f.wire === 2 && f.bytes !== undefined) {
      let pos = 0;
      while (pos < f.bytes.length) {
        const [v, next] = readVarint(f.bytes, pos);
        pos = next;
        out.push(Number(BigInt.asUintN(32, v)));
      }
    } else throw new ProtoError(`field ${no} has wire type ${f.wire}, expected a repeated enum`);
  }
  return out;
}

export function has(m: Fields, no: number): boolean {
  return m.has(no);
}

// --- google.protobuf.Struct / Value / ListValue --------------------------------------------------------

const MAX_DEPTH = 32;

/** google.protobuf.Value to JSON (null, number, string, bool, object, list). */
export function valueToJson(m: Fields, depth = 0): unknown {
  if (depth > MAX_DEPTH) throw new ProtoError("Struct nested too deeply");
  if (has(m, 1)) return null;
  if (has(m, 2)) {
    const f = last(m, 2);
    if (f?.wire !== 1 || f.bytes === undefined) throw new ProtoError("number_value is not a double");
    return f.bytes.readDoubleLE(0);
  }
  if (has(m, 3)) return str(m, 3);
  if (has(m, 4)) return bool(m, 4);
  if (has(m, 5)) return structToJson(msg(m, 5) ?? new Map(), depth + 1);
  if (has(m, 6)) return msgs(msg(m, 6) ?? new Map(), 1).map((v) => valueToJson(v, depth + 1));
  return null;
}

/** google.protobuf.Struct (map<string, Value> fields = 1) to a JSON object. */
export function structToJson(m: Fields, depth = 0): Record<string, unknown> {
  if (depth > MAX_DEPTH) throw new ProtoError("Struct nested too deeply");
  const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const entry of msgs(m, 1)) {
    const k = str(entry, 1);
    const v = msg(entry, 2);
    setOwn(out, k, v === null ? null : valueToJson(v, depth));
  }
  return out;
}

// --- encoding -----------------------------------------------------------------------------------------

function varint(n: bigint | number): Buffer {
  let v = BigInt.asUintN(64, BigInt(n));
  const out: number[] = [];
  while (v >= 0x80n) {
    out.push(Number((v & 0x7fn) | 0x80n));
    v >>= 7n;
  }
  out.push(Number(v));
  return Buffer.from(out);
}

/** A message under construction. Fields at their default value are left out, as proto3 does. */
export class Writer {
  private readonly parts: Buffer[] = [];

  private key(no: number, wire: number): void {
    this.parts.push(varint((no << 3) | wire));
  }

  uint(no: number, v: number | bigint): this {
    if (BigInt(v) === 0n) return this;
    this.key(no, 0);
    this.parts.push(varint(v));
    return this;
  }

  bool(no: number, v: boolean): this {
    return v ? this.uint(no, 1) : this;
  }

  /** A varint field written even when it is zero (a set oneof member). */
  varintAlways(no: number, v: number): this {
    this.key(no, 0);
    this.parts.push(varint(v));
    return this;
  }

  /** An enum value (always written when non-zero). */
  enum(no: number, v: number): this {
    return this.uint(no, v);
  }

  bytes(no: number, v: Buffer | Uint8Array, always = false): this {
    if (v.length === 0 && !always) return this;
    this.key(no, 2);
    this.parts.push(varint(v.length), Buffer.from(v));
    return this;
  }

  str(no: number, v: string): this {
    return this.bytes(no, Buffer.from(v, "utf8"));
  }

  /** A nested message; written even when empty (a set oneof member that has no fields, like Skip {}). */
  msg(no: number, w: Writer): this {
    return this.bytes(no, w.finish(), true);
  }

  double(no: number, v: number): this {
    this.key(no, 1);
    const b = Buffer.alloc(8);
    b.writeDoubleLE(v, 0);
    this.parts.push(b);
    return this;
  }

  finish(): Buffer {
    return Buffer.concat(this.parts);
  }
}

/** JSON to google.protobuf.Value (for tests and stand-in callers). Each oneof member is written even at its default. */
export function jsonToValue(v: unknown): Writer {
  const w = new Writer();
  if (v === null || v === undefined) return w.varintAlways(1, 0);
  if (typeof v === "number") return w.double(2, v);
  if (typeof v === "string") return w.bytes(3, Buffer.from(v, "utf8"), true);
  if (typeof v === "boolean") return w.varintAlways(4, v ? 1 : 0);
  if (Array.isArray(v)) {
    const list = new Writer();
    for (const x of v) list.msg(1, jsonToValue(x));
    return w.msg(6, list);
  }
  return w.msg(5, jsonToStruct(v as Record<string, unknown>));
}

export function jsonToStruct(o: Record<string, unknown>): Writer {
  const w = new Writer();
  for (const [k, v] of Object.entries(o)) w.msg(1, new Writer().str(1, k).msg(2, jsonToValue(v)));
  return w;
}
