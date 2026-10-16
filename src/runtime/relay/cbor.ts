/**
 * A minimal CBOR reader (RFC 8949) for what WebAuthn hands the firewall: the
 * attestation object (a map of fmt, attStmt and authData) and COSE public
 * keys. Definite lengths only (WebAuthn's CTAP2 canonical encoding never uses
 * indefinite ones), bounded depth and sizes, and the end offset is returned so
 * a COSE key followed by extension data can be split. Anything unexpected
 * throws: the caller treats that as a failed check.
 */

export type CborValue = number | bigint | string | boolean | null | undefined | Uint8Array | CborValue[] | Map<CborValue, CborValue>;

const MAX_DEPTH = 8;
const MAX_ITEMS = 1024;

export class CborError extends Error {}

/** Decodes one item at `offset`. Returns the value and the offset after it. */
export function decodeCbor(buf: Uint8Array, offset = 0, depth = 0): { value: CborValue; end: number } {
  if (depth > MAX_DEPTH) throw new CborError("CBOR nested too deeply");
  if (offset >= buf.length) throw new CborError("CBOR ends early");
  const ib = buf[offset] as number;
  const major = ib >> 5;
  const info = ib & 0x1f;
  let p = offset + 1;
  const need = (n: number): void => {
    if (p + n > buf.length) throw new CborError("CBOR ends early");
  };
  let arg: number | bigint;
  if (info < 24) arg = info;
  else if (info === 24) {
    need(1);
    arg = buf[p] as number;
    p += 1;
  } else if (info === 25) {
    need(2);
    arg = ((buf[p] as number) << 8) | (buf[p + 1] as number);
    p += 2;
  } else if (info === 26) {
    need(4);
    arg = Buffer.from(buf.subarray(p, p + 4)).readUInt32BE(0);
    p += 4;
  } else if (info === 27) {
    need(8);
    const big = Buffer.from(buf.subarray(p, p + 8)).readBigUInt64BE(0);
    arg = big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big;
    p += 8;
  } else throw new CborError("indefinite or reserved CBOR length");
  const len = (): number => {
    if (typeof arg !== "number" || arg > buf.length) throw new CborError("CBOR length too large");
    return arg;
  };
  switch (major) {
    case 0:
      return { value: arg, end: p };
    case 1:
      return { value: typeof arg === "number" ? -1 - arg : -1n - arg, end: p };
    case 2: {
      const n = len();
      need(n);
      return { value: buf.slice(p, p + n), end: p + n };
    }
    case 3: {
      const n = len();
      need(n);
      return { value: new TextDecoder("utf-8", { fatal: true }).decode(buf.subarray(p, p + n)), end: p + n };
    }
    case 4: {
      const n = len();
      if (n > MAX_ITEMS) throw new CborError("CBOR array too long");
      const out: CborValue[] = [];
      for (let i = 0; i < n; i++) {
        const r = decodeCbor(buf, p, depth + 1);
        out.push(r.value);
        p = r.end;
      }
      return { value: out, end: p };
    }
    case 5: {
      const n = len();
      if (n > MAX_ITEMS) throw new CborError("CBOR map too long");
      const out = new Map<CborValue, CborValue>();
      for (let i = 0; i < n; i++) {
        const k = decodeCbor(buf, p, depth + 1);
        const v = decodeCbor(buf, k.end, depth + 1);
        if (out.has(k.value)) throw new CborError("duplicate CBOR map key");
        out.set(k.value, v.value);
        p = v.end;
      }
      return { value: out, end: p };
    }
    case 6:
      throw new CborError("CBOR tags are not expected here");
    default:
      if (info === 20) return { value: false, end: p };
      if (info === 21) return { value: true, end: p };
      if (info === 22) return { value: null, end: p };
      if (info === 23) return { value: undefined, end: p };
      throw new CborError("CBOR floats and simple values are not expected here");
  }
}

/** Decodes a buffer that must hold exactly one item. */
export function decodeCborExact(buf: Uint8Array): CborValue {
  const r = decodeCbor(buf, 0);
  if (r.end !== buf.length) throw new CborError("trailing bytes after CBOR");
  return r.value;
}
