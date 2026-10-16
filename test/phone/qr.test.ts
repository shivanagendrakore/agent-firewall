/**
 * Item P: the QR encoder. A small reader written here from ISO/IEC 18004 decodes what the encoder drew:
 * the format information (level M, the mask), the zigzag placement, de-interleaving, a Reed-Solomon
 * check of every block, and the byte-mode payload, which must be the pairing link exactly.
 */
import { describe, expect, it } from "vitest";
import { blocksM, byteCapacity, encodeQr, formatBits, functionModules, maskBit, placementOrder, renderQr, rsRemainder, type QrCode } from "../../src/runtime/relay/qr.js";

function read(qr: QrCode): { text: string; mask: number; rsOk: boolean } {
  const m = qr.modules;
  // Format bits around the top-left finder (the copy drawFormat puts at x = 8, y = 0..8 and y = 8, x = 0..7).
  let bits = 0;
  const at = (x: number, y: number): number => ((m[y] as boolean[])[x] ? 1 : 0);
  const cells: [number, number][] = [[8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8], [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]];
  cells.forEach(([x, y], i) => (bits |= at(x, y) << i));
  const mask = [0, 1, 2, 3, 4, 5, 6, 7].find((k) => formatBits(k) === bits);
  if (mask === undefined) throw new Error("no level-M format information");
  const fn = functionModules(qr.version);
  const order = placementOrder(fn, qr.size);
  const raw: number[] = [];
  order.forEach(([x, y], i) => {
    if (i >> 3 >= raw.length) raw.push(0);
    const bit = ((m[y] as boolean[])[x] as boolean) !== maskBit(mask, x, y) ? 1 : 0;
    raw[i >> 3] = ((raw[i >> 3] as number) | (bit << (7 - (i & 7)))) & 0xff;
  });
  const spec = blocksM(qr.version);
  const blocks = spec.data.map(() => ({ d: [] as number[], e: [] as number[] }));
  let k = 0;
  const maxD = Math.max(...spec.data);
  for (let i = 0; i < maxD; i++) spec.data.forEach((n, b) => i < n && (blocks[b] as { d: number[] }).d.push(raw[k++] as number));
  for (let i = 0; i < spec.ec; i++) blocks.forEach((b) => b.e.push(raw[k++] as number));
  const rsOk = blocks.every((b) => rsRemainder(b.d, spec.ec).every((x, i) => x === b.e[i]));
  const data = blocks.flatMap((b) => b.d);
  const bitAt = (i: number): number => ((data[i >> 3] as number) >> (7 - (i & 7))) & 1;
  const take = (start: number, n: number): number => Array.from({ length: n }, (_, j) => bitAt(start + j)).reduce((a, b) => (a << 1) | b, 0);
  if (take(0, 4) !== 0b0100) throw new Error("not byte mode");
  const cbits = qr.version <= 9 ? 8 : 16;
  const len = take(4, cbits);
  const out = Buffer.from(Array.from({ length: len }, (_, j) => take(4 + cbits + j * 8, 8)));
  return { text: out.toString("utf8"), mask, rsOk };
}

describe("QR encoder", () => {
  const link = "https://approve.launchsafe.com/firewall/pair#v=1&p=0192f1c4-7b7e-7c2a-9d1e-3a5b6c7d8e9f&s=Qk9JWkFxZ0V1cUd0R2J5c3E1d1p2b0xHQ0x5Q0h6cXc&f=8a3c1d2e4f5a6b7c";
  it("encodes the pairing link so a reader gets it back, with valid Reed-Solomon blocks", () => {
    const qr = encodeQr(link);
    expect(qr.version).toBeGreaterThanOrEqual(7);
    expect(qr.size).toBe(qr.version * 4 + 17);
    const r = read(qr);
    expect(r.text).toBe(link);
    expect(r.rsOk).toBe(true);
    expect(r.mask).toBe(qr.mask);
  });
  it("round-trips every version from 1 to 10 at its capacity", () => {
    for (let v = 1; v <= 10; v++) {
      const text = "x".repeat(byteCapacity(v));
      const qr = encodeQr(text);
      expect(qr.version).toBe(v);
      const r = read(qr);
      expect(r.text).toBe(text);
      expect(r.rsOk).toBe(true);
    }
    expect(byteCapacity(10)).toBe(213);
  });
  it("refuses text beyond version 10", () => {
    expect(() => encodeQr("x".repeat(214))).toThrow(/too long/);
  });
  it("renders two module rows per line with a quiet zone, black on white with ANSI", () => {
    const qr = encodeQr("hello");
    const plain = renderQr(qr, { ansi: false });
    expect(plain.length).toBe(Math.ceil((qr.size + 4) / 2));
    expect(plain.every((l) => [...l].length === qr.size + 4)).toBe(true);
    expect(plain.join("")).toMatch(/[█▀▄]/);
    const line = renderQr(qr, { ansi: true })[0] as string;
    expect(line.startsWith("\u001b[30;47m") && line.endsWith("\u001b[0m")).toBe(true);
  });
});
