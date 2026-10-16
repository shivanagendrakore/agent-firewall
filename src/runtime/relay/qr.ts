/**
 * A zero-dependency QR code encoder for the pairing link: byte mode, error
 * correction level M, versions 1 to 10 (up to 213 bytes, enough for the
 * pairing URL with room to spare), rendered for a terminal with Unicode half
 * blocks so two module rows fit one text line. Follows ISO/IEC 18004: Reed-
 * Solomon over GF(256) with 0x11D, interleaved blocks, the eight masks with
 * the standard penalty score, BCH-coded format and version information.
 */

/** Per version (index 1 to 10): EC codewords per block, and the data codewords of each block, for level M. */
const BLOCKS_M: readonly { ec: number; data: readonly number[] }[] = [
  { ec: 0, data: [] },
  { ec: 10, data: [16] },
  { ec: 16, data: [28] },
  { ec: 26, data: [44] },
  { ec: 18, data: [32, 32] },
  { ec: 24, data: [43, 43] },
  { ec: 16, data: [27, 27, 27, 27] },
  { ec: 18, data: [31, 31, 31, 31] },
  { ec: 22, data: [38, 38, 39, 39] },
  { ec: 22, data: [36, 36, 36, 37, 37] },
  { ec: 26, data: [43, 43, 43, 43, 44] },
];

const ALIGN: readonly (readonly number[])[] = [[], [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];

export const MAX_VERSION = 10;

export interface QrCode {
  version: number;
  size: number;
  /** modules[y][x], true = dark. */
  modules: boolean[][];
  mask: number;
}

function gfMul(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

function rsDivisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = gfMul(result[j] as number, root);
      if (j + 1 < degree) result[j] = (result[j] as number) ^ (result[j + 1] as number);
    }
    root = gfMul(root, 0x02);
  }
  return result;
}

/** The Reed-Solomon error-correction codewords of `data` (exported for the tests' syndrome check). */
export function rsRemainder(data: readonly number[], degree: number): number[] {
  const divisor = rsDivisor(degree);
  const result = new Array<number>(degree).fill(0);
  for (const b of data) {
    const factor = b ^ (result.shift() as number);
    result.push(0);
    for (let i = 0; i < degree; i++) result[i] = (result[i] as number) ^ gfMul(divisor[i] as number, factor);
  }
  return result;
}

function dataCapacity(version: number): number {
  return (BLOCKS_M[version] as { data: readonly number[] }).data.reduce((a, b) => a + b, 0);
}

/** The bytes in byte mode that fit level M at `version` (the count field is 8 bits to version 9, 16 from 10). */
export function byteCapacity(version: number): number {
  const countBits = version <= 9 ? 8 : 16;
  return Math.floor((dataCapacity(version) * 8 - 4 - countBits) / 8);
}

function dataCodewords(bytes: Uint8Array, version: number): number[] {
  const bits: number[] = [];
  const put = (v: number, n: number): void => {
    for (let i = n - 1; i >= 0; i--) bits.push((v >>> i) & 1);
  };
  put(0b0100, 4);
  put(bytes.length, version <= 9 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  const capBits = dataCapacity(version) * 8;
  put(0, Math.min(4, capBits - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);
  const out: number[] = [];
  for (let i = 0; i < bits.length; i += 8) out.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  for (let pad = 0xec; out.length < dataCapacity(version); pad ^= 0xec ^ 0x11) out.push(pad);
  return out;
}

/** Data and EC codewords interleaved as they are placed in the symbol. */
export function interleave(data: readonly number[], version: number): number[] {
  const spec = BLOCKS_M[version] as { ec: number; data: readonly number[] };
  const blocks: { d: number[]; e: number[] }[] = [];
  let k = 0;
  for (const n of spec.data) {
    const d = data.slice(k, k + n);
    k += n;
    blocks.push({ d, e: rsRemainder(d, spec.ec) });
  }
  const out: number[] = [];
  const maxD = Math.max(...spec.data);
  for (let i = 0; i < maxD; i++) for (const b of blocks) if (i < b.d.length) out.push(b.d[i] as number);
  for (let i = 0; i < spec.ec; i++) for (const b of blocks) out.push(b.e[i] as number);
  return out;
}

class Grid {
  readonly size: number;
  readonly modules: boolean[][];
  readonly fn: boolean[][];
  constructor(readonly version: number) {
    this.size = version * 4 + 17;
    this.modules = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
    this.fn = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
  }
  set(x: number, y: number, dark: boolean): void {
    (this.modules[y] as boolean[])[x] = dark;
    (this.fn[y] as boolean[])[x] = true;
  }
}

function drawFunctionPatterns(g: Grid): void {
  const s = g.size;
  for (let i = 0; i < s; i++) {
    g.set(6, i, i % 2 === 0);
    g.set(i, 6, i % 2 === 0);
  }
  const finder = (cx: number, cy: number): void => {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx;
        const y = cy + dy;
        if (x < 0 || y < 0 || x >= s || y >= s) continue;
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        g.set(x, y, d !== 2 && d !== 4);
      }
    }
  };
  finder(3, 3);
  finder(s - 4, 3);
  finder(3, s - 4);
  const pos = ALIGN[g.version] as readonly number[];
  const last = pos.length - 1;
  for (let i = 0; i < pos.length; i++) {
    for (let j = 0; j < pos.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) g.set((pos[i] as number) + dx, (pos[j] as number) + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }
  drawFormat(g, 0);
  if (g.version >= 7) {
    let rem = g.version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (g.version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = ((bits >>> i) & 1) !== 0;
      const a = s - 11 + (i % 3);
      const b = Math.floor(i / 3);
      g.set(a, b, bit);
      g.set(b, a, bit);
    }
  }
}

/** The 15 format bits for level M (00) and `mask`. Exported for the tests' reader. */
export function formatBits(mask: number): number {
  const data = (0b00 << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

function drawFormat(g: Grid, mask: number): void {
  const s = g.size;
  const bits = formatBits(mask);
  const bit = (i: number): boolean => ((bits >>> i) & 1) !== 0;
  for (let i = 0; i <= 5; i++) g.set(8, i, bit(i));
  g.set(8, 7, bit(6));
  g.set(8, 8, bit(7));
  g.set(7, 8, bit(8));
  for (let i = 9; i < 15; i++) g.set(14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) g.set(s - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) g.set(8, s - 15 + i, bit(i));
  g.set(8, s - 8, true);
}

/** The order modules are filled in: the zigzag over two-column strips, skipping function modules. */
export function placementOrder(fn: readonly (readonly boolean[])[], size: number): [number, number][] {
  const out: [number, number][] = [];
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!(fn[y] as readonly boolean[])[x]) out.push([x, y]);
      }
    }
  }
  return out;
}

export function maskBit(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0:
      return (x + y) % 2 === 0;
    case 1:
      return y % 2 === 0;
    case 2:
      return x % 3 === 0;
    case 3:
      return (x + y) % 3 === 0;
    case 4:
      return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5:
      return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6:
      return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    default:
      return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
  }
}

function penalty(m: readonly (readonly boolean[])[], size: number): number {
  let p = 0;
  const at = (x: number, y: number): boolean => (m[y] as readonly boolean[])[x] as boolean;
  for (const horizontal of [true, false]) {
    for (let a = 0; a < size; a++) {
      let run = 1;
      let line = "";
      for (let b = 0; b < size; b++) {
        const v = horizontal ? at(b, a) : at(a, b);
        line += v ? "1" : "0";
        if (b > 0) {
          const prev = horizontal ? at(b - 1, a) : at(a, b - 1);
          if (v === prev) run++;
          else {
            if (run >= 5) p += run - 2;
            run = 1;
          }
        }
      }
      if (run >= 5) p += run - 2;
      for (const pat of ["10111010000", "00001011101"]) for (let i = line.indexOf(pat); i !== -1; i = line.indexOf(pat, i + 1)) p += 40;
    }
  }
  let dark = 0;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (at(x, y)) dark++;
      if (x < size - 1 && y < size - 1) {
        const c = at(x, y);
        if (at(x + 1, y) === c && at(x, y + 1) === c && at(x + 1, y + 1) === c) p += 3;
      }
    }
  }
  const total = size * size;
  p += Math.max(0, Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
  return p;
}

/** The function-pattern map of a version (true = not a data module); for the tests' reader. */
export function functionModules(version: number): boolean[][] {
  const g = new Grid(version);
  drawFunctionPatterns(g);
  return g.fn;
}

/** The block structure at level M (EC codewords per block, data codewords per block); for the tests' reader. */
export function blocksM(version: number): { ec: number; data: readonly number[] } {
  return BLOCKS_M[version] as { ec: number; data: readonly number[] };
}

/** Encodes `text` (UTF-8) in the smallest version from 1 to 10 at level M. Throws when it does not fit. */
export function encodeQr(text: string): QrCode {
  const bytes = new TextEncoder().encode(text);
  let version = 1;
  while (version <= MAX_VERSION && byteCapacity(version) < bytes.length) version++;
  if (version > MAX_VERSION) throw new Error(`the pairing link is too long for a QR code (${bytes.length} bytes, at most ${byteCapacity(MAX_VERSION)})`);
  const codewords = interleave(dataCodewords(bytes, version), version);
  const base = new Grid(version);
  drawFunctionPatterns(base);
  const order = placementOrder(base.fn, base.size);
  let best: QrCode | null = null;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const g = new Grid(version);
    drawFunctionPatterns(g);
    order.forEach(([x, y], i) => {
      const dark = i < codewords.length * 8 ? (((codewords[i >>> 3] as number) >>> (7 - (i & 7))) & 1) === 1 : false;
      (g.modules[y] as boolean[])[x] = dark !== maskBit(mask, x, y);
    });
    drawFormat(g, mask);
    const score = penalty(g.modules, g.size);
    if (score < bestScore) {
      bestScore = score;
      best = { version, size: g.size, modules: g.modules, mask };
    }
  }
  return best as QrCode;
}

/**
 * Terminal lines for a QR code: two module rows per line with half blocks and a two-module quiet zone.
 * With ansi (a real terminal), black on white is forced, so it scans on dark and light themes alike;
 * without, dark modules are printed as blocks for a light background.
 */
export function renderQr(qr: QrCode, o: { ansi: boolean }): string[] {
  const q = 2;
  const n = qr.size + q * 2;
  const dark = (x: number, y: number): boolean => x >= q && y >= q && x < qr.size + q && y < qr.size + q && ((qr.modules[y - q] as boolean[])[x - q] as boolean);
  const lines: string[] = [];
  for (let y = 0; y < n; y += 2) {
    let line = "";
    for (let x = 0; x < n; x++) {
      const top = dark(x, y);
      const bottom = y + 1 < n && dark(x, y + 1);
      line += top && bottom ? "█" : top ? "▀" : bottom ? "▄" : " ";
    }
    lines.push(o.ansi ? `\u001b[30;47m${line}\u001b[0m` : line);
  }
  return lines;
}
