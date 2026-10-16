#!/usr/bin/env node
/**
 * Generates the extension icons (icons/icon.svg and icons/icon-{16,32,48,128}.png)
 * from one geometry: a neutral shield with a check mark. No third-party brand,
 * no dependencies (the PNGs are rasterised here and written with node:zlib).
 * The outputs are committed; run `npm run icons` to regenerate them.
 */
import { deflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const OUT = join(resolve(dirname(fileURLToPath(import.meta.url)), ".."), "icons");
const SIZES = [16, 32, 48, 128];
const SHIELD = [31, 42, 68]; // #1F2A44: reads on light and dark toolbars
const MARK = [255, 255, 255];

/** The shield outline on a 128 grid: flat top, straight sides, a rounded point at the bottom. */
function shieldPoints() {
  const pts = [];
  const half = (y) => (y <= 60 ? 46 : 46 * Math.cos(((y - 60) / 60) * (Math.PI / 2)));
  for (let y = 10; y <= 120; y += 2) pts.push([64 - half(y), y]);
  for (let y = 120; y >= 10; y -= 2) pts.push([64 + half(y), y]);
  return pts;
}
const CHECK = [[38, 62], [57, 82], [92, 44]];
const CHECK_WIDTH = 11;

function inPolygon(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i];
    const [xj, yj] = poly[j];
    if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}
function distToSegment(px, py, [ax, ay], [bx, by]) {
  const dx = bx - ax;
  const dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}
const onCheck = (x, y) => CHECK_WIDTH / 2 >= Math.min(distToSegment(x, y, CHECK[0], CHECK[1]), distToSegment(x, y, CHECK[1], CHECK[2]));

function raster(size) {
  const poly = shieldPoints();
  const ss = 4;
  const px = Buffer.alloc(size * size * 4);
  for (let py = 0; py < size; py++) {
    for (let pxl = 0; pxl < size; pxl++) {
      let cover = 0;
      let mark = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const x = ((pxl + (sx + 0.5) / ss) * 128) / size;
          const y = ((py + (sy + 0.5) / ss) * 128) / size;
          if (!inPolygon(x, y, poly)) continue;
          cover++;
          if (onCheck(x, y)) mark++;
        }
      }
      const n = ss * ss;
      const i = (py * size + pxl) * 4;
      const m = cover === 0 ? 0 : mark / cover;
      for (let c = 0; c < 3; c++) px[i + c] = Math.round(SHIELD[c] * (1 - m) + MARK[c] * m);
      px[i + 3] = Math.round((cover / n) * 255);
    }
  }
  return px;
}

const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}
function png(size) {
  const rgba = raster(size);
  const rows = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) rgba.copy(rows, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(rows, { level: 9 })), chunk("IEND", Buffer.alloc(0))]);
}

function svg() {
  const d = shieldPoints().map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)} ${y}`).join(" ") + " Z";
  const hex = (c) => `#${c.map((v) => v.toString(16).padStart(2, "0")).join("")}`;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">\n  <path d="${d}" fill="${hex(SHIELD)}"/>\n  <polyline points="${CHECK.map((p) => p.join(",")).join(" ")}" fill="none" stroke="${hex(MARK)}" stroke-width="${CHECK_WIDTH}" stroke-linecap="butt" stroke-linejoin="miter"/>\n</svg>\n`;
}

mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, "icon.svg"), svg());
for (const s of SIZES) writeFileSync(join(OUT, `icon-${s}.png`), png(s));
console.info(`icons: wrote icon.svg and ${SIZES.map((s) => `icon-${s}.png`).join(", ")}`);
