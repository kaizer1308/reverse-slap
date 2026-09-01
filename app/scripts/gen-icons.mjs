// app/scripts/gen-icons.mjs
//
// Generates the bundle icons from the brand source image at
// src/assets/reverse-slop-icon.png. Tauri needs a set of PNGs plus an ICO at
// build time; `tauri icon` requires the tauri CLI to fetch its own tooling, so
// the resampling happens here: the source is decoded, area-averaged down to
// each target size, and re-encoded, all with node:zlib, no image library
//
// Run with: npm run icons

import { deflateSync, inflateSync } from "node:zlib";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const sourcePath = join(scriptDir, "..", "src", "assets", "reverse-slop-icon.png");
const outDir = join(scriptDir, "..", "src-tauri", "icons");
mkdirSync(outDir, { recursive: true });

const kSig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const crcTable = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

// decoding

/** Decode an 8-bit non-interlaced PNG (colour types 2 RGB and 6 RGBA) to RGBA. */
function decodePng(buf) {
  if (!buf.subarray(0, 8).equals(kSig)) throw new Error("source is not a PNG");

  let width = 0;
  let height = 0;
  let bitDepth = 0;
  let colorType = 0;
  let interlace = 0;
  const idat = [];

  let off = 8;
  while (off < buf.length) {
    const len = buf.readUInt32BE(off);
    const type = buf.toString("ascii", off + 4, off + 8);
    const data = buf.subarray(off + 8, off + 8 + len);
    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      bitDepth = data[8];
      colorType = data[9];
      interlace = data[12];
    } else if (type === "IDAT") {
      idat.push(data);
    } else if (type === "IEND") {
      break;
    }
    off += 12 + len;
  }

  if (bitDepth !== 8) throw new Error(`unsupported bit depth ${bitDepth} (need 8)`);
  if (interlace !== 0) throw new Error("interlaced PNGs are not supported");
  const channels = colorType === 2 ? 3 : colorType === 6 ? 4 : 0;
  if (!channels) throw new Error(`unsupported colour type ${colorType} (need RGB/RGBA)`);

  const raw = inflateSync(Buffer.concat(idat));
  const stride = width * channels;
  const out = Buffer.alloc(width * height * 4);
  const row = Buffer.alloc(stride);
  const prev = Buffer.alloc(stride);

  const paeth = (a, b, c) => {
    const p = a + b - c;
    const pa = Math.abs(p - a);
    const pb = Math.abs(p - b);
    const pc = Math.abs(p - c);
    return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
  };

  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)];
    raw.copy(row, 0, y * (stride + 1) + 1, (y + 1) * (stride + 1));
    for (let i = 0; i < stride; i++) {
      const left = i >= channels ? row[i - channels] : 0;
      const up = prev[i];
      const upLeft = i >= channels ? prev[i - channels] : 0;
      if (filter === 1) row[i] = (row[i] + left) & 0xff;
      else if (filter === 2) row[i] = (row[i] + up) & 0xff;
      else if (filter === 3) row[i] = (row[i] + ((left + up) >> 1)) & 0xff;
      else if (filter === 4) row[i] = (row[i] + paeth(left, up, upLeft)) & 0xff;
    }
    for (let x = 0; x < width; x++) {
      const s = x * channels;
      const d = (y * width + x) * 4;
      out[d] = row[s];
      out[d + 1] = row[s + 1];
      out[d + 2] = row[s + 2];
      out[d + 3] = channels === 4 ? row[s + 3] : 255;
    }
    row.copy(prev);
  }
  return { width, height, rgba: out };
}

// resampling

/** Area-average downscale: each destination pixel averages the source pixels
 *  it covers, with fractional weights at the box edges. */
function resample(src, sw, sh, dw, dh) {
  const dst = Buffer.alloc(dw * dh * 4);
  const sx = sw / dw;
  const sy = sh / dh;
  for (let dy = 0; dy < dh; dy++) {
    const y0 = dy * sy;
    const y1 = y0 + sy;
    for (let dx = 0; dx < dw; dx++) {
      const x0 = dx * sx;
      const x1 = x0 + sx;
      let r = 0;
      let g = 0;
      let b = 0;
      let a = 0;
      let wsum = 0;
      for (let yy = Math.floor(y0); yy < Math.min(Math.ceil(y1), sh); yy++) {
        const wy = Math.min(y1, yy + 1) - Math.max(y0, yy);
        if (wy <= 0) continue;
        for (let xx = Math.floor(x0); xx < Math.min(Math.ceil(x1), sw); xx++) {
          const wx = Math.min(x1, xx + 1) - Math.max(x0, xx);
          if (wx <= 0) continue;
          const w = wx * wy;
          const i = (yy * sw + xx) * 4;
          r += src[i] * w;
          g += src[i + 1] * w;
          b += src[i + 2] * w;
          a += src[i + 3] * w;
          wsum += w;
        }
      }
      const d = (dy * dw + dx) * 4;
      dst[d] = Math.round(r / wsum);
      dst[d + 1] = Math.round(g / wsum);
      dst[d + 2] = Math.round(b / wsum);
      dst[d + 3] = Math.round(a / wsum);
    }
  }
  return dst;
}

// encoding

function png(size, px) {
  const stride = size * 4;
  const filtered = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y++) {
    filtered[y * (stride + 1)] = 0; // filter type: none
    px.copy(filtered, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type: RGBA
  return Buffer.concat([
    kSig,
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(filtered, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function ico(frames) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(frames.length, 4);

  let offset = 6 + 16 * frames.length;
  const entries = frames.map(({ size, data }) => {
    const e = Buffer.alloc(16);
    e[0] = size >= 256 ? 0 : size; // 0 encodes 256
    e[1] = size >= 256 ? 0 : size;
    e.writeUInt16LE(1, 4); // planes
    e.writeUInt16LE(32, 6); // bit count
    e.writeUInt32LE(data.length, 8);
    e.writeUInt32LE(offset, 12);
    offset += data.length;
    return e;
  });
  return Buffer.concat([header, ...entries, ...frames.map((f) => f.data)]);
}

// generate

const source = decodePng(readFileSync(sourcePath));
console.log(`source: ${source.width}x${source.height} ${sourcePath}`);

const sizes = [32, 128, 256, 512];
const rendered = new Map(sizes.map((s) => [s, resample(source.rgba, source.width, source.height, s, s)]));
for (const s of [16, 48, 64]) rendered.set(s, resample(source.rgba, source.width, source.height, s, s));

const written = [];
for (const size of sizes) {
  const name = size === 512 ? "icon.png" : `${size}x${size}.png`;
  writeFileSync(join(outDir, name), png(size, rendered.get(size)));
  written.push(name);
}
writeFileSync(join(outDir, "128x128@2x.png"), png(256, rendered.get(256)));
written.push("128x128@2x.png");
writeFileSync(
  join(outDir, "icon.ico"),
  ico([16, 32, 48, 64, 128, 256].map((s) => ({ size: s, data: png(s, rendered.get(s)) }))),
);
written.push("icon.ico");

console.log(`wrote ${written.length} icons to src-tauri/icons: ${written.join(", ")}`);
