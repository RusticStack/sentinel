// Dependency-free so the TOTP seed never leaves this page.

const ECC_PER_BLOCK = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28];
const BLOCKS = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49];
const LEVEL_M = 0;

export interface Qr { size: number; version: number; mask: number; modules: Uint8Array }

function rawModules(ver: number): number {
  let n = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const align = Math.floor(ver / 7) + 2;
    n -= (25 * align - 10) * align - 55;
    if (ver >= 7) n -= 36;
  }
  return n;
}

const dataCodewords = (ver: number) => (rawModules(ver) >> 3) - ECC_PER_BLOCK[ver]! * BLOCKS[ver]!;

function gfMul(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

function rsDivisor(degree: number): Uint8Array {
  const out = new Uint8Array(degree);
  out[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      out[j] = gfMul(out[j]!, root);
      if (j + 1 < degree) out[j]! ^= out[j + 1]!;
    }
    root = gfMul(root, 2);
  }
  return out;
}

export function rsRemainder(data: ArrayLike<number>, degree: number): Uint8Array {
  const divisor = rsDivisor(degree);
  const out = new Uint8Array(degree);
  for (let k = 0; k < data.length; k++) {
    const factor = data[k]! ^ out[0]!;
    out.copyWithin(0, 1);
    out[degree - 1] = 0;
    for (let i = 0; i < degree; i++) out[i]! ^= gfMul(divisor[i]!, factor);
  }
  return out;
}

function codewords(bytes: Uint8Array, ver: number): Uint8Array {
  const capacity = dataCodewords(ver);
  const data = new Uint8Array(capacity);
  let bit = 0;
  const put = (value: number, len: number) => {
    for (let i = len - 1; i >= 0; i--, bit++) if ((value >>> i) & 1) data[bit >> 3]! |= 0x80 >> (bit & 7);
  };
  put(0b0100, 4);
  put(bytes.length, ver < 10 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  put(0, Math.min(4, capacity * 8 - bit));
  bit = (bit + 7) & ~7;
  for (let i = bit >> 3, pad = 0xec; i < capacity; i++, pad ^= 0xec ^ 0x11) data[i] = pad;

  const blocks = BLOCKS[ver]!;
  const eccLen = ECC_PER_BLOCK[ver]!;
  const raw = rawModules(ver) >> 3;
  const short = blocks - (raw % blocks);
  const shortLen = Math.floor(raw / blocks);
  const parts: Uint8Array[] = [];
  for (let i = 0, k = 0; i < blocks; i++) {
    const len = shortLen - eccLen + (i < short ? 0 : 1);
    const block = new Uint8Array(shortLen + 1);
    const dat = data.subarray(k, k + len);
    block.set(dat);
    block.set(rsRemainder(dat, eccLen), shortLen + 1 - eccLen);
    parts.push(block);
    k += len;
  }
  const out = new Uint8Array(raw);
  let n = 0;
  for (let i = 0; i <= shortLen; i++) {
    for (let j = 0; j < blocks; j++) {
      // A short block has no byte at the long blocks' last data position.
      if (i !== shortLen - eccLen || j >= short) out[n++] = parts[j]![i]!;
    }
  }
  return out;
}

function alignmentPositions(ver: number, size: number): number[] {
  if (ver === 1) return [];
  const count = Math.floor(ver / 7) + 2;
  const step = Math.floor((ver * 8 + count * 3 + 5) / (count * 4 - 4)) * 2;
  const out = [6];
  for (let i = 0, pos = size - 7; i < count - 1; i++, pos -= step) out.splice(1, 0, pos);
  return out;
}

function penalty(m: Uint8Array, size: number): number {
  let score = 0;
  let dark = 0;
  const finder = (bits: number) => bits === 0b10111010000 || bits === 0b00001011101;
  for (let pass = 0; pass < 2; pass++) {
    for (let a = 0; a < size; a++) {
      let run = 0;
      let prev = -1;
      let window = 0;
      for (let b = 0; b < size; b++) {
        const v = pass === 0 ? m[a * size + b]! : m[b * size + a]!;
        if (pass === 0) dark += v;
        if (v === prev) {
          run++;
          if (run === 5) score += 3;
          else if (run > 5) score++;
        } else {
          prev = v;
          run = 1;
        }
        window = ((window << 1) | v) & 0x7ff;
        if (b >= 10 && finder(window)) score += 40;
      }
    }
  }
  for (let y = 0; y + 1 < size; y++) {
    for (let x = 0; x + 1 < size; x++) {
      const v = m[y * size + x]!;
      if (v === m[y * size + x + 1] && v === m[(y + 1) * size + x] && v === m[(y + 1) * size + x + 1]) score += 3;
    }
  }
  const total = size * size;
  return score + (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
}

function masked(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0: return (x + y) % 2 === 0;
    case 1: return y % 2 === 0;
    case 2: return x % 3 === 0;
    case 3: return (x + y) % 3 === 0;
    case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    default: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
  }
}

export function formatBits(mask: number): number {
  const data = (LEVEL_M << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

export function encodeQr(text: string): Qr | null {
  const bytes = new TextEncoder().encode(text);
  let ver = 1;
  while (ver <= 40 && bytes.length + (ver < 10 ? 2 : 3) > dataCodewords(ver)) ver++;
  if (ver > 40) return null;
  const size = ver * 4 + 17;
  const base = new Uint8Array(size * size);
  const fixed = new Uint8Array(size * size);
  const set = (x: number, y: number, dark: boolean) => {
    base[y * size + x] = dark ? 1 : 0;
    fixed[y * size + x] = 1;
  };

  for (let i = 0; i < size; i++) {
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]] as const) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx;
        const y = cy + dy;
        if (x < 0 || y < 0 || x >= size || y >= size) continue;
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        set(x, y, d !== 2 && d !== 4);
      }
    }
  }
  const align = alignmentPositions(ver, size);
  const last = align.length - 1;
  for (let i = 0; i <= last; i++) {
    for (let j = 0; j <= last; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) set(align[i]! + dx, align[j]! + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  }
  const drawFormat = (bits: number) => {
    const bit = (i: number) => ((bits >>> i) & 1) === 1;
    for (let i = 0; i <= 5; i++) set(8, i, bit(i));
    set(8, 7, bit(6));
    set(8, 8, bit(7));
    set(7, 8, bit(8));
    for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
    set(8, size - 8, true);
  };
  drawFormat(0); // reserve the format areas before the data is placed
  if (ver >= 7) {
    let rem = ver;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (ver << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) === 1;
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      set(a, b, dark);
      set(b, a, dark);
    }
  }

  const data = codewords(bytes, ver);
  const total = data.length * 8;
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    const upward = ((right + 1) & 2) === 0;
    for (let vert = 0; vert < size; vert++) {
      const y = upward ? size - 1 - vert : vert;
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        if (fixed[y * size + x] || i >= total) continue;
        base[y * size + x] = (data[i >> 3]! >>> (7 - (i & 7))) & 1;
        i++;
      }
    }
  }

  let best: Uint8Array | null = null;
  let bestMask = 0;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    drawFormat(formatBits(mask));
    const candidate = base.slice();
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) if (!fixed[y * size + x] && masked(mask, x, y)) candidate[y * size + x]! ^= 1;
    }
    const score = penalty(candidate, size);
    if (score < bestScore) {
      best = candidate;
      bestMask = mask;
      bestScore = score;
    }
  }
  return { size, version: ver, mask: bestMask, modules: best! };
}

export function qrPath(qr: Qr): string {
  let d = "";
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) if (qr.modules[y * qr.size + x]) d += `M${x + 4} ${y + 4}h1v1h-1z`;
  }
  return d;
}

export function totpSecret(uri: string): string | null {
  if (!uri.startsWith("otpauth://")) return null;
  const query = uri.indexOf("?");
  if (query < 0) return null;
  const secret = new URLSearchParams(uri.slice(query + 1)).get("secret");
  if (!secret || !/^[A-Z2-7]+=*$/i.test(secret)) return null;
  return secret.replace(/=+$/, "").toUpperCase().replace(/(.{4})(?=.)/g, "$1 ");
}
