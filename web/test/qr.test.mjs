// The authenticator QR encoder and seed extraction, run with
// `node --test test/*.test.mjs` on the verification VPS.
import assert from "node:assert/strict";
import test from "node:test";
import { encodeQr, formatBits, rsRemainder, totpSecret } from "../app/utils/qr.ts";

const URI = "otpauth://totp/Sentinel:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Sentinel&algorithm=SHA1&digits=6&period=30";

test("Reed-Solomon codewords match the standard's HELLO WORLD 1-M example", () => {
  const data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17];
  assert.deepEqual([...rsRemainder(data, 10)], [196, 35, 39, 119, 235, 215, 231, 226, 93, 23]);
});

test("format bits are the standard's level M codewords", () => {
  // ISO/IEC 18004 table C.1, level M, masks 0..7.
  const expected = [0x5412, 0x5125, 0x5e7c, 0x5b4b, 0x45f9, 0x40ce, 0x4f97, 0x4aa0];
  for (let mask = 0; mask < 8; mask++) assert.equal(formatBits(mask), expected[mask], `mask ${mask}`);
});

function at(qr, x, y) { return qr.modules[y * qr.size + x] === 1; }

function finderAt(qr, ox, oy) {
  for (let dy = 0; dy < 7; dy++) {
    for (let dx = 0; dx < 7; dx++) {
      const d = Math.max(Math.abs(dx - 3), Math.abs(dy - 3));
      if (at(qr, ox + dx, oy + dy) !== (d !== 2)) return false;
    }
  }
  return true;
}

test("an otpauth URI encodes as a well-formed symbol of the smallest version", () => {
  const qr = encodeQr(URI);
  assert.ok(qr);
  // 119 bytes plus the header at level M need version 7 (124 data
  // codewords; version 6 has 108).
  assert.equal(qr.version, 7);
  assert.equal(qr.size, 45);
  assert.ok(finderAt(qr, 0, 0) && finderAt(qr, qr.size - 7, 0) && finderAt(qr, 0, qr.size - 7), "finder patterns");
  for (let i = 8; i < qr.size - 8; i++) {
    assert.equal(at(qr, i, 6), i % 2 === 0, `horizontal timing ${i}`);
    assert.equal(at(qr, 6, i), i % 2 === 0, `vertical timing ${i}`);
  }
  assert.ok(at(qr, 8, qr.size - 8), "dark module");
  // Both copies of the format information name level M and the chosen mask.
  const bits = formatBits(qr.mask);
  const first = [];
  for (let i = 0; i <= 5; i++) first.push(at(qr, 8, i));
  first.push(at(qr, 8, 7), at(qr, 8, 8), at(qr, 7, 8));
  for (let i = 9; i < 15; i++) first.push(at(qr, 14 - i, 8));
  const second = [];
  for (let i = 0; i < 8; i++) second.push(at(qr, qr.size - 1 - i, 8));
  for (let i = 8; i < 15; i++) second.push(at(qr, 8, qr.size - 15 + i));
  const want = [...Array(15)].map((_, i) => ((bits >>> i) & 1) === 1);
  assert.deepEqual(first, want);
  assert.deepEqual(second, want);
});

test("longer input grows the version and uses the 16-bit length field", () => {
  const qr = encodeQr(`otpauth://totp/Sentinel:${"a".repeat(200)}?secret=JBSWY3DPEHPK3PXP&issuer=Sentinel`);
  assert.ok(qr && qr.version >= 10);
  assert.equal(qr.size, qr.version * 4 + 17);
  assert.equal(encodeQr("x".repeat(3000)), null, "past version 40");
});

test("the seed is taken from the URI and grouped for typing", () => {
  assert.equal(totpSecret(URI), "JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP");
  assert.equal(totpSecret("otpauth://totp/x?issuer=S&secret=jbswy3dp%3D%3D"), "JBSW Y3DP");
  for (const bad of ["https://evil/?secret=JBSWY3DP", "otpauth://totp/x", "otpauth://totp/x?secret=not*base32", "otpauth://totp/x?secret="])
    assert.equal(totpSecret(bad), null, bad);
});
