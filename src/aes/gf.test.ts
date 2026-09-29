import { describe, expect, it } from 'vitest';
import { AES_POLY, GF_INV, gmul, ginv, INV_SBOX, MIX_COLUMNS, SBOX, sboxAffine, xtime } from './gf.js';

describe('GF(2^8) arithmetic', () => {
  it('uses the reduction polynomial FIPS 197 section 4.2 fixes', () => {
    expect(AES_POLY).toBe(0x11b);
  });

  it('xtime matches the worked examples in FIPS 197 section 4.2.1', () => {
    // {57} . {02} = {ae}, and {57} . {04} = {47} after one more reduction.
    expect(xtime(0x57)).toBe(0xae);
    expect(xtime(0xae)).toBe(0x47);
    expect(xtime(0x47)).toBe(0x8e);
  });

  it('reproduces the FIPS 197 section 4.2 product {57} . {83} = {c1}', () => {
    expect(gmul(0x57, 0x83)).toBe(0xc1);
  });

  it('is a commutative ring with 1 as its identity', () => {
    for (let a = 0; a < 256; a += 7) {
      expect(gmul(a, 1)).toBe(a);
      expect(gmul(a, 0)).toBe(0);
      for (let b = 0; b < 256; b += 11) expect(gmul(a, b)).toBe(gmul(b, a));
    }
  });

  it('gives every non-zero element exactly one inverse, and maps 0 to 0', () => {
    expect(ginv(0)).toBe(0);
    for (let a = 1; a < 256; a++) expect(gmul(a, ginv(a))).toBe(1);
    // A bijection on the 256 bytes, so the table is a permutation.
    expect(new Set(GF_INV).size).toBe(256);
  });

  it('agrees with the multiplicative order of the field: a^255 = 1', () => {
    for (let a = 1; a < 256; a++) {
      let acc = 1;
      for (let i = 0; i < 255; i++) acc = gmul(acc, a);
      expect(acc).toBe(1);
    }
  });
});

describe('the S-box, assembled rather than transcribed', () => {
  it('is the affine map of section 5.1.1 applied to the inverse', () => {
    for (let x = 0; x < 256; x++) expect(SBOX[x]).toBe(sboxAffine(GF_INV[x]));
  });

  // KAT: the published S-box values at the four corners of the FIPS 197
  // table (section 5.1.1, Figure 7) plus the two the standard's own prose
  // names. If the field arithmetic or the affine map is wrong, these move.
  it('matches the published S-box at the corners and named entries', () => {
    expect(SBOX[0x00]).toBe(0x63);
    expect(SBOX[0x0f]).toBe(0x76);
    expect(SBOX[0xf0]).toBe(0x8c);
    expect(SBOX[0xff]).toBe(0x16);
    expect(SBOX[0x53]).toBe(0xed);
    expect(SBOX[0x01]).toBe(0x7c);
  });

  // KAT: the first row of the FIPS 197 S-box table, verbatim from the standard.
  it('matches row 0 of the FIPS 197 S-box table', () => {
    const row0 = [
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ];
    expect([...SBOX.subarray(0, 16)]).toEqual(row0);
  });

  it('is a permutation, and INV_SBOX undoes it', () => {
    expect(new Set(SBOX).size).toBe(256);
    for (let x = 0; x < 256; x++) expect(INV_SBOX[SBOX[x]]).toBe(x);
  });
});

describe('the MixColumns matrix', () => {
  it('has the coefficients of FIPS 197 section 5.1.3 and no zero entry', () => {
    expect(MIX_COLUMNS.map((r) => [...r])).toEqual([
      [0x02, 0x03, 0x01, 0x01],
      [0x01, 0x02, 0x03, 0x01],
      [0x01, 0x01, 0x02, 0x03],
      [0x03, 0x01, 0x01, 0x02],
    ]);
    // Every coefficient being non-zero is what makes BGE's step A1 work at
    // all: the constant it perturbs has to move bijectively. See bge.ts.
    for (const row of MIX_COLUMNS) for (const c of row) expect(c).not.toBe(0);
  });
});
