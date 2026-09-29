/**
 * GF(2^8) as AES defines it, hand-rolled.
 *
 * The field is GF(2)[x]/(m(x)) with m(x) = x^8 + x^4 + x^3 + x + 1, the
 * irreducible polynomial FIPS 197 section 4.2 fixes as 0x11b. Nothing here is a
 * precomputed constant lifted from a spec appendix: the S-box is BUILT from the
 * multiplicative inverse and the affine map of section 5.1.1, and `gf.test.ts`
 * then checks the result against the published table. That direction matters
 * for this lab in particular -- the whole point of a white-box implementation is
 * that the key is folded into tables, and the second DCA target is the
 * multiplicative inverse *inside* SubBytes, which only exists as a separate
 * object if the S-box was assembled rather than pasted.
 */

/** The AES reduction polynomial, x^8 + x^4 + x^3 + x + 1. */
export const AES_POLY = 0x11b;

/**
 * Multiply by x (i.e. by 0x02) in GF(2^8), reducing mod m(x) on overflow.
 * FIPS 197 section 4.2.1 calls this xtime.
 */
export function xtime(a: number): number {
  const shifted = a << 1;
  return (shifted & 0x100) !== 0 ? (shifted ^ AES_POLY) & 0xff : shifted & 0xff;
}

/** Multiplication in GF(2^8): shift-and-add over the bits of `b`. */
export function gmul(a: number, b: number): number {
  let acc = 0;
  let x = a & 0xff;
  let y = b & 0xff;
  while (y !== 0) {
    if ((y & 1) !== 0) acc ^= x;
    x = xtime(x);
    y >>= 1;
  }
  return acc & 0xff;
}

/**
 * The multiplicative inverse in GF(2^8), with 0 mapped to 0.
 *
 * Computed as a^254 = a^(2^8 - 2) by square-and-multiply, which is the field's
 * own definition (a^255 = 1 for every non-zero a) rather than a table lookup.
 * FIPS 197 section 5.1.1 defines SubBytes over exactly this map, and defines
 * the image of 0 to be 0 -- the one place the "inverse" is not an inverse.
 */
export function ginv(a: number): number {
  if ((a & 0xff) === 0) return 0;
  let result = 1;
  let base = a & 0xff;
  // 254 = 0b11111110.
  for (let bit = 0; bit < 8; bit++) {
    if ((254 >> bit) & 1) result = gmul(result, base);
    base = gmul(base, base);
  }
  return result;
}

/**
 * The affine transformation of FIPS 197 section 5.1.1, applied after the
 * inverse: b'_i = b_i ^ b_(i+4) ^ b_(i+5) ^ b_(i+6) ^ b_(i+7) ^ c_i, indices
 * mod 8, with the constant byte c = 0x63.
 */
export function sboxAffine(b: number): number {
  let out = 0;
  for (let i = 0; i < 8; i++) {
    const bit =
      ((b >> i) & 1) ^
      ((b >> ((i + 4) % 8)) & 1) ^
      ((b >> ((i + 5) % 8)) & 1) ^
      ((b >> ((i + 6) % 8)) & 1) ^
      ((b >> ((i + 7) % 8)) & 1) ^
      ((0x63 >> i) & 1);
    out |= bit << i;
  }
  return out;
}

function buildInverseTable(): Uint8Array {
  const table = new Uint8Array(256);
  for (let x = 0; x < 256; x++) table[x] = ginv(x);
  return table;
}

function buildSbox(inverses: Uint8Array): Uint8Array {
  const table = new Uint8Array(256);
  for (let x = 0; x < 256; x++) table[x] = sboxAffine(inverses[x]);
  return table;
}

function invert(table: Uint8Array): Uint8Array {
  const out = new Uint8Array(256);
  for (let x = 0; x < 256; x++) out[table[x]] = x;
  return out;
}

/** x -> x^-1 in GF(2^8), 0 -> 0. The inner half of SubBytes, and DCA target (b). */
export const GF_INV: Uint8Array = buildInverseTable();

/** The AES S-box, assembled from `GF_INV` and `sboxAffine`. */
export const SBOX: Uint8Array = buildSbox(GF_INV);

/** The inverse S-box, derived by inverting `SBOX` rather than transcribed. */
export const INV_SBOX: Uint8Array = invert(SBOX);

/**
 * The MixColumns matrix of FIPS 197 section 5.1.3, row-major.
 *
 * Chow's construction needs it column-wise as well -- the Ty_i tables in
 * `wb-gen.ts` are built from its COLUMNS -- so it is exported as the matrix
 * rather than as four hard-coded coefficient tuples.
 */
export const MIX_COLUMNS: readonly (readonly number[])[] = [
  [0x02, 0x03, 0x01, 0x01],
  [0x01, 0x02, 0x03, 0x01],
  [0x01, 0x01, 0x02, 0x03],
  [0x03, 0x01, 0x01, 0x02],
];

/**
 * Coefficient `MIX_COLUMNS[outRow][inRow]` times `value`.
 *
 * Chow's Ty_i tables (section 3.1) are built from the COLUMNS of the MixColumns
 * matrix: Ty_i spreads one input byte across all four output bytes of a column,
 * so the coefficient wanted is the one at (output row, input row).
 */
export function mixColumnByte(outRow: number, inRow: number, value: number): number {
  return gmul(MIX_COLUMNS[outRow][inRow], value);
}
