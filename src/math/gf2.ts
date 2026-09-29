/**
 * Linear algebra over GF(2), for Chow's mixing bijections.
 *
 * Chow, Eisen, Johnson and van Oorschot (SAC 2002) section 3.2 inserts two
 * kinds of invertible GF(2)-linear map into the AES table network so that no
 * table's input or output is a plain AES value:
 *
 *   - an 8 x 8 matrix on every byte crossing a round boundary, and
 *   - a 32 x 32 matrix on every MixColumns result.
 *
 * The external encodings of section 3.3 are 128 x 128 maps on the whole block.
 * All three are the same object at different sizes, so this module implements
 * one representation -- rows of an n x n matrix, packed LSB-first into 32-bit
 * words -- and gives the two hot sizes their own straight-line evaluator,
 * because building the network multiplies 288 tables by 256 entries by a
 * 32 x 32 matrix-vector product.
 *
 * The bit convention is: row i of the matrix produces output bit i, and bit j
 * of that row selects input bit j. Nothing cryptographic depends on which end
 * is called bit 0 -- only on using the same end everywhere -- so the byte
 * packing lives in exactly one place (`blockDiagonal32` and `wordOfBytes`) and
 * every other function is convention-free.
 */

/** A square GF(2) matrix: `n` rows, each `words` 32-bit words, LSB-first. */
export interface BitMatrix {
  readonly n: number;
  readonly words: number;
  readonly rows: Uint32Array;
}

/** A source of uniform bytes. Implemented by `Rng` in `src/wb/rng.ts`. */
export interface ByteSource {
  bytes(count: number): Uint8Array;
}

export function bitMatrix(n: number): BitMatrix {
  const words = (n + 31) >> 5;
  return { n, words, rows: new Uint32Array(n * words) };
}

export function getBit(m: BitMatrix, row: number, col: number): number {
  return (m.rows[row * m.words + (col >> 5)] >>> (col & 31)) & 1;
}

export function setBit(m: BitMatrix, row: number, col: number, value: number): void {
  const index = row * m.words + (col >> 5);
  const mask = 1 << (col & 31);
  if (value & 1) m.rows[index] |= mask;
  else m.rows[index] &= ~mask;
}

export function identity(n: number): BitMatrix {
  const m = bitMatrix(n);
  for (let i = 0; i < n; i++) setBit(m, i, i, 1);
  return m;
}

/** The number of 1 bits in a 32-bit word, mod 2. */
export function parity32(x: number): number {
  let v = x ^ (x >>> 16);
  v ^= v >>> 8;
  v ^= v >>> 4;
  v ^= v >>> 2;
  v ^= v >>> 1;
  return v & 1;
}

/** Apply an 8 x 8 matrix (8 rows packed one per word) to a byte. */
export function apply8(rows: Uint8Array, v: number): number {
  let out = 0;
  for (let i = 0; i < 8; i++) out |= parity32(rows[i] & v) << i;
  return out & 0xff;
}

/** Apply a 32 x 32 matrix (32 rows, one word each) to a 32-bit word. */
export function apply32(rows: Uint32Array, v: number): number {
  let out = 0;
  for (let i = 0; i < 32; i++) out |= parity32(rows[i] & v) << i;
  return out >>> 0;
}

/** Apply a 128 x 128 matrix (128 rows of 4 words) to a 4-word vector. */
export function apply128(rows: Uint32Array, v: Uint32Array, out: Uint32Array): Uint32Array {
  out[0] = 0;
  out[1] = 0;
  out[2] = 0;
  out[3] = 0;
  for (let i = 0; i < 128; i++) {
    const base = i * 4;
    const bit =
      parity32(rows[base] & v[0]) ^
      parity32(rows[base + 1] & v[1]) ^
      parity32(rows[base + 2] & v[2]) ^
      parity32(rows[base + 3] & v[3]);
    if (bit) out[i >> 5] |= 1 << (i & 31);
  }
  return out;
}

/**
 * Gauss-Jordan elimination over GF(2), returning the inverse or `null` when the
 * matrix is singular. Row operations are XORs of whole packed rows, so the cost
 * is O(n^2 * words) word operations.
 */
export function invertMatrix(m: BitMatrix): BitMatrix | null {
  const { n, words } = m;
  const a = new Uint32Array(m.rows);
  const inv = identity(n);
  const b = inv.rows;

  for (let col = 0; col < n; col++) {
    let pivot = -1;
    for (let row = col; row < n; row++) {
      if ((a[row * words + (col >> 5)] >>> (col & 31)) & 1) {
        pivot = row;
        break;
      }
    }
    if (pivot < 0) return null;
    if (pivot !== col) {
      for (let w = 0; w < words; w++) {
        const t = a[pivot * words + w];
        a[pivot * words + w] = a[col * words + w];
        a[col * words + w] = t;
        const u = b[pivot * words + w];
        b[pivot * words + w] = b[col * words + w];
        b[col * words + w] = u;
      }
    }
    for (let row = 0; row < n; row++) {
      if (row === col) continue;
      if (!((a[row * words + (col >> 5)] >>> (col & 31)) & 1)) continue;
      for (let w = 0; w < words; w++) {
        a[row * words + w] ^= a[col * words + w];
        b[row * words + w] ^= b[col * words + w];
      }
    }
  }
  return inv;
}

/**
 * A uniformly random invertible n x n matrix over GF(2).
 *
 * Rejection sampling, not a product of elementary matrices: the density of
 * invertible matrices is prod_{i=1..n} (1 - 2^-i), which is 0.2887 for n >= 8,
 * so the expected number of draws is under 3.5 at every size used here. That
 * keeps the distribution exactly uniform over GL(n, 2), which a bounded product
 * of elementary operations would not.
 */
export function randomInvertible(n: number, rng: ByteSource): { m: BitMatrix; inv: BitMatrix; draws: number } {
  for (let draws = 1; ; draws++) {
    const m = bitMatrix(n);
    const raw = rng.bytes(n * m.words * 4);
    for (let i = 0; i < m.rows.length; i++) {
      const o = i * 4;
      m.rows[i] = ((raw[o] | (raw[o + 1] << 8) | (raw[o + 2] << 16) | (raw[o + 3] << 24)) >>> 0);
    }
    // Zero the bits past column n-1 so the matrix really is n x n.
    const slack = n & 31;
    if (slack !== 0) {
      const mask = (1 << slack) - 1;
      for (let row = 0; row < n; row++) m.rows[row * m.words + m.words - 1] &= mask;
    }
    const inv = invertMatrix(m);
    if (inv) return { m, inv, draws };
  }
}

/** The 8 rows of an 8 x 8 matrix as bytes, for `apply8`. */
export function rows8(m: BitMatrix): Uint8Array {
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) out[i] = m.rows[i] & 0xff;
  return out;
}

/** The 32 rows of a 32 x 32 matrix as words, for `apply32`. */
export function rows32(m: BitMatrix): Uint32Array {
  return new Uint32Array(m.rows.subarray(0, 32));
}

/**
 * Pack four bytes into the 32-bit word this lab uses for a MixColumns column:
 * byte 0 occupies bits 0-7, byte 1 bits 8-15, and so on.
 *
 * This is the ONLY place the byte order of a column word is decided, and
 * `blockDiagonal32` is the only other function that has to agree with it.
 */
export function wordOfBytes(b0: number, b1: number, b2: number, b3: number): number {
  return ((b0 & 0xff) | ((b1 & 0xff) << 8) | ((b2 & 0xff) << 16) | ((b3 & 0xff) << 24)) >>> 0;
}

/** Byte `index` (0-3) of a column word packed by `wordOfBytes`. */
export function byteOfWord(word: number, index: number): number {
  return (word >>> (index * 8)) & 0xff;
}

/**
 * The 32 x 32 block-diagonal matrix that applies four 8 x 8 matrices to the
 * four bytes of a column word. Chow needs this to push the per-byte mixing
 * bijections of round r through the same table that removes the 32-bit one.
 */
export function blockDiagonal32(blocks: readonly BitMatrix[]): BitMatrix {
  if (blocks.length !== 4) throw new Error('blockDiagonal32 expects exactly four 8 x 8 blocks');
  const out = bitMatrix(32);
  for (let b = 0; b < 4; b++) {
    for (let i = 0; i < 8; i++) {
      for (let j = 0; j < 8; j++) {
        if (getBit(blocks[b], i, j)) setBit(out, b * 8 + i, b * 8 + j, 1);
      }
    }
  }
  return out;
}
