/**
 * Chow's internal encodings, and the wires they live on.
 *
 * Chow et al. section 2.2 ("networked encoding") is the idea the whole
 * construction rests on: every table's output is scrambled by a secret bijection
 * and the next table's input is unscrambled by that bijection's inverse, so the
 * pair cancels at run time and neither table ever holds a plain AES value. A
 * bijection on 8 or 32 bits cannot be stored -- 2^32 entries -- so section 2.2
 * builds it as a CONCATENATION of 4-bit bijections, one per nibble. That nibble
 * width is the single most consequential parameter in the design: it is why
 * first-order DCA works (Bos et al., CHES 2016) and what Rivain and Wang
 * (TCHES 2019) later attacked at wider widths too.
 *
 * A "wire" here is one value passing between tables, described by the list of
 * nibble bijections riding on it: 2 for a byte, 8 for a 32-bit column word, 32
 * for a 128-bit block. Nibble n occupies bits 4n .. 4n+3, which is the same
 * convention `wordOfBytes` in `math/gf2.ts` uses for bytes -- so byte b of a
 * wire is nibbles 2b and 2b+1, and `sliceWire` is the only place that has to
 * know it.
 */

import { invertPermutation, randomPermutation, type Rng } from './rng.js';

/** A 4-bit bijection: 16 entries, a permutation of 0..15. */
export type Nibble = Uint8Array;

/** One value in transit, as the nibble bijections encoding it. */
export type Wire = readonly Nibble[];

export const NIBBLES_PER_BYTE = 2;
export const NIBBLES_PER_WORD = 8;
export const NIBBLES_PER_BLOCK = 32;

export function randomWire(nibbles: number, rng: Rng): Wire {
  const out: Nibble[] = [];
  for (let n = 0; n < nibbles; n++) out.push(randomPermutation(16, rng));
  return out;
}

/**
 * An un-encoded wire. Used where the program meets the outside world: with no
 * external encoding the first tables read plaintext bytes and the last write
 * ciphertext bytes, so those wires carry the identity and nothing else would be
 * correct.
 */
export function identityWire(nibbles: number): Wire {
  const id = new Uint8Array(16);
  for (let i = 0; i < 16; i++) id[i] = i;
  const out: Nibble[] = [];
  for (let n = 0; n < nibbles; n++) out.push(id);
  return out;
}

export function invertWire(w: Wire): Wire {
  return w.map((n) => invertPermutation(n));
}

/** Nibbles [start, start + count) of a wire, as a wire of their own. */
export function sliceWire(w: Wire, start: number, count: number): Wire {
  return w.slice(start, start + count);
}

/** Byte `index` of a wire, as a 2-nibble wire. */
export function byteWire(w: Wire, index: number): Wire {
  return sliceWire(w, index * NIBBLES_PER_BYTE, NIBBLES_PER_BYTE);
}

/** Apply a wire's bijections to a value of up to 32 bits. */
export function encodeNumber(w: Wire, value: number): number {
  let out = 0;
  for (let n = 0; n < w.length; n++) out |= w[n][(value >>> (4 * n)) & 15] << (4 * n);
  return out >>> 0;
}

/** Apply a wire's bijections to a 128-bit value held as four 32-bit words. */
export function encodeVector(w: Wire, v: Uint32Array, out: Uint32Array): Uint32Array {
  out[0] = 0;
  out[1] = 0;
  out[2] = 0;
  out[3] = 0;
  for (let n = 0; n < w.length; n++) {
    const word = n >> 3;
    const shift = (n & 7) * 4;
    out[word] |= w[n][(v[word] >>> shift) & 15] << shift;
  }
  return out;
}

/**
 * A 4-bit XOR table (Chow's Type IV), as a 256-entry byte table.
 *
 * The index packs the two ENCODED input nibbles into one byte -- left in the
 * high nibble, right in the low -- which is exactly the shape a table lookup
 * takes in a compiled implementation, and the reason the trace samples DCA
 * reads are lookup arguments rather than plain values. The table decodes both,
 * XORs, and re-encodes under the output wire's bijection.
 *
 * Only the low nibble of each entry is meaningful; the high nibble is zero. The
 * lab reports the allocated size of these tables honestly (256 bytes each) and
 * says where the packed 128-byte figure in the literature comes from.
 */
export function xorTable(left: Nibble, right: Nibble, out: Nibble, into: Uint8Array, offset: number): void {
  const decLeft = invertPermutation(left);
  const decRight = invertPermutation(right);
  for (let a = 0; a < 16; a++) {
    for (let b = 0; b < 16; b++) {
      into[offset + ((a << 4) | b)] = out[decLeft[a] ^ decRight[b]];
    }
  }
}

/**
 * Build a whole wire's worth of XOR tables: one per nibble position, writing
 * `nibbles * 256` bytes at `offset`. Returns the number of tables written, so
 * the caller's inventory count is derived from the build rather than asserted
 * alongside it.
 */
export function xorWireTables(
  left: Wire,
  right: Wire,
  out: Wire,
  into: Uint8Array,
  offset: number,
): number {
  if (left.length !== right.length || left.length !== out.length) {
    throw new Error('an XOR tree step needs three wires of the same width');
  }
  for (let n = 0; n < left.length; n++) xorTable(left[n], right[n], out[n], into, offset + n * 256);
  return left.length;
}

/** Look up one encoded nibble pair in a Type IV table. */
export function xorLookup(tables: Uint8Array, offset: number, nibble: number, left: number, right: number): number {
  return tables[offset + nibble * 256 + (((left & 15) << 4) | (right & 15))];
}
