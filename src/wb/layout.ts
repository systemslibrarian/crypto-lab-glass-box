/**
 * The table network's geometry: how many tables of each type there are and where
 * each one sits in its flat array.
 *
 * This is PUBLIC information in the threat model white-box cryptography assumes.
 * An attacker holding the program can read its table layout off the binary; Chow
 * et al. never claim otherwise, and BGE's algebraic attack starts from exactly
 * this knowledge. So `src/attack/bge.ts` imports this file, and invariant I2
 * still holds: what the attack may not import is `wb-gen.ts` (which knows the key
 * and the encodings) and `remote-enc.ts` (which holds the external ones).
 * `isolation.test.ts` reads the imports and enforces that distinction.
 */

export const ROUNDS_WITH_MIXCOLUMNS = 9;
export const COLUMNS = 4;
export const ROWS = 4;
/** Three XOR steps sum four words: (a ^ b), (c ^ d), then those two. */
export const TREE_STEPS = 3;
export const NIBBLES_PER_WORD = 8;
/** A 16-way XOR tree over 128-bit values: 8 + 4 + 2 + 1 steps. */
export const BLOCK_TREE_STEPS = 15;
export const NIBBLES_PER_BLOCK = 32;

export const TYPE_II_LENGTH = ROUNDS_WITH_MIXCOLUMNS * COLUMNS * ROWS * 256;
export const TYPE_III_LENGTH = TYPE_II_LENGTH;
export const TYPE_IV_LENGTH = ROUNDS_WITH_MIXCOLUMNS * COLUMNS * TREE_STEPS * NIBBLES_PER_WORD * 256;
export const TYPE_V_LENGTH = 16 * 256;

/** `round` is 0-based here: round 1 of the cipher is index 0. */
export const typeIIOffset = (round: number, col: number, row: number): number =>
  ((round * COLUMNS + col) * ROWS + row) << 8;

export const typeIIIOffset = (round: number, col: number, byte: number): number =>
  ((round * COLUMNS + col) * ROWS + byte) << 8;

/** Offset of the eight nibble tables belonging to one XOR-tree step. */
export const typeIVOffset = (round: number, col: number, step: number): number =>
  ((round * COLUMNS + col) * TREE_STEPS + step) * NIBBLES_PER_WORD * 256;

/** XOR two encoded 32-bit words through eight Type IV nibble tables. */
export function xorEncodedWord(tables: Uint8Array, offset: number, left: number, right: number): number {
  let out = 0;
  for (let n = 0; n < 8; n++) {
    const shift = n * 4;
    out |= tables[offset + n * 256 + ((((left >>> shift) & 15) << 4) | ((right >>> shift) & 15))] << shift;
  }
  return out >>> 0;
}
