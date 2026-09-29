/**
 * BGE, step A1: strip the non-linear part of a round's output encodings.
 *
 * Billet, Gilbert and Ech-Chatbi, "Cryptanalysis of a White Box AES
 * Implementation", SAC 2004, LNCS 3357, 227-240. (The third author is Charaf
 * ECH-CHATBI. Some secondary sources expand BGE wrongly; this lab does not.)
 *
 * BGE is the other half of the story DCA tells. It needs NO traces, no chosen
 * inputs and no execution at all -- it reads the tables. Its published work
 * factor is 2^30 with negligible memory, and Lepoint, Rivain, De Mulder, Roelse
 * and Preneel (SAC 2013) later cut that to 2^22. The published attack covers
 * Chow's construction including the external input and output encodings Chow
 * specifies, which is why "hold the encodings outside the program" stops DCA and
 * does not make the key unextractable.
 *
 * WHAT THIS FILE RUNS, AND WHAT IT DOES NOT. Step A1 is implemented and executed
 * live, on the real tables, in the browser. Steps A2 (pinning the affine parts,
 * which needs the affine-equivalence algorithm of Biryukov, De Canniere, Braeken
 * and Preneel, EUROCRYPT 2003) and A3 (extracting the round key) are NOT run
 * here. The page says so in those words and prints the published figures rather
 * than animating a computation that is not happening.
 *
 * THE OBSERVATION A1 RESTS ON. Composing one round's tables for one column gives
 * a function of four bytes to four bytes in which every internal 4-bit encoding
 * and the whole 32-bit mixing bijection have cancelled -- they were inverse pairs
 * on wires inside the column. What survives is
 *
 *     R_j(x)_i = P_i( sum_n  a_(i,n) . S( Q_n^-1(x_n) ^ k_n ) )
 *
 * with P_i and Q_n byte bijections and a_(i,n) the MixColumns coefficients. So
 * the nibble width Chow chose is not an algebraic obstacle at all: it is gone
 * before the attack starts. That is the thing this act exists to show, and it is
 * shown by computing it.
 *
 * Fix bytes 1..3 and vary byte 0. Then f_i^(b)(x) = R_j(x, b, 0, 0)_i is
 *
 *     P_i( a . S(Q_0^-1(x)) ^ g_i(b) )
 *
 * where g_i is a bijection of b because every MixColumns coefficient is non-zero.
 * So the set { f_i^(b) o (f_i^(0))^-1 : b } is
 *
 *     { P_i o (^ d) o P_i^-1 : d in GF(2^8) }
 *
 * -- a group of 256 permutations isomorphic to (GF(2^8), ^). Choosing a GF(2)
 * basis of that group and reading off coordinates gives P_i^-1 up to an unknown
 * GF(2)-affine map, which is exactly what A1 claims.
 *
 * INVARIANT I2. This module imports the table GEOMETRY (`wb/layout.ts`) and
 * nothing that knows a secret. It never sees the key, the encodings, the mixing
 * bijections or the remote party.
 */

import { ROUNDS_WITH_MIXCOLUMNS, typeIIIOffset, typeIIOffset, typeIVOffset, xorEncodedWord } from '../wb/layout.js';

/** Just the tables a column walk needs. Handed over as data, not imported. */
export interface ColumnTables {
  readonly typeII: Uint32Array;
  readonly typeIII: Uint32Array;
  readonly typeIVa: Uint8Array;
  readonly typeIVb: Uint8Array;
}

/**
 * Walk one column of one round, from its four encoded input bytes to its four
 * encoded output bytes.
 *
 * `round` is 1-based. This is the same walk `wb-run.ts` does, re-derived here
 * from the tables so the attack depends on the program's shape and not on the
 * program's code.
 */
export function columnFunction(
  tables: ColumnTables,
  round: number,
  column: number,
  input: Uint8Array,
  out: Uint8Array,
): Uint8Array {
  const r = round - 1;
  const w0 = tables.typeII[typeIIOffset(r, column, 0) + input[0]];
  const w1 = tables.typeII[typeIIOffset(r, column, 1) + input[1]];
  const w2 = tables.typeII[typeIIOffset(r, column, 2) + input[2]];
  const w3 = tables.typeII[typeIIOffset(r, column, 3) + input[3]];
  const a01 = xorEncodedWord(tables.typeIVa, typeIVOffset(r, column, 0), w0, w1);
  const a23 = xorEncodedWord(tables.typeIVa, typeIVOffset(r, column, 1), w2, w3);
  const mixed = xorEncodedWord(tables.typeIVa, typeIVOffset(r, column, 2), a01, a23);
  const y0 = tables.typeIII[typeIIIOffset(r, column, 0) + (mixed & 0xff)];
  const y1 = tables.typeIII[typeIIIOffset(r, column, 1) + ((mixed >>> 8) & 0xff)];
  const y2 = tables.typeIII[typeIIIOffset(r, column, 2) + ((mixed >>> 16) & 0xff)];
  const y3 = tables.typeIII[typeIIIOffset(r, column, 3) + ((mixed >>> 24) & 0xff)];
  const b01 = xorEncodedWord(tables.typeIVb, typeIVOffset(r, column, 0), y0, y1);
  const b23 = xorEncodedWord(tables.typeIVb, typeIVOffset(r, column, 1), y2, y3);
  const col = xorEncodedWord(tables.typeIVb, typeIVOffset(r, column, 2), b01, b23);
  out[0] = col & 0xff;
  out[1] = (col >>> 8) & 0xff;
  out[2] = (col >>> 16) & 0xff;
  out[3] = (col >>> 24) & 0xff;
  return out;
}

function composePermutations(outer: Uint8Array, inner: Uint8Array, into: Uint8Array): Uint8Array {
  for (let x = 0; x < 256; x++) into[x] = outer[inner[x]];
  return into;
}

function invertPermutation(p: Uint8Array): Uint8Array {
  const out = new Uint8Array(256);
  for (let x = 0; x < 256; x++) out[p[x]] = x;
  return out;
}

function isPermutation(p: Uint8Array): boolean {
  const seen = new Uint8Array(256);
  for (let x = 0; x < 256; x++) {
    if (seen[p[x]]) return false;
    seen[p[x]] = 1;
  }
  return true;
}

function keyOf(p: Uint8Array): string {
  // A stable identity for a permutation, so group membership is a map lookup.
  return String.fromCharCode.apply(null, Array.from(p) as number[]);
}

/** BGE's failure codes. Surfaced in the UI; each has a claims-suite assertion. */
export const BGE_FAILURE_CODES = [
  'ROUND_OUT_OF_RANGE',
  'COLUMN_OUT_OF_RANGE',
  'NOT_A_BIJECTION',
  'GROUP_NOT_ELEMENTARY_ABELIAN',
  'GROUP_ORDER_WRONG',
] as const;
export type BgeFailureCode = (typeof BGE_FAILURE_CODES)[number];

export class BgeError extends Error {
  constructor(
    readonly code: BgeFailureCode,
    message: string,
  ) {
    super(message);
    this.name = 'BgeError';
  }
}

export interface BgeByteResult {
  readonly row: number;
  /** The recovered map, equal to the true output encoding's inverse up to a GF(2)-affine map. */
  readonly recovered: Uint8Array;
  /** Size of the group extracted from the tables. Must be 256. */
  readonly groupOrder: number;
  /** Every non-identity element must be its own inverse. */
  readonly everyElementIsAnInvolution: boolean;
  /** The eight group elements chosen as a GF(2) basis, as their delta coordinates. */
  readonly basis: readonly number[];
  /**
   * Distinct values of f^(b)(x) ^ f^(b')(x) over the 256 values of x, BEFORE the
   * recovered map is applied. More than one means the encoding is still there.
   */
  readonly spreadBefore: number;
  /** The same count after. Exactly 1 is what A1 achieves. */
  readonly spreadAfter: number;
}

export interface BgeResult {
  readonly round: number;
  readonly column: number;
  readonly bytes: readonly BgeByteResult[];
  /** Column-function evaluations performed. The measured cost of the step. */
  readonly evaluations: number;
  readonly elapsedMs: number;
  /** True only when all four output encodings were stripped to affine. */
  readonly stripped: boolean;
}

/**
 * Run step A1 on one column of one round.
 *
 * Cost: 2^16 column evaluations to tabulate f_i^(b) for every b, then a few
 * hundred thousand permutation operations per output byte. Both are measured and
 * reported rather than asserted.
 */
export function runBgeStepA1(tables: ColumnTables, round: number, column: number): BgeResult {
  const startedAt = Date.now();
  if (!Number.isInteger(round) || round < 1 || round > ROUNDS_WITH_MIXCOLUMNS) {
    throw new BgeError('ROUND_OUT_OF_RANGE', `only rounds 1 to ${ROUNDS_WITH_MIXCOLUMNS} have a column to attack`);
  }
  if (!Number.isInteger(column) || column < 0 || column > 3) {
    throw new BgeError('COLUMN_OUT_OF_RANGE', 'a round has four columns, 0 to 3');
  }

  // f[i][b] as a 256-entry permutation: x -> R(x, b, 0, 0)_i.
  const f: Uint8Array[][] = [[], [], [], []];
  for (let i = 0; i < 4; i++) for (let b = 0; b < 256; b++) f[i].push(new Uint8Array(256));
  const input = new Uint8Array(4);
  const out = new Uint8Array(4);
  let evaluations = 0;
  for (let b = 0; b < 256; b++) {
    input[1] = b;
    input[2] = 0;
    input[3] = 0;
    for (let x = 0; x < 256; x++) {
      input[0] = x;
      columnFunction(tables, round, column, input, out);
      evaluations++;
      for (let i = 0; i < 4; i++) f[i][b][x] = out[i];
    }
  }

  const results: BgeByteResult[] = [];
  const scratch = new Uint8Array(256);
  for (let i = 0; i < 4; i++) {
    if (!isPermutation(f[i][0])) {
      throw new BgeError('NOT_A_BIJECTION', `row ${i} of round ${round} column ${column} is not a bijection in x`);
    }
    const baseInverse = invertPermutation(f[i][0]);

    // The group  { f^(b) o (f^(0))^-1 }  =  { P o (^ delta) o P^-1 }.
    const elements: Uint8Array[] = [];
    const index = new Map<string, number>();
    for (let b = 0; b < 256; b++) {
      const g = composePermutations(f[i][b], baseInverse, new Uint8Array(256));
      const k = keyOf(g);
      if (!index.has(k)) {
        index.set(k, elements.length);
        elements.push(g);
      }
    }
    if (elements.length !== 256) {
      throw new BgeError(
        'GROUP_ORDER_WRONG',
        `the extracted group has ${elements.length} elements, and an isomorphic copy of (GF(2^8), XOR) has 256`,
      );
    }
    let allInvolutions = true;
    for (const g of elements) {
      composePermutations(g, g, scratch);
      for (let x = 0; x < 256; x++) {
        if (scratch[x] !== x) {
          allInvolutions = false;
          break;
        }
      }
      if (!allInvolutions) break;
    }
    if (!allInvolutions) {
      throw new BgeError(
        'GROUP_NOT_ELEMENTARY_ABELIAN',
        'an element of the extracted group is not its own inverse, so it is not (GF(2^8), XOR)',
      );
    }

    // A GF(2) basis, found greedily: take any element not yet in the span, and
    // extend the span by composing it with everything already reachable. When
    // the span reaches 256 the group IS that span, which proves closure without
    // a separate 2^16-composition check.
    const coordinate = new Map<string, number>();
    const identity = new Uint8Array(256);
    for (let x = 0; x < 256; x++) identity[x] = x;
    coordinate.set(keyOf(identity), 0);
    const spanned: Uint8Array[] = [identity];
    const basis: number[] = [];
    for (const g of elements) {
      const k = keyOf(g);
      if (coordinate.has(k)) continue;
      const bit = 1 << basis.length;
      basis.push(bit);
      const grown = spanned.length;
      for (let s = 0; s < grown; s++) {
        const product = composePermutations(g, spanned[s], new Uint8Array(256));
        const pk = keyOf(product);
        const value = bit | (coordinate.get(keyOf(spanned[s])) ?? 0);
        if (!coordinate.has(pk)) {
          coordinate.set(pk, value);
          spanned.push(product);
        }
      }
      if (spanned.length === 256) break;
    }
    if (spanned.length !== 256 || basis.length !== 8) {
      throw new BgeError(
        'GROUP_NOT_ELEMENTARY_ABELIAN',
        `the group spans ${spanned.length} elements from ${basis.length} generators, not 256 from 8`,
      );
    }

    // The regular action: for each y there is exactly one group element taking
    // the base point to y, and its coordinate is the recovered value.
    const recovered = new Uint8Array(256);
    const filled = new Uint8Array(256);
    for (const g of spanned) {
      const y = g[0];
      recovered[y] = coordinate.get(keyOf(g)) ?? 0;
      filled[y] = 1;
    }
    if (!isPermutation(recovered) || filled.some((v) => v === 0)) {
      throw new BgeError('NOT_A_BIJECTION', 'the recovered encoding is not a bijection, so the action was not regular');
    }

    // The secret-free verification, and the thing to put on screen: for two
    // choices of the fixed byte, f^(b)(x) ^ f^(b')(x) varies with x, and after
    // the recovered map is applied the difference is ONE value for every x.
    const before = new Set<number>();
    const after = new Set<number>();
    for (let x = 0; x < 256; x++) {
      before.add(f[i][1][x] ^ f[i][7][x]);
      after.add(recovered[f[i][1][x]] ^ recovered[f[i][7][x]]);
    }

    results.push({
      row: i,
      recovered,
      groupOrder: elements.length,
      everyElementIsAnInvolution: allInvolutions,
      basis,
      spreadBefore: before.size,
      spreadAfter: after.size,
    });
  }

  return {
    round,
    column,
    bytes: results,
    evaluations,
    elapsedMs: Date.now() - startedAt,
    stripped: results.every((r) => r.spreadAfter === 1 && r.groupOrder === 256),
  };
}

/**
 * Is `t` a GF(2)-affine map? The property step A1 leaves behind, and the one
 * step A2 would have to remove.
 *
 * Checked over all 2^16 pairs: an affine map satisfies
 * t(u ^ v) = t(u) ^ t(v) ^ t(0) for every u and v.
 */
export function isAffineOverGF2(t: Uint8Array): boolean {
  const zero = t[0];
  for (let u = 0; u < 256; u++) {
    for (let v = 0; v < 256; v++) {
      if (t[u ^ v] !== (t[u] ^ t[v] ^ zero)) return false;
    }
  }
  return true;
}

/**
 * The published complexity figures, so the page can print them as citations
 * rather than as things this lab measured.
 */
export const PUBLISHED_WORK_FACTORS = {
  bge2004: {
    exponent: 30,
    source:
      'Billet, Gilbert and Ech-Chatbi, SAC 2004; the decomposition is set out in Muir, ePrint 2013/104, section 5.1',
  },
  lepoint2013: { exponent: 22, source: 'Lepoint, Rivain, De Mulder, Roelse and Preneel, SAC 2013' },
} as const;
