/**
 * Build a Chow-style white-box AES-128 from a key.
 *
 * Chow, Eisen, Johnson and van Oorschot, "White-Box Cryptography and an AES
 * Implementation" (SAC 2002). The construction turns AES into a network of
 * lookup tables with the key folded in, so that a program which computes
 * AES_K contains no byte, word or matrix equal to K.
 *
 * THE REORDERING (Chow section 2.3). ShiftRows is a byte permutation and
 * AddRoundKey/SubBytes are byte-wise, so a round can be rewritten as
 *
 *     ShiftRows  ->  T-box (add a pre-shifted round key, then SubBytes)  ->  MixColumns
 *
 * which lets a single 256-entry table hold "XOR this key byte, then S-box". The
 * key never appears; only S(x ^ k) for all 256 x does. `aes-ref.test.ts` pins
 * the arithmetic this depends on, and `wb-run.test.ts` checks the built network
 * against FIPS 197 and against WebCrypto.
 *
 * THE TABLE TYPES (Chow section 3, with Muir's ePrint 2013/104 naming):
 *
 *   Type II   8 -> 32  MB_j . Ty_i(S(L^-1(x) ^ k)).  One per row per column per
 *                      round: the T-box, the MixColumns column it feeds, and the
 *                      32-bit mixing bijection, fused into one table.
 *   Type IV   8 -> 4   A nibble XOR. Four 32-bit words are summed by a tree of
 *                      these, 8 per 32-bit XOR, 3 XORs per tree.
 *   Type III  8 -> 32  MB_j^-1 restricted to one input byte, with the next
 *                      round's 8-bit mixing bijections applied to each output
 *                      byte. Four of them, summed by a second Type IV tree.
 *   Type V    8 -> 8   Round 10, which has no MixColumns.
 *   Type IA   8 -> 128 An external encoding, fanned out and summed by a 15-step
 *                      Type IV tree. Only present when the mode has one.
 *
 * WHAT THE ENCODINGS DO, AND WHY THE MIXING BIJECTIONS ARE NOT OPTIONAL. Every
 * wire between two tables carries a secret 4-bit bijection per nibble
 * (`encoding.ts`), and the 8-bit and 32-bit GF(2) mixing bijections of Chow
 * section 3.2 sit under them. Dropping the mixing bijections would make the
 * lab's pictures simpler and the construction a different, weaker object: the
 * T-box output would be a nibble-encoded S-box output, and the encodings could
 * be peeled off one byte at a time. They are built here at full size.
 *
 * DETERMINISM ACROSS MODES. Every draw the AES core needs is taken BEFORE any
 * external section is built, and the core's endpoint wires are drawn whether or
 * not the mode uses them. So one seed gives a byte-identical core in all five
 * Act 5 states -- which is what makes "compiling the encodings in changes
 * nothing DCA reads" a comparison rather than a claim.
 */

import { expandKey, SHIFT_ROWS, shiftRows } from '../aes/aes-ref.js';
import { mixColumnByte, SBOX } from '../aes/gf.js';
import {
  byteWire,
  encodeNumber,
  encodeVector,
  identityWire,
  invertWire,
  NIBBLES_PER_BLOCK,
  NIBBLES_PER_WORD,
  randomWire,
  type Wire,
  xorWireTables,
} from './encoding.js';
import { apply128, apply32, apply8, byteOfWord, randomInvertible, rows32, rows8, wordOfBytes } from '../math/gf2.js';
import {
  BLOCK_TREE_STEPS,
  COLUMNS,
  ROUNDS_WITH_MIXCOLUMNS,
  ROWS,
  TREE_STEPS,
  typeIIIOffset,
  typeIIOffset,
  typeIVOffset,
  TYPE_II_LENGTH,
  TYPE_III_LENGTH,
  TYPE_IV_LENGTH,
  TYPE_V_LENGTH,
} from './layout.js';
import type { Rng } from './rng.js';
import type {
  EncodingPlacement,
  ExternalEncodingHandover,
  LinearSection,
  NetworkInventory,
  TableGroup,
  WhiteBoxNetwork,
} from './types.js';

/**
 * Ty_i of Chow section 3.1: one input byte spread across a MixColumns column.
 *
 * `row` is the input row i; the result's byte m is MC[m][i] . value, so summing
 * Ty_i(Y[i, j]) over i = 0..3 is exactly MixColumns on column j.
 */
export function tyTable(row: number, value: number): number {
  return wordOfBytes(
    mixColumnByte(0, row, value),
    mixColumnByte(1, row, value),
    mixColumnByte(2, row, value),
    mixColumnByte(3, row, value),
  );
}

interface CoreWires {
  /** Output wire of each Type II table. */
  readonly t2: Wire[][][];
  /** Output wires of the three steps of each Type II XOR tree. */
  readonly treeA: Wire[][][];
  /** Output wire of each Type III table. */
  readonly t3: Wire[][][];
  /** Output wires of the three steps of each Type III XOR tree. */
  readonly treeB: Wire[][][];
  readonly coreInput: Wire;
  readonly coreOutput: Wire;
}

function nest<T>(rounds: number, cols: number, inner: number, make: () => T): T[][][] {
  const out: T[][][] = [];
  for (let r = 0; r < rounds; r++) {
    const perRound: T[][] = [];
    for (let c = 0; c < cols; c++) {
      const perCol: T[] = [];
      for (let k = 0; k < inner; k++) perCol.push(make());
      perRound.push(perCol);
    }
    out.push(perRound);
  }
  return out;
}

function drawCoreWires(rng: Rng): CoreWires {
  // Drawn in a fixed order that does not depend on the placement, so a seed
  // pins the core across all five Act 5 states.
  return {
    t2: nest(ROUNDS_WITH_MIXCOLUMNS, COLUMNS, ROWS, () => randomWire(NIBBLES_PER_WORD, rng)),
    treeA: nest(ROUNDS_WITH_MIXCOLUMNS, COLUMNS, TREE_STEPS, () => randomWire(NIBBLES_PER_WORD, rng)),
    t3: nest(ROUNDS_WITH_MIXCOLUMNS, COLUMNS, ROWS, () => randomWire(NIBBLES_PER_WORD, rng)),
    treeB: nest(ROUNDS_WITH_MIXCOLUMNS, COLUMNS, TREE_STEPS, () => randomWire(NIBBLES_PER_WORD, rng)),
    coreInput: randomWire(NIBBLES_PER_BLOCK, rng),
    coreOutput: randomWire(NIBBLES_PER_BLOCK, rng),
  };
}

/** The placement's answer to "does the program strip an input encoding?" */
function hasInputEncoding(placement: EncodingPlacement): boolean {
  return placement === 'compiled-in' || placement === 'remote-both' || placement === 'remote-input';
}

/** ...and "does it add an output encoding?" */
function hasOutputEncoding(placement: EncodingPlacement): boolean {
  return placement === 'compiled-in' || placement === 'remote-both' || placement === 'remote-output';
}

/**
 * Build a 128-bit linear map as 16 fan-out tables plus a 15-step XOR tree.
 *
 * The endpoint wires are given by the caller: a value crossing the program's
 * boundary is un-encoded, and one staying inside is not. The tree's internal
 * wires are always freshly encoded, so even the un-protected wrapper sections of
 * the `compiled-in` mode leak nothing through their intermediates -- which
 * matters, because those intermediates are in the trace.
 */
function buildLinearSection(
  id: LinearSection['id'],
  label: string,
  matrixRows: Uint32Array,
  inputWire: Wire,
  outputWire: Wire,
  rng: Rng,
): LinearSection {
  const fan = new Uint32Array(16 * 256 * 4);
  const xor = new Uint8Array(BLOCK_TREE_STEPS * NIBBLES_PER_BLOCK * 256);

  const fanWires: Wire[] = [];
  for (let b = 0; b < 16; b++) fanWires.push(randomWire(NIBBLES_PER_BLOCK, rng));
  const level0: Wire[] = [];
  for (let s = 0; s < 8; s++) level0.push(randomWire(NIBBLES_PER_BLOCK, rng));
  const level1: Wire[] = [];
  for (let s = 0; s < 4; s++) level1.push(randomWire(NIBBLES_PER_BLOCK, rng));
  const level2: Wire[] = [];
  for (let s = 0; s < 2; s++) level2.push(randomWire(NIBBLES_PER_BLOCK, rng));

  const v = new Uint32Array(4);
  const y = new Uint32Array(4);
  const enc = new Uint32Array(4);
  for (let b = 0; b < 16; b++) {
    const dec = invertWire(byteWire(inputWire, b));
    for (let x = 0; x < 256; x++) {
      const plain = (dec[0][x & 15] | (dec[1][(x >> 4) & 15] << 4)) & 0xff;
      v[0] = 0;
      v[1] = 0;
      v[2] = 0;
      v[3] = 0;
      v[b >> 2] = plain << ((b & 3) * 8);
      apply128(matrixRows, v, y);
      encodeVector(fanWires[b], y, enc);
      const at = (b * 256 + x) * 4;
      fan[at] = enc[0];
      fan[at + 1] = enc[1];
      fan[at + 2] = enc[2];
      fan[at + 3] = enc[3];
    }
  }

  let step = 0;
  const writeStep = (left: Wire, right: Wire, out: Wire): void => {
    xorWireTables(left, right, out, xor, step * NIBBLES_PER_BLOCK * 256);
    step++;
  };
  for (let s = 0; s < 8; s++) writeStep(fanWires[2 * s], fanWires[2 * s + 1], level0[s]);
  for (let s = 0; s < 4; s++) writeStep(level0[2 * s], level0[2 * s + 1], level1[s]);
  for (let s = 0; s < 2; s++) writeStep(level1[2 * s], level1[2 * s + 1], level2[s]);
  writeStep(level2[0], level2[1], outputWire);

  return { id, label, fan, xor, inputWire, outputWire };
}

function inventoryOf(network: {
  typeII: Uint32Array;
  typeIII: Uint32Array;
  typeIVa: Uint8Array;
  typeIVb: Uint8Array;
  typeV: Uint8Array;
  preCore: readonly LinearSection[];
  postCore: readonly LinearSection[];
}): NetworkInventory {
  const sections = [...network.preCore, ...network.postCore];
  const groups: TableGroup[] = [
    {
      id: 'type-ii',
      label: 'Type II (8 -> 32)',
      count: network.typeII.length / 256,
      entryBytes: 256 * 4,
      bytes: network.typeII.byteLength,
      note: 'T-box, one MixColumns column and the 32-bit mixing bijection, fused',
    },
    {
      id: 'type-iii',
      label: 'Type III (8 -> 32)',
      count: network.typeIII.length / 256,
      entryBytes: 256 * 4,
      bytes: network.typeIII.byteLength,
      note: 'removes the 32-bit mixing bijection, applies the next round’s 8-bit ones',
    },
    {
      id: 'type-iv',
      label: 'Type IV (8 -> 4)',
      count: (network.typeIVa.length + network.typeIVb.length) / 256,
      entryBytes: 256,
      bytes: network.typeIVa.byteLength + network.typeIVb.byteLength,
      note: 'nibble XOR; eight sum one 32-bit word, three steps sum four of them',
    },
    {
      id: 'type-v',
      label: 'Type V (8 -> 8)',
      count: network.typeV.length / 256,
      entryBytes: 256,
      bytes: network.typeV.byteLength,
      note: 'round 10, which has no MixColumns',
    },
  ];
  if (sections.length > 0) {
    groups.push({
      id: 'type-ia',
      label: 'Type IA/IB (8 -> 128)',
      count: (sections.length * 16 * 256 * 4) / (256 * 4),
      entryBytes: 256 * 16,
      bytes: sections.reduce((n, s) => n + s.fan.byteLength, 0),
      note: `external encodings: ${sections.map((s) => s.label).join(', ')}`,
    });
    groups.push({
      id: 'type-iv-ext',
      label: 'Type IV, external (8 -> 4)',
      count: sections.reduce((n, s) => n + s.xor.length / 256, 0),
      entryBytes: 256,
      bytes: sections.reduce((n, s) => n + s.xor.byteLength, 0),
      note: 'the 15-step trees that sum each 128-bit fan-out',
    });
  }
  const tables = groups.reduce((n, g) => n + g.count, 0);
  const bytes = groups.reduce((n, g) => n + g.bytes, 0);
  // The literature stores two 4-bit entries per byte. Reported beside the
  // allocated figure so neither number has to be taken on trust.
  const packedBytes = groups.reduce((n, g) => n + (g.entryBytes === 256 ? g.bytes / 2 : g.bytes), 0);
  return { groups, tables, bytes, packedBytes };
}

/**
 * The byte bijections sitting on a round-column boundary -- what BGE calls the
 * output encodings P_i of that round's column.
 *
 * This exists for ONE reason: `bge.test.ts` verifies that the attack's recovered
 * encoding really is the true one up to a GF(2)-affine map, and that is not a
 * property a secret-free check can establish. It costs nothing, because the
 * attack modules cannot import this file at all -- `isolation.test.ts` reads
 * their imports and fails if they do. The UI never calls it either.
 */
export interface BuildInternals {
  /** P for round r (1-based), column j, row i: plain Z_r[i, j] -> the encoded byte. */
  outputByteBijection(round: number, column: number, row: number): Uint8Array;
}

// [extension] point -- TWO THINGS THIS FUNCTION IS THE SEAM FOR.
//
// A MASKED white-box variant splits every value on every wire into shares and
// builds the tables over the shares. It changes `buildNetwork` and nothing
// else: the evaluator, the tracer and both attacks work on whatever tables they
// are handed, which is why they take tables rather than a generator.
//
// IMPORTING SOMEONE ELSE'S TABLES -- the SideChannelMarvels "Deadpool"
// challenge set is the obvious source -- needs a loader that produces a
// `WhiteBoxNetwork` without a key, plus a `BuildReport` that admits there is no
// ground truth to compare a recovery against, so invariant I3's reveal has to
// become "here is what came out" rather than "here is what came out, and it is
// right". Check each challenge's licence before shipping its tables.

export interface BuildResult {
  readonly network: WhiteBoxNetwork;
  readonly handover: ExternalEncodingHandover;
  readonly internals: BuildInternals;
}

/**
 * Build the network. `key` is used here and nowhere the attack can reach: the
 * tables are the only thing that leaves this function, and the key travels to
 * the invariant-I3 comparison by a separate channel (see `lab.worker.ts`).
 */
export function buildNetwork(key: Uint8Array, placement: EncodingPlacement, rng: Rng): BuildResult {
  const startedAt = Date.now();
  const roundKeys = expandKey(key);
  /** SR(k^r) for r = 0..9, so a T-box can add the key after ShiftRows. */
  const shifted: Uint8Array[] = [];
  for (let r = 0; r < 10; r++) shifted.push(shiftRows(roundKeys.subarray(16 * r, 16 * r + 16)));
  const lastRoundKey = roundKeys.subarray(160, 176);

  let matrixDraws = 0;

  // ── Chow section 3.2: the mixing bijections ──────────────────────────────
  // L[r][m]: an 8 x 8 bijection on state byte m leaving round r (r = 1..9).
  // MB[r][j]: a 32 x 32 bijection on column j's MixColumns result.
  const L: Uint8Array[][] = [];
  const Linv: Uint8Array[][] = [];
  const MBinv: Uint32Array[][] = [];
  const MB: Uint32Array[][] = [];
  for (let r = 0; r < ROUNDS_WITH_MIXCOLUMNS; r++) {
    const rowL: Uint8Array[] = [];
    const rowLi: Uint8Array[] = [];
    for (let m = 0; m < 16; m++) {
      const drawn = randomInvertible(8, rng);
      matrixDraws += drawn.draws;
      rowL.push(rows8(drawn.m));
      rowLi.push(rows8(drawn.inv));
    }
    L.push(rowL);
    Linv.push(rowLi);
    const rowMB: Uint32Array[] = [];
    const rowMBi: Uint32Array[] = [];
    for (let j = 0; j < COLUMNS; j++) {
      const drawn = randomInvertible(32, rng);
      matrixDraws += drawn.draws;
      rowMB.push(rows32(drawn.m));
      rowMBi.push(rows32(drawn.inv));
    }
    MB.push(rowMB);
    MBinv.push(rowMBi);
  }
  const wires = drawCoreWires(rng);

  const typeII = new Uint32Array(TYPE_II_LENGTH);
  const typeIII = new Uint32Array(TYPE_III_LENGTH);
  const typeIVa = new Uint8Array(TYPE_IV_LENGTH);
  const typeIVb = new Uint8Array(TYPE_IV_LENGTH);
  const typeV = new Uint8Array(TYPE_V_LENGTH);

  const identity32Nibbles = identityWire(NIBBLES_PER_BLOCK);
  const coreInputWire = hasInputEncoding(placement) ? wires.coreInput : identity32Nibbles;
  const coreOutputWire = hasOutputEncoding(placement) ? wires.coreOutput : identity32Nibbles;

  /** The encoded byte a Type II table at (r, j, i) reads. */
  const typeIIInputWire = (r: number, j: number, i: number): Wire => {
    const source = SHIFT_ROWS[i + 4 * j];
    if (r === 0) return byteWire(coreInputWire, source);
    // Byte i of column (source >> 2) of the previous round's second XOR tree.
    return byteWire(wires.treeB[r - 1][source >> 2][2], source & 3);
  };

  for (let r = 0; r < ROUNDS_WITH_MIXCOLUMNS; r++) {
    for (let j = 0; j < COLUMNS; j++) {
      for (let i = 0; i < ROWS; i++) {
        const m = i + 4 * j;
        const source = SHIFT_ROWS[m];
        const dec = invertWire(typeIIInputWire(r, j, i));
        const out = wires.t2[r][j][i];
        const keyByte = shifted[r][m];
        const unmix = r === 0 ? null : Linv[r - 1][source];
        const base = typeIIOffset(r, j, i);
        for (let x = 0; x < 256; x++) {
          const decoded = (dec[0][x & 15] | (dec[1][(x >> 4) & 15] << 4)) & 0xff;
          const plain = unmix === null ? decoded : apply8(unmix, decoded);
          const sboxed = SBOX[plain ^ keyByte];
          typeII[base + x] = encodeNumber(out, apply32(MB[r][j], tyTable(i, sboxed)));
        }
      }

      // The first XOR tree: (t2_0 ^ t2_1), (t2_2 ^ t2_3), then those two.
      const a = wires.t2[r][j];
      const tA = wires.treeA[r][j];
      xorWireTables(a[0], a[1], tA[0], typeIVa, typeIVOffset(r, j, 0));
      xorWireTables(a[2], a[3], tA[1], typeIVa, typeIVOffset(r, j, 1));
      xorWireTables(tA[0], tA[1], tA[2], typeIVa, typeIVOffset(r, j, 2));

      // Type III: strip MB_j, then apply the next round's 8-bit bijections to
      // each output byte. Summing the four results gives blockDiag(L) . Z_r[.,j]
      // because both maps are GF(2)-linear.
      for (let b = 0; b < ROWS; b++) {
        const dec = invertWire(byteWire(tA[2], b));
        const out = wires.t3[r][j][b];
        const base = typeIIIOffset(r, j, b);
        for (let x = 0; x < 256; x++) {
          const decoded = (dec[0][x & 15] | (dec[1][(x >> 4) & 15] << 4)) & 0xff;
          const placed = (decoded << (b * 8)) >>> 0;
          const stripped = apply32(MBinv[r][j], placed);
          const mixed = wordOfBytes(
            apply8(L[r][0 + 4 * j], byteOfWord(stripped, 0)),
            apply8(L[r][1 + 4 * j], byteOfWord(stripped, 1)),
            apply8(L[r][2 + 4 * j], byteOfWord(stripped, 2)),
            apply8(L[r][3 + 4 * j], byteOfWord(stripped, 3)),
          );
          typeIII[base + x] = encodeNumber(out, mixed);
        }
      }

      const c = wires.t3[r][j];
      const tB = wires.treeB[r][j];
      xorWireTables(c[0], c[1], tB[0], typeIVb, typeIVOffset(r, j, 0));
      xorWireTables(c[2], c[3], tB[1], typeIVb, typeIVOffset(r, j, 1));
      xorWireTables(tB[0], tB[1], tB[2], typeIVb, typeIVOffset(r, j, 2));
    }
  }

  // ── Round 10: no MixColumns, so one 8 -> 8 table per state byte ──────────
  for (let m = 0; m < 16; m++) {
    const source = SHIFT_ROWS[m];
    const dec = invertWire(byteWire(wires.treeB[ROUNDS_WITH_MIXCOLUMNS - 1][source >> 2][2], source & 3));
    const out = byteWire(coreOutputWire, m);
    const unmix = Linv[ROUNDS_WITH_MIXCOLUMNS - 1][source];
    for (let x = 0; x < 256; x++) {
      const decoded = (dec[0][x & 15] | (dec[1][(x >> 4) & 15] << 4)) & 0xff;
      const plain = apply8(unmix, decoded);
      const value = SBOX[plain ^ shifted[ROUNDS_WITH_MIXCOLUMNS][m]] ^ lastRoundKey[m];
      typeV[(m << 8) + x] = encodeNumber(out, value);
    }
  }

  // ── Chow section 3.3: the external encodings ─────────────────────────────
  const wantsExternal = hasInputEncoding(placement) || hasOutputEncoding(placement);
  const drawnF = wantsExternal ? randomInvertible(128, rng) : null;
  const drawnG = wantsExternal ? randomInvertible(128, rng) : null;
  if (drawnF) matrixDraws += drawnF.draws;
  if (drawnG) matrixDraws += drawnG.draws;

  const preCore: LinearSection[] = [];
  const postCore: LinearSection[] = [];

  if (placement === 'compiled-in' && drawnF && drawnG) {
    // The encoder is in the binary, so the program applies F and then strips it.
    preCore.push(
      buildLinearSection('encode-in', 'F, the input encoder', drawnF.m.rows, identity32Nibbles, identity32Nibbles, rng),
    );
  }
  if (hasInputEncoding(placement) && drawnF) {
    preCore.push(
      buildLinearSection(
        'strip-in',
        'F⁻¹, stripped inside the core',
        drawnF.inv.rows,
        identity32Nibbles,
        coreInputWire,
        rng,
      ),
    );
  }
  if (hasOutputEncoding(placement) && drawnG) {
    postCore.push(
      buildLinearSection(
        'add-out',
        'G, applied inside the core',
        drawnG.m.rows,
        coreOutputWire,
        identity32Nibbles,
        rng,
      ),
    );
  }
  if (placement === 'compiled-in' && drawnG) {
    postCore.push(
      buildLinearSection(
        'decode-out',
        'G⁻¹, the output decoder',
        drawnG.inv.rows,
        identity32Nibbles,
        identity32Nibbles,
        rng,
      ),
    );
  }

  const partial = { typeII, typeIII, typeIVa, typeIVb, typeV, preCore, postCore };
  const network: WhiteBoxNetwork = {
    placement,
    ...partial,
    coreInputWire,
    coreOutputWire,
    inventory: inventoryOf(partial),
    matrixDraws,
    buildMs: Date.now() - startedAt,
  };
  const handover: ExternalEncodingHandover = {
    inputRows: drawnF ? drawnF.m.rows : new Uint32Array(0),
    outputInverseRows: drawnG ? drawnG.inv.rows : new Uint32Array(0),
    present: wantsExternal,
  };
  const internals: BuildInternals = {
    outputByteBijection(round: number, column: number, row: number): Uint8Array {
      if (round < 1 || round > ROUNDS_WITH_MIXCOLUMNS) throw new Error('rounds 1 to 9 have column boundaries');
      const r = round - 1;
      const wire = byteWire(wires.treeB[r][column][2], row);
      const mix = L[r][row + 4 * column];
      const table = new Uint8Array(256);
      for (let u = 0; u < 256; u++) table[u] = encodeNumber(wire, apply8(mix, u));
      return table;
    },
  };
  return { network, handover, internals };
}
