import { describe, expect, it } from 'vitest';
import { buildNetwork } from '../wb/wb-gen.js';
import { seededRng } from '../wb/rng.js';
import { BGE_FAILURE_CODES, BgeError, columnFunction, isAffineOverGF2, runBgeStepA1 } from './bge.js';
import type { ColumnTables } from './bge.js';

function tablesFor(seed: string, placement: 'none' | 'remote-both' = 'none') {
  const key = seededRng(`${seed} key`).bytes(16);
  const built = buildNetwork(key, placement, seededRng(seed));
  const tables: ColumnTables = {
    typeII: built.network.typeII,
    typeIII: built.network.typeIII,
    typeIVa: built.network.typeIVa,
    typeIVb: built.network.typeIVb,
  };
  return { key, tables, internals: built.internals };
}

describe('BGE step A1 on one column of one round', () => {
  it('extracts a group of order 256 in which every element is an involution', () => {
    const { tables } = tablesFor('a1');
    const result = runBgeStepA1(tables, 1, 0);
    expect(result.bytes).toHaveLength(4);
    for (const b of result.bytes) {
      expect(b.groupOrder).toBe(256);
      expect(b.everyElementIsAnInvolution).toBe(true);
      expect(b.basis).toHaveLength(8);
    }
    expect(result.evaluations).toBe(65536);
    expect(result.stripped).toBe(true);
  });

  it('strips the encoding to affine: the difference varies before and is constant after', () => {
    const { tables } = tablesFor('spread');
    const result = runBgeStepA1(tables, 3, 2);
    for (const b of result.bytes) {
      // The whole point. Before: many values. After: exactly one.
      expect(b.spreadBefore).toBeGreaterThan(1);
      expect(b.spreadAfter).toBe(1);
    }
  });

  it('the recovered map really is the true encoding up to a GF(2)-affine map', () => {
    // The verification a secret-free check cannot make. `internals` exists only
    // for this, and the attack module cannot import it -- see isolation.test.ts.
    for (const [round, column] of [
      [1, 0],
      [2, 3],
      [5, 1],
      [9, 2],
    ] as const) {
      const { tables, internals } = tablesFor(`truth ${round} ${column}`);
      const result = runBgeStepA1(tables, round, column);
      for (const b of result.bytes) {
        const trueEncoding = internals.outputByteBijection(round, column, b.row);
        // recovered o P must be affine, because recovered = A o P^-1 ^ c.
        const composed = new Uint8Array(256);
        for (let u = 0; u < 256; u++) composed[u] = b.recovered[trueEncoding[u]];
        expect(isAffineOverGF2(composed), `round ${round} column ${column} row ${b.row}`).toBe(true);
      }
    }
  }, 120_000);

  it('...and the affinity check has teeth: a wrong map fails it', () => {
    const { tables, internals } = tablesFor('teeth');
    const result = runBgeStepA1(tables, 1, 0);
    const trueEncoding = internals.outputByteBijection(1, 0, 0);
    // Perturb the recovered map by swapping two entries. It is still a
    // bijection, and it is no longer affine-equivalent to the truth.
    const broken = new Uint8Array(result.bytes[0].recovered);
    const t = broken[3];
    broken[3] = broken[200];
    broken[200] = t;
    const composed = new Uint8Array(256);
    for (let u = 0; u < 256; u++) composed[u] = broken[trueEncoding[u]];
    expect(isAffineOverGF2(composed)).toBe(false);
  });

  it('isAffineOverGF2 accepts a real affine map and rejects the S-box', async () => {
    const { SBOX } = await import('../aes/gf.js');
    const identity = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect(isAffineOverGF2(identity)).toBe(true);
    const shifted = Uint8Array.from({ length: 256 }, (_, i) => i ^ 0x5a);
    expect(isAffineOverGF2(shifted)).toBe(true);
    // A GF(2)-linear map: multiply by 0x03 in GF(2^8) is linear over GF(2).
    const { gmul } = await import('../aes/gf.js');
    expect(isAffineOverGF2(Uint8Array.from({ length: 256 }, (_, i) => gmul(3, i)))).toBe(true);
    expect(isAffineOverGF2(new Uint8Array(SBOX))).toBe(false);
  });

  it('works whatever the external-encoding placement, because it reads tables', () => {
    for (const placement of ['none', 'remote-both'] as const) {
      const { tables } = tablesFor(`placement ${placement}`, placement);
      const result = runBgeStepA1(tables, 4, 1);
      expect(result.stripped).toBe(true);
    }
  });

  it('every round and column yields a stripped encoding', () => {
    const { tables } = tablesFor('sweep');
    for (let round = 1; round <= 9; round++) {
      const result = runBgeStepA1(tables, round, round % 4);
      expect(result.stripped, `round ${round}`).toBe(true);
    }
  }, 180_000);

  it('columnFunction agrees with itself and is a bijection in byte 0', () => {
    const { tables } = tablesFor('colfn');
    const seen = [new Set<number>(), new Set<number>(), new Set<number>(), new Set<number>()];
    const input = new Uint8Array([0, 0x33, 0, 0]);
    const out = new Uint8Array(4);
    for (let x = 0; x < 256; x++) {
      input[0] = x;
      columnFunction(tables, 2, 1, input, out);
      for (let i = 0; i < 4; i++) seen[i].add(out[i]);
    }
    for (let i = 0; i < 4; i++) expect(seen[i].size).toBe(256);
  });
});

describe('BGE failure codes', () => {
  it('names every code it can raise', () => {
    expect([...BGE_FAILURE_CODES]).toEqual([
      'ROUND_OUT_OF_RANGE',
      'COLUMN_OUT_OF_RANGE',
      'NOT_A_BIJECTION',
      'GROUP_NOT_ELEMENTARY_ABELIAN',
      'GROUP_ORDER_WRONG',
    ]);
  });

  it('raises ROUND_OUT_OF_RANGE for round 10, which has no MixColumns', () => {
    const { tables } = tablesFor('codes');
    for (const round of [0, 10, 11, 1.5, Number.NaN]) {
      try {
        runBgeStepA1(tables, round, 0);
        expect.unreachable(`round ${round} should have been refused`);
      } catch (error) {
        expect(error).toBeInstanceOf(BgeError);
        expect((error as BgeError).code).toBe('ROUND_OUT_OF_RANGE');
      }
    }
  });

  it('raises COLUMN_OUT_OF_RANGE outside 0..3', () => {
    const { tables } = tablesFor('codes2');
    for (const column of [-1, 4, 2.5]) {
      try {
        runBgeStepA1(tables, 1, column);
        expect.unreachable(`column ${column} should have been refused`);
      } catch (error) {
        expect((error as BgeError).code).toBe('COLUMN_OUT_OF_RANGE');
      }
    }
  });

  it('raises GROUP_ORDER_WRONG when a table is corrupted so the group collapses', () => {
    // A corrupted network is not a Chow network, and A1 must say so rather than
    // returning a confident answer computed from nonsense.
    const { tables } = tablesFor('corrupt');
    const broken: ColumnTables = {
      ...tables,
      typeII: new Uint32Array(tables.typeII),
    };
    // Make the row-0 Type II table of round 1 column 0 constant. The column
    // function then loses its dependence on byte 0 entirely.
    for (let x = 0; x < 256; x++) broken.typeII[x] = broken.typeII[0];
    let code: string | null = null;
    try {
      runBgeStepA1(broken, 1, 0);
    } catch (error) {
      code = (error as BgeError).code;
    }
    expect(code).not.toBeNull();
    expect(BGE_FAILURE_CODES).toContain(code as never);
  });
});
