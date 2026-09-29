import { describe, expect, it } from 'vitest';
import { buildNetwork } from '../wb/wb-gen.js';
import { collectTraces } from '../wb/wb-run.js';
import { seededRng } from '../wb/rng.js';
import { expandKey, invertKeySchedule } from '../aes/aes-ref.js';
import { GF_INV, SBOX } from '../aes/gf.js';
import {
  CHANCE_CORRECT_BYTES,
  DCA_TARGETS,
  dcaCurves,
  judgeRecovery,
  predictBit,
  runDca,
  TARGET_READS,
  walshHadamard,
  type DcaRequest,
} from './dca.js';
import type { DcaTarget, EncodingPlacement, TraceWindow } from '../wb/types.js';

const ALL_BITS = [0, 1, 2, 3, 4, 5, 6, 7];

/**
 * Build one instance, trace it, and hand DCA exactly what an attacker holding
 * the program would have: the values it was called with (or returned) and the
 * trace. The key is returned separately and is only ever used AFTER `runDca`
 * commits (invariant I3).
 */
function mount(
  placement: EncodingPlacement,
  seed: string,
  traces: number,
  window: TraceWindow = 'first-round',
): { request: Omit<DcaRequest, 'targets' | 'bits4'>; key: Uint8Array; lastRoundKey: Uint8Array; totalBits: number } {
  const key = seededRng(`${seed} key`).bytes(16);
  const { network } = buildNetwork(key, placement, seededRng(seed));
  const inputs = seededRng(`${seed} inputs ${traces}`).bytes(traces * 16);
  const set = collectTraces(network, inputs, traces);
  const w = set.map.windows[window];
  return {
    request: {
      bits: set.bits,
      stride: set.stride,
      traces,
      sampleStart: w.startBit,
      sampleCount: w.bits,
      known: window === 'first-round' ? set.inputs : set.outputs,
    },
    key,
    lastRoundKey: new Uint8Array(expandKey(key).subarray(160, 176)),
    totalBits: set.totalBits,
  };
}

describe('the hypotheses DCA forms', () => {
  it('names the three targets and which observed value each reads', () => {
    expect([...DCA_TARGETS]).toEqual(['sbox-output', 'inverse', 'last-round']);
    expect(TARGET_READS['sbox-output']).toBe('program input');
    expect(TARGET_READS['inverse']).toBe('program input');
    expect(TARGET_READS['last-round']).toBe('program output');
  });

  it('predictBit reads the right bit of the right intermediate', () => {
    for (let known = 0; known < 256; known += 11) {
      for (let guess = 0; guess < 256; guess += 13) {
        for (const bit of ALL_BITS) {
          expect(predictBit('sbox-output', known, guess, bit)).toBe((SBOX[known ^ guess] >>> bit) & 1);
          expect(predictBit('inverse', known, guess, bit)).toBe((GF_INV[known ^ guess] >>> bit) & 1);
        }
      }
    }
  });

  it('a single-bit prediction splits the traces roughly in half', () => {
    // If it did not, the difference of means would be computed over a lopsided
    // partition and the distinguisher would lose most of its power.
    for (const target of ['sbox-output', 'inverse'] as DcaTarget[]) {
      for (const bit of ALL_BITS) {
        let ones = 0;
        for (let known = 0; known < 256; known++) ones += predictBit(target, known, 0x5a, bit);
        expect(ones).toBe(128);
      }
    }
  });
});

describe('the Walsh-Hadamard transform the fast scorer uses', () => {
  it('applied twice, scales by 256', () => {
    const a = new Float64Array(256);
    for (let i = 0; i < 256; i++) a[i] = ((i * 37) % 251) - 125;
    const original = Float64Array.from(a);
    walshHadamard(a);
    walshHadamard(a);
    for (let i = 0; i < 256; i++) expect(a[i]).toBe(256 * original[i]);
  });

  it('computes the XOR convolution, checked against the O(n^2) definition', () => {
    const a = new Float64Array(256);
    const b = new Float64Array(256);
    for (let i = 0; i < 256; i++) {
      a[i] = (i * 7) % 19;
      b[i] = (SBOX[i] >>> 2) & 1;
    }
    const brute = new Float64Array(256);
    for (let g = 0; g < 256; g++) {
      let acc = 0;
      for (let v = 0; v < 256; v++) acc += a[v] * b[v ^ g];
      brute[g] = acc;
    }
    const fa = Float64Array.from(a);
    const fb = Float64Array.from(b);
    walshHadamard(fa);
    walshHadamard(fb);
    const product = new Float64Array(256);
    for (let i = 0; i < 256; i++) product[i] = fa[i] * fb[i];
    walshHadamard(product);
    for (let g = 0; g < 256; g++) expect(product[g] / 256).toBe(brute[g]);
  });
});

describe('the fast and direct scorers are the same attack', () => {
  it('agree on every byte, peak, sample and margin', () => {
    // An independent re-derivation, not a cross-check of one implementation
    // against itself: the direct scorer partitions traces and counts bits, the
    // fast one convolves per-value counts. They share no arithmetic.
    const { request } = mount('none', 'agree', 192);
    for (const target of ['sbox-output', 'inverse', 'last-round'] as DcaTarget[]) {
      const base = { ...request, targets: [target], bits4: [0, 5] };
      const fast = runDca({ ...base, method: 'fast' });
      const direct = runDca({ ...base, method: 'direct' });
      expect([...fast.recovered]).toEqual([...direct.recovered]);
      for (let i = 0; i < 16; i++) {
        expect(fast.bytes[i].peak).toBeCloseTo(direct.bytes[i].peak, 12);
        expect(fast.bytes[i].runnerUp).toBeCloseTo(direct.bytes[i].runnerUp, 12);
        expect(fast.bytes[i].peakSample).toBe(direct.bytes[i].peakSample);
        expect(fast.bytes[i].peakBit).toBe(direct.bytes[i].peakBit);
        expect([...fast.bytes[i].peaks]).toEqual([...direct.bytes[i].peaks]);
        expect(fast.bytes[i].bestDelta).toBeCloseTo(direct.bytes[i].bestDelta, 12);
      }
      // The per-combo ranks are what the extremity distinguisher is defined on,
      // so they have to agree too -- a rank is a total order and a single
      // swapped pair would change a recovered byte.
      expect([...fast.ranks]).toEqual([...direct.ranks]);
    }
  }, 300_000);
});

/**
 * The rank-extremity distinguisher, and the observation it rests on.
 *
 * Bos et al. section 5.4: a target bit that does not leak very often ranks the
 * TRUE byte last rather than at a random position. These tests measure whether
 * that reproduces on this generator, and whether it is strong enough to recover
 * a key on its own -- both of which the page claims.
 */
describe('rank extremity (Bos et al. section 5.4)', () => {
  const ALL_BITS_LOCAL = [0, 1, 2, 3, 4, 5, 6, 7];

  it('ranks the true byte at one extreme far more often than chance', () => {
    const { request, key } = mount('none', 'rank', 2048);
    const result = runDca({
      ...request,
      targets: ['sbox-output', 'inverse'],
      bits4: ALL_BITS_LOCAL,
      distinguisher: 'peak',
    });
    const combos = result.combos.length;
    expect(combos).toBe(16);
    let extreme = 0;
    let middle = 0;
    for (let m = 0; m < 16; m++) {
      for (let c = 0; c < combos; c++) {
        const rank = result.ranks[(m * combos + c) * 256 + key[m]];
        expect(rank).toBeGreaterThanOrEqual(1);
        expect(rank).toBeLessThanOrEqual(256);
        if (rank === 1 || rank === 256) extreme++;
        else middle++;
      }
    }
    // Uniform would put about 2 of 256 at the extremes; measured here it is the
    // large majority. The threshold is deliberately far below what was measured
    // (231 of 256 over five instances) so the test is about the phenomenon
    // rather than about one instance.
    expect(extreme + middle).toBe(16 * 16);
    expect(extreme).toBeGreaterThan(0.6 * (extreme + middle));
  }, 180_000);

  it('recovers the whole key on its own at 2,048 traces', () => {
    for (const seed of ['e0', 'e1']) {
      const { request, key } = mount('none', seed, 2048);
      const result = runDca({
        ...request,
        targets: ['sbox-output', 'inverse'],
        bits4: ALL_BITS_LOCAL,
        distinguisher: 'extremity',
      });
      expect(result.distinguisher).toBe('extremity');
      expect(judgeRecovery(result.recovered, key).correctCount, seed).toBe(16);
      // And it is not a near-tie: the winner stands clear of the field.
      for (const b of result.bytes) expect(b.margin, `${seed} byte ${b.index}`).toBeGreaterThan(0.1);
    }
  }, 300_000);

  it('...and needs those traces: at 384 it is measurably worse than the peak reading', () => {
    // The honest other half. A weaker signal needs more of it, and the page says
    // so rather than offering the distinguisher as a free upgrade.
    const { request, key } = mount('none', 'e2', 384);
    const base = { ...request, targets: ['sbox-output', 'inverse'] as DcaTarget[], bits4: ALL_BITS_LOCAL };
    const byPeak = judgeRecovery(runDca({ ...base, distinguisher: 'peak' }).recovered, key).correctCount;
    const byExtremity = judgeRecovery(runDca({ ...base, distinguisher: 'extremity' }).recovered, key).correctCount;
    expect(byPeak).toBeGreaterThanOrEqual(14);
    expect(byExtremity).toBeLessThan(byPeak);
  }, 300_000);

  it('the two distinguishers read the same scores and disagree only in how they combine them', () => {
    const { request } = mount('none', 'e3', 256);
    const base = { ...request, targets: ['sbox-output'] as DcaTarget[], bits4: [0, 4] };
    const a = runDca({ ...base, distinguisher: 'peak' });
    const b = runDca({ ...base, distinguisher: 'extremity' });
    // Same underlying measurement...
    expect([...a.ranks]).toEqual([...b.ranks]);
    // ...different combination, so the score arrays are in different units.
    expect(a.bytes[0].peaks[a.bytes[0].guess]).toBeCloseTo(a.bytes[0].bestDelta, 12);
    expect(b.bytes[0].peaks[b.bytes[0].guess]).toBeGreaterThan(1);
  }, 180_000);
});

describe('dcaCurves', () => {
  it('its maximum over the window is the peak runDca reports', () => {
    const { request } = mount('none', 'curves', 192);
    const full = { ...request, targets: ['sbox-output'] as DcaTarget[], bits4: [2] };
    const result = runDca(full);
    const { curves, sampleCount, max } = dcaCurves(full, 0, 'sbox-output', 2);
    expect(sampleCount).toBe(request.sampleCount);
    for (let g = 0; g < 256; g++) {
      let best = 0;
      for (let s = 0; s < sampleCount; s++) best = Math.max(best, curves[g * sampleCount + s]);
      expect(best).toBeCloseTo(result.bytes[0].peaks[g], 6);
    }
    expect(max).toBeGreaterThan(0);
    expect(max).toBeCloseTo(result.bytes[0].peak, 6);
  });
});

/**
 * ACCEPTANCE THRESHOLDS.
 *
 * Every number below was MEASURED on this generator, over five instances at two
 * trace counts, and the seeds and trace counts are in the test names so a run can
 * be reproduced exactly. They are properties of THIS lab's generator, not of
 * Chow's construction: a different set of encodings, a different key, or a
 * different number of traces gives different figures. Bos et al.'s own reported
 * figures are quoted in the README as theirs, never merged with these.
 *
 * Measured on 2026-09-29 over instances `t0`..`t4`:
 *   input side, SubBytes-output target, all 8 bits, N = 384:   12-16 of 16
 *   input side, inverse target,         all 8 bits, N = 384:   13-16 of 16
 *   input side, both targets combined,  all 8 bits, N = 384:   14-16 of 16
 *   input side, both targets combined,  all 8 bits, N = 1024:  15-16 of 16
 *   every byte reported at margin >= 0.15 was correct in all 50 measured runs
 *   remote-both, either side:                                  0 of 16
 */
describe('DCA against the real network: measured recovery', () => {
  it('recovers most of the key from one target at N = 384, and the rest when the targets are combined', () => {
    const { request, key } = mount('none', 't0', 384);
    const single = runDca({ ...request, targets: ['sbox-output'], bits4: ALL_BITS });
    const singleVerdict = judgeRecovery(single.recovered, key);
    expect(singleVerdict.correctCount).toBeGreaterThanOrEqual(12);

    const combined = runDca({ ...request, targets: ['sbox-output', 'inverse'], bits4: ALL_BITS });
    const combinedVerdict = judgeRecovery(combined.recovered, key);
    expect(combinedVerdict.correctCount).toBeGreaterThanOrEqual(14);
    expect(combinedVerdict.correctCount).toBeGreaterThanOrEqual(singleVerdict.correctCount);
  }, 120_000);

  it('recovers the whole key at N = 1024 on instances t1 and t3', () => {
    for (const seed of ['t1', 't3']) {
      const { request, key } = mount('none', seed, 1024);
      const result = runDca({ ...request, targets: ['sbox-output', 'inverse'], bits4: ALL_BITS });
      expect(judgeRecovery(result.recovered, key).correctCount, seed).toBe(16);
    }
  }, 240_000);

  it('a high margin was right every time it appeared on the input side', () => {
    for (const seed of ['t0', 't2', 't4']) {
      const { request, key } = mount('none', seed, 384);
      const result = runDca({ ...request, targets: ['sbox-output', 'inverse'], bits4: ALL_BITS });
      const confident = result.bytes.filter((b) => b.margin >= 0.15);
      expect(confident.length, seed).toBeGreaterThan(10);
      for (const b of confident) expect(result.recovered[b.index], `${seed} byte ${b.index}`).toBe(key[b.index]);
    }
  }, 240_000);

  it('fewer traces recovers fewer bytes', () => {
    // The edge case the UI has to show honestly rather than hide: DCA is a
    // statistical attack and 24 traces is not enough for one.
    const small = mount('none', 't0', 24);
    const large = mount('none', 't0', 384);
    const a = runDca({ ...small.request, targets: ['sbox-output'], bits4: ALL_BITS });
    const b = runDca({ ...large.request, targets: ['sbox-output'], bits4: ALL_BITS });
    expect(judgeRecovery(a.recovered, small.key).correctCount).toBeLessThan(
      judgeRecovery(b.recovered, large.key).correctCount,
    );
  }, 120_000);

  it('the winning sample lands inside the window it was told to scan', () => {
    const { request } = mount('none', 't1', 256);
    const result = runDca({ ...request, targets: ['sbox-output'], bits4: ALL_BITS });
    for (const b of result.bytes) {
      expect(b.peakSample).toBeGreaterThanOrEqual(request.sampleStart);
      expect(b.peakSample).toBeLessThan(request.sampleStart + request.sampleCount);
    }
  }, 120_000);
});

describe('Act 5: where the external encodings live', () => {
  it('compiled-in gives the SAME recovery as no external encoding at all', () => {
    // Bos et al. section 5.4, as a measurement. The program is bigger and its
    // trace is longer; the bytes DCA recovers are identical.
    const plain = mount('none', 'act5', 384);
    const compiled = mount('compiled-in', 'act5', 384);
    const a = runDca({ ...plain.request, targets: ['sbox-output', 'inverse'], bits4: ALL_BITS });
    const b = runDca({ ...compiled.request, targets: ['sbox-output', 'inverse'], bits4: ALL_BITS });
    expect([...b.recovered]).toEqual([...a.recovered]);
    expect(compiled.totalBits).toBeGreaterThan(plain.totalBits);
    expect(judgeRecovery(b.recovered, compiled.key).correctCount).toBeGreaterThanOrEqual(14);
  }, 180_000);

  it('a remote OUTPUT encoding does not protect the input side', () => {
    const plain = mount('none', 'act5', 384);
    const remote = mount('remote-output', 'act5', 384);
    const a = runDca({ ...plain.request, targets: ['sbox-output', 'inverse'], bits4: ALL_BITS });
    const b = runDca({ ...remote.request, targets: ['sbox-output', 'inverse'], bits4: ALL_BITS });
    expect([...b.recovered]).toEqual([...a.recovered]);
  }, 180_000);

  it('remote on BOTH sides leaves the input side at chance', () => {
    for (const seed of ['t0', 't1', 't2']) {
      const { request, key } = mount('remote-both', seed, 384);
      const result = runDca({ ...request, targets: ['sbox-output', 'inverse'], bits4: ALL_BITS });
      const verdict = judgeRecovery(result.recovered, key);
      // Chance is 16/256 = 0.0625 bytes. Two or more would be a 1-in-10^4 event
      // per instance, and would mean an I2/I7 leak rather than luck.
      expect(verdict.correctCount, seed).toBeLessThanOrEqual(2);
      expect(verdict.complete).toBe(false);
    }
    expect(CHANCE_CORRECT_BYTES).toBeCloseTo(0.0625, 6);
  }, 240_000);

  it('remote on BOTH sides leaves the output side at chance too', () => {
    for (const seed of ['t0', 't1']) {
      const { request, lastRoundKey } = mount('remote-both', seed, 384, 'last-rounds');
      const result = runDca({ ...request, targets: ['last-round'], bits4: ALL_BITS });
      expect(judgeRecovery(result.recovered, lastRoundKey).correctCount, seed).toBeLessThanOrEqual(2);
    }
  }, 180_000);

  it('a remote INPUT encoding closes the input side', () => {
    const { request, key } = mount('remote-input', 't0', 384);
    const result = runDca({ ...request, targets: ['sbox-output', 'inverse'], bits4: ALL_BITS });
    expect(judgeRecovery(result.recovered, key).correctCount).toBeLessThanOrEqual(2);
  }, 120_000);

  it('...and leaves the output side PARTIALLY open: some of k10, never all of it', () => {
    // A lab-original measurement, not a figure from any paper. Chow's first-round
    // tables are 8 -> 32, so a first-round key byte is exposed through eight
    // encoded nibbles; his last-round tables are 8 -> 8, so a last-round key byte
    // is exposed through two. Four times fewer places for a correlation to be,
    // and the measured result is partial recovery that does not complete.
    for (const seed of ['t0', 't1', 't2']) {
      const { request, lastRoundKey, key } = mount('remote-input', seed, 1024, 'last-rounds');
      const result = runDca({ ...request, targets: ['last-round'], bits4: ALL_BITS });
      const verdict = judgeRecovery(result.recovered, lastRoundKey);
      const confident = result.bytes.filter((b) => b.margin >= 0.15);
      expect(confident.length, `${seed} confident`).toBeGreaterThanOrEqual(4);
      for (const b of confident)
        expect(result.recovered[b.index], `${seed} byte ${b.index}`).toBe(lastRoundKey[b.index]);
      // Partial: better than chance, and not complete.
      expect(verdict.correctCount, `${seed} k10`).toBeGreaterThanOrEqual(4);
      expect(verdict.complete, `${seed} complete`).toBe(false);
      // And the key does not follow, because inverting the AES-128 schedule
      // needs all sixteen bytes of k10 and one wrong byte corrupts everything.
      expect(judgeRecovery(invertKeySchedule(result.recovered), key).correctCount).toBeLessThanOrEqual(2);
    }
  }, 300_000);
});

describe('invariant I3 and the fail-closed paths', () => {
  it('runDca has no way to take the key: the verdict is a separate call', () => {
    const { request, key } = mount('none', 't0', 64);
    const result = runDca({ ...request, targets: ['sbox-output'], bits4: [0] });
    // The committed answer exists before any comparison happens.
    expect(result.recovered).toHaveLength(16);
    const verdict = judgeRecovery(result.recovered, key);
    expect(verdict.correct).toHaveLength(16);
    expect(verdict.correctCount).toBe(verdict.correct.filter(Boolean).length);
    expect(verdict.complete).toBe(verdict.correctCount === 16);
  });

  it('judgeRecovery refuses keys that are not 16 bytes', () => {
    expect(() => judgeRecovery(new Uint8Array(15), new Uint8Array(16))).toThrow(/16 bytes/);
    expect(() => judgeRecovery(new Uint8Array(16), new Uint8Array(17))).toThrow(/16 bytes/);
  });

  it('refuses a misaligned stride, a short known array, no target and an empty window', () => {
    const { request } = mount('none', 't0', 64);
    expect(() => runDca({ ...request, stride: 3, targets: ['sbox-output'], bits4: [0] })).toThrow(/32-bit words/);
    expect(() => runDca({ ...request, known: new Uint8Array(5), targets: ['sbox-output'], bits4: [0] })).toThrow(
      /16 observed bytes/,
    );
    expect(() => runDca({ ...request, targets: [], bits4: [0] })).toThrow(/at least one target/);
    expect(() => runDca({ ...request, targets: ['sbox-output'], bits4: [] })).toThrow(/at least one target/);
    expect(() => runDca({ ...request, sampleCount: 0, targets: ['sbox-output'], bits4: [0] })).toThrow(
      /at least one sample/,
    );
  });
});
