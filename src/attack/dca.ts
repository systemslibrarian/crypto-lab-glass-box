/**
 * Differential computation analysis.
 *
 * Bos, Hubain, Michiels and Teuwen, "Differential Computation Analysis: Hiding
 * Your White-Box Designs is Not Enough", CHES 2016, LNCS 9813, 215-236 (ePrint
 * 2015/753). The attack is DPA's difference-of-means distinguisher applied to a
 * SOFTWARE execution trace instead of a power trace, and its striking property
 * is how little it needs to know: not the table layout, not the encodings, not
 * which design the implementation is -- only the values going in, and a trace.
 *
 * WHY IT WORKS AT ALL, which is the thing worth getting right. Chow's internal
 * encodings are concatenations of 4-bit bijections. A sample in the trace is one
 * bit of f(v), where f is a secret 4-bit bijection and v is a nibble of a
 * GF(2)-linear image of S(x ^ k). A 4-bit bijection cannot make all four output
 * bits statistically independent of all four input bits, so for some (prediction
 * bit, sample bit) pairs the correlation is non-zero -- and a difference of means
 * over a few hundred traces finds it. DCA succeeds THROUGH Chow's encodings, not
 * because they are absent.
 *
 * And what that does NOT license: "4 bits leak, 8 bits are safe" is false.
 * Rivain and Wang (TCHES 2019(2), 225-255) analysed when DCA works against
 * internal encodings and broke encodings wider than 4 bits, including a
 * byte-encoded implementation that plain DCA had failed on. Nibble width is why
 * FIRST-ORDER DCA works here; it is not the boundary of the attack family.
 *
 * INVARIANT I2. This module imports the two hypothesis functions from
 * `aes/aes-ref.ts` and nothing else. It cannot see the key, the encodings, the
 * tables, or the remote party -- `isolation.test.ts` reads this file's imports
 * and fails if that changes. Everything it knows arrives as (observed value,
 * trace) pairs.
 */

import { inverseHypothesis, lastRoundHypothesis, sboxOutputHypothesis } from '../aes/aes-ref.js';
import type { DcaTarget } from '../wb/types.js';

export const DCA_TARGETS: readonly DcaTarget[] = ['sbox-output', 'inverse', 'last-round'];

export const TARGET_LABELS: Readonly<Record<DcaTarget, string>> = {
  'sbox-output': 'SubBytes output, S(p ^ k)',
  inverse: 'multiplicative inverse inside SubBytes, (p ^ k)⁻¹',
  'last-round': 'round-10 state before SubBytes, S⁻¹(c ^ k¹⁰)',
};

/** Which observed value a target is predicted from. */
export const TARGET_READS: Readonly<Record<DcaTarget, 'program input' | 'program output'>> = {
  'sbox-output': 'program input',
  inverse: 'program input',
  'last-round': 'program output',
};

function hypothesis(target: DcaTarget, known: number, guess: number): number {
  switch (target) {
    case 'sbox-output':
      return sboxOutputHypothesis(known, guess);
    case 'inverse':
      return inverseHypothesis(known, guess);
    case 'last-round':
      return lastRoundHypothesis(known, guess);
  }
}

/** One bit of the predicted intermediate. The whole of what DCA asks of the cipher. */
export function predictBit(target: DcaTarget, known: number, guess: number, bit: number): number {
  return (hypothesis(target, known, guess) >>> bit) & 1;
}

export interface DcaRequest {
  /** Sample-major packed trace bits, 4-byte-aligned rows. */
  readonly bits: Uint8Array;
  readonly stride: number;
  readonly traces: number;
  /** The window, as absolute sample indices. */
  readonly sampleStart: number;
  readonly sampleCount: number;
  /** 16 observed bytes per trace: the program's input, or its output. */
  readonly known: Uint8Array;
  /** One or two targets. Two means the learner asked to combine them. */
  readonly targets: readonly DcaTarget[];
  /** One bit index, or all eight. */
  readonly bits4: readonly number[];
  /**
   * `fast` scores every hypothesis at once through an XOR-convolution; `direct`
   * scores them one at a time with masked popcounts. They are required to agree
   * exactly -- see `dca.test.ts`, which is how the fast path earns its keep.
   */
  readonly method?: 'fast' | 'direct';
}

export interface DcaByteResult {
  readonly index: number;
  readonly guess: number;
  readonly peak: number;
  readonly runnerUpGuess: number;
  readonly runnerUp: number;
  /** (peak - runnerUp) / peak, in [0, 1]. 0 means a tie: no information. */
  readonly margin: number;
  /** Absolute sample index where the winning guess peaked. */
  readonly peakSample: number;
  readonly peakTarget: DcaTarget;
  readonly peakBit: number;
  /** |difference of means| per guess, for the plot. */
  readonly peaks: Float32Array;
}

export interface DcaResult {
  readonly bytes: readonly DcaByteResult[];
  /** The 16 recovered bytes, in order. Committed before any comparison (I3). */
  readonly recovered: Uint8Array;
  readonly targets: readonly DcaTarget[];
  readonly bits4: readonly number[];
  readonly sampleStart: number;
  readonly sampleCount: number;
  readonly traces: number;
  readonly elapsedMs: number;
  readonly method: 'fast' | 'direct';
}

/**
 * The Walsh-Hadamard transform over GF(2)^8, in place.
 *
 * This is what makes the attack interactive at Bos et al.'s 2,000 traces. All
 * three hypotheses have the shape f(known ^ guess), so the quantity DCA needs --
 * for every guess, how many traces with a 1 at this sample predicted a 1 --
 * is an XOR-convolution of the per-known-value counts with the predicted bit:
 *
 *     hit(g) = sum_v A[v] . b(v ^ g) = (A * b)[g],  A * b = WHT(WHT(A) . WHT(b)) / 256
 *
 * so 256 hypotheses cost one 2,048-step transform instead of 256 passes over the
 * trace. The saving grows with the trace count, because the transform is over the
 * 256 byte values rather than over the traces. Exactness matters and is kept:
 * every intermediate here is an integer below 2^37, well inside a float64's
 * 53-bit mantissa, so `fast` and `direct` agree to the bit rather than to a
 * tolerance.
 */
export function walshHadamard(a: Float64Array): void {
  for (let len = 1; len < 256; len <<= 1) {
    for (let i = 0; i < 256; i += len << 1) {
      for (let j = i; j < i + len; j++) {
        const u = a[j];
        const v = a[j + len];
        a[j] = u + v;
        a[j + len] = u - v;
      }
    }
  }
}

/** The transform of the predicted bit, as a function of `known ^ guess`. */
function predictedBitSpectrum(target: DcaTarget, bit: number): Float64Array {
  const b = new Float64Array(256);
  for (let u = 0; u < 256; u++) b[u] = (hypothesis(target, u, 0) >>> bit) & 1;
  walshHadamard(b);
  return b;
}

interface PeakState {
  readonly peaks: Float64Array;
  readonly samples: Int32Array;
  readonly targets: DcaTarget[];
  readonly bits: Int32Array;
}

function newPeakState(fallback: DcaTarget): PeakState {
  return {
    peaks: new Float64Array(256),
    samples: new Int32Array(256).fill(-1),
    targets: new Array<DcaTarget>(256).fill(fallback),
    bits: new Int32Array(256).fill(-1),
  };
}

function offer(
  state: PeakState,
  guess: number,
  magnitude: number,
  sample: number,
  target: DcaTarget,
  bit: number,
): void {
  if (magnitude > state.peaks[guess]) {
    state.peaks[guess] = magnitude;
    state.samples[guess] = sample;
    state.targets[guess] = target;
    state.bits[guess] = bit;
  }
}

/** Count of 1 bits, for the direct scorer. */
function popcount(x: number): number {
  let v = x - ((x >>> 1) & 0x55555555);
  v = (v & 0x33333333) + ((v >>> 2) & 0x33333333);
  v = (v + (v >>> 4)) & 0x0f0f0f0f;
  return (Math.imul(v, 0x01010101) >>> 24) & 0x3f;
}

function scoreByteDirect(
  request: DcaRequest,
  columns: Uint32Array,
  words: number,
  index: number,
  state: PeakState,
): void {
  const { traces, sampleStart, sampleCount, known, targets, bits4 } = request;
  const totals = new Int32Array(sampleCount);
  for (let s = 0; s < sampleCount; s++) {
    const base = (sampleStart + s) * words;
    let total = 0;
    for (let w = 0; w < words; w++) total += popcount(columns[base + w]);
    totals[s] = total;
  }
  const selection = new Uint32Array(words);
  for (const target of targets) {
    for (const bit of bits4) {
      for (let guess = 0; guess < 256; guess++) {
        selection.fill(0);
        let ones = 0;
        for (let t = 0; t < traces; t++) {
          if ((hypothesis(target, known[t * 16 + index], guess) >>> bit) & 1) {
            selection[t >>> 5] |= 1 << (t & 31);
            ones++;
          }
        }
        const zeros = traces - ones;
        // A degenerate partition distinguishes nothing; scoring it 0 is the
        // honest reading rather than a skipped case.
        if (ones === 0 || zeros === 0) continue;
        for (let s = 0; s < sampleCount; s++) {
          const base = (sampleStart + s) * words;
          let hit = 0;
          for (let w = 0; w < words; w++) hit += popcount(columns[base + w] & selection[w]);
          const delta = hit / ones - (totals[s] - hit) / zeros;
          offer(state, guess, delta < 0 ? -delta : delta, sampleStart + s, target, bit);
        }
      }
    }
  }
}

function scoreByteFast(
  request: DcaRequest,
  columns: Uint32Array,
  words: number,
  index: number,
  state: PeakState,
  spectra: ReadonlyMap<string, Float64Array>,
): void {
  const { traces, sampleStart, sampleCount, known, targets, bits4 } = request;

  // Traces grouped by the observed byte this key byte pairs with.
  const bucket = new Uint8Array(traces);
  const counts = new Float64Array(256);
  for (let t = 0; t < traces; t++) {
    const v = known[t * 16 + index];
    bucket[t] = v;
    counts[v] += 1;
  }
  const countSpectrum = new Float64Array(counts);
  walshHadamard(countSpectrum);

  // ones(g): how many traces predict a 1 under guess g. Independent of the
  // sample, so it is computed once per (target, bit).
  const onesFor = new Map<string, Float64Array>();
  for (const target of targets) {
    for (const bit of bits4) {
      const key = `${target}:${bit}`;
      const spectrum = spectra.get(key);
      if (!spectrum) throw new Error(`no spectrum for ${key}`);
      const product = new Float64Array(256);
      for (let u = 0; u < 256; u++) product[u] = countSpectrum[u] * spectrum[u];
      walshHadamard(product);
      for (let g = 0; g < 256; g++) product[g] /= 256;
      onesFor.set(key, product);
    }
  }

  const a = new Float64Array(256);
  const spectrumA = new Float64Array(256);
  const product = new Float64Array(256);
  for (let s = 0; s < sampleCount; s++) {
    a.fill(0);
    const base = (sampleStart + s) * words;
    let total = 0;
    for (let w = 0; w < words; w++) {
      let x = columns[base + w];
      while (x !== 0) {
        const lowest = x & -x;
        const t = (w << 5) + 31 - Math.clz32(lowest);
        a[bucket[t]] += 1;
        total += 1;
        x ^= lowest;
      }
    }
    if (total === 0 || total === traces) {
      // A sample that never moves carries no difference of means at all.
      continue;
    }
    spectrumA.set(a);
    walshHadamard(spectrumA);
    for (const target of targets) {
      for (const bit of bits4) {
        const spectrum = spectra.get(`${target}:${bit}`);
        if (!spectrum) throw new Error('missing spectrum');
        const ones = onesFor.get(`${target}:${bit}`);
        if (!ones) throw new Error('missing partition sizes');
        for (let u = 0; u < 256; u++) product[u] = spectrumA[u] * spectrum[u];
        walshHadamard(product);
        for (let g = 0; g < 256; g++) {
          const n1 = ones[g];
          const n0 = traces - n1;
          if (n1 === 0 || n0 === 0) continue;
          const hit = product[g] / 256;
          const delta = hit / n1 - (total - hit) / n0;
          offer(state, g, delta < 0 ? -delta : delta, sampleStart + s, target, bit);
        }
      }
    }
  }
}

/**
 * Score all 256 hypotheses for all 16 key bytes.
 *
 * The distinguisher is the difference of means: split the traces by the
 * predicted bit, average each sample over both halves, and take the largest
 * absolute difference over samples. The score of a guess is that peak; the
 * recovered byte is the argmax over guesses. Where the learner has asked for
 * more than one target or more than one bit, the peak is the largest over all of
 * them -- which is what a real attacker does, and what Bos et al. describe when
 * they report combining targets.
 */
export function runDca(request: DcaRequest, onProgress?: (byteIndex: number) => void): DcaResult {
  const startedAt = Date.now();
  const { bits, stride, traces, sampleStart, sampleCount, known, targets, bits4 } = request;
  const method = request.method ?? 'fast';
  if (stride % 4 !== 0) throw new Error('the trace stride must be a whole number of 32-bit words');
  if (known.length !== traces * 16) throw new Error('known must hold 16 observed bytes per trace');
  if (targets.length === 0 || bits4.length === 0) throw new Error('DCA needs at least one target and one bit');
  if (sampleCount <= 0) throw new Error('the trace window must contain at least one sample');

  const words = stride / 4;
  const columns = new Uint32Array(bits.buffer, bits.byteOffset, bits.byteLength / 4);
  const spectra = new Map<string, Float64Array>();
  for (const target of targets) {
    for (const bit of bits4) spectra.set(`${target}:${bit}`, predictedBitSpectrum(target, bit));
  }

  const results: DcaByteResult[] = [];
  const recovered = new Uint8Array(16);
  for (let index = 0; index < 16; index++) {
    const state = newPeakState(targets[0]);
    if (method === 'direct') scoreByteDirect(request, columns, words, index, state);
    else scoreByteFast(request, columns, words, index, state, spectra);

    let winner = 0;
    for (let guess = 1; guess < 256; guess++) if (state.peaks[guess] > state.peaks[winner]) winner = guess;
    let runnerUpGuess = winner === 0 ? 1 : 0;
    for (let guess = 0; guess < 256; guess++) {
      if (guess === winner) continue;
      if (state.peaks[guess] > state.peaks[runnerUpGuess]) runnerUpGuess = guess;
    }
    const peak = state.peaks[winner];
    const runnerUp = state.peaks[runnerUpGuess];
    recovered[index] = winner;
    results.push({
      index,
      guess: winner,
      peak,
      runnerUpGuess,
      runnerUp,
      margin: peak > 0 ? (peak - runnerUp) / peak : 0,
      peakSample: state.samples[winner],
      peakTarget: state.targets[winner],
      peakBit: state.bits[winner],
      peaks: Float32Array.from(state.peaks),
    });
    if (onProgress) onProgress(index + 1);
  }

  return {
    bytes: results,
    recovered,
    targets,
    bits4,
    sampleStart,
    sampleCount,
    traces,
    elapsedMs: Date.now() - startedAt,
    method,
  };
}

/**
 * The difference-of-means curve over the window, for every guess, for one key
 * byte and one (target, bit).
 *
 * This is what the 256-curve plot draws. It is a separate call because the plot
 * needs 256 x window values and the recovery needs only the peaks -- keeping
 * `runDca` from carrying a megabyte of curve data it does not use.
 */
export function dcaCurves(
  request: DcaRequest,
  index: number,
  target: DcaTarget,
  bit: number,
): { curves: Float32Array; sampleCount: number; max: number } {
  const state = newPeakState(target);
  const words = request.stride / 4;
  const columns = new Uint32Array(request.bits.buffer, request.bits.byteOffset, request.bits.byteLength / 4);
  const { traces, sampleStart, sampleCount, known } = request;
  const spectrum = predictedBitSpectrum(target, bit);

  const bucket = new Uint8Array(traces);
  const counts = new Float64Array(256);
  for (let t = 0; t < traces; t++) {
    const v = known[t * 16 + index];
    bucket[t] = v;
    counts[v] += 1;
  }
  const countSpectrum = new Float64Array(counts);
  walshHadamard(countSpectrum);
  const onesProduct = new Float64Array(256);
  for (let u = 0; u < 256; u++) onesProduct[u] = countSpectrum[u] * spectrum[u];
  walshHadamard(onesProduct);
  for (let g = 0; g < 256; g++) onesProduct[g] /= 256;

  const curves = new Float32Array(256 * sampleCount);
  const a = new Float64Array(256);
  const spectrumA = new Float64Array(256);
  const product = new Float64Array(256);
  let max = 0;
  for (let s = 0; s < sampleCount; s++) {
    a.fill(0);
    const base = (sampleStart + s) * words;
    let total = 0;
    for (let w = 0; w < words; w++) {
      let x = columns[base + w];
      while (x !== 0) {
        const lowest = x & -x;
        a[bucket[(w << 5) + 31 - Math.clz32(lowest)]] += 1;
        total += 1;
        x ^= lowest;
      }
    }
    if (total === 0 || total === traces) continue;
    spectrumA.set(a);
    walshHadamard(spectrumA);
    for (let u = 0; u < 256; u++) product[u] = spectrumA[u] * spectrum[u];
    walshHadamard(product);
    for (let g = 0; g < 256; g++) {
      const n1 = onesProduct[g];
      const n0 = traces - n1;
      if (n1 === 0 || n0 === 0) continue;
      const hit = product[g] / 256;
      const delta = hit / n1 - (total - hit) / n0;
      const magnitude = delta < 0 ? -delta : delta;
      curves[g * sampleCount + s] = magnitude;
      if (magnitude > max) max = magnitude;
    }
  }
  void state;
  return { curves, sampleCount, max };
}

/**
 * Compare a committed recovery against the truth.
 *
 * Invariant I3: this is called AFTER `runDca` has returned, never inside the
 * scoring loop, and the scoring loop has no argument it could take the key
 * through. Splitting it out is what makes that checkable.
 */
export interface RecoveryVerdict {
  readonly correct: readonly boolean[];
  readonly correctCount: number;
  /** True only when all sixteen bytes match. */
  readonly complete: boolean;
}

export function judgeRecovery(recovered: Uint8Array, truth: Uint8Array): RecoveryVerdict {
  if (recovered.length !== 16 || truth.length !== 16) throw new Error('both keys are 16 bytes');
  const correct: boolean[] = [];
  for (let i = 0; i < 16; i++) correct.push(recovered[i] === truth[i]);
  const correctCount = correct.filter(Boolean).length;
  return { correct, correctCount, complete: correctCount === 16 };
}

/**
 * The number of correct bytes a blind guesser would expect, for the page to
 * print beside a failed recovery: 16 bytes at 1/256 each.
 */
export const CHANCE_CORRECT_BYTES = 16 / 256;
