/**
 * Evaluate the table network, and -- when asked -- record its own table lookups.
 *
 * WHAT THE TRACE IS. Real differential computation analysis (Bos, Hubain,
 * Michiels and Teuwen, CHES 2016) runs a white-box binary under dynamic binary
 * instrumentation -- Intel PIN, Valgrind, a debugger -- and records the
 * addresses and values the program reads and writes. A browser cannot do that,
 * so this lab records the same quantity from the inside: the OUTPUT of every
 * table lookup, bit-serialised in execution order. That is a real software
 * execution trace of a real table network; it is not a simulation of a side
 * channel, and it is not the physical power trace DPA uses. The page says so.
 *
 * THE BUFFER (invariant I5). Traces go into a caller-allocated typed array at an
 * offset the caller advances -- no `push`, no per-lookup allocation. The layout
 * is SAMPLE-MAJOR: sample s, trace t is bit `t & 7` of
 * `bits[s * stride + (t >> 3)]`. That is the layout DCA wants, because scoring a
 * key hypothesis means AND-ing a partition bitset against one sample's column
 * and counting bits; laying it out trace-major would cost a transpose of
 * millions of bits per run.
 *
 * WINDOWING. Bos et al. narrow a captured trace to a single round by inspecting
 * its structure before running the statistics; the round boundaries are visible
 * because the program's inner loop repeats. `traceMapFor` publishes those
 * boundaries so the page can offer the same choice and label it, rather than
 * quietly choosing for the attacker.
 */

import { SHIFT_ROWS } from '../aes/aes-ref.js';
import {
  COLUMNS,
  ROUNDS_WITH_MIXCOLUMNS,
  ROWS,
  typeIIIOffset,
  typeIIOffset,
  typeIVOffset,
  xorEncodedWord,
} from './layout.js';
import type { LinearSection, TraceWindow, WhiteBoxNetwork } from './types.js';

/** Bits one 128-bit external section contributes to a trace. */
export const SECTION_TRACE_BITS = 16 * 128 + 15 * 32 * 4;
/** Bits one of rounds 1-9 contributes: four columns of Type II, tree, Type III, tree. */
export const ROUND_TRACE_BITS = COLUMNS * (ROWS * 32 + 3 * 32 + ROWS * 32 + 3 * 32);
/** Round 10 is sixteen 8-bit lookups. */
export const FINAL_ROUND_TRACE_BITS = 16 * 8;

export interface TraceSegment {
  readonly id: string;
  readonly label: string;
  readonly startBit: number;
  readonly bits: number;
}

export interface TraceWindowRange {
  readonly startBit: number;
  readonly bits: number;
  readonly label: string;
}

export interface TraceMap {
  readonly segments: readonly TraceSegment[];
  readonly totalBits: number;
  readonly windows: Readonly<Record<TraceWindow, TraceWindowRange>>;
}

export function traceMapFor(network: WhiteBoxNetwork): TraceMap {
  const segments: TraceSegment[] = [];
  let at = 0;
  const push = (id: string, label: string, bits: number): void => {
    segments.push({ id, label, startBit: at, bits });
    at += bits;
  };
  for (const s of network.preCore) push(`pre:${s.id}`, s.label, SECTION_TRACE_BITS);
  let firstRound: TraceSegment | null = null;
  let ninthRound: TraceSegment | null = null;
  for (let r = 1; r <= ROUNDS_WITH_MIXCOLUMNS; r++) {
    push(`round:${r}`, `round ${r}`, ROUND_TRACE_BITS);
    if (r === 1) firstRound = segments[segments.length - 1];
    if (r === ROUNDS_WITH_MIXCOLUMNS) ninthRound = segments[segments.length - 1];
  }
  push('round:10', 'round 10', FINAL_ROUND_TRACE_BITS);
  const finalRound = segments[segments.length - 1];
  for (const s of network.postCore) push(`post:${s.id}`, s.label, SECTION_TRACE_BITS);

  // `firstRound` and `ninthRound` are assigned by the loop above, which always
  // runs; the non-null assertions would be the alternative and this is checkable.
  if (!firstRound || !ninthRound) throw new Error('the core always contributes rounds 1 and 9');

  return {
    segments,
    totalBits: at,
    windows: {
      'first-round': {
        startBit: firstRound.startBit,
        bits: firstRound.bits,
        label: 'round 1 of the table network',
      },
      'last-rounds': {
        startBit: ninthRound.startBit,
        bits: ninthRound.bits + finalRound.bits,
        label: 'rounds 9 and 10 of the table network',
      },
      'whole-program': { startBit: 0, bits: at, label: 'every lookup the program makes' },
    },
  };
}

/** Byte `index` of a 128-bit value held as four 32-bit words. */
export function byteAt(vector: Uint32Array, index: number): number {
  return (vector[index >> 2] >>> ((index & 3) * 8)) & 0xff;
}

function setByte(vector: Uint32Array, index: number, value: number): void {
  const word = index >> 2;
  const shift = (index & 3) * 8;
  vector[word] = ((vector[word] & ~(0xff << shift)) | ((value & 0xff) << shift)) >>> 0;
}

interface Sink {
  readonly bits: Uint8Array;
  readonly stride: number;
  readonly byteBase: number;
  readonly mask: number;
  cursor: number;
}

function record(sink: Sink | null, value: number, width: number): void {
  if (sink === null) return;
  const { bits, stride, byteBase, mask } = sink;
  let cursor = sink.cursor;
  for (let b = 0; b < width; b++) {
    if ((value >>> b) & 1) bits[cursor * stride + byteBase] |= mask;
    cursor++;
  }
  sink.cursor = cursor;
}

/** XOR two encoded 128-bit values through thirty-two Type IV nibble tables. */
function xorBlock(
  tables: Uint8Array,
  step: number,
  left: Uint32Array,
  leftAt: number,
  right: Uint32Array,
  rightAt: number,
  out: Uint32Array,
  outAt: number,
): void {
  const base = step * 32 * 256;
  for (let w = 0; w < 4; w++) {
    const lw = left[leftAt + w];
    const rw = right[rightAt + w];
    let acc = 0;
    for (let k = 0; k < 8; k++) {
      const shift = k * 4;
      const a = (lw >>> shift) & 15;
      const b = (rw >>> shift) & 15;
      acc |= tables[base + (w * 8 + k) * 256 + ((a << 4) | b)] << shift;
    }
    out[outAt + w] = acc >>> 0;
  }
}

/** Scratch space one evaluation needs, allocated once per worker call. */
export interface RunScratch {
  readonly stage16: Uint32Array;
  readonly stage8: Uint32Array;
  readonly stage4: Uint32Array;
  readonly stage2: Uint32Array;
  readonly vector: Uint32Array;
  readonly next: Uint32Array;
  readonly encoded: Uint8Array;
  readonly nextEncoded: Uint8Array;
  readonly words: Uint32Array;
}

export function makeScratch(): RunScratch {
  return {
    stage16: new Uint32Array(16 * 4),
    stage8: new Uint32Array(8 * 4),
    stage4: new Uint32Array(4 * 4),
    stage2: new Uint32Array(2 * 4),
    vector: new Uint32Array(4),
    next: new Uint32Array(4),
    encoded: new Uint8Array(16),
    nextEncoded: new Uint8Array(16),
    words: new Uint32Array(4),
  };
}

function runSection(
  section: LinearSection,
  input: Uint32Array,
  output: Uint32Array,
  scratch: RunScratch,
  sink: Sink | null,
): void {
  const { fan, xor } = section;
  const { stage16, stage8, stage4, stage2 } = scratch;
  for (let b = 0; b < 16; b++) {
    const at = (b * 256 + byteAt(input, b)) * 4;
    const to = b * 4;
    stage16[to] = fan[at];
    stage16[to + 1] = fan[at + 1];
    stage16[to + 2] = fan[at + 2];
    stage16[to + 3] = fan[at + 3];
    record(sink, fan[at], 32);
    record(sink, fan[at + 1], 32);
    record(sink, fan[at + 2], 32);
    record(sink, fan[at + 3], 32);
  }
  for (let s = 0; s < 8; s++) {
    xorBlock(xor, s, stage16, 2 * s * 4, stage16, (2 * s + 1) * 4, stage8, s * 4);
    for (let w = 0; w < 4; w++) record(sink, stage8[s * 4 + w], 32);
  }
  for (let s = 0; s < 4; s++) {
    xorBlock(xor, 8 + s, stage8, 2 * s * 4, stage8, (2 * s + 1) * 4, stage4, s * 4);
    for (let w = 0; w < 4; w++) record(sink, stage4[s * 4 + w], 32);
  }
  for (let s = 0; s < 2; s++) {
    xorBlock(xor, 12 + s, stage4, 2 * s * 4, stage4, (2 * s + 1) * 4, stage2, s * 4);
    for (let w = 0; w < 4; w++) record(sink, stage2[s * 4 + w], 32);
  }
  xorBlock(xor, 14, stage2, 0, stage2, 4, output, 0);
  for (let w = 0; w < 4; w++) record(sink, output[w], 32);
}

/**
 * Run the program on one 16-byte input, optionally recording every lookup.
 *
 * `input` is what the PROGRAM is called with, which is not always a plaintext:
 * with the input encoding handled remotely it is F(P) for a P the caller knows
 * and the attacker does not. `output` is likewise what the program returns.
 */
export function runNetwork(
  network: WhiteBoxNetwork,
  input: Uint8Array,
  scratch: RunScratch,
  sink: Sink | null = null,
): Uint8Array {
  const { vector, next, encoded, nextEncoded, words } = scratch;
  vector[0] = 0;
  vector[1] = 0;
  vector[2] = 0;
  vector[3] = 0;
  for (let m = 0; m < 16; m++) setByte(vector, m, input[m]);

  let current = vector;
  let spare = next;
  for (const section of network.preCore) {
    runSection(section, current, spare, scratch, sink);
    const swap = current;
    current = spare;
    spare = swap;
  }
  for (let m = 0; m < 16; m++) encoded[m] = byteAt(current, m);

  let state = encoded;
  let nextState = nextEncoded;
  for (let r = 0; r < ROUNDS_WITH_MIXCOLUMNS; r++) {
    for (let j = 0; j < COLUMNS; j++) {
      for (let i = 0; i < ROWS; i++) {
        const w = network.typeII[typeIIOffset(r, j, i) + state[SHIFT_ROWS[i + 4 * j]]];
        words[i] = w;
        record(sink, w, 32);
      }
      const a01 = xorEncodedWord(network.typeIVa, typeIVOffset(r, j, 0), words[0], words[1]);
      record(sink, a01, 32);
      const a23 = xorEncodedWord(network.typeIVa, typeIVOffset(r, j, 1), words[2], words[3]);
      record(sink, a23, 32);
      const mixed = xorEncodedWord(network.typeIVa, typeIVOffset(r, j, 2), a01, a23);
      record(sink, mixed, 32);

      for (let b = 0; b < ROWS; b++) {
        const w = network.typeIII[typeIIIOffset(r, j, b) + ((mixed >>> (b * 8)) & 0xff)];
        words[b] = w;
        record(sink, w, 32);
      }
      const b01 = xorEncodedWord(network.typeIVb, typeIVOffset(r, j, 0), words[0], words[1]);
      record(sink, b01, 32);
      const b23 = xorEncodedWord(network.typeIVb, typeIVOffset(r, j, 1), words[2], words[3]);
      record(sink, b23, 32);
      const column = xorEncodedWord(network.typeIVb, typeIVOffset(r, j, 2), b01, b23);
      record(sink, column, 32);

      for (let i = 0; i < ROWS; i++) nextState[i + 4 * j] = (column >>> (i * 8)) & 0xff;
    }
    const swap = state;
    state = nextState;
    nextState = swap;
  }

  const result = new Uint8Array(16);
  for (let m = 0; m < 16; m++) {
    const value = network.typeV[(m << 8) + state[SHIFT_ROWS[m]]];
    result[m] = value;
    record(sink, value, 8);
  }

  if (network.postCore.length > 0) {
    current[0] = 0;
    current[1] = 0;
    current[2] = 0;
    current[3] = 0;
    for (let m = 0; m < 16; m++) setByte(current, m, result[m]);
    for (const section of network.postCore) {
      runSection(section, current, spare, scratch, sink);
      const swap = current;
      current = spare;
      spare = swap;
    }
    for (let m = 0; m < 16; m++) result[m] = byteAt(current, m);
  }
  return result;
}

export interface TraceSet {
  /** Sample-major packed bits: sample s, trace t at bit `t & 7` of `bits[s * stride + (t >> 3)]`. */
  readonly bits: Uint8Array;
  readonly stride: number;
  readonly traces: number;
  readonly totalBits: number;
  readonly map: TraceMap;
  /** What the program was called with, 16 bytes per trace. */
  readonly inputs: Uint8Array;
  /** What the program returned, 16 bytes per trace. */
  readonly outputs: Uint8Array;
}

/**
 * Bytes per sample row.
 *
 * Rounded up to a whole number of 32-bit words, not bytes: `dca.ts` reads each
 * sample's column as a `Uint32Array` and ANDs it against a partition bitset, and
 * a 4-byte-aligned stride is what lets it do that without a copy. The waste is
 * at most three bytes per sample.
 */
export function traceStrideBytes(traces: number): number {
  return ((traces + 31) >> 5) * 4;
}

/** Bytes a trace set of this shape will occupy, computed BEFORE allocation. */
export function traceSetBytes(totalBits: number, traces: number): number {
  return totalBits * traceStrideBytes(traces) + traces * 32;
}

/**
 * Run `traces` encryptions on the given inputs, recording each.
 *
 * `inputs` is supplied by the caller rather than generated here, because who
 * chooses the program's input is exactly what Act 5 is about: in the
 * remote-encoding states the attacker picks it and cannot say what plaintext it
 * corresponds to.
 */
export function collectTraces(
  network: WhiteBoxNetwork,
  inputs: Uint8Array,
  traces: number,
  onProgress?: (done: number) => void,
): TraceSet {
  if (inputs.length !== traces * 16) throw new Error('inputs must hold exactly 16 bytes per trace');
  const map = traceMapFor(network);
  const stride = traceStrideBytes(traces);
  const bits = new Uint8Array(map.totalBits * stride);
  const outputs = new Uint8Array(traces * 16);
  const scratch = makeScratch();
  const block = new Uint8Array(16);
  for (let t = 0; t < traces; t++) {
    block.set(inputs.subarray(t * 16, t * 16 + 16));
    const sink: Sink = { bits, stride, byteBase: t >> 3, mask: 1 << (t & 7), cursor: 0 };
    const out = runNetwork(network, block, scratch, sink);
    if (sink.cursor !== map.totalBits) {
      throw new Error(`trace map says ${map.totalBits} bits, the run wrote ${sink.cursor}`);
    }
    outputs.set(out, t * 16);
    if (onProgress && (t & 31) === 31) onProgress(t + 1);
  }
  if (onProgress) onProgress(traces);
  return { bits, stride, traces, totalBits: map.totalBits, map, inputs, outputs };
}

/** Read one bit of a trace set. Used by the heatmap and by the tests. */
export function traceBit(set: Pick<TraceSet, 'bits' | 'stride'>, sample: number, trace: number): number {
  return (set.bits[sample * set.stride + (trace >> 3)] >>> (trace & 7)) & 1;
}
