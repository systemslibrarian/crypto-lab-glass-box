/**
 * The lab's compute thread.
 *
 * Everything expensive happens here: building 2,032 lookup tables, running
 * hundreds of encryptions with the tracer attached, scoring 4,096 key hypotheses
 * against up to 3.7 million trace bits, and BGE's 65,536 column evaluations. On
 * the UI thread any one of those would freeze the page for seconds, and a page
 * that freezes cannot report progress, which is the difference between "it is
 * working" and "it is broken".
 *
 * It is also where the invariants live that a UI cannot enforce:
 *
 *  I2/I7  The attack is handed only what an attacker could observe. In the remote
 *         placements that is the value the PROGRAM was called with, never the
 *         plaintext -- see `knownFor`.
 *  I3     `runDca` returns a committed answer, and only then does `judgeRecovery`
 *         compare it with the truth. The two calls are adjacent here so the order
 *         is readable rather than documented.
 *  I5     Trace buffers are sized before allocation and refused above the stated
 *         budget, with a named code.
 */

/// <reference lib="webworker" />

import { aes128Encrypt, expandKey, invertKeySchedule } from './aes/aes-ref.js';
import { runBgeStepA1, BgeError } from './attack/bge.js';
import {
  CHANCE_CORRECT_BYTES,
  dcaCurves,
  judgeRecovery,
  predictBit,
  runDca,
  type DcaRequest,
  type Distinguisher,
} from './attack/dca.js';
import {
  LAB_FAILURE_CODES,
  MAX_TRACES,
  MIN_TRACES,
  TRACE_BUDGET_BYTES,
  type BgeReport,
  type BuildReport,
  type DcaByteReport,
  type DcaReport,
  type FailureCode,
  type HeatmapReport,
  type LabRequest,
  type LabResponse,
  type TraceReport,
  type VerificationReport,
} from './protocol.js';
import { createRemoteParty, inputIsRemote, outputIsRemote, type RemoteParty } from './wb/remote-enc.js';
import { seededRng, systemRng } from './wb/rng.js';
import { buildNetwork } from './wb/wb-gen.js';
import {
  collectTraces,
  makeScratch,
  runNetwork,
  traceBit,
  traceMapFor,
  traceSetBytes,
  type TraceSet,
} from './wb/wb-run.js';
import type { AttackSurface, DcaTarget, EncodingPlacement, TraceWindow, WhiteBoxNetwork } from './wb/types.js';

class LabError extends Error {
  constructor(
    readonly code: FailureCode,
    message: string,
  ) {
    super(message);
  }
}

interface Session {
  readonly network: WhiteBoxNetwork;
  readonly party: RemoteParty;
  readonly key: Uint8Array;
  readonly lastRoundKey: Uint8Array;
  readonly placement: EncodingPlacement;
  /**
   * The seed this instance was built from, empty for an unseeded one. Kept so
   * the TRACE can be drawn reproducibly too: a seed that pinned the program but
   * not the plaintexts fed to it would make "the same link gives the same
   * recovery" false, because the recovery is measured off those plaintexts.
   */
  readonly seed: string;
}

let session: Session | null = null;
let traceSet: TraceSet | null = null;

function post(message: LabResponse, transfer: Transferable[] = []): void {
  (self as unknown as Worker).postMessage(message, transfer);
}

function parseKey(hex: string): Uint8Array {
  const cleaned = hex.replace(/\s+/g, '').toLowerCase();
  if (!/^[0-9a-f]*$/.test(cleaned)) {
    throw new LabError('KEY_HEX_MALFORMED', 'the key must be hexadecimal: the digits 0-9 and the letters a-f.');
  }
  if (cleaned.length !== 32) {
    const bytes = cleaned.length / 2;
    throw new LabError(
      'KEY_LENGTH_INVALID',
      `AES-128 takes a 16-byte key, which is 32 hex digits. That is ${cleaned.length} digits${
        cleaned.length % 2 === 0 ? `, or ${bytes} bytes` : ''
      }.`,
    );
  }
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(cleaned.slice(2 * i, 2 * i + 2), 16);
  return out;
}

const hex = (bytes: Uint8Array): string => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

/** AES-ECB over one block via WebCrypto AES-CBC with a zero IV: the independent path. */
async function webCryptoBlock(key: Uint8Array, block: Uint8Array): Promise<Uint8Array | null> {
  if (!self.crypto?.subtle) return null;
  try {
    const imported = await self.crypto.subtle.importKey('raw', key as BufferSource, 'AES-CBC', false, ['encrypt']);
    const out = await self.crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: new Uint8Array(16) },
      imported,
      block as BufferSource,
    );
    return new Uint8Array(out).subarray(0, 16);
  } catch {
    return null;
  }
}

/** Invariant I1, run on every build so the page never claims it without checking. */
async function verify(network: WhiteBoxNetwork, party: RemoteParty, key: Uint8Array): Promise<VerificationReport> {
  const scratch = makeScratch();
  const through = (plaintext: Uint8Array): Uint8Array =>
    party.decodeOutput(runNetwork(network, party.encodeInput(plaintext), scratch));

  const fipsKey = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
  const fipsPlain = new Uint8Array([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  ]);
  // The FIPS vector needs its own instance, because this network holds the
  // reader's key. Same placement, same randomness source shape.
  const fipsBuild = buildNetwork(fipsKey, network.placement, systemRng());
  const fipsParty = createRemoteParty(network.placement, fipsBuild.handover);
  const fipsCiphertext = fipsParty.decodeOutput(
    runNetwork(fipsBuild.network, fipsParty.encodeInput(fipsPlain), makeScratch()),
  );

  const randomBlocks = 8;
  let matching = 0;
  let available = true;
  for (let i = 0; i < randomBlocks; i++) {
    const plaintext = systemRng().bytes(16);
    const mine = through(plaintext);
    const theirs = await webCryptoBlock(key, plaintext);
    if (theirs === null) {
      available = false;
      // Fall back to this repo's own reference, and say so in the report.
      if (hex(mine) === hex(aes128Encrypt(key, plaintext))) matching++;
    } else if (hex(mine) === hex(theirs)) {
      matching++;
    }
  }

  return {
    fipsVectorMatches: hex(fipsCiphertext) === '69c4e0d86a7b0430d8cdb78070b4c55a',
    fipsCiphertextHex: hex(fipsCiphertext),
    randomBlocks,
    randomBlocksMatching: matching,
    webCryptoAvailable: available,
  };
}

async function handleBuild(id: number, keyHex: string, placement: EncodingPlacement, seed: string): Promise<void> {
  const key = parseKey(keyHex);
  const rng = seed.length > 0 ? seededRng(seed) : systemRng();
  post({ kind: 'progress', id, phase: 'building the table network', done: 0, total: 1 });
  const { network, handover } = buildNetwork(key, placement, rng);
  const party = createRemoteParty(placement, handover);
  session = {
    network,
    party,
    key,
    lastRoundKey: new Uint8Array(expandKey(key).subarray(160, 176)),
    placement,
    seed,
  };
  traceSet = null;

  post({ kind: 'progress', id, phase: 'checking the network against WebCrypto', done: 1, total: 2 });
  const verification = await verify(network, party, key);

  const map = traceMapFor(network);
  const report: BuildReport = {
    kind: 'build',
    placement,
    groups: network.inventory.groups,
    tables: network.inventory.tables,
    bytes: network.inventory.bytes,
    packedBytes: network.inventory.packedBytes,
    matrixDraws: network.matrixDraws,
    buildMs: network.buildMs,
    traceBits: map.totalBits,
    segments: map.segments.map((s) => ({ id: s.id, label: s.label, startBit: s.startBit, bits: s.bits })),
    verification,
    randomnessOrigin: rng.origin,
    encoderInProgram: placement === 'compiled-in',
    inputIsRemote: inputIsRemote(placement),
    outputIsRemote: outputIsRemote(placement),
  };
  post({ id, ...report });
}

/**
 * Who chooses the program's input, and what the attacker can say about it.
 *
 * With the input encoding handled remotely the attacker cannot produce a chosen
 * PLAINTEXT at all -- they can only feed the program values and watch. So the
 * inputs are drawn uniformly either way, and what changes is whether the
 * attacker's hypotheses have anything true to be about.
 */
function handleTrace(id: number, traces: number): void {
  const current = session;
  if (!current) throw new LabError('NO_PROGRAM_BUILT', 'build the program first: the trace is of its table lookups.');
  if (!Number.isInteger(traces) || traces < MIN_TRACES || traces > MAX_TRACES) {
    throw new LabError(
      'TRACE_COUNT_OUT_OF_RANGE',
      `the trace count must be a whole number between ${MIN_TRACES} and ${MAX_TRACES}.`,
    );
  }
  const map = traceMapFor(current.network);
  const predicted = traceSetBytes(map.totalBits, traces);
  if (predicted > TRACE_BUDGET_BYTES) {
    throw new LabError(
      'TRACE_BUDGET_EXCEEDED',
      `${traces} traces of ${map.totalBits} bits would need ${(predicted / 1048576).toFixed(1)} MB, over this lab's ${(
        TRACE_BUDGET_BYTES / 1048576
      ).toFixed(0)} MB budget. The size is computed before anything is allocated.`,
    );
  }
  const startedAt = Date.now();
  /*
   * The attacker's chosen plaintexts. Seeded when the instance is, so a seeded
   * run really is one run: same program, same plaintexts, same recovery, which
   * is what the page and the share link both say.
   *
   * The stream is derived from seed + '/traces' rather than continuing the one
   * that built the encodings. Domain separation costs nothing here and keeps
   * the two uses of a seed from ever being the same bytes -- a trace input that
   * happened to be encoding material would be a hard thing to notice and an
   * embarrassing thing to explain.
   *
   * It does not make the attack easier. DCA needs plaintexts it KNOWS, not
   * plaintexts that are unpredictable; where they came from is not an input to
   * the statistic. An unseeded instance still draws them from the system RNG.
   */
  const inputs =
    current.seed.length > 0 ? seededRng(`${current.seed}/traces`).bytes(traces * 16) : systemRng().bytes(traces * 16);
  const set = collectTraces(current.network, inputs, traces, (done) => {
    post({ kind: 'progress', id, phase: 'running traced encryptions', done, total: traces });
  });
  traceSet = set;

  let varying = 0;
  for (let s = 0; s < set.totalBits; s++) {
    const first = traceBit(set, s, 0);
    for (let t = 1; t < traces; t++) {
      if (traceBit(set, s, t) !== first) {
        varying++;
        break;
      }
    }
  }
  const report: TraceReport = {
    kind: 'trace',
    traces,
    bitsPerTrace: set.totalBits,
    bufferBytes: set.bits.byteLength + set.inputs.byteLength + set.outputs.byteLength,
    predictedBufferBytes: predicted,
    elapsedMs: Date.now() - startedAt,
    varyingSamples: varying / set.totalBits,
    windows: set.map.windows,
  };
  post({ id, ...report });
}

function windowFor(surface: AttackSurface): TraceWindow {
  return surface === 'input' ? 'first-round' : 'last-rounds';
}

function requestFor(
  surface: AttackSurface,
  set: TraceSet,
  targets: readonly DcaTarget[],
  bits: readonly number[],
  distinguisher: Distinguisher,
): DcaRequest {
  const w = set.map.windows[windowFor(surface)];
  return {
    bits: set.bits,
    stride: set.stride,
    traces: set.traces,
    sampleStart: w.startBit,
    sampleCount: w.bits,
    // The attacker's observable: the value the PROGRAM was called with, or the
    // value it returned. Never a plaintext they have no way to know.
    known: surface === 'input' ? set.inputs : set.outputs,
    targets,
    bits4: bits,
    distinguisher,
  };
}

function handleDca(
  id: number,
  surface: AttackSurface,
  targets: readonly DcaTarget[],
  bits: readonly number[],
  distinguisher: Distinguisher,
  curveByte: number | null,
): void {
  const current = session;
  if (!current) throw new LabError('NO_PROGRAM_BUILT', 'build the program first.');
  const set = traceSet;
  if (!set) throw new LabError('NO_TRACES_RECORDED', 'record some traces first: DCA is a statistical attack on them.');
  if (targets.length === 0 || bits.length === 0) {
    throw new LabError(
      'NO_HYPOTHESIS_SELECTED',
      'pick at least one target and one prediction bit: with none there is nothing to correlate.',
    );
  }

  const request = requestFor(surface, set, targets, bits, distinguisher);
  post({ kind: 'progress', id, phase: 'scoring 4,096 key hypotheses', done: 0, total: 16 });
  const result = runDca(request, (done) => {
    post({ kind: 'progress', id, phase: 'scoring 4,096 key hypotheses', done, total: 16 });
  });

  // Invariant I3: the attack has committed. Only now is the truth consulted.
  const truth = surface === 'input' ? current.key : current.lastRoundKey;
  const verdict = judgeRecovery(result.recovered, truth);

  const derivedKey = surface === 'output' ? invertKeySchedule(result.recovered) : null;
  const derivedVerdict = derivedKey ? judgeRecovery(derivedKey, current.key) : null;

  const bytes: DcaByteReport[] = result.bytes.map((b) => ({
    index: b.index,
    guess: b.guess,
    peak: b.peak,
    runnerUpGuess: b.runnerUpGuess,
    runnerUp: b.runnerUp,
    margin: b.margin,
    peakSample: b.peakSample,
    peakTarget: b.peakTarget,
    peakBit: b.peakBit,
    bestDelta: b.bestDelta,
    correct: verdict.correct[b.index],
    truth: truth[b.index],
    peaks: b.peaks,
  }));

  let curves: DcaReport['curves'] = null;
  if (curveByte !== null && curveByte >= 0 && curveByte < 16) {
    const winner = result.bytes[curveByte];
    const target = winner.peakTarget;
    const bit = winner.peakBit >= 0 ? winner.peakBit : bits[0];
    const computed = dcaCurves(request, curveByte, target, bit);
    curves = { byteIndex: curveByte, target, bit, values: computed.curves, max: computed.max };
  }

  // Invariant I3 again: the rank table is read out of the committed scoring, and
  // the TRUTH is used only here, after `runDca` has returned, to say which row of
  // each table belongs to the real key byte.
  const combos = result.combos;
  const trueRanks = new Int32Array(16 * combos.length);
  let extremeRanks = 0;
  for (let m = 0; m < 16; m++) {
    for (let c = 0; c < combos.length; c++) {
      const rank = result.ranks[(m * combos.length + c) * 256 + truth[m]];
      trueRanks[m * combos.length + c] = rank;
      if (rank === 1 || rank === 256) extremeRanks++;
    }
  }

  const hypothesisValid = surface === 'input' ? !inputIsRemote(current.placement) : !outputIsRemote(current.placement);

  const report: DcaReport = {
    kind: 'dca',
    surface,
    window: windowFor(surface),
    windowLabel: set.map.windows[windowFor(surface)].label,
    sampleStart: request.sampleStart,
    sampleCount: request.sampleCount,
    traces: set.traces,
    targets,
    bits,
    distinguisher,
    combos,
    trueRanks,
    extremeRanks,
    elapsedMs: result.elapsedMs,
    bytes,
    recoveredHex: hex(result.recovered),
    correctCount: verdict.correctCount,
    complete: verdict.complete,
    recovers: surface === 'input' ? 'key' : 'last-round-key',
    derivedKeyHex: derivedKey ? hex(derivedKey) : null,
    derivedKeyCorrectCount: derivedVerdict ? derivedVerdict.correctCount : null,
    truthHex: hex(truth),
    chanceCorrect: CHANCE_CORRECT_BYTES,
    hypothesisValid,
    curves,
  };
  post({ id, ...report }, curves ? [curves.values.buffer] : []);
}

function handleHeatmap(
  id: number,
  sortBy: { byteIndex: number; guess: number; target: DcaTarget; bit: number } | null,
  window: TraceWindow,
  focusSample: number | null,
  maxRows: number,
  focusHalfWidth: number,
): void {
  const set = traceSet;
  if (!set) throw new LabError('NO_TRACES_RECORDED', 'record some traces first.');
  const w = set.map.windows[window];
  const current = session;
  if (!current) throw new LabError('NO_PROGRAM_BUILT', 'build the program first.');

  // Row order: as recorded, or split by the bit a hypothesis predicts. The split
  // is the whole exhibit -- under the right guess a band appears at the leaking
  // sample, and under a wrong one it does not.
  let order: number[] = [];
  let splitRow: number | null = null;
  if (sortBy) {
    const known = window === 'first-round' ? set.inputs : set.outputs;
    const zero: number[] = [];
    const one: number[] = [];
    for (let t = 0; t < set.traces; t++) {
      const value = known[t * 16 + sortBy.byteIndex];
      (predictBit(sortBy.target, value, sortBy.guess, sortBy.bit) === 1 ? one : zero).push(t);
    }
    order = [...zero, ...one];
    splitRow = zero.length;
  } else {
    for (let t = 0; t < set.traces; t++) order.push(t);
  }

  const rows = Math.min(order.length, maxRows);
  // Even subsampling preserves the two blocks when the rows were split.
  const pick = (r: number): number => order[Math.floor((r * order.length) / rows)];
  const scaledSplit = splitRow === null ? null : Math.round((splitRow * rows) / order.length);

  const cols = w.bits;
  const full = new Uint8Array(rows * cols);
  for (let r = 0; r < rows; r++) {
    const t = pick(r);
    for (let c = 0; c < cols; c++) full[r * cols + c] = traceBit(set, w.startBit + c, t) ? 235 : 22;
  }

  let focus: Uint8Array | null = null;
  let focusCols = 0;
  let focusStart = 0;
  let meanZero: Float32Array | null = null;
  let meanOne: Float32Array | null = null;
  const groupZeroTraces = splitRow ?? order.length;
  const groupOneTraces = order.length - groupZeroTraces;
  if (focusSample !== null) {
    focusStart = Math.max(w.startBit, Math.min(focusSample - focusHalfWidth, w.startBit + cols - 1));
    const end = Math.min(w.startBit + cols, focusStart + focusHalfWidth * 2 + 1);
    focusCols = end - focusStart;
    focus = new Uint8Array(rows * focusCols);
    for (let r = 0; r < rows; r++) {
      const t = pick(r);
      for (let c = 0; c < focusCols; c++) focus[r * focusCols + c] = traceBit(set, focusStart + c, t) ? 235 : 22;
    }
    // The two means, over EVERY trace in each half rather than the drawn rows:
    // the strip is a sample of the data, the bars are the whole statistic.
    meanZero = new Float32Array(focusCols);
    meanOne = new Float32Array(focusCols);
    for (let c = 0; c < focusCols; c++) {
      let zeros = 0;
      let ones = 0;
      for (let i = 0; i < order.length; i++) {
        const bit = traceBit(set, focusStart + c, order[i]);
        if (i < groupZeroTraces) zeros += bit;
        else ones += bit;
      }
      meanZero[c] = groupZeroTraces > 0 ? zeros / groupZeroTraces : 0;
      meanOne[c] = groupOneTraces > 0 ? ones / groupOneTraces : 0;
    }
  }

  const report: HeatmapReport = {
    kind: 'heatmap',
    full,
    rows,
    cols,
    rowsAvailable: order.length,
    startSample: w.startBit,
    focus,
    focusCols,
    focusStartSample: focusStart,
    splitRow: scaledSplit,
    sortedBy: sortBy
      ? `byte ${sortBy.byteIndex}, guess 0x${sortBy.guess.toString(16).padStart(2, '0')}, bit ${sortBy.bit}`
      : null,
    meanZero,
    meanOne,
    groupZeroTraces,
    groupOneTraces,
  };
  const transfer: Transferable[] = [full.buffer];
  if (focus) transfer.push(focus.buffer);
  if (meanZero) transfer.push(meanZero.buffer);
  if (meanOne) transfer.push(meanOne.buffer);
  post({ id, ...report }, transfer);
}

function handleBge(id: number, round: number, column: number): void {
  const current = session;
  if (!current) throw new LabError('NO_PROGRAM_BUILT', 'build the program first: BGE reads its tables.');
  const result = runBgeStepA1(
    {
      typeII: current.network.typeII,
      typeIII: current.network.typeIII,
      typeIVa: current.network.typeIVa,
      typeIVb: current.network.typeIVb,
    },
    round,
    column,
  );
  const report: BgeReport = {
    kind: 'bge',
    round: result.round,
    column: result.column,
    evaluations: result.evaluations,
    elapsedMs: result.elapsedMs,
    stripped: result.stripped,
    bytes: result.bytes.map((b) => ({
      row: b.row,
      groupOrder: b.groupOrder,
      everyElementIsAnInvolution: b.everyElementIsAnInvolution,
      basisSize: b.basis.length,
      spreadBefore: b.spreadBefore,
      spreadAfter: b.spreadAfter,
    })),
  };
  post({ id, ...report });
}

self.addEventListener('message', (event: MessageEvent<LabRequest>) => {
  const request = event.data;
  void (async (): Promise<void> => {
    try {
      switch (request.kind) {
        case 'build':
          await handleBuild(request.id, request.keyHex, request.placement, request.seed);
          break;
        case 'trace':
          handleTrace(request.id, request.traces);
          break;
        case 'dca':
          handleDca(
            request.id,
            request.surface,
            request.targets,
            request.bits,
            request.distinguisher,
            request.curveByte,
          );
          break;
        case 'heatmap':
          handleHeatmap(
            request.id,
            request.sortBy ? { ...request.sortBy } : null,
            request.window,
            request.focusSample,
            request.maxRows,
            request.focusHalfWidth,
          );
          break;
        case 'bge':
          handleBge(request.id, request.round, request.column);
          break;
      }
    } catch (error) {
      if (error instanceof LabError) {
        post({ kind: 'failure', id: request.id, code: error.code, message: error.message });
      } else if (error instanceof BgeError) {
        post({ kind: 'failure', id: request.id, code: error.code, message: error.message });
      } else {
        // Nothing else should reach here. Reporting it as a lab failure keeps the
        // page honest rather than silently idle, and the codes list stays closed.
        post({
          kind: 'failure',
          id: request.id,
          code: LAB_FAILURE_CODES[0],
          message: `unexpected: ${error instanceof Error ? error.message : String(error)}`,
        });
      }
    }
  })();
});
