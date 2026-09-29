/**
 * What the UI thread and the worker say to each other, and the failure codes the
 * lab can raise.
 *
 * ON THE FAILURE CODES, which is a point worth making rather than a formality:
 * every code below belongs to THIS LAB'S input validation. The white-box program
 * has none. It cannot tell that it is being traced, cannot refuse to run, and
 * raises nothing when its key is being extracted -- there is no code for that,
 * because a table network has no way to notice. The page says so where a reader
 * will see it, and the absence is the exhibit.
 */

import type { BgeFailureCode } from './attack/bge.js';
import type { AttackSurface, DcaTarget, EncodingPlacement, TableGroup, TraceWindow } from './wb/types.js';

export const LAB_FAILURE_CODES = [
  /** The key field held something that is not hexadecimal. */
  'KEY_HEX_MALFORMED',
  /** The key field held the wrong number of bytes for AES-128. */
  'KEY_LENGTH_INVALID',
  /** The trace count was outside the range the page states. */
  'TRACE_COUNT_OUT_OF_RANGE',
  /** The trace buffer this run would need exceeds the stated budget. */
  'TRACE_BUDGET_EXCEEDED',
  /** No target or no prediction bit was selected, so there is nothing to score. */
  'NO_HYPOTHESIS_SELECTED',
  /** Asked to trace or attack before a program existed. */
  'NO_PROGRAM_BUILT',
  /** Asked to attack before any traces were recorded. */
  'NO_TRACES_RECORDED',
] as const;
export type LabFailureCode = (typeof LAB_FAILURE_CODES)[number];

/** Every code the page can surface, the lab's and the algebraic attack's. */
export type FailureCode = LabFailureCode | BgeFailureCode;

export const MIN_TRACES = 8;
/**
 * The cap, and the reason for it.
 *
 * DCA's scoring cost is almost flat in the trace count -- the convolution is over
 * the 256 byte values, not over the traces -- so the binding constraint is the
 * trace buffer, which is (bits per trace) x ceil(N / 32) x 4 bytes. With the
 * external encodings compiled in a trace is 32,128 bits, so N = 2,048 needs about
 * 8.4 MB and N = 8,192 would need 33 MB before the attack starts. 2,048 also
 * comfortably covers the 2,000 traces Bos et al. report using, which is the
 * figure a reader is most likely to want to reproduce.
 */
export const MAX_TRACES = 2048;
export const DEFAULT_TRACES = 384;
/** The budget `TRACE_BUDGET_EXCEEDED` guards, in bytes. */
export const TRACE_BUDGET_BYTES = 24 * 1024 * 1024;

export interface BuildRequest {
  readonly kind: 'build';
  readonly keyHex: string;
  readonly placement: EncodingPlacement;
  /** Empty means crypto.getRandomValues; anything else makes the instance reproducible. */
  readonly seed: string;
}

export interface TraceRequest {
  readonly kind: 'trace';
  readonly traces: number;
}

export interface DcaRunRequest {
  readonly kind: 'dca';
  readonly surface: AttackSurface;
  readonly targets: readonly DcaTarget[];
  readonly bits: readonly number[];
  /** Which key byte the 256-curve plot should be computed for, or null for none. */
  readonly curveByte: number | null;
}

export interface HeatmapRequest {
  readonly kind: 'heatmap';
  /** Sort the trace rows by the bit this hypothesis predicts, or null to leave them in order. */
  readonly sortBy: { readonly byteIndex: number; readonly guess: number; readonly target: DcaTarget; readonly bit: number } | null;
  readonly window: TraceWindow;
  /** Absolute sample index to centre the zoomed strip on. */
  readonly focusSample: number | null;
  readonly maxRows: number;
  readonly focusHalfWidth: number;
}

export interface BgeRequest {
  readonly kind: 'bge';
  readonly round: number;
  readonly column: number;
}

/** One request without its correlation id, which the client adds. */
export type RequestBody = BuildRequest | TraceRequest | DcaRunRequest | HeatmapRequest | BgeRequest;

export type LabRequest = RequestBody & { readonly id: number };

export interface VerificationReport {
  /** FIPS 197 Appendix C.1, run through the table network end to end. */
  readonly fipsVectorMatches: boolean;
  readonly fipsCiphertextHex: string;
  /** Random blocks compared against WebCrypto, the independent path. */
  readonly randomBlocks: number;
  readonly randomBlocksMatching: number;
  readonly webCryptoAvailable: boolean;
}

export interface BuildReport {
  readonly kind: 'build';
  readonly placement: EncodingPlacement;
  readonly groups: readonly TableGroup[];
  readonly tables: number;
  readonly bytes: number;
  readonly packedBytes: number;
  readonly matrixDraws: number;
  readonly buildMs: number;
  readonly traceBits: number;
  readonly segments: readonly { id: string; label: string; startBit: number; bits: number }[];
  readonly verification: VerificationReport;
  readonly randomnessOrigin: 'system' | 'seed';
  /** True when the program contains the encoder as well as the core that strips it. */
  readonly encoderInProgram: boolean;
  readonly inputIsRemote: boolean;
  readonly outputIsRemote: boolean;
}

export interface TraceReport {
  readonly kind: 'trace';
  readonly traces: number;
  readonly bitsPerTrace: number;
  readonly bufferBytes: number;
  readonly predictedBufferBytes: number;
  readonly elapsedMs: number;
  /** Fraction of samples that took both values across the trace set. */
  readonly varyingSamples: number;
  readonly windows: Readonly<Record<TraceWindow, { startBit: number; bits: number; label: string }>>;
}

export interface DcaByteReport {
  readonly index: number;
  readonly guess: number;
  readonly peak: number;
  readonly runnerUpGuess: number;
  readonly runnerUp: number;
  readonly margin: number;
  readonly peakSample: number;
  readonly peakTarget: DcaTarget;
  readonly peakBit: number;
  readonly correct: boolean;
  readonly truth: number;
  readonly peaks: Float32Array;
}

export interface DcaReport {
  readonly kind: 'dca';
  readonly surface: AttackSurface;
  readonly window: TraceWindow;
  readonly windowLabel: string;
  readonly sampleStart: number;
  readonly sampleCount: number;
  readonly traces: number;
  readonly targets: readonly DcaTarget[];
  readonly bits: readonly number[];
  readonly elapsedMs: number;
  readonly bytes: readonly DcaByteReport[];
  /** What the attack committed to, before any comparison. */
  readonly recoveredHex: string;
  readonly correctCount: number;
  readonly complete: boolean;
  /** What the recovery is OF: the key, or the last round key. */
  readonly recovers: 'key' | 'last-round-key';
  /** For the output side: the key the inverse schedule gives, and how much of it is right. */
  readonly derivedKeyHex: string | null;
  readonly derivedKeyCorrectCount: number | null;
  readonly truthHex: string;
  /** Bytes a blind guesser would expect to get right. */
  readonly chanceCorrect: number;
  /** Whether the placement gives this surface a hypothesis it can even form. */
  readonly hypothesisValid: boolean;
  readonly curves: { byteIndex: number; target: DcaTarget; bit: number; values: Float32Array; max: number } | null;
}

export interface HeatmapReport {
  readonly kind: 'heatmap';
  /** Row-major greyscale, one byte per cell, `rows` x `cols`. */
  readonly full: Uint8Array;
  readonly rows: number;
  readonly cols: number;
  readonly rowsAvailable: number;
  readonly startSample: number;
  /** The zoomed strip around `focusSample`, same encoding. */
  readonly focus: Uint8Array | null;
  readonly focusCols: number;
  readonly focusStartSample: number;
  /** Where the two halves of the partition meet, when the rows were sorted. */
  readonly splitRow: number | null;
  readonly sortedBy: string | null;
  /**
   * Per focus column, the fraction of ONE bits among the traces whose predicted
   * bit is 0, and among those whose predicted bit is 1 -- over every trace, not
   * just the rows drawn. Their difference IS the difference of means the attack
   * maximises, so drawing the pair beside the strip shows the statistic itself
   * rather than a picture of the data it came from.
   */
  readonly meanZero: Float32Array | null;
  readonly meanOne: Float32Array | null;
  readonly groupZeroTraces: number;
  readonly groupOneTraces: number;
}

export interface BgeReport {
  readonly kind: 'bge';
  readonly round: number;
  readonly column: number;
  readonly evaluations: number;
  readonly elapsedMs: number;
  readonly stripped: boolean;
  readonly bytes: readonly {
    row: number;
    groupOrder: number;
    everyElementIsAnInvolution: boolean;
    basisSize: number;
    spreadBefore: number;
    spreadAfter: number;
  }[];
}

export interface ProgressMessage {
  readonly kind: 'progress';
  readonly id: number;
  readonly phase: string;
  readonly done: number;
  readonly total: number;
}

export interface FailureMessage {
  readonly kind: 'failure';
  readonly id: number;
  readonly code: FailureCode;
  readonly message: string;
}

export type LabResponse =
  | ProgressMessage
  | FailureMessage
  | ({ readonly id: number } & (BuildReport | TraceReport | DcaReport | HeatmapReport | BgeReport));
