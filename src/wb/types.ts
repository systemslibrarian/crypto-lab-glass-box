import type { Wire } from './encoding.js';

/**
 * Where the external encodings live. This is the Act 5 toggle, and it is the
 * only thing in the lab that changes whether DCA has a valid hypothesis at all.
 *
 * Chow et al. section 3.3 specifies external input and output encodings F and G,
 * so a white-box program computes G o AES_K o F^-1 rather than AES_K. Bos,
 * Hubain, Michiels and Teuwen (CHES 2016) scope DCA to implementations applying
 * "at most a single remotely handled external encoding", and report in section
 * 5.4 that encodings which are part of the binary made no difference to the
 * attack, because the attacker knows the original plaintexts before any encoding
 * is applied. These five states are that sentence, made measurable.
 */
export type EncodingPlacement =
  /** F = G = identity. The program is plain AES. */
  | 'none'
  /** F and G exist, and so do their inverses -- all four inside the program. */
  | 'compiled-in'
  /** F and G are held outside the program, on both sides. */
  | 'remote-both'
  /** Only F is held outside. The program's output is a real AES ciphertext. */
  | 'remote-input'
  /** Only G is held outside. The program's input is a real AES plaintext. */
  | 'remote-output';

export const ENCODING_PLACEMENTS: readonly EncodingPlacement[] = [
  'none',
  'compiled-in',
  'remote-both',
  'remote-input',
  'remote-output',
];

/**
 * Which side of the cipher the attacker can form hypotheses about, given what
 * the program's interface exposes.
 */
export type AttackSurface = 'input' | 'output';

/** What DCA predicts. Act 4's two targets, plus the last-round mirror. */
export type DcaTarget =
  /** S(x ^ g), the first-round SubBytes output. */
  | 'sbox-output'
  /** (x ^ g)^-1, the multiplicative inverse inside SubBytes. */
  | 'inverse'
  /** S^-1(c ^ g), the round-10 state before the final SubBytes. */
  | 'last-round';

/** The slice of the recorded trace DCA scores. */
export type TraceWindow = 'first-round' | 'last-rounds' | 'whole-program';

/** One kind of table in the shipped program, counted and measured. */
export interface TableGroup {
  readonly id: string;
  /** Chow's own name for it, where he has one. */
  readonly label: string;
  readonly count: number;
  /** Bytes one table occupies as this lab allocates it. */
  readonly entryBytes: number;
  readonly bytes: number;
  readonly note: string;
}

export interface NetworkInventory {
  readonly groups: readonly TableGroup[];
  readonly tables: number;
  readonly bytes: number;
  /**
   * The same total with each 4-bit XOR table packed two entries to a byte, which
   * is how the literature counts them. Reported alongside the allocated figure
   * rather than instead of it.
   */
  readonly packedBytes: number;
}

/** A 128-bit GF(2)-linear map realised as Chow Type IA/IB tables plus an XOR tree. */
export interface LinearSection {
  readonly id: 'encode-in' | 'strip-in' | 'add-out' | 'decode-out';
  readonly label: string;
  /** 16 tables x 256 entries x 4 words: byte b of the input to a 128-bit vector. */
  readonly fan: Uint32Array;
  /** 15 XOR-tree steps x 32 nibbles x 256 entries. */
  readonly xor: Uint8Array;
  readonly inputWire: Wire;
  readonly outputWire: Wire;
}

export interface WhiteBoxNetwork {
  readonly placement: EncodingPlacement;
  /** 9 rounds x 4 columns x 4 rows x 256 entries, 8 -> 32 (Chow Type II). */
  readonly typeII: Uint32Array;
  /** 9 x 4 x 4 x 256, 8 -> 32 (Chow Type III: undoes the 32-bit mixing bijection). */
  readonly typeIII: Uint32Array;
  /** 9 x 4 x 3 steps x 8 nibbles x 256, 8 -> 4 (Chow Type IV), after the Type II tables. */
  readonly typeIVa: Uint8Array;
  /** The same, after the Type III tables. */
  readonly typeIVb: Uint8Array;
  /** 16 x 256, 8 -> 8: round 10, which has no MixColumns. */
  readonly typeV: Uint8Array;
  /** Applied to the program's input, in order. */
  readonly preCore: readonly LinearSection[];
  /** Applied to the core's output, in order. */
  readonly postCore: readonly LinearSection[];
  /** Encoding on the 16 bytes entering round 1. */
  readonly coreInputWire: Wire;
  /** Encoding on the 16 bytes leaving round 10. */
  readonly coreOutputWire: Wire;
  readonly inventory: NetworkInventory;
  /** How many draws `randomInvertible` needed, summed. Reported, not hidden. */
  readonly matrixDraws: number;
  readonly buildMs: number;
}

/**
 * The half of the external encodings that does NOT ship inside the program.
 *
 * The build tool knows every encoding -- it made them. The point of invariant I7
 * is not that this object is unreachable in principle, it is that the ATTACK
 * modules cannot import it: `src/attack/*` may not import `wb-gen.ts` or
 * `remote-enc.ts`, and `isolation.test.ts` reads the source to check it. In the
 * remote states this object is what a separate party holds, and the attacker's
 * observable input is the program's input rather than the plaintext.
 */
export interface ExternalEncodingHandover {
  /** F as 128 rows of 4 words. The program contains F^-1 as Type IA tables. */
  readonly inputRows: Uint32Array;
  /** G^-1. The program contains G as Type IB tables. */
  readonly outputInverseRows: Uint32Array;
  readonly present: boolean;
}
