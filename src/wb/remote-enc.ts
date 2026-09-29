/**
 * The external-encoding party that is NOT inside the program (invariant I7).
 *
 * Chow et al. section 3.3: a white-box program computes G o AES_K o F^-1, not
 * AES_K. Somebody has to hold F and G. This module is that somebody, and it is a
 * separate module on purpose -- `src/attack/*` may not import it, and
 * `isolation.test.ts` reads the source to check that, so the third Act 5 state
 * is an information barrier rather than a flag the UI sets.
 *
 * What the party does depends on which encodings are remote:
 *
 *   none, compiled-in   nothing. The program's interface is already plain AES.
 *   remote-both         applies F on the way in and G^-1 on the way out.
 *   remote-input        applies F only. The program returns a real ciphertext.
 *   remote-output       applies G^-1 only. The program takes a real plaintext.
 *
 * So one statement covers all five states, which is how invariant I1 is checked
 * uniformly:  decodeOutput(program(encodeInput(P))) == AES-128(K, P).
 *
 * And the honest half: this MOVES the problem. Something outside the program now
 * holds a secret and has to apply it to every block. The page says so in the
 * same panel that reports the attack failing.
 */

import { apply128 } from '../math/gf2.js';
import type { EncodingPlacement, ExternalEncodingHandover } from './types.js';

export interface RemoteParty {
  /** True when this party holds anything at all. */
  readonly holdsInput: boolean;
  readonly holdsOutput: boolean;
  /** P -> whatever the program must be called with. */
  encodeInput(plaintext: Uint8Array): Uint8Array;
  /** Whatever the program returned -> the AES ciphertext. */
  decodeOutput(programOutput: Uint8Array): Uint8Array;
}

function applyBlock(rows: Uint32Array, block: Uint8Array): Uint8Array {
  const v = new Uint32Array(4);
  for (let m = 0; m < 16; m++) v[m >> 2] |= block[m] << ((m & 3) * 8);
  const y = new Uint32Array(4);
  apply128(rows, v, y);
  const out = new Uint8Array(16);
  for (let m = 0; m < 16; m++) out[m] = (y[m >> 2] >>> ((m & 3) * 8)) & 0xff;
  return out;
}

/** Which placements leave the input encoding outside the program. */
export function inputIsRemote(placement: EncodingPlacement): boolean {
  return placement === 'remote-both' || placement === 'remote-input';
}

/** Which placements leave the output encoding outside the program. */
export function outputIsRemote(placement: EncodingPlacement): boolean {
  return placement === 'remote-both' || placement === 'remote-output';
}

export function createRemoteParty(
  placement: EncodingPlacement,
  handover: ExternalEncodingHandover,
): RemoteParty {
  const holdsInput = inputIsRemote(placement);
  const holdsOutput = outputIsRemote(placement);
  if ((holdsInput || holdsOutput) && !handover.present) {
    throw new Error(`placement ${placement} needs external encodings, and none were handed over`);
  }
  return {
    holdsInput,
    holdsOutput,
    encodeInput(plaintext: Uint8Array): Uint8Array {
      if (plaintext.length !== 16) throw new Error('a block is 16 bytes');
      return holdsInput ? applyBlock(handover.inputRows, plaintext) : new Uint8Array(plaintext);
    },
    decodeOutput(programOutput: Uint8Array): Uint8Array {
      if (programOutput.length !== 16) throw new Error('a block is 16 bytes');
      return holdsOutput ? applyBlock(handover.outputInverseRows, programOutput) : new Uint8Array(programOutput);
    },
  };
}

/**
 * What the attacker can observe about one run, in this placement.
 *
 * This is the shape the DCA module is given, and the only shape. In the remote
 * states `plaintextKnown` is false and `observedInput` is the program's input --
 * a value the attacker chose and cannot relate to any AES plaintext. Nothing
 * here carries a plaintext the attacker has no right to.
 */
export interface Observability {
  /** Can the attacker relate the program's input to an AES plaintext? */
  readonly plaintextKnown: boolean;
  /** Can the attacker relate the program's output to an AES ciphertext? */
  readonly ciphertextKnown: boolean;
}

export function observabilityOf(placement: EncodingPlacement): Observability {
  return {
    plaintextKnown: !inputIsRemote(placement),
    ciphertextKnown: !outputIsRemote(placement),
  };
}
