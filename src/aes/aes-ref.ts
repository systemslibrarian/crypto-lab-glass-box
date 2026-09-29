/**
 * A minimal AES-128 reference (FIPS 197).
 *
 * Two jobs, and they are deliberately separate:
 *
 *  1. It is the correctness reference the white-box table network is checked
 *     against -- alongside WebCrypto, which is the INDEPENDENT path (see
 *     `wb-run.test.ts`). A network that agreed only with this file would prove
 *     nothing about AES; it would prove the two share a bug.
 *  2. It supplies the two intermediates DCA predicts: the first-round SubBytes
 *     output and the multiplicative inverse inside SubBytes. Those are the
 *     attacker's hypotheses, so they are computed from the KNOWN input and a
 *     GUESSED key byte only -- never from the real key. See `dca.ts`.
 *
 * The state is the flat 16-byte array of FIPS 197 section 3.4: byte r + 4c is
 * row r, column c, so the input bytes fill the state column by column.
 */

import { GF_INV, gmul, INV_SBOX, MIX_COLUMNS, SBOX } from './gf.js';

export const AES_BLOCK_BYTES = 16;
export const AES128_KEY_BYTES = 16;
export const AES128_ROUNDS = 10;

/** Rcon[j] for j = 1..10: x^(j-1) in GF(2^8), the leading byte of the round constant. */
export const RCON: readonly number[] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/**
 * ShiftRows as a permutation of flat state indices: `SHIFT_ROWS[i]` is the
 * index the byte at output position `i` is READ FROM.
 *
 * Chow's construction needs this as data rather than as a loop, because the
 * round keys have to be pre-shifted to be folded into the T-boxes: the byte a
 * round-r T-box consumes comes from a different column than the one it feeds.
 */
export const SHIFT_ROWS: Uint8Array = (() => {
  const p = new Uint8Array(16);
  for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) p[r + 4 * c] = r + 4 * ((c + r) % 4);
  return p;
})();

export function shiftRows(state: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = state[SHIFT_ROWS[i]];
  return out;
}

function subWord(w: number): number {
  return (
    ((SBOX[(w >>> 24) & 0xff] << 24) |
      (SBOX[(w >>> 16) & 0xff] << 16) |
      (SBOX[(w >>> 8) & 0xff] << 8) |
      SBOX[w & 0xff]) >>>
    0
  );
}

function rotWord(w: number): number {
  return ((w << 8) | (w >>> 24)) >>> 0;
}

/**
 * The AES-128 key schedule of FIPS 197 section 5.2, returned as 11 round keys
 * of 16 bytes laid out in state order (round r occupies bytes 16r .. 16r + 15).
 */
export function expandKey(key: Uint8Array): Uint8Array {
  if (key.length !== AES128_KEY_BYTES) throw new Error(`AES-128 needs a ${AES128_KEY_BYTES}-byte key`);
  const w = new Uint32Array(44);
  for (let i = 0; i < 4; i++) {
    w[i] = ((key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3]) >>> 0;
  }
  for (let i = 4; i < 44; i++) {
    let temp = w[i - 1];
    if (i % 4 === 0) temp = (subWord(rotWord(temp)) ^ (RCON[i / 4 - 1] << 24)) >>> 0;
    w[i] = (w[i - 4] ^ temp) >>> 0;
  }
  const out = new Uint8Array(176);
  for (let i = 0; i < 44; i++) {
    out[4 * i] = (w[i] >>> 24) & 0xff;
    out[4 * i + 1] = (w[i] >>> 16) & 0xff;
    out[4 * i + 2] = (w[i] >>> 8) & 0xff;
    out[4 * i + 3] = w[i] & 0xff;
  }
  return out;
}

/**
 * Run the AES-128 key schedule BACKWARDS, from the last round key to the first.
 *
 * The output-side attack of Act 5 recovers k^10, not the key: with the input
 * encoding handled remotely the attacker can only relate hypotheses to the
 * ciphertext. The schedule is invertible, so k^10 is the key -- which is the
 * point worth making on screen, because it is the reason "the last round key is
 * not the key" is false for AES-128.
 */
export function invertKeySchedule(lastRoundKey: Uint8Array): Uint8Array {
  if (lastRoundKey.length !== 16) throw new Error('the last round key is 16 bytes');
  const w = new Uint32Array(44);
  for (let i = 0; i < 4; i++) {
    const o = 4 * i;
    w[40 + i] =
      ((lastRoundKey[o] << 24) | (lastRoundKey[o + 1] << 16) | (lastRoundKey[o + 2] << 8) | lastRoundKey[o + 3]) >>> 0;
  }
  for (let i = 43; i >= 4; i--) {
    let temp = w[i - 1];
    if (i % 4 === 0) temp = (subWord(rotWord(temp)) ^ (RCON[i / 4 - 1] << 24)) >>> 0;
    w[i - 4] = (w[i] ^ temp) >>> 0;
  }
  const key = new Uint8Array(16);
  for (let i = 0; i < 4; i++) {
    key[4 * i] = (w[i] >>> 24) & 0xff;
    key[4 * i + 1] = (w[i] >>> 16) & 0xff;
    key[4 * i + 2] = (w[i] >>> 8) & 0xff;
    key[4 * i + 3] = w[i] & 0xff;
  }
  return key;
}

function addRoundKey(state: Uint8Array, roundKeys: Uint8Array, round: number): void {
  for (let i = 0; i < 16; i++) state[i] ^= roundKeys[16 * round + i];
}

function subBytes(state: Uint8Array): void {
  for (let i = 0; i < 16; i++) state[i] = SBOX[state[i]];
}

function mixColumns(state: Uint8Array): void {
  for (let c = 0; c < 4; c++) {
    const a0 = state[4 * c];
    const a1 = state[4 * c + 1];
    const a2 = state[4 * c + 2];
    const a3 = state[4 * c + 3];
    for (let r = 0; r < 4; r++) {
      state[4 * c + r] =
        gmul(MIX_COLUMNS[r][0], a0) ^
        gmul(MIX_COLUMNS[r][1], a1) ^
        gmul(MIX_COLUMNS[r][2], a2) ^
        gmul(MIX_COLUMNS[r][3], a3);
    }
  }
}

/** AES-128 encryption of one block, FIPS 197 section 5.1. */
export function encryptBlock(roundKeys: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (plaintext.length !== AES_BLOCK_BYTES) throw new Error('AES operates on 16-byte blocks');
  const state = new Uint8Array(plaintext);
  addRoundKey(state, roundKeys, 0);
  for (let round = 1; round < AES128_ROUNDS; round++) {
    subBytes(state);
    const shifted = shiftRows(state);
    state.set(shifted);
    mixColumns(state);
    addRoundKey(state, roundKeys, round);
  }
  subBytes(state);
  state.set(shiftRows(state));
  addRoundKey(state, roundKeys, AES128_ROUNDS);
  return state;
}

/** Convenience: expand and encrypt in one call. */
export function aes128Encrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return encryptBlock(expandKey(key), plaintext);
}

// ── The attacker's hypotheses ───────────────────────────────────────────────
//
// Both take a KNOWN byte and a GUESSED key byte. Neither has any access to the
// real key: `dca.ts` imports these two functions and nothing else from this
// file, which is what makes invariant I2 checkable rather than aspirational.

/** S(x ^ g): the first-round SubBytes output. DCA target (a). */
export function sboxOutputHypothesis(knownByte: number, guess: number): number {
  return SBOX[(knownByte ^ guess) & 0xff];
}

/**
 * (x ^ g)^-1 in GF(2^8): the multiplicative inverse INSIDE SubBytes, before the
 * affine map. DCA target (b).
 *
 * This is a genuinely different hypothesis, not a relabelling. S = A o inv for
 * a GF(2)-affine A, so the bits of inv(x ^ g) are a different basis of the same
 * 8-dimensional space as the bits of S(x ^ g) -- and because the encoded nibble
 * a trace samples is some fixed GF(2)-linear image of that space, changing
 * basis changes which single-bit predictions correlate with it. Bos, Hubain,
 * Michiels and Teuwen (CHES 2016) report recovering bytes from the inverse
 * target that the SubBytes-output target left unrecovered.
 */
export function inverseHypothesis(knownByte: number, guess: number): number {
  return GF_INV[(knownByte ^ guess) & 0xff];
}

/**
 * S^-1(c ^ g): the last-round hypothesis, predicted from the CIPHERTEXT.
 *
 * The output-side attack in Act 5 uses this. c is a ciphertext byte, g a guess
 * at the corresponding byte of k^10, and the value is the round-10 state before
 * the final SubBytes -- which is what the last table in the network reads.
 */
export function lastRoundHypothesis(ciphertextByte: number, guess: number): number {
  return INV_SBOX[(ciphertextByte ^ guess) & 0xff];
}
