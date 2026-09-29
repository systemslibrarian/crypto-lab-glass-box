/**
 * The randomness the white-box generator draws its encodings from.
 *
 * Invariant I6: keys and encodings come from `crypto.getRandomValues`. A seed
 * field exists for reproducibility, and an instance built from a seed is
 * labelled NON-SECRET on the page, because it is: the seed determines every
 * encoding, every mixing bijection and (if generated rather than typed) the key.
 *
 * The seeded path is a real cipher rather than a toy generator, and it reuses
 * the AES-128 this lab has already checked against FIPS 197 and WebCrypto:
 *
 *   key      = AES-128-CBC-MAC of the seed's UTF-8 bytes under an all-zero key
 *   keystream = AES-128-CTR under that key, counter starting at 0
 *
 * CBC-MAC under a FIXED, published key is not a MAC -- it is being used here as
 * a keyless compression function to turn an arbitrary seed string into 16 bytes,
 * and nothing in this lab depends on it being unforgeable. Saying so is the
 * point; a lab that quietly reached for a MAC as a hash and did not mention it
 * would be teaching the wrong reflex.
 */

import { AES_BLOCK_BYTES, encryptBlock, expandKey } from '../aes/aes-ref.js';
import type { ByteSource } from '../math/gf2.js';

export interface Rng extends ByteSource {
  /** Uniform bytes. */
  bytes(count: number): Uint8Array;
  /** A uniform integer in [0, bound). */
  below(bound: number): number;
  /** What this source is, for the UI to print honestly. */
  readonly origin: 'system' | 'seed';
  /** The seed, when there is one. */
  readonly seed: string | null;
}

function belowFrom(source: { bytes(count: number): Uint8Array }, bound: number): number {
  if (bound <= 0 || bound > 0x1000000) throw new Error(`below(${bound}) is out of range`);
  // Rejection sampling against the largest multiple of `bound` that fits in
  // three bytes, so the result is exactly uniform rather than modulo-biased.
  const limit = Math.floor(0x1000000 / bound) * bound;
  for (;;) {
    const b = source.bytes(3);
    const value = b[0] | (b[1] << 8) | (b[2] << 16);
    if (value < limit) return value % bound;
  }
}

/** `crypto.getRandomValues`. The default, and the only non-reproducible source. */
export function systemRng(): Rng {
  const self = {
    origin: 'system' as const,
    seed: null,
    bytes(count: number): Uint8Array {
      const out = new Uint8Array(count);
      // getRandomValues refuses more than 65536 bytes per call.
      for (let offset = 0; offset < count; offset += 65536) {
        crypto.getRandomValues(out.subarray(offset, Math.min(offset + 65536, count)));
      }
      return out;
    },
    below(bound: number): number {
      return belowFrom(self, bound);
    },
  };
  return self;
}

/** AES-128-CBC-MAC under an all-zero key: a keyless map from bytes to 16 bytes. */
export function deriveSeedKey(seedBytes: Uint8Array): Uint8Array {
  const zeroKey = expandKey(new Uint8Array(16));
  // 10*: one 0x80 byte then zeros, so distinct seeds never share a padded form.
  const padded = new Uint8Array(Math.ceil((seedBytes.length + 1) / AES_BLOCK_BYTES) * AES_BLOCK_BYTES);
  padded.set(seedBytes);
  padded[seedBytes.length] = 0x80;
  let chain: Uint8Array = new Uint8Array(AES_BLOCK_BYTES);
  for (let offset = 0; offset < padded.length; offset += AES_BLOCK_BYTES) {
    const block = new Uint8Array(AES_BLOCK_BYTES);
    for (let i = 0; i < AES_BLOCK_BYTES; i++) block[i] = padded[offset + i] ^ chain[i];
    chain = encryptBlock(zeroKey, block);
  }
  return chain;
}

/**
 * A reproducible source: AES-128-CTR keystream under a key derived from `seed`.
 *
 * Reproducible is the whole feature and the whole caveat. The page says so
 * beside the field.
 */
export function seededRng(seed: string): Rng {
  const roundKeys = expandKey(deriveSeedKey(new TextEncoder().encode(seed)));
  let counterHigh = 0;
  let counterLow = 0;
  let block: Uint8Array = new Uint8Array(0);
  let used = 0;

  const refill = (): void => {
    const counter = new Uint8Array(AES_BLOCK_BYTES);
    counter[8] = (counterHigh >>> 24) & 0xff;
    counter[9] = (counterHigh >>> 16) & 0xff;
    counter[10] = (counterHigh >>> 8) & 0xff;
    counter[11] = counterHigh & 0xff;
    counter[12] = (counterLow >>> 24) & 0xff;
    counter[13] = (counterLow >>> 16) & 0xff;
    counter[14] = (counterLow >>> 8) & 0xff;
    counter[15] = counterLow & 0xff;
    counterLow = (counterLow + 1) >>> 0;
    if (counterLow === 0) counterHigh = (counterHigh + 1) >>> 0;
    block = encryptBlock(roundKeys, counter);
    used = 0;
  };

  const self = {
    origin: 'seed' as const,
    seed,
    bytes(count: number): Uint8Array {
      const out = new Uint8Array(count);
      for (let i = 0; i < count; i++) {
        if (used >= block.length) refill();
        out[i] = block[used++];
      }
      return out;
    },
    below(bound: number): number {
      return belowFrom(self, bound);
    },
  };
  return self;
}

/**
 * A uniformly random permutation of `size` elements, by Fisher-Yates with the
 * unbiased `below` above.
 *
 * Chow's internal encodings are 4-bit bijections, so `size` is 16 almost
 * everywhere in this lab. There are 16! ~= 2^44 of them, and the network needs
 * tens of thousands; drawing each uniformly is what makes the phrase "random
 * nibble encoding" true rather than decorative.
 */
export function randomPermutation(size: number, rng: Rng): Uint8Array {
  const p = new Uint8Array(size);
  for (let i = 0; i < size; i++) p[i] = i;
  for (let i = size - 1; i > 0; i--) {
    const j = rng.below(i + 1);
    const t = p[i];
    p[i] = p[j];
    p[j] = t;
  }
  return p;
}

/** The inverse of a permutation table. */
export function invertPermutation(p: Uint8Array): Uint8Array {
  const out = new Uint8Array(p.length);
  for (let i = 0; i < p.length; i++) out[p[i]] = i;
  return out;
}
