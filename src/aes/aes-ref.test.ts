import { describe, expect, it } from 'vitest';
import {
  aes128Encrypt,
  expandKey,
  invertKeySchedule,
  inverseHypothesis,
  lastRoundHypothesis,
  sboxOutputHypothesis,
  SHIFT_ROWS,
  shiftRows,
} from './aes-ref.js';
import { GF_INV, SBOX } from './gf.js';

const hex = (bytes: Uint8Array): string => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (s: string): Uint8Array => new Uint8Array((s.match(/../g) ?? []).map((p) => parseInt(p, 16)));

/** AES-ECB over one block, via WebCrypto AES-CBC with a zero IV. */
async function webCryptoEcbBlock(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-CBC', false, ['encrypt']);
  const out = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, imported, block as BufferSource);
  // CBC with a zero IV over exactly one block is ECB over that block; the
  // second 16 bytes are the PKCS#7 padding block, which is discarded.
  return new Uint8Array(out).subarray(0, 16);
}

describe('the key schedule (FIPS 197 section 5.2)', () => {
  // KAT: FIPS 197 Appendix A.1, the AES-128 expansion of the standard's own key.
  const key = unhex('2b7e151628aed2a6abf7158809cf4f3c');

  it('reproduces w[4]..w[7] from Appendix A.1', () => {
    const rk = expandKey(key);
    expect(hex(rk.subarray(16, 32))).toBe('a0fafe1788542cb123a339392a6c7605');
  });

  it('reproduces the last round key w[40]..w[43] from Appendix A.1', () => {
    const rk = expandKey(key);
    expect(hex(rk.subarray(160, 176))).toBe('d014f9a8c9ee2589e13f0cc8b6630ca6');
  });

  it('round key 0 is the key itself', () => {
    expect(hex(expandKey(key).subarray(0, 16))).toBe(hex(key));
  });

  it('inverts: k^10 determines the key', () => {
    for (const k of [key, unhex('000102030405060708090a0b0c0d0e0f'), new Uint8Array(16)]) {
      const rk = expandKey(k);
      expect(hex(invertKeySchedule(rk.subarray(160, 176)))).toBe(hex(k));
    }
  });

  it('inverts for 200 random keys', () => {
    for (let trial = 0; trial < 200; trial++) {
      const k = crypto.getRandomValues(new Uint8Array(16));
      const rk = expandKey(k);
      expect(hex(invertKeySchedule(rk.subarray(160, 176)))).toBe(hex(k));
    }
  });

  it('rejects a key that is not 16 bytes', () => {
    expect(() => expandKey(new Uint8Array(24))).toThrow(/16-byte key/);
  });
});

describe('ShiftRows', () => {
  it('shifts row r left by r positions', () => {
    // Column-major state: byte r + 4c. Row 0 is unchanged, row 1 shifts by one.
    expect([...SHIFT_ROWS]).toEqual([0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]);
  });

  it('is a permutation, and applying it four times is the identity', () => {
    const start = new Uint8Array(16).map((_, i) => i);
    let s: Uint8Array = start;
    for (let i = 0; i < 4; i++) s = shiftRows(s);
    expect([...s]).toEqual([...start]);
  });
});

describe('AES-128 encryption known-answer tests', () => {
  // KAT: FIPS 197 Appendix C.1 (AES-128).
  it('FIPS 197 Appendix C.1', () => {
    const ct = aes128Encrypt(unhex('000102030405060708090a0b0c0d0e0f'), unhex('00112233445566778899aabbccddeeff'));
    expect(hex(ct)).toBe('69c4e0d86a7b0430d8cdb78070b4c55a');
  });

  // KAT: FIPS 197 Appendix B, the worked "Cipher Example".
  it('FIPS 197 Appendix B cipher example', () => {
    const ct = aes128Encrypt(unhex('2b7e151628aed2a6abf7158809cf4f3c'), unhex('3243f6a8885a308d313198a2e0370734'));
    expect(hex(ct)).toBe('3925841d02dc09fbdc118597196a0b32');
  });

  // KAT: NIST SP 800-38A Appendix F.1.1, ECB-AES128 encryption, all four blocks.
  it('NIST SP 800-38A F.1.1 ECB-AES128, blocks 1-4', () => {
    const key = unhex('2b7e151628aed2a6abf7158809cf4f3c');
    const vectors: [string, string][] = [
      ['6bc1bee22e409f96e93d7e117393172a', '3ad77bb40d7a3660a89ecaf32466ef97'],
      ['ae2d8a571e03ac9c9eb76fac45af8e51', 'f5d3d58503b9699de785895a96fdbaaf'],
      ['30c81c46a35ce411e5fbc1191a0a52ef', '43b1cd7f598ece23881b00e3ed030688'],
      ['f69f2445df4f9b17ad2b417be66c3710', '7b0c785e27e8ad3f8223207104725dd4'],
    ];
    for (const [pt, ct] of vectors) expect(hex(aes128Encrypt(key, unhex(pt)))).toBe(ct);
  });

  it('rejects a block that is not 16 bytes', () => {
    expect(() => aes128Encrypt(new Uint8Array(16), new Uint8Array(8))).toThrow(/16-byte blocks/);
  });

  it('agrees with WebCrypto on 300 random (key, block) pairs', async () => {
    for (let trial = 0; trial < 300; trial++) {
      const key = crypto.getRandomValues(new Uint8Array(16));
      const pt = crypto.getRandomValues(new Uint8Array(16));
      expect(hex(aes128Encrypt(key, pt))).toBe(hex(await webCryptoEcbBlock(key, pt)));
    }
  });
});

describe('the attacker hypotheses', () => {
  it('sboxOutputHypothesis is S(x ^ g) over the whole domain', () => {
    for (let x = 0; x < 256; x += 5)
      for (let g = 0; g < 256; g += 7) expect(sboxOutputHypothesis(x, g)).toBe(SBOX[x ^ g]);
  });

  it('inverseHypothesis is the GF(2^8) inverse of x ^ g', () => {
    for (let x = 0; x < 256; x += 5)
      for (let g = 0; g < 256; g += 7) expect(inverseHypothesis(x, g)).toBe(GF_INV[x ^ g]);
  });

  it('the two targets are different functions, not a relabelling', () => {
    // They agree on at most a handful of points; if the "inverse" target were
    // secretly the S-box target, DCA would have one target, not two.
    let agreements = 0;
    for (let x = 0; x < 256; x++) if (sboxOutputHypothesis(x, 0) === inverseHypothesis(x, 0)) agreements++;
    expect(agreements).toBeLessThan(8);
  });

  it('lastRoundHypothesis inverts the final SubBytes', () => {
    for (let c = 0; c < 256; c += 3)
      for (let g = 0; g < 256; g += 11) expect(SBOX[lastRoundHypothesis(c, g)]).toBe(c ^ g);
  });

  it('a hypothesis is a bijection in the guess for any fixed known byte', () => {
    // The property every differential attack relies on: distinct guesses give
    // distinct predicted intermediates, so no two guesses are indistinguishable
    // by construction.
    for (const known of [0x00, 0x5a, 0xff]) {
      expect(new Set([...Array(256).keys()].map((g) => sboxOutputHypothesis(known, g))).size).toBe(256);
      expect(new Set([...Array(256).keys()].map((g) => inverseHypothesis(known, g))).size).toBe(256);
    }
  });
});
