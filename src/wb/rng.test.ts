import { describe, expect, it } from 'vitest';
import { deriveSeedKey, invertPermutation, randomPermutation, seededRng, systemRng } from './rng.js';
import { aes128Encrypt } from '../aes/aes-ref.js';

const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

describe('the seeded source is a real AES-128-CTR keystream', () => {
  it('derives its key by CBC-MAC under an all-zero key, verifiably', () => {
    // A one-block seed: CBC-MAC over the 10* padded block equals a single
    // AES encryption of it under the zero key. Recomputed here by the
    // independent route, so the derivation is checked rather than described.
    const seed = 'glass';
    const padded = new Uint8Array(16);
    padded.set(new TextEncoder().encode(seed));
    padded[seed.length] = 0x80;
    expect(hex(deriveSeedKey(new TextEncoder().encode(seed)))).toBe(hex(aes128Encrypt(new Uint8Array(16), padded)));
  });

  it('a seed reproduces the exact byte stream', () => {
    const a = seededRng('glass box');
    const b = seededRng('glass box');
    expect(hex(a.bytes(4096))).toBe(hex(b.bytes(4096)));
  });

  it('different seeds give different streams, and one changed bit is enough', () => {
    const a = hex(seededRng('glass box').bytes(64));
    expect(a).not.toBe(hex(seededRng('glass boy').bytes(64)));
    expect(a).not.toBe(hex(seededRng('glass box ').bytes(64)));
    expect(a).not.toBe(hex(seededRng('').bytes(64)));
  });

  it('is the CTR keystream, block for block', () => {
    // Block n of the stream must equal AES(key, counter = n). Recomputed by the
    // independent route rather than by calling the generator twice.
    const key = deriveSeedKey(new TextEncoder().encode('ctr check'));
    const stream = seededRng('ctr check').bytes(48);
    for (let n = 0; n < 3; n++) {
      const counter = new Uint8Array(16);
      counter[15] = n;
      expect(hex(stream.subarray(16 * n, 16 * n + 16))).toBe(hex(aes128Encrypt(key, counter)));
    }
  });

  it('crosses its block boundary without repeating or dropping a byte', () => {
    const whole = hex(seededRng('boundary').bytes(64));
    const source = seededRng('boundary');
    // Same 64 bytes, drawn in awkward pieces.
    const pieces = [source.bytes(1), source.bytes(14), source.bytes(3), source.bytes(46)];
    expect(pieces.map(hex).join('')).toBe(whole);
  });

  it('reports its origin honestly', () => {
    expect(seededRng('x').origin).toBe('seed');
    expect(seededRng('x').seed).toBe('x');
    expect(systemRng().origin).toBe('system');
    expect(systemRng().seed).toBeNull();
  });
});

describe('below() is uniform, not modulo-biased', () => {
  it('refuses a bound it cannot sample uniformly', () => {
    expect(() => systemRng().below(0)).toThrow(/out of range/);
    expect(() => systemRng().below(1 << 25)).toThrow(/out of range/);
  });

  it('covers every residue for a bound that does not divide 2^24', () => {
    // 2^24 mod 17 != 0, so a naive modulo would over-represent low residues.
    // 17 * 4000 draws: every bucket must be within 25% of the 4000 expected.
    const rng = seededRng('uniformity');
    const counts = new Array<number>(17).fill(0);
    for (let i = 0; i < 17 * 4000; i++) counts[rng.below(17)]++;
    for (const c of counts) {
      expect(c).toBeGreaterThan(3000);
      expect(c).toBeLessThan(5000);
    }
  });
});

describe('randomPermutation', () => {
  it('produces a bijection of the requested size', () => {
    const rng = seededRng('perm');
    for (let trial = 0; trial < 200; trial++) {
      const p = randomPermutation(16, rng);
      expect(new Set(p).size).toBe(16);
      expect(invertPermutation(p)).toEqual(Uint8Array.from({ length: 16 }, (_, i) => p.indexOf(i)));
    }
  });

  it('round-trips through its inverse', () => {
    const rng = systemRng();
    const p = randomPermutation(16, rng);
    const q = invertPermutation(p);
    for (let x = 0; x < 16; x++) expect(q[p[x]]).toBe(x);
  });

  it('reaches many distinct permutations, so "random nibble encoding" is literal', () => {
    const rng = seededRng('spread');
    const seen = new Set<string>();
    for (let trial = 0; trial < 500; trial++) seen.add(hex(randomPermutation(16, rng)));
    // 16! is about 2^44, so 500 draws colliding would be a broken generator.
    expect(seen.size).toBe(500);
  });

  it('is not the identity in any meaningful fraction of draws', () => {
    const rng = seededRng('identity');
    let identities = 0;
    for (let trial = 0; trial < 1000; trial++) {
      const p = randomPermutation(16, rng);
      if (p.every((v, i) => v === i)) identities++;
    }
    expect(identities).toBe(0);
  });
});
