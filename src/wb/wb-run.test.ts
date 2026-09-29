import { describe, expect, it } from 'vitest';
import { buildNetwork } from './wb-gen.js';
import { createRemoteParty } from './remote-enc.js';
import { collectTraces, makeScratch, runNetwork, traceBit, traceMapFor, traceSetBytes } from './wb-run.js';
import { seededRng, systemRng } from './rng.js';
import { ENCODING_PLACEMENTS, type EncodingPlacement } from './types.js';

const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (s: string): Uint8Array => new Uint8Array((s.match(/../g) ?? []).map((p) => parseInt(p, 16)));

async function webCryptoEcbBlock(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-CBC', false, ['encrypt']);
  const out = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, imported, block as BufferSource);
  return new Uint8Array(out).subarray(0, 16);
}

/** Build, then run one block end to end through the remote party's wrapper. */
function endToEnd(key: Uint8Array, placement: EncodingPlacement, seed: string) {
  const { network, handover } = buildNetwork(key, placement, seededRng(seed));
  const party = createRemoteParty(placement, handover);
  const scratch = makeScratch();
  return {
    network,
    party,
    encrypt: (plaintext: Uint8Array): Uint8Array =>
      party.decodeOutput(runNetwork(network, party.encodeInput(plaintext), scratch)),
  };
}

describe('invariant I1: the network is AES-128, in every encoding mode', () => {
  // KAT: FIPS 197 Appendix C.1, through the table network rather than the cipher.
  it.each(ENCODING_PLACEMENTS)('FIPS 197 Appendix C.1 under placement %s', (placement) => {
    const { encrypt } = endToEnd(unhex('000102030405060708090a0b0c0d0e0f'), placement, `kat ${placement}`);
    expect(hex(encrypt(unhex('00112233445566778899aabbccddeeff')))).toBe('69c4e0d86a7b0430d8cdb78070b4c55a');
  });

  // KAT: FIPS 197 Appendix B.
  it.each(ENCODING_PLACEMENTS)('FIPS 197 Appendix B under placement %s', (placement) => {
    const { encrypt } = endToEnd(unhex('2b7e151628aed2a6abf7158809cf4f3c'), placement, `appx-b ${placement}`);
    expect(hex(encrypt(unhex('3243f6a8885a308d313198a2e0370734')))).toBe('3925841d02dc09fbdc118597196a0b32');
  });

  // KAT: NIST SP 800-38A F.1.1, all four ECB-AES128 blocks, through the network.
  it.each(ENCODING_PLACEMENTS)('NIST SP 800-38A F.1.1 blocks 1-4 under placement %s', (placement) => {
    const { encrypt } = endToEnd(unhex('2b7e151628aed2a6abf7158809cf4f3c'), placement, `38a ${placement}`);
    const vectors: [string, string][] = [
      ['6bc1bee22e409f96e93d7e117393172a', '3ad77bb40d7a3660a89ecaf32466ef97'],
      ['ae2d8a571e03ac9c9eb76fac45af8e51', 'f5d3d58503b9699de785895a96fdbaaf'],
      ['30c81c46a35ce411e5fbc1191a0a52ef', '43b1cd7f598ece23881b00e3ed030688'],
      ['f69f2445df4f9b17ad2b417be66c3710', '7b0c785e27e8ad3f8223207104725dd4'],
    ];
    for (const [pt, ct] of vectors) expect(hex(encrypt(unhex(pt)))).toBe(ct);
  });

  it.each(ENCODING_PLACEMENTS)(
    'agrees with WebCrypto on 20 random (key, block) pairs under placement %s',
    async (placement) => {
      // WebCrypto is the INDEPENDENT path: agreeing with this repo's own
      // reference would only prove the two share a bug.
      for (let trial = 0; trial < 20; trial++) {
        const key = crypto.getRandomValues(new Uint8Array(16));
        const { encrypt } = endToEnd(key, placement, `rand ${placement} ${trial}`);
        for (let block = 0; block < 5; block++) {
          const pt = crypto.getRandomValues(new Uint8Array(16));
          expect(hex(encrypt(pt))).toBe(hex(await webCryptoEcbBlock(key, pt)));
        }
      }
    },
    120_000,
  );

  it('an unseeded instance from crypto.getRandomValues is AES too', async () => {
    const key = crypto.getRandomValues(new Uint8Array(16));
    const { network, handover } = buildNetwork(key, 'remote-both', systemRng());
    const party = createRemoteParty('remote-both', handover);
    const scratch = makeScratch();
    for (let trial = 0; trial < 8; trial++) {
      const pt = crypto.getRandomValues(new Uint8Array(16));
      const got = party.decodeOutput(runNetwork(network, party.encodeInput(pt), scratch));
      expect(hex(got)).toBe(hex(await webCryptoEcbBlock(key, pt)));
    }
  });
});

describe('the external encodings really are external', () => {
  it('the program alone is NOT AES when the encodings are remote', () => {
    const key = unhex('000102030405060708090a0b0c0d0e0f');
    const pt = unhex('00112233445566778899aabbccddeeff');
    const scratch = makeScratch();
    for (const placement of ['remote-both', 'remote-input', 'remote-output'] as const) {
      const { network } = buildNetwork(key, placement, seededRng('external'));
      // Feeding the raw plaintext straight in, with no remote party, must NOT
      // produce the ciphertext -- otherwise the encodings are decoration.
      expect(hex(runNetwork(network, pt, scratch))).not.toBe('69c4e0d86a7b0430d8cdb78070b4c55a');
    }
  });

  it('the program alone IS AES when the encodings are compiled in', () => {
    const scratch = makeScratch();
    for (const placement of ['none', 'compiled-in'] as const) {
      const { network } = buildNetwork(unhex('000102030405060708090a0b0c0d0e0f'), placement, seededRng('internal'));
      expect(hex(runNetwork(network, unhex('00112233445566778899aabbccddeeff'), scratch))).toBe(
        '69c4e0d86a7b0430d8cdb78070b4c55a',
      );
    }
  });

  it('the remote party refuses a placement it has no encodings for', () => {
    const { handover } = buildNetwork(new Uint8Array(16), 'none', seededRng('bare'));
    expect(() => createRemoteParty('remote-both', handover)).toThrow(/needs external encodings/);
    expect(() => createRemoteParty('none', handover).encodeInput(new Uint8Array(8))).toThrow(/16 bytes/);
  });
});

describe('the table inventory is computed, not asserted', () => {
  it('every group’s bytes equal its count times its entry size', () => {
    for (const placement of ENCODING_PLACEMENTS) {
      const { network } = buildNetwork(new Uint8Array(16), placement, seededRng('inv'));
      const { groups, tables, bytes } = network.inventory;
      for (const g of groups) expect(g.bytes).toBe(g.count * g.entryBytes);
      expect(tables).toBe(groups.reduce((n, g) => n + g.count, 0));
      expect(bytes).toBe(groups.reduce((n, g) => n + g.bytes, 0));
    }
  });

  it('counts the table types Chow’s construction calls for', () => {
    const { network } = buildNetwork(new Uint8Array(16), 'none', seededRng('counts'));
    const by = (id: string): number => network.inventory.groups.find((g) => g.id === id)?.count ?? 0;
    // 9 rounds x 4 columns x 4 rows.
    expect(by('type-ii')).toBe(144);
    expect(by('type-iii')).toBe(144);
    // Two trees per column, three steps each, eight nibble tables per step.
    expect(by('type-iv')).toBe(9 * 4 * 2 * 3 * 8);
    expect(by('type-v')).toBe(16);
    expect(by('type-ia')).toBe(0);
    expect(network.inventory.tables).toBe(144 + 144 + 1728 + 16);
  });

  it('the external sections add tables, and compiled-in adds twice as many as remote-both', () => {
    const counts: Record<string, number> = {};
    for (const placement of ENCODING_PLACEMENTS) {
      const { network } = buildNetwork(new Uint8Array(16), placement, seededRng('grow'));
      counts[placement] = network.inventory.tables;
    }
    expect(counts['none']).toBeLessThan(counts['remote-output']);
    expect(counts['remote-output']).toBe(counts['remote-input']);
    expect(counts['remote-both'] - counts['none']).toBe(2 * (counts['remote-input'] - counts['none']));
    expect(counts['compiled-in'] - counts['none']).toBe(2 * (counts['remote-both'] - counts['none']));
  });

  it('the packed total is smaller than the allocated total, by the 4-bit tables', () => {
    const { network } = buildNetwork(new Uint8Array(16), 'none', seededRng('packed'));
    const { bytes, packedBytes, groups } = network.inventory;
    const nibbleBytes = groups.filter((g) => g.entryBytes === 256).reduce((n, g) => n + g.bytes, 0);
    expect(packedBytes).toBe(bytes - nibbleBytes / 2);
    expect(packedBytes).toBeLessThan(bytes);
  });
});

describe('the recorded trace', () => {
  it('the trace map accounts for every bit the run writes', () => {
    // `collectTraces` throws if the cursor and the map disagree, so reaching a
    // result at all is the assertion; the sizes are checked here as well.
    for (const placement of ENCODING_PLACEMENTS) {
      const { network } = buildNetwork(new Uint8Array(16), placement, seededRng('map'));
      const map = traceMapFor(network);
      expect(map.totalBits).toBe(map.segments.reduce((n, s) => n + s.bits, 0));
      const inputs = seededRng('inputs').bytes(4 * 16);
      const set = collectTraces(network, inputs, 4);
      expect(set.totalBits).toBe(map.totalBits);
      expect(set.bits.length).toBe(map.totalBits * set.stride);
    }
  });

  it('the core contributes 9 x 1792 + 128 bits whatever the placement', () => {
    for (const placement of ENCODING_PLACEMENTS) {
      const { network } = buildNetwork(new Uint8Array(16), placement, seededRng('core-bits'));
      const map = traceMapFor(network);
      const core = map.segments.filter((s) => s.id.startsWith('round:'));
      expect(core.reduce((n, s) => n + s.bits, 0)).toBe(9 * 1792 + 128);
      expect(map.windows['first-round'].bits).toBe(1792);
      expect(map.windows['last-rounds'].bits).toBe(1792 + 128);
      expect(map.windows['whole-program'].bits).toBe(map.totalBits);
    }
  });

  it('traceSetBytes predicts the allocation before it happens', () => {
    const { network } = buildNetwork(new Uint8Array(16), 'none', seededRng('size'));
    const map = traceMapFor(network);
    const traces = 96;
    const predicted = traceSetBytes(map.totalBits, traces);
    const set = collectTraces(network, seededRng('in').bytes(traces * 16), traces);
    expect(set.bits.byteLength + set.inputs.byteLength + set.outputs.byteLength).toBe(predicted);
  });

  it('is not constant, and not all ones: the lookups really differ per trace', () => {
    const { network } = buildNetwork(unhex('000102030405060708090a0b0c0d0e0f'), 'none', seededRng('vary'));
    const traces = 64;
    const set = collectTraces(network, seededRng('varyin').bytes(traces * 16), traces);
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
    // A trace of a 4-bit-encoded network should vary on most samples.
    expect(varying).toBeGreaterThan(set.totalBits * 0.8);
  });

  it('is reproducible: the same inputs give the same bits', () => {
    const { network } = buildNetwork(unhex('0f0e0d0c0b0a09080706050403020100'), 'none', seededRng('repro'));
    const inputs = seededRng('repro-in').bytes(16 * 16);
    const a = collectTraces(network, inputs, 16);
    const b = collectTraces(network, inputs, 16);
    expect(hex(a.bits)).toBe(hex(b.bits));
    expect(hex(a.outputs)).toBe(hex(b.outputs));
  });

  it('refuses an input array of the wrong length', () => {
    const { network } = buildNetwork(new Uint8Array(16), 'none', seededRng('len'));
    expect(() => collectTraces(network, new Uint8Array(17), 2)).toThrow(/16 bytes per trace/);
  });
});

describe('a seed pins the core across all five Act 5 states', () => {
  it('the first round of the trace is identical for none and compiled-in', () => {
    // The Bos et al. section 5.4 result, as a comparison rather than a claim:
    // external encodings compiled into the program cancel before round 1, so
    // the samples DCA reads are the same ones.
    const key = unhex('000102030405060708090a0b0c0d0e0f');
    const traces = 24;
    const inputs = seededRng('pin-in').bytes(traces * 16);
    const read = (placement: EncodingPlacement): string => {
      const { network } = buildNetwork(key, placement, seededRng('pinned'));
      const set = collectTraces(network, inputs, traces);
      const w = set.map.windows['first-round'];
      return hex(set.bits.subarray(w.startBit * set.stride, (w.startBit + w.bits) * set.stride));
    };
    expect(read('compiled-in')).toBe(read('none'));
  });

  it('...but the whole-program traces are NOT identical, because the program is bigger', () => {
    const key = unhex('000102030405060708090a0b0c0d0e0f');
    const traces = 8;
    const inputs = seededRng('pin-in2').bytes(traces * 16);
    const sets = (['none', 'compiled-in'] as const).map((placement) => {
      const { network } = buildNetwork(key, placement, seededRng('pinned2'));
      return collectTraces(network, inputs, traces);
    });
    expect(sets[1].totalBits).toBeGreaterThan(sets[0].totalBits);
  });
});
