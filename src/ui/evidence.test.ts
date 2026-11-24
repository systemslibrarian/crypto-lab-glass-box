import { describe, expect, it } from 'vitest';
import type { BgeReport, VerificationReport } from '../protocol.js';
import { bgePassed, verificationPassed } from './evidence.js';
const aes: VerificationReport = { fipsVectorMatches: true, fipsCiphertextHex: '69c4e0d86a7b0430d8cdb78070b4c55a', randomBlocks: 8, randomBlocksMatching: 8, webCryptoAvailable: true };
const algebra: BgeReport = { kind: 'bge', round: 1, column: 0, evaluations: 65536, elapsedMs: 1, stripped: true,
  bytes: [0,1,2,3].map(row => ({ row, groupOrder: 256, everyElementIsAnInvolution: true, basisSize: 8, spreadBefore: 20, spreadAfter: 1 })) };
describe('complete named evidence', () => {
  it('accepts complete matching reference and four-output algebraic evidence', () => {
    expect(verificationPassed(aes)).toBe(true); expect(bgePassed(algebra)).toBe(true);
  });
  it.each([0,1,7,9])('refuses %i matching random blocks instead of eight', n => {
    expect(verificationPassed({ ...aes, randomBlocks:n, randomBlocksMatching:n })).toBe(false);
  });
  it('refuses a success flag beside an incorrect named ciphertext', () => {
    expect(verificationPassed({ ...aes, fipsCiphertextHex:'00'.repeat(16) })).toBe(false);
  });
  it('refuses missing, empty and duplicated algebra rows even with a success flag', () => {
    expect(bgePassed(null)).toBe(false);
    expect(bgePassed({ ...algebra, bytes:[] })).toBe(false);
    expect(bgePassed({ ...algebra, bytes:algebra.bytes.slice(0,3) })).toBe(false);
    expect(bgePassed({ ...algebra, bytes:[...algebra.bytes.slice(0,3),algebra.bytes[0]] })).toBe(false);
  });
  it('refuses a row whose difference still varies, despite the aggregate success flag', () => {
    expect(bgePassed({ ...algebra, bytes:algebra.bytes.map((r,i) => i===2 ? {...r,spreadAfter:2} : r) })).toBe(false);
  });
});
