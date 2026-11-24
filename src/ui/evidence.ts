import type { BgeReport, VerificationReport } from '../protocol.js';

/** The named evidence must be complete as well as internally agreeing. */
export function verificationPassed(v: VerificationReport): boolean {
  return v.fipsVectorMatches && v.fipsCiphertextHex === '69c4e0d86a7b0430d8cdb78070b4c55a' &&
    v.randomBlocks === 8 && v.randomBlocksMatching === 8;
}

export function bgePassed(report: BgeReport | null): boolean {
  return report !== null && report.stripped && report.evaluations === 65536 &&
    report.bytes.length === 4 && new Set(report.bytes.map((b) => b.row)).size === 4 &&
    report.bytes.every((b) => Number.isInteger(b.row) && b.row >= 0 && b.row < 4 &&
      b.groupOrder === 256 && b.everyElementIsAnInvolution && b.basisSize === 8 && b.spreadAfter === 1);
}
