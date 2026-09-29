# Glass Box

**Chow-style white-box AES-128, built in your browser and broken in two different ways.**

[Live demo](https://systemslibrarian.github.io/crypto-lab-glass-box/)

---

## What It Is

White-box cryptography asks a question ordinary cryptography does not: can a
program keep a key secret from someone who owns the machine it runs on, can read
every byte of it, run it as often as they like on inputs they choose, and watch
every value it puts in memory? Software that has to decrypt on hardware its owner
controls — a streaming client, a payment app, a licence check — has to answer it
somehow, because it ships the key inside the binary.

Chow, Eisen, Johnson and van Oorschot answered it in 2002 (SAC 2002) with the
construction everything since is built on: **do not store the key at all**. Rewrite
AES as a network of lookup tables, build each table with the round key already
folded in, and scramble every value passing between tables with a secret random
bijection so no intermediate is a plain AES value either. This lab builds that,
for real, from a key you choose, and then takes the key back out of it twice.

**The primitives, exactly.** AES-128 as FIPS 197 defines it, with the S-box
assembled from the GF(2^8) multiplicative inverse and the section 5.1.1 affine map
rather than transcribed. Chow's table network at full size: T-boxes, Ty_i tables
for MixColumns, nibble XOR tables, random 4-bit internal encodings on every wire,
and the 8x8 and 32x32 GF(2) mixing bijections of his section 3.2 — 2,032 tables
and 724 KB for the plain form, 4,016 tables and 1.43 MB when the external
encodings are compiled in.
Differential computation analysis exactly as Bos, Hubain, Michiels and Teuwen
describe it (CHES 2016): a difference of means over a software execution trace,
with 4,096 hypotheses scored per attack. Step A1 of the Billet–Gilbert–Ech-Chatbi
algebraic attack (SAC 2004), run live on the tables.

**The security model.** The attacker holds the program. That is the whole model,
and it is the one white-box cryptography was invented for. Nothing is assumed
about the attacker's side channels, timing or fault capability, because they do
not need any: they can read the tables.

**Not production crypto.** It runs entirely in your browser with no backend, the
key lives for as long as the tab does and is never sent anywhere, and the whole
point of it is to be broken. Do not use it to protect anything.

### The mathematics, in one paragraph

Chow reorders the AES round so ShiftRows comes first, which lets a single
256-entry table hold "add this round key byte, then apply the S-box". MixColumns
is folded into the same lookup by composing it with Ty_i, which spreads one input
byte across all four bytes of a column; the four results are summed by a tree of
4-bit XOR tables, because a table XOR-ing two bytes would need 65,536 entries and
one XOR-ing two nibbles needs 256. The full derivation of the BGE step this lab
runs — why composing one round's tables makes every internal encoding cancel, and
why the resulting set of 256 permutations is a group isomorphic to (GF(2^8), XOR)
— is a progressive-disclosure panel inside Act 6, next to the computation that
performs it, rather than a separate document that could drift from the code.

---

## Exhibits

1. **The white-box threat model.** Plain language, no hex: what the attacker can
   do, and why "do not store the key" is a structural claim rather than a
   difficulty claim.
2. **Build the glass box.** Enter or generate an AES-128 key. The page compiles it
   into the table network in your browser and then checks that network against
   WebCrypto — an independent AES — on random blocks, and against the FIPS 197
   Appendix C.1 vector, before telling you anything else. The table inventory and
   the program size are read off the arrays that were allocated. A diagram of one
   column draws encoded wires solid and un-encoded ones hollow, puts remote
   encodings outside the program boundary, and has no box holding the key.
3. **Make the program tell on itself.** Run N traced encryptions and record the
   output of every table lookup, in order, into a preallocated bit matrix. The
   buffer size is computed before it is allocated. The trace looks like noise,
   which is the honest result and the reason the next act is needed.
4. **Take the key out of the trace.** For each key byte and each of 256 candidate
   values, predict one bit of a first-round intermediate, split the traces by that
   prediction, and measure the difference in the averages. Two targets — the
   SubBytes output and the multiplicative inverse inside it — which can be
   combined. A sixteen-cell strip shows what was recovered, what was missed, and
   the margin between each byte's best and second-best candidate, computed without
   the key. And the mechanism itself: the same traces split by the predicted bit,
   with the two group means drawn beneath as a pair of bars per sample. Under the
   value the attack chose, one pair pulls apart. Under a deliberately wrong value,
   every pair stays level.
5. **What actually stops it: where the encoding lives.** Five states, each
   measured rather than asserted, accumulating into a comparison table: no
   external encodings; encodings compiled into the program; and encodings applied
   remotely on both sides, on the input side only, and on the output side only.
6. **The algebraic route.** BGE step A1, run live on the tables you built, with no
   traces at all. It extracts a group of 256 permutations from the tables, verifies
   it is isomorphic to (GF(2^8), XOR), and reports each output encoding stripped to
   a GF(2)-affine map — checkable on screen without any secret, because a quantity
   that varied before the recovered map is applied is constant after it.
7. **What came after.** Lepoint et al. (SAC 2013) cutting BGE to 2^22, and
   Rivain–Wang (TCHES 2019) breaking encodings wider than 4 bits.

---

## When to Use It

Use it to understand why "the key is not in the binary" is a different claim from
"the key cannot be extracted from the binary", and what it costs to get from one
to the other. It is the right demo for anyone who has been told that a white-box
implementation makes a shipped key safe.

**Do NOT use it to protect anything**, and do not read any result here as a
statement about white-box schemes in general. Every measurement on this page is
about the construction this page builds and the papers it cites. In particular,
do not read Act 4 as "4-bit encodings leak, wider ones are safe" — Rivain and Wang
broke encodings wider than 4 bits, including a byte-encoded implementation that
plain DCA had failed on. Nibble width is why FIRST-ORDER difference of means works
on Chow's design; it is not the boundary of the attack family.

---

## Live Demo

<https://systemslibrarian.github.io/crypto-lab-glass-box/>

Type a key or press Generate, press Trace it, press Run the attack, and watch
fourteen or so of the sixteen key bytes come back. Then tick the second target and
run it again to get the rest. Then change where the external encodings live in Act
2 and see which of those changes does anything. Then run Act 6, which recovers the
encodings from the tables without running the program once.

---

## What Can Go Wrong

**The things this construction does not protect against, and the ones this page
gets wrong if you are not careful.**

- **A few hundred execution traces are enough.** Not a fault attack, not a timing
  attack, not a physical measurement — just a recording of what the program read
  and wrote, and a difference of means. On this generator, one target at 384
  traces recovers 12 to 16 bytes of 16; the two targets combined recover 14 to 16.
- **Compiling the external encodings into the program buys nothing.** If the
  encoder is in the binary, the attacker can get from a plaintext they chose to
  the value the AES core sees, so the first-round hypotheses stay valid. Act 5
  measures this: the program grows, the trace grows, and the attack recovers
  exactly the same sixteen bytes.
- **Holding the encodings outside the program stops THIS attack, and moves the
  problem.** Something out there now holds a secret and has to apply it to every
  block — another piece of software, on some machine, with a secret in it. And it
  does not make the key unextractable: BGE recovers it from the tables alone, and
  its published attack covers the external encodings Chow specifies.
- **The construction has no failure code.** It cannot tell that it is being
  traced, cannot refuse to run, and raises nothing while its key is being
  extracted. Every failure code this page can show belongs to the page's own input
  validation, and the scope card says so in the same table.
- **A confident-looking answer can still be wrong.** The margin between a byte's
  best and second-best candidate is computed without the key, so it is the
  confidence an attacker really has — and on this generator every byte above a
  0.15 margin was correct in all fifty measured input-side runs. That is a
  measurement, not a guarantee: in the remote-both state, where the attack is at
  chance, a spurious high margin has been observed, and it was wrong.
- **The attack is asymmetric, and this is a lab-original measurement rather than a
  figure from any paper.** Attacking the output side recovers only part of the
  last round key and does not complete. Chow's first-round tables are 8 -> 32, so a
  first-round key byte is exposed through eight encoded nibbles; his round-10
  tables are 8 -> 8, so a last-round key byte is exposed through two. Four times
  fewer places for a correlation to be. And inverting the AES-128 key schedule
  needs all sixteen bytes of k^10, so a partial recovery of it yields nothing.
- **What this page's trace is not.** Real DCA captures the same kind of data from
  a foreign binary with dynamic binary instrumentation — Intel PIN, Valgrind, a
  debugger — which a browser cannot run. This page records the output of every
  table lookup from the inside. That is a real software execution trace of a real
  table network; it is not a physical side channel, and it is not a capture of
  someone else's binary. One consequence is visible in Act 3: a real ADDRESS trace
  shows the round structure plainly, because table base addresses repeat, and a
  trace of encoded lookup outputs does not.

---

## Real-World Usage

White-box implementations of AES and of other primitives ship in DRM clients,
mobile payment applications (host card emulation), pay-TV, and software licensing.
The commercial ones add obfuscation, control-flow flattening, anti-debugging and
sometimes masking on top of a Chow-style core; those raise the cost of getting a
trace, and the published attacks assume you got one. The practical significance of
DCA is exactly that it needs so little: Bos et al. point out that it requires
almost no knowledge of the design under attack, which is why it reached
implementations whose internals were never published.

The WhibOx contest series and the SideChannelMarvels "Deadpool" collection of
public challenge binaries are where this line of work is exercised in the open.
Importing such a challenge's tables is an extension seam marked in this lab's
source and deliberately not built: it needs a licence check first.

---

## How to Run Locally

```bash
npm install
npm run dev          # serves the lab
npm test             # the unit and correctness suite
npm run build        # typecheck, then production build
npm run test:a11y    # WCAG 2.1 A/AA gate against the production build
npm run test:claims  # does the page tell the truth?
```

`npm run test:a11y` and `npm run test:claims` build the site and serve it on port
4685 before running, so what they judge is what ships.

---

## Related Demos

- [Power Trace](https://systemslibrarian.github.io/crypto-lab-power-trace/) —
  first-order DPA on a physical power measurement. Same distinguisher, different
  channel: DCA is that attack with a software execution trace in place of a
  current probe, which is the observation Bos et al. start from.
- [Masked Core](https://systemslibrarian.github.io/crypto-lab-masked-core/) —
  second-order CPA against a masking countermeasure. The countermeasure line this
  lab's Act 7 names as out of scope.
- [Timing Oracle](https://systemslibrarian.github.io/crypto-lab-timing-oracle/) —
  a side channel that needs no access to the binary at all, for contrast with a
  threat model that assumes total access.
- [AES Modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — AES
  itself, if the cipher rather than the implementation is the unfamiliar part.
- [Model Breach](https://systemslibrarian.github.io/crypto-lab-model-breach/) —
  what happens when a security model's assumptions drift from deployment. The
  white-box model is the extreme case: the attacker owns everything.

---

## Build & Verify

**154 tests, all executed, none skipped.**

- **117 unit tests** (Vitest, `src/**/*.test.ts`).
- **34 claims tests** (Playwright, `e2e/claims.spec.ts`) — checking that the page
  tells the truth, by comparing values the page itself printed and re-deriving its
  claims from what is on screen.
- **3 accessibility tests** (Playwright + `@axe-core/playwright`,
  `e2e/a11y.spec.ts`) — the WCAG 2.1 A/AA gate, driven through thirty-odd states
  at 1280, 380 and 280 CSS pixels.

**Known-answer tests, from the specifications:**

| KAT | Where |
|---|---|
| FIPS 197 section 4.2.1 `xtime`, and the section 4.2 product {57}.{83} = {c1} | `src/aes/gf.test.ts` |
| FIPS 197 Figure 7 S-box, row 0 and six named entries, checked against an S-box ASSEMBLED from the field inverse and the section 5.1.1 affine map | `src/aes/gf.test.ts` |
| FIPS 197 Appendix A.1 key expansion, w[4]..w[7] and w[40]..w[43] | `src/aes/aes-ref.test.ts` |
| FIPS 197 Appendix B cipher example, and Appendix C.1 | `src/aes/aes-ref.test.ts` |
| NIST SP 800-38A F.1.1 ECB-AES128, all four blocks | `src/aes/aes-ref.test.ts` |
| The same four vector sets again, through the TABLE NETWORK, in all five external-encoding placements | `src/wb/wb-run.test.ts` |
| WebCrypto cross-check: 300 random (key, block) pairs against the reference, and 20 keys x 5 blocks x 5 placements through the network | `src/aes/aes-ref.test.ts`, `src/wb/wb-run.test.ts` |
| WebCrypto cross-check through the shipped page: 120 random blocks across five placements | `e2e/claims.spec.ts` |

**What is verified beyond the KATs:**

- **Invariant I1** — the network is AES-128 in every encoding placement, checked
  against WebCrypto (the independent path) as well as this repo's reference.
- **Invariant I2** — the attack modules cannot import a secret. `src/attack/*` may
  not import `wb-gen.ts`, `remote-enc.ts`, `rng.ts`, `encoding.ts` or `wb-run.ts`;
  `src/attack/isolation.test.ts` reads their imports and enforces it, and proves
  the check bites on a fabricated import.
- **Invariant I3** — `runDca` returns a committed answer and takes no argument it
  could reach the key through; `judgeRecovery` is a separate call.
- **BGE step A1 is correct, not merely self-consistent** — the recovered map
  composed with the true encoding is verified to be GF(2)-affine over all 2^16
  pairs, on four rounds and four columns; and a one-swap perturbation of the
  recovered map is verified to fail that check.
- **The two DCA scorers agree exactly** — a masked-popcount scorer and an
  XOR-convolution scorer sharing no arithmetic, required to produce identical
  peaks, samples, bits and margins.
- **The acceptance thresholds are measured, and recorded with their seeds and
  trace counts** in `src/attack/dca.test.ts`. They are properties of this
  generator, not of Chow's construction, and not the figures from any paper. The
  paper's own figures are quoted as the paper's, in Act 5 and below.

**Reported by Bos, Hubain, Michiels and Teuwen (CHES 2016)** about the
implementations they attacked, not about this one: 15 of 16 bytes from one target
on one instance at 2,000 traces, 16 of 16 using the multiplicative-inverse target,
and the full key whenever the two were combined across the instances they tested.

**Accessibility gate.** `@axe-core/playwright` scans the production build for zero
WCAG 2.1 A/AA violations and zero unexplained `incomplete` results, alongside a
composite-aware arithmetic contrast walk, a non-text-contrast and generated-content
oracle ratcheted against an empty baseline, a keyboard-reachability check on every
scrolling region, and a reflow check at 380 and 280 CSS pixels. The deploy is
blocked if any of it fails.

---

## Performance

Measured on an Apple-silicon laptop. Everything below runs in a Web Worker, so
the page stays responsive and reports progress while it happens.

| Step | Cost |
|---|---|
| Build a plain program: 2,032 tables, 724 KB | ~110 ms |
| Build with the external encodings compiled in: 4,016 tables, 1.43 MB | ~215 ms |
| 384 traced encryptions, 16,256 samples recorded each | ~40 ms |
| DCA, one target, all eight prediction bits: 32,768 hypothesis evaluations | ~0.95 s |
| DCA, both targets combined: 65,536 hypothesis evaluations | ~2.1 s |
| BGE step A1: 65,536 column evaluations | ~60 ms |

Each build is followed by the WebCrypto comparison on eight random blocks, which
is what the page waits for before reporting anything.

The attack's cost is almost flat in the trace count, which is why 2,048 traces are
as interactive as 128: the scoring is an XOR-convolution over the 256 byte values
rather than a pass over the traces. The binding constraint is the trace buffer,
and the page computes its size before allocating it and refuses anything over
24 MB by name.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
