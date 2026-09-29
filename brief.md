# Build brief — crypto-lab-glass-box (Revision 2)

Written against `audits/_MASTER-TEMPLATE.md` (copy it into this repo alongside this brief). The template is binding; where this brief and the template disagree, the template wins and the disagreement goes in the PR description.

---

## NEW DEMO BRIEF

| Field | Value |
|---|---|
| Repo name | `crypto-lab-glass-box` (check the catalog for a name collision before creating the repo) |
| Short name (H1) | Glass Box |
| Subtitle (spec label) | Chow et al. white-box AES · DCA (Bos et al. 2016) · BGE (2004) |
| One-liner | Hide an AES key inside lookup tables, then watch it leak out of the program's own memory reads. |
| Concept to teach | White-box cryptography tries to keep a key secret from an attacker who can see and run every instruction. Chow's table-network AES does this with random encodings. Two independent attacks break it. DCA is statistical: it needs little knowledge of the white-box design and correlates known inputs and key hypotheses with execution traces such as memory accesses. BGE is algebraic: it strips the encodings off the table network. |
| Primitives / spec | AES-128 (FIPS 197); Chow, Eisen, Johnson, van Oorschot, "White-Box Cryptography and an AES Implementation", SAC 2002; Bos, Hubain, Michiels, Teuwen, "Differential Computation Analysis: Hiding your White-Box Designs is Not Enough", CHES 2016, LNCS 9813 pp. 215–236 (ePrint 2015/753); Billet, Gilbert, Ech-Chatbi, "Cryptanalysis of a White Box AES Implementation", SAC 2004, LNCS 3357 pp. 227–240 |
| `--accent` | `#38BDF8` (proposed; confirm neighbouring catalog cards differ per `CLAUDE.md`) |
| Favicon emoji | 🧊 |
| In scope | Client-side construction of a Chow-style white-box AES-128 from a user-chosen key; self-instrumented computation traces; live DCA key recovery with two targets; an encoding-placement toggle that shows exactly which condition stops DCA; BGE section (see Act 6 for its build gate) |
| Non-goals | Commercial/obfuscated white-box designs; masked white-box implementations; DFA (fault attacks); higher-order DCA / MIA / collision attacks (Rivain–Wang) beyond a text reference; attacking binaries the lab does not own; any claim about the security of white-box schemes outside the ones this lab builds |

---

## Revision notes (keep in the repo)

- The gap analysis that proposed this lab expanded BGE as "Billet-Gilbert-Echauzier". That is wrong: the third author is **Charaf Ech-Chatbi**. Do not reproduce the wrong name anywhere.
- An early review draft claimed DCA succeeds *because* the implementation has no encodings. That is wrong. DCA succeeds *through* Chow's internal encodings.
- **Revision 1 claimed that turning on external encodings makes DCA fail. That is wrong.** Bos et al. §5.4 attacked a Karroumi-style challenge with external encodings and got the same result as without them: the attacker knows the original plaintexts before any encoding is applied, so encodings compiled into the program make no difference. The paper's stated scope is that DCA works against implementations that apply **at most one remotely handled** external encoding. DCA was frustrated only where the encodings were *not part of the binary*, so the attacker could not relate real AES inputs/outputs to the computation. The Act 5 toggle is redesigned around that condition.
- Revision 1 said DCA works "because" the encodings are 4 bits wide. That is too monocausal. Nibble width is why Chow's construction leaks to plain first-order DCA. But Rivain–Wang (TCHES 2019) show DCA-like attacks break encodings wider than 4 bits, including a byte-encoded implementation that plain DCA had failed on. Never imply "4-bit vulnerable, 8-bit safe."
- Revision 1's honesty panel said "no published white-box AES scheme is known to resist key extraction." That is a broad survey claim no cited source establishes, so it's removed. The panel speaks only about the schemes this lab builds and cites.

---

## 1. SCOPE

Single page, Demo / Full-lab dual depth per the template.

- **Act 1 — The white-box threat model.** Plain language before any hex: the attacker holds the program, can run it, pause it, and read every table and every memory access. The key must still not come out.
- **Act 2 — Build the glass box.** The user enters or generates an AES-128 key. The page builds the table network in-browser: T-boxes (key + S-box folded in), Tyi tables (MixColumns), XOR tables, random 4-bit internal encodings, and Chow's linear mixing bijections (V1). Show the table count and total byte size, computed rather than hard-coded. Encrypt a block through the network and through a reference AES; they must match.
- **Act 3 — Trace it.** Run N encryptions (user-set, default in the low hundreds) on random plaintexts. Each run records every first-round table lookup output into a preallocated typed buffer. Show the trace matrix as a heatmap (bit-serialized).
- **Act 4 — DCA.** For each key byte and each of 256 guesses, predict one chosen bit of a first-round intermediate. Split the traces by that bit and compute the difference of means per trace sample. Offer two targets (V3):
  - (a) the SubBytes output;
  - (b) the multiplicative inverse inside SubBytes.
  
  Plot the peak per guess, recover byte by byte, report per-byte margins, and compare with the key only after the attack commits (I3). If one target leaves bytes unrecovered, show that honestly and let the learner switch or combine targets.
- **Act 5 — What actually stops DCA: where the encoding lives.** A three-way toggle, each state measured, never asserted:
  1. **No external encodings.** DCA recovers the key.
  2. **External encodings compiled into the program.** DCA still recovers the key, because the attacker feeds known plaintexts into the program before the encoding is applied. This is the Bos et al. §5.4 result, and it is the surprise the act exists to show.
  3. **External encodings applied remotely (outside the program) on both input and output.** The attacker sees only encoded values, can't relate them to real AES inputs/outputs, and DCA has no valid hypotheses. Plus a sub-toggle for **remote on one side only**: DCA attacks from the unencoded side (Bos et al. scope: "at most one remotely handled external encoding"; V2).
  
  The panel states plainly that state 3 moves the problem, not solves it. Something outside the program has to hold and apply those encodings.
- **Act 6 — BGE, the algebraic route.** BGE works from the tables themselves, not from traces, and its published attack covers Chow's construction including the external encodings Chow specifies (V4; don't generalize this to arbitrary external encodings in other designs). **Build gate:** implement BGE live on at least one column of one round if it runs in the browser within the template's interaction budget. If full or partial BGE is not built, this act is a clearly labeled explanation ("not run in this page") with the complexity figures. It must never be an animation that pretends to run the attack. BGE must not delay shipping Acts 1–5.
- **Act 7 — What came after.** Lepoint et al. (SAC 2013) cut BGE's work factor to 2^22. Rivain–Wang (TCHES 2019) analyzed when and why DCA works against internal encodings and broke encodings wider than 4 bits. Text only.

## 2. SECURITY / CORRECTNESS INVARIANTS

Invariants beat features when they conflict.

- **I1.** For every key and plaintext, the white-box network produces the same ciphertext as FIPS 197 AES-128. Verify against FIPS 197 Appendix C.1 and against WebCrypto AES-CBC with a zero IV on a single block (equivalent to ECB for one block). WebCrypto is the independent path. When compiled-in external encodings are on, compare end-to-end with decode(encode(·)) removed. When remote encodings are on, compare after the page's "remote party" applies and removes them.
- **I2.** The attack code never reads the key, the encodings, or any generator-internal variable. DCA sees only (known input, trace) pairs; in remote-encoding mode, "known input" is whatever the attacker could actually observe. BGE sees only the published tables. Enforce this with a module boundary and a test that the attack module imports nothing from the generator.
- **I3.** The recovered-key display compares against the true key only *after* the attack has committed its answer.
- **I4.** Every rendered verdict ("key recovered", "DCA failed", "byte 7 wrong") is computed from the run. Each gets a §4.1c mutation that flips the underlying data and must flip the verdict.
- **I5.** Trace buffers are preallocated typed arrays sized from N × samples, with no per-lookup `push`.
- **I6.** Randomness for keys and encodings comes from `crypto.getRandomValues`. A seed field may exist for reproducibility, but it is labeled as making the instance non-secret.
- **I7.** The "remote" encoding party is a separate module the attack can't import, so state 3 of Act 5 is a real information barrier, not a UI flag.

## 3. ARCHITECTURE

- `aes-ref` — minimal reference for the DCA *predictions* (first-round S-box output and GF(2^8) inverse). WebCrypto is used for full-cipher checks.
- `wb-gen` — builds the Chow network from key + randomness, with optional compiled-in external encodings. It exports tables only; the key reaches the I3 comparison through a separate channel.
- `remote-enc` — the out-of-program party for Act 5 state 3.
- `wb-run` — evaluates the network and, when tracing, writes lookup outputs into the provided typed buffer at an offset pointer.
- `dca` — pure function (observed inputs, traces, target, bit) → per-byte guess scores. No access to `wb-gen` or `remote-enc`.
- `bge` — only if Act 6's build gate passes; it takes the tables as input.
- Workers: tracing and DCA run in a Web Worker. Plot with canvas or uPlot fed directly from the typed arrays.
- Any WASM is optional. If used, the JS path stays as the tested reference.

## 4. UI

Follow the template's hero roles: subtitle = spec label only; description = what the demo demonstrates; "Why it matters" = real-world stakes (DRM and apps that ship keys inside the binary). Keep the description and the why-box distinct.

Controls: key field + generate; encoding placement (none / compiled-in / remote both sides / remote one side); N-traces slider; target selector (SubBytes output / inverse); bit selector; run button; per-byte result strip (16 cells, correct/incorrect after the I3 reveal) with margins.

## 5. VISUAL SEMANTICS

- A table-network diagram where encoded wires are drawn opaque and unencoded values clear. Remote encodings are drawn *outside* the program boundary.
- Don't draw a picture that implies the key is stored anywhere as a value.
- The trace heatmap is bits × samples. The DCA plot shows 256 faint guess curves with the winning guess highlighted only after the computation picks it.
- No decorative motion.

## 6. EDGE CASES

- N too small: DCA gets bytes wrong. Show that honestly, with per-byte margins.
- A target that leaves some bytes unrecovered on a given instance. Show which bytes, and allow a target switch; never force a success.
- Remote both sides: the DCA output must look like noise. If it ever "succeeds" there, that's a bug (likely an I2/I7 leak).
- Memory: compute the trace buffer size before allocation, and cap N with a stated reason.

## 7. EXTENSION SEAMS

- Byte (8-bit) encodings plus a Rivain–Wang-style attack panel.
- DFA (fault injection into the network).
- A masked white-box variant.
- Importing a public challenge's tables (SideChannelMarvels "Deadpool" set). Licence check first.

---

## Tests (template mechanisms — do not invent new ones)

In `e2e/claims.spec.ts`:
- I1 across the FIPS vector plus ≥100 random (key, plaintext) pairs against WebCrypto, in every encoding mode.
- Parts sum to whole: the displayed table count × sizes equals the displayed total bytes.
- **Compiled-in external encodings: DCA recovery equals no-external-encoding recovery** on the same fixed-seed instance (the Bos §5.4 claim, tested).
- **Remote both sides: recovery is at chance level** (a §4.1d negative claim: the page claims failure, so test the failure).
- **Remote one side: recovery succeeds from the unencoded side.**
- Recovery thresholds per target at default N are **acceptance thresholds derived empirically from this generator**. Measure them, record them with the seed and N, and never present them as properties of Chow's construction.
- A §4.1c mutation for every verdict string.

---

## Verification gates (resolve against primary sources before the relevant act is built; record page/section used)

- **V1.** Chow 2002: exact table types, encoding widths (nibble concatenations), and mixing bijection sizes (8×8, 32×32). Muir's "A Tutorial on White-box AES" (ePrint 2013/104) is a secondary guide; cite Chow for anything normative.
- **V2 — CLOSED (Revision 3; the scope half closed in Revision 2).** Bos et al. 2016: scope "at most a single remotely handled external encoding" (abstract/intro); §5.4, Karroumi challenge, external encodings made no difference because the original plaintexts were known before encoding; failure case where the encodings were not part of the binary. The failure case is §5.5 — the one challenge DCA could not break had encodings that were not in the binary, and an algebraic attack broke it instead. Recorded in the README's primary-sources table.
- **V3 — CLOSED (Revision 3).** Bos et al. 2016 on Chow/Karroumi. All three figures read out of §5.4 and its Tables 1 and 2, and the page now quotes the paper rather than paraphrasing a reviewer: 15/16 at 2,000 traces on the SubBytes target with the missing byte "trivial using brute-force"; 16/16 on the multiplicative-inverse target, "reduced to about 500" traces, with the caveat that it "may vary for other generations"; combined, "we could always recover the full key". §5.4 also yields a fourth thing the brief did not ask for — the rank-extremity observation — which is now a second live distinguisher in act 4.
- **V4 — CLOSED (Revision 3), by removing the claim rather than by confirming it.** The 2^30 and the negligible memory are verified, and its decomposition is now cited to Muir §5.1 (2^24 per output encoding, 16 x 2^24 = 2^28 per round, three rounds < 2^30). The reviewer's claim that the paper explicitly covers Chow's external encodings could not be confirmed from a section that was actually read, so act 6 no longer says it. What act 6 says instead is what this lab runs: step A1, live, on the tables the page built, with zero traces — and that the published attack builds on A1 to reach the key while this page does not do the reaching.
- **V5 — verified (abstract).** Lepoint, Rivain, De Mulder, Roelse, Preneel, "Two Attacks on a White-Box AES Implementation", SAC 2013: BGE reduced to 2^22.
- **V6 — verified (abstract).** Rivain & Wang, TCHES 2019(2), 225–255: nibble encodings vulnerable to DCA; DCA-like attacks break encodings wider than 4 bits; broke a byte-encoded implementation DCA had failed on.

## Honesty panel (draft wording; finalize after V3–V4)

- The traces come from the page instrumenting its own table lookups. Real DCA captures the same kind of data from a foreign binary with dynamic binary instrumentation (Intel PIN, Valgrind), which a browser can't run.
- Chow's 4-bit internal encodings don't hide first-order correlations well enough to stop DCA. Wider encodings aren't a fix either: later attacks break those too.
- External encodings built into the program don't stop DCA, because the attacker still chooses the plaintext going in. Only encodings applied *outside* the program, on both sides, block this attack, and then something outside the program has to hold them.
- BGE's algebraic attack recovers the key from Chow's full construction, including its external encodings, without any traces.