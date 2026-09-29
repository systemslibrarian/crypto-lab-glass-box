# Glass Box: the path to a 10/10 demo

## Verdict

This is already an unusually strong technical demo. The cryptography is real, the attack boundary is enforced, the claims are tested, failures are shown honestly, and the expensive work stays off the UI thread. The gap is not more crypto or more controls. It is getting a first-time visitor to the existing payoff quickly, clearly, and with a climax that matches the promise.

**Current assessment: about 8.5/10 overall.** The engineering and honesty are near 10/10; the first-run demo experience is closer to 7/10 because the key recovery is buried under a very long linear lab.

### Measured baseline

- All **117 unit tests pass**, and the production build succeeds.
- A default 384-trace run completed in under a second end to end.
- The default SubBytes-only attack took about four seconds and recovered **13/16 bytes** on the inspected instance.
- Enabling the inverse target on the same traces took about three seconds and recovered **16/16 bytes**.
- Live BGE step A1 performed 65,536 column evaluations and stripped the output encodings to affine in **39 ms** of worker time.
- At 1440 x 900 the page is about **9,807 px** tall. The Build, Trace, and Attack controls begin around 3,251, 5,028, and 6,359 px.
- At 390 x 844 the page grows to about **18,891 px**. Those controls begin around 5,588, 7,809, and 10,592 px.
- The mobile layout does not overflow horizontally, but the 940-unit network SVG is scaled to about 343 CSS px. Its 10 px SVG labels therefore render at roughly 3.6 CSS px and are not practically readable.

## What must stay

- The full-size Chow-style table network and independent WebCrypto check.
- The hard module boundary that prevents DCA and BGE from reading secrets.
- Computed verdicts, honest partial recoveries, confidence margins, and negative tests.
- The distinction between self-instrumented browser traces and instrumentation of a foreign binary.
- The alarm semantics: recovering a key is a security failure, not a green success.
- No decorative animation, fake attack, hidden answer, backend, or simplified crypto.
- The current accessibility and claims gates.

## The 10/10 first-run story

A newcomer should be able to reach this sequence without already understanding the page:

1. **Build:** “The key is gone; 2,032 tables still implement AES-128.”
2. **Trace:** “The lookup outputs look like noise.”
3. **Attack once:** “One hypothesis target recovers most of the key.”
4. **Finish the attack:** “Add the inverse target” recovers the missing bytes and reveals 16/16.
5. **Move the boundary:** Compiled-in encodings still fail; remote encodings on both sides stop this DCA run.
6. **Change attack families:** BGE reads the tables with zero traces and strips the nonlinear output encodings anyway.

That is a superb story. The product work is to make it the obvious route rather than something a visitor reconstructs from seven long acts.

## P0: blockers to 10/10

### 1. Close the primary-source gates

The brief still marks core source work as unfinished:

- V2 still needs the exact section for the remotely held encoding failure case.
- V3's 15/16, 16/16, and combined-target figures have not been re-verified in the paper.
- V4's claim that BGE covers Chow's external encodings is still carried at second hand.

These claims already appear in the page or README with caveats. A top-tier security demo should cite the exact paper section/page for every central historical claim and remove “reported at second hand” from the core teaching path. Until that is done, omit the unverified figures from the main flow or label them as unresolved research notes rather than demo evidence.

### 2. Make the BGE promise match what runs

The README says the lab is “broken in two different ways” and “takes the key back out of it twice.” The live BGE code runs step A1 only; A2 and A3, including round-key extraction, are explicitly not implemented.

Choose one honest endpoint:

- **Best 10/10 version:** implement A2 and A3 so the second route really ends with an independently recovered key.
- **Smaller immediate fix:** change the top-level promise everywhere to say that DCA recovers the key while live BGE A1 strips the nonlinear encodings and demonstrates the algebraic route. Do not imply two live key recoveries.

The smaller copy fix should happen even if full BGE remains a later stretch goal.

### 3. Ship the promised Demo / Full Lab depth split

Add a guided **Demo** route while preserving the current page as **Full Lab** depth.

- Put one primary action in the hero: **Start the guided attack**.
- Keep the full scope, derivations, inventories, failure codes, and citations available as progressive disclosure.
- In Demo mode, show one active stage at a time with a compact progress rail: Build -> Trace -> Recover -> Move encodings -> BGE.
- After every completed stage, present exactly one obvious next action and keep “inspect the evidence” as the secondary action.
- Do not auto-play the attack. The learner should cause every security failure.

Acceptance target: the first meaningful control appears in the first viewport, and a newcomer can reach the first recovery in under 30 seconds without scrolling through prerequisite essays.

### 4. Choreograph partial recovery into the climax

The honest 13/16 default result is pedagogically useful, but it currently reads like a weak ending unless the visitor notices a checkbox introduced much earlier.

After the first attack, make the result state-aware:

- Highlight the three missed bytes.
- Explain in one sentence that a different basis of the same SubBytes intermediate can expose them.
- Present a primary action such as **Add the inverse target and recover the missing bytes**.
- Reuse the same traces, run the second computation, and reveal the changed cells.

For a guided route, use a fixed, tested seed and label it clearly as a reproducible, non-secret demo instance. Keep random instances in Full Lab mode. This guarantees the narrative without faking a verdict.

### 5. Give mobile a real visualization, not a scaled desktop one

Create a responsive version of the table-network diagram:

- Stack it into four readable stages on narrow screens, or place the full-size diagram in an explicitly labelled horizontal scroller.
- Keep the program boundary and remote party visible at the same time; those are the concept, not decoration.
- Use a mobile-specific legend and tap-to-focus stage details.
- Apply the same treatment to wide plots and result tables.

Acceptance target: at 390 px wide, every essential diagram label is readable at 100% zoom and the learner can distinguish encoded wires, clear wires, trace taps, and the program boundary without reading the caption.

## P1: highest-impact polish

### Put the mechanism beside the result

The existing “Why it works” inspector is the headline teaching visual, but it appears after a dense result panel. Integrate one byte's mechanism into the attack result:

- Show the 256 guesses competing.
- Select the winning guess only after scoring.
- Show the predicted-0 and predicted-1 groups and the one sample where their means separate.
- Offer a deliberate wrong guess beside it so the bars stay level.
- Then map that winning guess directly into its byte cell.

This should be a user-driven step or a short computation-linked transition, never an idle animation.

### Move caveats to the moment they matter

The opening scope panel is rigorous but consumes roughly 2,654 px on a phone before Act 1 begins. Keep a short “real / simulated / not production” summary near the top, then move detail to the relevant acts:

- Trace instrumentation caveat beside the heatmap.
- Generator-specific recovery rates beside the DCA verdict.
- External-encoding scope beside the placement experiment.
- A1/A2/A3 boundary beside BGE.

This preserves every caveat while reducing the feeling that the visitor must pass an oral exam before touching the demo.

### Make Act 5 a visual comparison

The seven-combination sweep is valuable. Present its output as the decisive comparison:

- Keep the AES core visually fixed.
- Move only F and G across the program boundary.
- Highlight whether input-side or output-side hypotheses remain valid.
- Build the result matrix row by row from measured runs.
- End on remote-both, then offer BGE as the immediate counterpoint.

### Strengthen navigation and result hierarchy

- Add a compact sticky act/progress navigator with current, complete, and next states.
- Make the recovered key strip the visual center of Act 4; put timings and implementation inventory below it.
- Keep controls close to the output they change.
- Preserve user context after rebuilds and explain invalidated traces in the same place as the next action.

## P2: differentiators

- Complete BGE through key extraction if the implementation cost is acceptable. That would make the “two independent attacks” promise genuinely exceptional.
- Add a small address-trace versus lookup-output comparison to bridge the browser trace to real dynamic binary instrumentation.
- Add a shareable reproducible run link containing seed, placement, trace count, and targets, clearly marked as non-secret.
- Add Open Graph metadata and a purpose-built social preview showing the encoded network, trace, and recovered key; the current document has basic metadata but no rich share card.
- Record a short, deterministic demo capture for the README, while keeping the live page as the source of truth.

## Do not spend the next cycle on

- More correctness tests before fixing the first-run route; the existing suite is already a major strength.
- More knobs, attack variants, or mathematical prose in the default path.
- A visual rebrand that breaks fleet consistency.
- Decorative motion, simulated traces, or a pre-baked success result.
- Hiding failed bytes or weakening the remote-both negative case to manufacture a cleaner story.

## Recommended implementation order

1. Verify V2-V4 against primary sources and align every headline with the live BGE scope.
2. Add the Demo / Full Lab shell and move the first action into the hero.
3. Implement the state-aware SubBytes -> inverse-target recovery sequence.
4. Recompose the network and DCA visuals for mobile and place the mechanism beside the result.
5. Turn Act 5 into the guided boundary experiment and lead directly into BGE.
6. Add one Playwright journey test for the complete guided path at desktop and 390 px.
7. Run five newcomer playtests. The success criterion is not “they finished”; it is that they can explain why compiled-in encodings fail, why remote-both stops this DCA, and why that still does not settle the table-only attack.

## Definition of 10/10

- The what and why are clear in five seconds.
- The first action is above the fold on desktop and mobile.
- A first-time visitor reaches a measured full key recovery without knowing which controls to combine.
- The DCA distinguisher is visible, not merely described.
- The encoding-placement surprise is learned by changing the boundary and measuring the outcome.
- The BGE headline says exactly what the shipped computation proves.
- Every central historical claim is tied to a verified primary-source location.
- Every essential visual is legible at 390 px.
- The current correctness, isolation, claims, and accessibility gates remain green.

**Highest-ROI change:** build the guided Demo route around the already-working partial -> full recovery sequence. It turns the existing technical achievement into a demo people will actually experience.