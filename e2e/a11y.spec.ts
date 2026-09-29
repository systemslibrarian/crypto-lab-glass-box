import { expect, test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW, REFLOW, reportCollected, watchPageErrors } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, exactly as a
 * reader gets it -- one white-box program built and checked against WebCrypto,
 * nothing traced, nothing attacked, every disclosure shut and every result panel
 * holding a placeholder; the shared skip link focused; a malformed key and a key
 * of the wrong length, which paint the `aria-invalid` boundary and two named
 * refusals; a seeded instance, which relabels its own randomness as not secret;
 * all five external-encoding placements, each of which redraws the network
 * diagram; a trace count the lab refuses by name and one it accepts; the attack
 * with one target and then with two, the sixteen-cell key strip in its found and
 * missed states at once, the trace strip split by the value the attack chose and
 * then by a deliberately wrong one, a second key byte inspected, and the refusal
 * when no target is selected; the output side, which has one target and says why;
 * the state the negative claim is about, with its four green checks and the claim
 * printed beside them; BGE step A1 on a chosen round and column; all eight
 * disclosures open; three hover states; four focus rings; and the placement log
 * with several measured rows. Every one of those is scanned, at desktop, phone
 * and sub-phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no content is
 * revealed from script, why the lab's defaults are asserted rather than assumed
 * -- this page boots asynchronously, building a 2,032-table network in a worker
 * before act 2 exists, so a scan that did not wait would measure a placeholder --
 * and why `violations` is not the whole oracle.
 *
 * Dark is the only theme this lab ships. The loop is kept so the shape matches
 * its siblings, and `boot` seeds `localStorage` with `light` on purpose, so the
 * anti-flash script's overwrite is exercised rather than assumed.
 */
for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 280px — reflow headroom below the 320px threshold`, async ({
    page,
  }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(REFLOW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @280px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
