import { expect, test, type Page } from '@playwright/test';

/**
 * Does the page tell the truth?
 *
 * The rule that makes these tests worth anything is that they compare two values
 * THE PAGE ITSELF PRINTED, or re-derive a claim from what is on screen by a
 * different route than the source takes. A test that recomputes the same
 * expression the source uses will happily agree with a bug.
 *
 * Three kinds of check live here, and the mix is deliberate, because internal
 * consistency alone is not enough -- a page can be consistently wrong:
 *
 *   CROSS-CHECKS          two surfaces that must agree: the inventory's per-type
 *                         byte figures against the program-size line, the trace
 *                         buffer's prediction against what was allocated, the
 *                         sixteen key-byte cells against the committed hex.
 *   RE-DERIVATIONS        recompute the claim from the page's raw output by
 *                         another route: count matching bytes between the
 *                         committed key and the truth and compare that with the
 *                         printed score; recompute each margin from the peak and
 *                         runner-up in the detail table.
 *   PARTS SUM TO WHOLE    the table types sum to the program; the trace segments
 *                         sum to the bits per trace.
 *
 * And one external authority that is not the page: the FIPS 197 Appendix C.1
 * vector, and WebCrypto, which the page runs itself on random blocks and reports
 * the result of.
 */

const BASE_KEY = '000102030405060708090a0b0c0d0e0f';
const FIPS_C1_CIPHERTEXT = '69c4e0d8 6a7b0430 d8cdb780 70b4c55a';

type Placement = 'none' | 'compiled-in' | 'remote-both' | 'remote-input' | 'remote-output';

async function boot(page: Page): Promise<void> {
  page.setDefaultTimeout(60_000);
  await page.goto('.');
  await expect(page.locator('#build-verdict .pill-text')).toHaveText('IT IS AES-128');
}

async function setSeed(page: Page, seed: string): Promise<void> {
  await page.fill('#seed', seed);
  await page.locator('#seed').dispatchEvent('change');
}

/**
 * Wait for an act to FINISH, not merely for its verdict to be present.
 *
 * Several of this page's verdicts read the same after a re-run as before it --
 * rebuilding with a different seed still says "IT IS AES-128" -- so asserting
 * the verdict text would pass instantly against the PREVIOUS run's output and
 * then read stale values. The page prints a run counter in each status line for
 * exactly this reason; these helpers wait for it to advance.
 */
function runNumber(text: string): number {
  const match = text.match(/#(\d+)/);
  return match ? Number(match[1]) : 0;
}

async function afterRun(page: Page, statusId: string, act: () => Promise<void>): Promise<void> {
  const status = page.locator(`#${statusId}`);
  const before = runNumber((await status.innerText()).trim());
  await act();
  // Waiting for the text to merely CHANGE is not enough: the first thing a
  // click does is replace the status with a progress line, so a change-only
  // wait returns while the work is still running and every read after it is
  // stale. The counter only advances when the act has finished.
  await expect
    .poll(async () => runNumber((await status.innerText()).trim()), { timeout: 180_000 })
    .toBeGreaterThan(before);
}

async function runBge(page: Page, round: string, column: string): Promise<void> {
  await page.locator('#bge-round').selectOption(round);
  await page.locator('#bge-column').selectOption(column);
  await afterRun(page, 'bge-status', () => page.locator('#run-bge').click());
}

async function build(page: Page, placement: Placement, keyHex = BASE_KEY): Promise<void> {
  await page.fill('#key-hex', keyHex);
  await afterRun(page, 'build-status', async () => {
    await page.locator(`#placement-${placement}`).check();
    await page.locator('#build').click();
  });
  await expect(page.locator('#build-verdict .pill-text')).toHaveText('IT IS AES-128');
  await expect(page.locator('#build-out')).toContainText(placementLabel(placement));
}

function placementLabel(placement: Placement): string {
  return {
    none: 'no external encodings',
    'compiled-in': 'compiled into the program',
    'remote-both': 'remote, both sides',
    'remote-input': 'remote, input side only',
    'remote-output': 'remote, output side only',
  }[placement];
}

async function trace(page: Page, traces: number): Promise<void> {
  await page.fill('#traces', String(traces));
  await afterRun(page, 'trace-status', () => page.locator('#trace').click());
  await expect(page.locator('#trace-status')).toContainText('recorded');
}

async function attack(
  page: Page,
  surface: 'input' | 'output',
  targets: ('sbox' | 'inverse')[] = ['sbox'],
): Promise<void> {
  await page.locator(`#surface-${surface}`).check();
  if (surface === 'input') {
    await page.locator('#target-sbox').setChecked(targets.includes('sbox'));
    await page.locator('#target-inverse').setChecked(targets.includes('inverse'));
  }
  await afterRun(page, 'dca-status', () => page.locator('#run-dca').click());
  await expect(page.locator('#dca-status')).toContainText('scored');
  await expect(page.locator('#dca-verdict')).toBeVisible();
}

/** A definition-list value, by the term beside it. */
async function definition(page: Page, scope: string, term: string): Promise<string> {
  const value = page
    .locator(`${scope} dl.defs dt`, { hasText: term })
    .first()
    .locator('xpath=following-sibling::dd[1]');
  return (await value.innerText()).replace(/\s+/g, ' ').trim();
}

/**
 * The FIRST number in a rendered string.
 *
 * Deliberately not "strip everything that is not a digit": these read-outs say
 * things like "14 of 16 (a blind guesser would expect 0.06)", and a strip would
 * silently produce 14160.06 and then compare it against 14. That happened while
 * this file was being written, which is why the parse is anchored.
 */
const number = (text: string): number => {
  const match = text.replace(/,/g, '').match(/-?\d+(?:\.\d+)?/);
  if (!match) throw new Error(`no number in ${JSON.stringify(text)}`);
  return Number(match[0]);
};

test.describe('Act 2: what the page says it built', () => {
  test('parts sum to whole: every table type’s bytes add up to the program size', async ({ page }) => {
    await boot(page);
    for (const placement of ['none', 'compiled-in', 'remote-both'] as Placement[]) {
      await build(page, placement);
      const rows = page.locator('#build-out table.matrix tbody tr');
      const count = await rows.count();
      expect(count).toBeGreaterThan(0);
      let tables = 0;
      let bytes = 0;
      for (let i = 0; i < count; i++) {
        const cells = await rows.nth(i).locator('th, td').allInnerTexts();
        const [, tablesText, eachText, bytesText] = cells;
        const n = number(tablesText);
        const each = number(eachText);
        const total = /MB/.test(bytesText) ? number(bytesText) * 1048576 : number(bytesText) * 1024;
        // The row is internally consistent: tables x bytes-each = bytes.
        expect(Math.abs(n * each - total), `${placement} row ${i}`).toBeLessThan(total * 0.005 + 1);
        tables += n;
        bytes += n * each;
      }
      // ...and the rows sum to the two headline figures beside them.
      expect(number(await definition(page, '#build-out', 'Tables in the program')), placement).toBe(tables);
      const printed = await definition(page, '#build-out', 'Program size, as allocated here');
      const printedBytes = /MB/.test(printed) ? number(printed) * 1048576 : number(printed) * 1024;
      expect(Math.abs(printedBytes - bytes), placement).toBeLessThan(bytes * 0.005 + 1);
    }
  });

  test('the table counts are Chow’s, re-derived from the construction rather than read off', async ({ page }) => {
    await boot(page);
    await build(page, 'none');
    const byType = async (label: string): Promise<number> =>
      number(
        await page
          .locator('#build-out table.matrix tbody tr', { hasText: label })
          .first()
          .locator('td')
          .first()
          .innerText(),
      );
    // 9 rounds x 4 columns x 4 rows of Type II, the same of Type III, two
    // three-step XOR trees of eight nibble tables each per column, and 16 Type V.
    expect(await byType('Type II')).toBe(9 * 4 * 4);
    expect(await byType('Type III')).toBe(9 * 4 * 4);
    expect(await byType('Type IV')).toBe(9 * 4 * 2 * 3 * 8);
    expect(await byType('Type V')).toBe(16);
    expect(number(await definition(page, '#build-out', 'Tables in the program'))).toBe(9 * 4 * 4 * 2 + 9 * 4 * 48 + 16);
  });

  test('it really is AES: the FIPS vector on screen, and WebCrypto on 120 random blocks', async ({ page }) => {
    // The one authority here that is not the page. The FIPS 197 Appendix C.1
    // ciphertext is fixed by the standard, and the random-block comparison is
    // run by the shipped code against WebCrypto -- an independent AES -- with
    // the result reported rather than assumed. Five placements, three keys
    // each, eight blocks per build: 120 comparisons.
    await boot(page);
    let compared = 0;
    for (const placement of ['none', 'compiled-in', 'remote-both', 'remote-input', 'remote-output'] as Placement[]) {
      for (let attempt = 0; attempt < 3; attempt++) {
        await page.locator(`#placement-${placement}`).check();
        await page.locator('#generate-key').click();
        await expect(page.locator('#build-verdict .pill-text')).toHaveText('IT IS AES-128');
        const detail = await page.locator('#build-verdict .verdict-detail').innerText();
        const match = detail.match(/on (\d+) of (\d+) random blocks/);
        expect(match, `${placement} attempt ${attempt}`).not.toBeNull();
        expect(detail).toContain('WebCrypto');
        expect(match![1]).toBe(match![2]);
        compared += Number(match![1]);
        // The FIPS vector is checked on its own instance, every build.
        expect(await definition(page, '#build-out', 'FIPS 197 C.1 through the network')).toBe(FIPS_C1_CIPHERTEXT);
        // The key really was regenerated rather than reused.
        expect(await page.locator('#key-hex').inputValue()).toMatch(/^[0-9a-f]{32}$/);
      }
    }
    expect(compared, 'at least 100 random blocks compared against WebCrypto').toBeGreaterThanOrEqual(100);
  });

  test('the diagram says what the placement is, and never draws the key', async ({ page }) => {
    await boot(page);
    for (const placement of ['none', 'compiled-in', 'remote-both', 'remote-input', 'remote-output'] as Placement[]) {
      await build(page, placement);
      const label = await page.locator('svg.diagram').getAttribute('aria-label');
      expect(label, placement).toBeTruthy();
      expect(label!.length, placement).toBeGreaterThan(80);
    }
    // A Chow network does not store the key, and the picture must not imply it
    // does. What it says instead is checked, so the claim is in the DOM.
    // `innerText` is an HTMLElement property; an SVG needs `textContent`.
    const text = await page.locator('svg.diagram').evaluate((el) => el.textContent ?? '');
    expect(text).toContain('no box here holds k');
    expect(text).toContain('these 256 outputs exist');
  });

  test('a seeded instance is labelled not secret, and an unseeded one is not labelled reproducible', async ({
    page,
  }) => {
    await boot(page);
    await setSeed(page, 'claims-seed');
    await build(page, 'none');
    expect(await definition(page, '#build-out', 'Encodings drawn from')).toContain('NOT secret');
    await setSeed(page, '');
    await build(page, 'none');
    expect(await definition(page, '#build-out', 'Encodings drawn from')).toContain('crypto.getRandomValues');
    expect(await definition(page, '#build-out', 'Encodings drawn from')).toContain('not reproducible');
  });
});

test.describe('Act 3: the recording', () => {
  test('parts sum to whole: the segment map adds up to the bits per trace', async ({ page }) => {
    await boot(page);
    await build(page, 'compiled-in');
    await trace(page, 64);
    const rows = page.locator('#trace-out table.matrix tbody tr');
    const count = await rows.count();
    let bits = 0;
    let expectedStart = 0;
    for (let i = 0; i < count; i++) {
      const cells = await rows.nth(i).locator('th, td').allInnerTexts();
      const start = number(cells[1]);
      const size = number(cells[2]);
      // The segments tile the trace with no gap and no overlap.
      expect(start, `segment ${i} starts where the previous one ended`).toBe(expectedStart);
      expectedStart = start + size;
      bits += size;
    }
    expect(number(await definition(page, '#trace-out', 'Samples per trace'))).toBe(bits);
  });

  test('the buffer was sized before it was allocated, and the sizes agree', async ({ page }) => {
    await boot(page);
    await build(page, 'none');
    await trace(page, 128);
    const line = await definition(page, '#trace-out', 'Buffer size');
    const sizes = line.match(/[\d.]+ KB|[\d.]+ MB/g) ?? [];
    expect(sizes, line).toHaveLength(2);
    const allocated = sizes[0] ?? '';
    // The prediction was made before anything was allocated; they must agree.
    expect(sizes[1], line).toBe(allocated);
    // And the figure is what the layout implies: bits x ceil(N/32) x 4 bytes,
    // plus 16 input and 16 output bytes per trace. Re-derived, not re-read.
    const bits = number(await definition(page, '#trace-out', 'Samples per trace'));
    const traces = number(await definition(page, '#trace-out', 'Traced encryptions'));
    const expectedBytes = bits * Math.ceil(traces / 32) * 4 + traces * 32;
    const printed = number(allocated) * (/MB/.test(allocated) ? 1048576 : 1024);
    expect(Math.abs(printed - expectedBytes)).toBeLessThan(expectedBytes * 0.01 + 1);
  });
});

test.describe('Act 4: what the attack claims', () => {
  test('the score is what the two hex strings on screen actually agree on', async ({ page }) => {
    // An independent re-derivation: count matching bytes between the committed
    // recovery and the truth, both parsed off the page, and compare that with
    // the score the page printed. A source that miscounted would disagree here.
    await boot(page);
    await setSeed(page, 'claims-score');
    await build(page, 'none');
    await trace(page, 384);
    await attack(page, 'input', ['sbox', 'inverse']);
    const recovered = (await definition(page, '#dca-out', 'What the attack committed to')).replace(/\s/g, '');
    const truth = (await definition(page, '#dca-out', 'The truth, consulted only afterwards')).replace(/\s/g, '');
    expect(recovered).toMatch(/^[0-9a-f]{32}$/);
    expect(truth).toBe(BASE_KEY);
    let matching = 0;
    for (let i = 0; i < 16; i++) if (recovered.slice(2 * i, 2 * i + 2) === truth.slice(2 * i, 2 * i + 2)) matching++;
    expect(number(await definition(page, '#dca-out', 'Bytes correct'))).toBe(matching);
    const headline = await page.locator('#dca-verdict .pill-text').innerText();
    expect(headline).toContain(`${matching} OF 16`);
  });

  test('the sixteen cells say the same thing as the committed hex', async ({ page }) => {
    await boot(page);
    await setSeed(page, 'claims-cells');
    await build(page, 'none');
    await trace(page, 256);
    await attack(page, 'input');
    const recovered = (await definition(page, '#dca-out', 'What the attack committed to')).replace(/\s/g, '');
    const truth = (await definition(page, '#dca-out', 'The truth, consulted only afterwards')).replace(/\s/g, '');
    const cells = page.locator('#byte-strip .byte-cell');
    await expect(cells).toHaveCount(16);
    let found = 0;
    for (let i = 0; i < 16; i++) {
      const value = await cells.nth(i).locator('.byte-value').innerText();
      const stateText = await cells.nth(i).locator('.byte-state').innerText();
      expect(value, `cell ${i}`).toBe(recovered.slice(2 * i, 2 * i + 2));
      const isRight = recovered.slice(2 * i, 2 * i + 2) === truth.slice(2 * i, 2 * i + 2);
      expect(stateText, `cell ${i}`).toBe(isRight ? 'found' : 'missed');
      if (isRight) found++;
    }
    expect(number(await definition(page, '#dca-out', 'Bytes correct'))).toBe(found);
  });

  test('every margin is (peak − runner-up) / peak, recomputed from the detail table', async ({ page }) => {
    await boot(page);
    await setSeed(page, 'claims-margin');
    await build(page, 'none');
    await trace(page, 256);
    await attack(page, 'input');
    await page.locator('details.more', { hasText: 'Per-byte detail' }).locator('summary').click();
    const rows = page.locator('#dca-inspect table.matrix.detail tbody tr');
    await expect(rows).toHaveCount(16);
    for (let i = 0; i < 16; i++) {
      const cells = await rows.nth(i).locator('th, td').allInnerTexts();
      const peak = Number(cells[2]);
      const runnerUp = Number((cells[3].match(/at ([\d.]+)/) ?? [])[1]);
      const margin = number(cells[4]);
      expect(peak, `row ${i}`).toBeGreaterThan(0);
      expect(runnerUp, `row ${i}`).toBeLessThanOrEqual(peak);
      expect(Math.abs(Math.round(((peak - runnerUp) / peak) * 100) - margin), `row ${i}`).toBeLessThanOrEqual(1);
      // The strip's margin agrees with the table's, for the same byte.
      const stripMargin = number(
        await page.locator('#byte-strip .byte-cell').nth(i).locator('.byte-margin').innerText(),
      );
      expect(stripMargin, `row ${i} strip`).toBe(margin);
    }
  });

  test('the winning sample is inside the window the page says it scanned', async ({ page }) => {
    await boot(page);
    await build(page, 'none');
    await trace(page, 256);
    await attack(page, 'input');
    const detail = await page.locator('#dca-verdict .verdict-detail').innerText();
    const samples = number((detail.match(/([\d,]+) samples/) ?? [])[1]);
    expect(samples).toBe(1792);
    await page.locator('details.more', { hasText: 'Per-byte detail' }).locator('summary').click();
    const rows = page.locator('#dca-inspect table.matrix.detail tbody tr');
    for (let i = 0; i < 16; i++) {
      const cells = await rows.nth(i).locator('th, td').allInnerTexts();
      const sample = number(cells[5]);
      expect(sample, `row ${i}`).toBeLessThan(samples);
    }
  });

  test('the canvas descriptions are rewritten from the data, not written once', async ({ page }) => {
    await boot(page);
    await build(page, 'none');
    await trace(page, 256);
    await attack(page, 'input');
    const before = await page.locator('#peaks-plot').getAttribute('aria-label');
    // A byte the inspector is not already showing: after a run it opens on the
    // byte the attack was most confident about, which can be any of them.
    const shown = Number(await page.locator('#byte-select').inputValue());
    const other = String((shown + 7) % 16);
    await page.locator('#byte-select').selectOption(other);
    await expect(page.locator('#peaks-plot')).toHaveAttribute('aria-label', new RegExp(`key byte ${other}\\b`));
    const after = await page.locator('#peaks-plot').getAttribute('aria-label');
    expect(after).not.toBe(before);
    // And the visible caption says the same thing as the label a reader hears.
    expect((await page.locator('#peaks-plot-cap').innerText()).trim()).toBe(after!.trim());
  });
});

test.describe('Act 5: where the encodings live, measured', () => {
  test('compiling the encodings in changes the program and not the recovery', async ({ page }) => {
    // The Bos et al. section 5.4 claim, tested. One seed pins the AES core, so
    // the two runs differ only in where the external encodings live.
    await boot(page);
    await setSeed(page, 'act5-fixed');

    await build(page, 'none');
    const plainTables = number(await definition(page, '#build-out', 'Tables in the program'));
    const plainBits = number(await definition(page, '#build-out', 'Bits one trace will record'));
    await trace(page, 384);
    await attack(page, 'input', ['sbox', 'inverse']);
    const plainRecovered = (await definition(page, '#dca-out', 'What the attack committed to')).replace(/\s/g, '');
    const plainScore = number(await definition(page, '#dca-out', 'Bytes correct'));

    await build(page, 'compiled-in');
    const compiledTables = number(await definition(page, '#build-out', 'Tables in the program'));
    const compiledBits = number(await definition(page, '#build-out', 'Bits one trace will record'));
    await trace(page, 384);
    await attack(page, 'input', ['sbox', 'inverse']);
    const compiledRecovered = (await definition(page, '#dca-out', 'What the attack committed to')).replace(/\s/g, '');

    // The program really changed...
    expect(compiledTables).toBeGreaterThan(plainTables);
    expect(compiledBits).toBeGreaterThan(plainBits);
    // ...and the attack recovered exactly the same sixteen bytes.
    expect(compiledRecovered).toBe(plainRecovered);
    expect(plainScore).toBeGreaterThanOrEqual(14);
    // The page says so itself, from the rows it logged.
    await expect(page.locator('#compiled-in-comparison')).toHaveAttribute('data-comparison', 'identical');
    await expect(page.locator('#compiled-in-comparison')).toContainText('THE ENCODING CHANGED NOTHING');
  });

  test('a remote OUTPUT encoding leaves the input side wide open', async ({ page }) => {
    await boot(page);
    await setSeed(page, 'act5-fixed');
    await build(page, 'remote-output');
    await trace(page, 384);
    await attack(page, 'input', ['sbox', 'inverse']);
    expect(number(await definition(page, '#dca-out', 'Bytes correct'))).toBeGreaterThanOrEqual(14);
  });

  test('a remote INPUT encoding closes the input side and leaves the output side partly open', async ({ page }) => {
    await boot(page);
    await setSeed(page, 'act5-fixed');
    await build(page, 'remote-input');
    await trace(page, 1024);

    await attack(page, 'input', ['sbox', 'inverse']);
    expect(number(await definition(page, '#dca-out', 'Bytes correct'))).toBeLessThanOrEqual(2);
    await expect(page.locator('#no-hypothesis-note')).toBeVisible();

    await attack(page, 'output');
    // Better than chance and not complete -- a lab-original measurement, and the
    // page has to report both halves of it.
    const score = number(await definition(page, '#dca-out', 'Bytes correct'));
    expect(score).toBeGreaterThanOrEqual(4);
    expect(score).toBeLessThan(16);
    await expect(page.locator('#dca-verdict .pill-text')).toContainText('ROUND KEY PARTLY RECOVERED');
    // And the key does not follow, because the schedule needs all sixteen.
    const derived = number(await definition(page, '#dca-out', 'and how much of it is right'));
    expect(derived).toBeLessThanOrEqual(2);
    expect(await definition(page, '#dca-out', 'and how much of it is right')).toContain('ALL sixteen bytes');
  });

  test('the log row agrees with the verdict that produced it', async ({ page }) => {
    await boot(page);
    await build(page, 'none');
    await trace(page, 256);
    await attack(page, 'input');
    const score = number(await definition(page, '#dca-out', 'Bytes correct'));
    const row = page.locator('#placement-log table.matrix tbody tr').first();
    await expect(row.locator('[data-log-recovered]')).toHaveAttribute('data-log-recovered', String(score));
    await expect(row).toContainText(`${score} of 16`);
  });
});

/**
 * Section 4.1d -- the negative claim, tested as a result rather than left as
 * prose.
 *
 * The fixture is a state the page can really be driven into where EVERY check
 * the construction and this page perform reports success, and the named property
 * is violated anyway. Three things are asserted: that the fixture is reachable
 * through the UI, that everything in it is green, and that the limitation is on
 * screen in that state -- visible, not in the README, not behind a disclosure.
 */
test.describe('NEG-1 as an evidence fixture', () => {
  const NEG_1_OPENING = 'Holding Chow’s external encodings outside the program stops this trace-based attack';

  /** Reach the fixture: the encodings held remotely on both sides, traced and attacked. */
  async function reachFixture(page: Page): Promise<void> {
    await setSeed(page, 'neg-1');
    await build(page, 'remote-both');
    await trace(page, 384);
    await attack(page, 'input', ['sbox', 'inverse']);
    await expect(page.locator('#dca-verdict .pill-text')).toContainText('NO RECOVERY');
    await expect(page.locator('#neg-fixture [data-fixture-verdict]')).toHaveAttribute(
      'data-fixture-verdict',
      'reached',
    );
  }

  test('1. the fixture is reachable, and 2. every check the page performs is green', async ({ page }) => {
    await boot(page);
    await reachFixture(page);
    const panel = page.locator('#neg-fixture');

    // Enumerated from what the page PAINTED, not from a flag this test set.
    const performed = panel.locator('[data-check]');
    const count = await performed.count();
    expect(count, 'the fixture must exercise at least one real check').toBe(4);
    for (let i = 0; i < count; i++) {
      await expect(performed.nth(i)).toHaveAttribute('data-check', 'pass');
      await expect(performed.nth(i).locator('[data-verdict="check"]')).toContainText('HELD');
    }
    // Nothing anywhere on the page reports a failed check in this state.
    await expect(page.locator('[data-check="fail"]')).toHaveCount(0);

    // The construction's own report is a success, and names no code.
    const text = (await panel.innerText()).replace(/\s+/g, ' ');
    expect(text).toContain('The program raised no failure code');
    expect(text).toContain('There is none to raise');
    expect(text).toContain('cannot tell that it is being traced');

    // ...and the property is violated anyway, by an attack that ran no traces.
    expect(text).toMatch(/stripped all four output encodings/);
    expect(text).toContain('zero traces');
  });

  test('the absence of a failure code is rendered, not merely implied', async ({ page }) => {
    await boot(page);
    await reachFixture(page);
    // The scope card names every code the page CAN raise and says, in the same
    // table, that the program itself raises none.
    await page.locator('details.more', { hasText: 'The failure codes this lab can raise' }).locator('summary').click();
    const codes = await page.locator('#scope table.matrix tbody tr').allInnerTexts();
    expect(codes.join(' ')).toContain('KEY_HEX_MALFORMED');
    expect(codes.join(' ')).toContain('ROUND_OUT_OF_RANGE');
    const none = codes.find((row) => row.includes('(none)'));
    expect(none, 'the program’s own row must exist').toBeTruthy();
    expect(none).toContain('the white-box program itself');
    expect(none).toContain('while it is being broken');
  });

  test('3. the limitation is on screen in that state, visible and not behind a disclosure', async ({ page }) => {
    await boot(page);
    // Before the fixture is reached, the claim is not being made about a state
    // that does not exist yet.
    await expect(page.locator('#neg-fixture [data-negative-claim]')).toHaveCount(0);

    await reachFixture(page);
    const claim = page.locator('#neg-fixture [data-negative-claim="NEG-1"]');
    await expect(claim).toHaveCount(1);
    await expect(claim).toBeVisible();
    await expect(claim).toContainText(NEG_1_OPENING);

    // Not behind a disclosure, and inside the panel that holds the fixture.
    const insideDetails = await claim.evaluate((el) => !!el.closest('details'));
    expect(insideDetails, 'the negative claim must not be behind a disclosure').toBe(false);
    const insideFixture = await claim.evaluate((el) => !!el.closest('#act-placement'));
    expect(insideFixture, 'the claim must be tied to the state that demonstrates it').toBe(true);

    // The scope card quotes the SAME sentence, from the same constant.
    const scopeClaim = await page.locator('#scope [data-negative-claim="NEG-1"] .neg-claim-text').innerText();
    expect(scopeClaim.trim()).toBe((await claim.locator('.neg-claim-text').innerText()).trim());
  });

  test('the fixture says plainly that state 3 moves the problem rather than solving it', async ({ page }) => {
    await boot(page);
    await reachFixture(page);
    const text = (await page.locator('#neg-fixture').innerText()).replace(/\s+/g, ' ');
    expect(text).toContain('The problem moves rather than dissolving');
    expect(text).toContain('applies them to every block');
    // ...and the paper says it too, with the section it says it in.
    expect(text).toContain('Section 6');
    expect(text).toContain('the primary reason why we were not able to extract the secret key');
  });

  test('the claim retires with its fixture: change the placement and it is gone', async ({ page }) => {
    await boot(page);
    await reachFixture(page);
    await expect(page.locator('#neg-fixture [data-negative-claim]')).toHaveCount(1);

    await build(page, 'none');
    await expect(page.locator('#neg-fixture [data-negative-claim]')).toHaveCount(0);
    await expect(page.locator('#neg-fixture .placeholder')).toHaveCount(1);
    // The scope card's copy stays, because it is a statement about the lab
    // rather than about a state.
    await expect(page.locator('#scope [data-negative-claim="NEG-1"]')).toHaveCount(1);
  });
});

test.describe('Act 6: the algebraic attack', () => {
  test('step A1 reports a group of order 256 and a spread that collapses to one', async ({ page }) => {
    await boot(page);
    await build(page, 'remote-both');
    await runBge(page, '4', '1');
    await expect(page.locator('#bge-verdict')).toHaveAttribute('data-bge-verdict', 'stripped');
    const rows = page.locator('#bge-out table.matrix tbody tr');
    await expect(rows).toHaveCount(4);
    for (let i = 0; i < 4; i++) {
      const cells = await rows.nth(i).locator('th, td').allInnerTexts();
      expect(number(cells[1]), `row ${i} group order`).toBe(256);
      expect(cells[2], `row ${i} involutions`).toContain('yes');
      expect(number(cells[3]), `row ${i} basis`).toBe(8);
      // The result: the difference varied before and is one value after.
      expect(number(cells[4]), `row ${i} spread before`).toBeGreaterThan(1);
      expect(cells[5], `row ${i} spread after`).toContain('1 value');
      expect(cells[5], `row ${i} spread after`).toContain('constant in x');
    }
    await expect(page.locator('#bge-verdict')).toContainText('not one traced encryption');
  });

  test('it does not claim to run the steps it does not run', async ({ page }) => {
    await boot(page);
    const honest = page.locator('.honest-panel');
    await expect(honest).toContainText('The steps after A1 are not implemented here');
    await expect(honest).toContainText('nothing on this page pretends to');
    // The promise and the computation have to agree: one attack reaches a key,
    // the other reaches the encodings, and the page says which is which.
    await expect(honest).toContainText('one reaches a key and the other reaches the encodings');
    await expect(honest).toContainText('2^30');
    await expect(honest).toContainText('2^22');
    await expect(honest).toContainText('Step A1 only');
    // And the third author is named correctly, everywhere.
    const body = await page.locator('#app').innerText();
    expect(body).toContain('Ech-Chatbi');
    expect(body).not.toContain('Echauzier');
  });
});

test.describe('failure paths: the page names the actual cause', () => {
  test('KEY_HEX_MALFORMED and KEY_LENGTH_INVALID', async ({ page }) => {
    await boot(page);
    await page.fill('#key-hex', 'zz0102030405060708090a0b0c0d0e0f');
    await page.locator('#build').click();
    await expect(page.locator('#key-error')).toContainText('KEY_HEX_MALFORMED');
    await expect(page.locator('#key-error')).toContainText('hexadecimal');
    await expect(page.locator('#key-hex')).toHaveAttribute('aria-invalid', 'true');

    await page.fill('#key-hex', '00010203');
    await page.locator('#build').click();
    await expect(page.locator('#key-error')).toContainText('KEY_LENGTH_INVALID');
    await expect(page.locator('#key-error')).toContainText('8 digits');
    await expect(page.locator('#key-error')).toContainText('4 bytes');

    await page.fill('#key-hex', BASE_KEY);
    await page.locator('#build').click();
    await expect(page.locator('#key-error')).toBeEmpty();
    await expect(page.locator('#key-hex')).not.toHaveAttribute('aria-invalid', 'true');
  });

  test('TRACE_COUNT_OUT_OF_RANGE, at both ends, with the range named', async ({ page }) => {
    await boot(page);
    for (const value of ['99999', '1', '0']) {
      await page.fill('#traces', value);
      await page.locator('#trace').click();
      await expect(page.locator('#trace-error')).toContainText('TRACE_COUNT_OUT_OF_RANGE');
      await expect(page.locator('#trace-error')).toContainText('between 8 and 2048');
      await expect(page.locator('#traces')).toHaveAttribute('aria-invalid', 'true');
    }
    await trace(page, 64);
    await expect(page.locator('#trace-error')).toBeEmpty();
  });

  test('TRACE_BUDGET_EXCEEDED, on the placement whose program is twice the size', async ({ page }) => {
    // The guard is on BYTES, not on the trace count, and it bites on exactly one
    // placement -- which is the reason it exists and what makes it worth showing.
    await boot(page);
    await build(page, 'none');
    await trace(page, 2048);
    await expect(page.locator('#trace-error')).toBeEmpty();

    await build(page, 'compiled-in');
    await page.fill('#traces', '2048');
    await page.locator('#trace').click();
    await expect(page.locator('#trace-error')).toContainText('TRACE_BUDGET_EXCEEDED');
    await expect(page.locator('#trace-error')).toContainText('7 MB budget');
    await expect(page.locator('#trace-error')).toContainText('computed before anything is allocated');
    await expect(page.locator('#traces')).toHaveAttribute('aria-invalid', 'true');

    // ...and the same placement accepts a count the budget does allow.
    await trace(page, 1024);
    await expect(page.locator('#trace-error')).toBeEmpty();
  });

  test('NO_PROGRAM_BUILT, after a build that failed', async ({ page }) => {
    await boot(page);
    await page.fill('#key-hex', 'nonsense');
    await page.locator('#build').click();
    await expect(page.locator('#key-error')).toContainText('KEY_HEX_MALFORMED');
    // There is now no program, so the acts that need one must say so by name
    // rather than silently doing nothing.
    await page.locator('#trace').click();
    await expect(page.locator('#trace-error')).toContainText('NO_PROGRAM_BUILT');
    await page.locator('#run-bge').click();
    await expect(page.locator('#bge-error')).toContainText('NO_PROGRAM_BUILT');
    await expect(page.locator('#bge-error')).toContainText('reads its tables');
  });

  test('NO_TRACES_RECORDED and NO_HYPOTHESIS_SELECTED', async ({ page }) => {
    await boot(page);
    await page.locator('#run-dca').click();
    await expect(page.locator('#dca-error')).toContainText('NO_TRACES_RECORDED');
    await expect(page.locator('#dca-error')).toContainText('statistical attack');

    await trace(page, 64);
    await page.locator('#target-sbox').uncheck();
    await page.locator('#target-inverse').uncheck();
    await page.locator('#run-dca').click();
    await expect(page.locator('#dca-error')).toContainText('NO_HYPOTHESIS_SELECTED');
    await expect(page.locator('#dca-error')).toContainText('nothing to correlate');
  });

  test('every declared code is either raised here or named on the page', async ({ page }) => {
    await boot(page);
    await page.locator('details.more', { hasText: 'The failure codes this lab can raise' }).locator('summary').click();
    const table = (await page.locator('#scope table.matrix').innerText()).replace(/\s+/g, ' ');
    for (const code of [
      'KEY_HEX_MALFORMED',
      'KEY_LENGTH_INVALID',
      'TRACE_COUNT_OUT_OF_RANGE',
      'TRACE_BUDGET_EXCEEDED',
      'NO_HYPOTHESIS_SELECTED',
      'NO_PROGRAM_BUILT',
      'NO_TRACES_RECORDED',
      'ROUND_OUT_OF_RANGE',
      'COLUMN_OUT_OF_RANGE',
      'NOT_A_BIJECTION',
      'GROUP_NOT_ELEMENTARY_ABELIAN',
      'GROUP_ORDER_WRONG',
    ]) {
      expect(table, code).toContain(code);
    }
  });
});

/**
 * The guided route, end to end, pressing nothing but the one button the page
 * offers next.
 *
 * This is the test that stands in for a newcomer. It never touches a control it
 * was not pointed at, it never combines two settings from knowledge the page did
 * not give it, and it asserts that the first thing it is asked to press is
 * visible without scrolling -- on a desktop and on a phone.
 */
test.describe('the guided route', () => {
  for (const viewport of [
    { width: 1440, height: 900, label: 'desktop' },
    { width: 390, height: 844, label: 'phone' },
  ]) {
    test(`one button per stage reaches a full recovery (${viewport.label})`, async ({ page }) => {
      test.setTimeout(900_000);
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      await boot(page);

      // 1. The first action is in the first viewport, unscrolled.
      const first = page.locator('#guide-action button');
      const box = await first.boundingBox();
      expect(box, 'the guided action must be on the page').not.toBeNull();
      expect(box!.y + box!.height, `${viewport.label}: the first action must fit above the fold`).toBeLessThanOrEqual(
        viewport.height,
      );
      expect(await page.evaluate(() => window.scrollY)).toBe(0);

      // 2. The rail starts with Build already done -- the page builds on load --
      //    and Trace as the next thing.
      await expect(page.locator('#guide-rail [data-stage="build"]')).toHaveAttribute('data-state', 'done');
      await expect(page.locator('#guide-rail [data-stage="trace"]')).toHaveAttribute('data-state', 'active');

      // 3. Press whatever it offers, until it offers nothing more. Driven by
      //    the page rather than by a fixed script: one press can finish more
      //    than one stage -- the placement sweep ends on the state the negative
      //    claim is about, and reaching that state runs the algebraic attack
      //    too, because the claim is not made without its evidence.
      const stages = ['build', 'trace', 'recover', 'boundary', 'tables'];
      const stateOf = (stage: string): Promise<string | null> =>
        page.locator(`#guide-rail [data-stage="${stage}"]`).getAttribute('data-state');
      const remaining = async (): Promise<number> => {
        let n = 0;
        for (const stage of stages) if ((await stateOf(stage)) !== 'done') n++;
        return n;
      };

      for (let press = 0; press < stages.length; press++) {
        const left = await remaining();
        if (left === 0) break;
        const label = await first.innerText();
        await first.click();
        await expect.poll(remaining, { timeout: 600_000 }).toBeLessThan(left);
        expect(await first.innerText(), `the action must change after "${label}"`).not.toBe(label);
      }

      // 4. Every stage is done, and the key really came out along the way.
      expect(await remaining(), 'the guided route must complete').toBe(0);
      for (const stage of stages) {
        await expect(page.locator(`#guide-rail [data-stage="${stage}"]`)).toHaveAttribute('data-state', 'done');
      }
      await expect(page.locator('#guide-lead')).toContainText('You have run the whole route');
      // The placement sweep leaves the page on remote-both, so the last verdict
      // on screen is the defended one; the recovery it passed through is in the log.
      const log = (await page.locator('#placement-log').innerText()).replace(/\s+/g, ' ');
      expect(log).toContain('no external encodings');
      expect(log).toMatch(/1[4-6] of 16/);
      await expect(page.locator('#bge-verdict')).toHaveAttribute('data-bge-verdict', 'stripped');

      // 5. And none of it pushed the page sideways.
      const overflow = await page.evaluate(() => {
        const doc = document.documentElement;
        return doc.scrollWidth > doc.clientWidth ? `${doc.scrollWidth} > ${doc.clientWidth}` : null;
      });
      expect(overflow, `${viewport.label}: no horizontal overflow`).toBeNull();
    });
  }
});

/**
 * Every central historical claim is tied to a place in a paper, and the page
 * says which. These assertions exist so a citation cannot quietly drift away
 * from the sentence it supports.
 */
test.describe('primary sources', () => {
  test('the page cites the section each claim comes from', async ({ page }) => {
    await boot(page);
    for (const d of await page.locator('details.more').all()) await d.locator('summary').click();
    const body = (await page.locator('#app').innerText()).replace(/\s+/g, ' ');

    // Bos et al. (CHES 2016): the compiled-in result, the failure case, the
    // scope, and the reported figures.
    expect(body).toContain('section 5.4');
    expect(body).toContain('gave similar results');
    expect(body).toContain('section 5.5');
    expect(body).toContain('infeasible to apply a meaningful DPA attack');
    expect(body).toContain('at most a single remotely handled external encoding');
    expect(body).toContain('not a white-box implementation of a standard algorithm');
    expect(body).toContain('15 out of 16 key bytes');
    // Section 6 is cited beside the NEG-1 fixture, which only exists once the
    // page has been driven into the state the claim is about -- so it is
    // asserted there, in the fixture's own test, rather than here.

    // BGE: the decomposition of the published work factor, and what this page
    // does NOT run.
    expect(body).toContain('2^24');
    expect(body).toContain('2^28');
    expect(body).toContain('2^30');
    expect(body).toContain('one reaches a key and the other reaches the encodings');

    // FIPS 197 and the construction.
    expect(body).toContain('FIPS 197');
    expect(body).toContain('Ech-Chatbi');
    expect(body).not.toContain('Echauzier');
  });
});

/**
 * The rank table and the second distinguisher.
 *
 * These reproduce a published observation on the reader's own instance, so the
 * tests check that the page reports what it measured rather than a number
 * someone typed into the copy.
 */
test.describe('Act 4: reading the failures', () => {
  test('the rank table is the true byte\u2019s rank, and the count of extremes matches the cells', async ({ page }) => {
    await boot(page);
    await setSeed(page, 'ranks');
    await build(page, 'none');
    // 2,048, which is the trace count Bos et al. report their tables at. The
    // effect is weaker with fewer traces and the page says so, so a test that
    // asserted it at 384 would be asserting the wrong thing.
    await trace(page, 2048);
    await attack(page, 'input', ['sbox', 'inverse']);
    await page.locator('details.more', { hasText: 'Where the true byte ranked' }).locator('summary').click();

    const rows = page.locator('#dca-inspect table.matrix.ranks tbody tr');
    await expect(rows).toHaveCount(16); // two targets x eight prediction bits
    let extremes = 0;
    let cells = 0;
    for (let r = 0; r < 16; r++) {
      const values = (await rows.nth(r).locator('td').allInnerTexts()).map((t) => Number(t));
      expect(values).toHaveLength(16); // one per key byte
      for (const v of values) {
        expect(v, `row ${r}`).toBeGreaterThanOrEqual(1);
        expect(v, `row ${r}`).toBeLessThanOrEqual(256);
        cells++;
        if (v === 1 || v === 256) extremes++;
      }
    }
    expect(cells).toBe(256);
    // The sentence under the table has to be the count of the table above it.
    const caption = await page.locator('#dca-inspect').innerText();
    expect(caption.replace(/\s+/g, ' ')).toContain(`${extremes} of 256 cells sit at 1 or 256`);
    // And the phenomenon is really there: an even spread would give about two.
    expect(extremes).toBeGreaterThan(150);
  });

  test('the second distinguisher scores in its own units and says so', async ({ page }) => {
    await boot(page);
    await setSeed(page, 'extremity');
    await build(page, 'none');
    await trace(page, 2048);

    await attack(page, 'input', ['sbox', 'inverse']);
    const byPeak = (await definition(page, '#dca-out', 'What the attack committed to')).replace(/\s/g, '');

    await page.locator('#distinguisher-select').selectOption('extremity');
    await afterRun(page, 'dca-status', () => page.locator('#run-dca').click());
    const byExtremity = (await definition(page, '#dca-out', 'What the attack committed to')).replace(/\s/g, '');
    const truth = (await definition(page, '#dca-out', 'The truth, consulted only afterwards')).replace(/\s/g, '');

    // Two different readings of the same traces, and at this trace count both
    // arrive at the key -- which is the claim the page makes about it.
    expect(byExtremity).toBe(truth);
    expect(byPeak).toBe(truth);
    // The scores are not differences of means any more, so they are not in [0, 1].
    await page.locator('details.more', { hasText: 'Per-byte detail' }).locator('summary').click();
    const firstPeak = Number(
      await page.locator('#dca-inspect table.matrix.detail tbody tr').first().locator('td').nth(1).innerText(),
    );
    expect(firstPeak).toBeGreaterThan(1);
  });
});

test.describe('reproducible run links', () => {
  test('a link carries a key the PAGE chose, and never one the reader typed', async ({ page }) => {
    await boot(page);
    await setSeed(page, 'link-seed');
    await build(page, 'remote-output');
    await page.fill('#traces', '512');

    // A key the reader typed does not travel -- and `build` above types one, so
    // this is the state a reader reaches by using the field at all.
    await page.locator('#copy-run-link').click();
    await expect(page.locator('#share-status')).toContainText('NOT the key you typed');
    await expect(page.locator('#share-status')).toContainText('should not put a reader');

    // A key the PAGE chose does. Asserted on the NOTE rather than on the word
    // "Copied", because a headless browser will not hand the page a clipboard
    // and the note is what matters either way.
    await afterRun(page, 'build-status', () => page.locator('#generate-key').click());
    await page.locator('#copy-run-link').click();
    await expect(page.locator('#share-status')).toContainText('The link carries the key');
    await expect(page.locator('#share-status')).toContainText('not secret');
  });

  test('a seed reproduces the RUN, not just the instance -- and no seed does not', async ({ page }) => {
    // What the link promises. A seed that pinned the encodings but not the
    // plaintexts traced under them would give the same program and a different
    // result, which is not what "reproducible" means to anyone reading it.
    //
    // Margins are the sharp instrument here: a margin is (peak - runner-up) /
    // peak over the measured trace bits, so two runs agreeing on all sixteen to
    // the printed percent is not something a different set of plaintexts does.
    const measure = async (seed: string): Promise<string[]> => {
      await boot(page);
      if (seed.length > 0) await setSeed(page, seed);
      await build(page, 'none');
      await trace(page, 256);
      await attack(page, 'input', ['sbox', 'inverse']);
      return page.locator('#byte-strip .byte-margin').allInnerTexts();
    };

    const first = await measure('repro-seed');
    const second = await measure('repro-seed');
    expect(first).toHaveLength(16);
    expect(second).toEqual(first);

    // And the unseeded path really is unseeded, so the label on it is not a
    // formality. Sixteen margins agreeing by chance is not a thing that happens.
    const loose = await measure('');
    expect(loose).toHaveLength(16);
    expect(loose).not.toEqual(first);
  });

  test('opening a link reproduces the settings it carried', async ({ page }) => {
    await page.goto(
      './?seed=shared-seed&key=2b7e151628aed2a6abf7158809cf4f3c&placement=compiled-in&traces=768&surface=input&targets=sbox-output,inverse&bits=3&score=extremity',
    );
    await expect(page.locator('#build-verdict .pill-text')).toHaveText('IT IS AES-128');
    await expect(page.locator('#key-hex')).toHaveValue('2b7e151628aed2a6abf7158809cf4f3c');
    await expect(page.locator('#seed')).toHaveValue('shared-seed');
    await expect(page.locator('input[name="placement"]:checked')).toHaveValue('compiled-in');
    await expect(page.locator('#traces')).toHaveValue('768');
    await expect(page.locator('#target-sbox')).toBeChecked();
    await expect(page.locator('#target-inverse')).toBeChecked();
    await expect(page.locator('#bit-select')).toHaveValue('3');
    await expect(page.locator('#distinguisher-select')).toHaveValue('extremity');
    await expect(page.locator('#build-out')).toContainText('NOT secret');
  });

  test('a link full of nonsense is ignored rather than trusted', async ({ page }) => {
    await page.goto('./?key=not-a-key&placement=banana&traces=999999&bits=99&score=magic&surface=sideways');
    await expect(page.locator('#build-verdict .pill-text')).toHaveText('IT IS AES-128');
    // Every rejected parameter falls back to the shipped default.
    await expect(page.locator('#key-hex')).toHaveValue('000102030405060708090a0b0c0d0e0f');
    await expect(page.locator('input[name="placement"]:checked')).toHaveValue('none');
    await expect(page.locator('#traces')).toHaveValue('384');
    await expect(page.locator('#bit-select')).toHaveValue('all');
    await expect(page.locator('#distinguisher-select')).toHaveValue('peak');
    await expect(page.locator('input[name="surface"]:checked')).toHaveValue('input');
  });
});

test.describe('the sweep', () => {
  test('measures all seven combinations and ends on the state the claim is about', async ({ page }) => {
    test.setTimeout(600_000);
    await boot(page);
    // A seed, like every other act-5 test here. Without one the sweep builds
    // `sweep-${Date.now()}` -- a different instance on every run -- and the
    // comparison below is then an assertion about an unrepeatable measurement.
    // It failed in CI exactly that way: 15 bytes against 16 at 256 traces, on
    // an instance no one could look at afterwards.
    await setSeed(page, 'act5-fixed');
    await page.fill('#traces', '256');
    await page.locator('#sweep').click();
    await expect(page.locator('#sweep-status')).toContainText('Measured all 7 combinations', { timeout: 420_000 });

    // Seven rows, one per (placement, side), each carrying what it measured.
    const rows = page.locator('#placement-log table.matrix tbody tr');
    await expect(rows).toHaveCount(7);
    const text = (await page.locator('#placement-log').innerText()).replace(/\s+/g, ' ');
    for (const label of [
      'no external encodings',
      'compiled into the program',
      'remote, both sides',
      'remote, input side only',
      'remote, output side only',
    ]) {
      expect(text, label).toContain(label);
    }
    // One seed across the sweep, so this is a comparison of placements rather
    // than of seven unrelated instances -- and the headline result follows.
    // A seed now pins the traced plaintexts too, so this is reproducible rather
    // than merely likely.
    await expect(page.locator('#compiled-in-comparison')).toHaveAttribute('data-comparison', 'identical');
    // The outcome that would actually contradict Bos et al. 5.4 has its own
    // state, so a failure here cannot quietly read as the benign one.
    await expect(page.locator('#compiled-in-comparison')).not.toHaveAttribute('data-comparison', 'refuted');

    // It leaves the page on the state the negative claim is about, with the
    // claim and its four green checks on screen.
    await expect(page.locator('input[name="placement"]:checked')).toHaveValue('remote-both');
    await expect(page.locator('#dca-verdict .pill-text')).toContainText('NO RECOVERY');
    await expect(page.locator('#neg-fixture [data-negative-claim="NEG-1"]')).toBeVisible();
    await expect(page.locator('#neg-fixture [data-check="pass"]')).toHaveCount(4);
  });
});

test.describe('retirement and the no-op guard', () => {
  test('rebuilding retires the trace and the attack, and says so', async ({ page }) => {
    await boot(page);
    await build(page, 'none');
    await trace(page, 128);
    await attack(page, 'input');
    await expect(page.locator('#dca-verdict')).toBeVisible();

    await build(page, 'compiled-in');
    // The stale verdicts are gone...
    await expect(page.locator('#dca-verdict')).toHaveCount(0);
    await expect(page.locator('#trace-out table.matrix')).toHaveCount(0);
    // ...and the page says they were retired, rather than blanking silently.
    await expect(page.locator('#trace-retired')).toHaveAttribute('data-retired', 'trace');
    await expect(page.locator('#trace-retired')).toContainText('described a different program');
    await expect(page.locator('#dca-retired')).toHaveAttribute('data-retired', 'dca');
    await expect(page.locator('#dca-retired')).toContainText('a different key');
  });

  test('re-selecting the SAME placement does not retire a fresh verdict', async ({ page }) => {
    await boot(page);
    await build(page, 'remote-output');
    await trace(page, 128);
    await attack(page, 'input');
    const before = await page.locator('#dca-verdict').innerText();

    await page.locator('#placement-remote-output').check();
    await page.waitForTimeout(300);
    await expect(page.locator('#dca-verdict')).toHaveCount(1);
    expect(await page.locator('#dca-verdict').innerText()).toBe(before);
    await expect(page.locator('#dca-retired')).toHaveCount(0);
  });
});

test.describe('scope, persistence and hidden content', () => {
  test('the honest framing is on the page, in the words the template asks for', async ({ page }) => {
    await boot(page);
    // The summary is visible without opening anything; the detail is one click
    // away and still on the page.
    const summary = (await page.locator('#scope-summary').innerText()).replace(/\s+/g, ' ');
    expect(summary).toContain('Not production crypto');
    expect(summary).toContain('instrumenting itself');
    for (const d of await page.locator('#scope details.more').all()) await d.locator('summary').click();
    const scope = (await page.locator('#scope').innerText()).replace(/\s+/g, ' ');
    expect(scope).toContain('Not production crypto');
    expect(scope).toContain('Do not use it to protect anything');
    expect(scope).toContain('What it does not prove');
    expect(scope).toContain('the program instrumenting itself');
    expect(scope).toContain('Rivain and Wang broke encodings wider than 4 bits');
    // The two wrong claims the brief's revision notes call out must not appear.
    const body = (await page.locator('#app').innerText()).replace(/\s+/g, ' ');
    expect(body).not.toContain('no published white-box AES scheme');
    expect(body).not.toMatch(/4-bit vulnerable/i);
  });

  test('nothing but the theme is persisted, and the theme is dark', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('theme', 'light'));
    await boot(page);
    expect(await page.evaluate(() => Object.keys(localStorage))).toEqual(['theme']);
    expect(await page.evaluate(() => localStorage.getItem('theme'))).toBe('dark');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect(page.locator('#theme-toggle, .theme-toggle, [data-theme-toggle]')).toHaveCount(0);
  });

  test('no element is [hidden] while it paints', async ({ page }) => {
    // The section 4.1 cascade trap: a class rule setting `display` outranks the
    // UA `[hidden]` rule, so the element paints while the code believes it is
    // hidden. This lab uses none, and this is what keeps that true.
    await boot(page);
    await build(page, 'none');
    await trace(page, 64);
    await attack(page, 'input');
    const painting = await page.evaluate(() =>
      Array.from(document.querySelectorAll('[hidden]'))
        .filter((el) => getComputedStyle(el).display !== 'none')
        .map((el) => el.tagName + '.' + el.className),
    );
    expect(painting).toEqual([]);
  });

  test('nothing on the page renders the word "undefined" or "null"', async ({ page }) => {
    // A guard for a whole class of silent failure. The production bundle turns a
    // module-level `const` into a `var`, so a declaration used before its line is
    // reached gives `undefined` rather than a temporal-dead-zone error -- and
    // `Node.append(undefined)` puts the five characters "undefined" on the page.
    // That really happened here, to act 2's share control.
    await boot(page);
    await build(page, 'none');
    await trace(page, 64);
    await attack(page, 'input');
    for (const d of await page.locator('details.more').all()) await d.locator('summary').click();
    const text = await page.locator('#app').innerText();
    expect(text, 'a bare "undefined" on the page is a declaration used before it was initialised').not.toMatch(
      /\bundefined\b/,
    );
    expect(text).not.toMatch(/\bNaN\b/);
    expect(text).not.toMatch(/\[object Object\]/);
  });

  test('the scripture footer is the last visible element, verbatim and once', async ({ page }) => {
    await boot(page);
    const footer = page.locator('.scripture-footer');
    await expect(footer).toHaveCount(1);
    await expect(footer).toHaveText(
      'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31',
    );
  });

  test('responsive: no horizontal overflow at phone width after a full run', async ({ page }) => {
    await page.setViewportSize({ width: 380, height: 844 });
    await boot(page);
    await build(page, 'none');
    await trace(page, 128);
    await attack(page, 'input');
    const overflow = await page.evaluate(() => {
      const doc = document.documentElement;
      return doc.scrollWidth > doc.clientWidth ? { scrollWidth: doc.scrollWidth, clientWidth: doc.clientWidth } : null;
    });
    expect(overflow).toBeNull();
  });
});
