import { expect, test, type Page } from '@playwright/test';

// These controls alter only replies in this isolated page; the actual worker
// still performs the calculation. No production hook or pinned fixture changes.
async function fault(page: Page, mode: string): Promise<void> {
  await page.addInitScript((initial: string) => {
    const scope = window as typeof window & { reviewFault: string; releaseReview?: () => void };
    scope.reviewFault = initial;
    const original = Worker.prototype.addEventListener;
    Worker.prototype.addEventListener = function(type: string, listener: EventListenerOrEventListenerObject, options?: boolean | AddEventListenerOptions) {
      if (type !== 'message') return original.call(this, type, listener, options);
      return original.call(this, type, (event: Event) => {
        const message = (event as MessageEvent).data;
        const deliver = (data: unknown): void => {
          const e = new MessageEvent('message', { data });
          if (typeof listener === 'function') listener.call(this, e); else listener.handleEvent(e);
        };
        if (scope.reviewFault === 'worker-error' && message.kind === 'build') {
          this.dispatchEvent(new ErrorEvent('error', { message: 'isolated calculation worker failure' }));
        } else if (scope.reviewFault === 'message-error' && message.kind === 'build') {
          this.dispatchEvent(new MessageEvent('messageerror'));
        } else if (scope.reviewFault === 'bge-failure' && message.kind === 'bge') {
          deliver({ kind: 'failure', id: message.id, code: 'NOT_A_BIJECTION', message: 'isolated missing algebraic evidence' });
        } else if (scope.reviewFault === 'zero-checks' && message.kind === 'build') {
          deliver({ ...message, verification: { ...message.verification, randomBlocks: 0, randomBlocksMatching: 0 } });
        } else if (scope.reviewFault === 'held-build' && message.kind === 'build') {
          scope.releaseReview = () => deliver(message);
        } else deliver(message);
      }, options);
    };
  }, mode);
}
async function boot(page: Page, query = ''): Promise<void> {
  page.setDefaultTimeout(15_000);
  await page.goto(`.${query}`);
  await expect(page.locator('#build-verdict [data-check]')).toHaveAttribute('data-check', 'pass');
  await expect(page.locator('html')).not.toHaveAttribute('data-busy', '');
}
async function traceAndAttack(page: Page): Promise<void> {
  await page.locator('#traces').fill('8');
  await page.locator('#trace').click();
  await expect(page.locator('#trace-status')).toContainText('recorded 8 traces');
  await page.locator('#run-dca').click();
  await expect(page.locator('#dca-verdict')).toBeVisible();
  await expect(page.locator('html')).not.toHaveAttribute('data-busy', '');
}

test.describe('student review: evidence belongs to the current calculation', () => {
  test('a failed rebuild retires prior trace, recovery and algebra results', async ({ page }) => {
    await boot(page, '?seed=student-review');
    await traceAndAttack(page);
    await page.locator('#run-bge').click();
    await expect(page.locator('#bge-verdict')).toBeVisible();
    await page.locator('#key-hex').fill('not a key');
    await page.locator('#build').click();
    await expect(page.locator('#key-error')).toContainText('KEY_HEX_MALFORMED');
    await expect(page.locator('#dca-verdict')).toHaveCount(0, { timeout: 2_000 });
    await expect(page.locator('#bge-verdict')).toHaveCount(0);
    await expect(page.locator('#trace-out')).not.toContainText('Traced encryptions');
  });
  test('a refused new trace cannot leave the old recovery verdict', async ({ page }) => {
    await boot(page, '?seed=student-review');
    await traceAndAttack(page);
    await page.locator('#traces').fill('0');
    await page.locator('#trace').click();
    await expect(page.locator('#trace-error')).toContainText('TRACE_COUNT_OUT_OF_RANGE');
    await expect(page.locator('#dca-verdict')).toHaveCount(0, { timeout: 2_000 });
  });
  test('the algebraic fixture cannot succeed when its calculation failed', async ({ page }) => {
    await fault(page, 'bge-failure');
    await boot(page, '?seed=student-review&placement=remote-both');
    await traceAndAttack(page);
    await expect(page.locator('#neg-fixture')).toContainText('could not be run');
    await expect(page.locator('#neg-fixture [data-fixture-verdict]')).toHaveAttribute('data-fixture-verdict', 'incomplete', { timeout: 2_000 });
    await expect(page.locator('#neg-fixture')).not.toContainText('ENCODINGS RECOVERED ANYWAY');
    await expect(page.locator('#neg-fixture [data-negative-claim]')).toHaveCount(0);
  });
  test('zero random comparisons cannot count as complete AES evidence', async ({ page }) => {
    await fault(page, 'zero-checks');
    await page.goto('.');
    await expect(page.locator('#build-verdict [data-check]')).toHaveAttribute('data-check', 'fail', { timeout: 5_000 });
  });
  test('settings cannot change beneath a pending calculation', async ({ page }) => {
    await fault(page, 'held-build');
    await page.goto('.');
    await expect.poll(() => page.evaluate(() => typeof (window as unknown as { releaseReview?: unknown }).releaseReview)).toBe('function');
    await expect(page.locator('#key-hex')).toBeDisabled({ timeout: 2_000 });
    await expect(page.locator('#placement-remote-both')).toBeDisabled();
    await page.evaluate(() => (window as unknown as { releaseReview: () => void }).releaseReview());
    await expect(page.locator('#build-verdict [data-check]')).toHaveAttribute('data-check', 'pass');
    await expect(page.locator('#key-hex')).toBeEnabled();
  });
  test('fractional trace counts are refused without rounding', async ({ page }) => {
    await boot(page);
    await page.locator('#traces').fill('8.5');
    await page.locator('#trace').click();
    await expect(page.locator('#trace-error')).toContainText('TRACE_COUNT_OUT_OF_RANGE', { timeout: 2_000 });
    await expect(page.locator('#traces')).toHaveValue('8.5');
  });
  for (const mode of ['worker-error', 'message-error']) {
    test(`${mode} ends pending work and explains how to retry`, async ({ page }) => {
      await fault(page, mode);
      await page.goto('.');
      await expect(page.locator('#key-error')).toContainText('WORKER_UNAVAILABLE');
      await expect(page.locator('#key-error')).toContainText('Reload');
      await expect(page.locator('html')).not.toHaveAttribute('data-busy', '');
      await expect(page.locator('#build')).toBeEnabled();
      await expect(page.locator('#build-verdict [data-check="pass"]')).toHaveCount(0);
      await page.locator('#build').click();
      await expect(page.locator('#key-error')).toContainText('WORKER_UNAVAILABLE');
      await expect(page.locator('#build')).toBeEnabled();
    });
  }
  test('different seeded instances cannot support a placement comparison', async ({ page }) => {
    await boot(page, '?seed=first-review-instance');
    await traceAndAttack(page);
    await page.locator('#seed').fill('second-review-instance');
    await page.locator('#placement-compiled-in').check();
    await expect(page.locator('#build-verdict [data-check]')).toHaveAttribute('data-check', 'pass');
    await expect(page.locator('html')).not.toHaveAttribute('data-busy', '');
    await traceAndAttack(page);
    await expect(page.locator('#compiled-in-comparison')).toHaveAttribute('data-comparison', 'incomparable');
    await expect(page.locator('#compiled-in-comparison')).toContainText('THE RUNS ARE NOT MATCHED');
  });
  test('each input target retires the previous recovery', async ({ page }) => {
    await boot(page, '?seed=target-review');
    await traceAndAttack(page);
    await page.locator('#target-sbox').uncheck();
    await expect(page.locator('#dca-verdict')).toHaveCount(0);
    await page.locator('#target-inverse').check();
    await page.locator('#run-dca').click();
    await expect(page.locator('#dca-verdict')).toBeVisible();
    await expect(page.locator('html')).not.toHaveAttribute('data-busy', '');
    await page.locator('#target-inverse').uncheck();
    await expect(page.locator('#dca-verdict')).toHaveCount(0);
  });
  test('an unseeded sweep retains the seed and controls for the measured run', async ({ page }) => {
    await boot(page);
    await expect(page.locator('#seed')).toHaveValue('');
    await page.locator('#traces').fill('8');
    await page.locator('#sweep').click();
    await expect(page.locator('#sweep-status')).toContainText('Measured all 7 combinations', { timeout: 60_000 });
    await expect(page.locator('html')).not.toHaveAttribute('data-busy', '');
    const seed = await page.locator('#seed').inputValue();
    expect(seed).toMatch(/^sweep-\d+$/);
    await expect(page.locator('#sweep-status')).toContainText(seed);
    await expect(page.locator('input[name="placement"]:checked')).toHaveValue('remote-both');
    await expect(page.locator('input[name="surface"]:checked')).toHaveValue('input');
    await expect(page.locator('#target-sbox')).toBeChecked();
    await expect(page.locator('#target-inverse')).toBeChecked();
  });
});
