import { expect, test } from '@playwright/test';

/**
 * Renders the share card from the LIVE page rather than from a mock-up, so the
 * picture a link preview shows is a real run of this lab and cannot drift away
 * from what the page does.
 */
test('compose the social preview', async ({ page }) => {
  page.setDefaultTimeout(180_000);
  await page.setViewportSize({ width: 1200, height: 630 });
  await page.goto('.');
  await expect(page.locator('#build-status')).toContainText('Program #1');
  await page.fill('#traces', '512');
  await page.locator('#trace').click();
  await expect(page.locator('#trace-status')).toContainText('Run #1');
  await page.locator('#target-inverse').check();
  await page.locator('#run-dca').click();
  await expect(page.locator('#dca-status')).toContainText('Attack #1');
  // Frame BOTH halves of the mechanism: the 256 candidates competing on the
  // left, and the traces those candidates were scored against on the right.
  //
  // The two sticky bars are un-stuck for the shot only. They belong on the page
  // and would sit across the top of the picture; nothing else is changed, so
  // what the card shows is still a real run of this lab.
  await page.addStyleTag({ content: '.cl-topbar, #app .act-nav { position: static !important; }' });
  await page.locator('#dca-inspect .two-up').scrollIntoViewIfNeeded();
  await page.evaluate(() => {
    const target = document.querySelector('#dca-inspect .two-up');
    if (!target) return;
    const box = target.getBoundingClientRect();
    window.scrollBy(0, box.top - Math.max(0, (window.innerHeight - box.height) / 2));
  });
  // A full-viewport shot, so the file really is the 1200 x 630 the metadata
  // declares rather than whatever an element happened to measure.
  await page.screenshot({ path: 'public/og-image.png' });
  const size = await page.evaluate(() => ({ w: window.innerWidth, h: window.innerHeight }));
  expect(size).toEqual({ w: 1200, h: 630 });
});
