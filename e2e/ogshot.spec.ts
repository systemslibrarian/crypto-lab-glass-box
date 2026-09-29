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
  // Frame the CLIMAX: the verdict line and the sixteen recovered byte cells
  // under it. A link preview gets one glance, and the one thing worth showing
  // in it is that the key came back out of a program that does not contain it.
  //
  // The two sticky bars are un-stuck for the shot only. They belong on the page
  // and would sit across the top of the picture; nothing else is changed, so
  // what the card shows is still a real run of this lab.
  //
  // The zoom is the one liberty taken, and it takes nothing away: at 1200 x 630
  // the verdict, its figures and the strip stand 735 px tall, so the card is
  // rendered as if the window were wider and photographed at 1200. Every pixel
  // in the file is still this run; none of it is hidden to make it fit.
  await page.addStyleTag({
    content: '.cl-topbar, #app .act-nav { position: static !important; } #app { zoom: 0.84; }',
  });
  await page.locator('#dca-verdict').scrollIntoViewIfNeeded();
  await page.evaluate(() => {
    const top = document.querySelector('#dca-verdict');
    const bottom = document.querySelector('#byte-strip');
    if (!top || !bottom) throw new Error('the card frames #dca-verdict through #byte-strip');
    // Centre the pair in the viewport rather than pinning the top of it, so a
    // row growing or shrinking moves the crop instead of cutting the strip off.
    const a = top.getBoundingClientRect();
    const b = bottom.getBoundingClientRect();
    window.scrollBy(0, a.top - (window.innerHeight - (b.bottom - a.top)) / 2);
  });
  // Both ends have to be INSIDE the frame; a card that crops the key strip is
  // worse than no card, and a silent crop is exactly what a screenshot hides.
  for (const sel of ['#dca-verdict', '#byte-strip']) {
    const box = await page.locator(sel).boundingBox();
    expect(box, sel).not.toBeNull();
    expect(box!.y, `${sel} top is above the frame`).toBeGreaterThanOrEqual(0);
    expect(box!.y + box!.height, `${sel} bottom is below the frame`).toBeLessThanOrEqual(630);
  }
  // A full-viewport shot, so the file really is the 1200 x 630 the metadata
  // declares rather than whatever an element happened to measure.
  await page.screenshot({ path: 'public/og-image.png' });
  const size = await page.evaluate(() => ({ w: window.innerWidth, h: window.innerHeight }));
  expect(size).toEqual({ w: 1200, h: 630 });
});
