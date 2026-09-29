import { defineConfig, devices } from '@playwright/test';

/**
 * Everything runs against the PRODUCTION build served by `vite preview`, so what
 * passes here is what ships.
 *
 * PORT 4685 is unique to this lab in committed state across the 212 sibling
 * repos. Never the Vite default 4173: with this many labs side by side, a shared
 * port plus `reuseExistingServer` means a run can silently scan a DIFFERENT
 * lab's preview, which has really happened in this fleet.
 *
 * A note on how it was checked, because the obvious survey is wrong. Grepping
 * the siblings for `localhost:[0-9]+` misses every config that builds its URL
 * from a `PORT` constant -- which is most of the recent ones, including this
 * file. That survey reported 4646 free; it is not, `crypto-lab-harvest-timeline`
 * has it. The survey that found the clash matches `localhost:`, `PORT =` and
 * `port` alike, over committed AND working-tree copies, and it puts 182 ports in
 * use across the fleet rather than the 97 the narrow form found.
 */
const PORT = 4685;
const BASE = `http://localhost:${PORT}/crypto-lab-glass-box/`;

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  /**
   * Generous, and measured rather than guessed. The a11y drive builds several
   * white-box programs (2,032 tables each), traces hundreds of encryptions and
   * scores 4,096 key hypotheses, scanning after every state at three viewport
   * widths. The claims suite runs the same pipeline across five encoding
   * placements.
   */
  timeout: 900_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: BASE,
    colorScheme: 'dark', // dark is the only theme
  },
  projects: [
    { name: 'a11y', testMatch: /a11y\.spec\.ts/, use: { ...devices['Desktop Chrome'], colorScheme: 'dark' } },
    { name: 'claims', testMatch: /claims\.spec\.ts/, use: { ...devices['Desktop Chrome'], colorScheme: 'dark' } },
  ],
  webServer: {
    /**
     * Build before serving. `vite preview` only serves whatever is already in
     * `dist/`, so without the build in front a failing compile leaves the
     * previous good bundle in place and the whole suite passes green against
     * source that no longer compiles -- which silently invalidates every
     * mutation check, the only thing that proves a test has teeth.
     */
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: BASE,
    /**
     * Deliberately NOT `!process.env.CI`. Reusing a preview server that is
     * already listening means the `npm run build` in front of it never runs, so
     * the suite tests whatever is already in `dist/` -- a stale bundle, silently.
     * A stray server now produces a loud "port in use" instead.
     */
    reuseExistingServer: false,
    timeout: 240_000,
  },
});
