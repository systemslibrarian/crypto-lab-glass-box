import { defineConfig, configDefaults } from 'vitest/config';

// base must match the GitHub Pages project subpath:
// https://systemslibrarian.github.io/crypto-lab-glass-box/
export default defineConfig({
  base: '/crypto-lab-glass-box/',
  worker: {
    // The lab's heavy work -- building 2,032 lookup tables, tracing hundreds of
    // encryptions and scoring 4,096 key hypotheses -- runs in a module worker.
    // `es` keeps the worker an ES module in the production bundle too, so the
    // `import` graph the unit tests exercise is the one that ships.
    format: 'es',
  },
  test: {
    // Colocated unit tests only; keep the Playwright specs in e2e/ out of the
    // Vitest run so they are not collected as unit tests.
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
  },
});
