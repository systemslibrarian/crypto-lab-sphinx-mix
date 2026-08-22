import { defineConfig, configDefaults } from 'vitest/config';

// base must match the GitHub Pages project subpath:
// https://systemslibrarian.github.io/crypto-lab-sphinx-mix/
export default defineConfig({
  base: '/crypto-lab-sphinx-mix/',
  test: {
    // Colocated unit tests only; the Playwright specs in e2e/ are not Vitest.
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
    // Vitest's 5s default is not enough for the traffic suite, and raising it
    // is the honest fix rather than shrinking the fixtures: one run there
    // builds and routes up to 128 REAL Sphinx packets, which is hundreds of
    // ristretto255 scalar multiplications, and `runTraffic` additionally
    // yields to the event loop so the browser can paint mid-build. Nothing is
    // skipped or sampled to fit a clock.
    testTimeout: 120_000,
  },
});
