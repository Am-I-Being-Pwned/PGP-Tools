import { defineConfig } from "@playwright/test";

/**
 * Config for the store-listing screenshot tooling in `e2e-capture/`.
 *
 * Separate from `playwright.config.ts` on purpose: that one's `testDir` is
 * `./e2e`, so `pnpm test:e2e` and CI never see these, and the e2e test
 * count in the README stays a count of tests rather than of tests plus
 * artwork jobs. Run by hand when the UI changes:
 *
 *     npx playwright test --config=playwright.capture.config.ts
 *
 * Then re-render the tiles in `assets/store-listing/promo`.
 */
export default defineConfig({
  testDir: "./e2e-capture",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  timeout: 180_000,
  expect: { timeout: 15_000 },
  use: { actionTimeout: 20_000 },
});
