import { defineConfig } from "@playwright/test";

/**
 * E2E config for driving the built extension in a real Chromium.
 *
 * The tests load the unpacked MV3 build from `.output/chrome-mv3`, so run
 * `pnpm build` (or at least `wxt build`) first. They run headless via
 * Chromium's new headless mode (which loads extensions); set `HEADED=1`
 * to watch a real window.
 *
 * State (chrome.storage) persists within a single test file's context, so
 * tests run serially with one worker to keep ordering deterministic.
 */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [["list"]],
  timeout: 60_000,
  expect: { timeout: 10_000 },
  use: {
    actionTimeout: 15_000,
    trace: "retain-on-failure",
  },
});
