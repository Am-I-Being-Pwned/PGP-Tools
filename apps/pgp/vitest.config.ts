import { defineConfig } from "vitest/config";

// tests/unit mirrors src/: pure logic only (no DOM, no chrome.*, no WASM).
// WASM is covered by the Rust tests, the UI by Playwright (tests/e2e).
export default defineConfig({
  // WXT's `~/` root alias, for the unit tests.
  resolve: { alias: { "~": `${import.meta.dirname}/src` } },
  // The UI kit is one barrel, so a test importing a helper from it also
  // loads its components.
  oxc: { jsx: { runtime: "automatic" } },
  test: {
    environment: "node",
    include: ["tests/unit/**/*.test.ts"],
    // Installs an en-backed `chrome.i18n` so `t()` resolves in node.
    setupFiles: ["tests/unit/lib/i18n/fake-chrome-i18n.ts"],
    // The JSON report is what the README's unit-test badge counts
    // (scripts/update-badges.mjs). `vitest list` can't be used for that:
    // since vitest 5 it prints one unexpanded line per `it.each`. It
    // lives under coverage/ so turbo caches it with the coverage summary.
    reporters: [
      "default",
      ["json", { outputFile: "coverage/test-results.json" }],
    ],
    coverage: {
      provider: "v8",
      // `src/lib/` ONLY, and the badge says "lib coverage" for the same
      // reason. These tests run without a DOM, so widening the
      // denominator to src/components/ and src/entrypoints/ would fold in ~4000
      // statements that vitest was never the tool for -- they are
      // covered by the Playwright suite against the real built
      // extension, and by the Rust tests for anything touching WASM.
      // The resulting number would be a smaller figure describing a
      // larger claim, which is worse than not measuring.
      include: ["src/lib/**"],
      exclude: ["src/lib/**/*.d.ts"],
      reporter: ["text-summary", "json-summary"],
      reportsDirectory: "coverage",
    },
  },
});
