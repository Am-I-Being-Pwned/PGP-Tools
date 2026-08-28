import { defineConfig } from "vitest/config";

// Unit tests cover the pure logic in lib/ and components/ (no DOM, no
// chrome.* APIs, no WASM). Anything that needs the WASM engine is
// covered by the Rust tests in gpg-wasm/src/tests.rs instead.
export default defineConfig({
  test: {
    environment: "node",
    include: ["**/*.test.ts"],
    exclude: ["node_modules/**", ".output/**", ".wxt/**", "gpg-wasm/**"],
    coverage: {
      provider: "v8",
      // `lib/` ONLY, and the badge says "lib coverage" for the same
      // reason. These tests run without a DOM, so widening the
      // denominator to components/ and entrypoints/ would fold in ~4000
      // statements that vitest was never the tool for -- they are
      // covered by the Playwright suite against the real built
      // extension, and by the Rust tests for anything touching WASM.
      // The resulting number would be a smaller figure describing a
      // larger claim, which is worse than not measuring.
      include: ["lib/**"],
      // `fake-*.ts` are TEST DOUBLES (a chrome.storage area, the wasm
      // sealing primitives). They are imported only from `*.test.ts` and
      // tree-shaken out of the extension bundle, so measuring how much
      // of a stub the tests exercise would only pad the denominator with
      // code that never ships.
      exclude: ["lib/**/*.test.ts", "lib/**/*.d.ts", "lib/**/fake-*.ts"],
      reporter: ["text-summary", "json-summary"],
      reportsDirectory: "coverage",
    },
  },
});
