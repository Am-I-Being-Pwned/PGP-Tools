import { defineConfig } from "vitest/config";

// Unit tests cover the pure logic in lib/ and components/ (no DOM, no
// chrome.* APIs, no WASM). Anything that needs the WASM engine is
// covered by the Rust tests in gpg-wasm/src/tests.rs instead.
export default defineConfig({
  test: {
    environment: "node",
    include: ["**/*.test.ts"],
    exclude: ["node_modules/**", ".output/**", ".wxt/**", "gpg-wasm/**"],
  },
});
