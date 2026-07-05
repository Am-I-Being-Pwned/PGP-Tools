import { expect, test } from "./fixtures";
import { onboardWithPassword, unlockWithPassword } from "./helpers";
import { scanWasmMemory } from "./wasm-memory";

// Reads the extension's live WASM linear memory (via CDP, against the
// production build) and checks that a distinctive master password does
// not linger there. The password is copied into WASM as the Argon2 input
// on every unlock; its absence afterwards is a real, in-browser check of
// the zeroize-on-free allocator. (The JS-heap copy is out of scope -- this
// asserts about WASM memory only.)

const SENTINEL = "ZEROIZE-ME-master-passw0rd-sentinel-do-not-leak";

test("the master password does not linger in WASM memory", async ({
  panel,
}) => {
  await onboardWithPassword(panel, SENTINEL);
  // Lock (reload drops the in-page session) and unlock, running the
  // password through Argon2 again.
  await panel.reload();
  await unlockWithPassword(panel, SENTINEL);

  const counts = await scanWasmMemory(panel, [SENTINEL, "gpg-wasm ok"]);

  // Control: a static wasm string proves we're scanning live wasm memory.
  expect(counts["gpg-wasm ok"]).toBeGreaterThan(0);
  // The real assertion.
  expect(
    counts[SENTINEL],
    "master password must not remain in WASM memory after unlock",
  ).toBe(0);
});
