import type { Page } from "@playwright/test";

import { expect, readStorage, test } from "./fixtures";
import { scanJsHeap } from "./heap";
import { strongRetainers } from "./heap-retainers";
import {
  decryptInWorkspace,
  encryptToSelfInWorkspace,
  lockMasterViaPalette,
  seedVault,
  setWorkspaceMode,
  unlockWithPassword,
} from "./helpers";
import { scanWasmMemory } from "./wasm-memory";

// The workspace draft (lib/workspace-draft.ts + App.tsx's doMasterLock)
// keeps the user's in-progress message across an auto-lock. Its whole
// reason to exist as an encrypted blob rather than plain App state is that
// the plaintext draft must not survive the lock event in the JS heap. Only
// the ciphertext, encrypted under a separate in-WASM draft key, is supposed
// to be left behind.
//
// A canary goes into the workspace and the vault is master-locked in-app
// via `doMasterLock` (a reload would not exercise the draft path at all).
// The first test covers the ciphertext path, WASM, and storage. The second
// covers the JS heap: it used to fail (see SECURITY.md §8.11), and passes
// now that the composer input is uncontrolled -- the plaintext lives in a
// ref and the DOM node, never in React render state, so `wipe()` at lock
// time actually releases it. React double-buffers hook state onto
// `fiber.alternate` and keeps effect closures reachable from a GC root long
// after unmount, which is why a controlled `value={input}` could not be
// fixed by clearing the DOM alone.

// Tracing MUST be off for this file. Playwright's snapshot cache attaches a
// `__playwright_snapshot_cache_` symbol to DOM nodes holding cached
// serialised values -- including a textarea's text. That makes the HARNESS a
// live retainer of the canary and fails the heap assertion for a reason that
// has nothing to do with the app. This spec is uniquely exposed because its
// canary IS an input's value; the other heap specs are unaffected. Verified
// both ways: with tracing on the only retainer left is Playwright's cache,
// with it off the count is 0. Do not "fix" a red here by relaxing the
// assertion -- check the retainer chain first.
test.use({ trace: "off" });

const MASTER = "correct horse battery staple";
/** Unique, newline-free, and not a literal anywhere in the bundle. */
const CANARY = "DRAFT-CANARY-4c8e02f5-do-not-leak";
const MESSAGE = `half-written note ${CANARY} finish this later`;
/** Present on every screen incl. the master lock screen (AppFooter). */
const HEAP_CONTROL = "A privacy tool by";
/** Canary for the DECRYPTED-OUTPUT test below. Distinct from CANARY so a
 *  hit can never be confused with the input-draft chain. Kept at offset 0
 *  of the message: V8 truncates each recorded string value to the first
 *  1024 chars, so a needle beyond that returns 0 for the wrong reason. */
const OUTPUT_CANARY = "OUTPUT-CANARY-9b71ad34-do-not-leak";
const SECRET_MESSAGE = `${OUTPUT_CANARY} the decrypted body of a message`;
/** A static string in the wasm data segment (see memory.spec.ts). */
const WASM_CONTROL = "gpg-wasm ok";

/** Type an in-progress message, then master-lock in-app so the draft is
 *  encrypted under the in-WASM draft key and stashed at App level. */
async function draftThenLock(panel: Page): Promise<void> {
  await seedVault(panel, MASTER);
  await setWorkspaceMode(panel, "Encrypt");
  await panel.locator("textarea").first().fill(MESSAGE);
  await expect(panel.locator("textarea").first()).toHaveValue(MESSAGE);
  await lockMasterViaPalette(panel);
}

test("the workspace draft crosses a master lock as ciphertext, in WASM and on disk", async ({
  panel,
}) => {
  await draftThenLock(panel);

  await test.step("the plaintext is gone from WASM linear memory", async () => {
    // encryptDraft copies the plaintext into wasm (`Zeroizing<Vec<u8>>` on
    // entry); the zeroize-on-free allocator has to wipe the marshalled copy.
    const counts = await scanWasmMemory(panel, [CANARY, WASM_CONTROL]);
    expect(
      counts[WASM_CONTROL],
      "control present (scanning live wasm memory)",
    ).toBeGreaterThan(0);
    expect(
      counts[CANARY],
      "draft plaintext must not linger in WASM memory after encryptDraft",
    ).toBe(0);
  });

  await test.step("the draft was never written to storage in cleartext", async () => {
    for (const area of ["local", "sync", "session"] as const) {
      const dump = JSON.stringify(await readStorage(panel, area));
      expect(
        dump.includes(CANARY),
        `draft plaintext must not reach chrome.storage.${area}`,
      ).toBe(false);
    }
  });

  await test.step("unlock rehydrates the draft (so the checks above measured a live secret)", async () => {
    await unlockWithPassword(panel, MASTER);
    await expect(panel.locator("textarea").first()).toHaveValue(MESSAGE, {
      timeout: 15_000,
    });
  });
});

// ── regression guard for a fixed defect ──────────────────────────────
// This test used to fail and was marked test.fail(). It now passes; the
// test.fail() is gone, so a regression fails the run.
//
// The original defect: `doMasterLock` encrypted the draft and unmounted the
// workspace, but the plaintext outlived the lock via this chain --
//
//   (GC roots) → C++ Persistent roots
//     → autofill::FormTracker  [native] <textarea id="pgp-input">
//       → property[get value]  [closure]
//         → context[n]         [string] "half-written note DRAFT-CANARY…"
//
// React installs its own value getter/setter on CONTROLLED inputs
// (inputValueTracking) whose closure captures the last value it saw, and
// Chromium's autofill FormTracker holds a C++ Persistent handle to the
// last-interacted form control, so unmounting did not free it. Durable
// across 6 forced GCs over 10s with heavy string churn.
//
// Blanking the DOM value (as ImportKeyPage's resetAndClose does for pasted
// key armor) removed THAT chain and revealed a second one: React
// double-buffers hook state onto `fiber.alternate` and keeps effect closures
// hanging off it reachable from a GC root, so `value={input}` meant the
// plaintext survived in render state regardless of the DOM.
//
// The actual fix was to stop holding it in render state at all: the composer
// input is now UNCONTROLLED (ref + DOM node only, like ImportKeyPage's paste
// box), and doMasterLock pulls the draft via `WorkspaceDraftSource.getDraft`
// then calls `wipe()` -- clearing the ref, the DOM value, and the clear-undo
// buffer -- before flipping masterUnlocked. See SECURITY.md §8.11.
//
// NOTE: this test asserts only on the INPUT draft. Decrypted output is
// covered separately, by the test below.
test("the draft plaintext does not survive a master lock in the JS heap", async ({
  panel,
}) => {
  await draftThenLock(panel);

  const control = await strongRetainers(panel, HEAP_CONTROL);
  expect(control.count, "control retained (analysis works)").toBeGreaterThan(0);
  const hits = await strongRetainers(panel, CANARY);
  expect(
    hits.count,
    `draft plaintext must not be retained by any live JS object after a master lock${hits.report}`,
  ).toBe(0);

  // The plain heap scan -- the same check heap.spec.ts applies to private
  // key material -- must also come back clean.
  const counts = await scanJsHeap(panel, [CANARY, HEAP_CONTROL]);
  expect(counts[HEAP_CONTROL], "control present (scan works)").toBeGreaterThan(
    0,
  );
  expect(
    counts[CANARY],
    "draft plaintext must not appear in a heap snapshot after a master lock",
  ).toBe(0);
});

// ── regression guard for T-OUTPUT-HEAP-RESIDUE ───────────────────────
// The sibling of the test above, for the other half of §8.11. `s.output`
// holds DECRYPTED MESSAGE PLAINTEXT, and it used to be ordinary React
// render state -- so it survived an in-app master lock by exactly the
// mechanism the input draft used to suffer from: React double-buffers hook
// state onto `fiber.alternate` and keeps effect closures hanging off it
// reachable from a GC root long after unmount. Measured count was 1 after a
// real encrypt->decrypt->lock cycle; only a reload cleared it.
//
// The fix mirrors the input: output lives in `outputRef` plus the display
// node's `textContent`, never in render state. Only `hasOutput` (a boolean)
// is derived into state. The result `<pre>` is written imperatively through
// a callback ref rather than as a React child -- rendering `{output}` as
// JSX would put the string straight back into the fiber's element tree --
// and `doMasterLock`'s `wipe()` now clears the output ref and node too.
//
// This does a REAL round trip (encrypt in the app, then decrypt the app's
// own ciphertext) so the canary reaching the heap is genuinely decrypted
// output, not something the test typed straight in. Note the same plaintext
// is also the encrypt-side INPUT earlier in the cycle, so a non-zero count
// could in principle come from either -- the retainer chain in the failure
// report is what tells them apart, and both are supposed to be zero.
//
// Tracing is off for the whole file (see the note at the top); this test
// needs that for the same reason the draft test does.
test("decrypted output does not survive a master lock in the JS heap", async ({
  panel,
}) => {
  await seedVault(panel, MASTER);
  const armored = await encryptToSelfInWorkspace(panel, SECRET_MESSAGE);
  // Asserts the plaintext is on screen, which also proves the uncontrolled
  // `<pre>` really renders (its text is set via textContent, not JSX).
  await decryptInWorkspace(panel, armored, SECRET_MESSAGE);
  await lockMasterViaPalette(panel);

  const control = await strongRetainers(panel, HEAP_CONTROL);
  expect(control.count, "control retained (analysis works)").toBeGreaterThan(0);
  const hits = await strongRetainers(panel, OUTPUT_CANARY);
  expect(
    hits.count,
    `decrypted output must not be retained by any live JS object after a master lock${hits.report}`,
  ).toBe(0);

  const counts = await scanJsHeap(panel, [OUTPUT_CANARY, HEAP_CONTROL]);
  expect(counts[HEAP_CONTROL], "control present (scan works)").toBeGreaterThan(
    0,
  );
  expect(
    counts[OUTPUT_CANARY],
    "decrypted output must not appear in a heap snapshot after a master lock",
  ).toBe(0);
});
