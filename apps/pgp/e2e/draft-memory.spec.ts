import type { Page } from "@playwright/test";

import { expect, readStorage, test } from "./fixtures";
import { scanJsHeap } from "./heap";
import { strongRetainers } from "./heap-retainers";
import {
  lockMasterViaPalette,
  seedVault,
  setWorkspaceMode,
  unlockWithPassword,
} from "./helpers";
import { scanWasmMemory } from "./wasm-memory";

// The workspace draft (lib/workspace-draft.ts + App.tsx's doMasterLock)
// keeps the user's in-progress message across an auto-lock. Its whole
// reason to exist as an encrypted blob rather than plain App state is the
// claim in App.tsx: "The plaintext draft never survives the lock event in
// the JS heap." Only the ciphertext, encrypted under a separate in-WASM
// draft key, is supposed to be left behind.
//
// A canary goes into the workspace and the vault is master-locked in-app
// via `doMasterLock` (a reload would not exercise the draft path at all).
// The first test checks the parts of that claim that hold: the ciphertext
// path itself, WASM, and storage. The second checks the JS heap -- and
// currently fails, which is the point of it.

const MASTER = "correct horse battery staple";
/** Unique, newline-free, and not a literal anywhere in the bundle. */
const CANARY = "DRAFT-CANARY-4c8e02f5-do-not-leak";
const MESSAGE = `half-written note ${CANARY} finish this later`;
/** Present on every screen incl. the master lock screen (AppFooter). */
const HEAP_CONTROL = "A privacy tool by";
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

// ── known defect: expected to fail ───────────────────────────────────
// Marked test.fail() rather than deleted or weakened, so the suite reports
// it the moment it starts passing (an unexpected pass fails the run).
//
// `doMasterLock` encrypts the draft and unmounts the workspace, but
// nothing blanks the input first, so the plaintext outlives the lock. The
// retainer chain, printed by the assertion below and reproduced here:
//
//   (GC roots) → C++ Persistent roots
//     → autofill::FormTracker  [native] <textarea id="pgp-input">
//       → property[get value]  [closure]
//         → context[n]         [string] "half-written note DRAFT-CANARY…"
//
// Two things combine. React installs its own `value` getter/setter on
// controlled inputs (inputValueTracking) whose closure captures the last
// value it saw -- that `context[n]` slot IS the user's plaintext. And
// Chromium's autofill FormTracker holds a C++ *Persistent* handle to the
// last-interacted form control, so unmounting the textarea does not free
// it: the node, the tracker closure, and the plaintext all stay reachable
// from a GC root. Verified durable -- it survives 6 forced GCs over 10s
// with heavy string churn.
//
// ImportKeyPage already solves exactly this for pasted key armor,
// deliberately and with a comment: `resetAndClose` sets
// `textareaRef.current.value = ""` before the panel slides out (assigning
// through React's patched setter is what replaces the captured value). The
// workspace needs the same at lock time: once the draft ciphertext is
// stashed, clear input/output in state AND blank the textarea's DOM value
// before flipping `masterUnlocked`. Nothing is lost -- rehydration comes
// from the ciphertext.
test("the draft plaintext does not survive a master lock in the JS heap", async ({
  panel,
}) => {
  test.fail();
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
