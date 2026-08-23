import { readFile } from "node:fs/promises";
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

// ── binary + multi-file decrypted results ────────────────────────────
//
// Everything above measures STRINGS. The two tests below measure BYTES,
// because the remaining half of a decrypt result never becomes a string:
//
//   - `binaryOutput` (a `Uint8Array`) -- a decrypted payload that isn't
//     valid UTF-8, or a decrypted zip archive.
//   - `fileResults` (`{ name, data: Uint8Array }[]`) -- one entry per file
//     when several encrypted files are decrypted in one go.
//
// Unlike the input and the text output, these two CANNOT be moved out of
// React render state: the results card renders a row per file, so the
// values have to be renderable. That leaves them exposed to exactly the
// retainer chain §8.11 describes for the text output --
// `fiber.alternate -> updateQueue.lastEffect.create -> ... ->
// lastRenderedState` -- which unmounting does not release. `resetOutput()`
// would clear them the ordinary way, but it is not called at lock, and
// calling it there would not help: `doMasterLock` flips `masterUnlocked`
// in the same synchronous run, so the `setState` is batched with the
// unmount and never commits.
//
// The fix is therefore a WIPE, not a drop: `wipePlaintext` (which
// `doMasterLock` already calls) zeroes the buffers in place via
// `zeroizeResultBytes`, so it does not matter who is still holding them.
//
// WHY A NEW SCANNER. `heap.ts` / `heap-retainers.ts` search a heap
// snapshot's string table, and V8 records only string VALUES there -- a
// typed array appears as a node with a size and no contents. A snapshot
// search for these canaries returns 0 whether or not the bytes are live,
// i.e. it would pass vacuously. `liveByteArrays` below asks the question
// that can actually be answered for bytes: CDP `Runtime.queryObjects`
// (the same primitive `wasm-memory.ts` uses) collects garbage and hands
// back every LIVE `Uint8Array`, and we scan those. Each test takes the
// same measurement BEFORE the lock as a positive control, so a green run
// always proves the scanner can see this canary.

/** Canary bytes for the binary-output branch. */
const BINARY_CANARY = "BINARY-CANARY-6d81f0a2-do-not-leak";
/** Canaries for the two files of the multi-file branch. */
const FILE_CANARY_A = "FILEA-CANARY-13c7be95-do-not-leak";
const FILE_CANARY_B = "FILEB-CANARY-a0e4d268-do-not-leak";

/** Content for a file whose DECRYPTED form must take the binary branch:
 *  the trailing bytes are not valid UTF-8, so `executeDecrypt`'s
 *  `TextDecoder(..., { fatal: true })` throws and the result lands in
 *  `binaryOutput` instead of the (already-covered) text output. The
 *  canary sits at offset 0 and the leading bytes are not `PK`, so the
 *  zip-archive branch doesn't claim it either. */
function binaryPayload(canary: string): Buffer {
  return Buffer.concat([
    Buffer.from(canary, "ascii"),
    Buffer.from([0xff, 0xfe, 0x80, 0x00, 0xc0]),
  ]);
}

/**
 * How many LIVE objects still hold `needle`'s bytes in a `Uint8Array`,
 * plus a printable summary for the assertion message.
 *
 * WHY NOT `Uint8Array.prototype`. The obvious shape -- CDP
 * `Runtime.queryObjects` over `Uint8Array.prototype`, the way
 * `wasm-memory.ts` queries `WebAssembly.Memory.prototype` -- returns an
 * EMPTY array: V8's queryObjects filter skips typed arrays and array
 * buffers entirely (verified against a blank page: `Object.prototype`
 * returned 1104 objects, `Uint8Array.prototype` and
 * `ArrayBuffer.prototype` returned 0). A scan built on it would report 0
 * hits forever -- the vacuous green this whole file exists to avoid.
 *
 * So we query the plain objects instead and look at what they POINT AT.
 * That is the right question anyway, because the retainers in question
 * are plain object literals:
 *
 *   - React's hook records (`{ memoizedState, baseState, queue, ... }`)
 *     and their update queues (`{ lastRenderedState, ... }`) -- the
 *     `fiber.alternate` chain of T-OUTPUT-HEAP-RESIDUE. `binaryOutput`
 *     hangs directly off these.
 *   - each `FileResult` (`{ name, data }`) of `fileResults`.
 *
 * One level of array indirection is followed (`fileResults` is an array
 * of views held in a property) but no deeper: the point is to name the
 * retainers this change is about, not to write a general heap walker.
 *
 * WASM linear memory is excluded on purpose. wasm-bindgen keeps cached
 * views over the whole wasm heap alive for the life of the module, so
 * without this the scan would also be measuring wasm -- a different
 * property, owned by a different mechanism (Rust's zeroize-on-free) and
 * already asserted by `scanWasmMemory` in the first test of this file.
 * Mixing them in would make a JS-retention regression indistinguishable
 * from a wasm-zeroization one.
 */
async function liveByteArrays(
  page: Page,
  needle: string,
): Promise<{ count: number; report: string }> {
  const client = await page.context().newCDPSession(page);
  await client.send("Runtime.enable");
  await client.send("HeapProfiler.enable");
  // queryObjects collects garbage itself before answering, so only live
  // objects come back; this makes that explicit and matches what
  // `scanJsHeap` does before its snapshot.
  await client.send("HeapProfiler.collectGarbage");

  const instancesOf = async (expression: string) => {
    const proto = await client.send("Runtime.evaluate", { expression });
    const protoId = proto.result.objectId;
    if (!protoId) throw new Error(`could not resolve ${expression}`);
    const objects = await client.send("Runtime.queryObjects", {
      prototypeObjectId: protoId,
    });
    return objects.objects.objectId;
  };

  const objectsId = await instancesOf("Object.prototype");
  if (!objectsId) throw new Error("no plain objects found");
  // May legitimately be absent if wasm hasn't been instantiated yet.
  const memoriesId = await instancesOf("WebAssembly.Memory.prototype");

  // `this` is every live plain object; `memories` every live
  // WebAssembly.Memory (whose buffers are skipped -- see above).
  const scanFn = `function (needle, memories) {
    const wasmBuffers = new Set();
    for (const m of memories ?? []) {
      try { wasmBuffers.add(m.buffer); } catch (e) { /* ignore */ }
    }
    const bytes = [];
    for (let i = 0; i < needle.length; i++) bytes.push(needle.charCodeAt(i));
    const offsetIn = (a) => {
      const len = a.length;
      for (let i = 0; i + bytes.length <= len; i++) {
        if (a[i] !== bytes[0]) continue;
        let match = true;
        for (let j = 1; j < bytes.length; j++) {
          if (a[i + j] !== bytes[j]) { match = false; break; }
        }
        if (match) return i;
      }
      return -1;
    };
    const hits = [];
    for (const o of this) {
      let keys;
      // Own properties only, and only DATA properties: invoking a getter
      // during a heap sweep could both throw and have side effects.
      try { keys = Object.getOwnPropertyNames(o); } catch (e) { continue; }
      for (const k of keys) {
        let d;
        try { d = Object.getOwnPropertyDescriptor(o, k); } catch (e) { continue; }
        if (!d || !("value" in d)) continue;
        const v = d.value;
        const views = v instanceof Uint8Array
          ? [v]
          : (Array.isArray(v) ? v.filter((x) => x instanceof Uint8Array) : []);
        for (const a of views) {
          let at;
          try {
            if (wasmBuffers.has(a.buffer)) continue;
            at = offsetIn(a);
          } catch (e) { continue; }
          if (at === -1) continue;
          let preview = "";
          const end = Math.min(a.length, at + bytes.length + 16);
          for (let n = at; n < end; n++) preview += String.fromCharCode(a[n]);
          hits.push({ via: k, length: a.length, offset: at, preview: preview });
        }
      }
    }
    return hits;
  }`;

  const res = await client.send("Runtime.callFunctionOn", {
    objectId: objectsId,
    functionDeclaration: scanFn,
    arguments: [
      { value: needle },
      ...(memoriesId ? [{ objectId: memoriesId }] : []),
    ],
    returnByValue: true,
  });
  await client.send("HeapProfiler.disable");

  const hits = res.result.value as {
    via: string;
    length: number;
    offset: number;
    preview: string;
  }[];
  const report = hits
    .map(
      (h) =>
        `\n  live object property ${JSON.stringify(h.via)} -> Uint8Array(${h.length}) @${h.offset}: ${JSON.stringify(h.preview)}`,
    )
    .join("");
  return { count: hits.length, report };
}

/** Stage files on the workspace drop zone. The hidden input with no
 *  `accept` list is the workspace one (see crx-memory.spec.ts). */
async function stageWorkspaceFiles(
  panel: Page,
  files: { name: string; mimeType: string; buffer: Buffer }[],
): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel
    .locator('input[type="file"]:not([accept])')
    .first()
    .setInputFiles(files);
}

/** Clear input, files and results between operations. */
async function clearWorkspace(panel: Page): Promise<void> {
  await panel.getByRole("button", { name: "Clear input and output" }).click();
}

/** Encrypt a FILE to the already-selected recipient and return the
 *  ciphertext bytes the app produced. File input + `armor: false` means
 *  the ciphertext is binary, which is what makes the decrypt of it come
 *  back as bytes rather than text. */
async function encryptFileToSelf(
  panel: Page,
  name: string,
  content: Buffer,
): Promise<Buffer> {
  await stageWorkspaceFiles(panel, [
    { name, mimeType: "application/octet-stream", buffer: content },
  ]);
  await panel.getByRole("button", { name: /^encrypt$/i }).click();
  const download = panel.getByRole("button", { name: "Download" });
  await expect(download).toBeVisible({ timeout: 15_000 });
  const downloadEvent = panel.waitForEvent("download");
  await download.click();
  const file = await downloadEvent;
  const path = await file.path();
  const bytes = await readFile(path);
  await clearWorkspace(panel);
  return bytes;
}

/** Onboard, pick the single own key as recipient, and leave the
 *  workspace in encrypt mode ready to take files. */
async function seedAndSelectSelf(panel: Page): Promise<void> {
  await seedVault(panel, MASTER);
  await setWorkspaceMode(panel, "Encrypt");
  // The recipient box starts empty by design; the only option is the key
  // onboarding generated. The selection survives "Clear input and
  // output", so this is done once per test.
  await panel.getByRole("combobox", { name: "Recipients" }).click();
  await panel.getByRole("option").first().click();
  await expect(
    panel.getByRole("button", { name: /^Remove / }).first(),
  ).toBeVisible();
}

// ── regression guard: the binary half of T-OUTPUT-HEAP-RESIDUE ───────
//
// `wipePlaintext` cleared four refs and two DOM nodes and stopped there,
// so a decrypt that produced BINARY output kept its plaintext bytes in
// `binaryOutput` across a master lock. Verified by removing the wipe: this
// test then reports 8 live retainers of the decrypted bytes, named
// `binaryOutput` (the hook's returned state object), `memoizedState`,
// `baseState` and `lastRenderedState` -- React's hook record and its
// update queue, i.e. exactly the `fiber.alternate` chain of §8.11. The text output had been moved to a
// ref and was covered by the test above; this branch was not, and the age
// work routes decrypts through it (`executeDecryptAge` sets
// `setBinaryOutput`), so it is not a corner case.
test("decrypted binary output does not survive a master lock in the JS heap", async ({
  panel,
}) => {
  await seedAndSelectSelf(panel);

  // A real round trip through the app: encrypt a file whose plaintext is
  // not valid UTF-8, then decrypt the app's own ciphertext, so the bytes
  // that reach `binaryOutput` are genuinely decrypted output.
  const ciphertext = await encryptFileToSelf(
    panel,
    "secret.bin",
    binaryPayload(BINARY_CANARY),
  );
  await stageWorkspaceFiles(panel, [
    {
      name: "secret.bin.gpg",
      mimeType: "application/octet-stream",
      buffer: ciphertext,
    },
  ]);
  // A dropped .gpg auto-selects decrypt.
  await panel.getByRole("button", { name: /^decrypt$/i }).click();
  // Binary results are never shown as text; the Download affordance
  // appearing is what says the payload landed in `binaryOutput`.
  await expect(panel.getByRole("button", { name: "Download" })).toBeVisible({
    timeout: 15_000,
  });

  // Positive control, and the reason this test cannot pass vacuously: the
  // same scan must SEE the canary while the result is on screen.
  const before = await liveByteArrays(panel, BINARY_CANARY);
  expect(
    before.count,
    "control: the decrypted bytes must be visible to the scanner before the lock",
  ).toBeGreaterThan(0);

  await lockMasterViaPalette(panel);

  const after = await liveByteArrays(panel, BINARY_CANARY);
  expect(
    after.count,
    `decrypted binary output must not be readable from any live Uint8Array after a master lock${after.report}`,
  ).toBe(0);
});

// ── regression guard: the multi-file half of T-OUTPUT-HEAP-RESIDUE ───
//
// Same defect, other state slot: decrypting several files at once fills
// `fileResults` with one `{ name, data }` per file and `wipePlaintext`
// never touched it. Verified the same way: without the wipe this test
// reports the decrypted bytes still readable through a live FileResult's
// `data` property, per file. Two files rather than one on purpose -- a single file
// takes the branch above, and the loop that builds `fileResults` is what
// this covers.
test("decrypted multi-file results do not survive a master lock in the JS heap", async ({
  panel,
}) => {
  await seedAndSelectSelf(panel);

  const ctA = await encryptFileToSelf(
    panel,
    "first.bin",
    binaryPayload(FILE_CANARY_A),
  );
  const ctB = await encryptFileToSelf(
    panel,
    "second.bin",
    binaryPayload(FILE_CANARY_B),
  );

  await stageWorkspaceFiles(panel, [
    {
      name: "first.bin.gpg",
      mimeType: "application/octet-stream",
      buffer: ctA,
    },
    {
      name: "second.bin.gpg",
      mimeType: "application/octet-stream",
      buffer: ctB,
    },
  ]);
  await panel.getByRole("button", { name: /^decrypt$/i }).click();
  // The multi-file branch is the only one that reports a file count.
  await expect(panel.getByText(/2 files decrypted/)).toBeVisible({
    timeout: 15_000,
  });

  for (const canary of [FILE_CANARY_A, FILE_CANARY_B]) {
    const before = await liveByteArrays(panel, canary);
    expect(
      before.count,
      `control: ${canary} must be visible to the scanner before the lock`,
    ).toBeGreaterThan(0);
  }

  await lockMasterViaPalette(panel);

  for (const canary of [FILE_CANARY_A, FILE_CANARY_B]) {
    const after = await liveByteArrays(panel, canary);
    expect(
      after.count,
      `decrypted file contents must not be readable from any live Uint8Array after a master lock (${canary})${after.report}`,
    ).toBe(0);
  }
});

// ── regression guard: the CONTEXT-MENU PENDING OP half of §8.11 ──────
//
// Third state slot of the same defect class. `openPanelWithOperation`
// (background) writes the user's raw selection to
// `chrome.storage.session` under `SESSION_PENDING_OP`;
// `usePendingOperation` consumed it unconditionally on mount and moved
// it into REACT STATE in `App` -- the whole object, `text` included, and
// `text` is the plaintext the user is about to encrypt.
//
// THE CASE THAT ACTUALLY LEAKED is the one where nothing can consume it:
// the panel showing the master-unlock screen. `WorkspaceView` is not
// mounted then, so the op sat in `App`'s hook state for the entire
// locked window -- measured as one live retainer,
//
//   property[lastRenderedState] → property[text]
//     → string:"PENDING-CANARY-… selection to encrypt"
//
// i.e. this hook's own update queue, the `fiber.alternate` chain of
// T-OUTPUT-HEAP-RESIDUE. `doMasterLock` removed the STORAGE copy ("Wipe
// any unconsumed context-menu pending op") and nothing released this one.
//
// TWO FIXES, both exercised below. (1) The hook no longer consumes until
// `App` is rendering a tree that can route the op, so the payload waits
// in session storage -- where T-PENDING-OP-AT-REST already accounts for
// it, bounded by `PENDING_OP_TTL_MS` and `sweepStalePendingOp` -- instead
// of in the heap. (2) `doMasterLock` calls `clearPending()` next to its
// existing `storage.session.remove`, for a selection that arrived while
// unlocked and had not been routed when the lock landed. Dropping the
// reference is enough for (2): unlike `binaryOutput`/`fileResults` below,
// this state belongs to `App`, which stays mounted and re-renders into
// the lock screen, so the `null` commits and overwrites the retained
// value.
//
// WHICH SCANNER, and why. A pending op's payload is a STRING, so the
// string-table tools (`strongRetainers` / `scanJsHeap`) are the right
// ones -- `liveByteArrays` above exists only because V8 records no
// contents for typed arrays, which is not this canary's problem. The
// scanner's positive control here is the post-unlock measurement: the
// same needle, the same call, MUST come back non-zero once the op is
// routed, so the locked-window zero cannot be a scanner that sees
// nothing.
const PENDING_CANARY = "PENDING-CANARY-7f2a91c4-do-not-leak";
const PENDING_TEXT = `${PENDING_CANARY} selection to encrypt`;

/** Simulate the background's context-menu write. The panel and the
 *  worker share `chrome.storage.session`, so writing it from the panel
 *  realm drives `usePendingOperation`'s `onChanged` listener down exactly
 *  the path `openPanelWithOperation` does. */
async function deliverPendingOp(panel: Page, text: string): Promise<void> {
  await panel.evaluate(
    ([key, value]) =>
      chrome.storage.session.set({
        [key]: {
          type: "PENDING_OPERATION",
          id: "e2e-pending-op",
          action: "encrypt",
          text: value,
          sourceTabId: 1,
          createdAt: Date.now(),
        },
      }),
    ["pgp_pending_operation", text] as const,
  );
}

test("a context-menu selection is not held in the JS heap while the vault is locked", async ({
  panel,
}) => {
  await seedVault(panel, MASTER);
  await lockMasterViaPalette(panel);

  // The context menu fires against the locked panel. Nothing on screen
  // can route this.
  await deliverPendingOp(panel, PENDING_TEXT);
  // Long enough to cover the hook's mount read AND its 400ms defensive
  // re-poll, so a zero below is not just "we measured too early".
  await panel.waitForTimeout(1_500);

  const whileLocked = await strongRetainers(panel, PENDING_CANARY);
  expect(
    whileLocked.count,
    `a selection delivered while locked must stay in session storage, not in App state${whileLocked.report}`,
  ).toBe(0);

  // ...and it is DEFERRED, not destroyed: still in session storage (the
  // exposure T-PENDING-OP-AT-REST accepts and bounds), and applied the
  // moment the panel can act on it.
  const stored = JSON.stringify(await readStorage(panel, "session"));
  expect(
    stored.includes(PENDING_CANARY),
    "the deferred op must still be in session storage for the unlock to consume",
  ).toBe(true);

  await unlockWithPassword(panel, MASTER);
  await expect(panel.locator("textarea").first()).toHaveValue(PENDING_TEXT, {
    timeout: 15_000,
  });

  // POSITIVE CONTROL for the assertion above: same needle, same scanner,
  // at the one moment the selection IS expected to be live. Without this
  // the locked-window zero could mean "delivery never happened" or "this
  // scanner cannot see strings".
  const whileRouted = await strongRetainers(panel, PENDING_CANARY);
  expect(
    whileRouted.count,
    "control: the routed selection must be visible to the scanner",
  ).toBeGreaterThan(0);

  // And the second half: an in-app lock releases every copy again --
  // App's pending state (`clearPending()` in `doMasterLock`), the
  // storage entry, and the composer draft it was routed into.
  await lockMasterViaPalette(panel);

  const control = await strongRetainers(panel, HEAP_CONTROL);
  expect(control.count, "control retained (analysis works)").toBeGreaterThan(0);
  const hits = await strongRetainers(panel, PENDING_CANARY);
  expect(
    hits.count,
    `a context-menu selection must not be retained by any live JS object after a master lock${hits.report}`,
  ).toBe(0);

  const counts = await scanJsHeap(panel, [PENDING_CANARY, HEAP_CONTROL]);
  expect(counts[HEAP_CONTROL], "control present (scan works)").toBeGreaterThan(
    0,
  );
  expect(
    counts[PENDING_CANARY],
    "a context-menu selection must not appear in a heap snapshot after a master lock",
  ).toBe(0);
});
