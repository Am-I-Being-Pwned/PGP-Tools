import type { Page } from "@playwright/test";

import { expect, readStorage, test } from "./fixtures";
import { scanJsHeap } from "./heap";
import {
  enableSaveToHistory,
  encryptToSelfInWorkspace,
  goToKeys,
  importContact,
  lockMasterViaPalette,
  openHistoryPage,
  runPaletteAction,
  seedVault,
  unlockWithPassword,
} from "./helpers";
import { keyBySlug } from "./keys";

// The opt-in operation history (lib/storage/history.ts) persists up to
// 2 MB of PLAINTEXT MESSAGE CONTENT (32 KB per entry) -- by far the most
// sensitive thing the extension writes that isn't key material. Its module
// doc-comment makes two claims this spec turns into assertions:
//
//   1. what lands in chrome.storage.local is genuinely ciphertext -- only
//      the small manifest is plaintext, and it holds segment numbers and
//      byte sizes, never entry data;
//   2. "No plaintext is ever cached at module level -- every read
//      decrypts on demand and every local goes out of scope when the call
//      returns, so dropping the contacts session (master lock) leaves
//      nothing readable here."
//
// (2) is checked the way heap.spec.ts checks private keys: a canary we
// control goes into a recorded entry, and after an in-app master lock a
// CDP heap snapshot must not contain it.

const MASTER = "correct horse battery staple";
/** Unique, newline-free, and not a literal anywhere in the bundle. */
const CANARY = "HISTORY-CANARY-9d41f7ab-do-not-leak";
const MESSAGE = `dinner at eight ${CANARY} bring the documents`;
/** Present on every screen incl. the master lock screen (AppFooter), so
 *  it proves the heap scan is actually finding live strings. */
const HEAP_CONTROL = "A privacy tool by";

const HISTORY_KEY = "pgp_history";
const SEGMENT_PREFIX = "pgp_history_seg_";

interface SegmentRef {
  n: number;
  bytes: number;
}

/** Opt in (history is off by default) and record one encrypt entry whose
 *  `content` is the canary message -- a text encrypt captures `s.input`
 *  verbatim. Returns once the segment blob exists on disk; capture is
 *  fire-and-forget, so it has to be waited for. */
async function recordCanaryEntry(panel: Page): Promise<void> {
  await enableSaveToHistory(panel);
  await encryptToSelfInWorkspace(panel, MESSAGE);
  await expect
    .poll(
      async () => {
        const local = await readStorage(panel, "local");
        return Object.keys(local).filter((k) => k.startsWith(SEGMENT_PREFIX))
          .length;
      },
      { timeout: 15_000 },
    )
    .toBeGreaterThan(0);
}

test("recorded history content is ciphertext at rest, with a metadata-only manifest", async ({
  panel,
}) => {
  await seedVault(panel, MASTER);
  await recordCanaryEntry(panel);

  const local = await readStorage(panel, "local");

  await test.step("the plaintext manifest carries no entry data", () => {
    const manifest = local[HISTORY_KEY] as { segs?: SegmentRef[] };
    expect(Object.keys(manifest)).toEqual(["segs"]);
    expect(manifest.segs?.length).toBeGreaterThan(0);
    for (const seg of manifest.segs ?? []) {
      expect(Object.keys(seg).sort()).toEqual(["bytes", "n"]);
      expect(typeof seg.n).toBe("number");
      expect(typeof seg.bytes).toBe("number");
    }
  });

  await test.step("every segment is an opaque AES-GCM blob", () => {
    const segments = Object.entries(local).filter(([k]) =>
      k.startsWith(SEGMENT_PREFIX),
    );
    expect(segments.length).toBeGreaterThan(0);
    for (const [, blob] of segments) {
      expect(Object.keys(blob as object).sort()).toEqual(["ciphertext", "iv"]);
    }
  });

  await test.step("the message content is nowhere in chrome.storage", async () => {
    for (const area of ["local", "sync", "session"] as const) {
      const dump = JSON.stringify(await readStorage(panel, area));
      expect(
        dump.includes(CANARY),
        `message content must not be readable in chrome.storage.${area}`,
      ).toBe(false);
    }
  });

  await test.step("but it IS readable through the app while unlocked", async () => {
    // Searching the history decrypts every segment; a content hit renders a
    // snippet under the row, which proves the plaintext round-tripped.
    await openHistoryPage(panel);
    await panel.getByLabel("Search history").fill(CANARY);
    await expect(panel.getByText(CANARY).first()).toBeVisible();
  });
});

test("a master lock leaves no decrypted history in the JS heap", async ({
  panel,
}) => {
  await seedVault(panel, MASTER);
  await recordCanaryEntry(panel);

  // Clear the workspace before locking. The encrypted message is still the
  // live value of the workspace textarea, and a textarea value survives its
  // unmount as a Blink-owned external string (draft-memory.spec.ts owns
  // that finding). Clearing removes that unrelated copy so what follows
  // measures the history store's claim -- that nothing module-level caches
  // decrypted entries -- rather than the input box.
  //
  // The History *viewer* is deliberately not opened here for the same
  // reason: typing the canary into its search box, or rendering a matched
  // snippet, plants the same DOM-value residue. The unlock step at the end
  // proves the entry was really there.
  await runPaletteAction(panel, "Clear input");
  await lockMasterViaPalette(panel);

  await test.step("the canary is absent from a heap snapshot", async () => {
    const counts = await scanJsHeap(panel, [CANARY, HEAP_CONTROL]);
    expect(
      counts[HEAP_CONTROL],
      "control present (scan works)",
    ).toBeGreaterThan(0);
    expect(
      counts[CANARY],
      "recorded history content must not be retained in the JS heap after a master lock",
    ).toBe(0);
  });

  await test.step("the entry survived the lock (so the scan measured a live secret)", async () => {
    await unlockWithPassword(panel, MASTER);
    await openHistoryPage(panel);
    await panel.getByLabel("Search history").fill(CANARY);
    await expect(panel.getByText(CANARY).first()).toBeVisible();
  });
});

// ── segments are bound to their slot and their store ─────────────────
// History used to have no envelope of its own: `writeSegment` called
// `encryptContacts`, so every segment was sealed under the same in-WASM
// CONTACTS_KEY as the keyring, the contacts list, the settings blob and
// the CRX key store -- and under the same fixed AAD,
// `CONTACTS_AAD = "gpg-tools:contacts:master"`. Nothing in the sealed data
// named the store or the segment, so anyone who could write
// chrome.storage.local -- with NO knowledge of the vault key -- could
// replay a segment into another slot, or into an entirely different store,
// and the AEAD accepted it. This spec used to demonstrate exactly that.
//
// Each segment is now sealed for its own storage key as the domain: the
// wasm side derives BOTH an HKDF subkey and the AAD from it (see
// `gpg-wasm/src/lib.rs` `encrypt_store` and `lib/storage/envelope.ts`), so
// moving an intact blob to any other key breaks its tag check. The two
// attacks below must now FAIL, and each is paired with a positive control
// so a passing assertion cannot be a dead code path.
const CONTACTS_KEY = "pgp_public_contacts";
const contact = keyBySlug("standard");

interface StoredBlob {
  iv: string;
  ciphertext: string;
}

/** The contact as it appears ON SCREEN. A bare `getByText` also matches a
 *  copy inside the inactive Main tab's recipient picker, which is in the
 *  DOM but hidden -- so `.first()` on the unfiltered locator can resolve
 *  to a node that will never become visible. */
function visibleContact(panel: Page) {
  return panel.getByText(contact.label).filter({ visible: true });
}

/** The manifest's record of segment `n`, or undefined. */
async function segmentRef(
  panel: Page,
  n: number,
): Promise<SegmentRef | undefined> {
  const local = await readStorage(panel, "local");
  const manifest = local[HISTORY_KEY] as { segs?: SegmentRef[] };
  return manifest.segs?.find((s) => s.n === n);
}

/**
 * Close the History slide-over and wait until it is really gone.
 *
 * Why this exists -- the flake it replaces had two independent halves, and
 * the old `Escape` + `Escape` + `goToKeys(...)` sequence needed both to go
 * its way:
 *
 *  1. **Escape does not always close the page.** The search input swallows
 *     Escape while its query is non-empty (`HistoryPage.tsx`: Esc clears
 *     the query, a *second* Esc closes) -- and the box only mounts at all
 *     once the async `loadHistory()` resolves with entries, so whether a
 *     given Escape closes the page, clears a query, or lands on the
 *     document depends on timing the test never controlled.
 *  2. **The panel outlives its close by 300 ms.** `useSlideOver.close()`
 *     flips `entered` and only calls `onClosed` after `SLIDE_MS`, so a
 *     `fixed inset-0 z-50` overlay stays mounted (and top of the Escape
 *     stack) for that window.
 *
 * Either way the following tab click could be fired at a page that was
 * still covered, or never closed -- and `toBeVisible` retries the
 * *assertion*, never the lost click, so it just burned its timeout.
 *
 * Clearing the query first means exactly one Escape is needed, and waiting
 * for the region to be DETACHED (not merely hidden) means nothing runs
 * during the slide-out.
 */
async function closeHistoryPage(panel: Page): Promise<void> {
  const search = panel.getByLabel("Search history");
  if ((await search.count()) > 0) await search.fill("");
  await panel.keyboard.press("Escape");
  await expect(panel.getByRole("region", { name: "History" })).toHaveCount(0);
}

// Two separate tests, not two steps of one: each attack must be provable
// on its own. (Checked by collapsing every domain to a single constant in
// `envelope.ts` and rebuilding -- both tests then fail, each on its own
// assertion. As two steps of one test the first failure would have masked
// the second.)

test("a history segment does not replay into another segment slot", async ({
  panel,
}) => {
  await seedVault(panel, MASTER);
  await recordCanaryEntry(panel);

  // How many nodes one canary entry renders in the viewer. Measured
  // rather than hardcoded (the snippet is nested markup), so the
  // duplicate-row check below can't drift with the row layout.
  let canaryNodes = 0;
  await test.step("baseline: one recorded entry, as the viewer renders it", async () => {
    await openHistoryPage(panel);
    await panel.getByLabel("Search history").fill(CANARY);
    await expect(panel.getByText(CANARY).first()).toBeVisible();
    canaryNodes = await panel.getByText(CANARY).count();
    expect(canaryNodes).toBeGreaterThan(0);
    await closeHistoryPage(panel);
  });

  await test.step("a segment does not replay into another segment slot", async () => {
    // One storage write sets up BOTH halves of this step, so they run
    // through the same `loadHistory` -> `adoptStraySegments` pass and the
    // only difference between them is which slot the blob sits in:
    //
    //   - forget segment 0 in the manifest, leaving its real blob a stray.
    //     Adopting it back is the POSITIVE CONTROL: adoption only happens
    //     for a segment `readSegment` actually DECRYPTED and got valid
    //     entries out of, so seeing seg 0 return proves the prefix scan,
    //     the decrypt and the adopt path are all live in this run.
    //   - plant a byte-for-byte copy of that same blob at segment 1. No
    //     knowledge of the vault key needed -- just a copy of the
    //     ciphertext. It must NOT be adopted.
    await panel.evaluate(async () => {
      const all = await chrome.storage.local.get(null);
      await chrome.storage.local.set({
        pgp_history: { segs: [] },
        pgp_history_seg_1: all.pgp_history_seg_0,
      });
    });

    await openHistoryPage(panel);

    // `adoptStraySegments` scans ascending and writes the manifest ONCE
    // after deciding about every stray, so as soon as segment 0 is back
    // the verdict on segment 1 is already in that same manifest.
    await expect
      .poll(async () => (await segmentRef(panel, 0))?.bytes ?? 0, {
        timeout: 15_000,
      })
      .toBeGreaterThan(0);

    expect(
      await segmentRef(panel, 1),
      "a segment blob copied into another slot must fail its tag check, so adoptStraySegments must not adopt it",
    ).toBeUndefined();

    // ...and the viewer still shows the entry ONCE: an adopted replay
    // would have rendered a second, identical row, i.e. double the
    // baseline node count.
    await panel.getByLabel("Search history").fill(CANARY);
    await expect(
      panel.getByText(CANARY),
      "a replayed segment must not surface as a duplicate history row",
    ).toHaveCount(canaryNodes);
  });
});

test("a history segment is no longer accepted as the contacts blob", async ({
  panel,
}) => {
  await seedVault(panel, MASTER, [contact.publicKey]);
  await recordCanaryEntry(panel);

  await test.step("the seeded contact is on the Keys tab to begin with", async () => {
    await goToKeys(panel);
    await expect(visibleContact(panel).first()).toBeVisible();
  });

  // Keep both blobs: the real one to restore, the segment to compare
  // against after the app has had its chance to overwrite it.
  const before = await readStorage(panel, "local");
  const realContacts = before[CONTACTS_KEY] as StoredBlob;
  const segment = before[`${SEGMENT_PREFIX}0`] as StoredBlob;

  await test.step("the substituted blob is not read as a contacts list", async () => {
    await panel.evaluate(
      async ([contactsKey]) => {
        const all = await chrome.storage.local.get(null);
        await chrome.storage.local.set({
          [contactsKey]: all.pgp_history_seg_0,
        });
      },
      [CONTACTS_KEY],
    );
    await panel.reload();
    await unlockWithPassword(panel, MASTER);
    await goToKeys(panel);

    // The contact being gone is NOT what this step establishes: the write
    // above destroyed the real blob, so it would be gone either way.
    await expect(visibleContact(panel)).toHaveCount(0);

    // What DOES distinguish the fix is whether the substituted blob is
    // READ as a contacts list. Before the fix the AEAD accepted it, every
    // item failed `isValidContact`, and the store read as a legitimately
    // empty list -- indistinguishable, from the UI, from having no
    // contacts. The next contacts write would then have persisted that
    // empty list and cemented the loss. Now the tag check fails,
    // `loadEncryptedArray` rejects, and the read-modify-write never runs.
    //
    // Probe it through the app's own read-modify-write and use a reload as
    // the barrier, so there is no timing to get wrong: whatever the import
    // was going to write has either landed or been abandoned by the time
    // the panel comes back.
    await importContact(panel, contact.publicKey).catch(() => undefined);
    await panel.reload();
    await unlockWithPassword(panel, MASTER);

    expect(
      (await readStorage(panel, "local"))[CONTACTS_KEY],
      "a contacts blob that failed to open must not be replaced by the write that follows the failed read -- pre-fix this slot held a fresh single-contact blob and the user's other contacts were gone for good",
    ).toEqual(segment);
  });

  // POSITIVE CONTROL: put the real blob back and it opens again, in its
  // own slot, under the same session key. So the rejection above was the
  // domain binding, not a broken vault or a store that never loads.
  await test.step("restoring the real blob makes the contact readable again", async () => {
    await panel.evaluate(
      async ({ contactsKey, blob }) => {
        await chrome.storage.local.set({ [contactsKey]: blob });
      },
      { contactsKey: CONTACTS_KEY, blob: realContacts },
    );
    await panel.reload();
    await unlockWithPassword(panel, MASTER);
    await goToKeys(panel);
    await expect(visibleContact(panel).first()).toBeVisible();
  });
});
