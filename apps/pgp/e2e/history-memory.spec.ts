import type { Page } from "@playwright/test";

import { expect, readStorage, test } from "./fixtures";
import { scanJsHeap } from "./heap";
import {
  enableSaveToHistory,
  encryptToSelfInWorkspace,
  goToKeys,
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

// ── consequence of sharing the contacts session key ──────────────────
// History does not have a key of its own: `writeSegment` calls
// `encryptContacts`, so segments are sealed under the same in-WASM
// CONTACTS_KEY as the keyring, the contacts list, the settings blob and
// the CRX key store -- and under the same fixed AAD,
// `CONTACTS_AAD = "gpg-tools:contacts:master"` (gpg-wasm/src/lib.rs).
// Nothing in the sealed data names the store or the segment it belongs to.
//
// Contrast the workspace draft, which does it the other way: its own
// in-WASM key AND its own versioned AAD, "gpg-tools:workspace-draft:v1".
//
// The confidentiality consequence is the intended one and is covered
// above: history is unreadable the moment the master session drops. The
// INTEGRITY consequence is what this test demonstrates -- an encrypted
// blob is not bound to where it is stored, so anyone who can write
// chrome.storage.local (without knowing the vault key) can replay a
// history segment into another slot, or into an entirely different store,
// and the AEAD accepts it.
const CONTACTS_KEY = "pgp_public_contacts";
const contact = keyBySlug("standard");

test("history ciphertext is not bound to its slot or its store", async ({
  panel,
}) => {
  await seedVault(panel, MASTER, [contact.publicKey]);
  await recordCanaryEntry(panel);

  await test.step("a segment replays into another segment slot", async () => {
    // No knowledge of the key needed -- just a copy of the ciphertext.
    await panel.evaluate(async () => {
      const all = await chrome.storage.local.get(null);
      await chrome.storage.local.set({
        pgp_history_seg_1: all.pgp_history_seg_0,
      });
    });
    // Opening history runs loadHistory -> adoptStraySegments, which finds
    // segments by prefix scan and adopts one only if `readSegment` DECRYPTED
    // it and got valid entries out (a failed tag check yields [] and is
    // skipped). So the manifest growing to include segment 1, with a
    // non-zero plaintext size, is proof the AEAD accepted a segment blob in
    // a slot it was never sealed for.
    await openHistoryPage(panel);
    await expect
      .poll(
        async () => {
          const local = await readStorage(panel, "local");
          const manifest = local[HISTORY_KEY] as { segs?: SegmentRef[] };
          return manifest.segs?.find((s) => s.n === 1)?.bytes ?? 0;
        },
        { timeout: 15_000 },
      )
      .toBeGreaterThan(0);
  });

  await test.step("a segment is also accepted as the CONTACTS blob", async () => {
    // Before: the seeded contact is on the Keys tab.
    await panel.keyboard.press("Escape");
    await panel.keyboard.press("Escape");
    await goToKeys(panel);
    await expect(panel.getByText(contact.label).first()).toBeVisible();

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

    // The contact list is silently empty and nothing is reported. Note what
    // this step does and does not establish: the *decryption* half of the
    // claim is proved by the slot-replay step above (adoptStraySegments only
    // adopts a segment it actually decrypted). Here the visible outcome is
    // the same whether the tag check passed and the items failed
    // `isPublicContactKey`, or the tag check failed outright -- because
    // loadEncryptedArray gives the UI no way to tell those apart. Either
    // way, a store swapped out from under the app loses the user's contacts
    // without a word.
    await expect(panel.getByText(contact.label)).toHaveCount(0);
    await expect(panel.locator("p.text-destructive")).toHaveCount(0);
  });
});
