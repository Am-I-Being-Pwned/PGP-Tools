import { expect, readStorage, test } from "./fixtures";
import {
  goToKeys,
  seedVault,
  switchStorageTo,
  unlockWithPassword,
} from "./helpers";
import { TEST_KEYS } from "./keys";

const PASSWORD = "correct horse battery staple";

// chrome.storage.sync's per-item cap. Chrome measures an item as the
// JSON-stringified value plus the key's length; a single encrypted blob
// bigger than this is exactly what threw "kQuotaBytesPerItem quota
// exceeded" before chunking existed.
const SYNC_PER_ITEM_CAP = 8192;
const CONTACTS_KEY = "pgp_public_contacts";

function itemBytes(key: string, value: unknown): number {
  return key.length + JSON.stringify(value).length;
}

test("switching a large vault to sync chunks it under the 8 KB/item cap", async ({
  panel,
}) => {
  // Seed a vault whose encrypted contacts blob comfortably exceeds a
  // single sync item (would throw pre-chunking) in one setup call.
  await seedVault(
    panel,
    PASSWORD,
    TEST_KEYS.map((k) => k.publicKey),
  );

  await test.step("contacts start as one un-chunked local item", async () => {
    const local = await readStorage(panel, "local");
    const blob = local[CONTACTS_KEY] as Record<string, unknown>;
    expect(Object.keys(blob).sort()).toEqual(["ciphertext", "iv"]);
    // Big enough that it could not fit one sync item verbatim.
    expect(itemBytes(CONTACTS_KEY, blob)).toBeGreaterThan(SYNC_PER_ITEM_CAP);
  });

  // The switch that used to throw.
  await switchStorageTo(panel, "sync");

  await test.step("sync holds a chunk manifest, not the raw blob", async () => {
    const sync = await readStorage(panel, "sync");
    const head = sync[CONTACTS_KEY] as { __sc?: number };
    expect(typeof head.__sc, "head key is a chunk manifest").toBe("number");
    expect(head.__sc).toBeGreaterThanOrEqual(2);
    // The chunk items the manifest promises all exist.
    for (let i = 0; i < (head.__sc ?? 0); i++) {
      expect(sync[`${CONTACTS_KEY}::sc${i}`], `chunk ${i}`).toBeTruthy();
    }
  });

  await test.step("no sync item exceeds the per-item quota", async () => {
    const sync = await readStorage(panel, "sync");
    for (const [key, value] of Object.entries(sync)) {
      expect(itemBytes(key, value), `item "${key}"`).toBeLessThanOrEqual(
        SYNC_PER_ITEM_CAP,
      );
    }
  });

  await test.step("old local copy is purged after the commit", async () => {
    const local = await readStorage(panel, "local");
    expect(local[CONTACTS_KEY]).toBeUndefined();
  });

  await test.step("contacts round-trip: reassembled from sync after reload", async () => {
    await panel.reload();
    await unlockWithPassword(panel, PASSWORD);
    await goToKeys(panel);
    // Every imported contact is present again -- proving getChunked
    // stitched the sync chunks back into the original blob.
    for (const key of TEST_KEYS) {
      await expect(panel.getByText(key.label).first()).toBeVisible();
    }
  });

  await test.step("switching back to local re-joins the blob and purges chunks", async () => {
    await switchStorageTo(panel, "local");

    const local = await readStorage(panel, "local");
    const blob = local[CONTACTS_KEY] as Record<string, unknown>;
    expect(Object.keys(blob).sort()).toEqual(["ciphertext", "iv"]);

    // Nothing chunked (or otherwise) left stranded in sync.
    const sync = await readStorage(panel, "sync");
    const strays = Object.keys(sync).filter((k) =>
      k.startsWith(CONTACTS_KEY),
    );
    expect(strays).toEqual([]);
  });
});
