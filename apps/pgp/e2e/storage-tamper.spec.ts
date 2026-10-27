import type { Page } from "@playwright/test";

import { expect, readStorage, test } from "./fixtures";
import {
  importContact,
  onboardWithPassword,
  seedVault,
  unlockWithPassword,
} from "./helpers";
import { keyBySlug } from "./keys";

// The storage-write attacker (SECURITY.md §17): someone who can write
// chrome.storage -- for a sync user, anyone signed in to their Google
// account -- but does not know the vault password. The unit suite
// (lib/storage/integrity.test.ts) pins each defence against the storage
// layer; this spec pins what the panel SHOWS for the ones with UI.

const PASSWORD = "correct horse battery staple";
const BANNER = /older than the copy this device last saw, or are missing/;

test("a forged onboardingComplete: false does not put onboarding over a vault", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  const protection = (await readStorage(panel, "local")).pgp_master_protection;

  await panel.evaluate(() =>
    chrome.storage.sync.set({
      pgp_preferences: { storageLocation: "local", onboardingComplete: false },
    }),
  );
  await panel.reload();

  // The lock screen, not onboarding: there is nowhere to set a password
  // that would replace the vault's master protection.
  await expect(panel.getByLabel("Master password")).toBeVisible();
  await expect(panel.getByRole("button", { name: "Next" })).toBeHidden();
  await unlockWithPassword(panel, PASSWORD);
  expect((await readStorage(panel, "local")).pgp_master_protection).toEqual(
    protection,
  );
});

test("a flipped storageLocation does not move a device that recorded its own", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await panel.evaluate(() =>
    chrome.storage.sync.set({
      pgp_preferences: { storageLocation: "sync", onboardingComplete: false },
    }),
  );
  await panel.reload();

  // This device's own record (chrome.storage.local) says local, so the
  // synced bootstrap is only advice: straight to the lock screen.
  await unlockWithPassword(panel, PASSWORD);
});

test("with no device record, a flipped storageLocation says where the vault is, and points back", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  // As after an upgrade from a build that kept no device record.
  await panel.evaluate(async () => {
    await chrome.storage.local.remove("pgp_device_location");
    await chrome.storage.sync.set({
      pgp_preferences: { storageLocation: "sync", onboardingComplete: false },
    });
  });
  await panel.reload();

  await expect(
    panel.getByText("Your vault is stored somewhere else"),
  ).toBeVisible();
  await expect(panel.getByRole("button", { name: "Next" })).toBeHidden();

  await panel
    .getByRole("button", { name: "Use the vault where it is" })
    .click();
  await unlockWithPassword(panel, PASSWORD);
  const boot = (await readStorage(panel, "sync")).pgp_preferences as {
    storageLocation?: string;
  };
  expect(boot.storageLocation).toBe("local");
  expect((await readStorage(panel, "local")).pgp_device_location).toBe("local");
  // Nothing was copied into sync on the way.
  expect(
    (await readStorage(panel, "sync")).pgp_master_protection,
  ).toBeUndefined();
});

/** Any validly shaped master protection, planted in sync with the
 *  bootstrap pointed there: nothing unlocks it. */
async function plantSyncVault(panel: Page) {
  await panel.evaluate(() =>
    chrome.storage.sync.set({
      pgp_master_protection: {
        method: "password",
        kdfSalt: "ZXZpbA==",
        encryptedCanary: "Y2FuYXJ5",
        canaryIv: "aXY=",
      },
      pgp_preferences: { storageLocation: "sync", onboardingComplete: true },
    }),
  );
}

test("a master protection planted in sync does not take over the lock screen", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await plantSyncVault(panel);
  await panel.reload();

  // A wrong password first: the lock screen mentions the other vault...
  await panel.getByLabel("Master password").fill("not the password");
  await panel.getByRole("button", { name: "Unlock" }).click();
  await expect(
    panel.getByText("A vault is also stored in synced storage."),
  ).toBeVisible({ timeout: 15_000 });
  // ...but the real one is still the one it opens.
  await unlockWithPassword(panel, PASSWORD);
});

test("with no device record, two vaults are a choice, not a silent pick", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await panel.evaluate(() =>
    chrome.storage.local.remove("pgp_device_location"),
  );
  await plantSyncVault(panel);
  await panel.reload();

  await expect(
    panel.getByText("Two vaults are stored in this browser"),
  ).toBeVisible();
  await panel
    .getByRole("button", { name: "Use the vault on this device" })
    .click();
  await unlockWithPassword(panel, PASSWORD);
  expect((await readStorage(panel, "local")).pgp_device_location).toBe("local");
});

test("an odd storageLocation value reads as local", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await panel.evaluate(async () => {
    await chrome.storage.local.remove("pgp_device_location");
    await chrome.storage.sync.set({
      pgp_preferences: { storageLocation: "SYNC", onboardingComplete: true },
    });
  });
  await panel.reload();
  await unlockWithPassword(panel, PASSWORD);
});

test("deleted settings read as the strictest preset, with a warning", async ({
  panel,
}) => {
  // Onboarding's preset step writes the settings blob, and with it this
  // device's mark for it.
  await onboardWithPassword(panel, PASSWORD);
  await expect(panel.getByText(BANNER)).toBeHidden();

  await panel.evaluate(() => chrome.storage.local.remove("pgp_settings"));
  await panel.reload();
  await unlockWithPassword(panel, PASSWORD);

  await expect(panel.getByText(BANNER)).toBeVisible();
  await expect(
    panel.getByText(/strictest security preset is in effect/),
  ).toBeVisible();

  await panel.getByRole("button", { name: "Dismiss" }).click();
  await expect(panel.getByText(BANNER)).toBeHidden();
});

test("an older contacts blob written back raises the warning", async ({
  panel,
}) => {
  await seedVault(panel, PASSWORD, [keyBySlug("standard").publicKey]);
  const older = (await readStorage(panel, "local")).pgp_public_contacts;
  await importContact(panel, keyBySlug("noEmail").publicKey);

  // The attacker writes back the earlier, still validly sealed blob.
  await panel.evaluate(
    (blob) => chrome.storage.local.set({ pgp_public_contacts: blob }),
    older,
  );
  await panel.reload();
  await unlockWithPassword(panel, PASSWORD);

  await expect(panel.getByText(BANNER)).toBeVisible();
});

test("settings that will not open read as the strictest preset, with a warning", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  // Another store's sealed blob moved into the settings slot: a valid
  // envelope that will not open there.
  await panel.evaluate(async () => {
    const { pgp_keyring } = await chrome.storage.local.get("pgp_keyring");
    await chrome.storage.local.set({ pgp_settings: pgp_keyring });
  });
  await panel.reload();
  await unlockWithPassword(panel, PASSWORD);

  await expect(panel.getByText(BANNER)).toBeVisible();
  await expect(
    panel.getByText(/settings could not be read, so the strictest/),
  ).toBeVisible();
});

test("a deleted ledger is reported on every unlock until dismissed", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await panel.evaluate(() => chrome.storage.local.remove("pgp_integrity"));
  const LOST = /record of what it last saw was deleted/;

  await panel.reload();
  await unlockWithPassword(panel, PASSWORD);
  await expect(panel.getByText(LOST)).toBeVisible();

  await panel.reload();
  await unlockWithPassword(panel, PASSWORD);
  await expect(panel.getByText(LOST)).toBeVisible();
  await panel.getByRole("button", { name: "Dismiss" }).click();
  await expect(panel.getByText(LOST)).toBeHidden();

  await panel.reload();
  await unlockWithPassword(panel, PASSWORD);
  await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible();
  await expect(panel.getByText(BANNER)).toBeHidden();
});
