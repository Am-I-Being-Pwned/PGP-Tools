import { ciphertextBytes, expect, readStorage, test } from "./fixtures";
import {
  goToKeys,
  isPaddedBucket,
  onboardWithPassword,
  unlockWithPassword,
} from "./helpers";

const PASSWORD = "correct horse battery staple";

test("lock (reload) then unlock preserves keys and keeps storage padded", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await goToKeys(panel);

  // The generated identity is visible while unlocked.
  await expect(panel.getByText("E2E Test <e2e@test.local>")).toBeVisible();
  const before = ciphertextBytes(
    (await readStorage(panel, "local")).pgp_keyring,
  );
  expect(isPaddedBucket(before)).toBe(true);

  await test.step("reloading drops the in-page WASM session -> locked", async () => {
    await panel.reload();
    // Master lock screen: the password field is present, the keys are not.
    await expect(panel.getByLabel("Master password")).toBeVisible();
    await expect(panel.getByRole("tab", { name: "Keys" })).toBeHidden();
  });

  await test.step("unlocking restores the same keys, still padded", async () => {
    await unlockWithPassword(panel, PASSWORD);
    await goToKeys(panel);
    await expect(panel.getByText("E2E Test <e2e@test.local>")).toBeVisible();

    // Round-trip: the keyring still decrypts, and normalization on unlock
    // kept it in a canonical padded bucket.
    const after = ciphertextBytes(
      (await readStorage(panel, "local")).pgp_keyring,
    );
    expect(isPaddedBucket(after)).toBe(true);
    expect(after).toBe(before);
  });

  await test.step("a wrong password is rejected", async () => {
    await panel.reload();
    await panel.getByLabel("Master password").fill("wrong password entirely");
    await panel.getByRole("button", { name: "Unlock" }).click();
    await expect(panel.getByText("Wrong password.")).toBeVisible();
    await expect(panel.getByRole("tab", { name: "Keys" })).toBeHidden();
  });
});
