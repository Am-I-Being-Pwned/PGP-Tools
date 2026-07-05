import { ciphertextBytes, expect, readStorage, test } from "./fixtures";
import { goToKeys, isPaddedBucket, onboardWithPassword } from "./helpers";

const PASSWORD = "correct horse battery staple";

test("onboarding encrypts and pads storage, and splits settings", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  // Persist a settings field so the encrypted settings blob is written.
  await goToKeys(panel);

  const local = await readStorage(panel, "local");
  const sync = await readStorage(panel, "sync");

  await test.step("keyring is an encrypted, padded blob", () => {
    const keyring = local.pgp_keyring;
    expect(keyring, "keyring should exist").toBeTruthy();
    // { iv, ciphertext } shape -- not plaintext.
    expect(Object.keys(keyring as object).sort()).toEqual(["ciphertext", "iv"]);
    expect(isPaddedBucket(ciphertextBytes(keyring))).toBe(true);
  });

  await test.step("settings are encrypted (not plaintext prefs)", () => {
    const settings = local.pgp_settings;
    expect(settings, "settings blob should exist").toBeTruthy();
    expect(Object.keys(settings as object).sort()).toEqual([
      "ciphertext",
      "iv",
    ]);
  });

  await test.step("sync holds only the plaintext bootstrap", () => {
    const boot = sync.pgp_preferences as Record<string, unknown>;
    expect(boot).toBeTruthy();
    // Only the two fields needed pre-unlock; no leaked settings.
    expect(Object.keys(boot).sort()).toEqual([
      "onboardingComplete",
      "storageLocation",
    ]);
    expect(boot.onboardingComplete).toBe(true);
  });

  await test.step("no plaintext key material anywhere in storage", () => {
    const dump = JSON.stringify({ local, sync });
    for (const marker of [
      "BEGIN PGP PRIVATE KEY",
      "BEGIN PGP PUBLIC KEY",
      "e2e@test.local",
      "E2E Test",
    ]) {
      expect(dump, `must not leak "${marker}"`).not.toContain(marker);
    }
  });
});
