import type { Page } from "@playwright/test";

import { edgeKey } from "./edge-keys";
import { expect, test } from "./fixtures";
import { goToKeys, importFileInPanel } from "./helpers";
import { PRIVATE_KEY_FIXTURE } from "./private-key";
import { addPrfAuthenticatorWithId, exportCredentials } from "./webauthn-carry";

// "Unlock keys with the vault" end to end, on a virtual PRF authenticator.
//
// The property under test is a COUNT: with the option on, the one
// ceremony that opens the vault also opens every key sealed under the
// master salt, and no other ceremony runs. The virtual authenticator's
// per-credential `signCount` increments once per completed
// `navigator.credentials.get`, so the sum across the authenticator is an
// exact ceremony counter -- a UI assertion alone ("the key shows Lock")
// could pass with a second, per-key prompt hiding behind it.

const IMPORT_PW = "import-protect-password-123";
// The password-protected control: a GnuPG-style S2K-protected export,
// imported under a password rather than the passkey.
const PASSWORD_KEY = edgeKey("protectedPrivate");

async function setUnlockWithVault(panel: Page, on: boolean): Promise<void> {
  await panel.getByRole("tab", { name: "Settings" }).click();
  const sw = panel.getByRole("switch", { name: /Unlock keys with the vault/ });
  await expect(sw).toBeVisible();
  if ((await sw.getAttribute("aria-checked")) !== String(on)) await sw.click();
  await expect(sw).toHaveAttribute("aria-checked", String(on));
}

/** Import an armored private key protected by the master passkey (the
 *  picker's default, with "use the same passkey" ticked). */
async function importPrivateKeyWithPasskey(
  panel: Page,
  armoredPrivateKey: string,
  ownerName: string,
): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  await importFileInPanel(panel, armoredPrivateKey);
  await panel.getByRole("button", { name: "Continue" }).click();
  await panel.getByRole("button", { name: "Import", exact: true }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();
  await expect(panel.getByText(ownerName).last()).toBeVisible();
}

async function signCount(
  auth: Awaited<ReturnType<typeof addPrfAuthenticatorWithId>>,
): Promise<number> {
  const creds = (await exportCredentials(auth)) as { signCount: number }[];
  return creds.reduce((n, c) => n + c.signCount, 0);
}

/** Reload (drops the wasm session -> lock screen), let the lock screen's
 *  auto-prompt run the master ceremony, and wait for the main UI. Only
 *  clicks the button if the auto-prompt lost the focus race, and only
 *  after a pause long enough that a click can't abort a ceremony that is
 *  about to complete (which would count as two). */
async function reloadAndUnlock(panel: Page) {
  await panel.reload();
  await panel.bringToFront();
  const keysTab = panel.getByRole("tab", { name: "Keys" });
  const unlocked = await keysTab
    .waitFor({ state: "visible", timeout: 5_000 })
    .then(() => true)
    .catch(() => false);
  if (!unlocked) {
    await panel.getByRole("button", { name: "Unlock with passkey" }).click();
    await expect(keysTab).toBeVisible({ timeout: 20_000 });
  }
}

const lockButtons = (panel: Page) =>
  panel.getByRole("button", { name: "Lock", exact: true });
const unlockButtons = (panel: Page) =>
  panel.getByRole("button", { name: "Unlock", exact: true });

test("one vault ceremony unlocks the keys sealed under it, and only when opted in", async ({
  context,
  extensionId,
}) => {
  const panel = await context.newPage();
  const auth = await addPrfAuthenticatorWithId(context, panel);
  await panel.goto(`chrome-extension://${extensionId}/sidepanel.html`);
  await panel.bringToFront();

  await test.step("onboard with a passkey master; leave the option OFF", async () => {
    await panel.getByRole("button", { name: "Next" }).click();
    await panel.getByRole("button", { name: "Create passkey" }).click();
    await panel.getByPlaceholder("Your full name").fill("Vault User");
    await panel.getByPlaceholder("you@example.com").fill("vault@test.local");
    await panel.getByRole("button", { name: "Create my PGP key" }).click();
    // The opt-in is offered on the preset step for passkey masters.
    const optIn = panel.getByRole("checkbox", {
      name: /Unlock keys with the vault/,
    });
    await expect(optIn).toBeVisible({ timeout: 30_000 });
    await expect(optIn).not.toBeChecked();
    await panel.getByRole("button", { name: "Keep the defaults" }).click();
    await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible({
      timeout: 30_000,
    });
  });

  await test.step("negative control: off means the key stays locked after the vault opens", async () => {
    await reloadAndUnlock(panel);
    await goToKeys(panel);
    await expect(unlockButtons(panel)).toHaveCount(1);
    await expect(lockButtons(panel)).toHaveCount(0);
  });

  await test.step("turn the option on in Settings", async () => {
    await setUnlockWithVault(panel, true);
  });

  await test.step("the vault ceremony now unlocks the key, with exactly one ceremony", async () => {
    const before = await signCount(auth);
    await reloadAndUnlock(panel);
    await goToKeys(panel);
    await expect(lockButtons(panel)).toHaveCount(1);
    await expect(unlockButtons(panel)).toHaveCount(0);
    expect(await signCount(auth), "exactly one WebAuthn assertion").toBe(
      before + 1,
    );
  });

  await test.step("a key imported under its OWN passkey salt is not opened by the vault", async () => {
    // Import while the option is OFF so the blob gets a random salt (the
    // pre-feature shape every single-key import has), then turn it back
    // on. Same credential as the master, different salt.
    await setUnlockWithVault(panel, false);
    await importPrivateKeyWithPasskey(
      panel,
      PRIVATE_KEY_FIXTURE.privateKey,
      PRIVATE_KEY_FIXTURE.name,
    );
    await setUnlockWithVault(panel, true);
    await reloadAndUnlock(panel);
    await goToKeys(panel);
    // Onboarding key live, imported key still on its own prompt.
    await expect(lockButtons(panel)).toHaveCount(1);
    await expect(unlockButtons(panel)).toHaveCount(1);
  });

  await test.step("its own prompt moves it over: one ceremony, no migration step", async () => {
    // The user unlocks the key exactly as before. That single ceremony
    // also evaluates the master salt (PRF `second`), and the key is
    // re-sealed under the master on the spot.
    const before = await signCount(auth);
    await unlockButtons(panel).click();
    await expect(lockButtons(panel)).toHaveCount(2, { timeout: 20_000 });
    expect(await signCount(auth), "exactly one ceremony for the unlock").toBe(
      before + 1,
    );
  });

  await test.step("both keys now open off the single vault ceremony", async () => {
    const before = await signCount(auth);
    await reloadAndUnlock(panel);
    await goToKeys(panel);
    await expect(lockButtons(panel)).toHaveCount(2);
    await expect(unlockButtons(panel)).toHaveCount(0);
    expect(await signCount(auth)).toBe(before + 1);
  });

  await test.step("a password-protected key keeps its password", async () => {
    await goToKeys(panel);
    await panel.getByRole("button", { name: "Import Key" }).click();
    await importFileInPanel(panel, PASSWORD_KEY.privateKey ?? "");
    await panel.getByRole("button", { name: "Continue" }).click();
    await panel
      .getByPlaceholder("Key passphrase")
      .fill(PASSWORD_KEY.passphrase ?? "");
    await panel.locator('input[name="protection"]').nth(1).check();
    await panel.getByLabel("Password", { exact: true }).fill(IMPORT_PW);
    await panel.getByLabel("Confirm password").fill(IMPORT_PW);
    await panel.getByRole("button", { name: "Import", exact: true }).click();
    await expect(
      panel.getByRole("region", { name: "Import key" }),
    ).toBeHidden();
    await reloadAndUnlock(panel);
    await goToKeys(panel);
    await expect(lockButtons(panel)).toHaveCount(2);
    await expect(unlockButtons(panel)).toHaveCount(1);
  });

  await test.step("turning it off restores the per-key prompt", async () => {
    await setUnlockWithVault(panel, false);
    await reloadAndUnlock(panel);
    await goToKeys(panel);
    await expect(unlockButtons(panel)).toHaveCount(3);
    await expect(lockButtons(panel)).toHaveCount(0);
  });

  await panel.close();
});
