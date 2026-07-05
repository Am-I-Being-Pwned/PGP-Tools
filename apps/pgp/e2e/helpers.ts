import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";

/**
 * Drive the onboarding flow with a password master and generate a first
 * ECC key. Leaves the panel on the unlocked main UI (My Keys visible).
 */
export async function onboardWithPassword(
  panel: Page,
  password: string,
): Promise<void> {
  // Storage step (default: local).
  await panel.getByRole("button", { name: "Next" }).click();

  // Protection step: switch from the passkey default to password.
  await panel.locator('input[name="protection"]').nth(1).check();
  await panel.getByLabel("Password", { exact: true }).fill(password);
  await panel.getByLabel("Confirm password").fill(password);
  await panel.getByRole("button", { name: "Set password" }).click();

  // Identity step: fill name/email, generate an ECC key (fast).
  await panel.getByPlaceholder("Your full name").fill("E2E Test");
  await panel.getByPlaceholder("you@example.com").fill("e2e@test.local");
  await panel.getByRole("button", { name: "Create my PGP key" }).click();

  // Onboarding lands on the main UI (default: Main/workspace tab).
  await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible({
    timeout: 30_000,
  });
}

/** Onboard with a password master but SKIP generating a key ("I'll set
 *  up later"), so a later import leaves exactly one key to target. */
export async function onboardWithPasswordSkipKey(
  panel: Page,
  password: string,
): Promise<void> {
  await panel.getByRole("button", { name: "Next" }).click();
  await panel.locator('input[name="protection"]').nth(1).check();
  await panel.getByLabel("Password", { exact: true }).fill(password);
  await panel.getByLabel("Confirm password").fill(password);
  await panel.getByRole("button", { name: "Set password" }).click();
  await panel.getByRole("button", { name: "I'll set up later" }).click();
  await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible({
    timeout: 30_000,
  });
}

/** Unlock the single key on the Keys tab (password protection). */
export async function unlockOnlyKey(
  panel: Page,
  password: string,
): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Unlock", exact: true }).click();
  const pw = panel.getByPlaceholder("Enter password");
  await pw.fill(password);
  await pw.press("Enter");
  await expect(panel.getByRole("button", { name: "Lock" })).toBeVisible();
}

/** Lock the single (unlocked) key from the Keys tab -- in-app, no reload. */
export async function lockOnlyKey(panel: Page): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Lock" }).click();
  await expect(
    panel.getByRole("button", { name: "Unlock", exact: true }),
  ).toBeVisible();
}

/** Sign a plaintext message in the workspace with the (single) own key. */
export async function signInWorkspace(
  panel: Page,
  message: string,
): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.getByRole("combobox").first().click();
  await panel.getByRole("option", { name: "Sign", exact: true }).click();
  await panel.locator("textarea").first().fill(message);
  await panel.getByRole("button", { name: /^sign$/i }).click();
  await expect(
    panel.getByText("BEGIN PGP SIGNED MESSAGE").first(),
  ).toBeVisible();
}

/** Encrypt `plaintext` to the single own key via the workspace and return
 *  the armored ciphertext (produced by the app, so it round-trips). */
export async function encryptToSelfInWorkspace(
  panel: Page,
  plaintext: string,
): Promise<string> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.getByRole("combobox").first().click();
  await panel.getByRole("option", { name: "Encrypt", exact: true }).click();
  // Recipient: the single own (encryption-capable) key.
  await panel.getByRole("combobox").nth(1).click();
  await panel.getByRole("option").first().click();
  await panel.locator("textarea").first().fill(plaintext);
  await panel.getByRole("button", { name: /^encrypt$/i }).click();
  const pre = panel.locator("pre").first();
  await expect(pre).toContainText("BEGIN PGP MESSAGE");
  return pre.innerText();
}

/** Decrypt an armored message in the workspace (auto-selects decrypt). */
export async function decryptInWorkspace(
  panel: Page,
  ciphertext: string,
  expectedPlaintext: string,
): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("textarea").first().fill(ciphertext);
  await panel.getByRole("button", { name: /^decrypt$/i }).click();
  await expect(panel.getByText(expectedPlaintext).first()).toBeVisible();
}

/** Unlock the vault from the master lock screen with a password. */
export async function unlockWithPassword(
  panel: Page,
  password: string,
): Promise<void> {
  await panel.getByLabel("Master password").fill(password);
  await panel.getByRole("button", { name: "Unlock" }).click();
  await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible({
    timeout: 15_000,
  });
}

/** Switch to the Keys tab (also persists `activeTab`, a settings field,
 *  which forces the encrypted settings blob to be written). */
export async function goToKeys(panel: Page): Promise<void> {
  await panel.getByRole("tab", { name: "Keys" }).click();
  await expect(panel.getByRole("heading", { name: "My Keys" })).toBeVisible();
}

/** True iff `(ciphertextBytes - 16 GCM tag)` is a power-of-two padding
 *  bucket >= 2048 -- i.e. the blob was saved with length-hiding padding. */
export function isPaddedBucket(ciphertextBytes: number): boolean {
  const plaintext = ciphertextBytes - 16;
  return plaintext >= 2048 && (plaintext & (plaintext - 1)) === 0;
}

/** Import an armored public key as a contact via the Keys-tab drop zone's
 *  file input. Returns after the "Added" toast confirms success. */
export async function importContact(
  panel: Page,
  armoredPublicKey: string,
): Promise<void> {
  await goToKeys(panel);
  // The contact drop zone's hidden file input (distinct accept list).
  await panel
    .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt"]')
    .setInputFiles({
      name: "key.asc",
      mimeType: "application/pgp-keys",
      buffer: Buffer.from(armoredPublicKey, "utf8"),
    });
  // `.first()` tolerates a prior import's toast still being on screen.
  await expect(panel.getByText(/Added \d+ contact/).first()).toBeVisible();
}

/** Import an armored, unprotected private key via the Import Key dialog,
 *  re-protecting it with `password`. Returns once the key card appears. */
export async function importPrivateKey(
  panel: Page,
  armoredPrivateKey: string,
  password: string,
  ownerName: string,
): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  await panel
    .getByPlaceholder("Paste a key here, or browse for a file...")
    .fill(armoredPrivateKey);
  await panel.getByRole("button", { name: "Next" }).click();
  // Protection step: choose password, set it, import.
  await panel.locator('input[name="protection"]').nth(1).check();
  await panel.getByLabel("Password", { exact: true }).fill(password);
  await panel.getByLabel("Confirm password").fill(password);
  // `exact` so it doesn't also match the "Import Key" button behind the modal.
  await panel.getByRole("button", { name: "Import", exact: true }).click();
  // Success closes the dialog (the paste textarea disappears); on error it
  // stays open. Then confirm the key landed on the Keys tab.
  await expect(
    panel.getByPlaceholder("Paste a key here, or browse for a file..."),
  ).toBeHidden();
  await expect(panel.getByText(ownerName).last()).toBeVisible();
}

/** Paste a cleartext-signed message into the workspace (auto-switches to
 *  Verify) and run verification. */
export async function verifySignedMessage(
  panel: Page,
  signedMessage: string,
): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("textarea").first().fill(signedMessage);
  // The idle action button is labelled with the (auto-selected) mode.
  await panel.getByRole("button", { name: /^verify$/i }).click();
}
