import { readFile } from "node:fs/promises";

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

  // Preset step: keep the defaults so specs see the stock preferences.
  await panel
    .getByRole("button", { name: "Keep the defaults" })
    .click({ timeout: 30_000 });

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
  await panel.getByRole("button", { name: "Keep the defaults" }).click();
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
  // Armored output is never displayed anymore; completion swaps the
  // action bar to Download + Copy. The Copy button renders ONLY when
  // armored text output exists, so its presence proves the signature
  // was produced.
  await expect(panel.getByRole("button", { name: "Download" })).toBeVisible();
  await expect(panel.getByRole("button", { name: "Copy" })).toBeVisible();
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
  // Recipient: the box starts empty by design; pick the single own
  // (encryption-capable) key from the dropdown.
  await panel.getByRole("combobox", { name: "Recipients" }).click();
  await panel.getByRole("option").first().click();
  await expect(
    panel.getByRole("button", { name: /^Remove / }).first(),
  ).toBeVisible();
  await panel.locator("textarea").first().fill(plaintext);
  await panel.getByRole("button", { name: /^encrypt$/i }).click();
  // Ciphertext is never displayed; Download is the interface. Capture
  // the download and read the armor back out of the file.
  const downloadEvent = panel.waitForEvent("download");
  await panel.getByRole("button", { name: "Download" }).click();
  const file = await downloadEvent;
  const path = await file.path();
  const armored = await readFile(path, "utf8");
  expect(armored).toContain("BEGIN PGP MESSAGE");
  return armored;
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

/** Open Settings and switch key storage between "this device only" and
 *  "sync across devices", waiting for the migration to finish. Throws if
 *  the migration surfaces an error (e.g. sync quota exhausted). */
export async function switchStorageTo(
  panel: Page,
  target: "local" | "sync",
): Promise<void> {
  const label = target === "sync" ? "Sync across devices" : "This device only";
  await panel.getByRole("tab", { name: "Settings" }).click();
  await expect(
    panel.getByRole("heading", { name: "Key storage" }),
  ).toBeVisible();
  const radio = panel.getByRole("radio", { name: new RegExp(label) });
  // click(), not check(): the radio is controlled and only reflects the
  // new location once the async migration commits, so check()'s
  // post-click state assertion would fail mid-migration.
  await radio.click();
  // Migration is done once the picker reflects the new location (an inline
  // spinner shows on the target row meanwhile -- no "Migrating..." text).
  await expect(radio).toBeChecked({ timeout: 30_000 });
  // The migration error paragraph (destructive text) must not appear.
  await expect(panel.locator("p.text-destructive")).toHaveCount(0);
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

/** Import an armored, unprotected private key via the Import Key page,
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
  // `exact` so it doesn't also match the "Import Key" button behind the page.
  await panel.getByRole("button", { name: "Import", exact: true }).click();
  // Success closes the page (the paste textarea disappears); on error it
  // stays open. Then confirm the key landed on the Keys tab.
  await expect(
    panel.getByPlaceholder("Paste a key here, or browse for a file..."),
  ).toBeHidden();
  await expect(panel.getByText(ownerName).last()).toBeVisible();
  // Wait for the slide-over to finish its exit animation: its onClose
  // fires a deferred nav.collapseToTop() that would dismiss any page the
  // test opens in the meantime.
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();
}

/** Import an armored public key via the Import Key page, expecting it to
 *  be REJECTED with an error matching `reason` (the page stays open). */
export async function importContactExpectRejected(
  panel: Page,
  armoredPublicKey: string,
  reason: RegExp,
): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  await panel
    .getByPlaceholder("Paste a key here, or browse for a file...")
    .fill(armoredPublicKey);
  // Public armor is imported straight from the paste step.
  await panel.getByRole("button", { name: "Import", exact: true }).click();
  await expect(panel.getByRole("alert")).toContainText(reason);
}

/** Pick a workspace mode explicitly (auto-detect only fires for
 *  recognizable PGP blocks, so plain-text tests set the mode by hand). */
export async function setWorkspaceMode(
  panel: Page,
  mode: "Encrypt" | "Decrypt" | "Sign" | "Verify",
): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.getByRole("combobox").first().click();
  await panel.getByRole("option", { name: mode, exact: true }).click();
}

/** Import many contacts in a single file drop -- the drop zone splits a
 *  file into individual public-key blocks -- returning after the batch
 *  "Added N contacts" toast. Far faster than one import at a time; use it
 *  to seed a vault with a lot of key material. */
export async function importContactsBulk(
  panel: Page,
  armoredPublicKeys: string[],
): Promise<void> {
  await goToKeys(panel);
  await panel
    .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt"]')
    .setInputFiles({
      name: "contacts.asc",
      mimeType: "application/pgp-keys",
      buffer: Buffer.from(armoredPublicKeys.join("\n"), "utf8"),
    });
  await expect(
    panel
      .getByText(new RegExp(`Added ${armoredPublicKeys.length} contact`))
      .first(),
  ).toBeVisible();
}

/**
 * One-call test setup: onboard with a password master (generating a first
 * key), then bulk-import `contactKeys` as contacts. Leaves the panel
 * unlocked on the Keys tab with a populated vault -- a ready starting
 * point for storage / backup / recipient tests without repeating the
 * onboarding + import boilerplate in every spec.
 */
export async function seedVault(
  panel: Page,
  password: string,
  contactKeys: string[] = [],
): Promise<void> {
  await onboardWithPassword(panel, password);
  if (contactKeys.length > 0) await importContactsBulk(panel, contactKeys);
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
