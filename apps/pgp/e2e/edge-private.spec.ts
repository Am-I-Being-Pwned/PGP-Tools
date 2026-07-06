import type { Page } from "@playwright/test";

import { edgeKey } from "./edge-keys";
import { expect, test } from "./fixtures";
import {
  onboardWithPasswordSkipKey,
  signInWorkspace,
  unlockOnlyKey,
} from "./helpers";

const PASSWORD = "correct horse battery staple";

/** Drive the Import Key flow for a passphrase-protected private key up to
 *  (and including) the final Import click: paste -> unlock (source
 *  passphrase) -> re-protect with `PASSWORD`. Assertions stay in the tests. */
async function driveProtectedImport(
  panel: Page,
  armoredPrivateKey: string,
  sourcePassphrase: string,
): Promise<void> {
  await panel.getByRole("tab", { name: "Keys" }).click();
  await panel.getByRole("button", { name: "Import Key" }).click();
  await panel
    .getByPlaceholder("Paste a key here, or browse for a file...")
    .fill(armoredPrivateKey);
  await panel.getByRole("button", { name: "Next" }).click();

  // Unlock step: the key announces its own passphrase protection.
  await expect(
    panel.getByText("This key is protected with a passphrase", {
      exact: false,
    }),
  ).toBeVisible();
  await panel.getByPlaceholder("Key passphrase").fill(sourcePassphrase);
  await panel.getByRole("button", { name: "Next" }).click();

  // Protect step: re-protect with a password master.
  await panel.locator('input[name="protection"]').nth(1).check();
  await panel.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await panel.getByLabel("Confirm password").fill(PASSWORD);
  await panel.getByRole("button", { name: "Import", exact: true }).click();
}

// Private keys as they actually arrive from GnuPG: S2K-protected under a
// source passphrase (the default `gpg --export-secret-keys` shape) and
// the offline-primary variant (`--export-secret-subkeys`, primary secret
// stubbed out). The extension re-protects on import, so the unlock step
// must round-trip the source passphrase correctly -- and fail legibly
// when it can't.

test("imports a passphrase-protected private key and signs with it", async ({
  panel,
}) => {
  const key = edgeKey("protectedPrivate");
  await onboardWithPasswordSkipKey(panel, PASSWORD);

  await driveProtectedImport(panel, key.privateKey ?? "", key.passphrase ?? "");
  // Success closes the slide-over and the key lands on the Keys tab.
  await expect(
    panel.getByPlaceholder("Paste a key here, or browse for a file..."),
  ).toBeHidden();
  await expect(panel.getByText("Petra Protected").last()).toBeVisible();

  // Prove the imported key is actually usable end-to-end.
  await unlockOnlyKey(panel, PASSWORD);
  await signInWorkspace(panel, "signed with an imported protected key");
});

test("rejects a wrong source passphrase with a clear error", async ({
  panel,
}) => {
  const key = edgeKey("protectedPrivate");
  await onboardWithPasswordSkipKey(panel, PASSWORD);

  await driveProtectedImport(panel, key.privateKey ?? "", "not the passphrase");
  await expect(panel.getByText("Incorrect passphrase")).toBeVisible();
  // The flow stays open so the user can go back and retry.
  await expect(panel.getByRole("button", { name: "Import", exact: true }))
    .toBeVisible();
});

test("surfaces a legible error for an offline-primary key (stubbed secret)", async ({
  panel,
}) => {
  const key = edgeKey("offlinePrimary");
  await onboardWithPasswordSkipKey(panel, PASSWORD);

  await driveProtectedImport(panel, key.privateKey ?? "", key.passphrase ?? "");
  // The primary key's secret is a GNU-dummy stub, so re-protection cannot
  // succeed -- but the failure must be a readable error naming the cause
  // and the fix, not a crash or a silent no-op.
  await expect(
    panel.getByText(/offline primary key/).first(),
  ).toBeVisible();
  // Nothing was half-imported: the key never appears on the Keys tab
  // (still mounted behind the slide-over).
  await expect(panel.getByText("Oscar Offline")).toHaveCount(0);
});
