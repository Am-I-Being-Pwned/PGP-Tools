import { readFileSync } from "node:fs";

import type { Page } from "@playwright/test";

import { expect, readStorage, test } from "./fixtures";
import {
  goToKeys,
  importPrivateKey,
  onboardWithPassword,
  onboardWithPasswordSkipKey,
  unlockOnlyKey,
} from "./helpers";
import { PRIVATE_KEY_FIXTURE } from "./private-key";

const PASSWORD = "correct horse battery staple";

// The revocation certificate is the user's escape hatch when a key is
// lost or compromised. Generated keys mint one at creation; imported
// keys can mint one from the details page (unlocked). Either way the
// user must be able to get it OUT -- download or copy -- because a cert
// that only lives inside the vault is useless in the "lost access"
// scenario it exists for.

async function openOnlyKeyDetails(panel: Page) {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Key details" }).first().click();
  await expect(
    panel.getByRole("heading", { name: "Revocation certificate" }),
  ).toBeVisible();
}

/** Close the details slide-over and wait for its exit animation, so the
 *  deferred nav cleanup can't dismiss the next page the test opens. */
async function closeKeyDetails(panel: Page) {
  await panel.getByRole("button", { name: "Back" }).click();
  await expect(
    panel.getByRole("region", { name: /^Key details for/ }),
  ).toBeHidden();
}

test("a generated key ships with a downloadable revocation certificate", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await openOnlyKeyDetails(panel);

  const [download] = await Promise.all([
    panel.waitForEvent("download"),
    panel.getByRole("button", { name: "Download", exact: true }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/^revocation-[0-9A-F]{16}\.asc$/);

  await test.step("the stored certificate is encrypted at rest", async () => {
    const certificate = readFileSync(await download.path(), "utf8");
    expect(certificate).toContain("BEGIN PGP SIGNATURE");
    // A distinctive base64 body line must not appear anywhere in
    // chrome.storage: the cert lives inside the keyring blob, which is
    // AES-GCM-encrypted under the master session before it is written.
    const needle = certificate
      .split("\n")
      .find((line) => line.length >= 40 && !line.startsWith("-"));
    expect(needle).toBeTruthy();
    const local = await readStorage(panel, "local");
    const sync = await readStorage(panel, "sync");
    expect(JSON.stringify({ local, sync })).not.toContain(needle);
  });

  await panel.getByRole("button", { name: "Copy", exact: true }).click();
  await expect(
    panel.getByText("Revocation certificate copied").first(),
  ).toBeVisible();
});

test("an imported key mints its revocation certificate on demand", async ({
  panel,
}) => {
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await importPrivateKey(
    panel,
    PRIVATE_KEY_FIXTURE.privateKey,
    PASSWORD,
    PRIVATE_KEY_FIXTURE.name,
  );

  await test.step("locked key: creating fails with an unlock hint", async () => {
    await openOnlyKeyDetails(panel);
    await panel
      .getByRole("button", { name: "Create revocation certificate" })
      .click();
    await expect(panel.getByText(/Unlock this key first/)).toBeVisible();
    await closeKeyDetails(panel);
  });

  await test.step("unlocked key: certificate is created and persisted", async () => {
    await unlockOnlyKey(panel, PASSWORD);
    await openOnlyKeyDetails(panel);
    await panel
      .getByRole("button", { name: "Create revocation certificate" })
      .click();
    await expect(
      panel.getByText("Revocation certificate created").first(),
    ).toBeVisible();
    await expect(
      panel.getByRole("button", { name: "Download", exact: true }),
    ).toBeVisible();

    // Reopen the page: the certificate was persisted to the keyring,
    // not just held in component state.
    await closeKeyDetails(panel);
    await openOnlyKeyDetails(panel);
    await expect(
      panel.getByRole("button", { name: "Download", exact: true }),
    ).toBeVisible();
    await expect(
      panel.getByRole("button", { name: "Create revocation certificate" }),
    ).toHaveCount(0);
  });
});
