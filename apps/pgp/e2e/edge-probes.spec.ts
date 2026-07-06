import { edgeKey } from "./edge-keys";
import { expect, test } from "./fixtures";
import { goToKeys, importContact, onboardWithPassword } from "./helpers";

const PASSWORD = "correct horse battery staple";

// Probes for interop hazards a correspondent's tooling can trigger:
// a refreshed key (extended expiry) re-sent to the user, a binary
// (non-armored) .gpg export, and a user ID carrying Unicode bidi
// overrides. Each asserts the behavior the user needs, so a regression
// here means "the extension became the blocker".

test("re-importing a refreshed key updates the stored expiry", async ({
  panel,
}) => {
  const key = edgeKey("refreshed");
  await onboardWithPassword(panel, PASSWORD);

  await test.step("import the original (1y-expiry) export", async () => {
    await importContact(panel, key.publicKey);
    const v1Year = new Date(key.expiresAt ?? 0).getFullYear();
    await expect(
      panel.getByText(new RegExp(`Expires .*${v1Year}`)),
    ).toBeVisible();
  });

  await test.step("re-import the refreshed (3y-expiry) export", async () => {
    await goToKeys(panel);
    await panel
      .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt"]')
      .setInputFiles({
        name: "refreshed.asc",
        mimeType: "application/pgp-keys",
        buffer: Buffer.from(key.publicKeyUpdated ?? "", "utf8"),
      });
    // The refresh must land -- silently keeping the stale expiry means
    // encryption to this contact starts failing when v1 lapses.
    const v2Year = new Date(key.updatedExpiresAt ?? 0).getFullYear();
    await expect(
      panel.getByText(new RegExp(`Expires .*${v2Year}`)),
    ).toBeVisible();
  });
});

test("imports a binary (non-armored) .gpg public key file", async ({
  panel,
}) => {
  const key = edgeKey("binary");
  await onboardWithPassword(panel, PASSWORD);
  await goToKeys(panel);

  // The drop zone's accept list includes .gpg, so raw OpenPGP bytes (the
  // `gpg --export` default) must import -- not silently mangle through a
  // UTF-8 text decode.
  await panel
    .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt"]')
    .setInputFiles({
      name: "bianca.gpg",
      mimeType: "application/octet-stream",
      buffer: Buffer.from(key.publicKeyBinaryB64 ?? "", "base64"),
    });
  await expect(panel.getByText(/Added 1 contact/).first()).toBeVisible();
  await expect(panel.getByText("Bianca Binary").first()).toBeVisible();
});

test("strips bidi override characters from displayed user IDs", async ({
  panel,
}) => {
  const key = edgeKey("bidiUid");
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, key.publicKey);

  // The UID contains U+202E RIGHT-TO-LEFT OVERRIDE, which visually
  // reverses the characters after it -- classic address-spoofing. The
  // rendered contact must not carry the override into the DOM.
  const name = await panel.getByText(/Eve .*Bidi/).first().textContent();
  expect(name).toBeTruthy();
  // U+202A-U+202E (embedding/override) and U+2066-U+2069 (isolates).
  expect(name).not.toMatch(/[\u202A-\u202E\u2066-\u2069]/u);
});
