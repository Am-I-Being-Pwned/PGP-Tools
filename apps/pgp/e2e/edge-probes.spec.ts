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

test("global drop routes a binary key export to import, not the workspace", async ({
  panel,
}) => {
  const key = edgeKey("binary");
  await onboardWithPassword(panel, PASSWORD);

  // Simulate dragging a raw `gpg --export` file (no extension, no armor)
  // onto the app: dragenter mounts the global overlay, then the drop
  // lands on it -- the exact shape that used to fall through to the
  // workspace's encrypt catch-all.
  await panel.evaluate(async (b64) => {
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const file = new File([bytes], "openpgp");
    const dt = new DataTransfer();
    dt.items.add(file);
    const opts = { bubbles: true, cancelable: true, dataTransfer: dt };
    window.dispatchEvent(new DragEvent("dragenter", opts));
    await new Promise((resolve) => setTimeout(resolve, 100));
    const overlayLabel = [...document.querySelectorAll("p")].find(
      (p) => p.textContent === "Drop to import",
    );
    if (!overlayLabel) throw new Error("global drop overlay did not mount");
    overlayLabel.dispatchEvent(new DragEvent("drop", opts));
  }, key.publicKeyBinaryB64 ?? "");

  // The drop routes to the Keys tab and opens Import prefilled with the
  // armored form of the binary key.
  await expect(panel.getByRole("region", { name: "Import key" })).toBeVisible();
  await expect(panel.getByText(/Detected:/)).toBeVisible();
  // Rendered capitalized via CSS; the DOM text is lowercase.
  await expect(panel.getByText("public", { exact: true })).toBeVisible();
  await panel.getByRole("button", { name: "Import", exact: true }).click();
  await expect(
    panel.getByRole("region", { name: "Import key" }),
  ).toBeHidden();
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
