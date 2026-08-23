import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures";
import {
  goToKeys,
  importContact,
  importFileInPanel,
  onboardWithPassword,
} from "./helpers";
import { keyBySlug } from "./keys";
import { PRIVATE_KEY_FIXTURE } from "./private-key";

const PASSWORD = "correct horse battery staple";
const contact = keyBySlug("standard");

/** Drop key text on the contacts drop zone, the way a user would. */
async function dropOnContacts(panel: Page, armored: string) {
  await goToKeys(panel);
  await panel
    .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt"]')
    .setInputFiles({
      name: "key.asc",
      mimeType: "application/pgp-keys",
      buffer: Buffer.from(armored, "utf8"),
    });
}

test("importing shows the key, never its armor", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  await importFileInPanel(panel, contact.publicKey);

  const page = panel.getByRole("region", { name: "Import key" });
  // The whole point: identity and fingerprint, not a base64 blob.
  await expect(page.getByText(contact.label).first()).toBeVisible();
  await expect(page.getByText("Fingerprint")).toBeVisible();
  await expect(page).not.toContainText("BEGIN PGP");
  await expect(page).not.toContainText("END PGP");

  await panel.getByRole("button", { name: "Import contact" }).click();
  await expect(page).toBeHidden();
  await expect(panel.getByText(contact.label).first()).toBeVisible();
});

test("the imported card is highlighted in the list", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await dropOnContacts(panel, contact.publicKey);
  await panel.getByRole("button", { name: "Import contact" }).click();

  // The card pulses so the eye lands on what just changed. The class is
  // dropped on a timer, so this asserts while it is still on.
  await expect(panel.locator(".just-imported")).toHaveCount(1);
  await expect(panel.locator(".just-imported")).toContainText(contact.label);
});

test("re-importing an unchanged key says so, and offers to show it", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, contact.publicKey);

  await dropOnContacts(panel, contact.publicKey);

  // The preview STAYS: sliding in and straight back out again was
  // disorienting. Nothing is written, and the offered action is the
  // useful one -- go and look at the key we already have.
  const page = panel.getByRole("region", { name: "Import key" });
  await expect(page.getByText("Already in your keys")).toBeVisible();
  await expect(
    panel.getByRole("button", { name: "Import contact" }),
  ).toHaveCount(0);

  await panel.getByRole("button", { name: "Show it in your keys" }).click();
  await expect(page).toBeHidden();
  await expect(panel.locator(".just-imported")).toContainText(contact.label);
  // Still exactly one card for this key -- not a second copy.
  await expect(panel.getByText(contact.label)).toHaveCount(1);
});

test("a private key previews before the protection step", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  await importFileInPanel(panel, PRIVATE_KEY_FIXTURE.privateKey);

  const page = panel.getByRole("region", { name: "Import key" });
  await expect(page.getByText("Private key")).toBeVisible();
  await expect(page).not.toContainText("BEGIN PGP");
  // Public keys import outright; a private one continues to protection.
  await expect(
    panel.getByRole("button", { name: "Import contact" }),
  ).toHaveCount(0);
  await panel.getByRole("button", { name: "Continue" }).click();
  await expect(panel.getByText("Choose how to protect")).toBeVisible();
});

test("importing a key pasted while encrypting hands you back to the workspace", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("#pgp-input").fill(contact.publicKey);

  // The banner routes to the import flow...
  await panel.getByRole("button", { name: "Import it as a contact" }).click();
  await panel.getByRole("button", { name: "Import contact" }).click();

  // ...and importing hands you straight back to what you were doing,
  // rather than stranding you on the Keys tab.
  await expect(panel.locator("#pgp-input")).toBeVisible();
  await expect(panel.getByRole("tab", { name: "Main" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
});

test("Back from an import you never asked for returns in one press", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("#pgp-input").fill(contact.publicKey);
  await panel.getByRole("button", { name: "Import it as a contact" }).click();

  const page = panel.getByRole("region", { name: "Import key" });
  await expect(page).toBeVisible();
  // One Back: no empty drop zone in between (there was no source step),
  // and no detour via the Keys tab.
  await panel.getByRole("button", { name: "Back" }).click();
  await expect(page).toBeHidden();
  await expect(panel.locator("#pgp-input")).toBeVisible();
  await expect(panel.getByRole("tab", { name: "Main" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
});

test("a key you already have is not offered for import", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, contact.publicKey);

  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("#pgp-input").fill(contact.publicKey);

  // We know we have it, so don't pretend otherwise.
  await expect(
    panel.getByText(new RegExp(`You already have ${contact.label}'s key`)),
  ).toBeVisible();
  await expect(
    panel.getByRole("button", { name: "Import it as a contact" }),
  ).toHaveCount(0);

  // The action takes you to the key, highlighted.
  await panel.getByRole("button", { name: "Show it in your keys" }).click();
  await expect(panel.locator(".just-imported")).toContainText(contact.label);
});

test("the paste box takes a key without ever holding one", async ({
  panel,
  context,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();

  // Focused on open, so the paste has an obvious home and needs no aiming.
  const box = panel.getByLabel("Paste a key");
  await expect(box).toBeFocused();

  // It is a target, not a field: typing lands nowhere and says why.
  await panel.keyboard.type("hello");
  await expect(box).toHaveValue("");
  await expect(panel.getByText(/Paste the whole key block/)).toBeVisible();

  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await panel.evaluate(
    (t) => navigator.clipboard.writeText(t),
    contact.publicKey,
  );
  await box.focus();
  await panel.keyboard.press(
    process.platform === "darwin" ? "Meta+V" : "Control+V",
  );

  // Straight to the preview, and the armor is never rendered -- not in
  // the box it was pasted into, not anywhere else.
  const page = panel.getByRole("region", { name: "Import key" });
  await expect(page.getByText("Fingerprint")).toBeVisible();
  await expect(page).not.toContainText("BEGIN PGP");
  await expect(panel.getByLabel("Paste a key")).toHaveCount(0);
});
