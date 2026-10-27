import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures";
import {
  importContact,
  onboardWithPassword,
  setWorkspaceMode,
  verifySignedMessage,
} from "./helpers";
import { keyBySlug } from "./keys";

const PASSWORD = "correct horse battery staple";

const alice = keyBySlug("standard");

/** Address the message to Alice through the recipient box. */
async function addAlice(panel: Page) {
  const input = panel.getByRole("combobox", { name: "Recipients" });
  await input.fill("alice");
  await input.press("Enter");
  await expect(panel.getByTitle(new RegExp(alice.label))).toHaveCount(1);
  // Until its exit animation ends, the closing list still owns Escape.
  await expect(
    panel.locator("[data-radix-popper-content-wrapper]"),
  ).toHaveCount(0);
}

test("the reset button clears the recipients with the message", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, alice.publicKey);
  await setWorkspaceMode(panel, "Encrypt");
  await addAlice(panel);
  await panel.locator("#pgp-input").fill("hello");

  await panel.getByRole("button", { name: "Clear input and output" }).click();

  await expect(panel.locator("#pgp-input")).toHaveValue("");
  await expect(panel.getByTitle(new RegExp(alice.label))).toHaveCount(0);
});

test("double Escape clears recipients alone, and Undo brings them back", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, alice.publicKey);
  await setWorkspaceMode(panel, "Encrypt");
  await addAlice(panel);

  // Nothing written: the recipients alone are worth clearing.
  await panel.locator("#pgp-input").focus();
  await panel.keyboard.press("Escape");
  await panel.keyboard.press("Escape");
  await expect(panel.getByTitle(new RegExp(alice.label))).toHaveCount(0);

  await panel.getByRole("button", { name: "Undo" }).click();
  await expect(panel.getByTitle(new RegExp(alice.label))).toHaveCount(1);
  // Until its exit animation ends, the closing list still owns Escape.
  await expect(
    panel.locator("[data-radix-popper-content-wrapper]"),
  ).toHaveCount(0);
});

test("switching mode dismisses the last mode's toast", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await setWorkspaceMode(panel, "Encrypt");
  await panel.locator("#pgp-input").fill("hello");
  await panel.keyboard.press("Escape");
  await panel.keyboard.press("Escape");
  await expect(panel.getByText("Workspace cleared")).toBeVisible();

  // Automatic too: pasted ciphertext of another kind switches mode.
  await panel.locator("#pgp-input").fill(alice.signedMessage);
  await expect(panel.getByRole("radio", { name: "Verify" })).toBeChecked();
  await expect(panel.getByText("Workspace cleared")).toHaveCount(0);
});

test("editing a signed message after leaving Verify stays in that mode", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await setWorkspaceMode(panel, "Encrypt");
  const box = panel.locator("#pgp-input");
  // Arriving armor still picks the mode for you...
  await box.fill(alice.signedMessage);
  await expect(panel.getByRole("radio", { name: "Verify" })).toBeChecked();

  // ...but once you pick another, typing does not take it back.
  await panel.getByRole("radio", { name: "Encrypt", exact: true }).click();
  await box.press("End");
  await box.pressSequentially("more");
  await expect(
    panel.getByRole("radio", { name: "Encrypt", exact: true }),
  ).toBeChecked();
});

test("a verified message shows its verdict over the signed text alone", async ({
  panel,
}) => {
  // Like a decrypted message: the signer's card, then only the text the
  // signature covers -- the pasted armor is gone, not under it.
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, alice.publicKey);
  await verifySignedMessage(panel, alice.signedMessage);

  const verdict = panel.getByText("Signature verified");
  await expect(verdict).toBeVisible();
  await expect(panel.locator("#pgp-input")).toHaveCount(0);
  const text = panel.locator("pre").filter({ hasText: "BEGIN PGP" });
  await expect(text).toHaveCount(0);

  // Back returns to the message as it was pasted.
  await panel.getByRole("button", { name: "Back" }).click();
  await expect(panel.locator("#pgp-input")).toHaveValue(alice.signedMessage);
});

test("a double-Escape clear puts focus back in the message box", async ({
  panel,
}) => {
  // A clear is "start again": the next thing to do is type.
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, alice.publicKey);
  await setWorkspaceMode(panel, "Encrypt");
  await addAlice(panel);
  const box = panel.locator("#pgp-input");
  await box.fill("draft to clear");

  await box.press("Escape");
  await box.press("Escape");

  await expect(box).toHaveValue("");
  await expect(box).toBeFocused();
});

test("the reset button puts focus back in the message box", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await setWorkspaceMode(panel, "Encrypt");
  const box = panel.locator("#pgp-input");
  await box.fill("something");

  await panel.getByRole("button", { name: "Clear input and output" }).click();

  await expect(box).toBeFocused();
});

test("Clear text puts focus back in the message box", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await setWorkspaceMode(panel, "Verify");
  const box = panel.locator("#pgp-input");
  await box.fill("not a signed message");

  await panel.getByRole("button", { name: "Clear text" }).click();

  await expect(box).toHaveValue("");
  await expect(box).toBeFocused();
});
