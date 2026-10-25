import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures";
import {
  importContact,
  onboardWithPassword,
  setWorkspaceMode,
} from "./helpers";
import { keyBySlug } from "./keys";

const PASSWORD = "correct horse battery staple";
const MESSAGE = "Meet me at the usual place at 8. Bring the drive.";

/** Stage a plain file through the workspace's own file input. */
async function attach(panel: Page, name: string, body: string): Promise<void> {
  await panel
    .locator('input[type="file"]:not([accept])')
    .setInputFiles({ name, mimeType: "text/plain", buffer: Buffer.from(body) });
  await expect(panel.getByText(name, { exact: true })).toBeVisible();
}

test.describe("a message with attachments (encrypt)", () => {
  test("attaching keeps the message, and both are encrypted", async ({
    panel,
  }) => {
    await onboardWithPassword(panel, PASSWORD);
    await importContact(panel, keyBySlug("standard").publicKey);
    await setWorkspaceMode(panel, "Encrypt");
    await panel.getByRole("combobox", { name: "Recipients" }).click();
    await panel
      .getByRole("option", { name: /Alice Example/ })
      .first()
      .click();
    await panel.keyboard.press("Escape");
    const box = panel.locator("#pgp-input");
    await box.fill(MESSAGE);

    await attach(panel, "notes.txt", "attached");

    // The message box is still there, still holding what was written.
    await expect(box).toHaveValue(MESSAGE);

    await panel.getByRole("button", { name: /^encrypt$/i }).click();

    // The message counts as a file: two of them, zipped by default.
    await expect(panel.getByText(/2 files zipped and encrypted/)).toBeVisible();

    // Unzipped, each is its own output (the message's is msg.txt.gpg).
    await panel.getByRole("switch", { name: "Zip files" }).click();
    await panel.getByRole("button", { name: /^encrypt$/i }).click();
    await expect(panel.getByText(/2 files encrypted/)).toBeVisible();
  });

  test("typing after attaching keeps the file", async ({ panel }) => {
    await onboardWithPassword(panel, PASSWORD);
    // Attached elsewhere first, then brought to Encrypt: the reported
    // path. Typing the message must not drop the attachment.
    await setWorkspaceMode(panel, "Sign");
    await attach(panel, "notes.txt", "attached");
    await setWorkspaceMode(panel, "Encrypt");
    const box = panel.locator("#pgp-input");
    await box.click();
    await panel.keyboard.type("hello");

    await expect(box).toHaveValue("hello");
    await expect(panel.getByText("notes.txt", { exact: true })).toBeVisible();
  });

  test("outside encrypt, staged files still take the box's place", async ({
    panel,
  }) => {
    await onboardWithPassword(panel, PASSWORD);
    await setWorkspaceMode(panel, "Sign");
    await attach(panel, "notes.txt", "attached");
    await expect(panel.locator("#pgp-input")).toHaveCount(0);
  });
});
