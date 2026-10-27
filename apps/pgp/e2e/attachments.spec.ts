import { readFile } from "node:fs/promises";
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
    await panel.getByRole("switch", { name: "Zip", exact: true }).click();
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

  test("Clear text clears the message and keeps the files", async ({
    panel,
  }) => {
    await onboardWithPassword(panel, PASSWORD);
    await setWorkspaceMode(panel, "Encrypt");
    const box = panel.locator("#pgp-input");
    await box.fill(MESSAGE);
    await attach(panel, "notes.txt", "attached");

    await panel.getByRole("button", { name: "Clear text" }).click();
    await expect(box).toHaveValue("");
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

/** Encrypt `text` to the one own key, signed or not; the armor, read
 *  back from the download. */
async function encryptToSelf(
  panel: Page,
  text: string,
  signed: boolean,
): Promise<string> {
  await setWorkspaceMode(panel, "Encrypt");
  await panel.getByRole("combobox", { name: "Recipients" }).click();
  await panel.getByRole("option").first().click();
  await panel.keyboard.press("Escape");
  const sign = panel.getByRole("switch", { name: "Sign", exact: true });
  if ((await sign.getAttribute("aria-checked")) !== String(signed)) {
    await sign.click();
  }
  await panel.locator("#pgp-input").fill(text);
  await panel.getByRole("button", { name: /^encrypt$/i }).click();
  const download = panel.waitForEvent("download");
  await panel.getByRole("button", { name: "Download" }).click();
  const armored = await readFile(await (await download).path(), "utf8");
  await panel.getByRole("button", { name: "Clear input and output" }).click();
  return armored;
}

test.describe("a batch of files (decrypt)", () => {
  test("two files that decrypt to one name are saved apart, and the signer note names what was saved", async ({
    panel,
  }) => {
    await onboardWithPassword(panel, PASSWORD);
    const signed = await encryptToSelf(panel, "signed copy", true);
    const unsigned = await encryptToSelf(panel, "unsigned copy", false);

    // "report.txt.gpg" and "report.txt.asc" both lose their ciphertext
    // extension. The browser would rename the second on disk while the
    // panel still called both "report.txt".
    await attach(panel, "report.txt.gpg", signed);
    await attach(panel, "report.txt.asc", unsigned);
    await setWorkspaceMode(panel, "Decrypt");
    await panel.getByRole("button", { name: /^decrypt$/i }).click();

    // A mixed batch: the note lists each OUTPUT, de-duplicated.
    await expect(panel.getByText(/“report\.txt”: E2E Test/)).toBeVisible();
    await expect(
      panel.getByText(/“report \(2\)\.txt”: not signed/),
    ).toBeVisible();

    const names: string[] = [];
    panel.on("download", (d) => names.push(d.suggestedFilename()));
    await panel.getByRole("button", { name: "Download" }).click();
    await expect.poll(() => names.length).toBe(2);
    expect(names).toEqual(["report.txt", "report (2).txt"]);
  });
});
