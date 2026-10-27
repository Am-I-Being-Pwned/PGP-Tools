import type { Page } from "@playwright/test";

import { edgeKey, MESSAGE } from "./edge-keys";
import { expect, test } from "./fixtures";
import {
  importContact,
  onboardWithPassword,
  setWorkspaceMode,
  verifySignedMessage,
} from "./helpers";

// A green "Signature verified" card vouches for something. What these
// pin is WHAT: exactly the text that was signed, shown beside the
// verdict, and -- for several files -- every file, never just the one
// that happened to set the card last.

const PASSWORD = "correct horse battery staple";
const rachel = edgeKey("rsa4096");
const rita = edgeKey("revoked");

/** Stage files in the workspace's own drop zone. */
async function stageFiles(
  panel: Page,
  files: { name: string; text: string }[],
): Promise<void> {
  await panel
    .locator('input[type="file"]:not([accept])')
    .setInputFiles(
      files.map(({ name, text }) => ({
        name,
        mimeType: "text/plain",
        buffer: Buffer.from(text, "utf8"),
      })),
    );
}

async function verifyStaged(panel: Page): Promise<void> {
  await setWorkspaceMode(panel, "Verify");
  await panel.getByRole("button", { name: /^verify/i }).click();
}

test("a verified message shows exactly the signed text, and when it was signed", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);

  await verifySignedMessage(panel, rachel.signedMessage ?? "");

  await expect(panel.getByText("Signature verified").first()).toBeVisible();
  await expect(panel.getByText("Signed text")).toBeVisible();
  await expect(
    panel.locator("pre").filter({ hasText: MESSAGE }).first(),
  ).toBeVisible();
  await expect(panel.getByText(/^Signed \w/).first()).toBeVisible();
});

test("a signed file's content is shown under the verdict", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();

  await stageFiles(panel, [
    { name: "notice.asc", text: rachel.signedMessage ?? "" },
  ]);
  await verifyStaged(panel);

  await expect(panel.getByText("Signature verified").first()).toBeVisible();
  await expect(
    panel.locator("pre").filter({ hasText: MESSAGE }).first(),
  ).toBeVisible();
});

test("a signed file with text around its signed block is refused", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();

  await stageFiles(panel, [
    {
      name: "notice.asc",
      text: `Pay invoices to account 12345678.\n\n${rachel.signedMessage ?? ""}`,
    },
  ]);
  await verifyStaged(panel);

  await expect(
    panel.getByText(/text outside the signed message/).first(),
  ).toBeVisible();
  await expect(panel.getByText("Signature verified")).toHaveCount(0);
});

test("several files are each verified, and a mixed batch says who signed which", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();

  // Rachel's genuine notice next to one from a key we can't check: the
  // card must not read as Rachel vouching for both.
  await stageFiles(panel, [
    { name: "rachel.asc", text: rachel.signedMessage ?? "" },
    { name: "rita.asc", text: rita.signedMessage ?? "" },
  ]);
  await verifyStaged(panel);

  await expect(
    panel.getByText("Mixed signers"),
  ).toBeVisible();
  await expect(
    panel.getByText(/rachel\.asc: Rachel Rsa4096 · rita\.asc: Unknown signer/),
  ).toBeVisible();
  await expect(panel.getByText("Signature verified")).toHaveCount(0);
});

test("several files from the same signer get that signer's card", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();

  await stageFiles(panel, [
    { name: "one.asc", text: rachel.signedMessage ?? "" },
    { name: "two.asc", text: rachel.signedMessage ?? "" },
  ]);
  await verifyStaged(panel);

  await expect(panel.getByText("Signature verified").first()).toBeVisible();
  await expect(panel.getByText("Rachel Rsa4096").first()).toBeVisible();
});

test("one tampered file fails the whole batch", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();

  const tampered = (rachel.signedMessage ?? "").replace(
    MESSAGE,
    MESSAGE.replace("quick", "sneaky"),
  );
  await stageFiles(panel, [
    { name: "good.asc", text: rachel.signedMessage ?? "" },
    { name: "bad.asc", text: tampered },
  ]);
  await verifyStaged(panel);

  await expect(panel.getByText(/tampered/).first()).toBeVisible();
  await expect(panel.getByText("Signature verified")).toHaveCount(0);
});
