import { readFile } from "node:fs/promises";
import type { BrowserContext, Page } from "@playwright/test";

import { expect, readStorage, test } from "./fixtures";
import { strongRetainers } from "./heap-retainers";
import {
  lockMasterViaPalette,
  onboardWithPassword,
  runPaletteAction,
  setWorkspaceMode,
  unlockWithPassword,
} from "./helpers";

// Reply moves the decrypted message into a READER tab -- a dumb view with
// no vault or keys -- and turns the panel into the reply, addressed to
// the signer. The panel owns the message: the tab shows it only while
// the panel is unlocked, drops it on lock, gets it back on unlock, and
// loses it for good when the panel closes.

const PASSWORD = "correct horse battery staple";
const PLAINTEXT = "READER-CANARY-2f81 are we still on for Thursday?";

const box = (page: Page) => page.getByLabel("Message input");

/** Encrypt PLAINTEXT to the one own key, optionally signed by it, and
 *  return the armor (read back from the download). */
async function encryptToSelf(panel: Page, signed: boolean): Promise<string> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await setWorkspaceMode(panel, "Encrypt");
  await panel.getByRole("combobox", { name: "Recipients" }).click();
  await panel.getByRole("option").first().click();
  const sign = panel.getByRole("switch", { name: "Sign", exact: true });
  if ((await sign.getAttribute("aria-checked")) !== String(signed)) {
    await sign.click();
  }
  await box(panel).fill(PLAINTEXT);
  await panel.getByRole("button", { name: /^encrypt$/i }).click();
  const download = panel.waitForEvent("download");
  await panel.getByRole("button", { name: "Download" }).click();
  const armored = await readFile(await (await download).path(), "utf8");
  await panel.getByRole("button", { name: "Clear input and output" }).click();
  return armored;
}

async function decrypt(panel: Page, armored: string): Promise<void> {
  await box(panel).fill(armored);
  await panel.getByRole("button", { name: /^decrypt$/i }).click();
  await expect(panel.getByText(PLAINTEXT).first()).toBeVisible();
}

/** Decrypt a self-signed message, press Reply, return the reader tab. */
async function openReader(context: BrowserContext, panel: Page): Promise<Page> {
  await onboardWithPassword(panel, PASSWORD);
  await decrypt(panel, await encryptToSelf(panel, true));
  const opened = context.waitForEvent("page");
  await panel.getByRole("button", { name: "Reply", exact: true }).click();
  const reader = await opened;
  await reader.waitForLoadState();
  return reader;
}

const readerText = (reader: Page) => reader.locator("#message");

test("Reply shows the message in a reader tab and turns the panel into the reply", async ({
  context,
  panel,
}) => {
  const reader = await openReader(context, panel);

  await expect(readerText(reader)).toHaveText(PLAINTEXT);
  // The panel's own signer card, verified.
  await expect(reader.getByText("E2E Test").first()).toBeVisible();
  await expect(reader.getByText("Signature verified")).toBeVisible();
  await expect(reader).toHaveTitle("Message - PGP Tools");
  expect(reader.url()).toMatch(/reader\.html#[0-9a-f]{32}$/);

  // The panel is the reply: encrypt, addressed to the signer, empty --
  // and it no longer shows the message itself.
  await expect(panel.getByRole("combobox").first()).toHaveText(/Encrypt/);
  await expect(panel.getByRole("button", { name: /^Remove / })).toBeVisible();
  await expect(box(panel)).toHaveValue("");
  await expect(panel.getByText(PLAINTEXT)).toHaveCount(0);

  // Nothing about it reached storage.
  for (const area of ["local", "sync", "session"] as const) {
    expect(JSON.stringify(await readStorage(panel, area))).not.toContain(
      "READER-CANARY",
    );
  }
});

test("the shortcut and the command palette open Reply too", async ({
  context,
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  const armored = await encryptToSelf(panel, true);

  await decrypt(panel, armored);
  let opened = context.waitForEvent("page");
  await panel.keyboard.press("ControlOrMeta+Shift+R");
  let reader = await opened;
  await expect(readerText(reader)).toHaveText(PLAINTEXT);
  await reader.close();

  // Reply left the panel as the (empty) reply; decrypt again from there.
  await decrypt(panel, armored);
  opened = context.waitForEvent("page");
  await runPaletteAction(panel, "Reply to sender");
  reader = await opened;
  await expect(readerText(reader)).toHaveText(PLAINTEXT);
});

test("no Reply without a verified signer", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await decrypt(panel, await encryptToSelf(panel, false));
  await expect(panel.getByRole("button", { name: "Download" })).toBeVisible();
  await expect(
    panel.getByRole("button", { name: "Reply", exact: true }),
  ).toHaveCount(0);
});

test("locking the panel clears the reader; unlocking shows the message again", async ({
  context,
  panel,
}) => {
  const reader = await openReader(context, panel);
  await expect(readerText(reader)).toHaveText(PLAINTEXT);

  await lockMasterViaPalette(panel);
  await expect(reader.getByText("Unlock to decrypt")).toBeVisible();
  await expect(reader.getByText("Signature verified")).toHaveCount(0);
  await expect(readerText(reader)).toHaveText("");
  // Sealed in the panel, not held as a string by it.
  const panelHeap = await strongRetainers(panel, "READER-CANARY");
  expect(
    panelHeap.count,
    `the panel must not retain the message while locked${panelHeap.report}`,
  ).toBe(0);

  await unlockWithPassword(panel, PASSWORD);
  await expect(readerText(reader)).toHaveText(PLAINTEXT);
});

test("closing the panel closes the reader tab", async ({ context, panel }) => {
  const reader = await openReader(context, panel);
  await expect(readerText(reader)).toHaveText(PLAINTEXT);

  const closed = reader.waitForEvent("close");
  await panel.close();
  await closed;
  expect(reader.isClosed()).toBe(true);
});

test("a reader nobody opened shows nothing", async ({
  context,
  extensionId,
}) => {
  const page = await context.newPage();
  await page.goto(
    `chrome-extension://${extensionId}/reader.html#${"0".repeat(32)}`,
  );
  await expect(page.getByText(/no longer available/)).toBeVisible();
  await expect(readerText(page)).toHaveText("");
});
