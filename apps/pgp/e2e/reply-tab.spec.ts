import { readFile } from "node:fs/promises";
import type { BrowserContext, Page } from "@playwright/test";

import { expect, readStorage, test } from "./fixtures";
import { scanJsHeap } from "./heap";
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

/** The reader's text, read in the page's own context. The heap test
 *  must NOT use `toHaveText`/`getByText` on the canary: Playwright
 *  matches text with regexes in its injected context, and V8 then holds
 *  the matched string as that context's last RegExp match -- in the same
 *  process heap as both pages, so it reads as a leak that isn't ours. */
const readerTextNow = (reader: Page) =>
  readerText(reader).evaluate((el) => el.textContent);

test("the message leaves memory on lock: nothing in either page holds it", async ({
  context,
  panel,
}) => {
  const NEEDLE = "READER-CANARY-2f81";
  await onboardWithPassword(panel, PASSWORD);
  const armored = await encryptToSelf(panel, true);
  await box(panel).fill(armored);
  await panel.getByRole("button", { name: /^decrypt$/i }).click();
  const opened = context.waitForEvent("page");
  await panel.getByRole("button", { name: "Reply", exact: true }).click();
  const reader = await opened;
  await expect.poll(() => readerTextNow(reader)).toBe(PLAINTEXT);

  // Positive control: while shown, the scanner finds it. (The panel and
  // the reader share one renderer process, so a snapshot of either page
  // covers both.)
  expect(
    (await scanJsHeap(reader, [NEEDLE]))[NEEDLE],
    "control: the message is in the heap while the reader shows it",
  ).toBeGreaterThan(0);

  await lockMasterViaPalette(panel);
  await expect(reader.getByText("Unlock to decrypt")).toBeVisible();

  const locked = await strongRetainers(reader, NEEDLE);
  expect(
    locked.count,
    `nothing may hold the message once locked${locked.report}`,
  ).toBe(0);
  expect(
    (await scanJsHeap(reader, [NEEDLE]))[NEEDLE],
    "the message must be gone from the heap snapshot once locked",
  ).toBe(0);

  // And it comes back on unlock (same scanner, same needle).
  await unlockWithPassword(panel, PASSWORD);
  await expect.poll(() => readerTextNow(reader)).toBe(PLAINTEXT);
  expect((await scanJsHeap(reader, [NEEDLE]))[NEEDLE]).toBeGreaterThan(0);
});

test("a duplicated reader tab is locked too", async ({ context, panel }) => {
  const reader = await openReader(context, panel);
  await expect(readerText(reader)).toHaveText(PLAINTEXT);
  const copy = await context.newPage();
  await copy.goto(reader.url());
  await expect(readerText(copy)).toHaveText(PLAINTEXT);

  await lockMasterViaPalette(panel);
  for (const tab of [reader, copy]) {
    await expect(tab.getByText("Unlock to decrypt")).toBeVisible();
    await expect(readerText(tab)).toHaveText("");
    await expect(tab.getByText("Signature verified")).toHaveCount(0);
  }
});
