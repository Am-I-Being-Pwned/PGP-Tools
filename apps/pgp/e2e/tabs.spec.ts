import type { Page } from "@playwright/test";

import { expect, readStorage, test } from "./fixtures";
import {
  importContact,
  onboardWithPassword,
  unlockWithPassword,
} from "./helpers";
import { keyBySlug } from "./keys";

const PASSWORD = "correct horse battery staple";

function tab(panel: Page, name: string) {
  return panel.getByRole("tab", { name });
}

/** The encrypted settings blob as a comparable string. Every settings
 *  write re-encrypts with a fresh IV, so ANY persisted change shows up
 *  as a different blob -- which is how the test below proves a tab
 *  switch persists nothing. */
async function settingsBlob(panel: Page): Promise<string> {
  const stored = await readStorage(panel, "local");
  return JSON.stringify(stored.pgp_settings ?? null);
}

/** Click a tab and confirm it took. Switching writes nothing: which tab
 *  is open is UI state for this panel session, not a preference. */
async function changeTab(panel: Page, name: string): Promise<void> {
  await tab(panel, name).click();
  await expect(tab(panel, name)).toHaveAttribute("aria-selected", "true");
}

test("message input is focused when the panel opens on Main", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await expect(panel.locator("#pgp-input")).toBeFocused();

  await test.step("focus also lands after an unlock relaunch", async () => {
    await panel.reload();
    await unlockWithPassword(panel, PASSWORD);
    await expect(panel.locator("#pgp-input")).toBeFocused();
  });

  await test.step("the open-focus is one-shot, not per-visit", async () => {
    // Navigating away and back mid-session must not steal focus into the
    // textarea -- only the launch does that.
    await changeTab(panel, "Keys");
    await changeTab(panel, "Main");
    await expect(panel.locator("#pgp-input")).not.toBeFocused();
  });
});

test("the panel always launches on Main, wherever you left it", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await expect(tab(panel, "Main")).toHaveAttribute("aria-selected", "true");

  await test.step("switching tabs sticks within the session", async () => {
    await changeTab(panel, "Settings");
    // Re-applying preferences (on unlock, and on every storage.onChanged
    // echo) used to be able to move the user: it restored a saved tab.
    // Nothing does that now, but the echo still fires -- so let it land
    // and re-assert.
    await panel.waitForTimeout(300);
    await expect(tab(panel, "Settings")).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await expect(
      panel.getByRole("heading", { name: "Key storage" }),
    ).toBeVisible();
  });

  await test.step("Settings does not restore across relaunch", async () => {
    await panel.reload();
    await unlockWithPassword(panel, PASSWORD);
    await expect(tab(panel, "Main")).toHaveAttribute("aria-selected", "true");
  });

  await test.step("nor does Keys -- the workspace is what the app is for", async () => {
    // The regression this guards: importing, generating and revealing a
    // key all end on the Keys tab, so persisting the tab meant nearly
    // every launch opened on Keys.
    await changeTab(panel, "Keys");
    await panel.reload();
    await unlockWithPassword(panel, PASSWORD);
    await expect(tab(panel, "Main")).toHaveAttribute("aria-selected", "true");
    await expect(panel.locator("#pgp-input")).toBeVisible();
  });

  await test.step("a tab switch writes nothing to storage", async () => {
    // Which tab is open is not a preference, so it must not re-encrypt
    // the settings blob (or sync it to another device).
    const before = await settingsBlob(panel);
    await changeTab(panel, "Keys");
    await changeTab(panel, "Settings");
    await panel.waitForTimeout(300);
    expect(await settingsBlob(panel)).toBe(before);
  });
});

test("Tab skips the tab bar, the mode switch and the recipients' clear button", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  // Two recipients, so the clear-all button is drawn.
  await importContact(panel, keyBySlug("standard").publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();
  const recipients = panel.getByRole("combobox", { name: "Recipients" });
  for (let i = 0; i < 2; i++) {
    await recipients.click();
    await panel.getByRole("option").first().click();
  }
  await expect(
    panel.getByRole("button", { name: "Clear all recipients" }),
  ).toBeVisible();

  // Walk the whole Tab order once round and record every stop.
  const stops = new Set<string>();
  await panel.locator("body").focus();
  for (let i = 0; i < 40; i++) {
    await panel.keyboard.press("Tab");
    stops.add(
      await panel.evaluate(() => {
        const el = document.activeElement;
        if (!el) return "";
        return `${el.getAttribute("role") ?? el.tagName}:${
          el.getAttribute("aria-label") ?? el.textContent.trim()
        }`;
      }),
    );
  }
  const roles = [...stops].map((s) => s.split(":")[0]);
  expect(roles).not.toContain("tab");
  expect(roles).not.toContain("radio");
  expect([...stops].some((s) => s.includes("Clear all recipients"))).toBe(
    false,
  );
  expect([...stops].some((s) => s.startsWith("combobox:"))).toBe(true);
});
