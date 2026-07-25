import type { Page } from "@playwright/test";

import { expect, readStorage, test } from "./fixtures";
import { onboardWithPassword, unlockWithPassword } from "./helpers";

const PASSWORD = "correct horse battery staple";

function tab(panel: Page, name: string) {
  return panel.getByRole("tab", { name });
}

/** The encrypted settings blob as a comparable string. Every settings
 *  write re-encrypts with a fresh IV, so ANY persisted change (e.g.
 *  `activeTab`) shows up as a different blob. */
async function settingsBlob(panel: Page): Promise<string> {
  const stored = await readStorage(panel, "local");
  return JSON.stringify(stored.pgp_settings ?? null);
}

/** Click a tab and wait until the switch has been persisted (the blob
 *  rewrite is what later relaunch steps depend on). */
async function changeTabPersisted(panel: Page, name: string): Promise<void> {
  const before = await settingsBlob(panel);
  await tab(panel, name).click();
  await expect.poll(() => settingsBlob(panel)).not.toBe(before);
}

test("tab switching sticks, and Settings is never the launch tab", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await expect(tab(panel, "Main")).toHaveAttribute("aria-selected", "true");

  await test.step("switching to Settings sticks past the pref-sync echo", async () => {
    await changeTabPersisted(panel, "Settings");
    // Persisting `activeTab` fires storage.onChanged, which re-applies
    // preferences asynchronously. Regression guard: that re-apply used
    // to coerce Settings away, bouncing the user right back off the
    // tab they just clicked. Let the echo land, then re-assert.
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
    // Last tab is Settings; a fresh launch must land on Main instead.
    await panel.reload();
    await unlockWithPassword(panel, PASSWORD);
    await expect(tab(panel, "Main")).toHaveAttribute("aria-selected", "true");
  });

  await test.step("Keys restores across relaunch", async () => {
    await changeTabPersisted(panel, "Keys");
    await panel.reload();
    await unlockWithPassword(panel, PASSWORD);
    await expect(tab(panel, "Keys")).toHaveAttribute("aria-selected", "true");
    await expect(panel.getByRole("heading", { name: "My Keys" })).toBeVisible();
  });

  await test.step("Settings is still reachable after a restore", async () => {
    // The launch restore must not poison in-session navigation: the
    // user can still click over to Settings and stay there.
    await tab(panel, "Settings").click();
    await panel.waitForTimeout(300);
    await expect(tab(panel, "Settings")).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });
});
