import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures";
import { onboardWithPassword, setWorkspaceMode } from "./helpers";

const PASSWORD = "correct horse battery staple";

/** Drop focus entirely so keystrokes land on <body>. */
async function blurActive(panel: Page): Promise<void> {
  await panel.evaluate(() => {
    (document.activeElement as HTMLElement | null)?.blur();
  });
}

test.describe("type-to-focus (encrypt and sign modes)", () => {
  test("stray typing with nothing focused lands in the message box", async ({
    panel,
  }) => {
    await onboardWithPassword(panel, PASSWORD);
    const input = panel.locator("#pgp-input");
    await expect(input).toBeFocused();

    await blurActive(panel);
    await expect(input).not.toBeFocused();

    await panel.keyboard.type("hi");
    await expect(input).toBeFocused();
    await expect(input).toHaveValue("hi");
  });

  test("refocus appends at the end instead of clobbering existing text", async ({
    panel,
  }) => {
    await onboardWithPassword(panel, PASSWORD);
    const input = panel.locator("#pgp-input");
    await input.fill("abc");
    await blurActive(panel);

    await panel.keyboard.type("d");
    await expect(input).toHaveValue("abcd");
  });

  test("sign mode refocuses too", async ({ panel }) => {
    await onboardWithPassword(panel, PASSWORD);
    await setWorkspaceMode(panel, "Sign");
    const input = panel.locator("#pgp-input");
    await blurActive(panel);

    await panel.keyboard.type("hi");
    await expect(input).toBeFocused();
    await expect(input).toHaveValue("hi");
  });

  test("decrypt and verify modes are left alone", async ({ panel }) => {
    await onboardWithPassword(panel, PASSWORD);
    const input = panel.locator("#pgp-input");
    for (const mode of ["Decrypt", "Verify"] as const) {
      await setWorkspaceMode(panel, mode);
      await blurActive(panel);

      await panel.keyboard.type("x");
      await expect(input).not.toBeFocused();
      await expect(input).toHaveValue("");
    }
  });

  test("typing on another tab does not focus the hidden workspace box", async ({
    panel,
  }) => {
    await onboardWithPassword(panel, PASSWORD);
    await panel.getByRole("tab", { name: "Keys" }).click();
    await blurActive(panel);

    await panel.keyboard.type("x");
    const input = panel.locator("#pgp-input");
    await expect(input).not.toBeFocused();

    // Back on Main the box is still pristine.
    await panel.getByRole("tab", { name: "Main" }).click();
    await expect(input).toHaveValue("");
  });

  test("typing while a real field is focused stays in that field", async ({
    panel,
  }) => {
    await onboardWithPassword(panel, PASSWORD);
    // The mode combobox owns its own type-ahead; keystrokes on it must
    // not be stolen into the message box.
    const trigger = panel.getByRole("combobox").first();
    await trigger.focus();
    await panel.keyboard.type("x");
    await expect(panel.locator("#pgp-input")).not.toBeFocused();
  });
});
