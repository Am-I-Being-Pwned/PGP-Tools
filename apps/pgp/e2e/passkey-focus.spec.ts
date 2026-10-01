import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures";
import { addPrfAuthenticator } from "./webauthn";

// A passkey prompt is not always an in-browser overlay. macOS's Touch ID
// sheet is, but Windows Hello is a separate system window: opening it
// moves window focus out of Chrome, and `chrome.windows.onFocusChanged`
// fires. With "lock when I switch away" on (the strictest preset), that
// used to lock the vault in the middle of the very prompt the user was
// answering.
//
// No Windows needed to reproduce it: hold a ceremony open, then move
// Chrome's window focus elsewhere -- the same event Windows Hello causes.

/** Hold every `navigator.credentials.get` until released, so the test
 *  controls how long the "prompt" is open. The real virtual
 *  authenticator still runs the ceremony once released. */
async function installCeremonyGate(panel: Page): Promise<void> {
  await panel.addInitScript(`(() => {
  const state = { hold: false, entered: 0 };
  Object.defineProperty(window, "__ceremonyGate", { value: state });
  const container = navigator.credentials;
  const original = container.get.bind(container);
  Object.defineProperty(container, "get", {
    configurable: true,
    writable: true,
    value: async function (options) {
      state.entered += 1;
      while (state.hold) await new Promise((r) => setTimeout(r, 25));
      return original(options);
    },
  });
})();`);
}

interface Gate {
  __ceremonyGate: { hold: boolean; entered: number };
}

const holdCeremonies = (panel: Page, hold: boolean) =>
  panel.evaluate((h) => {
    (window as unknown as Gate).__ceremonyGate.hold = h;
  }, hold);

const ceremoniesStarted = (panel: Page) =>
  panel.evaluate(() => (window as unknown as Gate).__ceremonyGate.entered);

test("a passkey prompt that takes window focus doesn't lock the vault under it", async ({
  context,
  extensionId,
}) => {
  const panel = await context.newPage();
  await addPrfAuthenticator(context, panel);
  await installCeremonyGate(panel);
  await panel.goto(`chrome-extension://${extensionId}/sidepanel.html`);
  await panel.bringToFront();

  const keysTab = panel.getByRole("tab", { name: "Keys" });

  await test.step("onboard with a passkey and the strictest preset", async () => {
    await panel.getByRole("button", { name: "Next" }).click();
    await panel.getByRole("button", { name: "Create passkey" }).click();
    await panel.getByPlaceholder("Your full name").fill("Focus User");
    await panel.getByPlaceholder("you@example.com").fill("focus@test.local");
    await panel.getByRole("button", { name: "Create my PGP key" }).click();
    // Strictest preset: lock on tab-away + never cache keys, so the key
    // needs its own passkey prompt while the vault is open.
    await panel
      .getByText("If this leaks, I'm in trouble")
      .click({ timeout: 30_000 });
    await panel.getByRole("button", { name: "Use this preset" }).click();
    await expect(keysTab).toBeVisible({ timeout: 30_000 });
  });

  await test.step("start a key unlock and hold its prompt open", async () => {
    await keysTab.click();
    // Generation leaves the new key unlocked; lock it so it needs a prompt.
    await panel.getByRole("button", { name: "Lock", exact: true }).click();
    const before = await ceremoniesStarted(panel);
    await holdCeremonies(panel, true);
    await panel.getByRole("button", { name: "Unlock", exact: true }).click();
    await expect.poll(() => ceremoniesStarted(panel)).toBe(before + 1);
    // While the prompt is open the button is disabled ("...") so a second
    // click can't replace the prompt.
    await expect(
      panel.getByRole("button", { name: "...", exact: true }),
    ).toBeDisabled();
  });

  await test.step("window focus leaves, as Windows Hello makes it", async () => {
    const other = await panel.evaluate(async () => {
      const w = await chrome.windows.create({
        url: "about:blank",
        focused: true,
      });
      return w.id ?? -1;
    });
    // Give onFocusChanged time to arrive and (formerly) lock.
    await panel.waitForTimeout(1_000);
    // Still in the vault. (Before the fix the vault locked here and the
    // Keys tab disappeared -- verified by running this test without it.)
    await expect(keysTab).toBeVisible();
    await panel.evaluate((id) => chrome.windows.remove(id), other);
  });

  await test.step("the prompt completes and the key unlocks", async () => {
    await panel.bringToFront();
    await holdCeremonies(panel, false);
    await expect(
      panel.getByRole("button", { name: "Lock", exact: true }),
    ).toBeVisible({ timeout: 20_000 });
  });

  await test.step("tab-away lock still works once no prompt is open", async () => {
    await panel.evaluate(() =>
      chrome.windows.create({ url: "about:blank", focused: true }),
    );
    await expect(
      panel.getByRole("button", { name: "Unlock with passkey" }),
    ).toBeVisible({ timeout: 10_000 });
  });

  await panel.close();
});
