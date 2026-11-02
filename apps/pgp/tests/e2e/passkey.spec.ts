import { expect, test } from "./fixtures";
import { addPrfAuthenticator } from "./webauthn";

// Passkey master protection end-to-end, driven by a virtual WebAuthn
// authenticator with PRF support. Onboard with a passkey, lock, then
// unlock with the same passkey.
test("onboards, locks, and unlocks with a PRF passkey", async ({
  context,
  extensionId,
}) => {
  const panel = await context.newPage();
  await addPrfAuthenticator(context, panel);
  await panel.goto(`chrome-extension://${extensionId}/sidepanel.html`);
  // WebAuthn ceremonies require the page to hold focus.
  await panel.bringToFront();

  await test.step("onboard with the passkey (default) protection", async () => {
    await panel.getByRole("button", { name: "Next" }).click();
    // Passkey is the default method; the button reads "Create passkey".
    await panel.getByRole("button", { name: "Create passkey" }).click();
    await panel.getByPlaceholder("Your full name").fill("Passkey User");
    await panel.getByPlaceholder("you@example.com").fill("passkey@test.local");
    await panel.getByRole("button", { name: "Create my PGP key" }).click();
    await panel
      .getByRole("button", { name: "Keep the defaults" })
      .click({ timeout: 30_000 });
    await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible({
      timeout: 30_000,
    });
  });

  await test.step("lock via reload, then unlock with the passkey", async () => {
    await panel.reload();
    await panel.bringToFront();
    // The lock screen auto-prompts, but that can race the page regaining
    // focus. Clicking the button re-runs the ceremony deterministically
    // (now focused); the `.catch` covers the case where the auto-prompt
    // already unlocked and the button is gone.
    await panel
      .getByRole("button", { name: "Unlock with passkey" })
      .click({ timeout: 5_000 })
      .catch(() => undefined);
    await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible({
      timeout: 20_000,
    });
  });

  await panel.close();
});
