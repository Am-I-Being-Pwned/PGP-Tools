import type { Page } from "@playwright/test";

import { edgeKey } from "./edge-keys";
import { expect, test } from "./fixtures";
import {
  deliverPendingOp,
  encryptToSelfInWorkspace,
  goToKeys,
  importContact,
  lockOnlyKey,
  onboardWithPassword,
  unlockWithPassword,
} from "./helpers";
import { addPrfAuthenticatorWithId, exportCredentials } from "./webauthn-carry";

// A message opened from the context menu runs by itself: verify always,
// decrypt only when the key it is addressed to is ALREADY open. What these
// pin is both halves -- it runs without a click when it can, and when it
// can't (a locked key) it neither decrypts nor starts an unlock on its
// own; the user's click is still what asks for a secret.

const PASSWORD = "correct horse battery staple";
const PLAINTEXT = "auto-run plaintext 3c1e";

const box = (panel: Page) => panel.getByLabel("Message input");

test("a decrypt from the context menu runs by itself when its key is already unlocked", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  const armored = await encryptToSelfInWorkspace(panel, PLAINTEXT);
  // Onboarding leaves the key it generated unlocked.
  await goToKeys(panel);
  await expect(
    panel.getByRole("button", { name: "Lock", exact: true }),
  ).toBeVisible();

  // Auto-download on: it is for results the user asked for, and this
  // input is whatever a web page put in the selection.
  await panel.getByRole("tab", { name: "Settings" }).click();
  const autoDownload = panel.getByRole("switch", {
    name: /Auto-download text results/,
  });
  await autoDownload.click();
  await expect(autoDownload).toHaveAttribute("aria-checked", "true");

  const downloads: string[] = [];
  panel.on("download", (d) => downloads.push(d.suggestedFilename()));
  await deliverPendingOp(panel, "decrypt", armored);
  // No click: the panel routes to Main and the plaintext appears.
  await expect(panel.getByText(PLAINTEXT).first()).toBeVisible();
  await panel.waitForTimeout(1_000);
  expect(downloads, "an auto-run never writes to disk").toEqual([]);
  // ...while the Download button still does.
  const saved = panel.waitForEvent("download");
  await panel.getByRole("button", { name: "Download" }).click();
  await saved;
});

test("a decrypt from the context menu waits for the click when its key is locked, and prompts nothing", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  const armored = await encryptToSelfInWorkspace(panel, PLAINTEXT);
  await lockOnlyKey(panel);

  await deliverPendingOp(panel, "decrypt", armored);
  await expect(box(panel)).toHaveValue(armored);
  const decrypt = panel.getByRole("button", { name: /^decrypt$/i });
  await expect(decrypt).toBeVisible();
  // Long enough for the auto-run to have fired had it been going to.
  await panel.waitForTimeout(1_000);
  await expect(panel.getByPlaceholder("Enter password")).toHaveCount(0);
  await expect(panel.getByText(PLAINTEXT)).toHaveCount(0);

  // The click still takes the ordinary path: it asks for the password.
  await decrypt.click();
  await expect(panel.getByPlaceholder(/password/i).first()).toBeVisible();
});

test("a verify delivered while the vault is locked runs after unlock, against the loaded contacts", async ({
  panel,
}) => {
  const signer = edgeKey("rsa4096");
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, signer.publicKey);

  // Reload drops the session: the panel comes back on the lock screen,
  // and the op waits in session storage until the vault opens. The
  // contacts are read after that; the settling gate is what makes the
  // order safe (the first-open test below is the one that fails without
  // it -- here the op's own storage read happens to lose the race).
  await panel.reload();
  await expect(panel.getByLabel("Master password")).toBeVisible();
  await deliverPendingOp(panel, "verify", signer.signedMessage ?? "");
  await unlockWithPassword(panel, PASSWORD);

  await expect(panel.getByText("Signature verified")).toBeVisible();
  await expect(panel.getByText("Rachel Rsa4096").first()).toBeVisible();
});

async function signCount(
  auth: Awaited<ReturnType<typeof addPrfAuthenticatorWithId>>,
): Promise<number> {
  const creds = (await exportCredentials(auth)) as { signCount: number }[];
  return creds.reduce((n, c) => n + c.signCount, 0);
}

test("first open: the vault ceremony opens the key and the message decrypts, with one ceremony", async ({
  context,
  extensionId,
}) => {
  const panel = await context.newPage();
  const auth = await addPrfAuthenticatorWithId(context, panel);
  await panel.goto(`chrome-extension://${extensionId}/sidepanel.html`);
  await panel.bringToFront();

  // Passkey master with "Unlock keys with the vault" opted in.
  await panel.getByRole("button", { name: "Next" }).click();
  await panel.getByRole("button", { name: "Create passkey" }).click();
  await panel.getByPlaceholder("Your full name").fill("Vault User");
  await panel.getByPlaceholder("you@example.com").fill("vault@test.local");
  await panel.getByRole("button", { name: "Create my PGP key" }).click();
  const optIn = panel.getByRole("checkbox", {
    name: /Unlock keys with the vault/,
  });
  await expect(optIn).toBeVisible({ timeout: 30_000 });
  await optIn.check();
  await panel.getByRole("button", { name: "Keep the defaults" }).click();
  await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible({
    timeout: 30_000,
  });

  const armored = await encryptToSelfInWorkspace(panel, PLAINTEXT);

  // The context menu opens a fresh panel onto the lock screen.
  await panel.reload();
  await panel.bringToFront();
  const before = await signCount(auth);
  await deliverPendingOp(panel, "decrypt", armored);
  const keysTab = panel.getByRole("tab", { name: "Keys" });
  const unlocked = await keysTab
    .waitFor({ state: "visible", timeout: 5_000 })
    .then(() => true)
    .catch(() => false);
  if (!unlocked) {
    await panel.getByRole("button", { name: "Unlock with passkey" }).click();
    await expect(keysTab).toBeVisible({ timeout: 20_000 });
  }

  await expect(panel.getByText(PLAINTEXT).first()).toBeVisible({
    timeout: 15_000,
  });
  // The vault's ceremony, and nothing else: the decrypt used the key the
  // vault opened rather than asking for it again.
  expect(await signCount(auth), "exactly one WebAuthn assertion").toBe(
    before + 1,
  );
  await panel.close();
});
