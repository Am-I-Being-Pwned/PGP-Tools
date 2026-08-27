import { readFile } from "node:fs/promises";

import { expect, test } from "./fixtures";
import {
  generateSshKeys,
  importContact,
  onboardWithPasswordSkipKey,
} from "./helpers";
import { keyBySlug } from "./keys";

/**
 * Encrypting to a password, end to end.
 *
 * The engine tests in `gpg-wasm/src/tests.rs` prove the ciphertext is
 * right -- including that real GnuPG opens it. What only this layer can
 * show is the part the user touches: that the badge arms only when the
 * password is confirmed, that an unconfirmed one cannot produce a
 * message, and that a password alone is enough to encrypt with no
 * recipients and no keys at all.
 */

const VAULT_PASSWORD = "correct horse battery staple";
const MESSAGE_PASSWORD = "a fine message password";
const MESSAGE = "meet me at the usual place";

/** The badge that turns symmetric encryption on. `ToggleBadge` renders
 *  `role="switch"`, not a button -- the same handle `setKeyDiscovery` in
 *  helpers.ts uses for the settings toggles. */
function passwordBadge(panel: import("@playwright/test").Page) {
  return panel.getByRole("switch", { name: "Password", exact: true });
}

async function goToEncrypt(
  panel: import("@playwright/test").Page,
): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.getByRole("combobox").first().click();
  await panel.getByRole("option", { name: "Encrypt", exact: true }).click();
}

/** Press the badge, type a password in the dialog, confirm. */
async function setMessagePassword(
  panel: import("@playwright/test").Page,
  password: string,
): Promise<void> {
  await passwordBadge(panel).click();
  await panel.getByLabel("Message password", { exact: true }).fill(password);
  await panel.getByRole("button", { name: "Set password" }).click();
  await expect(
    panel.getByRole("region", { name: "Password for this message" }),
  ).toBeHidden();
}

test("a password alone encrypts, with no keys and no recipients", async ({
  panel,
}) => {
  // The `gpg -c` case. The vault is empty -- there is no key to encrypt
  // to and none needed, which is the whole point of the feature.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await goToEncrypt(panel);
  await panel.locator("textarea").first().fill(MESSAGE);

  const encrypt = panel.getByRole("button", { name: /^encrypt$/i });
  // Without a password there is nobody to encrypt to, so the button is
  // held shut and says why.
  await expect(encrypt).toBeDisabled();

  await setMessagePassword(panel, MESSAGE_PASSWORD);

  await expect(encrypt).toBeEnabled();
  await encrypt.click();
  await expect(panel.getByRole("button", { name: "Download" })).toBeVisible();
});

test("a too-short password cannot be set, and cancelling arms nothing", async ({
  panel,
}) => {
  // A typo here is silent and permanent -- the message would encrypt
  // cleanly and open for nobody, including the sender. So the gate is on
  // a password actually being SET, not on the badge being pressed.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await goToEncrypt(panel);
  await panel.locator("textarea").first().fill(MESSAGE);

  const encrypt = panel.getByRole("button", { name: /^encrypt$/i });
  await expect(encrypt).toBeDisabled();

  await passwordBadge(panel).click();
  const field = panel.getByLabel("Message password", { exact: true });
  const setBtn = panel.getByRole("button", { name: "Set password" });

  // Empty, then too short: the primary action stays shut and says why.
  await expect(setBtn).toBeDisabled();
  await field.fill("short");
  await expect(panel.getByText(/at least 8 characters/i)).toBeVisible();
  await expect(setBtn).toBeDisabled();

  // Cancelling leaves the badge OFF -- pressing it is not the same as
  // setting a password, and the badge must not claim otherwise.
  await panel.getByRole("button", { name: "Cancel" }).click();
  await expect(passwordBadge(panel)).toHaveAttribute("aria-checked", "false");
  await expect(encrypt).toBeDisabled();
});

test("the dialog is usable with the keyboard alone", async ({ panel }) => {
  // No mouse past opening it: type, tab to the reveal and toggle it,
  // tab on to the primary action and press it. Every control has to be
  // in the tab order for this to pass -- an icon with a click handler
  // instead of a real <button> would drop out of it silently.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await goToEncrypt(panel);
  await panel.locator("textarea").first().fill(MESSAGE);
  await passwordBadge(panel).click();

  const field = panel.getByLabel("Message password", { exact: true });
  // Autofocused, so typing works with no click at all.
  await expect(field).toBeFocused();
  await panel.keyboard.type(MESSAGE_PASSWORD);
  await expect(field).toHaveAttribute("type", "password");
  // Focus must SURVIVE the typing. It did not before the slide-over's
  // focus trap learned to respect React's autoFocus: the trap activated
  // mid-word and pulled focus to the header's Back button, so the rest
  // of the password went nowhere.
  await expect(field).toBeFocused();

  // Tab reaches the reveal toggle, and Space activates it.
  await panel.keyboard.press("Tab");
  await expect(
    panel.getByRole("button", { name: "Show password" }),
  ).toBeFocused();
  await panel.keyboard.press(" ");
  await expect(field).toHaveAttribute("type", "text");
  await expect(field).toHaveValue(MESSAGE_PASSWORD);

  // Tab on to the primary action and press it.
  await panel.keyboard.press("Tab");
  await expect(
    panel.getByRole("button", { name: "Set password" }),
  ).toBeFocused();
  await panel.keyboard.press("Enter");

  await expect(
    panel.getByRole("region", { name: "Password for this message" }),
  ).toBeHidden();
  await expect(passwordBadge(panel)).toHaveAttribute("aria-checked", "true");
  await expect(panel.getByRole("button", { name: /^encrypt$/i })).toBeEnabled();
});

test("Enter in the field submits, and Escape closes without arming", async ({
  panel,
}) => {
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await goToEncrypt(panel);
  await panel.locator("textarea").first().fill(MESSAGE);

  // Escape first: opens, backs out, nothing set.
  await passwordBadge(panel).click();
  await panel
    .getByLabel("Message password", { exact: true })
    .fill(MESSAGE_PASSWORD);
  await panel.keyboard.press("Escape");
  await expect(passwordBadge(panel)).toHaveAttribute("aria-checked", "false");

  // Then Enter straight from the field.
  await passwordBadge(panel).click();
  const field = panel.getByLabel("Message password", { exact: true });
  await field.fill(MESSAGE_PASSWORD);
  await field.press("Enter");
  await expect(passwordBadge(panel)).toHaveAttribute("aria-checked", "true");
});

test("what it encrypts can be decrypted again with the same password", async ({
  panel,
}) => {
  // The round trip through the real app: encrypt to a password, take the
  // armor back out of the download, paste it in, and open it. This is
  // the only test that proves the two halves of the feature agree.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await goToEncrypt(panel);
  await panel.locator("textarea").first().fill(MESSAGE);
  await setMessagePassword(panel, MESSAGE_PASSWORD);

  const download = panel.waitForEvent("download");
  await panel.getByRole("button", { name: /^encrypt$/i }).click();
  await panel.getByRole("button", { name: "Download" }).click();
  const file = await download;
  const armored = await readFile(await file.path(), "utf8");
  expect(armored).toContain("BEGIN PGP MESSAGE");

  // Back in as a fresh decrypt. The box is refilled directly rather than
  // hunting for a reset control -- what is being tested is the round
  // trip, not the clear button.
  await panel.getByRole("combobox").first().click();
  await panel.getByRole("option", { name: "Decrypt", exact: true }).click();
  await panel.locator("textarea").first().fill(armored);
  await panel.getByRole("button", { name: /^decrypt$/i }).click();
  const field = panel.getByPlaceholder("Enter message password");
  await field.fill(MESSAGE_PASSWORD);
  await field.press("Enter");
  await expect(panel.getByText(MESSAGE)).toBeVisible();
});

/**
 * REGRESSION, reported from the running app. The gate the command
 * palette and the mod+Enter shortcut consult is a SEPARATE one from the
 * button's, and it still asked "are there recipients?" -- so with the
 * Password badge armed and no recipients, the button was live while the
 * palette refused with "Run Encrypt is disabled: Select at least one
 * recipient".
 *
 * Every other test in this file drives the BUTTON, which is exactly why
 * they all passed while this was broken. The precise pin is the unit
 * test in `lib/actions/definitions.test.ts`; these two prove the context
 * actually reaching the registry carries the same answer.
 *
 * Split in two so neither has to CLOSE the palette: it does not close on
 * Escape under Playwright, and a test that fights the harness reports
 * the harness rather than the product.
 */
test("the palette explains itself when nothing can open the message", async ({
  panel,
}) => {
  // The control. Without it the pass below could come from never having
  // found the action at all.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await goToEncrypt(panel);
  await panel.locator("textarea").first().fill(MESSAGE);

  await panel.keyboard.press("ControlOrMeta+k");
  await expect(
    panel.getByRole("option", { name: /Run Encrypt/ }),
  ).toContainText("Select at least one recipient");
});

test("the palette runs a password-only encrypt", async ({ panel }) => {
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await goToEncrypt(panel);
  await panel.locator("textarea").first().fill(MESSAGE);
  await setMessagePassword(panel, MESSAGE_PASSWORD);

  await panel.keyboard.press("ControlOrMeta+k");
  const runItem = panel.getByRole("option", { name: /Run Encrypt/ });
  await expect(runItem).toBeVisible();
  await expect(runItem).not.toContainText("Select at least one recipient");

  // Selected with the keyboard: cmdk items are driven by its own
  // highlight, not by a plain click target.
  await panel.keyboard.type("Run Encrypt");
  await panel.keyboard.press("Enter");

  await expect(panel.getByRole("button", { name: "Download" })).toBeVisible();
});

test("a password dims SSH recipients, and says why", async ({ panel }) => {
  // age has no password mode, so a message cannot be both. The picker
  // has to REFUSE the combination rather than let it be made -- the
  // encrypt path takes the age branch on an SSH selection and never sees
  // the password, so the silent outcome is a file with no password on it
  // and a lit Password badge above the button.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  const [ssh] = generateSshKeys(1);
  await importContact(panel, ssh.publicLineWithComment);
  await importContact(panel, keyBySlug("standard").publicKey);

  await goToEncrypt(panel);
  await panel.locator("textarea").first().fill(MESSAGE);

  // Before the password: the SSH contact is offered like any other.
  await panel.getByRole("combobox", { name: "Recipients" }).click();
  // Found by its "SSH" badge, not by the key comment: a contact imported
  // from a bare public line keeps no comment, so it renders under its
  // fingerprint. The badge is what the picker guarantees.
  const sshOption = panel.getByRole("option", { name: /SSH/ });
  await expect(sshOption).toBeVisible();
  await expect(sshOption).not.toHaveAttribute("aria-disabled", "true");
  await panel.keyboard.press("Escape");

  await setMessagePassword(panel, MESSAGE_PASSWORD);

  // After: dimmed, unpickable, and the reason is on screen -- not only
  // in a `title` tooltip, which touch and the keyboard never see.
  await panel.getByRole("combobox", { name: "Recipients" }).click();
  await expect(sshOption).toHaveAttribute("aria-disabled", "true");
  await expect(panel.getByText(/age has none/i)).toBeVisible();

  // The PGP contact beside it stays pickable: the password is ADDITIVE
  // for OpenPGP, not a mode that rules everything else out.
  await expect(
    panel.getByRole("option", { name: /Alice Example/ }),
  ).not.toHaveAttribute("aria-disabled", "true");
});

test("tabbing into Recipients opens the list", async ({ panel }) => {
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await importContact(panel, keyBySlug("standard").publicKey);
  await goToEncrypt(panel);

  const box = panel.getByRole("combobox", { name: "Recipients" });
  await expect(box).toHaveAttribute("aria-expanded", "false");

  // Focus the message box, then Tab -- the recipient input is the next
  // stop, and arriving there by keyboard should show what can be picked.
  await panel.locator("textarea").first().click();
  await panel.locator("textarea").first().press("Tab");

  await expect(box).toBeFocused();
  await expect(box).toHaveAttribute("aria-expanded", "true");
});

test("focus that did not come from a Tab leaves the list shut", async ({
  panel,
}) => {
  // The property the focus handler is guarded for. The picker's own doc
  // comment says focus is not intent -- the box is also focused when the
  // panel regains focus and by re-renders after the Run shortcut -- so
  // only a Tab arrival opens it. Programmatic focus stands in for those
  // here; all three reach the handler with no Tab keydown behind them.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await importContact(panel, keyBySlug("standard").publicKey);
  await goToEncrypt(panel);

  const box = panel.getByRole("combobox", { name: "Recipients" });
  await box.evaluate((el: HTMLElement) => {
    el.focus();
  });

  await expect(box).toBeFocused();
  await expect(box).toHaveAttribute("aria-expanded", "false");
});

test("Escape from the recipient box lands back in the message box", async ({
  panel,
}) => {
  // The layering: press #1 closes the list, press #2 puts the cursor in
  // the message. It is a CALLBACK rather than the event bubbling to the
  // workspace's Escape listener -- the recipient input sits inside a
  // cmdk `Command` root that consumes Escape, so the documented
  // "falls through" layer was doing nothing at all.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await importContact(panel, keyBySlug("standard").publicKey);
  await goToEncrypt(panel);

  const box = panel.locator("textarea").first();
  const recipients = panel.getByRole("combobox", { name: "Recipients" });

  await recipients.click();
  await panel.keyboard.press("ArrowDown"); // open the list
  await expect(recipients).toHaveAttribute("aria-expanded", "true");

  await panel.keyboard.press("Escape");
  await expect(recipients).toHaveAttribute("aria-expanded", "false");
  // Still in the recipient box: closing the list is its own layer.
  await expect(recipients).toBeFocused();

  await panel.keyboard.press("Escape");
  await expect(box).toBeFocused();
});

test("Escape on an empty workspace puts the cursor back in the message box", async ({
  panel,
}) => {
  // Escape means "put me back" everywhere else in this panel. On an
  // empty workspace it was the one press that did nothing at all: it
  // silently armed a double-tap for a clear that returns early because
  // there is nothing staged.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await goToEncrypt(panel);

  const box = panel.locator("textarea").first();
  await expect(box).toHaveValue("");

  // Focus something that is NOT the message box, with no dropdown of its
  // own to peel first.
  await panel.getByRole("switch", { name: "Password", exact: true }).focus();
  await panel.keyboard.press("Escape");

  await expect(box).toBeFocused();
});

test("Escape still clears a NON-empty workspace on a double tap", async ({
  panel,
}) => {
  // The layer the new one must not have eaten. With something staged,
  // two quick presses still clear it -- undoably.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await goToEncrypt(panel);
  const box = panel.locator("textarea").first();
  await box.fill(MESSAGE);
  await box.click();

  await panel.keyboard.press("Escape");
  await panel.keyboard.press("Escape");

  await expect(box).toHaveValue("");
  await expect(panel.getByText(/cleared/i).first()).toBeVisible();
});
