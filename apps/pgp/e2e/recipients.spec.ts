import { readFileSync } from "node:fs";

import { expect, test } from "./fixtures";
import { goToKeys, importContact, onboardWithPassword } from "./helpers";
import { keyBySlug } from "./keys";

const PASSWORD = "correct horse battery staple";

const encryptable = keyBySlug("standard");
const signOnly = keyBySlug("signOnly");

test("sign-only contacts are not offered as encryption recipients", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, encryptable.publicKey);
  await importContact(panel, signOnly.publicKey);

  // Encrypt mode (default) shows the recipient picker; its label is
  // wired to the inline combobox input, so getByLabel targets it
  // directly.
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.getByLabel("Recipients").click();

  // Options only exist while the popover is open, so this doesn't collide
  // with the (hidden) Keys tab contact cards.
  await expect(
    panel.getByRole("option", { name: new RegExp(encryptable.label) }),
  ).toBeVisible();
  await expect(
    panel.getByRole("option", { name: new RegExp(signOnly.label) }),
  ).toHaveCount(0);
});

test("typing in the recipient box filters, Enter picks a chip", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, encryptable.publicKey);

  await panel.getByRole("tab", { name: "Main" }).click();
  const input = panel.getByRole("combobox", { name: "Recipients" });

  // Typing straight into the box opens the dropdown and filters it --
  // there is no second search field.
  await input.fill("alice");
  await expect(
    panel.getByRole("option", { name: new RegExp(encryptable.label) }),
  ).toBeVisible();
  await input.fill("no such contact");
  await expect(panel.getByText("No matches")).toBeVisible();

  // Enter picks the highlighted option, closes the dropdown, and
  // renders the pick as a chip inside the box (the box starts empty --
  // nothing is pre-selected).
  await input.fill("alice");
  await input.press("Enter");
  await expect(panel.getByRole("option")).toHaveCount(0);
  await expect(panel.getByTitle(new RegExp(encryptable.label))).toHaveCount(1);
  await expect(input).toHaveValue("");

  // Backspace on the empty input pops the last chip back off.
  await input.press("Backspace");
  await expect(panel.getByTitle(new RegExp(encryptable.label))).toHaveCount(0);
});

test("typing while a chip is focused diverts into the search input", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, encryptable.publicKey);

  await panel.getByRole("tab", { name: "Main" }).click();
  const input = panel.getByRole("combobox", { name: "Recipients" });
  await input.fill("alice");
  await input.press("Enter");

  // Focus a chip (its whole body is the remove button) and type: the
  // keystrokes must land in the search input, not vanish into a
  // non-editable button.
  const chips = panel.getByRole("button", { name: /^Remove / });
  await chips.first().focus();
  await panel.keyboard.type("zz");
  await expect(input).toBeFocused();
  await expect(input).toHaveValue("zz");
  // Typing (not the refocus itself) opened the dropdown, so the
  // empty filter result shows.
  await expect(panel.getByText("No matches")).toBeVisible();

  // Space is not stolen: on a focused chip it still activates the
  // remove button instead of typing into the search input.
  // One Escape both closes the list and clears the query (Radix's
  // dismissable layer routes the close through onOpenChange, which
  // resets the search). A SECOND press would land on the exhausted
  // layer, which hands focus to the message box on a timeout -- and
  // that steal can outrace the chip focus below on a slow machine,
  // sending the Space to the textarea instead of the chip.
  await input.press("Escape");
  await expect(panel.getByRole("option")).toHaveCount(0);
  await expect(input).toHaveValue("");
  const before = await chips.count();
  await chips.first().focus();
  await expect(chips.first()).toBeFocused();
  await panel.keyboard.press(" ");
  await expect(chips).toHaveCount(before - 1);
  await expect(input).toHaveValue("");
});

test("mod+Enter with the recipient dropdown open runs the action, not a pick", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, encryptable.publicKey);

  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("#pgp-input").fill("hello");
  const input = panel.getByRole("combobox", { name: "Recipients" });
  await input.fill("alice");
  await input.press("Enter");
  await expect(panel.getByRole("button", { name: /^Remove / })).toHaveCount(1);

  // Reopen the dropdown so the own key is highlighted as a pickable
  // option, then hit the Run shortcut with the list open.
  await input.click();
  await expect(panel.getByRole("option").first()).toBeVisible();
  const mod = process.platform === "darwin" ? "Meta" : "Control";
  await input.press(`${mod}+Enter`);

  // The encrypt ran (Download appears) and the shortcut neither picked
  // the highlighted option nor left the dropdown open.
  await expect(panel.getByRole("button", { name: "Download" })).toBeVisible();
  await expect(panel.getByRole("option")).toHaveCount(0);
  await expect(panel.getByRole("button", { name: /^Remove / })).toHaveCount(1);
});

// This is the regression guard for the dropdown appearing unbidden --
// it fails against the version that opened the list on focus. A companion
// test that ran a full encrypt round trip to assert the same thing was
// removed: it never failed against the buggy version (so it guarded
// nothing) and was intermittently flaky under load, apparently on the
// encrypt rather than the dropdown.
test("focus alone never opens the recipient dropdown", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, encryptable.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();

  // Tabbing/refocusing into the box (which also happens when the panel
  // regains focus, or when a re-render hands focus back after the Run
  // shortcut) must not pop the list open -- only a deliberate gesture does.
  const input = panel.getByRole("combobox", { name: "Recipients" });
  await input.focus();
  await expect(input).toBeFocused();
  await expect(panel.getByRole("option")).toHaveCount(0);

  // Arrow keys, typing and clicking still open it.
  await input.press("ArrowDown");
  await expect(panel.getByRole("option").first()).toBeVisible();
  await input.press("Escape");
  await expect(panel.getByRole("option")).toHaveCount(0);
  await input.pressSequentially("al");
  await expect(panel.getByRole("option").first()).toBeVisible();
  await input.press("Escape");
  await input.press("Escape");
  await expect(panel.getByRole("option")).toHaveCount(0);
  await input.click();
  await expect(panel.getByRole("option").first()).toBeVisible();
});

test("a row's (i) opens the key's details without picking it or closing the list", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, encryptable.publicKey);

  await panel.getByRole("tab", { name: "Main" }).click();
  const input = panel.getByRole("combobox", { name: "Recipients" });
  await input.fill("alice");
  const row = panel.getByRole("option", {
    name: new RegExp(encryptable.label),
  });
  await row.getByRole("button", { name: "Key details" }).click();

  const details = panel.getByRole("region", { name: /^Key details for/ });
  await expect(details).toBeVisible();
  await expect(details).toContainText(encryptable.name);
  await panel.getByRole("button", { name: "Back" }).click();
  await expect(details).toBeHidden();

  // Back lands on the list as it was left: still open, still filtered.
  await expect(row).toBeVisible();
  await expect(input).toHaveValue("alice");

  // Looking was not choosing: no chip.
  await expect(panel.getByTitle(new RegExp(encryptable.label))).toHaveCount(0);
});

test("your own key imported again as a contact is offered once", async ({
  panel,
}) => {
  // The same fingerprint as an own key and a contact used to appear
  // under Contacts twice: the own record matched the contact's id.
  await onboardWithPassword(panel, PASSWORD);
  await goToKeys(panel);
  const [download] = await Promise.all([
    panel.waitForEvent("download"),
    (async () => {
      await panel.getByRole("button", { name: "Key options" }).first().click();
      await panel
        .getByRole("menuitem", { name: "Download public key" })
        .click();
    })(),
  ]);
  const ownPublic = readFileSync(await download.path(), "utf8");
  await importContact(panel, ownPublic);

  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.getByRole("combobox", { name: "Recipients" }).fill("e2e");
  await expect(panel.getByRole("option")).toHaveCount(1);
});
