import { expect, test } from "./fixtures";
import { importContact, onboardWithPassword } from "./helpers";
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
  // directly (the mode Select is the panel's other combobox).
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
  // renders the pick as a chip inside the box (alongside the app's
  // default encrypt-to-self chip for the user's own key).
  await input.fill("alice");
  await input.press("Enter");
  await expect(panel.getByRole("option")).toHaveCount(0);
  await expect(panel.getByTitle(new RegExp(encryptable.label))).toHaveCount(1);
  await expect(input).toHaveValue("");

  // Backspace on the empty input pops the last chip back off.
  await input.press("Backspace");
  await expect(panel.getByTitle(new RegExp(encryptable.label))).toHaveCount(0);
});
