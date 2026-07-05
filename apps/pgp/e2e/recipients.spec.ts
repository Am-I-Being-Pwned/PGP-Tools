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

  // Encrypt mode (default) shows the recipient picker. Two comboboxes are
  // present: [0] is the mode Select, [1] is "Key for recipient".
  await panel.getByRole("tab", { name: "Main" }).click();
  await expect(panel.getByText("Key for recipient")).toBeVisible();
  await panel.getByRole("combobox").nth(1).click();

  // Options only exist while the popover is open, so this doesn't collide
  // with the (hidden) Keys tab contact cards.
  await expect(
    panel.getByRole("option", { name: new RegExp(encryptable.label) }),
  ).toBeVisible();
  await expect(
    panel.getByRole("option", { name: new RegExp(signOnly.label) }),
  ).toHaveCount(0);
});
