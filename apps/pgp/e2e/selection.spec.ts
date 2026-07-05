import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures";
import { seedVault } from "./helpers";
import { keyBySlug } from "./keys";

const PASSWORD = "correct horse battery staple";

// A spread of distinct contact identities to seed. Names are unique so a
// card can be located by its display name and a deletion asserted by absence.
const ALICE = keyBySlug("standard"); // "Alice Example"
const BOB = keyBySlug("noEmail"); // "Bob NoEmail"
const CAROL = keyBySlug("comment"); // "Carol Work (work laptop)"
const DAVE = keyBySlug("rsa"); // "Dave RSA"

/** The card container for the contact whose display name contains `name`. */
function contactCard(panel: Page, name: string) {
  return panel.locator("div.group").filter({ hasText: name }).first();
}

/** The floating "magic island" selection toolbar. */
function selectionBar(panel: Page) {
  return panel.getByRole("toolbar", { name: "Selection actions" });
}

/** Open a contact's ⋮ menu and click its "Select" item to enter selection. */
async function startSelectViaMenu(panel: Page, name: string): Promise<void> {
  await contactCard(panel, name)
    .getByRole("button", { name: "Contact options" })
    .click();
  await panel.getByRole("menuitem", { name: "Select" }).click();
}

test.describe("bulk selection of contacts", () => {
  test("enter selection via the ⋮ Select menu shows '1 selected'", async ({
    panel,
  }) => {
    await seedVault(panel, PASSWORD, [ALICE.publicKey, BOB.publicKey]);

    await startSelectViaMenu(panel, ALICE.name);

    const bar = selectionBar(panel);
    await expect(bar).toBeVisible();
    await expect(bar.getByText("1 selected")).toBeVisible();
    // The two bulk actions are offered.
    await expect(bar.getByRole("button", { name: "Export" })).toBeVisible();
    await expect(bar.getByRole("button", { name: "Delete" })).toBeVisible();
  });

  test("selecting a second contact updates the count; deselecting all auto-exits", async ({
    panel,
  }) => {
    await seedVault(panel, PASSWORD, [ALICE.publicKey, BOB.publicKey]);

    await startSelectViaMenu(panel, ALICE.name);
    const bar = selectionBar(panel);
    await expect(bar.getByText("1 selected")).toBeVisible();

    // In selection mode a tap on a card toggles it (the ⋮ menu is hidden).
    await contactCard(panel, BOB.name).click();
    await expect(bar.getByText("2 selected")).toBeVisible();

    // Deselect both -> selecting nothing auto-exits selection mode.
    await contactCard(panel, ALICE.name).click();
    await expect(bar.getByText("1 selected")).toBeVisible();
    await contactCard(panel, BOB.name).click();
    await expect(bar).toBeHidden();
  });

  test("bulk delete removes the selected contacts and keeps the rest", async ({
    panel,
  }) => {
    await seedVault(panel, PASSWORD, [
      ALICE.publicKey,
      BOB.publicKey,
      CAROL.publicKey,
      DAVE.publicKey,
    ]);

    // Select Alice (via menu) + Bob (via tap) -> 2 selected.
    await startSelectViaMenu(panel, ALICE.name);
    await contactCard(panel, BOB.name).click();
    const bar = selectionBar(panel);
    await expect(bar.getByText("2 selected")).toBeVisible();

    // Delete -> confirm on the dedicated "Delete selected?" page.
    await bar.getByRole("button", { name: "Delete" }).click();
    const confirm = panel.getByRole("region", { name: "Delete selected?" });
    await expect(confirm).toBeVisible();
    await confirm
      .getByRole("button", { name: "Delete 2 items permanently" })
      .click();

    // The two selected contacts are gone; the others remain.
    await expect(panel.getByText(ALICE.name)).toHaveCount(0);
    await expect(panel.getByText(BOB.name)).toHaveCount(0);
    await expect(panel.getByText("Carol Work").first()).toBeVisible();
    await expect(panel.getByText(DAVE.name).first()).toBeVisible();
    // Selection mode exits after the deletion.
    await expect(bar).toBeHidden();
  });

  test("bulk export of a contacts-only selection opens the Export All Keys dialog", async ({
    panel,
  }) => {
    await seedVault(panel, PASSWORD, [ALICE.publicKey, BOB.publicKey]);

    // Select two contacts only (no private keys) -> export needs no unlock.
    await startSelectViaMenu(panel, ALICE.name);
    await contactCard(panel, BOB.name).click();
    const bar = selectionBar(panel);
    await expect(bar.getByText("2 selected")).toBeVisible();

    await bar.getByRole("button", { name: "Export" }).click();

    // The existing bulk-export dialog opens, scoped to the selection. With
    // contacts only, it lands straight on the export step: an "Export"
    // button (no passphrase, no unlock) is present.
    const dialog = panel.getByRole("dialog", { name: "Export All Keys" });
    await expect(dialog).toBeVisible();
    await expect(
      dialog.getByRole("button", { name: "Export", exact: true }),
    ).toBeVisible();
  });

  test("enter selection via long-press on a card", async ({ panel }) => {
    await seedVault(panel, PASSWORD, [ALICE.publicKey, BOB.publicKey]);

    const card = contactCard(panel, ALICE.name);
    await expect(card).toBeVisible();
    const box = await card.boundingBox();
    if (!box) throw new Error("contact card has no bounding box");
    const cx = box.x + box.width / 2;
    const cy = box.y + box.height / 2;

    // Press and hold ~600ms without moving to trip the 500ms long-press.
    await panel.mouse.move(cx, cy);
    await panel.mouse.down();
    await panel.waitForTimeout(650);
    await panel.mouse.up();

    const bar = selectionBar(panel);
    await expect(bar).toBeVisible();
    await expect(bar.getByText("1 selected")).toBeVisible();
  });
});
