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

  test("bulk export of a contacts-only selection downloads immediately", async ({
    panel,
  }) => {
    await seedVault(panel, PASSWORD, [ALICE.publicKey, BOB.publicKey]);

    // Select two contacts only (no private keys) -> nothing to unlock.
    await startSelectViaMenu(panel, ALICE.name);
    await contactCard(panel, BOB.name).click();
    const bar = selectionBar(panel);
    await expect(bar.getByText("2 selected")).toBeVisible();

    // Export downloads the .asc straight away -- no unlock/passphrase page.
    const [download] = await Promise.all([
      panel.waitForEvent("download"),
      bar.getByRole("button", { name: "Export" }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/^pgp-tools-keys-.*\.asc$/);
    await expect(
      panel.getByRole("region", { name: "Export keys" }),
    ).toHaveCount(0);

    // Exporting deselects; the toast's "Reselect" brings the same set back.
    await expect(bar).toBeHidden();
    await panel.getByRole("button", { name: "Reselect" }).click();
    await expect(selectionBar(panel).getByText("2 selected")).toBeVisible();
  });

  test("select all selects every card, then toggles back off", async ({
    panel,
  }) => {
    // Onboarding creates one private key; plus three contacts = four selectable.
    await seedVault(panel, PASSWORD, [
      ALICE.publicKey,
      BOB.publicKey,
      CAROL.publicKey,
    ]);

    await startSelectViaMenu(panel, ALICE.name);
    const bar = selectionBar(panel);
    await expect(bar.getByText("1 selected")).toBeVisible();

    // "Select all" grabs the private key + every contact.
    await bar.getByRole("button", { name: "Select all" }).click();
    await expect(bar.getByText("4 selected")).toBeVisible();

    // The control flips to "Deselect all"; clicking it clears + exits.
    await bar.getByRole("button", { name: "Deselect all" }).click();
    await expect(bar).toBeHidden();
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

const ERIN = keyBySlug("signOnly"); // "Erin SignOnly"
const FRANK = keyBySlug("signOnlyNoEmail"); // "Frank SignOnlyNoEmail"

/** Every selectable card on screen, in the order the user sees them. */
function contactCards(panel: Page) {
  return panel.locator('[data-select-id^="contact:"]');
}

/** Enter selection mode on the nth contact card, positionally. */
async function startSelectAt(panel: Page, index: number): Promise<void> {
  await contactCards(panel)
    .nth(index)
    .getByRole("button", { name: "Contact options" })
    .click();
  await panel.getByRole("menuitem", { name: "Select" }).click();
}

test.describe("shift-click range selection", () => {
  test("shift-click sweeps in every card between the anchor and the target", async ({
    panel,
  }) => {
    await seedVault(panel, PASSWORD, [
      ALICE.publicKey,
      BOB.publicKey,
      CAROL.publicKey,
      DAVE.publicKey,
    ]);

    // Positional, not by name: the range is defined by what is on screen, so
    // the test must not depend on the order the vault hands contacts back in.
    const contacts = contactCards(panel);
    await expect(contacts).toHaveCount(4);

    await startSelectAt(panel, 0);
    const bar = selectionBar(panel);
    await expect(bar.getByText("1 selected")).toBeVisible();

    // First -> last with Shift: the two cards in between come too.
    await contacts.nth(3).click({ modifiers: ["Shift"] });
    await expect(bar.getByText("4 selected")).toBeVisible();
  });

  test("a second shift-click re-sweeps from the same anchor, widening or narrowing", async ({
    panel,
  }) => {
    await seedVault(panel, PASSWORD, [
      ALICE.publicKey,
      BOB.publicKey,
      CAROL.publicKey,
      DAVE.publicKey,
    ]);

    const contacts = contactCards(panel);
    await startSelectAt(panel, 0);
    const bar = selectionBar(panel);

    await contacts.nth(1).click({ modifiers: ["Shift"] });
    await expect(bar.getByText("2 selected")).toBeVisible();

    // Widening measures from the ORIGINAL anchor, not from the card the last
    // shift-click landed on -- so this is 4, not 3.
    await contacts.nth(3).click({ modifiers: ["Shift"] });
    await expect(bar.getByText("4 selected")).toBeVisible();

    // And clicking back nearer the anchor NARROWS it: the range replaces the
    // selection rather than piling onto it.
    await contacts.nth(1).click({ modifiers: ["Shift"] });
    await expect(bar.getByText("2 selected")).toBeVisible();
  });

  test("a shift-range covers what is on screen, not what the filter hides", async ({
    panel,
  }) => {
    // Six contacts is what makes the contacts search box appear.
    await seedVault(panel, PASSWORD, [
      ALICE.publicKey,
      BOB.publicKey,
      CAROL.publicKey,
      DAVE.publicKey,
      ERIN.publicKey,
      FRANK.publicKey,
    ]);
    await expect(contactCards(panel)).toHaveCount(6);

    // "no" matches "Bob NoEmail", "Erin SigNOnly" and "Frank
    // SignOnlyNoEmail", leaving Carol and Dave hidden INSIDE that run. (Not a
    // term like "o": the search reads the raw user ID too, and every seeded
    // address ends in ".com".) So the visible run is 3 cards where the full
    // list would give 5 -- a range built from state rather than from what is
    // rendered would quietly sweep the two hidden contacts in as well.
    await panel.getByPlaceholder("Search contacts...").fill("no");
    const shown = contactCards(panel);
    await expect(shown).toHaveCount(3);

    await startSelectAt(panel, 0);
    await shown.nth(2).click({ modifiers: ["Shift"] });
    const bar = selectionBar(panel);
    await expect(bar.getByText("3 selected")).toBeVisible();

    // Clearing the filter brings the hidden contacts back, unselected.
    await panel.getByPlaceholder("Search contacts...").fill("");
    await expect(contactCards(panel)).toHaveCount(6);
    await expect(bar.getByText("3 selected")).toBeVisible();
    await expect(
      contactCards(panel).filter({ hasText: DAVE.name }),
    ).not.toHaveClass(/ring-2/);
  });

  test("shift-clicking with no anchor yet just toggles that one card", async ({
    panel,
  }) => {
    await seedVault(panel, PASSWORD, [
      ALICE.publicKey,
      BOB.publicKey,
      CAROL.publicKey,
    ]);

    await startSelectAt(panel, 0);
    const bar = selectionBar(panel);
    // "Select all" then "Deselect all" would exit; instead clear the anchor
    // the only other way a user can -- selecting everything.
    await bar.getByRole("button", { name: "Select all" }).click();
    await expect(bar.getByText("4 selected")).toBeVisible();

    // No anchor now: Shift must not sweep, it just unpicks this one.
    await contactCards(panel)
      .nth(2)
      .click({ modifiers: ["Shift"] });
    await expect(bar.getByText("3 selected")).toBeVisible();
  });

  test("cards do not select their text under a shift-click", async ({
    panel,
  }) => {
    await seedVault(panel, PASSWORD, [ALICE.publicKey, BOB.publicKey]);

    const userSelect = await contactCards(panel)
      .first()
      .evaluate((el) => {
        const card = el.firstElementChild;
        if (!card) throw new Error("wrapper has no card inside it");
        return getComputedStyle(card).userSelect;
      });
    expect(userSelect).toBe("none");
  });
});
