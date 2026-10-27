import type { Locator, Page } from "@playwright/test";

import { expect, test } from "./fixtures";
import {
  deliverPendingOp,
  dropContactsFile,
  goToKeys,
  importContactsBulk,
  pasteIntoImport,
  readContacts,
  reviewImportButton,
  seedVault,
  verifySignedMessage,
} from "./helpers";
import { IDENTITY_KEYS } from "./identity-keys";

// Binding a name and an address to a key is the user's call, never the
// app's. A key file is attacker-supplied text: a bundle can carry a
// DIFFERENT key wearing a saved contact's exact user ID, and it used to
// be saved without anyone seeing it. These pin the fix end to end:
// every import is listed on a Review before anything is written, a key
// claiming someone's identity starts on Skip and says whose, and the
// one statement about who a key belongs to -- "verified" -- is made only
// by the user and never handed to a different key.

const PASSWORD = "correct horse battery staple";

const ALICE = IDENTITY_KEYS.alice;
const ALICE_MINIMAL = IDENTITY_KEYS.aliceMinimal;
const ALICE_UPDATED = IDENTITY_KEYS.aliceUpdated;
const IMPOSTOR = IDENTITY_KEYS.impostor;
const OTHER_EMAIL = IDENTITY_KEYS.otherEmail;
const LOOKALIKE = IDENTITY_KEYS.lookalike;
const BOB = IDENTITY_KEYS.bob;

/** The 16-hex key id the panel prints. */
const shortId = (fingerprint: string) => fingerprint.slice(-16).toUpperCase();

const importPage = (panel: Page) =>
  panel.getByRole("region", { name: "Import key" });

/** One key's row on the import Review. */
const reviewRow = (panel: Page, fingerprint: string) =>
  panel.locator(`[data-review-key="${fingerprint}"]`);

/** One contact's card on the Keys tab. */
const contactCard = (panel: Page, fingerprint: string) =>
  panel.locator(`[data-select-id="contact:${fingerprint}"]`);

const choice = (row: Locator, label: string) =>
  row.getByRole("radio", { name: label, exact: true });

async function storedFingerprints(panel: Page): Promise<string[]> {
  return (await readContacts(panel)).map((c) => c.keyId.toUpperCase()).sort();
}

/** The two ways an untrusted bundle reaches the import flow. */
type Delivery = "file drop" | "context menu";

async function deliverBundle(
  panel: Page,
  how: Delivery,
  armored: string[],
): Promise<void> {
  if (how === "file drop") {
    await dropContactsFile(panel, armored);
  } else {
    // "Open in PGP Tools" on a page's selection: the background writes
    // the pending op and the panel routes it to the Import page.
    await deliverPendingOp(panel, "import-public", armored.join("\n"));
  }
  await expect(importPage(panel).getByText("Review keys")).toBeVisible();
}

/** Assert the impostor's row: the address warning naming Alice and her
 *  key id, starting on Skip, with all three choices offered. */
async function expectAddressConflict(panel: Page): Promise<Locator> {
  const row = reviewRow(panel, IMPOSTOR.fingerprint);
  await expect(row).toBeVisible();
  // The row shows who the key claims to be AND which key it is.
  await expect(row).toContainText("alice@example.test");
  await expect(row).toContainText(shortId(IMPOSTOR.fingerprint));
  await expect(row).toContainText(
    `alice@example.test already belongs to Alice (${shortId(ALICE.fingerprint)})`,
  );
  await expect(choice(row, "Skip")).toHaveAttribute("aria-checked", "true");
  await expect(choice(row, "Keep both")).toHaveAttribute(
    "aria-checked",
    "false",
  );
  await expect(choice(row, "Replace")).toBeVisible();
  // "Keep both", not a plain "Import": the choice says what it does.
  await expect(choice(row, "Import")).toHaveCount(0);
  return row;
}

/** Open a contact's details from its card. */
async function openContactDetails(
  panel: Page,
  fingerprint: string,
): Promise<Locator> {
  await goToKeys(panel);
  await contactCard(panel, fingerprint)
    .getByRole("button", { name: "Key details" })
    .click();
  const details = panel.getByRole("region", { name: /^Key details for/ });
  await expect(details).toBeVisible();
  return details;
}

async function closeDetails(panel: Page, details: Locator): Promise<void> {
  await details.getByRole("button", { name: "Back", exact: true }).click();
  await expect(details).toBeHidden();
}

async function markVerified(panel: Page, fingerprint: string): Promise<void> {
  const details = await openContactDetails(panel, fingerprint);
  await details.getByRole("button", { name: "Mark as verified" }).click();
  await expect(details.getByText(/^Verified by you on /)).toBeVisible();
  await closeDetails(panel, details);
}

/** Open the encrypt recipient dropdown on the Main tab. */
async function openRecipientPicker(panel: Page): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.getByRole("radio", { name: "Encrypt", exact: true }).click();
  await panel.getByRole("combobox", { name: "Recipients" }).click();
  await expect(panel.getByRole("option").first()).toBeVisible();
}

const recipientRow = (panel: Page, fingerprint: string) =>
  panel.getByRole("option").filter({ hasText: shortId(fingerprint) });

// ── 1. the advisory's proof of concept ─────────────────────────────────

for (const how of ["file drop", "context menu"] as const) {
  test(`${how}: a bundle smuggling a new key under a contact's identity stops on the Review, and Skip leaves it out`, async ({
    panel,
  }) => {
    await seedVault(panel, PASSWORD, [ALICE.publicKey]);
    expect(await storedFingerprints(panel)).toEqual([ALICE.fingerprint]);

    // A plain copy of Alice's key (so the bundle looks like hers), the
    // impostor wearing her exact user ID, and an innocent bystander.
    await deliverBundle(panel, how, [
      ALICE_MINIMAL.publicKey,
      IMPOSTOR.publicKey,
      BOB.publicKey,
    ]);
    const page = importPage(panel);
    await expect(
      page.getByText("3 keys found. Nothing is saved until you choose."),
    ).toBeVisible();

    await expectAddressConflict(panel);
    // Alice's own copy changes nothing: listed, with no choice to make.
    const aliceRow = reviewRow(panel, ALICE.fingerprint);
    await expect(aliceRow).toContainText("Already saved");
    await expect(aliceRow.getByRole("radiogroup")).toHaveCount(0);
    // The bystander is new and unclaimed: it starts on Import.
    const bobRow = reviewRow(panel, BOB.fingerprint);
    await expect(bobRow).toContainText("New");
    await expect(choice(bobRow, "Import")).toHaveAttribute(
      "aria-checked",
      "true",
    );
    // "Import all" is still there, but it says what it would do.
    await expect(
      page.getByRole("button", { name: "Import all anyway" }),
    ).toBeVisible();
    await expect(
      page.getByText("Includes 1 key that claims someone you already have."),
    ).toBeVisible();

    // ── the invariant: NOTHING is written before the user chooses ────
    expect(await storedFingerprints(panel)).toEqual([ALICE.fingerprint]);

    await reviewImportButton(panel, 1).click();
    await expect(page).toBeHidden();
    expect(await storedFingerprints(panel)).toEqual(
      [ALICE.fingerprint, BOB.fingerprint].sort(),
    );
    await expect(contactCard(panel, IMPOSTOR.fingerprint)).toHaveCount(0);
  });

  test(`${how}: "Keep both" saves the impostor beside Alice, and both are marked "Same address"`, async ({
    panel,
  }) => {
    await seedVault(panel, PASSWORD, [ALICE.publicKey]);
    await deliverBundle(panel, how, [
      ALICE_MINIMAL.publicKey,
      IMPOSTOR.publicKey,
    ]);
    const row = await expectAddressConflict(panel);
    // One key to decide on: no "Import all" for a choice of one.
    await expect(
      importPage(panel).getByRole("button", { name: /^Import all/ }),
    ).toHaveCount(0);
    await expect(
      importPage(panel).getByRole("button", { name: "Nothing selected" }),
    ).toBeDisabled();

    await choice(row, "Keep both").click();
    await reviewImportButton(panel, 1).click();
    await expect(importPage(panel)).toBeHidden();

    expect(await storedFingerprints(panel)).toEqual(
      [ALICE.fingerprint, IMPOSTOR.fingerprint].sort(),
    );
    await goToKeys(panel);
    for (const fpr of [ALICE.fingerprint, IMPOSTOR.fingerprint]) {
      await expect(
        contactCard(panel, fpr).getByText("Same address", { exact: true }),
      ).toBeVisible();
    }

    // The encrypt picker tells the two apart by key id, and flags both.
    await openRecipientPicker(panel);
    for (const fpr of [ALICE.fingerprint, IMPOSTOR.fingerprint]) {
      const option = recipientRow(panel, fpr);
      await expect(option).toHaveCount(1);
      await expect(option).toContainText("Same address");
    }
  });

  test(`${how}: "Replace" swaps Alice's key for the new one, and the new key is not verified`, async ({
    panel,
  }) => {
    await seedVault(panel, PASSWORD, [ALICE.publicKey]);
    // Alice's key was verified -- which must never carry over to a
    // different key that takes its place.
    await markVerified(panel, ALICE.fingerprint);

    await deliverBundle(panel, how, [
      ALICE_MINIMAL.publicKey,
      IMPOSTOR.publicKey,
    ]);
    const row = await expectAddressConflict(panel);
    await choice(row, "Replace").click();
    expect(await storedFingerprints(panel)).toEqual([ALICE.fingerprint]);
    await reviewImportButton(panel, 1).click();
    await expect(importPage(panel)).toBeHidden();

    const stored = await readContacts(panel);
    expect(stored.map((c) => c.keyId.toUpperCase())).toEqual([
      IMPOSTOR.fingerprint,
    ]);
    expect(stored[0].verified).toBeUndefined();
    expect(stored[0].verifiedAt).toBeUndefined();
    expect(stored[0].previousKeyIds?.map((k) => k.toUpperCase())).toEqual([
      ALICE.fingerprint,
    ]);

    await goToKeys(panel);
    const card = contactCard(panel, IMPOSTOR.fingerprint);
    await expect(card).toBeVisible();
    await expect(card.getByText("Verified", { exact: true })).toHaveCount(0);
    const details = await openContactDetails(panel, IMPOSTOR.fingerprint);
    await expect(
      details.getByRole("button", { name: "Mark as verified" }),
    ).toBeVisible();
  });
}

// ── 2. one key is enough to get the Review ─────────────────────────────

test("a single pasted key claiming a contact's address gets the Review, not the plain preview", async ({
  panel,
  context,
}) => {
  await seedVault(panel, PASSWORD, [ALICE.publicKey]);
  await pasteIntoImport(panel, context, IMPOSTOR.publicKey);

  const page = importPage(panel);
  await expect(page.getByText("Review keys")).toBeVisible();
  await expect(
    page.getByText("1 key found. Nothing is saved until you choose."),
  ).toBeVisible();
  await expectAddressConflict(panel);
  // Not the single-key preview, whose button would save in one click.
  await expect(
    page.getByRole("button", { name: "Import contact" }),
  ).toHaveCount(0);
  // A single key is never "Import all".
  await expect(page.getByRole("button", { name: /^Import all/ })).toHaveCount(
    0,
  );
  expect(await storedFingerprints(panel)).toEqual([ALICE.fingerprint]);
});

// ── 2b. two new keys in one bundle claiming one address ────────────────

test("two new keys in one bundle sharing an address are both held back, with no Replace", async ({
  panel,
}) => {
  // Nobody is saved yet: the clash is between the incoming keys
  // themselves, and neither one is "the real Alice" to the app.
  await seedVault(panel, PASSWORD);
  await deliverBundle(panel, "file drop", [
    ALICE.publicKey,
    IMPOSTOR.publicKey,
    BOB.publicKey,
  ]);
  for (const key of [ALICE, IMPOSTOR]) {
    const row = reviewRow(panel, key.fingerprint);
    await expect(row).toContainText("alice@example.test already belongs to");
    await expect(choice(row, "Skip")).toHaveAttribute("aria-checked", "true");
    await expect(choice(row, "Keep both")).toBeVisible();
    // The other holder is not a stored contact: nothing to replace.
    await expect(choice(row, "Replace")).toHaveCount(0);
  }
  await expect(
    choice(reviewRow(panel, BOB.fingerprint), "Import"),
  ).toHaveAttribute("aria-checked", "true");
  await expect(
    importPage(panel).getByText(
      "Includes 2 keys that claim someone you already have.",
    ),
  ).toBeVisible();
  expect(await readContacts(panel)).toEqual([]);

  await reviewImportButton(panel, 1).click();
  await expect(importPage(panel)).toBeHidden();
  expect(await storedFingerprints(panel)).toEqual([BOB.fingerprint]);
});

// ── 3. names that read the same ────────────────────────────────────────

test("the same name under another address, or a Cyrillic look-alike, is a name conflict with no Replace", async ({
  panel,
}) => {
  // The look-alike fixture's first letter really is Cyrillic, not Latin.
  const cyrillicA = String.fromCharCode(0x410);
  expect(LOOKALIKE.uid.startsWith(`${cyrillicA}lice `)).toBe(true);
  expect(LOOKALIKE.uid.startsWith("Alice")).toBe(false);

  await seedVault(panel, PASSWORD, [ALICE.publicKey]);

  for (const key of [OTHER_EMAIL, LOOKALIKE]) {
    await dropContactsFile(panel, [key.publicKey]);
    const page = importPage(panel);
    await expect(page.getByText("Review keys")).toBeVisible();
    const row = reviewRow(panel, key.fingerprint);
    await expect(row).toContainText(
      `Same name as Alice (${shortId(ALICE.fingerprint)}), but a different key.`,
    );
    await expect(choice(row, "Skip")).toHaveAttribute("aria-checked", "true");
    await expect(choice(row, "Keep both")).toBeVisible();
    // Replace is for an address: a name match is not the same person.
    await expect(choice(row, "Replace")).toHaveCount(0);
    expect(await storedFingerprints(panel)).toEqual([ALICE.fingerprint]);

    // Back out: still nothing saved.
    await page.getByRole("button", { name: "Back", exact: true }).click();
    await expect(page).toBeHidden();
    expect(await storedFingerprints(panel)).toEqual([ALICE.fingerprint]);
  }

  // Kept deliberately, both cards say "Same name".
  await dropContactsFile(panel, [LOOKALIKE.publicKey]);
  await choice(reviewRow(panel, LOOKALIKE.fingerprint), "Keep both").click();
  await reviewImportButton(panel, 1).click();
  await expect(importPage(panel)).toBeHidden();
  await goToKeys(panel);
  for (const fpr of [ALICE.fingerprint, LOOKALIKE.fingerprint]) {
    await expect(
      contactCard(panel, fpr).getByText("Same name", { exact: true }),
    ).toBeVisible();
  }
});

// ── 4. "Mark as verified" ──────────────────────────────────────────────

test("marking a contact verified shows everywhere, survives a re-import of the same key, and can be undone", async ({
  panel,
}) => {
  await seedVault(panel, PASSWORD, [ALICE.publicKey]);
  const card = contactCard(panel, ALICE.fingerprint);
  await expect(card.getByText("Verified", { exact: true })).toHaveCount(0);

  await markVerified(panel, ALICE.fingerprint);
  await expect(card.getByText("Verified", { exact: true })).toBeVisible();
  let [stored] = await readContacts(panel);
  expect(stored.verified).toBe(true);
  expect(typeof stored.verifiedAt).toBe("number");

  await openRecipientPicker(panel);
  await expect(recipientRow(panel, ALICE.fingerprint)).toContainText(
    "Verified",
  );
  await panel.keyboard.press("Escape");

  // The same key again, unchanged: nothing to save, no Review.
  await dropContactsFile(panel, [ALICE.publicKey]);
  const page = importPage(panel);
  await expect(page).toBeVisible();
  await expect(page.getByText("Review keys")).toHaveCount(0);
  await page.getByRole("button", { name: "Back", exact: true }).click();
  await expect(page).toBeHidden();

  // A real update of Alice's OWN key (a new subkey): same fingerprint, so
  // it is the key she verified, and the mark stays.
  const armorBefore = stored.armoredPublicKey;
  await dropContactsFile(panel, [ALICE_UPDATED.publicKey]);
  await expect(page.getByText("Review keys")).toHaveCount(0);
  await page.getByRole("button", { name: "Update contact" }).click();
  await expect(page).toBeHidden();
  [stored] = await readContacts(panel);
  // The record really was rewritten with the new subkey...
  expect(stored.armoredPublicKey).not.toEqual(armorBefore);
  expect(stored.verified).toBe(true);
  await goToKeys(panel);
  await expect(card.getByText("Verified", { exact: true })).toBeVisible();

  // Unmark.
  const details = await openContactDetails(panel, ALICE.fingerprint);
  await expect(details.getByText(/^Verified by you on /)).toBeVisible();
  await details.getByRole("button", { name: "Unmark" }).click();
  await expect(
    details.getByRole("button", { name: "Mark as verified" }),
  ).toBeVisible();
  await closeDetails(panel, details);
  await expect(card.getByText("Verified", { exact: true })).toHaveCount(0);
  [stored] = await readContacts(panel);
  expect(stored.verified).toBeUndefined();

  await openRecipientPicker(panel);
  await expect(recipientRow(panel, ALICE.fingerprint)).not.toContainText(
    "Verified",
  );
});

// ── 5. the picker shows which key ──────────────────────────────────────

test("every PGP row in the recipient picker shows its 16-hex key id", async ({
  panel,
}) => {
  await seedVault(panel, PASSWORD, [ALICE.publicKey, BOB.publicKey]);
  await openRecipientPicker(panel);

  for (const key of [ALICE, BOB]) {
    const option = recipientRow(panel, key.fingerprint);
    await expect(option).toHaveCount(1);
    await expect(option.locator("[data-key-id]")).toHaveText(
      new RegExp(`^${shortId(key.fingerprint)}`),
    );
  }
  // Own key included: every row carries one.
  const options = panel.getByRole("option");
  const count = await options.count();
  expect(count).toBeGreaterThanOrEqual(3);
  for (let i = 0; i < count; i++) {
    await expect(options.nth(i).locator("[data-key-id]")).toHaveText(
      /^[0-9A-F]{16}/,
    );
  }
});

// ── 6. a backup is reviewed too ────────────────────────────────────────

test("restoring a backup with conflicting keys opens the Review, and Import all anyway takes everything", async ({
  panel,
}) => {
  await seedVault(panel, PASSWORD, [ALICE.publicKey]);

  await panel.getByRole("tab", { name: "Settings" }).click();
  await panel.getByRole("button", { name: "Import keys" }).click();
  await panel
    .getByPlaceholder("Paste keys here, or browse for a file...")
    .fill(
      [
        ALICE_MINIMAL.publicKey,
        IMPOSTOR.publicKey,
        OTHER_EMAIL.publicKey,
        BOB.publicKey,
      ].join("\n"),
    );
  await panel.getByRole("button", { name: "Next" }).click();

  await expect(
    panel.getByText("4 keys found. Nothing is saved until you choose."),
  ).toBeVisible();
  await expectAddressConflict(panel);
  await expect(
    choice(reviewRow(panel, OTHER_EMAIL.fingerprint), "Skip"),
  ).toHaveAttribute("aria-checked", "true");
  await expect(
    panel.getByText("Includes 2 keys that claim someone you already have."),
  ).toBeVisible();
  expect(await storedFingerprints(panel)).toEqual([ALICE.fingerprint]);

  await panel.getByRole("button", { name: "Import all anyway" }).click();
  await expect(panel.getByText("Added 3 contacts").first()).toBeVisible();
  expect(await storedFingerprints(panel)).toEqual(
    [
      ALICE.fingerprint,
      IMPOSTOR.fingerprint,
      OTHER_EMAIL.fingerprint,
      BOB.fingerprint,
    ].sort(),
  );
});

// ── 7. a good signature is not a verified identity ─────────────────────

test("a good signature from a contact not marked verified says so, and stops once it is", async ({
  panel,
}) => {
  await seedVault(panel, PASSWORD, [ALICE.publicKey]);
  const signed = ALICE.signedMessage;

  await verifySignedMessage(panel, signed);
  await expect(panel.getByText("Signature verified")).toBeVisible();
  await expect(
    panel.getByText(/key not marked verified by you/).first(),
  ).toBeVisible();

  await markVerified(panel, ALICE.fingerprint);
  // The verdict replaces the input box; start a fresh verify.
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.getByRole("button", { name: "Clear input and output" }).click();
  await verifySignedMessage(panel, signed);
  await expect(panel.getByText("Signature verified")).toBeVisible();
  await expect(panel.getByText(/key not marked verified by you/)).toHaveCount(
    0,
  );
});

// Keep the bulk helper honest: seeding several unrelated keys still lands
// them all through the Review without a conflict in sight.
test("importContactsBulk seeds unrelated keys through the Review", async ({
  panel,
}) => {
  await seedVault(panel, PASSWORD);
  await importContactsBulk(panel, [ALICE.publicKey, BOB.publicKey]);
  expect(await storedFingerprints(panel)).toEqual(
    [ALICE.fingerprint, BOB.fingerprint].sort(),
  );
});
