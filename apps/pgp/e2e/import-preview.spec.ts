import { readFile } from "node:fs/promises";
import type { BrowserContext, Page } from "@playwright/test";

import { expect, test } from "./fixtures";
import {
  decryptInWorkspace,
  encryptToSelfInWorkspace,
  generateSshKeys,
  goToKeys,
  importContact,
  importFileInPanel,
  onboardWithPassword,
  onboardWithPasswordSkipKey,
  readContacts,
} from "./helpers";
import { keyBySlug } from "./keys";
import { PRIVATE_KEY_FIXTURE } from "./private-key";

const PASSWORD = "correct horse battery staple";
const contact = keyBySlug("standard");

/** Drop key text on the contacts drop zone, the way a user would. */
async function dropOnContacts(panel: Page, armored: string) {
  await goToKeys(panel);
  await panel
    .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt"]')
    .setInputFiles({
      name: "key.asc",
      mimeType: "application/pgp-keys",
      buffer: Buffer.from(armored, "utf8"),
    });
}

test("importing shows the key, never its armor", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  await importFileInPanel(panel, contact.publicKey);

  const page = panel.getByRole("region", { name: "Import key" });
  // The whole point: identity and fingerprint, not a base64 blob.
  await expect(page.getByText(contact.label).first()).toBeVisible();
  await expect(page.getByText("Fingerprint")).toBeVisible();
  await expect(page).not.toContainText("BEGIN PGP");
  await expect(page).not.toContainText("END PGP");

  await panel.getByRole("button", { name: "Import contact" }).click();
  await expect(page).toBeHidden();
  await expect(panel.getByText(contact.label).first()).toBeVisible();
});

test("the imported card is highlighted in the list", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await dropOnContacts(panel, contact.publicKey);
  await panel.getByRole("button", { name: "Import contact" }).click();

  // The card pulses so the eye lands on what just changed. The class is
  // dropped on a timer, so this asserts while it is still on.
  await expect(panel.locator(".just-imported")).toHaveCount(1);
  await expect(panel.locator(".just-imported")).toContainText(contact.label);
});

test("re-importing an unchanged key says so, and offers to show it", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, contact.publicKey);

  await dropOnContacts(panel, contact.publicKey);

  // The preview STAYS: sliding in and straight back out again was
  // disorienting. Nothing is written, and the offered action is the
  // useful one -- go and look at the key we already have.
  const page = panel.getByRole("region", { name: "Import key" });
  await expect(page.getByText("Already in your keys")).toBeVisible();
  await expect(
    panel.getByRole("button", { name: "Import contact" }),
  ).toHaveCount(0);

  await panel.getByRole("button", { name: "Show it in your keys" }).click();
  await expect(page).toBeHidden();
  await expect(panel.locator(".just-imported")).toContainText(contact.label);
  // Still exactly one card for this key -- not a second copy.
  await expect(panel.getByText(contact.label)).toHaveCount(1);
});

test("a private key previews before the protection step", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  await importFileInPanel(panel, PRIVATE_KEY_FIXTURE.privateKey);

  const page = panel.getByRole("region", { name: "Import key" });
  await expect(page.getByText("Private key")).toBeVisible();
  await expect(page).not.toContainText("BEGIN PGP");
  // Public keys import outright; a private one continues to protection.
  await expect(
    panel.getByRole("button", { name: "Import contact" }),
  ).toHaveCount(0);
  await panel.getByRole("button", { name: "Continue" }).click();
  await expect(panel.getByText("Choose how to protect")).toBeVisible();
});

test("an import never moves you; the toast offers the trip instead", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("#pgp-input").fill(contact.publicKey);

  await panel.getByRole("button", { name: "Import it as a contact" }).click();
  await panel.getByRole("button", { name: "Import contact" }).click();

  // Still exactly where they were -- importing a key is not a reason to
  // yank someone off what they were doing.
  await expect(panel.locator("#pgp-input")).toBeVisible();
  await expect(panel.getByRole("tab", { name: "Main" })).toHaveAttribute(
    "aria-selected",
    "true",
  );

  // The toast reports it and carries the trip as a button they can ignore.
  await expect(panel.getByText("Key added")).toBeVisible();
  await panel.getByRole("button", { name: "View key" }).click();
  await expect(panel.getByRole("tab", { name: "Keys" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(panel.locator(".just-imported")).toContainText(contact.label);
});

test("Back from an import you never asked for returns in one press", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("#pgp-input").fill(contact.publicKey);
  await panel.getByRole("button", { name: "Import it as a contact" }).click();

  const page = panel.getByRole("region", { name: "Import key" });
  await expect(page).toBeVisible();
  // One Back: no empty drop zone in between (there was no source step),
  // and no detour via the Keys tab.
  await panel.getByRole("button", { name: "Back" }).click();
  await expect(page).toBeHidden();
  await expect(panel.locator("#pgp-input")).toBeVisible();
  await expect(panel.getByRole("tab", { name: "Main" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
});

test("a key you already have is not offered for import", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, contact.publicKey);

  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("#pgp-input").fill(contact.publicKey);

  // We know we have it, so don't pretend otherwise.
  await expect(
    panel.getByText(new RegExp(`You already have ${contact.label}'s key`)),
  ).toBeVisible();
  await expect(
    panel.getByRole("button", { name: "Import it as a contact" }),
  ).toHaveCount(0);

  // The action takes you to the key, highlighted.
  await panel.getByRole("button", { name: "Show it in your keys" }).click();
  await expect(panel.locator(".just-imported")).toContainText(contact.label);
});

test("the paste box takes a key without ever holding one", async ({
  panel,
  context,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();

  // Focused on open, so the paste has an obvious home and needs no aiming.
  const box = panel.getByLabel("Paste a key");
  await expect(box).toBeFocused();

  // It is a target, not a field: typing lands nowhere and says why.
  await panel.keyboard.type("hello");
  await expect(box).toHaveValue("");
  await expect(panel.getByText(/Paste the whole key block/)).toBeVisible();

  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await panel.evaluate(
    (t) => navigator.clipboard.writeText(t),
    contact.publicKey,
  );
  await box.focus();
  await panel.keyboard.press(
    process.platform === "darwin" ? "Meta+V" : "Control+V",
  );

  // Straight to the preview, and the armor is never rendered -- not in
  // the box it was pasted into, not anywhere else.
  const page = panel.getByRole("region", { name: "Import key" });
  await expect(page.getByText("Fingerprint")).toBeVisible();
  await expect(page).not.toContainText("BEGIN PGP");
  await expect(panel.getByLabel("Paste a key")).toHaveCount(0);
});

test("a key inside a decrypted message can be imported from the result", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);

  // The way keys actually travel: a correspondent sends theirs inside a
  // message. Round-trip a real one through the app so the key is in
  // DECRYPTED OUTPUT, not just pasted into the box.
  const message = `Here's my new key, save it:\n\n${contact.publicKey}`;
  const armored = await encryptToSelfInWorkspace(panel, message);
  await decryptInWorkspace(panel, armored, "Here's my new key");

  await expect(
    panel.getByText(/This message contains Alice Example's public key/),
  ).toBeVisible();

  // Importing from the result opens the same preview as anywhere else...
  await panel.getByRole("button", { name: "Import it as a contact" }).click();
  const page = panel.getByRole("region", { name: "Import key" });
  await expect(page.getByText("Fingerprint")).toBeVisible();
  await panel.getByRole("button", { name: "Import contact" }).click();
  await expect(page).toBeHidden();

  // ...and afterwards the offer is replaced by the truth: we have it.
  await expect(
    panel.getByText(/You already have Alice Example's key/),
  ).toBeVisible();
  await expect(
    panel.getByRole("button", { name: "Import it as a contact" }),
  ).toHaveCount(0);
});

test("key details downloads the public key", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, contact.publicKey);
  await panel.getByRole("button", { name: "Key details" }).first().click();

  const download = panel.waitForEvent("download");
  await panel.getByRole("button", { name: "Download public key" }).click();
  const file = await download;
  // Named after the owner, and the armor is the public half only.
  expect(file.suggestedFilename()).toMatch(/-public\.asc$/);
  const body = await readFile(await file.path(), "utf8");
  expect(body).toContain("BEGIN PGP PUBLIC KEY BLOCK");
  expect(body).not.toContain("PRIVATE KEY");
});

// ── grouping several pasted SSH public keys ──────────────────────────
//
// Pasting 2+ SSH public lines used to bulk-import them, one contact per
// line, with no way back: the app cannot know whether three `.pub` files
// are three machines of one person or three different people, and it
// silently answered "three people". It now asks -- except when the lines
// answer for themselves by carrying the SAME comment.
//
// The property that carries the weight here is a STORAGE one ("exactly
// one contact holding three recipients"), so these assert on the
// decrypted contacts store. Counting cards in the DOM cannot tell one
// contact from a label that matched twice.

/** Paste `text` into the Import Key page's paste box with a real paste
 *  gesture -- the flow has no typable field, and this feature is reached
 *  by pasting. */
async function pasteIntoImport(
  panel: Page,
  context: BrowserContext,
  text: string,
): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  const box = panel.getByLabel("Paste a key");
  await expect(box).toBeFocused();
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await panel.evaluate((t) => navigator.clipboard.writeText(t), text);
  await box.focus();
  await panel.keyboard.press(
    process.platform === "darwin" ? "Meta+V" : "Control+V",
  );
}

/** The grouping question, as it appears on the preview. */
function groupNameField(panel: Page) {
  return panel.getByPlaceholder("e.g. Alice (all machines)");
}

test("SSH keys that agree on a comment are grouped without asking", async ({
  panel,
  context,
}) => {
  // The strictest rule that can exist: every line carries a comment and
  // every comment is byte-identical. The lines have said whose they are,
  // so there is nothing to ask.
  const keys = generateSshKeys(3, () => "alice@corp");
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await pasteIntoImport(
    panel,
    context,
    keys.map((k) => k.publicLineWithComment).join("\n"),
  );

  const page = panel.getByRole("region", { name: "Import key" });
  await expect(page.getByText("alice@corp").first()).toBeVisible();
  await expect(page.getByText("3 keys")).toBeVisible();
  // No question asked -- and the button says "contact", singular, rather
  // than the "Import 3 contacts" of the undecided case.
  await expect(groupNameField(panel)).toHaveCount(0);
  await expect(page.getByText(/^SHA256:/)).toHaveCount(3);
  await panel.getByRole("button", { name: "Import contact" }).click();
  await expect(page).toBeHidden();

  const stored = await readContacts(panel);
  expect(stored).toHaveLength(1);
  expect(stored[0].userIds).toEqual(["alice@corp"]);
  expect(stored[0].recipients?.map((r) => r.keyId)).toEqual(
    keys.map((k) => k.fingerprint),
  );
});

test("declining the grouping offer files the keys separately", async ({
  panel,
  context,
}) => {
  // Comments that do not agree: `root@web01` and `root@db02` share a user
  // and nothing else. Blank is the default and a real answer -- today's
  // behaviour, one contact per key.
  const keys = generateSshKeys(3, (i) => `root@host-${i + 1}`);
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await pasteIntoImport(
    panel,
    context,
    keys.map((k) => k.publicLineWithComment).join("\n"),
  );

  await expect(groupNameField(panel)).toBeVisible();
  // The footer states which answer the blank field is, instead of
  // leaving the user to infer it.
  const confirm = panel.getByRole("button", { name: "Import 3 contacts" });
  await expect(confirm).toBeVisible();
  await confirm.click();
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();

  const stored = await readContacts(panel);
  expect(stored).toHaveLength(3);
  // Three records of one key each -- not one record with three
  // recipients. `recipients` is written only when there is more than one
  // key, so its absence is what "a single-key contact" means on disk.
  expect(stored.map((c) => c.recipients)).toEqual([
    undefined,
    undefined,
    undefined,
  ]);
  expect(stored.map((c) => c.keyId).sort()).toEqual(
    keys.map((k) => k.fingerprint).sort(),
  );
});

test("naming the group files one contact holding every key", async ({
  panel,
  context,
}) => {
  const keys = generateSshKeys(3, (i) => `alice@machine-${i + 1}`);
  const name = "Alice (all machines)";
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await pasteIntoImport(
    panel,
    context,
    keys.map((k) => k.publicLineWithComment).join("\n"),
  );

  await groupNameField(panel).fill(name);
  // Typing a name changes what the button will do, so it changes what
  // the button says.
  await panel.getByRole("button", { name: "Import as one contact" }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();

  // ── the assertion this test exists for ────────────────────────────
  // ONE record, holding all three keys, under the name the user gave --
  // a storage property, so it is read out of storage. A hand-grouped
  // contact must reach the store in exactly the shape a fetched one
  // does, which is what makes the encrypt path treat them alike.
  const stored = await readContacts(panel);
  expect(stored).toHaveLength(1);
  expect(stored[0].userIds).toEqual([name]);
  expect(stored[0].recipients?.map((r) => r.keyId)).toEqual(
    keys.map((k) => k.fingerprint),
  );

  // And the name the user typed is what the list calls them.
  await goToKeys(panel);
  await expect(panel.getByText(name)).toHaveCount(1);
  await expect(panel.getByText("3 keys")).toBeVisible();
});
