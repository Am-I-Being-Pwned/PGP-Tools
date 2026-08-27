import { readFile } from "node:fs/promises";
import type { BrowserContext, Page } from "@playwright/test";

import type { SshKeyPair } from "./helpers";
import { expect, test } from "./fixtures";
import {
  ageStanzaTags,
  generateSshKeys,
  goToKeys,
  onboardWithPasswordSkipKey,
  readContacts,
  setEncryptToSelf,
  setWorkspaceMode,
  unlockWithPassword,
} from "./helpers";

/**
 * Importing a GitHub user's SSH keys, end to end -- and the one thing
 * about it that nothing else in this suite would catch.
 *
 * A person is not a key: a GitHub user commonly publishes three (laptop,
 * desktop, phone) and the contact holds all of them, because you cannot
 * know which machine they will read from. The failure mode of the whole
 * change is "encrypted to only the FIRST of the three", and that looks
 * perfect from the sender's side -- the import succeeds, the card shows
 * the contact, the encrypt succeeds, and the sender can even decrypt it
 * themselves. It surfaces weeks later as "I can't open your message".
 *
 * So the assertion that matters here is the last one: after encrypting
 * to a three-key contact, decrypt with the SECOND identity, and then
 * with the THIRD -- each time with the earlier identities deleted, so
 * nothing but that key's own stanza can be what worked.
 *
 * ── Interception ─────────────────────────────────────────────────────
 * The fetch happens in the MV3 service worker, not in the panel. In
 * Playwright 1.61 `context.route()` DOES reach service-worker requests:
 * the Chromium backend attaches a CRNetworkManager to every service
 * worker target and enables request interception whenever the context
 * has routes and `serviceWorkers` is not "block" (the default is
 * "allow"). That was read off the bundled implementation rather than
 * assumed -- see `CRServiceWorker._isNetworkInspectionEnabled` and the
 * `sw.updateRequestInterception()` call in `CRBrowserContext`. A CDP
 * session on the worker target is NOT usable here: `newCDPSession`
 * accepts only a Page or a Frame and throws on a Worker.
 *
 * The stub is verified rather than trusted: `stubGithubKeys` counts the
 * requests it served, and the test asserts the count. If interception
 * ever stops reaching the worker, the lookup hits the real api.github.com
 * (or fails offline) and the count assertion fails -- this spec cannot
 * quietly pass by never having intercepted anything.
 *
 * ── A KNOWN PRODUCT BUG THIS FILE CATCHES ────────────────────────────
 * "a GitHub user's three keys import as one contact, and all three can
 * decrypt" FAILS, and it is right to. The recipient chip resolves its
 * selection out of `[...myKeys, ...contacts]` by `keyId`
 * (`useWorkspaceOperations.selectedRecipientKeys`), and a contact record's
 * `keyId` is its HEAD key's fingerprint -- so when the user already holds
 * that same key as an identity of their own, the lookup finds the OWN key
 * first. An own key has no `recipients` list, `toSelectedRecipient` takes
 * its single-key branch, and the message is silently encrypted to that ONE
 * key instead of the contact's whole set. That is exactly the failure this
 * spec was written for, arrived at from an unexpected direction; it is
 * reported, not worked around here. The header of the ciphertext that test
 * produces carries a single `-> ssh-ed25519` stanza.
 *
 * The per-key tests below steer AROUND that bug on purpose (their contact's
 * head key is deliberately not one of the user's own), because they are
 * about a different property and a second test failing for the first
 * test's reason would prove nothing new.
 */

const PASSWORD = "correct horse battery staple";
const GITHUB_USER = "octocat";
const MESSAGE = "three machines, one message";

/**
 * Answer `https://api.github.com/users/*\/keys` with `lines`, in the
 * response shape the real endpoint uses (an array of `{id, key}`; the
 * parser reads `key` and ignores everything else).
 *
 * Returns a counter so the test can prove the stub was actually reached.
 */
async function stubGithubKeys(
  context: BrowserContext,
  lines: string[],
): Promise<{ count: () => number }> {
  let served = 0;
  await context.route("https://api.github.com/users/*/keys", async (route) => {
    served += 1;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(lines.map((key, id) => ({ id, key }))),
    });
  });
  return { count: () => served };
}

/** Answer the lookup with a failure status instead.
 *
 * `access-control-expose-headers` is set from `headers` rather than left
 * out, because this is a CROSS-ORIGIN read: the worker's fetch of
 * api.github.com can only see the CORS-safelisted response headers plus
 * whatever that header names. `x-ratelimit-reset` is not safelisted, so a
 * stub that merely SETS it hands the worker a header it is not allowed to
 * read -- `headers.get()` returns null and the reset time silently
 * vanishes. The real endpoint exposes it (verified against the live API);
 * a stub that did not would be less permissive than production and would
 * fail a test the shipped code passes. */
async function stubGithubStatus(
  context: BrowserContext,
  status: number,
  headers: Record<string, string> = {},
): Promise<void> {
  const exposed = Object.keys(headers);
  await context.route("https://api.github.com/users/*/keys", (route) =>
    route.fulfill({
      status,
      contentType: "application/json",
      headers: {
        ...headers,
        ...(exposed.length > 0
          ? { "access-control-expose-headers": exposed.join(", ") }
          : {}),
      },
      body: JSON.stringify({ message: "Not Found" }),
    }),
  );
}

/** Import an OpenSSH private key as one of the user's own identities,
 *  protected with `password`. */
async function importSshIdentity(
  panel: Page,
  keyPair: SshKeyPair,
): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  await panel
    .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt,.pem"]')
    .setInputFiles({
      name: "id_ed25519",
      mimeType: "text/plain",
      buffer: Buffer.from(keyPair.privateKey, "utf8"),
    });
  // Same preview every other kind gets; Continue moves to protection.
  await panel.getByRole("button", { name: "Continue" }).click();
  await panel.locator('input[name="protection"]').nth(1).check();
  await panel.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await panel.getByLabel("Confirm password").fill(PASSWORD);
  await panel.getByRole("button", { name: "Import", exact: true }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();
  await expect(panel.getByText(keyPair.comment).first()).toBeVisible();
}

/** Look up `user` on the Keys tab's import flow, landing on the preview. */
async function lookUpGithubUser(panel: Page, user: string): Promise<void> {
  await goToKeys(panel);
  // Wait for any previous import panel to finish sliding OUT before
  // opening a new one. The slide-over animates on a transform, so a
  // freshly-opened panel's controls are "visible" while still moving,
  // and Playwright's actionability check waits for stability -- which
  // never arrives if the old panel is animating away underneath. Only
  // the tests that import a key before looking one up hit this, which
  // is why it shows up in exactly one spec.
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();
  await panel.getByRole("button", { name: "Import Key" }).click();
  const field = panel.getByLabel(/look someone up/i);
  const lookUp = panel.getByRole("button", { name: "Look up", exact: true });
  // A fill that lands while the panel is still sliding in can be undone
  // by the re-render behind it: `fill` asserts the value it typed at the
  // moment it types it, so it returns happily and the field is empty a
  // frame later. The button is the only durable signal -- it is disabled
  // until the field holds something -- so re-fill until it goes live,
  // rather than spending the timeout clicking a dead control (which is
  // exactly how this read in CI: "element is not enabled", 28 retries).
  await expect
    .poll(async () => {
      await field.fill(user);
      return lookUp.isEnabled();
    })
    .toBe(true);
  await lookUp.click();
}

/** Delete one own key, typing its name into the confirmation. */
async function deleteOwnKey(panel: Page, name: string): Promise<void> {
  await goToKeys(panel);
  // The innermost div that both shows this key's name and carries a
  // card's own options button: the card root, without depending on any
  // class name.
  const card = panel
    .locator("div", {
      has: panel.getByRole("button", { name: "Key options" }),
    })
    .filter({ hasText: name })
    .last();
  await card.getByRole("button", { name: "Key options" }).click();
  await panel.getByRole("menuitem", { name: "Delete key" }).click();
  await panel.getByRole("textbox", { name: /to confirm/ }).fill(name);
  await panel.getByRole("button", { name: "Delete key permanently" }).click();
  await expect(panel.getByText(name)).toHaveCount(0);
}

/** Unlock every locked key on the Keys tab. Deleting a key does not lock
 *  the others, but an import that did not cache its unlock would leave
 *  one locked -- and a decrypt with no usable identity is exactly the
 *  false negative this spec must not produce. */
async function unlockAllKeys(panel: Page): Promise<void> {
  await goToKeys(panel);
  const unlocks = panel.getByRole("button", { name: "Unlock", exact: true });
  for (let i = await unlocks.count(); i > 0; i = await unlocks.count()) {
    await unlocks.first().click();
    const field = panel.getByPlaceholder("Enter password");
    await field.fill(PASSWORD);
    await field.press("Enter");
    await expect(unlocks).toHaveCount(i - 1);
  }
}

/** Decrypt `ciphertext` in the workspace and assert the plaintext. */
async function decryptExpecting(
  panel: Page,
  ciphertext: string,
  plaintext: string,
): Promise<void> {
  await unlockAllKeys(panel);
  await setWorkspaceMode(panel, "Decrypt");
  await panel.locator("textarea").first().fill(ciphertext);
  await panel.getByRole("button", { name: /^decrypt$/i }).click();
  await expect(panel.getByText(plaintext).first()).toBeVisible();
}

test("a GitHub user's three keys import as one contact, and all three can decrypt", async ({
  context,
  panel,
}) => {
  const keys = generateSshKeys(3);
  const github = await stubGithubKeys(
    context,
    keys.map((k) => k.publicLine),
  );

  // No PGP key: the only recipients in play are age ones, so nothing
  // here can accidentally be an OpenPGP round-trip.
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  for (const key of keys) await importSshIdentity(panel, key);

  await lookUpGithubUser(panel, GITHUB_USER);

  // The preview is the SAME body every other kind lands in, showing one
  // row per key. Every fingerprint in full, never "3 keys": the
  // fingerprints are the only out-of-band check the user has against
  // GitHub having handed back a key this person never published.
  const preview = panel.getByRole("region", { name: "Import key" });
  await expect(preview).toContainText(`${GITHUB_USER} (GitHub)`);
  await expect(preview).toContainText("Keys");
  await expect(preview.getByText(/^SHA256:/)).toHaveCount(3);
  await preview.getByRole("button", { name: "Import contact" }).click();
  await expect(preview).toBeHidden();
  expect(github.count()).toBe(1);

  // One contact, holding three keys, marked with where it came from.
  await goToKeys(panel);
  await expect(panel.getByText(`${GITHUB_USER} (GitHub)`)).toHaveCount(1);
  await expect(panel.getByText("3 keys").first()).toBeVisible();
  await expect(panel.getByText(`From github.com/${GITHUB_USER}`)).toBeVisible();

  // Encrypt to the contact -- one chip, one selection, three stanzas.
  await setWorkspaceMode(panel, "Encrypt");
  const recipients = panel.getByRole("combobox", { name: "Recipients" });
  await recipients.fill(GITHUB_USER);
  await recipients.press("Enter");
  await panel.locator("textarea").first().fill(MESSAGE);
  await panel.getByRole("button", { name: /^encrypt$/i }).click();
  const downloaded = panel.waitForEvent("download");
  await panel.getByRole("button", { name: "Download" }).click();
  const ciphertext = await readFile(await (await downloaded).path(), "utf8");
  expect(ciphertext).toContain("BEGIN AGE ENCRYPTED FILE");

  // ── the assertion this whole spec exists for ──────────────────────
  // Decrypting with key 1 would prove nothing: it is the contact's head
  // key, and "encrypted to only the first recipient" passes that test.
  // Delete it, and the only way the message opens is a second stanza.
  await deleteOwnKey(panel, keys[0].comment);
  await decryptExpecting(panel, ciphertext, MESSAGE);

  // And again: with the first two gone, only the THIRD key's stanza can
  // be what opened it.
  await deleteOwnKey(panel, keys[1].comment);
  await decryptExpecting(panel, ciphertext, MESSAGE);
});

test("re-looking up the same user updates the contact instead of adding a second", async ({
  context,
  panel,
}) => {
  const keys = generateSshKeys(3);
  // First fetch: two keys.
  const first = await stubGithubKeys(
    context,
    keys.slice(0, 2).map((k) => k.publicLine),
  );
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await lookUpGithubUser(panel, GITHUB_USER);
  await panel.getByRole("button", { name: "Import contact" }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();
  expect(first.count()).toBe(1);

  // Second fetch: the first key is gone and two new ones appeared, so
  // the record's OWN id changes. Matching by fingerprint would file this
  // as a new contact and leave a stale duplicate behind.
  await context.unroute("https://api.github.com/users/*/keys");
  await stubGithubKeys(context, [keys[1].publicLine, keys[2].publicLine]);
  await lookUpGithubUser(panel, GITHUB_USER);
  const preview = panel.getByRole("region", { name: "Import key" });
  await expect(preview).toContainText("Updates the key you already have");
  await expect(preview).toContainText("1 key added");
  await expect(preview).toContainText("1 key removed");
  await preview.getByRole("button", { name: "Update contact" }).click();
  await expect(preview).toBeHidden();

  // THE assertion: one RECORD, not one rendered label. The upsert is on
  // the contact's SOURCE (`{type: "github", user}`), not on its keyId --
  // the keyId moved when the first key stopped being published, so a
  // keyId-only upsert would leave the old record behind and this count
  // would be 2.
  const stored = await readContacts(panel);
  expect(stored).toHaveLength(1);
  expect(stored[0].source).toMatchObject({ type: "github", user: GITHUB_USER });
  // And it is the SECOND fetch's key set that survived.
  expect(stored[0].recipients?.map((r) => r.keyId)).toEqual([
    stored[0].keyId,
    expect.any(String),
  ]);

  await goToKeys(panel);
  await expect(panel.getByText(`${GITHUB_USER} (GitHub)`)).toHaveCount(1);
});

test("an unknown account is refused inline, without a toast", async ({
  context,
  panel,
}) => {
  await stubGithubStatus(context, 404);
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await lookUpGithubUser(panel, "definitely-not-a-real-account");

  // The message is actionable ("check the spelling"), so it stays on the
  // step in the error slot rather than expiring in a toast -- and the
  // flow stays on the source step, ready for another try.
  await expect(panel.getByRole("alert")).toContainText(/no GitHub account/i);
  await expect(panel.getByRole("button", { name: "Look up" })).toBeVisible();
});

test("an account with no SSH keys says so where the answer is expected", async ({
  context,
  panel,
}) => {
  // A real account that has simply published nothing: GitHub answers
  // `200 []`, which is a successful lookup with an empty result -- not
  // an error, and the only outcome in this flow the user cannot fix.
  const github = await stubGithubKeys(context, []);
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await lookUpGithubUser(panel, GITHUB_USER);
  expect(github.count()).toBe(1);

  // It is the ANSWER to the lookup, so it has to be noticed: its own
  // callout attached to the field, not a fourth muted line among the
  // standing help text, which is what it used to be.
  const status = panel.getByRole("status");
  await expect(status).toBeVisible();
  await expect(status).toContainText(
    new RegExp(`${GITHUB_USER} hasn't published any SSH keys`, "i"),
  );
  // Not the destructive slot: nothing failed and there is nothing to
  // retry, and painting a correct answer red teaches people to distrust
  // it (see githubFailureCopy).
  await expect(panel.getByRole("alert")).toHaveCount(0);
  // And it says what to do instead, on a step still able to do it.
  await expect(status).toContainText(/paste their key here instead/i);
  await expect(panel.getByRole("button", { name: "Look up" })).toBeVisible();
});

test("a rate limit says it is shared, and when it lifts", async ({
  context,
  panel,
}) => {
  const resetAt = Math.floor(Date.now() / 1000) + 10 * 60;
  await stubGithubStatus(context, 403, {
    "x-ratelimit-remaining": "0",
    "x-ratelimit-reset": String(resetAt),
  });
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await lookUpGithubUser(panel, GITHUB_USER);

  // "You have made too many requests" is the natural reading and it is
  // usually wrong: the lookup is unauthenticated, so the budget is per
  // IP address and an office or VPN shares one.
  const alert = panel.getByRole("alert");
  await expect(alert).toContainText(/IP address/);
  await expect(alert).toContainText(/Try again in about/);
});

test("a paste into the GitHub field is a username, not armor", async ({
  context,
  panel,
}) => {
  const [key] = generateSshKeys(1);
  const github = await stubGithubKeys(context, [key.publicLine]);
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();

  // The source step listens for paste on the DOCUMENT, because there is
  // no textarea to aim at. Without the field-aware bail, this paste is
  // claimed by that listener, preventDefault'd, and handed to the key
  // parser -- which says it doesn't look like a key while the field the
  // user pasted into stays empty.
  const field = panel.getByLabel(/look someone up/i);
  await field.focus();
  // A REAL paste gesture, because the bug is in a real paste listener: a
  // synthetic ClipboardEvent would not insert the text either, so it
  // could not tell the two behaviours apart.
  await panel.evaluate(async (user) => {
    await navigator.clipboard.writeText(user);
  }, GITHUB_USER);
  await field.press("ControlOrMeta+v");
  await expect(field).toHaveValue(GITHUB_USER);
  await expect(panel.getByRole("alert")).toHaveCount(0);

  // And the pasted name is what gets looked up.
  await panel.getByRole("button", { name: "Look up" }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toContainText(
    `${GITHUB_USER} (GitHub)`,
  );
  expect(github.count()).toBe(1);
});

// ── per-key enable/disable on a multi-key contact ─────────────────────

/**
 * Open a contact's key-details page. The card itself is the target: it
 * carries the click handler, so this is the same gesture a user makes.
 */
async function openContactDetails(panel: Page, label: string): Promise<void> {
  await goToKeys(panel);
  await panel.getByText(label, { exact: true }).click();
  await expect(
    panel.getByRole("region", { name: `Key details for ${label}` }),
  ).toBeVisible();
}

/** One key's row on the details page, found by the fingerprint it prints.
 *  The innermost div holding that text, so nothing depends on a class
 *  name -- and the fingerprint is unique on the page, because a multi-key
 *  contact deliberately has no head fingerprint in its facts card (it
 *  would be printing one of these rows twice, and implying a primary key
 *  this model does not have). */
function recipientRow(panel: Page, fingerprint: string) {
  return panel
    .locator("div")
    .filter({ has: panel.getByText(fingerprint, { exact: true }) })
    .last();
}

/** Force the workspace's "Decrypt with" identity, rather than accepting
 *  the one the panel auto-selected by matching the header. Located via
 *  its label because `KeySelector`'s trigger has no accessible name of
 *  its own and there are several comboboxes on screen. */
async function decryptWithIdentity(panel: Page, name: string): Promise<void> {
  const selector = panel
    .locator("div")
    .filter({ has: panel.getByText("Decrypt with", { exact: true }) })
    .last();
  await selector.getByRole("combobox").click();
  await panel.getByRole("option", { name, exact: true }).click();
  await expect(selector.getByRole("combobox")).toContainText(name);
}

test("a key turned off on a contact is left out of the message", async ({
  context,
  panel,
}) => {
  // FOUR keys, of which the user holds the last three as identities of
  // their own. The contact's HEAD key (keys[0]) is deliberately NOT one
  // of them: a contact record's id is its head key's fingerprint, and the
  // recipient chip resolves that id against the user's own keys first, so
  // a shared head key silently collapses the whole contact to one key.
  // That is a real (reported) bug, and not this test's subject -- see the
  // file header.
  const keys = generateSshKeys(4);
  await stubGithubKeys(
    context,
    keys.map((k) => k.publicLine),
  );
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  for (const key of keys.slice(1)) await importSshIdentity(panel, key);

  await lookUpGithubUser(panel, GITHUB_USER);
  const preview = panel.getByRole("region", { name: "Import key" });
  await preview.getByRole("button", { name: "Import contact" }).click();
  await expect(preview).toBeHidden();

  // Turn ONE key off -- one the user can also decrypt with, so "the
  // message didn't open" can only mean "there was no stanza for it".
  const off = keys[1];
  const label = `${GITHUB_USER} (GitHub)`;
  await openContactDetails(panel, label);
  await recipientRow(panel, off.fingerprint)
    .getByRole("button", { name: "Don't use", exact: true })
    .click();
  await expect(recipientRow(panel, off.fingerprint)).toContainText("Not used");

  // Persisted, not merely rendered: the toggle writes optimistically, so
  // the on-screen state proves nothing about the record an encrypt will
  // read. Polled because that write is in flight.
  await expect
    .poll(async () => {
      const [contact] = await readContacts(panel);
      return contact.recipients?.filter((r) => r.disabled).map((r) => r.keyId);
    })
    .toEqual([off.fingerprint]);

  // And it survives the panel being torn down and the store re-read from
  // disk -- a preference that only lives in a mounted component's state
  // would pass every assertion above.
  await panel.reload();
  await unlockWithPassword(panel, PASSWORD);
  await openContactDetails(panel, label);
  await expect(recipientRow(panel, off.fingerprint)).toContainText("Not used");
  await expect(
    recipientRow(panel, off.fingerprint).getByRole("button", {
      name: "Use",
      exact: true,
    }),
  ).toBeVisible();
  await panel.getByRole("button", { name: "Back" }).click();
  // The card says what the file will actually contain, not how many keys
  // the person has.
  await expect(panel.getByText("3 of 4 keys")).toBeVisible();

  // Encrypt with "Also encrypt to me" OFF: with it on, one of the user's
  // own keys rides along and adds a stanza that has nothing to do with
  // the contact's recipient list -- and here that key would BE the one
  // just turned off.
  await setEncryptToSelf(panel, false);
  const recipients = panel.getByRole("combobox", { name: "Recipients" });
  await recipients.fill(GITHUB_USER);
  await recipients.press("Enter");
  await panel.locator("textarea").first().fill(MESSAGE);
  await panel.getByRole("button", { name: /^encrypt$/i }).click();
  const downloaded = panel.waitForEvent("download");
  await panel.getByRole("button", { name: "Download" }).click();
  const ciphertext = await readFile(await (await downloaded).path(), "utf8");

  // ── the assertion this test exists for, part one ──────────────────
  // WHICH keys the file is encrypted to, read straight off its own
  // header. "It still decrypts" cannot tell an excluded key from an
  // included one; a missing stanza tag can.
  expect(ageStanzaTags(ciphertext).sort()).toEqual(
    [keys[0], keys[2], keys[3]].map((k) => k.stanzaTag).sort(),
  );

  // ── part two: the same fact, in the terms the user experiences ────
  // Forced onto the disabled key's identity (the panel would otherwise
  // helpfully pick one that works), the message does not open.
  await unlockAllKeys(panel);
  await setWorkspaceMode(panel, "Decrypt");
  await panel.locator("textarea").first().fill(ciphertext);
  await decryptWithIdentity(panel, off.comment);
  await panel.getByRole("button", { name: /^decrypt$/i }).click();
  await expect(panel.getByRole("alert")).toContainText(
    /isn't encrypted to any of your SSH keys/,
  );
  await expect(panel.getByText(MESSAGE)).toHaveCount(0);

  // Positive control for that failure: the ciphertext is fine, and an
  // identity that was NOT turned off opens it. Without this, "decryption
  // failed" would also be satisfied by an encrypt that produced garbage.
  await decryptWithIdentity(panel, keys[2].comment);
  await panel.getByRole("button", { name: /^decrypt$/i }).click();
  await expect(panel.getByText(MESSAGE).first()).toBeVisible();
});

test("the last key in use on a contact cannot be turned off", async ({
  context,
  panel,
}) => {
  // Two keys, so one toggle reaches the boundary. No own identities are
  // needed: this is about the control, not about what decrypts.
  const keys = generateSshKeys(2);
  await stubGithubKeys(
    context,
    keys.map((k) => k.publicLine),
  );
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await lookUpGithubUser(panel, GITHUB_USER);
  await panel.getByRole("button", { name: "Import contact" }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();

  await openContactDetails(panel, `${GITHUB_USER} (GitHub)`);
  await recipientRow(panel, keys[0].fingerprint)
    .getByRole("button", { name: "Don't use", exact: true })
    .click();
  await expect(recipientRow(panel, keys[0].fingerprint)).toContainText(
    "Not used",
  );

  // Dimmed WITH a reason rather than hidden -- and genuinely inert, not
  // merely styled: `toBeDisabled` is the assertion, because a control
  // that only LOOKS disabled would still encrypt to nobody when clicked.
  const last = recipientRow(panel, keys[1].fingerprint).getByRole("button", {
    name: "Don't use",
    exact: true,
  });
  await expect(last).toBeDisabled();
  await expect(last).toHaveAttribute(
    "title",
    /only key left in use.*encrypt messages to nobody/,
  );

  // Nothing changed underneath it either: still exactly one key off.
  const [contact] = await readContacts(panel);
  expect(contact.recipients?.filter((r) => r.disabled)).toHaveLength(1);
});
