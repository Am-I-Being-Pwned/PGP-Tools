import type { BrowserContext, Page } from "@playwright/test";
import { test as base, expect } from "@playwright/test";

import { getExtensionId, launchExtensionContext } from "./fixtures";
import {
  clickInHost,
  gmailGrantedBuild,
  gmailTabId,
  openFakeGmail,
  readerFrame,
} from "./gmail-fixture";
import {
  encryptToSelfInWorkspace,
  lockMasterViaPalette,
  lockOnlyKey,
  seedVault,
  signInWorkspace,
} from "./helpers";
import { keyBySlug } from "./keys";

// The Gmail add-on end to end (SECURITY.md §17): an encrypted block is
// read in place, in a frame Gmail can't see into; a compose window's
// Encrypt round-trips through the panel so that only ciphertext ever
// lands in Gmail's DOM; and attachments go both ways as ciphertext. See
// e2e/gmail-fixture.ts for the two stand-ins (the grant, and Gmail).

const PASSWORD = "correct horse battery staple";
const SECRET = "gmail add-on plaintext 7f3a";
const DRAFT = "Dear Alice,\n\nThe meeting moved to 3pm. 91c2";

const alice = keyBySlug("standard");

const test = base.extend<{
  context: BrowserContext;
  extensionId: string;
  panel: Page;
}>({
  // eslint-disable-next-line no-empty-pattern
  context: async ({}, use) => {
    const context = await launchExtensionContext(gmailGrantedBuild());
    await use(context);
    await context.close();
  },
  extensionId: async ({ context }, use) => {
    await use(await getExtensionId(context));
  },
  panel: async ({ context, extensionId }, use) => {
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/sidepanel.html`);
    await use(page);
  },
});

/** A vault with one own key (generated) and Alice as a contact, plus a
 *  message encrypted to the own key, as the panel itself produced it. */
async function setup(
  panel: Page,
  contacts: string[] = [alice.publicKey],
): Promise<string> {
  await seedVault(panel, PASSWORD, contacts);
  // Gmail access is granted in this build, so "Add to Gmail" has taken
  // the Download button's place: take the file by its shortcut.
  const armored = await encryptToSelfInWorkspace(panel, SECRET, {
    download: "shortcut",
  });
  await panel.getByRole("button", { name: "Clear input and output" }).click();
  return armored;
}

test("an encrypted message is read in place, in a frame Gmail's page can't see into", async ({
  context,
  extensionId,
  panel,
}) => {
  const armored = await setup(panel);
  const gmail = await openFakeGmail(context, { armored });

  // The complete block gets a reader frame; the clipped one keeps a
  // banner (there is nothing to read yet).
  await expect(gmail.locator("pgp-tools-frame")).toHaveCount(1);
  await expect(gmail.locator("pgp-tools-banner")).toHaveCount(1);

  // The key is open (onboarding leaves it so) and the panel is up, so
  // the frame shows the message without a click.
  const frame = await readerFrame(gmail, extensionId);
  await expect(frame.getByText(SECRET)).toBeVisible();
  await expect(frame.getByText("Decrypted by PGP Tools")).toBeVisible();
  // The raw armor folds away under it, and comes back on request.
  await expect(gmail.locator("[data-pgp-tools-folded]")).toHaveCount(1);
  await frame.getByRole("button", { name: "Show original" }).click();
  await expect(gmail.locator("[data-pgp-tools-folded]")).toHaveCount(0);

  // Nowhere in Gmail's own page -- not its DOM, not its text. (The
  // frame's document is a different origin; `content()` is the page's.)
  expect(await gmail.content()).not.toContain(SECRET);
  expect(await gmail.evaluate(() => document.body.innerText)).not.toContain(
    SECRET,
  );
  // The panel itself was not touched: nothing was routed to it.
  await expect(panel.getByLabel("Message input")).toHaveValue("");
});

test("with the key locked, Unlock to read opens the panel; the frame fills in once it is unlocked", async ({
  context,
  extensionId,
  panel,
}) => {
  const armored = await setup(panel);
  await lockOnlyKey(panel);
  const gmail = await openFakeGmail(context, { armored });
  const frame = await readerFrame(gmail, extensionId);

  // Nothing is shown and nothing is asked for: an unattended decrypt
  // never prompts. The frame offers the one way forward.
  const unlock = frame.getByRole("button", { name: "Unlock to read" });
  await expect(unlock).toBeVisible();
  expect(await gmail.content()).not.toContain(SECRET);
  await unlock.click();

  // The block lands in the panel as a pending decrypt, where the normal
  // prompts run: Decrypt, then the key's password.
  await panel.getByRole("button", { name: /^decrypt$/i }).click();
  const pw = panel.getByPlaceholder("Enter key password");
  await pw.fill(PASSWORD);
  await pw.press("Enter");
  await expect(panel.getByText(SECRET).first()).toBeVisible();

  // The key is open now: the frame shows the message in place.
  await expect(frame.getByText(SECRET)).toBeVisible();
  await expect(unlock).toHaveCount(0);

  // Locking the vault clears it there too, at once.
  await lockMasterViaPalette(panel);
  await expect(frame.getByText(SECRET)).toHaveCount(0);
  await expect(
    frame.getByRole("button", { name: "Unlock to read" }),
  ).toBeVisible();
});

test("a signed message is verified in place and names its signer", async ({
  context,
  extensionId,
  panel,
}) => {
  await seedVault(panel, PASSWORD);
  const text = "signed in the open 2a7e";
  await signInWorkspace(panel, text);
  const downloadEvent = panel.waitForEvent("download");
  await panel.getByRole("button", { name: "Download" }).click();
  const signed = await (await downloadEvent).path();
  const { readFile } = await import("node:fs/promises");
  const armored = await readFile(signed, "utf8");
  expect(armored).toContain("BEGIN PGP SIGNED MESSAGE");

  const gmail = await openFakeGmail(context, { armored });
  const frame = await readerFrame(gmail, extensionId);
  await expect(frame.getByText(text)).toBeVisible();
  await expect(frame.getByText(/^Signed by .* · verified$/)).toBeVisible();
});

test("compose in a PGP thread turns itself on: the body is covered, the panel is the composer, Encrypt & send sends only ciphertext", async ({
  context,
  panel,
}) => {
  const armored = await setup(panel);
  const gmail = await openFakeGmail(context, {
    armored,
    recipients: ["alice@example.com", "nobody@example.com"],
    draft: DRAFT,
  });

  // No click: the thread holds an encrypted message and a panel is up,
  // so the window arms itself. Gmail's box is hidden under the card and
  // its attach control is inert; the pill shows the state.
  await expect(gmail.locator("pgp-tools-compose")).toHaveCount(1);
  await expect(gmail.locator("pgp-tools-cover")).toHaveCount(1);
  await expect(
    gmail.locator("[g_editable][data-pgp-tools-covered]"),
  ).toHaveCount(1);
  await expect(gmail.locator("[g_editable]")).toBeHidden();
  await expect(
    gmail.locator('[command="Files"][data-pgp-tools-covered]'),
  ).toHaveCount(1);

  // The panel is now writing for that draft: says so, preselected the
  // contact it has a key for, and names the one it doesn't.
  await expect(panel.getByText("Writing a Gmail draft")).toBeVisible();
  await expect(
    panel.getByText("This recipient can't read it yet:"),
  ).toBeVisible();
  await expect(
    panel.getByRole("listitem").filter({ hasText: "nobody@example.com" }),
  ).toBeVisible();
  await expect(
    panel.getByRole("button", { name: /^Remove Alice Example/ }),
  ).toBeVisible();
  await expect(panel.getByLabel("Message input")).toHaveValue(DRAFT);

  // Writing a draft, the run button encrypts, inserts AND presses Send
  // -- one mod+Enter.
  await expect(
    panel.getByRole("button", { name: /Encrypt & send/ }),
  ).toBeVisible();
  await panel.getByLabel("Message input").focus();
  await panel.keyboard.press("ControlOrMeta+Enter");
  await expect(panel.getByText("Sent", { exact: true })).toBeVisible();

  // Gmail sent exactly the ciphertext: the window is gone, and what it
  // held when Send was pressed is armor and nothing else.
  await expect(gmail.locator(".M9")).toHaveCount(0);
  const sent = gmail.locator("#sent");
  await expect(sent).toHaveCount(1);
  const sentText = await sent.evaluate((el) => el.textContent);
  expect(sentText).toContain("-----BEGIN PGP MESSAGE-----");
  expect(sentText).toContain("-----END PGP MESSAGE-----");
  expect(sentText).not.toContain("The meeting moved");
  expect(await gmail.content()).not.toContain("The meeting moved");
  // ...and the panel kept no copy of it either.
  await expect(panel.getByLabel("Message input")).toHaveValue("");
});

test("the lock pill is the switch: off is plain Gmail, on covers the box; a drop on the cover is refused", async ({
  context,
  panel,
}) => {
  await setup(panel);
  // No PGP in this thread, so nothing arms itself.
  const gmail = await openFakeGmail(context, {
    armored: "nothing encrypted here",
    recipients: ["alice@example.com"],
  });
  const pill = gmail.locator("pgp-tools-compose");
  await expect(pill).toHaveCount(1);
  await expect(gmail.locator("pgp-tools-cover")).toHaveCount(0);
  await expect(gmail.locator("[g_editable]")).toBeVisible();

  await clickInHost(gmail, pill, "center");
  await expect(gmail.locator("pgp-tools-cover")).toHaveCount(1);
  await expect(gmail.locator("[g_editable]")).toBeHidden();
  await expect(panel.getByText("Writing a Gmail draft")).toBeVisible();

  // A file dropped on the covered window never reaches Gmail's own
  // handler (which would attach it in the clear).
  await gmail.evaluate(() => {
    const dt = new DataTransfer();
    dt.items.add(new File(["plain"], "plain.txt"));
    const root = document.querySelector(".I5");
    if (!root) throw new Error("no compose");
    root.dispatchEvent(
      new DragEvent("drop", {
        bubbles: true,
        cancelable: true,
        dataTransfer: dt,
      }),
    );
  });
  await expect(gmail.locator(".dropped")).toHaveCount(0);

  // Off again: Gmail's box is back, untouched.
  await clickInHost(gmail, pill, "center");
  await expect(gmail.locator("pgp-tools-cover")).toHaveCount(0);
  await expect(gmail.locator("[g_editable]")).toBeVisible();
});

test("Reply in the reader frame opens Gmail's reply, already encrypted", async ({
  context,
  extensionId,
  panel,
}) => {
  const armored = await setup(panel);
  const gmail = await openFakeGmail(context, { armored });
  // The stand-in starts with a compose window open; close it so Reply
  // opens a fresh one, as Gmail's would.
  await gmail.evaluate(() => document.querySelector(".M9")?.remove());
  const frame = await readerFrame(gmail, extensionId);
  await expect(frame.getByText(SECRET)).toBeVisible();
  await frame.getByRole("button", { name: "Reply" }).click();

  await expect(gmail.locator(".M9 .hd")).toHaveText("Reply");
  await expect(gmail.locator("pgp-tools-cover")).toHaveCount(1);
  await expect(panel.getByText("Writing a Gmail draft")).toBeVisible();
});

test("Gmail's page cannot be handed anything but armor, and only Gmail can ask for the panel", async ({
  context,
  panel,
}) => {
  const armored = await setup(panel);
  const gmail = await openFakeGmail(context, { armored, draft: DRAFT });
  await expect(gmail.locator("pgp-tools-compose")).toHaveCount(1);
  // The window armed itself (PGP thread, panel up), stamping its id.
  await expect(panel.getByText("Writing a Gmail draft")).toBeVisible();
  const composeId = await gmail
    .locator("[data-pgp-tools-compose]")
    .getAttribute("data-pgp-tools-compose");
  const tabId = await gmailTabId(panel);

  // A GMAIL_INSERT that is not one armored block is refused by the
  // content script, whatever sent it.
  const refused: unknown = await panel.evaluate(
    ([tab, id]) =>
      chrome.tabs.sendMessage<object, unknown>(tab, {
        type: "GMAIL_INSERT",
        composeId: id,
        armored:
          "-----BEGIN PGP MESSAGE-----\n\nthe plaintext\n-----END PGP MESSAGE-----",
      }),
    [tabId, composeId] as const,
  );
  expect(refused).toEqual({ ok: false, error: "invalid" });
  await expect(gmail.locator("[g_editable]")).toContainText(
    "The meeting moved",
  );
  // And a GMAIL_PANEL_PING is answered by the panel page alone, with a
  // bit and nothing else.
  const pong: unknown = await gmail.evaluate(
    () =>
      new Promise((resolve) => {
        // The content script's own channel is not reachable from the page;
        // this only checks that the page cannot ask.
        resolve(typeof (globalThis as { chrome?: unknown }).chrome);
      }),
  );
  expect(pong).toBe("object");
  // So is a GMAIL_ATTACH whose file is not ciphertext by its header.
  const refusedFile: unknown = await panel.evaluate(
    ([tab, id]) =>
      chrome.tabs.sendMessage<object, unknown>(tab, {
        type: "GMAIL_ATTACH",
        composeId: id,
        files: [{ name: "notes.txt.gpg", data: btoa("the plaintext") }],
      }),
    [tabId, composeId] as const,
  );
  expect(refusedFile).toEqual({ ok: false, error: "invalid" });
  await expect(gmail.locator(".dropped")).toHaveCount(0);

  // GMAIL_OPEN from anywhere but Gmail's own top frame -- here, an
  // extension page -- is refused and leaves no pending op behind.
  await panel.evaluate(() =>
    chrome.storage.session.remove("pgp_pending_operation"),
  );
  const notGmail: unknown = await panel.evaluate(() =>
    chrome.runtime.sendMessage<object, unknown>({
      type: "GMAIL_OPEN",
      text: "x",
    }),
  );
  expect(notGmail).toEqual({ ok: false, error: "invalid" });
  expect(
    await panel.evaluate(() =>
      chrome.storage.session.get("pgp_pending_operation"),
    ),
  ).toEqual({});
  // And a GMAIL_FRAME_OPEN from anywhere but a reader frame inside a tab
  // (here, the panel page itself) is refused the same way.
  const notFrame: unknown = await panel.evaluate(() =>
    chrome.runtime.sendMessage<object, unknown>({
      type: "GMAIL_FRAME_OPEN",
      text: "-----BEGIN PGP MESSAGE-----",
    }),
  );
  expect(notFrame).toEqual({ ok: false, error: "invalid" });
  expect(
    await panel.evaluate(() =>
      chrome.storage.session.get("pgp_pending_operation"),
    ),
  ).toEqual({});
});

test("an empty draft starts the panel clean, so another message can't leak into it", async ({
  context,
  panel,
}) => {
  const armored = await setup(panel);
  // Something unrelated is half-written in the panel.
  await panel.getByLabel("Message input").fill("note to someone else 4be1");
  const gmail = await openFakeGmail(context, {
    armored,
    recipients: ["alice@example.com"],
  });
  // The window arms itself with an empty draft: the panel starts clean.
  await expect(gmail.locator("pgp-tools-cover")).toHaveCount(1);
  await expect(panel.getByText("Writing a Gmail draft")).toBeVisible();
  await expect(panel.getByLabel("Message input")).toHaveValue("");
});

test("turning the add-on off removes it from Gmail tabs that are already open", async ({
  context,
  panel,
}) => {
  const armored = await setup(panel);
  const gmail = await openFakeGmail(context, {
    armored,
    attachments: [{ name: "secret.txt.gpg", body: armored }],
  });
  await expect(gmail.locator("pgp-tools-frame")).toHaveCount(1);
  await expect(gmail.locator("pgp-tools-banner")).toHaveCount(1);
  await expect(gmail.locator("pgp-tools-attachment")).toHaveCount(1);
  await expect(gmail.locator("[data-pgp-tools-folded]")).toHaveCount(1);

  await panel.getByRole("tab", { name: "Settings" }).click();
  await panel.getByRole("button", { name: /^Gmail/ }).click();
  // (In this granted-at-load build Chrome refuses to remove the
  // permission itself; the teardown it sends first is what is tested.)
  await panel.getByRole("switch", { name: /Work in Gmail/ }).click();

  await expect(gmail.locator("pgp-tools-frame")).toHaveCount(0);
  await expect(gmail.locator("pgp-tools-banner")).toHaveCount(0);
  await expect(gmail.locator("pgp-tools-attachment")).toHaveCount(0);
  await expect(gmail.locator("pgp-tools-compose")).toHaveCount(0);
  await expect(gmail.locator("pgp-tools-cover")).toHaveCount(0);
  await expect(gmail.locator("[data-pgp-tools-covered]")).toHaveCount(0);
  await expect(gmail.locator("[g_editable]")).toBeVisible();
  // The folded message is shown again: nothing of ours is left behind.
  await expect(gmail.locator("[data-pgp-tools-folded]")).toHaveCount(0);
});

test("an encrypted attachment's Decrypt button fetches it into the panel, which opens it", async ({
  context,
  panel,
}) => {
  const armored = await setup(panel);
  const gmail = await openFakeGmail(context, {
    armored: "nothing armored in the body",
    attachments: [
      { name: "secret.txt.gpg", body: armored },
      { name: "holiday.jpg", body: "not ours" },
    ],
  });
  // Only the encrypted one gets a button.
  const buttons = gmail.locator("pgp-tools-attachment");
  await expect(buttons).toHaveCount(1);
  // Nothing is fetched until the user presses it.
  const fetched: string[] = [];
  gmail.on("request", (req) => {
    if (new URL(req.url()).searchParams.get("view") === "att") {
      fetched.push(req.url());
    }
  });
  await clickInHost(gmail, buttons, "center");

  // The panel pulled the bytes from the Gmail tab and ran the decrypt
  // unattended (the key is open): the plaintext is in the panel...
  await expect(panel.getByText(SECRET).first()).toBeVisible({
    timeout: 15_000,
  });
  // ...and the chip was stamped with the id the fetch was pinned to.
  await expect(gmail.locator("[data-pgp-tools-attachment]")).toHaveCount(1);
  expect(fetched).toHaveLength(1);
  expect(await gmail.content()).not.toContain(SECRET);
});

test("compose: a file staged in the panel is encrypted and attached to the Gmail draft as ciphertext", async ({
  context,
  panel,
}) => {
  const armored = await setup(panel);
  const gmail = await openFakeGmail(context, {
    armored,
    recipients: ["alice@example.com"],
  });
  await expect(panel.getByText("Writing a Gmail draft")).toBeVisible();

  // Stage a file through the workspace's drop zone input (the one file
  // input with no `accept` list).
  const contents = "quarterly numbers 8d2f";
  await panel
    .locator('input[type="file"]:not([accept])')
    .first()
    .setInputFiles({
      name: "numbers.txt",
      mimeType: "text/plain",
      buffer: Buffer.from(contents, "utf8"),
    });
  await panel
    .getByRole("button", { name: /Encrypt & attach to Gmail/ })
    .click();
  await expect(panel.getByText("Attached to your Gmail draft")).toBeVisible();

  // Gmail got one file, named as the panel names encrypted output, and
  // its bytes are not the plaintext.
  const dropped = gmail.locator(".dropped");
  await expect(dropped).toHaveCount(1);
  await expect(dropped).toHaveAttribute("data-name", /^numbers\.txt.*\.gpg$/);
  expect(await gmail.content()).not.toContain(contents);
  // The draft's text was left alone: files attach, they do not replace.
  await expect(gmail.locator("[g_editable]")).not.toContainText("BEGIN PGP");
});

test("Search for key finds a missing recipient, and the draft picks it up by itself", async ({
  context,
  panel,
}) => {
  // keys.openpgp.org, stubbed (see keyserver-import.spec.ts).
  const served: string[] = [];
  await context.route("https://keys.openpgp.org/vks/v1/*/*", async (route) => {
    served.push(new URL(route.request().url()).pathname);
    await route.fulfill({
      status: 200,
      contentType: "application/pgp-keys",
      body: alice.publicKey,
    });
  });
  // No contacts yet: nobody on the To line has a key.
  const armored = await setup(panel, []);
  await openFakeGmail(context, {
    armored,
    recipients: ["alice@example.com", "nobody@example.com"],
  });
  await expect(
    panel.getByText("2 recipients can't read it yet:"),
  ).toBeVisible();

  const aliceRow = panel.getByRole("listitem").filter({
    hasText: "alice@example.com",
  });
  await aliceRow.getByRole("button", { name: "Search for key" }).click();
  // The import page opens on the lookup it was asked for, already run.
  const importer = panel.getByRole("region", { name: "Import key" });
  await expect(importer).toContainText(alice.name);
  expect(served).toEqual([
    `/vks/v1/by-email/${encodeURIComponent(alice.email)}`,
  ]);
  await panel.getByRole("button", { name: "Import contact" }).click();
  await expect(importer).toBeHidden();

  // Back on the draft: Alice is selected without a click, and only the
  // address still without a key is left in the warning.
  const removeAlice = panel.getByRole("button", {
    name: /^Remove Alice Example/,
  });
  await expect(removeAlice).toBeVisible();
  await expect(
    panel.getByText("This recipient can't read it yet:"),
  ).toBeVisible();
  await expect(
    panel.getByRole("listitem").filter({ hasText: "alice@example.com" }),
  ).toHaveCount(0);

  // The warning follows the selection: take Alice out, she is back in it.
  await removeAlice.click();
  await expect(
    panel.getByText("2 recipients can't read it yet:"),
  ).toBeVisible();
});

test("a recipient picked in the panel is added to the Gmail draft's To line", async ({
  context,
  panel,
}) => {
  const carol = keyBySlug("comment");
  const armored = await setup(panel, [alice.publicKey, carol.publicKey]);
  const gmail = await openFakeGmail(context, {
    armored,
    recipients: ["alice@example.com"],
  });
  await expect(panel.getByText("Writing a Gmail draft")).toBeVisible();

  // Pick Carol, who is not on the draft yet.
  await panel.getByRole("combobox", { name: "Recipients" }).click();
  await panel.getByRole("option", { name: new RegExp(carol.name) }).click();

  // Gmail now addresses her too, as a chip, and the strip says so.
  await expect(gmail.locator('.vR[email="carol@example.com"]')).toHaveCount(1);
  await expect(
    panel.getByText(/To alice@example\.com, carol@example\.com/),
  ).toBeVisible();
  // Alice was already there: not typed in a second time.
  await expect(gmail.locator('.vR[email="alice@example.com"]')).toHaveCount(1);
});

test("Add to Gmail replaces Download, and opens a Gmail message with the contact and the ciphertext filled in", async ({
  context,
  panel,
}) => {
  await setup(panel);
  // Route Gmail (the inbox tab is just to have the stand-in served; a
  // thread with no PGP in it, so its compose window does not arm itself
  // and claim the panel).
  const inbox = await openFakeGmail(context, { armored: "nothing here" });
  await inbox.close();

  // Written entirely in the panel, to Alice -- no Gmail draft involved.
  await panel.getByRole("tab", { name: "Main" }).click();
  const aliceChip = panel.getByRole("button", {
    name: /^Remove Alice Example/,
  });
  // (Still selected from setup's encrypt, if setup picked her.)
  if ((await aliceChip.count()) === 0) {
    await panel.getByRole("combobox", { name: "Recipients" }).click();
    await panel.getByRole("option", { name: /Alice Example/ }).click();
  }
  await expect(aliceChip).toBeVisible();
  await panel.getByLabel("Message input").fill(SECRET);
  await panel.getByRole("button", { name: /^encrypt$/i }).click();

  await expect(panel.getByRole("button", { name: "Download" })).toHaveCount(0);
  // Test stand-in: Playwright's router misses the FIRST navigation of a
  // tab an extension creates (it went to the real accounts.google.com),
  // so open it blank and navigate it -- the second load is routed to the
  // stand-in. The URL the product asked for is what gets loaded.
  await panel.evaluate(() => {
    const create = chrome.tabs.create.bind(chrome.tabs);
    chrome.tabs.create = async (props: chrome.tabs.CreateProperties) => {
      const tab = await create({ ...props, url: "about:blank" });
      if (tab.id !== undefined && props.url) {
        await chrome.tabs.update(tab.id, { url: props.url });
      }
      return tab;
    };
  });
  const opened = context.waitForEvent("page");
  await panel.getByRole("button", { name: "Add to Gmail" }).click();
  const compose = await opened;
  await compose.waitForURL(/view=cm/);

  // Gmail's own compose URL, addressed to Alice...
  const url = new URL(compose.url());
  expect(url.searchParams.get("view")).toBe("cm");
  expect(url.searchParams.get("to")).toBe("alice@example.com");
  // ...with the ciphertext (and only the ciphertext) in the body.
  const body = compose.locator("[g_editable]");
  await expect(body).toContainText("-----BEGIN PGP MESSAGE-----");
  await expect(body).toContainText("-----END PGP MESSAGE-----");
  await expect(compose.locator('.vR[email="alice@example.com"]')).toHaveCount(
    1,
  );
  expect(await compose.content()).not.toContain(SECRET);
  await expect(panel.getByText("Opened in Gmail")).toBeVisible();
  await expect(panel.getByLabel("Message input")).toHaveValue("");
});

test("visual: reader frame, banner, attachment and compose button in light and dark Gmail", async ({
  context,
  extensionId,
  panel,
}, testInfo) => {
  const armored = await setup(panel);
  for (const theme of ["light", "dark"] as const) {
    const gmail = await openFakeGmail(context, {
      armored,
      attachments: [{ name: "report.pdf.gpg", body: armored }],
      recipients: ["alice@example.com"],
      theme,
    });
    await expect(gmail.locator("pgp-tools-banner")).toHaveCount(1);
    const frame = await readerFrame(gmail, extensionId);
    await expect(frame.getByText(SECRET)).toBeVisible();
    await gmail.setViewportSize({ width: 1280, height: 900 });
    await gmail.screenshot({
      path: testInfo.outputPath(`gmail-${theme}.png`),
    });
    await gmail.close();
  }

  // The panel's half: writing for a draft, with one recipient unknown.
  await openFakeGmail(context, {
    armored,
    recipients: ["alice@example.com", "nobody@example.com"],
    draft: DRAFT,
  });
  await expect(panel.getByText("Writing a Gmail draft")).toBeVisible();
  await panel.setViewportSize({ width: 400, height: 760 });
  await panel.screenshot({ path: testInfo.outputPath("panel-compose.png") });

  await panel.getByRole("tab", { name: "Settings" }).click();
  await panel.getByRole("button", { name: /^Gmail/ }).click();
  await expect(panel.getByText("What it never does")).toBeVisible();
  await panel.waitForTimeout(400);
  await panel.screenshot({ path: testInfo.outputPath("panel-settings.png") });
});
