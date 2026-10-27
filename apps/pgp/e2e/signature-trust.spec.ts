import type { Page } from "@playwright/test";

import { edgeKey, MESSAGE } from "./edge-keys";
import { expect, test } from "./fixtures";
import {
  importContact,
  onboardWithPassword,
  onboardWithPasswordSkipKey,
  setWorkspaceMode,
  verifySignedMessage,
} from "./helpers";
import { SAM } from "./message-trust";

// A green "Signature verified" card vouches for something. What these
// pin is WHAT: exactly the text that was signed, shown beside the
// verdict, and -- for several files -- every file, never just the one
// that happened to set the card last.

const PASSWORD = "correct horse battery staple";
const rachel = edgeKey("rsa4096");
const rita = edgeKey("revoked");

/** Stage files in the workspace's own drop zone. */
async function stageFiles(
  panel: Page,
  files: { name: string; text: string }[],
): Promise<void> {
  await panel.locator('input[type="file"]:not([accept])').setInputFiles(
    files.map(({ name, text }) => ({
      name,
      mimeType: "text/plain",
      buffer: Buffer.from(text, "utf8"),
    })),
  );
}

async function verifyStaged(panel: Page): Promise<void> {
  await setWorkspaceMode(panel, "Verify");
  await panel.getByRole("button", { name: /^verify/i }).click();
}

test("a verified message shows exactly the signed text, and when it was signed", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);

  await verifySignedMessage(panel, rachel.signedMessage ?? "");

  await expect(panel.getByText("Signature verified").first()).toBeVisible();
  await expect(panel.locator("#pgp-input")).toHaveCount(0);
  await expect(
    panel.locator("pre").filter({ hasText: MESSAGE }).first(),
  ).toBeVisible();
  await expect(panel.getByText(/^Signed \w/).first()).toBeVisible();
});

test("a signed file's content is shown under the verdict", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();

  await stageFiles(panel, [
    { name: "notice.asc", text: rachel.signedMessage ?? "" },
  ]);
  await verifyStaged(panel);

  await expect(panel.getByText("Signature verified").first()).toBeVisible();
  await expect(
    panel.locator("pre").filter({ hasText: MESSAGE }).first(),
  ).toBeVisible();
});

test("a signed file with text around its signed block is refused", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();

  await stageFiles(panel, [
    {
      name: "notice.asc",
      text: `Pay invoices to account 12345678.\n\n${rachel.signedMessage ?? ""}`,
    },
  ]);
  await verifyStaged(panel);

  await expect(
    panel.getByText(/text outside the signed message/).first(),
  ).toBeVisible();
  await expect(panel.getByText("Signature verified")).toHaveCount(0);
});

test("several files are each verified, and a mixed batch says who signed which", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();

  // Rachel's genuine notice next to one from a key we can't check: the
  // card must not read as Rachel vouching for both.
  await stageFiles(panel, [
    { name: "rachel.asc", text: rachel.signedMessage ?? "" },
    { name: "rita.asc", text: rita.signedMessage ?? "" },
  ]);
  await verifyStaged(panel);

  await expect(panel.getByText("Mixed signers")).toBeVisible();
  // One file per line, each name quoted: a name can't pose as a verdict.
  await expect(panel.getByText(/.rachel\.asc.: Rachel Rsa4096/)).toBeVisible();
  await expect(panel.getByText(/.rita\.asc.: Unknown signer/)).toBeVisible();
  await expect(panel.getByText("Signature verified")).toHaveCount(0);
});

test("several files from the same signer get that signer's card", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();

  await stageFiles(panel, [
    { name: "one.asc", text: rachel.signedMessage ?? "" },
    { name: "two.asc", text: rachel.signedMessage ?? "" },
  ]);
  await verifyStaged(panel);

  await expect(panel.getByText("Signature verified").first()).toBeVisible();
  await expect(panel.getByText("Rachel Rsa4096").first()).toBeVisible();
});

test("one tampered file fails the whole batch", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();

  const tampered = (rachel.signedMessage ?? "").replace(
    MESSAGE,
    MESSAGE.replace("quick", "sneaky"),
  );
  await stageFiles(panel, [
    { name: "good.asc", text: rachel.signedMessage ?? "" },
    { name: "bad.asc", text: tampered },
  ]);
  await verifyStaged(panel);

  await expect(panel.getByText(/tampered/).first()).toBeVisible();
  await expect(panel.getByText("Signature verified")).toHaveCount(0);
});

test("a file added while Verify runs is never shown under its verdict", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();
  // Slow every file read, standing in for a large file or a slow disk,
  // so a second file can land while the first is being verified.
  await panel.evaluate(() => {
    // eslint-disable-next-line @typescript-eslint/unbound-method -- re-bound below
    const read = Blob.prototype.arrayBuffer;
    Blob.prototype.arrayBuffer = function (this: Blob) {
      return new Promise((resolve) =>
        setTimeout(() => resolve(read.call(this)), 1500),
      );
    };
  });

  await stageFiles(panel, [
    { name: "genuine.asc", text: rachel.signedMessage ?? "" },
  ]);
  await verifyStaged(panel);
  await stageFiles(panel, [{ name: "payload.asc", text: "not verified" }]);

  await panel.waitForTimeout(2500);
  await expect(panel.getByText("Signature verified")).toHaveCount(0);
  await expect(panel.getByText("payload.asc")).toBeVisible();
});

test("a new file with a staged file's name replaces it", async ({ panel }) => {
  // Re-downloading release.asc and dropping it in used to be ignored, so
  // Verify checked the OLD file and said so in green.
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();

  await stageFiles(panel, [
    { name: "release.asc", text: rachel.signedMessage ?? "" },
  ]);
  await verifyStaged(panel);
  await expect(panel.getByText("Signature verified").first()).toBeVisible();

  const tampered = (rachel.signedMessage ?? "").replace(
    MESSAGE,
    MESSAGE.replace("quick", "sneaky"),
  );
  // Out of the verified message's view, back to the staged files.
  await panel.getByRole("button", { name: "Back" }).click();
  await stageFiles(panel, [{ name: "release.asc", text: tampered }]);
  await expect(panel.getByText("Signature verified")).toHaveCount(0);
  await panel.getByRole("button", { name: /^verify/i }).click();
  await expect(panel.getByText(/tampered/).first()).toBeVisible();
  await expect(panel.getByText("release.asc")).toHaveCount(1);
});

test("removing a file clears the verdict that listed it", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, rachel.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();

  await stageFiles(panel, [
    { name: "rachel.asc", text: rachel.signedMessage ?? "" },
    { name: "rita.asc", text: rita.signedMessage ?? "" },
  ]);
  await verifyStaged(panel);
  await expect(panel.getByText("Mixed signers")).toBeVisible();

  await panel.getByRole("button", { name: "Remove" }).last().click();
  await expect(panel.getByText("Mixed signers")).toHaveCount(0);
});

test("a file that isn't UTF-8 is refused rather than misread", async ({
  panel,
}) => {
  // File.text() would turn the Latin-1 byte into U+FFFD: a genuine file
  // reads as tampered, and a crafted one as text it doesn't contain.
  await onboardWithPassword(panel, PASSWORD);
  await panel.getByRole("tab", { name: "Main" }).click();
  const latin1 = Buffer.concat([
    Buffer.from(
      "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\ncaf",
      "utf8",
    ),
    Buffer.from([0xe9]),
    Buffer.from(
      "\n-----BEGIN PGP SIGNATURE-----\n\niQ==\n-----END PGP SIGNATURE-----\n",
      "utf8",
    ),
  ]);
  await panel.locator('input[type="file"]:not([accept])').setInputFiles({
    name: "menu.asc",
    mimeType: "text/plain",
    buffer: latin1,
  });
  await verifyStaged(panel);
  await expect(panel.getByText(/isn't UTF-8 text/)).toBeVisible();
});

// ── a "PGP MESSAGE" that was never encrypted ─────────────────────────
//
// Anything Sam ever signed in public can be re-sent by anyone as a PGP
// MESSAGE. It used to "decrypt" -- after unlocking a key -- into the
// same green card and Reply button as private mail from Sam.

/** Paste into the message box and press Decrypt (the mode the armor
 *  picks on its own). */
async function pasteAndDecrypt(panel: Page, armored: string): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("textarea").first().fill(armored);
  await expect(panel.getByRole("button", { name: /^decrypt$/i })).toBeVisible();
  await panel.getByRole("button", { name: /^decrypt$/i }).click();
}

test("a signed message that was never encrypted opens as not encrypted, with no key and no Reply", async ({
  panel,
}) => {
  // No key of our own at all: nothing here needs one, and nothing asks.
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await importContact(panel, SAM.publicKey);

  await pasteAndDecrypt(panel, SAM.signedOnly);

  await expect(panel.getByText("Not encrypted", { exact: true })).toBeVisible();
  await expect(
    panel.getByText(/signed, but not encrypted: anyone could have sent you/),
  ).toBeVisible();
  await expect(
    panel.locator("pre").filter({ hasText: SAM.publicStatement }),
  ).toBeVisible();
  await expect(panel.getByText("Signature verified")).toHaveCount(0);
  await expect(
    panel.getByRole("button", { name: "Reply", exact: true }),
  ).toHaveCount(0);
  await expect(panel.locator('input[type="password"]')).toHaveCount(0);
});

test("a bare PGP MESSAGE says it was neither encrypted nor signed", async ({
  panel,
}) => {
  await onboardWithPasswordSkipKey(panel, PASSWORD);

  await pasteAndDecrypt(panel, SAM.storedOnly);

  await expect(panel.getByText("Not encrypted or signed")).toBeVisible();
  await expect(
    panel.getByText(/This message was not encrypted, so anyone could/),
  ).toBeVisible();
  await expect(
    panel.getByRole("button", { name: "Reply", exact: true }),
  ).toHaveCount(0);
});

test("a .gpg file that is only signed is not shown as decrypted", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, SAM.publicKey);
  await panel.getByRole("tab", { name: "Main" }).click();

  await panel.locator('input[type="file"]:not([accept])').setInputFiles({
    name: "statement.txt.gpg",
    mimeType: "application/octet-stream",
    buffer: Buffer.from(SAM.signedOnlyBinaryB64, "base64"),
  });
  await setWorkspaceMode(panel, "Decrypt");
  await panel.getByRole("button", { name: /^decrypt$/i }).click();

  await expect(panel.getByText("Not encrypted", { exact: true })).toBeVisible();
  await expect(panel.getByText("Signature verified")).toHaveCount(0);
  await expect(panel.locator('input[type="password"]')).toHaveCount(0);
});

test("a batch with an unencrypted file is refused by that file's name", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await panel.getByRole("tab", { name: "Main" }).click();

  await stageFiles(panel, [
    { name: "one.asc", text: SAM.storedOnly },
    { name: "statement.asc", text: SAM.signedOnly },
  ]);
  await setWorkspaceMode(panel, "Decrypt");
  await panel.getByRole("button", { name: /^decrypt$/i }).click();

  await expect(
    panel.getByText(/one\.asc is not encrypted\. Decrypt it on its own/),
  ).toBeVisible();
  await expect(panel.getByText(/files? decrypted/)).toHaveCount(0);
});

// ── a lone CR under a text-mode signature ────────────────────────────
//
// Sequoia reads \r, \n and \r\n alike as a line break when hashing a
// text signature, so Sam's signature over "Approved:\nNO" also covers
// "Approved:\rNO" -- which a browser draws as "Approved:NO".

test("a lone CR under a good signature is amber, said, and drawn", async ({
  panel,
}) => {
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await importContact(panel, SAM.publicKey);

  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("textarea").first().fill(SAM.loneCr);
  await setWorkspaceMode(panel, "Verify");
  await panel.getByRole("button", { name: /^verify$/i }).click();

  await expect(panel.getByText("Check line breaks")).toBeVisible();
  await expect(
    panel.getByText(/carriage return without a line feed/),
  ).toBeVisible();
  // Drawn as a symbol and a break, never folded into "Approved:NO".
  await expect(panel.locator("pre").first()).toHaveText("Approved:\u240d\nNO");
});

test("a lone CR in an unencrypted message gets both warnings", async ({
  panel,
}) => {
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await importContact(panel, SAM.publicKey);

  await pasteAndDecrypt(panel, SAM.loneCr);

  await expect(panel.getByText("Not encrypted", { exact: true })).toBeVisible();
  await expect(
    panel.getByText(/carriage return without a line feed/),
  ).toBeVisible();
});

// Text about to be SIGNED that holds characters the box does not draw
// (a page's selection, a paste) is held back until the user says so:
// a right-to-left override makes a signed "1000" read as "0001".
test.describe("hidden characters before a signature", () => {
  const RLO = String.fromCodePoint(0x202e);
  const PDF = String.fromCodePoint(0x202c);
  const TRICK = `Pay ${RLO}0001${PDF} EUR`;
  const box = (panel: Page) => panel.locator("#pgp-input");
  const strip = (panel: Page) => panel.getByTestId("hidden-chars-strip");
  const signButton = (panel: Page) =>
    panel.getByRole("button", { name: /^sign$/i });

  test("Sign waits for 'Sign anyway', and then signs the text as it is", async ({
    panel,
  }) => {
    await onboardWithPassword(panel, PASSWORD);
    await setWorkspaceMode(panel, "Sign");
    await box(panel).fill(TRICK);
    await signButton(panel).click();

    await expect(strip(panel)).toBeVisible();
    await expect(strip(panel)).toContainText("U+202E");
    await expect(panel.getByRole("button", { name: "Download" })).toHaveCount(
      0,
    );

    await strip(panel).getByRole("button", { name: "Sign anyway" }).click();
    await expect(panel.getByRole("button", { name: "Download" })).toBeVisible();
    await expect(strip(panel)).toHaveCount(0);
  });

  test("'Remove them' cleans the box, and the clean text signs without asking", async ({
    panel,
  }) => {
    await onboardWithPassword(panel, PASSWORD);
    await setWorkspaceMode(panel, "Sign");
    await box(panel).fill(`${TRICK}\rthanks`);
    await signButton(panel).click();
    await strip(panel).getByRole("button", { name: "Remove them" }).click();
    await expect(box(panel)).toHaveValue("Pay 0001 EUR\nthanks");
    await expect(strip(panel)).toHaveCount(0);

    await signButton(panel).click();
    await expect(panel.getByRole("button", { name: "Download" })).toBeVisible();
  });

  test("Encrypt with Sign on asks too; ordinary text never does", async ({
    panel,
  }) => {
    await onboardWithPassword(panel, PASSWORD);
    await setWorkspaceMode(panel, "Encrypt");
    await panel.getByRole("combobox", { name: "Recipients" }).click();
    await panel.getByRole("option").first().click();
    await panel.keyboard.press("Escape");
    const sign = panel.getByRole("switch", { name: "Sign", exact: true });
    if ((await sign.getAttribute("aria-checked")) !== "true")
      await sign.click();

    await box(panel).fill(TRICK);
    await panel.getByRole("button", { name: /^encrypt$/i }).click();
    await expect(strip(panel)).toBeVisible();

    // Emoji (VS16, ZWJ) and CRLF are text, not tricks.
    const heart = String.fromCodePoint(0x2764, 0xfe0f);
    const coder = String.fromCodePoint(0x1f469, 0x200d, 0x1f4bb);
    await box(panel).fill(`Thanks ${heart} ${coder}\r\nSee you`);
    await expect(strip(panel)).toHaveCount(0);
    await panel.getByRole("button", { name: /^encrypt$/i }).click();
    await expect(panel.getByRole("button", { name: "Download" })).toBeVisible();
    await expect(strip(panel)).toHaveCount(0);
  });
});
