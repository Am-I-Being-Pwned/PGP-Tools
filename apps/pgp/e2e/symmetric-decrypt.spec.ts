import { expect, test } from "./fixtures";
import {
  goToKeys,
  onboardWithPasswordSkipKey,
  setWorkspaceMode,
} from "./helpers";

/**
 * Reading a `gpg --symmetric` message, end to end.
 *
 * The vectors are the real GnuPG CLI's output (2.5.21), pinned in
 * `gpg-wasm/src/tests.rs` and repeated here so the UI is exercised
 * against bytes this app cannot itself produce. Cross-tool
 * compatibility is the only specification for symmetric decryption --
 * the app is decrypt-only, so a self-round-trip is not available even in
 * principle.
 *
 * What THIS layer adds over the Rust tests:
 *
 *  1. NO KEY IS NEEDED. Every test here onboards with `SkipKey`, so the
 *     vault is empty. A password-encrypted message is readable by anyone
 *     holding the password, and requiring a key of one's own to read one
 *     would be requiring a key for nothing. The Rust tests cannot show
 *     this -- only the UI can, by not asking.
 *  2. THE RIGHT PROMPT. There is one password row in this workspace and
 *     it means two different things; the placeholder is the whole of the
 *     distinction, so it is asserted rather than assumed.
 *  3. A WRONG PASSWORD LEAVES THE PROMPT UP. The user's next action is
 *     to retype, and it should be waiting where they left it.
 */

const VAULT_PASSWORD = "correct horse battery staple";
/** The password the FIXTURES were encrypted under. Identical to the vault
 *  password on purpose -- if the two were ever confused by the code, a
 *  test using different strings would catch it, and a test using the same
 *  string would not. So they are the same, and the wrong-password test
 *  below is what separates them. */
const MESSAGE_PASSWORD = "correct horse battery staple";
const PLAINTEXT = "the password is the key";

/** `gpg -c --rfc4880`: v4 SKESK, AES-256-CFB, MDC. */
const GPG_SYMMETRIC_V4 = `-----BEGIN PGP MESSAGE-----

jA0ECQMIgYlslpAs65D/0lEB7S0K0+CFdt0IhAB8VpcBcK/6SkSMUGzegcLuFyBj
KAFUrRe5nBt9CNXSIRuIDsj+k2V4YT+ZnsBO4kx2F3RFv3sKEN8v1cKMq86Qif+p
wjg=
=AEHv
-----END PGP MESSAGE-----
`;

/** `gpg -c --force-ocb`: the pre-RFC-9580 AEAD packet, which this app
 *  cannot read at all. Kept as a fixture because the REQUIREMENT is
 *  about the message the user sees, not about reading it. */
const GPG_SYMMETRIC_OCB = `-----BEGIN PGP MESSAGE-----

jE0FCQIDCFDkvEpE6tIy/xwgVAOzARqn7B1V/V0igvN9GNaewd51FLEE94tolfSs
tDn7/sE05fHil10ZCdhTAnGx7bVB6yGRd7UX5yttXNRbAQkCEFu+HvJvMd14ux7U
BAvbQR/CoZcWMx90z36ymHrm5LUALjtjcYkd3M0qyXdT2V1xx22/z/fY7vH/vASM
ZEoKujuEOCe/thf7tS6NbpbbXH2lOPGdUySXjA==
=u+/p
-----END PGP MESSAGE-----
`;

/** Paste a message into the workspace and press Decrypt. */
async function stageAndDecrypt(
  panel: import("@playwright/test").Page,
  armored: string,
): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("textarea").first().fill(armored);
  // Armored ciphertext switches the mode on its own; assert it rather
  // than force it, since that nudge is part of the flow.
  await expect(panel.getByRole("button", { name: /^decrypt$/i })).toBeVisible();
  await panel.getByRole("button", { name: /^decrypt$/i }).click();
}

test("a gpg -c message is readable with no keys in the vault at all", async ({
  panel,
}) => {
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await stageAndDecrypt(panel, GPG_SYMMETRIC_V4);

  // The message needs no key, so the app must not be asking for one.
  await expect(panel.getByText("Decrypt with")).toHaveCount(0);
  await expect(panel.getByText("No keys yet")).toHaveCount(0);

  const field = panel.getByPlaceholder("Enter message password");
  await expect(field).toBeVisible();
  await field.fill(MESSAGE_PASSWORD);
  await field.press("Enter");

  await expect(panel.getByText(PLAINTEXT)).toBeVisible();
  // The prompt comes down once the message is open.
  await expect(field).toHaveCount(0);
});

test("a wrong password says so under the field, and leaves it up", async ({
  panel,
}) => {
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await stageAndDecrypt(panel, GPG_SYMMETRIC_V4);

  const field = panel.getByPlaceholder("Enter message password");
  await field.fill("not the password");
  await field.press("Enter");

  // A v4 SKESK unwraps with no integrity check, so this failure actually
  // arrives as an MDC mismatch from deep inside the reader. The user must
  // still be told about their password, not about corruption.
  await expect(panel.getByText(/didn't open this message/i)).toBeVisible();
  await expect(panel.getByText(/corrupted/i)).toHaveCount(0);
  // Still up, still where they left it: the next action is to retype.
  await expect(field).toBeVisible();
  await expect(panel.getByText(PLAINTEXT)).toHaveCount(0);

  // And the right password then works from the same prompt.
  await field.fill(MESSAGE_PASSWORD);
  await field.press("Enter");
  await expect(panel.getByText(PLAINTEXT)).toBeVisible();
});

test("an unreadable AEAD message blames the format, not the password", async ({
  panel,
}) => {
  // The failure this guards against is a loop with no exit: told to check
  // a password that is already correct, the user retypes forever. No
  // password opens this message.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await stageAndDecrypt(panel, GPG_SYMMETRIC_OCB);

  const field = panel.getByPlaceholder("Enter message password");
  await expect(field).toBeVisible();
  await field.fill(MESSAGE_PASSWORD);
  await field.press("Enter");

  await expect(panel.getByText(/AEAD \(OCB\) format/i)).toBeVisible();
  await expect(panel.getByText(/didn't open this message/i)).toHaveCount(0);
});

test("a key-encrypted message still asks for a key, not a password", async ({
  panel,
}) => {
  // The negative control. The password path must not swallow the ordinary
  // case -- with no SKESK in the message there is nothing to ask a
  // password for, and the key picker has to still be there.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await goToKeys(panel);
  await setWorkspaceMode(panel, "Decrypt");
  await panel
    .locator("textarea")
    .first()
    .fill(
      `-----BEGIN PGP MESSAGE-----

hF4Dhe4kFYYSt7ISAQdA0000000000000000000000000000000000000000000000
=abcd
-----END PGP MESSAGE-----
`,
    );

  await expect(panel.getByPlaceholder("Enter message password")).toHaveCount(0);
  await expect(panel.getByText("Decrypt with")).toBeVisible();
});

/** Paste `text` into the workspace box for real -- via the clipboard and
 *  a paste keystroke, not `fill()`. The distinction is the whole point of
 *  these tests: armor repair rides on the paste, never on typing. */
async function pasteIntoWorkspace(
  panel: import("@playwright/test").Page,
  text: string,
): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  const box = panel.locator("textarea").first();
  await box.click();
  await panel.evaluate(async (t) => {
    await navigator.clipboard.writeText(t);
  }, text);
  await box.press("ControlOrMeta+v");
}

test("a message mangled into a JSON string still decrypts", async ({
  panel,
}) => {
  // The end-to-end proof for `repairArmorEscapes`: unit tests assert the
  // transform, this asserts the REAL engine accepts what it produces.
  // Copied out of a log line or an API response, this is what arrives.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  await pasteIntoWorkspace(panel, JSON.stringify({ body: GPG_SYMMETRIC_V4 }));

  // The box shows the repaired armor, not what was pasted -- the repair
  // is visible and undoable rather than hidden inside the parser.
  await expect(panel.locator("textarea").first()).toHaveValue(
    /-----BEGIN PGP MESSAGE-----\n/,
  );

  await panel.getByRole("button", { name: /^decrypt$/i }).click();
  const field = panel.getByPlaceholder("Enter message password");
  await field.fill(MESSAGE_PASSWORD);
  await field.press("Enter");
  await expect(panel.getByText(PLAINTEXT)).toBeVisible();
});

test("typing is never rewritten, even when it looks like mangled armor", async ({
  panel,
}) => {
  // The rule: repair is for content that ARRIVES, not for content being
  // composed. `fill()` drives the box's onChange the way typing does, so
  // this is the typing path, and it must leave every character alone --
  // including a complete escaped block, which the paste path WOULD
  // repair. Someone writing about PGP gets to quote armor at it.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  const typed = GPG_SYMMETRIC_V4.replaceAll("\n", "\\n");
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("textarea").first().fill(typed);
  await expect(panel.locator("textarea").first()).toHaveValue(typed);
});

test("pasting a code snippet is left alone", async ({ panel }) => {
  // The safety property on the path that DOES repair: block-scoping is
  // what keeps a backslash-n outside any BEGIN/END pair intact.
  await onboardWithPasswordSkipKey(panel, VAULT_PASSWORD);
  const code = 'console.log("line one\\nline two");';
  await pasteIntoWorkspace(panel, code);
  await expect(panel.locator("textarea").first()).toHaveValue(code);
});
