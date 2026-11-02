import { expect, test } from "./fixtures";
import {
  importContact,
  onboardWithPassword,
  verifySignedMessage,
} from "./helpers";
import { TEST_KEYS } from "./keys";

const PASSWORD = "correct horse battery staple";

// Data-driven: every fixture key -- name+email, no email, comment, RSA,
// and sign-only (with and without email) -- must import as a contact and
// verify a signature it produced. Sign-only keys are the regression:
// they have no encryption subkey but are still valid for verification.
for (const key of TEST_KEYS) {
  test(`imports and verifies a signature: ${key.slug} (${key.description})`, async ({
    panel,
  }) => {
    await onboardWithPassword(panel, PASSWORD);

    await test.step("import the public key as a contact", async () => {
      await importContact(panel, key.publicKey);
    });

    await test.step("verify a message signed by that key", async () => {
      await verifySignedMessage(panel, key.signedMessage);
      await expect(panel.getByText("Signature verified")).toBeVisible();
      // The verified signer is attributed to the right identity.
      await expect(panel.getByText(key.label).first()).toBeVisible();
    });
  });
}
