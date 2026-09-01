import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { edgeKey, MESSAGE } from "./edge-keys";
import { expect, test } from "./fixtures";
import {
  importContact,
  importContactExpectRejected,
  onboardWithPassword,
  setWorkspaceMode,
  verifySignedMessage,
} from "./helpers";

const PASSWORD = "correct horse battery staple";

// "Wild and whacky" public keys a real correspondent might hand the user:
// expired, revoked, multi-UID, RSA-4096 -- plus every verify outcome
// (valid / unknown signer / tampered / unsigned). Import must either work
// or fail with a message that tells the user what to do next; verify must
// never present "we don't hold the signer's key" as a scary failure.

test("rejects an expired key with the expiry date", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContactExpectRejected(
    panel,
    edgeKey("expired").publicKey,
    // The health banner spells it out across a few lines: when it
    // expired, and what to do about it.
    /expired[\s\S]*Ask the owner for an updated key/,
    /expired[\s\S]*current key/,
  );
});

test("rejects a revoked key with the revocation reason", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContactExpectRejected(
    panel,
    edgeKey("revoked").publicKey,
    /has been revoked/,
  );
});

test("imports a multi-UID key (work + personal email)", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, edgeKey("multiUid").publicKey);
  await expect(panel.getByText("Mallory Multi").first()).toBeVisible();
});

test("imports an RSA-4096 key and verifies its signature", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, edgeKey("rsa4096").publicKey);
  await verifySignedMessage(panel, edgeKey("rsa4096").signedMessage ?? "");
  await expect(panel.getByText("Signature verified")).toBeVisible();
  await expect(panel.getByText("Rachel Rsa4096").first()).toBeVisible();
});

// The messy/sample-failed regression shape: a message signed by a key
// the user does NOT hold (e.g. a key-rotation notice signed by the newly
// announced key), while their contacts are non-empty. This must classify
// as "unknown signer" -- with the signer's key ID so the user can go
// fetch it -- not a hard failure.
test("verify with an unknown signer shows the signer card, not an error", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, edgeKey("multiUid").publicKey);

  // Signed by rsa4096, which is NOT in keys or contacts.
  await verifySignedMessage(panel, edgeKey("rsa4096").signedMessage ?? "");
  await expect(panel.getByText("Unverified").first()).toBeVisible();
  await expect(panel.getByText("Unknown signer").first()).toBeVisible();
  // The signer's key ID is surfaced so the user can locate the key.
  await expect(
    panel
      .getByText(new RegExp(edgeKey("rsa4096").fingerprint.slice(-16)))
      .first(),
  ).toBeVisible();
  await expect(panel.getByText(/Verification failed/)).toBeHidden();
});

// The original real-world sample lives in messy/sample-failed (gitignored
// on purpose -- real key material that shouldn't ship in the repo), so
// this regression runs only where that directory exists.
const SAMPLE_DIR = join(
  import.meta.dirname,
  "..",
  "..",
  "..",
  "messy",
  "sample-failed",
);

test("real-world sample: rotation notice verifies as unknown signer", async ({
  panel,
}) => {
  test.skip(
    !existsSync(join(SAMPLE_DIR, "key.asc")),
    "messy/sample-failed not present (local-only sample)",
  );
  const publicKey = readFileSync(join(SAMPLE_DIR, "key.asc"), "utf8");
  const notice = readFileSync(join(SAMPLE_DIR, "msg.gpg"), "utf8");

  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, publicKey);
  await verifySignedMessage(panel, notice);
  await expect(panel.getByText("Unverified").first()).toBeVisible();
  await expect(panel.getByText("Unknown signer").first()).toBeVisible();
  await expect(panel.getByText(/Verification failed/)).toBeHidden();
});

// The sample that prompted the armor-recovery fix: a Kleopatra export
// with CRLF line endings and a `Comment: Fingerprint: ...` header. It
// parses fine in the engine -- what broke it was the paste/drop repair
// step ahead of the engine treating intact CRLF armor as collapsed.
test("real-world sample: a CRLF Kleopatra export imports as a contact", async ({
  panel,
}) => {
  test.skip(
    !existsSync(join(SAMPLE_DIR, "public-pgp-key.txt")),
    "messy/sample-failed not present (local-only sample)",
  );
  const publicKey = readFileSync(
    join(SAMPLE_DIR, "public-pgp-key.txt"),
    "utf8",
  );

  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, publicKey);
  await expect(panel.getByText("SWIFT_Security_Alert").first()).toBeVisible();
});

test("verify of a message signed by an expired key degrades to unknown signer", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  // The expired cert can't be imported, so its signature can never be
  // attributed -- but the verify flow must still degrade gracefully.
  await verifySignedMessage(panel, edgeKey("expired").signedMessage ?? "");
  await expect(panel.getByText("Unverified").first()).toBeVisible();
  await expect(panel.getByText("Unknown signer").first()).toBeVisible();
});

test("verify flags a tampered message as a failed signature", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await importContact(panel, edgeKey("rsa4096").publicKey);

  const tampered = (edgeKey("rsa4096").signedMessage ?? "").replace(
    MESSAGE,
    MESSAGE.replace("quick", "sneaky"),
  );
  await verifySignedMessage(panel, tampered);
  await expect(panel.getByText(/tampered/)).toBeVisible();
});

test("verify of unsigned text says so plainly", async ({ panel }) => {
  await onboardWithPassword(panel, PASSWORD);
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("textarea").first().fill("just some plain text");
  await setWorkspaceMode(panel, "Verify");
  await panel.getByRole("button", { name: /^verify$/i }).click();
  // Plain text isn't a PGP message at all; the error classifier says so
  // with paste-the-full-block guidance (the "not signed" classification
  // is reserved for parseable PGP data).
  await expect(panel.getByText(/doesn't look like PGP data/)).toBeVisible();
});
