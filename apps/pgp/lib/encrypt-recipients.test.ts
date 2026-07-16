import { describe, expect, it } from "vitest";

import { buildEncryptRecipients } from "./encrypt-recipients";

const RECIPIENT = { keyId: "AAAA", armored: "recipient-armor" };
const RECIPIENT_2 = { keyId: "BBBB", armored: "recipient-2-armor" };
const OWN_A = { keyId: "1111", publicKeyArmored: "own-a-armor" };
const OWN_B = { keyId: "2222", publicKeyArmored: "own-b-armor" };
const OWN_A_SELECTED = { keyId: OWN_A.keyId, armored: OWN_A.publicKeyArmored };

describe("buildEncryptRecipients", () => {
  it("adds the first own key when encrypt-to-self is enabled", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_A.publicKeyArmored,
    ]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBe(OWN_A.keyId);
  });

  it("prefers the signing key as the self recipient", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      signingKeyId: OWN_B.keyId,
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_B.publicKeyArmored,
    ]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBe(OWN_B.keyId);
  });

  it("falls back to the first own key when the signing key is unknown", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      signingKeyId: "deleted-key",
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_A.publicKeyArmored,
    ]);
  });

  it("dedupes when the recipient is one of the user's own keys", () => {
    const result = buildEncryptRecipients({
      recipients: [OWN_A_SELECTED],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
    });
    expect(result.recipientPublicKeys).toEqual([OWN_A.publicKeyArmored]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBeNull();
  });

  it("does not warn when disabled but the recipient is self", () => {
    const result = buildEncryptRecipients({
      recipients: [OWN_A_SELECTED],
      encryptToSelf: false,
      ownKeys: [OWN_A],
    });
    expect(result.recipientPublicKeys).toEqual([OWN_A.publicKeyArmored]);
    expect(result.selfExcluded).toBe(false);
  });

  it("flags self-exclusion when no own key exists", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: true,
      ownKeys: [],
    });
    expect(result.recipientPublicKeys).toEqual([RECIPIENT.armored]);
    expect(result.selfExcluded).toBe(true);
  });

  it("flags self-exclusion when disabled", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: false,
      ownKeys: [OWN_A],
    });
    expect(result.recipientPublicKeys).toEqual([RECIPIENT.armored]);
    expect(result.selfExcluded).toBe(true);
  });

  it("encrypts to all selected recipients plus the self key", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT, RECIPIENT_2],
      encryptToSelf: true,
      ownKeys: [OWN_A],
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      RECIPIENT_2.armored,
      OWN_A.publicKeyArmored,
    ]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBe(OWN_A.keyId);
  });

  it("dedupes selected recipients by fingerprint", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT, { keyId: RECIPIENT.keyId, armored: "dupe" }],
      encryptToSelf: false,
      ownKeys: [],
    });
    expect(result.recipientPublicKeys).toEqual([RECIPIENT.armored]);
  });

  it("skips the self key when an own key is already among the recipients", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT, OWN_A_SELECTED],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_A.publicKeyArmored,
    ]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBeNull();
  });

  it("does not warn when disabled but an own key is among multiple recipients", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT, OWN_A_SELECTED, RECIPIENT_2],
      encryptToSelf: false,
      ownKeys: [OWN_A],
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_A.publicKeyArmored,
      RECIPIENT_2.armored,
    ]);
    expect(result.selfExcluded).toBe(false);
  });

  it("flags self-exclusion for multiple recipients when disabled", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT, RECIPIENT_2],
      encryptToSelf: false,
      ownKeys: [OWN_A],
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      RECIPIENT_2.armored,
    ]);
    expect(result.selfExcluded).toBe(true);
    expect(result.selfKeyId).toBeNull();
  });
});
