import { describe, expect, it } from "vitest";

import { buildEncryptRecipients } from "./encrypt-recipients";

const RECIPIENT = { keyId: "AAAA", armored: "recipient-armor" };
const OWN_A = { keyId: "1111", publicKeyArmored: "own-a-armor" };
const OWN_B = { keyId: "2222", publicKeyArmored: "own-b-armor" };

describe("buildEncryptRecipients", () => {
  it("adds the first own key when encrypt-to-self is enabled", () => {
    const result = buildEncryptRecipients({
      recipientKeyId: RECIPIENT.keyId,
      recipientArmored: RECIPIENT.armored,
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_A.publicKeyArmored,
    ]);
    expect(result.selfExcluded).toBe(false);
  });

  it("prefers the signing key as the self recipient", () => {
    const result = buildEncryptRecipients({
      recipientKeyId: RECIPIENT.keyId,
      recipientArmored: RECIPIENT.armored,
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      signingKeyId: OWN_B.keyId,
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_B.publicKeyArmored,
    ]);
    expect(result.selfExcluded).toBe(false);
  });

  it("falls back to the first own key when the signing key is unknown", () => {
    const result = buildEncryptRecipients({
      recipientKeyId: RECIPIENT.keyId,
      recipientArmored: RECIPIENT.armored,
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
      recipientKeyId: OWN_A.keyId,
      recipientArmored: OWN_A.publicKeyArmored,
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
    });
    expect(result.recipientPublicKeys).toEqual([OWN_A.publicKeyArmored]);
    expect(result.selfExcluded).toBe(false);
  });

  it("does not warn when disabled but the recipient is self", () => {
    const result = buildEncryptRecipients({
      recipientKeyId: OWN_A.keyId,
      recipientArmored: OWN_A.publicKeyArmored,
      encryptToSelf: false,
      ownKeys: [OWN_A],
    });
    expect(result.recipientPublicKeys).toEqual([OWN_A.publicKeyArmored]);
    expect(result.selfExcluded).toBe(false);
  });

  it("flags self-exclusion when no own key exists", () => {
    const result = buildEncryptRecipients({
      recipientKeyId: RECIPIENT.keyId,
      recipientArmored: RECIPIENT.armored,
      encryptToSelf: true,
      ownKeys: [],
    });
    expect(result.recipientPublicKeys).toEqual([RECIPIENT.armored]);
    expect(result.selfExcluded).toBe(true);
  });

  it("flags self-exclusion when disabled", () => {
    const result = buildEncryptRecipients({
      recipientKeyId: RECIPIENT.keyId,
      recipientArmored: RECIPIENT.armored,
      encryptToSelf: false,
      ownKeys: [OWN_A],
    });
    expect(result.recipientPublicKeys).toEqual([RECIPIENT.armored]);
    expect(result.selfExcluded).toBe(true);
  });
});
