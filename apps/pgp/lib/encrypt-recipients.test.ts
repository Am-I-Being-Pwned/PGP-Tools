import { describe, expect, it } from "vitest";

import { buildEncryptRecipients, resolveSelfKey } from "./encrypt-recipients";

const RECIPIENT = { keyId: "AAAA", armored: "recipient-armor" };
const RECIPIENT_2 = { keyId: "BBBB", armored: "recipient-2-armor" };
const OWN_A = { keyId: "1111", publicKeyArmored: "own-a-armor" };
const OWN_B = { keyId: "2222", publicKeyArmored: "own-b-armor" };
const OWN_A_SELECTED = { keyId: OWN_A.keyId, armored: OWN_A.publicKeyArmored };
const OWN_B_SELECTED = { keyId: OWN_B.keyId, armored: OWN_B.publicKeyArmored };

describe("resolveSelfKey", () => {
  it("returns null when the user owns no keys", () => {
    expect(resolveSelfKey([], null)).toBeNull();
    expect(resolveSelfKey([], OWN_A.keyId, OWN_B.keyId)).toBeNull();
  });

  it("falls back to the first key when no default is set", () => {
    expect(resolveSelfKey([OWN_A, OWN_B], null)).toBe(OWN_A);
  });

  it("prefers a valid default key over the first key", () => {
    expect(resolveSelfKey([OWN_A, OWN_B], OWN_B.keyId)).toBe(OWN_B);
  });

  it("prefers the default key over the signing key", () => {
    expect(resolveSelfKey([OWN_A, OWN_B], OWN_B.keyId, OWN_A.keyId)).toBe(
      OWN_B,
    );
  });

  it("uses the signing key when no default is set", () => {
    expect(resolveSelfKey([OWN_A, OWN_B], null, OWN_B.keyId)).toBe(OWN_B);
  });

  it("ignores a stale default and falls back to the signing key", () => {
    expect(resolveSelfKey([OWN_A, OWN_B], "deleted-key", OWN_B.keyId)).toBe(
      OWN_B,
    );
  });

  it("ignores a stale default and falls back to the first key", () => {
    expect(resolveSelfKey([OWN_A, OWN_B], "deleted-key")).toBe(OWN_A);
  });

  it("ignores a stale signing key too", () => {
    expect(resolveSelfKey([OWN_A, OWN_B], null, "deleted-key")).toBe(OWN_A);
  });
});

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

  it("prefers the default key as the self recipient", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      defaultKeyId: OWN_B.keyId,
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_B.publicKeyArmored,
    ]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBe(OWN_B.keyId);
  });

  it("prefers the default key over the signing key", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      signingKeyId: OWN_A.keyId,
      defaultKeyId: OWN_B.keyId,
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_B.publicKeyArmored,
    ]);
    expect(result.selfKeyId).toBe(OWN_B.keyId);
  });

  it("ignores a stale default key and falls back to the signing key", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      signingKeyId: OWN_B.keyId,
      defaultKeyId: "deleted-key",
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_B.publicKeyArmored,
    ]);
    expect(result.selfKeyId).toBe(OWN_B.keyId);
  });

  it("does not double-add when the default key is a selected recipient", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT, OWN_B_SELECTED],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      defaultKeyId: OWN_B.keyId,
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_B.publicKeyArmored,
    ]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBeNull();
  });

  it("skips the self key when ANOTHER own key is a selected recipient, even with a default set", () => {
    const result = buildEncryptRecipients({
      recipients: [OWN_A_SELECTED],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      defaultKeyId: OWN_B.keyId,
    });
    expect(result.recipientPublicKeys).toEqual([OWN_A.publicKeyArmored]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBeNull();
  });
});
