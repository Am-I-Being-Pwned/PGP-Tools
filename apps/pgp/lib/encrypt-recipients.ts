/** One of the user's own keys, as needed for recipient assembly. Both
 *  `ProtectedKeyBlob` and any {keyId, publicKeyArmored} pair satisfy it. */
interface OwnKey {
  keyId: string;
  publicKeyArmored: string;
}

/** The armored key set an encrypt operation should target, plus whether
 *  the user's own key ended up excluded (so the caller can warn that the
 *  ciphertext will be unreadable to them). */
export interface EncryptRecipients {
  recipientPublicKeys: string[];
  /** True when the user will NOT be able to decrypt the result:
   *  encrypt-to-self is off (or they own no key) and the recipient
   *  isn't one of their own keys. */
  selfExcluded: boolean;
}

/**
 * Assemble the recipient key set for an encrypt operation. With
 * encrypt-to-self enabled, the user's own public key rides along so they
 * can decrypt their own ciphertext later — preferring the key they're
 * signing with (one identity per message), else their first key. When the
 * chosen recipient already IS one of their keys, nothing is added.
 */
export function buildEncryptRecipients(options: {
  recipientKeyId: string;
  recipientArmored: string;
  encryptToSelf: boolean;
  ownKeys: OwnKey[];
  /** The key selected for signing, when the message is also signed. */
  signingKeyId?: string | null;
}): EncryptRecipients {
  const { recipientKeyId, recipientArmored, encryptToSelf, ownKeys } = options;

  // The recipient is one of the user's own keys: they can already
  // decrypt the result, so never double-add (or warn).
  if (ownKeys.some((k) => k.keyId === recipientKeyId)) {
    return { recipientPublicKeys: [recipientArmored], selfExcluded: false };
  }

  if (!encryptToSelf || ownKeys.length === 0) {
    return { recipientPublicKeys: [recipientArmored], selfExcluded: true };
  }

  const selfKey =
    ownKeys.find((k) => k.keyId === options.signingKeyId) ?? ownKeys[0];
  return {
    recipientPublicKeys: [recipientArmored, selfKey.publicKeyArmored],
    selfExcluded: false,
  };
}
