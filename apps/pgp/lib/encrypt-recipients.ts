/** One of the user's own keys, as needed for recipient assembly. Both
 *  `ProtectedKeyBlob` and any {keyId, publicKeyArmored} pair satisfy it. */
interface OwnKey {
  keyId: string;
  publicKeyArmored: string;
}

/** A recipient the user selected in the picker. */
export interface SelectedRecipient {
  keyId: string;
  armored: string;
}

/** The armored key set an encrypt operation should target, plus whether
 *  the user's own key ended up excluded (so the caller can warn that the
 *  ciphertext will be unreadable to them). */
export interface EncryptRecipients {
  recipientPublicKeys: string[];
  /** True when the user will NOT be able to decrypt the result:
   *  encrypt-to-self is off (or they own no key) and none of the
   *  selected recipients is one of their own keys. */
  selfExcluded: boolean;
  /** Key id of the user's own key that rode along via encrypt-to-self,
   *  or null when none was added (excluded, or a selected recipient
   *  already is one of the user's keys). Lets callers report the FINAL
   *  recipient set (e.g. history capture) without re-deriving the
   *  selection. */
  selfKeyId: string | null;
}

/**
 * Pick which of the user's own keys should represent them in an
 * operation. Resolution order: the configured default key (when it
 * still exists among `myKeys`), then the signing key (when the message
 * is also signed), then the first key. A stale `defaultKeyId` pointing
 * at a deleted key is ignored gracefully. Returns null when the user
 * owns no keys.
 */
export function resolveSelfKey<K extends { keyId: string }>(
  myKeys: readonly K[],
  defaultKeyId: string | null,
  signingKeyId?: string | null,
): K | null {
  if (myKeys.length === 0) return null;
  return (
    myKeys.find((k) => defaultKeyId !== null && k.keyId === defaultKeyId) ??
    myKeys.find((k) => signingKeyId != null && k.keyId === signingKeyId) ??
    myKeys[0]
  );
}

/**
 * Assemble the recipient key set for an encrypt operation. Selected
 * recipients are deduped by fingerprint. With encrypt-to-self enabled,
 * the user's own public key rides along so they can decrypt their own
 * ciphertext later — preferring their configured default key, else the
 * key they're signing with (one identity per message), else their
 * first key (see resolveSelfKey). When a selected recipient already IS
 * one of their keys, nothing is added.
 */
export function buildEncryptRecipients(options: {
  recipients: SelectedRecipient[];
  encryptToSelf: boolean;
  ownKeys: OwnKey[];
  /** The key selected for signing, when the message is also signed. */
  signingKeyId?: string | null;
  /** The user's configured default key, when set. */
  defaultKeyId?: string | null;
}): EncryptRecipients {
  const { recipients, encryptToSelf, ownKeys } = options;

  const deduped: SelectedRecipient[] = [];
  for (const recipient of recipients) {
    if (!deduped.some((r) => r.keyId === recipient.keyId)) {
      deduped.push(recipient);
    }
  }
  const recipientPublicKeys = deduped.map((r) => r.armored);

  // A selected recipient is one of the user's own keys: they can already
  // decrypt the result, so never double-add (or warn).
  const selfSelected = deduped.some((r) =>
    ownKeys.some((k) => k.keyId === r.keyId),
  );
  if (selfSelected) {
    return { recipientPublicKeys, selfExcluded: false, selfKeyId: null };
  }

  const selfKey = encryptToSelf
    ? resolveSelfKey(ownKeys, options.defaultKeyId ?? null, options.signingKeyId)
    : null;
  if (selfKey === null) {
    return { recipientPublicKeys, selfExcluded: true, selfKeyId: null };
  }

  return {
    recipientPublicKeys: [...recipientPublicKeys, selfKey.publicKeyArmored],
    selfExcluded: false,
    selfKeyId: selfKey.keyId,
  };
}
