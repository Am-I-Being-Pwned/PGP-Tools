import type { PublicContactKey } from "./storage/contacts";
import type { StoredKeyKind } from "./storage/key-kind";
import type { ProtectedKeyBlob } from "./storage/keyring";
import { t } from "./i18n";
import { activeRecipients } from "./storage/contacts";
import { storedKeyKind } from "./storage/key-kind";

interface OwnKey {
  keyId: string;
  publicKeyArmored: string;
  /** Absent means `"pgp"`. */
  kind?: StoredKeyKind;
}

export interface SelectedRecipient {
  /** Id of the selected record (contact id for a multi-key contact) --
   *  what dedupe and encrypt-to-self compare on. */
  keyId: string;
  /** The record's head key. */
  armored: string;
  /** Every key to encrypt to. Absent means `[armored]`. */
  armoredAll?: string[];
  /** Absent means `"pgp"`. */
  kind?: StoredKeyKind;
}

type PickerKey = OwnKey | PublicContactKey;

/**
 * Resolve picker selection ids to records. Shared by the preview and the
 * encrypt so they cannot disagree.
 *
 * Own keys are searched first, never the contact: a contact's id is its
 * head fingerprint, and a crafted `.pub` grouping the user's key with an
 * attacker's would otherwise make "encrypt to yourself" also encrypt to
 * the attacker. An id that is yours means your key.
 */
export function resolveSelectedRecipients(
  selectedIds: readonly string[],
  contacts: readonly PublicContactKey[],
  ownKeys: readonly ProtectedKeyBlob[],
): (ProtectedKeyBlob | PublicContactKey)[] {
  // Prefer the usable contact the picker showed; a stale selection still
  // fails loudly at encrypt time.
  return selectedIds
    .map(
      (id) =>
        ownKeys.find((k) => k.keyId === id) ??
        contacts.find(
          (c) => c.keyId === id && c.usableForEncryption !== false,
        ) ??
        contacts.find((c) => c.keyId === id),
    )
    .filter((k) => k !== undefined);
}

export function toSelectedRecipient(key: PickerKey): SelectedRecipient {
  if ("armoredPublicKey" in key) {
    return {
      keyId: key.keyId,
      armored: key.armoredPublicKey,
      // Encrypt to every ACTIVE key: this is the one place that decides
      // the recipient set, so turned-off keys must drop out here. Empty
      // when all are off, and buildEncryptRecipients refuses that rather
      // than falling back to `armored`.
      armoredAll: activeRecipients(key).map((r) => r.armored),
      kind: storedKeyKind(key),
    };
  }
  return {
    keyId: key.keyId,
    armored: key.publicKeyArmored,
    // Required: without it an SSH recipient is handed to OpenPGP.
    kind: storedKeyKind(key),
  };
}

/** An age message can't carry an OpenPGP password (SKESK). Separate from
 *  {@link mixedEngineReason} because the user has not mixed anything. */
export function sshPasswordReason(): string {
  return t("actions_ssh_password_reason");
}

/** OpenPGP and age are different formats; a mixed set would silently
 *  produce two ciphertexts, so it is refused. */
export function mixedEngineReason(): string {
  return t("actions_mixed_engine_reason");
}

export function noActiveKeyReason(): string {
  return t("actions_no_active_key_reason");
}

/** `engine` is null when the set is empty or mixed; `reason` is non-null
 *  only when mixed. */
export interface RecipientEngine {
  engine: StoredKeyKind | null;
  reason: string | null;
}

export function resolveRecipientEngine(
  recipients: readonly SelectedRecipient[],
): RecipientEngine {
  // Empty implies no engine, not "PGP by default".
  if (recipients.length === 0) return { engine: null, reason: null };
  const kinds = new Set(recipients.map(storedKeyKind));
  if (kinds.size > 1) return { engine: null, reason: mixedEngineReason() };
  const [engine] = kinds;
  return { engine, reason: null };
}

export interface EncryptRecipients {
  recipientPublicKeys: string[];
  /** Null when the selection is empty or refused. */
  engine: StoredKeyKind | null;
  /** Non-null when the operation MUST NOT run. `recipientPublicKeys` is
   *  then empty, so a caller that forgets to check encrypts to nobody
   *  rather than the wrong set. */
  refusal: string | null;
  /** True when the user won't be able to decrypt the result. */
  selfExcluded: boolean;
  /** Own key added via encrypt-to-self, or null. */
  selfKeyId: string | null;
}

/** The user's own key for an operation: configured default (if it still
 *  exists), then the signing key, then the first. Null if none. */
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
 * Assemble the recipient key set: dedupe, refuse mixed engines or
 * all-keys-off contacts, and add the user's own key (same engine only)
 * when encrypt-to-self is on and they aren't already a recipient.
 */
export function buildEncryptRecipients(options: {
  recipients: SelectedRecipient[];
  encryptToSelf: boolean;
  ownKeys: OwnKey[];
  signingKeyId?: string | null;
  defaultKeyId?: string | null;
}): EncryptRecipients {
  const { recipients, encryptToSelf, ownKeys } = options;

  const { engine, reason: mixed } = resolveRecipientEngine(recipients);
  // A contact whose keys were all turned off after selection: never fall
  // back to its (turned-off) head key.
  const reason =
    mixed ??
    (recipients.some((r) => r.armoredAll?.length === 0)
      ? noActiveKeyReason()
      : null);
  if (reason !== null) {
    return {
      recipientPublicKeys: [],
      selfExcluded: false,
      selfKeyId: null,
      engine: null,
      refusal: reason,
    };
  }

  // Encrypt-to-self must stay inside the chosen engine.
  const eligibleOwnKeys =
    engine === null
      ? ownKeys
      : ownKeys.filter((k) => storedKeyKind(k) === engine);

  const deduped: SelectedRecipient[] = [];
  for (const recipient of recipients) {
    if (!deduped.some((r) => r.keyId === recipient.keyId)) {
      deduped.push(recipient);
    }
  }
  // Also dedupe armored strings: two contacts can share a key.
  const recipientPublicKeys = [
    ...new Set(deduped.flatMap((r) => r.armoredAll ?? [r.armored])),
  ];

  const selfSelected = deduped.some((r) =>
    ownKeys.some((k) => k.keyId === r.keyId),
  );
  if (selfSelected) {
    return {
      recipientPublicKeys,
      selfExcluded: false,
      selfKeyId: null,
      engine,
      refusal: null,
    };
  }

  const selfKey = encryptToSelf
    ? resolveSelfKey(
        eligibleOwnKeys,
        options.defaultKeyId ?? null,
        options.signingKeyId,
      )
    : null;
  if (selfKey === null) {
    return {
      recipientPublicKeys,
      selfExcluded: true,
      selfKeyId: null,
      engine,
      refusal: null,
    };
  }

  return {
    recipientPublicKeys: [...recipientPublicKeys, selfKey.publicKeyArmored],
    selfExcluded: false,
    selfKeyId: selfKey.keyId,
    engine: engine ?? storedKeyKind(selfKey),
    refusal: null,
  };
}
