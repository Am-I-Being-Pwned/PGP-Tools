import type { PublicContactKey } from "./storage/contacts";
import type { StoredKeyKind } from "./storage/key-kind";
import { activeRecipients } from "./storage/contacts";
import { storedKeyKind } from "./storage/key-kind";

/** One of the user's own keys, as needed for recipient assembly. Both
 *  `ProtectedKeyBlob` and any {keyId, publicKeyArmored} pair satisfy it. */
interface OwnKey {
  keyId: string;
  publicKeyArmored: string;
  /** Absent means `"pgp"` -- see `storage/key-kind.ts`. */
  kind?: StoredKeyKind;
}

/** A recipient the user selected in the picker. */
export interface SelectedRecipient {
  /** Id of the selected RECORD -- what dedupe and encrypt-to-self
   *  compare on. For a contact holding several keys this is the contact
   *  id, not the only key being encrypted to; see `armoredAll`. */
  keyId: string;
  /** The record's head key. Kept as the single source of truth for a
   *  caller that predates multi-key contacts. */
  armored: string;
  /** Every key this recipient should be encrypted to. Absent means
   *  `[armored]`, so a caller written before contacts could hold more
   *  than one key keeps working unchanged. */
  armoredAll?: string[];
  /** Which engine this recipient belongs to. Absent means `"pgp"`, so a
   *  caller that predates the age engine keeps working. */
  kind?: StoredKeyKind;
}

/** A key the picker can offer: one of the user's own keys, or a contact.
 *  The two are told apart structurally, by `armoredPublicKey`. */
type PickerKey = OwnKey | PublicContactKey;

/**
 * The picker's selection, as `buildEncryptRecipients` wants it.
 *
 * This is the one place that knows a contact's armored bytes live under
 * a different field name than an own key's, and the ONE place that
 * expands a contact into its full key list -- both `WorkspaceView` (for
 * the `selfExcluded` preview) and `useWorkspaceOperations` (for the
 * encrypt itself) go through it, so the preview cannot disagree with
 * what actually runs.
 */
export function toSelectedRecipient(key: PickerKey): SelectedRecipient {
  if ("armoredPublicKey" in key) {
    return {
      keyId: key.keyId,
      armored: key.armoredPublicKey,
      // A contact may hold several keys (a GitHub user commonly has
      // three). Encrypt to all of them: any one of the person's
      // identities then decrypts, and we cannot know which machine they
      // are reading from. A single-key contact yields a one-element list
      // here, identical to the old behaviour.
      //
      // ACTIVE, not all: this is the one place that decides what a
      // message is actually encrypted to, so a key the user turned off
      // has to drop out HERE -- the details page still lists it, and
      // must, or it could never be turned back on. `activeRecipients`
      // never returns an empty list (see its safety net), so this can
      // never collapse to encrypting to nobody.
      armoredAll: activeRecipients(key).map((r) => r.armored),
      kind: storedKeyKind(key),
    };
  }
  return {
    keyId: key.keyId,
    armored: key.publicKeyArmored,
    // Without this the engine layer is inert: every recipient looks like
    // a PGP one (absent kind means "pgp"), so a mixed set is never
    // detected and an SSH recipient is handed to OpenPGP.
    kind: storedKeyKind(key),
  };
}

/**
 * Why a mixed selection is refused.
 *
 * OpenPGP and age are two different file formats, not two ciphers behind
 * one container: there is no message that is both. Encrypting to a mixed
 * set could only mean silently producing TWO ciphertexts, and the user
 * would have no way to tell which recipient got which -- so the selection
 * is refused up front instead, with this reason for the UI to show.
 */
export const MIXED_ENGINE_REASON =
  "PGP and SSH recipients can't be combined in one message: OpenPGP and age are different formats. Encrypt to one group, then the other.";

/** The single engine a recipient set implies. `engine` is null when the
 *  set is empty (nothing to imply one) or when it is mixed, and `reason`
 *  is non-null in exactly the mixed case. */
export interface RecipientEngine {
  engine: StoredKeyKind | null;
  reason: string | null;
}

/** Which engine will encrypt this selection, or a refusal if it names
 *  more than one. */
export function resolveRecipientEngine(
  recipients: readonly SelectedRecipient[],
): RecipientEngine {
  // Nothing selected implies no engine -- not "PGP by default". The
  // caller's own key decides in that case (see buildEncryptRecipients).
  if (recipients.length === 0) return { engine: null, reason: null };
  const kinds = new Set(recipients.map(storedKeyKind));
  if (kinds.size > 1) return { engine: null, reason: MIXED_ENGINE_REASON };
  const [engine] = kinds;
  return { engine, reason: null };
}

/** The armored key set an encrypt operation should target, plus whether
 *  the user's own key ended up excluded (so the caller can warn that the
 *  ciphertext will be unreadable to them). */
export interface EncryptRecipients {
  recipientPublicKeys: string[];
  /** The engine that will encrypt: `"pgp"` (OpenPGP) or `"ssh"` (age).
   *  Null when the selection is empty or refused. */
  engine: StoredKeyKind | null;
  /** Non-null when the operation MUST NOT run, with the reason to show
   *  the user. Currently only a mixed PGP/SSH selection
   *  ({@link MIXED_ENGINE_REASON}). `recipientPublicKeys` is empty in
   *  that case, so a caller that forgets to check encrypts to nobody
   *  rather than to the wrong set. */
  refusal: string | null;
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

  const { engine, reason } = resolveRecipientEngine(recipients);
  if (reason !== null) {
    return {
      recipientPublicKeys: [],
      selfExcluded: false,
      selfKeyId: null,
      engine: null,
      refusal: reason,
    };
  }

  // Encrypt-to-self must stay inside the chosen engine: adding a PGP key
  // to an age message is the same mixing, arrived at by a different
  // route. With no recipients selected there is no engine to match yet,
  // so every own key stays eligible.
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
  // One selected recipient can contribute several keys (a contact
  // holding more than one). Dedupe the resulting ARMORED STRINGS as well
  // as the records: two contacts can legitimately list the same key --
  // the same person added twice, or a shared deploy key -- and a
  // duplicate age stanza is wasteful and odd-looking in the header.
  const recipientPublicKeys = [
    ...new Set(
      deduped.flatMap((r) =>
        r.armoredAll && r.armoredAll.length > 0 ? r.armoredAll : [r.armored],
      ),
    ),
  ];

  // A selected recipient is one of the user's own keys: they can already
  // decrypt the result, so never double-add (or warn).
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
