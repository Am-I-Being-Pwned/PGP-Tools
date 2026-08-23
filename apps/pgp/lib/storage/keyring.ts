import type {
  EncryptedBlob,
  PasskeyEncryptedBlob,
  PasswordEncryptedBlob,
} from "../protection/encrypt-private-key";
import type { KeyProtection } from "../protection/protected-blob";
import type { KindDiscriminated, StoredKeyKind } from "./key-kind";
import { STORAGE_KEYRING } from "../constants";
import { AppError } from "../errors/app-error";
import { hasContactsSession } from "../pgp/wasm";
import { kindField } from "./key-kind";
import { createProtectedStore } from "./protected-store";

// ── key blob ─────────────────────────────────────────────────────────

export interface ProtectedKeyBlob extends KindDiscriminated {
  version: 1;
  /** The key's stable identity: an OpenPGP fingerprint for a `pgp` blob,
   *  the OpenSSH `SHA256:...` fingerprint for an `ssh` one. Either way,
   *  what the seal's AAD binds the ciphertext to. */
  keyId: string;
  /** OpenPGP User IDs. An SSH key has none: it carries a single free-text
   *  comment (conventionally `user@host`), which is stored here as the
   *  sole element so the UI has one name field to render, not two. */
  userIds: string[];
  algorithm: string;
  /** Local, user-set display name. Never touches the certificate: the
   *  User IDs remain the cryptographic identity; this is just what the
   *  UI shows. Cleared (undefined) reverts to the first User ID. */
  alias?: string;
  /** The public half, in whatever form the engine publishes it: armored
   *  cert for `pgp`, canonical `<type> <base64>` recipient line for
   *  `ssh`. */
  publicKeyArmored: string;
  /** OpenPGP only -- age has no revocation concept. */
  revocationCertificate?: string;
  /** Non-blocking flag from key parsing (e.g. relies on a SHA-1 binding
   *  signature). Shown as a warning badge; the key is still usable. */
  securityWarning?: string;
  /** How the private half is sealed at rest. The same union every
   *  protected key type uses — see `protection/protected-blob.ts`. */
  protection: KeyProtection;
  encryptedPrivateKey: string; // base64 ciphertext
  iv: string; // base64
  createdAt: number;
  lastUsedAt: number;
}

// ── constructors ─────────────────────────────────────────────────────

/**
 * Assemble a stored blob from a fresh seal.
 *
 * `kind` defaults to `"pgp"` and is only ever PERSISTED for `"ssh"` (see
 * `key-kind.ts`), so a PGP blob written today is byte-identical to one
 * written before SSH existed.
 */
export function blobFromEncrypted(
  keyId: string,
  userIds: string[],
  algorithm: string,
  publicKeyArmored: string,
  encrypted: EncryptedBlob,
  kind: StoredKeyKind = "pgp",
): ProtectedKeyBlob {
  const protection: KeyProtection =
    encrypted.method === "passkey"
      ? {
          method: "passkey",
          credentialId: encrypted.credentialId,
          prfSalt: encrypted.prfSalt,
          storedSecret: encrypted.storedSecret,
        }
      : {
          method: "password",
          kdfSalt: encrypted.salt,
        };

  return {
    version: 1,
    ...kindField(kind),
    keyId,
    userIds,
    algorithm,
    publicKeyArmored,
    protection,
    encryptedPrivateKey: encrypted.ciphertext,
    iv: encrypted.iv,
    createdAt: Date.now(),
    lastUsedAt: Date.now(),
  };
}

/** Reconstruct an EncryptedBlob from a stored ProtectedKeyBlob. */
export function encryptedBlobFromProtected(
  blob: ProtectedKeyBlob,
): EncryptedBlob {
  if (blob.protection.method === "passkey") {
    return {
      method: "passkey",
      ciphertext: blob.encryptedPrivateKey,
      iv: blob.iv,
      credentialId: blob.protection.credentialId,
      prfSalt: blob.protection.prfSalt,
      storedSecret: blob.protection.storedSecret,
    } satisfies PasskeyEncryptedBlob;
  }
  return {
    method: "password",
    ciphertext: blob.encryptedPrivateKey,
    iv: blob.iv,
    salt: blob.protection.kdfSalt,
  } satisfies PasswordEncryptedBlob;
}

// ── encrypted storage ───────────────────────────────────────────────
// AES-256-GCM encrypted blob via WASM contacts session key.
// Same scheme as contacts — see encrypted-store.ts.

function isValidBlob(v: unknown): v is ProtectedKeyBlob {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.keyId === "string" &&
    typeof o.publicKeyArmored === "string" &&
    typeof o.encryptedPrivateKey === "string" &&
    typeof o.iv === "string" &&
    typeof o.protection === "object" &&
    o.protection !== null &&
    typeof (o.protection as Record<string, unknown>).method === "string"
  );
}

const keyringStore = createProtectedStore<ProtectedKeyBlob>({
  storageKey: STORAGE_KEYRING,
  isValid: isValidBlob,
  label: "keyring",
  idOf: (blob) => blob.keyId,
});

/** One-time upgrade of a keyring blob to canonical padding and to the
 *  domain-bound sealing envelope. */
export function normalizeKeyringPadding(): Promise<void> {
  return keyringStore.normalize();
}

// ── CRUD (all mutations serialized via withLock) ─────────────────────

export async function getKeyring(): Promise<ProtectedKeyBlob[]> {
  return keyringStore.getAll();
}

export async function addKey(blob: ProtectedKeyBlob): Promise<void> {
  await keyringStore.put(blob);
}

/** Delete one key.
 *
 *  Guarded on the vault session, and it must stay that way. A locked
 *  vault makes the load return `[]` -- indistinguishable from an empty
 *  keyring -- so an unguarded delete would compute "nothing left", take
 *  the empty-store shortcut, and `removeItem` the sealed blob: every key
 *  destroyed, without the vault ever being opened. The CRX store has
 *  carried the same guard since it was written (see its `requireSession`
 *  and the comment above it); the keyring simply never got one. */
export async function removeKey(keyId: string): Promise<void> {
  await keyringStore.remove(keyId, {
    guard: async () => {
      if (!(await hasContactsSession())) {
        throw new AppError(
          "vault-locked",
          "Cannot delete a key: the vault is locked",
        );
      }
      return true;
    },
  });
}

/** Set (or clear, with an empty/blank value) a key's local display
 *  alias. Non-destructive: only the stored metadata changes. */
export async function updateAlias(keyId: string, alias: string): Promise<void> {
  const trimmed = alias.trim();
  await keyringStore.update(keyId, (key) => {
    key.alias = trimmed || undefined;
  });
}

/** Backfill the revocation certificate for an imported key (generated
 *  keys store one at creation time). Overwriting is harmless: every
 *  revocation certificate ever minted for a key stays valid. */
export async function updateRevocationCertificate(
  keyId: string,
  armored: string,
): Promise<void> {
  await keyringStore.update(
    keyId,
    (key) => {
      key.revocationCertificate = armored;
    },
    {
      // Unlike the metadata setters above, a miss here must NOT no-op:
      // the caller reports "certificate created" on success, and a cert
      // that was never persisted would make that a false assurance (e.g.
      // the key was deleted, or the vault locked mid-flight and the load
      // returned nothing).
      onMissing: () => {
        throw new AppError(
          "key-not-found",
          "Key not found - the certificate was not saved.",
        );
      },
    },
  );
}

export async function updateLastUsed(keyId: string): Promise<void> {
  await keyringStore.update(keyId, (key) => {
    key.lastUsedAt = Date.now();
  });
}
