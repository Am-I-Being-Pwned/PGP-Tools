import { STORAGE_KEYRING } from "~/lib/constants";
import { AppError } from "~/lib/errors/app-error";
import { hasContactsSession } from "~/lib/pgp/wasm";
import type {
  EncryptedBlob,
  PasskeyEncryptedBlob,
  PasswordEncryptedBlob,
} from "~/lib/protection/encrypt-private-key";
import type { KeyProtection } from "~/lib/protection/protected-blob";
import {
  kindField,
  type KindDiscriminated,
  type StoredKeyKind,
} from "./key-kind";
import { createProtectedStore } from "./protected-store";

// ── key blob ─────────────────────────────────────────────────────────

export interface ProtectedKeyBlob extends KindDiscriminated {
  version: 1;
  /** OpenPGP fingerprint (`pgp`) or OpenSSH `SHA256:...` (`ssh`); what the
   *  seal's AAD binds to. */
  keyId: string;
  /** OpenPGP User IDs; an SSH key stores its comment as the sole element. */
  userIds: string[];
  algorithm: string;
  /** Local display name only; never touches the certificate. */
  alias?: string;
  /** Armored cert (`pgp`) or `<type> <base64>` recipient line (`ssh`). */
  publicKeyArmored: string;
  /** OpenPGP only -- age has no revocation concept. */
  revocationCertificate?: string;
  /** Non-blocking parse warning (e.g. SHA-1 binding); key stays usable. */
  securityWarning?: string;
  /** How the private half is sealed (`protection/protected-blob.ts`). */
  protection: KeyProtection;
  encryptedPrivateKey: string; // base64 ciphertext
  iv: string; // base64
  createdAt: number;
  lastUsedAt: number;
}

// ── constructors ─────────────────────────────────────────────────────

/** Assemble a stored blob from a fresh seal. `kind` is only persisted for
 *  "ssh" (`key-kind.ts`). */
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

/** Delete one key. Must stay guarded on the vault session: a locked load
 *  returns `[]`, so an unguarded delete would persist "nothing left" over
 *  every key without the vault ever being opened. */
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

/** Set (or clear, with a blank value) a key's local display alias. */
export async function updateAlias(keyId: string, alias: string): Promise<void> {
  const trimmed = alias.trim();
  await keyringStore.update(keyId, (key) => {
    key.alias = trimmed || undefined;
  });
}

/** Swap a key's at-rest sealing. Other fields are read fresh under the
 *  lock so a stale snapshot can't clobber them. Throws when the key is
 *  missing: the caller reports success, so a silent no-op would lie. */
export async function replaceKeyProtection(
  keyId: string,
  parts: Pick<ProtectedKeyBlob, "protection" | "encryptedPrivateKey" | "iv">,
): Promise<void> {
  await keyringStore.update(
    keyId,
    (key) => {
      key.protection = parts.protection;
      key.encryptedPrivateKey = parts.encryptedPrivateKey;
      key.iv = parts.iv;
    },
    {
      onMissing: (id) => {
        throw new AppError("key-not-found", `Key ${id} is not in the keyring`);
      },
    },
  );
}

/** Backfill an imported key's revocation certificate. Overwriting is
 *  harmless: every minted revocation cert stays valid. */
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
      // Must NOT no-op: the caller reports "certificate created".
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
