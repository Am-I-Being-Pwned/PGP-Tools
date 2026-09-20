import type { PrivateKeyExporter } from "../../components/keys/ExportPrivateKeyPage";
import type { CrxSigningKeyBlob } from "../crx/types";
import type { ProtectedKeyBlob } from "../storage/keyring";
import { serializeCrxKeyBlocks } from "../crx/backup";
import {
  closeCrxKey,
  exportCrxPrivateKeyPem,
  openCrxKey,
  resealCrxKeyUnderPassword,
} from "../crx/operations";
import { AppError } from "../errors/app-error";
import { t } from "../i18n";
import { encryptKeyForExportWithHandle, getKeyArmored } from "../pgp/wasm";

/**
 * Exporter for a PGP private key. The key is already unlocked in the session,
 * so there is no unlock gate: each export fetches the live session handle via
 * `getKeyHandle` (which returns null if the key has since locked) and does not
 * release it -- the session owns its handle.
 */
export function pgpKeyExporter(
  blob: ProtectedKeyBlob,
  getKeyHandle: (keyId: string) => number | null,
): PrivateKeyExporter {
  return {
    title: t("keygen_exporter_pgp_title"),
    isPasskey: blob.protection.method === "passkey",
    needsUnlock: false,
    acquire: () => {
      const handle = getKeyHandle(blob.keyId);
      return handle === null
        ? Promise.reject(
            new AppError("key-locked", t("keygen_error_key_not_unlocked")),
          )
        : Promise.resolve(handle);
    },
    release: () => {
      /* session owns the handle; nothing to drop */
    },
    exportEncrypted: async (handle, passphrase) => {
      const bytes = new TextEncoder().encode(passphrase);
      try {
        return await encryptKeyForExportWithHandle(handle, bytes);
      } finally {
        bytes.fill(0);
      }
    },
    exportPlaintext: (handle) => getKeyArmored(handle),
    encryptedBlurb: t("keygen_exporter_pgp_encrypted_blurb"),
    encryptedButton: t("keygen_export_with_passphrase"),
    plaintextBlurb: t("keygen_exporter_pgp_plaintext_blurb"),
    plaintextButton: t("keygen_export_without_passphrase"),
  };
}

/**
 * Exporter for a CRX signing key. A CRX key has no persistent unlocked session
 * (sealed at rest), so the dialog's unlock gate opens a transient WASM handle
 * that the dialog holds and drops on close.
 */
export function crxKeyExporter(blob: CrxSigningKeyBlob): PrivateKeyExporter {
  const isPasskey = blob.protection.method === "passkey";
  return {
    title: t("keygen_exporter_crx_title"),
    isPasskey,
    needsUnlock: true,
    acquire: (password) => openCrxKey(blob, password),
    release: (handle) => {
      void closeCrxKey(handle);
    },
    exportEncrypted: async (handle, passphrase) => {
      const portable = await resealCrxKeyUnderPassword(
        handle,
        passphrase,
        blob.label,
      );
      return serializeCrxKeyBlocks([portable]);
    },
    exportPlaintext: (handle) => exportCrxPrivateKeyPem(handle),
    unlockBlurb: isPasskey
      ? t("keygen_exporter_crx_unlock_passkey")
      : t("keygen_exporter_crx_unlock_password"),
    encryptedBlurb: t("keygen_exporter_crx_encrypted_blurb"),
    encryptedButton: t("keygen_exporter_crx_encrypted_button"),
    plaintextBlurb: t("keygen_exporter_crx_plaintext_blurb"),
    plaintextButton: t("keygen_exporter_crx_plaintext_button"),
  };
}
