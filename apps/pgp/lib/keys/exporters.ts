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
    title: "Export Private Key",
    isPasskey: blob.protection.method === "passkey",
    needsUnlock: false,
    acquire: () => {
      const handle = getKeyHandle(blob.keyId);
      return handle === null
        ? Promise.reject(new Error("Key is not unlocked."))
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
    encryptedBlurb:
      "Set a passphrase to encrypt the exported key. Anyone with this passphrase and the exported key can decrypt your messages and sign as you.",
    encryptedButton: "Export with passphrase",
    plaintextBlurb:
      "Plaintext export. Anyone who reads your clipboard gets full control of this key.",
    plaintextButton: "Export without passphrase (unsafe)",
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
    title: "Copy CRX private key",
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
    unlockBlurb: `Unlock this signing key to copy it. ${
      isPasskey ? "Authenticate with your passkey." : "Enter the key password."
    }`,
    encryptedBlurb:
      "Set a passphrase to encrypt the copied key (re-importable into PGP Tools via Import Keys). Anyone with this passphrase and the copied block can sign extensions as you.",
    encryptedButton: "Copy with passphrase",
    plaintextBlurb:
      "Plaintext export (raw PKCS#8 PEM). Anyone who reads your clipboard gets full control of this signing key.",
    plaintextButton: "Copy without passphrase (unsafe)",
  };
}
