import { useCopyToClipboard } from "~/hooks/useCopyToClipboard";
import { useKeyring } from "~/hooks/useKeyring";
import { usePreferences } from "~/hooks/usePreferences";
import { useVault } from "~/hooks/useVault";
import { publicKeyDerToPem, type CrxSigningKeyBlob } from "~/lib/crx/types";
import { t } from "~/lib/i18n";
import { downloadPublicKey } from "~/lib/keys/export-bundle";
import { crxKeyExporter, pgpKeyExporter } from "~/lib/keys/exporters";
import { isPgpRecord, isSshRecord } from "~/lib/storage/key-kind";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { formatAlgorithm, formatFingerprint } from "~/lib/utils/formatting";
import type { KeyCardModel } from "./KeyCard";
import type { KeysSubRoute } from "./keys-routes";

/**
 * One descriptor per own key, PGP then SSH then CRX, so all render through
 * KeyCard in one list. Split by `isPgpRecord` / `isSshRecord` (legacy keys
 * carry no `kind`), and not cosmetically: `pgpKeyExporter` is the OpenPGP
 * plaintext trapdoor, and an SSH identity must have no such export
 * (SECURITY.md) -- it leaves only as ciphertext this app produced.
 */
export function useKeyCardModels(
  crxKeys: CrxSigningKeyBlob[],
  push: (route: KeysSubRoute) => void,
): KeyCardModel[] {
  const keyring = useKeyring();
  const { session } = useVault();
  const { defaultKeyId } = usePreferences();
  const { copy } = useCopyToClipboard();

  const ownModel = (blob: ProtectedKeyBlob): KeyCardModel => {
    const ssh = isSshRecord(blob);
    // An SSH key's name is its `ssh-keygen` comment, or nothing at all.
    const realName =
      blob.userIds[0] ?? (ssh ? blob.keyId : t("keys_unknown_name"));
    return {
      // The id namespace names the STORE: SSH lives in the keyring too.
      kind: "pgp",
      id: blob.keyId,
      displayName: blob.alias ?? realName,
      realName,
      // An OpenSSH fingerprint is a base64 hash: its tail identifies
      // nothing, so it shows whole; and no 4-char-block line for it.
      shortId: ssh ? blob.keyId : blob.keyId.slice(-16),
      algorithm: formatAlgorithm(blob.algorithm),
      fingerprint: ssh ? undefined : formatFingerprint(blob.keyId),
      badge: ssh ? "SSH" : undefined,
      isDefault: !ssh && defaultKeyId != null && blob.keyId === defaultKeyId,
      protectionMethod: blob.protection.method,
      securityWarning: blob.securityWarning,
      session: {
        isUnlocked: session.isUnlocked(blob.keyId),
        unlockWithPassword: (pw) => session.unlockWithPassword(blob, pw),
        unlockWithPasskey: () => session.unlockWithPasskey(blob),
        lock: () => session.lock(blob.keyId),
      },
      exporter: ssh ? null : pgpKeyExporter(blob, session.getKeyHandle),
      // No label: KeyCard shows its own inline "copied" note.
      onCopyPublicKey: () => void copy(blob.publicKeyArmored),
      // An SSH recipient line downloads as `.pub`, what other tools expect.
      onDownloadPublicKey: () =>
        downloadPublicKey(
          blob.publicKeyArmored,
          blob.alias ?? realName,
          ssh ? "pub" : "asc",
        ),
      onDelete: () =>
        push({
          page: "confirm-delete",
          target: { kind: "own", keyBlob: blob },
        }),
      onRename: () =>
        push({ page: "rename", target: { kind: "own", keyBlob: blob } }),
      onShowDetails: () =>
        push({ page: "details", target: { kind: "own", keyBlob: blob } }),
    };
  };

  const crxModel = (blob: CrxSigningKeyBlob): KeyCardModel => ({
    kind: "crx",
    id: blob.extensionId,
    displayName: blob.label ?? blob.extensionId,
    realName: blob.extensionId,
    shortId: blob.extensionId.slice(0, 16),
    algorithm: formatAlgorithm(blob.algorithm),
    badge: "CRX",
    protectionMethod: blob.protection.method,
    session: undefined,
    exporter: crxKeyExporter(blob),
    onCopyPublicKey: () => void copy(publicKeyDerToPem(blob.publicKeyDerB64)),
    onDownloadPublicKey: () =>
      downloadPublicKey(
        publicKeyDerToPem(blob.publicKeyDerB64),
        blob.label ?? blob.extensionId,
        "pem",
      ),
    onDelete: () =>
      push({
        page: "confirm-delete",
        target: { kind: "crx", keyBlob: blob },
      }),
    onRename: () =>
      push({ page: "rename", target: { kind: "crx", keyBlob: blob } }),
    onShowDetails: undefined,
  });

  // One list: a second heading would make the user know which engine
  // their own key belongs to before they could find it.
  return [
    ...keyring.keys.filter(isPgpRecord).map(ownModel),
    ...keyring.keys.filter(isSshRecord).map(ownModel),
    ...crxKeys.map(crxModel),
  ];
}
