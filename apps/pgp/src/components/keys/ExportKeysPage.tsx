import { useEffect, useRef, useState } from "react";

import { BlockStack, Button } from "@amibeingpwned/ui";

import { Emphasised } from "~/components/shared/Emphasised";
import { SubPage } from "~/components/shared/SubPage";
import { useAsyncAction } from "~/hooks";
import { serializeCrxKeyBlocks } from "~/lib/crx/backup";
import {
  closeCrxKey,
  openCrxKey,
  resealCrxKeyUnderPassword,
} from "~/lib/crx/operations";
import type { CrxSigningKeyBlob } from "~/lib/crx/types";
import { t, tn } from "~/lib/i18n";
import { backupFileName } from "~/lib/keys/export-bundle";
import { encryptKeyForExportWithHandle, getKeyArmored } from "~/lib/pgp/wasm";
import { isWebAuthnCancel } from "~/lib/protection/webauthn-prf";
import type { PublicContactKey } from "~/lib/storage/contacts";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { toast } from "~/lib/toast";
import { downloadText } from "~/lib/utils/download";
import {
  ExportPassphraseFields,
  useExportPassphrase,
} from "./ExportPassphraseFields";
import { KeyUnlockRow } from "./KeyUnlockRow";

type Step = "unlock" | "export";

export interface ExportKeysProps {
  myKeys: ProtectedKeyBlob[];
  contacts: PublicContactKey[];
  crxKeys?: CrxSigningKeyBlob[];
  isUnlocked: (keyId: string) => boolean;
  getKeyHandle: (keyId: string) => number | null;
  onUnlockWithPassword: (
    blob: ProtectedKeyBlob,
    password: string,
  ) => Promise<boolean>;
  onUnlockWithPasskey: (
    blob: ProtectedKeyBlob,
  ) => Promise<boolean | "cancelled">;
  /** Replaces the default success toast. `unsafe` marks the plaintext path. */
  onExported?: (count: number, unsafe: boolean) => void;
}

interface ExportKeysFlowProps extends ExportKeysProps {
  onClose: () => void;
}

/**
 * Bulk export of everything passed in to one armored `.asc`. Locked keys
 * are unlocked first, then re-sealed under one export passphrase. CRX keys
 * go only in the passphrase-encrypted path.
 */
function useExportKeysFlow({
  onClose,
  myKeys,
  contacts,
  crxKeys,
  isUnlocked,
  getKeyHandle,
  onUnlockWithPassword,
  onUnlockWithPasskey,
  onExported,
}: ExportKeysFlowProps) {
  const [step, setStep] = useState<Step>("unlock");
  const [passwords, setPasswords] = useState<Record<string, string>>({});
  const [unlockErrors, setUnlockErrors] = useState<Record<string, string>>({});
  const [unlockingId, setUnlockingId] = useState<string | null>(null);
  // Synchronous in-flight guard: state lands a render late, and a second CRX
  // unlock would open two WASM handles and leak the first.
  const unlockInFlight = useRef(false);

  const [crxHandles, setCrxHandles] = useState<Record<string, number>>({});
  // Unmount cleanup reads this ref; []-deps effects see only initial state.
  const crxHandlesRef = useRef<Record<string, number>>({});
  const [crxPasswords, setCrxPasswords] = useState<Record<string, string>>({});
  const [crxErrors, setCrxErrors] = useState<Record<string, string>>({});

  const fields = useExportPassphrase();
  const exportAction = useAsyncAction((e) => ({
    message:
      e instanceof Error
        ? t("keygen_export_failed_detail", { message: e.message })
        : t("keygen_export_failed"),
  }));
  const error = exportAction.error?.message ?? null;
  const exporting = exportAction.busy;

  const allCrxKeys = crxKeys ?? [];
  const lockedKeys = myKeys.filter((k) => !isUnlocked(k.keyId));
  const unlockedKeys = myKeys.filter((k) => isUnlocked(k.keyId));
  const lockedCrxKeys = allCrxKeys.filter(
    (k) => !(k.extensionId in crxHandles),
  );
  const unlockedCrxKeys = allCrxKeys.filter((k) => k.extensionId in crxHandles);
  const allUnlocked = lockedKeys.length === 0 && lockedCrxKeys.length === 0;
  const needsPassphrase = unlockedKeys.length > 0 || unlockedCrxKeys.length > 0;
  const hasPgpPrivate = unlockedKeys.length > 0;
  const crxCount = allCrxKeys.length;

  useEffect(() => {
    if (step === "unlock" && allUnlocked) setStep("export");
  }, [step, allUnlocked]);

  useEffect(() => {
    crxHandlesRef.current = crxHandles;
  }, [crxHandles]);

  // An Argon2id derive can outlive the slide-out; a late handle must be
  // dropped, not left decrypted in WASM untracked.
  const unmounted = useRef(false);

  // Drop CRX handles on any unmount so no signing key outlives "Lock".
  // dropCrxKey is idempotent.
  useEffect(() => {
    return () => {
      unmounted.current = true;
      for (const handle of Object.values(crxHandlesRef.current)) {
        void closeCrxKey(handle);
      }
    };
  }, []);

  const resetAndClose = () => {
    for (const handle of Object.values(crxHandles)) void closeCrxKey(handle);
    setCrxHandles({});
    onClose();
  };

  const handleUnlockPassword = async (blob: ProtectedKeyBlob) => {
    if (unlockInFlight.current) return;
    unlockInFlight.current = true;
    setUnlockingId(blob.keyId);
    setUnlockErrors((e) => ({ ...e, [blob.keyId]: "" }));
    try {
      const ok = await onUnlockWithPassword(blob, passwords[blob.keyId] ?? "");
      if (!ok) {
        setUnlockErrors((e) => ({
          ...e,
          [blob.keyId]: t("keygen_error_wrong_password"),
        }));
      } else {
        setPasswords((p) => ({ ...p, [blob.keyId]: "" }));
      }
    } finally {
      unlockInFlight.current = false;
      setUnlockingId(null);
    }
  };

  const handleUnlockPasskey = async (blob: ProtectedKeyBlob) => {
    if (unlockInFlight.current) return;
    unlockInFlight.current = true;
    setUnlockingId(blob.keyId);
    setUnlockErrors((e) => ({ ...e, [blob.keyId]: "" }));
    try {
      const res = await onUnlockWithPasskey(blob);
      if (res !== true && res !== "cancelled") {
        setUnlockErrors((e) => ({
          ...e,
          [blob.keyId]: t("keygen_error_passkey_failed"),
        }));
      }
    } finally {
      unlockInFlight.current = false;
      setUnlockingId(null);
    }
  };

  const handleUnlockCrxPassword = async (blob: CrxSigningKeyBlob) => {
    if (unlockInFlight.current || blob.extensionId in crxHandlesRef.current)
      return;
    unlockInFlight.current = true;
    setUnlockingId(blob.extensionId);
    setCrxErrors((e) => ({ ...e, [blob.extensionId]: "" }));
    try {
      const handle = await openCrxKey(
        blob,
        crxPasswords[blob.extensionId] ?? "",
      );
      if (unmounted.current) {
        void closeCrxKey(handle);
        return;
      }
      setCrxHandles((h) => ({ ...h, [blob.extensionId]: handle }));
      setCrxPasswords((p) => ({ ...p, [blob.extensionId]: "" }));
    } catch {
      setCrxErrors((e) => ({
        ...e,
        [blob.extensionId]: t("keygen_error_wrong_password"),
      }));
    } finally {
      unlockInFlight.current = false;
      setUnlockingId(null);
    }
  };

  const handleUnlockCrxPasskey = async (blob: CrxSigningKeyBlob) => {
    if (unlockInFlight.current || blob.extensionId in crxHandlesRef.current)
      return;
    unlockInFlight.current = true;
    setUnlockingId(blob.extensionId);
    setCrxErrors((e) => ({ ...e, [blob.extensionId]: "" }));
    try {
      const handle = await openCrxKey(blob);
      if (unmounted.current) {
        void closeCrxKey(handle);
        return;
      }
      setCrxHandles((h) => ({ ...h, [blob.extensionId]: handle }));
    } catch (e) {
      if (!isWebAuthnCancel(e)) {
        setCrxErrors((errs) => ({
          ...errs,
          [blob.extensionId]: t("keygen_error_passkey_failed"),
        }));
      }
    } finally {
      unlockInFlight.current = false;
      setUnlockingId(null);
    }
  };

  /** `crxBlock` null skips CRX entirely (the plaintext path). */
  const buildAndDownload = async (
    privateArmor: (handle: number) => Promise<string>,
    crxBlock:
      ((handle: number, blob: CrxSigningKeyBlob) => Promise<string>) | null,
  ) => {
    const parts: string[] = [];
    for (const key of myKeys) {
      const handle = getKeyHandle(key.keyId);
      if (handle === null) continue;
      parts.push((await privateArmor(handle)).trim());
    }
    for (const contact of contacts) {
      parts.push(contact.armoredPublicKey.trim());
    }
    if (crxBlock) {
      for (const crx of allCrxKeys) {
        if (!(crx.extensionId in crxHandles)) continue;
        parts.push((await crxBlock(crxHandles[crx.extensionId], crx)).trim());
      }
    }
    downloadText(parts.join("\n\n") + "\n", backupFileName());
    return parts.length;
  };

  // No console.* on failure (SECURITY.md §9): the message may carry
  // unlock / WASM context, and the extension console outlives the session.
  const handleEncryptedExport = async () => {
    const invalid = needsPassphrase ? fields.validate() : null;
    if (invalid) {
      exportAction.setError(invalid);
      return;
    }
    const { passphrase } = fields;
    await exportAction.run(async () => {
      const passphraseBytes = new TextEncoder().encode(passphrase);
      try {
        const count = await buildAndDownload(
          (handle) => encryptKeyForExportWithHandle(handle, passphraseBytes),
          async (handle, crx) => {
            const portable = await resealCrxKeyUnderPassword(
              handle,
              passphrase,
              crx.label,
            );
            return serializeCrxKeyBlocks([portable]);
          },
        );
        if (onExported) onExported(count, false);
        else
          toast.success(tn("keygen_export_toast_exported", count), {
            id: "keys-exported",
          });
        resetAndClose();
      } finally {
        passphraseBytes.fill(0);
      }
    });
  };

  // PGP only: CRX keys are never written unencrypted.
  const handleUnsafeExport = () =>
    exportAction.run(async () => {
      const count = await buildAndDownload(getKeyArmored, null);
      if (onExported) onExported(count, true);
      else
        toast.success(tn("keygen_export_toast_exported_unsafe", count), {
          id: "keys-exported",
        });
      resetAndClose();
    });

  return {
    step,
    setStep,
    myKeys,
    contacts,
    allCrxKeys,
    isUnlocked,
    unlockingId,
    passwords,
    setPasswords,
    unlockErrors,
    crxHandles,
    crxPasswords,
    setCrxPasswords,
    crxErrors,
    fields,
    error,
    exporting,
    lockedKeys,
    unlockedKeys,
    lockedCrxKeys,
    unlockedCrxKeys,
    needsPassphrase,
    hasPgpPrivate,
    crxCount,
    handleUnlockPassword,
    handleUnlockPasskey,
    handleUnlockCrxPassword,
    handleUnlockCrxPasskey,
    handleEncryptedExport,
    handleUnsafeExport,
  };
}

type ExportKeysFlow = ReturnType<typeof useExportKeysFlow>;

function ExportKeysBody({ f }: { f: ExportKeysFlow }) {
  return f.step === "unlock" ? (
    <div className="space-y-3">
      <p className="text-muted-foreground text-xs">
        {t("keygen_export_unlock_intro")}
      </p>

      <BlockStack>
        {f.myKeys.map((blob) => (
          <KeyUnlockRow
            key={blob.keyId}
            name={blob.userIds[0] ?? blob.keyId.slice(-16)}
            fingerprint={blob.keyId}
            unlocked={f.isUnlocked(blob.keyId)}
            isPasskey={blob.protection.method === "passkey"}
            busy={f.unlockingId === blob.keyId}
            password={f.passwords[blob.keyId] ?? ""}
            error={f.unlockErrors[blob.keyId]}
            onPasswordChange={(v) =>
              f.setPasswords((p) => ({ ...p, [blob.keyId]: v }))
            }
            onUnlockPassword={() => void f.handleUnlockPassword(blob)}
            onUnlockPasskey={() => void f.handleUnlockPasskey(blob)}
          />
        ))}

        {f.allCrxKeys.map((blob) => (
          <KeyUnlockRow
            key={blob.extensionId}
            name={blob.label ?? blob.extensionId.slice(0, 16)}
            fingerprint={blob.extensionId}
            badge="CRX"
            unlocked={blob.extensionId in f.crxHandles}
            isPasskey={blob.protection.method === "passkey"}
            busy={f.unlockingId === blob.extensionId}
            password={f.crxPasswords[blob.extensionId] ?? ""}
            error={f.crxErrors[blob.extensionId]}
            onPasswordChange={(v) =>
              f.setCrxPasswords((p) => ({ ...p, [blob.extensionId]: v }))
            }
            onUnlockPassword={() => void f.handleUnlockCrxPassword(blob)}
            onUnlockPasskey={() => void f.handleUnlockCrxPasskey(blob)}
          />
        ))}
      </BlockStack>

      {f.contacts.length > 0 && (
        <p className="text-muted-foreground text-xs">
          {tn("keygen_export_contacts_included", f.contacts.length)}
        </p>
      )}

      <Button
        variant="outline"
        className="w-full"
        onClick={() => f.setStep("export")}
      >
        {f.myKeys.length === 0 && f.crxCount === 0
          ? t("common_continue")
          : t("keygen_export_skip_locked")}
      </Button>
    </div>
  ) : (
    <div className="space-y-3">
      <p className="text-muted-foreground text-xs">
        <Emphasised
          text={t("keygen_export_summary", {
            ext: ".asc",
            private_keys: tn(
              "keygen_export_summary_private_keys",
              f.unlockedKeys.length,
            ),
            contacts: tn("keygen_export_summary_contacts", f.contacts.length),
            private_block: "PGP PRIVATE KEY BLOCK",
            public_block: "PGP PUBLIC KEY BLOCK",
          })}
          terms={[".asc", "PGP PRIVATE KEY BLOCK", "PGP PUBLIC KEY BLOCK"]}
          wrap={(term, key) => (
            <span key={key} className="font-mono">
              {term}
            </span>
          )}
        />
      </p>

      {f.unlockedCrxKeys.length > 0 && (
        <p className="text-muted-foreground text-xs">
          {tn("keygen_export_crx_included", f.unlockedCrxKeys.length)}
        </p>
      )}

      {f.lockedKeys.length + f.lockedCrxKeys.length > 0 && (
        <p className="text-warn rounded-lg bg-[#252012] px-3 py-2.5 text-xs">
          {tn(
            "keygen_export_still_locked",
            f.lockedKeys.length + f.lockedCrxKeys.length,
          )}{" "}
          <button
            type="button"
            className="underline"
            onClick={() => f.setStep("unlock")}
          >
            {t("keygen_export_go_back_unlock")}
          </button>
          {t("keygen_export_still_locked_after")}
        </p>
      )}

      {f.needsPassphrase ? (
        <>
          <p className="text-muted-foreground text-xs">
            {t("keygen_export_passphrase_intro")}
          </p>
          <ExportPassphraseFields
            fields={f.fields}
            error={f.error}
            busy={f.exporting}
            submitLabel={t("keygen_export_with_passphrase")}
            busyLabel={t("keygen_exporting")}
            onSubmit={() => void f.handleEncryptedExport()}
            plaintext={
              f.hasPgpPrivate
                ? {
                    warning:
                      t("keygen_export_plaintext_warning_file") +
                      (f.crxCount > 0
                        ? " " + t("keygen_export_plaintext_crx_left_out")
                        : ""),
                    button: t("keygen_export_without_passphrase"),
                    onExport: () => void f.handleUnsafeExport(),
                  }
                : undefined
            }
          />
        </>
      ) : f.contacts.length > 0 ? (
        <>
          {f.error && <p className="text-destructive text-xs">{f.error}</p>}
          <Button
            className="w-full"
            onClick={() => void f.handleEncryptedExport()}
            disabled={f.exporting}
          >
            {f.exporting ? t("keygen_exporting") : t("keygen_export")}
          </Button>
        </>
      ) : (
        <p className="text-muted-foreground text-xs">
          {t("keygen_export_nothing")}
        </p>
      )}
    </div>
  );
}

/** Hooks must mount inside the SubPage so `close` exists. */
function ExportKeysFlowBody({
  close,
  ...props
}: ExportKeysProps & { close: () => void }) {
  const flow = useExportKeysFlow({ onClose: close, ...props });
  return <ExportKeysBody f={flow} />;
}

interface ExportKeysPageProps extends ExportKeysProps {
  onClose: () => void;
  title?: string;
}

export function ExportKeysPage({
  onClose,
  title = t("keygen_export_title"),
  ...props
}: ExportKeysPageProps) {
  return (
    <SubPage title={title} onClose={onClose}>
      {(api) => <ExportKeysFlowBody close={api.close} {...props} />}
    </SubPage>
  );
}
