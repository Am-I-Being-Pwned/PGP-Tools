import { useEffect, useRef, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { serializeCrxKeyBlocks } from "../../lib/crx/backup";
import {
  closeCrxKey,
  openCrxKey,
  resealCrxKeyUnderPassword,
} from "../../lib/crx/operations";
import { t, tn } from "../../lib/i18n";
import { backupFileName } from "../../lib/keys/export-bundle";
import {
  encryptKeyForExportWithHandle,
  getKeyArmored,
} from "../../lib/pgp/wasm";
import { isWebAuthnCancel } from "../../lib/protection/webauthn-prf";
import { toast } from "../../lib/toast";
import { downloadText } from "../../lib/utils/download";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { Emphasised } from "../shared/Emphasised";
import { SubPage } from "../shared/SubPage";
import { KeyUnlockRow } from "./KeyUnlockRow";

type Step = "unlock" | "export";

/** The keys/contacts + vault callbacks the export flow operates on. */
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
  /** Called on a successful export in place of the default success toast, so a
   *  caller can react (e.g. deselect and offer "Reselect"). Omitted ⇒ default
   *  toast. `unsafe` is true for the plaintext (unencrypted) path. */
  onExported?: (count: number, unsafe: boolean) => void;
}

interface ExportKeysFlowProps extends ExportKeysProps {
  /** Slide the page out (state is dropped on unmount). */
  onClose: () => void;
}

/**
 * The whole bulk-export flow -- state, WASM-handle lifecycle, and export
 * actions. Lives for exactly one mount of {@link ExportKeysPage}.
 *
 * Bulk export of EVERYTHING passed in: every private key, every CRX signing
 * key, and every contact's public key, in one armored `.asc` file. Exporting a
 * private key needs its decrypted WASM handle, so every locked key -- PGP or
 * CRX -- must be unlocked first (password / passkey), then re-sealed under the
 * single export passphrase, which is what makes the backup portable across
 * devices. Output is standard ASCII-armored OpenPGP; CRX keys go in labelled
 * `PGP TOOLS CRX SIGNING KEY` blocks and only in the passphrase-encrypted path.
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
  // Synchronous in-flight guard: `unlockingId` state lands a render late, so
  // Enter-spam during a multi-second Argon2id derive could start a second
  // unlock — for CRX keys that opens two WASM handles and leaks the first
  // (only the last lands in `crxHandles`).
  const unlockInFlight = useRef(false);

  // CRX keys unlock into WASM handles held here for the life of the flow;
  // dropped on close. Keyed by extensionId.
  const [crxHandles, setCrxHandles] = useState<Record<string, number>>({});
  // Mirror of `crxHandles` for the unmount cleanup below: an effect with []
  // deps captures the initial (empty) state, so it must read from a ref to
  // see the handles actually opened during the flow's life.
  const crxHandlesRef = useRef<Record<string, number>>({});
  const [crxPasswords, setCrxPasswords] = useState<Record<string, string>>({});
  const [crxErrors, setCrxErrors] = useState<Record<string, string>>({});

  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [unsafeConfirm, setUnsafeConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  const allCrxKeys = crxKeys ?? [];
  const lockedKeys = myKeys.filter((k) => !isUnlocked(k.keyId));
  const unlockedKeys = myKeys.filter((k) => isUnlocked(k.keyId));
  const lockedCrxKeys = allCrxKeys.filter(
    (k) => !(k.extensionId in crxHandles),
  );
  const unlockedCrxKeys = allCrxKeys.filter((k) => k.extensionId in crxHandles);
  const allUnlocked = lockedKeys.length === 0 && lockedCrxKeys.length === 0;
  // A passphrase is required whenever any private key material will be
  // written -- PGP privates OR CRX keys (which are always sealed on export).
  const needsPassphrase = unlockedKeys.length > 0 || unlockedCrxKeys.length > 0;
  // The plaintext escape hatch only makes sense for GnuPG-interop PGP keys.
  const hasPgpPrivate = unlockedKeys.length > 0;
  const crxCount = allCrxKeys.length;

  // Skip (or leave) the unlock step the moment nothing is locked -- this also
  // covers the initial mount when every key is already unlocked.
  useEffect(() => {
    if (step === "unlock" && allUnlocked) setStep("export");
  }, [step, allUnlocked]);

  // Keep the ref in sync so the unmount cleanup sees the latest handles.
  useEffect(() => {
    crxHandlesRef.current = crxHandles;
  }, [crxHandles]);

  // True once the flow has unmounted, so a CRX unlock still in flight (a
  // multi-second Argon2id derive can outlive the 300ms slide-out) can
  // detect it resolved into a dead flow and drop its fresh handle instead
  // of leaving it decrypted in WASM untracked.
  const unmounted = useRef(false);

  // Drop any opened CRX handles on unmount -- whether the page slid out
  // normally or the whole tree got swapped (a pending op switches tabs, the
  // vault locks) -- so no signing key lingers decrypted in WASM past "Lock".
  // dropCrxKey on an already-dropped handle is a harmless no-op, so this
  // can't double-free.
  useEffect(() => {
    return () => {
      unmounted.current = true;
      for (const handle of Object.values(crxHandlesRef.current)) {
        void closeCrxKey(handle);
      }
    };
  }, []);

  const resetAndClose = () => {
    // Drop any CRX handles we opened so no key material lingers in WASM.
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
      // The flow unmounted while the unlock was in flight: the handle
      // belongs to nobody (the unmount cleanup already ran), so drop it.
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
      // Same in-flight-past-unmount guard as the password path above.
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

  /** Build the armored bundle from the now-unlocked keys + contacts.
   *  `privateArmor` renders each PGP private key; `crxBlock`, when provided,
   *  re-seals + serializes each unlocked CRX key (null skips CRX entirely,
   *  e.g. the plaintext path). */
  const buildAndDownload = async (
    privateArmor: (handle: number) => Promise<string>,
    crxBlock:
      ((handle: number, blob: CrxSigningKeyBlob) => Promise<string>) | null,
  ) => {
    const parts: string[] = [];
    for (const key of myKeys) {
      const handle = getKeyHandle(key.keyId);
      if (handle === null) continue; // re-locked mid-flight; shouldn't happen
      parts.push((await privateArmor(handle)).trim());
    }
    for (const contact of contacts) {
      parts.push(contact.armoredPublicKey.trim());
    }
    if (crxBlock) {
      for (const crx of allCrxKeys) {
        if (!(crx.extensionId in crxHandles)) continue; // left locked -> skipped
        parts.push((await crxBlock(crxHandles[crx.extensionId], crx)).trim());
      }
    }
    downloadText(parts.join("\n\n") + "\n", backupFileName());
    return parts.length;
  };

  const handleEncryptedExport = async () => {
    setError(null);
    if (needsPassphrase) {
      if (passphrase.length < 8) {
        setError(t("keygen_error_passphrase_short"));
        return;
      }
      if (passphrase !== confirmPassphrase) {
        setError(t("keygen_error_passphrase_mismatch"));
        return;
      }
    }
    setExporting(true);
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
    } catch (e) {
      // No console.* here (SECURITY.md §9): the message may carry unlock /
      // WASM context, and the extension console outlives the session.
      setError(
        e instanceof Error
          ? t("keygen_export_failed_detail", { message: e.message })
          : t("keygen_export_failed"),
      );
    } finally {
      passphraseBytes.fill(0);
      setExporting(false);
    }
  };

  const handleUnsafeExport = async () => {
    setError(null);
    setExporting(true);
    try {
      // Plaintext path is PGP-only; CRX keys are not written unencrypted.
      const count = await buildAndDownload(getKeyArmored, null);
      if (onExported) onExported(count, true);
      else
        toast.success(tn("keygen_export_toast_exported_unsafe", count), {
          id: "keys-exported",
        });
      resetAndClose();
    } catch (e) {
      setError(
        e instanceof Error
          ? t("keygen_export_failed_detail", { message: e.message })
          : t("keygen_export_failed"),
      );
    } finally {
      setExporting(false);
    }
  };

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
    passphrase,
    setPassphrase,
    confirmPassphrase,
    setConfirmPassphrase,
    unsafeConfirm,
    setUnsafeConfirm,
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

/** The two-step export body. Reads everything from `f`. */
function ExportKeysBody({ f }: { f: ExportKeysFlow }) {
  const {
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
    passphrase,
    setPassphrase,
    confirmPassphrase,
    setConfirmPassphrase,
    unsafeConfirm,
    setUnsafeConfirm,
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
  } = f;

  return step === "unlock" ? (
    <div className="space-y-3">
      <p className="text-muted-foreground text-xs">
        {t("keygen_export_unlock_intro")}
      </p>

      <div className="space-y-2">
        {myKeys.map((blob) => (
          <KeyUnlockRow
            key={blob.keyId}
            name={blob.userIds[0] ?? blob.keyId.slice(-16)}
            unlocked={isUnlocked(blob.keyId)}
            isPasskey={blob.protection.method === "passkey"}
            busy={unlockingId === blob.keyId}
            password={passwords[blob.keyId] ?? ""}
            error={unlockErrors[blob.keyId]}
            onPasswordChange={(v) =>
              setPasswords((p) => ({ ...p, [blob.keyId]: v }))
            }
            onUnlockPassword={() => void handleUnlockPassword(blob)}
            onUnlockPasskey={() => void handleUnlockPasskey(blob)}
          />
        ))}

        {allCrxKeys.map((blob) => (
          <KeyUnlockRow
            key={blob.extensionId}
            name={blob.label ?? blob.extensionId.slice(0, 16)}
            badge="CRX"
            unlocked={blob.extensionId in crxHandles}
            isPasskey={blob.protection.method === "passkey"}
            busy={unlockingId === blob.extensionId}
            password={crxPasswords[blob.extensionId] ?? ""}
            error={crxErrors[blob.extensionId]}
            onPasswordChange={(v) =>
              setCrxPasswords((p) => ({ ...p, [blob.extensionId]: v }))
            }
            onUnlockPassword={() => void handleUnlockCrxPassword(blob)}
            onUnlockPasskey={() => void handleUnlockCrxPasskey(blob)}
          />
        ))}
      </div>

      {contacts.length > 0 && (
        <p className="text-muted-foreground text-xs">
          {tn("keygen_export_contacts_included", contacts.length)}
        </p>
      )}

      <Button
        variant="outline"
        className="w-full"
        onClick={() => setStep("export")}
      >
        {myKeys.length === 0 && crxCount === 0
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
              unlockedKeys.length,
            ),
            contacts: tn("keygen_export_summary_contacts", contacts.length),
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

      {unlockedCrxKeys.length > 0 && (
        <p className="text-muted-foreground text-xs">
          {tn("keygen_export_crx_included", unlockedCrxKeys.length)}
        </p>
      )}

      {lockedKeys.length + lockedCrxKeys.length > 0 && (
        <p className="rounded border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-400">
          {tn(
            "keygen_export_still_locked",
            lockedKeys.length + lockedCrxKeys.length,
          )}{" "}
          <button
            type="button"
            className="underline"
            onClick={() => setStep("unlock")}
          >
            {t("keygen_export_go_back_unlock")}
          </button>
          {t("keygen_export_still_locked_after")}
        </p>
      )}

      {needsPassphrase ? (
        <>
          <p className="text-muted-foreground text-xs">
            {t("keygen_export_passphrase_intro")}
          </p>
          <input
            type="password"
            autoComplete="new-password"
            placeholder={t("keygen_passphrase_placeholder")}
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            className={INPUT_CLASS}
            autoFocus
          />
          <input
            type="password"
            autoComplete="new-password"
            placeholder={t("keygen_confirm_passphrase_placeholder")}
            value={confirmPassphrase}
            onChange={(e) => setConfirmPassphrase(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void handleEncryptedExport();
            }}
            className={INPUT_CLASS}
          />
          {error && <p className="text-destructive text-xs">{error}</p>}
          <Button
            className="w-full"
            onClick={() => void handleEncryptedExport()}
            disabled={exporting || !passphrase}
          >
            {exporting
              ? t("keygen_exporting")
              : t("keygen_export_with_passphrase")}
          </Button>

          {hasPgpPrivate && (
            <div className="border-border space-y-2 border-t pt-3">
              <p className="text-destructive text-[11px]">
                {t("keygen_export_plaintext_warning_file")}
                {crxCount > 0
                  ? " " + t("keygen_export_plaintext_crx_left_out")
                  : ""}{" "}
                {t("keygen_type_to_confirm_before")}{" "}
                <span className="font-mono font-bold">
                  {t("keygen_confirm_word")}
                </span>{" "}
                {t("keygen_type_to_confirm_after")}
              </p>
              <input
                type="text"
                autoComplete="off"
                spellCheck={false}
                value={unsafeConfirm}
                onChange={(e) => setUnsafeConfirm(e.target.value)}
                placeholder={t("keygen_confirm_word")}
                className={INPUT_CLASS}
              />
              <Button
                variant="destructive"
                size="sm"
                className="w-full"
                disabled={
                  exporting || unsafeConfirm !== t("keygen_confirm_word")
                }
                onClick={() => void handleUnsafeExport()}
              >
                {t("keygen_export_without_passphrase")}
              </Button>
            </div>
          )}
        </>
      ) : contacts.length > 0 ? (
        <>
          {error && <p className="text-destructive text-xs">{error}</p>}
          <Button
            className="w-full"
            onClick={() => void handleEncryptedExport()}
            disabled={exporting}
          >
            {exporting ? t("keygen_exporting") : t("keygen_export")}
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

/** Hook host: the flow's hooks must live in a component that mounts inside
 *  the SubPage (so its `close` exists), not in the page function itself. */
function ExportKeysFlowBody({
  close,
  ...props
}: ExportKeysProps & { close: () => void }) {
  const flow = useExportKeysFlow({ onClose: close, ...props });
  return <ExportKeysBody f={flow} />;
}

interface ExportKeysPageProps extends ExportKeysProps {
  /** Called after the slide-out finishes (parent unmounts the page). */
  onClose: () => void;
  /** Header title; Settings passes "Export all keys". */
  title?: string;
}

/**
 * Slide-over subpage for the bulk-export flow, shared by the selection
 * island (Keys tab) and Settings' "Export all keys". State lives for one
 * mount; closing (back / Escape / success) unmounts it, and the unmount
 * cleanup drops any CRX handles opened along the way.
 */
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
