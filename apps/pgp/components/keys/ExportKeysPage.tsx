import { useEffect, useRef, useState } from "react";
import { CheckIcon, LockIcon } from "lucide-react";

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
import { backupFileName } from "../../lib/keys/export-bundle";
import {
  encryptKeyForExportWithHandle,
  getKeyArmored,
} from "../../lib/pgp/wasm";
import { isWebAuthnCancel } from "../../lib/protection/webauthn-prf";
import { toast } from "../../lib/toast";
import { downloadText } from "../../lib/utils/download";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { SubPage } from "../shared/SubPage";

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
        setUnlockErrors((e) => ({ ...e, [blob.keyId]: "Wrong password." }));
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
          [blob.keyId]: "Passkey authentication failed.",
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
      setCrxErrors((e) => ({ ...e, [blob.extensionId]: "Wrong password." }));
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
          [blob.extensionId]: "Passkey authentication failed.",
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
        setError("Passphrase must be at least 8 characters.");
        return;
      }
      if (passphrase !== confirmPassphrase) {
        setError("Passphrases do not match.");
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
        toast.success(`Exported ${count} key${count === 1 ? "" : "s"}`, {
          id: "keys-exported",
        });
      resetAndClose();
    } catch (e) {
      // No console.* here (SECURITY.md §9): the message may carry unlock /
      // WASM context, and the extension console outlives the session.
      setError(
        e instanceof Error ? `Export failed: ${e.message}` : "Export failed.",
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
        toast.success(
          `Exported ${count} key${count === 1 ? "" : "s"} (private keys UNENCRYPTED)`,
          { id: "keys-exported" },
        );
      resetAndClose();
    } catch (e) {
      setError(
        e instanceof Error ? `Export failed: ${e.message}` : "Export failed.",
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
        Exporting a private key requires unlocking it first. Unlock the keys
        below to include them in the backup.
      </p>

      <div className="space-y-2">
        {myKeys.map((blob) => {
          const unlocked = isUnlocked(blob.keyId);
          const name = blob.userIds[0] ?? blob.keyId.slice(-16);
          const isPasskey = blob.protection.method === "passkey";
          const busy = unlockingId === blob.keyId;
          return (
            <div
              key={blob.keyId}
              className="border-border rounded-md border p-2"
            >
              <div className="flex items-center gap-2">
                <span
                  className={
                    unlocked ? "text-green-400" : "text-muted-foreground"
                  }
                >
                  {unlocked ? (
                    <CheckIcon className="h-4 w-4" />
                  ) : (
                    <LockIcon className="h-4 w-4" />
                  )}
                </span>
                <span className="min-w-0 flex-1 truncate text-sm">{name}</span>
                {!unlocked && isPasskey && (
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy}
                    onClick={() => void handleUnlockPasskey(blob)}
                  >
                    {busy ? "..." : "Unlock"}
                  </Button>
                )}
              </div>

              {!unlocked && !isPasskey && (
                <div className="mt-2 flex items-stretch gap-2">
                  <input
                    type="password"
                    autoComplete="current-password"
                    placeholder="Key password"
                    value={passwords[blob.keyId] ?? ""}
                    onChange={(e) =>
                      setPasswords((p) => ({
                        ...p,
                        [blob.keyId]: e.target.value,
                      }))
                    }
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void handleUnlockPassword(blob);
                    }}
                    className={`${INPUT_CLASS} h-9 flex-1 py-0`}
                  />
                  <Button
                    size="sm"
                    className="h-9 shrink-0"
                    disabled={busy || !(passwords[blob.keyId] ?? "")}
                    onClick={() => void handleUnlockPassword(blob)}
                  >
                    {busy ? "..." : "Unlock"}
                  </Button>
                </div>
              )}

              {unlockErrors[blob.keyId] && (
                <p className="text-destructive mt-1 text-xs">
                  {unlockErrors[blob.keyId]}
                </p>
              )}
            </div>
          );
        })}

        {allCrxKeys.map((blob) => {
          const unlocked = blob.extensionId in crxHandles;
          const name = blob.label ?? blob.extensionId.slice(0, 16);
          const isPasskey = blob.protection.method === "passkey";
          const busy = unlockingId === blob.extensionId;
          return (
            <div
              key={blob.extensionId}
              className="border-border rounded-md border p-2"
            >
              <div className="flex items-center gap-2">
                <span
                  className={
                    unlocked ? "text-green-400" : "text-muted-foreground"
                  }
                >
                  {unlocked ? (
                    <CheckIcon className="h-4 w-4" />
                  ) : (
                    <LockIcon className="h-4 w-4" />
                  )}
                </span>
                <span className="min-w-0 flex-1 truncate text-sm">
                  {name}
                  <span className="text-muted-foreground ml-1.5 text-[11px]">
                    CRX
                  </span>
                </span>
                {!unlocked && isPasskey && (
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy}
                    onClick={() => void handleUnlockCrxPasskey(blob)}
                  >
                    {busy ? "..." : "Unlock"}
                  </Button>
                )}
              </div>

              {!unlocked && !isPasskey && (
                <div className="mt-2 flex items-stretch gap-2">
                  <input
                    type="password"
                    autoComplete="current-password"
                    placeholder="Key password"
                    value={crxPasswords[blob.extensionId] ?? ""}
                    onChange={(e) =>
                      setCrxPasswords((p) => ({
                        ...p,
                        [blob.extensionId]: e.target.value,
                      }))
                    }
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void handleUnlockCrxPassword(blob);
                    }}
                    className={`${INPUT_CLASS} h-9 flex-1 py-0`}
                  />
                  <Button
                    size="sm"
                    className="h-9 shrink-0"
                    disabled={busy || !(crxPasswords[blob.extensionId] ?? "")}
                    onClick={() => void handleUnlockCrxPassword(blob)}
                  >
                    {busy ? "..." : "Unlock"}
                  </Button>
                </div>
              )}

              {crxErrors[blob.extensionId] && (
                <p className="text-destructive mt-1 text-xs">
                  {crxErrors[blob.extensionId]}
                </p>
              )}
            </div>
          );
        })}
      </div>

      {contacts.length > 0 && (
        <p className="text-muted-foreground text-xs">
          {contacts.length} contact{contacts.length === 1 ? "" : "s"} will also
          be included (public keys, no unlock needed).
        </p>
      )}

      <Button
        variant="outline"
        className="w-full"
        onClick={() => setStep("export")}
      >
        {myKeys.length === 0 && crxCount === 0
          ? "Continue"
          : "Skip locked keys and continue"}
      </Button>
    </div>
  ) : (
    <div className="space-y-3">
      <p className="text-muted-foreground text-xs">
        Downloads one <span className="font-mono">.asc</span> file (standard
        ASCII-armored OpenPGP): your {unlockedKeys.length} unlocked private key
        {unlockedKeys.length === 1 ? "" : "s"} as{" "}
        <span className="font-mono">PGP PRIVATE KEY BLOCK</span>s and your{" "}
        {contacts.length} contact{contacts.length === 1 ? "" : "s"} as{" "}
        <span className="font-mono">PGP PUBLIC KEY BLOCK</span>s.
      </p>

      {unlockedCrxKeys.length > 0 && (
        <p className="text-muted-foreground text-xs">
          Plus {unlockedCrxKeys.length} CRX signing key
          {unlockedCrxKeys.length === 1 ? "" : "s"}, re-encrypted under this
          passphrase so they restore on any device.
        </p>
      )}

      {lockedKeys.length + lockedCrxKeys.length > 0 && (
        <p className="rounded border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-400">
          {lockedKeys.length + lockedCrxKeys.length} key
          {lockedKeys.length + lockedCrxKeys.length === 1 ? "" : "s"} still
          locked and will be left out.{" "}
          <button
            type="button"
            className="underline"
            onClick={() => setStep("unlock")}
          >
            Go back to unlock
          </button>
          .
        </p>
      )}

      {needsPassphrase ? (
        <>
          <p className="text-muted-foreground text-xs">
            Set a passphrase to encrypt the exported private keys (OpenPGP S2K
            -- imports into GnuPG and other tools). Anyone with this passphrase
            and the file can decrypt your messages and sign as you.
          </p>
          <input
            type="password"
            autoComplete="new-password"
            placeholder="Passphrase (min 8 characters)"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            className={INPUT_CLASS}
            autoFocus
          />
          <input
            type="password"
            autoComplete="new-password"
            placeholder="Confirm passphrase"
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
            {exporting ? "Exporting..." : "Export with passphrase"}
          </Button>

          {hasPgpPrivate && (
            <div className="border-border space-y-2 border-t pt-3">
              <p className="text-destructive text-[11px]">
                Plaintext export. Anyone who reads the downloaded file gets full
                control of every PGP key in it.
                {crxCount > 0
                  ? " CRX signing keys are left out of a plaintext export -- use a passphrase to include them."
                  : ""}{" "}
                Type <span className="font-mono font-bold">EXPORT</span> to
                confirm:
              </p>
              <input
                type="text"
                autoComplete="off"
                spellCheck={false}
                value={unsafeConfirm}
                onChange={(e) => setUnsafeConfirm(e.target.value)}
                placeholder="EXPORT"
                className={INPUT_CLASS}
              />
              <Button
                variant="destructive"
                size="sm"
                className="w-full"
                disabled={exporting || unsafeConfirm !== "EXPORT"}
                onClick={() => void handleUnsafeExport()}
              >
                Export without passphrase (unsafe)
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
            {exporting ? "Exporting..." : "Export"}
          </Button>
        </>
      ) : (
        <p className="text-muted-foreground text-xs">Nothing to export.</p>
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
  title = "Export keys",
  ...props
}: ExportKeysPageProps) {
  return (
    <SubPage title={title} onClose={onClose}>
      {(api) => <ExportKeysFlowBody close={api.close} {...props} />}
    </SubPage>
  );
}
