import { useRef, useState } from "react";

import { Button, Input } from "@amibeingpwned/ui";

import { ImportReview } from "~/components/keys/ImportReview";
import { ProtectionMethodPicker } from "~/components/keys/ProtectionMethodPicker";
import { useProtectionChoice } from "~/components/keys/useProtectionChoice";
import { SubPage, type SubPageAction } from "~/components/shared/SubPage";
import { useAsyncAction } from "~/hooks";
import { splitArmoredKeyBlocks } from "~/lib/armor-blocks";
import { parseCrxKeyBlocks } from "~/lib/crx/backup";
import {
  crxBlobIdentityMatches,
  type CrxSigningKeyBlob,
} from "~/lib/crx/types";
import { t, tn } from "~/lib/i18n";
import {
  mergeSameKey,
  prepareImport,
  storedKeysFrom,
  withIdentityConflicts,
} from "~/lib/import/prepare";
import {
  applyReview,
  defaultDecision,
  needsDecision,
  type ReviewDecision,
  type ReviewedContact,
} from "~/lib/import/review";
import { isPublicKind, type IncomingKey } from "~/lib/import/types";
import { importKey } from "~/lib/pgp/key-management";
import type { KeyInfo } from "~/lib/pgp/types";
import { importAndProtect } from "~/lib/protection/protect-flow";
import {
  authenticateAndGetPrf,
  generatePrfSalt,
  isWebAuthnCancel,
  registerPasskey,
} from "~/lib/protection/webauthn-prf";
import type { PublicContactKey } from "~/lib/storage/contacts";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { toast } from "~/lib/toast";
import { errorMessage } from "~/lib/utils/errors";

type Step = "paste" | "unlock" | "protect" | "review";

interface ParsedPrivate {
  armored: string;
  keyInfo: KeyInfo;
  secretEncrypted: boolean;
}

interface ImportAllKeysPageProps {
  onClose: () => void;
  myKeys: ProtectedKeyBlob[];
  contacts: PublicContactKey[];
  onAddKey: (blob: ProtectedKeyBlob) => Promise<void>;
  onAddContact: (contact: ReviewedContact) => Promise<void>;
  onRemoveContact: (keyId: string) => Promise<void>;
  onAddCrxKey?: (blob: CrxSigningKeyBlob) => Promise<void>;
  /** For skip-if-present: an import must never overwrite a live key. */
  crxKeys?: CrxSigningKeyBlob[];
  reusePasskeyCredentialId?: string;
  /** With reuse, the one ceremony runs under the master's PRF salt so the
   *  vault ceremony opens every imported key. */
  masterSealSalt?: ArrayBuffer;
}

/** Review row: nothing secret (the armor stays in `parsedPrivates`). */
function privateRow(key: ParsedPrivate): IncomingKey {
  return {
    keyId: key.keyInfo.keyId,
    kind: "pgp-private",
    status: "new",
    info: key.keyInfo,
    details: null,
    userIds: key.keyInfo.userIds,
    changes: [],
    publicArmored: "",
  };
}

function crxRow(blob: CrxSigningKeyBlob): IncomingKey {
  return {
    keyId: blob.extensionId,
    kind: "crx",
    status: "new",
    info: null,
    details: null,
    userIds: [blob.label ?? t("import_crx_headline")],
    changes: [],
    publicArmored: "",
  };
}

/**
 * Bulk import of an "Export all keys" dump. Private keys share one source
 * passphrase and one protection method (one WebAuthn ceremony via PRF
 * reuse). Every key is listed on the Review before anything is asked for
 * or saved.
 */
export function ImportAllKeysPage({
  onClose,
  myKeys,
  contacts,
  onAddKey,
  onAddContact,
  onRemoveContact,
  onAddCrxKey,
  crxKeys,
  reusePasskeyCredentialId,
  masterSealSalt,
}: ImportAllKeysPageProps) {
  const [step, setStep] = useState<Step>("paste");
  const [text, setText] = useState("");
  // A dismissed passkey prompt is not an error.
  const work = useAsyncAction((e) =>
    isWebAuthnCancel(e)
      ? null
      : { message: errorMessage(e, t("settings_import_failed")) },
  );
  const error = work.error?.message ?? null;
  const setError = work.setError;
  const importing = work.busy;
  const [parsedPrivates, setParsedPrivates] = useState<ParsedPrivate[]>([]);
  const [parsedCrx, setParsedCrx] = useState<CrxSigningKeyBlob[]>([]);
  const [skippedPrivates, setSkippedPrivates] = useState(0);
  const [sourcePassphrase, setSourcePassphrase] = useState("");
  const choice = useProtectionChoice({
    reusePasskeyCredentialId,
    masterSealSalt,
  });
  const fileInputRef = useRef<HTMLInputElement>(null);

  // A backup can come from anyone, so every key is reviewed first;
  // contacts and CRX keys are written at the very end.
  const [reviewKeys, setReviewKeys] = useState<IncomingKey[] | null>(null);
  const [publicKeys, setPublicKeys] = useState<IncomingKey[]>([]);
  const [decisions, setDecisions] = useState<
    ReadonlyMap<string, ReviewDecision>
  >(new Map());

  /** `privateIds`: a public copy of the backup's own private key is its
   *  public half, not a contact. */
  const classifyPublics = async (
    blocks: string[],
    privateIds: ReadonlySet<string>,
  ): Promise<IncomingKey[]> => {
    if (blocks.length === 0) return [];
    const stored = storedKeysFrom(myKeys, contacts);
    const keys: IncomingKey[] = [];
    for (const block of blocks) {
      const prepared = await prepareImport(block, stored);
      keys.push(...prepared.keys.filter((k) => isPublicKind(k.kind)));
    }
    // Merged so every User ID is checked; conflicts are recomputed across
    // the whole backup in `withConflicts`.
    return (await mergeSameKey(keys, stored))
      .filter((k) => !privateIds.has(k.keyId.toUpperCase()))
      .map(({ conflict: _c, ...k }) => k);
  };

  /** Private and CRX rows are checked too: a private key named as a
   *  contact would otherwise go in silently. */
  const withConflicts = (rows: IncomingKey[]) =>
    withIdentityConflicts(rows, storedKeysFrom(myKeys, contacts));

  const toastRejected = (checked: IncomingKey[]) => {
    const rejected = checked.filter((k) => k.status === "rejected");
    if (rejected.length > 0)
      toast.error(
        rejected[0].rejection
          ? tn("settings_import_contacts_rejected_reason", rejected.length, {
              reason: rejected[0].rejection,
            })
          : tn("settings_import_contacts_rejected", rejected.length),
        { id: "contacts-rejected" },
      );
  };

  /** Called last, after any private keys are saved. */
  const commitPublics = async (
    keys: IncomingKey[],
    chosen: ReadonlyMap<string, ReviewDecision>,
  ) => {
    if (!keys.some(needsDecision)) {
      toastRejected(keys);
      return;
    }
    const { added, updated, replaced, keyIds } = await applyReview(
      keys,
      chosen,
      { contacts, add: onAddContact, remove: onRemoveContact },
    );
    // Stable ids so a re-run updates the toasts instead of stacking.
    if (added > 0)
      toast.success(tn("settings_import_contacts_added", added), {
        id: "contacts-added",
      });
    const saved = new Set(keyIds);
    const flagged = keys.filter(
      (k) => saved.has(k.keyId) && k.securityWarning?.includes("SHA-1"),
    ).length;
    if (flagged > 0)
      toast.warning(tn("settings_import_contacts_flagged", flagged), {
        id: "contacts-flagged",
      });
    if (updated + replaced > 0)
      toast.info(tn("settings_import_contacts_updated", updated + replaced), {
        id: "contacts-updated",
      });
  };

  /** A row with no entry takes its default, as `applyReview` reads it. */
  const isChosen = (
    chosen: ReadonlyMap<string, ReviewDecision>,
    key: IncomingKey,
  ) => (chosen.get(key.keyId) ?? defaultDecision(key)) !== "skip";

  const finishReview = async (
    chosen: ReadonlyMap<string, ReviewDecision>,
    close: () => void,
  ) => {
    if (!reviewKeys) return;
    setError(null);
    const chosenIds = new Set(
      reviewKeys.filter((k) => isChosen(chosen, k)).map((k) => k.keyId),
    );
    const privates = parsedPrivates.filter((p) =>
      chosenIds.has(p.keyInfo.keyId),
    );
    const crx = parsedCrx.filter((b) => chosenIds.has(b.extensionId));
    setDecisions(chosen);
    if (privates.length > 0) {
      setParsedPrivates(privates);
      setParsedCrx(crx);
      setStep(privates.some((p) => p.secretEncrypted) ? "unlock" : "protect");
      return;
    }
    await work.run(async () => {
      if (skippedPrivates > 0)
        toast.info(tn("settings_import_private_skipped", skippedPrivates), {
          id: "private-keys-skipped",
        });
      await importCrxBlobs(crx);
      await commitPublics(publicKeys, chosen);
      close();
    });
  };

  /** Never before the user has passed the whole flow. */
  const importCrxBlobs = async (blobs: CrxSigningKeyBlob[]) => {
    if (blobs.length === 0 || !onAddCrxKey) return;
    let added = 0;
    const failures: string[] = [];
    for (const blob of blobs) {
      try {
        await onAddCrxKey(blob);
        added++;
      } catch (e) {
        failures.push(
          t("settings_import_crx_failure_detail", {
            name: blob.label ?? blob.extensionId.slice(0, 8),
            error: errorMessage(e, t("settings_import_unknown_error")),
          }),
        );
      }
    }
    if (failures.length > 0)
      toast.error(tn("settings_import_crx_failed", failures.length), {
        id: "crx-restore-failed",
        description: failures[0],
      });
    if (added > 0)
      toast.success(tn("settings_import_crx_restored", added), {
        id: "crx-restored",
      });
  };

  const handlePasteNext = async (close: () => void) => {
    setError(null);
    const crxBlocks = onAddCrxKey ? parseCrxKeyBlocks(text) : [];
    const { publicKeys: publicBlocks, privateKeys } =
      splitArmoredKeyBlocks(text);
    if (
      publicBlocks.length === 0 &&
      privateKeys.length === 0 &&
      crxBlocks.length === 0
    ) {
      setError(t("settings_import_no_keys"));
      return;
    }

    // Vet CRX now, write at the end: reject a public key that doesn't hash
    // to its extension id (not AEAD-covered); never overwrite a held id.
    const existingCrx = new Set((crxKeys ?? []).map((k) => k.extensionId));
    const crxBlobs: CrxSigningKeyBlob[] = [];
    let skippedCrx = 0;
    let invalidCrx = 0;
    for (const blob of crxBlocks) {
      if (!(await crxBlobIdentityMatches(blob))) {
        invalidCrx++;
      } else if (existingCrx.has(blob.extensionId)) {
        skippedCrx++;
      } else {
        crxBlobs.push(blob);
      }
    }
    if (skippedCrx > 0)
      toast.info(tn("settings_import_crx_skipped", skippedCrx), {
        id: "crx-skipped",
      });
    if (invalidCrx > 0)
      toast.error(tn("settings_import_crx_rejected", invalidCrx), {
        id: "crx-rejected",
      });

    const existing = new Set(myKeys.map((k) => k.keyId));
    const privates: ParsedPrivate[] = [];
    let skipped = 0;
    let unparseable = 0;
    for (const block of privateKeys) {
      try {
        const result = await importKey(block);
        if (result.type !== "private") {
          unparseable++;
          continue;
        }
        if (existing.has(result.keyInfo.keyId)) {
          skipped++;
          continue;
        }
        privates.push({
          armored: block,
          keyInfo: result.keyInfo,
          secretEncrypted: result.secretEncrypted,
        });
      } catch {
        unparseable++;
      }
    }

    if (unparseable > 0) {
      setError(tn("settings_import_private_unparseable", unparseable));
    }

    const checked = withConflicts([
      ...privates.map(privateRow),
      ...crxBlobs.map(crxRow),
      ...(await classifyPublics(
        publicBlocks,
        new Set(privates.map((p) => p.keyInfo.keyId.toUpperCase())),
      )),
    ]);
    const publics = checked.filter((k) => isPublicKind(k.kind));
    const secretRows = checked.filter((k) => !isPublicKind(k.kind));
    setParsedPrivates(privates);
    setParsedCrx(crxBlobs);
    setSkippedPrivates(skipped);
    setPublicKeys(publics);

    if (secretRows.length === 0 && !publics.some(needsDecision)) {
      if (skipped > 0)
        toast.info(tn("settings_import_private_skipped", skipped), {
          id: "private-keys-skipped",
        });
      toastRejected(publics);
      if (unparseable === 0) close();
      return;
    }
    setReviewKeys([...secretRows, ...publics]);
    setStep("review");
  };

  const handleProtectSubmit = async (close: () => void) => {
    const invalid = choice.validate();
    if (invalid) {
      setError(invalid);
      return;
    }

    let prfOutput: Uint8Array | undefined;
    await work.run(async () => {
      try {
        await protectAll(close, (out) => (prfOutput = out));
      } finally {
        prfOutput?.fill(0);
      }
    });
  };

  const protectAll = async (
    close: () => void,
    holdPrf: (prfOutput: Uint8Array) => void,
  ) => {
    // One WebAuthn ceremony for the whole batch.
    let passkeyReuse:
      | { credentialId: string; prfOutput: Uint8Array; prfSalt: ArrayBuffer }
      | undefined;
    if (choice.method === "passkey") {
      let credentialId = choice.reusing ? reusePasskeyCredentialId : undefined;
      // Only a REUSED master credential may take the master salt; a
      // freshly registered passkey gets its own random one below.
      const sealSalt = credentialId ? masterSealSalt : undefined;
      if (!credentialId) {
        const reg = await registerPasskey(
          t("settings_import_passkey_name"),
          t("settings_import_passkey_name"),
        );
        if (!reg.prfEnabled) {
          throw new Error(t("settings_import_prf_unsupported"));
        }
        credentialId = reg.credentialId;
      }
      const prfSalt = sealSalt ?? generatePrfSalt();
      const { prfOutput } = await authenticateAndGetPrf(credentialId, prfSalt);
      holdPrf(prfOutput);
      passkeyReuse = { credentialId, prfOutput, prfSalt };
    }

    let imported = 0;
    for (const key of parsedPrivates) {
      try {
        const { blob } = await importAndProtect(
          key.armored,
          key.secretEncrypted ? sourcePassphrase : null,
          passkeyReuse
            ? {
                method: "passkey",
                reusePasskeyCredentialId: passkeyReuse.credentialId,
                prfReuse: {
                  prfOutput: passkeyReuse.prfOutput,
                  prfSalt: passkeyReuse.prfSalt,
                },
              }
            : { method: "password", password: choice.password },
          {
            userIdHint:
              key.keyInfo.userIds[0] ?? t("settings_import_default_user_id"),
          },
        );
        await onAddKey(blob);
        imported++;
      } catch (e) {
        // A wrong passphrase fails every key alike: stop at the first.
        if (imported > 0)
          toast.success(tn("settings_import_private_imported", imported), {
            id: "private-keys-imported",
          });
        const name = key.keyInfo.userIds[0] ?? key.keyInfo.keyId.slice(-8);
        setError(
          t("settings_import_failed_named", {
            name,
            error: errorMessage(e, t("settings_import_unknown_error")),
          }),
        );
        if (key.secretEncrypted) setStep("unlock");
        return;
      }
    }

    toast.success(tn("settings_import_private_imported", imported), {
      id: "private-keys-imported",
    });
    if (skippedPrivates > 0)
      toast.info(tn("settings_import_private_skipped", skippedPrivates), {
        id: "private-keys-skipped",
      });
    await importCrxBlobs(parsedCrx);
    await commitPublics(publicKeys, decisions);
    close();
  };

  const encryptedCount = parsedPrivates.filter((p) => p.secretEncrypted).length;

  // The protect step's buttons live in ProtectionMethodPicker.
  const actions: SubPageAction[] | undefined =
    step === "paste"
      ? [
          {
            text: t("settings_import_next"),
            busyText: t("settings_import_importing"),
            disabled: !text.trim(),
            onClick: (api) => handlePasteNext(api.close),
          },
          { type: "outline", text: t("common_cancel") },
        ]
      : step === "unlock"
        ? [
            {
              text: t("settings_import_next"),
              disabled: !sourcePassphrase,
              onClick: () => {
                setError(null);
                setStep("protect");
              },
            },
            {
              type: "outline",
              text: t("common_back"),
              onClick: () => {
                setStep("paste");
                setError(null);
                setSourcePassphrase("");
              },
            },
          ]
        : undefined;

  return (
    <SubPage
      title={t("settings_import_keys_title")}
      onClose={onClose}
      actions={actions}
    >
      {(api) => (
        <>
          {step === "paste" && (
            <div className="space-y-3">
              <p className="text-muted-foreground text-xs">
                {t("settings_import_paste_intro")}
              </p>
              <textarea
                placeholder={t("settings_import_paste_placeholder")}
                value={text}
                onChange={(e) => setText(e.target.value)}
                className="surface-field placeholder:text-muted-foreground focus:ring-ring w-full rounded-lg p-3 font-mono text-xs focus:ring-2 focus:outline-none"
                rows={6}
              />
              <input
                ref={fileInputRef}
                type="file"
                accept=".asc,.gpg,.pub,.key,.pgp,.txt"
                className="hidden"
                onChange={async (e) => {
                  const file = e.target.files?.[0];
                  if (file) setText(await file.text());
                  e.target.value = "";
                }}
              />
              <Button
                variant="outline"
                size="sm"
                onClick={() => fileInputRef.current?.click()}
              >
                {t("settings_import_browse")}
              </Button>

              {error && (
                <p className="text-bad text-xs" role="alert">
                  {error}
                </p>
              )}
            </div>
          )}

          {step === "unlock" && (
            <div className="space-y-3">
              <p className="text-muted-foreground text-xs">
                {tn("settings_import_unlock_intro", parsedPrivates.length, {
                  encrypted: encryptedCount,
                })}
              </p>
              <Input
                type="password"
                autoFocus
                autoComplete="current-password"
                value={sourcePassphrase}
                onChange={(e) => setSourcePassphrase(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") api.runAction(0);
                }}
                placeholder={t("settings_import_passphrase_placeholder")}
                className="p-2 font-mono text-xs"
              />
              {error && (
                <p className="text-bad text-xs" role="alert">
                  {error}
                </p>
              )}
            </div>
          )}

          {step === "review" && reviewKeys && (
            <ImportReview
              keys={reviewKeys}
              busy={importing}
              error={error}
              allowImportAll
              onImport={(decisions) => void finishReview(decisions, api.close)}
            />
          )}

          {step === "protect" && (
            <div className="space-y-3">
              <p className="text-muted-foreground text-xs">
                {tn("settings_import_protect_intro", parsedPrivates.length)}
              </p>
              <ProtectionMethodPicker
                {...choice.pickerProps}
                error={error}
                onSubmit={() => void handleProtectSubmit(api.close)}
                onBack={() => {
                  setStep(encryptedCount > 0 ? "unlock" : "paste");
                  setError(null);
                }}
                submitting={importing}
                submitLabel={tn(
                  "settings_import_submit",
                  parsedPrivates.length,
                )}
              />
            </div>
          )}
        </>
      )}
    </SubPage>
  );
}
