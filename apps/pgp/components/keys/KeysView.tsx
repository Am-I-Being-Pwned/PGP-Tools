import { useEffect, useMemo, useRef, useState } from "react";
import { ImportIcon, PlusIcon } from "lucide-react";

import { Block, BlockLabel } from "@amibeingpwned/ui/block";
import { Button } from "@amibeingpwned/ui/button";
import { Input } from "@amibeingpwned/ui/input";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { KeyCardModel } from "./KeyCard";
import type { KeyDetailsTarget } from "./KeyDetailsPage";
import { useContacts } from "../../hooks/useContacts";
import { useCopyToClipboard } from "../../hooks/useCopyToClipboard";
import { useCrxKeys } from "../../hooks/useCrxKeys";
import { useKeyring } from "../../hooks/useKeyring";
import { useNav } from "../../hooks/useNav";
import { usePreferences } from "../../hooks/usePreferences";
import { useVault } from "../../hooks/useVault";
import { publicKeyDerToPem } from "../../lib/crx/types";
import { AppError } from "../../lib/errors/app-error";
import { presentError } from "../../lib/errors/present";
import { t, tn } from "../../lib/i18n";
import { contactClash, contactClashes } from "../../lib/identity/binding";
import {
  KEYSERVER_HOST,
  keyserverFailureCopy,
} from "../../lib/import/keyserver";
import { reviewed } from "../../lib/import/review";
import {
  checkRevocation,
  fingerprintQuery,
} from "../../lib/import/revocation-check";
import {
  downloadPublicKey,
  downloadPublicKeysBundle,
} from "../../lib/keys/export-bundle";
import { crxKeyExporter, pgpKeyExporter } from "../../lib/keys/exporters";
import { revocationCertificateWithHandle } from "../../lib/pgp/wasm";
import { isPgpRecord, isSshRecord } from "../../lib/storage/key-kind";
import { toast } from "../../lib/toast";
import { formatAlgorithm, formatFingerprint } from "../../lib/utils/formatting";
import {
  displayUserId,
  parseUserId,
  realIdentity,
} from "../../lib/utils/key-naming";
import { ConfirmPage } from "../shared/ConfirmPage";
import { RenamePage } from "../shared/RenamePage";
import { useNavStack } from "../shared/useNavStack";
import { ContactCard } from "./ContactCard";
import { ContactDropZone } from "./ContactDropZone";
import { ExportKeysPage } from "./ExportKeysPage";
import { GenerateKeyPage } from "./GenerateKeyPage";
import { ImportKeyPage } from "./ImportKeyPage";
import { KeyCard } from "./KeyCard";
import { KeyDetailsPage } from "./KeyDetailsPage";
import { SelectionBar } from "./SelectionBar";

/** A key whose local display name is being edited. */
type RenameTarget =
  | { kind: "own"; keyBlob: ProtectedKeyBlob }
  | { kind: "crx"; keyBlob: CrxSigningKeyBlob }
  | { kind: "contact"; contact: PublicContactKey };

/** What the subject is REALLY called, under the rename field so an alias
 *  never hides it. An SSH key may have no comment: its fingerprint ends
 *  the chain. A CRX key has nothing but its extension id. */
function realIdentityOf(target: RenameTarget): string {
  if (target.kind === "crx") return target.keyBlob.extensionId;
  const record = target.kind === "own" ? target.keyBlob : target.contact;
  return realIdentity(record.userIds[0] ?? record.keyId);
}

/** A pending deletion, confirmed on its own slide-over page. */
type DeleteTarget =
  | { kind: "own"; keyBlob: ProtectedKeyBlob }
  | { kind: "contact"; contact: PublicContactKey }
  | { kind: "crx"; keyBlob: CrxSigningKeyBlob };

/** Slide-over subpages of the Keys tab, managed as a nav stack: push to
 *  drill in, pop to go back. New subpages are one union member away. */
type KeysRoute =
  | { page: "generate" }
  | { page: "import"; initialArmored?: string | null }
  | { page: "details"; target: KeyDetailsTarget }
  | { page: "confirm-delete"; target: DeleteTarget }
  | { page: "bulk-delete" }
  | { page: "bulk-export" }
  | { page: "rename"; target: RenameTarget };

/**
 * A keyring list drawn as one card: flat blocks with 2px of page between
 * them. Not `BlockStack`, which clips its children to round the outer
 * corners -- that would also clip the outward ring a just-imported row
 * pulses with. Instead the first and last rows pick up the 12px corners
 * themselves. Every child is a plain wrapper (the `data-select-id` one,
 * for cards) around exactly one block, hence the `>*>*` reach.
 */
const LIST_STACK =
  "flex flex-col gap-0.5 [&>*:first-child>*]:rounded-t-xl [&>*:last-child>*]:rounded-b-xl";

/** Composite selection id, namespaced so PGP keys, CRX keys, and contacts can
 *  coexist in one selection set. */
const selId = (kind: "pgp" | "crx" | "contact", id: string) => `${kind}:${id}`;

export function KeysView() {
  const keyring = useKeyring();
  const contactStore = useContacts();
  const crx = useCrxKeys();
  const { session, ...vault } = useVault();
  const appNav = useNav();
  const myKeys = keyring.keys;
  const contacts = contactStore.contacts;
  const isUnlocked = session.isUnlocked;
  const onUnlockWithPassword = session.unlockWithPassword;
  const onUnlockWithPasskey = session.unlockWithPasskey;
  const onLock = session.lock;
  const onDeleteKey = vault.deleteKey;
  const onAddKey = vault.addKey;
  const onAddContact = contactStore.add;
  const onSetContactVerified = contactStore.setVerified;
  const onMergeContactKey = contactStore.mergeKey;
  const onDeleteContact = contactStore.remove;
  const getKeyHandle = session.getKeyHandle;
  const onSaveRevocationCertificate = keyring.setRevocationCertificate;
  const highlightKeyIds = appNav.highlightKeyIds;
  const autoOpenRoute = appNav.keysRoute;
  const onEncryptTo = appNav.encryptTo;
  const primaryPasskeyCredentialId = vault.masterPasskeyCredentialId;
  const masterSealSalt = vault.masterSealSalt;
  const onKeyCached = vault.onKeyCached;
  const cacheKeys = vault.cacheKeys;
  const crxKeys = crx.keys;
  const onAddCrxKey = crx.add;
  const onDeleteCrxKey = crx.remove;
  const onSetDefaultKey = vault.setDefaultKey;
  const onRenameKey = keyring.rename;
  const onRenameCrxKey = crx.rename;
  const onRenameContact = contactStore.rename;
  const { advancedMode, crxSigningEnabled, keyDiscoveryEnabled, defaultKeyId } =
    usePreferences();
  const [selectionMode, setSelectionMode] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  // The rendered card list, used to resolve shift-click ranges in the order
  // the user actually sees.
  const listRef = useRef<HTMLDivElement>(null);
  const nav = useNavStack<KeysRoute>();

  // Fingerprints written by the most recent import: the matching cards
  // scroll into view and pulse once, so the panel sliding away hands the
  // eye straight to what changed. Cleared on a timer -- a permanent ring
  // would just become decoration.
  const [justImported, setJustImported] = useState<Set<string>>(new Set());
  const highlightTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(highlightTimer.current), []);

  const highlightImported = (keyIds: string[]) => {
    if (keyIds.length === 0) return;
    setJustImported(new Set(keyIds));
    clearTimeout(highlightTimer.current);
    // Comfortably longer than the 1.6s pulse plus the panel's slide-out,
    // so the animation isn't half-finished behind a closing panel.
    highlightTimer.current = setTimeout(() => setJustImported(new Set()), 2600);
  };

  useEffect(() => {
    if (!highlightKeyIds?.length) return;
    highlightImported(highlightKeyIds);
    appNav.consume("highlightKeyIds");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [highlightKeyIds]);

  const { copy } = useCopyToClipboard();
  const navPush = nav.push;
  const consumeIntent = appNav.consume;

  useEffect(() => {
    if (autoOpenRoute) {
      navPush({ page: autoOpenRoute });
      consumeIntent("keysRoute");
    }
  }, [autoOpenRoute, consumeIntent, navPush]);

  // Leaving nothing selected exits selection mode.
  useEffect(() => {
    if (selectionMode && selected.size === 0) setSelectionMode(false);
  }, [selectionMode, selected]);

  // CRX keys join the same list, gated on the feature being enabled.
  const shownCrxKeys = crxSigningEnabled ? crxKeys : [];

  // Where a shift-click measures its range FROM: the last card the user
  // touched without shift. Kept across renders (never rendered), and reset
  // whenever the selection is torn down, so a stale anchor can't sweep in a
  // range the user can no longer see.
  const anchorRef = useRef<string | null>(null);

  // Reading the order off the DOM rather than rebuilding it here is what
  // makes the range match what the user is looking at: the contacts list
  // owns its own search box, so the ids on screen are not `selectableIds`
  // whenever a filter is active. Scoped to this view's root -- a
  // document-wide query would also sweep up cards rendered by an open panel.
  const visibleIds = () =>
    Array.from(
      listRef.current?.querySelectorAll<HTMLElement>("[data-select-id]") ?? [],
    ).flatMap((el) => (el.dataset.selectId ? [el.dataset.selectId] : []));

  const toggleSelect = (id: string, extend = false) => {
    const anchor = anchorRef.current;
    if (extend && anchor && anchor !== id) {
      const ids = visibleIds();
      const from = ids.indexOf(anchor);
      const to = ids.indexOf(id);
      if (from !== -1 && to !== -1) {
        // The range REPLACES the selection, and the anchor stays put -- the
        // standard shift-click contract. Sweeping in additively would look
        // right while widening a range and then do nothing at all while
        // narrowing one, since every card the user wanted dropped is already
        // selected. Re-clicking nearer the anchor has to shrink the run.
        setSelected(
          new Set(ids.slice(Math.min(from, to), Math.max(from, to) + 1)),
        );
        return;
      }
    }
    anchorRef.current = id;
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const startSelect = (id: string) => {
    anchorRef.current = id;
    setSelectionMode(true);
    setSelected((s) => new Set(s).add(id));
  };
  const exitSelection = () => {
    anchorRef.current = null;
    setSelected(new Set());
    setSelectionMode(false);
  };

  // Resolve the current selection back to concrete blobs for bulk actions.
  const selectedMyKeys = myKeys.filter((k) =>
    selected.has(selId("pgp", k.keyId)),
  );
  const selectedCrxKeys = shownCrxKeys.filter((k) =>
    selected.has(selId("crx", k.extensionId)),
  );
  const selectedContacts = contacts.filter((c) =>
    selected.has(selId("contact", c.keyId)),
  );

  // Every selectable card's id (contacts only when the vault is unlocked, so
  // "select all" matches what's actually on screen).
  const selectableIds = [
    ...myKeys.map((k) => selId("pgp", k.keyId)),
    ...shownCrxKeys.map((k) => selId("crx", k.extensionId)),
    ...contacts.map((c) => selId("contact", c.keyId)),
  ];
  const allSelected =
    selectableIds.length > 0 && selectableIds.every((id) => selected.has(id));
  const toggleSelectAll = () => {
    if (allSelected) {
      exitSelection();
    } else {
      anchorRef.current = null;
      setSelectionMode(true);
      setSelected(new Set(selectableIds));
    }
  };

  // After a bulk action we deselect, but the toast offers "Reselect" to bring
  // the same set back (export is non-destructive, so every id is still valid).
  const afterExport = (count: number, unsafe: boolean) => {
    const prev = new Set(selected);
    exitSelection();
    toast.success(
      unsafe ? tn("keys_exported_unsafe", count) : tn("keys_exported", count),
      {
        id: "keys-exported",
        action: {
          label: t("keys_reselect"),
          onClick: () => {
            setSelected(prev);
            setSelectionMode(true);
          },
        },
      },
    );
  };

  // Export the selection. A contacts-only selection has no private key to
  // unlock, so skip the unlock/passphrase page and just download the public
  // keys; anything with a private key (PGP or CRX) opens the page.
  // An SSH identity has no private-key export at all (see the pgpModels
  // note): the export page's paths run through `getKeyArmored`, the
  // OpenPGP trapdoor, which has no SSH sibling by design. Selecting one
  // alongside PGP keys exports the PGP keys and says what was left out,
  // rather than silently handing an SSH handle to the PGP exporter.
  const exportableMyKeys = selectedMyKeys.filter(isPgpRecord);
  const skippedSshKeys = selectedMyKeys.length - exportableMyKeys.length;

  const bulkExport = () => {
    if (skippedSshKeys > 0) {
      toast.info(tn("keys_ssh_export_skipped", skippedSshKeys), {
        id: "ssh-export-skipped",
      });
    }
    if (exportableMyKeys.length === 0 && selectedCrxKeys.length === 0) {
      afterExport(downloadPublicKeysBundle(selectedContacts), false);
      return;
    }
    nav.push({ page: "bulk-export" });
  };

  const bulkDelete = async () => {
    for (const k of selectedMyKeys) await onDeleteKey(k.keyId);
    for (const k of selectedCrxKeys) await onDeleteCrxKey(k.extensionId);
    for (const c of selectedContacts) await onDeleteContact(c.keyId);
  };

  // One descriptor per key so PGP, SSH and CRX all render through
  // KeyCard. Split by `isPgpRecord` / `isSshRecord` (legacy keys carry no
  // `kind`), and not cosmetically: `pgpKeyExporter` is the OpenPGP
  // plaintext trapdoor, and an SSH identity must have no such export
  // (SECURITY.md) -- it leaves only as ciphertext this app produced.
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
        isUnlocked: isUnlocked(blob.keyId),
        unlockWithPassword: (pw) => onUnlockWithPassword(blob, pw),
        unlockWithPasskey: () => onUnlockWithPasskey(blob),
        lock: () => onLock(blob.keyId),
      },
      exporter: ssh ? null : pgpKeyExporter(blob, getKeyHandle),
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
        nav.push({
          page: "confirm-delete",
          target: { kind: "own", keyBlob: blob },
        }),
      onRename: () =>
        nav.push({ page: "rename", target: { kind: "own", keyBlob: blob } }),
      onShowDetails: () =>
        nav.push({ page: "details", target: { kind: "own", keyBlob: blob } }),
    };
  };

  /**
   * Ask keys.openpgp.org whether a contact's key has been revoked, and
   * keep what it says: the answer is merged into the stored cert the way
   * every import is, so a revocation sticks and nothing is rolled back.
   * One toast, updated in place from "checking" to the answer.
   */
  const checkContactRevocation = async (contact: PublicContactKey) => {
    const name =
      parseUserId(displayUserId(contact) ?? "").name ||
      contact.keyId.slice(-16);
    const id = `revocation-check-${contact.keyId}`;
    toast.message(
      t("keys_check_revocation_running", { host: KEYSERVER_HOST }),
      {
        id,
      },
    );
    try {
      // Merged into the contact as it is when the answer arrives, never
      // the copy captured on click: a revocation imported, a rename or a
      // delete during the fetch must survive it.
      const result = await checkRevocation(
        { keyId: contact.keyId, armored: contact.armoredPublicKey },
        onMergeContactKey,
      );
      switch (result.kind) {
        case "gone":
          toast.dismiss(id);
          break;
        case "needs-review":
          // New names or addresses on the key: never bound here, without
          // the Review that checks them against everyone else and asks.
          toast.info(t("keys_check_revocation_needs_review", { name }), {
            id,
          });
          nav.push({ page: "import", initialArmored: result.armored });
          break;
        case "revoked":
        case "current":
          if (result.kind === "revoked") {
            toast.error(t("keys_check_revocation_revoked", { name }), {
              id,
              duration: 10_000,
            });
          } else {
            toast.success(
              t("keys_check_revocation_current", {
                name,
                host: KEYSERVER_HOST,
              }),
              { id },
            );
          }
          break;
        case "not-published":
          toast.info(
            t("keys_check_revocation_not_published", {
              name,
              host: KEYSERVER_HOST,
            }),
            { id },
          );
          break;
        case "wrong-key":
          toast.error(
            t("import_keyserver_wrong_key", {
              host: KEYSERVER_HOST,
              subject: contact.keyId.replace(/(.{4})(?=.)/g, "$1 "),
            }),
            { id },
          );
          break;
        case "failed": {
          const query = fingerprintQuery(contact.keyId);
          toast.error(
            result.error === "unreachable" || !query
              ? t("import_worker_unreachable")
              : keyserverFailureCopy(result.error, query, result.retryAt)
                  .message,
            { id },
          );
          break;
        }
      }
    } catch (e) {
      toast.error(presentError(e, t("keys_check_revocation_failed")).message, {
        id,
      });
    }
  };

  const crxModels: KeyCardModel[] = shownCrxKeys.map((blob) => ({
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
      nav.push({
        page: "confirm-delete",
        target: { kind: "crx", keyBlob: blob },
      }),
    onRename: () =>
      nav.push({ page: "rename", target: { kind: "crx", keyBlob: blob } }),
    onShowDetails: undefined,
  }));

  // One list: a second heading would make the user know which engine
  // their own key belongs to before they could find it.
  const keyModels = [
    ...myKeys.filter(isPgpRecord).map(ownModel),
    ...myKeys.filter(isSshRecord).map(ownModel),
    ...crxModels,
  ];

  return (
    // Plain wrapper (no space-y) so mounting the sticky bar doesn't shift the
    // first spaced child down by a gap; the vertical rhythm lives on the inner
    // div, whose first child is always "My Keys".
    <div ref={listRef}>
      <SelectionBar
        open={selectionMode}
        count={selected.size}
        allSelected={allSelected}
        onToggleAll={toggleSelectAll}
        onExport={bulkExport}
        onDelete={() => nav.push({ page: "bulk-delete" })}
        onExit={exitSelection}
      />

      <div className="space-y-4">
        <div>
          {/* The label, with the two ways to add a key as small chips on
              the same line. */}
          <div className="mb-1.5 flex items-center gap-2">
            <BlockLabel as="h2" className="flex-1">
              {t("keys_my_keys_heading")}
            </BlockLabel>
            <Button
              variant="outline"
              size="sm"
              className="h-7 px-2.5 text-xs"
              onClick={() => nav.push({ page: "generate" })}
            >
              <PlusIcon className="h-3.5 w-3.5" />
              {t("keys_generate_button")}
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7 px-2.5 text-xs"
              onClick={() => nav.push({ page: "import" })}
            >
              <ImportIcon className="h-3.5 w-3.5" />
              {t("keys_import_button")}
            </Button>
          </div>
          {keyModels.length === 0 ? (
            <p className="text-muted-foreground px-1 text-sm">
              {t("keys_empty")}
            </p>
          ) : (
            <div className={LIST_STACK}>
              {keyModels.map((model) => {
                const id = selId(model.kind, model.id);
                return (
                  <div key={id} data-select-id={id}>
                    <KeyCard
                      model={model}
                      justImported={justImported.has(model.id)}
                      advancedMode={advancedMode}
                      selectionMode={selectionMode}
                      selected={selected.has(id)}
                      onToggleSelect={(extend) => toggleSelect(id, extend)}
                      onStartSelect={() => startSelect(id)}
                    />
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <ContactsList
          contacts={contacts}
          ownKeys={myKeys}
          justImported={justImported}
          onCheckRevocation={
            keyDiscoveryEnabled
              ? (contact) => void checkContactRevocation(contact)
              : undefined
          }
          onRequestRename={(contact) =>
            nav.push({
              page: "rename",
              target: { kind: "contact", contact },
            })
          }
          onImportText={(text) =>
            nav.push({ page: "import", initialArmored: text })
          }
          onRequestRemove={(contact) =>
            nav.push({
              page: "confirm-delete",
              target: { kind: "contact", contact },
            })
          }
          onEncryptTo={onEncryptTo}
          onShowDetails={(contact) =>
            nav.push({ page: "details", target: { kind: "contact", contact } })
          }
          advancedMode={advancedMode}
          selectionMode={selectionMode}
          selected={selected}
          onToggleSelect={toggleSelect}
          onStartSelect={startSelect}
        />

        {nav.stack.map((entry) => {
          const { route } = entry;
          if (route.page === "generate") {
            return (
              <GenerateKeyPage
                key={entry.id}
                onClose={() => nav.remove(entry.id)}
                onKeyGenerated={(keyId, keyHandle) => {
                  if (keyHandle !== undefined) {
                    onKeyCached(keyId, keyHandle);
                  }
                }}
                addKey={onAddKey}
                reusePasskeyCredentialId={primaryPasskeyCredentialId}
                masterSealSalt={masterSealSalt}
                cacheKey={cacheKeys}
                crxSigningEnabled={crxSigningEnabled}
                addCrxKey={onAddCrxKey}
              />
            );
          }
          if (route.page === "import") {
            return (
              <ImportKeyPage
                key={entry.id}
                onClose={() => nav.remove(entry.id)}
                onImportPrivate={onAddKey}
                onImportPublic={onAddContact}
                onRemoveContact={onDeleteContact}
                existingKeys={myKeys}
                existingContacts={contacts}
                reusePasskeyCredentialId={primaryPasskeyCredentialId}
                masterSealSalt={masterSealSalt}
                initialArmored={route.initialArmored}
                crxSigningEnabled={crxSigningEnabled}
                keyDiscoveryEnabled={keyDiscoveryEnabled}
                onImportCrx={onAddCrxKey}
                // Both an import and a "show it in your keys" land the
                // same way here: the user is already looking at the list.
                onImported={highlightImported}
              />
            );
          }
          if (route.page === "rename") {
            const target = route.target;
            // Clean display name from the first User ID ("Name <email>" ->
            // "Name"), so the field starts from the current name to tweak
            // rather than blank. CRX keys have no such identity; fall back
            // to their label only.
            const realIdentity = realIdentityOf(target);
            const currentName =
              target.kind === "crx"
                ? (target.keyBlob.label ?? "")
                : ((target.kind === "own"
                    ? target.keyBlob.alias
                    : target.contact.alias) ?? realIdentity);
            return (
              <RenamePage
                key={entry.id}
                title={
                  target.kind === "own"
                    ? t("keys_rename_key_title")
                    : target.kind === "crx"
                      ? t("keys_rename_crx_title")
                      : t("keys_rename_contact_title")
                }
                fieldLabel={t("keys_rename_field_label")}
                initialValue={currentName}
                hint={t("keys_rename_hint", { identity: realIdentity })}
                placeholder={
                  target.kind === "own"
                    ? t("keys_rename_placeholder_key")
                    : target.kind === "crx"
                      ? t("keys_rename_placeholder_crx")
                      : t("keys_rename_placeholder_contact")
                }
                onCancel={() => nav.remove(entry.id)}
                onSave={async (value) => {
                  if (target.kind === "own") {
                    await onRenameKey(target.keyBlob.keyId, value);
                  } else if (target.kind === "crx") {
                    await onRenameCrxKey(target.keyBlob.extensionId, value);
                  } else {
                    await onRenameContact(target.contact.keyId, value);
                  }
                  // Reveal the (refreshed) list beneath as this slides out.
                  nav.collapseToTop();
                }}
              />
            );
          }
          if (route.page === "details") {
            // A contact is read from the live list, not the snapshot the
            // route was pushed with: a revocation check run from this
            // page must show its answer here, not only after leaving it.
            const target =
              route.target.kind === "contact"
                ? {
                    ...route.target,
                    contact:
                      contacts.find(
                        (c) =>
                          route.target.kind === "contact" &&
                          c.keyId === route.target.contact.keyId,
                      ) ?? route.target.contact,
                  }
                : route.target;
            return (
              <KeyDetailsPage
                key={entry.id}
                target={target}
                onBack={() => nav.remove(entry.id)}
                clash={
                  target.kind === "contact"
                    ? contactClash(target.contact.keyId, contacts, myKeys)
                    : undefined
                }
                onShowHolder={(holder) => {
                  const contact = contacts.find(
                    (c) => c.keyId === holder.keyId,
                  );
                  const own = myKeys.find((k) => k.keyId === holder.keyId);
                  if (contact)
                    nav.push({
                      page: "details",
                      target: { kind: "contact", contact },
                    });
                  else if (own)
                    nav.push({
                      page: "details",
                      target: { kind: "own", keyBlob: own },
                    });
                }}
                onSetVerified={
                  target.kind === "contact" && !target.contact.revoked
                    ? (v) => onSetContactVerified(target.contact.keyId, v)
                    : undefined
                }
                onCheckRevocation={
                  keyDiscoveryEnabled &&
                  target.kind === "contact" &&
                  !isSshRecord(target.contact) &&
                  !target.contact.revoked
                    ? () => void checkContactRevocation(target.contact)
                    : undefined
                }
                onEncryptTo={
                  // Never for a revoked contact: the engine refuses it.
                  target.kind === "contact" && !target.contact.revoked
                    ? () => {
                        nav.clear();
                        onEncryptTo(target.contact.keyId);
                      }
                    : undefined
                }
                onRename={
                  // A contact reaches the SAME rename page as an own key:
                  // the details target union is the rename target union
                  // for these two members, so there is nothing to
                  // translate and no second page to keep in step.
                  () => nav.push({ page: "rename", target })
                }
                isDefault={
                  target.kind === "own" &&
                  defaultKeyId != null &&
                  target.keyBlob.keyId === defaultKeyId
                }
                // Only the user's own PGP keys can be the default --
                // never contacts (no private key) or CRX keys.
                onSetDefault={
                  target.kind === "own"
                    ? (next) =>
                        onSetDefaultKey(next ? target.keyBlob.keyId : null)
                    : undefined
                }
                onDelete={() => nav.push({ page: "confirm-delete", target })}
                onGenerateRevocation={
                  // Only offer generation when we can also persist the
                  // result -- minting a cert that silently vanishes on
                  // the next open would be a false assurance.
                  target.kind === "own"
                    ? async () => {
                        const handle = getKeyHandle(target.keyBlob.keyId);
                        if (handle === null) {
                          throw new AppError(
                            "key-locked",
                            t("keys_revocation_unlock_first"),
                          );
                        }
                        const armored =
                          await revocationCertificateWithHandle(handle);
                        await onSaveRevocationCertificate(
                          target.keyBlob.keyId,
                          armored,
                        );
                        return armored;
                      }
                    : undefined
                }
              />
            );
          }
          if (route.page === "bulk-delete") {
            // Deleting private key material (PGP or CRX) is unrecoverable,
            // so those bulk deletes are gated behind type-to-confirm;
            // contacts-only selections keep the plain confirm.
            const hasPrivate =
              selectedMyKeys.length > 0 || selectedCrxKeys.length > 0;
            return (
              <ConfirmPage
                key={entry.id}
                title={t("keys_bulk_delete_title")}
                confirmLabel={tn("keys_bulk_delete_confirm", selected.size)}
                confirmPromptText={
                  hasPrivate
                    ? tn("keys_bulk_delete_prompt", selected.size)
                    : undefined
                }
                onCancel={() => nav.remove(entry.id)}
                onConfirm={async () => {
                  // Contacts-only bulk deletes are reversible: keep the
                  // removed blobs in memory and offer Undo. Mixed
                  // selections with private keys stay irreversible (the
                  // type-to-confirm above is the safeguard there).
                  const removedContacts = hasPrivate ? [] : selectedContacts;
                  await bulkDelete();
                  nav.collapseToTop();
                  exitSelection();
                  if (removedContacts.length > 0) {
                    toast.success(
                      tn("keys_contacts_removed", removedContacts.length),
                      {
                        id: "contact-removed",
                        action: {
                          label: t("keys_undo"),
                          onClick: () =>
                            void (async () => {
                              for (const c of removedContacts) {
                                // Undoing the user's own delete: putting
                                // back what they had, not a new binding.
                                await onAddContact(reviewed(c));
                              }
                            })(),
                        },
                      },
                    );
                  }
                }}
              >
                <BulkDeleteSummary
                  privateKeys={selectedMyKeys.length}
                  signingKeys={selectedCrxKeys.length}
                  contacts={selectedContacts.length}
                />
              </ConfirmPage>
            );
          }
          if (route.page === "bulk-export") {
            return (
              <ExportKeysPage
                key={entry.id}
                onClose={() => nav.remove(entry.id)}
                myKeys={exportableMyKeys}
                contacts={selectedContacts}
                crxKeys={selectedCrxKeys}
                isUnlocked={isUnlocked}
                getKeyHandle={getKeyHandle}
                onUnlockWithPassword={onUnlockWithPassword}
                onUnlockWithPasskey={onUnlockWithPasskey}
                onExported={afterExport}
              />
            );
          }
          const target = route.target;
          return (
            <ConfirmPage
              key={entry.id}
              title={
                target.kind === "contact"
                  ? t("keys_confirm_remove_contact_title")
                  : t("keys_confirm_delete_key_title")
              }
              confirmLabel={
                target.kind === "contact"
                  ? t("keys_remove_contact")
                  : t("keys_delete_key_permanently")
              }
              // Both "own" (PGP) and "crx" targets hold private key
              // material, so they require typing the key's name; contact
              // removal (public key only) keeps the plain confirm.
              confirmPromptText={
                target.kind === "own"
                  ? parseUserId(target.keyBlob.userIds[0]).name
                  : target.kind === "crx"
                    ? (target.keyBlob.label ?? target.keyBlob.extensionId)
                    : undefined
              }
              onCancel={() => nav.remove(entry.id)}
              onConfirm={async () => {
                if (target.kind === "own") {
                  await onDeleteKey(target.keyBlob.keyId);
                } else if (target.kind === "contact") {
                  await onDeleteContact(target.contact.keyId);
                  // A contact is just a public key: deleting is cheap to
                  // reverse, so offer Undo. The blob only lives in this
                  // closure; once the toast expires it's gone for good.
                  const removed = target.contact;
                  toast.success(tn("keys_contacts_removed", 1), {
                    id: "contact-removed",
                    action: {
                      label: t("keys_undo"),
                      onClick: () => void onAddContact(reviewed(removed)),
                    },
                  });
                } else {
                  await onDeleteCrxKey(target.keyBlob.extensionId);
                }
                // Drop the pages underneath now, so this page's slide-out
                // reveals the key list rather than a stale details view of
                // the just-deleted key. The confirm page then slides out
                // and pops itself via onCancel.
                nav.collapseToTop();
              }}
            >
              <DeleteSummary target={target} />
            </ConfirmPage>
          );
        })}
      </div>
    </div>
  );
}

/** Short breakdown of a mixed bulk deletion, rendered inside ConfirmPage. */
function BulkDeleteSummary({
  privateKeys,
  signingKeys,
  contacts,
}: {
  privateKeys: number;
  signingKeys: number;
  contacts: number;
}) {
  const parts: string[] = [];
  if (privateKeys) parts.push(tn("keys_count_private_keys", privateKeys));
  if (signingKeys) parts.push(tn("keys_count_signing_keys", signingKeys));
  if (contacts) parts.push(tn("keys_count_contacts", contacts));
  const hasPrivate = privateKeys > 0 || signingKeys > 0;
  return (
    <>
      <p className="font-medium">{parts.join(", ")}</p>
      <p className="mt-2">
        {hasPrivate
          ? t("keys_bulk_delete_private_body")
          : t("keys_bulk_delete_contacts_body")}
      </p>
    </>
  );
}

/** What's being deleted + what it costs, rendered inside ConfirmPage. */
function DeleteSummary({ target }: { target: DeleteTarget }) {
  if (target.kind === "crx") {
    return (
      <>
        <p className="font-medium">
          {target.keyBlob.label ?? target.keyBlob.extensionId}
        </p>
        <p className="text-muted-foreground mt-0.5 font-mono text-[10px]">
          {target.keyBlob.extensionId}
        </p>
        <p className="mt-2">{t("keys_delete_crx_body")}</p>
      </>
    );
  }
  const isOwn = target.kind === "own";
  const keyId = isOwn ? target.keyBlob.keyId : target.contact.keyId;
  // The name the user knows this contact by, alias included -- removing
  // "Alice (all machines)" must not be confirmed against a `user@host`
  // comment they have never seen. Own keys keep their real identity: the
  // confirm prompt above asks the user to type it.
  const name = isOwn
    ? (target.keyBlob.userIds[0] ?? t("keys_unknown_name"))
    : (displayUserId(target.contact) ?? t("keys_unknown_name"));
  return (
    <>
      <p className="font-medium">{name}</p>
      <p className="text-muted-foreground mt-0.5 font-mono text-[10px]">
        {keyId.slice(-16)}
      </p>
      <p className="mt-2">
        {isOwn ? t("keys_delete_key_body") : t("keys_remove_contact_body")}
      </p>
    </>
  );
}

function ContactsList({
  contacts,
  ownKeys,
  onRequestRemove,
  onRequestRename,
  onCheckRevocation,
  onEncryptTo,
  onShowDetails,
  advancedMode,
  selectionMode,
  selected,
  onToggleSelect,
  onStartSelect,
  justImported,
  onImportText,
}: {
  contacts: PublicContactKey[];
  /** The user's own keys: a contact claiming their identity is marked. */
  ownKeys: ProtectedKeyBlob[];
  onRequestRemove: (contact: PublicContactKey) => void;
  /** Absent when the host cannot persist a rename, which hides the
   *  menu item rather than offering one that silently does nothing. */
  onRequestRename?: (contact: PublicContactKey) => void;
  /** Absent with key discovery off: the check asks keys.openpgp.org. */
  onCheckRevocation?: (contact: PublicContactKey) => void;
  onEncryptTo?: (keyId: string) => void;
  onShowDetails: (contact: PublicContactKey) => void;
  advancedMode?: boolean;
  selectionMode: boolean;
  selected: Set<string>;
  onToggleSelect: (id: string, extend: boolean) => void;
  onStartSelect: (id: string) => void;
  /** Fingerprints to scroll to and pulse after an import. */
  justImported: Set<string>;
  /** Hand dropped/pasted key text to the import panel, which previews a
   *  single key and bulk-imports a bundle. */
  onImportText: (text: string) => void;
}) {
  const [search, setSearch] = useState("");
  const { copy } = useCopyToClipboard();
  // SSH contacts too: an SSH key's comment is the contact's name, it is
  // whatever the `.pub` file said, and `alice@corp.com` as a comment
  // claims that address as plainly as a User ID does.
  const clashes = useMemo(
    () => contactClashes(contacts, ownKeys),
    [contacts, ownKeys],
  );

  const filtered = search
    ? contacts.filter((c) => {
        const q = search.toLowerCase();
        // Both names, not just the displayed one: after a rename the
        // real identity is still how the user might look for them.
        return (
          (displayUserId(c) ?? "").toLowerCase().includes(q) ||
          (c.userIds[0] ?? "").toLowerCase().includes(q) ||
          c.keyId.toLowerCase().includes(q)
        );
      })
    : contacts;

  return (
    <div>
      <BlockLabel as="h2" className="mb-1.5">
        {contacts.length > 0
          ? t("keys_contacts_heading_count", { count: contacts.length })
          : t("keys_contacts_heading")}
      </BlockLabel>
      <>
        {/* One card for the whole job: the drop row, the search (once
              the list is long enough to need one), then the contacts. */}
        <div className={LIST_STACK}>
          <div>
            <ContactDropZone onKeyText={onImportText} />
          </div>
          {contacts.length > 5 && (
            <div>
              <Block className="p-2">
                <Input
                  type="text"
                  placeholder={t("keys_search_contacts_placeholder")}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </Block>
            </div>
          )}
          {filtered.map((c) => {
            const id = selId("contact", c.keyId);
            return (
              <div key={c.keyId} data-select-id={id}>
                <ContactCard
                  contact={c}
                  clash={clashes.get(c.keyId)}
                  justImported={justImported.has(c.keyId)}
                  onRemove={() => onRequestRemove(c)}
                  onEncryptTo={
                    onEncryptTo && !c.revoked
                      ? () => onEncryptTo(c.keyId)
                      : undefined
                  }
                  onCopyPublicKey={() =>
                    void copy(c.armoredPublicKey, {
                      label: t("common_public_key"),
                    })
                  }
                  onDownloadPublicKey={() =>
                    downloadPublicKey(
                      c.armoredPublicKey,
                      parseUserId(displayUserId(c) ?? "").name || c.keyId,
                    )
                  }
                  onRename={
                    onRequestRename ? () => onRequestRename(c) : undefined
                  }
                  onCheckRevocation={
                    // An SSH key has nothing on the keyserver, and a
                    // revoked one has nothing left to learn.
                    onCheckRevocation && !isSshRecord(c) && !c.revoked
                      ? () => onCheckRevocation(c)
                      : undefined
                  }
                  onShowDetails={() => onShowDetails(c)}
                  advancedMode={advancedMode}
                  selectionMode={selectionMode}
                  selected={selected.has(id)}
                  onToggleSelect={(extend) => onToggleSelect(id, extend)}
                  onStartSelect={() => onStartSelect(id)}
                />
              </div>
            );
          })}
        </div>
        {search && filtered.length === 0 && (
          <p className="text-muted-foreground mt-2 text-center text-xs">
            {t("keys_no_contacts_match", { query: search })}
          </p>
        )}
      </>
    </div>
  );
}
