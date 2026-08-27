import { useEffect, useRef, useState } from "react";
import { ImportIcon, PlusIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { KeyCardModel } from "./KeyCard";
import type { KeyDetailsTarget } from "./KeyDetailsPage";
import { useCopyToClipboard } from "../../hooks/useCopyToClipboard";
import { publicKeyDerToPem } from "../../lib/crx/types";
import {
  downloadPublicKey,
  downloadPublicKeysBundle,
} from "../../lib/keys/export-bundle";
import { crxKeyExporter, pgpKeyExporter } from "../../lib/keys/exporters";
import { revocationCertificateWithHandle } from "../../lib/pgp/wasm";
import { isPgpRecord, isSshRecord } from "../../lib/storage/key-kind";
import { toast } from "../../lib/toast";
import { formatAlgorithm, formatFingerprint } from "../../lib/utils/formatting";
import { displayUserId, parseUserId } from "../../lib/utils/key-naming";
import { INPUT_CLASS } from "../../lib/utils/styles";
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

interface KeysViewProps {
  myKeys: ProtectedKeyBlob[];
  contacts: PublicContactKey[];
  contactsLocked: boolean;
  isUnlocked: (keyId: string) => boolean;
  onUnlockWithPassword: (
    blob: ProtectedKeyBlob,
    password: string,
  ) => Promise<boolean>;
  onUnlockWithPasskey: (
    blob: ProtectedKeyBlob,
  ) => Promise<boolean | "cancelled">;
  onLock: (keyId: string) => void;
  onDeleteKey: (keyId: string) => Promise<void>;
  onAddKey: (blob: ProtectedKeyBlob) => Promise<void>;
  onAddContact: (contact: PublicContactKey) => Promise<void>;
  onDeleteContact: (keyId: string) => Promise<void>;
  getKeyHandle: (keyId: string) => number | null;
  /** Persist a revocation certificate minted for an imported key. */
  onSaveRevocationCertificate?: (
    keyId: string,
    armored: string,
  ) => Promise<void>;
  advancedMode?: boolean;
  /** Scroll to and pulse these keys: an import that happened elsewhere
   *  (the app-level import panel), or a "show it in your keys" action. */
  highlightKeyIds?: string[] | null;
  onHighlightConsumed?: () => void;
  /** A subpage requested from outside (command palette). */
  autoOpenRoute?: "generate" | "import" | null;
  onAutoOpenRouteConsumed?: () => void;
  onEncryptTo?: (keyId: string) => void;
  primaryPasskeyCredentialId?: string;
  /** Called when a newly generated key is cached in WASM. */
  onKeyCached?: (keyId: string, keyHandle: number) => void;
  /** Whether to cache decrypted keys in WASM after generation. */
  cacheKeys?: boolean;
  /** When true, expose CRX (Chrome extension) signing keys. */
  crxSigningEnabled?: boolean;
  /** Master enable for the import step's network lookups (GitHub SSH
   *  keys, keys.openpgp.org certificates). */
  keyDiscoveryEnabled?: boolean;
  crxKeys?: CrxSigningKeyBlob[];
  onAddCrxKey?: (blob: CrxSigningKeyBlob) => Promise<void>;
  onDeleteCrxKey?: (extensionId: string) => Promise<void>;
  /** The user's configured default key, when set (own PGP keys only). */
  defaultKeyId?: string | null;
  /** Persist (keyId) or clear (null) the default-key choice. */
  onSetDefaultKey?: (keyId: string | null) => void;
  /** Set a local display alias on a PGP key. */
  onRenameKey?: (keyId: string, alias: string) => Promise<void>;
  /** Set the user-facing label on a CRX signing key. */
  onRenameCrxKey?: (extensionId: string, label: string) => Promise<void>;
  /** Set a local display alias on a contact. Without it a contact is
   *  stuck with whatever `userIds[0]` it was imported with -- which for
   *  an SSH key is the key's comment, and may be `user@laptop`, may
   *  differ between one person's keys, or may not exist at all. */
  onRenameContact?: (keyId: string, alias: string) => Promise<void>;
}

/** A key whose local display name is being edited. */
type RenameTarget =
  | { kind: "own"; keyBlob: ProtectedKeyBlob }
  | { kind: "crx"; keyBlob: CrxSigningKeyBlob }
  | { kind: "contact"; contact: PublicContactKey };

/**
 * What the subject is REALLY called, shown under the rename field so a
 * local name never hides the identity it stands in for.
 *
 * One function for all three targets because the fallback chain is the
 * thing that must not drift: an SSH key (own or contact) has no User IDs
 * at all, only a comment, and may not even have that -- hence the
 * fingerprint at the end of the chain. A CRX signing key has no identity
 * beyond its extension ID.
 */
function realIdentityOf(target: RenameTarget): string {
  if (target.kind === "crx") return target.keyBlob.extensionId;
  const record = target.kind === "own" ? target.keyBlob : target.contact;
  const { name, comment } = parseUserId(record.userIds[0] ?? record.keyId);
  return comment ? `${name} (${comment})` : name;
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

/** Composite selection id, namespaced so PGP keys, CRX keys, and contacts can
 *  coexist in one selection set. */
const selId = (kind: "pgp" | "crx" | "contact", id: string) => `${kind}:${id}`;

export function KeysView({
  myKeys,
  contacts,
  contactsLocked,
  isUnlocked,
  onUnlockWithPassword,
  onUnlockWithPasskey,
  onLock,
  onDeleteKey,
  onAddKey,
  onAddContact,
  onDeleteContact,
  getKeyHandle,
  onSaveRevocationCertificate,
  advancedMode,
  highlightKeyIds,
  onHighlightConsumed,
  autoOpenRoute,
  onAutoOpenRouteConsumed,
  onEncryptTo,
  primaryPasskeyCredentialId,
  onKeyCached,
  cacheKeys,
  crxSigningEnabled,
  keyDiscoveryEnabled,
  crxKeys,
  onAddCrxKey,
  onDeleteCrxKey,
  defaultKeyId,
  onSetDefaultKey,
  onRenameKey,
  onRenameCrxKey,
  onRenameContact,
}: KeysViewProps) {
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
    onHighlightConsumed?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [highlightKeyIds]);

  const { copy } = useCopyToClipboard();
  const navPush = nav.push;

  useEffect(() => {
    if (autoOpenRoute) {
      navPush({ page: autoOpenRoute });
      onAutoOpenRouteConsumed?.();
    }
  }, [autoOpenRoute, onAutoOpenRouteConsumed, navPush]);

  // Leaving nothing selected exits selection mode.
  useEffect(() => {
    if (selectionMode && selected.size === 0) setSelectionMode(false);
  }, [selectionMode, selected]);

  // CRX keys join the same list, gated on the feature being enabled.
  const shownCrxKeys = crxSigningEnabled && crxKeys ? crxKeys : [];

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
    ...(contactsLocked ? [] : contacts.map((c) => selId("contact", c.keyId))),
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
      `Exported ${count} key${count === 1 ? "" : "s"}${
        unsafe ? " (private keys UNENCRYPTED)" : ""
      }`,
      {
        id: "keys-exported",
        action: {
          label: "Reselect",
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
      toast.info(
        `${skippedSshKeys} SSH key${skippedSshKeys === 1 ? "" : "s"} can't be exported - an imported SSH key never leaves this device.`,
        { id: "ssh-export-skipped" },
      );
    }
    if (exportableMyKeys.length === 0 && selectedCrxKeys.length === 0) {
      afterExport(downloadPublicKeysBundle(selectedContacts), false);
      return;
    }
    nav.push({ page: "bulk-export" });
  };

  const bulkDelete = async () => {
    for (const k of selectedMyKeys) await onDeleteKey(k.keyId);
    for (const k of selectedCrxKeys) await onDeleteCrxKey?.(k.extensionId);
    for (const c of selectedContacts) await onDeleteContact(c.keyId);
  };

  // Build one unified descriptor per key so PGP + SSH + CRX render
  // through KeyCard.
  //
  // The keyring holds both engines, so it is split by `isPgpRecord` /
  // `isSshRecord` (never by reading `blob.kind`, which is absent on every
  // key stored before the age engine existed). The split is not cosmetic:
  // `pgpKeyExporter` is backed by `getKeyArmored`, the OpenPGP plaintext
  // export trapdoor, and SECURITY.md says an imported SSH identity must
  // have no such thing -- it can leave this app only as ciphertext it
  // produced. Attaching the PGP exporter to every own key would have
  // offered "Copy private key" on an SSH key and failed somewhere deep in
  // wasm, or worse, not failed.
  const pgpModels: KeyCardModel[] = myKeys.filter(isPgpRecord).map((blob) => {
    const realName = blob.userIds[0] ?? "Unknown";
    return {
      kind: "pgp",
      id: blob.keyId,
      displayName: blob.alias ?? realName,
      realName,
      shortId: blob.keyId.slice(-16),
      algorithm: formatAlgorithm(blob.algorithm),
      fingerprint: formatFingerprint(blob.keyId),
      isDefault: defaultKeyId != null && blob.keyId === defaultKeyId,
      protectionMethod: blob.protection.method,
      securityWarning: blob.securityWarning,
      session: {
        isUnlocked: isUnlocked(blob.keyId),
        unlockWithPassword: (pw) => onUnlockWithPassword(blob, pw),
        unlockWithPasskey: () => onUnlockWithPasskey(blob),
        lock: () => onLock(blob.keyId),
      },
      exporter: pgpKeyExporter(blob, getKeyHandle),
      // No label: KeyCard shows its own inline "Public key copied"
      // feedback; the hook still surfaces a rejected write.
      onCopyPublicKey: () => void copy(blob.publicKeyArmored),
      onDownloadPublicKey: () =>
        downloadPublicKey(blob.publicKeyArmored, blob.alias ?? realName),
      onDelete: () =>
        nav.push({
          page: "confirm-delete",
          target: { kind: "own", keyBlob: blob },
        }),
      onRename: onRenameKey
        ? () =>
            nav.push({ page: "rename", target: { kind: "own", keyBlob: blob } })
        : undefined,
      onShowDetails: () =>
        nav.push({ page: "details", target: { kind: "own", keyBlob: blob } }),
    };
  });

  const sshModels: KeyCardModel[] = myKeys.filter(isSshRecord).map((blob) => {
    // An SSH key's name is the comment `ssh-keygen` wrote (`user@host`),
    // or nothing at all -- there are no User IDs to fall back through.
    const realName = blob.userIds[0] ?? blob.keyId;
    return {
      // The card's id namespace names the STORE it came from, and an SSH
      // identity lives in the same keyring as the PGP certs.
      kind: "pgp",
      id: blob.keyId,
      displayName: blob.alias ?? realName,
      realName,
      // The WHOLE `SHA256:...` fingerprint, not a tail slice: an OpenSSH
      // fingerprint is a base64 hash, and its last 16 characters are not
      // an identifier anyone recognises or can look up (unlike a PGP long
      // key id, which is a real short form).
      shortId: blob.keyId,
      algorithm: formatAlgorithm(blob.algorithm),
      // No `fingerprint` line in advanced mode: that row regroups a hex
      // fingerprint into 4-character blocks, which would chop a base64
      // hash into meaningless quarters. `shortId` above already shows it
      // in full, in the only form it has.
      badge: "SSH",
      protectionMethod: blob.protection.method,
      securityWarning: blob.securityWarning,
      // SSH keys really do unlock into a handle store (SSH_KEY_STORE),
      // so the lock/unlock lifecycle is genuine here -- unlike CRX keys,
      // which are sealed at rest and have no session.
      session: {
        isUnlocked: isUnlocked(blob.keyId),
        unlockWithPassword: (pw) => onUnlockWithPassword(blob, pw),
        unlockWithPasskey: () => onUnlockWithPasskey(blob),
        lock: () => onLock(blob.keyId),
      },
      // No private-key export for an SSH identity -- see the note above
      // pgpModels.
      exporter: null,
      // The "public key" of an SSH identity is its recipient line; `.pub`
      // is the extension every other tool expects it under.
      onCopyPublicKey: () => void copy(blob.publicKeyArmored),
      onDownloadPublicKey: () =>
        downloadPublicKey(blob.publicKeyArmored, blob.alias ?? realName, "pub"),
      onDelete: () =>
        nav.push({
          page: "confirm-delete",
          target: { kind: "own", keyBlob: blob },
        }),
      onRename: onRenameKey
        ? () =>
            nav.push({ page: "rename", target: { kind: "own", keyBlob: blob } })
        : undefined,
      onShowDetails: () =>
        nav.push({ page: "details", target: { kind: "own", keyBlob: blob } }),
    };
  });

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
    onRename: onRenameCrxKey
      ? () =>
          nav.push({ page: "rename", target: { kind: "crx", keyBlob: blob } })
      : undefined,
    onShowDetails: undefined,
  }));

  // One list, in one place: an SSH key is one of the user's keys, and a
  // second heading would ask the user to know which engine they need
  // before they can find their own key.
  const keyModels = [...pgpModels, ...sshModels, ...crxModels];

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
          <h2 className="mb-2 text-sm font-semibold">My Keys</h2>
          {keyModels.length === 0 ? (
            <p className="text-muted-foreground text-sm">
              No keys yet. Generate or import a key to get started.
            </p>
          ) : (
            <div className="space-y-2">
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

        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            className="bg-border/90 hover:bg-border flex-1"
            onClick={() => nav.push({ page: "generate" })}
          >
            <PlusIcon className="h-4 w-4" />
            Generate Key
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="bg-border/90 hover:bg-border flex-1"
            onClick={() => nav.push({ page: "import" })}
          >
            <ImportIcon className="h-4 w-4" />
            Import Key
          </Button>
        </div>

        <ContactsList
          contacts={contacts}
          contactsLocked={contactsLocked}
          justImported={justImported}
          onRequestRename={
            onRenameContact
              ? (contact) =>
                  nav.push({
                    page: "rename",
                    target: { kind: "contact", contact },
                  })
              : undefined
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
                onClose={nav.pop}
                onKeyGenerated={(keyId, keyHandle) => {
                  if (keyHandle !== undefined && onKeyCached) {
                    onKeyCached(keyId, keyHandle);
                  }
                }}
                addKey={onAddKey}
                reusePasskeyCredentialId={primaryPasskeyCredentialId}
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
                onClose={nav.pop}
                onImportPrivate={onAddKey}
                onImportPublic={onAddContact}
                existingKeys={myKeys}
                existingContacts={contacts}
                reusePasskeyCredentialId={primaryPasskeyCredentialId}
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
                    ? "Rename key"
                    : target.kind === "crx"
                      ? "Rename signing key"
                      : "Rename contact"
                }
                fieldLabel="Display name"
                initialValue={currentName}
                hint={`Shown in place of ${realIdentity}. This is a local label only.`}
                placeholder={
                  target.kind === "own"
                    ? "e.g. Work laptop"
                    : target.kind === "crx"
                      ? "e.g. My Extension"
                      : "e.g. Alice (all machines)"
                }
                onCancel={nav.pop}
                onSave={async (value) => {
                  if (target.kind === "own") {
                    await onRenameKey?.(target.keyBlob.keyId, value);
                  } else if (target.kind === "crx") {
                    await onRenameCrxKey?.(target.keyBlob.extensionId, value);
                  } else {
                    await onRenameContact?.(target.contact.keyId, value);
                  }
                  // Reveal the (refreshed) list beneath as this slides out.
                  nav.collapseToTop();
                }}
              />
            );
          }
          if (route.page === "details") {
            const target = route.target;
            return (
              <KeyDetailsPage
                key={entry.id}
                target={target}
                onBack={nav.pop}
                onEncryptTo={
                  target.kind === "contact" && onEncryptTo
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
                  (target.kind === "own" && onRenameKey) ||
                  (target.kind === "contact" && onRenameContact)
                    ? () => nav.push({ page: "rename", target })
                    : undefined
                }
                isDefault={
                  target.kind === "own" &&
                  defaultKeyId != null &&
                  target.keyBlob.keyId === defaultKeyId
                }
                // Only the user's own PGP keys can be the default --
                // never contacts (no private key) or CRX keys.
                onSetDefault={
                  target.kind === "own" && onSetDefaultKey
                    ? (next) =>
                        onSetDefaultKey(next ? target.keyBlob.keyId : null)
                    : undefined
                }
                onDelete={() => nav.push({ page: "confirm-delete", target })}
                onGenerateRevocation={
                  // Only offer generation when we can also persist the
                  // result -- minting a cert that silently vanishes on
                  // the next open would be a false assurance.
                  target.kind === "own" && onSaveRevocationCertificate
                    ? async () => {
                        const handle = getKeyHandle(target.keyBlob.keyId);
                        if (handle === null) {
                          throw new Error(
                            "Unlock this key first, then try again.",
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
                title="Delete selected?"
                confirmLabel={`Delete ${selected.size} item${selected.size === 1 ? "" : "s"} permanently`}
                confirmPromptText={
                  hasPrivate
                    ? `delete ${selected.size} key${selected.size === 1 ? "" : "s"}`
                    : undefined
                }
                onCancel={nav.pop}
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
                      removedContacts.length === 1
                        ? "Contact removed"
                        : `${removedContacts.length} contacts removed`,
                      {
                        id: "contact-removed",
                        action: {
                          label: "Undo",
                          onClick: () =>
                            void (async () => {
                              for (const c of removedContacts) {
                                await onAddContact(c);
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
                onClose={nav.pop}
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
                target.kind === "contact" ? "Remove contact?" : "Delete key?"
              }
              confirmLabel={
                target.kind === "contact"
                  ? "Remove contact"
                  : "Delete key permanently"
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
              onCancel={nav.pop}
              onConfirm={async () => {
                if (target.kind === "own") {
                  await onDeleteKey(target.keyBlob.keyId);
                } else if (target.kind === "contact") {
                  await onDeleteContact(target.contact.keyId);
                  // A contact is just a public key: deleting is cheap to
                  // reverse, so offer Undo. The blob only lives in this
                  // closure; once the toast expires it's gone for good.
                  const removed = target.contact;
                  toast.success("Contact removed", {
                    id: "contact-removed",
                    action: {
                      label: "Undo",
                      onClick: () => void onAddContact(removed),
                    },
                  });
                } else {
                  await onDeleteCrxKey?.(target.keyBlob.extensionId);
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
  if (privateKeys)
    parts.push(`${privateKeys} private key${privateKeys === 1 ? "" : "s"}`);
  if (signingKeys)
    parts.push(`${signingKeys} signing key${signingKeys === 1 ? "" : "s"}`);
  if (contacts) parts.push(`${contacts} contact${contacts === 1 ? "" : "s"}`);
  const hasPrivate = privateKeys > 0 || signingKeys > 0;
  return (
    <>
      <p className="font-medium">{parts.join(", ")}</p>
      <p className="mt-2">
        {hasPrivate
          ? "This permanently deletes the selected private keys from this device. Anything encrypted only to a deleted key becomes unrecoverable. Make sure you have a backup if you might ever need them."
          : "You'll no longer be able to encrypt to these contacts or verify their signatures. You can re-import their public keys later."}
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
        <p className="mt-2">
          You can no longer sign updates for this extension, and the key can't
          be recovered unless you have a backup.
        </p>
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
    ? (target.keyBlob.userIds[0] ?? "Unknown")
    : (displayUserId(target.contact) ?? "Unknown");
  return (
    <>
      <p className="font-medium">{name}</p>
      <p className="text-muted-foreground mt-0.5 font-mono text-[10px]">
        {keyId.slice(-16)}
      </p>
      <p className="mt-2">
        {isOwn
          ? "This permanently deletes the private key from this device. Anything encrypted only to this key becomes unrecoverable. Make sure you have a backup if you might ever need it."
          : "You'll no longer be able to encrypt messages to this contact or verify their signatures. You can re-import their public key later."}
      </p>
    </>
  );
}

function ContactsList({
  contacts,
  contactsLocked,
  onRequestRemove,
  onRequestRename,
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
  contactsLocked: boolean;
  onRequestRemove: (contact: PublicContactKey) => void;
  /** Absent when the host cannot persist a rename, which hides the
   *  menu item rather than offering one that silently does nothing. */
  onRequestRename?: (contact: PublicContactKey) => void;
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
      <h2 className="mb-2 text-sm font-semibold">
        Contacts
        {contactsLocked
          ? " (encrypted)"
          : contacts.length > 0
            ? ` (${contacts.length})`
            : ""}
      </h2>
      {contactsLocked ? (
        <div className="border-border bg-muted/30 rounded-lg border p-4 text-center">
          <p className="text-muted-foreground text-sm">
            Contacts are encrypted. Unlock PGP Tools to view and manage them.
          </p>
        </div>
      ) : (
        <>
          <ContactDropZone onKeyText={onImportText} />
          {contacts.length > 5 && (
            <input
              type="text"
              placeholder="Search contacts..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className={`${INPUT_CLASS} mt-2`}
            />
          )}
          {filtered.length > 0 && (
            <div className="mt-2 space-y-2">
              {filtered.map((c) => {
                const id = selId("contact", c.keyId);
                return (
                  <div key={c.keyId} data-select-id={id}>
                    <ContactCard
                      contact={c}
                      justImported={justImported.has(c.keyId)}
                      onRemove={() => onRequestRemove(c)}
                      onEncryptTo={
                        onEncryptTo ? () => onEncryptTo(c.keyId) : undefined
                      }
                      onCopyPublicKey={() =>
                        void copy(c.armoredPublicKey, { label: "Public key" })
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
          )}
          {search && filtered.length === 0 && (
            <p className="text-muted-foreground mt-2 text-center text-xs">
              No contacts match "{search}"
            </p>
          )}
        </>
      )}
    </div>
  );
}
