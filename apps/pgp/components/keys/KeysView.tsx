import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@amibeingpwned/ui/button";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { KeyDetailsTarget } from "./KeyDetailsPage";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { ConfirmPage } from "../shared/ConfirmPage";
import { ContactCard } from "./ContactCard";
import { ContactDropZone } from "./ContactDropZone";
import { CrxKeyCard } from "./CrxKeyCard";
import { GenerateKeyDialog } from "./GenerateKeyDialog";
import { ImportKeyDialog } from "./ImportKeyDialog";
import { KeyCard } from "./KeyCard";
import { KeyDetailsPage } from "./KeyDetailsPage";

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
  advancedMode?: boolean;
  /** When non-null, opens the Import dialog with this armored text prefilled. */
  autoOpenImport?: string | null;
  onAutoOpenImportConsumed?: () => void;
  onEncryptTo?: (keyId: string) => void;
  primaryPasskeyCredentialId?: string;
  /** Called when a newly generated key is cached in WASM. */
  onKeyCached?: (keyId: string, keyHandle: number) => void;
  /** Whether to cache decrypted keys in WASM after generation. */
  cacheKeys?: boolean;
  /** When true, expose CRX (Chrome extension) signing keys. */
  crxSigningEnabled?: boolean;
  crxKeys?: CrxSigningKeyBlob[];
  onAddCrxKey?: (blob: CrxSigningKeyBlob) => Promise<void>;
  onDeleteCrxKey?: (extensionId: string) => Promise<void>;
}

/** A pending deletion, confirmed on its own slide-over page. */
type DeleteTarget =
  | { kind: "own"; keyBlob: ProtectedKeyBlob }
  | { kind: "contact"; contact: PublicContactKey }
  | { kind: "crx"; keyBlob: CrxSigningKeyBlob };

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
  advancedMode,
  autoOpenImport,
  onAutoOpenImportConsumed,
  onEncryptTo,
  primaryPasskeyCredentialId,
  onKeyCached,
  cacheKeys,
  crxSigningEnabled,
  crxKeys,
  onAddCrxKey,
  onDeleteCrxKey,
}: KeysViewProps) {
  const [showGenerate, setShowGenerate] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [importInitialArmored, setImportInitialArmored] = useState<
    string | null
  >(null);
  const [detailsTarget, setDetailsTarget] = useState<KeyDetailsTarget | null>(
    null,
  );
  const [deleteTarget, setDeleteTarget] = useState<DeleteTarget | null>(null);

  useEffect(() => {
    if (autoOpenImport) {
      setImportInitialArmored(autoOpenImport);
      setShowImport(true);
      onAutoOpenImportConsumed?.();
    }
  }, [autoOpenImport, onAutoOpenImportConsumed]);

  const handleExportPublic = async (blob: ProtectedKeyBlob) => {
    await navigator.clipboard.writeText(blob.publicKeyArmored);
  };

  // CRX keys join the same list, gated on the feature being enabled.
  const shownCrxKeys = crxSigningEnabled && crxKeys ? crxKeys : [];

  return (
    <div className="space-y-4">
      <div>
        <h2 className="mb-2 text-sm font-semibold">My Keys</h2>
        {myKeys.length === 0 && shownCrxKeys.length === 0 ? (
          <p className="text-muted-foreground text-sm">
            No keys yet. Generate or import a key to get started.
          </p>
        ) : (
          <div className="space-y-2">
            {myKeys.map((blob) => (
              <KeyCard
                key={blob.keyId}
                keyBlob={blob}
                isUnlocked={isUnlocked(blob.keyId)}
                onUnlockWithPassword={(pw) => onUnlockWithPassword(blob, pw)}
                onUnlockWithPasskey={() => onUnlockWithPasskey(blob)}
                onLock={() => onLock(blob.keyId)}
                onDelete={() => setDeleteTarget({ kind: "own", keyBlob: blob })}
                onExportPublic={() => handleExportPublic(blob)}
                onExportPrivate={() => getKeyHandle(blob.keyId)}
                onShowDetails={() =>
                  setDetailsTarget({ kind: "own", keyBlob: blob })
                }
                advancedMode={advancedMode}
              />
            ))}
            {shownCrxKeys.map((blob) => (
              <CrxKeyCard
                key={blob.extensionId}
                keyBlob={blob}
                onDelete={() => setDeleteTarget({ kind: "crx", keyBlob: blob })}
              />
            ))}
          </div>
        )}
      </div>

      <div className="flex gap-2">
        <Button
          variant="outline"
          size="sm"
          className="flex-1"
          onClick={() => setShowGenerate(true)}
        >
          Generate Key
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="flex-1"
          onClick={() => setShowImport(true)}
        >
          Import Key
        </Button>
      </div>

      <ContactsList
        contacts={contacts}
        contactsLocked={contactsLocked}
        onRequestRemove={(contact) =>
          setDeleteTarget({ kind: "contact", contact })
        }
        onAddContact={onAddContact}
        onEncryptTo={onEncryptTo}
        onShowDetails={(contact) =>
          setDetailsTarget({ kind: "contact", contact })
        }
        advancedMode={advancedMode}
      />

      {detailsTarget && (
        <KeyDetailsPage
          target={detailsTarget}
          onBack={() => setDetailsTarget(null)}
          onEncryptTo={
            detailsTarget.kind === "contact" && onEncryptTo
              ? () => {
                  setDetailsTarget(null);
                  onEncryptTo(detailsTarget.contact.keyId);
                }
              : undefined
          }
          onDelete={() => setDeleteTarget(detailsTarget)}
        />
      )}

      {deleteTarget && (
        <ConfirmPage
          title={
            deleteTarget.kind === "contact" ? "Remove contact?" : "Delete key?"
          }
          confirmLabel={
            deleteTarget.kind === "contact"
              ? "Remove contact"
              : "Delete key permanently"
          }
          onCancel={() => setDeleteTarget(null)}
          onConfirm={async () => {
            try {
              if (deleteTarget.kind === "own") {
                await onDeleteKey(deleteTarget.keyBlob.keyId);
              } else if (deleteTarget.kind === "contact") {
                await onDeleteContact(deleteTarget.contact.keyId);
              } else {
                await onDeleteCrxKey?.(deleteTarget.keyBlob.extensionId);
              }
              setDeleteTarget(null);
              setDetailsTarget(null);
            } catch (e) {
              toast.error(
                e instanceof Error ? e.message : "Failed to delete key",
              );
            }
          }}
        >
          <DeleteSummary target={deleteTarget} />
        </ConfirmPage>
      )}

      <GenerateKeyDialog
        open={showGenerate}
        onClose={() => setShowGenerate(false)}
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

      <ImportKeyDialog
        open={showImport}
        onClose={() => {
          setShowImport(false);
          setImportInitialArmored(null);
        }}
        onImportPrivate={onAddKey}
        onImportPublic={onAddContact}
        reusePasskeyCredentialId={primaryPasskeyCredentialId}
        initialArmored={importInitialArmored}
        crxSigningEnabled={crxSigningEnabled}
        onImportCrx={onAddCrxKey}
      />
    </div>
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
  const userIds = isOwn ? target.keyBlob.userIds : target.contact.userIds;
  const keyId = isOwn ? target.keyBlob.keyId : target.contact.keyId;
  const name = userIds[0] ?? "Unknown";
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
  onAddContact,
  onEncryptTo,
  onShowDetails,
  advancedMode,
}: {
  contacts: PublicContactKey[];
  contactsLocked: boolean;
  onRequestRemove: (contact: PublicContactKey) => void;
  onAddContact: (contact: PublicContactKey) => Promise<void>;
  onEncryptTo?: (keyId: string) => void;
  onShowDetails: (contact: PublicContactKey) => void;
  advancedMode?: boolean;
}) {
  const [search, setSearch] = useState("");

  const filtered = search
    ? contacts.filter((c) => {
        const q = search.toLowerCase();
        return (
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
          <ContactDropZone
            onImport={onAddContact}
            existingKeyIds={contacts.map((c) => c.keyId)}
          />
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
              {filtered.map((c) => (
                <ContactCard
                  key={c.keyId}
                  contact={c}
                  onRemove={() => onRequestRemove(c)}
                  onEncryptTo={
                    onEncryptTo ? () => onEncryptTo(c.keyId) : undefined
                  }
                  onCopyPublicKey={() => {
                    void navigator.clipboard.writeText(c.armoredPublicKey);
                    toast.success("Public key copied");
                  }}
                  onShowDetails={() => onShowDetails(c)}
                  advancedMode={advancedMode}
                />
              ))}
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
