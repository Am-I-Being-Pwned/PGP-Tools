import { useEffect, useState } from "react";
import { toast } from "sonner";

import { TrashIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { publicKeyDerToPem } from "../../lib/crx/types";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { ContactCard } from "./ContactCard";
import { ContactDropZone } from "./ContactDropZone";
import { GenerateKeyDialog } from "./GenerateKeyDialog";
import { ImportKeyDialog } from "./ImportKeyDialog";
import { KeyCard } from "./KeyCard";

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

  return (
    <div className="space-y-4">
      <div>
        <h2 className="mb-2 text-sm font-semibold">My Keys</h2>
        {myKeys.length === 0 ? (
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
                onDelete={() => onDeleteKey(blob.keyId)}
                onExportPublic={() => handleExportPublic(blob)}
                onExportPrivate={() => getKeyHandle(blob.keyId)}
                advancedMode={advancedMode}
              />
            ))}
          </div>
        )}
      </div>

      {crxSigningEnabled && crxKeys && crxKeys.length > 0 && (
        <div>
          <h2 className="mb-2 text-sm font-semibold">CRX signing keys</h2>
          <div className="space-y-2">
            {crxKeys.map((blob) => (
              <div
                key={blob.extensionId}
                className="border-border flex items-center gap-2 rounded-lg border p-3"
              >
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">
                    {blob.label ?? blob.extensionId}
                  </p>
                  <p className="text-muted-foreground truncate font-mono text-xs">
                    {blob.extensionId}
                  </p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    void navigator.clipboard.writeText(
                      publicKeyDerToPem(blob.publicKeyDerB64),
                    );
                    toast.success("Public key copied");
                  }}
                >
                  Copy public key
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  className="text-muted-foreground hover:text-destructive"
                  aria-label="Delete CRX signing key"
                  onClick={() => void onDeleteCrxKey?.(blob.extensionId)}
                >
                  <TrashIcon className="h-4 w-4" />
                </Button>
              </div>
            ))}
          </div>
        </div>
      )}

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
        onDeleteContact={onDeleteContact}
        onAddContact={onAddContact}
        onEncryptTo={onEncryptTo}
        advancedMode={advancedMode}
      />

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
      />
    </div>
  );
}

function ContactsList({
  contacts,
  contactsLocked,
  onDeleteContact,
  onAddContact,
  onEncryptTo,
  advancedMode,
}: {
  contacts: PublicContactKey[];
  contactsLocked: boolean;
  onDeleteContact: (keyId: string) => Promise<void>;
  onAddContact: (contact: PublicContactKey) => Promise<void>;
  onEncryptTo?: (keyId: string) => void;
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
                  onRemove={() => onDeleteContact(c.keyId)}
                  onEncryptTo={
                    onEncryptTo ? () => onEncryptTo(c.keyId) : undefined
                  }
                  onCopyPublicKey={() => {
                    void navigator.clipboard.writeText(c.armoredPublicKey);
                    toast.success("Public key copied");
                  }}
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
