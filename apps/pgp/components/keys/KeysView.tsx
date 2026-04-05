import { useEffect, useState } from "react";
import { format } from "date-fns";
import { SquareCheckBigIcon, SquareIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@amibeingpwned/ui/button";
import {
  Command,
  CommandEmpty,
  CommandInput,
  CommandItem,
  CommandList,
} from "@amibeingpwned/ui/command";

import type { ImportKeyFromLink } from "../../lib/messages";
import type { KeyInfo } from "../../lib/pgp/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { parsePublicKey } from "../../lib/pgp/key-management";
import { parseUserId } from "../../lib/utils/key-naming";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { Dialog } from "../shared/Dialog";
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
  onUnlockWithPasskey: (blob: ProtectedKeyBlob) => Promise<boolean | "cancelled">;
  onLock: (keyId: string) => void;
  onDeleteKey: (keyId: string) => Promise<void>;
  onAddKey: (blob: ProtectedKeyBlob) => Promise<void>;
  onAddContact: (contact: PublicContactKey) => Promise<void>;
  onDeleteContact: (keyId: string) => Promise<void>;
  getKeyHandle: (keyId: string) => number | null;
  advancedMode?: boolean;
  autoOpenGenerate?: boolean;
  onAutoOpenConsumed?: () => void;
  importKeyFromLink?: ImportKeyFromLink | null;
  onImportKeyConsumed?: () => void;
  onEncryptTo?: (keyId: string) => void;
  unlockRequestKeyId?: string | null;
  onUnlockRequestConsumed?: () => void;
  primaryPasskeyCredentialId?: string;
  /** Called when a newly generated key is cached in WASM. */
  onKeyCached?: (keyId: string, keyHandle: number) => void;
  /** Whether to cache decrypted keys in WASM after generation. */
  cacheKeys?: boolean;
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
  autoOpenGenerate,
  onAutoOpenConsumed,
  importKeyFromLink,
  onImportKeyConsumed,
  onEncryptTo,
  unlockRequestKeyId,
  onUnlockRequestConsumed,
  primaryPasskeyCredentialId,
  onKeyCached,
  cacheKeys,
}: KeysViewProps) {
  const [showGenerate, setShowGenerate] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [pendingImports, setPendingImports] = useState<
    { keyInfo: KeyInfo; armored: string; selected: boolean }[]
  >([]);

  useEffect(() => {
    if (autoOpenGenerate) {
      setShowGenerate(true);
      onAutoOpenConsumed?.();
    }
  }, [autoOpenGenerate, onAutoOpenConsumed]);

  useEffect(() => {
    if (!importKeyFromLink) return;
    onImportKeyConsumed?.();

    if (importKeyFromLink.error) {
      toast.error(importKeyFromLink.error);
      return;
    }

    if (!importKeyFromLink.armoredKey) return;

    const armored = importKeyFromLink.armoredKey;

    if (armored.includes("PRIVATE KEY")) {
      setShowImport(true);
      toast.info(
        "This is a private key - use the Import dialog to add it with protection.",
      );
      return;
    }

    void (async () => {
      try {
        const keyInfo = await parsePublicKey(armored);
        const alreadyHave =
          contacts.some((c) => c.keyId === keyInfo.keyId) ||
          myKeys.some((k) => k.keyId === keyInfo.keyId);
        if (alreadyHave) {
          toast.info(
            `${keyInfo.userIds[0] ?? "Key"} is already in your keyring`,
          );
          return;
        }
        setPendingImports((prev) => {
          if (prev.some((p) => p.keyInfo.keyId === keyInfo.keyId)) return prev;
          return [...prev, { keyInfo, armored, selected: true }];
        });
      } catch (e) {
        toast.error(e instanceof Error ? e.message : "Failed to parse key");
      }
    })();
  }, [importKeyFromLink, onImportKeyConsumed]);

  const handleExportPublic = async (blob: ProtectedKeyBlob) => {
    await navigator.clipboard.writeText(blob.publicKeyArmored);
  };

  return (
    <div className="space-y-4">
      <Dialog
        open={pendingImports.length > 0}
        onClose={() => setPendingImports([])}
        title="Keys from Downloads"
        className="mx-2"
      >
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            {pendingImports.length} key{pendingImports.length > 1 ? "s" : ""}{" "}
            detected from downloaded files. Select which to import as contacts.
          </p>
          <Command className="border-border rounded-md border">
            <CommandInput placeholder="Search keys..." />
            <CommandList className="h-[300px]">
              <CommandEmpty>No keys match.</CommandEmpty>
              {pendingImports.map((entry, i) => {
                const {
                  name: rawName,
                  email,
                  comment,
                } = parseUserId(entry.keyInfo.userIds[0]);
                const name = comment ? `${rawName} (${comment})` : rawName;
                const fp = entry.keyInfo.keyId.match(/.{1,4}/g)?.join(" ");
                return (
                  <CommandItem
                    key={entry.keyInfo.keyId}
                    value={entry.keyInfo.userIds.join(" ")}
                    onSelect={() => {
                      setPendingImports((prev) =>
                        prev.map((p, j) =>
                          j === i ? { ...p, selected: !p.selected } : p,
                        ),
                      );
                    }}
                    className="cursor-pointer gap-2 py-2 select-text"
                  >
                    {entry.selected ? (
                      <SquareCheckBigIcon className="text-primary h-4 w-4 shrink-0" />
                    ) : (
                      <SquareIcon className="text-muted-foreground h-4 w-4 shrink-0" />
                    )}
                    <div className="min-w-0 flex-1 space-y-0.5">
                      <p className="truncate text-sm font-medium">{name}</p>
                      {email && (
                        <p className="text-muted-foreground text-xs">{email}</p>
                      )}
                      <p className="text-muted-foreground font-mono text-xs">
                        {entry.keyInfo.keyId.slice(-16)} -{" "}
                        {entry.keyInfo.algorithm}
                      </p>
                      <p className="text-muted-foreground font-mono text-xs leading-relaxed">
                        {fp}
                      </p>
                      {entry.keyInfo.expiresAt && (
                        <p className="text-muted-foreground text-xs">
                          Expires{" "}
                          {format(new Date(entry.keyInfo.expiresAt), "PPP")}
                        </p>
                      )}
                    </div>
                  </CommandItem>
                );
              })}
            </CommandList>
          </Command>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              className="flex-1"
              onClick={() => setPendingImports([])}
            >
              Deny All
            </Button>
            <Button
              size="sm"
              className="flex-1"
              disabled={!pendingImports.some((p) => p.selected)}
              onClick={async () => {
                const selected = pendingImports.filter((p) => p.selected);
                let imported = 0;
                for (const entry of selected) {
                  try {
                    await onAddContact({
                      keyId: entry.keyInfo.keyId,
                      userIds: entry.keyInfo.userIds,
                      algorithm: entry.keyInfo.algorithm,
                      armoredPublicKey: entry.armored,
                      addedAt: Date.now(),
                      lastUsedAt: Date.now(),
                    });
                    imported++;
                  } catch {
                    // skip failed imports
                  }
                }
                setPendingImports([]);
                if (imported > 0) {
                  toast.success(
                    `Imported ${imported} key${imported > 1 ? "s" : ""}`,
                  );
                }
              }}
            >
              Import Selected
            </Button>
          </div>
        </div>
      </Dialog>

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
                onUnlockWithPassword={async (pw) => {
                  const ok = await onUnlockWithPassword(blob, pw);
                  if (ok && blob.keyId === unlockRequestKeyId) {
                    onUnlockRequestConsumed?.();
                  }
                  return ok;
                }}
                onUnlockWithPasskey={async () => {
                  const result = await onUnlockWithPasskey(blob);
                  if (result === true && blob.keyId === unlockRequestKeyId) {
                    onUnlockRequestConsumed?.();
                  }
                  return result;
                }}
                onLock={() => onLock(blob.keyId)}
                onDelete={() => onDeleteKey(blob.keyId)}
                onExportPublic={() => handleExportPublic(blob)}
                onExportPrivate={() => getKeyHandle(blob.keyId)}
                advancedMode={advancedMode}
                autoExpand={blob.keyId === unlockRequestKeyId}
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
      />

      <ImportKeyDialog
        open={showImport}
        onClose={() => setShowImport(false)}
        onImportPrivate={onAddKey}
        onImportPublic={onAddContact}
        reusePasskeyCredentialId={primaryPasskeyCredentialId}
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
          <ContactDropZone onImport={onAddContact} existingKeyIds={contacts.map((c) => c.keyId)} />
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
