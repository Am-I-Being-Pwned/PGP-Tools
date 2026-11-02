import { useMemo, useState } from "react";

import { Block, BlockLabel, Input } from "@amibeingpwned/ui";

import { useCopyToClipboard } from "~/hooks/useCopyToClipboard";
import { t } from "~/lib/i18n";
import { contactClashes } from "~/lib/identity/binding";
import { downloadPublicKey } from "~/lib/keys/export-bundle";
import type { PublicContactKey } from "~/lib/storage/contacts";
import { isSshRecord } from "~/lib/storage/key-kind";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { displayUserId, parseUserId } from "~/lib/utils/key-naming";
import { ContactCard } from "./ContactCard";
import { ContactDropZone } from "./ContactDropZone";
import { LIST_STACK, selId } from "./keys-routes";

export function ContactsList({
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
