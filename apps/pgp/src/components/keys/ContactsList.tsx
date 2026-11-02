import { useMemo, useState } from "react";

import { Block, BlockLabel, Input } from "@amibeingpwned/ui";

import { useContacts } from "~/hooks/useContacts";
import { useCopyToClipboard } from "~/hooks/useCopyToClipboard";
import { useKeyring } from "~/hooks/useKeyring";
import { useNav } from "~/hooks/useNav";
import { usePreferences } from "~/hooks/usePreferences";
import { t } from "~/lib/i18n";
import { contactClashes } from "~/lib/identity/binding";
import { downloadPublicKey } from "~/lib/keys/export-bundle";
import { isSshRecord } from "~/lib/storage/key-kind";
import { displayUserId, parseUserId } from "~/lib/utils/key-naming";
import { ContactCard } from "./ContactCard";
import { ContactDropZone } from "./ContactDropZone";
import { useKeysTab } from "./keys-context";
import { LIST_STACK, selId } from "./keys-routes";
import { useContactRevocationCheck } from "./useContactRevocationCheck";

export function ContactsList() {
  const { contacts } = useContacts();
  const { keys: ownKeys } = useKeyring();
  const { advancedMode, keyDiscoveryEnabled } = usePreferences();
  const { encryptTo } = useNav();
  const { nav, selection, justImported } = useKeysTab();
  const checkRevocation = useContactRevocationCheck((armored) =>
    nav.push({ page: "import", initialArmored: armored }),
  );
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
            <ContactDropZone
              onKeyText={(text) =>
                nav.push({ page: "import", initialArmored: text })
              }
            />
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
                  onRemove={() =>
                    nav.push({
                      page: "confirm-delete",
                      target: { kind: "contact", contact: c },
                    })
                  }
                  onEncryptTo={c.revoked ? undefined : () => encryptTo(c.keyId)}
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
                  onRename={() =>
                    nav.push({
                      page: "rename",
                      target: { kind: "contact", contact: c },
                    })
                  }
                  onCheckRevocation={
                    // An SSH key has nothing on the keyserver, and a
                    // revoked one has nothing left to learn.
                    keyDiscoveryEnabled && !isSshRecord(c) && !c.revoked
                      ? () => void checkRevocation(c)
                      : undefined
                  }
                  onShowDetails={() =>
                    nav.push({
                      page: "details",
                      target: { kind: "contact", contact: c },
                    })
                  }
                  advancedMode={advancedMode}
                  selectionMode={selection.selectionMode}
                  selected={selection.selected.has(id)}
                  onToggleSelect={(extend) =>
                    selection.toggleSelect(id, extend)
                  }
                  onStartSelect={() => selection.startSelect(id)}
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
