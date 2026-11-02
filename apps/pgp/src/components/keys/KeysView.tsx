import { useEffect, useRef } from "react";
import { ImportIcon, PlusIcon } from "lucide-react";

import { BlockLabel, Button } from "@amibeingpwned/ui";

import { useNavStack } from "~/components/shared/useNavStack";
import { useContacts } from "~/hooks/useContacts";
import { useCrxKeys } from "~/hooks/useCrxKeys";
import { useKeyring } from "~/hooks/useKeyring";
import { useNav } from "~/hooks/useNav";
import { usePreferences } from "~/hooks/usePreferences";
import { t, tn } from "~/lib/i18n";
import { downloadPublicKeysBundle } from "~/lib/keys/export-bundle";
import { toast } from "~/lib/toast";
import { ContactsList } from "./ContactsList";
import { KeyCard } from "./KeyCard";
import { LIST_STACK, selId, type KeysSubRoute } from "./keys-routes";
import { KeysSubPages } from "./KeysSubPages";
import { SelectionBar } from "./SelectionBar";
import { useContactRevocationCheck } from "./useContactRevocationCheck";
import { useImportHighlight } from "./useImportHighlight";
import { useKeyCardModels } from "./useKeyCardModels";
import { useKeySelection } from "./useKeySelection";

export function KeysView() {
  const keyring = useKeyring();
  const contactStore = useContacts();
  const crx = useCrxKeys();
  const appNav = useNav();
  const { advancedMode, crxSigningEnabled, keyDiscoveryEnabled } =
    usePreferences();
  const nav = useNavStack<KeysSubRoute>();
  const [justImported, highlightImported] = useImportHighlight();

  const navPush = nav.push;
  const consumeIntent = appNav.consume;
  useEffect(() => {
    if (appNav.keysRoute) {
      navPush({ page: appNav.keysRoute });
      consumeIntent("keysRoute");
    }
  }, [appNav.keysRoute, consumeIntent, navPush]);

  // CRX keys join the same list, gated on the feature being enabled.
  const shownCrxKeys = crxSigningEnabled ? crx.keys : [];
  const listRef = useRef<HTMLDivElement>(null);
  const selection = useKeySelection(listRef, {
    myKeys: keyring.keys,
    crxKeys: shownCrxKeys,
    contacts: contactStore.contacts,
  });
  const keyModels = useKeyCardModels(shownCrxKeys, nav.push);
  const checkContactRevocation = useContactRevocationCheck((armored) =>
    nav.push({ page: "import", initialArmored: armored }),
  );

  // A contacts-only selection has no private key to unlock: download the
  // public keys directly. Selected SSH keys are left out, and said so,
  // rather than handed to the PGP exporter.
  const bulkExport = () => {
    const skippedSsh =
      selection.selectedMyKeys.length - selection.exportableMyKeys.length;
    if (skippedSsh > 0) {
      toast.info(tn("keys_ssh_export_skipped", skippedSsh), {
        id: "ssh-export-skipped",
      });
    }
    if (
      selection.exportableMyKeys.length === 0 &&
      selection.selectedCrxKeys.length === 0
    ) {
      selection.afterExport(
        downloadPublicKeysBundle(selection.selectedContacts),
        false,
      );
      return;
    }
    nav.push({ page: "bulk-export" });
  };

  return (
    // Plain wrapper (no space-y) so mounting the sticky bar doesn't shift
    // the first spaced child; it is also the selection's range scope.
    <div ref={listRef}>
      <SelectionBar
        open={selection.selectionMode}
        count={selection.selected.size}
        allSelected={selection.allSelected}
        onToggleAll={selection.toggleSelectAll}
        onExport={bulkExport}
        onDelete={() => nav.push({ page: "bulk-delete" })}
        onExit={selection.exitSelection}
      />

      <div className="space-y-4">
        <div>
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
          )}
        </div>

        <ContactsList
          contacts={contactStore.contacts}
          ownKeys={keyring.keys}
          justImported={justImported}
          onCheckRevocation={
            keyDiscoveryEnabled
              ? (contact) => void checkContactRevocation(contact)
              : undefined
          }
          onRequestRename={(contact) =>
            nav.push({ page: "rename", target: { kind: "contact", contact } })
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
          onEncryptTo={appNav.encryptTo}
          onShowDetails={(contact) =>
            nav.push({ page: "details", target: { kind: "contact", contact } })
          }
          advancedMode={advancedMode}
          selectionMode={selection.selectionMode}
          selected={selection.selected}
          onToggleSelect={selection.toggleSelect}
          onStartSelect={selection.startSelect}
        />

        <KeysSubPages
          nav={nav}
          selection={selection}
          onImported={highlightImported}
        />
      </div>
    </div>
  );
}
