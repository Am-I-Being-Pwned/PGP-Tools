import { ImportKeyPage } from "~/components/keys/ImportKeyPage";
import { useContacts } from "~/hooks/useContacts";
import { useCrxKeys } from "~/hooks/useCrxKeys";
import { useKeyring } from "~/hooks/useKeyring";
import { useNav } from "~/hooks/useNav";
import { usePreferences } from "~/hooks/usePreferences";
import { useVault } from "~/hooks/useVault";
import { tn } from "~/lib/i18n";
import { toast } from "~/lib/toast";

/** Imports a key arriving from outside the Keys tab, over whatever tab is showing. */
export function ImportOverlay() {
  const nav = useNav();
  const vault = useVault();
  const keyring = useKeyring();
  const contacts = useContacts();
  const crx = useCrxKeys();
  const { keyDiscoveryEnabled, crxSigningEnabled } = usePreferences();
  if (!nav.importing) return null;

  const onImported = (keyIds: string[], opts?: { reveal?: boolean }) => {
    if (keyIds.length === 0) return;
    if (opts?.reveal) {
      nav.revealKeys(keyIds);
      return;
    }
    // An import never moves the user.
    if (nav.tab === "keys") {
      nav.highlightKeys(keyIds);
      return;
    }
    toast.success(tn("app_import_added", keyIds.length), {
      id: "import-added",
      action: {
        label: tn("app_import_view_key", keyIds.length),
        onClick: () => nav.revealKeys(keyIds),
      },
    });
  };

  return (
    <ImportKeyPage
      onClose={nav.closeImport}
      onImportPrivate={vault.addKey}
      onImportPublic={contacts.add}
      onRemoveContact={contacts.remove}
      existingKeys={keyring.keys}
      existingContacts={contacts.contacts}
      reusePasskeyCredentialId={vault.masterPasskeyCredentialId}
      masterSealSalt={vault.masterSealSalt}
      initialArmored={nav.importing.prefill}
      initialLookup={nav.importing.lookup}
      keyDiscoveryEnabled={keyDiscoveryEnabled}
      crxSigningEnabled={crxSigningEnabled}
      onImportCrx={crx.add}
      onImported={onImported}
    />
  );
}
