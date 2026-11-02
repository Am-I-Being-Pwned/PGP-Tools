import { RenamePage } from "~/components/shared/RenamePage";
import {
  useContacts,
  useCrxKeys,
  useKeyring,
  usePreferences,
  useVault,
} from "~/hooks";
import { t } from "~/lib/i18n";
import { BulkDeletePage, ConfirmDeletePage } from "./DeletePages";
import { ExportKeysPage } from "./ExportKeysPage";
import { GenerateKeyPage } from "./GenerateKeyPage";
import { ImportKeyPage } from "./ImportKeyPage";
import { KeyDetailsRoute } from "./KeyDetailsRoute";
import { realIdentityOf, type KeysNav, type RenameTarget } from "./keys-routes";
import type { KeySelection } from "./useKeySelection";

/** The keys subpage stack, one panel per entry, keyed by entry id so a
 *  panel keeps its mount when entries below it drop. */
export function KeysSubPages({
  nav,
  selection,
  onImported,
}: {
  nav: KeysNav;
  selection: KeySelection;
  onImported: (keyIds: string[]) => void;
}) {
  return nav.stack.map(({ id, route }) => {
    const close = () => nav.remove(id);
    switch (route.page) {
      case "generate":
        return <GenerateRoute key={id} onClose={close} />;
      case "import":
        return (
          <ImportRoute
            key={id}
            initialArmored={route.initialArmored}
            onClose={close}
            onImported={onImported}
          />
        );
      case "rename":
        return (
          <RenameRoute
            key={id}
            target={route.target}
            onCancel={close}
            onSaved={nav.collapseToTop}
          />
        );
      case "details":
        return (
          <KeyDetailsRoute
            key={id}
            target={route.target}
            nav={nav}
            onBack={close}
          />
        );
      case "bulk-delete":
        return (
          <BulkDeletePage
            key={id}
            selection={selection}
            onCancel={close}
            onDeleted={nav.collapseToTop}
          />
        );
      case "bulk-export":
        return (
          <BulkExportRoute key={id} selection={selection} onClose={close} />
        );
      case "confirm-delete":
        return (
          <ConfirmDeletePage
            key={id}
            target={route.target}
            onCancel={close}
            onDeleted={nav.collapseToTop}
          />
        );
    }
  });
}

function GenerateRoute({ onClose }: { onClose: () => void }) {
  const vault = useVault();
  const crx = useCrxKeys();
  const { crxSigningEnabled } = usePreferences();
  return (
    <GenerateKeyPage
      onClose={onClose}
      onKeyGenerated={(keyId, keyHandle) => {
        if (keyHandle !== undefined) {
          vault.onKeyCached(keyId, keyHandle);
        }
      }}
      addKey={vault.addKey}
      reusePasskeyCredentialId={vault.masterPasskeyCredentialId}
      masterSealSalt={vault.masterSealSalt}
      cacheKey={vault.cacheKeys}
      crxSigningEnabled={crxSigningEnabled}
      addCrxKey={crx.add}
    />
  );
}

function ImportRoute({
  initialArmored,
  onClose,
  onImported,
}: {
  initialArmored?: string | null;
  onClose: () => void;
  onImported: (keyIds: string[]) => void;
}) {
  const keyring = useKeyring();
  const contactStore = useContacts();
  const crx = useCrxKeys();
  const vault = useVault();
  const { crxSigningEnabled, keyDiscoveryEnabled } = usePreferences();
  return (
    <ImportKeyPage
      onClose={onClose}
      onImportPrivate={vault.addKey}
      onImportPublic={contactStore.add}
      onRemoveContact={contactStore.remove}
      existingKeys={keyring.keys}
      existingContacts={contactStore.contacts}
      reusePasskeyCredentialId={vault.masterPasskeyCredentialId}
      masterSealSalt={vault.masterSealSalt}
      initialArmored={initialArmored}
      crxSigningEnabled={crxSigningEnabled}
      keyDiscoveryEnabled={keyDiscoveryEnabled}
      onImportCrx={crx.add}
      // An import and a "show it in your keys" land the same way here:
      // the user is already looking at the list.
      onImported={onImported}
    />
  );
}

function RenameRoute({
  target,
  onCancel,
  onSaved,
}: {
  target: RenameTarget;
  onCancel: () => void;
  /** Reveal the (refreshed) list beneath as this slides out. */
  onSaved: () => void;
}) {
  const keyring = useKeyring();
  const contactStore = useContacts();
  const crx = useCrxKeys();
  // The field starts from the current name to tweak, not blank. CRX keys
  // have no User ID; they fall back to their label only.
  const realIdentity = realIdentityOf(target);
  const currentName =
    target.kind === "crx"
      ? (target.keyBlob.label ?? "")
      : ((target.kind === "own"
          ? target.keyBlob.alias
          : target.contact.alias) ?? realIdentity);
  return (
    <RenamePage
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
      onCancel={onCancel}
      onSave={async (value) => {
        if (target.kind === "own") {
          await keyring.rename(target.keyBlob.keyId, value);
        } else if (target.kind === "crx") {
          await crx.rename(target.keyBlob.extensionId, value);
        } else {
          await contactStore.rename(target.contact.keyId, value);
        }
        onSaved();
      }}
    />
  );
}

function BulkExportRoute({
  selection,
  onClose,
}: {
  selection: KeySelection;
  onClose: () => void;
}) {
  const { session } = useVault();
  return (
    <ExportKeysPage
      onClose={onClose}
      myKeys={selection.exportableMyKeys}
      contacts={selection.selectedContacts}
      crxKeys={selection.selectedCrxKeys}
      isUnlocked={session.isUnlocked}
      getKeyHandle={session.getKeyHandle}
      onUnlockWithPassword={session.unlockWithPassword}
      onUnlockWithPasskey={session.unlockWithPasskey}
      onExported={selection.afterExport}
    />
  );
}
