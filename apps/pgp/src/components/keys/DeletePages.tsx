import { ConfirmPage } from "~/components/shared/ConfirmPage";
import { useContacts, useCrxKeys, useVault } from "~/hooks";
import { t, tn } from "~/lib/i18n";
import { reviewed } from "~/lib/import/review";
import { toast } from "~/lib/toast";
import { displayUserId, parseUserId } from "~/lib/utils/key-naming";
import type { DeleteTarget } from "./keys-routes";
import type { KeySelection } from "./useKeySelection";

/** One key or contact. `onDeleted` must drop the pages underneath, so this
 *  page's slide-out reveals the list, not a stale view of the deleted key. */
export function ConfirmDeletePage({
  target,
  onCancel,
  onDeleted,
}: {
  target: DeleteTarget;
  onCancel: () => void;
  onDeleted: () => void;
}) {
  const vault = useVault();
  const contactStore = useContacts();
  const crx = useCrxKeys();
  return (
    <ConfirmPage
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
      // Own and CRX keys hold private key material, so they require typing
      // the key's name; contact removal (public key only) keeps the plain
      // confirm.
      confirmPromptText={
        target.kind === "own"
          ? parseUserId(target.keyBlob.userIds[0]).name
          : target.kind === "crx"
            ? (target.keyBlob.label ?? target.keyBlob.extensionId)
            : undefined
      }
      onCancel={onCancel}
      onConfirm={async () => {
        if (target.kind === "own") {
          await vault.deleteKey(target.keyBlob.keyId);
        } else if (target.kind === "contact") {
          await contactStore.remove(target.contact.keyId);
          // A contact is just a public key, so offer Undo. The blob only
          // lives in this closure; once the toast expires it's gone.
          const removed = target.contact;
          toast.success(tn("keys_contacts_removed", 1), {
            id: "contact-removed",
            action: {
              label: t("keys_undo"),
              onClick: () => void contactStore.add(reviewed(removed)),
            },
          });
        } else {
          await crx.remove(target.keyBlob.extensionId);
        }
        onDeleted();
      }}
    >
      <DeleteSummary target={target} />
    </ConfirmPage>
  );
}

export function BulkDeletePage({
  selection,
  onCancel,
  onDeleted,
}: {
  selection: KeySelection;
  onCancel: () => void;
  onDeleted: () => void;
}) {
  const vault = useVault();
  const contactStore = useContacts();
  const crx = useCrxKeys();
  const { selected, selectedMyKeys, selectedCrxKeys, selectedContacts } =
    selection;
  // Deleting private key material (PGP or CRX) is unrecoverable, so it is
  // gated behind type-to-confirm; contacts-only keeps the plain confirm.
  const hasPrivate = selectedMyKeys.length > 0 || selectedCrxKeys.length > 0;
  return (
    <ConfirmPage
      title={t("keys_bulk_delete_title")}
      confirmLabel={tn("keys_bulk_delete_confirm", selected.size)}
      confirmPromptText={
        hasPrivate ? tn("keys_bulk_delete_prompt", selected.size) : undefined
      }
      onCancel={onCancel}
      onConfirm={async () => {
        // Contacts-only deletes are reversible (Undo from memory); with
        // private keys the type-to-confirm is the safeguard.
        const removedContacts = hasPrivate ? [] : selectedContacts;
        for (const k of selectedMyKeys) await vault.deleteKey(k.keyId);
        for (const k of selectedCrxKeys) await crx.remove(k.extensionId);
        for (const c of selectedContacts) await contactStore.remove(c.keyId);
        onDeleted();
        selection.exitSelection();
        if (removedContacts.length > 0) {
          toast.success(tn("keys_contacts_removed", removedContacts.length), {
            id: "contact-removed",
            action: {
              label: t("keys_undo"),
              onClick: () =>
                void (async () => {
                  for (const c of removedContacts) {
                    // Undoing the user's own delete: putting back what
                    // they had, not a new binding.
                    await contactStore.add(reviewed(c));
                  }
                })(),
            },
          });
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
  // A contact by the name the user knows it by, alias included -- never a
  // `user@host` comment they have never seen. Own keys keep their real
  // identity: the confirm prompt asks the user to type it.
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
