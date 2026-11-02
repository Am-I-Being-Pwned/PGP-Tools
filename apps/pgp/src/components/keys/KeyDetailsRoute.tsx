import { useContacts } from "~/hooks/useContacts";
import { useKeyring } from "~/hooks/useKeyring";
import { useNav } from "~/hooks/useNav";
import { usePreferences } from "~/hooks/usePreferences";
import { useVault } from "~/hooks/useVault";
import { AppError } from "~/lib/errors/app-error";
import { t } from "~/lib/i18n";
import { contactClash } from "~/lib/identity/binding";
import { revocationCertificateWithHandle } from "~/lib/pgp/wasm";
import { isSshRecord } from "~/lib/storage/key-kind";
import { KeyDetailsPage, type KeyDetailsTarget } from "./KeyDetailsPage";
import type { KeysNav } from "./keys-routes";
import { useContactRevocationCheck } from "./useContactRevocationCheck";

/** KeyDetailsPage wired to the stores, for the keys subpage stack. */
export function KeyDetailsRoute({
  target: pushed,
  nav,
  onBack,
}: {
  target: KeyDetailsTarget;
  nav: KeysNav;
  onBack: () => void;
}) {
  const keyring = useKeyring();
  const contactStore = useContacts();
  const { session, ...vault } = useVault();
  const appNav = useNav();
  const { keyDiscoveryEnabled, defaultKeyId } = usePreferences();
  const checkContactRevocation = useContactRevocationCheck((armored) =>
    nav.push({ page: "import", initialArmored: armored }),
  );

  // A contact is read from the live list, not the snapshot the route was
  // pushed with: a revocation check run from this page must show its
  // answer here, not only after leaving it.
  const target: KeyDetailsTarget =
    pushed.kind === "contact"
      ? {
          ...pushed,
          contact:
            contactStore.contacts.find(
              (c) => c.keyId === pushed.contact.keyId,
            ) ?? pushed.contact,
        }
      : pushed;

  return (
    <KeyDetailsPage
      target={target}
      onBack={onBack}
      clash={
        target.kind === "contact"
          ? contactClash(
              target.contact.keyId,
              contactStore.contacts,
              keyring.keys,
            )
          : undefined
      }
      onShowHolder={(holder) => {
        const contact = contactStore.contacts.find(
          (c) => c.keyId === holder.keyId,
        );
        const own = keyring.keys.find((k) => k.keyId === holder.keyId);
        if (contact)
          nav.push({ page: "details", target: { kind: "contact", contact } });
        else if (own)
          nav.push({ page: "details", target: { kind: "own", keyBlob: own } });
      }}
      onSetVerified={
        target.kind === "contact" && !target.contact.revoked
          ? (v) => contactStore.setVerified(target.contact.keyId, v)
          : undefined
      }
      onCheckRevocation={
        keyDiscoveryEnabled &&
        target.kind === "contact" &&
        !isSshRecord(target.contact) &&
        !target.contact.revoked
          ? () => void checkContactRevocation(target.contact)
          : undefined
      }
      onEncryptTo={
        // Never for a revoked contact: the engine refuses it.
        target.kind === "contact" && !target.contact.revoked
          ? () => {
              nav.clear();
              appNav.encryptTo(target.contact.keyId);
            }
          : undefined
      }
      // The details target union is the rename target union for these two
      // members: one rename page, nothing to translate.
      onRename={() => nav.push({ page: "rename", target })}
      isDefault={
        target.kind === "own" &&
        defaultKeyId != null &&
        target.keyBlob.keyId === defaultKeyId
      }
      // Only the user's own keys can be the default -- never contacts (no
      // private key) or CRX keys.
      onSetDefault={
        target.kind === "own"
          ? (next) => vault.setDefaultKey(next ? target.keyBlob.keyId : null)
          : undefined
      }
      onDelete={() => nav.push({ page: "confirm-delete", target })}
      onGenerateRevocation={
        // Only when the result can be persisted: a cert that silently
        // vanishes on the next open would be a false assurance.
        target.kind === "own"
          ? async () => {
              const handle = session.getKeyHandle(target.keyBlob.keyId);
              if (handle === null) {
                throw new AppError(
                  "key-locked",
                  t("keys_revocation_unlock_first"),
                );
              }
              const armored = await revocationCertificateWithHandle(handle);
              await keyring.setRevocationCertificate(
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
