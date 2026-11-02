import { useContacts } from "~/hooks/useContacts";
import { presentError } from "~/lib/errors/present";
import { t } from "~/lib/i18n";
import { KEYSERVER_HOST, keyserverFailureCopy } from "~/lib/import/keyserver";
import {
  checkRevocation,
  fingerprintQuery,
} from "~/lib/import/revocation-check";
import type { PublicContactKey } from "~/lib/storage/contacts";
import { toast } from "~/lib/toast";
import { displayUserId, parseUserId } from "~/lib/utils/key-naming";

/**
 * Ask keys.openpgp.org whether a contact's key has been revoked, and keep
 * what it says: the answer is merged into the stored cert like every
 * import, so a revocation sticks. One toast, updated in place.
 */
export function useContactRevocationCheck(
  /** New names or addresses on the key: never bound here, only through
   *  the import Review that checks them against everyone else. */
  onNeedsReview: (armored: string) => void,
) {
  const { mergeKey } = useContacts();

  return async (contact: PublicContactKey) => {
    const name =
      parseUserId(displayUserId(contact) ?? "").name ||
      contact.keyId.slice(-16);
    const id = `revocation-check-${contact.keyId}`;
    toast.message(
      t("keys_check_revocation_running", { host: KEYSERVER_HOST }),
      { id },
    );
    try {
      // Merged into the contact as it is when the answer arrives, never
      // the copy captured on click: a revocation imported, a rename or a
      // delete during the fetch must survive it.
      const result = await checkRevocation(
        { keyId: contact.keyId, armored: contact.armoredPublicKey },
        mergeKey,
      );
      switch (result.kind) {
        case "gone":
          toast.dismiss(id);
          break;
        case "needs-review":
          toast.info(t("keys_check_revocation_needs_review", { name }), {
            id,
          });
          onNeedsReview(result.armored);
          break;
        case "revoked":
          toast.error(t("keys_check_revocation_revoked", { name }), {
            id,
            duration: 10_000,
          });
          break;
        case "current":
          toast.success(
            t("keys_check_revocation_current", { name, host: KEYSERVER_HOST }),
            { id },
          );
          break;
        case "not-published":
          toast.info(
            t("keys_check_revocation_not_published", {
              name,
              host: KEYSERVER_HOST,
            }),
            { id },
          );
          break;
        case "wrong-key":
          toast.error(
            t("import_keyserver_wrong_key", {
              host: KEYSERVER_HOST,
              subject: contact.keyId.replace(/(.{4})(?=.)/g, "$1 "),
            }),
            { id },
          );
          break;
        case "failed": {
          const query = fingerprintQuery(contact.keyId);
          toast.error(
            result.error === "unreachable" || !query
              ? t("import_worker_unreachable")
              : keyserverFailureCopy(result.error, query, result.retryAt)
                  .message,
            { id },
          );
          break;
        }
      }
    } catch (e) {
      toast.error(presentError(e, t("keys_check_revocation_failed")).message, {
        id,
      });
    }
  };
}
