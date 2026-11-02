import { useSyncExternalStore } from "react";

import { mergeIntoContact } from "~/lib/import-public-keys";
import type { ReviewedContact } from "~/lib/import/review";
import {
  removeContact,
  saveContact,
  setContactVerified,
  updateContactAlias,
} from "~/lib/storage/contacts";
import { contactsList } from "~/lib/storage/vault-lists";

/** Only a reviewed contact can be added -- see `lib/import/review`. */
const add = (contact: ReviewedContact) => saveContact(contact);

/** The contacts as stored; every write (from here or anywhere else)
 *  reaches `contacts` on its own. */
export function useContacts() {
  const { items, loading, error } = useSyncExternalStore(
    contactsList.subscribe,
    contactsList.get,
  );
  return {
    contacts: items,
    loading,
    error,
    add,
    remove: removeContact,
    rename: updateContactAlias,
    mergeKey: mergeIntoContact,
    setVerified: setContactVerified,
  };
}
