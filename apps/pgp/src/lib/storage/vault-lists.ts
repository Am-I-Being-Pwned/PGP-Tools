import {
  STORAGE_CONTACTS,
  STORAGE_CRX_KEYS,
  STORAGE_KEYRING,
} from "~/lib/constants";
import { getCrxKeys } from "~/lib/crx/storage";
import type { CrxSigningKeyBlob } from "~/lib/crx/types";
import { backfillContacts } from "./contact-backfill";
import { loadContacts, type PublicContactKey } from "./contacts";
import { getKeyring, type ProtectedKeyBlob } from "./keyring";
import { createLiveList } from "./live-list";

/** The vault's sealed lists, as the panel shows them. They read `[]`
 *  while locked, so the panel refreshes them when the vault opens. */
export const keyringList = createLiveList<ProtectedKeyBlob>(
  STORAGE_KEYRING,
  getKeyring,
);

export const contactsList = createLiveList<PublicContactKey>(
  STORAGE_CONTACTS,
  async () => {
    const contacts = await loadContacts();
    backfillContacts(contacts);
    return contacts;
  },
);

export const crxKeysList = createLiveList<CrxSigningKeyBlob>(
  STORAGE_CRX_KEYS,
  getCrxKeys,
);

/** Read every list again: the vault opened or moved. */
export async function refreshVaultLists(): Promise<void> {
  await Promise.all([
    keyringList.refresh(),
    contactsList.refresh(),
    crxKeysList.refresh(),
  ]);
}
