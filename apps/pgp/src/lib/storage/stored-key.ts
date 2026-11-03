import type { PublicContactKey } from "./contacts";
import type { ProtectedKeyBlob } from "./keyring";

/** A key the panel holds: one of the user's own, or a contact's. */
export type StoredKey = ProtectedKeyBlob | PublicContactKey;

/** Only contacts carry their armored public key. */
export function isContact(key: StoredKey): key is PublicContactKey {
  return "armoredPublicKey" in key;
}
