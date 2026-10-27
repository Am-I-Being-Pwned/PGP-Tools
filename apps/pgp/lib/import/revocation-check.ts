/**
 * "Has this contact revoked their key?" -- asked of keys.openpgp.org.
 *
 * A revocation only helps if it reaches you, and nothing pushes it: the
 * owner publishes it and everyone holding the key has to go and look.
 * This looks, for one contact, by FINGERPRINT (the query that cannot
 * return someone else's key), and folds whatever comes back into the
 * stored cert through the same merge every import uses -- so the answer
 * can only ever add what the owner signed, never roll the contact back.
 */

import type { StoredCert } from "../import-public-keys";
import type { KeyserverQuery } from "../keyserver/query";
import type {
  KeyserverKeyFailure,
  KeyserverKeyRequest,
  KeyserverKeyResponse,
} from "../messages";
import type { KeyInfo } from "../pgp/types";
import { mergeIntoStored } from "../import-public-keys";
import { parseKeyserverQuery } from "../keyserver/query";
import { parseKeys } from "../pgp/wasm";

export type RevocationCheck =
  /** The keyserver's copy (merged with ours) is revoked. */
  | { kind: "revoked"; merged: { keyInfo: KeyInfo; armored: string } }
  /** Not revoked as far as the keyserver knows. The merge may still have
   *  brought news -- a new expiry, a new subkey -- so it is returned. */
  | { kind: "current"; merged: { keyInfo: KeyInfo; armored: string } }
  /** The keyserver doesn't publish this key: nothing to check against. */
  | { kind: "not-published" }
  /** It answered with a different key than the one asked for. */
  | { kind: "wrong-key" }
  /** The lookup itself failed. */
  | {
      kind: "failed";
      error: KeyserverKeyFailure | "unreachable";
      retryAt?: number;
    };

export type KeyserverSend = (
  request: KeyserverKeyRequest,
) => Promise<KeyserverKeyResponse | undefined>;

/** The worker owns the only fetch; the panel only asks it. */
export const sendToWorker: KeyserverSend = (request) =>
  chrome.runtime.sendMessage<
    KeyserverKeyRequest,
    KeyserverKeyResponse | undefined
  >(request);

/** The fingerprint query for a stored contact, or null when its id isn't one. */
export function fingerprintQuery(keyId: string): KeyserverQuery | null {
  const query = parseKeyserverQuery(keyId);
  return query?.kind === "fingerprint" ? query : null;
}

export async function checkRevocation(
  contact: StoredCert,
  send: KeyserverSend = sendToWorker,
): Promise<RevocationCheck> {
  const query = fingerprintQuery(contact.keyId);
  if (!query) return { kind: "failed", error: "invalid-query" };

  const response = await send({ type: "KEYSERVER_KEY_REQUEST", query });
  if (!response) return { kind: "failed", error: "unreachable" };
  if (!response.ok) {
    return response.error === "not-found"
      ? { kind: "not-published" }
      : { kind: "failed", error: response.error, retryAt: response.retryAt };
  }

  // Untrusted text until the engine says otherwise -- and it must be
  // THIS key, whatever else the response carries.
  let certs;
  try {
    certs = await parseKeys(response.armored);
  } catch {
    return { kind: "wrong-key" };
  }
  const same = certs.find(
    (c) => c.keyInfo.keyId.toUpperCase() === contact.keyId.toUpperCase(),
  );
  if (!same) return { kind: "wrong-key" };

  const merged = await mergeIntoStored(contact, same.armored);
  return merged.keyInfo.revoked
    ? { kind: "revoked", merged }
    : { kind: "current", merged };
}
