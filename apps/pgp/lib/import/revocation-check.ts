/**
 * "Has this contact revoked their key?" -- asked of keys.openpgp.org by
 * FINGERPRINT (cannot return someone else's key), folded in via the
 * import merge so it can only add what the owner signed. A copy adding
 * User IDs is not saved here; it returns `needs-review`.
 */

import type { StoredCert } from "../import-public-keys";
import type { KeyserverQuery } from "../keyserver/query";
import type {
  KeyserverKeyFailure,
  KeyserverKeyRequest,
  KeyserverKeyResponse,
} from "../messages";
import type { KeyInfo } from "../pgp/types";
import { parseKeyserverQuery } from "../keyserver/query";
import { parseKeys } from "../pgp/wasm";

export type RevocationCheck =
  | { kind: "revoked" }
  /** Not revoked; any other merged news was saved. */
  | { kind: "current" }
  /** Adds User IDs: nothing written, `armored` goes through import Review. */
  | { kind: "needs-review"; armored: string }
  /** Contact removed mid-check: nothing written. */
  | { kind: "gone" }
  | { kind: "not-published" }
  | { kind: "wrong-key" }
  | {
      kind: "failed";
      error: KeyserverKeyFailure | "unreachable";
      retryAt?: number;
    };

/** Merges into the contact as it is NOW, not when the check started. */
export type MergeIntoContact = (
  keyId: string,
  armored: string,
) => Promise<{ keyInfo: KeyInfo; needsReview?: true } | undefined>;

export type KeyserverSend = (
  request: KeyserverKeyRequest,
) => Promise<KeyserverKeyResponse | undefined>;

export const sendToWorker: KeyserverSend = (request) =>
  chrome.runtime.sendMessage<
    KeyserverKeyRequest,
    KeyserverKeyResponse | undefined
  >(request);

export function fingerprintQuery(keyId: string): KeyserverQuery | null {
  const query = parseKeyserverQuery(keyId);
  return query?.kind === "fingerprint" ? query : null;
}

export async function checkRevocation(
  contact: StoredCert,
  merge: MergeIntoContact,
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

  // Untrusted until the engine says otherwise, and it must be THIS key.
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

  const merged = await merge(contact.keyId, same.armored);
  if (!merged) return { kind: "gone" };
  if (merged.needsReview)
    return { kind: "needs-review", armored: same.armored };
  return merged.keyInfo.revoked ? { kind: "revoked" } : { kind: "current" };
}
