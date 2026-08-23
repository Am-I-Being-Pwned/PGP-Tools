import type { KeyDetails, KeyInfo } from "../pgp/types";
import type { IncomingKey } from "./types";
import { detectImportOverwrite } from "../import-overwrite";
import { importRejectionMessage, isUsableContact } from "../import-public-keys";
import { extractPublicKey, parseKeyDetails, parseKeys } from "../pgp/wasm";

/**
 * Turn pasted/dropped text into the objects the import UI renders.
 *
 * Everything the old flow made the user discover by pressing Next --
 * "is this a key at all", "whose is it", "do I already have it", "is it
 * even usable" -- is answered here, up front, so the panel can show a
 * preview instead of a wall of armor.
 */

/** One stored key an import can collide with, plus its public armor so a
 *  byte-identical re-import can be told from a real change. */
export interface StoredKey {
  keyId: string;
  userIds: string[];
  /** PUBLIC armor -- `ProtectedKeyBlob.publicKeyArmored` for own keys,
   *  `PublicContactKey.armoredPublicKey` for contacts. */
  armored: string;
  addedAt?: number;
  createdAt?: number;
  expiresAt?: number | null;
}

export interface StoredKeys {
  /** The user's own keys (keyring), matched against private imports. */
  own: StoredKey[];
  /** Contacts, matched against public imports. */
  contacts: StoredKey[];
}

/** Normalized armor, for the byte-identical comparison that separates a
 *  no-op re-import from a genuine update. Line endings and trailing
 *  whitespace differ freely between tools that emit the same cert. */
function normalizeArmor(armored: string): string {
  return armored.replace(/\r\n/g, "\n").trim();
}

/** Best-effort breakdown: a cert we can't decompose still previews from
 *  its KeyInfo, the subkey list simply doesn't render. */
async function safeDetails(armored: string): Promise<KeyDetails | null> {
  try {
    return await parseKeyDetails(armored);
  } catch {
    return null;
  }
}

/** Cheap change `detectImportOverwrite` can't see: it compares stored
 *  metadata, which records no subkeys. */
function subkeyChanges(
  incoming: KeyDetails | null,
  stored: KeyDetails | null,
): string[] {
  if (!incoming || !stored) return [];
  const known = new Set(stored.keys.map((k) => k.fingerprint));
  const added = incoming.keys.filter((k) => !known.has(k.fingerprint)).length;
  return added === 0 ? [] : [`${added} new subkey${added === 1 ? "" : "s"}`];
}

/**
 * Classify one parsed cert against what's already stored.
 *
 * `duplicate` means importing would change nothing -- same fingerprint
 * AND byte-identical public armor. Anything else sharing a fingerprint
 * is an `update`: the owner extended the expiry, added a user ID or
 * rotated a subkey, and the stored record should catch up.
 */
export async function classifyCert(
  keyInfo: KeyInfo,
  publicArmored: string,
  stored: StoredKey[],
): Promise<IncomingKey> {
  const kind: IncomingKey["kind"] = keyInfo.isPrivate ? "private" : "public";
  const details = await safeDetails(publicArmored);
  const base = {
    keyId: keyInfo.keyId,
    kind,
    userIds: keyInfo.userIds,
    info: keyInfo,
    details,
    securityWarning: keyInfo.securityWarning,
    publicArmored,
  };

  if (!isUsableContact(keyInfo)) {
    return {
      ...base,
      status: "rejected",
      changes: [],
      rejection: importRejectionMessage(keyInfo),
    };
  }

  const match = stored.find(
    (s) => s.keyId.toUpperCase() === keyInfo.keyId.toUpperCase(),
  );
  if (!match) return { ...base, status: "new", changes: [] };

  if (normalizeArmor(match.armored) === normalizeArmor(publicArmored)) {
    return {
      ...base,
      status: "duplicate",
      changes: [],
      existingAddedAt: match.addedAt ?? match.createdAt ?? null,
    };
  }

  const overwrite = detectImportOverwrite(keyInfo.keyId, stored, {
    expiresAt: keyInfo.expiresAt,
    userIds: keyInfo.userIds,
  });
  const changes = [
    ...(overwrite?.changes ?? []),
    ...subkeyChanges(details, await safeDetails(match.armored)),
  ];

  return {
    ...base,
    status: "update",
    // The fingerprint matched but nothing we display differs -- say that,
    // rather than showing an empty "what changed" list.
    changes: changes.length > 0 ? changes : ["The key has been re-issued"],
    existingAddedAt: overwrite?.addedAt ?? null,
  };
}

export interface PreparedImport {
  /** Every cert found, classified, in the order they appeared. */
  keys: IncomingKey[];
  /**
   * Private armor per fingerprint, for the keys that carry secret
   * material. Handed to the protect step and dropped with the panel --
   * it is deliberately NOT on IncomingKey, which flows into React state
   * and the preview component (see SECURITY.md's zeroization table).
   */
  secrets: Map<string, string>;
  /** The text carried no OpenPGP certificate at all. */
  unparseable: boolean;
}

/**
 * Classify every cert in a blob of armor.
 *
 * A single block may bundle several certs (publishers rotate keys
 * yearly); when a block has at least one usable cert its unusable
 * siblings are stale rotations, dropped rather than reported -- the same
 * rule `importPublicKeyBlocks` already applies.
 */
export async function prepareImport(
  text: string,
  stored: StoredKeys,
): Promise<PreparedImport> {
  let certs;
  try {
    certs = await parseKeys(text);
  } catch {
    return { keys: [], secrets: new Map(), unparseable: true };
  }
  if (certs.length === 0) {
    return { keys: [], secrets: new Map(), unparseable: true };
  }

  const secrets = new Map<string, string>();
  const classified: IncomingKey[] = [];

  for (const cert of certs) {
    // A private cert re-armors WITH its secret material, so the preview
    // never sees `cert.armored`: the public half is extracted for
    // display and comparison, and the secret half is parked in `secrets`
    // for the protect step alone.
    let publicArmored = cert.armored;
    if (cert.keyInfo.isPrivate) {
      try {
        publicArmored = await extractPublicKey(cert.armored);
      } catch {
        // Can't strip the secret half -- refuse to carry this cert
        // rather than risk private armor reaching the preview.
        continue;
      }
      secrets.set(cert.keyInfo.keyId, cert.armored);
    }
    classified.push(
      await classifyCert(
        cert.keyInfo,
        publicArmored,
        cert.keyInfo.isPrivate ? stored.own : stored.contacts,
      ),
    );
  }

  if (classified.length === 0) {
    return { keys: [], secrets, unparseable: true };
  }

  const usable = classified.filter((k) => k.status !== "rejected");
  return {
    // Rejects are kept only when there's nothing usable to show instead:
    // that's the case where the user needs to be told why.
    keys: usable.length > 0 ? usable : classified,
    secrets,
    unparseable: false,
  };
}

/** Nothing to do -- every key found is already stored, byte for byte.
 *  The panel is skipped in that case: the list just highlights what's
 *  already there. */
export function isNoOp(prepared: PreparedImport): boolean {
  return (
    prepared.keys.length > 0 &&
    prepared.keys.every((k) => k.status === "duplicate")
  );
}

/** The keys that actually write something when imported. */
export function importable(keys: IncomingKey[]): IncomingKey[] {
  return keys.filter((k) => k.status === "new" || k.status === "update");
}
