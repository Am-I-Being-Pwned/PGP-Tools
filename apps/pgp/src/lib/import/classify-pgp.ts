import { t, tn } from "~/lib/i18n";
import { detectImportOverwrite } from "~/lib/import-overwrite";
import {
  importRejectionMessage,
  isUsableContact,
  mergeIntoStored,
} from "~/lib/import-public-keys";
import type { KeyDetails, KeyInfo } from "~/lib/pgp/types";
import { parseKeyDetails, parseKeys } from "~/lib/pgp/wasm";
import type { StoredKey } from "./stored-keys";
import { PENDING_KEY_ID, type IncomingKey } from "./types";

/** Line endings and trailing whitespace differ freely between tools emitting the same cert. */
function normalizeArmor(armored: string): string {
  return armored.replace(/\r\n/g, "\n").trim();
}

async function safeDetails(armored: string): Promise<KeyDetails | null> {
  try {
    return await parseKeyDetails(armored);
  } catch {
    return null;
  }
}

async function safeInfo(armored: string): Promise<KeyInfo | null> {
  try {
    return (await parseKeys(armored))[0]?.keyInfo ?? null;
  } catch {
    return null;
  }
}

/** Subkey changes, which `detectImportOverwrite` can't see (stored metadata has no subkeys). */
function subkeyChanges(
  incoming: KeyDetails | null,
  stored: KeyDetails | null,
): string[] {
  if (!incoming || !stored) return [];
  const known = new Set(stored.keys.map((k) => k.fingerprint));
  const added = incoming.keys.filter((k) => !known.has(k.fingerprint)).length;
  return added === 0 ? [] : [tn("import_change_new_subkeys", added)];
}

/** `duplicate` = same fingerprint AND byte-identical public armor; anything
 *  else sharing a fingerprint is an `update`. */
export async function classifyCert(
  incomingInfo: KeyInfo,
  incomingArmored: string,
  stored: StoredKey[],
): Promise<IncomingKey> {
  const match = stored.find(
    (s) => s.keyId.toUpperCase() === incomingInfo.keyId.toUpperCase(),
  );
  // A held contact takes the MERGE of both copies, never the incoming one
  // verbatim: an old copy can't undo a revocation. Own keys are left alone --
  // their secret half is the incoming cert.
  let keyInfo = incomingInfo;
  let publicArmored = incomingArmored;
  if (match && !incomingInfo.isPrivate) {
    try {
      const merged = await mergeIntoStored(match, incomingArmored);
      keyInfo = merged.keyInfo;
      publicArmored = merged.armored;
    } catch {
      // The stored armor no longer parses; fall back to the old path.
    }
  }

  const kind: IncomingKey["kind"] = keyInfo.isPrivate
    ? "pgp-private"
    : "pgp-public";
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

  if (!match && !isUsableContact(keyInfo)) {
    return {
      ...base,
      status: "rejected",
      changes: [],
      rejection: importRejectionMessage(keyInfo),
    };
  }
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
  const storedInfo = await safeInfo(match.armored);
  const changes = [
    ...(keyInfo.revoked && !storedInfo?.revoked
      ? [t("import_change_revoked")]
      : []),
    ...(overwrite?.changes ?? []),
    ...subkeyChanges(details, await safeDetails(match.armored)),
  ];

  return {
    ...base,
    status: "update",
    changes: changes.length > 0 ? changes : [t("import_change_reissued")],
    existingAddedAt: overwrite?.addedAt ?? null,
  };
}

export function revocationForUnknownKey(): IncomingKey {
  return {
    keyId: PENDING_KEY_ID,
    kind: "pgp-public",
    status: "rejected",
    info: null,
    details: null,
    userIds: [t("import_revocation_headline")],
    changes: [],
    rejection: t("import_reject_revocation_unknown"),
    publicArmored: "",
  };
}
