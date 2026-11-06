import { t } from "~/lib/i18n";
import { identityConflict, type IdentityHolder } from "~/lib/identity/binding";
import { sameSource } from "~/lib/storage/contacts";
import { sshKeyHolders } from "./classify-ssh";
import type { StoredKey, StoredKeys } from "./stored-keys";
import { isSecretKind, PENDING_KEY_ID, type IncomingKey } from "./types";

/**
 * Mark every key whose import would bind it to an identity someone else holds
 * (same address, or a lookalike name); the import screen won't save a marked
 * key without a user decision. New keys are checked on all User IDs, updates
 * only on the ones they ADD. Checked against stored keys and every other new
 * key in the import, both ways -- coming first doesn't make a key "real".
 *
 * SSH keys are checked on their comment / group label, and an SSH key or group
 * carrying a key the user already holds is marked `kind: "key"`.
 *
 * Private (and backup CRX) keys become the user's OWN keys: checked against
 * contacts and the import, and against own keys only for a LOOKALIKE (same
 * name and address is a rotation).
 */
export function withIdentityConflicts(
  keys: IncomingKey[],
  stored: StoredKeys,
): IncomingKey[] {
  const holder = (k: StoredKey, own: boolean): IdentityHolder => ({
    keyId: k.keyId,
    userIds: k.userIds,
    ...(k.alias ? { alias: k.alias } : {}),
    ...(k.revoked ? { revoked: true } : {}),
    ...(own ? { own: true } : {}),
  });
  const isNew = (k: IncomingKey) =>
    (k.kind === "pgp-public" || k.kind === "ssh-public") && k.status === "new";
  const isNewSecret = (k: IncomingKey) =>
    isSecretKind(k.kind) &&
    k.status === "new" &&
    k.keyId !== PENDING_KEY_ID &&
    claimedIds(k).length > 0;
  // Only new keys join the holders; a new private key joins as the user's own
  // (a CRX label names an extension, so it holds nothing).
  const holders: IdentityHolder[] = [
    ...stored.contacts.map((k) => holder(k, false)),
    ...stored.own.map((k) => holder(k, true)),
    ...keys.filter(isNew).map((k) => ({
      keyId: k.keyId,
      userIds: claimedIds(k),
      incoming: true as const,
      ...(k.info?.revoked ? { revoked: true } : {}),
    })),
    ...keys
      .filter((k) => isNewSecret(k) && k.kind !== "crx")
      .map((k) => ({
        keyId: k.keyId,
        userIds: claimedIds(k),
        incoming: true as const,
        own: true as const,
      })),
  ];
  return keys.map((key) => {
    if (isNewSecret(key)) return withSecretConflict(key, holders);
    if (key.kind !== "pgp-public" && key.kind !== "ssh-public") return key;
    if (key.status !== "new" && key.status !== "update") return key;

    const source = key.group?.source ?? key.source;
    // The record an update refreshes isn't a rival. Never for a NEW key: a
    // re-fetch returning a different key is exactly the change that must ask.
    const self = (c: StoredKey) =>
      key.status === "update" &&
      (source
        ? sameSource(c, { source })
        : c.keyId.toUpperCase() === key.keyId.toUpperCase());

    if (key.kind === "ssh-public") {
      const held = sshKeyHolders(
        key.group ? key.group.members.map((m) => m.keyId) : [key.keyId],
        stored,
      );
      // A paste adding keys to a contact names that contact: the update IS the
      // claim. Holders are named by the user's alias when there is one.
      const rivals = [
        ...held.own.map((k) => holder(k, true)),
        ...held.contacts
          .filter((c) => !(source && sameSource(c, { source })))
          .map((c) => holder(c, false)),
      ];
      if (rivals.length > 0) {
        return { ...key, conflict: { kind: "key", holders: rivals } };
      }
    }

    let userIds = claimedIds(key);
    if (key.status === "update") {
      const before = new Set(
        stored.contacts.filter(self).flatMap((c) => c.userIds),
      );
      userIds = userIds.filter((u) => !before.has(u));
    }
    if (userIds.length === 0) return key;
    const conflict = identityConflict(
      { keyId: key.keyId, userIds },
      holders.filter(
        (h) =>
          !stored.contacts.some(
            (c) => c.keyId === h.keyId && !h.own && !h.incoming && self(c),
          ),
      ),
      { includeRevoked: true },
    );
    return conflict ? { ...key, conflict } : key;
  });
}

/** Private/CRX key conflicts: own keys only count when it LOOKS like theirs
 *  without being it. */
function withSecretConflict(
  key: IncomingKey,
  holders: readonly IdentityHolder[],
): IncomingKey {
  const claim = { keyId: key.keyId, userIds: claimedIds(key) };
  const others = holders.filter((h) => !h.own);
  const own = holders.filter((h) => h.own);
  const theirs = identityConflict(claim, others, { includeRevoked: true });
  if (theirs) return { ...key, conflict: theirs };
  const mine = identityConflict(claim, own);
  const lookalike =
    mine &&
    (mine.kind === "address" ? mine.lookalike === true : !mine.sameName);
  return lookalike ? { ...key, conflict: mine } : key;
}

/** The identity an incoming key claims: User IDs, or SSH comment / group
 *  label. Never the app's placeholder headlines, which every such key would "share". */
export function claimedIds(key: IncomingKey): string[] {
  if (key.kind === "crx")
    return key.userIds.filter((u) => u !== t("import_crx_headline"));
  if (key.kind === "ssh-private")
    return key.userIds.filter((u) => u !== t("import_ssh_private_headline"));
  if (key.kind !== "ssh-public" || key.group) return key.userIds;
  return key.userIds.filter((u) => u !== t("import_ssh_headline"));
}
