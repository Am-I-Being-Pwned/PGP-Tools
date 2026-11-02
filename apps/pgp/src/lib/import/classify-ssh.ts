import { LEGACY_PEM_ENCRYPTED } from "~/lib/armor-blocks";
import { t, tn } from "~/lib/i18n";
import type { SshRecipientInfo } from "~/lib/pgp/wasm";
import type { ContactRecipient } from "~/lib/storage/contacts";
import { stripInvisible } from "~/lib/utils/lookalike";
import { storedKeyIds, type StoredKey, type StoredKeys } from "./stored-keys";
import { PENDING_KEY_ID, type IncomingKey } from "./types";

/** A raw RSA private key PEM (CRX signing key). Never a PGP armored block, and
 *  never legacy `Proc-Type: 4,ENCRYPTED` (left for the age engine's message). */
export const RSA_PEM_RE = /-----BEGIN (?:RSA )?PRIVATE KEY-----/;
export function isRsaPrivatePem(text: string): boolean {
  return (
    RSA_PEM_RE.test(text) &&
    !text.includes("PGP") &&
    !text.includes(LEGACY_PEM_ENCRYPTED)
  );
}

/** A CRX signing key: nothing to parse, no fingerprint until import time, but
 *  still an IncomingKey so it takes the same preview -> protect path. */
export function crxSigningKey(): IncomingKey {
  return {
    keyId: PENDING_KEY_ID,
    kind: "crx",
    status: "new",
    info: null,
    details: null,
    // Not a real user ID: the preview headline.
    userIds: [t("import_crx_headline")],
    changes: [],
    publicArmored: "",
  };
}

// ── SSH (age engine) ─────────────────────────────────────────────────

/** An SSH public key: no certificate, so `info`/`details` are null; its
 *  comment becomes the display name. */
export function sshPublicKey(
  info: { fingerprint: string; recipient: string; comment: string },
  stored: StoredKeys,
): IncomingKey {
  const trimmed = cleanSshComment(info.comment);
  const base = {
    keyId: info.fingerprint,
    kind: "ssh-public" as const,
    info: null,
    details: null,
    userIds: trimmed ? [trimmed] : [t("import_ssh_headline")],
    changes: [],
    publicArmored: info.recipient,
  };
  // No `update` for SSH keys: same fingerprint is the same key. Never `new`
  // when the user already holds it anywhere (contact, group member, own key) --
  // a second record would hide the first in the picker or sit next to "You".
  const held = sshKeyHolders([info.fingerprint], stored);
  const holder = [...held.contacts, ...held.own].at(0);
  return holder
    ? {
        ...base,
        status: "duplicate",
        existingAddedAt: holder.addedAt ?? holder.createdAt ?? null,
      }
    : { ...base, status: "new" };
}

/** Longest SSH comment shown or compared, as the engine caps it. */
export const SSH_COMMENT_MAX = 120;

/** Strip control/invisible chars, trim, cap. Duplicates the engine's
 *  `sanitize_comment` on purpose: this attacker-supplied text becomes a
 *  contact name, so don't depend on the engine build. */
export function cleanSshComment(comment: string): string {
  const clean = stripInvisible(comment).trim();
  return [...clean].length > SSH_COMMENT_MAX
    ? `${[...clean].slice(0, SSH_COMMENT_MAX).join("")}\u2026`
    : clean;
}

/** Stored records (own keys, and contacts by ANY of their keys) holding any of
 *  `fingerprints`. Exact compare -- SSH fingerprints are case-sensitive base64. */
export function sshKeyHolders(
  fingerprints: readonly string[],
  stored: StoredKeys,
): { own: StoredKey[]; contacts: StoredKey[] } {
  const wanted = new Set(fingerprints);
  return {
    own: stored.own.filter((k) => wanted.has(k.keyId)),
    contacts: stored.contacts.filter((c) =>
      storedKeyIds(c).some((id) => wanted.has(id)),
    ),
  };
}

/** An OpenSSH private key: identity is only recovered inside wasm at the
 *  protect step, so it arrives as {@link PENDING_KEY_ID}. */
export function sshPrivateKey(): IncomingKey {
  return {
    keyId: PENDING_KEY_ID,
    kind: "ssh-private",
    status: "new",
    info: null,
    details: null,
    userIds: [t("import_ssh_private_headline")],
    changes: [],
    publicArmored: "",
  };
}

/** A `.pub` line the engine refuses, carrying the engine's own reason (never
 *  drop it silently). `keyId` is {@link PENDING_KEY_ID}. */
export function rejectedSshPublicKey(
  line: string,
  rejection: string,
): IncomingKey {
  return {
    keyId: PENDING_KEY_ID,
    kind: "ssh-public",
    status: "rejected",
    info: null,
    details: null,
    userIds: [t("import_ssh_headline")],
    changes: [],
    rejection,
    publicArmored: line.trim(),
  };
}

/** A private key format the age engine names and refuses. Nothing goes in `secrets`. */
export function rejectedSshPrivateKey(rejection: string): IncomingKey {
  return {
    keyId: PENDING_KEY_ID,
    kind: "ssh-private",
    status: "rejected",
    info: null,
    details: null,
    userIds: [t("import_ssh_private_headline")],
    changes: [],
    rejection,
    publicArmored: "",
  };
}

/** The canonical line wasm returned, never the pasted one. */
export function sshMember(info: SshRecipientInfo): ContactRecipient {
  return {
    keyId: info.fingerprint,
    armored: info.recipient,
    algorithm: info.algorithm,
  };
}

/**
 * The name several pasted keys AGREE on, or null: every line commented and
 * every comment byte-identical. Automatic grouping must never guess --
 * `root@web01` and `root@db02` may be two people encrypted to as one. When
 * they don't agree the user is asked ({@link PreparedImport.groupProposal}).
 */
export function sharedComment(
  parsed: readonly SshRecipientInfo[],
): string | null {
  const first = parsed[0] ? cleanSshComment(parsed[0].comment) : "";
  if (!first) return null;
  return parsed.every((i) => cleanSshComment(i.comment) === first)
    ? first
    : null;
}

/**
 * Several SSH public keys as ONE incoming {@link ContactGroup}, the same shape
 * a GitHub lookup produces. No `source`: hand-supplied.
 *
 * A group is never `new` over a key the user holds (a pasted file pairing
 * Alice's key with Mallory's must not take Alice over, nor hide her or "You"):
 *
 *  - every key already saved -> `duplicate`.
 *  - changes the keys of ONE hand-supplied contact sharing its id -> `update`
 *    of that record; `withIdentityConflicts` marks it, so it starts on Skip.
 *  - otherwise -> new, headed by a key NOBODY holds; also marked (and Skip)
 *    when it carries a held key.
 */
export function sshGroupKey(
  label: string,
  members: ContactRecipient[],
  stored: StoredKeys,
): IncomingKey {
  const base = {
    kind: "ssh-public" as const,
    info: null,
    details: null,
    userIds: [label],
  };
  const group = (list: ContactRecipient[]) => ({
    ...base,
    // Also the stored record's id, which is why the head is CHOSEN below.
    keyId: list[0].keyId,
    publicArmored: list[0].armored,
    group: { label, members: list, rejected: [] },
  });

  const ids = members.map((m) => m.keyId);
  const held = sshKeyHolders(ids, stored);
  const heldIds = new Set([
    ...held.own.map((k) => k.keyId),
    ...held.contacts.flatMap(storedKeyIds),
  ]);

  if (held.contacts.length === 1 && held.own.length === 0) {
    const [record] = held.contacts;
    const before = new Set(storedKeyIds(record));
    const after = new Set(ids);
    const added = ids.filter((id) => !before.has(id)).length;
    const removed = [...before].filter((id) => !after.has(id)).length;
    if (added === 0 && removed === 0) {
      return {
        ...group(members),
        status: "duplicate",
        changes: [],
        existingAddedAt: record.addedAt ?? null,
      };
    }
    // Only a hand-supplied record, through its own id (a paste never replaces a
    // fetched person -- see `upsertContacts`).
    const head = record.source
      ? undefined
      : members.find((m) => m.keyId === record.keyId);
    if (head) {
      return {
        ...group([head, ...members.filter((m) => m !== head)]),
        status: "update",
        changes: [
          ...(added > 0 ? [tn("import_change_keys_added", added)] : []),
          ...(removed > 0 ? [tn("import_change_keys_removed", removed)] : []),
        ],
        existingAddedAt: record.addedAt ?? null,
      };
    }
  }

  const fresh = members.filter((m) => !heldIds.has(m.keyId));
  if (fresh.length === 0) {
    return {
      ...group(members),
      status: "duplicate",
      changes: [],
      existingAddedAt: null,
    };
  }
  return {
    ...group([...fresh, ...members.filter((m) => heldIds.has(m.keyId))]),
    status: "new",
    changes: [],
  };
}
