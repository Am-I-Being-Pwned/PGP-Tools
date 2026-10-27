import type { IdentityHolder } from "../identity/binding";
import type { KeyDetails, KeyInfo } from "../pgp/types";
import type { SshRecipientInfo } from "../pgp/wasm";
import type {
  ContactRecipient,
  ContactSource,
  PublicContactKey,
} from "../storage/contacts";
import type { ProtectedKeyBlob } from "../storage/keyring";
import type { IncomingKey } from "./types";
import {
  LEGACY_PEM_ENCRYPTED,
  looksLikeForeignSshPrivateKey,
  splitSshPrivateKeyBlocks,
  splitSshPublicKeyCandidateLines,
} from "../armor-blocks";
import { t, tn } from "../i18n";
import { identityConflict } from "../identity/binding";
import { detectImportOverwrite } from "../import-overwrite";
import {
  applyRevocation,
  importRejectionMessage,
  isUsableContact,
  mergeIntoStored,
} from "../import-public-keys";
import {
  extractPublicKey,
  mergePublicKey,
  parseKeyDetails,
  parseKeys,
  parseSshRecipient,
  sshPrivateKeyFormatRejection,
} from "../pgp/wasm";
import { contactRecipients } from "../storage/contact-recipients";
import { sameSource } from "../storage/contacts";
import { stripInvisible } from "../utils/lookalike";
import { isSecretKind, PENDING_KEY_ID } from "./types";

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
  /** Where a fetched contact came from; absent when hand-supplied. */
  source?: ContactSource;
  /** A revoked key no longer holds its address (see identity/binding). */
  revoked?: boolean;
  /** Every key a contact record holds, when it holds more than one (a
   *  GitHub person, a pasted group): `contactRecipients(c)`'s
   *  fingerprints. Absent means just `keyId`. An SSH import is checked
   *  against every one of them -- a key already saved inside someone's
   *  group is a key the user already holds. */
  recipientIds?: string[];
  /** The local name the user gave it (`PublicContactKey.alias`, a
   *  key's alias): how a conflict names the person whose keys an import
   *  would change, and one more name an import is compared against --
   *  a comment-less SSH contact the user called "Alice" has no other. */
  alias?: string;
}

export interface StoredKeys {
  /** The user's own keys (keyring), matched against private imports. */
  own: StoredKey[];
  /** Contacts, matched against public imports. */
  contacts: StoredKey[];
}

/**
 * The keyring and contacts in the shape every `prepare*` entry point
 * takes. One builder, so the import panel and the backup restore
 * classify against the same facts -- the restore used to pass no own
 * keys at all, so a backup key wearing the user's own name or address
 * was never flagged.
 */
export function storedKeysFrom(
  own: readonly ProtectedKeyBlob[],
  contacts: readonly PublicContactKey[],
): StoredKeys {
  return {
    own: own.map((k) => ({
      keyId: k.keyId,
      userIds: k.userIds,
      armored: k.publicKeyArmored,
      createdAt: k.createdAt,
      ...(k.alias ? { alias: k.alias } : {}),
    })),
    contacts: contacts.map((c) => ({
      keyId: c.keyId,
      userIds: c.userIds,
      armored: c.armoredPublicKey,
      addedAt: c.addedAt,
      expiresAt: c.expiresAt,
      ...(c.source ? { source: c.source } : {}),
      ...(c.revoked ? { revoked: true } : {}),
      // Every key on the record, not just its head: an SSH import is
      // checked against all of them (see `sshKeyHolders`).
      ...(c.recipients
        ? { recipientIds: contactRecipients(c).map((r) => r.keyId) }
        : {}),
      ...(c.alias ? { alias: c.alias } : {}),
    })),
  };
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

/** The stored cert's KeyInfo, to tell what an update changes. */
async function safeInfo(armored: string): Promise<KeyInfo | null> {
  try {
    return (await parseKeys(armored))[0]?.keyInfo ?? null;
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
  return added === 0 ? [] : [tn("import_change_new_subkeys", added)];
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
  incomingInfo: KeyInfo,
  incomingArmored: string,
  stored: StoredKey[],
): Promise<IncomingKey> {
  const match = stored.find(
    (s) => s.keyId.toUpperCase() === incomingInfo.keyId.toUpperCase(),
  );
  // A contact we already hold takes the MERGE of both copies, never the
  // incoming one verbatim: an old copy can't undo a revocation or bring
  // back a revoked subkey, and a revoked copy revokes the contact rather
  // than being turned away while the stale copy stays live. Own keys
  // (private imports) are left as they were -- their secret half is the
  // incoming cert, and the user is the one who revokes them.
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
    // The fingerprint matched but nothing we display differs -- say that,
    // rather than showing an empty "what changed" list.
    changes: changes.length > 0 ? changes : [t("import_change_reissued")],
    existingAddedAt: overwrite?.addedAt ?? null,
  };
}

/** A revocation certificate for a key the user doesn't hold: nothing to
 *  apply it to, and worth saying so rather than "not a key". */
function revocationForUnknownKey(): IncomingKey {
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

/**
 * Which non-OpenPGP engines this import accepts.
 *
 * A disabled engine is not merely refused, it is not recognised: its key
 * falls through to the OpenPGP parse and comes back `unparseable`, which
 * is exactly what the panel showed before the engine existed. That is why
 * the flag lives here rather than in the panel -- the classifier is the
 * one place that decides what a blob of text IS.
 */
export interface ImportEngines {
  /** RSA signing keys for Chrome extensions (.crx). */
  crx?: boolean;
  /** OpenSSH keys, used with age: `.pub` recipient lines and OpenSSH
   *  private key containers. */
  ssh?: boolean;
}

/** A raw RSA private key PEM (PKCS#8 or PKCS#1) -- a CRX signing key, not
 *  OpenPGP. Matched only when it is NOT a PGP armored block, so a PGP
 *  private key that happens to mention the phrase can't be mistaken for
 *  one -- and not when the PEM is encrypted with the legacy
 *  `Proc-Type: 4,ENCRYPTED` scheme, which `parse_rsa_private_pem` cannot
 *  read either: claiming it here only replaced the age engine's "convert
 *  it with `ssh-keygen -p -f`" with a generic CRX parse failure. */
const RSA_PEM_RE = /-----BEGIN (?:RSA )?PRIVATE KEY-----/;
function isRsaPrivatePem(text: string): boolean {
  return (
    RSA_PEM_RE.test(text) &&
    !text.includes("PGP") &&
    !text.includes(LEGACY_PEM_ENCRYPTED)
  );
}

/**
 * The CRX signing key as the rest of the flow sees it.
 *
 * There is nothing to parse: no certificate, no user IDs, no dates, and
 * no fingerprint until the extension ID is derived at import time. It is
 * still an IncomingKey so it gets the same source -> preview -> protect
 * path as everything else -- the preview simply has less to show, which
 * is a rendering question (see KeyFacts) rather than a second flow.
 */
function crxSigningKey(): IncomingKey {
  return {
    keyId: PENDING_KEY_ID,
    kind: "crx",
    status: "new",
    info: null,
    details: null,
    // Not a real user ID -- the preview's headline, for a key that
    // carries no identity of its own.
    userIds: [t("import_crx_headline")],
    changes: [],
    publicArmored: "",
  };
}

// ── SSH (age engine) ─────────────────────────────────────────────────

/**
 * An SSH key as the rest of the flow sees it.
 *
 * There is nothing certificate-shaped to parse: no user IDs, no created
 * date, no expiry, no subkeys -- so `info` and `details` are null, the
 * CRX precedent for an engine whose keys carry no certificate. What an
 * SSH key does carry is a free-text comment (`ssh-keygen` writes
 * `user@host`), which becomes the display name.
 */
function sshPublicKey(
  info: { fingerprint: string; recipient: string; comment: string },
  stored: StoredKeys,
): IncomingKey {
  const trimmed = cleanSshComment(info.comment);
  const base = {
    keyId: info.fingerprint,
    kind: "ssh-public" as const,
    info: null,
    details: null,
    // Not a real user ID -- the preview's headline, for a key that
    // carries no identity beyond its comment.
    userIds: trimmed ? [trimmed] : [t("import_ssh_headline")],
    changes: [],
    publicArmored: info.recipient,
  };
  // No `update` state for an SSH key: the recipient line is canonical and
  // carries nothing that can change -- no expiry to extend, no user ID to
  // add, no subkey to rotate. Same fingerprint means the same key, so
  // re-importing it is always a no-op.
  //
  // Wherever the user already holds it: as a contact of its own, as one
  // of a group's keys, or as one of their OWN keys. Never `new` in any of
  // those cases -- a second record for a key the user has would either
  // hide behind the first in the recipient picker or (an own key) sit
  // next to "You" under somebody else's name, and the comment that names
  // it is whatever the file says.
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
const SSH_COMMENT_MAX = 120;

/**
 * A key comment as the import uses it: invisible and control characters
 * out, trimmed, capped. The engine already does this (`sanitize_comment`
 * in `gpg-wasm/src/age.rs`); it is repeated here because the comment is
 * attacker-supplied text that becomes a contact's name, and one cheap
 * pass is worth not depending on which build of the engine produced it.
 */
function cleanSshComment(comment: string): string {
  const clean = stripInvisible(comment).trim();
  return [...clean].length > SSH_COMMENT_MAX
    ? `${[...clean].slice(0, SSH_COMMENT_MAX).join("")}\u2026`
    : clean;
}

/** Every key fingerprint a stored record holds. */
function storedKeyIds(record: StoredKey): string[] {
  return record.recipientIds && record.recipientIds.length > 0
    ? record.recipientIds
    : [record.keyId];
}

/**
 * Which stored records already hold any of `fingerprints`: the user's own
 * keys, and every contact holding one of them as ANY of its keys (not
 * just its head). Compared exactly -- an SSH fingerprint is base64, so
 * case is part of it.
 */
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

/**
 * An OpenSSH private key. Like a CRX signing key, its identity is only
 * recovered inside the protect step -- the fingerprint lives in the
 * key file, which may be passphrase-encrypted and is in any case never
 * parsed outside wasm -- so it arrives as {@link PENDING_KEY_ID} with no
 * public half to preview.
 */
function sshPrivateKey(): IncomingKey {
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

/**
 * A `.pub` line the engine refuses, carrying the engine's own reason.
 *
 * The OpenPGP path has said why a key is unusable since it existed
 * (`importRejectionMessage`); this is the same contract for the age
 * engine. Its messages are more actionable still -- each names the key
 * type and the `ssh-keygen` command that fixes it -- so dropping the line
 * silently, as this loop used to, replaced the one thing worth saying
 * with "that doesn't look like a key".
 *
 * `keyId` is {@link PENDING_KEY_ID}: the fingerprint is computed inside
 * wasm from a blob it just refused, so there is none to report -- the same
 * position a CRX signing key is in before its extension id is derived.
 */
function rejectedSshPublicKey(line: string, rejection: string): IncomingKey {
  return {
    keyId: PENDING_KEY_ID,
    kind: "ssh-public",
    status: "rejected",
    info: null,
    details: null,
    userIds: [t("import_ssh_headline")],
    changes: [],
    rejection,
    // The line as pasted: unusable as a recipient, but it is what the
    // user is being told about, so the preview can still show it.
    publicArmored: line.trim(),
  };
}

/** A private key file in a format the age engine names and refuses --
 *  PuTTY `.ppk`, PKCS#8, legacy encrypted PEM. Nothing is parsed and
 *  nothing is carried in `secrets`: it is rejected, not imported. */
function rejectedSshPrivateKey(rejection: string): IncomingKey {
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

/** One parsed `.pub` line as a member of a contact. The canonical line
 *  wasm returned, never the pasted one -- that is what gets stored and
 *  what the engine expects back as a recipient. */
function sshMember(info: SshRecipientInfo): ContactRecipient {
  return {
    keyId: info.fingerprint,
    armored: info.recipient,
    algorithm: info.algorithm,
  };
}

/**
 * The name several pasted keys AGREE they belong to, or null.
 *
 * The automatic grouping rule, and deliberately the strictest one that
 * can exist: every line must carry a comment and every comment must be
 * byte-identical. Anything looser is a guess -- `root@web01` and
 * `root@db02` share a user and nothing else, and folding them into one
 * contact silently makes two machines (quite possibly two people) a
 * single identity that is then encrypted to as one. Automatic grouping
 * must never guess; when the comments do not agree, the user is asked
 * instead (see {@link PreparedImport.groupProposal}).
 */
function sharedComment(parsed: readonly SshRecipientInfo[]): string | null {
  const first = parsed[0] ? cleanSshComment(parsed[0].comment) : "";
  if (!first) return null;
  return parsed.every((i) => cleanSshComment(i.comment) === first)
    ? first
    : null;
}

/**
 * Several SSH public keys as ONE incoming contact.
 *
 * The same {@link ContactGroup} a GitHub lookup produces, so the preview,
 * the facts card and `groupContact` all work on it unchanged -- and so a
 * hand-grouped contact reaches storage in exactly the shape a fetched one
 * does. No `source`: a pasted group is hand-supplied, and absent is what
 * that means on the stored record too.
 *
 * What it is depends on which of its keys the user ALREADY holds, and
 * this is where a pasted file used to take a contact over. A `.pub` file
 * pairing Alice's real key with Mallory's under the comment
 * `alice@laptop` was a "new" contact whose id was Alice's key -- so on
 * save it upserted over Alice, kept the name the user gave her, and from
 * then on "Alice" encrypted to Mallory too. With Mallory's key first, it
 * was a second contact holding Alice's key, and the picker hid the real
 * Alice behind it. With the user's OWN key in it, the picker hid "You".
 * So a group is never `new` over a key the user holds:
 *
 *  - every key already saved -> `duplicate`. Nothing new to write, and
 *    grouping keys that sit on different records would merge people.
 *  - adds to (or drops from) the keys of ONE hand-supplied contact that
 *    it shares that contact's id with -> an `update` of that record,
 *    headed by its id so the save lands on it, with "N keys added" said.
 *    `withIdentityConflicts` marks it, so it starts on Skip.
 *  - otherwise -> a new record, headed by a key NOBODY holds, so it can
 *    never replace (or share an id with) a contact or an own key. Also
 *    marked when it carries a held key, and also starts on Skip.
 *
 * There is still no `update` for a group whose keys are unchanged: a
 * recipient line carries nothing that can change.
 */
function sshGroupKey(
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
    // The head member's, so every path that reads an IncomingKey's
    // identity -- the preview, the highlight-after-import, the map key --
    // works on a group without knowing it is one. It is also the stored
    // record's id, which is why the head is CHOSEN below.
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
    // Only a hand-supplied record, and only through its own id: that is
    // the one record the save will land on (a fetched person is never
    // replaced by a paste -- see `upsertContacts`).
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
    // Every key is already the user's or a contact's. Nothing is new, and
    // there is no id this record could take that is not someone else's.
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

/** The headline for a group the user has not named yet. Never stored:
 *  leaving the name blank imports the keys separately instead. */
function proposalLabel(count: number): string {
  return tn("import_group_proposal_label", count);
}

/** The message an engine threw, or a last-resort generic. Engine errors
 *  are already user-facing prose (see `gpg-wasm/src/age.rs`), so they are
 *  surfaced verbatim rather than re-worded here.
 *
 *  Exported for `github.ts`, which refuses fetched lines through the
 *  same engine and must report them in the same words -- two copies of
 *  this would be two wordings for one refusal. */
export function engineRejection(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.trim() || t("import_reject_ssh_generic");
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
  /**
   * The same keys as `keys`, offered as ONE contact under a name the
   * user supplies.
   *
   * Present only when several pasted SSH public keys did NOT auto-group
   * (see {@link sharedComment}) and every one of them is new. A
   * self-hosting friend's three keys, commented `alice@laptop`,
   * `alice@desktop` and not at all, are one person -- but nothing in the
   * text says so, and the import must not decide it. So both readings
   * are carried: `keys` is what importing them separately produces
   * (today's behaviour, and what a blank name still means), and this is
   * what grouping them produces. Its `group.label` is a placeholder for
   * the preview headline; the user's name replaces it before anything is
   * stored.
   */
  groupProposal?: IncomingKey;
}

/**
 * Classify every cert in a blob of armor.
 *
 * A single block may bundle several certs (publishers rotate keys
 * yearly); when a block has at least one usable cert its unusable
 * siblings are stale rotations, dropped rather than reported.
 *
 * This is the ONE place that decides what pasted text is. Every engine
 * is recognised here and returns an IncomingKey, so the panel routes a
 * CRX signing key exactly as it routes an OpenPGP cert -- an engine
 * added by short-circuiting the panel instead would be a third flow to
 * keep in step with the other two.
 */
export async function prepareImport(
  text: string,
  stored: StoredKeys,
  engines: ImportEngines = {},
): Promise<PreparedImport> {
  const prepared = await classifyImport(text, stored, engines);
  return { ...prepared, keys: withIdentityConflicts(prepared.keys, stored) };
}

/**
 * Mark every public key whose import would bind it to an identity
 * someone else holds -- a contact's or the user's own address, or a
 * name that reads the same. A new key is checked on all its User IDs;
 * an update only on the ones it ADDS (a key the user already has can
 * still pick up someone else's name). Checked against the stored keys
 * and every other new key in this import, both ways: in a bundle
 * carrying two keys for one address, neither is the "real" one by
 * virtue of coming first. The import screen will not save a marked key
 * without the user choosing what to do with it.
 *
 * SSH keys are checked the same way, on their comment (or a group's
 * label): it is the contact's name, it is whatever the file says, and
 * `alice@corp.com` as a comment claims that address as plainly as a
 * User ID does. And first, an SSH key or group that carries a key the
 * user ALREADY holds is marked `kind: "key"` (see `sshGroupKey` for why
 * that is how a contact used to be taken over).
 *
 * A private key (and a backup's CRX key, by its label) is checked too:
 * saved, it becomes one of the user's OWN keys, and a key named as a
 * contact -- or as a lookalike of the user -- went in silently. It is
 * checked against contacts and the other keys in the import like any
 * key, and against the user's own keys only for a LOOKALIKE: a new key
 * of theirs sharing their name and address is how a rotation looks.
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
  // An update or a duplicate is already here as its stored record, and a
  // rejected key will not be saved: only new keys join the holders. A
  // new private key joins as one of the user's own (a CRX key's label
  // names an extension, not a person, so it holds nothing).
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
    // The record this import refreshes, when it is an update: a fetched
    // person by its lookup, anything else by its id. Its own name is not
    // a rival. Never for a NEW key: one from the same lookup (a keyserver
    // re-fetch that came back with a different key) is exactly the
    // identity change that must still ask.
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
      // A paste that adds keys to a contact names that contact: the
      // update IS the claim. A refresh of a fetched person does not, for
      // the keys its own lookup returned. Holders are named as the user
      // knows them: by the alias they gave, when there is one (a single
      // SSH key saved before it kept its comment has no name at all).
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

/**
 * A private or CRX key's conflict (see `withIdentityConflicts`): with a
 * contact or another key in the import, as any key; with the user's own
 * keys only when it LOOKS like theirs without being it -- the same
 * address or name as one of theirs is their next key.
 */
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

/**
 * The identity an incoming key claims: its User IDs, or an SSH key's
 * comment / a group's label. Not the "SSH key" headline a comment-less
 * line is shown under -- that is the app's placeholder, not a claim, and
 * every such key would otherwise "share" it. Nor the headline a key
 * with no identity of its own is shown under (a CRX key, an OpenSSH
 * private key before it is read).
 */
export function claimedIds(key: IncomingKey): string[] {
  if (key.kind === "crx")
    return key.userIds.filter((u) => u !== t("import_crx_headline"));
  if (key.kind === "ssh-private")
    return key.userIds.filter((u) => u !== t("import_ssh_private_headline"));
  if (key.kind !== "ssh-public" || key.group) return key.userIds;
  return key.userIds.filter((u) => u !== t("import_ssh_headline"));
}

async function classifyImport(
  text: string,
  stored: StoredKeys,
  engines: ImportEngines,
): Promise<PreparedImport> {
  // Recognised before the OpenPGP parse, which would only fail on it.
  // The PEM is secret material, so it travels in `secrets` like any
  // other private half -- never on the IncomingKey.
  //
  // Before the SSH branch too, and that ordering settles the one overlap
  // between the engines: a plain `-----BEGIN PRIVATE KEY-----` is both
  // valid PKCS#8 and a valid CRX signing key, and CRX is the engine that
  // can actually use it. With CRX off it falls through and the age
  // engine names it (`MSG_PKCS8`) instead.
  if (engines.crx && isRsaPrivatePem(text)) {
    return {
      keys: [crxSigningKey()],
      secrets: new Map([[PENDING_KEY_ID, text.trim()]]),
      unparseable: false,
    };
  }

  if (engines.ssh) {
    // Private first: an OpenSSH container carries the public half inside
    // its body, so checking the public form first would be checking the
    // wrong thing about the same file.
    const [sshPrivate] = splitSshPrivateKeyBlocks(text);
    if (sshPrivate) {
      return {
        keys: [sshPrivateKey()],
        secrets: new Map([[PENDING_KEY_ID, sshPrivate]]),
        unparseable: false,
      };
    }

    // Recognised but refused: PuTTY `.ppk`, PKCS#8, legacy encrypted PEM.
    // The engine has a specific message for each; asked here, before a
    // password is chosen, rather than at the protect step.
    if (looksLikeForeignSshPrivateKey(text)) {
      // `text` here can be a COMPLETE unencrypted private key file -- a
      // PKCS#8 `-----BEGIN PRIVATE KEY-----` reaches this branch whenever
      // the CRX engine is off. The bytes handed across the wasm boundary
      // are therefore held in a named binding and `.fill(0)`'d in a
      // `finally`, the same contract every other secret-bearing call site
      // in this app keeps (`lib/age/protect-flow.ts`,
      // `lib/protection/protect-runner.ts`). The Rust side owns and wipes
      // its own copy (`Zeroizing` in `ssh_private_key_format_rejection`);
      // this scrubs OURS, which nothing else would.
      //
      // Honestly: `text` is itself an immutable JS string and cannot be
      // zeroized, so this removes one additional plaintext copy from the
      // heap rather than eliminating the exposure. Taking bytes instead of
      // a string all the way into `prepareImport` is the only way to close
      // it, and that is a caller-wide refactor, not this call site.
      const keyFile = new TextEncoder().encode(text);
      let rejection: string | null;
      try {
        rejection = await sshPrivateKeyFormatRejection(keyFile);
      } finally {
        keyFile.fill(0);
      }
      if (rejection) {
        return {
          keys: [rejectedSshPrivateKey(rejection)],
          secrets: new Map(),
          unparseable: false,
        };
      }
    }

    // The CANDIDATE splitter, not the narrow one: any
    // `<algorithm> AAAA<base64>` line, whatever the algorithm calls
    // itself. The narrow form matches `ssh-ed25519|ssh-rsa` only, so an
    // ECDSA / FIDO `sk-*` / `ssh-dss` `.pub` was never split out here at
    // all -- it fell through to the OpenPGP parse and came back
    // `unparseable`, which is the panel's "that doesn't look like a key"
    // standing in for three of the engine's eight curated refusals.
    //
    // Fourth instance of one pattern. A `catch { continue }` in this loop
    // swallowed five of those messages; `github/response.ts` filtered the
    // rest out of the fetch path; `splitSshPublicKeyLines` withheld the
    // remaining three from the paste path. The invariant, stated once:
    // THE ENGINE DECIDES VALIDITY; EVERY LAYER ABOVE IT FORWARDS AND
    // DISPLAYS. Shape is all that is checked here -- `parseSshRecipient`
    // says whether a line is usable, and a line it refuses becomes a
    // `rejected` IncomingKey carrying its words.
    //
    // Widening the shape widens routing with it: `classify-action.ts` and
    // `drop-routing.ts` use the same splitter, so a pasted ECDSA `.pub`
    // reaches this function instead of stopping at a route that never
    // opens the import flow.
    const lines = splitSshPublicKeyCandidateLines(text);
    if (lines.length > 0) {
      const keys: IncomingKey[] = [];
      // The parsed form of every line that was accepted, kept alongside
      // the IncomingKeys because a group is assembled from the engine's
      // own output (fingerprint, canonical line, algorithm) -- none of
      // which an ssh-public IncomingKey carries in a form worth
      // re-deriving.
      const parsed: SshRecipientInfo[] = [];
      for (const line of lines) {
        try {
          // The wasm parse is what makes the line canonical; a line it
          // refuses is never stored as a recipient the engine would later
          // reject -- but it IS reported, with the engine's own reason.
          const info = await parseSshRecipient(line);
          // Deduplicated on the fingerprint, as `prepareGithubImport`
          // does: the same line pasted twice is one key. Kept, it made a
          // group with the key in it twice (a duplicate age stanza) and
          // an import that counted it twice.
          if (parsed.some((p) => p.fingerprint === info.fingerprint)) continue;
          parsed.push(info);
          keys.push(sshPublicKey(info, stored));
        } catch (error) {
          keys.push(rejectedSshPublicKey(line, engineRejection(error)));
        }
      }
      // Same rule the OpenPGP path applies below: an unusable line
      // alongside usable ones is a stale entry in someone's
      // `authorized_keys`, not something to interrupt the import for.
      const usable = keys.filter((k) => k.status !== "rejected");

      if (usable.length > 1) {
        const members = parsed.map(sshMember);
        // The lines say, unambiguously, that they are one person's: one
        // contact, no question asked.
        const shared = sharedComment(parsed);
        if (shared !== null) {
          return {
            keys: [sshGroupKey(shared, members, stored)],
            secrets: new Map(),
            unparseable: false,
          };
        }
        // They might be one person's, and only the user knows. Both
        // readings travel; the preview asks. Skipped once any of them is
        // already stored, so the offer is never over a set where
        // "import these separately" and "import these as one" do
        // different amounts of work.
        if (usable.every((k) => k.status === "new")) {
          return {
            keys: usable,
            groupProposal: sshGroupKey(
              proposalLabel(members.length),
              members,
              stored,
            ),
            secrets: new Map(),
            unparseable: false,
          };
        }
      }

      return {
        keys: usable.length > 0 ? usable : keys,
        secrets: new Map(),
        unparseable: false,
      };
    }
  }

  let certs;
  try {
    certs = await parseKeys(text);
  } catch {
    // Not a key -- but a bare revocation certificate is the one thing a
    // contact's owner hands out to say "stop trusting this key".
    const revoked = await applyRevocation(
      text,
      stored.contacts.map((c) => ({ keyId: c.keyId, armored: c.armored })),
    );
    if (revoked === "unknown") {
      return {
        keys: [revocationForUnknownKey()],
        secrets: new Map(),
        unparseable: false,
      };
    }
    if (revoked) {
      return {
        keys: [
          await classifyCert(revoked.keyInfo, revoked.armored, stored.contacts),
        ],
        secrets: new Map(),
        unparseable: false,
      };
    }
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
      // The first copy's secret half: a second private copy of the same
      // key is dropped below, and must not swap in its secret unseen.
      if (!secrets.has(cert.keyInfo.keyId))
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

  const merged = await mergeSameKey(classified, stored);
  const usable = merged.filter((k) => k.status !== "rejected");
  return {
    // Rejects are kept only when there's nothing usable to show instead:
    // that's the case where the user needs to be told why.
    keys: usable.length > 0 ? usable : merged,
    secrets,
    unparseable: false,
  };
}

/**
 * Several copies of ONE key (same fingerprint) in one import, as one.
 *
 * The Review keys its decisions by fingerprint, so two rows for one key
 * shared one Skip/Import switch -- and the identity check looked at each
 * copy's User IDs apart, so a copy that added a User ID claiming someone
 * else's address could sit behind a harmless one. Public copies are
 * MERGED through the engine, exactly as an update is merged into the
 * stored contact (it only keeps what the owner signed), and the merge is
 * classified once, so the row shows -- and the identity check sees --
 * every User ID any copy carries. A private copy keeps only the first:
 * its secret half is what gets protected, and there is nothing to merge
 * a secret half with. A public copy and a private copy of the same key
 * stay apart (one is a contact, the other the user's own key).
 *
 * Exported for the backup restore, which classifies its file a block at
 * a time and so meets copies this function's caller never sees together.
 */
export async function mergeSameKey(
  keys: IncomingKey[],
  stored: StoredKeys,
): Promise<IncomingKey[]> {
  const groupOf = (k: IncomingKey) =>
    k.kind === "pgp-public" || k.kind === "pgp-private"
      ? `${k.kind}:${k.keyId.toUpperCase()}`
      : null;
  const copies = new Map<string, IncomingKey[]>();
  for (const key of keys) {
    const group = groupOf(key);
    if (group === null || key.keyId === PENDING_KEY_ID) continue;
    copies.set(group, [...(copies.get(group) ?? []), key]);
  }
  const out: IncomingKey[] = [];
  const done = new Set<string>();
  for (const key of keys) {
    const group = groupOf(key);
    const same = group === null ? undefined : copies.get(group);
    if (group === null || !same || same.length < 2) {
      out.push(key);
      continue;
    }
    if (done.has(group)) continue;
    done.add(group);
    if (key.kind === "pgp-private") {
      out.push(key);
      continue;
    }
    out.push(await mergeCopies(same, stored));
  }
  return out;
}

/** One public key's copies, merged and classified as a single cert.
 *  A copy the engine will not merge (it never parsed as this key) is
 *  left out of the merge rather than failing the import. */
async function mergeCopies(
  copies: IncomingKey[],
  stored: StoredKeys,
): Promise<IncomingKey> {
  let armored = copies[0].publicArmored;
  for (const copy of copies.slice(1)) {
    try {
      armored = await mergePublicKey(armored, copy.publicArmored);
    } catch {
      // Keep what is merged so far.
    }
  }
  try {
    const cert = (await parseKeys(armored)).at(0);
    if (cert)
      return await classifyCert(cert.keyInfo, cert.armored, stored.contacts);
  } catch {
    // Fall through to the first copy as it was classified.
  }
  return copies[0];
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
