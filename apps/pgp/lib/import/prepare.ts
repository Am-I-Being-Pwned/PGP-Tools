import {
  LEGACY_PEM_ENCRYPTED,
  looksLikeForeignSshPrivateKey,
  splitSshPrivateKeyBlocks,
  splitSshPublicKeyCandidateLines,
} from "~/lib/armor-blocks";
import { t, tn } from "~/lib/i18n";
import { identityConflict, type IdentityHolder } from "~/lib/identity/binding";
import { detectImportOverwrite } from "~/lib/import-overwrite";
import {
  applyRevocation,
  importRejectionMessage,
  isUsableContact,
  mergeIntoStored,
} from "~/lib/import-public-keys";
import type { KeyDetails, KeyInfo } from "~/lib/pgp/types";
import {
  extractPublicKey,
  mergePublicKey,
  parseKeyDetails,
  parseKeys,
  parseSshRecipient,
  sshPrivateKeyFormatRejection,
  type SshRecipientInfo,
} from "~/lib/pgp/wasm";
import { contactRecipients } from "~/lib/storage/contact-recipients";
import {
  sameSource,
  type ContactRecipient,
  type ContactSource,
  type PublicContactKey,
} from "~/lib/storage/contacts";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { stripInvisible } from "~/lib/utils/lookalike";
import { isSecretKind, PENDING_KEY_ID, type IncomingKey } from "./types";

/** Turn pasted/dropped text into the objects the import UI previews. */

/** A stored key an import can collide with; `armored` tells a no-op re-import from a change. */
export interface StoredKey {
  keyId: string;
  userIds: string[];
  /** PUBLIC armor only. */
  armored: string;
  addedAt?: number;
  createdAt?: number;
  expiresAt?: number | null;
  /** Where a fetched contact came from; absent when hand-supplied. */
  source?: ContactSource;
  /** A revoked key no longer holds its address (see identity/binding). */
  revoked?: boolean;
  /** Every key a multi-key contact holds; an SSH import is checked against all of them. */
  recipientIds?: string[];
  /** The user's local name for it: names conflicts, and is compared against imports. */
  alias?: string;
}

export interface StoredKeys {
  /** The user's own keys (keyring), matched against private imports. */
  own: StoredKey[];
  /** Contacts, matched against public imports. */
  contacts: StoredKey[];
}

/** The keyring and contacts as every `prepare*` entry point takes them. One
 *  builder so import and backup restore classify against the same facts. */
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
      ...(c.recipients
        ? { recipientIds: contactRecipients(c).map((r) => r.keyId) }
        : {}),
      ...(c.alias ? { alias: c.alias } : {}),
    })),
  };
}

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

/** Which non-OpenPGP engines this import accepts. A disabled engine's key is
 *  not recognised at all (falls through to `unparseable`); the classifier is
 *  the one place that decides what text IS. */
export interface ImportEngines {
  /** RSA signing keys for Chrome extensions (.crx). */
  crx?: boolean;
  /** OpenSSH keys, used with age. */
  ssh?: boolean;
}

/** A raw RSA private key PEM (CRX signing key). Never a PGP armored block, and
 *  never legacy `Proc-Type: 4,ENCRYPTED` (left for the age engine's message). */
const RSA_PEM_RE = /-----BEGIN (?:RSA )?PRIVATE KEY-----/;
function isRsaPrivatePem(text: string): boolean {
  return (
    RSA_PEM_RE.test(text) &&
    !text.includes("PGP") &&
    !text.includes(LEGACY_PEM_ENCRYPTED)
  );
}

/** A CRX signing key: nothing to parse, no fingerprint until import time, but
 *  still an IncomingKey so it takes the same preview -> protect path. */
function crxSigningKey(): IncomingKey {
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
const SSH_COMMENT_MAX = 120;

/** Strip control/invisible chars, trim, cap. Duplicates the engine's
 *  `sanitize_comment` on purpose: this attacker-supplied text becomes a
 *  contact name, so don't depend on the engine build. */
function cleanSshComment(comment: string): string {
  const clean = stripInvisible(comment).trim();
  return [...clean].length > SSH_COMMENT_MAX
    ? `${[...clean].slice(0, SSH_COMMENT_MAX).join("")}\u2026`
    : clean;
}

function storedKeyIds(record: StoredKey): string[] {
  return record.recipientIds && record.recipientIds.length > 0
    ? record.recipientIds
    : [record.keyId];
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

/** A `.pub` line the engine refuses, carrying the engine's own reason (never
 *  drop it silently). `keyId` is {@link PENDING_KEY_ID}. */
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
    publicArmored: line.trim(),
  };
}

/** A private key format the age engine names and refuses. Nothing goes in `secrets`. */
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

/** The canonical line wasm returned, never the pasted one. */
function sshMember(info: SshRecipientInfo): ContactRecipient {
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
function sharedComment(parsed: readonly SshRecipientInfo[]): string | null {
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

/** Placeholder headline; never stored (a blank name imports keys separately). */
function proposalLabel(count: number): string {
  return tn("import_group_proposal_label", count);
}

/** The engine's message (already user-facing prose), or a generic fallback.
 *  Shared with `github.ts` so one refusal has one wording. */
export function engineRejection(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.trim() || t("import_reject_ssh_generic");
}

export interface PreparedImport {
  keys: IncomingKey[];
  /** Private armor per fingerprint, for the protect step only. Deliberately
   *  NOT on IncomingKey, which reaches React state (SECURITY.md zeroization table). */
  secrets: Map<string, string>;
  /** The text carried no OpenPGP certificate at all. */
  unparseable: boolean;
  /**
   * The same keys offered as ONE contact under a user-supplied name. Present
   * only when several new SSH public keys did NOT auto-group: the import must
   * not decide they're one person, so both readings travel and the preview
   * asks. `group.label` is a placeholder replaced before storing.
   */
  groupProposal?: IncomingKey;
}

/**
 * Classify every cert in a blob of armor. When a block has a usable cert, its
 * unusable siblings are stale rotations and are dropped.
 *
 * The ONE place that decides what pasted text is: every engine returns an
 * IncomingKey here rather than short-circuiting the panel.
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

async function classifyImport(
  text: string,
  stored: StoredKeys,
  engines: ImportEngines,
): Promise<PreparedImport> {
  // Before the OpenPGP parse. The PEM is secret, so it travels in `secrets`.
  // Before the SSH branch too: a plain PKCS#8 `BEGIN PRIVATE KEY` is valid for
  // both, and CRX can use it; with CRX off the age engine names it (`MSG_PKCS8`).
  if (engines.crx && isRsaPrivatePem(text)) {
    return {
      keys: [crxSigningKey()],
      secrets: new Map([[PENDING_KEY_ID, text.trim()]]),
      unparseable: false,
    };
  }

  if (engines.ssh) {
    // Private first: an OpenSSH container embeds the public half.
    const [sshPrivate] = splitSshPrivateKeyBlocks(text);
    if (sshPrivate) {
      return {
        keys: [sshPrivateKey()],
        secrets: new Map([[PENDING_KEY_ID, sshPrivate]]),
        unparseable: false,
      };
    }

    // Refused formats get the engine's specific message here, before a
    // password is chosen.
    if (looksLikeForeignSshPrivateKey(text)) {
      // `text` may be a COMPLETE unencrypted private key (PKCS#8 with CRX off), so
      // our copy of the bytes is `.fill(0)`'d in `finally`, as at every other
      // secret-bearing call site. `text` itself is an immutable string and can't
      // be zeroized -- this only removes one extra heap copy.
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

    // The CANDIDATE splitter (any `<alg> AAAA<base64>` line), so ECDSA / `sk-*` /
    // `ssh-dss` reach the engine and get its refusal rather than `unparseable`.
    // Invariant: THE ENGINE DECIDES VALIDITY; EVERY LAYER ABOVE IT FORWARDS AND
    // DISPLAYS. `classify-action.ts` and `drop-routing.ts` share this splitter.
    const lines = splitSshPublicKeyCandidateLines(text);
    if (lines.length > 0) {
      const keys: IncomingKey[] = [];
      // Engine output per accepted line; groups are built from it.
      const parsed: SshRecipientInfo[] = [];
      for (const line of lines) {
        try {
          // A refused line is never stored, but IS reported with the engine's reason.
          const info = await parseSshRecipient(line);
          // Dedup on fingerprint: the same line twice is one key.
          if (parsed.some((p) => p.fingerprint === info.fingerprint)) continue;
          parsed.push(info);
          keys.push(sshPublicKey(info, stored));
        } catch (error) {
          keys.push(rejectedSshPublicKey(line, engineRejection(error)));
        }
      }
      // As in the OpenPGP path: an unusable line beside usable ones is stale.
      const usable = keys.filter((k) => k.status !== "rejected");

      if (usable.length > 1) {
        const members = parsed.map(sshMember);
        const shared = sharedComment(parsed);
        if (shared !== null) {
          return {
            keys: [sshGroupKey(shared, members, stored)],
            secrets: new Map(),
            unparseable: false,
          };
        }
        // Might be one person's -- only the user knows, so both readings travel.
        // Only when all are new, so both readings do the same amount of work.
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
    // Not a key -- but maybe a bare revocation certificate.
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
    // The preview never sees a private `cert.armored`: the public half is
    // extracted for display, the secret half parked in `secrets`.
    let publicArmored = cert.armored;
    if (cert.keyInfo.isPrivate) {
      try {
        publicArmored = await extractPublicKey(cert.armored);
      } catch {
        // Refuse rather than risk private armor reaching the preview.
        continue;
      }
      // First copy wins: a later private copy must not swap in its secret unseen.
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
    // Rejects are kept only when there's nothing usable, so the user learns why.
    keys: usable.length > 0 ? usable : merged,
    secrets,
    unparseable: false,
  };
}

/**
 * Several copies of ONE fingerprint in one import, as one row -- otherwise a
 * copy adding a User ID that claims someone else's address could hide behind
 * a harmless one. Public copies are MERGED through the engine and classified
 * once; a private copy keeps only the first (nothing to merge a secret with).
 * Public and private copies of one key stay apart.
 *
 * Exported for backup restore, which classifies a block at a time.
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

/** A copy the engine won't merge is left out rather than failing the import. */
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

/** Every key found is already stored byte for byte; the panel is skipped. */
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
