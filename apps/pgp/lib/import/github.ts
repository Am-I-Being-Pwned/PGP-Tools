import type { GithubKeysFailure } from "../messages";
import type { ContactRecipient, PublicContactKey } from "../storage/contacts";
import type { PreparedImport } from "./prepare";
import type { ContactGroup, IncomingKey, RejectedLine } from "./types";
import { MAX_KEYS } from "../github/response";
import { t, tn } from "../i18n";
import { parseSshRecipient } from "../pgp/wasm";
import {
  contactRecipients,
  isRecipientDisabled,
  sameSource,
} from "../storage/contacts";
import { engineRejection, withIdentityConflicts } from "./prepare";
import { PENDING_KEY_ID } from "./types";

/**
 * A GitHub user's published SSH keys, turned into the ONE object the
 * import panel already renders.
 *
 * Split the way `prepare.ts` splits `classifyCert` out of
 * `prepareImport`: {@link classifyGithubGroup} is pure and is where the
 * new/duplicate/update decision actually lives, so it is testable
 * without a wasm engine or a stub for one. {@link prepareGithubImport}
 * is the thin part that calls wasm.
 *
 * The background worker forwards the response body's strings WITHOUT
 * deciding they are keys (see `lib/github/response.ts`): every one of
 * them is run through `parseSshRecipient` here, which is the only thing
 * in this app that gets to say a line is a usable recipient.
 */

/** What a GitHub import is classified against. Full contact records
 *  rather than `prepare.ts`'s flattened {@link StoredKey}, because the
 *  identity being matched is the contact's SOURCE and its whole
 *  recipient list -- neither of which survives that flattening. */
export interface GithubStoredContacts {
  contacts: readonly PublicContactKey[];
  /** The user's own keys. An account listing one of them is checked
   *  like any other key the user already holds (see
   *  `classifyGithubGroup`). */
  own?: readonly OwnKeyRef[];
}

/** What a lookup needs of one of the user's own keys. */
export interface OwnKeyRef {
  keyId: string;
  userIds: string[];
}

/** The auto-label. GitHub accounts have no display name in this
 *  response, and asking for one would put a text field in front of an
 *  import that otherwise needs no decisions -- so the account name is
 *  the name, marked with where it came from. It goes in `userIds[0]`,
 *  the one field every consumer reads for "who is this". */
export function githubLabel(username: string): string {
  // Provenance tag, not prose: it is persisted in the contact record and
  // asserted on by tests, so it stays locale-independent.
  return `${username} (GitHub)`;
}

/**
 * Assemble the fetched keys into a group. Pure: the parsing has already
 * happened, so this is just the shape.
 */
export function githubGroup(
  username: string,
  members: ContactRecipient[],
  rejected: RejectedLine[],
  fetchedAt: number,
): ContactGroup {
  return {
    label: githubLabel(username),
    source: { type: "github", user: username, fetchedAt },
    members,
    rejected,
  };
}

/**
 * Classify a fetched group against the stored contacts.
 *
 * Matched by SOURCE, never by fingerprint. A fetched contact's `keyId`
 * is only its FIRST key's fingerprint, so the day someone deletes their
 * oldest GitHub key the record's id changes -- a fingerprint match would
 * then file the same person as a second contact, and `saveContact`
 * upserts on the source for exactly that reason.
 *
 * The comparison itself is between fingerprint SETS. GitHub returns the
 * keys in whatever order it likes and nothing documents that order, so
 * a list-equality check would report a reordering as an update and make
 * "nothing has changed" unreachable.
 */
export function classifyGithubGroup(
  group: ContactGroup,
  contacts: readonly PublicContactKey[],
  own: readonly OwnKeyRef[] = [],
): IncomingKey {
  const base = {
    kind: "ssh-public" as const,
    info: null,
    details: null,
    userIds: [group.label],
    group,
  };

  // Every line was refused. There is no head member to be a contact, so
  // this is a rejection -- carrying the engine's reasons, which is the
  // only useful thing left to say (`rejectedSshPublicKey` in prepare.ts
  // takes the same position for a pasted line).
  if (group.members.length === 0) {
    return {
      ...base,
      keyId: PENDING_KEY_ID,
      status: "rejected",
      changes: [],
      rejection: groupRejection(group),
      publicArmored: "",
    };
  }

  const existing = contacts.find((c) =>
    sameSource(c, { source: group.source }),
  );

  // Keys somebody else already holds: one of the user's own, or one on a
  // contact that is not this account's record. The head -- the stored
  // record's id -- is never one of them. Headed by a contact's key, the
  // save upserted over that contact (an account listing Alice's key
  // first replaced the hand-added Alice); headed by an own key, the
  // record shared an id with "You" and the picker resolved one as the
  // other. So the head is the first key nobody else holds.
  const ownIds = new Set(own.map((k) => k.keyId));
  const others = contacts.filter((c) => c !== existing);
  const elsewhere = new Set([
    ...ownIds,
    ...others.flatMap((c) => contactRecipients(c).map((r) => r.keyId)),
  ]);
  const fetched = new Set(group.members.map((r) => r.keyId));
  const stored = existing
    ? new Set(contactRecipients(existing).map((r) => r.keyId))
    : null;
  const added = stored
    ? [...fetched].filter((fp) => !stored.has(fp)).length
    : 0;
  const removed = stored
    ? [...stored].filter((fp) => !fetched.has(fp)).length
    : 0;
  const changed = added > 0 || removed > 0;

  // An account whose every key is held elsewhere has nothing new to save
  // -- unless it is a REFRESH of this account's record and the set moved.
  // Then the record must change (a key the account no longer lists has
  // to stop being encrypted to), so it keeps its own id while that is
  // still listed and no other contact has taken it; the keys held
  // elsewhere still mark it (`withIdentityConflicts`), so the Review
  // asks first.
  const head =
    group.members.find((m) => !elsewhere.has(m.keyId)) ??
    (existing && changed
      ? group.members.find(
          (m) =>
            m.keyId === existing.keyId &&
            !others.some((c) => c.keyId === m.keyId),
        )
      : undefined);
  const members = head
    ? [head, ...group.members.filter((m) => m !== head)]
    : group.members;
  const withHead = {
    ...base,
    group: { ...group, members },
    // The head member's, so every path that reads an IncomingKey's
    // identity -- the preview, the highlight-after-import, the map key --
    // works on a group without knowing it is one. It is also what the
    // stored record's `keyId`/`armoredPublicKey` will be.
    keyId: members[0].keyId,
    publicArmored: members[0].armored,
  };
  const changes = [
    ...(added > 0 ? [tn("import_change_keys_added", added)] : []),
    ...(removed > 0 ? [tn("import_change_keys_removed", removed)] : []),
  ];

  if (!head && existing && changed) {
    // The account's record has to change and there is no id it can take
    // that is not somebody else's: saving would land on that contact.
    // Never "nothing has changed" -- the keys it dropped are still being
    // encrypted to -- so it is refused, saying so.
    return {
      ...withHead,
      status: "rejected",
      changes,
      rejection: t("import_github_refresh_all_held", {
        username: group.source?.user ?? "",
      }),
      existingAddedAt: existing.addedAt,
    };
  }
  if (!head) {
    return {
      ...withHead,
      status: "duplicate",
      changes: [],
      existingAddedAt: existing?.addedAt ?? null,
    };
  }
  if (!existing) return { ...withHead, status: "new", changes: [] };

  if (!changed) {
    return {
      ...withHead,
      status: "duplicate",
      changes: [],
      existingAddedAt: existing.addedAt,
    };
  }

  // Every key the account still lists is one the user turned off on this
  // record. Saved, the record would hold only keys they said not to use,
  // and nothing would be left to encrypt to; that is asked about, not
  // done quietly (and the record is unusable for encryption until a key
  // is turned back on -- see `activeRecipients`).
  const off = new Set(
    contactRecipients(existing)
      .filter(isRecipientDisabled)
      .map((r) => r.keyId),
  );
  const allOff = [...fetched].every((fp) => off.has(fp));

  return {
    ...withHead,
    status: "update",
    changes,
    existingAddedAt: existing.addedAt,
    ...(allOff ? { allKeysOff: true as const } : {}),
  };
}

/** Why a group with nothing usable in it can't be imported. Names the
 *  engine's reason when the keys all failed for the same one, which is
 *  the common case (a user whose only key is an ECDSA key); otherwise
 *  the per-line reasons are listed in the preview below. */
function groupRejection(group: ContactGroup): string {
  const reasons = new Set(group.rejected.map((r) => r.reason));
  if (reasons.size === 1) return [...reasons][0];
  return t("import_github_none_usable");
}

export interface PrepareGithubOptions {
  /** Published keys the worker's caps held back -- see
   *  `lib/github/response.ts`. Surfaced as a rejected line, because the
   *  preview otherwise claims the list is the whole account. */
  omitted?: number;
  /** Injectable clock, for the `fetchedAt` stamp. */
  now?: number;
}

/**
 * Fetched lines -> the single {@link IncomingKey} the preview renders.
 *
 * A line the engine refuses is kept as a {@link RejectedLine} rather
 * than skipped. The age engine writes eight curated refusals (ECDSA,
 * FIDO/security-key, DSA, an RSA key too small or too large, ...), each
 * naming the key type and what to do about it, and dropping them leaves
 * a contact quietly missing one of the keys its owner actually uses --
 * which surfaces as "they can't read my message", never as an error.
 * `prepareImport`'s SSH loop was written with a bare `catch { continue }`
 * once and this is the same mistake in a new place.
 */
export async function prepareGithubImport(
  username: string,
  lines: readonly string[],
  stored: GithubStoredContacts,
  options: PrepareGithubOptions = {},
): Promise<PreparedImport> {
  const { omitted = 0, now = Date.now() } = options;
  const members: ContactRecipient[] = [];
  const rejected: RejectedLine[] = [];

  // The worker's caps, said out loud. It forwards at most MAX_KEYS lines
  // and skips any single key string over MAX_KEY_CHARS; without this the
  // preview would print "messages are encrypted to every key listed
  // above" over a list that is quietly missing some of the account's
  // keys -- the same silence this whole function exists to avoid, one
  // level up.
  if (omitted > 0) {
    rejected.push({
      line: tn("import_github_omitted_line", omitted),
      reason: t("import_github_omitted_reason", {
        max: MAX_KEYS,
        count: omitted,
        username,
      }),
    });
  }

  for (const line of lines) {
    try {
      // The ONLY thing that decides a fetched string is a key. What the
      // worker forwarded is untrusted text off the network; what goes
      // into `members` is the canonical line wasm handed back.
      const info = await parseSshRecipient(line);
      // Deduplicated on the fingerprint: a duplicate member would be a
      // duplicate age stanza, and would make the set comparison above
      // depend on multiplicity.
      if (members.some((m) => m.keyId === info.fingerprint)) continue;
      members.push({
        keyId: info.fingerprint,
        armored: info.recipient,
        algorithm: info.algorithm,
      });
    } catch (error) {
      rejected.push({ line: line.trim(), reason: engineRejection(error) });
    }
  }

  // Then the same checks a paste gets: a key someone already holds, and
  // the account's label against every contact's name (a GitHub account
  // called "alice" is not the Alice in the contact list just by saying
  // so).
  return {
    keys: withIdentityConflicts(
      [
        classifyGithubGroup(
          githubGroup(username, members, rejected, now),
          stored.contacts,
          stored.own,
        ),
      ],
      {
        own: (stored.own ?? []).map((k) => ({
          keyId: k.keyId,
          userIds: k.userIds,
          armored: "",
        })),
        contacts: stored.contacts.map((c) => ({
          keyId: c.keyId,
          userIds: c.userIds,
          armored: c.armoredPublicKey,
          recipientIds: contactRecipients(c).map((r) => r.keyId),
          ...(c.alias ? { alias: c.alias } : {}),
          ...(c.source ? { source: c.source } : {}),
          ...(c.revoked ? { revoked: true } : {}),
        })),
      },
    ),
    // No secret material can arrive this way: a `.pub` line is a public
    // half, and the panel never reaches the protect step for one.
    secrets: new Map(),
    unparseable: false,
  };
}

// ── failure copy ─────────────────────────────────────────────────────

/**
 * What the panel says about each failure code.
 *
 * The worker forwards a tagged code and never GitHub's own prose (see
 * `lib/messages.ts`), so the wording is decided here -- and it is decided
 * once, in a pure function, rather than in a `switch` inside a render.
 *
 * The tone matters as much as the words. `no-keys` is the one failure
 * where the user did nothing wrong and nothing is broken: the person they
 * looked up simply has no SSH keys on GitHub. Painting that red teaches
 * people to distrust a correct answer.
 */
export interface GithubFailureCopy {
  /** "error" is the destructive slot; "notice" is muted body text. */
  tone: "error" | "notice";
  message: string;
}

/** Roughly how long until a rate limit lifts, in words. Rounded up, and
 *  vague on purpose -- the reset header is minute-granular and a precise
 *  countdown would just be wrong a second later. */
function resetHint(resetAt: number, now: number): string {
  const minutes = Math.ceil((resetAt - now) / 60_000);
  if (minutes <= 1) return t("import_retry_minute");
  if (minutes < 60) return tn("import_retry_minutes", minutes);
  const hours = Math.ceil(minutes / 60);
  return tn("import_retry_hours", hours);
}

export function githubFailureCopy(
  failure: GithubKeysFailure,
  username: string,
  resetAt?: number,
  now: number = Date.now(),
): GithubFailureCopy {
  switch (failure) {
    case "invalid-username":
      return {
        tone: "error",
        message: t("import_github_invalid_username"),
      };
    case "not-found":
      return {
        tone: "error",
        message: t("import_github_not_found", { username }),
      };
    case "no-keys":
      // Not an error: nothing failed, and the user has nothing to fix.
      return {
        tone: "notice",
        message: t("import_github_no_keys", { username }),
      };
    case "offline":
      return {
        tone: "error",
        message: t("import_github_offline"),
      };
    case "rate-limited":
      return {
        tone: "error",
        message: [
          // Said explicitly because the natural reading -- "I have made
          // too many requests" -- is usually wrong. The lookup is
          // unauthenticated, so GitHub counts per IP address: an office,
          // a VPN or a campus network shares one budget.
          t("import_github_rate_limited"),
          resetAt !== undefined ? resetHint(resetAt, now) : "",
        ]
          .filter(Boolean)
          .join(" "),
      };
    case "server-error":
      return {
        tone: "error",
        message: t("import_github_server_error"),
      };
  }
}
