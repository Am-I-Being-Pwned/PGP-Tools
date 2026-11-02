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
 * A GitHub user's published SSH keys as one import-panel object.
 * {@link classifyGithubGroup} is pure (no wasm); {@link prepareGithubImport}
 * calls wasm. Every forwarded string goes through `parseSshRecipient`, the
 * only thing allowed to say a line is a usable recipient.
 */

/** Full contact records, not {@link StoredKey}: matching needs the SOURCE
 *  and the whole recipient list. */
export interface GithubStoredContacts {
  contacts: readonly PublicContactKey[];
  own?: readonly OwnKeyRef[];
}

/** What a lookup needs of one of the user's own keys. */
export interface OwnKeyRef {
  keyId: string;
  userIds: string[];
}

/** The auto-label, stored in `userIds[0]`: account name plus provenance. */
export function githubLabel(username: string): string {
  // Persisted and asserted on by tests: keep locale-independent.
  return `${username} (GitHub)`;
}

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
 * Matched by SOURCE, never by fingerprint: a contact's `keyId` is its first
 * key's, which changes when that key is deleted. Compared as fingerprint
 * SETS because GitHub's ordering is undocumented.
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

  // Every line refused: a rejection carrying the engine's reasons.
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

  // The head (the stored record's id) must be a key nobody else holds:
  // an own or another contact's key as head would upsert over that record.
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

  // Every key held elsewhere: nothing new, unless this REFRESHES the
  // account's record and the set moved -- then it keeps its own id if still
  // listed and untaken; the conflicts still make Review ask first.
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
    // The head member's, so single-key code paths work on a group unchanged.
    keyId: members[0].keyId,
    publicArmored: members[0].armored,
  };
  const changes = [
    ...(added > 0 ? [tn("import_change_keys_added", added)] : []),
    ...(removed > 0 ? [tn("import_change_keys_removed", removed)] : []),
  ];

  if (!head && existing && changed) {
    // No id left that isn't someone else's, and dropped keys are still being
    // encrypted to: refuse, never "nothing has changed".
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

  // Every still-listed key is one the user turned off: saving would leave
  // nothing to encrypt to, so ask rather than do it quietly.
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

/** Names the engine's reason when all keys failed for the same one. */
function groupRejection(group: ContactGroup): string {
  const reasons = new Set(group.rejected.map((r) => r.reason));
  if (reasons.size === 1) return [...reasons][0];
  return t("import_github_none_usable");
}

export interface PrepareGithubOptions {
  /** Keys the worker's caps held back (`lib/github/response.ts`); surfaced
   *  as a rejected line so the preview never claims to be the whole account. */
  omitted?: number;
  now?: number;
}

/**
 * Fetched lines -> the single {@link IncomingKey} the preview renders.
 *
 * A refused line is kept as a {@link RejectedLine}, never skipped: a
 * silently missing key surfaces only as "they can't read my message".
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

  // Say the worker's caps out loud; never imply a truncated list is complete.
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
      // The ONLY thing that decides a fetched (untrusted) string is a key;
      // `members` holds wasm's canonical line.
      const info = await parseSshRecipient(line);
      // A duplicate member would be a duplicate age stanza.
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

  // Same checks as a paste: held keys, and the label against every contact name.
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
    // A `.pub` line is public only; no secret material arrives this way.
    secrets: new Map(),
    unparseable: false,
  };
}

// ── failure copy ─────────────────────────────────────────────────────

/**
 * Panel copy per failure code. The worker forwards a code, never GitHub's
 * prose (`lib/messages.ts`). `no-keys` is not the user's fault, so it is a
 * notice, not red.
 */
export interface GithubFailureCopy {
  tone: "error" | "notice";
  message: string;
}

/** Rounded up and vague on purpose: the reset header is minute-granular. */
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
          // Unauthenticated, so GitHub counts per IP: shared networks share a budget.
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
