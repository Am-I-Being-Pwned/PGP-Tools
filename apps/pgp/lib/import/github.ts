import type { GithubKeysFailure } from "../messages";
import type { ContactRecipient, PublicContactKey } from "../storage/contacts";
import type { PreparedImport } from "./prepare";
import type { ContactGroup, IncomingKey, RejectedLine } from "./types";
import { parseSshRecipient } from "../pgp/wasm";
import { contactRecipients, sameSource } from "../storage/contacts";
import { engineRejection } from "./prepare";
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
}

/** The auto-label. GitHub accounts have no display name in this
 *  response, and asking for one would put a text field in front of an
 *  import that otherwise needs no decisions -- so the account name is
 *  the name, marked with where it came from. It goes in `userIds[0]`,
 *  the one field every consumer reads for "who is this". */
export function githubLabel(username: string): string {
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

/** "1 key added" / "2 keys removed". */
function keyCount(n: number, verb: string): string {
  return `${n} key${n === 1 ? "" : "s"} ${verb}`;
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

  const head = group.members[0];
  const withHead = {
    ...base,
    // The head member's, so every path that reads an IncomingKey's
    // identity -- the preview, the highlight-after-import, the map key --
    // works on a group without knowing it is one. It is also what the
    // stored record's `keyId`/`armoredPublicKey` will be.
    keyId: head.keyId,
    publicArmored: head.armored,
  };

  const existing = contacts.find((c) => sameSource(c, { source: group.source }));
  if (!existing) return { ...withHead, status: "new", changes: [] };

  const stored = new Set(contactRecipients(existing).map((r) => r.keyId));
  const fetched = new Set(group.members.map((r) => r.keyId));
  const added = [...fetched].filter((fp) => !stored.has(fp)).length;
  const removed = [...stored].filter((fp) => !fetched.has(fp)).length;

  if (added === 0 && removed === 0) {
    return {
      ...withHead,
      status: "duplicate",
      changes: [],
      existingAddedAt: existing.addedAt,
    };
  }

  return {
    ...withHead,
    status: "update",
    changes: [
      ...(added > 0 ? [keyCount(added, "added")] : []),
      ...(removed > 0 ? [keyCount(removed, "removed")] : []),
    ],
    existingAddedAt: existing.addedAt,
  };
}

/** Why a group with nothing usable in it can't be imported. Names the
 *  engine's reason when the keys all failed for the same one, which is
 *  the common case (a user whose only key is an ECDSA key); otherwise
 *  the per-line reasons are listed in the preview below. */
function groupRejection(group: ContactGroup): string {
  const reasons = new Set(group.rejected.map((r) => r.reason));
  if (reasons.size === 1) return [...reasons][0];
  return "None of the published keys can be used for encryption.";
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
  now: number = Date.now(),
): Promise<PreparedImport> {
  const members: ContactRecipient[] = [];
  const rejected: RejectedLine[] = [];

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

  return {
    keys: [
      classifyGithubGroup(
        githubGroup(username, members, rejected, now),
        stored.contacts,
      ),
    ],
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
  if (minutes <= 1) return "Try again in a minute.";
  if (minutes < 60) return `Try again in about ${minutes} minutes.`;
  const hours = Math.ceil(minutes / 60);
  return `Try again in about ${hours} hour${hours === 1 ? "" : "s"}.`;
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
        message:
          "That isn't a GitHub username. Use the account name from the profile URL, e.g. “octocat” for github.com/octocat.",
      };
    case "not-found":
      return {
        tone: "error",
        message: `There's no GitHub account called “${username}”. Check the spelling - the name in the profile URL is the one to use.`,
      };
    case "no-keys":
      // Not an error: nothing failed, and the user has nothing to fix.
      return {
        tone: "notice",
        message: `${username} hasn't published any SSH keys on GitHub. Ask them to add one at github.com/settings/keys, or paste their key here instead.`,
      };
    case "offline":
      return {
        tone: "error",
        message:
          "Couldn't reach github.com. Check your connection and try again.",
      };
    case "rate-limited":
      return {
        tone: "error",
        message: [
          // Said explicitly because the natural reading -- "I have made
          // too many requests" -- is usually wrong. The lookup is
          // unauthenticated, so GitHub counts per IP address: an office,
          // a VPN or a campus network shares one budget.
          "GitHub is rate-limiting this network. The limit is counted per IP address, so it can be used up by other people on the same connection.",
          resetAt !== undefined ? resetHint(resetAt, now) : "",
        ]
          .filter(Boolean)
          .join(" "),
      };
    case "server-error":
      return {
        tone: "error",
        message: "GitHub couldn't answer just now. Try again in a moment.",
      };
  }
}
