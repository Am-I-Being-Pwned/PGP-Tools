/**
 * The GitHub import's decisions, with no engine behind them.
 *
 * Two things are being pinned here, and neither is enforced by types:
 *
 *  1. A fetched contact's identity is its SOURCE, not its fingerprint.
 *     `keyId` is only the FIRST key's fingerprint, so the day someone
 *     deletes their oldest GitHub key the record's id changes -- and a
 *     fingerprint-keyed classifier would file the same person as a new
 *     contact, which `saveContact` would then store alongside the old
 *     one. The symptom is two "octocat (GitHub)" cards, one of them
 *     stale, and messages encrypted to whichever the user happens to
 *     pick.
 *  2. A refused line is REPORTED. The age engine's refusals name the key
 *     type and what to do about it; a swallowed one leaves a contact
 *     silently missing a key its owner actually uses, which surfaces
 *     only as "they can't read my message". `prepareImport`'s SSH loop
 *     was written with a bare `catch { continue }` once.
 *
 * The set comparison gets its own test for the same reason: GitHub does
 * not document the order it lists keys in, so a list-equality check
 * would report a reorder as an update and make "nothing has changed"
 * unreachable.
 */

import { describe, expect, it } from "vitest";

import type { PublicContactKey } from "../storage/contacts";
import type { ContactGroup } from "./types";
import {
  classifyGithubGroup,
  githubFailureCopy,
  githubGroup,
  githubLabel,
} from "./github";

const FP_A = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const FP_B = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const FP_C = "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

function member(keyId: string) {
  return { keyId, armored: `ssh-ed25519 ${keyId}`, algorithm: "ssh-ed25519" };
}

function group(
  members: string[],
  rejected: { line: string; reason: string }[] = [],
  user = "octocat",
): ContactGroup {
  return githubGroup(user, members.map(member), rejected, 1000);
}

/** A stored contact for `user`, holding `members`. Written the way the
 *  store writes it: `recipients` only when there is more than one, and
 *  the head always agreeing with the top-level fields. */
function stored(user: string, members: string[]): PublicContactKey {
  const list = members.map(member);
  return {
    kind: "ssh",
    keyId: list[0].keyId,
    userIds: [githubLabel(user)],
    algorithm: list[0].algorithm,
    armoredPublicKey: list[0].armored,
    addedAt: 500,
    lastUsedAt: 500,
    usableForEncryption: true,
    expiresAt: null,
    source: { type: "github", user, fetchedAt: 500 },
    ...(list.length > 1 ? { recipients: list } : {}),
  };
}

describe("classifyGithubGroup - identity", () => {
  it("is `new` when no contact carries this source", () => {
    const key = classifyGithubGroup(group([FP_A, FP_B]), []);
    expect(key.status).toBe("new");
    expect(key.kind).toBe("ssh-public");
    // The head member's, so every preview/compare path works unchanged.
    expect(key.keyId).toBe(FP_A);
    expect(key.publicArmored).toBe(`ssh-ed25519 ${FP_A}`);
    expect(key.userIds).toEqual(["octocat (GitHub)"]);
    expect(key.group?.members).toHaveLength(2);
  });

  it("matches on the source even when the first key is gone", () => {
    // The whole reason the match is by source. The stored record's
    // `keyId` is FP_A; the fetch no longer contains FP_A at all, so a
    // fingerprint match finds nothing and would say "new".
    const key = classifyGithubGroup(
      group([FP_B, FP_C]),
      [stored("octocat", [FP_A, FP_B])],
    );
    expect(key.status).toBe("update");
    expect(key.changes).toEqual(["1 key added", "1 key removed"]);
    expect(key.existingAddedAt).toBe(500);
  });

  it("does not match a hand-supplied contact that shares a fingerprint", () => {
    // No source at all: hand-supplied is not an identity, and two
    // source-less contacts are two contacts (see `sameSource`).
    const pasted: PublicContactKey = {
      ...stored("octocat", [FP_A]),
      source: undefined,
      userIds: ["alice@example.com"],
    };
    expect(classifyGithubGroup(group([FP_A]), [pasted]).status).toBe("new");
  });

  it("does not match a different github user with the same keys", () => {
    const key = classifyGithubGroup(
      group([FP_A], [], "hubot"),
      [stored("octocat", [FP_A])],
    );
    expect(key.status).toBe("new");
  });
});

describe("classifyGithubGroup - what changed", () => {
  it("is `duplicate` when the same keys come back in a different order", () => {
    // GitHub's ordering is not contractual. Comparing as a list would
    // make "nothing has changed" unreachable for a reordered response,
    // and every re-fetch would offer a pointless update.
    const key = classifyGithubGroup(
      group([FP_C, FP_A, FP_B]),
      [stored("octocat", [FP_A, FP_B, FP_C])],
    );
    expect(key.status).toBe("duplicate");
    expect(key.changes).toEqual([]);
  });

  it("counts only additions when a key was added", () => {
    const key = classifyGithubGroup(
      group([FP_A, FP_B, FP_C]),
      [stored("octocat", [FP_A])],
    );
    expect(key.status).toBe("update");
    expect(key.changes).toEqual(["2 keys added"]);
  });

  it("counts only removals when a key was revoked upstream", () => {
    const key = classifyGithubGroup(
      group([FP_A]),
      [stored("octocat", [FP_A, FP_B])],
    );
    expect(key.status).toBe("update");
    expect(key.changes).toEqual(["1 key removed"]);
  });

  it("reads a single-key stored contact through the accessor", () => {
    // The stored record has no `recipients` field at all (that is the
    // migration rule); reading `contact.recipients` directly would see
    // undefined and report every re-fetch as an update.
    const one = stored("octocat", [FP_A]);
    expect(one.recipients).toBeUndefined();
    expect(classifyGithubGroup(group([FP_A]), [one]).status).toBe("duplicate");
  });
});

describe("classifyGithubGroup - refused lines", () => {
  const ECDSA = "ECDSA keys are not supported. Use an ed25519 key instead.";

  it("carries the engine's reason for every refused line", () => {
    const key = classifyGithubGroup(
      group([FP_A], [{ line: "ecdsa-sha2-nistp256 AAAA", reason: ECDSA }]),
      [],
    );
    // Importable -- one key IS usable -- but the refusal travels with it
    // so the preview can say which key of theirs is missing and why.
    expect(key.status).toBe("new");
    expect(key.group?.rejected).toEqual([
      { line: "ecdsa-sha2-nistp256 AAAA", reason: ECDSA },
    ]);
  });

  it("rejects the import when nothing published is usable, naming the reason", () => {
    const key = classifyGithubGroup(
      group([], [{ line: "ecdsa-sha2-nistp256 AAAA", reason: ECDSA }]),
      [],
    );
    expect(key.status).toBe("rejected");
    // The engine's own words, not a generic "can't import this".
    expect(key.rejection).toBe(ECDSA);
    // No head member exists, so there is no fingerprint to claim.
    expect(key.keyId).toBe("pending");
    expect(key.publicArmored).toBe("");
  });

  it("summarises when the refusals differ", () => {
    const key = classifyGithubGroup(
      group([], [
        { line: "a", reason: ECDSA },
        { line: "b", reason: "DSA keys are not supported." },
      ]),
      [],
    );
    expect(key.status).toBe("rejected");
    expect(key.rejection).toBe(
      "None of the published keys can be used for encryption.",
    );
  });
});

describe("githubFailureCopy", () => {
  it("does not paint `no-keys` as an error", () => {
    // Nothing failed and the user has nothing to fix: the person they
    // looked up simply publishes no SSH keys. Red text here teaches
    // people to distrust a correct answer.
    const copy = githubFailureCopy("no-keys", "octocat");
    expect(copy.tone).toBe("notice");
    expect(copy.message).toContain("octocat");
  });

  it("treats every other code as an error", () => {
    for (const code of [
      "invalid-username",
      "not-found",
      "offline",
      "rate-limited",
      "server-error",
    ] as const) {
      expect(githubFailureCopy(code, "octocat").tone).toBe("error");
      expect(githubFailureCopy(code, "octocat").message.length).toBeGreaterThan(
        0,
      );
    }
  });

  it("says a rate limit is shared, and when it lifts", () => {
    // The natural reading of "rate limited" is "I did too much". The
    // lookup is unauthenticated, so GitHub counts per IP: an office or a
    // VPN uses up one budget between everyone on it.
    const copy = githubFailureCopy(
      "rate-limited",
      "octocat",
      1000 + 12 * 60_000,
      1000,
    );
    expect(copy.message).toMatch(/IP address/);
    expect(copy.message).toMatch(/about 12 minutes/);
  });

  it("says nothing about timing when no reset time was reported", () => {
    const copy = githubFailureCopy("rate-limited", "octocat");
    expect(copy.message).toMatch(/IP address/);
    expect(copy.message).not.toMatch(/Try again in/);
  });
});

describe("githubLabel", () => {
  it("names the account and where it came from", () => {
    // Auto-labelled: no prompt, no extra field. It lands in `userIds[0]`,
    // which is the one field every consumer reads for "who is this".
    expect(githubLabel("octocat")).toBe("octocat (GitHub)");
  });
});
