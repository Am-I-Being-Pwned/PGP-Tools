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

import { beforeEach, describe, expect, it, vi } from "vitest";

import type { PublicContactKey } from "../storage/contacts";
import type { ContactGroup } from "./types";
import { parseGithubKeysResponse } from "../github/response";
import { parseSshRecipient } from "../pgp/wasm";
import {
  classifyGithubGroup,
  githubFailureCopy,
  githubGroup,
  githubLabel,
  prepareGithubImport,
} from "./github";
import { defaultDecision } from "./review";

// The engine, stubbed to say exactly what the real one says: a
// fingerprint for a supported type, and one of its eight curated
// refusals for everything else. Only `prepareGithubImport` reaches it;
// every other test in this file is pure.
vi.mock("../pgp/wasm", () => ({ parseSshRecipient: vi.fn() }));

const ECDSA_REFUSAL =
  "ECDSA keys are not supported for encryption. Add an Ed25519 key with `ssh-keygen -t ed25519`.";

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
    const key = classifyGithubGroup(group([FP_B, FP_C]), [
      stored("octocat", [FP_A, FP_B]),
    ]);
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
    // ...and since its only key is already saved there, nothing is new:
    // headed by that key, the save used to replace the hand-added
    // contact with this account.
    expect(classifyGithubGroup(group([FP_A]), [pasted]).status).toBe(
      "duplicate",
    );
  });

  it("does not match a different github user with the same keys", () => {
    const key = classifyGithubGroup(group([FP_A], [], "hubot"), [
      stored("octocat", [FP_A]),
    ]);
    // Not an update of octocat -- and not a record that would land on
    // octocat's id either.
    expect(key.status).toBe("duplicate");
  });
});

describe("classifyGithubGroup - keys the user already holds", () => {
  const pasted: PublicContactKey = {
    ...stored("octocat", [FP_A]),
    source: undefined,
    userIds: ["Alice"],
    alias: "Alice",
  };

  it("never heads the record with a hand-added contact's key", () => {
    // Attack (d): an account listing Alice's key first. Headed by it, the
    // save upserted over Alice.
    const key = classifyGithubGroup(group([FP_A, FP_B]), [pasted]);
    expect(key.status).toBe("new");
    expect(key.keyId).toBe(FP_B);
    expect(key.group?.members.map((m) => m.keyId)).toEqual([FP_B, FP_A]);
  });

  it("never heads the record with one of the user's own keys", () => {
    const key = classifyGithubGroup(
      group([FP_A, FP_B]),
      [],
      [{ keyId: FP_A, userIds: ["me"] }],
    );
    expect(key.keyId).toBe(FP_B);
  });

  it("moves a refreshed record's head off an own key too", () => {
    const key = classifyGithubGroup(
      group([FP_A, FP_B, FP_C]),
      [stored("octocat", [FP_A, FP_B])],
      [{ keyId: FP_A, userIds: ["me"] }],
    );
    expect(key.status).toBe("update");
    expect(key.keyId).toBe(FP_B);
  });
});

describe("classifyGithubGroup - a refresh that drops a key", () => {
  // The account's record holds [A, X]; the account removed X. A is also
  // held elsewhere -- by a hand-added contact, or as the user's own key
  // -- so there is no key "nobody else holds" to head the record with.
  // That used to read as "nothing new to save": `duplicate`, and X went
  // on being encrypted to.
  const account = stored("octocat", [FP_A, FP_C]);
  const alice: PublicContactKey = {
    ...stored("x", [FP_B, FP_A]),
    source: undefined,
    userIds: ["Alice"],
  };

  it("is an update, kept on its own id, when a contact also holds the key", () => {
    const key = classifyGithubGroup(group([FP_A]), [account, alice]);
    expect(key.status).toBe("update");
    expect(key.keyId).toBe(FP_A);
    expect(key.changes).toEqual(["1 key removed"]);
  });

  it("is an update when the key left is the user's own", () => {
    const key = classifyGithubGroup(
      group([FP_A]),
      [account],
      [{ keyId: FP_A, userIds: ["me"] }],
    );
    expect(key.status).toBe("update");
    expect(key.changes).toEqual(["1 key removed"]);
  });

  it("asks first: the key held elsewhere still marks it", async () => {
    vi.mocked(parseSshRecipient).mockReset();
    vi.mocked(parseSshRecipient).mockImplementation((line: string) =>
      Promise.resolve({
        fingerprint: line.split(" ")[1],
        recipient: line,
        algorithm: "ssh-ed25519",
        comment: "",
      }),
    );
    const prepared = await prepareGithubImport(
      "octocat",
      [`ssh-ed25519 ${FP_A}`],
      { contacts: [account, alice] },
    );
    const [key] = prepared.keys;
    expect(key.status).toBe("update");
    expect(key.conflict?.kind).toBe("key");
    expect(defaultDecision(key)).toBe("skip");
  });

  it("is refused, never `duplicate`, when its only id is another contact's", () => {
    // The record's head is gone and the key left is ANOTHER contact's id:
    // saving would land on that contact. It cannot be saved -- but it is
    // not "nothing changed" either.
    const bob: PublicContactKey = {
      ...stored("x", [FP_B]),
      source: undefined,
      userIds: ["Bob"],
    };
    const key = classifyGithubGroup(group([FP_B]), [account, bob]);
    expect(key.status).toBe("rejected");
    expect(key.changes).toEqual(["1 key added", "2 keys removed"]);
    expect(key.rejection).toContain("octocat");
  });

  it("is still `duplicate` when nothing changed", () => {
    const key = classifyGithubGroup(group([FP_C, FP_A]), [account, alice]);
    expect(key.status).toBe("duplicate");
  });
});

describe("classifyGithubGroup - keys the user turned off", () => {
  const off = (keyId: string) => ({
    ...member(keyId),
    disabled: true as const,
  });
  const withOff = (list: ReturnType<typeof member>[]): PublicContactKey => ({
    ...stored("octocat", [list[0].keyId]),
    recipients: list,
  });

  it("asks when every key the account still lists is one the user turned off", () => {
    // [A, B, C(off)] -> the account deleted A and B.
    const record = withOff([member(FP_A), member(FP_B), off(FP_C)]);
    const key = classifyGithubGroup(group([FP_C]), [record]);
    expect(key.status).toBe("update");
    expect(key.allKeysOff).toBe(true);
    expect(defaultDecision(key)).toBe("skip");
  });

  it("asks for two such keys as for one", () => {
    const record = withOff([member(FP_A), off(FP_B), off(FP_C)]);
    const key = classifyGithubGroup(group([FP_B, FP_C]), [record]);
    expect(key.allKeysOff).toBe(true);
  });

  it("does not ask while a key the user kept, or a new one, is listed", () => {
    const record = withOff([member(FP_A), member(FP_B), off(FP_C)]);
    expect(
      classifyGithubGroup(group([FP_B, FP_C]), [record]).allKeysOff,
    ).toBeUndefined();
    const fresh = "SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
    const key = classifyGithubGroup(group([FP_C, fresh]), [record]);
    expect(key.allKeysOff).toBeUndefined();
    expect(defaultDecision(key)).toBe("import");
  });
});

describe("prepareGithubImport - checked like a paste", () => {
  beforeEach(() => {
    vi.mocked(parseSshRecipient).mockReset();
    vi.mocked(parseSshRecipient).mockImplementation((line: string) => {
      const keyId = line.split(" ")[1];
      return Promise.resolve({
        fingerprint: keyId,
        recipient: line,
        algorithm: "ssh-ed25519",
        comment: "",
      });
    });
  });

  it("marks an account carrying a contact's key, and starts it on Skip", async () => {
    const pasted: PublicContactKey = {
      ...stored("octocat", [FP_A]),
      source: undefined,
      userIds: ["alice@laptop"],
    };
    const prepared = await prepareGithubImport(
      "mallory",
      [`ssh-ed25519 ${FP_A}`, `ssh-ed25519 ${FP_B}`],
      { contacts: [pasted] },
    );
    const [key] = prepared.keys;
    expect(key.conflict?.kind).toBe("key");
    expect(key.conflict?.holders.map((h) => h.keyId)).toEqual([FP_A]);
    expect(defaultDecision(key)).toBe("skip");
  });

  it("marks an account carrying the user's own key", async () => {
    const prepared = await prepareGithubImport(
      "octocat",
      [`ssh-ed25519 ${FP_A}`, `ssh-ed25519 ${FP_B}`],
      { contacts: [], own: [{ keyId: FP_A, userIds: ["me"] }] },
    );
    expect(prepared.keys[0].conflict?.holders[0].own).toBe(true);
  });

  it("does not mark a refresh for the keys its own account returned", async () => {
    const prepared = await prepareGithubImport(
      "octocat",
      [`ssh-ed25519 ${FP_A}`, `ssh-ed25519 ${FP_B}`, `ssh-ed25519 ${FP_C}`],
      { contacts: [stored("octocat", [FP_A, FP_B])] },
    );
    expect(prepared.keys[0].status).toBe("update");
    expect(prepared.keys[0].conflict).toBeUndefined();
  });

  it("checks the account name against the contacts' names", async () => {
    // A lookalike of a contact's name: "carol" with a Cyrillic а. The
    // very same name is someone else who shares it, and is not asked.
    const carol: PublicContactKey = {
      ...stored("x", [FP_C]),
      source: undefined,
      userIds: ["C\u0430rol <carol@example.com>"],
    };
    const prepared = await prepareGithubImport(
      "carol",
      [`ssh-ed25519 ${FP_A}`],
      { contacts: [carol] },
    );
    expect(prepared.keys[0].conflict?.kind).toBe("name");
  });
});

describe("classifyGithubGroup - what changed", () => {
  it("is `duplicate` when the same keys come back in a different order", () => {
    // GitHub's ordering is not contractual. Comparing as a list would
    // make "nothing has changed" unreachable for a reordered response,
    // and every re-fetch would offer a pointless update.
    const key = classifyGithubGroup(group([FP_C, FP_A, FP_B]), [
      stored("octocat", [FP_A, FP_B, FP_C]),
    ]);
    expect(key.status).toBe("duplicate");
    expect(key.changes).toEqual([]);
  });

  it("counts only additions when a key was added", () => {
    const key = classifyGithubGroup(group([FP_A, FP_B, FP_C]), [
      stored("octocat", [FP_A]),
    ]);
    expect(key.status).toBe("update");
    expect(key.changes).toEqual(["2 keys added"]);
  });

  it("counts only removals when a key was revoked upstream", () => {
    const key = classifyGithubGroup(group([FP_A]), [
      stored("octocat", [FP_A, FP_B]),
    ]);
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
      group(
        [],
        [
          { line: "a", reason: ECDSA },
          { line: "b", reason: "DSA keys are not supported." },
        ],
      ),
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

  it("carries the reset header all the way from a raw 403 to the words", () => {
    // The seam the e2e nearly became the only cover for: the response
    // parser turns `x-ratelimit-reset` (unix SECONDS) into `resetAt`
    // (ms), and the copy turns that into a clause. Either half can be
    // right while the join is wrong, and a lost reset time is invisible
    // -- the rest of the sentence still renders.
    const now = 1_750_000_000_000;
    const result = parseGithubKeysResponse({
      status: 403,
      contentType: "application/json",
      body: "{}",
      rateLimitRemaining: "0",
      rateLimitReset: String(1_750_000_000 + 15 * 60),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const copy = githubFailureCopy(
      result.error,
      "octocat",
      result.resetAt,
      now,
    );
    expect(copy.message).toMatch(/about 15 minutes/);
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

describe("prepareGithubImport - the engine decides, not the worker", () => {
  const stub = vi.mocked(parseSshRecipient);

  /** Ed25519 parses; anything else comes back as the engine's own
   *  refusal, which is the text the preview must show. */
  function engine() {
    stub.mockReset();
    stub.mockImplementation((line: string) => {
      if (!line.startsWith("ssh-ed25519")) throw new Error(ECDSA_REFUSAL);
      return Promise.resolve({
        fingerprint: `SHA256:${line.slice(-8)}`,
        recipient: line,
        algorithm: "ssh-ed25519",
      } as Awaited<ReturnType<typeof parseSshRecipient>>);
    });
  }

  const ED_A = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAaaaaaaaa";
  const ED_B = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAbbbbbbbb";
  const ECDSA = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY";

  it("reports an ECDSA-only account with the engine's words, not silence", async () => {
    engine();
    const prepared = await prepareGithubImport(
      "octocat",
      [ECDSA],
      { contacts: [] },
      { now: 1000 },
    );
    const key = prepared.keys[0];
    // Rejected, and carrying WHY -- not "octocat hasn't published any
    // SSH keys", which is what the user used to be told.
    expect(key.status).toBe("rejected");
    expect(key.group?.rejected).toEqual([
      { line: ECDSA, reason: ECDSA_REFUSAL },
    ]);
    expect(key.rejection).toBe(ECDSA_REFUSAL);
  });

  it("keeps the refusal alongside the keys that did parse", async () => {
    engine();
    const prepared = await prepareGithubImport(
      "octocat",
      [ED_A, ED_B, ECDSA],
      { contacts: [] },
      { now: 1000 },
    );
    const key = prepared.keys[0];
    expect(key.status).toBe("new");
    expect(key.group?.members).toHaveLength(2);
    // The preview says "encrypted to every key listed above"; a silently
    // dropped third key makes that sentence false.
    expect(key.group?.rejected.map((r) => r.reason)).toEqual([ECDSA_REFUSAL]);
  });

  it("says so when the worker's caps held keys back", async () => {
    engine();
    const prepared = await prepareGithubImport(
      "octocat",
      [ED_A],
      { contacts: [] },
      { omitted: 3, now: 1000 },
    );
    const rejected = prepared.keys[0].group?.rejected ?? [];
    expect(rejected).toHaveLength(1);
    expect(rejected[0].reason).toMatch(/3 of octocat's published keys/);
    expect(rejected[0].reason).toMatch(/at most 20 keys/);
  });

  it("says nothing about caps when nothing was held back", async () => {
    engine();
    const prepared = await prepareGithubImport("octocat", [ED_A], {
      contacts: [],
    });
    expect(prepared.keys[0].group?.rejected).toEqual([]);
  });
});
