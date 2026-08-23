import { describe, expect, it } from "vitest";

import type { PublicContactKey } from "./storage/contacts";
import type { ProtectedKeyBlob } from "./storage/keyring";
import {
  buildEncryptRecipients,
  MIXED_ENGINE_REASON,
  resolveRecipientEngine,
  resolveSelectedRecipients,
  resolveSelfKey,
  toSelectedRecipient,
} from "./encrypt-recipients";

const RECIPIENT = { keyId: "AAAA", armored: "recipient-armor" };
const RECIPIENT_2 = { keyId: "BBBB", armored: "recipient-2-armor" };
const OWN_A = { keyId: "1111", publicKeyArmored: "own-a-armor" };
const OWN_B = { keyId: "2222", publicKeyArmored: "own-b-armor" };
const OWN_A_SELECTED = { keyId: OWN_A.keyId, armored: OWN_A.publicKeyArmored };
const OWN_B_SELECTED = { keyId: OWN_B.keyId, armored: OWN_B.publicKeyArmored };

describe("resolveSelfKey", () => {
  it("returns null when the user owns no keys", () => {
    expect(resolveSelfKey([], null)).toBeNull();
    expect(resolveSelfKey([], OWN_A.keyId, OWN_B.keyId)).toBeNull();
  });

  it("falls back to the first key when no default is set", () => {
    expect(resolveSelfKey([OWN_A, OWN_B], null)).toBe(OWN_A);
  });

  it("prefers a valid default key over the first key", () => {
    expect(resolveSelfKey([OWN_A, OWN_B], OWN_B.keyId)).toBe(OWN_B);
  });

  it("prefers the default key over the signing key", () => {
    expect(resolveSelfKey([OWN_A, OWN_B], OWN_B.keyId, OWN_A.keyId)).toBe(
      OWN_B,
    );
  });

  it("uses the signing key when no default is set", () => {
    expect(resolveSelfKey([OWN_A, OWN_B], null, OWN_B.keyId)).toBe(OWN_B);
  });

  it("ignores a stale default and falls back to the signing key", () => {
    expect(resolveSelfKey([OWN_A, OWN_B], "deleted-key", OWN_B.keyId)).toBe(
      OWN_B,
    );
  });

  it("ignores a stale default and falls back to the first key", () => {
    expect(resolveSelfKey([OWN_A, OWN_B], "deleted-key")).toBe(OWN_A);
  });

  it("ignores a stale signing key too", () => {
    expect(resolveSelfKey([OWN_A, OWN_B], null, "deleted-key")).toBe(OWN_A);
  });
});

describe("buildEncryptRecipients", () => {
  it("adds the first own key when encrypt-to-self is enabled", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_A.publicKeyArmored,
    ]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBe(OWN_A.keyId);
  });

  it("prefers the signing key as the self recipient", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      signingKeyId: OWN_B.keyId,
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_B.publicKeyArmored,
    ]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBe(OWN_B.keyId);
  });

  it("falls back to the first own key when the signing key is unknown", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      signingKeyId: "deleted-key",
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_A.publicKeyArmored,
    ]);
  });

  it("dedupes when the recipient is one of the user's own keys", () => {
    const result = buildEncryptRecipients({
      recipients: [OWN_A_SELECTED],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
    });
    expect(result.recipientPublicKeys).toEqual([OWN_A.publicKeyArmored]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBeNull();
  });

  it("does not warn when disabled but the recipient is self", () => {
    const result = buildEncryptRecipients({
      recipients: [OWN_A_SELECTED],
      encryptToSelf: false,
      ownKeys: [OWN_A],
    });
    expect(result.recipientPublicKeys).toEqual([OWN_A.publicKeyArmored]);
    expect(result.selfExcluded).toBe(false);
  });

  it("flags self-exclusion when no own key exists", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: true,
      ownKeys: [],
    });
    expect(result.recipientPublicKeys).toEqual([RECIPIENT.armored]);
    expect(result.selfExcluded).toBe(true);
  });

  it("flags self-exclusion when disabled", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: false,
      ownKeys: [OWN_A],
    });
    expect(result.recipientPublicKeys).toEqual([RECIPIENT.armored]);
    expect(result.selfExcluded).toBe(true);
  });

  it("encrypts to all selected recipients plus the self key", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT, RECIPIENT_2],
      encryptToSelf: true,
      ownKeys: [OWN_A],
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      RECIPIENT_2.armored,
      OWN_A.publicKeyArmored,
    ]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBe(OWN_A.keyId);
  });

  it("dedupes selected recipients by fingerprint", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT, { keyId: RECIPIENT.keyId, armored: "dupe" }],
      encryptToSelf: false,
      ownKeys: [],
    });
    expect(result.recipientPublicKeys).toEqual([RECIPIENT.armored]);
  });

  it("skips the self key when an own key is already among the recipients", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT, OWN_A_SELECTED],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_A.publicKeyArmored,
    ]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBeNull();
  });

  it("does not warn when disabled but an own key is among multiple recipients", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT, OWN_A_SELECTED, RECIPIENT_2],
      encryptToSelf: false,
      ownKeys: [OWN_A],
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_A.publicKeyArmored,
      RECIPIENT_2.armored,
    ]);
    expect(result.selfExcluded).toBe(false);
  });

  it("flags self-exclusion for multiple recipients when disabled", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT, RECIPIENT_2],
      encryptToSelf: false,
      ownKeys: [OWN_A],
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      RECIPIENT_2.armored,
    ]);
    expect(result.selfExcluded).toBe(true);
    expect(result.selfKeyId).toBeNull();
  });

  it("prefers the default key as the self recipient", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      defaultKeyId: OWN_B.keyId,
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_B.publicKeyArmored,
    ]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBe(OWN_B.keyId);
  });

  it("prefers the default key over the signing key", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      signingKeyId: OWN_A.keyId,
      defaultKeyId: OWN_B.keyId,
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_B.publicKeyArmored,
    ]);
    expect(result.selfKeyId).toBe(OWN_B.keyId);
  });

  it("ignores a stale default key and falls back to the signing key", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      signingKeyId: OWN_B.keyId,
      defaultKeyId: "deleted-key",
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_B.publicKeyArmored,
    ]);
    expect(result.selfKeyId).toBe(OWN_B.keyId);
  });

  it("does not double-add when the default key is a selected recipient", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT, OWN_B_SELECTED],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      defaultKeyId: OWN_B.keyId,
    });
    expect(result.recipientPublicKeys).toEqual([
      RECIPIENT.armored,
      OWN_B.publicKeyArmored,
    ]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBeNull();
  });

  it("skips the self key when ANOTHER own key is a selected recipient, even with a default set", () => {
    const result = buildEncryptRecipients({
      recipients: [OWN_A_SELECTED],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_B],
      defaultKeyId: OWN_B.keyId,
    });
    expect(result.recipientPublicKeys).toEqual([OWN_A.publicKeyArmored]);
    expect(result.selfExcluded).toBe(false);
    expect(result.selfKeyId).toBeNull();
  });
});

/**
 * The engine split.
 *
 * OpenPGP and age produce two different files; there is no message that
 * is both. The failure being prevented is not a crash but a plausible
 * half-success -- an "encrypt" that quietly reaches only the recipients
 * of whichever engine won -- so the mixed case is refused with a reason
 * the UI can show, and the recipient list is emptied so a caller that
 * ignores the refusal encrypts to nobody rather than to the wrong subset.
 *
 * `kind` is absent on every recipient the app built before the age engine
 * existed, and absent MEANS pgp (see `storage/key-kind.ts`) -- so the
 * whole suite above, which sets no `kind` at all, is also the regression
 * test for that.
 */
const SSH_RECIPIENT = {
  keyId: "SHA256:aaa",
  armored: "ssh-ed25519 AAAAC3Nza a@h",
  kind: "ssh" as const,
};
const SSH_RECIPIENT_2 = {
  keyId: "SHA256:bbb",
  armored: "ssh-ed25519 AAAAC3Nzb b@h",
  kind: "ssh" as const,
};
const OWN_SSH = {
  keyId: "SHA256:me",
  publicKeyArmored: "ssh-ed25519 AAAAC3Nzc me@h",
  kind: "ssh" as const,
};

describe("resolveRecipientEngine", () => {
  it("reports no engine for an empty selection", () => {
    expect(resolveRecipientEngine([])).toEqual({ engine: null, reason: null });
  });

  it("treats a recipient with no kind as pgp", () => {
    expect(resolveRecipientEngine([RECIPIENT])).toEqual({
      engine: "pgp",
      reason: null,
    });
  });

  it("reports ssh for an all-SSH selection", () => {
    expect(resolveRecipientEngine([SSH_RECIPIENT, SSH_RECIPIENT_2])).toEqual({
      engine: "ssh",
      reason: null,
    });
  });

  it("refuses a mixed selection with a reason", () => {
    const { engine, reason } = resolveRecipientEngine([
      RECIPIENT,
      SSH_RECIPIENT,
    ]);
    expect(engine).toBeNull();
    expect(reason).toBe(MIXED_ENGINE_REASON);
  });

  it("refuses a mix of an explicit pgp kind and an absent one alike", () => {
    // Absent and explicit "pgp" must be the SAME engine, or a contact
    // saved before the field existed would refuse to share a message
    // with one saved after.
    expect(
      resolveRecipientEngine([{ ...RECIPIENT, kind: "pgp" }, RECIPIENT_2])
        .reason,
    ).toBeNull();
  });
});

describe("buildEncryptRecipients - engines", () => {
  it("refuses to build a mixed recipient set, and hands back none", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT, SSH_RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A],
    });
    expect(result.refusal).toBe(MIXED_ENGINE_REASON);
    expect(result.recipientPublicKeys).toEqual([]);
    expect(result.engine).toBeNull();
    expect(result.selfKeyId).toBeNull();
  });

  it("reports the pgp engine for a legacy (kind-less) selection", () => {
    const result = buildEncryptRecipients({
      recipients: [RECIPIENT],
      encryptToSelf: false,
      ownKeys: [OWN_A],
    });
    expect(result.engine).toBe("pgp");
    expect(result.refusal).toBeNull();
  });

  it("keeps encrypt-to-self inside the SSH engine", () => {
    const result = buildEncryptRecipients({
      recipients: [SSH_RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_SSH],
    });
    expect(result.engine).toBe("ssh");
    expect(result.recipientPublicKeys).toEqual([
      SSH_RECIPIENT.armored,
      OWN_SSH.publicKeyArmored,
    ]);
    expect(result.selfKeyId).toBe(OWN_SSH.keyId);
  });

  it("flags self-exclusion when the user owns no key for this engine", () => {
    // Adding their PGP key to an age message would be the same mixing,
    // reached by a different route -- so it is excluded, and said so.
    const result = buildEncryptRecipients({
      recipients: [SSH_RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A],
    });
    expect(result.recipientPublicKeys).toEqual([SSH_RECIPIENT.armored]);
    expect(result.selfExcluded).toBe(true);
    expect(result.selfKeyId).toBeNull();
  });

  it("ignores a default key from the other engine", () => {
    const result = buildEncryptRecipients({
      recipients: [SSH_RECIPIENT],
      encryptToSelf: true,
      ownKeys: [OWN_A, OWN_SSH],
      defaultKeyId: OWN_A.keyId,
    });
    expect(result.selfKeyId).toBe(OWN_SSH.keyId);
  });

  it("takes the engine from the self key when nothing is selected", () => {
    const result = buildEncryptRecipients({
      recipients: [],
      encryptToSelf: true,
      ownKeys: [OWN_SSH],
    });
    expect(result.engine).toBe("ssh");
    expect(result.recipientPublicKeys).toEqual([OWN_SSH.publicKeyArmored]);
  });
});

describe("multi-recipient contacts", () => {
  /** A contact holding `armors` keys, as the picker hands it over. */
  function contact(
    keyId: string,
    armors: string[],
    kind: "pgp" | "ssh" = "ssh",
  ) {
    return {
      kind,
      keyId,
      userIds: [keyId],
      algorithm: "ssh-ed25519",
      armoredPublicKey: armors[0],
      addedAt: 1,
      lastUsedAt: 1,
      ...(armors.length > 1
        ? {
            recipients: armors.map((armored, i) => ({
              keyId: `${keyId}-${i}`,
              armored,
              algorithm: "ssh-ed25519",
            })),
          }
        : {}),
    };
  }

  it("expands one 3-key contact into three armored strings", () => {
    const result = buildEncryptRecipients({
      recipients: [toSelectedRecipient(contact("octocat", ["k0", "k1", "k2"]))],
      encryptToSelf: false,
      ownKeys: [],
    });
    expect(result.recipientPublicKeys).toEqual(["k0", "k1", "k2"]);
    expect(result.engine).toBe("ssh");
  });

  it("dedupes to the union when two contacts share a key", () => {
    const result = buildEncryptRecipients({
      recipients: [
        toSelectedRecipient(contact("octocat", ["k0", "shared"])),
        toSelectedRecipient(contact("hubot", ["shared", "k9"])),
      ],
      encryptToSelf: false,
      ownKeys: [],
    });
    // Union, in first-seen order -- a repeated age stanza is wasteful
    // and odd-looking in the header.
    expect(result.recipientPublicKeys).toEqual(["k0", "shared", "k9"]);
  });

  it("still refuses a multi-key SSH contact mixed with a PGP contact", () => {
    const result = buildEncryptRecipients({
      recipients: [
        toSelectedRecipient(contact("octocat", ["k0", "k1", "k2"])),
        toSelectedRecipient(contact("carol", ["pgp-armor"], "pgp")),
      ],
      encryptToSelf: true,
      ownKeys: [OWN_A],
    });
    expect(result.refusal).toBe(MIXED_ENGINE_REASON);
    expect(result.recipientPublicKeys).toEqual([]);
    expect(result.engine).toBeNull();
  });

  it("appends exactly one own key alongside a 3-key contact", () => {
    const ownSsh = {
      keyId: "SHA256:mine",
      publicKeyArmored: "my-ssh-armor",
      kind: "ssh" as const,
    };
    const result = buildEncryptRecipients({
      recipients: [toSelectedRecipient(contact("octocat", ["k0", "k1", "k2"]))],
      encryptToSelf: true,
      ownKeys: [OWN_A, ownSsh],
    });
    expect(result.recipientPublicKeys).toEqual([
      "k0",
      "k1",
      "k2",
      "my-ssh-armor",
    ]);
    expect(result.selfKeyId).toBe(ownSsh.keyId);
  });

  it("leaves a single-key contact exactly as before", () => {
    const one = toSelectedRecipient(contact("carol", ["only"], "pgp"));
    expect(one.armored).toBe("only");
    expect(one.armoredAll).toEqual(["only"]);
    expect(
      buildEncryptRecipients({
        recipients: [one],
        encryptToSelf: false,
        ownKeys: [],
      }).recipientPublicKeys,
    ).toEqual(["only"]);
  });

  it("treats an own key (no armoredAll) as its single armored string", () => {
    const own = toSelectedRecipient(OWN_A);
    expect(own.armoredAll).toBeUndefined();
    expect(
      buildEncryptRecipients({
        recipients: [own],
        encryptToSelf: false,
        ownKeys: [],
      }).recipientPublicKeys,
    ).toEqual([OWN_A.publicKeyArmored]);
  });
});

/**
 * Turning a contact's key off has to bite HERE, in the one place that
 * decides what a message is encrypted to. Everything else about the
 * feature is cosmetic if this list is wrong.
 */
describe("disabled recipients - what actually gets encrypted to", () => {
  /** A 3-key SSH contact; `off` names the indexes the user turned off.
   *  `disabled` is written only where it is true -- absent means
   *  enabled, and `false` is never stored. */
  function contact(off: number[] = []) {
    const armors = ["k0", "k1", "k2"];
    return {
      kind: "ssh" as const,
      keyId: "octocat",
      userIds: ["octocat"],
      algorithm: "ssh-ed25519",
      armoredPublicKey: armors[0],
      addedAt: 1,
      lastUsedAt: 1,
      recipients: armors.map((armored, i) => ({
        keyId: `octocat-${i}`,
        armored,
        algorithm: "ssh-ed25519",
        ...(off.includes(i) ? { disabled: true as const } : {}),
      })),
    };
  }

  it("expands only the ACTIVE keys", () => {
    expect(toSelectedRecipient(contact([1])).armoredAll).toEqual(["k0", "k2"]);
    expect(toSelectedRecipient(contact([0, 2])).armoredAll).toEqual(["k1"]);
  });

  it("expands all of them when none is turned off", () => {
    expect(toSelectedRecipient(contact()).armoredAll).toEqual([
      "k0",
      "k1",
      "k2",
    ]);
  });

  it("drops the disabled key from the assembled recipient set", () => {
    const result = buildEncryptRecipients({
      recipients: [toSelectedRecipient(contact([1]))],
      encryptToSelf: false,
      ownKeys: [],
    });
    expect(result.recipientPublicKeys).toEqual(["k0", "k2"]);
    expect(result.recipientPublicKeys).not.toContain("k1");
  });

  it("still encrypts to SOMEBODY when a stored record has every key off", () => {
    // The UI refuses to reach this state; a hand-edited blob could. The
    // fallback must be "the pre-feature behaviour", never an empty
    // recipient set -- a file encrypted to nobody is unrecoverable.
    const result = buildEncryptRecipients({
      recipients: [toSelectedRecipient(contact([0, 1, 2]))],
      encryptToSelf: false,
      ownKeys: [],
    });
    expect(result.recipientPublicKeys).toEqual(["k0", "k1", "k2"]);
  });

  it("keeps the head key as `armored` even when the head is turned off", () => {
    // `armored` is the RECORD's head key, which dedupe and downgraded
    // callers compare on; only `armoredAll` narrows.
    const selected = toSelectedRecipient(contact([0]));
    expect(selected.armored).toBe("k0");
    expect(selected.armoredAll).toEqual(["k1", "k2"]);
  });
});

describe("resolveSelectedRecipients", () => {
  /**
   * The regression this exists for: a contact's `keyId` IS its head
   * recipient's fingerprint, so when that key is also one of the user's
   * own identities the id lives in both collections. Resolving to the
   * own key drops the contact's other recipients and the message is
   * encrypted to ONE key instead of all of them -- a valid age file the
   * person's other machines cannot open, with nothing failing or
   * warning. Found by e2e (1 stanza where 3 were expected).
   */
  const head = {
    keyId: "SHA256:head",
    armored: "ssh-ed25519 AAAAhead",
    algorithm: "ssh-ed25519",
  };
  const second = {
    keyId: "SHA256:two",
    armored: "ssh-ed25519 AAAAtwo",
    algorithm: "ssh-ed25519",
  };

  const contact = {
    keyId: head.keyId,
    userIds: ["otto"],
    algorithm: "ssh-ed25519",
    armoredPublicKey: head.armored,
    recipients: [head, second],
    kind: "ssh" as const,
    addedAt: 0,
    lastUsedAt: 0,
  } as unknown as PublicContactKey;

  const ownKeyWithSameFingerprint = {
    keyId: head.keyId,
    userIds: ["me"],
    algorithm: "ssh-ed25519",
    publicKeyArmored: head.armored,
    kind: "ssh" as const,
  } as unknown as ProtectedKeyBlob;

  it("prefers the contact when an own key shares its head fingerprint", () => {
    const [resolved] = resolveSelectedRecipients(
      [head.keyId],
      [contact],
      [ownKeyWithSameFingerprint],
    );
    expect(resolved).toBe(contact);
    // The property that actually matters: every recipient survives.
    expect(toSelectedRecipient(resolved).armoredAll).toEqual([
      head.armored,
      second.armored,
    ]);
  });

  it("still resolves an own key that no contact claims", () => {
    const own = { ...ownKeyWithSameFingerprint, keyId: "SHA256:mine" };
    const [resolved] = resolveSelectedRecipients(
      ["SHA256:mine"],
      [contact],
      [own as unknown as ProtectedKeyBlob],
    );
    expect(resolved).toBe(own);
  });

  it("drops an id that matches nothing", () => {
    expect(resolveSelectedRecipients(["nope"], [contact], [])).toEqual([]);
  });
});
