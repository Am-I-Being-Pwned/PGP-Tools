/**
 * The OpenPGP -> presentation adapter behind the key body.
 *
 * `KeyPreviewBody` used to take a `KeyInfo` directly, which quietly made
 * "a key" mean "an OpenPGP certificate". It now takes {@link KeyFacts},
 * and every engine supplies the facts it has. Two properties make that
 * work, and neither is enforced by the compiler:
 *
 *  1. The PGP adapter is lossless -- if it drops `expiresAt`, or turns a
 *     `null` expiry into `undefined`, the body stops rendering a row it
 *     used to render and nobody sees an error.
 *  2. Absent is a first-class state, not a missing value. An engine with
 *     no creation date, no expiry and no health verdict (SSH, CRX)
 *     supplies none of them, and the body must read that as "there is no
 *     such fact", never as "the fact hasn't loaded yet".
 *
 * `null` and `undefined` therefore mean different things here and are
 * asserted separately throughout: `expiresAt: null` renders "Never";
 * `expiresAt` absent renders nothing at all.
 */

import { describe, expect, it } from "vitest";

import type { KeyDetails, KeyInfo, SubkeyDetail } from "../../lib/pgp/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ComponentKeyRow, KeyFacts } from "./key-facts";
import {
  activeRecipients,
  contactRecipients,
} from "../../lib/storage/contacts";
import { pgpKeyFacts, sshGroupKeyFacts, sshKeyFacts } from "./key-facts";

const FP = "3A9E1F5C7B2D48E6A0C1938574FD62B0E4A75C11";
const CREATED = Date.UTC(2024, 0, 2);
const EXPIRES = Date.UTC(2027, 0, 4);

function info(over: Partial<KeyInfo> = {}): KeyInfo {
  return {
    keyId: FP,
    userIds: ["Alice <alice@example.com>"],
    algorithm: "ed25519",
    createdAt: CREATED,
    expiresAt: EXPIRES,
    isPrivate: false,
    usableForEncryption: true,
    usableForSigning: true,
    ...over,
  };
}

function subkey(over: Partial<SubkeyDetail> = {}): SubkeyDetail {
  return {
    fingerprint: FP,
    keyId: FP.slice(-16),
    algorithm: "ed25519",
    bits: 256,
    createdAt: CREATED,
    expiresAt: null,
    isPrimary: true,
    canSign: true,
    canEncrypt: false,
    canCertify: true,
    canAuthenticate: false,
    status: "active",
    ...over,
  };
}

describe("pgpKeyFacts", () => {
  it("carries every fact the cert has through unchanged", () => {
    const details: KeyDetails = {
      keys: [subkey(), subkey({ fingerprint: "SUB-1", isPrimary: false })],
      truncated: true,
    };
    const facts = pgpKeyFacts(info(), details);

    expect(facts.fingerprint).toBe(FP);
    expect(facts.algorithm).toBe("ed25519");
    expect(facts.createdAt).toBe(CREATED);
    expect(facts.expiresAt).toBe(EXPIRES);
    expect(facts.health).toEqual({
      usableForEncryption: true,
      usableForSigning: true,
      policyError: undefined,
    });
    // The component rows are a pass-through, not a mapping: every field
    // the breakdown parsed has to reach the row the UI renders.
    expect(facts.components).toEqual({ rows: details.keys, truncated: true });
    expect(facts.components?.rows[0]).toEqual(details.keys[0]);
  });

  it("keeps the identifier the cert's fingerprint, not its short key id", () => {
    // The facts card copies this value; a short id here would silently
    // downgrade what the user pastes elsewhere as the key's identity.
    expect(pgpKeyFacts(info(), null).fingerprint).toBe(FP);
    expect(pgpKeyFacts(info(), null).fingerprint).toHaveLength(40);
  });

  it("distinguishes a never-expiring key from one with no expiry concept", () => {
    // null => the row renders "Never". undefined => the row is absent.
    // Collapsing the two would tell the user a key never expires when in
    // fact nothing was ever asserted about it.
    const never = pgpKeyFacts(info({ expiresAt: null }), null);
    expect(never.expiresAt).toBeNull();
    expect("expiresAt" in never).toBe(true);

    const sshLike: KeyFacts = {
      fingerprint: "SHA256:abc",
      algorithm: "ed25519",
    };
    expect(sshLike.expiresAt).toBeUndefined();
    expect("expiresAt" in sshLike).toBe(false);
  });

  it("carries a policy rejection into the health verdict", () => {
    // The health banner is the only place a user learns why a key was
    // refused; a dropped `policyError` turns that into a silent refusal.
    const facts = pgpKeyFacts(
      info({
        usableForEncryption: false,
        usableForSigning: false,
        policyError: "Relies on a SHA-1 binding signature",
      }),
      null,
    );
    expect(facts.health).toEqual({
      usableForEncryption: false,
      usableForSigning: false,
      policyError: "Relies on a SHA-1 binding signature",
    });
  });

  it("omits the breakdown entirely when it failed to parse", () => {
    // NOT `{ rows: [], truncated: false }` -- an empty rows array is a
    // cert with no component keys, which would render an empty section
    // where the real answer is "we couldn't decompose this cert".
    const facts = pgpKeyFacts(info(), null);
    expect(facts.components).toBeUndefined();
    expect(facts.createdAt).toBe(CREATED);
    expect(facts.health).toBeDefined();
  });
});

describe("KeyFacts as an engine-generic shape", () => {
  it("accepts a key with a fingerprint and an algorithm and nothing else", () => {
    // The SSH / CRX case. Only two fields are required; everything else
    // being absent must be an ordinary, complete value -- no crash, and
    // nothing a renderer could mistake for "still loading".
    const facts: KeyFacts = {
      fingerprint: "SHA256:2f9c1b",
      algorithm: "ssh-ed25519",
    };

    expect(Object.keys(facts).sort()).toEqual(["algorithm", "fingerprint"]);
    expect(facts.createdAt).toBeUndefined();
    expect(facts.expiresAt).toBeUndefined();
    expect(facts.health).toBeUndefined();
    expect(facts.components).toBeUndefined();
    // Anything reading these has to cope with `undefined` rather than
    // waiting for a value that is never coming.
    expect(JSON.parse(JSON.stringify(facts))).toEqual(facts);
  });

  it("takes an OpenPGP SubkeyDetail as a component row without mapping", () => {
    // `ComponentKeyRow` is documented as a structural subset of
    // `SubkeyDetail` so the adapter can stay a pass-through. If the two
    // drift, this assignment stops compiling -- which is the point.
    const row: ComponentKeyRow = subkey({
      status: "revoked",
      revocationReason: "superseded",
    });
    expect(row.status).toBe("revoked");
    expect(row.revocationReason).toBe("superseded");
    expect(row.bits).toBe(256);
  });
});

describe("sshKeyFacts", () => {
  const FINGERPRINT = "SHA256:1SW9SD9BdyMCLwPCLtN4a3ZDNz5oIpvo/1Rk0nCyLqk";

  it("carries the two facts an SSH key has", () => {
    const facts = sshKeyFacts(FINGERPRINT, "ssh-ed25519");
    expect(facts.fingerprint).toBe(FINGERPRINT);
    expect(facts.algorithm).toBe("ssh-ed25519");
  });

  it("leaves every certificate fact ABSENT, not null", () => {
    // Absent means the row doesn't render at all; `null` would render
    // "Never" for the expiry and a blank for the rest. An SSH key is not
    // a certificate with empty fields.
    const facts = sshKeyFacts(FINGERPRINT, "ssh-rsa");
    expect(facts).not.toHaveProperty("createdAt");
    expect(facts).not.toHaveProperty("expiresAt");
    expect(facts).not.toHaveProperty("health");
    expect(facts).not.toHaveProperty("components");
  });
});

describe("sshGroupKeyFacts", () => {
  const members = [
    {
      keyId: "SHA256:aaa",
      armored: "ssh-ed25519 AAA",
      algorithm: "ssh-ed25519",
    },
    { keyId: "SHA256:bbb", armored: "ssh-rsa BBB", algorithm: "ssh-rsa" },
    {
      keyId: "SHA256:ccc",
      armored: "ssh-ed25519 CCC",
      algorithm: "ssh-ed25519",
    },
  ];

  it("shows EVERY fingerprint, in full", () => {
    // The fingerprints are the only out-of-band check a user has: they
    // can read them off github.com/<user>.keys, or ask the person over
    // another channel. Summarising three keys as "3 keys", or listing
    // two and a "+1 more", removes the one thing that makes "did GitHub
    // hand back a key this person never published?" a checkable
    // question. So: a row each, and the fingerprint uncut.
    const facts = sshGroupKeyFacts(members);
    expect(facts.components?.rows.map((r) => r.fingerprint)).toEqual([
      "SHA256:aaa",
      "SHA256:bbb",
      "SHA256:ccc",
    ]);
    expect(facts.components?.truncated).toBe(false);
    // Per-key algorithm, not the head's repeated three times: a contact
    // whose phone key is ssh-rsa and laptop ed25519 is ordinary.
    expect(facts.components?.rows.map((r) => r.algorithm)).toEqual([
      "ssh-ed25519",
      "ssh-rsa",
      "ssh-ed25519",
    ]);
  });

  it("keeps the head key as the record's identity", () => {
    // What the facts card shows, and what the stored contact's `keyId`
    // will be (see `recipientsField`).
    const facts = sshGroupKeyFacts(members);
    expect(facts.fingerprint).toBe("SHA256:aaa");
    expect(facts.algorithm).toBe("ssh-ed25519");
  });

  it("lists every key as a peer, never as a subkey of the first", () => {
    // The body renders exactly the non-primary rows, so a row marked
    // primary would vanish from the list -- and these keys are not a
    // certificate's components in any case: they are separate keys
    // belonging to one person.
    const facts = sshGroupKeyFacts(members);
    expect(facts.components?.rows.every((r) => !r.isPrimary)).toBe(true);
    expect(facts.components?.title).toBe("Keys");
    expect(facts.components?.rowLabel).toBe("Key");
  });

  it("gives the rows no dates, and no verdict beyond `it parsed`", () => {
    // Absent, not null: an SSH key records no creation date, and a row
    // that printed one anyway would be printing the epoch.
    const facts = sshGroupKeyFacts(members);
    for (const row of facts.components?.rows ?? []) {
      expect(row).not.toHaveProperty("createdAt");
      expect(row).not.toHaveProperty("expiresAt");
      // An age recipient that parses IS an encryption key, and can be
      // nothing else -- age has no signatures.
      expect(row.canEncrypt).toBe(true);
      expect(row.canSign).toBe(false);
      expect(row.status).toBe("active");
    }
    expect(facts).not.toHaveProperty("health");
  });

  it("degrades to a one-row card for a contact with a single key", () => {
    const facts = sshGroupKeyFacts([members[0]]);
    expect(facts.components?.rows).toHaveLength(1);
    expect(facts.fingerprint).toBe("SHA256:aaa");
  });
});

/**
 * What the DETAILS page shows for a stored multi-key contact.
 *
 * The details page and the import preview share `KeyPreviewBody`
 * precisely so they cannot drift, but the details page used to call the
 * single-key builder unconditionally: the preview listed all three
 * fingerprints and the details page listed one. This pins the exact
 * expression the page now evaluates -- `sshGroupKeyFacts` over
 * `contactRecipients` -- so the two screens agree about how many keys a
 * person has.
 */
describe("a stored 3-key contact, as the details page builds it", () => {
  // Real-length OpenSSH fingerprints: 43 base64 characters after the
  // prefix. Truncation only shows up at full length.
  const FPS = [
    "SHA256:IoCz+8Ykvdvfq1sQ2pQm5oYtxK3n0uWJZ9hVbGfR7Ac",
    "SHA256:Xr4dLpQ0mNbT7yUvCeHgJk2WsZaFo9RiD3lPnQxYtB8",
    "SHA256:9kMzTvBnQeR2sYuIoPaSdFgHjKlZxCvBnM4qWeRtY6U",
  ];
  const contact: PublicContactKey = {
    kind: "ssh",
    keyId: FPS[0],
    userIds: ["octocat"],
    algorithm: "ssh-ed25519",
    armoredPublicKey: "ssh-ed25519 AAAA0 octocat@laptop",
    addedAt: 1,
    lastUsedAt: 1,
    source: { type: "github", user: "octocat", fetchedAt: 1 },
    recipients: FPS.map((keyId, i) => ({
      keyId,
      armored: `ssh-ed25519 AAAA${i} octocat@host${i}`,
      algorithm: i === 1 ? "ssh-rsa" : "ssh-ed25519",
    })),
  };

  it("lists all three keys, each with its FULL fingerprint", () => {
    const facts = sshGroupKeyFacts(contactRecipients(contact));
    expect(facts.components?.rows).toHaveLength(3);
    expect(facts.components?.rows.map((r) => r.fingerprint)).toEqual(FPS);
    // Uncut, not "SHA256:IoCz…": the fingerprint is the only out-of-band
    // check that GitHub returned the key its owner published, and half a
    // hash checks nothing.
    for (const row of facts.components?.rows ?? []) {
      expect(row.fingerprint).toHaveLength("SHA256:".length + 43);
      expect(row.fingerprint).not.toContain("…");
    }
    expect(facts.components?.truncated).toBe(false);
  });

  it("keeps a key the user turned off in the list", () => {
    // The display list is every key: one that vanished when excluded
    // could never be turned back on. `activeRecipients` is what narrows,
    // and only for encryption.
    const withOff: PublicContactKey = {
      ...contact,
      recipients: contact.recipients?.map((r, i) =>
        i === 1 ? { ...r, disabled: true as const } : r,
      ),
    };
    const facts = sshGroupKeyFacts(contactRecipients(withOff));
    expect(facts.components?.rows.map((r) => r.fingerprint)).toEqual(FPS);
    expect(activeRecipients(withOff)).toHaveLength(2);
  });

  it("shows one row for a single-key contact, without the field", () => {
    // A legacy record: `recipients` absent means the single top-level
    // key, so the same expression yields a one-row card.
    const legacy: PublicContactKey = {
      keyId: FPS[0],
      userIds: ["dev@host"],
      algorithm: "ssh-ed25519",
      armoredPublicKey: "ssh-ed25519 AAAA0 dev@host",
      addedAt: 1,
      lastUsedAt: 1,
    };
    expect(sshGroupKeyFacts(contactRecipients(legacy)).components?.rows).toEqual(
      [expect.objectContaining({ fingerprint: FPS[0] })],
    );
  });
});
