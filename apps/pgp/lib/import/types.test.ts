/**
 * The import pipeline's engine routing.
 *
 * `KeyKind` is the switch that decides where an incoming key goes: a
 * public half is stored as a contact immediately, anything else carries
 * secret material and must be routed through the protect step with its
 * armor kept out of React state. Mis-classify a kind and the failure is
 * not an error -- it is a private key written into the contacts store in
 * the clear, or a public key sent through a password prompt that can't
 * work.
 *
 * `isPublicKind` is written as a deny-by-default set membership, so a
 * newly-added kind is treated as secret rather than as public. That is
 * the safe direction, but it was wrong for "ssh-public" when that kind
 * arrived, so the table below is typed as an EXHAUSTIVE
 * `Record<KeyKind, ...>`:
 * adding a member to the union without deciding its side here fails
 * `tsc --noEmit` (which CI runs alongside this suite), and the runtime
 * assertions then check the helpers agree with the decision.
 */

import { describe, expect, it } from "vitest";

import type { IncomingKey, KeyKind } from "./types";
import { isPublicKind, isSecretKind, PENDING_KEY_ID } from "./types";

/**
 * Every member of `KeyKind` and which half it is. Exhaustive by type:
 * a new kind is a compile error until it is classified here.
 */
const CLASSIFICATION: Record<KeyKind, "public" | "secret"> = {
  "pgp-public": "public",
  "pgp-private": "secret",
  // An SSH public key line is somebody else's public half: it goes
  // straight to contacts, exactly like a PGP public cert. The OpenSSH
  // private container takes the protect path.
  "ssh-public": "public",
  "ssh-private": "secret",
  crx: "secret",
};

const ALL_KINDS = Object.keys(CLASSIFICATION) as KeyKind[];

describe("isPublicKind / isSecretKind", () => {
  it("classifies every member of the KeyKind union", () => {
    for (const kind of ALL_KINDS) {
      expect(isPublicKind(kind)).toBe(CLASSIFICATION[kind] === "public");
    }
  });

  it("partitions the union -- every kind is exactly one of the two", () => {
    // The protect step and the contact store are driven by these two
    // predicates independently; a kind that answered true (or false) to
    // both would be either stored twice or dropped.
    for (const kind of ALL_KINDS) {
      expect(isSecretKind(kind)).toBe(!isPublicKind(kind));
    }
    expect(ALL_KINDS.filter(isPublicKind).sort()).toEqual([
      "pgp-public",
      "ssh-public",
    ]);
    expect(ALL_KINDS.filter(isSecretKind).sort()).toEqual([
      "crx",
      "pgp-private",
      "ssh-private",
    ]);
  });

  it("treats an unrecognised kind as carrying secrets", () => {
    // The deny-by-default half of the contract: a kind that slipped
    // through unclassified must take the protect path, never the
    // publish-to-contacts path.
    // Deliberately a kind that does NOT exist yet -- native age keys
    // (`age1...` recipients) are the marked extension point in
    // `gpg-wasm/src/age.rs`, so they are the next plausible addition.
    expect(isPublicKind("age-public" as KeyKind)).toBe(false);
    expect(isSecretKind("age-public" as KeyKind)).toBe(true);
  });
});

describe("PENDING_KEY_ID", () => {
  it("is not a plausible fingerprint", () => {
    // It is a map key inside the flow only. A CRX key's real identity is
    // its extension id, derived from the public half inside the protect
    // step; this placeholder must never be mistaken for one or reach
    // storage as one.
    expect(PENDING_KEY_ID).toBe("pending");
    expect(/^[0-9A-F]{16,40}$/i.test(PENDING_KEY_ID)).toBe(false);
    expect(/^[a-p]{32}$/.test(PENDING_KEY_ID)).toBe(false);
  });
});

describe("IncomingKey", () => {
  it("has no field that could hold secret material", () => {
    // Structural half of the "private armor stays in `secrets`" rule
    // (`prepare.test.ts` covers the behavioural half): the preview object
    // is handed to React state and serialized to the UI, so the only
    // armor field on it is the PUBLIC one, and its name says so.
    //
    // Exhaustive by type -- a new field on `IncomingKey` is a compile
    // error until it is listed here, and a field called `privateArmored`
    // or `secretPem` then fails the assertions below.
    const FIELDS: Record<keyof Required<IncomingKey>, true> = {
      keyId: true,
      kind: true,
      status: true,
      info: true,
      details: true,
      userIds: true,
      changes: true,
      existingAddedAt: true,
      rejection: true,
      securityWarning: true,
      publicArmored: true,
      // A fetched person's keys. Public halves only: its members carry
      // the same canonical recipient line `publicArmored` does, and its
      // rejected lines are the text that was fetched.
      group: true,
    };
    const names = Object.keys(FIELDS);

    expect(names.filter((n) => /armor|pem/i.test(n))).toEqual([
      "publicArmored",
    ]);
    expect(names.filter((n) => /secret|private|passphrase|password/i.test(n)))
      .toEqual([]);
  });
});
