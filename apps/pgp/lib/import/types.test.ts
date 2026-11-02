/**
 * The import pipeline's engine routing. A misclassified kind means a
 * private key stored as a contact in the clear, so `isPublicKind` is
 * deny-by-default and the table below is an EXHAUSTIVE
 * `Record<KeyKind, ...>`: a new kind fails `tsc --noEmit` until decided.
 */

import { describe, expect, it } from "vitest";

import {
  isPublicKind,
  isSecretKind,
  PENDING_KEY_ID,
  type IncomingKey,
  type KeyKind,
} from "./types";

const CLASSIFICATION: Record<KeyKind, "public" | "secret"> = {
  "pgp-public": "public",
  "pgp-private": "secret",
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
    // The two predicates drive storage independently; both or neither true
    // would store twice or drop.
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
    // Deny-by-default: an unclassified kind takes the protect path.
    expect(isPublicKind("age-public" as KeyKind)).toBe(false);
    expect(isSecretKind("age-public" as KeyKind)).toBe(true);
  });
});

describe("PENDING_KEY_ID", () => {
  it("is not a plausible fingerprint", () => {
    // A flow-only map key; must never reach storage as an id.
    expect(PENDING_KEY_ID).toBe("pending");
    expect(/^[0-9A-F]{16,40}$/i.test(PENDING_KEY_ID)).toBe(false);
    expect(/^[a-p]{32}$/.test(PENDING_KEY_ID)).toBe(false);
  });
});

describe("IncomingKey", () => {
  it("has no field that could hold secret material", () => {
    // Structural half of "private armor stays in `secrets`": the preview goes
    // to React state, so its only armor field is the PUBLIC one. Exhaustive
    // by type, so a new field must be listed here.
    const FIELDS: Record<keyof Required<IncomingKey>, true> = {
      keyId: true,
      kind: true,
      status: true,
      info: true,
      details: true,
      userIds: true,
      changes: true,
      replaces: true,
      conflict: true,
      existingAddedAt: true,
      rejection: true,
      securityWarning: true,
      publicArmored: true,
      // Public halves only.
      group: true,
      // Provenance only; no key material.
      source: true,
      allKeysOff: true,
    };
    const names = Object.keys(FIELDS);

    expect(names.filter((n) => /armor|pem/i.test(n))).toEqual([
      "publicArmored",
    ]);
    expect(
      names.filter((n) => /secret|private|passphrase|password/i.test(n)),
    ).toEqual([]);
  });
});
